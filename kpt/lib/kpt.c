#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define __USE_GNU

/* Standard Includes */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

/* Local Includes */
#include "kpt.h"
#include "kpt_utils.h"


/* Total number of loaded device credentials */
static int wpk_num = 0;
static int wpk_loading_idx = 0;

/**
 ******************************************************************
 *  KPT Device Credentials in multiple WPK files, each WPK file
 *  contains multiple credentials for different devices.
 *    WPK 0: (e.g. RSA2k)
 *          ESWK0  DEV_ID0  PARAM0  (e.g. for cpu_socket0->dev0)
 *          ESWK1  DEV_ID1  PARAM1  (e.g. for cpu_socket1->dev1)
 *         ...
 *    WPK 1: (e.g. ECC-P256)
 *          ESWKm  DEV_IDm  PARAMm
 *    ...
 *   WPK n: ESWKn  DEV_IDn  PARAMn
 *****************************************************************/
static kpt_dev_credential_st kpt_dev_crdt[MAX_WPK_NUM] = {{0}};

/**
 ******************************************************************
 *  Each instance will do KPT provision for each loaded WPK files 
 *  depends on the corresponding ESWK which matches the dev_id.
 *
 *    Instance 0: (e.g. located on cpu_socket0->dev0)
 *           WPK 0:  KPT_unwrap_ctx(0)  ESWK(cpu_socket0->dev0)
 *           WPK 1:  KPT_unwrap_ctx(1)  ESWK(cpu_socket0->dev0)
 *           ...
 *           WPK k:  KPT_unwrap_ctx(k)  ESWK(cpu_socket0->dev0)
 *    ...
 *    Instance n: (e.g. located on cpu_socket(i)->dev(j))
 *           WPK 0:  KPT_unwrap_ctx(0)  ESWK(cpu_socket(i)->dev(j))
 *           ...
 *           WPK k:  KPT_unwrap_ctx(k)  ESWK(cpu_socket(i)->dev(j))
 *****************************************************************/
kpt_inst_provision_context_st kpt_inst_prvs_ctx[MAX_CRYPTO_INSTANCES] = {{0}};

/* To specify the RSA op sizes supported by QAT engine */
#define RSA_KPT_RANGE_MIN 512
#define RSA_KPT_RANGE_MAX 8192
#define NO_PADDING 0
#define PADDING    1



/* For SWK */
ASN1_SEQUENCE(ESWK) = {
    ASN1_SIMPLE(ESWK, devSig, ASN1_OCTET_STRING),
    ASN1_SIMPLE(ESWK, secSWK, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(ESWK)
IMPLEMENT_ASN1_FUNCTIONS(ESWK)

ASN1_SEQUENCE(WRAPPINGMETADATA) = {
    ASN1_SIMPLE(WRAPPINGMETADATA, aesNonce, ASN1_OCTET_STRING),
    ASN1_SIMPLE(WRAPPINGMETADATA, wrappingAlg, ASN1_OBJECT),
    ASN1_SEQUENCE_OF(WRAPPINGMETADATA, eSWKs, ESWK)
}ASN1_SEQUENCE_END(WRAPPINGMETADATA)
IMPLEMENT_ASN1_FUNCTIONS(WRAPPINGMETADATA)

/* For RSA */
ASN1_SEQUENCE(RSAPUBLICKEY) = {
    ASN1_SIMPLE(RSAPUBLICKEY, n, ASN1_INTEGER),
    ASN1_SIMPLE(RSAPUBLICKEY, e, ASN1_INTEGER),
}ASN1_SEQUENCE_END(RSAPUBLICKEY)
IMPLEMENT_ASN1_FUNCTIONS(RSAPUBLICKEY)

ASN1_SEQUENCE(KPTRSAKEY) = {
    ASN1_SIMPLE(KPTRSAKEY, version, LONG),
    ASN1_SIMPLE(KPTRSAKEY, privateKeyType1, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KPTRSAKEY, privateKeyType2, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KPTRSAKEY, size, LONG),
    ASN1_SIMPLE(KPTRSAKEY, kptRSADsi, ASN1_OBJECT),
    ASN1_SIMPLE(KPTRSAKEY, publicKey, RSAPUBLICKEY),
    ASN1_SIMPLE(KPTRSAKEY, wrappingMetadata, WRAPPINGMETADATA),
}ASN1_SEQUENCE_END(KPTRSAKEY)
IMPLEMENT_ASN1_FUNCTIONS(KPTRSAKEY)

/* For ECC */
ASN1_SEQUENCE(KPTECCKEY) = {
    ASN1_SIMPLE(KPTECCKEY, version, LONG),
    ASN1_SIMPLE(KPTECCKEY, privateKey, ASN1_OCTET_STRING),
    ASN1_EXP_OPT(KPTECCKEY, curveName, ASN1_OBJECT, 0),
    ASN1_EXP_OPT(KPTECCKEY, publicKey, ASN1_BIT_STRING, 1),
    ASN1_SIMPLE(KPTECCKEY, wrappingMetadata, WRAPPINGMETADATA)
}ASN1_SEQUENCE_END(KPTECCKEY)
IMPLEMENT_ASN1_FUNCTIONS(KPTECCKEY)


/**
 ******************************************************************
 *    Curve       OID                    DER(OID)
 *    secp256r1  1.2.840.10045.3.1.7  06 08 2A 86 48 CE 3D 03 01 07
 *    secp384r1  1.3.132.0.34            06 05 2B 81 04 00 22
 *    secp521r1  1.3.132.0.35            06 05 2B 81 04 00 23
 *****************************************************************/
#define NID_SECP256R1 415
#define NID_SECP384R1 715
#define NID_SECP521R1 716

static unsigned char secp256_oid[] = {
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

static unsigned char secp384_oid[] = {
    0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22
};

static unsigned char secp521_oid[] = {
    0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23
};

static unsigned char rsa_oid[] = {
    0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01
};

#ifdef QAT_OPENSSL_3
static int (*default_rsa_init)(RSA *rsa) = NULL;
static __thread RSA *kpt_keymgmt_rsa = NULL;
static int (*default_ec_key_init)(EC_KEY *key) = NULL;
static void (*default_ec_key_finish)(EC_KEY *key) = NULL;
static int (*default_ec_key_copy)(EC_KEY *dest, const EC_KEY *src) = NULL;
static int (*default_ec_key_set_group)(EC_KEY *key, const EC_GROUP *grp) = NULL;
static int (*default_ec_key_set_private)(EC_KEY *key, const BIGNUM *priv_key) = NULL;
static int (*default_ec_key_set_public)(EC_KEY *key, const EC_POINT *pub_key) = NULL;
static __thread EC_KEY *kpt_keymgmt_ec_key = NULL;
#endif

/**
 *****************************************************************************
 * 
 * WPK files load and parse implementation.
 *
 *****************************************************************************/
int kpt_reset_wpk_num() {
    wpk_loading_idx = 0;
    return wpk_loading_idx;
}

/* Valid WPK index returns 1, invalid index returns 0. */
static int kpt_wpk_idx_check(int wpk_index) {
    return !(wpk_index < 0 || wpk_index > (wpk_num - 1));
}

static int parse_wrapping_metadata(WRAPPINGMETADATA *wrapping_metadata, 
                                   kpt_wpk_type wpktype, int nid)
{
    ESWK *eSWK = NULL;
    ASN1_OCTET_STRING *iv = NULL;
    ASN1_OCTET_STRING *swk_sec = NULL;
    ASN1_OCTET_STRING *swk_pub = NULL;
    int enc_algo_nid = 0;
    unsigned char *aad = NULL;
    int aad_len = 0;
    kpt_eswk_meta_data_st *eswk = NULL;
    kpt_dev_identity_st *dev_id = NULL;
    int socket_num = 0;
    int i = 0;

    socket_num = sk_ESWK_num(wrapping_metadata->eSWKs);
    if (socket_num <= 0) {
        WARN("Not found ESWK in current WPK file.\n");
        return 0;
    }

    enc_algo_nid = OBJ_obj2nid(wrapping_metadata->wrappingAlg);
    iv = wrapping_metadata->aesNonce;

    if (PEM_TYPE_ECC_WPK == wpktype) {
        switch(nid) {
            case NID_SECP256R1:
            {
                aad = secp256_oid;
                aad_len = sizeof(secp256_oid);
                break;
            }
            case NID_SECP384R1:
            {
                aad = secp384_oid;
                aad_len = sizeof(secp384_oid);
                break;
            }
            case NID_SECP521R1:
            {
                aad = secp521_oid;
                aad_len = sizeof(secp521_oid);
                break;
            }
            default:
            {
                WARN("Unknown ECC curve\n");
                return 0;
            }
            break;
        }
    }
    else if (PEM_TYPE_RSA_WPK == wpktype) {
        aad = rsa_oid;
        aad_len = sizeof(rsa_oid);
    }
    else {
        WARN("Unknown WPK type\n");
        return 0;
    }

    if (wpk_loading_idx < 0 || wpk_loading_idx > (MAX_WPK_NUM - 1)) {
        WARN("Invalid WPK index whiling loading.\n");
        return 0;
    }

    eswk = kpt_dev_crdt[wpk_loading_idx].eswk_data;
    dev_id = kpt_dev_crdt[wpk_loading_idx].dev_id;
    kpt_dev_crdt[wpk_loading_idx].total = socket_num;

    for (i = 0; i < socket_num; i++ )
    {
        if (enc_algo_nid != NID_aes_256_gcm) {
            WARN("Invalid wrapping algorithm for KPT\n");
            return 0;
        }

        eSWK = sk_ESWK_value(wrapping_metadata->eSWKs, i);
        if ((swk_sec = eSWK->secSWK) == NULL) return 0;
        if ((swk_pub = eSWK->devSig) == NULL) return 0;

        /* Encrypted SWK */
        if ((eswk[i].len_eswk = ASN1_STRING_length(swk_sec)) < 0) return 0;
        memcpy(eswk[i].eswk,
            ASN1_STRING_get0_data(swk_sec), 
            ASN1_STRING_length(swk_sec));

        /* IV */
        if ((eswk[i].len_iv = ASN1_STRING_length(iv)) < 0) return 0;
        memcpy(eswk[i].iv, 
            ASN1_STRING_get0_data(iv), 
            ASN1_STRING_length(iv));

        /* AAD data */
        if ((eswk[i].len_aad = aad_len) < 0) return 0;
        memcpy(eswk[i].aad, aad, aad_len);

        /* Signature */
        if ((dev_id[i].len_sig = ASN1_STRING_length(swk_pub)) < 0) return 0;
        memcpy(dev_id[i].signature, 
            ASN1_STRING_get0_data(swk_pub), 
            ASN1_STRING_length(swk_pub));

        DUMP_KPT_WRAPPING_DATA(
            eswk[i].eswk, eswk[i].len_eswk, 
            dev_id[i].signature, dev_id[i].len_sig,
            eswk[i].iv, eswk[i].len_iv,
            eswk[i].aad, eswk[i].len_aad);

    }

    DEBUG("Current WPK file has %d eSWK\n", socket_num);

    return 1;
}

#ifdef QAT_OPENSSL_3
int kpt_keymgmt_rsa_init(RSA *rsa)
{
    kpt_keymgmt_rsa = rsa;
    if (default_rsa_init && default_rsa_init != kpt_keymgmt_rsa_init)
        return default_rsa_init(rsa);
    return 1;
}

int kpt_keymgmt_ec_key_init(EC_KEY *key)
{
    kpt_keymgmt_ec_key = key;
    if (default_ec_key_init && default_ec_key_init != kpt_keymgmt_ec_key_init)
        return default_ec_key_init(key);
    return 1;
}

#endif
static EVP_PKEY *EVP_RSAWPK2PKEY(ENGINE *engine, const KPTRSAKEY *wpkinfo, 
                                 kpt_wpk_type wpktype)
{
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    kpt_rsa_wpk *rsa_wpk = NULL;

    RSAPUBLICKEY *pub_key = NULL;
    WRAPPINGMETADATA *wrapping_metadata = NULL;

    long version = 0, size = 0;
    ASN1_OCTET_STRING *wrapped_key_type1 = NULL;
    ASN1_OCTET_STRING *wrapped_key_type2 = NULL;

    ASN1_OBJECT *wrapping_algo = NULL;
    ASN1_OCTET_STRING *iv = NULL;
    int enc_algo_nid = 0;
    
    ASN1_INTEGER *n = NULL;
    ASN1_INTEGER *e = NULL;
    BIGNUM *n_bn = NULL;
    BIGNUM *e_bn = NULL;
#ifdef QAT_OPENSSL_3
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    RSA_METHOD *rsa_method = NULL;
    ENGINE * rsa_engine = NULL;
#endif

    /* struct kpt_rsa_key */
    if ((version = wpkinfo->version) < 0) 
        goto error;
    if ((size = wpkinfo->size) < 0) 
        goto error;
    if ((wrapping_metadata = wpkinfo->wrappingMetadata) == NULL) 
        goto error;
    if ((wrapped_key_type1 = wpkinfo->privateKeyType1) == NULL) 
        goto error;
    if ((wrapped_key_type2 = wpkinfo->privateKeyType2) == NULL) 
        goto error;
    if ((pub_key = wpkinfo->publicKey) == NULL) 
        goto error;

    /* struct wrapping_metadata */
    if ((wrapping_algo = wrapping_metadata->wrappingAlg) == NULL) 
        goto error;
    if ((iv = wrapping_metadata->aesNonce) == NULL) 
        goto error;

    /* struct rsa_public_key */
    if ((n = pub_key->n) == NULL) 
        goto error;
    if ((e = pub_key->e) == NULL) 
        goto error;

    /* Populate kpt_dev_crdt array */
    enc_algo_nid = OBJ_obj2nid(wrapping_algo);
    if (!parse_wrapping_metadata(wrapping_metadata, wpktype, 0)) {
        WARN("Error in parse_wrapping_metadata\n");
        goto error;
    }

#ifndef QAT_OPENSSL_3
    pkey = EVP_PKEY_new();
    if (!pkey) {
        WARN("Error in EVP_PKEY_new\n");
        goto error;
    }
    rsa = RSA_new();
    if (!rsa) {
        WARN("Error in RSA_new\n");
        goto error;
    }
#endif

    n_bn = ASN1_INTEGER_to_BN(n, NULL);
    e_bn = ASN1_INTEGER_to_BN(e, NULL);
#ifndef QAT_OPENSSL_3
    RSA_set0_key(rsa, n_bn, e_bn, NULL);
#endif

    /* Populate struct kpt_rsa_wpk_st */
    rsa_wpk = (kpt_rsa_wpk *)malloc(sizeof(kpt_rsa_wpk));
    if (!rsa_wpk)
        goto error;
    memset(rsa_wpk, 0, sizeof(kpt_rsa_wpk));

    rsa_wpk->version = version;
    rsa_wpk->size = size;
    rsa_wpk->wrapping_alg_nid = enc_algo_nid;

    BN_bn2bin(n_bn, rsa_wpk->n);
    BN_bn2bin(e_bn, rsa_wpk->e);
    rsa_wpk->n_size = BN_num_bytes(n_bn);
    rsa_wpk->e_size = BN_num_bytes(e_bn);

    if (wrapped_key_type1) {
        if ((rsa_wpk->wpk_type1_size = ASN1_STRING_length(wrapped_key_type1)) > 0) {
            memcpy(rsa_wpk->wpk_type1, ASN1_STRING_get0_data(wrapped_key_type1),
                rsa_wpk->wpk_type1_size);
        }
    }
    if (wrapped_key_type2) {
        if ((rsa_wpk->wpk_type2_size = ASN1_STRING_length(wrapped_key_type2)) > 0) {
            memcpy(rsa_wpk->wpk_type2, ASN1_STRING_get0_data(wrapped_key_type2),
                rsa_wpk->wpk_type2_size);
        }
    }

    /* Save for kpt handle look up */
    rsa_wpk->wpk_index = wpk_loading_idx;
    wpk_loading_idx++;
    wpk_num = wpk_loading_idx;
    DEBUG("Total WPK number: %d\n", wpk_loading_idx);

#ifdef QAT_OPENSSL_3
    rsa_engine = ENGINE_get_default_RSA();
    if (rsa_engine == NULL) {
        ENGINE_set_default_RSA(engine);
        rsa_engine = engine;
    }
    if (rsa_engine == NULL) {
        WARN("default rsa engine is null\n");
        goto error;
    }
    rsa_method = (RSA_METHOD *)ENGINE_get_RSA(rsa_engine);
    if (rsa_method == NULL) {
        WARN("rsa_method is null\n");
        goto error;
    }
    default_rsa_init = RSA_meth_get_init(rsa_method);
    bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n_bn);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e_bn);
    params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX_get0_global_default(), "RSA", NULL);
    EVP_PKEY_fromdata_init(ctx);
    RSA_meth_set_init(rsa_method, kpt_keymgmt_rsa_init);
    kpt_keymgmt_rsa = NULL;
    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params);
    RSA_meth_set_init(rsa_method, default_rsa_init);
    rsa = kpt_keymgmt_rsa;
    /* Save rsa_wpk into EVP_PKEY */
    if (RSA_set_ex_data(rsa, KEY_WRAP_STORAGE_INDEX, rsa_wpk) != 1) {
        WARN("Failed in RSA_set_ex_data\n");
        goto error;
    }
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
#else
    /* Save rsa_wpk into EVP_PKEY */
    if (RSA_set_ex_data(rsa, KEY_WRAP_STORAGE_INDEX, rsa_wpk) != 1) {
        WARN("Failed in RSA_set_ex_data\n");
        goto error;
    }

    EVP_PKEY_assign_RSA(pkey, rsa);
#endif
    return pkey;
error:
    free(rsa_wpk);
#ifdef QAT_OPENSSL_3
    if (params)
        OSSL_PARAM_free(params);
    if (bld)
        OSSL_PARAM_BLD_free(bld);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
#endif

    return NULL;
}

static EVP_PKEY *EVP_ECCWPK2PKEY(ENGINE *engine, const KPTECCKEY *wpkinfo,
                                      kpt_wpk_type wpktype)
{
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec = NULL;
    kpt_ecc_wpk *ecc_wpk = NULL;

    long version = 0;
    WRAPPINGMETADATA *wrapping_metadata = NULL;
    ASN1_OCTET_STRING *wrapped_key = NULL;
    unsigned char *priv_key_buf = NULL;
    int priv_key_buf_len;
    ASN1_OBJECT *curve_name = NULL;
    ASN1_BIT_STRING *pub_key = NULL;
    unsigned char *pub_key_buf = NULL;
    int pub_key_buf_len;
    EC_GROUP *group = NULL;

    ASN1_OBJECT *wrapping_algo = NULL;
    ASN1_OCTET_STRING *iv = NULL;
    size_t sz;
    int enc_algo_nid = 0;
    int curve_nid = 0;
    int ecbits;

    int i = 0;
#ifdef QAT_OPENSSL_3
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EC_KEY_METHOD *ec_key_method = NULL;
    const char *ec_group_name = NULL;
    BIGNUM *ec_priv_bn = NULL;
    ENGINE *ec_engine = NULL;
#endif


    /* struct kpt_ecc_key */
    if ((version = wpkinfo->version) < 0) goto error;
    if ((wrapping_metadata = wpkinfo->wrappingMetadata) == NULL) goto error;
    if ((wrapped_key = wpkinfo->privateKey) == NULL) goto error;
    if ((curve_name = wpkinfo->curveName) == NULL) goto error;
    if ((pub_key = wpkinfo->publicKey) == NULL) goto error;

    /* struct wrapping_metadata */
    if ((wrapping_algo = wrapping_metadata->wrappingAlg) == NULL) goto error;
    if ((iv = wrapping_metadata->aesNonce) == NULL) goto error;

    /* Populate kpt_dev_crdt array */
    enc_algo_nid = OBJ_obj2nid(wrapping_algo);
    curve_nid = OBJ_obj2nid(curve_name);
    if (!parse_wrapping_metadata(wrapping_metadata, wpktype, curve_nid)) {
        WARN("Error in parse_wrapping_metadata\n");
        goto error;
    }

#ifdef  QAT_OPENSSL_3
    bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        WARN("Error in OSSL_PARAM_BLD_new\n");
        goto error;
    }
#else
    pkey = EVP_PKEY_new();
    if (!pkey) {
        WARN("Error in EVP_PKEY_new\n");
        goto error;
    }
    ec = EC_KEY_new();
    if (!ec) {
        WARN("Error in EC_KEY_new\n");
        goto error;
    }
#endif
    /* Create Group */
    group = EC_GROUP_new_by_curve_name(curve_nid);
#ifdef QAT_OPENSSL_3
    ec_group_name = OBJ_nid2sn(curve_nid);
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, ec_group_name,
                                        strlen(ec_group_name));
#else
    EC_KEY_set_group(ec, group);
#endif
    /* Copy Public Key */
    if ((pub_key_buf_len = ASN1_STRING_length(pub_key)) < 0) goto error;
    pub_key_buf = malloc(pub_key_buf_len);
    memset(pub_key_buf, 0, pub_key_buf_len);
    memcpy(pub_key_buf, ASN1_STRING_get0_data(pub_key), pub_key_buf_len);

#ifdef QAT_OPENSSL_3
    if (!(i = OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                         pub_key_buf, pub_key_buf_len))) {
        WARN("Error in OSSL_PARAM_BLD_push_octet_string, return %d\n", i);
        goto error;
    }
#else
    if (!(i = EC_KEY_oct2key(ec, (const unsigned char *)pub_key_buf,
        pub_key_buf_len, NULL))) {
        WARN("Error in EC_KEY_oct2key, return %d\n", i);
        goto error;
    }
#endif

    /* Copy Private Key */
    if ((priv_key_buf_len = ASN1_STRING_length(wrapped_key)) < 0) goto error;
    priv_key_buf = malloc(priv_key_buf_len);
    memset(priv_key_buf, 0, priv_key_buf_len);
    memcpy(priv_key_buf, ASN1_STRING_get0_data(wrapped_key), priv_key_buf_len);
    ecbits = EC_GROUP_order_bits(group);
    sz = (ecbits + 7 ) / 8;
    /* Set a dummy private key to align with OpenSSL routine, the private key is
       not really used. */
#ifdef QAT_OPENSSL_3
    ec_priv_bn = BN_bin2bn(priv_key_buf, sz, NULL);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, ec_priv_bn);
#else
    if (!(i = EC_KEY_oct2priv(ec, (const unsigned char *)priv_key_buf, sz))) {
        WARN("Error in EC_KEY_oct2priv, return %d\n", i);
        goto error;
    }
#endif

    /* Populate struct kpt_ecc_wpk_st */
    ecc_wpk = (kpt_ecc_wpk *)malloc(sizeof(kpt_ecc_wpk));
    if (!ecc_wpk)
        goto error;
    memset(ecc_wpk, 0, sizeof(kpt_ecc_wpk));

    ecc_wpk->version = version;
    ecc_wpk->wrapping_alg_nid = enc_algo_nid;
    ecc_wpk->curve_nid = curve_nid;

    /* Copy private key */
    memcpy(ecc_wpk->wpk, priv_key_buf, priv_key_buf_len);
    ecc_wpk->wpk_size = priv_key_buf_len;

    /* Copy Public Key */
    memcpy(ecc_wpk->pub_key, pub_key_buf, pub_key_buf_len);
    ecc_wpk->pub_key_size = pub_key_buf_len;

#ifdef QAT_OPENSSL_3
    ec_engine = ENGINE_get_default_EC();
    if (ec_engine == NULL) {
        ENGINE_set_default_EC(engine);
        ec_engine = engine;
    }
    if (ec_engine == NULL) {
        WARN("default ec engine is null\n");
        goto error;
    }
    ec_key_method = (EC_KEY_METHOD *)ENGINE_get_EC(ec_engine);
    EC_KEY_METHOD_get_init(ec_key_method, &default_ec_key_init, &default_ec_key_finish,
                                &default_ec_key_copy, &default_ec_key_set_group,
                                &default_ec_key_set_private, &default_ec_key_set_public);
    params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX_get0_global_default(), "EC", NULL);
    EVP_PKEY_fromdata_init(ctx);
    EC_KEY_METHOD_set_init(ec_key_method, kpt_keymgmt_ec_key_init, default_ec_key_finish,
                                default_ec_key_copy, default_ec_key_set_group,
                                default_ec_key_set_private, default_ec_key_set_public);
    kpt_keymgmt_ec_key = NULL;
    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params);
    EC_KEY_METHOD_set_init(ec_key_method, default_ec_key_init, default_ec_key_finish,
                                default_ec_key_copy, default_ec_key_set_group,
                                default_ec_key_set_private, default_ec_key_set_public);
    ec = kpt_keymgmt_ec_key;
    kpt_keymgmt_ec_key = NULL;
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
#endif

    /* Save rsa_wpk into EVP_PKEY */
    if (EC_KEY_set_ex_data(ec, KEY_WRAP_STORAGE_INDEX, ecc_wpk) != 1) {
        WARN("Failed in EC_KEY_set_ex_data\n");
        goto error;
    }

    /* Save for kpt handle look up */
    ecc_wpk->wpk_index = wpk_loading_idx;
    wpk_loading_idx++;
    wpk_num = wpk_loading_idx;
    DEBUG("Total WPK number: %d\n", wpk_loading_idx);

#ifndef  QAT_OPENSSL_3
    EVP_PKEY_assign_EC_KEY(pkey, ec);
#endif
    return pkey;
error:
    if (ecc_wpk)
       free(ecc_wpk);
    if (pub_key_buf)
       free(pub_key_buf);
    if (priv_key_buf)
       free(priv_key_buf);
#ifdef QAT_OPENSSL_3
    if (params)
        OSSL_PARAM_free(params);
    if (bld)
        OSSL_PARAM_BLD_free(bld);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
#endif
    return NULL;
}

static EVP_PKEY *PEM_read_bio_WPK(ENGINE *e, BIO *bp)
{
    char *nm = NULL;
    char *header = NULL;
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long len;
    EVP_PKEY *pkey = NULL;

    if (!PEM_read_bio(bp, &nm, &header, &data, &len)) {
        WARN("Error in PEM_read_bio\n");
        return NULL;
    }

    p = data;
    if (strcmp(nm, PEM_STRING_WRAPPED_RSA_KEY) == 0) {
        DEBUG("Parse RSA WPK file\n");
        KPTRSAKEY *wpkinfo;
        wpkinfo = d2i_KPTRSAKEY(NULL, &p, len);
        if (wpkinfo == NULL) {
            goto error;
        }
        if (!(pkey = EVP_RSAWPK2PKEY(e, wpkinfo, PEM_TYPE_RSA_WPK))) {
            WARN("Error in EVP_RSAWPK2PKEY\n");
        }
    }
    else if (strcmp(nm, PEM_STRING_WRAPPED_ECC_KEY) == 0) {
        DEBUG("Parse ECC WPK file\n");
        KPTECCKEY *wpkinfo;
        wpkinfo = d2i_KPTECCKEY(NULL, &p, len);
        if (wpkinfo == NULL) {
            goto error;
        }
        if (!(pkey = EVP_ECCWPK2PKEY(e, wpkinfo, PEM_TYPE_ECC_WPK))) {
            WARN("Error in EVP_ECCWPK2PKEY\n");
        }
    }
    else {
        WARN("Invalid PEM_STRING for KPT\n");
    }

error:
    OPENSSL_free(nm);
    OPENSSL_clear_free(data, len);
    return pkey;
}

EVP_PKEY *kpt_load_priv_key(ENGINE *e, const char *wpk)
{
    EVP_PKEY *pkey = NULL;
    BIO *in;

    if (access(wpk, F_OK)) {
        WARN("File %s does not exist\n", wpk);
        goto error;
    }

    in = BIO_new(BIO_s_file());
    if (!in) {
        WARN("BIO new failed\n");
        goto error;
    }

    if (!BIO_read_filename(in, wpk)) {
        WARN("Read wrapped private key file %s failed\n", wpk);
        BIO_free(in);
        goto error;
    }

    DEBUG("Parse Wrapped Private Key(WPK): \n");
    if (!(pkey = PEM_read_bio_WPK(e, in))) {
        WARN("Error in PEM_read_bio_WPK\n");
        goto error;
    }

    return pkey;

error:
    WARN("Error in kpt_load_priv_key\n");
    return NULL;
}


/**
 ******************************************************************************
 * 
 * KPT init and finish implementation.
 *
 *****************************************************************************/
/* Valid instance index returns 1, invalid index returns 0. */
static int kpt_inst_idx_check(int qat_inst_index) {
    return !(qat_inst_index < 0 || qat_inst_index > (MAX_CRYPTO_INSTANCES - 1));
}

int kpt_instance_available(int qat_inst_index, int wpk_index) {
    if (!kpt_inst_idx_check(qat_inst_index)) {
        WARN("Invalid QAT instance index.\n");
        return 0;
    }

    if (!kpt_wpk_idx_check(wpk_index)) {
        WARN("Invalid WPK index.\n");
        return 0;
    }

    return (kpt_inst_prvs_ctx[qat_inst_index].kpt_enabled &&
    kpt_inst_prvs_ctx[qat_inst_index].meta_ctx[wpk_index].swk_provisioned);
}

static int get_encrypted_swk(CpaInstanceHandle qat_inst_handle, int wpk_idx)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyKptKeyManagementStatus kptStatus = CPA_CY_KPT_SUCCESS;
    CpaCyKptValidationKey DevCredential;
    kpt_dev_identity_st *dev_id = NULL;
    int num = 0;
    int i = 0;

    DevCredential.publicKey.modulusN.pData = 
        (Cpa8U *) qaeMemAllocNUMA(KPT_PER_PART_PUBKEY_N_SIZE_IN_BYTE, 0, 64);
    if (NULL == DevCredential.publicKey.modulusN.pData) {
        return -1;
    }
    DevCredential.publicKey.modulusN.dataLenInBytes = 
        KPT_PER_PART_PUBKEY_N_SIZE_IN_BYTE;

    DevCredential.publicKey.publicExponentE.pData = 
        (Cpa8U *) qaeMemAllocNUMA(KPT_PER_PART_PUBKEY_E_SIZE_IN_BYTE, 0, 64);
    if (NULL == DevCredential.publicKey.publicExponentE.pData) {
        qaeMemFreeNUMA((void **)&DevCredential.publicKey.modulusN.pData);
        return -1;
    }
    DevCredential.publicKey.publicExponentE.dataLenInBytes = 
        KPT_PER_PART_PUBKEY_E_SIZE_IN_BYTE;

    status = cpaCyKptQueryDeviceCredentials(qat_inst_handle, 
                                            &DevCredential, &kptStatus);
    if (CPA_STATUS_SUCCESS != status || CPA_CY_KPT_SUCCESS != kptStatus) {
        WARN("Failed to query dev credentials, kptstatus = %d\n", kptStatus);
        goto not_found;
    }

    /* The wpk_idx is passed in within valid range. */
    num = kpt_dev_crdt[wpk_idx].total;
    dev_id = kpt_dev_crdt[wpk_idx].dev_id;

    for(i = 0; i < num; i++) {
        if (!memcmp(dev_id[i].signature, DevCredential.signature, 
                   KPT_DEV_CREDENTIAL_SIZE_IN_BYTE)) {
            qaeMemFreeNUMA((void **)&DevCredential.publicKey.modulusN.pData);
            qaeMemFreeNUMA((void **)&DevCredential.publicKey.publicExponentE.pData);
            return i;
        }
    }

not_found:
    qaeMemFreeNUMA((void **)&DevCredential.publicKey.modulusN.pData);
    qaeMemFreeNUMA((void **)&DevCredential.publicKey.publicExponentE.pData);
    return -1;
}

int kpt_init(int qat_inst_index, CpaInstanceHandle qat_inst_handle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyKptKeyManagementStatus kptStatus = CPA_CY_KPT_SUCCESS;
    CpaCyCapabilitiesInfo CapInfo;
    kpt_inst_provision_context_st *ctx = NULL;
    kpt_provision_meta_cxt_st *meta_ctx = NULL;
    kpt_eswk_meta_data_st *eswk = NULL;
    CpaCyKptLoadKey *load_key = NULL;
    CpaCyKptUnwrapContext *unwrap_ctx = NULL;
    int wpk_idx = 0;
    int eswk_idx = 0;
    int pass = 0;

    if (!kpt_inst_idx_check(qat_inst_index)) {
        WARN("Invalid QAT instance index.\n");
        return 0;
    }

    ctx = &kpt_inst_prvs_ctx[qat_inst_index];
    ctx->instance_handle = qat_inst_handle;

    status = cpaCyQueryCapabilities(ctx->instance_handle, &CapInfo);
    if (CPA_STATUS_SUCCESS != status || 
        CPA_FALSE == CapInfo.kptSupported ||
        CPA_TRUE == CapInfo.symSupported) {
        ctx->kpt_enabled = 0;
        WARN("KPT is not supported on current instance\n");
        return 0;
    }

    ctx->kpt_enabled = 1;

    /* Each instance needs to support different wpks */
    for (wpk_idx = 0; wpk_idx < wpk_num; wpk_idx++) {

        meta_ctx = &(ctx->meta_ctx[wpk_idx]);

        /* Continue if no eswk is found */
        eswk_idx = get_encrypted_swk(qat_inst_handle, wpk_idx);
        if (eswk_idx < 0) {
            WARN("Device credential is not found in WPK file\n");
            continue;
        }

        eswk = &(kpt_dev_crdt[wpk_idx].eswk_data[eswk_idx]);
        load_key = &(meta_ctx->wrapping_key);

        load_key->wrappingAlgorithm = CPA_CY_KPT_WRAPPING_KEY_TYPE_AES256_GCM;
        load_key->eSWK.pData =
            (Cpa8U *)qaeMemAllocNUMA(eswk->len_eswk, 0, 64);
        if (NULL == load_key->eSWK.pData)
            return 0;

        if (eswk->len_eswk < 0) return 0;
        load_key->eSWK.dataLenInBytes = eswk->len_eswk;
        memcpy(load_key->eSWK.pData, eswk->eswk, eswk->len_eswk);
    
        unwrap_ctx = &(meta_ctx->unwrap_ctx);

        if (eswk->len_iv < 0) return 0;
        memcpy(unwrap_ctx->iv, eswk->iv, eswk->len_iv);

        if (eswk->len_aad < 0) return 0;
        memcpy(unwrap_ctx->additionalAuthData, eswk->aad, eswk->len_aad);
        unwrap_ctx->aadLenInBytes = eswk->len_aad;

        status = cpaCyKptLoadKey(ctx->instance_handle, load_key,
            &(unwrap_ctx->kptHandle), &kptStatus);

        if (CPA_STATUS_SUCCESS != status || kptStatus != CPA_CY_KPT_SUCCESS) {
            WARN("KPT Load Key Failed, kptStatus=%d\n", kptStatus);
            meta_ctx->swk_provisioned = 0;
            qaeMemFreeNUMA((void **)&load_key->eSWK.pData);
            continue;
        }

        meta_ctx->swk_provisioned = 1;

        DEBUG("Loads SWK for WPK%d: keyhandle 0x%lx\n", 
              wpk_idx, unwrap_ctx->kptHandle);

        pass = 1;

        if (load_key->eSWK.pData)
            qaeMemFreeNUMA((void **)&load_key->eSWK.pData);
    }

    if (pass)
        return 1;
    else
        return 0;
}

void kpt_finish(int qat_inst_index, CpaInstanceHandle qat_inst_handles)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyKptKeyManagementStatus kptStatus = CPA_CY_KPT_SUCCESS;
    kpt_inst_provision_context_st *ctx = NULL;
    kpt_provision_meta_cxt_st *meta_ctx = NULL;
    int wpk_idx = 0;

    if (!kpt_inst_idx_check(qat_inst_index)) {
        WARN("Invalid QAT instance index.\n");
        return;
    }

    ctx = &kpt_inst_prvs_ctx[qat_inst_index];

    if (!ctx->kpt_enabled) {
        DEBUG("Instance %d is not provisioned\n", qat_inst_index);
        return;
    }

    for (wpk_idx = 0; wpk_idx < wpk_num; wpk_idx++) {

        meta_ctx = &(ctx->meta_ctx[wpk_idx]);

        if (!meta_ctx->swk_provisioned) {
            DEBUG("WPK %d is not provisioned\n", wpk_idx);
            continue;
        }

        meta_ctx->swk_provisioned = 0;
        status = cpaCyKptDeleteKey(qat_inst_handles, 
            meta_ctx->unwrap_ctx.kptHandle, &kptStatus);
        if (CPA_STATUS_SUCCESS != status || kptStatus != CPA_CY_KPT_SUCCESS) {
            WARN("Instance %d Deletes SWK Failed\n", qat_inst_index);
            continue;
        }

        DEBUG("Instance %d Deletes SWK Successfully for WPK%d\n", 
                qat_inst_index, wpk_idx);
    }
}


/**
 *****************************************************************************
 * 
 * KPT RSA Decryption and Sign implementation.
 *
 *****************************************************************************/

int kpt_check_rsa_wpk(RSA *rsa) {
    if (rsa)
        return RSA_get_ex_data(rsa, KEY_WRAP_STORAGE_INDEX) ? 1 : 0;
    return -1;
}

static int kpt_rsa_range_check(int plen)
{
    return ((plen >= RSA_KPT_RANGE_MIN) && (plen <= RSA_KPT_RANGE_MAX));
}

static int build_kpt_decrypt_op_buf(int flen, const unsigned char *from,
                             unsigned char *to,
                             RSA *rsa, int padding,
                             CpaCyKptRsaDecryptOpData **dec_op_data,
                             CpaFlatBuffer **output_buffer,
                             int alloc_pad, int *wpk_index)
{
    int rsa_len = 0;
    int padding_result = 0;
    CpaCyKptRsaPrivateKey *cpa_prv_key = NULL;
    CpaFlatBuffer *priv_key = NULL;
    kpt_rsa_wpk *rsa_wpk = NULL;

    DEBUG("- Started\n");

    /* Retrieve data from ex_data field of rsa struct */
    rsa_wpk = (kpt_rsa_wpk *)RSA_get_ex_data(rsa, KEY_WRAP_STORAGE_INDEX);
    if (rsa_wpk == NULL) {
        WARN("Get RSA WPK data failed\n");
        return 0;
    }

    /* Using the PKEY matched WPK which is specified previously */
    *wpk_index = rsa_wpk->wpk_index;
    if (!kpt_wpk_idx_check(*wpk_index)) {
        WARN("Invalid WPK index.\n");
        return 0;
    }

    /* output signature should have same length as the RSA size */
    rsa_len = RSA_size(rsa);
    if (rsa_len < 0) {
        WARN("Failed to get RSA length.\n");
        return 0;
    }

    cpa_prv_key =
       (CpaCyKptRsaPrivateKey *) OPENSSL_zalloc(sizeof(CpaCyKptRsaPrivateKey));
    if (NULL == cpa_prv_key) {
        WARN("Failed to allocate cpa_prv_key\n");
        return 0;
    }

    /* output and input data MUST allocate memory for sign process */
    /* memory allocation for DecOpdata[IN] */
    *dec_op_data = OPENSSL_zalloc(sizeof(CpaCyKptRsaDecryptOpData));
    if (NULL == *dec_op_data) {
        WARN("Failed to allocate dec_op_data\n");
        OPENSSL_free(cpa_prv_key);
        return 0;
    }

    /* Setup the DecOpData structure */
    (*dec_op_data)->pRecipientPrivateKey = cpa_prv_key;

    cpa_prv_key->version = CPA_CY_RSA_VERSION_TWO_PRIME;

    /* Setup the private key type structure, type2 is in priority */
    if (rsa_wpk->wpk_type2_size > 0)
    {
        /* WPK Copy */
        cpa_prv_key->privateKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2;

        /* Memory allocate for flat buffer */
        priv_key = &(cpa_prv_key->privateKeyRep2.privateKey);
        priv_key->dataLenInBytes = (Cpa32U) rsa_wpk->wpk_type2_size;
        
        priv_key->pData = (Cpa8U *) qaeMemAllocNUMA(priv_key->dataLenInBytes,
                                                    0, 64);
        if (NULL == priv_key->pData) {
            priv_key->dataLenInBytes = 0;
            WARN("Failed to allocate priv_key->pData\n");
            return 0;
        }

        memcpy(priv_key->pData, rsa_wpk->wpk_type2, priv_key->dataLenInBytes);
    }
    else if (rsa_wpk->wpk_type1_size > 0)
    {
        cpa_prv_key->privateKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1;
        /* Memory allocate for flat buffer */
        priv_key = &(cpa_prv_key->privateKeyRep1.privateKey);
        priv_key->dataLenInBytes = (Cpa32U) rsa_wpk->wpk_type1_size;
        
        priv_key->pData = (Cpa8U *) qaeMemAllocNUMA(priv_key->dataLenInBytes,
                                                    0, 64);
        if (NULL == priv_key->pData) {
            priv_key->dataLenInBytes = 0;
            WARN("Failed to allocate priv_key->pData\n");
            return 0;
        }
        memcpy(priv_key->pData, rsa_wpk->wpk_type1, priv_key->dataLenInBytes);
    }
    else {
        WARN("Failed to decide key type\n");
        return 0;
    }

    (*dec_op_data)->inputData.dataLenInBytes =
           (padding != RSA_NO_PADDING) && alloc_pad ? rsa_len : flen;

    (*dec_op_data)->inputData.pData = (Cpa8U *) qaeMemAllocNUMA(
        ((padding != RSA_NO_PADDING) && alloc_pad) ? rsa_len : flen, 0, 64);
    if (NULL == (*dec_op_data)->inputData.pData) {
        WARN("Failed to allocate (*dec_op_data)->inputData.pData\n");
        return 0;
    }

    if (alloc_pad) {
        switch (padding) {
        case RSA_PKCS1_PADDING:
            padding_result =
                RSA_padding_add_PKCS1_type_1((*dec_op_data)->inputData.pData,
                                             rsa_len, from, flen);
            break;
        case RSA_X931_PADDING:
            padding_result =
                RSA_padding_add_X931((*dec_op_data)->inputData.pData,
                                     rsa_len, from, flen);
            break;
        case RSA_NO_PADDING:
            padding_result =
                RSA_padding_add_none((*dec_op_data)->inputData.pData,
                                     rsa_len, from, flen);
            break;
        default:
            break;
        }
    } else {
        padding_result =
            RSA_padding_add_none((*dec_op_data)->inputData.pData,
                                 rsa_len, from, flen);
    }

    if (padding_result <= 0) {
        WARN("Failed to add padding\n");
        /* Error is raised within the padding function. */
        return 0;
    }

    *output_buffer = OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (NULL == *output_buffer) {
        WARN("Failed to allocate output_buffer\n");
        return 0;
    }

    /*
     * Memory allocation for DecOpdata[IN] the size of outputBuffer
     * should big enough to contain RSA_size
     */
    (*output_buffer)->pData =
        (Cpa8U *) qaeMemAllocNUMA(rsa_len, 0, 64);

    if (NULL == (*output_buffer)->pData) {
        WARN("Failed to allocate output_buffer->pData\n");
        return 0;
    }
    (*output_buffer)->dataLenInBytes = rsa_len;

    DEBUG("- Finished\n");
    return 1;
}

void rsa_kpt_decrypt_op_buf_free(CpaCyKptRsaDecryptOpData *dec_op_data,
                                    CpaFlatBuffer *out_buf, int *wpk_index) {
    DEBUG("- Started\n");

    if (wpk_index) {
        *wpk_index = INVALID_WPK_IDX;
    }

    if (dec_op_data) {
        if (dec_op_data->inputData.pData)
            qaeMemFreeNUMA((void **)&dec_op_data->inputData.pData);

        if (dec_op_data->pRecipientPrivateKey) {
            if (CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2 == 
                dec_op_data->pRecipientPrivateKey->privateKeyRepType) {
                CpaCyKptRsaPrivateKeyRep2 *key = 
                    &dec_op_data->pRecipientPrivateKey->privateKeyRep2;
                OPENSSL_cleanse(key->privateKey.pData, key->privateKey.dataLenInBytes);
                if (key->privateKey.pData)
                    qaeMemFreeNUMA((void **)&key->privateKey.pData);
            }
            else if (CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1 ==
                dec_op_data->pRecipientPrivateKey->privateKeyRepType) {
                CpaCyKptRsaPrivateKeyRep1 *key = 
                    &dec_op_data->pRecipientPrivateKey->privateKeyRep1;
                OPENSSL_cleanse(key->privateKey.pData, key->privateKey.dataLenInBytes);
                if (key->privateKey.pData)
                    qaeMemFreeNUMA((void **)&key->privateKey.pData);
            }
            else {
                WARN("Wrong RSA key type found during cleanup.\n");
            }

            OPENSSL_free(dec_op_data->pRecipientPrivateKey);
        }
        OPENSSL_free(dec_op_data);
    }

    if (out_buf) {
        if (out_buf->pData)
            qaeMemFreeNUMA((void **)&out_buf->pData);
        OPENSSL_free(out_buf);
    }
}

int kpt_rsa_prepare(int flen, const unsigned char *from,
                     unsigned char *to, RSA *rsa, int padding,
                     CpaFlatBuffer **output_buffer, 
                     CpaCyKptRsaDecryptOpData **kpt_dec_op_data,
                     int alloc_pad, int *wpk_index)
{
    DEBUG("- Started\n");

    /* parameter checks */
    if (rsa == NULL || from == NULL || to == NULL || flen <= 0) {
        WARN("RSA key, input or output is NULL or invalid length, \
              flen = %d\n", flen);
        return 0;
    }

    if (output_buffer == NULL || kpt_dec_op_data == NULL || 
        wpk_index == NULL) {
        WARN("KPT input parameters are invalid.\n");
        return 0;
    }

    if (!kpt_rsa_range_check(RSA_bits((const RSA*)rsa)))
        return 0;

    /* Padding check
     * Note: RSA SSLv23 padding mode is remove in OpenSSL 3.0
     * https://github.com/openssl/openssl/issues/14283
     */

    if ((padding != RSA_NO_PADDING) &&
        (padding != RSA_PKCS1_PADDING) &&
        (padding != RSA_PKCS1_OAEP_PADDING) &&
#ifndef QAT_OPENSSL_3
        (padding != RSA_SSLV23_PADDING) &&
#endif
        (padding != RSA_X931_PADDING)) {
        WARN("Unknown Padding %d\n", padding);
        return 0;
    }

    if (!build_kpt_decrypt_op_buf(flen, from, to, rsa, padding,
                    kpt_dec_op_data, output_buffer, alloc_pad, wpk_index)) {
        WARN("Failure in build_kpt_decrypt_op_buf\n");
        rsa_kpt_decrypt_op_buf_free(*kpt_dec_op_data, *output_buffer, wpk_index);
        return 0;
    }

    DEBUG("- Finished\n");

    return 1;
}

/* Used for RSA Decrypt and RSA Sign */
int kpt_rsa_decrypt(int qat_inst_index,
                    const kpt_rsa_cb_func cb, void *cb_data, 
                    CpaCyKptRsaDecryptOpData *dec_op_data, 
                    CpaFlatBuffer *output_buf, int wpk_index)
{
    CpaStatus sts = CPA_STATUS_FAIL;
    CpaInstanceHandle qat_inst_handle;
    CpaCyKptUnwrapContext *kpt_unwrap_ctx = NULL;

    if (!kpt_inst_idx_check(qat_inst_index)) {
        WARN("Invalid QAT instance index.\n");
        return sts;
    }

    if (dec_op_data == NULL || output_buf == NULL) {
        WARN("KPT input parameters are invalid.\n");
        return sts;
    }

    if (!kpt_wpk_idx_check(wpk_index)) {
        WARN("Invalid WPK index.\n");
        return sts;
    }

    kpt_unwrap_ctx = 
        &(kpt_inst_prvs_ctx[qat_inst_index].meta_ctx[wpk_index].unwrap_ctx);
    qat_inst_handle = kpt_inst_prvs_ctx[qat_inst_index].instance_handle;

    DEBUG("Started - RSA Decryption\n");
    DUMP_KPT_RSA_DECRYPT(qat_inst_handle, kpt_unwrap_ctx->kptHandle, NULL, 
                         dec_op_data, output_buf);

    sts = cpaCyKptRsaDecrypt(qat_inst_handle, cb, cb_data, dec_op_data, 
                                output_buf, kpt_unwrap_ctx);

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", sts);
        return sts;
    }

    DEBUG("kpt_rsa_decrypt - status = %d\n", sts);
    return sts;
}

void kpt_rsa_finish(CpaCyKptRsaDecryptOpData *dec_op_data,
                                    CpaFlatBuffer *out_buf, int *wpk_index) {
    rsa_kpt_decrypt_op_buf_free(dec_op_data, out_buf, wpk_index);
}


/**
 *****************************************************************************
 * 
 * KPT ECDSA Sign implementation.
 *
 *****************************************************************************/

int kpt_check_ec_wpk(EC_KEY *eckey) {
    if (eckey)
        return EC_KEY_get_ex_data(eckey, KEY_WRAP_STORAGE_INDEX) ? 1 : 0;
    return -1;
}

static int kpt_BN_to_FB(CpaFlatBuffer * fb, const BIGNUM *bn)
{
    if ((fb == NULL || bn == NULL )) {
        WARN("Invalid input params.\n");
        return 0;
    }
    /* Memory allocate for flat buffer */
    fb->dataLenInBytes = (Cpa32U) BN_num_bytes(bn);
    if (0 == fb->dataLenInBytes) {
        fb->pData = NULL;
        DEBUG("Datalen = 0, zero byte memory allocation\n");
        return 0;
    }
    fb->pData = qaeMemAllocNUMA(fb->dataLenInBytes, 0, 64);
    if (NULL == fb->pData) {
        fb->dataLenInBytes = 0;
        WARN("Failed to allocate fb->pData\n");
        return 0;
    }
    /*
     * BN_bn2in() converts the absolute value of big number into big-endian
     * form and stores it at output buffer. the output buffer must point to
     * BN_num_bytes of memory
     */
    BN_bn2bin(bn, fb->pData);
    return 1;
}

int kpt_ecdsa_prepare(const unsigned char *dgst, int dgst_len,
                      const BIGNUM *in_kinv, const BIGNUM *in_r,
                      EC_KEY *eckey, BN_CTX **ctx, ECDSA_SIG **ret, 
                      CpaFlatBuffer **pResultR, CpaFlatBuffer **pResultS, 
                      BIGNUM **ecdsa_sig_r, BIGNUM **ecdsa_sig_s,
                      CpaCyKptEcdsaSignRSOpData **opData, int *wpk_index)
{
    int i = 0;
    BIGNUM *m = NULL, *order = NULL;
    const EC_GROUP *group;
    BIGNUM *priv_key = NULL;
    kpt_ecc_wpk *ecc_wpk = NULL;
    size_t buflen;

    DEBUG("- Started.\n");

    /* parameter checks */
    if (dgst == NULL || dgst_len <= 0 || eckey == NULL) {
        WARN("EC key or digest to be signed are invaliad.\n");
        return 0;
    }

    if (ctx == NULL || ret == NULL || pResultR == NULL || pResultS == NULL ||
        ecdsa_sig_r == NULL || ecdsa_sig_s == NULL || opData == NULL ||
        wpk_index == NULL) {
        WARN("Invalid KPT input param.\n");
        return 0;
    }

    ecc_wpk = (kpt_ecc_wpk *)EC_KEY_get_ex_data(eckey, KEY_WRAP_STORAGE_INDEX);
    if (ecc_wpk == NULL) {
        WARN("Get EC WPK data failed\n");
        return 0;
    }

    /* Using the PKEY matched WPK which is specified previously */
    *wpk_index = ecc_wpk->wpk_index;
    if (!kpt_wpk_idx_check(*wpk_index)) {
        WARN("Invalid WPK index.\n");
        return 0;
    }

    group = EC_KEY_get0_group(eckey);
    if (group == NULL) {
        WARN("Group is NULL\n");
        return 0;
    }

    *opData = (CpaCyKptEcdsaSignRSOpData *)
        OPENSSL_zalloc(sizeof(CpaCyKptEcdsaSignRSOpData));
    if (*opData == NULL) {
        WARN("Failure to allocate opData\n");
        return 0;
    }

    if ((*ret = ECDSA_SIG_new()) == NULL) {
        WARN("Failure to allocate ECDSA_SIG\n");
        goto err;
    }

    *ecdsa_sig_r = BN_new();
    *ecdsa_sig_s = BN_new();
    /* NULL checking of ecdsa_sig_r & ecdsa_sig_s done in ECDSA_SIG_set0() */
    if (ECDSA_SIG_set0(*ret, *ecdsa_sig_r, *ecdsa_sig_s) == 0) {
        WARN("Failure to allocate r and s values to assign to the ECDSA_SIG\n");
        goto err;
    }

    if ((*ctx = BN_CTX_new()) == NULL) {
        WARN("Failure to allocate ctx\n");
        goto err;
    }

    BN_CTX_start(*ctx);
    m = BN_CTX_get(*ctx);
    order = BN_CTX_get(*ctx);
    if (order == NULL || m == NULL) {
        WARN("Failure to allocate m or order\n");
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, *ctx)) {
        WARN("Failure to get order from group\n");
        goto err;
    }
    i = BN_num_bits(order);

    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;

    if (!BN_bin2bn(dgst, dgst_len, m)) {
        WARN("Failure to convert dgst to m\n");
        goto err;
    }

    /* If still too long truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7))) {
        WARN("Failure to truncate m\n");
        goto err;
    }

    priv_key = BN_new();
    if (!BN_bin2bn(ecc_wpk->wpk, ecc_wpk->wpk_size, priv_key)) {
        WARN("Failure to convert wpk to priv_key\n");
        goto err;
    }
    if (kpt_BN_to_FB(&((*opData)->privateKey), (BIGNUM *)priv_key) != 1 ||
        kpt_BN_to_FB(&((*opData)->m), m) != 1) {
        WARN("Failed to convert d, m to a flatbuffer\n");
        goto err;
    }

    buflen = EC_GROUP_get_degree(group);
    *pResultR = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (*pResultR == NULL) {
        WARN("Failure to allocate pResultR\n");
        goto err;
    }
    (*pResultR)->pData = qaeMemAllocNUMA(buflen, 0, 64);
    if ((*pResultR)->pData == NULL) {
        WARN("Failure to allocate pResultR->pData\n");
        goto err;
    }
    (*pResultR)->dataLenInBytes = (Cpa32U) buflen;
    *pResultS = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (*pResultS == NULL) {
        WARN("Failure to allocate pResultS\n");
        goto err;
    }
    (*pResultS)->pData = qaeMemAllocNUMA(buflen, 0, 64);
    if ((*pResultS)->pData == NULL) {
        WARN("Failure to allocate pResultS->pData\n");
        goto err;
    }
    (*pResultS)->dataLenInBytes = (Cpa32U) buflen;

    DEBUG("- Finished\n");
    return 1;
err:
    kpt_ecdsa_finish(*pResultR, *pResultS, *opData, *ctx, wpk_index);
    return 0;
}

int kpt_ecdsa_do_sign(int qat_inst_index,
                      const kpt_ecdsa_cb_func cb, void *cb_data, 
                      CpaCyKptEcdsaSignRSOpData *opData,
                      CpaBoolean *bEcdsaSignStatus,
                      CpaFlatBuffer *pResultR,
                      CpaFlatBuffer *pResultS,
                      int wpk_index)
{
    CpaStatus sts = CPA_STATUS_FAIL;
    CpaInstanceHandle qat_inst_handle;
    CpaCyKptUnwrapContext *kpt_unwrap_ctx = NULL;

    if (!kpt_inst_idx_check(qat_inst_index)) {
        WARN("Invalid QAT instance index.\n");
        return sts;
    }

    if (opData == NULL || bEcdsaSignStatus == NULL ||
        pResultR == NULL || pResultS == NULL) {
        WARN("KPT input parameters are invalid.\n");
        return sts;
    }

    if (!kpt_wpk_idx_check(wpk_index)) {
        WARN("Invalid WPK index.\n");
        return sts;
    }

    kpt_unwrap_ctx = 
        &(kpt_inst_prvs_ctx[qat_inst_index].meta_ctx[wpk_index].unwrap_ctx);
    qat_inst_handle = kpt_inst_prvs_ctx[qat_inst_index].instance_handle;

    DEBUG("Started - ECDSA\n");
    DUMP_KPT_ECDSA_SIGN(qat_inst_handle, 
                kpt_unwrap_ctx->kptHandle, opData, pResultR, pResultS);
    sts = cpaCyKptEcdsaSignRS(qat_inst_handle,
                        cb, cb_data, 
                        opData,
                        bEcdsaSignStatus, pResultR, pResultS, 
                        kpt_unwrap_ctx);

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", sts);
    }

    return sts;
}

void kpt_ecdsa_finish(CpaFlatBuffer *pResultR, CpaFlatBuffer *pResultS, 
                      CpaCyKptEcdsaSignRSOpData *opData, BN_CTX *ctx,
                      int *wpk_index)
{
    if (wpk_index) {
        *wpk_index = INVALID_WPK_IDX;
    }

    if (pResultR) {
        if (pResultR->pData)
            qaeMemFreeNUMA((void **)&(pResultR->pData));
        OPENSSL_free(pResultR);
    }

    if (pResultS) {
        if (pResultS->pData)
            qaeMemFreeNUMA((void **)&(pResultS->pData));
        OPENSSL_free(pResultS);
    }

    if (opData) {
        if (opData->m.pData)
            qaeMemFreeNUMA((void **)&(opData->m.pData));
        if (opData->privateKey.pData)
            qaeMemFreeNUMA((void **)&(opData->privateKey.pData));
        OPENSSL_free(opData);
    }

    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
}
