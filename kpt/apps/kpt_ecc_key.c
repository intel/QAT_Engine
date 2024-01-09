/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023-2024 Intel Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * ====================================================================
 */

/************************KPT ECC PRIVATE KEY ASN.1 Coding Format***************
 *
 * Intel_KPT_ECC_KEY  DEFINITIONS AUTOMATIC TAGS ::= BEGIN
 * KPTECCKEY ::= SEQUENCE {
 *    version       INTEGER { kptECCKeyVersion(1) } (kptECCKeyVersion),
 *    privateKey    OCTET STRING, --(xg||yg||n||q||a||b||d)'||Auth
 *    curveName     [0] OBJECT IDENTIFIER OPTIONAL,
 *    publicKey     [1] BIT STRING OPTIONAL,
 *    wrappingMetadata metadata
 *  }
 *
 * metadata ::= SEQUENCE {
 *   aesNonce      OCTET STRING (SIZE(12)),
 *   wrappingAlg   OBJECT IDENTIFIER ( id-aes256-GCM ),
 *   encryptedSWK  eSWKs
 *  }
 *
 * eSWKs ::= SEQUENCE OF eSWK
 *
 * eSWK ::= SEQUENCE {
 *   devSig    OCTET STRING,
 *   secSWK    OCTET STRING
 * }
 *
 * id-aes256-GCM OBJECT IDENTIFIER ::= { aes 46 }
 *
 * id-aes-gcm OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840)
 *                                    organization(1) gov(101) csor(3)
 *                                    nistAlgorithm(4) 1 }
 * END
 * **************************************************************************/

#include <openssl/pem.h>
#include <openssl/rand.h>
#include <string.h>

#include "kpt_key.h"
#include "kpt_swk.h"
#include "kpt_dev_pp.h"

#define KPT_ECC_KEY_VERSION (0x1)

#define EC_SIZE_BYTES_P256 (32)
#define EC_SIZE_BYTES_P384 (48)
#define EC_SIZE_BYTES_P521 (72)

#define EC_SIZE_BYTES_QW4 (32)
#define EC_SIZE_BYTES_QW8 (64)
#define EC_SIZE_BYTES_QW9 (72)

#define KPT_ECDSA_P256_AAD_LEN (10)
#define KPT_ECDSA_P384_AAD_LEN (7)
#define KPT_ECDSA_P521_AAD_LEN (7)

typedef struct kpt_ecc_key_st {
        long version;
        ASN1_OCTET_STRING *privateKey;
        ASN1_OBJECT *curveName;
        ASN1_BIT_STRING *publicKey;
        WRAPPINGMETADATA *wrappingMetadata;
} KPTECCKEY;
DECLARE_ASN1_FUNCTIONS(KPTECCKEY)

ASN1_SEQUENCE(KPTECCKEY) = {
        ASN1_SIMPLE(KPTECCKEY, version, LONG),
        ASN1_SIMPLE(KPTECCKEY, privateKey, ASN1_OCTET_STRING),
        ASN1_EXP_OPT(KPTECCKEY, curveName, ASN1_OBJECT, 0),
        ASN1_EXP_OPT(KPTECCKEY, publicKey, ASN1_BIT_STRING, 1),
        ASN1_SIMPLE(KPTECCKEY, wrappingMetadata, WRAPPINGMETADATA)
}ASN1_SEQUENCE_END(KPTECCKEY)
IMPLEMENT_ASN1_FUNCTIONS(KPTECCKEY)

/**
 *****************************************************************************
 *  Curve      OID                  DER(OID)
 *  secp256r1  1.2.840.10045.3.1.7  06 08 2A 86 48 CE 3D 03 01 07
 *  secp384r1  1.3.132.0.34         06 05 2B 81 04 00 22
 *  secp521r1  1.3.132.0.35         06 05 2B 81 04 00 23
 *****************************************************************************/
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

/* EC Key in ECDSA needs to be 8-bytes aligned */
static int ecc_get_key_size(int len_d)
{
    if (len_d <= EC_SIZE_BYTES_P256)
       len_d = EC_SIZE_BYTES_P256;
    else if (len_d <= EC_SIZE_BYTES_P384)
       len_d = EC_SIZE_BYTES_P384;
    else if (len_d <= EC_SIZE_BYTES_P521)
       len_d = EC_SIZE_BYTES_P521;
    else
       len_d = -1;

    return len_d;
}

static void hex_log(unsigned char *pData, unsigned int numBytes,
                    const char* caption)
{
    int i = 0;

    if (NULL == pData) {
        return;
    }
    if (caption != NULL) {
        log_print("\n=== %s ===\n", caption);
    }

    for (i = 0; i < numBytes; i++) {
        log_print("%02X ", pData[i]);
        if (!((i + 1) % 16))
            log_print("\n");
    }
    log_print("\n");
}

static int eckey_get_private_key(EC_KEY *eckey, unsigned char *buf_k, int *len_key)
{
    const BIGNUM *bn_d = NULL;
    unsigned char *buf_d = NULL;
    int len_d = 0, ret = -1;
    int key_size = 0;

    if (NULL == eckey || NULL == buf_k) {
        goto err;
    }

    if ((bn_d = EC_KEY_get0_private_key(eckey)) == NULL) {
        goto err;
    }

    len_d = (unsigned int) BN_num_bytes(bn_d);
    if ((buf_d = malloc(len_d)) == NULL) {
        goto err;
    }

    if (BN_bn2bin(bn_d, buf_d) == -1) {
        goto err;
    }

    /* Key size needs to be 8-bytes aligned */
    key_size = ecc_get_key_size(len_d);
    *len_key = key_size;

    /* KPT WPK only needs private d field */
    memcpy(buf_k + key_size - len_d, buf_d, len_d);
    ret = 0;
err:
    if (buf_d) {
        free(buf_d);
    }
    return ret;
}

static unsigned char * ecc_get_aad(int nid, int *aad_len){
    unsigned char *aad = NULL;

    switch (nid){
        case NID_SECP256R1:
        {
            aad = secp256_oid;
            *aad_len = KPT_ECDSA_P256_AAD_LEN;
            break;
        }
        case NID_SECP384R1:
        {
            aad = secp384_oid;
            *aad_len = KPT_ECDSA_P384_AAD_LEN;
            break;
        }
        case NID_SECP521R1:
        {
            aad = secp521_oid;
            *aad_len = KPT_ECDSA_P521_AAD_LEN;
            break;
        }
        default:
        {
            log_print("Unknown ECC curve\n");
        }
        break;
    }

    return aad;
}

int kpt_ecc_wpk_gen(unsigned char *cpk_file, unsigned char *wpk_file)
{
    EC_KEY *eckey = NULL;
    const EC_GROUP *group;
    const BIGNUM *cofactor = NULL;
    BIO *in = NULL, *out = NULL;
    KPTECCKEY *key = NULL;
    EC_POINT *pub_key = NULL;
    ASN1_OBJECT *enc_algo_id = NULL;
    ESWK *eSWK = NULL;
    int pub_len = 0;
    unsigned char *pub = NULL;
    WRAPPINGMETADATA *metadata = NULL;
    unsigned char ck[MAX_ECC_KEY_SIZE];
    unsigned char pk[MAX_ECC_KEY_SIZE];
    unsigned char swk[AES_GCM_256_KEY_SIZE];
    unsigned char *iv = NULL, *epk = NULL, *dev_sig = NULL, *eswk = NULL;
    unsigned char *aad;
    int aad_len = 0;
    memset(ck, 0, MAX_ECC_KEY_SIZE);
    memset(pk, 0, MAX_ECC_KEY_SIZE);
    int ck_len = 0, pk_len = 0;
    int nid = 0;
    int ret = 0, i = 0;

    iv = OPENSSL_malloc(AES_GCM_IV_SIZE);
    if (!iv) {
          goto err;
    }

    in = BIO_new(BIO_s_file());
    if (BIO_read_filename(in, cpk_file) <= 0) {
        goto err;
    }

    eckey = PEM_read_bio_ECPrivateKey(in, NULL, NULL, NULL);
    BIO_free(in);

    if (NULL == eckey) {
        goto err;
    }

    group = EC_KEY_get0_group(eckey);
    if (NULL == group) {
        goto err;
    }

    /* Get Private Key */
    eckey_get_private_key(eckey, ck, &ck_len);
    hex_log(ck, ck_len, "ck");

    /* Get SWK and IV */
    RAND_bytes(iv, AES_GCM_IV_SIZE);
    RAND_bytes(swk, sizeof(swk));
    hex_log(swk, sizeof(swk), "swk");
    hex_log(iv, AES_GCM_IV_SIZE, "iv");

    /* Get AAD */
    nid = EC_GROUP_get_curve_name(group);
    if (!(aad = ecc_get_aad(nid, &aad_len))) {
        goto err;
    }
    hex_log(aad, aad_len, "aad");

    /* Wrap Private Key with SWK */
    ret = wrap_key_with_gcm256(ck, ck_len, pk, &pk_len, swk, iv,
                               AES_GCM_IV_SIZE, aad, aad_len);
    if (ret) {
        goto err;
    }
    hex_log(pk, pk_len,"wrapped ecc key");
    log_print("wpk length %d\n\n", pk_len);

    key = KPTECCKEY_new();
    if (!key) {
        goto err;
    }

    metadata = key->wrappingMetadata;
    if (NULL == metadata) {
        goto err;
    }

    enc_algo_id = OBJ_txt2obj("aes-256-gcm", 0);
    metadata->wrappingAlg = enc_algo_id;
    ASN1_STRING_set0(metadata->aesNonce, iv, AES_GCM_IV_SIZE);

    /* Generate eSWK sequence */
    /* get instance->query per-part key */
    ret = kpt_get_per_part_key();
    if (ret) {
        goto err;
    }
    for (i = 0; i < cpu_socket_num; i++){
        eSWK = ESWK_new();

        eswk = OPENSSL_zalloc(KPT_PER_PART_KEY_N_LEN);
        if (!eswk) {
            goto err;
        }

        dev_sig = OPENSSL_zalloc(KPT_PER_PART_SIG_LEN);
        if (!dev_sig) {
            goto err;
        }

        hex_log(kpt_per_part_context_ptr[i].pub_n,
                        KPT_PER_PART_KEY_N_LEN,
                        "Per Part key N:");
        hex_log(kpt_per_part_context_ptr[i].pub_e,
                        KPT_PER_PART_KEY_E_LEN,
                        "Per Part key E");
        hex_log(kpt_per_part_context_ptr[i].sig,
                        KPT_PER_PART_SIG_LEN,
                        "signature");

        ret = encrypt_swk_with_per_part_key(swk, eswk, \
                   kpt_per_part_context_ptr[i].pub_n, \
                   kpt_per_part_context_ptr[i].len_pub_n, \
                   kpt_per_part_context_ptr[i].pub_e, \
                   kpt_per_part_context_ptr[i].len_pub_e);
        if (!ret) {
            goto err;
        }
        hex_log(eswk, KPT_PER_PART_KEY_N_LEN, "Encrypted SWK of KPT2");

        memcpy(dev_sig, kpt_per_part_context_ptr[i].sig, \
                        kpt_per_part_context_ptr[i].len_sig);

        ASN1_STRING_set0(eSWK->secSWK, eswk, KPT_PER_PART_KEY_N_LEN);
        ASN1_STRING_set0(eSWK->devSig, dev_sig, KPT_PER_PART_SIG_LEN);
        sk_ESWK_push(metadata->eSWKs, eSWK);
        log_print("The eswk counter is %d \n", sk_ESWK_num(metadata->eSWKs));
    }

    key->version = (long)KPT_ECC_KEY_VERSION;

    epk = OPENSSL_malloc(pk_len);
    if (!epk) {
       goto err;
    }
    memcpy(epk, pk, pk_len);
    ASN1_STRING_set0(key->privateKey, epk, pk_len);

    key->curveName = OBJ_nid2obj(EC_GROUP_get_curve_name(group));

    pub_key = (EC_POINT *)EC_KEY_get0_public_key(eckey);
    if (pub_key) {
        key->publicKey = ASN1_BIT_STRING_new();
        if (!key->publicKey) {
            goto err;
        }

        key->publicKey->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
        key->publicKey->flags |= ASN1_STRING_FLAG_BITS_LEFT;

        pub_len = EC_KEY_key2buf(eckey, EC_KEY_get_conv_form(eckey), &pub, NULL);
        ASN1_STRING_set0(key->publicKey, pub, pub_len);
    }

    out = BIO_new(BIO_s_file());
    if (NULL == out) {
        goto err;
    }

    BIO_write_filename(out, wpk_file);
    PEM_ASN1_write_bio((i2d_of_void *)i2d_KPTECCKEY,
                      "KPT ECC KEY", out, key, NULL, NULL, 0, NULL, NULL);
    BIO_flush(out);
    BIO_free(out);
err:
    if (eckey)
        EC_KEY_free(eckey);
    if (key)
        KPTECCKEY_free(key);
    if (iv)
        OPENSSL_free(iv);

    return ret;
}

int kpt_ecc_wpk_parse(kpt_ecc_wpk *ecc_wpk, unsigned char *wpk_file)
{
    KPTECCKEY *kpteckey = NULL;
    BIO *in = NULL;
    char *name = NULL, *header = NULL;
    unsigned char *data = 0;
    const unsigned char *p = NULL;
    long version  = 0;
    long len;
    int ret = 0, i = 0;
    unsigned char eswk[KPT_PER_PART_KEY_N_LEN] ;
    WRAPPINGMETADATA *metadata = NULL;

    in = BIO_new(BIO_s_file());
    if (BIO_read_filename(in, wpk_file) <= 0) {
        goto err;
    }

    ret = PEM_read_bio(in, &name, &header, &data, &len);
    p = data;
    d2i_KPTECCKEY(&kpteckey, &p, len);
    if (!kpteckey) {
        goto err;
    }

    ecc_wpk->version  = kpteckey->version;

    ecc_wpk->wpk_size = ASN1_STRING_length(kpteckey->privateKey);
    memcpy(ecc_wpk->wpk, ASN1_STRING_get0_data(kpteckey->privateKey), ecc_wpk->wpk_size);

    metadata = kpteckey->wrappingMetadata;
    ecc_wpk->wrapping_alg_nid = OBJ_obj2nid(metadata->wrappingAlg);

    for (i = 0; i < sk_ESWK_num(metadata->eSWKs); i++ ) {
        ESWK *eSWK = sk_ESWK_value(metadata->eSWKs, i);

        (ecc_wpk->swkSec_size)[i] = ASN1_STRING_length(eSWK->secSWK);
        memcpy((ecc_wpk->swkSec)[i], ASN1_STRING_get0_data(eSWK->secSWK),
               (ecc_wpk->swkSec_size)[i]);

        (ecc_wpk->swkPub_size)[i] = ASN1_STRING_length(eSWK->devSig);
        memcpy((ecc_wpk->swkPub)[i], ASN1_STRING_get0_data(eSWK->devSig),
               (ecc_wpk->swkPub_size)[i]);
    }

    ecc_wpk->curve_nid = OBJ_obj2nid(kpteckey->curveName);
    ecc_wpk->pub_key_size = ASN1_STRING_length(kpteckey->publicKey);
    memcpy(ecc_wpk->pub_key, ASN1_STRING_get0_data(kpteckey->publicKey), ecc_wpk->pub_key_size);

    log_print("\n=========================\n");
    log_print("WPK version: %ld\n", ecc_wpk->version);
    hex_log(ecc_wpk->wpk, ecc_wpk->wpk_size, "EC WPK");
    log_print("EC Curve NID: %d\n", ecc_wpk->curve_nid);
    hex_log(ecc_wpk->pub_key, ecc_wpk->pub_key_size, "EC Public Key");
    hex_log((unsigned char *)ASN1_STRING_get0_data(metadata->aesNonce),
            ASN1_STRING_length(metadata->aesNonce), "IV");
    log_print("\nWrapping Algorithm NID: %d\n", ecc_wpk->wrapping_alg_nid);
    for (i = 0; i < sk_ESWK_num(metadata->eSWKs); i++ ) {
        log_print("\nESWK %d\n", i);
        hex_log((ecc_wpk->swkSec)[i], (ecc_wpk->swkSec_size)[i], "Sec SWK");
        hex_log((ecc_wpk->swkPub)[i], (ecc_wpk->swkPub_size)[i], "Dev sig");
    }
    log_print("=========================\n\n");

err:
    if (kpteckey) {
        KPTECCKEY_free(kpteckey);
    }
    return ret;
}
