/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023-2025 Intel Corporation.
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

/************************KPT RSA PRIVATE KEY ASN.1 Coding Format***************
 *
 * Intel_KPT_RSA_Key  DEFINITIONS AUTOMATIC TAGS ::= BEGIN
 * KPTRSAKEY ::= SEQUENCE {
 *    version            INTEGER { kptRSAKeyVersion(1) } (kptRSAKeyVersion),
 *    privateKeyType1    OCTET STRING, --(d||n)'||auth
 *    privateKeyType2    OCTET STRING, --(p||q||dp||dq||qinv||e)'||auth
 *    size               INTEGER,
 *    kptRSADsi          ASN1_OBJECT,
 *    publicKey          rsa_public_key,
 *    wrappingMetadata   metadata
 *  }
 *
 * rsa_public_key ::= SEQUENCE {
 *   n  INTEGER,
 *   e  INTEGER
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

#include <string.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "kpt_key.h"
#include "kpt_swk.h"
#include "kpt_dev_pp.h"

typedef struct rsa_public_key {
        ASN1_INTEGER *n;
        ASN1_INTEGER *e;
} RSAPUBLICKEY;
DECLARE_ASN1_FUNCTIONS(RSAPUBLICKEY)

typedef struct kpt_rsa_key {
        long version;
        ASN1_OCTET_STRING *privateKeyType1;
        ASN1_OCTET_STRING *privateKeyType2;
        long size;
        ASN1_OBJECT *kptRSADsi;
        RSAPUBLICKEY *publicKey;
        WRAPPINGMETADATA *wrappingMetadata;
} KPTRSAKEY;
DECLARE_ASN1_FUNCTIONS(KPTRSAKEY)

ASN1_SEQUENCE(RSAPUBLICKEY) = {
        ASN1_SIMPLE(RSAPUBLICKEY, n, ASN1_INTEGER),
        ASN1_SIMPLE(RSAPUBLICKEY, e, ASN1_INTEGER)
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

/**
 *****************************************************************************
 *  Object         OID                 DER(OID)
 *  OBJ_pkcs1      1.2.840.113549.1.1  06 08 2A 86 48 86 F7 0D 01 01
 *****************************************************************************/
static unsigned char rsa_oid[] = {
        0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01
};

#define RSA_512_KEY_SIZE_IN_BYTE  (64)
#define RSA_1024_KEY_SIZE_IN_BYTE (128)
#define RSA_2048_KEY_SIZE_IN_BYTE (256)
#define RSA_3072_KEY_SIZE_IN_BYTE (384)
#define RSA_4096_KEY_SIZE_IN_BYTE (512)
#define RSA_8192_KEY_SIZE_IN_BYTE (1024)
#define KPT_RSA_TYPE1_KEY_SIZE(x) (x * 2)
#define KPT_RSA_TYPE2_KEY_SIZE(x) (x * 7)
#define KPT_RSA_KEY_VERSION (0x1)

#define MAX(x, y) (x > y) ? x : y

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
        log_print("%02x ", pData[i]);
        if (!((i + 1) % 16))
            log_print("\n");
    }
    log_print("\n");
}

static int rsa_get_key_size(int len_n)
{
    if (len_n <= RSA_512_KEY_SIZE_IN_BYTE)
        return RSA_512_KEY_SIZE_IN_BYTE;

    if (len_n <= RSA_1024_KEY_SIZE_IN_BYTE)
        return RSA_1024_KEY_SIZE_IN_BYTE;

    if (len_n <= RSA_2048_KEY_SIZE_IN_BYTE)
        return RSA_2048_KEY_SIZE_IN_BYTE;

    if (len_n <= RSA_3072_KEY_SIZE_IN_BYTE)
        return RSA_3072_KEY_SIZE_IN_BYTE;

    if (len_n <= RSA_4096_KEY_SIZE_IN_BYTE)
        return RSA_4096_KEY_SIZE_IN_BYTE;

    if (len_n <= RSA_8192_KEY_SIZE_IN_BYTE)
        return RSA_8192_KEY_SIZE_IN_BYTE;
}

static int generate_type1_wpk(const BIGNUM *n, const BIGNUM *d,
                              int key_size, unsigned char *key_type1,
                              unsigned char *swk, unsigned char *iv)
{
    unsigned char *buf = NULL, *src_buf = NULL, *tmp_buf = NULL;
    unsigned int len_n, len_d;
    int ret = -1, size_tmp = 0;

    if (n == NULL || d == NULL || key_type1 == NULL || swk == NULL ||
        iv  == NULL) {
        goto err;
    }
    if ((buf = malloc(key_size)) == NULL) {
        goto err;
    }

    if ((src_buf = malloc(KPT_RSA_TYPE1_KEY_SIZE(key_size))) == NULL) {
       goto err;
    }
    memset(src_buf, 0, KPT_RSA_TYPE1_KEY_SIZE(key_size));

    len_n = BN_num_bytes(n);
    len_d = BN_num_bytes(d);
    tmp_buf = src_buf;

    memset(src_buf, 0, KPT_RSA_TYPE1_KEY_SIZE(key_size));

    tmp_buf += key_size;
    memset(buf, 0, key_size);
    BN_bn2bin(d, buf);
    memcpy(tmp_buf - len_d, buf, len_d);

    tmp_buf += key_size;
    memset(buf, 0, key_size);
    BN_bn2bin(n, buf);
    memcpy(tmp_buf - len_n, buf, len_n);
    ret = wrap_key_with_gcm256(src_buf, KPT_RSA_TYPE1_KEY_SIZE(key_size),
                               key_type1, &size_tmp, swk, iv, AES_GCM_IV_SIZE,
                               rsa_oid, sizeof(rsa_oid));

err:
    if (buf) {
        free(buf);
    }
    if (src_buf) {
        free(src_buf);
    }
    return ret;
}

static int generate_type2_wpk(const BIGNUM *p, const BIGNUM *q,
                              const BIGNUM *dp, const BIGNUM *dq,
                              const BIGNUM *qinv, const BIGNUM *e,
                              int key_size, unsigned char *key_type2,
                              unsigned char *swk, unsigned char *iv)
{
    unsigned char *buf = NULL, *buf_e = NULL, *src_buf = NULL, *tmp_buf = NULL;
    unsigned int len_p, len_q, len_dp, len_dq, len_qinv, len_e;
    int ret = -1, size_tmp = 0;

    if (!p || !dp || !dq || !qinv ||
        !e || !key_type2 || !swk || !iv) {
        goto err;
    }

    if ((buf = malloc(key_size)) == NULL) {
        goto err;
    }
    if ((buf_e = malloc(key_size * 2)) == NULL) {
        goto err;
    }
    if ((src_buf = malloc(KPT_RSA_TYPE2_KEY_SIZE(key_size))) == NULL) {
        goto err;
    }
    memset(src_buf, 0, KPT_RSA_TYPE2_KEY_SIZE(key_size));

    len_p = BN_num_bytes(p);
    len_q = BN_num_bytes(q);
    len_dp = BN_num_bytes(dp);
    len_dq = BN_num_bytes(dq);
    len_qinv = BN_num_bytes(qinv);
    len_e = BN_num_bytes(e);
    tmp_buf = src_buf;

    tmp_buf += key_size;
    memset(buf, 0, key_size);
    BN_bn2bin(p, buf);
    memcpy(tmp_buf - len_p, buf, len_p);

    tmp_buf += key_size;
    memset(buf, 0, key_size);
    BN_bn2bin(q, buf);
    memcpy(tmp_buf - len_q, buf, len_q);

    tmp_buf += key_size;
    memset(buf, 0, key_size);
    BN_bn2bin(dp, buf);
    memcpy(tmp_buf - len_dp, buf, len_dp);

    tmp_buf += key_size;
    memset(buf, 0, key_size);
    BN_bn2bin(dq, buf);
    memcpy(tmp_buf - len_dq, buf, len_dq);

    tmp_buf += key_size;
    memset(buf, 0, key_size);
    BN_bn2bin(qinv, buf);
    memcpy(tmp_buf - len_qinv, buf, len_qinv);

    /* sizeof(e) is twice of sizeof(p) */
    tmp_buf += key_size * 2;
    memset(buf_e, 0, key_size * 2);
    BN_bn2bin(e, buf_e);
    memcpy(tmp_buf - len_e, buf_e, len_e);

    ret = wrap_key_with_gcm256(src_buf, KPT_RSA_TYPE2_KEY_SIZE(key_size),
                               key_type2, &size_tmp, swk, iv, AES_GCM_IV_SIZE,
                               rsa_oid, sizeof(rsa_oid));
err:
    if (buf) {
        free(buf);
    }

    if (buf_e) {
        free(buf_e);
    }

    if (src_buf) {
        free(src_buf);
    }
    return ret;
}

static int build_kpt_wpk(RSA *rsa, unsigned char **rsa_key_type1,
                         unsigned char **rsa_key_type2, unsigned int *rsa_key_size,
                         unsigned int *rsa_size_type1, unsigned int *rsa_size_type2,
                         unsigned char *swk, unsigned char *iv)
{
    const BIGNUM *p = NULL, *q = NULL, *dp = NULL, *dq = NULL, *qinv = NULL;
    const BIGNUM *n = NULL, *e = NULL, *d = NULL;
    unsigned int len_n = 0;
    unsigned char *key_type1 = NULL, *key_type2 = NULL;
    int ret = -1, key_size = 0;
    int size_type1 = 0, size_type2 = 0;

    if (!rsa || !rsa_key_type1 || !rsa_key_type2 || !rsa_key_size ||
        !rsa_size_type1 || !rsa_size_type2 || !swk || !iv) {
        return -1;
    }

    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dp, &dq, &qinv);
    RSA_get0_key(rsa, &n, &e, &d);
    len_n = (unsigned int) BN_num_bytes(n);

    key_size = rsa_get_key_size(len_n);
    if (key_size > 0) {
        size_type1 = KPT_RSA_TYPE1_KEY_SIZE(key_size) + AES_GCM_TAG_SIZE;
        size_type2 = KPT_RSA_TYPE2_KEY_SIZE(key_size/2) + AES_GCM_TAG_SIZE;

        if ((key_type1 = OPENSSL_malloc(size_type1)) == NULL) {
            goto err;
        }

        if ((key_type2 = OPENSSL_malloc(size_type2)) == NULL) {
            goto err;
        }

        ret = generate_type1_wpk(n, d, key_size, key_type1, swk, iv);
        if (ret < 0) {
            goto err;
        }

        ret = generate_type2_wpk(p, q, dp, dq, qinv, e, key_size/2, key_type2,
                                 swk, iv);
        if (ret < 0) {
            goto err;
        }

    }
    *rsa_key_type1 = key_type1;
    *rsa_key_type2 = key_type2;
    *rsa_key_size = key_size;
    *rsa_size_type1 = size_type1;
    *rsa_size_type2 = size_type2;

    return ret;
err:
    if (key_type1) {
        OPENSSL_free(key_type1);
    }
    if (key_type2) {
        OPENSSL_free(key_type2);
    }
    return -1;
}

static void build_rsa_public_key(RSA *rsa, RSAPUBLICKEY *pub_key)
{
    const BIGNUM *n = NULL, *e = NULL, *d = NULL;
    RSA_get0_key(rsa, &n, &e, &d);
    BN_to_ASN1_INTEGER(n, pub_key->n);
    BN_to_ASN1_INTEGER(e, pub_key->e);
}

int kpt_rsa_wpk_gen(unsigned char *cpk_file, unsigned char *wpk_file)
{
    RSA *rsa = NULL;
    EVP_PKEY *pkey = NULL;
    KPTRSAKEY *key = NULL;
    BIO *in = NULL;
    BIO *out = NULL;
    WRAPPINGMETADATA *metadata = NULL;
    RSAPUBLICKEY *pub_key = NULL;
    ASN1_OBJECT *enc_algo_id = NULL;
    ESWK *eSWK = NULL;
    unsigned char swk[AES_GCM_256_KEY_SIZE];
    unsigned char *key_type1 = NULL, *key_type2 = NULL;
    unsigned int key_size = 0, size_type1 = 0, size_type2 = 0;
    unsigned char *iv = NULL, *dev_sig = NULL, *eswk = NULL;
    int ret = 0, i = 0;

    if ((in = BIO_new(BIO_s_file())) == NULL) {
        log_err(" - BIO new failed\n");
        ret = -1;
        goto err;
    }

    if (!(BIO_read_filename(in,cpk_file))) {
        log_err(" - Read clear private key file %s failed\n", cpk_file);
        ret = -1;
        goto err;
    }

    /* read private key */
    if ((pkey = PEM_read_bio_PrivateKey(in,NULL,NULL,NULL)) == NULL) {
        log_err(" - Read Private Key error\n");
        ret = -1;
        goto err;
    }
    BIO_free(in);
    in = NULL;

    if ((rsa = EVP_PKEY_get1_RSA(pkey)) == NULL) {
        log_err(" - Get RSA Private Key error\n");
        ret = -1;
        goto err;
    }

    if ((iv = OPENSSL_malloc(AES_GCM_IV_SIZE)) == NULL) {
        ret = -1;
        goto err;
    }
    RAND_bytes(iv, AES_GCM_IV_SIZE);

    if ((key = KPTRSAKEY_new()) == NULL) {
        ret = -1;
        goto err;
    }

    if ((metadata = key->wrappingMetadata) == NULL) {
        ret = -1;
        goto err;
    }

    enc_algo_id = OBJ_txt2obj("aes-256-gcm", 0);
    metadata->wrappingAlg = enc_algo_id;

    RAND_bytes(swk, sizeof(swk));

    /* get instance->query per-part key */
    ret = kpt_get_per_part_key();
    if (ret != 0) {
        ret  = -1;
        goto err;
    }
    for (i = 0; i < cpu_socket_num; i++){
        if ((eSWK = ESWK_new()) == NULL) {
            ret = -1;
            goto err;
        }

        if ((eswk = OPENSSL_zalloc(KPT_PER_PART_KEY_N_LEN)) == NULL) {
            ret = -1;
            goto err;
        }

        if ((dev_sig = OPENSSL_zalloc(KPT_PER_PART_SIG_LEN)) == NULL) {
            ret = -1;
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
        if (ret <= 0) {
            ret = -1;
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
    ASN1_STRING_set0(metadata->aesNonce, iv, AES_GCM_IV_SIZE);

    pub_key = key->publicKey;
    if (!pub_key) {
        ret  = -1;
        goto err;
    }

    build_rsa_public_key(rsa, pub_key);
    ret = build_kpt_wpk(rsa, &key_type1, &key_type2, &key_size, &size_type1,
                        &size_type2, swk, iv);
    if (ret < 0) {
        ret = -1;
        goto err;
    }

    hex_log(key_type1, size_type1, "type1");
    hex_log(key_type2, size_type2, "type2");

    key->version = (long)KPT_RSA_KEY_VERSION;
    ASN1_STRING_set0(key->privateKeyType1, key_type1, size_type1);
    ASN1_STRING_set0(key->privateKeyType2, key_type2, size_type2);
    key->size = (long)key_size;
    key->kptRSADsi = OBJ_nid2obj(NID_pkcs1);
    key->publicKey = pub_key;

    if ((out = BIO_new(BIO_s_file())) == NULL) {
        ret = -1;
        goto err;
    }
    BIO_write_filename(out, wpk_file);
    PEM_ASN1_write_bio((i2d_of_void *)i2d_KPTRSAKEY,
                      "KPT RSA KEY", out, key, NULL, NULL, 0, NULL, NULL);
    BIO_flush(out);
    BIO_free(out);
err:
    if (key)
        KPTRSAKEY_free(key);
    if (rsa)
        RSA_free(rsa);
    if (pkey)
        EVP_PKEY_free(pkey);

    return ret;
}

int kpt_rsa_wpk_parse(kpt_rsa_wpk *rsa_wpk, unsigned char *wpk_file)
{
    KPTRSAKEY *kptrsakey = NULL;
    WRAPPINGMETADATA *metadata = NULL;
    RSAPUBLICKEY *pub = NULL;
    BIO *in = NULL;
    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    const unsigned char *p = NULL;
    long len;
    int ret = 0;
    BIGNUM *n = NULL, *e = NULL;
    int i;

    in = BIO_new(BIO_s_file());
    if (BIO_read_filename(in, wpk_file) <= 0) {
        goto err;
    }

    ret = PEM_read_bio(in, &name, &header, &data, &len);
    p = data;
    d2i_KPTRSAKEY(&kptrsakey, &p, len);
    if (!kptrsakey) {
        goto err;
    }

    BIO_free(in);
    in = NULL;
    rsa_wpk->version = kptrsakey->version;
    rsa_wpk->size = kptrsakey->size;
    rsa_wpk->rsa_nid = OBJ_obj2nid(kptrsakey->kptRSADsi);

    metadata = kptrsakey->wrappingMetadata;

    rsa_wpk->wrapping_alg_nid = OBJ_obj2nid(metadata->wrappingAlg);
    for (i = 0; i < sk_ESWK_num(metadata->eSWKs); i++ ) {
        ESWK *eSWK = sk_ESWK_value(metadata->eSWKs, i);

        (rsa_wpk->swkSec_size)[i] = ASN1_STRING_length(eSWK->secSWK);
        memcpy((rsa_wpk->swkSec)[i], ASN1_STRING_get0_data(eSWK->secSWK),
            (rsa_wpk->swkSec_size)[i]);

        (rsa_wpk->swkPub_size)[i] = ASN1_STRING_length(eSWK->devSig);
        memcpy((rsa_wpk->swkPub)[i], ASN1_STRING_get0_data(eSWK->devSig),
            (rsa_wpk->swkPub_size)[i]);
    }

    rsa_wpk->wpk_type1_size = ASN1_STRING_length(kptrsakey->privateKeyType1);
    memcpy(rsa_wpk->wpk_type1,
           ASN1_STRING_get0_data(kptrsakey->privateKeyType1),
           rsa_wpk->wpk_type1_size);

    rsa_wpk->wpk_type2_size = ASN1_STRING_length(kptrsakey->privateKeyType2);
    memcpy(rsa_wpk->wpk_type2,
           ASN1_STRING_get0_data(kptrsakey->privateKeyType2),
           rsa_wpk->wpk_type2_size);

    n = ASN1_INTEGER_to_BN(kptrsakey->publicKey->n, NULL);
    e = ASN1_INTEGER_to_BN(kptrsakey->publicKey->e, NULL);

    rsa_wpk->n_size = BN_num_bytes(n);
    rsa_wpk->e_size = BN_num_bytes(e);

    BN_bn2bin(n, rsa_wpk->n);
    BN_bn2bin(e, rsa_wpk->e);

    log_print("\n=========================\n");
    log_print("WPK version: %ld\n", rsa_wpk->version);
    hex_log(rsa_wpk->wpk_type1, rsa_wpk->wpk_type1_size, "RSA WPK TYPE1");
    hex_log(rsa_wpk->wpk_type2, rsa_wpk->wpk_type2_size, "RSA WPK TYPE2");
    log_print("\nWPK Size: %ld\n", rsa_wpk->size);
    log_print("\nRSA NID: %d\n", rsa_wpk->rsa_nid);
    hex_log(rsa_wpk->n, rsa_wpk->n_size, "RSA Public Key - N");
    hex_log(rsa_wpk->e, rsa_wpk->e_size, "RSA Public Key - E");
    hex_log((unsigned char *)ASN1_STRING_get0_data(metadata->aesNonce),
            ASN1_STRING_length(metadata->aesNonce), "IV");
    log_print("\nWrapping Algorithm NID: %d\n", rsa_wpk->wrapping_alg_nid);
    for (i = 0; i < sk_ESWK_num(metadata->eSWKs); i++ ) {
        log_print("\nESWK %d\n", i);
        hex_log((rsa_wpk->swkSec)[i], (rsa_wpk->swkSec_size)[i], "Sec SWK");
        hex_log((rsa_wpk->swkPub)[i], (rsa_wpk->swkPub_size)[i], "Dev sig");
    }
    log_print("=========================\n\n");

    return 0;

err:
    if (in) {
        BIO_free(in);
        in = NULL;
    }
    return -1;
}
