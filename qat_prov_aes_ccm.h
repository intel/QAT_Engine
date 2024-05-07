/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2024 Intel Corporation.
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
/*****************************************************************************
 * @file qat_prov_aes_ccm.h
 *
 * This file provides an interface to QAT provider AES-CCM operations
 *
 *****************************************************************************/

#ifndef QAT_PROV_AES_CCM_H
# define QAT_PROV_AES_CCM_H

# ifdef ENABLE_QAT_HW_CCM
#  include <string.h>
#  include <openssl/core.h>
#  include <openssl/provider.h>
#  include <openssl/modes.h>
#  include <openssl/types.h>
#  include <openssl/core_dispatch.h>
#  include <openssl/params.h>
#  include <openssl/err.h>
#  include <openssl/proverr.h>
#  include <openssl/core_names.h>

#  include "qat_utils.h"
#  include "e_qat.h"
#  include "qat_hw_ccm.h"

#  define IV_STATE_UNINITIALISED 0  /* initial state is not initialized */
#  define QAT_AES_BLOCK_SIZE   16

#  define PROV_CIPHER_FLAG_AEAD             0x0001
#  define PROV_CIPHER_FLAG_CUSTOM_IV        0x0002
#  define PROV_CIPHER_FLAG_CTS              0x0004
#  define PROV_CIPHER_FLAG_TLS1_MULTIBLOCK  0x0008
#  define PROV_CIPHER_FLAG_RAND_KEY         0x0010

typedef struct qat_evp_cipher_st {
    int nid;

    int block_size;
    /* Default value for variable length ciphers */
    int key_len;
    int iv_len;

    /* Legacy structure members */
    /* Various flags */
    unsigned long flags;
    /* How the EVP_CIPHER was created. */
    int origin;
    /* init key */
    int (*init)(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                const unsigned char *iv, int enc);
    /* encrypt/decrypt data */
    int (*do_cipher)(EVP_CIPHER_CTX *ctx, unsigned char *out,
                     const unsigned char *in, size_t inl);
    /* cleanup ctx */
    int (*cleanup)(EVP_CIPHER_CTX *);
    /* how big ctx->cipher_data needs to be */
    int ctx_size;
    /* Populate a ASN1_TYPE with parameters */
    int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Get parameters from a ASN1_TYPE */
    int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Miscellaneous operations */
    int (*ctrl)(EVP_CIPHER_CTX *, int type, int arg, void *ptr);
    /* Application data */
    void *app_data;
    /* New structure members */
    /* Above comment to be removed when legacy has gone */
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;
    CRYPTO_REF_COUNT references;
#if OPENSSL_VERSION_NUMBER < 0x30200000
    CRYPTO_RWLOCK *lock;
#endif
    OSSL_FUNC_cipher_newctx_fn *newctx;
    OSSL_FUNC_cipher_encrypt_init_fn *einit;
    OSSL_FUNC_cipher_decrypt_init_fn *dinit;
    OSSL_FUNC_cipher_update_fn *cupdate;
    OSSL_FUNC_cipher_final_fn *cfinal;
    OSSL_FUNC_cipher_cipher_fn *ccipher;
    OSSL_FUNC_cipher_freectx_fn *freectx;
    OSSL_FUNC_cipher_dupctx_fn *dupctx;
    OSSL_FUNC_cipher_get_params_fn *get_params;
    OSSL_FUNC_cipher_get_ctx_params_fn *get_ctx_params;
    OSSL_FUNC_cipher_set_ctx_params_fn *set_ctx_params;
    OSSL_FUNC_cipher_gettable_params_fn *gettable_params;
    OSSL_FUNC_cipher_gettable_ctx_params_fn *gettable_ctx_params;
    OSSL_FUNC_cipher_settable_ctx_params_fn *settable_ctx_params;
} QAT_EVP_CIPHER;

#  pragma pack(push, 16)
typedef struct qat_ccm_ctx_st {
    int inst_num;
    CpaCySymSessionSetupData *session_data;
    CpaCySymSessionCtx qat_ctx;
    int init_params_set;

    /* This flag is set to 1 when the session has been initialized */
    int is_session_init;

    /* QAT Op Params */
    CpaCySymOpData OpData;

    CpaBufferList srcBufferList;
    CpaBufferList dstBufferList;
    CpaFlatBuffer srcFlatBuffer;
    CpaFlatBuffer dstFlatBuffer;
    /* -- Crypto -- */

    /* Pointer to AAD.
     * In the TLS case this will contain the TLS header */
    Cpa8U *aad;

    /* Size of the meta data for the driver
     * It cannot allocate memory so this must be done by the user application */
    unsigned int meta_size;

    /* Pointer to pCipherKey */
    Cpa8U *cipher_key;

    /* Flag to keep track of key passed */
    int key_set;

    int qat_svm;
    int tls_aad_len;
    int tag_len;
    int iv_len;
    unsigned int iv_set;
    int iv_gen;
    Cpa8U next_iv[EVP_MAX_IV_LENGTH];
    unsigned char *iv;
    unsigned int mode;          /* The mode that we are using */
    size_t keylen;
    size_t ivlen_min;
    size_t tls_aad_pad_sz;
    uint64_t tls_enc_records;   /* Number of TLS records encrypted */

    /*
     * num contains the number of bytes of |iv| which are valid for modes that
     * manage partial blocks themselves.
     */
    size_t num;
    size_t bufsz;               /* Number of bytes in buf */

    unsigned int enc:1;         /* Set to 1 if we are encrypting or 0 otherwise */
    unsigned int pad:1;         /* Whether padding should be used or not */
    unsigned int iv_gen_rand:1; /* No IV was specified, so generate a rand IV */
    unsigned char buf[QAT_AES_BLOCK_SIZE]; /* Buffer of partial blocks processed via update calls */
    OSSL_LIB_CTX *libctx;       /* needed for rand calls */
    ctr128_f ctr;
    size_t L, M;
    int tag_set, len_set;
    int packet_size;
    int nid;
    void *sw_ctx_cipher_data;
    EVP_CIPHER_CTX *sw_ctx;
    QAT_EVP_CIPHER *sw_cipher;
} QAT_PROV_CCM_CTX;
#  pragma pack(pop)

struct evp_cipher_ctx_st {
    const EVP_CIPHER *cipher;
    ENGINE *engine;             /* functional reference if 'cipher' is
                                 * ENGINE-provided */
    int encrypt;                /* encrypt or decrypt */
    int buf_len;                /* number we have left */
    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
    unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    int num;                    /* used by cfb/ofb/ctr mode */
    void *app_data;             /* application stuff */
    int key_len;                /* May change for variable length cipher */
    unsigned long flags;        /* Various flags */
    void *cipher_data;          /* per EVP data */
    int final_used;
    int block_mask;
    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */

    /*
     * Opaque ctx returned from a providers cipher algorithm implementation
     * OSSL_FUNC_cipher_newctx()
     */
    void *algctx;
    EVP_CIPHER *fetched_cipher;
} /* EVP_CIPHER_CTX */ ;

typedef struct prov_aes_ccm_ctx_st {
    QAT_PROV_CCM_CTX base;      /* must be first entry in struct */
    QAT_EVP_CIPHER *cipher;
} QAT_PROV_AES_CCM_CTX;

size_t qat_aes_ccm_get_ivlen(QAT_PROV_CCM_CTX * ctx);
void qat_aes_ccm_init_ctx(void *provctx, QAT_PROV_CCM_CTX * ctx, size_t keybits,
                          size_t ivlen_min);
int qat_aes_ccm_get_ctx_params(void *vctx, OSSL_PARAM params[]);
int qat_aes_ccm_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
int qat_aes_ccm_einit(void *ctx, const unsigned char *inkey, size_t keylen,
                      const unsigned char *iv, size_t ivlen, int enc);
int qat_aes_ccm_dinit(void *ctx, const unsigned char *inkey, size_t keylen,
                      const unsigned char *iv, size_t ivlen, int enc);
int qat_aes_ccm_stream_update(void *ctx, unsigned char *out,
                              size_t *outl, size_t outsize,
                              const unsigned char *in, size_t inl);
int qat_aes_ccm_stream_final(void *ctx, unsigned char *out,
                             size_t *outl, size_t outsize);
int qat_aes_ccm_do_cipher(void *ctx, unsigned char *out,
                          size_t *outl, size_t outsize,
                          const unsigned char *in, size_t inl);
const char *qat_ccm_cipher_name(int nid);
QAT_EVP_CIPHER get_default_cipher_aes_ccm(int nid);

#  define QAT_aes_cipher(alg, lc, UCMODE, flags, kbits, blkbits, ivbits,nid)    \
static OSSL_FUNC_cipher_get_params_fn alg##_##kbits##_##lc##_get_params;        \
static int alg##_##kbits##_##lc##_get_params(OSSL_PARAM params[])               \
{                                                                               \
    return qat_aes_ccm_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE,     \
                                          flags, kbits, blkbits, ivbits);       \
}                                                                               \
static OSSL_FUNC_cipher_newctx_fn alg##_##kbits##_##lc##_newctx;                \
static void *alg##_##kbits##_##lc##_newctx(void *provctx)                       \
{                                                                               \
    return alg##_##lc##_newctx(provctx, kbits, nid);                            \
}                                                                               \
const OSSL_DISPATCH alg##kbits##lc##_functions[] = {                            \
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))alg##_##kbits##_##lc##_newctx }, \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))alg##_##lc##_freectx },         \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))alg##_##lc##_einit },      \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))alg##_##lc##_dinit },      \
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))alg##_##lc##_stream_update },    \
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))alg##_##lc##_stream_final },      \
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))alg##_##lc##_cipher },           \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                              \
      (void (*)(void)) alg##_##kbits##_##lc##_get_params },                     \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                          \
      (void (*)(void)) alg##_##lc##_get_ctx_params },                           \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                          \
      (void (*)(void)) alg##_##lc##_set_ctx_params },                           \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                         \
      (void (*)(void))alg##_##lc##_generic_gettable_params },                   \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                     \
      (void (*)(void))alg##_##lc##_aead_gettable_ctx_params },                  \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                     \
      (void (*)(void))alg##_##lc##_aead_settable_ctx_params },                  \
    { 0, NULL }                                                                 \
}
# endif                         /* ENABLE_QAT_HW_CCM */
#endif                          /* QAT_PROV_AES_CCM_H */
