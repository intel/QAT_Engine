/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023 Intel Corporation.
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
 * @file qat_prov_sm4_cbc.h
 *
 * This file provides an interface to Qat provider SM4-CBC operations
 *
 *****************************************************************************/
#ifndef QAT_PROV_SM4_CBC_H
# define QAT_PROV_SM4_CBC_H

# if defined(ENABLE_QAT_HW_SM4_CBC) || defined(ENABLE_QAT_SW_SM4_CBC)
# include <string.h>
# include <openssl/core.h>
# include <openssl/provider.h>
# include <openssl/modes.h>
# include <openssl/types.h>
# include <openssl/core_dispatch.h>
# include <openssl/params.h>
# include <openssl/err.h>
# include <openssl/proverr.h>
# include <openssl/core_names.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# include <openssl/sha.h>
# include <openssl/ossl_typ.h>
# ifdef ENABLE_QAT_SW_SM4_CBC
#  include "crypto_mb/sm4.h"
# endif

#define SM4_IV_LEN 16
#define IV_STATE_UNINITIALISED 0  /* initial state is not initialized */

# define PROV_CIPHER_FLAG_AEAD             0x0001
# define PROV_CIPHER_FLAG_CUSTOM_IV        0x0002
# define PROV_CIPHER_FLAG_CTS              0x0004
# define PROV_CIPHER_FLAG_TLS1_MULTIBLOCK  0x0008
# define PROV_CIPHER_FLAG_RAND_KEY         0x0010
# define QAT_SM4_CBC_BLOCK_SIZE   16

/* Internal flags that are only used within the provider */
#define PROV_CIPHER_FLAG_VARIABLE_LENGTH  0x0100
#define PROV_CIPHER_FLAG_INVERSE_CIPHER   0x0200

typedef _Atomic int CRYPTO_REF_COUNT;

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
    int (*init) (EVP_CIPHER_CTX *ctx, const unsigned char *key,
                 const unsigned char *iv, int enc);
    /* encrypt/decrypt data */
    int (*do_cipher) (EVP_CIPHER_CTX *ctx, unsigned char *out,
                      const unsigned char *in, size_t inl);
    /* cleanup ctx */
    int (*cleanup) (EVP_CIPHER_CTX *);
    /* how big ctx->cipher_data needs to be */
    int ctx_size;
    /* Populate a ASN1_TYPE with parameters */
    int (*set_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Get parameters from a ASN1_TYPE */
    int (*get_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Miscellaneous operations */
    int (*ctrl) (EVP_CIPHER_CTX *, int type, int arg, void *ptr);
    /* Application data */
    void *app_data;
    /* New structure members */
    /* Above comment to be removed when legacy has gone */
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;
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
} QAT_EVP_CIPHER_SM4_CBC;

typedef struct qat_prov_cbc_ctx_st {
    int nid;

    block128_f block;
    union {
        cbc128_f cbc;
        ctr128_f ctr;
        ecb128_f ecb;
    } stream;

    unsigned int mode;
    size_t keylen;           /* key size (in bytes) */
    size_t ivlen;
    size_t blocksize;
    size_t bufsz;            /* Number of bytes in buf */
    unsigned int cts_mode;   /* Use to set the type for CTS modes */
    unsigned int pad : 1;    /* Whether padding should be used or not */
    unsigned int enc : 1;    /* Set to 1 for encrypt, or 0 otherwise */
    unsigned int iv_set : 1; /* Set when the iv is copied to the iv/oiv buffers */
    unsigned int updated : 1; /* Set to 1 during update for one shot ciphers */
    unsigned int variable_keylength : 1;
    unsigned int inverse_cipher : 1; /* set to 1 to use inverse cipher */
    unsigned int use_bits : 1; /* Set to 0 for cfb1 to use bits instead of bytes */

    unsigned int tlsversion; /* If TLS padding is in use the TLS version number */
    unsigned char *tlsmac;   /* tls MAC extracted from the last record */
    int alloced;             /*
                              * Whether the tlsmac data has been allocated or
                              * points into the user buffer.
                              */
    size_t tlsmacsize;       /* Size of the TLS MAC */
    int removetlspad;        /* Whether TLS padding should be removed or not */
    size_t removetlsfixed;   /*
                              * Length of the fixed size data to remove when
                              * processing TLS data (equals mac size plus
                              * IV size if applicable)
                              */
    /*
     * num contains the number of bytes of |iv| which are valid for modes that
     * manage partial blocks themselves.
     */
    unsigned int num;

    /* The original value of the iv */
    unsigned char oiv[QAT_SM4_CBC_BLOCK_SIZE];
    /* Buffer of partial blocks processed via update calls */
    unsigned char buf[QAT_SM4_CBC_BLOCK_SIZE];
    unsigned char iv[QAT_SM4_CBC_BLOCK_SIZE];
    const void *ks; /* Pointer to algorithm specific key data */
    OSSL_LIB_CTX *libctx;
#if ENABLE_QAT_HW_SM4_CBC
    void *qat_cipher_ctx;
#endif
    EVP_CIPHER *sw_cipher;
#if ENABLE_QAT_SW_SM4_CBC
    sm4_key key;
#endif
    void *sw_ctx;
} QAT_PROV_CBC_CTX;

typedef struct qat_sm4cbc_ctx_st {
    QAT_PROV_CBC_CTX base;
    QAT_EVP_CIPHER_SM4_CBC *cipher;
}QAT_SM4CBC_CTX;

#define QAT_sm4_cbc_func(alg, lc, UCMODE, flags, kbits, blkbits, ivbits, typ)  \
static OSSL_FUNC_cipher_get_params_fn alg##_##kbits##_##lc##_get_params;       \
static int alg##_##kbits##_##lc##_get_params(OSSL_PARAM params[])              \
{                                                                              \
    return qat_sm4_cbc_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE,    \
                                          flags, kbits, blkbits, ivbits);      \
}                                                                              \
static OSSL_FUNC_cipher_newctx_fn alg##kbits##lc##_newctx;               \
static void * alg##kbits##lc##_newctx(void *provctx)                     \
{                                                                              \
    return alg##_##lc##_newctx(provctx, kbits, blkbits, ivbits, flags);        \
}                                                                              \
const OSSL_DISPATCH alg##_##lc##_functions[] = {                       \
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) alg##kbits##lc##_newctx},      \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) alg##_##lc##_freectx },          \
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void)) alg##_##lc##_dupctx },            \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))alg##_##lc##_einit },     \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))alg##_##lc##_dinit },     \
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))alg##_##lc##_block_update },    \
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))alg##_##lc##_block_final },      \
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))alg##_##lc##_cipher },          \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
      (void (*)(void)) alg##_##kbits##_##lc##_get_params },                    \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                         \
      (void (*)(void))alg##_##lc##_get_ctx_params },                           \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
      (void (*)(void))alg##_##lc##_set_ctx_params },                           \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void))alg##_##lc##_generic_gettable_params },                  \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void))qat_sm4_cbc_generic_gettable_ctx_params },              \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
     (void (*)(void))qat_sm4_cbc_generic_settable_ctx_params },               \
    { 0, NULL }                                                                \
}
# endif
#endif /* QAT_PROV_SM4_CBC_H */
