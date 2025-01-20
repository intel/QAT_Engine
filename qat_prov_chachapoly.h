/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2025 Intel Corporation.
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
 * @file qat_prov_chachapoly.h
 *
 * This file provides an interface of CHACHAPOLY operations for OpenSSL
 * 3.0 qatprovider.
 *
 *****************************************************************************/
#ifndef QAT_PROV_CHACHAPOLY_H
# define QAT_PROV_CHACHAPOLY_H

# include <string.h>
# include <openssl/core.h>
# include <openssl/modes.h>
# include <openssl/core_dispatch.h>
# include <openssl/params.h>
# include <openssl/err.h>
# include <openssl/proverr.h>
# include <openssl/core_names.h>
# include <openssl/rand.h>
# include <openssl/sha.h>
# include <openssl/prov_ssl.h>
# include <openssl/provider.h>
# include <openssl/types.h>
# include <openssl/evp.h>

# ifdef ENABLE_QAT_HW_CHACHAPOLY
#include "qat_hw_chachapoly.h"
#include "qat_provider.h"
#include "e_qat.h"

/* Internal flags that can be queried */
#define PROV_CIPHER_FLAG_AEAD             0x0001
#define PROV_CIPHER_FLAG_CUSTOM_IV        0x0002
#define PROV_CIPHER_FLAG_CTS              0x0004
#define PROV_CIPHER_FLAG_TLS1_MULTIBLOCK  0x0008
#define PROV_CIPHER_FLAG_RAND_KEY         0x0010
/* Internal flags that are only used within the provider */
#define PROV_CIPHER_FLAG_VARIABLE_LENGTH  0x0100
#define PROV_CIPHER_FLAG_INVERSE_CIPHER   0x0200

#define CHACHA20_KEYLEN (QAT_CHACHA_KEY_SIZE)
#define CHACHA20_BLKLEN (1)
#define CHACHA20_IVLEN (QAT_CHACHA_CTR_SIZE)
#define CHACHA20_FLAGS (PROV_CIPHER_FLAG_CUSTOM_IV)

# define OSSL_UNION_ALIGN       \
    double align;               \
    ossl_uintmax_t align_int;   \
    void *align_ptr


# define NO_TLS_PAYLOAD_LENGTH ((size_t)-1)
# define CHACHA20_POLY1305_IVLEN 12
# define GENERIC_BLOCK_SIZE 16

# define QAT_PROV_GET_ENC(ctx) ((ctx)->enc)

typedef void (*poly1305_blocks_f) (void *ctx, const unsigned char *inp,
                                   size_t len, unsigned int padbit);
typedef void (*poly1305_emit_f) (void *ctx, unsigned char mac[16],
                                 const unsigned int nonce[4]);

typedef struct qat_evp_cipher_st QAT_EVP_CIPHER;
typedef struct prov_cp_cipher_ctx_st QAT_PROV_CIPHER_CTX;
struct prov_cp_cipher_ctx_st {
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
    unsigned char oiv[GENERIC_BLOCK_SIZE];
    /* Buffer of partial blocks processed via update calls */
    unsigned char buf[GENERIC_BLOCK_SIZE];
    unsigned char iv[GENERIC_BLOCK_SIZE];
    const void *ks; /* Pointer to algorithm specific key data */
    OSSL_LIB_CTX *libctx;

    EVP_CIPHER_CTX *sw_ctx;
    QAT_EVP_CIPHER *sw_cipher;



    void *sw_ctx_cipher_data;
    int inst_num;
    int context_params_set;
    int session_init;

    CpaCySymSessionSetupData *session_data;
    CpaCySymSessionCtx session_ctx;
    CpaCySymOpData *opd;
    CpaBufferList pSrcBufferList;
    CpaBufferList pDstBufferList;
    CpaFlatBuffer src_buffer;
    CpaFlatBuffer dst_buffer;

    unsigned char tag[QAT_POLY1305_BLOCK_SIZE];
    unsigned char *tls_aad;
    unsigned char cipher_key[QAT_CHACHA_KEY_SIZE];
    unsigned char *mac_key;
    unsigned char nonce[QAT_CHACHA20_POLY1305_MAX_IVLEN];
    unsigned char derived_iv[QAT_CHACHA20_POLY1305_MAX_IVLEN];
    unsigned int counter[QAT_CHACHA_CTR_SIZE/4];
    unsigned int chacha_key[QAT_CHACHA_KEY_SIZE/4];

    int key_set;
    int mac_key_set;
    int tag_len;
    int nonce_len;
    int tls_aad_len;
    size_t tls_payload_length;
    int packet_size;
    int qat_svm;
    /* If tag_set 1 Encryption in qat,if tag_set 0 Encryption in Openssl SW */
    int tag_set;
};

typedef struct {
    QAT_PROV_CIPHER_CTX base;     /* must be first */
    union {
        OSSL_UNION_ALIGN;
        unsigned int d[QAT_CHACHA_KEY_SIZE / 4];
    } key;
    unsigned int  counter[QAT_CHACHA_CTR_SIZE / 4];
    unsigned char buf[QAT_CHACHA_BLK_SIZE];
    unsigned int  partial_len;
} PROV_CHACHA20_CTX;

typedef struct poly1305_context {
    double opaque[24];  /* large enough to hold internal state, declared
                         * 'double' to ensure at least 64-bit invariant
                         * alignment across all platforms and
                         * configurations */
    unsigned int nonce[4];
    unsigned char data[QAT_POLY1305_BLOCK_SIZE];
    size_t num;
    struct {
        poly1305_blocks_f blocks;
        poly1305_emit_f emit;
    } func;
} POLY1305;

typedef struct {
    QAT_PROV_CIPHER_CTX base;       /* must be first */
    PROV_CHACHA20_CTX chacha;
    POLY1305 poly1305;
    unsigned int nonce[12 / 4];
    unsigned char tag[QAT_POLY1305_BLOCK_SIZE];
    unsigned char tls_aad[QAT_POLY1305_BLOCK_SIZE];
    struct { uint64_t aad, text; } len;
    unsigned int aad : 1;
    unsigned int mac_inited : 1;
    size_t tag_len, nonce_len;
    size_t tls_payload_length;
    size_t tls_aad_pad_sz;
} PROV_CHACHA20_POLY1305_CTX;

struct qat_evp_cipher_st{
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
} /* EVP_CIPHER */ ;

struct evp_cipher_ctx_st {
    const EVP_CIPHER *cipher;
    ENGINE *engine;             /* functional reference if 'cipher' is
                                 * ENGINE-provided */
    int encrypt;                /* encrypt or decrypt */
    int buf_len;                /* number we have left */
    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
    unsigned int iv[3]; /* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    int num;                    /* used by cfb/ofb/ctr mode */
    /* FIXME: Should this even exist? It appears unused */
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

QAT_EVP_CIPHER get_default_cipher_chachapoly();
int qat_chacha20_poly1305_init(QAT_PROV_CIPHER_CTX *ctx,
                                      const unsigned char *user_key, int keylen,
                                      const unsigned char *iv, int ivlen, int enc);
int qat_chacha20_poly1305_do_cipher(QAT_PROV_CIPHER_CTX * ctx, unsigned char *out,
                                    size_t *padlen, size_t outl,
                                    const unsigned char *in, size_t len);
int qat_chacha20_poly1305_cleanup(QAT_PROV_CIPHER_CTX *ctx);
int qat_chacha20_poly1305_ctrl(QAT_PROV_CIPHER_CTX *ctx, int type, int arg,
                                      void *ptr);

# endif /* ENABLE_QAT_HW_CHACHAPOLY */
#endif
