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
 * @file qat_sw_sm4_gcm.h
 *
 * This file Provides SM4-GCM interface for OpenSSL engine
 *
 *****************************************************************************/

#ifndef QAT_SW_SM4_GCM_H
# define QAT_SW_SM4_GCM_H

# include <openssl/engine.h>
# include <openssl/ossl_typ.h>
# include <openssl/modes.h>

#ifdef ENABLE_QAT_SW_SM4_GCM
/* QAT_SW SM4 methods declaration */
#define QAT_BYTE_SHIFT 8
#define QAT_SM4_TAG_MIN_LEN 0
#define QAT_SM4_TAG_MAX_LEN 16
#define QAT_SM4_TLS_PAYLOADLENGTH_MSB_OFFSET 2
#define QAT_SM4_TLS_PAYLOADLENGTH_LSB_OFFSET 1
#define QAT_SM4_TLS_TOTAL_IV_LEN (EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN)

/* babassl flags needed for sw method */
#define CUSTOM_FLAGS    (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_FLAG_AEAD_CIPHER \
                         | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                         | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                         | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH \
                         | EVP_CIPH_GCM_MODE)

typedef struct {
    SM4_GCM_CTX_mb16 smctx;
    int init_flag;

    unsigned char* key;
    char key_len;
    int key_set;                /* Set if key initialized */

    unsigned char* tls_aad;
    int            aad_len;
    int            tls_aad_len;            /* TLS AAD length */
    unsigned int   tls_aad_set;

    unsigned char* tag;
    unsigned char* calculated_tag;
    int            tag_len;
    unsigned int   tag_set;
    unsigned int   tag_calculated;

    unsigned char* iv;
    unsigned char* next_iv;
    int            iv_len;
    unsigned int   iv_set;
    int            iv_gen;
    void*          sw_ctx_cipher_data;
} QAT_SM4_GCM_CTX;

/* sm4 key struct from BabaSSL */
# define SM4_KEY_SCHEDULE  32
typedef struct SM4_GCM_KEY_st {
    uint32_t rk[SM4_KEY_SCHEDULE];
} SM4_GCM_KEY;

typedef unsigned int u32;
typedef unsigned char u8;
typedef unsigned long long u64;

typedef struct {
    u64 hi, lo;
} u128;

struct gcm128_context {
    /* Following 6 names follow names in GCM specification */
    union {
        u64 u[2];
        u32 d[4];
        u8 c[16];
        size_t t[16 / sizeof(size_t)];
    } Yi, EKi, EK0, len, Xi, H;
    /*
     * Relative position of Xi, H and pre-computed Htable is used in some
     * assembler modules, i.e. don't change the order!
     */
    u128 Htable[16];
    void (*gmult) (u64 Xi[2], const u128 Htable[16]);
    void (*ghash) (u64 Xi[2], const u128 Htable[16], const u8 *inp,
                   size_t len);
    unsigned int mres, ares;
    block128_f block;
    void *key;
#if !defined(OPENSSL_SMALL_FOOTPRINT)
    unsigned char Xn[48];
#endif
};

typedef struct gcm128_context GCM128_CONTEXT;

typedef struct {
    SM4_GCM_KEY ks;             /* SM4 key schedule to use */
    int key_set;                /* Set if key initialized */
    int iv_set;                 /* Set if an iv is set */
    GCM128_CONTEXT gcm;
    unsigned char *iv;          /* Temporary IV store */
    int ivlen;                  /* IV length */
    int taglen;
    int iv_gen;                 /* It is OK to generate IVs */
    int tls_aad_len;            /* TLS AAD length */
    ctr128_f ctr;
} EVP_SM4_GCM_CTX;

#ifdef QAT_OPENSSL_PROVIDER
int qat_sw_sm4_gcm_init(void *ctx, const unsigned char *key, int keylen,
        const unsigned char *iv, int ivlen, int enc);
int qat_sw_sm4_gcm_ctrl(void *ctx, int type, int arg, void *ptr);
int qat_sw_sm4_gcm_cipher(void *ctx, unsigned char *out, size_t *padlen,
        size_t outsize, const unsigned char *in, size_t len);
int qat_sw_sm4_gcm_cleanup(void *ctx);
#else
int qat_sw_sm4_gcm_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
        const unsigned char *iv, int enc);
int qat_sw_sm4_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int qat_sw_sm4_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
        const unsigned char *in, size_t len);
int qat_sw_sm4_gcm_cleanup(EVP_CIPHER_CTX *ctx);
# endif

void process_mb_sm4_gcm_encrypt_reqs(mb_thread_data *tlv);
void process_mb_sm4_gcm_decrypt_reqs(mb_thread_data *tlv);
#endif /* ENABLE_QAT_SW_SM4_GCM */
#endif /* QAT_SW_SM4_GCM_H */
