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

/*****************************************************************************
 * @file qat_sw_sm4_ccm.h
 *
 * This file provides an SM4 CCM interfaces for an OpenSSL engine
 *
 *****************************************************************************/

#ifndef QAT_SW_SM4_CCM_H
# define QAT_SW_SM4_CCM_H

# include <openssl/engine.h>
# include <openssl/ossl_typ.h>
# include <openssl/modes.h>

# ifdef ENABLE_QAT_SW_SM4_CCM

#define QAT_BYTE_SHIFT 8
#define QAT_SM4_TAG_MIN_LEN 0
#define QAT_SM4_TAG_MAX_LEN 16
#define QAT_SM4_TLS_PAYLOADLENGTH_MSB_OFFSET 2
#define QAT_SM4_TLS_PAYLOADLENGTH_LSB_OFFSET 1
#define QAT_SM4_CCM_M_VALUE 12 
#define QAT_SM4_CCM_L_VALUE 8
#define QAT_SM4_CCM_OP_VALUE 15
#define SM4_KEY_SCHEDULE  32

/* babassl flags needed for sw method */
#define CUSTOM_CCM_FLAGS (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_FLAG_AEAD_CIPHER \
                         | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                         | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                         | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH \
                         | EVP_CIPH_CCM_MODE)

typedef struct {
    SM4_CCM_CTX_mb16 mb_ccmctx;
    int init_flag;

    unsigned char* key;
    int key_len;
    int key_set;                        /* Set if key initialized */

    unsigned char* tls_aad;
    int            aad_len;
    int            tls_aad_len;         /* TLS AAD length */
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
    int            msg_len;            /* Message Length */
    int            len_set;            /* Set if message length set */
    int            L, M;               /* L and M parameters from RFC3610 */
    void*          sw_ctx_cipher_data;

} QAT_SM4_CCM_CTX;


typedef unsigned char u8;
typedef unsigned long long u64;

typedef struct SM4_CCM_KEY_st {
    uint32_t rk[SM4_KEY_SCHEDULE];
} SM4_CCM_KEY;

struct ccm128_context {
union {
        u64 u[2];
        u8 c[16];
    } nonce, cmac;
    u64 blocks;
    block128_f block;
    void *key;
};

typedef struct ccm128_context CCM128_CONTEXT;

typedef struct {
    SM4_CCM_KEY ks;             /* SM4 key schedule to use */
    int key_set;                /* Set if key initialized */
    int iv_set;                 /* Set if an iv is set */
    int tag_set;                /* Set if tag is valid */
    int len_set;                /* Set if message length set */
    int L, M;                   /* L and M parameters from RFC3610 */
    int tls_aad_len;            /* TLS AAD length */
    CCM128_CONTEXT ccm;
    ccm128_f str;
} EVP_SM4_CCM_CTX;

#  ifdef QAT_OPENSSL_PROVIDER
int qat_sw_sm4_ccm_init(void *ctx, const unsigned char *key,
                        int keylen, const unsigned char *iv,
                        int ivlen, int enc);
int qat_sw_sm4_ccm_ctrl(void *ctx, int type, int p1, void *p2);
int qat_sw_sm4_ccm_do_cipher(void *ctx, unsigned char* out, size_t *padlen,
                         size_t outsize, const unsigned char* in, size_t len);
int qat_sw_sm4_ccm_cleanup(void *ctx);
#  else
int qat_sw_sm4_ccm_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
        const unsigned char *iv, int enc);
int qat_sw_sm4_ccm_ctrl(EVP_CIPHER_CTX *ctx, int type, int p1, void *p2);
int qat_sw_sm4_ccm_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
        const unsigned char *in, size_t len);
int qat_sw_sm4_ccm_cleanup(EVP_CIPHER_CTX *ctx);
#  endif /* QAT_OPENSSL_PROVIDER */

void process_mb_sm4_ccm_encrypt_reqs(mb_thread_data *tlv);
void process_mb_sm4_ccm_decrypt_reqs(mb_thread_data *tlv);

# endif /* ENABLE_QAT_SW_SM4_CCM */
#endif /* QAT_SW_SM4_H */
