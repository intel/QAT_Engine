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
 * @file qat_sw_sm4_cbc.h
 *
 * This file provides an SM4 interface for an OpenSSL engine
 *
 *****************************************************************************/

#ifndef QAT_SW_SM4_CBC_H
# define QAT_SW_SM4_CBC_H

# include <openssl/engine.h>
# include <openssl/ossl_typ.h>

/* BabaSSL includes needed for sw method */
# include <openssl/modes.h>

/* QAT_SW SM4 methods declaration */
#ifdef ENABLE_QAT_SW_SM4_CBC
#define SM4_IV_LEN 16

/* BabaSSL flags needed for sw method */
# define SM4_CBC_CUSTOM_FLAGS ( EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1 )

/* Guarantee the compatibility of OPENSSL1.1 */
#ifndef ecb128_f
typedef void (*ecb128_f) (const unsigned char *in, unsigned char *out,
                          size_t len, const void *key,
                          int enc);
#endif

typedef struct {
    sm4_key key;
    int8u iv[SM4_IV_LEN];
    int iv_set;
    int enc;
    void *sw_ctx_cipher_data;
} SM4_CBC_CTX;

/* sm4 key struct from BabaSSL */
# define SM4_KEY_SCHEDULE  32
typedef struct SM4_KEY_st {
    uint32_t rk[SM4_KEY_SCHEDULE];
} SM4_KEY;

typedef struct {
    union {
        SM4_KEY ks;
    } ks;
    block128_f block;
    union {
        ecb128_f ecb;
        cbc128_f cbc;
        ctr128_f ctr;
    } stream;
} EVP_SM4_KEY;

int qat_sw_sm4_cbc_key_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                   const unsigned char *iv, int enc);
int qat_sw_sm4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 const unsigned char *in, size_t len);
int qat_sw_sm4_cbc_cleanup(EVP_CIPHER_CTX *ctx);

void process_mb_sm4_cbc_key_init_reqs(mb_thread_data *tlv);
void process_mb_sm4_cbc_cipher_enc_reqs(mb_thread_data *tlv);
void process_mb_sm4_cbc_cipher_dec_reqs(mb_thread_data *tlv);
#endif /* ENABLE_QAT_SW_SM4_CBC */
#endif /* QAT_SW_SM4_CBC_H */
