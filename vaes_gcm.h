/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020 Intel Corporation.
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
 * @file vaes_gcm.h
 *
 * This file provides an interface for engine vectorized AES-GCM
 * cipher operations
 *
 ****************************************************************************/

#ifndef VAES_GCM_H
#define VAES_GCM_H

#include <openssl/evp.h>
#include <openssl/modes.h>
#include <intel-ipsec-mb.h>

#define VAESGCM_COMMON_CIPHER_FLAG EVP_CIPH_FLAG_DEFAULT_ASN1

#define VAESGCM_FLAGS (VAESGCM_COMMON_CIPHER_FLAG | EVP_CIPH_GCM_MODE | EVP_CIPH_CUSTOM_IV)

#define VAESGCM_FLAG                                                           \
    (VAESGCM_FLAGS | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER | \
     EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY)

#define vaesgcm_data(ctx) ((vaesgcm_ctx*)EVP_CIPHER_CTX_get_cipher_data(ctx))

#pragma pack(push, 16)
typedef struct vaesgcm_ctx_t {
    struct gcm_key_data     key_data;
    struct gcm_context_data gcm_ctx;

    int init_flags;

    unsigned int ckey_set;

    unsigned char* tls_aad;
    int            tls_aad_len;
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
}
__attribute__((aligned(64))) vaesgcm_ctx;
#pragma pack(pop)

const EVP_CIPHER *vaesgcm_create_cipher_meth(int nid, int keylen);

int  vaesgcm_init_ipsec_mb_mgr(void);
void vaesgcm_free_ipsec_mb_mgr(void);

void qat_imb_aes_gcm_precomp(int nid, IMB_MGR *ipsec_mgr,
                             const void *key,
                             struct gcm_key_data *key_data_ptr);

void qat_imb_aes_gcm_init_var_iv(int nid, IMB_MGR *ipsec_mgr,
                                struct gcm_key_data *key_data_ptr,
                                struct gcm_context_data *context_data,
                                const uint8_t *iv, const uint64_t iv_len,
                                const uint8_t *aad, const uint64_t aad_len);

void qat_imb_aes_gcm_enc_update(int nid, IMB_MGR *ipsec_mgr,
                                struct gcm_key_data *key_data_ptr,
                                struct gcm_context_data *context_data,
                                uint8_t *out, const uint8_t *in,
                                uint64_t len);

void qat_imb_aes_gcm_dec_update(int nid, IMB_MGR *ipsec_mgr,
                                struct gcm_key_data *key_data_ptr,
                                struct gcm_context_data *context_data,
                                uint8_t *out, const uint8_t *in,
                                uint64_t len);

void qat_imb_aes_gcm_enc_finalize(int nid, IMB_MGR *ipsec_mgr,
                                  const struct gcm_key_data *key_data_ptr,
                                  struct gcm_context_data *context_data,
                                  uint8_t *auth_tag, uint64_t auth_tag_len);

void qat_imb_aes_gcm_dec_finalize(int nid, IMB_MGR *ipsec_mgr,
                                  const struct gcm_key_data *key_data_ptr,
                                  struct gcm_context_data *context_data,
                                  uint8_t *auth_tag, uint64_t auth_tag_len);

#endif
