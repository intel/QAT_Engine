/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020-2024 Intel Corporation.
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
 * @file qat_hw_gcm.h
 *
 * This file provides a interface for AES-GCM operations
 *
 *****************************************************************************/

#ifndef QAT_HW_GCM_H
#define QAT_HW_GCM_H

# include <openssl/engine.h>

# include "cpa.h"
# include "cpa_types.h"
# include "cpa_cy_sym.h"
# include "cpa_cy_drbg.h"

# define AES_GCM_IV_LEN      12

# define QAT_GCM_GET_CTX(ctx) (EVP_CIPHER_CTX_get_cipher_data(ctx))
# define QAT_GCM_GET_ENC(ctx) ((ctx)->enc)

# define QAT_GCM_TLS_TOTAL_IV_LEN (EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN)
# define QAT_GCM_TLS_PAYLOADLENGTH_MSB_OFFSET 2
# define QAT_GCM_TLS_PAYLOADLENGTH_LSB_OFFSET 1

/* The length of valid GCM Tag must be between 0 and 16 Bytes */
# define QAT_GCM_TAG_MIN_LEN 0
# define QAT_GCM_TAG_MAX_LEN 16

# define QAT_GCM_FLAGS  (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_GCM_MODE   \
                         | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_AEAD_CIPHER \
                         | EVP_CIPH_FLAG_CUSTOM_CIPHER                    \
                         | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT)


/* AES-GCM context */
typedef struct qat_aes_gcm_ctx_t
{
    /* QAT Session Params */
    int inst_num;
    CpaCySymSessionSetupData* session_data;
    CpaCySymSessionCtx qat_ctx;
    int init_params_set;

    /* This flag is set to 1 when the session has been initialized */
    int is_session_init;

    /* QAT Op Params */
    CpaCySymOpData OpData;

    /* TODO Both buffer point to the same area of memory
     * and the operation is done in place.
     * Why am I using 2 separate buffers instead of one like in GCM sample?
     * Do I need to allocate and use separate metadata?
     */
    CpaBufferList srcBufferList;
    CpaBufferList dstBufferList;
    CpaFlatBuffer srcFlatBuffer;
    CpaFlatBuffer dstFlatBuffer;

    /* -- Crypto -- */

    /* Pointer to the IV that is used in the current operation:
     * - In Sync case this points to the contiguous memory buffer that is
     *   sent to the HW
     * - In asynch this point to the static memory in evp_ctx->iv hence it
     *   must not be alloc or free
     */
    Cpa8U *iv;

    /* IV that will be used in the next operation:
     * In the SW engine the IV in the context and the IV used by the cipher
     * are stored in different variables.
     * This is a separate value and can be modified without affecting
     * the current operation.
     * For example: TLS case increment the IV before doing the encryption,
     *  but the current operation still used the not-incremented IV
     */
    Cpa8U next_iv[EVP_MAX_IV_LENGTH];

    /* Length of the IV (it is always 12 Byte for GCM in TLS case */
    unsigned int iv_len;

    /* Flag that indicates whether the IV has been set
     * TODO The value is set correctly but never read and actually used...
     */
    unsigned char iv_set;

    /* This flag is used to control the generation of the IV */
    unsigned char iv_gen;

    /* The tag is saved in evp_ctx->buf */
    int tag_len;

    /* Pointer to AAD.
     * In the TLS case this will contain the TLS header */
    Cpa8U *aad;

    /* -- TLS data -- */

    /* Length of the AAD in the TLS case.
     * This is used like a flag: when Update case this is set to -1*/
    int tls_aad_len;

    /* Size of the meta data for the driver
     * It cannot allocate memory so this must be done by the user application */
    unsigned int meta_size;

    /* Pointer to pCipherKey */
    Cpa8U *cipher_key;

    /* Flag to keep track of key passed */
    int key_set;

    int qat_svm;
} qat_gcm_ctx;

#ifdef QAT_OPENSSL_PROVIDER
int qat_aes_gcm_init(void *ctx, const unsigned char *inkey,
                     int keylen, const unsigned char *iv, int ivlen,
                     int enc);
int qat_aes_gcm_cipher(void *ctx, unsigned char *out,
                       size_t *padlen,const unsigned char *in,
                       size_t len);
int qat_aes_gcm_ctrl(void *ctx, int type, int arg, void *ptr);
int qat_aes_gcm_cleanup(void *ctx);
#else
int qat_aes_gcm_init(EVP_CIPHER_CTX *ctx,
                     const unsigned char *inkey,
                     const unsigned char *iv, int enc);
int qat_aes_gcm_cipher(EVP_CIPHER_CTX *ctx,
                       unsigned char *out,
                       const unsigned char *in, size_t len);
int qat_aes_gcm_cleanup(EVP_CIPHER_CTX *ctx);
int qat_aes_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                     void *ptr);
#endif

#endif /* QAT_HW_GCM_H */
