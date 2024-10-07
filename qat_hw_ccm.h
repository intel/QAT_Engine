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
 * @file qat_hw_ccm.h
 *
 * This file provides a interface for AES-CCM operations
 *
 *****************************************************************************/

#ifndef QAT_HW_CCM_H
# define QAT_HW_CCM_H

# ifndef QAT_OPENSSL_PROVIDER
#  include <openssl/engine.h>
# endif
# include <openssl/evp.h>

# include "cpa.h"
# include "cpa_types.h"
# include "cpa_cy_sym.h"
# include "cpa_cy_drbg.h"

# define AES_CCM_IV_LEN      12
# define QAT_AES_CCM_OP_VALUE 15
# define QAT_CCM_IV_WRITE_BUFFER 1
# define QAT_CCM_AAD_WRITE_BUFFER 18

# define QAT_CCM_GET_CTX(ctx) (EVP_CIPHER_CTX_get_cipher_data(ctx))
# define QAT_CCM_GET_ENC(ctx) ((ctx)->enc)

# define QAT_CCM_TLS_TOTAL_IV_LEN (EVP_CCM_TLS_FIXED_IV_LEN + EVP_CCM_TLS_EXPLICIT_IV_LEN)
# define QAT_CCM_TLS_PAYLOADLENGTH_MSB_OFFSET 2
# define QAT_CCM_TLS_PAYLOADLENGTH_LSB_OFFSET 1

/* The length of valid CCM Tag must be between 0 and 16 Bytes */
# define QAT_CCM_TAG_MIN_LEN 0
# define QAT_CCM_TAG_MAX_LEN 16
# define QAT_CCM_IV_MAX_LEN 16

# define QAT_CCM_FLAGS  (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CCM_MODE   \
                         | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_AEAD_CIPHER \
                         | EVP_CIPH_FLAG_CUSTOM_CIPHER                    \
                         | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT)

/* AES-CCM context */
typedef struct qat_aes_ccm_ctx_t {
    /* QAT Session Params */
    int inst_num;
    CpaCySymSessionSetupData *session_data;
    CpaCySymSessionCtx qat_ctx;
    int init_params_set;

    /* This flag is set to 1 when the session has been initialized */
    int is_session_init;

    /* QAT Op Params */
    CpaCySymOpData OpData;

    /* TODO Both buffer point to the same area of memory
     * and the operation is done in place.
     * Why am I using 2 separate buffers instead of one like in CCM sample?
     * Do I need to allocate and use separate metadata?
     */
    CpaBufferList srcBufferList;
    CpaBufferList dstBufferList;
    CpaFlatBuffer srcFlatBuffer;
    CpaFlatBuffer dstFlatBuffer;

    /* -- Crypto -- */

    /* IV that will be used in the next operation:
     * For current operation using oPData.pIv.
     * In the SW engine the IV in the context and the IV used by the cipher
     * are stored in different variables.
     * This is a separate value and can be modified without affecting
     * the current operation.
     * For example: TLS case increment the IV before doing the encryption,
     *  but the current operation still used the not-incremented IV
     */
    Cpa8U next_iv[EVP_MAX_IV_LENGTH];

    /* Length of the IV (it is always 12 Byte for CCM in TLS case */
    unsigned int iv_len;

    /* Flag that indicates whether the IV has been set
     * TODO The value is set correctly but never read and actually used...
     */
    unsigned char iv_set;

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
    int len_set;
    int tag_set;
    int L, M;
    int packet_size;
    int nid;
    void *sw_ctx_cipher_data;
    int qat_svm;
    EVP_CIPHER_CTX *sw_ctx;
    EVP_CIPHER *sw_cipher;
} qat_ccm_ctx;

# ifdef QAT_OPENSSL_PROVIDER
int qat_aes_ccm_init(void *ctx, const unsigned char *inkey,
                     int keylen, const unsigned char *iv, int ivlen, int enc);
int qat_aes_ccm_cipher(void *ctx, unsigned char *out,
                       size_t *padlen, size_t outsize,
                       const unsigned char *in, size_t len);
int qat_aes_ccm_cleanup(void *ctx);
int qat_aes_ccm_ctrl(void *ctx, int type, int arg, void *ptr);
# else
int qat_aes_ccm_init(EVP_CIPHER_CTX *ctx,
                     const unsigned char *inkey,
                     const unsigned char *iv, int enc);
int qat_aes_ccm_cipher(EVP_CIPHER_CTX *ctx,
                       unsigned char *out, const unsigned char *in, size_t len);
int qat_aes_ccm_cleanup(EVP_CIPHER_CTX *ctx);
int qat_aes_ccm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
# endif

#endif                          /* QAT_HW_CCM_H */
