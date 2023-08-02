/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2023 Intel Corporation.
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
 * @file qat_hw_sm4_cbc.h
 *
 * This file provides an interface for engine SM4-CBC operations
 *
 *****************************************************************************/

#ifndef QAT_HW_SM4_CBC_H
# define QAT_HW_SM4_CBC_H

#ifdef QAT_HW

#ifndef SM4_BLOCK_SIZE
# define SM4_BLOCK_SIZE             16
#endif

# ifdef ENABLE_QAT_HW_SM4_CBC
# include <openssl/engine.h>
# include <openssl/ssl.h>
# include <openssl/crypto.h>

# include "cpa.h"
# include "cpa_types.h"
# include "cpa_cy_sym.h"
#ifdef ENABLE_QAT_SW_SM4_CBC
#  include "qat_sw_sm4_cbc.h"
#endif

#ifndef SM4_KEY_SIZE
# define SM4_KEY_SIZE               16
#endif

# define SM4_CBC_IV_LEN             16

# define INIT_SM4_QAT_CTX_INIT      0x0001
# define INIT_SM4_QAT_SESSION_INIT  0x0002
# define SM4_CBC_COEXIST_QAT_SW_MIN_PKT_LEN 256
# define SM4_CBC_COEXIST_QAT_SW_MAX_PKT_LEN 1024

# define QAT_COMMON_CIPHER_FLAG     EVP_CIPH_FLAG_DEFAULT_ASN1
# define QAT_CBC_FLAGS              (QAT_COMMON_CIPHER_FLAG | \
                                     EVP_CIPH_CBC_MODE      | \
                                     EVP_CIPH_CUSTOM_IV)

# define qat_sm4_get_cipher_data(ctx) \
         ((qat_sm4_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx))

# define INIT_SM4_CLEAR_ALL_FLAGS(qctx)  ((qctx)->init_flags = 0)
# define INIT_SM4_SET_FLAG(qctx, f)      ((qctx)->init_flags |= (f))
# define INIT_SM4_CLEAR_FLAG(qctx, f)    ((qctx)->init_flags &= ~(f))
# define INIT_SM4_IS_FLAG_SET(qctx,f)    ((qctx)->init_flags & (f))

typedef struct qat_sm4_op_params_t {
    CpaCySymOpData op_data;
    CpaBufferList src_sgl;
    CpaBufferList dst_sgl;
    CpaFlatBuffer src_fbuf;
    CpaFlatBuffer dst_fbuf;
} qat_sm4_op_params;

typedef struct qat_sm4_ctx_t {
    /* Pointer to context cipher data (ctx->cipher_data) that will be used by
     * Small packet offload feature and the s/w fallback feature. */
    void *sw_ctx_cipher_data;

    /* QAT Session Params */
    int inst_num;
    CpaCySymSessionSetupData *session_data;
    CpaCySymSessionCtx session_ctx;
    int init_flags;

    qat_sm4_op_params *op;
    unsigned int fallback;
} qat_sm4_ctx;

#ifdef ENABLE_QAT_SW_SM4_CBC
typedef struct {
    qat_sm4_ctx sm4cbc_qat_hw_ctx;
    SM4_CBC_CTX sm4cbc_qat_sw_ctx;
} sm4cbc_coexistence_ctx;
#endif

extern CpaStatus qat_sym_perform_op(int inst_num,
                             void *pCallbackTag,
                             const CpaCySymOpData * pOpData,
                             const CpaBufferList * pSrcBuffer,
                             CpaBufferList * pDstBuffer,
                             CpaBoolean * pVerifyResult);
int qat_sm4_cbc_init(EVP_CIPHER_CTX *ctx,
                                    const unsigned char *inkey,
                                    const unsigned char *iv, int enc);
int qat_sm4_cbc_cleanup(EVP_CIPHER_CTX *ctx);
int qat_sm4_cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                  const unsigned char *in, size_t len);

# endif /* ENABLE_QAT_HW_SM4_CBC */
# endif /* QAT_HW */
#endif  /* QAT_HW_SM4_H */
