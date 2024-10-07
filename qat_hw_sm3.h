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
 * @file qat_hw_sm3.h
 *
 * This file provides a interface for SM3 operations
 *
 *****************************************************************************/

#ifndef QAT_HW_SM3_H
# define QAT_HW_SM3_H

#ifndef QAT_OPENSSL_PROVIDER
# include <openssl/engine.h>
#endif
# include <openssl/evp.h>

# include "cpa.h"
# include "cpa_types.h"
# include "cpa_cy_sym.h"
# include "cpa_cy_drbg.h"

# ifdef ENABLE_QAT_HW_SM3

/* Digest Size */
#  define QAT_SM3_DIGEST_SIZE 32
/*Block Size */
#  define QAT_SM3_BLOCK_SIZE 64
/* State Size */
#  define QAT_SM3_STATE_SIZE 32

/* Min 260x to met 16k record offload, 16461 bytes in bulk crypto test */
#  define QAT_SM3_OFFLOAD_THRESHOLD (260 * QAT_SM3_BLOCK_SIZE)

#  define SM3_DIGEST_LENGTH 32
#  define SM3_WORD unsigned int

#  define SM3_CBLOCK      64
#  define SM3_LBLOCK      (SM3_CBLOCK/4)

typedef struct SM3state_st {
    SM3_WORD A, B, C, D, E, F, G, H;
    SM3_WORD Nl, Nh;
    SM3_WORD data[SM3_LBLOCK];
    unsigned int num;
} SM3_CTX;

typedef struct {
    int inst_num;
    int context_params_set;     /* True if init called */
    int qat_offloaded;          /* True if there was an offload. */

    int *rc_refs;               /* The count of the resource reference */

    int *data_refs;             /* The count of the resource reference */
    unsigned char *data;        /* The buffer */
    unsigned int num;           /* The data left in buffer */
    unsigned int rcv_count;     /* The data received */

    CpaCySymSessionSetupData *session_data;
    CpaCySymSessionCtx session_ctx;
    CpaCySymOpData *pOpData;
    CpaBufferList pSrcBufferList; /* For QAT metadata */
    unsigned char *digest_data;
    EVP_MD *sw_md;
    EVP_MD_CTX *sw_md_ctx;
    int qat_svm;
} QAT_SM3_CTX;

/* Totally 3 memory sections in application data, common EVP_MD,
   SM3_CTX used for SM3 software, and QAT_SM3_CTX for QAT_HW */
#  define QAT_SM3_GET_CTX(ctx) \
    ((QAT_SM3_CTX *) (EVP_MD_CTX_md_data(ctx) + sizeof(SM3_CTX)))

const EVP_MD *qat_hw_create_sm3_meth(int nid, int key_type);

#  ifndef QAT_OPENSSL_PROVIDER
int qat_hw_sm3_init(EVP_MD_CTX *ctx);
int qat_hw_sm3_update(EVP_MD_CTX *ctx, const void *in, size_t len);
int qat_hw_sm3_final(EVP_MD_CTX *ctx, unsigned char *md);
#  else
int qat_hw_sm3_init(void *ctx);
int qat_hw_sm3_update(void *ctx, const void *in, size_t len);
int qat_hw_sm3_copy(QAT_SM3_CTX *to, const QAT_SM3_CTX *from);
int qat_hw_sm3_final(void *ctx, unsigned char *md);
int qat_hw_sm3_cleanup(QAT_SM3_CTX *ctx);
#  endif /* QAT_OPENSSL_PROVIDER */
# endif                         /* ENABLE_QAT_HW_SM3 */
#endif                          /* QAT_HW_SM3_H */
