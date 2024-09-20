/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2024 Intel Corporation.
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
 * @file qat_hw_sha3.h
 *
 * This file provides a interface for SHA3 operations
 *
 *****************************************************************************/

#ifndef QAT_HW_SHA3_H
# define QAT_HW_SHA3_H

# ifdef QAT_OPENSSL_3
#  include <openssl/evp.h>
# else
#  include <openssl/engine.h>
# endif

# include "cpa.h"
# include "cpa_types.h"
# include "cpa_cy_sym.h"
# include "cpa_cy_drbg.h"

# define KECCAK1600_WIDTH 1600
# define SHA3_WORD unsigned int
# define SHA3_CBLOCK      64
# define SHA3_LBLOCK      (SHA3_CBLOCK/4)

/* Digest Size */
# define QAT_SHA3_224_DIGEST_SIZE 28
# define QAT_SHA3_256_DIGEST_SIZE 32
# define QAT_SHA3_384_DIGEST_SIZE 48
# define QAT_SHA3_512_DIGEST_SIZE 64
/*Block Size */
# define QAT_SHA3_224_BLOCK_SIZE 144
# define QAT_SHA3_256_BLOCK_SIZE 136
# define QAT_SHA3_384_BLOCK_SIZE 104
# define QAT_SHA3_512_BLOCK_SIZE 72
/* State Size */
# define QAT_SHA3_224_STATE_SIZE 28
# define QAT_SHA3_256_STATE_SIZE 32
# define QAT_SHA3_384_STATE_SIZE 48
# define QAT_SHA3_512_STATE_SIZE 64

# define QAT_SHA3_224_OFFLOAD_THRESHOLD (100 * QAT_SHA3_224_BLOCK_SIZE)
# define QAT_SHA3_256_OFFLOAD_THRESHOLD (120 * QAT_SHA3_256_BLOCK_SIZE)
# define QAT_SHA3_384_OFFLOAD_THRESHOLD (160 * QAT_SHA3_384_BLOCK_SIZE)
# define QAT_SHA3_512_OFFLOAD_THRESHOLD (200 * QAT_SHA3_512_BLOCK_SIZE)

# define QAT_SHA3_OFFLOAD_THRESHOLD (160 * QAT_SHA3_384_BLOCK_SIZE)

typedef struct SHA3state_st {
   SHA3_WORD A, B, C, D, E, F, G, H;
   SHA3_WORD Nl, Nh;
   SHA3_WORD data[SHA3_LBLOCK];
   unsigned int num;
} SHA3_CTX;

typedef struct {
#ifdef QAT_OPENSSL_PROVIDER
    uint64_t A[5][5];
#endif
    int inst_num;
    int context_params_set; /* True if init called */
    int session_init; /* True if QAT_HW update called */
    unsigned int qat_offloaded; /* True if there was an offload. */

    unsigned char data[QAT_SHA3_OFFLOAD_THRESHOLD]; /* The buffer */
    unsigned int num; /* The data left in buffer */
    unsigned int sw_offload; /* Fallback Flag for small pkt offload */

    CpaCySymSessionSetupData *session_data;
    CpaCySymSessionCtx session_ctx;
    CpaCySymOpData *opd;
    CpaBufferList pSrcBufferList; /* For QAT metadata */
    CpaFlatBuffer src_buffer;
    unsigned char digest_data[EVP_MAX_MD_SIZE];
    int md_size;             /* output length, variable in XOF */
    int qat_svm;
} qat_sha3_ctx;

# ifdef QAT_OPENSSL_PROVIDER
typedef struct qat_keccak_st QAT_KECCAK1600_CTX;
typedef size_t (sha3_absorb_fn)(void *vctx, const void *inp, size_t len);
typedef int (sha3_final_fn)(unsigned char *md, void *vctx);

typedef struct prov_sha3_meth_st
{
    sha3_absorb_fn *absorb;
    sha3_final_fn *final;
} QAT_PROV_SHA3_METHOD;

struct qat_keccak_st {
    uint64_t A[5][5];
    size_t block_size;          /* cached ctx->digest->block_size */
    size_t md_size;             /* output length, variable in XOF */
    size_t bufsz;               /* used bytes in below buffer */
    unsigned char buf[KECCAK1600_WIDTH / 8 - 32];
    unsigned char pad;
    int md_type;
    qat_sha3_ctx *qctx;
    QAT_PROV_SHA3_METHOD meth;

    EVP_MD *sw_md;
    EVP_MD_CTX *sw_md_ctx;
};

int qat_sha3_init(QAT_KECCAK1600_CTX *ctx);
int qat_sha3_cleanup(QAT_KECCAK1600_CTX *ctx);
int qat_sha3_final(QAT_KECCAK1600_CTX *ctx, unsigned char *md);
int qat_sha3_update(QAT_KECCAK1600_CTX *ctx, const void *in, size_t len);
int qat_sha3_copy(QAT_KECCAK1600_CTX *to, const QAT_KECCAK1600_CTX *from);
# endif
typedef struct {
    uint64_t A[5][5];
    size_t block_size;          /* SW cached ctx->digest->block_size */
    size_t md_size;             /* SW output length, variable in XOF */
    size_t num;                 /* SW used bytes in below buffer */
    unsigned char buf[KECCAK1600_WIDTH / 8 - 32];
    unsigned char pad;
} KECCAK1600_CTX;


# define QAT_SHA3_GET_CTX(ctx) \
        ((qat_sha3_ctx *) EVP_MD_CTX_md_data(ctx))

const EVP_MD *qat_create_sha3_meth(int nid, int key_type);

#endif /* QAT_HW_SHA3_H */

