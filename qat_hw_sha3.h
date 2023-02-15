/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022 Intel Corporation.
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

# include <openssl/engine.h>

# include "cpa.h"
# include "cpa_types.h"
# include "cpa_cy_sym.h"
# include "cpa_cy_drbg.h"

# define KECCAK1600_WIDTH 1600
# define SHA3_MDSIZE(bitlen)    (bitlen / 8)
# define KMAC_MDSIZE(bitlen)    2 * (bitlen / 8)
# define SHA3_BLOCKSIZE(bitlen) (KECCAK1600_WIDTH - bitlen * 2) / 8

typedef struct {
    uint64_t A[5][5];
    size_t block_size;          /* cached ctx->digest->block_size */
    size_t md_size;             /* output length, variable in XOF */

    void *sw_ctx_sha3_data;
    int inst_num;
    int context_params_set;
    int session_init;

    CpaCySymSessionSetupData *session_data;
    CpaCySymSessionCtx session_ctx;
    CpaCySymOpData *opd;
    CpaBufferList pSrcBufferList;
    CpaBufferList pDstBufferList;
    CpaFlatBuffer src_buffer[2];
    CpaFlatBuffer dst_buffer[2];
    int  hash_alg;
    int dgst_res_len;
    size_t digest_size;
    unsigned char digest_data[EVP_MAX_MD_SIZE];
    size_t packet_size;
    int update_flag;             /* track qat_sha3_update is called */
}qat_sha3_ctx;

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


const EVP_MD *qat_create_sha3_meth(int nid, int key_type);

#endif /* QAT_HW_SHA3_H */

