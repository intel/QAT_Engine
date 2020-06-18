/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2020 Intel Corporation.
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

/*
 * This file contains modified code from OpenSSL/BoringSSL used
 * in order to run certain operations in constant time.
 * It is subject to the following license:
 */

/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*****************************************************************************
 * @file qat_ciphers.c
 *
 * This file contains the engine implementations for cipher operations
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <pthread.h>
#include <signal.h>
#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "cmn_mem_drv_inf.h"
#endif

#include "qat_utils.h"
#include "e_qat.h"
#include "qat_callback.h"
#include "qat_polling.h"
#include "qat_events.h"
#include "e_qat_err.h"

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_sym.h"
#include "qat_ciphers.h"
#include "qat_constant_time.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/tls1.h>
#include <openssl/async.h>
#include <openssl/lhash.h>
#include <openssl/ssl.h>
#include <string.h>

#ifdef OPENSSL_ENABLE_QAT_CIPHERS
# ifdef OPENSSL_DISABLE_QAT_CIPHERS
#  undef OPENSSL_DISABLE_QAT_CIPHERS
# endif
#endif

#define GET_TLS_HDR(qctx, i)     ((qctx)->aad[(i)])
#define GET_TLS_VERSION(hdr)     (((hdr)[9]) << QAT_BYTE_SHIFT | (hdr)[10])
#define GET_TLS_PAYLOAD_LEN(hdr) (((((hdr)[11]) << QAT_BYTE_SHIFT) & 0xff00) | \
                                  ((hdr)[12] & 0x00ff))
#define SET_TLS_PAYLOAD_LEN(hdr, len)   \
                do { \
                    hdr[11] = (len & 0xff00) >> QAT_BYTE_SHIFT; \
                    hdr[12] = len & 0xff; \
                } while(0)

#define FLATBUFF_ALLOC_AND_CHAIN(b1, b2, len) \
                do { \
                    (b1).pData = qaeCryptoMemAlloc(len, __FILE__, __LINE__); \
                    (b2).pData = (b1).pData; \
                    (b1).dataLenInBytes = len; \
                    (b2).dataLenInBytes = len; \
                } while(0)

# define GET_SW_CIPHER(ctx) \
    qat_chained_cipher_sw_impl(EVP_CIPHER_CTX_nid((ctx)))


#define GET_SW_NON_CHAINED_CIPHER(ctx) \
    get_cipher_from_nid(EVP_CIPHER_CTX_nid((ctx)))

#define DEBUG_PPL DEBUG
#ifndef OPENSSL_DISABLE_QAT_CIPHERS
static int qat_chained_ciphers_init(EVP_CIPHER_CTX *ctx,
                                    const unsigned char *inkey,
                                    const unsigned char *iv, int enc);
static int qat_chained_ciphers_cleanup(EVP_CIPHER_CTX *ctx);
static int qat_chained_ciphers_do_cipher(EVP_CIPHER_CTX *ctx,
                                         unsigned char *out,
                                         const unsigned char *in, size_t len);
static int qat_chained_ciphers_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                    void *ptr);

#endif
static CpaStatus qat_sym_perform_op(int inst_num,
                                    void *pCallbackTag,
                                    const CpaCySymOpData * pOpData,
                                    const CpaBufferList * pSrcBuffer,
                                    CpaBufferList * pDstBuffer,
                                    CpaBoolean * pVerifyResult);

int qatPerformOpRetries = 0;

/* Setup template for Session Setup Data as most of the fields
 * are constant. The constant values of some of the fields are
 * chosen for Encryption operation.
 */
static const CpaCySymSessionSetupData template_ssd = {
    .sessionPriority = CPA_CY_PRIORITY_HIGH,
    .symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING,
    .cipherSetupData = {
                        .cipherAlgorithm = CPA_CY_SYM_CIPHER_AES_CBC,
                        .cipherKeyLenInBytes = 0,
                        .pCipherKey = NULL,
                        .cipherDirection = CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT,
                        },
    .hashSetupData = {
                      .hashAlgorithm = CPA_CY_SYM_HASH_SHA1,
                      .hashMode = CPA_CY_SYM_HASH_MODE_AUTH,
                      .digestResultLenInBytes = 0,
                      .authModeSetupData = {
                                            .authKey = NULL,
                                            .authKeyLenInBytes = HMAC_KEY_SIZE,
                                            .aadLenInBytes = 0,
                                            },
                      .nestedModeSetupData = {0},
                      },
    .algChainOrder = CPA_CY_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER,
    .digestIsAppended = CPA_TRUE,
    .verifyDigest = CPA_FALSE,
    .partialsNotRequired = CPA_TRUE,
};

static const CpaCySymOpData template_opData = {
    .sessionCtx = NULL,
    .packetType = CPA_CY_SYM_PACKET_TYPE_FULL,
    .pIv = NULL,
    .ivLenInBytes = 0,
    .cryptoStartSrcOffsetInBytes = QAT_BYTE_ALIGNMENT,
    .messageLenToCipherInBytes = 0,
    .hashStartSrcOffsetInBytes = QAT_BYTE_ALIGNMENT - TLS_VIRT_HDR_SIZE,
    .messageLenToHashInBytes = 0,
    .pDigestResult = NULL,
    .pAdditionalAuthData = NULL
};

static inline int get_digest_len(int nid)
{
    return (((nid) == NID_aes_128_cbc_hmac_sha1 ||
             (nid) == NID_aes_256_cbc_hmac_sha1) ?
            SHA_DIGEST_LENGTH : SHA256_DIGEST_LENGTH);
}

static inline const EVP_CIPHER *qat_chained_cipher_sw_impl(int nid)
{
    switch (nid) {
        case NID_aes_128_cbc_hmac_sha1:
            return EVP_aes_128_cbc_hmac_sha1();
        case NID_aes_256_cbc_hmac_sha1:
            return EVP_aes_256_cbc_hmac_sha1();
        case NID_aes_128_cbc_hmac_sha256:
            return EVP_aes_128_cbc_hmac_sha256();
        case NID_aes_256_cbc_hmac_sha256:
            return EVP_aes_256_cbc_hmac_sha256();
        default:
            WARN("Invalid nid %d\n", nid);
            return NULL;
    }
}

static inline const EVP_CIPHER *get_cipher_from_nid(int nid)
{
    switch (nid) {
        case NID_aes_128_cbc_hmac_sha1:
        case NID_aes_128_cbc_hmac_sha256:
            return EVP_aes_128_cbc();
        case NID_aes_256_cbc_hmac_sha1:
        case NID_aes_256_cbc_hmac_sha256:
            return EVP_aes_256_cbc();
        default:
            WARN("Invalid nid %d\n", nid);
            return NULL;
    }
}


static inline void qat_chained_ciphers_free_qop(qat_op_params **pqop,
        unsigned int *num_elem)
{
    unsigned int i = 0;
    qat_op_params *qop = NULL;
    if (pqop != NULL && ((qop = *pqop) != NULL)) {
        for (i = 0; i < *num_elem; i++) {
            QAT_CHK_QMFREE_FLATBUFF(qop[i].src_fbuf[0]);
            QAT_CHK_QMFREE_FLATBUFF(qop[i].src_fbuf[1]);
            QAT_QMEMFREE_BUFF(qop[i].src_sgl.pPrivateMetaData);
            QAT_QMEMFREE_BUFF(qop[i].dst_sgl.pPrivateMetaData);
            QAT_QMEMFREE_BUFF(qop[i].op_data.pIv);
        }
        OPENSSL_free(qop);
        *pqop = NULL;
        *num_elem = 0;
    }
}

const EVP_CIPHER *qat_create_cipher_meth(int nid, int keylen)
{
#ifndef OPENSSL_DISABLE_QAT_CIPHERS
    EVP_CIPHER *c = NULL;
    int res = 1;

    if ((c = EVP_CIPHER_meth_new(nid, AES_BLOCK_SIZE, keylen)) == NULL) {
        WARN("Failed to allocate cipher methods for nid %d\n", nid);
        return NULL;
    }

    res &= EVP_CIPHER_meth_set_iv_length(c, AES_IV_LEN);
    res &= EVP_CIPHER_meth_set_flags(c, QAT_CHAINED_FLAG);
    res &= EVP_CIPHER_meth_set_init(c, qat_chained_ciphers_init);
    res &= EVP_CIPHER_meth_set_do_cipher(c, qat_chained_ciphers_do_cipher);
    res &= EVP_CIPHER_meth_set_cleanup(c, qat_chained_ciphers_cleanup);
    res &= EVP_CIPHER_meth_set_impl_ctx_size(c, sizeof(qat_chained_ctx));
    res &= EVP_CIPHER_meth_set_set_asn1_params(c, EVP_CIPH_FLAG_DEFAULT_ASN1 ?
                                               NULL : EVP_CIPHER_set_asn1_iv);
    res &= EVP_CIPHER_meth_set_get_asn1_params(c, EVP_CIPH_FLAG_DEFAULT_ASN1 ?
                                               NULL : EVP_CIPHER_get_asn1_iv);
    res &= EVP_CIPHER_meth_set_ctrl(c, qat_chained_ciphers_ctrl);

    if (res == 0) {
        WARN("Failed to set cipher methods for nid %d\n", nid);
        EVP_CIPHER_meth_free(c);
        c = NULL;
    }

    return c;
#else
    return qat_chained_cipher_sw_impl(nid);
#endif
}

#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
# define CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT 2048

typedef struct cipher_threshold_table_s {
    int nid;
    int threshold;
} PKT_THRESHOLD;

static PKT_THRESHOLD qat_pkt_threshold_table[] = {
    {NID_aes_128_cbc_hmac_sha1, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_256_cbc_hmac_sha1, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_128_cbc_hmac_sha256,
     CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_256_cbc_hmac_sha256, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT}
};

static int pkt_threshold_table_size =
    (sizeof(qat_pkt_threshold_table) / sizeof(qat_pkt_threshold_table[0]));

int qat_pkt_threshold_table_set_threshold(const char *cn,
                                          int threshold)
{
    int i = 0;
    int nid;

    if(threshold < 0)
        threshold = 0;
    else if (threshold > 16384)
        threshold = 16384;

    DEBUG("Set small packet threshold for %s: %d\n", cn, threshold);

    nid = OBJ_sn2nid(cn);
    do {
        if (qat_pkt_threshold_table[i].nid == nid) {
            qat_pkt_threshold_table[i].threshold = threshold;
            return 1;
        }
    } while (++i < pkt_threshold_table_size);

    WARN("nid %d not found in threshold table\n", nid);
    return 0;
}

static inline int qat_pkt_threshold_table_get_threshold(int nid)
{
    int i = 0;
    do {
        if (qat_pkt_threshold_table[i].nid == nid) {
            return qat_pkt_threshold_table[i].threshold;
        }
    } while (++i < pkt_threshold_table_size);

    WARN("nid %d not found in threshold table", nid);
    return 0;
}
#endif

/******************************************************************************
* function:
*         qat_chained_callbackFn(void *callbackTag, CpaStatus status,
*                        const CpaCySymOp operationType, void *pOpData,
*                        CpaBufferList * pDstBuffer, CpaBoolean verifyResult)
*

* @param pCallbackTag  [IN] -  Opaque value provided by user while making
*                              individual function call. Cast to op_done_pipe_t.
* @param status        [IN] -  Status of the operation.
* @param operationType [IN] -  Identifies the operation type requested.
* @param pOpData       [IN] -  Pointer to structure with input parameters.
* @param pDstBuffer    [IN] -  Destination buffer to hold the data output.
* @param verifyResult  [IN] -  Used to verify digest result.
*
* description:
*   Callback function used by chained ciphers with pipeline support. This
*   function is called when operation is completed for each pipeline. However
*   the paused job is woken up when all the pipelines have been proccessed.
*
******************************************************************************/
static void qat_chained_callbackFn(void *callbackTag, CpaStatus status,
                                   const CpaCySymOp operationType,
                                   void *pOpData, CpaBufferList *pDstBuffer,
                                   CpaBoolean verifyResult)
{
    ASYNC_JOB *job = NULL;
    op_done_pipe_t *opdone = (op_done_pipe_t *)callbackTag;
    CpaBoolean res = CPA_FALSE;

    if (opdone == NULL) {
        WARN("Callback Tag NULL\n");
        return;
    }

    opdone->num_processed++;

    res = (status == CPA_STATUS_SUCCESS) && verifyResult ? CPA_TRUE : CPA_FALSE;

    /* If any single pipe processing failed, the entire operation
     * is treated as failure. The default value of opDone.verifyResult
     * is TRUE. Change it to false on Failure.
     */
    if (res == CPA_FALSE) {
        WARN("Pipe %u failed (status %d, verifyResult %d)\n",
              opdone->num_processed, status, verifyResult);
        opdone->opDone.verifyResult = CPA_FALSE;
    }

    /* The QAT API guarantees submission order for request
     * i.e. first in first out. If not all requests have been
     * submitted or processed, wait for more callbacks.
     */
    if ((opdone->num_submitted != opdone->num_pipes) ||
        (opdone->num_submitted != opdone->num_processed))
        return;

    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_cipher_pipeline_requests_in_flight);
    }

    /* Cache job pointer to avoid a race condition if opdone gets cleaned up
     * in the calling thread.
     */
    job = (ASYNC_JOB *)opdone->opDone.job;

    /* Mark job as done when all the requests have been submitted and
     * subsequently processed.
     */
    opdone->opDone.flag = 1;
    if (job) {
       qat_wake_job(job, ASYNC_STATUS_OK);
    }
}

/******************************************************************************
* function:
*         qat_setup_op_params(EVP_CIPHER_CTX *ctx)
*
* @param qctx    [IN]  - pointer to existing qat_chained_ctx
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function initialises the flatbuffer and flat buffer list for use.
*
******************************************************************************/
static int qat_setup_op_params(EVP_CIPHER_CTX *ctx)
{
    CpaCySymOpData *opd = NULL;
    Cpa32U msize = 0;
    qat_chained_ctx *qctx = qat_chained_data(ctx);
    int i = 0;
    unsigned int start;

    /* When no pipelines are used, numpipes = 1. The actual number of pipes are
     * not known until the start of do_cipher.
     */
    if (PIPELINE_USED(qctx)) {
        /* When Pipes have been previously used, the memory has been allocated
         * for max supported pipes although initialised only for numpipes.
         */
        start = qctx->npipes_last_used;
    } else {
        start = 1;
        /* When the context switches from using no pipes to using pipes,
         * free the previous allocated memory.
         */
        if (qctx->qop != NULL && qctx->qop_len < qctx->numpipes) {
            qat_chained_ciphers_free_qop(&qctx->qop, &qctx->qop_len);
            DEBUG_PPL("[%p] qop memory freed\n", ctx);
        }
    }

    /* Allocate memory for qop depending on whether pipes are used or not.
     * In case of pipes, allocate for the maximum supported pipes.
     */
    if (qctx->qop == NULL) {
        if (PIPELINE_USED(qctx)) {
            WARN("Pipeline used but no data allocated. Possible memory leak\n");
        }

        qctx->qop_len = qctx->numpipes > 1 ? QAT_MAX_PIPELINES : 1;
        qctx->qop = (qat_op_params *) OPENSSL_zalloc(sizeof(qat_op_params)
                                                     * qctx->qop_len);
        if (qctx->qop == NULL) {
            WARN("Unable to allocate memory[%lu bytes] for qat op params\n",
                 sizeof(qat_op_params) * qctx->qop_len);
            return 0;
        }
        /* start from 0 as New array of qat_op_params */
        start = 0;
    }

    for (i = start; i < qctx->numpipes; i++) {
        /* This is a whole block the size of the memory alignment. If the
         * alignment was to become smaller than the header size
         * (TLS_VIRT_HEADER_SIZE) which is unlikely then we would need to add
         * some more logic here to work out how many blocks of size
         * QAT_BYTE_ALIGNMENT we need to allocate to fit the header in.
         */
        FLATBUFF_ALLOC_AND_CHAIN(qctx->qop[i].src_fbuf[0],
                                 qctx->qop[i].dst_fbuf[0], QAT_BYTE_ALIGNMENT);
        if (qctx->qop[i].src_fbuf[0].pData == NULL) {
            WARN("Unable to allocate memory for TLS header\n");
            goto err;
        }
        memset(qctx->qop[i].src_fbuf[0].pData, 0, QAT_BYTE_ALIGNMENT);

        qctx->qop[i].src_fbuf[1].pData = NULL;
        qctx->qop[i].dst_fbuf[1].pData = NULL;

        qctx->qop[i].src_sgl.numBuffers = 2;
        qctx->qop[i].src_sgl.pBuffers = qctx->qop[i].src_fbuf;
        qctx->qop[i].src_sgl.pUserData = NULL;
        qctx->qop[i].src_sgl.pPrivateMetaData = NULL;

        qctx->qop[i].dst_sgl.numBuffers = 2;
        qctx->qop[i].dst_sgl.pBuffers = qctx->qop[i].dst_fbuf;
        qctx->qop[i].dst_sgl.pUserData = NULL;
        qctx->qop[i].dst_sgl.pPrivateMetaData = NULL;

        DEBUG("Pipe [%d] inst_num = %d\n", i, qctx->inst_num);
        DEBUG("Pipe [%d] No of buffers = %d\n", i, qctx->qop[i].src_sgl.numBuffers);

        /* setup meta data for buffer lists */
        if (msize == 0 &&
            cpaCyBufferListGetMetaSize(qat_instance_handles[qctx->inst_num],
                                       qctx->qop[i].src_sgl.numBuffers,
                                       &msize) != CPA_STATUS_SUCCESS) {
            WARN("cpaCyBufferListGetBufferSize failed.\n");
            goto err;
        }

        DEBUG("Pipe [%d] Size of meta data = %d\n", i, msize);

        if (msize) {
            qctx->qop[i].src_sgl.pPrivateMetaData =
                qaeCryptoMemAlloc(msize, __FILE__, __LINE__);
            qctx->qop[i].dst_sgl.pPrivateMetaData =
                qaeCryptoMemAlloc(msize, __FILE__, __LINE__);
            if (qctx->qop[i].src_sgl.pPrivateMetaData == NULL ||
                qctx->qop[i].dst_sgl.pPrivateMetaData == NULL) {
                WARN("QMEM alloc failed for PrivateData\n");
                goto err;
            }
        }

        opd = &qctx->qop[i].op_data;

        /* Copy the opData template */
        memcpy(opd, &template_opData, sizeof(template_opData));

        /* Update Opdata */
        opd->sessionCtx = qctx->session_ctx;
        opd->pIv = qaeCryptoMemAlloc(EVP_CIPHER_CTX_iv_length(ctx),
                                     __FILE__, __LINE__);
        if (opd->pIv == NULL) {
            WARN("QMEM Mem Alloc failed for pIv for pipe %d.\n", i);
            goto err;
        }

        opd->ivLenInBytes = (Cpa32U) EVP_CIPHER_CTX_iv_length(ctx);
    }

    DEBUG_PPL("[%p] qop setup for %u elements\n", ctx, qctx->qop_len);
    return 1;

 err:
    qat_chained_ciphers_free_qop(&qctx->qop, &qctx->qop_len);
    return 0;
}

/******************************************************************************
* function:
*         qat_chained_ciphers_init(EVP_CIPHER_CTX *ctx,
*                                    const unsigned char *inkey,
*                                    const unsigned char *iv,
*                                    int enc)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param inKey  [IN]  - input cipher key
* @param iv     [IN]  - initialisation vector
* @param enc    [IN]  - 1 encrypt 0 decrypt
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function initialises the cipher and hash algorithm parameters for this
*  EVP context.
*
******************************************************************************/
int qat_chained_ciphers_init(EVP_CIPHER_CTX *ctx,
                             const unsigned char *inkey,
                             const unsigned char *iv, int enc)
{
    CpaCySymSessionSetupData *ssd = NULL;
    Cpa32U sctx_size = 0;
    CpaCySymSessionCtx sctx = NULL;
    CpaStatus sts = 0;
    qat_chained_ctx *qctx = NULL;
    unsigned char *ckey = NULL;
    int ckeylen;
    int dlen;
    int ret = 0;

    if (ctx == NULL || inkey == NULL) {
        WARN("ctx or inkey is NULL.\n");
        return 0;
    }

    qctx = qat_chained_data(ctx);
    if (qctx == NULL) {
        WARN("qctx is NULL.\n");
        return 0;
    }

    INIT_SEQ_CLEAR_ALL_FLAGS(qctx);

    if (iv != NULL)
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv,
               EVP_CIPHER_CTX_iv_length(ctx));
    else
        memset(EVP_CIPHER_CTX_iv_noconst(ctx), 0,
               EVP_CIPHER_CTX_iv_length(ctx));

    ckeylen = EVP_CIPHER_CTX_key_length(ctx);
    ckey = OPENSSL_malloc(ckeylen);
    if (ckey == NULL) {
        WARN("Unable to allocate memory for Cipher key.\n");
        return 0;
    }
    memcpy(ckey, inkey, ckeylen);

    memset(qctx, 0, sizeof(*qctx));

    qctx->numpipes = 1;
    qctx->total_op = 0;
    qctx->npipes_last_used = 1;
    qctx->fallback = 0;

    qctx->hmac_key = OPENSSL_zalloc(HMAC_KEY_SIZE);
    if (qctx->hmac_key == NULL) {
        WARN("Unable to allocate memory for HMAC Key\n");
        goto err;
    }

    const EVP_CIPHER *sw_cipher = GET_SW_CIPHER(ctx);
    unsigned int sw_size = EVP_CIPHER_impl_ctx_size(sw_cipher);
    if (sw_size != 0) {
        qctx->sw_ctx_cipher_data = OPENSSL_zalloc(sw_size);
        if (qctx->sw_ctx_cipher_data == NULL) {
            WARN("Unable to allocate memory [%u bytes] for sw_ctx_cipher_data\n",
                 sw_size);
            goto err;
        }
    }

    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
    /* Run the software init function */
    ret = EVP_CIPHER_meth_get_init(sw_cipher)(ctx, inkey, iv, enc);
    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
    if (ret != 1)
        goto err;
    if (qat_get_qat_offload_disabled()) {
        /*
         * Setting qctx->fallback as a flag for the other functions.
         * This means in the other functions (and in the err section in this function)
         * we no longer need to check qat_get_qat_offload_disabled() but just check
         * the fallback flag instead.  This has the added benefit that even if
         * the engine control message to enable HW offload is sent it will not affect
         * requests that have already been init'd, they will continue to use SW until
         * the request is complete, i.e. no race condition.
         */
        qctx->fallback = 1;
        goto err;
    }

    ssd = OPENSSL_malloc(sizeof(CpaCySymSessionSetupData));
    if (ssd == NULL) {
        WARN("Failed to allocate session setup data\n");
        goto err;
    }
    qctx->session_data = ssd;

    /* Copy over the template for most of the values */
    memcpy(ssd, &template_ssd, sizeof(template_ssd));

    /* Change constant values for decryption */
    if (!enc) {
        ssd->cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;
        ssd->algChainOrder = CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH;
        ssd->verifyDigest = CPA_TRUE;
    }

    ssd->cipherSetupData.cipherKeyLenInBytes = ckeylen;
    ssd->cipherSetupData.pCipherKey = ckey;

    dlen = get_digest_len(EVP_CIPHER_CTX_nid(ctx));

    ssd->hashSetupData.digestResultLenInBytes = dlen;

    if (dlen != SHA_DIGEST_LENGTH)
        ssd->hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA256;

    ssd->hashSetupData.authModeSetupData.authKey = qctx->hmac_key;

    qctx->inst_num = get_next_inst_num();
    if (qctx->inst_num == QAT_INVALID_INSTANCE) {
        WARN("Failed to get a QAT instance.\n");
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
            qctx->fallback = 1;
        }
        goto err;
    }

    DEBUG("inst_num = %d\n", qctx->inst_num);
    DUMP_SESSION_SETUP_DATA(ssd);
    sts = cpaCySymSessionCtxGetSize(qat_instance_handles[qctx->inst_num], ssd, &sctx_size);

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("Failed to get SessionCtx size.\n");
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           qctx->inst_num,
                           qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            qctx->fallback = 1;
        }
        goto err;
    }

    DEBUG("Size of session ctx = %d\n", sctx_size);
    sctx = (CpaCySymSessionCtx) qaeCryptoMemAlloc(sctx_size, __FILE__,
                                                  __LINE__);
    if (sctx == NULL) {
        WARN("QMEM alloc failed for session ctx!\n");
        goto err;
    }

    qctx->session_ctx = sctx;

    qctx->qop = NULL;
    qctx->qop_len = 0;

    INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_QAT_CTX_INIT);

    DEBUG_PPL("[%p] qat chained cipher ctx %p initialised\n",ctx, qctx);
    return 1;

 err:
/* NOTE: no init seq flags will have been set if this 'err:' label code section is entered. */
    QAT_CLEANSE_FREE_BUFF(ckey, ckeylen);
    QAT_CLEANSE_FREE_BUFF(qctx->hmac_key, HMAC_KEY_SIZE);
    if (ssd != NULL)
        OPENSSL_free(ssd);
    qctx->session_data = NULL;
    QAT_QMEMFREE_BUFF(qctx->session_ctx);
    if ((qctx->fallback == 1) && (qctx->sw_ctx_cipher_data != NULL) && (ret == 1)) {
        DEBUG("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        return ret; /* result returned from running software init function */
    }
    if (qctx->sw_ctx_cipher_data != NULL) {
        OPENSSL_free(qctx->sw_ctx_cipher_data);
        qctx->sw_ctx_cipher_data = NULL;
    }
    return 0;
}

/******************************************************************************
* function:
*    qat_chained_ciphers_ctrl(EVP_CIPHER_CTX *ctx,
*                             int type, int arg, void *ptr)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param type   [IN]  - type of request either
*                       EVP_CTRL_AEAD_SET_MAC_KEY or EVP_CTRL_AEAD_TLS1_AAD
* @param arg    [IN]  - size of the pointed to by ptr
* @param ptr    [IN]  - input buffer contain the necessary parameters
*
* @retval x      The return value is dependent on the type of request being made
*       EVP_CTRL_AEAD_SET_MAC_KEY return of 1 is success
*       EVP_CTRL_AEAD_TLS1_AAD return value indicates the amount fo padding to
*               be applied to the SSL/TLS record
* @retval -1     function failed
*
* description:
*    This function is a generic control interface provided by the EVP API. For
*  chained requests this interface is used fro setting the hmac key value for
*  authentication of the SSL/TLS record. The second type is used to specify the
*  TLS virtual header which is used in the authentication calculationa nd to
*  identify record payload size.
*
******************************************************************************/
int qat_chained_ciphers_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    qat_chained_ctx *qctx = NULL;
    unsigned char *hmac_key = NULL;
    CpaCySymSessionSetupData *ssd = NULL;
    SHA_CTX hkey1;
    SHA256_CTX hkey256;
    CpaStatus sts;
    char *hdr = NULL;
    unsigned int len = 0;
    int retVal = 0;
    int retVal_sw = 0;
    int dlen = 0;

    if (ctx == NULL) {
        WARN("ctx parameter is NULL.\n");
        return -1;
    }

    qctx = qat_chained_data(ctx);

    if (qctx == NULL) {
        WARN("qctx is NULL.\n");
        return -1;
    }

    if (qctx->fallback == 1)
        goto sw_ctrl;

    dlen = get_digest_len(EVP_CIPHER_CTX_nid(ctx));

    switch (type) {
        case EVP_CTRL_AEAD_SET_MAC_KEY:
            hmac_key = qctx->hmac_key;
            ssd = qctx->session_data;

            memset(hmac_key, 0, HMAC_KEY_SIZE);

            if (arg > HMAC_KEY_SIZE) {
                if (dlen == SHA_DIGEST_LENGTH) {
                    SHA1_Init(&hkey1);
                    SHA1_Update(&hkey1, ptr, arg);
                    SHA1_Final(hmac_key, &hkey1);
                } else {
                    SHA256_Init(&hkey256);
                    SHA256_Update(&hkey256, ptr, arg);
                    SHA256_Final(hmac_key, &hkey256);
                }
            } else {
                memcpy(hmac_key, ptr, arg);
                ssd->hashSetupData.authModeSetupData.authKeyLenInBytes = arg;
            }

            INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_HMAC_KEY_SET);

            DEBUG("inst_num = %d\n", qctx->inst_num);
            DUMP_SESSION_SETUP_DATA(ssd);
            DEBUG("session_ctx = %p\n", qctx->session_ctx);

            if (!(is_instance_available(qctx->inst_num))) {
                WARN("No QAT instance available so not creating session.\n");
                if (qat_get_sw_fallback_enabled()) {
                    CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                    qctx->fallback = 1; /* Set fallback even if already set */
                }
                else {
                    WARN("- No QAT instance available and s/w fallback not enabled.\n");
                    retVal = 0; /* Fail if software fallback not enabled. */
                }
            } else {
                sts = cpaCySymInitSession(qat_instance_handles[qctx->inst_num],
                                          qat_chained_callbackFn,
                                          ssd, qctx->session_ctx);
                if (sts != CPA_STATUS_SUCCESS) {
                    WARN("cpaCySymInitSession failed! Status = %d\n", sts);
                    if (qat_get_sw_fallback_enabled() &&
                        ((sts == CPA_STATUS_RESTARTING) || (sts == CPA_STATUS_FAIL))) {
                        CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                                       qctx->inst_num,
                                       qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                                       __func__);
                        qctx->fallback = 1;
                    }
                    else
                        retVal = 0;
                } else {
                    if (qat_get_sw_fallback_enabled()) {
                        CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n",
                                       qctx->inst_num,
                                       qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                                       __func__);
                    }
                    INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_QAT_SESSION_INIT);
                    retVal = 1;
                }
            }
            break;

        case EVP_CTRL_AEAD_TLS1_AAD:
            /* This returns the amount of padding required for
               the send/encrypt direction.
            */
            if (arg != TLS_VIRT_HDR_SIZE || qctx->aad_ctr >= QAT_MAX_PIPELINES) {
                WARN("Invalid argument for AEAD_TLS1_AAD.\n");
                retVal = -1;
                break;
            }
            hdr = GET_TLS_HDR(qctx, qctx->aad_ctr);
            memcpy(hdr, ptr, TLS_VIRT_HDR_SIZE);
            qctx->aad_ctr++;
            if (qctx->aad_ctr > 1)
                INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_PPL_AADCTR_SET);

            len = GET_TLS_PAYLOAD_LEN(((char *)ptr));
            if (GET_TLS_VERSION(((char *)ptr)) >= TLS1_1_VERSION) {
                if (len < EVP_CIPHER_CTX_iv_length(ctx)) {
                    WARN("Length is smaller than the IV length\n");
                    retVal = 0;
                    break;
                }
                len -= EVP_CIPHER_CTX_iv_length(ctx);
            } else if (qctx->aad_ctr > 1) {
                /* pipelines are not supported for
                 * TLS version < TLS1.1
                 */
                WARN("AAD already set for TLS1.0\n");
                retVal = -1;
                break;
            }

            if (EVP_CIPHER_CTX_encrypting(ctx))
                retVal = (int)(((len + dlen + AES_BLOCK_SIZE)
                                & -AES_BLOCK_SIZE) - len);
            else
                retVal = dlen;

            INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_TLS_HDR_SET);
            break;

            /* All remaining cases are exclusive to pipelines and are not
             * used with small packet offload feature.
             */
        case EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS:
            if (arg > QAT_MAX_PIPELINES) {
                WARN("PIPELINE_OUTPUT_BUFS npipes(%d) > Max(%d).\n",
                     arg, QAT_MAX_PIPELINES);
                return -1;
            }
            qctx->p_out = (unsigned char **)ptr;
            qctx->numpipes = arg;
            INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_PPL_OBUF_SET);
            return 1;

        case EVP_CTRL_SET_PIPELINE_INPUT_BUFS:
            if (arg > QAT_MAX_PIPELINES) {
                WARN("PIPELINE_OUTPUT_BUFS npipes(%d) > Max(%d).\n",
                     arg, QAT_MAX_PIPELINES);
                return -1;
            }
            qctx->p_in = (unsigned char **)ptr;
            qctx->numpipes = arg;
            INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_PPL_IBUF_SET);
            return 1;

        case EVP_CTRL_SET_PIPELINE_INPUT_LENS:
            if (arg > QAT_MAX_PIPELINES) {
                WARN("PIPELINE_INPUT_LENS npipes(%d) > Max(%d).\n",
                     arg, QAT_MAX_PIPELINES);
                return -1;
            }
            qctx->p_inlen = (size_t *)ptr;
            qctx->numpipes = arg;
            INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_PPL_BUF_LEN_SET);
            return 1;

        default:
            WARN("Unknown type parameter\n");
            return -1;
    }

    /* Openssl EVP implementation changes the size of payload encoded in TLS
     * header pointed by ptr for EVP_CTRL_AEAD_TLS1_AAD, hence call is made
     * here after ptr has been processed by engine implementation.
     */
sw_ctrl:
    /* Currently, the s/w fallback feature does not support the use of pipelines.
     * However, even if the 'type' parameter passed in to this function implies
     * the use of pipelining, the s/w equivalent function (with this 'type' parameter)
     * will always be called if this 'sw_ctrl' label is reached.  If the s/w function
     * succeeds then, if fallback is set, this success is returned to the calling function.
     * If, however, the s/w function fails, then this s/w failure is always returned
     * to the calling function regardless of whether fallback is set. An example
     * would be multiple calls to this function with type == EVP_CTRL_AEAD_TLS1_AAD
     * such that qctx->aad_ctr becomes > 1, which would imply the use of pipelining.
     * These multiple calls are always made to the s/w equivalent function.
     */
    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
    retVal_sw = EVP_CIPHER_meth_get_ctrl(GET_SW_CIPHER(ctx))(ctx, type, arg, ptr);
    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
    if ((qctx->fallback == 1) && (retVal_sw > 0)) {
        DEBUG("- Switched to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        return retVal_sw;
    }
    if (retVal_sw <= 0) {
        WARN("s/w chained ciphers ctrl function failed.\n");
        return retVal_sw;
    }
    return retVal;
}


/******************************************************************************
* function:
*    qat_chained_ciphers_cleanup(EVP_CIPHER_CTX *ctx)
*
* @param ctx    [IN]  - pointer to existing ctx
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function will cleanup all allocated resources required to perfrom the
*  cryptographic transform.
*
******************************************************************************/
int qat_chained_ciphers_cleanup(EVP_CIPHER_CTX *ctx)
{
    qat_chained_ctx *qctx = NULL;
    CpaStatus sts = 0;
    CpaCySymSessionSetupData *ssd = NULL;
    int retVal = 1;

    if (ctx == NULL) {
        WARN("ctx parameter is NULL.\n");
        return 0;
    }

    qctx = qat_chained_data(ctx);
    if (qctx == NULL) {
        WARN("qctx parameter is NULL.\n");
        return 0;
    }

    if (qctx->sw_ctx_cipher_data != NULL) {
        OPENSSL_free(qctx->sw_ctx_cipher_data);
        qctx->sw_ctx_cipher_data = NULL;
    }

    /* ctx may be cleaned before it gets a chance to allocate qop */
    qat_chained_ciphers_free_qop(&qctx->qop, &qctx->qop_len);

    ssd = qctx->session_data;
    if (ssd) {
        if (INIT_SEQ_IS_FLAG_SET(qctx, INIT_SEQ_QAT_SESSION_INIT)) {
            if (is_instance_available(qctx->inst_num)) {
                /* Clean up session if hardware available regardless of whether in */
                /* fallback or not, if in INIT_SEQ_QAT_SESSION_INIT */
                sts = cpaCySymRemoveSession(qat_instance_handles[qctx->inst_num],
                                            qctx->session_ctx);
                if (sts != CPA_STATUS_SUCCESS) {
                    WARN("cpaCySymRemoveSession FAILED, sts = %d\n", sts);
                    retVal = 0;
                }
            }
        }
        QAT_QMEMFREE_BUFF(qctx->session_ctx);
        QAT_CLEANSE_FREE_BUFF(ssd->hashSetupData.authModeSetupData.authKey,
                              ssd->hashSetupData.authModeSetupData.
                              authKeyLenInBytes);
        QAT_CLEANSE_FREE_BUFF(ssd->cipherSetupData.pCipherKey,
                              ssd->cipherSetupData.cipherKeyLenInBytes);
        OPENSSL_free(ssd);
    }

    qctx->fallback = 0;
    INIT_SEQ_CLEAR_ALL_FLAGS(qctx);
    DEBUG_PPL("[%p] EVP CTX cleaned up\n", ctx);
    return retVal;
}


/******************************************************************************
* function:
*    qat_chained_ciphers_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
*                                  const unsigned char *in, size_t len)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param out   [OUT]  - output buffer for transform result
* @param in     [IN]  - input buffer
* @param len    [IN]  - length of input buffer
*
* @retval 0      function failed
* @retval 1      function succeeded
*
* description:
*    This function performs the cryptographic transform according to the
*  parameters setup during initialisation.
*
******************************************************************************/
int qat_chained_ciphers_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                  const unsigned char *in, size_t len)
{
    CpaStatus sts = 0;
    CpaCySymOpData *opd = NULL;
    CpaBufferList *s_sgl = NULL;
    CpaBufferList *d_sgl = NULL;
    CpaFlatBuffer *s_fbuf = NULL;
    CpaFlatBuffer *d_fbuf = NULL;
    int retVal = 0, job_ret = 0;
    unsigned int pad_check = 1;
    int pad_len = 0;
    int plen = 0;
    int plen_adj = 0;
    op_done_pipe_t done;
    qat_chained_ctx *qctx = NULL;
    unsigned char *inb, *outb;
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned char out_blk[TLS_MAX_PADDING_LENGTH + 1] = { 0x0 };
    const unsigned char *in_blk = NULL;
    unsigned int ivlen = 0;
    int dlen, vtls, enc, i, buflen;
    int discardlen = 0;
    char *tls_hdr = NULL;
    int pipe = 0;
    int error = 0;
    int outlen = -1;
    thread_local_variables_t *tlv = NULL;

    if (ctx == NULL) {
        WARN("CTX parameter is NULL.\n");
        return -1;
    }

    qctx = qat_chained_data(ctx);
    if (qctx == NULL) {
        WARN("QAT CTX NULL\n");
        return -1;
    }

    if (qctx->fallback == 1)
        goto fallback;

    if (!(is_instance_available(qctx->inst_num))) {
        WARN("No QAT instance available.\n");
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
            qctx->fallback = 1;
            goto fallback;
        } else {
            WARN("Fail - No QAT instance available and s/w fallback is not enabled.\n");
            return -1; /* Fail if software fallback not enabled. */
        }
    } else {
        if (!INIT_SEQ_IS_FLAG_SET(qctx, INIT_SEQ_QAT_CTX_INIT)) {
            WARN("QAT Context not initialised");
            return -1;
        }
    }

    /* Pipeline initialisation requires multiple EVP_CIPHER_CTX_ctrl
     * calls to set all required parameters. Check if all have been
     * provided. For Pipeline, in and out buffers can be NULL as these
     * are supplied through ctrl messages.
     */
    if (PIPELINE_INCOMPLETE_INIT(qctx) ||
        (!PIPELINE_SET(qctx) && (out == NULL
                                 || (len % AES_BLOCK_SIZE)))) {
        WARN("%s \n",
             PIPELINE_INCOMPLETE_INIT(qctx) ?
             "Pipeline not initialised completely" : len % AES_BLOCK_SIZE
             ? "Buffer Length not multiple of AES block size"
             : "out buffer null");
        return -1;
    }

    enc = EVP_CIPHER_CTX_encrypting(ctx);

    /* If we are encrypting and EVP_EncryptFinal_ex is called with a NULL
       input buffer then return 0. Note: we don't actually support partial
       requests in the engine but this workaround avoids an error from OpenSSL
       speed on the last request when measuring cipher performance. Speed is
       written to measure performance using partial requests.*/
    if (!PIPELINE_SET(qctx) &&
        in == NULL &&
        out != NULL &&
        enc) {
        DEBUG("QAT partial requests work-around: NULL input buffer passed.\n");
        return 0;
    }

    if (!INIT_SEQ_IS_FLAG_SET(qctx, INIT_SEQ_QAT_SESSION_INIT)) {
        /* The qat session is initialized when HMAC key is set. In case
         * HMAC key is not explicitly set, use default HMAC key of all zeros
         * and initialise a qat session.
         */

        if (!PIPELINE_SET(qctx) && !TLS_HDR_SET(qctx) && !enc) {
            /* When decrypting do not verify computed digest
             * against stored digest as there is none in this case.
             */
            qctx->session_data->verifyDigest = CPA_FALSE;
        }
        DEBUG("inst_num = %d\n", qctx->inst_num);
        DUMP_SESSION_SETUP_DATA(qctx->session_data);
        DEBUG("session_ctx = %p\n", qctx->session_ctx);

        if (!(is_instance_available(qctx->inst_num))) {
            WARN("No QAT instance available so not initialising session.\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                qctx->fallback = 1;
                goto fallback;
            } else {
                WARN("Fail - No QAT instance available and s/w fallback is not enabled.\n");
                return -1; /* Fail if software fallback not enabled. */
            }
        } else {
            sts = cpaCySymInitSession(qat_instance_handles[qctx->inst_num], qat_chained_callbackFn,
                                      qctx->session_data, qctx->session_ctx);
            if (sts != CPA_STATUS_SUCCESS) {
                WARN("cpaCySymInitSession failed! Status = %d\n", sts);
                if (qat_get_sw_fallback_enabled() &&
                    ((sts == CPA_STATUS_RESTARTING) || (sts == CPA_STATUS_FAIL))) {
                    CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                                   qctx->inst_num,
                                   qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                                   __func__);
                    qctx->fallback = 1;
                    goto fallback;
                }
                else
                    return -1;
            }
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n",
                               qctx->inst_num,
                               qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                               __func__);
            }
            INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_QAT_SESSION_INIT);
        }
    }

    ivlen = EVP_CIPHER_CTX_iv_length(ctx);
    dlen = get_digest_len(EVP_CIPHER_CTX_nid(ctx));

    /* Check and setup data structures for pipeline */
    if (PIPELINE_SET(qctx)) {
        /* All the aad data (tls header) should be present */
        if (qctx->aad_ctr != qctx->numpipes) {
            WARN("AAD data missing supplied %u of %u\n",
                 qctx->aad_ctr, qctx->numpipes);
            return -1;
        }
    } else {
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        if (len <=
            qat_pkt_threshold_table_get_threshold(EVP_CIPHER_CTX_nid(ctx))) {
            EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
            retVal = EVP_CIPHER_meth_get_do_cipher(GET_SW_CIPHER(ctx))
                     (ctx, out, in, len);
            EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
            if (retVal) {
                outlen = len;
            }
            goto cleanup;
        }
#endif
        /* When no TLS AAD information is supplied, for example: speed,
         * the payload length for encrypt/decrypt is equal to buffer len
         * and the HMAC is to be discarded. Set the fake AAD hdr to avoid
         * decision points in code for this special case handling.
         */
        if (!TLS_HDR_SET(qctx)) {
            tls_hdr = GET_TLS_HDR(qctx, 0);
            /* Mark an invalid tls version */
            tls_hdr[9] = tls_hdr[10] = 0;
            /* Set the payload length equal to entire length
             * of buffer i.e. there is no space for HMAC in
             * buffer.
             */
            SET_TLS_PAYLOAD_LEN(tls_hdr, 0);
            plen = len;
            /* Find the extra length for qat buffers to store the HMAC and
             * padding which is later discarded when the result is copied out.
             * Note: AES_BLOCK_SIZE must be a power of 2 for this algorithm to
             * work correctly.
             * If the digest len (dlen) is a multiple of AES_BLOCK_SIZE, then
             * discardlen could theoretically be equal to 'dlen'.  However
             * 1 byte is still needed for the required pad_len field which would
             * not be available in this case.  Therefore we add an additional AES_BLOCK_SIZE to
             * ensure that even for the case of (dlen % AES_BLOCK_SIZE == 0) there
             * is room for the pad_len field byte - in this specific case the pad space
             * field would comprise the remaining 15 bytes and the pad_len byte field
             * would be equal to 15.
             * The '& ~(AES_BLOCK_SIZE - 1)' element of the algorithm serves to round down
             * 'discardlen' to the nearest AES_BLOCK_SIZE multiple.
             */
            discardlen = ((len + dlen + AES_BLOCK_SIZE) & ~(AES_BLOCK_SIZE - 1))
                - len;
            /* Pump-up the len by this amount */
            len += discardlen;
        }
        /* If the same ctx is being re-used for multiple invocation
         * of this function without setting EVP_CTRL for number of pipes,
         * the PIPELINE_SET is true from previous invocation. Clear Pipeline
         * when add_ctr is 1. This means user wants to switch from pipeline mode
         * to non-pipeline mode for the same ctx.
         */
        CLEAR_PIPELINE(qctx);

        /* setting these helps avoid decision branches when
         * pipelines are not used.
         */
        qctx->p_in = (unsigned char **)&in;
        qctx->p_out = &out;
        qctx->p_inlen = &len;
    }

    DEBUG_PPL("[%p] Start Cipher operation with num pipes %u\n",
              ctx, qctx->numpipes);

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
            WARN("could not create local variables\n");
            return -1;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (qat_kill_thread(qat_timer_poll_func_thread, SIGUSR1) != 0) {
                WARN("qat_kill_thread error\n");
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                return -1;
            }
        }
    }

    if ((qat_setup_op_params(ctx) != 1) ||
        (qat_init_op_done_pipe(&done, qctx->numpipes) != 1)) {
        WARN("Failure in qat_setup_op_params or qat_init_op_done_pipe\n");
        QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
        return -1;
    }

    do {
        opd = &qctx->qop[pipe].op_data;
        tls_hdr = GET_TLS_HDR(qctx, pipe);
        vtls = GET_TLS_VERSION(tls_hdr);
        s_fbuf = qctx->qop[pipe].src_fbuf;
        d_fbuf = qctx->qop[pipe].dst_fbuf;
        s_sgl = &qctx->qop[pipe].src_sgl;
        d_sgl = &qctx->qop[pipe].src_sgl;
        inb = &qctx->p_in[pipe][0];
        outb = &qctx->p_out[pipe][0];
        buflen = qctx->p_inlen[pipe];

        if (vtls >= TLS1_1_VERSION) {
            /*
             * Note: The OpenSSL framework assumes that the IV field will be part
             * of the output data. In order to chain HASH and CIPHER we need to
             * present contiguous SGL to QAT, copy IV to output buffer now and
             * skip it for chained operation.
             */
            if (inb != outb)
                memcpy(outb, inb, ivlen);
            memcpy(opd->pIv, inb, ivlen);
            inb += ivlen;
            buflen -= ivlen;
            plen_adj = ivlen;
        } else {
            if (qctx->numpipes > 1) {
                WARN("Pipe %d tls hdr version < tls1.1\n", pipe);
                error = 1;
                break;
            }
            memcpy(opd->pIv, EVP_CIPHER_CTX_iv(ctx), ivlen);
        }

        /* Calculate payload and padding len */
        if (enc) {
            /* For encryption, payload length is in the header.
             * For non-TLS use case, plen has already been set above.
             * For TLS Version > 1.1 the payload length also contains IV len.
             */
            if (vtls >= TLS1_VERSION)
                plen = GET_TLS_PAYLOAD_LEN(tls_hdr) - plen_adj;

            /* Compute the padding length using total buffer length, payload
             * length, digest length and a byte to encode padding len.
             */
            pad_len = buflen - (plen + dlen) - 1;

            /* If padlen is negative, then size of supplied output buffer
             * is smaller than required.
             */
            if ((buflen % AES_BLOCK_SIZE) != 0 || pad_len < 0 ||
                pad_len > TLS_MAX_PADDING_LENGTH) {
                WARN("buffer len[%d] or pad_len[%d] incorrect\n",
                     buflen, pad_len);
                error = 1;
                break;
            }
        } else if (vtls >= TLS1_VERSION) {
            /* Decrypt the last block of the buffer to get the pad_len.
             * Calculate payload len using total length and padlen.
             * NOTE: plen so calculated does not account for ivlen
             *       if iv is appened for TLS Version >= 1.1
             */
            unsigned int tmp_padlen = TLS_MAX_PADDING_LENGTH + 1;
            unsigned int maxpad, res = 0xff;
            size_t j;
            uint8_t cmask, b;
            int rx_len = 0;
            EVP_CIPHER_CTX *dctx = NULL;
            int decryptFinal_out_len = 0;
            int decrypt_error = 0;


            if ((buflen - dlen) <= TLS_MAX_PADDING_LENGTH)
                tmp_padlen = (((buflen - dlen) + (AES_BLOCK_SIZE - 1))
                              / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
            in_blk = inb + (buflen - tmp_padlen);
            memcpy(ivec, in_blk - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

            dctx = EVP_CIPHER_CTX_new();
            if (dctx == NULL) {
                WARN("Failed to create decrypt context dctx.\n");
                error = 1;
                break;
            }
            EVP_CIPHER_CTX_init(dctx);

            if (!EVP_DecryptInit_ex(dctx, GET_SW_NON_CHAINED_CIPHER(ctx), NULL,
                                    qctx->session_data->cipherSetupData.pCipherKey, ivec)) {
                WARN("DecryptInit error occurred.\n");
                decrypt_error = 1;
            } else {
                EVP_CIPHER_CTX_set_flags(dctx, EVP_CIPH_NO_PADDING);
                if (!EVP_DecryptUpdate(dctx, out_blk, &rx_len, in_blk, tmp_padlen)
                    || !EVP_DecryptFinal_ex(dctx, out_blk + rx_len, &decryptFinal_out_len)) {
                    WARN("Decrypt error occurred.\n");
                    decrypt_error = 1;
                }
            }
            EVP_CIPHER_CTX_cleanup(dctx);
            OPENSSL_free(dctx);
            dctx = NULL;
            if (decrypt_error) {
                error = 1;
                break;
            }

            pad_len = out_blk[tmp_padlen - 1];
            /* Determine the maximum amount of padding that could be present */
            maxpad = buflen - (dlen + 1);
            maxpad |=
                (TLS_MAX_PADDING_LENGTH - maxpad) >> (sizeof(maxpad) * 8 - 8);
            maxpad &= TLS_MAX_PADDING_LENGTH;

            /* Check the padding in constant time */
            for (j = 0; j <= maxpad; j++) {
                cmask = qat_constant_time_ge_8(pad_len, j);
                b = out_blk[tmp_padlen - 1 - j];
                res &= ~(cmask & (pad_len ^ b));
            }
            res = qat_constant_time_eq(0xff, res & 0xff);
            pad_check &= (int)res;

            /* Adjust the amount of data to digest to be the maximum by setting
             * pad_len = 0 if the padding check failed or if the padding length
             * is greater than the maximum padding allowed. This adjustment
             * is done in constant time.
             */
            pad_check &= qat_constant_time_ge(maxpad, pad_len);
            pad_len *= pad_check;
            plen = buflen - (pad_len + 1 + dlen);
        }

        opd->messageLenToCipherInBytes = buflen;
        opd->messageLenToHashInBytes = TLS_VIRT_HDR_SIZE + plen;

        /* copy tls hdr in flatbuffer's last 13 bytes */
        memcpy(d_fbuf[0].pData + (d_fbuf[0].dataLenInBytes - TLS_VIRT_HDR_SIZE),
               tls_hdr, TLS_VIRT_HDR_SIZE);
        /* Update the value of payload before HMAC calculation */
        SET_TLS_PAYLOAD_LEN((d_fbuf[0].pData +
                             (d_fbuf[0].dataLenInBytes - TLS_VIRT_HDR_SIZE)),
                            plen);

        FLATBUFF_ALLOC_AND_CHAIN(s_fbuf[1], d_fbuf[1], buflen);
        if ((s_fbuf[1].pData) == NULL) {
            WARN("Failure in src buffer allocation.\n");
            error = 1;
            break;
        }

        memcpy(d_fbuf[1].pData, inb, buflen - discardlen);

        if (enc) {
            /* Add padding to input buffer at end of digest */
            for (i = plen + dlen; i < buflen; i++)
                d_fbuf[1].pData[i] = pad_len;
        } else {
            /* store IV for next cbc operation */
            if (vtls < TLS1_1_VERSION)
                memcpy(EVP_CIPHER_CTX_iv_noconst(ctx),
                       inb + (buflen - discardlen) - ivlen, ivlen);
        }

        DUMP_SYM_PERFORM_OP(qat_instance_handles[qctx->inst_num], opd, s_sgl, d_sgl);

        /* Increment prior to successful submission */
        done.num_submitted++;

        sts = qat_sym_perform_op(qctx->inst_num, &done, opd, s_sgl,
                                 d_sgl, &(qctx->session_data->verifyDigest));

        if (sts != CPA_STATUS_SUCCESS) {
            if (qat_get_sw_fallback_enabled() &&
                ((sts == CPA_STATUS_RESTARTING) || (sts == CPA_STATUS_FAIL))) {
                CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                               qctx->inst_num,
                               qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                               __func__);
                qctx->fallback = 1;
            }
            WARN("Failed to submit request to qat - status = %d\n", sts);
            error = 1;
            /* Decrement after failed submission */
            done.num_submitted--;
            break;
        }
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n",
                           qctx->inst_num,
                           qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
        }
    } while (++pipe < qctx->numpipes);

    /* If there has been an error during submission of the pipes
     * indicate to the callback function not to wait for the entire
     * pipeline.
     */
    if (error == 1)
        done.num_pipes = pipe;

    /* If there is nothing to wait for, do not pause or yield */
    if (done.num_submitted == 0 || (done.num_submitted == done.num_processed)) {
        if (done.opDone.job != NULL) {
            qat_clear_async_event_notification();
        }
        goto end;
    }

    if (enable_heuristic_polling) {
        QAT_ATOMIC_INC(num_cipher_pipeline_requests_in_flight);
    }

    do {
        if (done.opDone.job != NULL) {
            /* If we get a failure on qat_pause_job then we will
               not flag an error here and quit because we have
               an asynchronous request in flight.
               We don't want to start cleaning up data
               structures that are still being used. If
               qat_pause_job fails we will just yield and
               loop around and try again until the request
               completes and we can continue. */
            if ((job_ret = qat_pause_job(done.opDone.job, ASYNC_STATUS_OK)) == 0)
                pthread_yield();
        } else {
            pthread_yield();
        }
    } while (!done.opDone.flag ||
             QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

 end:
    qctx->total_op += done.num_processed;
    DUMP_SYM_PERFORM_OP_OUTPUT(&(qctx->session_data->verifyDigest), d_sgl);
    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

    if (error == 0 && (done.opDone.verifyResult == CPA_TRUE)) {
        retVal = 1 & pad_check;
        if (retVal == 1)
            outlen = 0;
    } else {
        if (qat_get_sw_fallback_enabled() && done.opDone.verifyResult == CPA_FALSE) {
            CRYPTO_QAT_LOG("Verification of result failed for qat inst_num %d device_id %d - fallback to SW - %s\n",
                           qctx->inst_num,
                           qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            qctx->fallback = 1; /* Probably already set anyway */
        }
    }
    qat_cleanup_op_done_pipe(&done);
    pipe = 0;
    do {
        if (retVal == 1) {
            memcpy(qctx->p_out[pipe] + plen_adj,
                   qctx->qop[pipe].dst_fbuf[1].pData,
                   qctx->p_inlen[pipe] - discardlen - plen_adj);
            outlen += buflen + plen_adj - discardlen;
        }
        qaeCryptoMemFreeNonZero(qctx->qop[pipe].src_fbuf[1].pData);
        qctx->qop[pipe].src_fbuf[1].pData = NULL;
        qctx->qop[pipe].dst_fbuf[1].pData = NULL;
    } while (++pipe < qctx->numpipes);

    if (enc && vtls < TLS1_1_VERSION)
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx),
               outb + buflen - discardlen - ivlen, ivlen);

#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
cleanup:
#endif
fallback:
    if (qctx->fallback == 1) {
        if (PIPELINE_SET(qctx)) {
            WARN("Pipelines are set when in s/w fallback mode, which is not supported.\n");
            return -1;
        } else {
            DEBUG("- Switched to software mode.\n");
            CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
            EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
            retVal = EVP_CIPHER_meth_get_do_cipher(GET_SW_CIPHER(ctx))
                (ctx, out, in, len);
            EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
            if (retVal)
                outlen = len;
        }
    }

    /* Reset the AAD counter forcing that new AAD information is provided
     * before each repeat invocation of this function.
     */
    qctx->aad_ctr = 0;

    /* This function can be called again with the same evp_cipher_ctx. */
    if (PIPELINE_SET(qctx)) {
        /* Number of pipes can grow between multiple invocation of this call.
         * Record the maximum number of pipes used so that data structures can
         * be allocated accordingly.
         */
        INIT_SEQ_CLEAR_FLAG(qctx, INIT_SEQ_PPL_AADCTR_SET);
        INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_PPL_USED);
        qctx->npipes_last_used = qctx->numpipes > qctx->npipes_last_used
            ? qctx->numpipes : qctx->npipes_last_used;
    }
    return outlen;
}


/******************************************************************************
 * function:
 *    CpaStatus qat_sym_perform_op(int                   inst_num,
 *                                 void                  *pCallbackTag,
 *                                 const CpaCySymOpData  *pOpData,
 *                                 const CpaBufferList   *pSrcBuffer,
 *                                 CpaBufferList         *pDstBuffer,
 *                                 CpaBoolean            *pVerifyResult)
 *
 * @param inst_num        [IN]  - The current instance
 * @param pCallbackTag    [IN]  - Pointer to op_done struct
 * @param pOpData         [IN]  - Operation parameters
 * @param pSrcBuffer      [IN]  - Source buffer list
 * @param pDstBuffer      [OUT] - Destination buffer list
 * @param pVerifyResult   [OUT] - Whether hash verified or not
 *
 * description:
 *   Wrapper around cpaCySymPerformOp which handles retries for us.
 *
 *******************************************************************************/

CpaStatus qat_sym_perform_op(int inst_num,
                             void *pCallbackTag,
                             const CpaCySymOpData * pOpData,
                             const CpaBufferList * pSrcBuffer,
                             CpaBufferList * pDstBuffer,
                             CpaBoolean * pVerifyResult)
{
    CpaStatus status;
    op_done_t *opDone = (op_done_t *)pCallbackTag;
    unsigned int uiRetry = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();

    do {
        status = cpaCySymPerformOp(qat_instance_handles[inst_num],
                                   pCallbackTag,
                                   pOpData,
                                   pSrcBuffer,
                                   pDstBuffer,
                                   pVerifyResult);
        if (status == CPA_STATUS_RETRY) {
            if (opDone->job) {
                if ((qat_wake_job(opDone->job, ASYNC_STATUS_EAGAIN) == 0) ||
                    (qat_pause_job(opDone->job, ASYNC_STATUS_EAGAIN) == 0)) {
                    WARN("Failed to wake or pause job\n");
                    QATerr(QAT_F_QAT_SYM_PERFORM_OP, QAT_R_WAKE_PAUSE_JOB_FAILURE);
                    status = CPA_STATUS_FAIL;
                    break;
                }
            } else {
                qatPerformOpRetries++;
                if (uiRetry >= iMsgRetry
                    && iMsgRetry != QAT_INFINITE_MAX_NUM_RETRIES) {
                    WARN("Maximum retries exceeded\n");
                    QATerr(QAT_F_QAT_SYM_PERFORM_OP, QAT_R_MAX_RETRIES_EXCEEDED);
                    status = CPA_STATUS_FAIL;
                    break;
                }
                uiRetry++;
                usleep(ulPollInterval +
                       (uiRetry % QAT_RETRY_BACKOFF_MODULO_DIVISOR));
            }
        }
    }
    while (status == CPA_STATUS_RETRY);
    return status;
}
