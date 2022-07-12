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
 * @file qat_hw_sha3.c
 *
 * This file contains the engine implementations for SHA3 Hash operations
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <string.h>
#include <pthread.h>
#include <signal.h>
#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_USDM_MEM
# include "qat_hw_usdm_inf.h"
#endif
#include "e_qat.h"
#include "qat_utils.h"
#include "qat_hw_callback.h"
#include "qat_hw_polling.h"
#include "qat_events.h"
#include "qat_evp.h"

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_sym.h"
#include "qat_hw_sha3.h"
#include "qat_hw_ciphers.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/tls1.h>
#include <openssl/async.h>
#include <openssl/ssl.h>

#ifdef QAT_HW_INTREE
# define ENABLE_QAT_HW_SHA3
#endif

# define GET_SW_SHA3_DIGEST(ctx) \
    qat_sha3_sw_impl(EVP_MD_CTX_type((ctx)) )

#ifdef ENABLE_QAT_HW_SHA3
# ifndef QAT_OPENSSL_PROVIDER
static int qat_sha3_init(EVP_MD_CTX *ctx);
static int qat_sha3_cleanup(EVP_MD_CTX *ctx);
static int qat_sha3_update(EVP_MD_CTX *ctx, const void *in, size_t len);
static int qat_sha3_final(EVP_MD_CTX *ctx, unsigned char *md);
static int qat_get_hash_alg_data(EVP_MD_CTX *ctx, qat_sha3_ctx *sha3_ctx);
static int qat_sha3_ctrl(EVP_MD_CTX *ctx, int type, int p1,void *p2);
static int qat_get_sha3_block_size(int nid);
static int qat_get_sha3_state_size(int nid);
# else
static int qat_get_hash_alg_data(QAT_KECCAK1600_CTX *ctx, qat_sha3_ctx *sha3_ctx);
# endif
#endif

static inline const EVP_MD *qat_sha3_sw_impl(int nid)
{
    switch (nid) {
    case NID_sha3_224:
       return EVP_sha3_224();
    case NID_sha3_256:
       return EVP_sha3_256();
    case NID_sha3_384:
       return EVP_sha3_384();
    case NID_sha3_512:
       return EVP_sha3_512();
    default:
       WARN("Invalid nid %d\n", nid);
       return NULL;
    }
}

const EVP_MD *qat_create_sha3_meth(int nid , int key_type)
{
#if defined(ENABLE_QAT_HW_SHA3) && !defined(QAT_OPENSSL_PROVIDER)
    EVP_MD *c = NULL;
    int res = 1;
    int blocksize,statesize = 0;

    if (qat_hw_offload &&
        (qat_hw_algo_enable_mask & ALGO_ENABLE_MASK_SHA3)) {
        if ((c = EVP_MD_meth_new(nid,key_type)) == NULL) {
            WARN("Failed to allocate digest methods for nid %d\n", nid);
            return NULL;
        }

        blocksize = qat_get_sha3_block_size(nid);
        if (!blocksize){
            WARN("Failed to get block size for nid %d\n", nid);
            EVP_MD_meth_free(c);
            return NULL;
        }

        statesize = qat_get_sha3_state_size(nid);
        if (!statesize){
            WARN("Failed to state size for nid %d\n", nid);
            EVP_MD_meth_free(c);
            return NULL;
        }

        res &= EVP_MD_meth_set_result_size(c, statesize);
        res &= EVP_MD_meth_set_input_blocksize(c,blocksize);
        res &= EVP_MD_meth_set_app_datasize(c, sizeof(EVP_MD*) + sizeof(qat_sha3_ctx));
        res &= EVP_MD_meth_set_flags(c, (EVP_MD_CTX_FLAG_ONESHOT|
                            EVP_MD_CTX_FLAG_NO_INIT));
        res &= EVP_MD_meth_set_init(c, qat_sha3_init);
        res &= EVP_MD_meth_set_update(c, qat_sha3_update);
        res &= EVP_MD_meth_set_final(c, qat_sha3_final);
        res &= EVP_MD_meth_set_cleanup(c, qat_sha3_cleanup);
        res &= EVP_MD_meth_set_ctrl(c, qat_sha3_ctrl);

        if (0 == res) {
            WARN("Failed to set cipher methods for nid %d\n", nid);
            EVP_MD_meth_free(c);
            return NULL;
        }

        qat_hw_sha_offload = 1;
        DEBUG("QAT HW SHA3 Registration succeeded\n");
        return c;
    }
    else {
        qat_hw_sha_offload = 0;
        DEBUG("QAT HW SHA3 is disabled, using OpenSSL SW\n");
        return qat_sha3_sw_impl(nid);
    }
#else
    qat_hw_sha_offload = 0;
    DEBUG("QAT HW SHA3 is disabled, using OpenSSL SW\n");
    return qat_sha3_sw_impl(nid);
#endif
}

#ifdef ENABLE_QAT_HW_SHA3
static const CpaCySymOpData template_opData = {
    .sessionCtx = NULL,
    .packetType = CPA_CY_SYM_PACKET_TYPE_FULL,
    .pIv = NULL,
    .ivLenInBytes = 0,
    .cryptoStartSrcOffsetInBytes = 0,
    .messageLenToCipherInBytes = 0,
    .hashStartSrcOffsetInBytes = 0,
    .messageLenToHashInBytes = 0,
    .pDigestResult = NULL,
    .pAdditionalAuthData = NULL
};

#ifndef QAT_OPENSSL_PROVIDER
static int qat_get_sha3_block_size(int nid)
{

    switch (nid) {
    case NID_sha3_224:
        return QAT_SHA3_224_BLOCK_SIZE;
    case NID_sha3_256:
        return QAT_SHA3_256_BLOCK_SIZE;
    case NID_sha3_384:
        return QAT_SHA3_384_BLOCK_SIZE;
    case NID_sha3_512:
        return QAT_SHA3_512_BLOCK_SIZE;
    default:
        WARN("Unsupported Hash Algorithm\n");
        return 0;
    }
}
static int qat_get_sha3_state_size(int nid)
{

    switch (nid) {
    case NID_sha3_224:
        return QAT_SHA3_224_STATE_SIZE;
    case NID_sha3_256:
        return QAT_SHA3_256_STATE_SIZE;
    case NID_sha3_384:
        return QAT_SHA3_384_STATE_SIZE;
    case NID_sha3_512:
        return QAT_SHA3_512_STATE_SIZE;
    default:
        WARN("Unsupported Hash Algorithm\n");
        return 0;
    }
}
#endif

#ifdef QAT_OPENSSL_PROVIDER
static int qat_get_hash_alg_data(QAT_KECCAK1600_CTX *ctx, qat_sha3_ctx *sha3_ctx)
#else
static int qat_get_hash_alg_data(EVP_MD_CTX *ctx, qat_sha3_ctx *sha3_ctx)
#endif
{
    if (ctx == NULL || sha3_ctx == NULL) {
        WARN("Either ctx %p or sha3_ctx %p is NULL\n", ctx, sha3_ctx);
        return 0;
    }
#ifdef QAT_OPENSSL_PROVIDER
    switch (ctx->md_type) {
#else
    switch (EVP_MD_CTX_type(ctx)) {
#endif
    case NID_sha3_224:
        sha3_ctx->hash_alg = CPA_CY_SYM_HASH_SHA3_224;
        sha3_ctx->digest_size = QAT_SHA3_224_DIGEST_SIZE;
        break;
    case NID_sha3_256:
        sha3_ctx->hash_alg = CPA_CY_SYM_HASH_SHA3_256;
        sha3_ctx->digest_size = QAT_SHA3_256_DIGEST_SIZE;
        break;
    case NID_sha3_384:
        sha3_ctx->hash_alg = CPA_CY_SYM_HASH_SHA3_384;
        sha3_ctx->digest_size = QAT_SHA3_384_DIGEST_SIZE;
        break;
    case NID_sha3_512:
        sha3_ctx->hash_alg = CPA_CY_SYM_HASH_SHA3_512;
        sha3_ctx->digest_size = QAT_SHA3_512_DIGEST_SIZE;
        break;
    default:
        WARN("Unsupported Hash Algorithm\n");
        return 0;
    }

    return 1;
}

/******************************************************************************
* function:
*         qat_sha3_session_data_init(EVP_MD_CTX *ctx,qat_sha3_ctx *sha3_ctx)
*
* @param ctx         [IN] - pointer to the existing context
* @param sha3_ctx    [IN] - pointer to the sha3 context
*
* description:
*    This function is to create QAT specific session data.
*
*    It will return 1 if successful and 0 on failure.
******************************************************************************/
#ifdef QAT_OPENSSL_PROVIDER
static int qat_sha3_session_data_init(QAT_KECCAK1600_CTX *ctx,
                                      qat_sha3_ctx *sha3_ctx)
#else
static int qat_sha3_session_data_init(EVP_MD_CTX *ctx,
                                      qat_sha3_ctx *sha3_ctx)
#endif
{
    if (NULL == sha3_ctx || NULL == ctx){
        WARN("sha3_ctx or ctx is NULL\n");
        QATerr(QAT_F_QAT_SHA3_SESSION_DATA_INIT, QAT_R_SHA3_CTX_NULL);
        return 0;
    }

    if(!qat_get_hash_alg_data(ctx,sha3_ctx)){
        WARN("Unsupported hash data\n");
        QATerr(QAT_F_QAT_SHA3_SESSION_DATA_INIT, QAT_R_INVALID_HASH_DATA);
        return 0;
    }

    sha3_ctx->session_data = OPENSSL_malloc(sizeof(CpaCySymSessionSetupData));
    if (NULL == sha3_ctx->session_data) {
        WARN("session setup data Malloc failure\n");
        QATerr(QAT_F_QAT_SHA3_SESSION_DATA_INIT, QAT_R_SSD_MALLOC_FAILURE);
        return 0;
    }

    /* Set priority and operation of this session */
    sha3_ctx->session_data->sessionPriority = CPA_CY_PRIORITY_HIGH;
    sha3_ctx->session_data->symOperation = CPA_CY_SYM_OP_HASH;
    /* --- Hash Configuration --- */

    /* Set the hash mode and the length of the digest */
    sha3_ctx->session_data->hashSetupData.hashAlgorithm = sha3_ctx->hash_alg;
    sha3_ctx->session_data->hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_PLAIN;
    sha3_ctx->session_data->hashSetupData.digestResultLenInBytes = sha3_ctx->digest_size;
    sha3_ctx->session_data->hashSetupData.authModeSetupData.authKey = NULL;
    sha3_ctx->session_data->hashSetupData.nestedModeSetupData.pInnerPrefixData = NULL;
    sha3_ctx->session_data->hashSetupData.nestedModeSetupData.pOuterPrefixData = NULL;

    /* Tag follows immediately after the region to hash */
    sha3_ctx->session_data->digestIsAppended = CPA_FALSE;

    /* digestVerify is not required to be set.*/
    sha3_ctx->session_data->verifyDigest = CPA_FALSE;

    sha3_ctx->opd = OPENSSL_zalloc(sizeof(template_opData));
    if (sha3_ctx->opd == NULL) {
        WARN("memory allocation failed for symopData struct.\n");
        QATerr(QAT_F_QAT_SHA3_SESSION_DATA_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    sha3_ctx->context_params_set = 1;

    return 1;
}

/******************************************************************************
* function:
*         qat_sha3_init(EVP_MD_CTX *ctx)
*
* @param ctx     [IN]  - pointer to existing context
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function initialises the hash algorithm parameters for EVP context.
*
******************************************************************************/
#ifdef QAT_OPENSSL_PROVIDER
int qat_sha3_init(QAT_KECCAK1600_CTX *ctx)
#else
static int qat_sha3_init(EVP_MD_CTX *ctx)
#endif
{
    qat_sha3_ctx* sha3_ctx = NULL;

    if (NULL == ctx) {
        WARN("ctx is NULL\n");
        return 0;
    }

    /* Initialise a QAT session and set the hash*/
#ifdef QAT_OPENSSL_PROVIDER
    sha3_ctx = ctx->qctx;
#else
    sha3_ctx = QAT_SHA3_GET_CTX(ctx);
#endif
    if (NULL == sha3_ctx) {
        WARN("sha3_ctx is NULL\n");
        return 0;
    }
#ifdef QAT_OPENSSL_PROVIDER
    sha3_ctx->block_size = ctx->block_size;
#else
    sha3_ctx->block_size = EVP_MD_CTX_block_size(ctx);
#endif
    if (!sha3_ctx->block_size) {
        WARN("sha3 ctx block size is NULL\n");
        return 0;
    }

#ifdef QAT_OPENSSL_PROVIDER
    sha3_ctx->md_size = ctx->md_size;
#else
    sha3_ctx->md_size = EVP_MD_CTX_size(ctx);
#endif
    if (!sha3_ctx->md_size) {
        WARN("sha3_ctx md size is NULL\n");
        return 0;
    }

#ifndef QAT_OPENSSL_PROVIDER
#ifndef ENABLE_QAT_HW_SMALL_PKT_OFFLOAD
    /* Update the software init data */
    KECCAK1600_CTX *k_ctx = EVP_MD_CTX_md_data(ctx);
    size_t bsz = EVP_MD_CTX_block_size(ctx);

    if (bsz <= sizeof(k_ctx->buf)) {
        memset(k_ctx->A, 0, sizeof(k_ctx->A));

        k_ctx->num = 0;
        k_ctx->block_size = bsz;
        k_ctx->md_size = EVP_MD_CTX_size(ctx);
        k_ctx->pad = '\x06';
    }
#endif
#endif
    /* Initialize QAT session */
    if (0 == qat_sha3_session_data_init(ctx, sha3_ctx)) {
        WARN("qat_session_data_init failed.\n");
        return 0;
    }

    return 1;
}

/******************************************************************************
* function:
*    qat_sha3_ctrl(EVP_MD_CTX *ctx,int type, int p1, void *p2)
*
* @param ctx     [IN]  - pointer to existing context
* @param type    [IN]  - type of request
* @param p1      [IN]  - size of the pointed to by ptr
* @param p2      [IN]  - input buffer contain the necessary parameters
*
* @retval  1     function succeeded
* @retval -1     function failed
*
* description:
*    This function is a generic control interface provided by the EVP API.
*
******************************************************************************/
#ifndef QAT_OPENSSL_PROVIDER
static int qat_sha3_ctrl(EVP_MD_CTX *ctx, int type, int p1, void *p2)
{
    qat_sha3_ctx *sha3_ctx = NULL;

    if (NULL == ctx) {
       WARN("ctx is NULL.\n");
       QATerr(QAT_F_QAT_SHA3_CTRL, QAT_R_CTX_NULL);
       return 0;
    }

    sha3_ctx = QAT_SHA3_GET_CTX(ctx);
    if (NULL == sha3_ctx) {
        WARN("SHA3ctx is NULL\n");
        QATerr(QAT_F_QAT_SHA3_CTRL, QAT_R_SHA3_CTX_NULL);
        return 0;
    }

    switch (type) {
    case EVP_MD_CTRL_XOF_LEN:
        sha3_ctx->md_size = p1;
        DEBUG("EVP_MD_CTRL_XOF_LEN, ctx = %p, type = %d, "
               "p1 = %d, p2 = %p\n", (void*)ctx, type, p1 ,(void*) p2);
        return 1;

    default:
        WARN("Invalid type %d\n", type);
        QATerr(QAT_F_QAT_SHA3_CTRL, QAT_R_INVALID_CTRL_TYPE);
        return -1;
    }
}
#endif

/******************************************************************************
* function:
*    qat_sha3_cleanup(EVP_MD_CTX *ctx)
*
* @param ctx    [IN]  - pointer to existing context
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function will cleanup all allocated resources required to perform the
*  cryptographic transform.
*
******************************************************************************/
#ifdef QAT_OPENSSL_PROVIDER
int qat_sha3_cleanup(QAT_KECCAK1600_CTX *ctx)
#else
static int qat_sha3_cleanup(EVP_MD_CTX *ctx)
#endif
{
    qat_sha3_ctx* sha3_ctx = NULL;
    CpaStatus status = 0;
    CpaCySymSessionSetupData* ssd = NULL;
    int ret_val = 1;

    if (NULL == ctx) {
        WARN("ctx is NULL\n");
        QATerr(QAT_F_QAT_SHA3_CLEANUP, QAT_R_CTX_NULL);
        return 0;
    }
#ifdef QAT_OPENSSL_PROVIDER
    sha3_ctx = ctx->qctx;
#else
    sha3_ctx = QAT_SHA3_GET_CTX(ctx);
#endif

    if (NULL == sha3_ctx) {
        WARN("sha3_ctx is NULL\n");
        QATerr(QAT_F_QAT_SHA3_CLEANUP, QAT_R_SHA3_CTX_NULL);
        return 0;
    }

    if (1 != sha3_ctx->session_init) {
        /* It is valid to call cleanup even if the context has not been
         * initialised. */
        return ret_val;
    }

    ssd = sha3_ctx->session_data;
    if (ssd) {
        if (sha3_ctx->session_init) {
            if (is_instance_available(sha3_ctx->inst_num)) {
                if ((status = cpaCySymRemoveSession(qat_instance_handles[sha3_ctx->inst_num], sha3_ctx->session_ctx))
                     != CPA_STATUS_SUCCESS) {
                     WARN("cpaCySymRemoveSession FAILED, status= %d.!\n", status);
                     ret_val = 0;
                /* Lets not return yet and instead make a best effort to
                 * cleanup the rest to avoid memory leaks
                 */
                 }
                 qaeCryptoMemFreeNonZero(sha3_ctx->session_ctx);
                 sha3_ctx->session_ctx = NULL;
	    }
        }

        /* Cleanup the memory */
        if (sha3_ctx->pSrcBufferList.pPrivateMetaData) {
            qaeCryptoMemFreeNonZero(sha3_ctx->pSrcBufferList.pPrivateMetaData);
            sha3_ctx->pSrcBufferList.pPrivateMetaData = NULL;
        }
        if (sha3_ctx->pDstBufferList.pPrivateMetaData) {
            qaeCryptoMemFreeNonZero(sha3_ctx->pDstBufferList.pPrivateMetaData);
            sha3_ctx->pDstBufferList.pPrivateMetaData = NULL;
        }
        if (sha3_ctx->opd) {
            OPENSSL_free(sha3_ctx->opd);
            sha3_ctx->opd = NULL;
        }
        OPENSSL_clear_free(ssd, sizeof(CpaCySymSessionSetupData));
    }
    sha3_ctx->session_init = 0;
    sha3_ctx->packet_size=0;
    return ret_val;
}

/******************************************************************************
 * function:
 *
 * static void qat_sha3_cb(void *pCallbackTag, CpaStatus status,
 *                        const CpaCySymOp operationType,
 *                        void *pOpData, CpaBufferList *pDstBuffer,
 *                        CpaBoolean verifyResult)
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
 Callback to indicate the completion of crypto operation
 ******************************************************************************/
static void qat_sha3_cb(void *pCallbackTag, CpaStatus status,
                        const CpaCySymOp operationType,
                        void *pOpData, CpaBufferList *pDstBuffer,
                        CpaBoolean verifyResult)
{
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_cipher_pipeline_requests_in_flight);
    }
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_HASH, pOpData,
                          NULL, CPA_TRUE);
}

/******************************************************************************
* function:
*         qat_sha3_setup_param(EVP_MD_CTX *ctx)
*
* @param ctx [IN] - pointer to context
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function synchronises the initialisation of the QAT session and
*  pre-allocates the necessary buffers for the session.
******************************************************************************/
static int qat_sha3_setup_param(qat_sha3_ctx *sha3_ctx)
{
    int numBuffers = 2;
    Cpa32U bufferMetaSize = 0;
    Cpa32U sctx_size = 0;
    CpaStatus status;

    if (sha3_ctx == NULL) {
        WARN("chachapoly context cipher data is NULL.\n");
        QATerr(QAT_F_QAT_SHA3_SETUP_PARAM, QAT_R_SHA3_CTX_NULL);
        return 0;
    }

    sha3_ctx->inst_num = get_next_inst_num();

    if (sha3_ctx->inst_num == QAT_INVALID_INSTANCE) {
        WARN("Failed to get a QAT instance.\n");
        QATerr(QAT_F_QAT_SHA3_SETUP_PARAM, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    DEBUG("inst_num = %d\n", sha3_ctx->inst_num);

    status = cpaCySymSessionCtxGetSize(qat_instance_handles[sha3_ctx->inst_num],
                                       sha3_ctx->session_data, &sctx_size);

    if (status != CPA_STATUS_SUCCESS) {
        WARN("Failed to get SessionCtx size.\n");
        QATerr(QAT_F_QAT_SHA3_SETUP_PARAM, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    DEBUG("Size of session ctx = %d\n", sctx_size);
    sha3_ctx->session_ctx = (CpaCySymSessionCtx) qaeCryptoMemAlloc(sctx_size,
                            __FILE__, __LINE__);
    if (sha3_ctx->session_ctx == NULL) {
        WARN("Memory alloc failed for session ctx\n");
        QATerr(QAT_F_QAT_SHA3_SETUP_PARAM, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    DUMP_SESSION_SETUP_DATA(sha3_ctx->session_data);
    /* Initialise Session data */
    status = cpaCySymInitSession(qat_instance_handles[sha3_ctx->inst_num],
                                 qat_sha3_cb,
                                 sha3_ctx->session_data, sha3_ctx->session_ctx);
    if (status != CPA_STATUS_SUCCESS) {
        WARN("cpaCySymInitSession failed! Status = %d\n", status);
        if (((status == CPA_STATUS_RESTARTING) || (status == CPA_STATUS_FAIL))) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d\n",
                           sha3_ctx->inst_num,
                           qat_instance_details[sha3_ctx->inst_num].qat_instance_info.physInstId.packageId);
        }
        QATerr(QAT_F_QAT_SHA3_SETUP_PARAM, ERR_R_INTERNAL_ERROR);
        qaeCryptoMemFreeNonZero(sha3_ctx->session_ctx);
        return 0;
    }

    /* Get buffer metasize */
    status = cpaCyBufferListGetMetaSize(qat_instance_handles[sha3_ctx->inst_num],
            numBuffers, &bufferMetaSize);
    if (status != CPA_STATUS_SUCCESS) {
        WARN("cpaCyBufferListGetMetaSize failed for the instance id %d\n",
              sha3_ctx->inst_num);
        QATerr(QAT_F_QAT_SHA3_SETUP_PARAM, ERR_R_INTERNAL_ERROR);
        qaeCryptoMemFreeNonZero(sha3_ctx->session_ctx);
        return 0;
    }

    DEBUG("Buffer MetaSize : %d\n", bufferMetaSize);
    sha3_ctx->pSrcBufferList.numBuffers = 1;
    sha3_ctx->pDstBufferList.numBuffers = 1;

    if (bufferMetaSize) {
        sha3_ctx->pSrcBufferList.pPrivateMetaData =
            qaeCryptoMemAlloc(bufferMetaSize, __FILE__, __LINE__);
        sha3_ctx->pDstBufferList.pPrivateMetaData =
            qaeCryptoMemAlloc(bufferMetaSize, __FILE__, __LINE__);
        if (sha3_ctx->pSrcBufferList.pPrivateMetaData == NULL ||
            sha3_ctx->pDstBufferList.pPrivateMetaData == NULL) {
            WARN("QMEM alloc failed for PrivateData\n");
            QATerr(QAT_F_QAT_SHA3_SETUP_PARAM, ERR_R_MALLOC_FAILURE);
            qaeCryptoMemFreeNonZero(sha3_ctx->session_ctx);
            qaeCryptoMemFreeNonZero(sha3_ctx->pSrcBufferList.pPrivateMetaData);
            qaeCryptoMemFreeNonZero(sha3_ctx->pDstBufferList.pPrivateMetaData);
            return 0;
        }
    } else {
        sha3_ctx->pSrcBufferList.pPrivateMetaData = NULL;
        sha3_ctx->pDstBufferList.pPrivateMetaData = NULL;
    }

    sha3_ctx->pDstBufferList.pUserData = NULL;
    sha3_ctx->pSrcBufferList.pUserData = NULL;
    sha3_ctx->pSrcBufferList.pBuffers = sha3_ctx->src_buffer;
    sha3_ctx->pDstBufferList.pBuffers = sha3_ctx->dst_buffer;
    sha3_ctx->src_buffer[0].pData = NULL;
    sha3_ctx->dst_buffer[0].pData = NULL;
    /* Mark session init as set.*/
    sha3_ctx->session_init = 1;

    return 1;
}

/******************************************************************************
* function:
*    qat_sha3_final(EVP_MD_CTX *ctx, unsigned char *md)
*
* @param ctx       [IN]  - pointer to existing context
* @param md        [OUT] - output buffer for digest result
*
* @retval -1     function failed
* @retval  1     function succeeded
*
* description:
*    This function performs the copy operation of digest into md buffer.
*
******************************************************************************/
#ifdef QAT_OPENSSL_PROVIDER
int qat_sha3_final(QAT_KECCAK1600_CTX *ctx, unsigned char *md)
#else
static int qat_sha3_final(EVP_MD_CTX *ctx, unsigned char *md)
#endif
{
    qat_sha3_ctx *sha3_ctx = NULL;
    int ret = 1;
    if (unlikely(ctx == NULL)) {
        WARN("ctx parameter is NULL.\n");
        QATerr(QAT_F_QAT_SHA3_FINAL, QAT_R_CTX_NULL);
        return -1;
    }

#ifdef QAT_OPENSSL_PROVIDER
    sha3_ctx = ctx->qctx;
#else
    sha3_ctx = QAT_SHA3_GET_CTX(ctx);
#endif
    if (sha3_ctx == NULL) {
        WARN("SHA3 context hash data is NULL.\n");
        QATerr(QAT_F_QAT_SHA3_FINAL, QAT_R_SHA3_CTX_NULL);
        return -1;
    }
    if (sha3_ctx->md_size == 0) {
        WARN("MD Size is NULL.\n");
        return ret;
    }
#ifndef QAT_OPENSSL_PROVIDER
#ifndef ENABLE_QAT_HW_SMALL_PKT_OFFLOAD
    if(sha3_ctx->packet_size <= CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT ) {
       ret = EVP_MD_meth_get_final(GET_SW_SHA3_DIGEST(ctx))
             (ctx, md);
       return ret;
    }
#endif
#endif
    /* Copy digest result into "md" buffer. */
    memcpy(md, sha3_ctx->digest_data, sha3_ctx->md_size);

    memset(sha3_ctx->digest_data, 0x00, sha3_ctx->md_size);

    return ret;
}

/******************************************************************************
* function:
*    qat_sha3_update(EVP_MD_CTX *ctx, const void *in, size_t len)
*
* @param ctx        [IN]  - pointer to existing context
* @param in         [IN]  - input buffer
* @param len        [IN]  - length of input buffer
*
* @retval -1      function failed
* @retval len     function succeeded
*
* description:
*    This function performs the cryptographic transform according to the
*  parameters setup during initialisation.
*
*
******************************************************************************/
#ifdef QAT_OPENSSL_PROVIDER
int qat_sha3_update(QAT_KECCAK1600_CTX *ctx, const void *in, size_t len)
#else
static int qat_sha3_update(EVP_MD_CTX *ctx, const void *in, size_t len)
#endif
{
    int outlen = 0;
    int job_ret = 0;
    CpaStatus status;
    op_done_t op_done;
    thread_local_variables_t *tlv = NULL;
    qat_sha3_ctx *sha3_ctx = NULL;
    unsigned buffer_len = 0;
    Cpa8U *pDigestBuffer = NULL;
#ifndef QAT_OPENSSL_PROVIDER
#ifndef ENABLE_QAT_HW_SMALL_PKT_OFFLOAD
    int retVal = 0;
#endif
#endif

    if (unlikely(ctx == NULL)) {
        WARN("ctx parameter is NULL.\n");
        QATerr(QAT_F_QAT_SHA3_UPDATE, QAT_R_CTX_NULL);
        return -1;
    }
#ifdef QAT_OPENSSL_PROVIDER
    sha3_ctx = ctx->qctx;
#else
    sha3_ctx = QAT_SHA3_GET_CTX(ctx);
#endif
    if (sha3_ctx == NULL) {
        WARN("SHA3 context hash data is NULL.\n");
        QATerr(QAT_F_QAT_SHA3_UPDATE, QAT_R_SHA3_CTX_NULL);
        return -1;
    }

    if (in != NULL) {
        sha3_ctx->packet_size = len;
#ifndef QAT_OPENSSL_PROVIDER
# ifndef ENABLE_QAT_HW_SMALL_PKT_OFFLOAD
        if (len <=
              qat_pkt_threshold_table_get_threshold(EVP_MD_CTX_type(ctx))) {
            KECCAK1600_CTX *k_ctx = EVP_MD_CTX_md_data(ctx);
            memset(k_ctx->A, 0, sizeof(k_ctx->A));
            retVal = EVP_MD_meth_get_update(GET_SW_SHA3_DIGEST(ctx))
                     (ctx, in, len);
	    if (retVal) {
                outlen = len;
            }
	    return outlen;
        }
# endif
#endif
        if (sha3_ctx->context_params_set && !sha3_ctx->session_init) {
            /* Set SHA3 opdata params and initialise session. */
            if (!qat_sha3_setup_param(sha3_ctx)) {
                 WARN("SHA3 operational params setup failed.\n");
                 QATerr(QAT_F_QAT_SHA3_UPDATE, ERR_R_INTERNAL_ERROR);
                 goto err;
            }
        }
        DEBUG("input length : %zu\n", len);

	    /*Get the md ctx size*/
#ifdef QAT_OPENSSL_PROVIDER
        sha3_ctx->md_size = ctx->md_size;
#else
        sha3_ctx->md_size = EVP_MD_CTX_size(ctx);
#endif
        /* Allocate buffer for HASH operation. */
        buffer_len = len + sha3_ctx->digest_size ;
        sha3_ctx->src_buffer[0].pData = qaeCryptoMemAlloc( buffer_len , __FILE__, __LINE__);

        if ((sha3_ctx->src_buffer[0].pData) == NULL) {
                WARN("Unable to allocate memory for buffer for sha3 hash.\n");
                QATerr(QAT_F_QAT_SHA3_UPDATE, ERR_R_MALLOC_FAILURE);
                goto err;
        }

        sha3_ctx->dst_buffer[0].pData = sha3_ctx->src_buffer[0].pData;

        memcpy(sha3_ctx->src_buffer[0].pData, in, buffer_len);

        tlv = qat_check_create_local_variables();
        if (NULL == tlv) {
            WARN("could not create local variables\n");
            QATerr(QAT_F_QAT_SHA3_UPDATE, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        qat_init_op_done(&op_done);
        if (op_done.job != NULL) {
            if (qat_setup_async_event_notification(op_done.job) == 0) {
                WARN("Failed to setup async event notification\n");
                QATerr(QAT_F_QAT_SHA3_UPDATE, ERR_R_INTERNAL_ERROR);
                qat_cleanup_op_done(&op_done);
                goto err;
            }
        }
        /* The variables in and out remain separate */
        pDigestBuffer =  sha3_ctx->src_buffer[0].pData  + len ;
        sha3_ctx->src_buffer[0].dataLenInBytes = buffer_len;
        sha3_ctx->pSrcBufferList.pUserData = NULL;
        sha3_ctx->dst_buffer[0].dataLenInBytes = buffer_len;
        sha3_ctx->pDstBufferList.pUserData = NULL;

        sha3_ctx->opd->sessionCtx = sha3_ctx->session_ctx;
        sha3_ctx->opd->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        /* Set messageLenToHashInBytes to the hash buffer length. */
        sha3_ctx->opd->messageLenToHashInBytes = len;
        /* Set the offset from where the tag needs to be written. */
        sha3_ctx->opd->hashStartSrcOffsetInBytes = 0;
        sha3_ctx->opd->pDigestResult = (Cpa8U *) pDigestBuffer;

        if (!is_instance_available(sha3_ctx->inst_num)) {
            WARN("QAT instance %d not available.\n", sha3_ctx->inst_num);
            QATerr(QAT_F_QAT_SHA3_UPDATE, ERR_R_INTERNAL_ERROR);
            if (op_done.job != NULL) {
                qat_clear_async_event_notification(op_done.job);
            }
            qat_cleanup_op_done(&op_done);
            goto err;
        }

        DUMP_SYM_PERFORM_OP_SHA3(qat_instance_handles[sha3_ctx->inst_num],
                                 sha3_ctx->opd, sha3_ctx->pSrcBufferList,
                                 sha3_ctx->pDstBufferList);
        status = qat_sym_perform_op(sha3_ctx->inst_num, &op_done, sha3_ctx->opd,
                                    &(sha3_ctx->pSrcBufferList),
                                    &(sha3_ctx->pDstBufferList),
                                    &(sha3_ctx->session_data->verifyDigest));
        if (status != CPA_STATUS_SUCCESS) {
            if (((status == CPA_STATUS_RESTARTING) || (status == CPA_STATUS_FAIL))) {
                  CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - %s\n",
                                 sha3_ctx->inst_num,
                                 qat_instance_details[sha3_ctx->inst_num].qat_instance_info.physInstId.packageId);
            }
            QATerr(QAT_F_QAT_SHA3_UPDATE, ERR_R_INTERNAL_ERROR);
            if (op_done.job != NULL) {
                qat_clear_async_event_notification(op_done.job);
            }
            qat_cleanup_op_done(&op_done);
            goto err;
        }

        QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
        if (qat_use_signals()) {
            if (tlv->localOpsInFlight == 1) {
                if (qat_kill_thread(qat_timer_poll_func_thread, SIGUSR1) != 0) {
                     WARN("qat_kill_thread error\n");
                     QATerr(QAT_F_QAT_SHA3_UPDATE, ERR_R_INTERNAL_ERROR);
                     QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                     goto err;
                }
            }
        }

        if (enable_heuristic_polling) {
             QAT_ATOMIC_INC(num_cipher_pipeline_requests_in_flight);
        }

        do {
            if (op_done.job != NULL) {
                /* If we get a failure on qat_pause_job then we will
                   not flag an error here and quit because we have
                   an asynchronous request in flight.
                   We don't want to start cleaning up data
                   structures that are still being used. If
                   qat_pause_job fails we will just yield and
                   loop around and try again until the request
                   completes and we can continue. */
                if ((job_ret = qat_pause_job(op_done.job, ASYNC_STATUS_OK)) == 0)
                         pthread_yield();
                } else {
                    pthread_yield();
                }
        } while (!op_done.flag ||
                  QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

        DUMP_SYM_PERFORM_OP_SHA3_OUTPUT(sha3_ctx->opd, sha3_ctx->pDstBufferList);

        QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

        if (op_done.verifyResult != CPA_TRUE) {
            WARN("Verification of result failed\n");
            QATerr(QAT_F_QAT_SHA3_UPDATE, ERR_R_INTERNAL_ERROR);
            if (op_done.status == CPA_STATUS_FAIL) {
                CRYPTO_QAT_LOG("Verification of result failed for qat inst_num %d device_id %d - %s\n",
                                inst_num,
                                qat_instance_details[sha3_ctx->_inst_num].qat_instance_info.physInstId.packageId);
                qat_cleanup_op_done(&op_done);
                goto err;
            }
        }
        outlen = len;
        qat_cleanup_op_done(&op_done);
        memcpy(sha3_ctx->digest_data, sha3_ctx->opd->pDigestResult, sha3_ctx->md_size);
    }
err:
    qaeCryptoMemFreeNonZero(sha3_ctx->src_buffer[0].pData);
    sha3_ctx->src_buffer[0].pData = NULL;
    sha3_ctx->dst_buffer[0].pData = NULL;
    sha3_ctx->opd->pDigestResult = NULL;
    return outlen;
}
#endif
