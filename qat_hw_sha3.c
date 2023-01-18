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

#ifdef ENABLE_QAT_HW_SHA3
# ifndef QAT_OPENSSL_PROVIDER
static int qat_sha3_init(EVP_MD_CTX *ctx);
static int qat_sha3_cleanup(EVP_MD_CTX *ctx);
static int qat_sha3_update(EVP_MD_CTX *ctx, const void *in, size_t len);
static int qat_sha3_final(EVP_MD_CTX *ctx, unsigned char *md);
static int qat_sha3_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int qat_sha3_ctrl(EVP_MD_CTX *ctx, int type, int p1,void *p2);
static int qat_get_sha3_block_size(int nid);
static int qat_get_sha3_state_size(int nid);
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
        res &= EVP_MD_meth_set_app_datasize(c,
			sizeof(EVP_MD*) + sizeof(qat_sha3_ctx) + sizeof(SHA3_CTX));
        res &= EVP_MD_meth_set_flags(c, EVP_MD_CTX_FLAG_REUSE);
        res &= EVP_MD_meth_set_init(c, qat_sha3_init);
        res &= EVP_MD_meth_set_update(c, qat_sha3_update);
        res &= EVP_MD_meth_set_final(c, qat_sha3_final);
        res &= EVP_MD_meth_set_copy(c, qat_sha3_copy);
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

static int qat_get_sha3_data_size(int nid)
{

    switch (nid) {
    case NID_sha3_224:
        return QAT_SHA3_224_OFFLOAD_THRESHOLD;
    case NID_sha3_256:
        return QAT_SHA3_256_OFFLOAD_THRESHOLD;
    case NID_sha3_384:
        return QAT_SHA3_384_OFFLOAD_THRESHOLD;
    case NID_sha3_512:
        return QAT_SHA3_512_OFFLOAD_THRESHOLD;
    default:
        WARN("Unsupported Hash Algorithm\n");
        return 0;
    }
}

static int qat_get_hash_alg_data(int nid)
{

    switch (nid) {
    case NID_sha3_224:
        return CPA_CY_SYM_HASH_SHA3_224;
    case NID_sha3_256:
        return CPA_CY_SYM_HASH_SHA3_256;
    case NID_sha3_384:
        return CPA_CY_SYM_HASH_SHA3_384;
    case NID_sha3_512:
        return CPA_CY_SYM_HASH_SHA3_512;
    default:
        WARN("Unsupported Hash Algorithm\n");
        return 0;
    }
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
    CpaCySymSessionSetupData *session_data;
    CpaCySymOpData *pOpData;

    if (NULL == sha3_ctx || NULL == ctx){
        WARN("sha3_ctx or ctx is NULL\n");
        QATerr(QAT_F_QAT_SHA3_SESSION_DATA_INIT, QAT_R_SHA3_CTX_NULL);
        return 0;
    }

    session_data = OPENSSL_zalloc(sizeof(CpaCySymSessionSetupData));
    if (NULL == session_data) {
        WARN("session setup data Malloc failure\n");
        QATerr(QAT_F_QAT_SHA3_SESSION_DATA_INIT, QAT_R_SSD_MALLOC_FAILURE);
        return 0;
    }

    /* Set priority and operation of this session */
    session_data->sessionPriority = CPA_CY_PRIORITY_HIGH;
    session_data->symOperation = CPA_CY_SYM_OP_HASH;
    /* --- Hash Configuration --- */

    /* Set the hash mode and the length of the digest */
#ifdef QAT_OPENSSL_PROVIDER
    session_data->hashSetupData.hashAlgorithm = qat_get_hash_alg_data(ctx->md_type); 
#else
    session_data->hashSetupData.hashAlgorithm = qat_get_hash_alg_data(EVP_MD_CTX_type(ctx));
#endif
    session_data->hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_PLAIN;
    session_data->hashSetupData.digestResultLenInBytes = sha3_ctx->md_size;
    session_data->hashSetupData.authModeSetupData.authKey = NULL;
    session_data->hashSetupData.nestedModeSetupData.pInnerPrefixData = NULL;
    session_data->hashSetupData.nestedModeSetupData.pOuterPrefixData = NULL;

    /* Tag follows immediately after the region to hash */
    session_data->digestIsAppended = CPA_FALSE;

    /* digestVerify is not required to be set.*/
    session_data->verifyDigest = CPA_FALSE;

    pOpData = OPENSSL_zalloc(sizeof(template_opData));
    if (pOpData == NULL) {
        WARN("memory allocation failed for symopData struct.\n");
        QATerr(QAT_F_QAT_SHA3_SESSION_DATA_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    sha3_ctx->session_data = session_data;
    sha3_ctx->opd = pOpData;

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

    DEBUG("QAT HW SHA3 init Started\n");
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
    sha3_ctx->md_size = ctx->md_size;
#else
    sha3_ctx->md_size = EVP_MD_CTX_size(ctx);
#endif
    if (!sha3_ctx->md_size) {
        WARN("sha3_ctx md size is NULL\n");
        return 0;
    }

    sha3_ctx->context_params_set = 0;
    sha3_ctx->session_init = 0;

#ifndef QAT_OPENSSL_PROVIDER
#ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
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
        WARN("digest cleanup without md_data\n");
        return 1;
    }

    if (sha3_ctx->session_init) {

        if (sha3_ctx->pSrcBufferList.pPrivateMetaData) {
            qaeCryptoMemFreeNonZero(sha3_ctx->pSrcBufferList.pPrivateMetaData);
            sha3_ctx->pSrcBufferList.pPrivateMetaData = NULL;
        }

        if (is_instance_available(sha3_ctx->inst_num)) {

            /* Wait for in-flight requests before removing session */
            CpaBoolean sessionInUse = CPA_FALSE;

            do
            {
                cpaCySymSessionInUse(sha3_ctx->session_ctx, &sessionInUse);
            } while (sessionInUse);

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

        sha3_ctx->session_init = 0;
    }

    if (sha3_ctx->context_params_set) {
        if (sha3_ctx->opd) {
            OPENSSL_free(sha3_ctx->opd);
            sha3_ctx->opd = NULL;
        }
        OPENSSL_clear_free(sha3_ctx->session_data, sizeof(CpaCySymSessionSetupData));

        sha3_ctx->context_params_set = 0;
    }

    DEBUG("cleanup done\n");
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
        WARN("sha3 context data is NULL.\n");
        QATerr(QAT_F_QAT_SHA3_SETUP_PARAM, QAT_R_SHA3_CTX_NULL);
        return 0;
    }

    /* Allocate instance */
    sha3_ctx->inst_num = get_next_inst_num(INSTANCE_TYPE_CRYPTO_SYM);
    if (sha3_ctx->inst_num == QAT_INVALID_INSTANCE) {
        WARN("Failed to get a QAT instance.\n");
        QATerr(QAT_F_QAT_SHA3_SETUP_PARAM, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    DEBUG("inst_num = %d\n", sha3_ctx->inst_num);

    /* Determine size of session context to allocate */
    status = cpaCySymSessionCtxGetSize(
        qat_instance_handles[sha3_ctx->inst_num],
        sha3_ctx->session_data,
        &sctx_size);
    if (status != CPA_STATUS_SUCCESS) {
        WARN("Failed to get SessionCtx size.\n");
        QATerr(QAT_F_QAT_SHA3_SETUP_PARAM, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    DEBUG("Size of session ctx = %d\n", sctx_size);

    sha3_ctx->session_ctx =
        (CpaCySymSessionCtx)qaeCryptoMemAlloc(sctx_size, __FILE__, __LINE__);
    if (sha3_ctx->session_ctx == NULL) {
        WARN("Memory alloc failed for session ctx\n");
        QATerr(QAT_F_QAT_SHA3_SETUP_PARAM, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    DUMP_SESSION_SETUP_DATA(sha3_ctx->session_data);
    /* Initialise Session data */
    /* Remove session should be added if session init fail. */
    status = cpaCySymInitSession(
        qat_instance_handles[sha3_ctx->inst_num],
        qat_sha3_cb,
        sha3_ctx->session_data,
        sha3_ctx->session_ctx);
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

    if (bufferMetaSize) {
        sha3_ctx->pSrcBufferList.pPrivateMetaData =
            qaeCryptoMemAlloc(bufferMetaSize, __FILE__, __LINE__);
        if (sha3_ctx->pSrcBufferList.pPrivateMetaData == NULL) {
            WARN("QMEM alloc failed for PrivateData\n");
            QATerr(QAT_F_QAT_SHA3_SETUP_PARAM, ERR_R_MALLOC_FAILURE);
            qaeCryptoMemFreeNonZero(sha3_ctx->session_ctx);
            qaeCryptoMemFreeNonZero(sha3_ctx->pSrcBufferList.pPrivateMetaData);
            return 0;
        }
        sha3_ctx->pSrcBufferList.numBuffers = 1;

    } else {
        sha3_ctx->pSrcBufferList.pPrivateMetaData = NULL;
        sha3_ctx->pSrcBufferList.numBuffers = 0;
    }

    sha3_ctx->pSrcBufferList.pUserData = NULL;
    sha3_ctx->pSrcBufferList.pBuffers = &sha3_ctx->src_buffer;
    sha3_ctx->src_buffer.pData = NULL;

    /* Mark session init as set. */
    sha3_ctx->session_init = 1;

    return 1;
}

#ifdef QAT_OPENSSL_PROVIDER
static int qat_hw_sha3_offload(QAT_KECCAK1600_CTX *ctx, const void *in, size_t len, int packet_type)
#else
static int qat_hw_sha3_offload(EVP_MD_CTX *ctx, const void *in, size_t len, int packet_type)
#endif
{
    int job_ret = 0;
    CpaStatus status;
    op_done_t op_done;
    thread_local_variables_t *tlv = NULL;
    qat_sha3_ctx *sha3_ctx = NULL;
    Cpa8U *pDigestBuffer = NULL;
    int ret = 0;

    if (unlikely((ctx == NULL) || (in == NULL))) {
        WARN("Either ctx %p or in %p is NULL\n", ctx, in);
        QATerr(QAT_F_QAT_HW_SHA3_OFFLOAD, QAT_R_INVALID_INPUT);
        return -1;
    }

#ifdef QAT_OPENSSL_PROVIDER
    sha3_ctx = ctx->qctx;
#else
    sha3_ctx = QAT_SHA3_GET_CTX(ctx);
#endif
    if (sha3_ctx == NULL) {
        WARN("SHA3 context hash data is NULL.\n");
        QATerr(QAT_F_QAT_HW_SHA3_OFFLOAD, QAT_R_SHA3_CTX_NULL);
        return -1;
    }

#ifdef QAT_OPENSSL_PROVIDER
    sha3_ctx->md_size = ctx->md_size;
#else
    sha3_ctx->md_size = EVP_MD_CTX_size(ctx);
#endif

    /* Initialize QAT session */
    if (!sha3_ctx->context_params_set) {
        if (0 == qat_sha3_session_data_init(ctx, sha3_ctx)) {
            WARN("qat_session_data_init failed.\n");
            QATerr(QAT_F_QAT_HW_SHA3_OFFLOAD, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    if (sha3_ctx->context_params_set && !sha3_ctx->session_init) {
        /* Set SHA3 opdata params and initialise session. */
        if (!qat_sha3_setup_param(sha3_ctx)) {
            WARN("SHA3 operational params setup failed.\n");
            QATerr(QAT_F_QAT_HW_SHA3_OFFLOAD, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    /* The variables in and out remain separate */
    sha3_ctx->src_buffer.pData = qaeCryptoMemAlloc(len + sha3_ctx->md_size, __FILE__, __LINE__);
    if ((sha3_ctx->src_buffer.pData) == NULL) {
        WARN("Unable to allocate memory for buffer for sha3 hash.\n");
        QATerr(QAT_F_QAT_HW_SHA3_OFFLOAD, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    sha3_ctx->src_buffer.dataLenInBytes = len + sha3_ctx->md_size;
    pDigestBuffer = sha3_ctx->src_buffer.pData + len;

    memcpy(sha3_ctx->src_buffer.pData, in, len);

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        QATerr(QAT_F_QAT_HW_SHA3_OFFLOAD, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_HW_SHA3_OFFLOAD, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            goto err;
        }
    }

    sha3_ctx->pSrcBufferList.pUserData = NULL;

    sha3_ctx->opd->sessionCtx = sha3_ctx->session_ctx;

    /* The type 'last partial cannot set without a partial set previous */
    if (CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL == packet_type &&
        sha3_ctx->qat_offloaded == 0) {
        DEBUG("SHA3 data packet type: FULL\n");
        sha3_ctx->opd->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
    }
    else {
        DEBUG("SHA3 data packet type partial or last partial\n");
        sha3_ctx->opd->packetType = packet_type;
    }

    /* The message length, in bytes, of the source buffer that the hash
     * will be computed on. */
    sha3_ctx->opd->messageLenToHashInBytes = len;
    sha3_ctx->opd->pDigestResult = pDigestBuffer;

    if (!is_instance_available(sha3_ctx->inst_num)) {
        WARN("QAT instance %d not available.\n", sha3_ctx->inst_num);
        QATerr(QAT_F_QAT_HW_SHA3_OFFLOAD, ERR_R_INTERNAL_ERROR);
        if (op_done.job != NULL) {
            qat_clear_async_event_notification(op_done.job);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    DUMP_SYM_PERFORM_OP_SHA3(qat_instance_handles[sha3_ctx->inst_num],
                             sha3_ctx->opd, sha3_ctx->pSrcBufferList,
                             sha3_ctx->pSrcBufferList);
    /* same src & dst for an in-place operation */
    status = qat_sym_perform_op(sha3_ctx->inst_num,
                                &op_done,
                                sha3_ctx->opd,
                                &(sha3_ctx->pSrcBufferList),
                                &(sha3_ctx->pSrcBufferList),
                                &(sha3_ctx->session_data->verifyDigest));

    if (status != CPA_STATUS_SUCCESS) {
        if (((status == CPA_STATUS_RESTARTING) || (status == CPA_STATUS_FAIL))) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - %s\n",
                            sha3_ctx->inst_num,
                            qat_instance_details[sha3_ctx->inst_num].qat_instance_info.physInstId.packageId);
        }
        QATerr(QAT_F_QAT_HW_SHA3_OFFLOAD, ERR_R_INTERNAL_ERROR);
        if (op_done.job != NULL) {
            qat_clear_async_event_notification(op_done.job);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n",
                    &hw_polling_thread_sem);
                QATerr(QAT_F_QAT_HW_SHA3_OFFLOAD, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                if (op_done.job != NULL) {
                    qat_clear_async_event_notification(op_done.job);
                }
                qat_cleanup_op_done(&op_done);
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
            if ((job_ret = qat_pause_job(op_done.job, ASYNC_STATUS_OK)) == 0) {
                sched_yield();
            }
        } else {
            sched_yield();
        }
    } while (!op_done.flag ||
                QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

    if (op_done.verifyResult != CPA_TRUE) {
        WARN("Verification of result failed\n");
        QATerr(QAT_F_QAT_HW_SHA3_OFFLOAD, ERR_R_INTERNAL_ERROR);
        if (op_done.status == CPA_STATUS_FAIL) {
            CRYPTO_QAT_LOG("Verification of result failed for qat inst_num %d device_id %d - %s\n",
                            inst_num,
                            qat_instance_details[sha3_ctx->_inst_num].qat_instance_info.physInstId.packageId);
            qat_cleanup_op_done(&op_done);
            goto err;
        }
    }
    qat_cleanup_op_done(&op_done);

    /* final partial */
    if (CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL == packet_type) {
        memcpy(sha3_ctx->digest_data, sha3_ctx->opd->pDigestResult, sha3_ctx->md_size);
    }
    else {
        sha3_ctx->qat_offloaded = 1;
    }
    ret = 1;

err:
    if (sha3_ctx->src_buffer.pData) {
        qaeCryptoMemFreeNonZero(sha3_ctx->src_buffer.pData);
        sha3_ctx->src_buffer.pData = NULL;
        sha3_ctx->opd->pDigestResult = NULL;
    }
    return ret;
}

#ifdef QAT_OPENSSL_PROVIDER
int qat_sha3_copy(QAT_KECCAK1600_CTX *to, const QAT_KECCAK1600_CTX *from)
#else
static int qat_sha3_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
#endif
{
    qat_sha3_ctx *qat_from, *qat_to;

    if (NULL == from || NULL == to) {
        WARN("Either from %p or to %p are NULL\n", from, to);
        return 0;
    }

#ifdef QAT_OPENSSL_PROVIDER
    qat_from = from->qctx;
    if (qat_from == NULL) {
        WARN("digest copy without md_data\n");
        return 1;
    }
    qat_to = to->qctx;
#else
    qat_from = QAT_SHA3_GET_CTX(from);
    if (qat_from == NULL) {
        WARN("digest copy without md_data\n");
        return 1;
    }
    qat_to = QAT_SHA3_GET_CTX(to);
#endif

    if (NULL == qat_to) {
        WARN("qat_to %p is NULL\n", qat_to);
        return 0;
    }

    qat_to->pSrcBufferList.numBuffers = 1;

    if (qat_from->pSrcBufferList.pPrivateMetaData) {
        qat_to->pSrcBufferList.pPrivateMetaData = qat_from->pSrcBufferList.pPrivateMetaData;
    } else {
        qat_to->pSrcBufferList.pPrivateMetaData = NULL;
    }

    qat_to->pSrcBufferList.pUserData = NULL;
    qat_to->pSrcBufferList.pBuffers = &qat_to->src_buffer;

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

    if (unlikely(ctx == NULL)) {
        WARN("ctx parameter is NULL.\n");
        QATerr(QAT_F_QAT_SHA3_FINAL, QAT_R_CTX_NULL);
        return -1;
    }

    DEBUG("QAT HW SHA3 final, ctx %p, md %p\n", ctx, md);
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

#ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    /* Another way to get threshold is qat_pkt_threshold_table_get_threshold */
    if (sha3_ctx->rcv_count < CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT) {
        int ret = 0;
# ifndef QAT_OPENSSL_PROVIDER
        ENGINE *e = ENGINE_get_digest_engine(EVP_MD_CTX_type(ctx));
        if (e != NULL)
            ENGINE_unregister_digests(e);

        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

        if (md_ctx == NULL)
            return 0;

        EVP_MD_CTX_set_flags(md_ctx, EVP_MD_CTX_FLAG_ONESHOT);
        ret = EVP_DigestInit_ex(md_ctx, qat_sha3_sw_impl(EVP_MD_CTX_type(ctx)), NULL);
        ret &= EVP_DigestUpdate(md_ctx, sha3_ctx->data, sha3_ctx->num);
        ret &= EVP_DigestFinal_ex(md_ctx, md, NULL);
        EVP_MD_CTX_free(md_ctx);
# else
        EVP_MD_CTX_set_flags(ctx->sw_md_ctx, EVP_MD_CTX_FLAG_ONESHOT);

        ctx->sw_md = EVP_MD_fetch(NULL, EVP_MD_get0_name(qat_sha3_sw_impl(ctx->md_type)),
			          "provider=default");
        ret = EVP_DigestInit_ex(ctx->sw_md_ctx, ctx->sw_md, NULL);
        ret &= EVP_DigestUpdate(ctx->sw_md_ctx, sha3_ctx->data, sha3_ctx->num);
        ret &= EVP_DigestFinal_ex(ctx->sw_md_ctx, md, NULL);

        OPENSSL_clear_free(sha3_ctx, sizeof(qat_sha3_ctx));
        EVP_MD_CTX_free(ctx->sw_md_ctx);
        EVP_MD_free(ctx->sw_md);
        ctx->sw_md_ctx = NULL;
        ctx->sw_md = NULL;

# endif
        return ret;
   }
#endif

    /* If num is 0, and a request has offloaded the
     * packet type previous should be LAST_PARTIAL or FULL */
    qat_hw_sha3_offload(ctx, sha3_ctx->data, sha3_ctx->num, CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL);

    /* Copy digest result into "md" buffer. */
    memcpy(md, sha3_ctx->digest_data, sha3_ctx->md_size);

    if (!qat_sha3_cleanup(ctx)) {
        WARN("qat_sha3_cleanup failed\n");
        QATerr(QAT_F_QAT_SHA3_FINAL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

#ifdef QAT_OPENSSL_PROVIDER
    OPENSSL_clear_free(sha3_ctx, sizeof(qat_sha3_ctx));
#endif
    return 1;
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
    const unsigned char *data = in;
    qat_sha3_ctx *sha3_ctx = NULL;
    unsigned char *p;
    size_t n;
    unsigned int data_size = 0;

    if (unlikely(ctx == NULL)) {
        WARN("ctx parameter is NULL.\n");
        QATerr(QAT_F_QAT_SHA3_UPDATE, QAT_R_CTX_NULL);
        return -1;
    }

    DEBUG("QAT HW SHA3 Update ctx %p, in %p, len %ld\n", ctx, in, len);

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

#ifdef QAT_OPENSSL_PROVIDER
    data_size = qat_get_sha3_data_size(ctx->md_type);
#else
    data_size = qat_get_sha3_data_size(EVP_MD_CTX_type(ctx));
#endif

    n = sha3_ctx->num;
    sha3_ctx->rcv_count += len;

    /* Packets left from previous process */
    if (n != 0) {
        p = (unsigned char *)sha3_ctx->data;

        /* Offload threshold met */
        if (len >= data_size || len + n >= data_size) {
            /* Use part of new packet filling the packet buffer */
            memcpy(p + n, data, data_size - n);
            qat_hw_sha3_offload(ctx, p, data_size, CPA_CY_SYM_PACKET_TYPE_PARTIAL);

            /* The data left of new input */
            n = data_size - n;
            data += n;
            len -= n;
            sha3_ctx->num = 0;
            /*
             * We use memset rather than OPENSSL_cleanse() here deliberately.
             * Using OPENSSL_cleanse() here could be a performance issue. It
             * will get properly cleansed on finalisation so this isn't a
             * security problem.
             */
            memset(p, 0, data_size); /* keep it zeroed */
        } else {
            /* Append the new packets to buffer */
            memcpy(p + n, data, len);
            sha3_ctx->num += (unsigned int)len;

            return 1;
        }
    }

    n = len / data_size;
    if (n > 0) {
        n *= data_size;

        qat_hw_sha3_offload(ctx, in, n, CPA_CY_SYM_PACKET_TYPE_PARTIAL);

        data += n;
        len -= n;
    }

    /* Save the bytes into buffer if there're some bytes left
     * after the previous update. */
    if (len != 0) {
        p = (unsigned char *)sha3_ctx->data;
        sha3_ctx->num = (unsigned int)len;
        memcpy(p, data, len);
    }

    return 1;
}
#endif
