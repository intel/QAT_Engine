/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023 Intel Corporation.
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
 * @file qat_hw_sm3.c
 *
 * This file contains the engine implementations for SM3 Hash operations
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
#include "qat_hw_sm3.h"
#include "qat_hw_ciphers.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/tls1.h>
#include <openssl/async.h>
#include <openssl/ssl.h>

#ifdef ENABLE_QAT_HW_SM3

static inline QAT_SM3_CTX *qat_hw_sm3_get_ctx(EVP_MD_CTX *ctx)
{
    if (unlikely(ctx == NULL)) {
        WARN("hw sm3 ctx %p is NULL\n", ctx);
        return NULL;
    }

    return ((QAT_SM3_CTX *) (EVP_MD_CTX_md_data(ctx) + sizeof(SM3_CTX)));
}

/******************************************************************************
 * function:
 *
 * static void qat_hw_sm3_cb(void *pCallbackTag, CpaStatus status,
 *                           const CpaCySymOp operationType,
 *                           void *pOpData, CpaBufferList *pDstBuffer,
 *                           CpaBoolean verifyResult)
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
static void qat_hw_sm3_cb(void *pCallbackTag, CpaStatus status,
                          const CpaCySymOp operationType,
                          void *pOpData, CpaBufferList *pDstBuffer,
                          CpaBoolean verifyResult)
{
    if (enable_heuristic_polling)
        QAT_ATOMIC_DEC(num_cipher_pipeline_requests_in_flight);

    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_HASH, pOpData,
                          NULL, CPA_TRUE);
}

/******************************************************************************
* function:
*         qat_hw_sm3_setup_param(EVP_MD_CTX *ctx)
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
static int qat_hw_sm3_setup_param(QAT_SM3_CTX *qat_sm3_ctx)
{
    int numBuffers = 2;
    Cpa32U bufferMetaSize = 0;
    Cpa32U sctx_size = 0;
    CpaStatus status;
    CpaCySymSessionSetupData *session_data;

    session_data = OPENSSL_zalloc(sizeof(CpaCySymSessionSetupData)
                                  + sizeof(CpaCySymOpData)
                                  + sizeof(int));
    if (NULL == session_data) {
        WARN("session setup data Malloc failure\n");
        QATerr(QAT_F_QAT_HW_SM3_SETUP_PARAM, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    qat_sm3_ctx->session_data = session_data;
    qat_sm3_ctx->pOpData = (void *)session_data
        + sizeof(CpaCySymSessionSetupData);
    qat_sm3_ctx->rc_refs = (void *)session_data
        + sizeof(CpaCySymSessionSetupData)
        + sizeof(CpaCySymOpData);

    session_data->sessionPriority = CPA_CY_PRIORITY_HIGH;
    /* Hash only operation on the data */
    session_data->symOperation = CPA_CY_SYM_OP_HASH;
    /* Place the digest result in a buffer unrelated to srcBuffer */
    session_data->digestIsAppended = CPA_FALSE;
    /* Set FALSE to generate a message digest, instead of doing digest verify */
    session_data->verifyDigest = CPA_FALSE;

    /* Set the hash mode and the length of the digest */
    session_data->hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SM3;
    session_data->hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_PLAIN;
    session_data->hashSetupData.digestResultLenInBytes = QAT_SM3_DIGEST_SIZE;
    session_data->hashSetupData.authModeSetupData.authKey = NULL;
    session_data->hashSetupData.nestedModeSetupData.pInnerPrefixData = NULL;
    session_data->hashSetupData.nestedModeSetupData.pOuterPrefixData = NULL;

    DUMP_SESSION_SETUP_DATA(qat_sm3_ctx->session_data);

    /* Allocate instance */
    qat_sm3_ctx->inst_num = get_next_inst_num(INSTANCE_TYPE_CRYPTO_SYM);
    if (qat_sm3_ctx->inst_num == QAT_INVALID_INSTANCE) {
        WARN("Failed to get a QAT instance.\n");
        QATerr(QAT_F_QAT_HW_SM3_SETUP_PARAM, QAT_R_GET_INSTANCE_FAILURE);
        goto err;
    }

    /* Determine size of session context to allocate */
    status =
        cpaCySymSessionCtxGetSize(qat_instance_handles[qat_sm3_ctx->inst_num],
                                  qat_sm3_ctx->session_data, &sctx_size);
    if (status != CPA_STATUS_SUCCESS) {
        WARN("Failed to get SessionCtx size.\n");
        QATerr(QAT_F_QAT_HW_SM3_SETUP_PARAM, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    DEBUG("Size of session ctx = %d\n", sctx_size);

    qat_sm3_ctx->session_ctx =
        (CpaCySymSessionCtx) qaeCryptoMemAlloc(sctx_size, __FILE__, __LINE__);
    if (qat_sm3_ctx->session_ctx == NULL) {
        WARN("Memory alloc failed for session ctx\n");
        QATerr(QAT_F_QAT_HW_SM3_SETUP_PARAM, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Initialise Session data */
    status = cpaCySymInitSession(qat_instance_handles[qat_sm3_ctx->inst_num],
                                 qat_hw_sm3_cb,
                                 qat_sm3_ctx->session_data,
                                 qat_sm3_ctx->session_ctx);
    if (status != CPA_STATUS_SUCCESS) {
        WARN("cpaCySymInitSession failed! Status = %d\n", status);
        if (((status == CPA_STATUS_RESTARTING) || (status == CPA_STATUS_FAIL))) {
            CRYPTO_QAT_LOG
                ("Failed to submit request to qat inst_num %d device_id %d\n",
                 qat_sm3_ctx->inst_num,
                 qat_instance_details[qat_sm3_ctx->inst_num].qat_instance_info.
                 physInstId.packageId);
        }
        QATerr(QAT_F_QAT_HW_SM3_SETUP_PARAM, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Get buffer metasize */
    status =
        cpaCyBufferListGetMetaSize(qat_instance_handles[qat_sm3_ctx->inst_num],
                                   numBuffers, &bufferMetaSize);
    if (status != CPA_STATUS_SUCCESS) {
        WARN("cpaCyBufferListGetMetaSize failed for the instance id %d\n",
             qat_sm3_ctx->inst_num);
        QATerr(QAT_F_QAT_HW_SM3_SETUP_PARAM, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    DEBUG("Buffer MetaSize : %d\n", bufferMetaSize);

    if (bufferMetaSize) {
        qat_sm3_ctx->pSrcBufferList.pPrivateMetaData =
            qaeCryptoMemAlloc(bufferMetaSize, __FILE__, __LINE__);
        if (qat_sm3_ctx->pSrcBufferList.pPrivateMetaData == NULL) {
            WARN("QMEM alloc failed for PrivateData\n");
            QATerr(QAT_F_QAT_HW_SM3_SETUP_PARAM, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        qat_sm3_ctx->pSrcBufferList.numBuffers = 1;

    } else {
        qat_sm3_ctx->pSrcBufferList.pPrivateMetaData = NULL;
        qat_sm3_ctx->pSrcBufferList.numBuffers = 0;
    }

    qat_sm3_ctx->context_params_set = 1;

    return 1;

 err:
    qaeCryptoMemFreeNonZero(qat_sm3_ctx->pSrcBufferList.pPrivateMetaData);
    qaeCryptoMemFreeNonZero(qat_sm3_ctx->session_ctx);
    OPENSSL_free(session_data);
    qat_sm3_ctx->session_data = NULL;
    qat_sm3_ctx->pOpData = NULL;
    qat_sm3_ctx->rc_refs = NULL;

    return 0;
}

static int qat_hw_sm3_do_offload(QAT_SM3_CTX *qat_sm3_ctx, const void *in,
                                 size_t len, int packet_type)
{
    int job_ret = 0;
    int ret = 0;                /* Default fail */
    CpaStatus status;
    op_done_t op_done;
    thread_local_variables_t *tlv = NULL;
    CpaFlatBuffer src_buffer;

    if (!qat_sm3_ctx->context_params_set) {
        if (!qat_hw_sm3_setup_param(qat_sm3_ctx)) {
            WARN("SM3 operational params setup failed.\n");
            QATerr(QAT_F_QAT_HW_SM3_DO_OFFLOAD, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    /* The variables in and out remain separate */
    src_buffer.pData =
        qaeCryptoMemAlloc(len + QAT_SM3_DIGEST_SIZE, __FILE__, __LINE__);
    if ((src_buffer.pData) == NULL) {
        WARN("Unable to allocate memory for buffer for sm3 hash.\n");
        QATerr(QAT_F_QAT_HW_SM3_DO_OFFLOAD, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    src_buffer.dataLenInBytes = len + QAT_SM3_DIGEST_SIZE;

    if (len == 0) {
        DEBUG("qat hw start offload: Length 0\n");
    } else {
        DUMPL("qat hw start offload", in, (len > 128) ? len : 128);
        memcpy(src_buffer.pData, in, len);
    }

    qat_sm3_ctx->pSrcBufferList.pBuffers = &src_buffer;

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        QATerr(QAT_F_QAT_HW_SM3_DO_OFFLOAD, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_HW_SM3_DO_OFFLOAD, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            goto err;
        }
    }

    qat_sm3_ctx->pSrcBufferList.pUserData = NULL;

    qat_sm3_ctx->pOpData->sessionCtx = qat_sm3_ctx->session_ctx;

    if (CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL == packet_type &&
        qat_sm3_ctx->qat_offloaded == 0) {
        qat_sm3_ctx->pOpData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
    } else {
        qat_sm3_ctx->pOpData->packetType = packet_type;
    }

    /* The message length, in bytes, of the source buffer that the hash
     * will be computed on. */
    qat_sm3_ctx->pOpData->messageLenToHashInBytes = len;
    qat_sm3_ctx->pOpData->pDigestResult = src_buffer.pData + len;

    if (!is_instance_available(qat_sm3_ctx->inst_num)) {
        WARN("QAT instance %d not available.\n", qat_sm3_ctx->inst_num);
        QATerr(QAT_F_QAT_HW_SM3_DO_OFFLOAD, ERR_R_INTERNAL_ERROR);
        if (op_done.job != NULL) {
            qat_clear_async_event_notification(op_done.job);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    /* same src & dst for an in-place operation */
    status = qat_sym_perform_op(qat_sm3_ctx->inst_num,
                                &op_done,
                                qat_sm3_ctx->pOpData,
                                &(qat_sm3_ctx->pSrcBufferList),
                                &(qat_sm3_ctx->pSrcBufferList),
                                &(qat_sm3_ctx->session_data->verifyDigest));

    if (status != CPA_STATUS_SUCCESS) {
        if (((status == CPA_STATUS_RESTARTING) || (status == CPA_STATUS_FAIL))) {
            CRYPTO_QAT_LOG
                ("Failed to submit request to qat inst_num %d device_id %d - %s\n",
                 qat_sm3_ctx->inst_num,
                 qat_instance_details[qat_sm3_ctx->inst_num].qat_instance_info.
                 physInstId.packageId);
        }
        QATerr(QAT_F_QAT_HW_SM3_DO_OFFLOAD, ERR_R_INTERNAL_ERROR);
        if (op_done.job != NULL)
            qat_clear_async_event_notification(op_done.job);

        qat_cleanup_op_done(&op_done);
        goto err;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n", &hw_polling_thread_sem);
                QATerr(QAT_F_QAT_HW_SM3_DO_OFFLOAD, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                if (op_done.job != NULL)
                    qat_clear_async_event_notification(op_done.job);

                qat_cleanup_op_done(&op_done);
                goto err;
            }
        }
    }

    if (enable_heuristic_polling)
        QAT_ATOMIC_INC(num_cipher_pipeline_requests_in_flight);

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
                sched_yield();

        } else {
            sched_yield();
        }
    } while (!op_done.flag || QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

    if (op_done.verifyResult != CPA_TRUE) {
        WARN("Verification of result failed\n");
        QATerr(QAT_F_QAT_HW_SM3_DO_OFFLOAD, ERR_R_INTERNAL_ERROR);
        if (op_done.status == CPA_STATUS_FAIL) {
            CRYPTO_QAT_LOG
                ("Verification of result failed for qat inst_num %d device_id %d - %s\n",
                 inst_num,
                 qat_instance_details[qat_sm3_ctx->_inst_num].qat_instance_info.
                 physInstId.packageId);
            qat_cleanup_op_done(&op_done);
            goto err;
        }
    }
    qat_cleanup_op_done(&op_done);

    /* final partial */
    if (CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL == packet_type) {
        memcpy(qat_sm3_ctx->digest_data, src_buffer.pData + len,
               QAT_SM3_DIGEST_SIZE);
        ret = 1;
    } else {
        qat_sm3_ctx->qat_offloaded = 1;
        ret = 1;
    }

 err:
    qaeCryptoMemFreeNonZero(src_buffer.pData);
    return ret;
}

/******************************************************************************
* function:
*         qat_hw_sm3_init(EVP_MD_CTX *ctx)
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
static int qat_hw_sm3_init(EVP_MD_CTX *ctx)
{
    return 1;
}

/******************************************************************************
* function:
*    qat_hw_sm3_update(EVP_MD_CTX *ctx, const void *in, size_t len)
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
static int qat_hw_sm3_update(EVP_MD_CTX *ctx, const void *in, size_t len)
{
    const unsigned char *data = in;

    QAT_SM3_CTX *qat_sm3_ctx = NULL;
    unsigned char *p;
    size_t n;

    if (len == 0) {
        DEBUG("sm3 hw update with len = 0 %p\n", ctx);
        return 1;
    }

    if (unlikely(in == NULL)) {
        WARN("in %p is NULL\n", in);
        QATerr(QAT_F_QAT_HW_SM3_UPDATE, QAT_R_INVALID_INPUT);
        return 0;
    }

    qat_sm3_ctx = qat_hw_sm3_get_ctx(ctx);
    if (unlikely(qat_sm3_ctx == NULL)) {
        WARN("SM3 context hash data is NULL.\n");
        QATerr(QAT_F_QAT_HW_SM3_UPDATE, QAT_R_SM3_CTX_NULL);
        return 0;
    }

    qat_sm3_ctx->rcv_count += len;
    DUMPL("sm3 hw update receive", in, len);

    n = qat_sm3_ctx->num;
    /* Packets left from previous process */
    if (n != 0) {
        p = (unsigned char *)qat_sm3_ctx->data;

        /* Offload threshold met */
        if (len >= QAT_SM3_OFFLOAD_THRESHOLD
            || len + n >= QAT_SM3_OFFLOAD_THRESHOLD) {
            /* Use part of new packet filling the packet buffer */
            memcpy(p + n, data, QAT_SM3_OFFLOAD_THRESHOLD - n);

            if (!qat_hw_sm3_do_offload
                (qat_sm3_ctx, p, QAT_SM3_OFFLOAD_THRESHOLD,
                 CPA_CY_SYM_PACKET_TYPE_PARTIAL))
                return 1;

            /* The data left of new input */
            n = QAT_SM3_OFFLOAD_THRESHOLD - n;
            data += n;
            len -= n;
            qat_sm3_ctx->num = 0;
            /*
             * We use memset rather than OPENSSL_cleanse() here deliberately.
             * Using OPENSSL_cleanse() here could be a performance issue. It
             * will get properly cleansed on finalisation so this isn't a
             * security problem.
             */
            memset(p, 0, QAT_SM3_OFFLOAD_THRESHOLD); /* keep it zeroed */
        } else {
            /* Append the new packets to buffer */
            memcpy(p + n, data, len);
            qat_sm3_ctx->num += (unsigned int)len;

            return 1;
        }
    }

    n = len / QAT_SM3_OFFLOAD_THRESHOLD;
    if (n > 0) {
        n *= QAT_SM3_OFFLOAD_THRESHOLD;

        if (!qat_hw_sm3_do_offload(qat_sm3_ctx, in, n,
                                   CPA_CY_SYM_PACKET_TYPE_PARTIAL))
            return 1;

        data += n;
        len -= n;
    }

    /* Save the bytes into buffer if there're some bytes left
       after the previous update. */
    if (len != 0) {
        qat_sm3_ctx->data = OPENSSL_zalloc(QAT_SM3_OFFLOAD_THRESHOLD);
        qat_sm3_ctx->data_refs = OPENSSL_zalloc(sizeof(int));

        p = (unsigned char *)qat_sm3_ctx->data;
        qat_sm3_ctx->num = (unsigned int)len;
        memcpy(p, data, len);
    }

    return 1;
}

static int qat_hw_sm3_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    QAT_SM3_CTX *qat_from;

    if (NULL == from) {
        WARN("sm3 copy from %p is NULL\n", from);
        QATerr(QAT_F_QAT_HW_SM3_COPY, QAT_R_CTX_NULL);
        return 0;
    }

    /* Digest-copy can be called without a md_data in some condition */
    if (EVP_MD_CTX_md_data(from) == 0) {
        DEBUG("digest copy without md_data\n");
        return 1;
    }

    qat_from = QAT_SM3_GET_CTX(from);
    if (NULL == qat_from) {
        WARN("qat_from %p is NULL\n", qat_from);
        QATerr(QAT_F_QAT_HW_SM3_COPY, QAT_R_CTX_NULL);
        return 0;
    }

    if (qat_from->rc_refs)
        (*qat_from->rc_refs)++;

    if (qat_from->data_refs)
        (*qat_from->data_refs)++;

    return 1;
}

/******************************************************************************
* function:
*    qat_hw_sm3_final(EVP_MD_CTX *ctx, unsigned char *md)
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
static int qat_hw_sm3_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    QAT_SM3_CTX *qat_sm3_ctx = NULL;

    if (md == NULL) {
        WARN("hw sm3 md is null\n");
        QATerr(QAT_F_QAT_HW_SM3_FINAL, QAT_R_INPUT_PARAM_INVALID);
        return 0;
    }

    qat_sm3_ctx = qat_hw_sm3_get_ctx(ctx);
    if (qat_sm3_ctx == NULL) {
        WARN("qat_sm3_ctx is NULL\n");
        QATerr(QAT_F_QAT_HW_SM3_FINAL, QAT_R_CTX_NULL);
        return 0;
    }
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    if (qat_sm3_ctx->rcv_count <= CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_HW_SM3) {
        /* Software calculation can start from init, because SPO threashold will
           always small than context buffer and all data are stored in context
           buffer */
        int (*sw_init_ptr)(EVP_MD_CTX *);
        int (*sw_update_ptr)(EVP_MD_CTX *, const void *, size_t);
        int (*sw_final_ptr)(EVP_MD_CTX *, unsigned char *);

        DUMPL("Start ossl calculate", qat_sm3_ctx->data, qat_sm3_ctx->num);

        sw_init_ptr = EVP_MD_meth_get_init((EVP_MD *)EVP_sm3());
        sw_update_ptr = EVP_MD_meth_get_update((EVP_MD *)EVP_sm3());
        sw_final_ptr = EVP_MD_meth_get_final((EVP_MD *)EVP_sm3());

        if ((*sw_init_ptr) (ctx) != 1
            || (*sw_update_ptr) (ctx, qat_sm3_ctx->data, qat_sm3_ctx->num) != 1
            || (*sw_final_ptr) (ctx, md) != 1) {
            WARN("Software calculate failed %p\n", ctx);
            return 0;
        }

        DUMPL("DigestResult (OSSL)", md, QAT_SM3_DIGEST_SIZE);

        return 1;
    }
# endif

    qat_sm3_ctx->digest_data = md;
    if (!qat_hw_sm3_do_offload(qat_sm3_ctx, qat_sm3_ctx->data, qat_sm3_ctx->num,
                               CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL))
        return 0;

    DUMPL("DigestResult (QAT_HW)", md, QAT_SM3_DIGEST_SIZE);

    return 1;
}

/******************************************************************************
* function:
*    qat_hw_sm3_cleanup(EVP_MD_CTX *ctx)
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
static int qat_hw_sm3_cleanup(EVP_MD_CTX *ctx)
{
    QAT_SM3_CTX *qat_sm3_ctx;
    CpaStatus status = 0;
    int ret_val = 1;
    CpaBoolean sessionInUse = CPA_FALSE;

    qat_sm3_ctx = qat_hw_sm3_get_ctx(ctx);
    if (NULL == qat_sm3_ctx) {
        WARN("qat_sm3_ctx is NULL\n");
        QATerr(QAT_F_QAT_HW_SM3_CLEANUP, QAT_R_CTX_NULL);
        return 0;
    }

    if (EVP_MD_CTX_md_data(ctx) == NULL) {
        DEBUG("digest cleanup without md_data\n");
        return 1;
    }

    if (qat_sm3_ctx->data_refs) {
        if (*qat_sm3_ctx->data_refs > 0) {
            (*qat_sm3_ctx->data_refs)--;
            DEBUG("HW SM3 data refrence decrease to %d\n",
                  *qat_sm3_ctx->data_refs);
        } else {
            OPENSSL_free(qat_sm3_ctx->data);
            OPENSSL_free(qat_sm3_ctx->data_refs);
        }
    }

    if (qat_sm3_ctx->context_params_set) {
        if (*qat_sm3_ctx->rc_refs > 0) {
            (*qat_sm3_ctx->rc_refs)--;
            DEBUG("HW SM3 resource refrence decrease to %d\n",
                  *qat_sm3_ctx->rc_refs);
            return 1;
        }

        if (is_instance_available(qat_sm3_ctx->inst_num)) {
            /* Wait for in-flight requests before removing session */
            do {
                cpaCySymSessionInUse(qat_sm3_ctx->session_ctx, &sessionInUse);
            } while (sessionInUse);

            if ((status =
                 cpaCySymRemoveSession(qat_instance_handles
                                       [qat_sm3_ctx->inst_num],
                                       qat_sm3_ctx->session_ctx))
                != CPA_STATUS_SUCCESS) {
                WARN("cpaCySymRemoveSession FAILED, status= %d.!\n", status);
                ret_val = 0;
            }
        } else {
            WARN("instance no longer available\n");
        }

        qaeCryptoMemFreeNonZero(qat_sm3_ctx->session_ctx);
        qat_sm3_ctx->session_ctx = NULL;

        qaeCryptoMemFreeNonZero(qat_sm3_ctx->pSrcBufferList.pPrivateMetaData);
        qat_sm3_ctx->pSrcBufferList.pPrivateMetaData = NULL;

        OPENSSL_free(qat_sm3_ctx->session_data);
        qat_sm3_ctx->session_data = NULL;

        qat_sm3_ctx->context_params_set = 0;
    }

    return ret_val;
}

const EVP_MD *qat_hw_create_sm3_meth(int nid, int key_type)
{
    int res = 1;
    EVP_MD *qat_hw_sm3_meth = NULL;

    if (qat_hw_offload && (qat_hw_algo_enable_mask & ALGO_ENABLE_MASK_SM3)) {
        if ((qat_hw_sm3_meth = EVP_MD_meth_new(nid, key_type)) == NULL) {
            WARN("Failed to allocate digest methods for nid %d\n", nid);
            QATerr(QAT_F_QAT_HW_CREATE_SM3_METH, QAT_R_INIT_FAILURE);
            return NULL;
        }

        res &= EVP_MD_meth_set_result_size(qat_hw_sm3_meth, QAT_SM3_STATE_SIZE);
        res &=
            EVP_MD_meth_set_input_blocksize(qat_hw_sm3_meth,
                                            QAT_SM3_BLOCK_SIZE);
        /* Totally 3 memory sections in application data, common EVP_MD,
           SM3_CTX used for SM3 software, and QAT_SM3_CTX for QAT_HW */
        res &= EVP_MD_meth_set_app_datasize(qat_hw_sm3_meth,
                                            sizeof(EVP_MD *) + sizeof(SM3_CTX) +
                                            sizeof(QAT_SM3_CTX));
        res &= EVP_MD_meth_set_flags(qat_hw_sm3_meth, EVP_MD_CTX_FLAG_REUSE);
        res &= EVP_MD_meth_set_init(qat_hw_sm3_meth, qat_hw_sm3_init);
        res &= EVP_MD_meth_set_update(qat_hw_sm3_meth, qat_hw_sm3_update);
        res &= EVP_MD_meth_set_final(qat_hw_sm3_meth, qat_hw_sm3_final);
        res &= EVP_MD_meth_set_copy(qat_hw_sm3_meth, qat_hw_sm3_copy);
        res &= EVP_MD_meth_set_cleanup(qat_hw_sm3_meth, qat_hw_sm3_cleanup);

        if (0 == res) {
            WARN("Failed to set MD methods for nid %d\n", nid);
            QATerr(QAT_F_QAT_HW_CREATE_SM3_METH, QAT_R_INIT_FAILURE);
            EVP_MD_meth_free(qat_hw_sm3_meth);
            return NULL;
        }

        qat_hw_sm3_offload = 1;
        DEBUG("QAT HW SM3 Registration succeeded\n");

        return qat_hw_sm3_meth;

    } else {
        qat_hw_sm3_offload = 0;
        DEBUG("QAT HW SM3 is disabled, using OpenSSL SW\n");

        return (EVP_MD *)EVP_sm3();
    }
}

#endif                          /* ENABLE_QAT_HW_SM3 */
