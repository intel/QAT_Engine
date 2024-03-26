/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2024 Intel Corporation.
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
 * @file qat_hw_asym_common.c
 *
 * This file contains common functions used for asymmetric operations
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifndef __USE_GNU
# define __USE_GNU
#endif

#include <pthread.h>
#include <signal.h>

#include <openssl/ossl_typ.h>
#include <openssl/bn.h>

#include "cpa_cy_ln.h"

#include "qat_hw_asym_common.h"
#include "qat_utils.h"
#include "e_qat.h"
#include "qat_hw_callback.h"
#include "qat_hw_polling.h"
#include "qat_events.h"

#define QAT_PERFORMOP_RETRIES 3
#ifdef ENABLE_QAT_HW_SM2
#define QAT_SM2_SIZE 32
#endif

/******************************************************************************
* function:
*         qat_BN_to_FB(CpaFlatBuffer *fb,
*                      BIGNUM *bn)
*
* @param fb [OUT] - API flatbuffer structure pointer
* @param bn [IN] - Big Number pointer
* @param qat_svm [OUT] - Instance Memory type
*
* description:
*   This function is used to transform the big number format to the flat buffer
*   format. The function is used to deliver the RSA Public/Private key structure
*   from OpenSSL layer to API layer.
******************************************************************************/
int qat_BN_to_FB(CpaFlatBuffer * fb, const BIGNUM *bn, int qat_svm)
{
    if (unlikely((fb == NULL ||
                  bn == NULL ))) {
        WARN("Invalid input params.\n");
        return 0;
    }
    /* Memory allocate for flat buffer */
    fb->dataLenInBytes = (Cpa32U) BN_num_bytes(bn);
    if (0 == fb->dataLenInBytes) {
        fb->pData = NULL;
        DEBUG("Datalen = 0, zero byte memory allocation\n");
        return 1;
    }
    if (!qat_svm)
        fb->pData = qaeCryptoMemAlloc(fb->dataLenInBytes, __FILE__, __LINE__);
    else
        fb->pData = OPENSSL_zalloc(fb->dataLenInBytes);
    if (NULL == fb->pData) {
        fb->dataLenInBytes = 0;
        WARN("Failed to allocate fb->pData\n");
        return 0;
    }
    /*
     * BN_bn2in() converts the absolute value of big number into big-endian
     * form and stores it at output buffer. the output buffer must point to
     * BN_num_bytes of memory
     */
    BN_bn2bin(bn, fb->pData);
    return 1;
}
# if defined(QAT_OPENSSL_PROVIDER) && defined(ENABLE_QAT_HW_SM2)
int qat_BN_to_FB_for_sm2(CpaFlatBuffer * fb, const BIGNUM *bn, int qat_svm)
{
    if (unlikely((fb == NULL ||
                  bn == NULL ))) {
        WARN("Invalid input params.\n");
        return 0;
    }
    /* Memory allocate for flat buffer */
    fb->dataLenInBytes = (Cpa32U) BN_num_bytes(bn);
    if (0 == fb->dataLenInBytes) {
        fb->pData = NULL;
        DEBUG("Datalen = 0, zero byte memory allocation\n");
        return 1;
    }
    if (fb->dataLenInBytes < QAT_SM2_SIZE)
        fb->dataLenInBytes = fb->dataLenInBytes + (QAT_SM2_SIZE - fb->dataLenInBytes);
    if (!qat_svm)
        fb->pData = qaeCryptoMemAlloc(fb->dataLenInBytes, __FILE__, __LINE__);
    else
	fb->pData = OPENSSL_zalloc(fb->dataLenInBytes);

    if (NULL == fb->pData) {
        fb->dataLenInBytes = 0;
        WARN("Failed to allocate fb->pData\n");
        return 0;
    }
    /*
     * BN_bn2in() converts the absolute value of big number into big-endian
     * form and stores it at output buffer. the output buffer must point to
     * BN_num_bytes of memory
     */
    BN_bn2bin(bn, fb->pData);
    return 1;
}
#endif

/* Callback to indicate QAT completion of bignum modular exponentiation */
static void qat_modexpCallbackFn(void *pCallbackTag, CpaStatus status,
                                 void *pOpData, CpaFlatBuffer * pOut)
{
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_asym_requests_in_flight);
    }
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, CPA_TRUE);
}

/******************************************************************************
* function:
          qat_mod_exp(BIGNUM *res, const BIGNUM *base, const BIGNUM *exp,
                      const BIGNUM *mod, int *fallback)
*
* @param res       [IN] - Result bignum of mod_exp
* @param base      [IN] - Base used for mod_exp
* @param exp       [IN] - Exponent used for mod_exp
* @param mod       [IN] - Modulus used for mod_exp
* @param fallback [OUT] - Pointer to Software Fallback flag
*
* description:
*   Bignum modular exponentiation function used in DH and DSA.
*
******************************************************************************/
int qat_mod_exp(BIGNUM *res, const BIGNUM *base, const BIGNUM *exp,
                const BIGNUM *mod, int *fallback)
{
    CpaCyLnModExpOpData opData;
    CpaFlatBuffer result = { 0, };
    CpaStatus status = 0;
    int retval = 1, job_ret = 0;
    int inst_num = QAT_INVALID_INSTANCE;
    int qatPerformOpRetries = 0;
    op_done_t op_done;
    int iMsgRetry = getQatMsgRetryCount();
    useconds_t ulPollInterval = getQatPollInterval();
    thread_local_variables_t *tlv = NULL;
    int qat_svm = QAT_INSTANCE_ANY;

    DEBUG(" - Started\n");

    opData.base.pData = NULL;
    opData.exponent.pData = NULL;
    opData.modulus.pData = NULL;

    if ((inst_num = get_instance(QAT_INSTANCE_ASYM, QAT_INSTANCE_ANY))
            == QAT_INVALID_INSTANCE) {
        WARN("Failed to get an instance\n");
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
            *fallback = 1;
        } else {
            QATerr(QAT_F_QAT_MOD_EXP, ERR_R_INTERNAL_ERROR);
        }
        retval = 0;
        goto exit;
    }
    qat_svm = !qat_instance_details[inst_num].qat_instance_info.requiresPhysicallyContiguousMemory;

    if (qat_BN_to_FB(&opData.base, (BIGNUM *)base, qat_svm) != 1 ||
        qat_BN_to_FB(&opData.exponent, (BIGNUM *)exp, qat_svm) != 1 ||
        qat_BN_to_FB(&opData.modulus, (BIGNUM *)mod, qat_svm) != 1) {
        WARN("Failed to convert base, exponent or modulus to flatbuffer\n");
        QATerr(QAT_F_QAT_MOD_EXP, QAT_R_BUF_CONV_FAIL);
        retval = 0;
        goto exit;
    }

    result.dataLenInBytes = BN_num_bytes(mod);
    result.pData = qat_mem_alloc(result.dataLenInBytes, qat_svm, __FILE__, __LINE__);
    if (NULL == result.pData) {
        WARN("Failed to allocate result.pData\n");
        QATerr(QAT_F_QAT_MOD_EXP, QAT_R_RESULT_PDATA_ALLOC_FAIL);
        retval = 0;
        goto exit;
    }

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
            WARN("could not create local variables\n");
            QATerr(QAT_F_QAT_MOD_EXP, ERR_R_INTERNAL_ERROR);
            retval = 0;
            goto exit;
    }

#ifdef QAT_BORINGSSL
    qat_init_op_done(&op_done,qat_svm);
#else
    qat_init_op_done(&op_done);
#endif
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failed to setup async event notifications\n");
            QATerr(QAT_F_QAT_MOD_EXP, QAT_R_MOD_SETUP_ASYNC_EVENT_FAIL);
            retval = 0;
            qat_cleanup_op_done(&op_done);
            goto exit;
        }
    }

    do {
        if (status == CPA_STATUS_RETRY &&
           (inst_num = get_instance(QAT_INSTANCE_ASYM, qat_svm))
            == QAT_INVALID_INSTANCE) {
            WARN("Failure to get an instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                *fallback = 1;
            } else {
                QATerr(QAT_F_QAT_MOD_EXP, QAT_R_MOD_GET_NEXT_INST_FAIL);
            }
            if (op_done.job != NULL) {
                qat_clear_async_event_notification(op_done.job);
            }
            retval = 0;
            qat_cleanup_op_done(&op_done);
            goto exit;
        }

        status = cpaCyLnModExp(qat_instance_handles[inst_num], qat_modexpCallbackFn, &op_done,
                               &opData, &result);
        if (status == CPA_STATUS_RETRY) {
            if (op_done.job == NULL) {
                usleep(ulPollInterval +
                       (qatPerformOpRetries % QAT_RETRY_BACKOFF_MODULO_DIVISOR));
                qatPerformOpRetries++;
                if (iMsgRetry != QAT_INFINITE_MAX_NUM_RETRIES) {
                    if (qatPerformOpRetries >= iMsgRetry) {
                        WARN("No. of retries exceeded max retry : %d\n", iMsgRetry);
                        break;
                    }
                }
            } else {
                if ((qat_wake_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0) ||
                    (qat_pause_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0)) {
                    WARN("qat_wake_job or qat_pause_job failed\n");
                    break;
                }
            }
        }
    }
    while (status == CPA_STATUS_RETRY);

    if (CPA_STATUS_SUCCESS != status) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        if (qat_get_sw_fallback_enabled() &&
            (status == CPA_STATUS_RESTARTING || status == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            *fallback = 1;
        } else {
            QATerr(QAT_F_QAT_MOD_EXP, QAT_R_MOD_LN_MOD_EXP_FAIL);
        }
        if (op_done.job != NULL)
            qat_clear_async_event_notification(op_done.job);
        retval = 0;
        qat_cleanup_op_done(&op_done);
        goto exit;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n",
                      &hw_polling_thread_sem);
                QATerr(QAT_F_QAT_MOD_EXP, ERR_R_INTERNAL_ERROR);
                retval = 0;
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                goto exit;
            }
        }
    }

    if (qat_get_sw_fallback_enabled()) {
        CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n",
                       inst_num,
                       qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                       __func__);
    }

    if (enable_heuristic_polling) {
        QAT_ATOMIC_INC(num_asym_requests_in_flight);
    }

    do {
        if(op_done.job != NULL) {
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
    }
    while (!op_done.flag ||
           QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

    if (op_done.verifyResult != CPA_TRUE) {
        WARN("Verification of result failed\n");
        if (qat_get_sw_fallback_enabled() && op_done.status == CPA_STATUS_FAIL) {
            CRYPTO_QAT_LOG("Verification of result failed for qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            *fallback = 1;
        } else {
            QATerr(QAT_F_QAT_MOD_EXP, ERR_R_INTERNAL_ERROR);
        }
        retval = 0;
        qat_cleanup_op_done(&op_done);
        goto exit;
    }

    qat_cleanup_op_done(&op_done);

    /* Convert the flatbuffer results back to a BN */
    BN_bin2bn(result.pData, result.dataLenInBytes, res);

 exit:

    QAT_MEM_FREE_FLATBUFF(opData.base, qat_svm);
    QAT_MEM_FREE_FLATBUFF(opData.exponent, qat_svm);
    QAT_MEM_FREE_FLATBUFF(opData.modulus, qat_svm);
    QAT_MEM_FREE_FLATBUFF(result, qat_svm);

    return retval;
}
