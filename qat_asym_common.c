/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2017 Intel Corporation.
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
 * @file qat_asym_common.c
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

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#include <openssl/async.h>
#endif
#include <openssl/ossl_typ.h>
#include <openssl/bn.h>

#include "cpa_cy_ln.h"

#include "qat_asym_common.h"
#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "cmn_mem_drv_inf.h"
#endif
#include "qat_utils.h"
#include "e_qat.h"
#include "qat_polling.h"
#include "qat_events.h"
#include "e_qat_err.h"

#define QAT_PERFORMOP_RETRIES 3

/******************************************************************************
* function:
*         qat_BN_to_FB(CpaFlatBuffer *fb,
*                      BIGNUM *bn)
*
* @param fb [OUT] - API flatbuffer structure pointer
* @param bn [IN] - Big Number pointer
*
* description:
*   This function is used to transform the big number format to the flat buffer
*   format. The function is used to deliver the RSA Public/Private key structure
*   from OpenSSL layer to API layer.
******************************************************************************/
int qat_BN_to_FB(CpaFlatBuffer * fb, const BIGNUM *bn)
{
    /* Memory allocate for flat buffer */
    fb->dataLenInBytes = (Cpa32U) BN_num_bytes(bn);
    if (0 == fb->dataLenInBytes) {
        fb->dataLenInBytes = 0;
        fb->pData = NULL;
        DEBUG("Datalen = 0, zero byte memory allocation\n");
        return 1;
    }
    fb->pData = qaeCryptoMemAlloc(fb->dataLenInBytes, __FILE__, __LINE__);
    if (NULL == fb->pData) {
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

/******************************************************************************
* function:
*         qat_mod_exp(BIGNUM * r, const BIGNUM * a, const BIGNUM * p,
                      const BIGNUM * m, BN_CTX * ctx)
*
* @param res  [IN] - Result bignum of mod_exp
* @param base [IN] - Base used for mod_exp
* @param exp  [IN] - Exponent used for mod_exp
* @param mod  [IN] - Modulus used for mod_exp
*
* description:
*   Bignum modular exponentiation function used in DH and DSA.
*
******************************************************************************/
int qat_mod_exp(BIGNUM *res, const BIGNUM *base, const BIGNUM *exp,
                const BIGNUM *mod)
{

    CpaCyLnModExpOpData opData;
    CpaFlatBuffer result = { 0, };
    CpaStatus status = 0;
    int retval = 1;
    CpaInstanceHandle instance_handle;
    int qatPerformOpRetries = 0;
    ASYNC_JOB *job = NULL;
    int iMsgRetry = getQatMsgRetryCount();
    useconds_t ulPollInterval = getQatPollInterval();

    DEBUG(" - Started\n");

    opData.base.pData = NULL;
    opData.exponent.pData = NULL;
    opData.modulus.pData = NULL;

    if (qat_BN_to_FB(&opData.base, (BIGNUM *)base) != 1 ||
        qat_BN_to_FB(&opData.exponent, (BIGNUM *)exp) != 1 ||
        qat_BN_to_FB(&opData.modulus, (BIGNUM *)mod) != 1) {
        WARN("Failed to convert base, exponent or modulus to flatbuffer\n");
        QATerr(QAT_F_QAT_MOD_EXP, QAT_R_BUF_CONV_FAIL);
        retval = 0;
        goto exit;
    }

    result.dataLenInBytes = BN_num_bytes(mod);
    result.pData =
        qaeCryptoMemAlloc(result.dataLenInBytes, __FILE__, __LINE__);
    if (NULL == result.pData) {
        WARN("Failed to allocate result.pData\n");
        QATerr(QAT_F_QAT_MOD_EXP, QAT_R_RESULT_PDATA_ALLOC_FAIL);
        retval = 0;
        goto exit;
    }

    if ((job = ASYNC_get_current_job()) != NULL) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failed to setup async event notifications\n");
            QATerr(QAT_F_QAT_MOD_EXP, QAT_R_MOD_SETUP_ASYNC_EVENT_FAIL);
            retval = 0;
            goto exit;
        }
    }

    instance_handle = get_next_inst();
    if (qat_use_signals()) {
        qat_atomic_inc(num_requests_in_flight);
        if (pthread_kill(timer_poll_func_thread, SIGUSR1) != 0) {
            WARN("pthread_kill error\n");
            QATerr(QAT_F_QAT_MOD_EXP, ERR_R_INTERNAL_ERROR);
            retval = 0;
            qat_atomic_dec(num_requests_in_flight);
            goto exit;
        }
    }
    do {
        if (NULL == (instance_handle = get_next_inst())) {
            WARN("Failure in get_next_inst()\n");
            QATerr(QAT_F_QAT_MOD_EXP, QAT_R_MOD_GET_NEXT_INST_FAIL);
            if (job != NULL) {
                qat_clear_async_event_notification();
            }
            retval = 0;
            qat_atomic_dec_if_polling(num_requests_in_flight);
            goto exit;
        }

        status = cpaCyLnModExp(instance_handle, NULL, NULL, &opData, &result);
        if (status == CPA_STATUS_RETRY) {
            if (job == NULL) {
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
                if ((qat_wake_job(job, 0) == 0) ||
                    (qat_pause_job(job, 0) == 0)) {
                    WARN("qat_wake_job or qat_pause_job failed\n");
                    break;
                }
            }
        }
    }
    while (status == CPA_STATUS_RETRY);

    if (CPA_STATUS_SUCCESS != status) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        QATerr(QAT_F_QAT_MOD_EXP, QAT_R_MOD_LN_MOD_EXP_FAIL);
        if (job != NULL) {
            qat_clear_async_event_notification();
        }
        retval = 0;
        qat_atomic_dec_if_polling(num_requests_in_flight);
        goto exit;
    }

    qat_atomic_dec_if_polling(num_requests_in_flight);

    /* Convert the flatbuffer results back to a BN */
    BN_bin2bn(result.pData, result.dataLenInBytes, res);

 exit:

    if (opData.base.pData)
        qaeCryptoMemFree(opData.base.pData);
    if (opData.exponent.pData)
        qaeCryptoMemFree(opData.exponent.pData);
    if (opData.modulus.pData)
        qaeCryptoMemFree(opData.modulus.pData);
    if (result.pData)
        qaeCryptoMemFree(result.pData);

    return retval;
}
