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

/*****************************************************************************
 * @file qat_dh.c
 *
 * This file provides implementations for Diffie Hellman operations through an
 * OpenSSL engine
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <pthread.h>
#include <signal.h>
#include "qat_dh.h"
#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "cmn_mem_drv_inf.h"
#endif
#include <openssl/async.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include "qat_asym_common.h"
#include "qat_utils.h"
#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_dh.h"
#include "qat_init.h"
#include "qat_callback.h"
#include "qat_polling.h"
#include "qat_events.h"
#include "e_qat_err.h"
#include <unistd.h>
#include <string.h>

#ifdef OPENSSL_ENABLE_QAT_DH
# ifdef OPENSSL_DISABLE_QAT_DH
#  undef OPENSSL_DISABLE_QAT_DH
# endif
#endif

/* To specify the DH op sizes supported by QAT engine */
#define DH_QAT_RANGE_MIN 768
#define DH_QAT_RANGE_MAX 4096

#ifndef OPENSSL_DISABLE_QAT_DH
static int qat_dh_generate_key(DH *dh);
static int qat_dh_compute_key(unsigned char *key, const BIGNUM *pub_key,
                              DH *dh);
static int qat_dh_mod_exp(const DH *dh, BIGNUM *r, const BIGNUM *a,
                          const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                          BN_MONT_CTX *m_ctx);
static int qat_dh_init(DH *dh);
static int qat_dh_finish(DH *dh);
#endif

static DH_METHOD *qat_dh_method = NULL;

DH_METHOD *qat_get_DH_methods(void)
{
#ifndef OPENSSL_DISABLE_QAT_DH
    int res = 1;
#endif

    if (qat_dh_method != NULL)
        return qat_dh_method;

#ifndef OPENSSL_DISABLE_QAT_DH
    if ((qat_dh_method = DH_meth_new("QAT DH method", 0)) == NULL) {
        WARN("Failure allocating DH methods\n");
        QATerr(QAT_F_QAT_GET_DH_METHODS, QAT_R_QAT_ALLOC_DH_METH_FAILURE);
        return NULL;
    }

    res &= DH_meth_set_generate_key(qat_dh_method, qat_dh_generate_key);
    res &= DH_meth_set_compute_key(qat_dh_method, qat_dh_compute_key);
    res &= DH_meth_set_bn_mod_exp(qat_dh_method, qat_dh_mod_exp);
    res &= DH_meth_set_init(qat_dh_method, qat_dh_init);
    res &= DH_meth_set_finish(qat_dh_method, qat_dh_finish);

    if (res == 0) {
        WARN("Failure setting DH methods\n");
        QATerr(QAT_F_QAT_GET_DH_METHODS, QAT_R_QAT_SET_DH_METH_FAILURE);
        return NULL;
    }
#else
    qat_dh_method = (DH_METHOD *)DH_get_default_method();
#endif

    return qat_dh_method;
}

void qat_free_DH_methods(void)
{
#ifndef OPENSSL_DISABLE_QAT_DH
    if (qat_dh_method != NULL) {
        DH_meth_free(qat_dh_method);
        qat_dh_method = NULL;
    } else {
     	WARN("Failure freeing DH methods\n");
        QATerr(QAT_F_QAT_FREE_DH_METHODS, QAT_R_FREE_DH_METH_FAILURE);
    }
#endif
}


#ifndef OPENSSL_DISABLE_QAT_DH
/*
 * The DH range check is performed so that if the op sizes are not in the
 * range supported by QAT engine then fall back to software
 */
static int dh_range_check(int plen)
{
    int range = 0;

    if ((plen >= DH_QAT_RANGE_MIN) && (plen <= DH_QAT_RANGE_MAX))
        range = 1;

    return range;
}

/* Callback to indicate QAT completion of DH generate & compute key */
static void qat_dhCallbackFn(void *pCallbackTag, CpaStatus status, void *pOpData,
                             CpaFlatBuffer * pPV)
{
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_asym_requests_in_flight);
    }
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, CPA_TRUE);
}

/******************************************************************************
* function:
*         qat_dh_generate_key(DH * dh)
*
* description:
*   Implement Diffie-Hellman phase 1 operations.
******************************************************************************/
int qat_dh_generate_key(DH *dh)
{
    int ok = 0, job_ret = 0, fallback = 0;
    int generate_new_priv_key = 0;
    int generate_new_pub_key = 0;
    unsigned length = 0;
    const BIGNUM *p = NULL, *q = NULL;
    const BIGNUM *g = NULL;
    BIGNUM *pub_key = NULL, *priv_key = NULL;
    const BIGNUM *temp_pub_key = NULL, *temp_priv_key = NULL;
    int inst_num = QAT_INVALID_INSTANCE;
    CpaCyDhPhase1KeyGenOpData *opData = NULL;
    CpaFlatBuffer *pPV = NULL;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    CpaStatus status;
    op_done_t op_done;
    size_t buflen;
    const DH_METHOD *sw_dh_method = DH_OpenSSL();
    thread_local_variables_t *tlv = NULL;

    DEBUG("- Started\n");

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode\n");
        return DH_meth_get_generate_key(sw_dh_method)(dh);
    }

    if (dh == NULL) {
        WARN("Input variable dh is null\n");
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, QAT_R_DH_NULL);
        return 0;
    }

    DH_get0_pqg(dh, &p, &q, &g);
    if (p == NULL || g == NULL) {
        WARN("Failed to get p, q, g\n");
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, QAT_R_P_Q_G_NULL);
        return 0;
    }

    /*
     * If the op sizes are not in the range supported by QAT engine then fall
     * back to software
     */

    if (!dh_range_check(BN_num_bits(p))) {
        if (sw_dh_method == NULL) {
            WARN("Failed to get sw_dh_method for %d bits\n", BN_num_bits(p));
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, QAT_R_SW_METHOD_NULL);
            return 0;
        }
        return DH_meth_get_generate_key(sw_dh_method)(dh);
    }

    DH_get0_key(dh, &temp_pub_key, &temp_priv_key);

    opData = (CpaCyDhPhase1KeyGenOpData *)
        OPENSSL_zalloc(sizeof(CpaCyDhPhase1KeyGenOpData));
    if (opData == NULL) {
        WARN("Failure allocating memory for opData\n");
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, QAT_R_OPDATA_MALLOC_FAILURE);
        return ok;
    }

    opData->primeP.pData = NULL;
    opData->baseG.pData = NULL;
    opData->privateValueX.pData = NULL;

    if (temp_priv_key == NULL) {
        if ((priv_key = BN_new()) == NULL) {
            WARN("Failed to allocate memory for priv_key\n");
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, QAT_R_PRIV_KEY_MALLOC_FAILURE);
            goto err;
        }
        generate_new_priv_key = 1;
    } else {
        if ((priv_key = BN_dup(temp_priv_key)) == NULL) {
            WARN("Failed to duplicate the private key\n");
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, QAT_R_PRIV_KEY_DUPLICATE_FAILURE);
            goto err;
        }
    }

    if (temp_pub_key == NULL) {
        if ((pub_key = BN_new()) == NULL) {
            WARN("Failed to allocate memory for pub_key\n");
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, QAT_R_PUB_KEY_MALLOC_FAILURE);
            goto err;
        }
        generate_new_pub_key = 1;
    } else {
        if ((pub_key = BN_dup(temp_pub_key)) == NULL) {
            WARN("Failed to duplicate the public key\n");
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, QAT_R_PUB_KEY_DUPLICATE_FAILURE);
            goto err;
        }
    }

    if (generate_new_priv_key) {
        if (q) {
            do {
                if (!BN_rand_range(priv_key, q)) {
                    WARN("Failed to generate random number for range %d\n",BN_num_bits(q));
                    QATerr(QAT_F_QAT_DH_GENERATE_KEY, QAT_R_PRIV_KEY_RAND_GENERATE_FAILURE);
                    goto err;
                }
            }
            while (BN_is_zero(priv_key) || BN_is_one(priv_key));
        } else {
            /* secret exponent length */
            length = DH_get_length(dh) ? DH_get_length(dh) : BN_num_bits(p) - 1;
            if (!BN_rand(priv_key, length, 0, 0)) {
                WARN("Failed to generate random number of length %d\n", length);
                QATerr(QAT_F_QAT_DH_GENERATE_KEY, QAT_R_PRIV_KEY_RAND_GENERATE_FAILURE);
                goto err;
            }
        }
    }

    buflen = BN_num_bytes(p);
    pPV = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (pPV == NULL) {
        WARN("Failed to allocate memory for pPV\n");
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, QAT_R_PPV_MALLOC_FAILURE);
        goto err;
    }
    pPV->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (pPV->pData == NULL) {
        WARN("Failed to allocate memory for pPV->pData\n");
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, QAT_R_PPV_PDATA_MALLOC_FAILURE);
        goto err;
    }
    pPV->dataLenInBytes = (Cpa32U) buflen;

    if ((qat_BN_to_FB(&(opData->primeP), (BIGNUM *)p) != 1) ||
        (qat_BN_to_FB(&(opData->baseG), (BIGNUM *)g) != 1) ||
        (qat_BN_to_FB(&(opData->privateValueX), (BIGNUM *)priv_key) != 1)) {
        WARN("Failed to convert p, g or priv_key to a flat buffer\n");
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, QAT_R_P_G_PRIV_KEY_CONVERT_TO_FB_FAILURE);
        goto err;
    }

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (qat_kill_thread(timer_poll_func_thread, SIGUSR1) != 0) {
                WARN("qat_kill_thread error\n");
                QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                goto err;
            }
        }
    }
    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            goto err;
        }
    }

    CRYPTO_QAT_LOG("KX - %s\n", __func__);
    do {
        if ((inst_num = get_next_inst_num()) == QAT_INVALID_INSTANCE) {
            WARN("Failed to get an instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                fallback = 1;
            } else {
                QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL) {
                qat_clear_async_event_notification();
            }
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            goto err;
        }

        CRYPTO_QAT_LOG("KX - %s\n", __func__);
        DUMP_DH_GEN_PHASE1(qat_instance_handles[inst_num], opData, pPV);
        status = cpaCyDhKeyGenPhase1(qat_instance_handles[inst_num],
                                     qat_dhCallbackFn,
                                     &op_done, opData, pPV);

        if (status == CPA_STATUS_RETRY) {
            if (op_done.job == NULL) {
                usleep(ulPollInterval +
                        (qatPerformOpRetries %
                         QAT_RETRY_BACKOFF_MODULO_DIVISOR));
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

    if (status != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        if (qat_get_sw_fallback_enabled() &&
            (status == CPA_STATUS_RESTARTING || status == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
        }
        if (op_done.job != NULL) {
            qat_clear_async_event_notification();
        }
        qat_cleanup_op_done(&op_done);
        QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
        goto err;
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
    }
    while (!op_done.flag ||
           QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DUMP_DH_GEN_PHASE1_OUTPUT(pPV);
    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

    if (op_done.verifyResult != CPA_TRUE) {
        WARN("Verification of result failed\n");
        if (qat_get_sw_fallback_enabled() && op_done.status == CPA_STATUS_FAIL) {
            CRYPTO_QAT_LOG("Verification of result failed for qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    qat_cleanup_op_done(&op_done);

    /* Convert the flatbuffer result back to a BN */
    BN_bin2bn(pPV->pData, pPV->dataLenInBytes, pub_key);

    if (!DH_set0_key(dh, pub_key, priv_key)) {
        WARN("Failure setting pub or priv key\n");
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ok = 1;
err:
    if (pPV) {
        if (pPV->pData) {
            qaeCryptoMemFree(pPV->pData);
        }
        OPENSSL_free(pPV);
    }

    if (opData) {
        if (opData->primeP.pData)
            qaeCryptoMemFree(opData->primeP.pData);
        if (opData->baseG.pData)
            qaeCryptoMemFree(opData->baseG.pData);
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(opData->privateValueX);
        OPENSSL_free(opData);
    }

    if (!ok) {
        if (generate_new_pub_key)
            BN_free(pub_key);
        if (generate_new_priv_key)
            BN_clear_free(priv_key);
    }

    if (fallback) {
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        return DH_meth_get_generate_key(sw_dh_method)(dh);
    }

    return ok;
}

/******************************************************************************
 * function:
 *         qat_dh_compute_key(unsigned char *key,
 *                            const BIGNUM * in_pub_key, DH * dh)
 *
 * description:
 *   Implement Diffie-Hellman phase 2 operations.
 ******************************************************************************/
int qat_dh_compute_key(unsigned char *key, const BIGNUM *in_pub_key, DH *dh)
{
    int ret = -1, job_ret = 0, fallback = 0;
    int check_result;
    int inst_num = QAT_INVALID_INSTANCE;
    CpaCyDhPhase2SecretKeyGenOpData *opData = NULL;
    CpaFlatBuffer *pSecretKey = NULL;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    CpaStatus status;
    op_done_t op_done;
    size_t buflen;
    int index = 1;
    const BIGNUM *p = NULL, *q = NULL;
    const BIGNUM *g = NULL;
    const BIGNUM *pub_key = NULL, *priv_key = NULL;
    const DH_METHOD *sw_dh_method = DH_OpenSSL();
    thread_local_variables_t *tlv = NULL;

    DEBUG("- Started\n");

    if (unlikely(key == NULL)) {
        WARN("Invalid variable key is NULL.\n");
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, QAT_R_KEY_NULL);
        return ret;
    }

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode\n");
        return DH_meth_get_compute_key(sw_dh_method)(key, in_pub_key, dh);

    }

    if (!dh) {
        WARN("Input variable dh is null\n");
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, QAT_R_DH_NULL);
        return ret;
    }

    DH_get0_pqg(dh, &p, &q, &g);
    DH_get0_key(dh, &pub_key, &priv_key);
    if (p == NULL || priv_key == NULL) {
        WARN("Failure getting p or priv_key\n");
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, QAT_R_P_Q_G_NULL);
        return ret;
    }

    /*
     * If the op sizes are not in the range supported by QAT engine then fall
     * back to software
     */

    if (!dh_range_check(BN_num_bits(p))) {
        if (sw_dh_method == NULL) {
            WARN("Failed to get sw_dh_method for bits %d\n", BN_num_bits(p));
            QATerr(QAT_F_QAT_DH_COMPUTE_KEY, QAT_R_SW_METHOD_NULL);
            return ret;
        }
        return DH_meth_get_compute_key(sw_dh_method)(key, in_pub_key, dh);
    }

    if (!DH_check_pub_key(dh, in_pub_key, &check_result) || check_result) {
        WARN("Failure checking pub key\n");
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, QAT_R_INVALID_PUB_KEY);
        return ret;
    }

    opData = (CpaCyDhPhase2SecretKeyGenOpData *)
        OPENSSL_zalloc(sizeof(CpaCyDhPhase2SecretKeyGenOpData));
    if (opData == NULL) {
        WARN("Failure allocating memory for opData\n");
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, QAT_R_OPDATA_MALLOC_FAILURE);
        return ret;
    }

    opData->primeP.pData = NULL;
    opData->remoteOctetStringPV.pData = NULL;
    opData->privateValueX.pData = NULL;

    buflen = BN_num_bytes(p);
    pSecretKey = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (pSecretKey == NULL) {
        WARN("Failure allocating memory for pSecretKey\n");
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, QAT_R_SECRET_KEY_MALLOC_FAILURE);
        goto err;
    }
    pSecretKey->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (pSecretKey->pData == NULL) {
        WARN("Failure allocating memory for pSecretKey data\n");
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, QAT_R_SECRET_KEY_PDATA_MALLOC_FAILURE);
        goto err;
    }
    pSecretKey->dataLenInBytes = (Cpa32U) buflen;

    if ((qat_BN_to_FB(&(opData->primeP), (BIGNUM *)p) != 1) ||
            (qat_BN_to_FB(&(opData->remoteOctetStringPV), (BIGNUM *)in_pub_key) != 1)
            || (qat_BN_to_FB(&(opData->privateValueX), (BIGNUM *)priv_key) !=
                1)) {
        WARN("Failure converting p, pub_key or priv_key into a flat buffer\n");
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, QAT_R_P_PUB_PRIV_KEY_CONVERT_TO_FB_FAILURE);
        goto err;
    }

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (qat_kill_thread(timer_poll_func_thread, SIGUSR1) != 0) {
                WARN("qat_kill_thread error\n");
                QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                goto err;
            }
        }
    }
    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            goto err;
        }
    }

    CRYPTO_QAT_LOG("KX - %s\n", __func__);
    do {
        if ((inst_num = get_next_inst_num()) == QAT_INVALID_INSTANCE) {
            WARN("Failed to get an instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                fallback = 1;
            } else {
                QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL) {
                qat_clear_async_event_notification();
            }
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            goto err;
        }

        CRYPTO_QAT_LOG("KX - %s\n", __func__);
        DUMP_DH_GEN_PHASE2(qat_instance_handles[inst_num], opData, pSecretKey);
        status = cpaCyDhKeyGenPhase2Secret(qat_instance_handles[inst_num],
                                           qat_dhCallbackFn,
                                           &op_done, opData, pSecretKey);

        if (status == CPA_STATUS_RETRY) {
            if (op_done.job == NULL) {
                usleep(ulPollInterval +
                        (qatPerformOpRetries %
                         QAT_RETRY_BACKOFF_MODULO_DIVISOR));
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

    if (status != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        if (qat_get_sw_fallback_enabled() &&
            (status == CPA_STATUS_RESTARTING || status == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        }
        if (op_done.job != NULL) {
            qat_clear_async_event_notification();
        }
        qat_cleanup_op_done(&op_done);
        QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
        goto err;
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
    }
    while (!op_done.flag ||
           QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DUMP_DH_GEN_PHASE2_OUTPUT(pSecretKey);
    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

    if (op_done.verifyResult != CPA_TRUE) {
        WARN("Verification of result failed\n");
        if (qat_get_sw_fallback_enabled() && op_done.status == CPA_STATUS_FAIL) {
            CRYPTO_QAT_LOG("Verification of result failed for qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    qat_cleanup_op_done(&op_done);

    if (unlikely(pSecretKey->pData == NULL)) {
        WARN("pSecretKey->pData is NULL\n");
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Remove leading zeros */
    if (!pSecretKey->pData[0]) {
        while (index < pSecretKey->dataLenInBytes && !pSecretKey->pData[index])
            index++;
        pSecretKey->dataLenInBytes = pSecretKey->dataLenInBytes - index;
        memcpy(key, &pSecretKey->pData[index],
                pSecretKey->dataLenInBytes);
    } else {
        memcpy(key, pSecretKey->pData, pSecretKey->dataLenInBytes);
    }
    ret = pSecretKey->dataLenInBytes;

 err:
    if (pSecretKey) {
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(*pSecretKey);
        OPENSSL_free(pSecretKey);
    }

    if (opData) {
        if (opData->primeP.pData)
            qaeCryptoMemFree(opData->primeP.pData);
        if (opData->remoteOctetStringPV.pData)
            qaeCryptoMemFree(opData->remoteOctetStringPV.pData);
        QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(opData->privateValueX);
        OPENSSL_free(opData);
    }

    if (fallback) {
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        return DH_meth_get_compute_key(sw_dh_method)(key, in_pub_key, dh);
    }

    return ret;
}

/******************************************************************************
* function:
*         qat_dh_mod_exp(const DH * dh, BIGNUM * r, const BIGNUM * a,
*                        const BIGNUM * p, const BIGNUM * m, BN_CTX * ctx,
*                        BN_MONT_CTX * m_ctx)
*
* @param dh    [IN] - Pointer to a OpenSSL DH struct.
* @param r     [IN] - Result bignum of mod_exp
* @param a     [IN] - Base used for mod_exp
* @param p     [IN] - Exponent used for mod_exp
* @param m     [IN] - Modulus used for mod_exp
* @param ctx   [IN] - EVP context.
* @param m_ctx [IN] - EVP context for Montgomery multiplication.
*
* description:
*   Overridden modular exponentiation function used in DH.
*
******************************************************************************/
int qat_dh_mod_exp(const DH *dh, BIGNUM *r, const BIGNUM *a,
                   const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                   BN_MONT_CTX *m_ctx)
{
    int ret = 0, fallback = 0;
    const DH_METHOD *sw_dh_method = DH_OpenSSL();

    DEBUG("- Started\n");

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode\n");
        return DH_meth_get_bn_mod_exp(sw_dh_method)(dh, r, a, p, m, ctx, m_ctx);
    }

    CRYPTO_QAT_LOG("KX - %s\n", __func__);
    ret = qat_mod_exp(r, a, p, m, &fallback);

    if (fallback) {
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        return DH_meth_get_bn_mod_exp(sw_dh_method)(dh, r, a, p, m, ctx, m_ctx);
    } else
        return ret;

}

/******************************************************************************
* function:
*         qat_dh_init(DH * dh)
*
* @param dh    [IN] - Pointer to a OpenSSL DH struct.
*
* description:
*   Overridden init function.
*   Calls the SW Implementation to ensure caching flag is set.
*
******************************************************************************/
int qat_dh_init(DH *dh)
{
    return DH_meth_get_init(DH_OpenSSL())(dh);
}

/******************************************************************************
* function:
*         qat_dh_finish(DH * dh)
*
* @param dh    [IN] - Pointer to a OpenSSL DH struct.
*
* description:
*   Overridden finish function.
*   Calls the SW Implementation to ensure cached data is freed.
*
******************************************************************************/
int qat_dh_finish(DH *dh)
{
    return DH_meth_get_finish(DH_OpenSSL())(dh);
}

#endif /* #ifndef OPENSSL_DISABLE_QAT_DH */
