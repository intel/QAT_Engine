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
 * @qat_prov_hw_ecx.c
 *
 * This file provides an implementation of X25519 and X448 operations
 * for qatprovider.
 *
 *****************************************************************************/
#ifdef ENABLE_QAT_HW_ECX
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define __USE_GNU

#include <pthread.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>

#include "openssl/ossl_typ.h"
#include "openssl/async.h"
#include "openssl/kdf.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "openssl/types.h"
#include "qat_utils.h"
#include "qat_hw_asym_common.h"
#include "e_qat.h"
#include "qat_hw_callback.h"
#include "qat_hw_polling.h"
#include "qat_events.h"
#include "qat_prov_ecx.h"

#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_USDM_MEM
# include "qat_hw_usdm_inf.h"
#endif

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_key.h"
#include "cpa_cy_ec.h"

#define QAT_X448_DATALEN       64
#define X448_DATA_KEY_DIFF      8

# ifdef QAT_OPENSSL_PROVIDER
void *qat_pkey_ecx_keygen(void *genctx, OSSL_CALLBACK *osslcb,
                          void *cbarg)
{
    CpaCyEcMontEdwdsPointMultiplyOpData *qat_ecx_op_data = NULL;

    int ret = 0;
    int job_ret = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean multiplyStatus = CPA_TRUE;
    CpaFlatBuffer *pXk = NULL;
    Cpa8U qat_keylen = 0;
    op_done_t op_done;
    int qatPerformOpRetries = 0;
    int iMsgRetry = getQatMsgRetryCount();
    unsigned long int ulPollInterval = getQatPollInterval();
    int inst_num = QAT_INVALID_INSTANCE;
    thread_local_variables_t *tlv = NULL;
    int fallback = 0;

    ECX_KEY *key = NULL;
    unsigned char *privkey = NULL;
    unsigned char *pubkey = NULL;
    int is_ecx_448 = 0;
    QAT_GEN_CTX *gctx = genctx;

    DEBUG("QAT HW ECX Started\n");

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        WARN("Cannot allocate key.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    key->references = 1;
    key->lock = CRYPTO_THREAD_lock_new();
    switch (gctx->type) {
     case ECX_KEY_TYPE_X25519:
            is_ecx_448 = 0;
            key->keylen = X25519_KEYLEN;
            qat_keylen = X25519_KEYLEN;
            DEBUG("EVP_PKEY_X25519\n");
            break;
     case ECX_KEY_TYPE_X448:
            is_ecx_448 = 1;
            key->keylen = X448_KEYLEN;
            qat_keylen = QAT_X448_DATALEN;
            DEBUG("EVP_PKEY_X448\n");
            break;
     default:
            WARN("Unsupported NID: %d\n", gctx->type);
            QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
            return 0;
    }

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode.\n");
        if (is_ecx_448 == 0) {
            typedef void* (*fun_ptr)(void *,OSSL_CALLBACK*,void*);
            fun_ptr fun = get_default_x25519_keymgmt().gen;
            return fun(genctx,osslcb,cbarg);
        } else {
            if (is_ecx_448 == 1) {
                typedef void* (*fun_ptr)(void *,OSSL_CALLBACK*,void*);
                fun_ptr fun = get_default_x448_keymgmt().gen;
                return fun(genctx,osslcb,cbarg);
            }
        }
    }
    qat_ecx_op_data = (CpaCyEcMontEdwdsPointMultiplyOpData *)
                       qaeCryptoMemAlloc(sizeof(CpaCyEcMontEdwdsPointMultiplyOpData),
                                         __FILE__, __LINE__);
    if (NULL == qat_ecx_op_data) {
        WARN("Failed to allocate memory for qat_ecx_op_data\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memset(qat_ecx_op_data, 0, sizeof(CpaCyEcMontEdwdsPointMultiplyOpData));

    qat_ecx_op_data->k.pData = (Cpa8U *)qaeCryptoMemAlloc(qat_keylen, __FILE__, __LINE__);
    if (qat_ecx_op_data->k.pData == NULL) {
        WARN("Failure to allocate k.pData.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    qat_ecx_op_data->k.dataLenInBytes = (Cpa32U)qat_keylen;

    pubkey = key->pubkey;
    privkey = key->privkey = OPENSSL_secure_zalloc(qat_keylen);
    if (privkey == NULL) {
        WARN("Cannot allocate privkey.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(key);
        key = NULL;
        goto err;
    }

    if (RAND_priv_bytes(privkey, key->keylen) <= 0) {
        WARN("RAND function failed for privkey.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    pXk = (CpaFlatBuffer *)OPENSSL_zalloc(sizeof(CpaFlatBuffer));
    if (NULL == pXk) {
        WARN("Failed to allocate memory for pXk\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pXk->pData = (Cpa8U *)qaeCryptoMemAlloc(qat_keylen, __FILE__, __LINE__);
    if (NULL == pXk->pData) {
        WARN("Failed to allocate memory for pXk data\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pXk->dataLenInBytes = qat_keylen;

    qat_ecx_op_data->generator = CPA_TRUE;
    qat_ecx_op_data->curveType =
        is_ecx_448 ? CPA_CY_EC_MONTEDWDS_CURVE448_TYPE : CPA_CY_EC_MONTEDWDS_CURVE25519_TYPE;

    if (0 == reverse_bytes(qat_ecx_op_data->k.pData, privkey, qat_keylen)) {
        WARN("Failed to reverse bytes for submission of data to QAT driver\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* ---- Perform the operation ---- */
    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            goto err;
        }
    }

    do {
        if ((inst_num = get_next_inst_num()) == QAT_INVALID_INSTANCE) {
            WARN("Failed to get an instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                fallback = 1;
            } else {
                QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL) {
                qat_clear_async_event_notification(op_done.job);
            }
            qat_cleanup_op_done(&op_done);
            goto err;
        }

        DUMP_EC_MONTEDWDS_POINT_MULTIPLY(qat_instance_handles[inst_num],
                                         qat_ecx_op_data, pXk, pYk);

        DEBUG("Calling cpaCyEcMontEdwdsPointMultiply.\n");
        status = cpaCyEcMontEdwdsPointMultiply(qat_instance_handles[inst_num],
                                               qat_ecx_cb,
                                               &op_done,
                                               qat_ecx_op_data,
                                               &multiplyStatus,
                                               pXk,
                                               NULL);
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
    } while (status == CPA_STATUS_RETRY);

    if (CPA_STATUS_SUCCESS != status) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        if (qat_get_sw_fallback_enabled() &&
            (status == CPA_STATUS_RESTARTING || status == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
        }
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
                QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                goto err;
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

    DUMP_EC_POINT_MULTIPLY_OUTPUT(multiplyStatus, pXk, pYk);
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
            QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    qat_cleanup_op_done(&op_done);

    if (0 == reverse_bytes(pubkey, pXk->pData, key->keylen)) {
        WARN("Failed to reverse bytes for data received from QAT driver\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    return key;

err:
    /* Clean the memory. */
    if (pXk != NULL) {
        if (pXk->pData != NULL) {
            OPENSSL_cleanse(pXk->pData, qat_keylen);
            qaeCryptoMemFreeNonZero(pXk->pData);
        }
        OPENSSL_free(pXk);
    }

    if (NULL != qat_ecx_op_data) {
        if (qat_ecx_op_data->k.pData != NULL) {
            OPENSSL_cleanse(qat_ecx_op_data->k.pData, qat_keylen);
            qaeCryptoMemFreeNonZero(qat_ecx_op_data->k.pData);
        }
        qaeCryptoMemFreeNonZero(qat_ecx_op_data);
        qat_ecx_op_data = NULL;
    }

    /* For success case cleanup will be taken care by calling application */
    if (ret == 0) {
        if (NULL != privkey) {
            OPENSSL_secure_free(privkey);
            if (NULL != key) {
                key->privkey = NULL;
                OPENSSL_free(key);
                key = NULL;
            }
        }
    }

    if (fallback) {
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        typedef void* (*fun_ptr)(void *,OSSL_CALLBACK*,void*);
        fun_ptr fun = get_default_x25519_keymgmt().gen;
        return fun(genctx,osslcb,cbarg);
    }
     return NULL;
}

static int qat_validate_ecx_derive(void *vecxctx,
                                   const unsigned char **privkey,
                                   const unsigned char **pubkey)
{
    QAT_ECX_CTX *ecxctx = (QAT_ECX_CTX *)vecxctx;

    if (ecxctx == NULL || ecxctx->key->privkey == NULL) {
        WARN("ecxctx or ecxctx->key->privkey is NULL\n");
        QATerr(QAT_F_QAT_VALIDATE_ECX_DERIVE, QAT_R_INVALID_PRIVATE_KEY);
        return 0;
    }
    if (ecxctx->peerkey->pubkey == NULL) {
        WARN("ecxctx->peerkey->pubkey is NULL\n");
        QATerr(QAT_F_QAT_VALIDATE_ECX_DERIVE, QAT_R_INVALID_PEER_KEY);
        return 0;
    }
    *privkey = ecxctx->key->privkey;
    *pubkey = ecxctx->peerkey->pubkey;

    return 1;
}

int qat_pkey_ecx_derive25519(void *vecxctx, unsigned char *secret, size_t *secretlen,
                             size_t outlen)
{
    CpaCyEcMontEdwdsPointMultiplyOpData *qat_ecx_op_data = NULL;

    int ret = 0;
    int job_ret = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean multiplyStatus = CPA_TRUE;
    CpaFlatBuffer *pXk = NULL;
    const unsigned char *privkey, *pubkey;
    Cpa8U dataLenInBytes = X25519_KEYLEN;
    op_done_t op_done;
    int qatPerformOpRetries = 0;
    int iMsgRetry = getQatMsgRetryCount();
    unsigned long int ulPollInterval = getQatPollInterval();
    int inst_num = QAT_INVALID_INSTANCE;
    thread_local_variables_t *tlv = NULL;
    int fallback = 0;

    DEBUG("QAT HW ECX Started\n");


    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode.\n");
        typedef int (*fun_ptr)(void *,unsigned char*,size_t*,size_t);
        fun_ptr fun = get_default_x25519_keyexch().derive;
        return fun(vecxctx,secret,secretlen,outlen);
    }

    if (!qat_validate_ecx_derive(vecxctx, &privkey, &pubkey))
        return 0;

    if (secret == NULL) {
        *secretlen = dataLenInBytes;
        return 1;
    }

    qat_ecx_op_data =
        (CpaCyEcMontEdwdsPointMultiplyOpData *)qaeCryptoMemAlloc(sizeof(CpaCyEcMontEdwdsPointMultiplyOpData),
                                                                 __FILE__, __LINE__);
    if (NULL == qat_ecx_op_data) {
        WARN("Failed to allocate memory for qat_ecx_op_data\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memset(qat_ecx_op_data, 0, sizeof(CpaCyEcMontEdwdsPointMultiplyOpData));

    qat_ecx_op_data->k.pData = (Cpa8U *)qaeCryptoMemAlloc(dataLenInBytes, __FILE__, __LINE__);
    if (qat_ecx_op_data->k.pData == NULL) {
        WARN("Failure to allocate k.pData.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    qat_ecx_op_data->k.dataLenInBytes = (Cpa32U)dataLenInBytes;

    qat_ecx_op_data->x.pData = (Cpa8U *)qaeCryptoMemAlloc(dataLenInBytes, __FILE__, __LINE__);
    if (qat_ecx_op_data->x.pData == NULL) {
        WARN("Failure to allocate x.pData.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    qat_ecx_op_data->x.dataLenInBytes = (Cpa32U)dataLenInBytes;

    pXk = (CpaFlatBuffer *)OPENSSL_zalloc(sizeof(CpaFlatBuffer));
    if (NULL == pXk) {
        WARN("Failed to allocate memory for pXk\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pXk->pData = (Cpa8U *)qaeCryptoMemAlloc(dataLenInBytes, __FILE__, __LINE__);
    if (NULL == pXk->pData) {
        WARN("Failed to allocate memory for pXk data\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pXk->dataLenInBytes = dataLenInBytes;

    qat_ecx_op_data->generator = CPA_FALSE;
    qat_ecx_op_data->curveType = CPA_CY_EC_MONTEDWDS_CURVE25519_TYPE;

    if (0 == reverse_bytes(qat_ecx_op_data->k.pData, (unsigned char *)privkey, dataLenInBytes)) {
        WARN("Failed to reverse bytes for submission of data to QAT driver\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (0 == reverse_bytes(qat_ecx_op_data->x.pData,(unsigned char *)pubkey, dataLenInBytes)) {
        WARN("Failed to reverse bytes for submission of data to QAT driver\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* ---- Perform the operation ---- */
    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            goto err;
        }
    }

    do {
        if ((inst_num = get_next_inst_num()) == QAT_INVALID_INSTANCE) {
            WARN("Failed to get an instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                fallback = 1;
            } else {
                QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL) {
                qat_clear_async_event_notification(op_done.job);
            }
            qat_cleanup_op_done(&op_done);
            goto err;
        }

        DUMP_EC_MONTEDWDS_POINT_MULTIPLY(qat_instance_handles[inst_num],
                                         qat_ecx_op_data, pXk, pYk);

        DEBUG("Calling cpaCyEcMontEdwdsPointMultiply.\n");
        status = cpaCyEcMontEdwdsPointMultiply(qat_instance_handles[inst_num],
                                               qat_ecx_cb,
                                               &op_done,
                                               qat_ecx_op_data,
                                               &multiplyStatus,
                                               pXk,
                                               NULL);
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
    } while (status == CPA_STATUS_RETRY);

    if (CPA_STATUS_SUCCESS != status) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        if (qat_get_sw_fallback_enabled() &&
            (status == CPA_STATUS_RESTARTING || status == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
        }
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
                QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                goto err;
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

    DUMP_EC_POINT_MULTIPLY_OUTPUT(multiplyStatus, pXk, pYk);
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
            QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    qat_cleanup_op_done(&op_done);

    if (0 == reverse_bytes(secret, pXk->pData, dataLenInBytes)) {
        WARN("Failed to reverse bytes for data received from QAT driver\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    *secretlen = (size_t)dataLenInBytes;
    ret = 1;

err:
    /* Clean the memory. */
    if (pXk != NULL) {
        if (pXk->pData != NULL) {
            OPENSSL_cleanse(pXk->pData, dataLenInBytes);
            qaeCryptoMemFreeNonZero(pXk->pData);
        }
        OPENSSL_free(pXk);
    }

    if (NULL != qat_ecx_op_data) {
        if (qat_ecx_op_data->k.pData != NULL) {
            OPENSSL_cleanse(qat_ecx_op_data->k.pData, dataLenInBytes);
            qaeCryptoMemFreeNonZero(qat_ecx_op_data->k.pData);
        }
        if (qat_ecx_op_data->x.pData != NULL) {
            OPENSSL_cleanse(qat_ecx_op_data->x.pData, dataLenInBytes);
            qaeCryptoMemFreeNonZero(qat_ecx_op_data->x.pData);
        }
        qaeCryptoMemFreeNonZero(qat_ecx_op_data);
        qat_ecx_op_data = NULL;
    }

    if (fallback) {
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        typedef int (*fun_ptr)(void *,unsigned char*,size_t*,size_t);
        fun_ptr fun = get_default_x25519_keyexch().derive;
        return fun(vecxctx,secret,secretlen,outlen);
    }
    return ret;
}

int qat_pkey_ecx_derive448(void *vecxctx, unsigned char *secret, size_t *secretlen,
                           size_t outlen)
{
    CpaCyEcMontEdwdsPointMultiplyOpData *qat_ecx_op_data = NULL;

    int ret = 0;
    int job_ret = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean multiplyStatus = CPA_TRUE;
    CpaFlatBuffer *pXk = NULL;
    const unsigned char *privkey, *pubkey;
    op_done_t op_done;
    int qatPerformOpRetries = 0;
    int iMsgRetry = getQatMsgRetryCount();
    unsigned long int ulPollInterval = getQatPollInterval();
    int inst_num = QAT_INVALID_INSTANCE;
    thread_local_variables_t *tlv = NULL;
    int fallback = 0;

    DEBUG("QAT HW ECX Started\n");


    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode.\n");
        typedef int (*fun_ptr)(void *,unsigned char*,size_t*,size_t);
        fun_ptr fun = get_default_x448_keyexch().derive;
        return fun(vecxctx,secret,secretlen,outlen);
    }

    if (!qat_validate_ecx_derive(vecxctx, &privkey, &pubkey))
        return 0;

    if (secret == NULL) {
        *secretlen = X448_KEYLEN;
        return 1;
    }

    qat_ecx_op_data =
        (CpaCyEcMontEdwdsPointMultiplyOpData *)qaeCryptoMemAlloc(sizeof(CpaCyEcMontEdwdsPointMultiplyOpData),
                                                                 __FILE__, __LINE__);
    if (NULL == qat_ecx_op_data) {
        WARN("Failed to allocate memory for qat_ecx_op_data\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memset(qat_ecx_op_data, 0, sizeof(CpaCyEcMontEdwdsPointMultiplyOpData));

    qat_ecx_op_data->k.pData = (Cpa8U *)qaeCryptoMemAlloc(QAT_X448_DATALEN, __FILE__, __LINE__);
    if (qat_ecx_op_data->k.pData == NULL) {
        WARN("Failure to allocate k.pData.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    qat_ecx_op_data->k.dataLenInBytes = QAT_X448_DATALEN;

    qat_ecx_op_data->x.pData = (Cpa8U *)qaeCryptoMemAlloc(QAT_X448_DATALEN, __FILE__, __LINE__);
    if (qat_ecx_op_data->x.pData == NULL) {
        WARN("Failure to allocate x.pData.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    qat_ecx_op_data->x.dataLenInBytes = QAT_X448_DATALEN;

    pXk = (CpaFlatBuffer *)OPENSSL_zalloc(sizeof(CpaFlatBuffer));
    if (NULL == pXk) {
        WARN("Failed to allocate memory for pXk\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pXk->pData = (Cpa8U *)qaeCryptoMemAlloc(QAT_X448_DATALEN, __FILE__, __LINE__);
    if (NULL == pXk->pData) {
        WARN("Failed to allocate memory for pXk data\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pXk->dataLenInBytes = QAT_X448_DATALEN;

    qat_ecx_op_data->generator = CPA_FALSE;
    qat_ecx_op_data->curveType = CPA_CY_EC_MONTEDWDS_CURVE448_TYPE;

    if (0 == reverse_bytes(qat_ecx_op_data->k.pData, (unsigned char *)privkey, QAT_X448_DATALEN)) {
        WARN("Failed to reverse bytes for submission of data to QAT driver\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (0 == reverse_bytes(qat_ecx_op_data->x.pData, (unsigned char *)pubkey, QAT_X448_DATALEN)) {
        WARN("Failed to reverse bytes for submission of data to QAT driver\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* ---- Perform the operation ---- */
    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            goto err;
        }
    }

    do {
        if ((inst_num = get_next_inst_num()) == QAT_INVALID_INSTANCE) {
            WARN("Failed to get an instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                fallback = 1;
            } else {
                QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL) {
                qat_clear_async_event_notification(op_done.job);
            }
            qat_cleanup_op_done(&op_done);
            goto err;
        }

        DUMP_EC_MONTEDWDS_POINT_MULTIPLY(qat_instance_handles[inst_num],
                                         qat_ecx_op_data, pXk, pYk);

        DEBUG("Calling cpaCyEcMontEdwdsPointMultiply.\n");
        status = cpaCyEcMontEdwdsPointMultiply(qat_instance_handles[inst_num],
                                               qat_ecx_cb,
                                               &op_done,
                                               qat_ecx_op_data,
                                               &multiplyStatus,
                                               pXk,
                                               NULL);
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
    } while (status == CPA_STATUS_RETRY);

    if (CPA_STATUS_SUCCESS != status) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        if (qat_get_sw_fallback_enabled() &&
            (status == CPA_STATUS_RESTARTING || status == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
        }
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
                QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                goto err;
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

    DUMP_EC_POINT_MULTIPLY_OUTPUT(multiplyStatus, pXk, pYk);
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
            QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    qat_cleanup_op_done(&op_done);

    if (0 == reverse_bytes(secret, pXk->pData, X448_KEYLEN)) {
        WARN("Failed to reverse bytes for data received from QAT driver\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    *secretlen = X448_KEYLEN;
    ret = 1;

err:
    /* Clean the memory. */
    if (pXk != NULL) {
        if (pXk->pData != NULL) {
            OPENSSL_cleanse(pXk->pData, QAT_X448_DATALEN);
            qaeCryptoMemFreeNonZero(pXk->pData);
        }
        OPENSSL_free(pXk);
    }

    if (NULL != qat_ecx_op_data) {
        if (qat_ecx_op_data->k.pData != NULL) {
            OPENSSL_cleanse(qat_ecx_op_data->k.pData, QAT_X448_DATALEN);
            qaeCryptoMemFreeNonZero(qat_ecx_op_data->k.pData);
        }
        if (qat_ecx_op_data->x.pData != NULL) {
            OPENSSL_cleanse(qat_ecx_op_data->x.pData, QAT_X448_DATALEN);
            qaeCryptoMemFreeNonZero(qat_ecx_op_data->x.pData);
        }
        qaeCryptoMemFreeNonZero(qat_ecx_op_data);
        qat_ecx_op_data = NULL;
    }

    if (fallback) {
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        typedef int (*fun_ptr)(void *,unsigned char*,size_t*,size_t);
        fun_ptr fun = get_default_x448_keyexch().derive;
        return fun(vecxctx,secret,secretlen,outlen);
    }
    return ret;
}
# endif /* Provider */
#endif /* ENABLE_QAT_HW_ECX */
