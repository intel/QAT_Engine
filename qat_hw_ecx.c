/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2019-2024 Intel Corporation.
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
 * @file qat_ecx.c
 *
 * This file provides an implementation of X25519 and X448 operations for an
 * OpenSSL engine.
 *
 *****************************************************************************/
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <pthread.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>

#include "openssl/ossl_typ.h"
#include "openssl/kdf.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "e_qat.h"
#include "qat_utils.h"
#include "qat_hw_asym_common.h"
#include "qat_hw_callback.h"
#include "qat_hw_polling.h"
#include "qat_events.h"
#ifdef QAT_OPENSSL_PROVIDER
# include "qat_prov_ecx.h"
#else
# include "qat_evp.h"
#endif

#ifdef ENABLE_QAT_SW_ECX
# include "qat_sw_ecx.h"
#endif
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
#include "qat_common.h"

#ifdef ENABLE_QAT_HW_ECX

int reverse_bytes(unsigned char *tobuffer, unsigned char *frombuffer,
                  unsigned int tosize, unsigned int fromsize)
{
    int i = 0;
    if (tobuffer == NULL || frombuffer == NULL) {
        WARN("Either tobuffer or frombuffer is  NULL \n");
        return 0;
    }

    if (fromsize == X448_KEYLEN)
        i = 8; /* Adds zeros at the beginning for 64 byte alignment */

    /* Reverse bytes and copy to dest buffer */
    for (; i < tosize; i++) {
        tobuffer[i] = frombuffer[--fromsize];
        if (fromsize <=0)
            break;
    }

    return 1;
}

/******************************************************************************
 * function:
 *         void qat_ecx_cb(void *pCallbackTag,
 *                         CpaStatus status,
 *                         void *pOpdata,
 *                         CpaBoolean multiplyStatus,
 *                         CpaFlatBuffer *pXk,
 *                         CpaFlatBuffer *pYk)
 *
 * @param pCallbackTag   [IN]  - Pointer to user data
 * @param status         [IN]  - Status of the operation
 * @param pOpData        [IN]  - Pointer to operation data included in the request
 * @param multiplyStatus [IN]  - Status of the point multiplication.
 * @param pXk            [IN]  - Pointer to the output buffer, provided in the request
 *                               invoking this callback, containing the x coordinate
 *                               of resultant EC point.
 * @param pYk            [IN]  - Pointer to the output buffer, provided in the request
 *                               invoking this callback, containing the y coordinate
 *                               of resultant EC point.
 *
 * description:
 *   Callback to indicate the completion of an X25519 or X448 point multiply
 *   operation offloaded to the QAT driver.
 *
 ******************************************************************************/
void qat_ecx_cb(void *pCallbackTag, CpaStatus status,
                void *pOpData, CpaBoolean multiplyStatus,
                CpaFlatBuffer *pXk, CpaFlatBuffer *pYk)
{
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_asym_requests_in_flight);
    }
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, multiplyStatus);
}

static void qat_pkey_ecx_keygen_op_data_free(CpaFlatBuffer *pXk,
        CpaCyEcMontEdwdsPointMultiplyOpData *qat_ecx_op_data,
        int qat_keylen, int qat_svm)
{
    /* Clean the memory. */
    if (pXk != NULL) {
        QAT_CLEANSE_MEMFREE_NONZERO_FLATBUFF(*pXk, qat_svm);
        OPENSSL_free(pXk);
    }

    if (NULL != qat_ecx_op_data) {
        QAT_CLEANSE_MEMFREE_NONZERO_FLATBUFF(qat_ecx_op_data->k, qat_svm);
        QAT_MEM_FREE_BUFF(qat_ecx_op_data, qat_svm);
    }
}

/* For OpenSSL 3.0, ECX25519 and ECX448 are not supported due to
 * the structure of EVP_PKEY_CTX and EVP_PKEY changed a lot,
 * Therefore, this function is wrapped to avoid the issue
 * introduced by reinforced casting of EVP_PKEY_CTX.
 */
# ifdef QAT_OPENSSL_PROVIDER
static void *qat_pkey_ecx_keygen(void *ctx, OSSL_CALLBACK *osslcb, void *cbarg)
#else
static int qat_pkey_ecx_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey, int type)
#endif
{
    CpaCyEcMontEdwdsPointMultiplyOpData *qat_ecx_op_data = NULL;

    int ret = 0;
    int job_ret = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean multiplyStatus = CPA_TRUE;
    CpaFlatBuffer *pXk = NULL;
    Cpa8U keylen = 0;
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
    int qat_svm = QAT_INSTANCE_ANY;

# ifndef QAT_OPENSSL_PROVIDER
    int (*sw_fn_ptr)(EVP_PKEY_CTX *, EVP_PKEY *) = NULL;
#else
    QAT_GEN_CTX *gctx = ctx;
# endif

    DEBUG("QAT HW ECX Started\n");
    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        WARN("Cannot allocate key.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /* In OpenSSL 3, the structure of ECX_KEY has changed a lot,
     * one of the most important changes is the introduction of
     * a reference count variable as well as a lock variable.
     * When the EVP_PKEY_free() function is finally called to
     * reclaim memory, openssl will first decrease the reference
     * count before freeing its memory. Since this variable is
     * generated by qatengine, we must update its reference
     * count accordingly, otherwise it will trigger openssl's panic.
     */
#ifdef QAT_OPENSSL_3
# if OPENSSL_VERSION_NUMBER < 0x30200000
    key->references = 1;
    key->lock = CRYPTO_THREAD_lock_new();
# else
    key->references.val = 1;
# endif
#endif

#ifndef QAT_OPENSSL_PROVIDER
    switch (type) {
    case EVP_PKEY_X25519:
        is_ecx_448 = 0;
        keylen = qat_keylen = X25519_KEYLEN;
        DEBUG("EVP_PKEY_X25519\n");
        break;
    case EVP_PKEY_X448:
        is_ecx_448 = 1;
        keylen = X448_KEYLEN;
        qat_keylen = QAT_X448_DATALEN;
        DEBUG("EVP_PKEY_X448\n");
        break;
    default:
        WARN("Unsupported NID: %d\n", type);
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
        OPENSSL_free(key);
        return 0;
    }

    if (qat_sw_ecx_keygen_req > 0 || qat_get_qat_offload_disabled()) {
        fallback = 1;
        goto err;
    }
#else
    switch (gctx->type) {
    case ECX_KEY_TYPE_X25519:
        is_ecx_448 = 0;
        keylen = key->keylen = X25519_KEYLEN;
        qat_keylen = X25519_KEYLEN;
        DEBUG("EVP_PKEY_X25519\n");
        break;
    case ECX_KEY_TYPE_X448:
        is_ecx_448 = 1;
        keylen = key->keylen = X448_KEYLEN;
        qat_keylen = QAT_X448_DATALEN;
        DEBUG("EVP_PKEY_X448\n");
        break;
    default:
        WARN("Unsupported NID: %d\n", gctx->type);
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
        OPENSSL_free(key);
        return 0;
    }

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode.\n");
        OPENSSL_free(key);

        if (!is_ecx_448) {
            typedef void* (*sw_prov_fun_ptr)(void *, OSSL_CALLBACK*, void*);
            sw_prov_fun_ptr sw_fn_ptr = get_default_x25519_keymgmt().gen;
            return sw_fn_ptr(ctx, osslcb, cbarg);
        } else if (is_ecx_448) {
            typedef void* (*sw_prov_fun_ptr)(void *, OSSL_CALLBACK*, void*);
            sw_prov_fun_ptr sw_fn_ptr = get_default_x448_keymgmt().gen;
            return sw_fn_ptr(ctx, osslcb, cbarg);
        }
    }
#endif
    if ((inst_num = get_instance(QAT_INSTANCE_ASYM, QAT_INSTANCE_ANY))
            == QAT_INVALID_INSTANCE) {
        WARN("Failed to get an instance\n");
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
            fallback = 1;
            goto err;
        } else {
            QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
            OPENSSL_free(key);
            return 0;
        }
    }

    qat_svm = !qat_instance_details[inst_num].qat_instance_info.requiresPhysicallyContiguousMemory;

    qat_ecx_op_data = (CpaCyEcMontEdwdsPointMultiplyOpData *)
                       qat_mem_alloc(sizeof(CpaCyEcMontEdwdsPointMultiplyOpData),
                                     qat_svm, __FILE__, __LINE__);
    if (NULL == qat_ecx_op_data) {
        WARN("Failed to allocate memory for qat_ecx_op_data\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(key);
        return 0;
    }
    memset(qat_ecx_op_data, 0, sizeof(CpaCyEcMontEdwdsPointMultiplyOpData));

    qat_ecx_op_data->k.pData = (Cpa8U *)qat_mem_alloc(qat_keylen, qat_svm, __FILE__, __LINE__);
    if (qat_ecx_op_data->k.pData == NULL) {
        WARN("Failure to allocate k.pData.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    qat_ecx_op_data->k.dataLenInBytes = (Cpa32U)qat_keylen;

    pubkey = key->pubkey;
    privkey = key->privkey = OPENSSL_secure_zalloc(keylen);
    if (privkey == NULL) {
        WARN("Cannot allocate privkey.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (RAND_priv_bytes(privkey, keylen) <= 0) {
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

    pXk->pData = (Cpa8U *)qat_mem_alloc(qat_keylen, qat_svm, __FILE__, __LINE__);
    if (NULL == pXk->pData) {
        WARN("Failed to allocate memory for pXk data\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pXk->dataLenInBytes = qat_keylen;

    qat_ecx_op_data->generator = CPA_TRUE;
    qat_ecx_op_data->curveType =
        is_ecx_448 ? CPA_CY_EC_MONTEDWDS_CURVE448_TYPE : CPA_CY_EC_MONTEDWDS_CURVE25519_TYPE;

    if (0 == reverse_bytes(qat_ecx_op_data->k.pData, privkey, qat_keylen, keylen)) {
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
        if (status == CPA_STATUS_RETRY &&
           (inst_num = get_instance(QAT_INSTANCE_ASYM, qat_svm))
                == QAT_INVALID_INSTANCE) {
            WARN("Failed to get an instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                fallback = 1;
            } else {
                QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL)
                qat_clear_async_event_notification(op_done.job);
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
            if (qat_ecx_coexist && !is_ecx_448) {
                if (op_done.job) {
                    DEBUG("cpaCyEcMontEdwdsPointMultiply Retry \n");
                    ++num_ecx_keygen_retry;
                    qat_sw_ecx_keygen_req += QAT_SW_SWITCH_MB8;
                    fallback = 1;
                    qat_cleanup_op_done(&op_done);
                    goto err;
                }
            } else {
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
        } else if (status == CPA_STATUS_UNSUPPORTED) {
            WARN("Algorithm Unsupported in QAT_HW! Using OpenSSL SW\n");
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
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n",
                      &hw_polling_thread_sem);
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

    if (qat_ecx_coexist) {
        ++num_ecx_hw_keygen_reqs;
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
                sched_yield();
        } else {
            sched_yield();
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

    if (0 == reverse_bytes(pubkey, pXk->pData, keylen, qat_keylen)) {
        WARN("Failed to reverse bytes for data received from QAT driver\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#ifdef QAT_OPENSSL_PROVIDER
    qat_pkey_ecx_keygen_op_data_free(pXk, qat_ecx_op_data, qat_keylen, qat_svm);
    return key;
#else
    EVP_PKEY_assign(pkey, (is_ecx_448 ? EVP_PKEY_X448 : EVP_PKEY_X25519), key);
    ret = 1;
#endif

err:
    qat_pkey_ecx_keygen_op_data_free(pXk, qat_ecx_op_data, qat_keylen, qat_svm);
    /* For success case cleanup will be taken care by calling application */
    if (!ret) {
        if (NULL != privkey) {
            OPENSSL_secure_free(privkey);
            privkey = NULL;
        }
        if (NULL != key) {
            OPENSSL_free(key);
            key = NULL;
        }
    }

    if (fallback) {
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
#ifdef QAT_OPENSSL_PROVIDER
        if (is_ecx_448 == 0) {
            typedef void* (*sw_prov_fun_ptr)(void *, OSSL_CALLBACK*, void*);
            sw_prov_fun_ptr sw_fun_ptr = get_default_x25519_keymgmt().gen;
            return sw_fun_ptr(ctx, osslcb, cbarg);
        } else if (is_ecx_448 == 1) {
                typedef void* (*sw_prov_fun_ptr)(void *, OSSL_CALLBACK*, void*);
                sw_prov_fun_ptr sw_fun_ptr = get_default_x448_keymgmt().gen;
                return sw_fun_ptr(ctx, osslcb, cbarg);
        }
#else
#ifdef ENABLE_QAT_SW_ECX
        if (qat_ecx_coexist && !is_ecx_448) {
            DEBUG("- Switched to QAT_SW mode\n");
            if (qat_sw_ecx_keygen_req > 0)
                --qat_sw_ecx_keygen_req;
            return multibuff_x25519_keygen(ctx, pkey);
        }
#endif
        WARN("- Fallback to software mode.\n");
        EVP_PKEY_meth_get_keygen((EVP_PKEY_METHOD *)
                                (is_ecx_448 ? sw_x448_pmeth : sw_x25519_pmeth),
                                NULL, &sw_fn_ptr);
        ret = (*sw_fn_ptr)(ctx, pkey);
#endif
    }
#ifdef QAT_OPENSSL_PROVIDER
    return NULL;
#else
    return ret;
#endif
}

# ifdef QAT_OPENSSL_PROVIDER
void *qat_pkey_ecx448_keygen(void *ctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    return qat_pkey_ecx_keygen(ctx, osslcb, cbarg);
}
void *qat_pkey_ecx25519_keygen(void *ctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    return qat_pkey_ecx_keygen(ctx, osslcb, cbarg);
}
#else
int qat_pkey_ecx448_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    return qat_pkey_ecx_keygen(ctx, pkey, EVP_PKEY_X448);
}
int qat_pkey_ecx25519_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    return qat_pkey_ecx_keygen(ctx, pkey, EVP_PKEY_X25519);
}
#endif

#ifdef QAT_OPENSSL_PROVIDER
static int qat_validate_ecx_derive(void *ctx,
                                   const unsigned char **privkey,
                                   const unsigned char **pubkey)
#else
static int qat_validate_ecx_derive(EVP_PKEY_CTX *ctx,
                                   const unsigned char **privkey,
                                   const unsigned char **pubkey)
#endif
{
#ifdef QAT_OPENSSL_PROVIDER
    QAT_ECX_CTX *ecxctx = (QAT_ECX_CTX *)ctx;

    if (ecxctx == NULL ||  ecxctx->key->privkey == NULL) {
        WARN("ecxctx or ecxctx->key->privkey is NULL\n");
        QATerr(QAT_F_QAT_VALIDATE_ECX_DERIVE, QAT_R_INVALID_PRIVATE_KEY);
        return 0;
    }

    *privkey = ecxctx->key->privkey;
    *pubkey = ecxctx->peerkey->pubkey;

#else
    const ECX_KEY *ecxkey, *peerecxkey;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *peerkey = NULL;

    if ((pkey = EVP_PKEY_CTX_get0_pkey(ctx)) == NULL ||
        (peerkey = EVP_PKEY_CTX_get0_peerkey(ctx)) == NULL) {
        WARN("ctx->pkey or ctx->peerkey is NULL\n");
        QATerr(QAT_F_QAT_VALIDATE_ECX_DERIVE, QAT_R_KEYS_NOT_SET);
        return 0;
    }

    ecxkey = (const ECX_KEY *)EVP_PKEY_get0((const EVP_PKEY *)pkey);
    peerecxkey = (const ECX_KEY *)EVP_PKEY_get0((const EVP_PKEY *)peerkey);

    if (ecxkey == NULL || ecxkey->privkey == NULL) {
        WARN("ecxkey or ecxkey->privkey is NULL\n");
        QATerr(QAT_F_QAT_VALIDATE_ECX_DERIVE, QAT_R_INVALID_PRIVATE_KEY);
        return 0;
    }
    if (peerecxkey == NULL) {
        WARN("peerecxkey is NULL\n");
        QATerr(QAT_F_QAT_VALIDATE_ECX_DERIVE, QAT_R_INVALID_PEER_KEY);
        return 0;
    }
    *privkey = ecxkey->privkey;
    *pubkey = peerecxkey->pubkey;
#endif
    return 1;
}

#ifdef QAT_OPENSSL_PROVIDER
int qat_pkey_ecx_derive25519(void *ctx, unsigned char *key, size_t *keylen,
                             size_t outlen)
#else
int qat_pkey_ecx_derive25519(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
#endif
{
    CpaCyEcMontEdwdsPointMultiplyOpData *qat_ecx_op_data = NULL;

#ifndef QAT_OPENSSL_PROVIDER
    int (*sw_fn_ptr)(EVP_PKEY_CTX *, unsigned char *, size_t *) = NULL;
#endif
    int ret = 0;
    int job_ret = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean multiplyStatus = CPA_TRUE;
    CpaFlatBuffer *pXk = NULL;
    const unsigned char *privkey = NULL, *pubkey = NULL;
    op_done_t op_done;
    int qatPerformOpRetries = 0;
    int iMsgRetry = getQatMsgRetryCount();
    unsigned long int ulPollInterval = getQatPollInterval();
    int inst_num = QAT_INVALID_INSTANCE;
    thread_local_variables_t *tlv = NULL;
    int fallback = 0;
    int qat_svm = QAT_INSTANCE_ANY;

    DEBUG("QAT HW ECX Started\n");
    START_RDTSC(&qat_hw_ecx_derive_req_prepare);

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL \n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
        return 0;
    }

#ifdef QAT_OPENSSL_PROVIDER
    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode.\n");
        typedef int (*sw_prov_fun_ptr)(void *, unsigned char*, size_t*, size_t);
        sw_prov_fun_ptr sw_fun_ptr = get_default_x25519_keyexch().derive;
        return sw_fun_ptr(ctx, key, keylen, outlen);
    }
#else
    if (qat_sw_ecx_derive_req > 0 || qat_get_qat_offload_disabled()) {
        fallback = 1;
        goto err;
    }
#endif

    if (!qat_validate_ecx_derive(ctx, &privkey, &pubkey))
        return 0;

    if (key == NULL) {
        *keylen = X25519_KEYLEN;
        return 1;
    }

    if ((inst_num = get_instance(QAT_INSTANCE_ASYM, qat_svm))
            == QAT_INVALID_INSTANCE) {
        WARN("Failed to get an instance\n");
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
            fallback = 1;
            goto err;
        } else {
            QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    qat_svm = !qat_instance_details[inst_num].qat_instance_info.requiresPhysicallyContiguousMemory;

    qat_ecx_op_data = (CpaCyEcMontEdwdsPointMultiplyOpData *)
		               qat_mem_alloc(sizeof(CpaCyEcMontEdwdsPointMultiplyOpData),
                                            qat_svm, __FILE__, __LINE__);
    if (NULL == qat_ecx_op_data) {
        WARN("Failed to allocate memory for qat_ecx_op_data\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memset(qat_ecx_op_data, 0, sizeof(CpaCyEcMontEdwdsPointMultiplyOpData));

    qat_ecx_op_data->k.pData = (Cpa8U *)qat_mem_alloc(X25519_KEYLEN, qat_svm,
                                                      __FILE__, __LINE__);
    if (qat_ecx_op_data->k.pData == NULL) {
        WARN("Failure to allocate k.pData.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    qat_ecx_op_data->k.dataLenInBytes = X25519_KEYLEN;
    qat_ecx_op_data->x.pData = (Cpa8U *)qat_mem_alloc(X25519_KEYLEN, qat_svm,
                                                      __FILE__, __LINE__);
    if (qat_ecx_op_data->x.pData == NULL) {
        WARN("Failure to allocate x.pData.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    qat_ecx_op_data->x.dataLenInBytes = X25519_KEYLEN;

    pXk = (CpaFlatBuffer *)OPENSSL_zalloc(sizeof(CpaFlatBuffer));
    if (NULL == pXk) {
        WARN("Failed to allocate memory for pXk\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pXk->pData = (Cpa8U *)qat_mem_alloc(X25519_KEYLEN, qat_svm, __FILE__, __LINE__);
    if (NULL == pXk->pData) {
        WARN("Failed to allocate memory for pXk data\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pXk->dataLenInBytes = X25519_KEYLEN;

    qat_ecx_op_data->generator = CPA_FALSE;
    qat_ecx_op_data->curveType = CPA_CY_EC_MONTEDWDS_CURVE25519_TYPE;

    if (0 == reverse_bytes(qat_ecx_op_data->k.pData,(unsigned char *)privkey,
                           X25519_KEYLEN, X25519_KEYLEN)) {
        WARN("Failed to reverse bytes for submission of data to QAT driver\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (0 == reverse_bytes(qat_ecx_op_data->x.pData, (unsigned char *)pubkey,
                           X25519_KEYLEN, X25519_KEYLEN)) {
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
    STOP_RDTSC(&qat_hw_ecx_derive_req_prepare, 1, "[QAT HW ECX: prepare]");

    do {
        START_RDTSC(&qat_hw_ecx_derive_req_submit);
        if (status == CPA_STATUS_RETRY &&
           (inst_num = get_instance(QAT_INSTANCE_ASYM, QAT_INSTANCE_ANY))
             == QAT_INVALID_INSTANCE) {
            WARN("Failed to get an instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                fallback = 1;
            } else {
                QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL)
                qat_clear_async_event_notification(op_done.job);
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
        STOP_RDTSC(&qat_hw_ecx_derive_req_submit, 1, "[QAT HW ECX: submit]");
        if (status == CPA_STATUS_RETRY) {
            if (qat_ecx_coexist) {
                if (op_done.job) {
                    START_RDTSC(&qat_hw_ecx_derive_req_retry);
                    DEBUG("cpaCyEcMontEdwdsPointMultiply Retry \n");
                    ++num_ecx_derive_retry;
                    qat_sw_ecx_derive_req += QAT_SW_SWITCH_MB8;
                    fallback = 1;
                    qat_cleanup_op_done(&op_done);
                    STOP_RDTSC(&qat_hw_ecx_derive_req_retry, 1, "[QAT HW ECX: retry]");
                    goto err;
                }
            } else {
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
        } else if (status == CPA_STATUS_UNSUPPORTED) {
            WARN("Algorithm Unsupported in QAT_HW! Using OpenSSL SW\n");
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
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n",
                      &hw_polling_thread_sem);
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

    if (qat_ecx_coexist)
        ++num_ecx_hw_derive_reqs;

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

    if (0 == reverse_bytes(key, pXk->pData, X25519_KEYLEN, X25519_KEYLEN)) {
        WARN("Failed to reverse bytes for data received from QAT driver\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    *keylen = X25519_KEYLEN;
    ret = 1;

err:
    START_RDTSC(&qat_hw_ecx_derive_req_cleanup);
    /* Clean the memory. */
    if (pXk != NULL) {
        QAT_CLEANSE_MEMFREE_NONZERO_FLATBUFF(*pXk, qat_svm);
        OPENSSL_free(pXk);
    }

    if (NULL != qat_ecx_op_data) {
        QAT_CLEANSE_MEMFREE_NONZERO_FLATBUFF(qat_ecx_op_data->k, qat_svm);
        QAT_CLEANSE_MEMFREE_NONZERO_FLATBUFF(qat_ecx_op_data->x, qat_svm);
        QAT_MEM_FREE_BUFF(qat_ecx_op_data, qat_svm);
    }
    STOP_RDTSC(&qat_hw_ecx_derive_req_cleanup, 1, "[QAT HW ECX: cleanup]");

    if (fallback) {
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
#ifdef QAT_OPENSSL_PROVIDER
        typedef int (*sw_prov_fun_ptr)(void *, unsigned char*, size_t*, size_t);
        sw_prov_fun_ptr sw_fun_ptr = get_default_x25519_keyexch().derive;
        return sw_fun_ptr(ctx, key, keylen, outlen);
#else
#ifdef ENABLE_QAT_SW_ECX
        if (qat_ecx_coexist) {
            DEBUG("- Switched to QAT_SW mode\n");
            if (qat_sw_ecx_derive_req > 0)
                --qat_sw_ecx_derive_req;
            return multibuff_x25519_derive(ctx, key, keylen);
        }
#endif
        WARN("- Fallback to software mode.\n");
        EVP_PKEY_meth_get_derive((EVP_PKEY_METHOD *)sw_x25519_pmeth, NULL, &sw_fn_ptr);
        ret = (*sw_fn_ptr)(ctx, key, keylen);
#endif
    }
    return ret;
}

#ifdef QAT_OPENSSL_PROVIDER
int qat_pkey_ecx_derive448(void *ctx, unsigned char *key, size_t *keylen,
                           size_t outlen)
#else
int qat_pkey_ecx_derive448(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
#endif
{
    CpaCyEcMontEdwdsPointMultiplyOpData *qat_ecx_op_data = NULL;

#ifndef QAT_OPENSSL_PROVIDER
    int (*sw_fn_ptr)(EVP_PKEY_CTX *, unsigned char *, size_t *) = NULL;
#endif
    int ret = 0;
    int job_ret = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean multiplyStatus = CPA_TRUE;
    CpaFlatBuffer *pXk = NULL;
    const unsigned char *privkey = NULL, *pubkey = NULL;
    op_done_t op_done;
    int qatPerformOpRetries = 0;
    int iMsgRetry = getQatMsgRetryCount();
    unsigned long int ulPollInterval = getQatPollInterval();
    int inst_num = QAT_INVALID_INSTANCE;
    thread_local_variables_t *tlv = NULL;
    int fallback = 0;
    int qat_svm = QAT_INSTANCE_ANY;

    DEBUG("QAT HW ECX Started\n");

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL \n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode.\n");
#ifdef QAT_OPENSSL_PROVIDER
        typedef int (*sw_prov_fun_ptr)(void *, unsigned char*, size_t*, size_t);
        sw_prov_fun_ptr sw_fun_ptr = get_default_x448_keyexch().derive;
        return sw_fun_ptr(ctx, key, keylen, outlen);
#else
        EVP_PKEY_meth_get_derive((EVP_PKEY_METHOD *)sw_x448_pmeth, NULL, &sw_fn_ptr);
        ret = (*sw_fn_ptr)(ctx, key, keylen);
        if (ret != 1) {
            WARN("s/w pkey_ecx_derive448 fn failed.\n");
            QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
        }
        return ret;
#endif
    }

    if (!qat_validate_ecx_derive(ctx, &privkey, &pubkey))
        return 0;

    if (key == NULL) {
        *keylen = X448_KEYLEN;
        return 1;
    }

    if ((inst_num = get_instance(QAT_INSTANCE_ASYM, QAT_INSTANCE_ANY))
            == QAT_INVALID_INSTANCE) {
        WARN("Failed to get an instance\n");
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
            fallback = 1;
            goto err;
        } else {
            QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    qat_svm = !qat_instance_details[inst_num].qat_instance_info.requiresPhysicallyContiguousMemory;

    qat_ecx_op_data = (CpaCyEcMontEdwdsPointMultiplyOpData *)
                       qat_mem_alloc(sizeof(CpaCyEcMontEdwdsPointMultiplyOpData),
                                     qat_svm, __FILE__, __LINE__);
    if (NULL == qat_ecx_op_data) {
        WARN("Failed to allocate memory for qat_ecx_op_data\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memset(qat_ecx_op_data, 0, sizeof(CpaCyEcMontEdwdsPointMultiplyOpData));

    qat_ecx_op_data->k.pData = (Cpa8U *)qat_mem_alloc(QAT_X448_DATALEN, qat_svm,
                                                      __FILE__, __LINE__);
    if (qat_ecx_op_data->k.pData == NULL) {
        WARN("Failure to allocate k.pData.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    qat_ecx_op_data->k.dataLenInBytes = QAT_X448_DATALEN;

    qat_ecx_op_data->x.pData = (Cpa8U *)qat_mem_alloc(QAT_X448_DATALEN, qat_svm,
                                                      __FILE__, __LINE__);
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

    pXk->pData = (Cpa8U *)qat_mem_alloc(QAT_X448_DATALEN, qat_svm, __FILE__, __LINE__);
    if (NULL == pXk->pData) {
        WARN("Failed to allocate memory for pXk data\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pXk->dataLenInBytes = QAT_X448_DATALEN;

    qat_ecx_op_data->generator = CPA_FALSE;
    qat_ecx_op_data->curveType = CPA_CY_EC_MONTEDWDS_CURVE448_TYPE;

    if (0 == reverse_bytes(qat_ecx_op_data->k.pData,(unsigned char *)privkey,
                           QAT_X448_DATALEN, X448_KEYLEN)) {
        WARN("Failed to reverse bytes for submission of data to QAT driver\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (0 == reverse_bytes(qat_ecx_op_data->x.pData, (unsigned char *)pubkey,
                           QAT_X448_DATALEN, X448_KEYLEN)) {
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
        if (status == CPA_STATUS_RETRY &&
           (inst_num = get_instance(QAT_INSTANCE_ASYM, qat_svm))
                == QAT_INVALID_INSTANCE) {
            WARN("Failed to get an instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                fallback = 1;
            } else {
                QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL)
                qat_clear_async_event_notification(op_done.job);
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
        } else if (status == CPA_STATUS_UNSUPPORTED) {
            WARN("Algorithm Unsupported in QAT_HW! Using OpenSSL SW\n");
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
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n",
                      &hw_polling_thread_sem);
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
                sched_yield();
        } else {
            sched_yield();
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

    if (0 == reverse_bytes(key, pXk->pData, X448_KEYLEN, QAT_X448_DATALEN)) {
        WARN("Failed to reverse bytes for data received from QAT driver\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    *keylen = X448_KEYLEN;
    ret = 1;

err:
    /* Clean the memory. */
    if (pXk != NULL) {
        QAT_CLEANSE_MEMFREE_NONZERO_FLATBUFF(*pXk, qat_svm);
        OPENSSL_free(pXk);
    }

    if (NULL != qat_ecx_op_data) {
        QAT_CLEANSE_MEMFREE_NONZERO_FLATBUFF(qat_ecx_op_data->k, qat_svm);
        QAT_CLEANSE_MEMFREE_NONZERO_FLATBUFF(qat_ecx_op_data->x, qat_svm);
        QAT_MEM_FREE_BUFF(qat_ecx_op_data, qat_svm);
    }

    if (fallback) {
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
#ifdef QAT_OPENSSL_PROVIDER
        typedef int (*sw_prov_fun_ptr)(void *, unsigned char*, size_t*, size_t);
        sw_prov_fun_ptr sw_fun_ptr = get_default_x448_keyexch().derive;
        return sw_fun_ptr(ctx, key, keylen, outlen);
#else
        EVP_PKEY_meth_get_derive((EVP_PKEY_METHOD *)sw_x448_pmeth, NULL, &sw_fn_ptr);
        ret = (*sw_fn_ptr)(ctx, key, keylen);
#endif
    }
    return ret;
}

# ifndef QAT_OPENSSL_PROVIDER
int qat_pkey_ecx_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    DEBUG("Started\n");

    /* Only need to handle peer key for derivation */
    if (type == EVP_PKEY_CTRL_PEER_KEY)
        return 1;
    return -2;
}
# endif
#endif /* ENABLE_QAT_HW_ECX */
