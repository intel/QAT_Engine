/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2019-2020 Intel Corporation.
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

#include "openssl/ossl_typ.h"
#include "openssl/async.h"
#include "openssl/kdf.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "qat_evp.h"
#include "qat_utils.h"
#include "qat_asym_common.h"
#include "e_qat.h"
#include "qat_callback.h"
#include "qat_polling.h"
#include "qat_events.h"

#include "e_qat_err.h"

#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "cmn_mem_drv_inf.h"
#endif

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_key.h"
#include "cpa_cy_ec.h"

#ifdef OPENSSL_ENABLE_QAT_ECX
# ifdef OPENSSL_DISABLE_QAT_ECX
#  undef OPENSSL_DISABLE_QAT_ECX
# endif
#endif

#define X25519_KEYLEN          32
#define X448_KEYLEN            56
#define QAT_X448_DATALEN       64
#define X448_DATA_KEY_DIFF      8


#ifndef OPENSSL_DISABLE_QAT_ECX
typedef struct {
    unsigned char pubkey[QAT_X448_DATALEN];
    unsigned char *privkey;
} ECX_KEY;

/* Function Declarations */
static int qat_pkey_ecx_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
static int qat_pkey_ecx_derive25519(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
static int qat_pkey_ecx_derive448(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
static int qat_pkey_ecx_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
#endif /* OPENSSL_DISABLE_QAT_ECX */

static EVP_PKEY_METHOD *_hidden_x25519_pmeth = NULL;
static EVP_PKEY_METHOD *_hidden_x448_pmeth = NULL;

#ifndef OPENSSL_DISABLE_QAT_ECX
/* Have a store of the s/w EVP_PKEY_METHOD for software fallback purposes. */
static const EVP_PKEY_METHOD *sw_x25519_pmeth = NULL;
static const EVP_PKEY_METHOD *sw_x448_pmeth = NULL;
#endif

EVP_PKEY_METHOD *qat_x25519_pmeth(void)
{
#ifdef OPENSSL_DISABLE_QAT_ECX
    const EVP_PKEY_METHOD *current_x25519_pmeth = NULL;
#endif
    if (_hidden_x25519_pmeth)
        return _hidden_x25519_pmeth;
#ifdef OPENSSL_DISABLE_QAT_ECX
    if ((current_x25519_pmeth = EVP_PKEY_meth_find(EVP_PKEY_X25519)) == NULL) {
        QATerr(QAT_F_QAT_X25519_PMETH, ERR_R_INTERNAL_ERROR);
        return NULL;
    }
#endif
    if ((_hidden_x25519_pmeth =
         EVP_PKEY_meth_new(EVP_PKEY_X25519, 0)) == NULL) {
        QATerr(QAT_F_QAT_X25519_PMETH, QAT_R_ALLOC_QAT_X25519_METH_FAILURE);
        return NULL;
    }

#ifdef OPENSSL_DISABLE_QAT_ECX
    EVP_PKEY_meth_copy(_hidden_x25519_pmeth, EVP_PKEY_meth_find(EVP_PKEY_X25519));
#else
    /* Now save the current (non-offloaded) x25519 pmeth to sw_x25519_pmeth */
    /* for software fallback purposes */
    if ((sw_x25519_pmeth = EVP_PKEY_meth_find(EVP_PKEY_X25519)) == NULL) {
        QATerr(QAT_F_QAT_X25519_PMETH, ERR_R_INTERNAL_ERROR);
        return NULL;
    }
    EVP_PKEY_meth_set_keygen(_hidden_x25519_pmeth, NULL, qat_pkey_ecx_keygen);
    EVP_PKEY_meth_set_derive(_hidden_x25519_pmeth, NULL, qat_pkey_ecx_derive25519);
    EVP_PKEY_meth_set_ctrl(_hidden_x25519_pmeth, qat_pkey_ecx_ctrl, NULL);
#endif
    return _hidden_x25519_pmeth;
}

EVP_PKEY_METHOD *qat_x448_pmeth(void)
{
#ifdef OPENSSL_DISABLE_QAT_ECX
    const EVP_PKEY_METHOD *current_x448_pmeth = NULL;
#endif
    if (_hidden_x448_pmeth)
        return _hidden_x448_pmeth;
#ifdef OPENSSL_DISABLE_QAT_ECX
    if ((current_x448_pmeth = EVP_PKEY_meth_find(EVP_PKEY_X448)) == NULL) {
        QATerr(QAT_F_QAT_X448_PMETH, ERR_R_INTERNAL_ERROR);
        return NULL;
    }
#endif
    if ((_hidden_x448_pmeth =
         EVP_PKEY_meth_new(EVP_PKEY_X448, 0)) == NULL) {
        QATerr(QAT_F_QAT_X448_PMETH, QAT_R_ALLOC_QAT_X448_METH_FAILURE);
        return NULL;
    }

#ifdef OPENSSL_DISABLE_QAT_ECX
    EVP_PKEY_meth_copy(_hidden_x448_pmeth, current_x448_pmeth);
#else
    /* Now save the current (non-offloaded) x448 pmeth to sw_x448_pmeth */
    /* for software fallback purposes */
    if ((sw_x448_pmeth = EVP_PKEY_meth_find(EVP_PKEY_X448)) == NULL) {
        QATerr(QAT_F_QAT_X448_PMETH, ERR_R_INTERNAL_ERROR);
        return NULL;
    }
    EVP_PKEY_meth_set_keygen(_hidden_x448_pmeth, NULL, qat_pkey_ecx_keygen);
    EVP_PKEY_meth_set_derive(_hidden_x448_pmeth, NULL, qat_pkey_ecx_derive448);
    EVP_PKEY_meth_set_ctrl(_hidden_x448_pmeth, qat_pkey_ecx_ctrl, NULL);
#endif
    return _hidden_x448_pmeth;
}


#ifndef OPENSSL_DISABLE_QAT_ECX

static inline int reverse_bytes(unsigned char *tobuffer,
                                unsigned char *frombuffer, unsigned int size)
{
    int i = 0;
    int tobuffer_frombuffer_length_diff = 0;

    if (tobuffer == NULL || frombuffer == NULL ) {
        WARN("Either tobuffer or frombuffer is  NULL %d\n", size);
        return 0;
    }

    if (X448_KEYLEN == size)
        tobuffer_frombuffer_length_diff = X448_DATA_KEY_DIFF;
    for (i = 0; i < size; i++) {
        tobuffer[i] = frombuffer[size - 1 - i + tobuffer_frombuffer_length_diff];
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
static void qat_ecx_cb(void *pCallbackTag, CpaStatus status,
                       void *pOpData, CpaBoolean multiplyStatus,
                       CpaFlatBuffer *pXk, CpaFlatBuffer *pYk)
{
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_asym_requests_in_flight);
    }
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, multiplyStatus);
}

static int qat_pkey_ecx_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    CpaCyEcMontEdwdsPointMultiplyOpData *qat_ecx_op_data = NULL;

    int (*sw_fn_ptr)(EVP_PKEY_CTX *, EVP_PKEY *) = NULL;
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
    int type = 0;
    int is_ecx_448 = 0;
    const EVP_PKEY_METHOD **pmeth_from_ctx;
    void *void_ptr_ctx = (void *)ctx;

    DEBUG("Start\n");

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Get X25519/X448 NID from the pmeth */
    pmeth_from_ctx = (const EVP_PKEY_METHOD **)void_ptr_ctx;
    EVP_PKEY_meth_get0_info(&type, NULL, *pmeth_from_ctx);
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
            return 0;
    }

   if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode.\n");
        EVP_PKEY_meth_get_keygen((EVP_PKEY_METHOD *)
                                 (is_ecx_448 ? sw_x448_pmeth : sw_x25519_pmeth),
                                 NULL, &sw_fn_ptr);
        ret = (*sw_fn_ptr)(ctx, pkey);
        if (ret != 1) {
            WARN("s/w pkey_ecx_keygen fn failed.\n");
            QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
        }
        return ret;
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

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        WARN("Cannot allocate key.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pubkey = key->pubkey;
    privkey = key->privkey = OPENSSL_secure_malloc(qat_keylen);
    if (privkey == NULL) {
        WARN("Cannot allocate privkey.\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(key);
        key = NULL;
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

    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
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
                qat_clear_async_event_notification();
            }
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
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

    if (0 == reverse_bytes(pubkey, pXk->pData, keylen)) {
        WARN("Failed to reverse bytes for data received from QAT driver\n");
        QATerr(QAT_F_QAT_PKEY_ECX_KEYGEN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    EVP_PKEY_assign(pkey, (is_ecx_448 ? EVP_PKEY_X448 : EVP_PKEY_X25519), key);
    ret = 1;

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
        EVP_PKEY_meth_get_keygen((EVP_PKEY_METHOD *)
                                 (is_ecx_448 ? sw_x448_pmeth : sw_x25519_pmeth),
                                 NULL, &sw_fn_ptr);
        ret = (*sw_fn_ptr)(ctx, pkey);
    }
    return ret;
}

static int qat_validate_ecx_derive(EVP_PKEY_CTX *ctx,
                                   const unsigned char **privkey,
                                   const unsigned char **pubkey)
{
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

    return 1;
}

static int qat_pkey_ecx_derive25519(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
    CpaCyEcMontEdwdsPointMultiplyOpData *qat_ecx_op_data = NULL;

    int (*sw_fn_ptr)(EVP_PKEY_CTX *, unsigned char *, size_t *) = NULL;
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

    DEBUG("Start\n");

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL \n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode.\n");
        EVP_PKEY_meth_get_derive((EVP_PKEY_METHOD *)sw_x25519_pmeth, NULL, &sw_fn_ptr);
        ret = (*sw_fn_ptr)(ctx, key, keylen);
        if (ret != 1) {
            WARN("s/w pkey_ecx_derive25519 fn failed.\n");
            QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
        }
        return ret;
    }

    if (!qat_validate_ecx_derive(ctx, &privkey, &pubkey))
        return 0;

    if (key == NULL) {
        *keylen = dataLenInBytes;
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
    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
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
                qat_clear_async_event_notification();
            }
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
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

    if (0 == reverse_bytes(key, pXk->pData, dataLenInBytes)) {
        WARN("Failed to reverse bytes for data received from QAT driver\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE25519, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    *keylen = (size_t)dataLenInBytes;
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
        EVP_PKEY_meth_get_derive((EVP_PKEY_METHOD *)sw_x25519_pmeth, NULL, &sw_fn_ptr);
        ret = (*sw_fn_ptr)(ctx, key, keylen);
    }
    return ret;
}

static int qat_pkey_ecx_derive448(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
    CpaCyEcMontEdwdsPointMultiplyOpData *qat_ecx_op_data = NULL;

    int (*sw_fn_ptr)(EVP_PKEY_CTX *, unsigned char *, size_t *) = NULL;
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

    DEBUG("Start\n");

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL \n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode.\n");
        EVP_PKEY_meth_get_derive((EVP_PKEY_METHOD *)sw_x448_pmeth, NULL, &sw_fn_ptr);
        ret = (*sw_fn_ptr)(ctx, key, keylen);
        if (ret != 1) {
            WARN("s/w pkey_ecx_derive448 fn failed.\n");
            QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
        }
        return ret;
    }

    if (!qat_validate_ecx_derive(ctx, &privkey, &pubkey))
        return 0;

    if (key == NULL) {
        *keylen = X448_KEYLEN;
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
    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
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
                qat_clear_async_event_notification();
            }
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
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

    if (0 == reverse_bytes(key, pXk->pData, X448_KEYLEN)) {
        WARN("Failed to reverse bytes for data received from QAT driver\n");
        QATerr(QAT_F_QAT_PKEY_ECX_DERIVE448, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    *keylen = X448_KEYLEN;
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
        EVP_PKEY_meth_get_derive((EVP_PKEY_METHOD *)sw_x448_pmeth, NULL, &sw_fn_ptr);
        ret = (*sw_fn_ptr)(ctx, key, keylen);
    }
    return ret;
}

static int qat_pkey_ecx_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    DEBUG("Start\n");

    /* Only need to handle peer key for derivation */
    if (type == EVP_PKEY_CTRL_PEER_KEY)
        return 1;
    return -2;
}

#endif /* OPENSSL_DISABLE_QAT_ECX */
