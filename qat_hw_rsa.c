/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2025 Intel Corporation.
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
 * @file qat_hw_rsa.c
 *
 * This file contains the engine implementations for RSA operations
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define __USE_GNU

#include <pthread.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "qat_utils.h"
#include "e_qat.h"
#include "qat_hw_callback.h"
#include "qat_hw_polling.h"
#include "qat_events.h"
#ifdef ENABLE_QAT_FIPS
# include "qat_prov_cmvp.h"
#endif

#include "cpa.h"
#include "cpa_types.h"

#include "cpa_cy_rsa.h"
#include "cpa_cy_ln.h"
#include "qat_hw_rsa.h"
#include "qat_hw_asym_common.h"
#include "icp_sal_poll.h"
#include "qat_evp.h"
#include "qat_constant_time.h"

#ifdef ENABLE_QAT_SW_RSA
# include "qat_sw_rsa.h"
#endif

/* To specify the RSA op sizes supported by QAT engine */
#ifdef QAT_INSECURE_ALGO
# define RSA_QAT_RANGE_MIN 512
#else
# define RSA_QAT_RANGE_MIN 2048
#endif
#if defined(QAT20_OOT) || defined(QAT_HW_INTREE) || defined(QAT_HW_FBSD_OOT) || defined(QAT_HW_FBSD_INTREE)
# define RSA_QAT_RANGE_MAX 8192
#else
# define RSA_QAT_RANGE_MAX 4096
#endif

#define NO_PADDING 0
#define PADDING    1

#ifdef ENABLE_QAT_HW_RSA
/*
 * The RSA range check is performed so that if the op sizes are not in the
 * range supported by QAT engine then fall back to software
 */

static inline int qat_rsa_range_check(int plen)
{
    return ((plen >= RSA_QAT_RANGE_MIN) && (plen <= RSA_QAT_RANGE_MAX));
}

static RSA *copy_rsa_public_to_private_exponent(RSA *rsa)
{
    RSA *rsa_copy = NULL;
    const BIGNUM *lenstra_n = NULL;
    const BIGNUM *lenstra_e = NULL;
    RSA_get0_key((const RSA *)rsa, &lenstra_n, &lenstra_e, NULL);
    rsa_copy = RSA_new();
    if (rsa_copy == NULL)
        return NULL;
    RSA_set0_key(rsa_copy, (BIGNUM *)lenstra_n, NULL, (BIGNUM *)lenstra_e);
    return rsa_copy;
}

/******************************************************************************
* function:
*         qat_rsaCallbackFn(void *pCallbackTag, CpaStatus status,
*                           void *pOpData, CpaFlatBuffer * pOut)
*
* @param pCallbackTag   [IN]  - Opaque User Data for this specific call. Will
*                               be returned unchanged in the callback.
* @param status         [IN]  - Status result of the RSA operation.
* @param pOpData        [IN]  - Structure containing all the data needed to
*                               perform the RSA encryption operation.
* @param pOut           [IN]  - Pointer to buffer into which the result of
*                               the RSA encryption is written.
* description:
*   Callback function used by RSA operations to indicate completion.
*   Calls back to qat_crypto_callbackFn() as functionally it does the same.
*
******************************************************************************/
static void qat_rsaCallbackFn(void *pCallbackTag, CpaStatus status, void *pOpData,
                              CpaFlatBuffer * pOut)
{
# ifdef QAT_BORINGSSL
    CpaBufferList pBuffer;
    pBuffer.pBuffers = pOut;

    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          &pBuffer, CPA_TRUE);
# else
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_asym_requests_in_flight);
    }
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, CPA_TRUE);
# endif /* QAT_BORINGSSL */
}

static void
rsa_decrypt_op_buf_free(CpaCyRsaDecryptOpData * dec_op_data,
                        CpaFlatBuffer * out_buf, int qat_svm)
{
    CpaCyRsaPrivateKeyRep2 *key = NULL;
    DEBUG("- Started\n");

    if (dec_op_data) {
	QAT_CLEANSE_MEMFREE_NONZERO_FLATBUFF(dec_op_data->inputData, qat_svm);

        if (dec_op_data->pRecipientPrivateKey) {
            key = &dec_op_data->pRecipientPrivateKey->privateKeyRep2;
            QAT_CLEANSE_MEMFREE_NONZERO_FLATBUFF(key->prime1P, qat_svm);
            QAT_CLEANSE_MEMFREE_NONZERO_FLATBUFF(key->prime2Q, qat_svm);
            QAT_CLEANSE_MEMFREE_NONZERO_FLATBUFF(key->exponent1Dp, qat_svm);
            QAT_CLEANSE_MEMFREE_NONZERO_FLATBUFF(key->exponent2Dq, qat_svm);
            QAT_CLEANSE_MEMFREE_NONZERO_FLATBUFF(key->coefficientQInv, qat_svm);
            OPENSSL_free(dec_op_data->pRecipientPrivateKey);
        }
        OPENSSL_free(dec_op_data);
    }

    if (out_buf) {
        if (out_buf->pData && !qat_svm)
            qaeCryptoMemFreeNonZero(out_buf->pData);
        OPENSSL_free(out_buf);
    }
    DEBUG("- Finished\n");
}


static int qat_rsa_decrypt(CpaCyRsaDecryptOpData * dec_op_data, int rsa_len,
                           CpaFlatBuffer * output_buf, int * fallback, int inst_num, int qat_svm)
{
    /* Used for RSA Decrypt and RSA Sign */
    op_done_t op_done;
    CpaStatus sts = CPA_STATUS_FAIL;
    thread_local_variables_t *tlv = NULL;
# ifdef QAT_BORINGSSL
    op_done_t *op_done_bssl = NULL;
# endif
    int job_ret = 0;
    int iMsgRetry = getQatMsgRetryCount();
    useconds_t ulPollInterval = getQatPollInterval();
    int qatPerformOpRetries = 0;

    DEBUG("- Started\n");

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
        return 0;
    }

#if defined(QAT_BORINGSSL)
    qat_init_op_done(&op_done, qat_svm);
#else
    qat_init_op_done(&op_done);
#endif
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failed to setup async event notifications\n");
            QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            return 0;
        }
    }
# ifdef QAT_BORINGSSL
    if (op_done.job != NULL) {
        op_done_bssl = (op_done_t*)op_done.job->copy_op_done(&op_done,
            sizeof(op_done), (void (*)(void *, void *, int))rsa_decrypt_op_buf_free);
    }
# endif
    STOP_RDTSC(&qat_hw_rsa_dec_req_prepare, 1, "[QAT HW RSA: prepare]");
    /*
     * cpaCyRsaDecrypt() is the function called for RSA Sign in the API.
     * For that particular case the dec_op_data [IN] contains both the
     * private key value and the message (hash) value. The output_buf [OUT]
     * stores the signature as the output once the request is fully completed.
     * The sts return value contains 0 (CPA_STATUS_SUCCESS) if the request
     * was successfully submitted.
     */
    CRYPTO_QAT_LOG("- RSA\n");
    do {
        START_RDTSC(&qat_hw_rsa_dec_req_submit);
        if (sts == CPA_STATUS_RETRY &&
           (inst_num = get_instance(QAT_INSTANCE_ASYM, qat_svm))
            == QAT_INVALID_INSTANCE) {
            WARN("Failed to get an instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                *fallback = 1;
            } else {
                QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
            }
# ifdef QAT_BORINGSSL
            if (op_done.job != NULL)
                op_done.job->free_op_done(op_done_bssl);
# endif
            if (op_done.job != NULL)
                qat_clear_async_event_notification(op_done.job);
            qat_cleanup_op_done(&op_done);
            return 0;
        }
        DUMP_RSA_DECRYPT(qat_instance_handles[inst_num], &op_done,
                         dec_op_data, output_buf);
# ifndef QAT_BORINGSSL
        sts = cpaCyRsaDecrypt(qat_instance_handles[inst_num],
                              qat_rsaCallbackFn, &op_done,
                              dec_op_data, output_buf);
# else
        if (op_done.job != NULL) {
            sts = cpaCyRsaDecrypt(qat_instance_handles[inst_num],
                                  qat_rsaCallbackFn,
                                  op_done_bssl, dec_op_data,
                                  output_buf);
        } /* No need for wake up job or pause job here */
        else {
            sts = cpaCyRsaDecrypt(qat_instance_handles[inst_num],
                                  qat_rsaCallbackFn, &op_done,
                                  dec_op_data, output_buf);
        }
# endif
        STOP_RDTSC(&qat_hw_rsa_dec_req_submit, 1, "[QAT HW RSA: submit]");
        if (sts == CPA_STATUS_RETRY) {
            DEBUG("cpaCyRsaDecrypt Retry \n");
            if (qat_rsa_coexist) {
                START_RDTSC(&qat_hw_rsa_dec_req_retry);
                ++num_rsa_priv_retry;
                qat_sw_rsa_priv_req += QAT_SW_SWITCH_MB8;
                *fallback = 1;
                qat_cleanup_op_done(&op_done);
                STOP_RDTSC(&qat_hw_rsa_dec_req_retry, 1, "[QAT HW RSA: retry]");
                return 0;
            } else {
                if (op_done.job == NULL) {
                    usleep(ulPollInterval + qatPerformOpRetries);
                    qatPerformOpRetries++;
                    if (iMsgRetry != QAT_INFINITE_MAX_NUM_RETRIES) {
                        if (qatPerformOpRetries >= iMsgRetry) {
                            WARN("No. of retries exceeded max retry : %d\n", iMsgRetry);
                            break;
                        }
                    }
                } else {
# ifndef QAT_BORINGSSL
                    if ((qat_wake_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0) ||
                        (qat_pause_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0)) {
                        WARN("qat_wake_job or qat_pause_job failed\n");
                        break;
                    }
# endif
                }
            }
        }
    }
    while (sts == CPA_STATUS_RETRY);

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", sts);
        if (qat_get_sw_fallback_enabled() && (sts == CPA_STATUS_RESTARTING || sts == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            *fallback = 1;
        } else if (sts == CPA_STATUS_UNSUPPORTED) {
            WARN("Algorithm Unsupported in QAT_HW! Using OpenSSL SW\n");
            *fallback = 1;
        } else {
            QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
        }
        if (op_done.job != NULL) {
# ifdef QAT_BORINGSSL
            op_done.job->free_op_done(op_done_bssl);
# endif
            qat_clear_async_event_notification(op_done.job);
        }
        qat_cleanup_op_done(&op_done);

        return 0;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n",
                      &hw_polling_thread_sem);
                QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
# ifdef QAT_BORINGSSL
                if (op_done.job != NULL)
                    op_done.job->free_op_done(op_done_bssl);
# endif
                return 0;
            }
        }
    }

# ifdef QAT_BORINGSSL
    if (op_done.job != NULL) {
        qat_cleanup_op_done(&op_done);
        return -1; /* Async mode for BoringSSL */
    }
# endif
    if (qat_get_sw_fallback_enabled()) {
        CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n",
                       inst_num,
                       qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                       __func__);
    }

    if (enable_heuristic_polling) {
        QAT_ATOMIC_INC(num_asym_requests_in_flight);
    }

    if (qat_rsa_coexist)
        ++num_rsa_hw_priv_reqs;

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
        }
        else {
# ifdef QAT_BORINGSSL
            /* Support inline polling in current scenario */
            if(getEnableInlinePolling()) {
                sts = icp_sal_CyPollInstance(qat_instance_handles[inst_num], 0);
		if (sts == CPA_STATUS_FAIL) {
                    WARN("icp_sal_CyPollInstance failed - status %d\n", sts);
                    QATerr(QAT_F_QAT_RSA_DECRYPT, QAT_R_POLL_INSTANCE_FAILURE);
                    qat_cleanup_op_done(&op_done);
                    return 0;
                }
                RSA_INLINE_POLLING_USLEEP();
            } else {
                sched_yield();
            }
# else
            sched_yield();
# endif /* QAT_BORINGSSL */
        }
    }
    while (!op_done.flag ||
           QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DUMP_RSA_DECRYPT_OUTPUT(output_buf);
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
            QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
        }
        qat_cleanup_op_done(&op_done);
        return 0;
    }

    qat_cleanup_op_done(&op_done);

    DEBUG("- Finished\n");
    return 1;
}

static int
build_decrypt_op_buf(int flen, const unsigned char *from, unsigned char *to,
                     RSA *rsa, int padding,
                     CpaCyRsaDecryptOpData ** dec_op_data,
                     CpaFlatBuffer ** output_buffer, int alloc_pad,
                     int inst_num, int qat_svm)
{
    int rsa_len = 0;
    int padding_result = 0;
    CpaCyRsaPrivateKey *cpa_prv_key = NULL;
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *dmp1 = NULL;
    const BIGNUM *dmq1 = NULL;
    const BIGNUM *iqmp = NULL;

    DEBUG("- Started\n");

    RSA_get0_factors((const RSA*)rsa, &p, &q);
    RSA_get0_crt_params((const RSA*)rsa, &dmp1, &dmq1, &iqmp);

    if (p == NULL || q == NULL || dmp1 == NULL || dmq1 == NULL || iqmp == NULL) {
        WARN("Either p %p, q %p, dmp1 %p, dmq1 %p, iqmp %p are NULL\n",
              p, q, dmp1, dmq1, iqmp);
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_P_Q_DMP_DMQ_IQMP_NULL);
        return 0;
    }

    DEBUG("flen = %d, padding = %d \n", flen, padding);
    /* output signature should have same length as the RSA size */
    rsa_len = RSA_size(rsa);

    /* Padding check */
    if ((padding != RSA_NO_PADDING) &&
        (padding != RSA_PKCS1_PADDING) &&
        (padding != RSA_PKCS1_OAEP_PADDING) &&
# ifndef QAT_OPENSSL_3
        (padding != RSA_SSLV23_PADDING) &&
# endif
        (padding != RSA_X931_PADDING)) {
        WARN("Unknown Padding %d\n", padding);
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_PADDING_UNKNOWN);
        return 0;
    }

    cpa_prv_key =
        (CpaCyRsaPrivateKey *) OPENSSL_zalloc(sizeof(CpaCyRsaPrivateKey));
    if (NULL == cpa_prv_key) {
        WARN("Failed to allocate cpa_prv_key\n");
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_PRIV_KEY_MALLOC_FAILURE);
        return 0;
    }

    /* output and input data MUST allocate memory for sign process */
    /* memory allocation for DecOpdata[IN] */
    *dec_op_data = OPENSSL_zalloc(sizeof(CpaCyRsaDecryptOpData));
    if (NULL == *dec_op_data) {
        WARN("Failed to allocate dec_op_data\n");
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_DEC_OP_DATA_MALLOC_FAILURE);
        OPENSSL_free(cpa_prv_key);
        return 0;
    }

    /* Setup the DecOpData structure */
    (*dec_op_data)->pRecipientPrivateKey = cpa_prv_key;

    cpa_prv_key->version = CPA_CY_RSA_VERSION_TWO_PRIME;

    /* Setup the private key rep type 2 structure */
    cpa_prv_key->privateKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2;
    if (qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.prime1P, p, qat_svm) != 1 ||
        qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.prime2Q, q, qat_svm) != 1 ||
        qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.exponent1Dp, dmp1, qat_svm) != 1 ||
        qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.exponent2Dq, dmq1, qat_svm) != 1 ||
        qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.coefficientQInv, iqmp, qat_svm) != 1) {
        WARN("Failed to convert privateKeyRep2 elements to flatbuffer\n");
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_P_Q_DMP_DMQ_CONVERT_TO_FB_FAILURE);
        return 0;
    }

    (*dec_op_data)->inputData.pData = (Cpa8U *) qat_mem_alloc(
                    ((padding != RSA_NO_PADDING) && alloc_pad) ? rsa_len : flen, qat_svm,
                    __FILE__,__LINE__);

    if (NULL == (*dec_op_data)->inputData.pData) {
        WARN("Failed to allocate (*dec_op_data)->inputData.pData\n");
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_INPUT_DATA_MALLOC_FAILURE);
        return 0;
    }

    (*dec_op_data)->inputData.dataLenInBytes =
        (padding != RSA_NO_PADDING) && alloc_pad ? rsa_len : flen;

    if (alloc_pad) {
        switch (padding) {
        case RSA_PKCS1_PADDING:
            padding_result =
                RSA_padding_add_PKCS1_type_1((*dec_op_data)->inputData.pData,
                                             rsa_len, from, flen);
            break;
        case RSA_X931_PADDING:
            padding_result =
                RSA_padding_add_X931((*dec_op_data)->inputData.pData,
                                     rsa_len, from, flen);
            break;
        case RSA_NO_PADDING:
            padding_result =
                RSA_padding_add_none((*dec_op_data)->inputData.pData,
                                     rsa_len, from, flen);
            break;
        default:
            QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, RSA_R_UNKNOWN_PADDING_TYPE);
            break;
        }
    } else {
        padding_result =
            RSA_padding_add_none((*dec_op_data)->inputData.pData,
                                 rsa_len, from, flen);
    }
    if (padding_result <= 0) {
        WARN("Failed to add padding\n");
        /* Error is raised within the padding function. */
        return 0;
    }

    *output_buffer = OPENSSL_zalloc(sizeof(CpaFlatBuffer));
    if (NULL == *output_buffer) {
        WARN("Failed to allocate output_buffer\n");
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_OUTPUT_BUF_MALLOC_FAILURE);
        return 0;
    }

    /*
     * Memory allocation for DecOpdata[IN] the size of outputBuffer
     * should big enough to contain RSA_size
     */
    if (qat_svm)
        (*output_buffer)->pData = (Cpa8U *) to;
    else
        (*output_buffer)->pData =
              (Cpa8U *) qaeCryptoMemAlloc(rsa_len, __FILE__, __LINE__);

    if (NULL == (*output_buffer)->pData) {
        WARN("Failed to allocate output_buffer->pData\n");
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_RSA_OUTPUT_BUF_PDATA_MALLOC_FAILURE);
        return 0;
    }
    (*output_buffer)->dataLenInBytes = rsa_len;

    DEBUG("- Finished\n");
    return 1;
}

static void
rsa_encrypt_op_buf_free(CpaCyRsaEncryptOpData * enc_op_data,
                        CpaFlatBuffer * out_buf, int qat_svm)
{
    DEBUG("- Started\n");

    if (enc_op_data) {
        if (enc_op_data->pPublicKey) {
            QAT_CLEANSE_MEMFREE_NONZERO_FLATBUFF(enc_op_data->pPublicKey->modulusN, qat_svm);
            QAT_CLEANSE_MEMFREE_NONZERO_FLATBUFF(enc_op_data->pPublicKey->publicExponentE, qat_svm);
            OPENSSL_free(enc_op_data->pPublicKey);
        }
        if (enc_op_data->inputData.pData) {
            OPENSSL_cleanse(enc_op_data->inputData.pData, enc_op_data->inputData.dataLenInBytes);
            QAT_MEM_FREE_NONZERO_BUFF(enc_op_data->inputData.pData,qat_svm);
        }
        OPENSSL_free(enc_op_data);
    }

    if (out_buf) {
        if (out_buf->pData && !qat_svm) {
            qaeCryptoMemFreeNonZero(out_buf->pData);
        }
        OPENSSL_free(out_buf);
    }
    DEBUG("- Finished\n");
}


static int qat_rsa_encrypt(CpaCyRsaEncryptOpData * enc_op_data,
                           CpaFlatBuffer * output_buf, int * fallback, int inst_num, int qat_svm)
{
    /* Used for RSA Encrypt and RSA Verify */
    op_done_t op_done;
    CpaStatus sts = CPA_STATUS_FAIL;
    int qatPerformOpRetries = 0;
    int job_ret = 0;
    thread_local_variables_t *tlv = NULL;

    int iMsgRetry = getQatMsgRetryCount();
    useconds_t ulPollInterval = getQatPollInterval();

    DEBUG("- Started\n");

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
        return 0;
    }

#if defined(QAT_BORINGSSL) && defined(ENABLE_QAT_HW_RSA)
    qat_init_op_done(&op_done, qat_svm);
#else
    qat_init_op_done(&op_done);
#endif
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            return 0;
        }
    }
    /*
     * cpaCyRsaEncrypt() is the function called for RSA verify in the API.
     * For that particular case the enc_op_data [IN] contains both the
     * public key value and the signature value. The output_buf [OUT]
     * stores the message as the output once the request is fully completed.
     * The sts return value contains 0 (CPA_STATUS_SUCCESS) if the request
     * was successfully submitted.
     */
    CRYPTO_QAT_LOG("RSA - %s\n", __func__);
    do {
        if (sts == CPA_STATUS_RETRY &&
           (inst_num = get_instance(QAT_INSTANCE_ASYM, qat_svm))
             == QAT_INVALID_INSTANCE) {
            WARN("Failed to get an instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                *fallback = 1;
            } else {
                QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL) {
                qat_clear_async_event_notification(op_done.job);
            }
            qat_cleanup_op_done(&op_done);
            return 0;
        }

        DUMP_RSA_ENCRYPT(qat_instance_handles[inst_num], &op_done, enc_op_data, output_buf);
        sts = cpaCyRsaEncrypt(qat_instance_handles[inst_num], qat_rsaCallbackFn, &op_done,
                              enc_op_data, output_buf);
        if (sts == CPA_STATUS_RETRY) {
            DEBUG("cpaCyRsaDecrypt Retry \n");
            if (op_done.job == NULL) {
                usleep(ulPollInterval + qatPerformOpRetries);
                qatPerformOpRetries++;
                if (iMsgRetry != QAT_INFINITE_MAX_NUM_RETRIES) {
                    if (qatPerformOpRetries >= iMsgRetry) {
                        WARN("No. of retries exceeded max retry : %d\n", iMsgRetry);
                        break;
                    }
                }
            } else {
                if (qat_rsa_coexist) {
                    ++num_rsa_pub_retry;
                    qat_sw_rsa_pub_req += QAT_SW_SWITCH_MB8;
                    *fallback = 1;
                    qat_cleanup_op_done(&op_done);
                    return 0;
                } else {
                    if ((qat_wake_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0) ||
                        (qat_pause_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0)) {
                        WARN("qat_wake_job or qat_pause_job failed\n");
                        break;
                    }
                }
            }
        }
    }
    while (sts == CPA_STATUS_RETRY);

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", sts);
        if (qat_get_sw_fallback_enabled() && (sts == CPA_STATUS_RESTARTING || sts == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            *fallback = 1;
        } else if (sts == CPA_STATUS_UNSUPPORTED) {
            WARN("Algorithm Unsupported in QAT_HW! Using OpenSSL SW\n");
            *fallback = 1;
        } else {
            QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
        }
        if (op_done.job != NULL) {
            qat_clear_async_event_notification(op_done.job);
        }
        qat_cleanup_op_done(&op_done);
        return 0;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n",
                      &hw_polling_thread_sem);
                QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                return 0;
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

    if (qat_rsa_coexist)
        ++num_rsa_hw_pub_reqs;

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
            if(getEnableInlinePolling()) {
                sts = icp_sal_CyPollInstance(qat_instance_handles[inst_num], 0);
	        if (sts == CPA_STATUS_FAIL) {
                    WARN("icp_sal_CyPollInstance failed - status %d\n", sts);
		    op_done.flag = 1;
                }
	    } else
                sched_yield();
        }
    } while (!op_done.flag || (sts == CPA_STATUS_RETRY) ||
             QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DUMP_RSA_ENCRYPT_OUTPUT(output_buf);
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
            QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
        }
        qat_cleanup_op_done(&op_done);
        return 0;
    }

    qat_cleanup_op_done(&op_done);

    return 1;
}

static int
build_encrypt_op_buf(int flen, const unsigned char *from, unsigned char *to,
                     RSA *rsa, int padding,
                     CpaCyRsaEncryptOpData ** enc_op_data,
                     CpaFlatBuffer ** output_buffer, int alloc_pad, int qat_svm)
{
    CpaCyRsaPublicKey *cpa_pub_key = NULL;
    int rsa_len = 0;
    int padding_result = 0;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;

    DEBUG("- Started\n");

    RSA_get0_key((const RSA*)rsa, &n, &e, &d);

    /* Note: not checking 'd' as it is not used */
    if (n == NULL || e == NULL) {
        WARN("RSA key values n = %p or e = %p are NULL\n", n, e);
        QATerr(QAT_F_BUILD_ENCRYPT_OP_BUF, QAT_R_N_E_NULL);
        return 0;
    }

    DEBUG("flen =%d, padding = %d \n", flen, padding);
    rsa_len = RSA_size(rsa);

    if ((padding != RSA_NO_PADDING) &&
        (padding != RSA_PKCS1_PADDING) &&
        (padding != RSA_PKCS1_OAEP_PADDING) &&
# ifndef QAT_OPENSSL_3
        (padding != RSA_SSLV23_PADDING) &&
# endif
        (padding != RSA_X931_PADDING)) {
        WARN("Unknown Padding %d\n", padding);
        QATerr(QAT_F_BUILD_ENCRYPT_OP_BUF, QAT_R_UNKNOWN_PADDING);
        return 0;
    }

    cpa_pub_key = OPENSSL_zalloc(sizeof(CpaCyRsaPublicKey));
    if (NULL == cpa_pub_key) {
        WARN("Public Key zalloc failed\n");
        QATerr(QAT_F_BUILD_ENCRYPT_OP_BUF, QAT_R_PUB_KEY_MALLOC_FAILURE);
        return 0;
    }

    /* Output and input data MUST allocate memory for RSA verify process */
    /* Memory allocation for EncOpData[IN] */
    *enc_op_data = OPENSSL_zalloc(sizeof(CpaCyRsaEncryptOpData));
    if (NULL == *enc_op_data) {
        WARN("Failed to allocate enc_op_data\n");
        QATerr(QAT_F_BUILD_ENCRYPT_OP_BUF, QAT_R_ENC_OP_DATA_MALLOC_FAILURE);
        OPENSSL_free(cpa_pub_key);
        return 0;
    }

    /* Setup the Encrypt operation Data structure */
    (*enc_op_data)->pPublicKey = cpa_pub_key;

    /* Passing Public key from big number format to big endian order binary */
    if (qat_BN_to_FB(&cpa_pub_key->modulusN, n, qat_svm) != 1 ||
        qat_BN_to_FB(&cpa_pub_key->publicExponentE, e, qat_svm) != 1) {
        WARN("Failed to convert cpa_pub_key elements to flatbuffer\n");
        QATerr(QAT_F_BUILD_ENCRYPT_OP_BUF, QAT_R_N_E_CONVERT_TO_FB_FAILURE);
        return 0;
    }

    (*enc_op_data)->inputData.pData = (Cpa8U *) qat_mem_alloc(
		    ((padding != RSA_NO_PADDING) && alloc_pad) ? rsa_len : flen, qat_svm,
		    __FILE__,__LINE__);

    if (NULL == (*enc_op_data)->inputData.pData) {
        WARN("Failed to allocate (*enc_op_data)->inputData.pData\n");
        QATerr(QAT_F_BUILD_ENCRYPT_OP_BUF, QAT_R_INPUT_DATA_MALLOC_FAILURE);
        return 0;
    }

    (*enc_op_data)->inputData.dataLenInBytes =
       ((padding != RSA_NO_PADDING) && alloc_pad) ? rsa_len : flen;

    if (alloc_pad) {
        switch (padding) {
        case RSA_PKCS1_PADDING:
            padding_result =
                RSA_padding_add_PKCS1_type_2((*enc_op_data)->inputData.pData,
                                             rsa_len, from, flen);
            break;
        case RSA_PKCS1_OAEP_PADDING:
            padding_result =
                RSA_padding_add_PKCS1_OAEP((*enc_op_data)->inputData.pData,
                                           rsa_len, from, flen, NULL, 0);
            break;
# ifndef QAT_OPENSSL_3
        case RSA_SSLV23_PADDING:
            padding_result =
                RSA_padding_add_SSLv23((*enc_op_data)->inputData.pData,
                                       rsa_len, from, flen);
            break;
# endif
        case RSA_NO_PADDING:
            padding_result =
                RSA_padding_add_none((*enc_op_data)->inputData.pData,
                                     rsa_len, from, flen);
            break;
        default:
            QATerr(QAT_F_BUILD_ENCRYPT_OP_BUF, RSA_R_UNKNOWN_PADDING_TYPE);
            break;
        }
    } else {
        padding_result =
            RSA_padding_add_none((*enc_op_data)->inputData.pData,
                                 rsa_len, from, flen);
    }

    if (padding_result <= 0) {
        WARN("Failed to add padding\n");
        /* Error is raised within the padding function. */
        return 0;
    }

    /*
     * Memory allocation for outputBuffer[OUT] OutputBuffer size initialize
     * as the size of rsa size
     */
    (*output_buffer) =
        (CpaFlatBuffer *) OPENSSL_zalloc(sizeof(CpaFlatBuffer));
    if (NULL == (*output_buffer)) {
        WARN("Failed to allocate output_buffer\n");
        QATerr(QAT_F_BUILD_ENCRYPT_OP_BUF, QAT_R_OUTPUT_BUF_MALLOC_FAILURE);
        return 0;
    }

    /*
     * outputBuffer size should large enough to hold the Hash value but
     * smaller than (RSA_size(rsa)-11)
     */
    (*output_buffer)->dataLenInBytes = rsa_len;
    if (!qat_svm)
        (*output_buffer)->pData = qaeCryptoMemAlloc(rsa_len, __FILE__, __LINE__);
    else
        (*output_buffer)->pData = (Cpa8U *) to;

     if (NULL == (*output_buffer)->pData) {
        WARN("Failed to allocate (*output_buffer)->pData\n");
        QATerr(QAT_F_BUILD_ENCRYPT_OP_BUF, QAT_R_OUTPUT_BUF_PDATA_MALLOC_FAILURE);
        return 0;;
    }

    DEBUG("- Finished\n");
    return 1;
}

/******************************************************************************
* function:
*         qat_rsa_priv_enc (int flen,
*                           const unsigned char *from,
*                           unsigned char *to,
*                           RSA *rsa,
*                           int padding)
*
* @param flen    [IN]  - length in bytes of input file
* @param from    [IN]  - pointer to the input file
* @param to      [OUT] - pointer to output signature
* @param rsa     [IN]  - pointer to private key structure
* @param padding [IN]  - Padding scheme
*
* description: Perform an RSA private encrypt (RSA Sign)
*              We use the decrypt implementation to achieve this.
******************************************************************************/
int qat_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to,
                     RSA *rsa, int padding)
{
    int rsa_len = 0;
    CpaCyRsaDecryptOpData *dec_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;
    int sts = 1, fallback = 0, dec_ret = 0;
    int inst_num = QAT_INVALID_INSTANCE;
    int qat_svm = QAT_INSTANCE_ANY;
# ifndef DISABLE_QAT_HW_LENSTRA_PROTECTION
    unsigned char *ver_msg = NULL;
    const BIGNUM *d = NULL;
    RSA *lenstra_rsa = NULL;
    int lenstra_ret = -1;
    int memcmp_ret = -1;
# endif

#ifdef ENABLE_QAT_HW_KPT
    if (rsa && qat_check_rsa_wpk(rsa) > 0) {
        if (is_kpt_mode()) {
            DEBUG("Run the qat_rsa_priv_enc in KPT mode.\n");
            return qat_hw_kpt_rsa_priv_enc(flen, from, to, rsa, padding);
        }
        else {
            WARN("Use the WPK in Non-KPT mode, return failed.\n");
            return 0;
        }
    }
#endif

    DEBUG("QAT HW RSA Started.\n");
#ifdef ENABLE_QAT_FIPS
    qat_fips_get_approved_status();
#endif

    if ((qat_sw_rsa_priv_req > 0) || qat_get_qat_offload_disabled()) {
        fallback = 1;
        goto exit;
    }

    START_RDTSC(&qat_hw_rsa_dec_req_prepare);

    /* Parameter Checking */
    /*
     * The input message length should be less than or equal to RSA size and also have
     * minimum space of at least 11 bytes of padding if using PKCS1 padding.
     */
    if (unlikely(rsa == NULL || from == NULL || to == NULL || flen <= 0)) {
        WARN("RSA key, input or output is NULL or invalid length, \
              flen = %d\n", flen);
        QATerr(QAT_F_QAT_RSA_PRIV_ENC, QAT_R_RSA_FROM_TO_NULL);
        return 0;
    }

    rsa_len = RSA_size(rsa);

    /*
    * If the op sizes are not in the range supported by QAT engine then fall
    * back to software
    */

    if (!qat_rsa_range_check(RSA_bits((const RSA*)rsa)))
        return RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())
                                     (flen, from, to, rsa, padding);

    if ((inst_num = get_instance(QAT_INSTANCE_ASYM, QAT_INSTANCE_ANY))
            == QAT_INVALID_INSTANCE) {
        WARN("Failed to get an instance\n");
        if (qat_get_sw_fallback_enabled()) {
            WARN("Failed to get an instance - fallback to SW - %s\n", __func__);
            sts = 0;
            goto exit;
        } else {
            QATerr(QAT_F_QAT_RSA_PRIV_ENC, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    qat_svm = !qat_instance_details[inst_num].qat_instance_info.requiresPhysicallyContiguousMemory;

    if (1 != build_decrypt_op_buf(flen, from, to, rsa, padding,
                                  &dec_op_data, &output_buffer, PADDING,
                                  inst_num, qat_svm)) {
        WARN("Failure in build_decrypt_op_buf\n");
        /* Errors are already raised within build_decrypt_op_buf. */
        sts = 0;
        goto exit;
    }

    dec_ret = qat_rsa_decrypt(dec_op_data, rsa_len, output_buffer, &fallback, inst_num, qat_svm);
    if (1 != dec_ret) {
# ifdef QAT_BORINGSSL
        if (-1 == dec_ret) {
            DEBUG("Async job pause, waiting for wake up.\n");

            /* For the Async mode when BoringSSL enabled, rsa_decrypt_op_buf_free is
            * called at the end of callback function. */
            return 1;
        }
        else
# endif /* QAT_BORINGSSL */
            WARN("Failure in qat_rsa_decrypt  fallback = %d\n", fallback);

        /* Errors are already raised within qat_rsa_decrypt. */
        sts = 0;
        goto exit;
    }

    if (unlikely(output_buffer->pData == NULL)) {
        WARN("output_buffer->pData is NULL\n");
        QATerr(QAT_F_QAT_RSA_PRIV_ENC, ERR_R_INTERNAL_ERROR);
        sts = 0;
        goto exit;
    }

    if (!qat_svm)
        memcpy(to, output_buffer->pData, rsa_len);

    rsa_decrypt_op_buf_free(dec_op_data, output_buffer, qat_svm);
    dec_op_data = NULL;
    output_buffer = NULL;

# ifndef DISABLE_QAT_HW_LENSTRA_PROTECTION
    lenstra_rsa = copy_rsa_public_to_private_exponent(rsa);
    if (lenstra_rsa != NULL)
        d = RSA_get0_d((const RSA*)lenstra_rsa);

    if (d != NULL) {
        ver_msg = OPENSSL_zalloc(flen);
        if (ver_msg == NULL) {
            WARN("ver_msg zalloc failed.\n");
            QATerr(QAT_F_QAT_RSA_PRIV_ENC, ERR_R_MALLOC_FAILURE);
            sts = 0;
            goto exit;
        }
#  ifdef ENABLE_QAT_HW_LENSTRA_VERIFY_HW
        lenstra_ret = qat_rsa_pub_dec(rsa_len, (const unsigned char *)to,
                                      ver_msg, rsa, padding);
#  else
        lenstra_ret = RSA_meth_get_priv_dec(RSA_PKCS1_OpenSSL())
                                           (rsa_len,
                                           (const unsigned char *)to,
                                           ver_msg, lenstra_rsa, padding);
#  endif
        memcmp_ret = CRYPTO_memcmp(from, ver_msg, flen);
        if ((qat_constant_time_le_int(lenstra_ret, 0)) | (memcmp_ret != 0)) {
            WARN("QAT RSA Verify failed - redoing sign operation in s/w\n");
            OPENSSL_free(ver_msg);
            return RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())
                                         (flen, from, to, rsa, padding);
        }
        OPENSSL_free(ver_msg);
    }
    if (lenstra_rsa != NULL)
        RSA_free(lenstra_rsa);
# endif

    DEBUG("- Finished\n");
    return rsa_len;

exit:
    START_RDTSC(&qat_hw_rsa_dec_req_cleanup);
    /* Free all the memory allocated in this function */
    rsa_decrypt_op_buf_free(dec_op_data, output_buffer, qat_svm);
    STOP_RDTSC(&qat_hw_rsa_dec_req_cleanup, 1, "[QAT HW RSA: cleanup]");

    if (fallback) {
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
#ifdef ENABLE_QAT_SW_RSA
        if (qat_rsa_coexist) {
            DEBUG("- Switch to QAT SW mode.\n");
            if (qat_sw_rsa_priv_req > 0)
                --qat_sw_rsa_priv_req;
            return multibuff_rsa_priv_enc(flen, from, to, rsa, padding);
        }
#endif
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        return RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())
                                    (flen, from, to, rsa, padding);
    }

    if (!sts)
        OPENSSL_cleanse(to, rsa_len);

    /* Return an error */
    return 0;
}

/******************************************************************************
* function:
*         qat_rsa_priv_dec(int flen,
*                          const unsigned char *from,
*                          unsigned char *to,
*                          RSA * rsa,
*                          int padding)
*
* @param flen    [IN]  - length in bytes of input
* @param from    [IN]  - pointer to the input
* @param to      [OUT] - pointer to output
* @param rsa     [IN]  - pointer to the private key structure
* @param padding [IN]  - Padding scheme
*
* description:
* description: Perform an RSA private decrypt. (RSA Decrypt)
******************************************************************************/
int qat_rsa_priv_dec(int flen, const unsigned char *from,
                     unsigned char *to, RSA *rsa, int padding)
{
    int rsa_len = 0;
    int output_len = -1;
    int sts = 1, fallback = 0, dec_ret = 0;
    CpaCyRsaDecryptOpData *dec_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;
    int inst_num = QAT_INVALID_INSTANCE;
    int qat_svm = QAT_INSTANCE_ANY;
# ifndef DISABLE_QAT_HW_LENSTRA_PROTECTION
    unsigned char *ver_msg = NULL;
    const BIGNUM *d = NULL;
    RSA *lenstra_rsa = NULL;
    int lenstra_ret = -1;
    int memcmp_ret = -1;
# endif
    unsigned char temp_buf[RSA_QAT_RANGE_MAX];
    unsigned char *select_ptr = NULL;
    int rsa_priv_dec_sts = -1;

#ifdef ENABLE_QAT_HW_KPT
    if (rsa && qat_check_rsa_wpk(rsa) > 0) {
        if (is_kpt_mode()) {
            DEBUG("Run the qat_rsa_priv_dec in KPT mode.\n");
            return qat_hw_kpt_rsa_priv_dec(flen, from, to, rsa, padding);
        }
        else {
            WARN("Use the WPK in Non-KPT mode, return failed.\n");
            return 0;
        }
    }
#endif

    DEBUG("QAT HW RSA Started.\n");

    if ((qat_sw_rsa_priv_req > 0) || qat_get_qat_offload_disabled()) {
        fallback = 1;
        goto exit;
    }

    START_RDTSC(&qat_hw_rsa_dec_req_prepare);
    /* parameter checks */
    if (unlikely(rsa == NULL || from == NULL || to == NULL ||
                 (flen != (rsa_len = RSA_size(rsa))))) {
        WARN("RSA key, input or output is NULL or invalid length, \
              flen = %d, rsa_len = %d\n", flen, rsa_len);
        QATerr(QAT_F_QAT_RSA_PRIV_DEC, QAT_R_RSA_FROM_TO_NULL);
        return 0;
    }

    /*
    * If the op sizes are not in the range supported by QAT engine then fall
    * back to software
    */

    if (!qat_rsa_range_check(RSA_bits((const RSA*)rsa)))
        return RSA_meth_get_priv_dec(RSA_PKCS1_OpenSSL())
                                     (flen, from, to, rsa, padding);

    if ((inst_num = get_instance(QAT_INSTANCE_ASYM, QAT_INSTANCE_ANY))
            == QAT_INVALID_INSTANCE) {
        WARN("Failed to get an instance\n");
        if (qat_get_sw_fallback_enabled()) {
            WARN("Failed to get an instance - fallback to SW - %s\n", __func__);
            sts = 0;
            goto exit;
        } else {
            QATerr(QAT_F_QAT_RSA_PRIV_DEC, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    qat_svm = !qat_instance_details[inst_num].qat_instance_info.requiresPhysicallyContiguousMemory;

    if (1 != build_decrypt_op_buf(flen, from, to, rsa, padding,
                                  &dec_op_data, &output_buffer, NO_PADDING,
                                  inst_num, qat_svm)) {
        WARN("Failure in build_decrypt_op_buf\n");
        /* Errors are already raised within build_decrypt_op_buf. */
        sts = 0;
        goto exit;
    }

    dec_ret = qat_rsa_decrypt(dec_op_data, rsa_len, output_buffer, &fallback, inst_num, qat_svm);
    if (1 != dec_ret) {
# ifdef QAT_BORINGSSL
        if (-1 == dec_ret) {
            DEBUG("Async job pause, waiting for wake up.\n");

            /* For the Async mode when BoringSSL enabled, rsa_decrypt_op_buf_free is
            * called at the end of callback function.
            * For private key decryption in BoringSSL, not add padding before return
            * since RSA_NO_PADDING is passed to RSA_decrypt in ssl_private_key_decrypt.
            */
            return 1;
        }
        else
# endif /* QAT_BORINGSSL */
            WARN("Failure in qat_rsa_decrypt  fallback = %d\n", fallback);

        if (fallback == 0) {
            /* Most but not all error cases are also raised within qat_rsa_decrypt. */
            QATerr(QAT_F_QAT_RSA_PRIV_DEC, ERR_R_INTERNAL_ERROR);
        }
        sts = 0;
        goto exit;
    }

# ifndef DISABLE_QAT_HW_LENSTRA_PROTECTION
    lenstra_rsa = copy_rsa_public_to_private_exponent(rsa);
    if (lenstra_rsa != NULL)
        d = RSA_get0_d((const RSA*)lenstra_rsa);

    if (d != NULL) {
        ver_msg = OPENSSL_zalloc(flen);
        if (ver_msg == NULL) {
            WARN("ver_msg zalloc failed.\n");
            QATerr(QAT_F_QAT_RSA_PRIV_DEC, ERR_R_MALLOC_FAILURE);
            sts = 0;
            goto exit;
        }
#  ifdef ENABLE_QAT_HW_LENSTRA_VERIFY_HW
        lenstra_ret = qat_rsa_pub_enc(rsa_len,
                        (const unsigned char *)output_buffer->pData,
                        ver_msg, rsa, RSA_NO_PADDING);
#  else
        lenstra_ret = RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())
                             (rsa_len,
                             (const unsigned char *)output_buffer->pData,
                             ver_msg, lenstra_rsa, RSA_NO_PADDING);
#  endif
        memcmp_ret = CRYPTO_memcmp(from, ver_msg, flen);
        if ((qat_constant_time_le_int(lenstra_ret, 0)) | (memcmp_ret != 0)) {
            WARN("- QAT RSA sign failed - redoing decrypt operation in s/w\n");
            OPENSSL_free(ver_msg);
            rsa_decrypt_op_buf_free(dec_op_data, output_buffer, qat_svm);
            return RSA_meth_get_priv_dec(RSA_PKCS1_OpenSSL())(flen, from, to, rsa, padding);
        }
        OPENSSL_free(ver_msg);
    }

    if(lenstra_rsa != NULL)
        RSA_free(lenstra_rsa);
# endif

    switch (padding) {
    case RSA_PKCS1_PADDING:
        output_len =
            RSA_padding_check_PKCS1_type_2(to,
                                           rsa_len,
                                           output_buffer->pData,
                                           output_buffer->dataLenInBytes,
                                           rsa_len);
        break;
    case RSA_PKCS1_OAEP_PADDING:
        output_len =
            RSA_padding_check_PKCS1_OAEP(to,
                                         rsa_len,
                                         output_buffer->pData,
                                         output_buffer->dataLenInBytes,
                                         rsa_len,
                                         NULL,
                                         0);
        break;
# ifndef QAT_OPENSSL_3
    case RSA_SSLV23_PADDING:
        output_len =
            RSA_padding_check_SSLv23(to,
                                     rsa_len,
                                     output_buffer->pData,
                                     output_buffer->dataLenInBytes,
                                     rsa_len);
        break;
# endif
    case RSA_NO_PADDING:
        output_len =
            RSA_padding_check_none(to,
                                   rsa_len,
                                   output_buffer->pData,
                                   output_buffer->dataLenInBytes,
                                   rsa_len);
        break;
    default:
        break;
    }

    rsa_priv_dec_sts = qat_constant_time_select_int((output_len < 0), 0, output_len);
    rsa_decrypt_op_buf_free(dec_op_data, output_buffer, qat_svm);
    dec_op_data = NULL;
    output_buffer = NULL;
    select_ptr = qat_constant_time_select_ptr((rsa_priv_dec_sts == 0), to, temp_buf);
    OPENSSL_cleanse(select_ptr, rsa_len);

    return rsa_priv_dec_sts;

 exit:
    START_RDTSC(&qat_hw_rsa_dec_req_cleanup);
    /* Free all the memory allocated in this function */
    rsa_decrypt_op_buf_free(dec_op_data, output_buffer, qat_svm);
    STOP_RDTSC(&qat_hw_rsa_dec_req_cleanup, 1, "[QAT HW RSA: cleanup]");

    if (fallback) {
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
#ifdef ENABLE_QAT_SW_RSA
        if (qat_rsa_coexist) {
            DEBUG("- Switch to QAT_SW mode.\n");
            if (qat_sw_rsa_priv_req > 0)
                --qat_sw_rsa_priv_req;
            return multibuff_rsa_priv_dec(flen, from, to, rsa, padding);
        }
#endif
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        return RSA_meth_get_priv_dec(RSA_PKCS1_OpenSSL())
                                    (flen, from, to, rsa, padding);
    }

    if (!sts)
        OPENSSL_cleanse(to, rsa_len);

    /* Return an error */
    return 0;
}

/******************************************************************************
* function:
*         qat_rsa_pub_enc(int flen,
*                         const unsigned char *from,
*                         unsigned char *to,
*                         RSA *rsa,
*                         int padding)
*
* @param flen    [IN]  - size in bytes of input
* @param from    [IN]  - pointer to the input
* @param to      [OUT] - pointer to output data
* @param rsa     [IN]  - pointer to public key structure
* @param padding [IN]  - Padding scheme
*
*
* description:
*   This function is rewrite of OpenSSL RSA_pub_enc() function. (RSA Encrypt)
*   All the inputs are pass form the above OpenSSL layer to the corresponding
*   API RSA sign function cpaCyRsaEncrypt().
******************************************************************************/
int qat_rsa_pub_enc(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding)
{
    int rsa_len = 0;
    CpaCyRsaEncryptOpData *enc_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;
    int sts = 1, fallback = 0;
    int inst_num = QAT_INVALID_INSTANCE;
    int qat_svm = QAT_INSTANCE_ANY;

    DEBUG("QAT HW RSA Started.\n");

    if ((qat_sw_rsa_pub_req > 0) || qat_get_qat_offload_disabled()) {
        fallback = 1;
        goto exit;
    }

    /* parameter checks */
    if (unlikely(rsa == NULL || from == NULL || to == NULL || flen < 0)) {
        WARN("RSA key %p, input %p or output %p are NULL, or flen invalid length.\n",
             rsa, from, to);
        QATerr(QAT_F_QAT_RSA_PUB_ENC, QAT_R_RSA_FROM_TO_NULL);
        return 0;
    }

    rsa_len = RSA_size(rsa);

    /*
    * If the op sizes are not in the range supported by QAT engine then fall
    * back to software
    */

    if (!qat_rsa_range_check(RSA_bits((const RSA*)rsa)))
        return RSA_meth_get_pub_enc(RSA_PKCS1_OpenSSL())
                                    (flen, from, to, rsa, padding);

    if ((inst_num = get_instance(QAT_INSTANCE_ASYM, QAT_INSTANCE_ANY))
            == QAT_INVALID_INSTANCE) {
        WARN("Failed to get an instance\n");
        if (qat_get_sw_fallback_enabled()) {
            WARN("Failed to get an instance - fallback to SW - %s\n", __func__);
            sts = 0;
            goto exit;
        } else {
            QATerr(QAT_F_QAT_RSA_PUB_ENC, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    qat_svm = !qat_instance_details[inst_num].qat_instance_info.requiresPhysicallyContiguousMemory;

    if (1 != build_encrypt_op_buf(flen, from, to, rsa, padding,
                                  &enc_op_data, &output_buffer, PADDING, qat_svm)) {
        WARN("Failure in build_encrypt_op_buf\n");
        /* Errors are already raised within build_encrypt_op_buf. */
        sts = 0;
        goto exit;
    }

    if (1 != qat_rsa_encrypt(enc_op_data, output_buffer, &fallback, inst_num, qat_svm)) {
        WARN("Failure in qat_rsa_encrypt\n");
        /* Errors are already raised within qat_rsa_encrypt. */
        sts = 0;
        goto exit;

    } else {
        if (unlikely(output_buffer->pData == NULL)) {
            WARN("output_buffer->pData is NULL\n");
            QATerr(QAT_F_QAT_RSA_PUB_ENC, ERR_R_INTERNAL_ERROR);
            sts = 0;
            goto exit;
        }
        if (!qat_svm)
            memcpy(to, output_buffer->pData, output_buffer->dataLenInBytes);
    }
    rsa_encrypt_op_buf_free(enc_op_data, output_buffer, qat_svm);
    enc_op_data = NULL;
    output_buffer = NULL;

    DEBUG("- Finished\n");
    return rsa_len;
 exit:
    /* Free all the memory allocated in this function */
    rsa_encrypt_op_buf_free(enc_op_data, output_buffer, qat_svm);

    if (fallback) {
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
#ifdef ENABLE_QAT_SW_RSA
        if (qat_rsa_coexist) {
            DEBUG("- Switch to QAT_SW mode.\n");
            if (qat_sw_rsa_pub_req > 0)
                --qat_sw_rsa_pub_req;
            return multibuff_rsa_pub_enc(flen, from, to, rsa, padding);
        }
#endif
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        return RSA_meth_get_pub_enc(RSA_PKCS1_OpenSSL())
                                    (flen, from, to, rsa, padding);
    }

    if (!sts)
        OPENSSL_cleanse(to, rsa_len);
    return 0;
}

/******************************************************************************
* function:
*         qat_rsa_pub_dec(int flen,
*                         const unsigned char *from,
*                         unsigned char *to,
*                         RSA *rsa,
*                         int padding)
*
* @param flen    [IN]  - size in bytes of input
* @param from    [IN]  - pointer to the input
* @param to      [OUT] - pointer to output data
* @param rsa     [IN]  - pointer to public key structure
* @param padding [IN]  - Padding scheme
*
* description:
*   This function is rewrite of OpenSSL RSA_pub_dec() function (RSA Verify)
*   All the inputs are pass form the above OpenSSL layer to the corresponding
*   API RSA verify function cpaCyRsaEncrypt().
*   The function returns the RSA recovered message output.
*   We use the encrypt implementation to achieve this.
******************************************************************************/
int qat_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to,
                    RSA *rsa, int padding)
{
    int rsa_len = 0;
    int output_len = -1;
    CpaCyRsaEncryptOpData *enc_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;
    int sts = 1, fallback = 0;
    int inst_num = QAT_INVALID_INSTANCE;
    int qat_svm = QAT_INSTANCE_ANY;
    unsigned char temp_buf[RSA_QAT_RANGE_MAX];
    unsigned char *select_ptr = NULL;
    int rsa_pub_dec_sts = -1;

    DEBUG("QAT HW RSA Started.\n");
#ifdef ENABLE_QAT_FIPS
    qat_fips_get_approved_status();
#endif

    if ((qat_sw_rsa_pub_req > 0) || qat_get_qat_offload_disabled()) {
        fallback = 1;
        goto exit;
    }

    /* parameter checking */
    if (rsa == NULL || from == NULL || to == NULL ||
        (flen != (rsa_len = RSA_size(rsa)))) {
        WARN("RSA key %p, input %p or output %p are NULL or invalid length, \
              flen = %d, rsa_len = %d\n", rsa, from, to, flen, rsa_len);
        QATerr(QAT_F_QAT_RSA_PUB_DEC, QAT_R_RSA_FROM_TO_NULL);
        return 0;
    }

    /*
    * If the op sizes are not in the range supported by QAT engine then fall
    * back to software
    */

    if (!qat_rsa_range_check(RSA_bits((const RSA*)rsa)))
        return RSA_meth_get_pub_dec(RSA_PKCS1_OpenSSL())
                                    (flen, from, to, rsa, padding);

    if ((inst_num = get_instance(QAT_INSTANCE_ASYM, QAT_INSTANCE_ANY))
            == QAT_INVALID_INSTANCE) {
        WARN("Failed to get an instance\n");
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
            fallback = 1;
            sts = 0;
            goto exit;
        } else {
            QATerr(QAT_F_QAT_RSA_PUB_DEC, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    qat_svm = !qat_instance_details[inst_num].qat_instance_info.requiresPhysicallyContiguousMemory;

    if (1 != build_encrypt_op_buf(flen, from, to, rsa, padding,
                                  &enc_op_data, &output_buffer, NO_PADDING, qat_svm)) {
        WARN("Failure in build_encrypt_op_buf\n");
        /* Errors are already raised within build_encrypt_op_buf. */
        sts = 0;
        goto exit;
    }

    if (1 != qat_rsa_encrypt(enc_op_data, output_buffer, &fallback, inst_num, qat_svm)) {
        WARN("Failure in qat_rsa_encrypt\n");
        /* Errors are already raised within qat_rsa_encrypt. */
        sts = 0;
        goto exit;
    }

    switch (padding) {
    case RSA_PKCS1_PADDING:
        output_len =
            RSA_padding_check_PKCS1_type_1(to,
                                           rsa_len,
                                           output_buffer->pData,
                                           output_buffer->dataLenInBytes,
                                           rsa_len);
        break;
    case RSA_X931_PADDING:
        output_len =
            RSA_padding_check_X931(to,
                                   rsa_len,
                                   output_buffer->pData,
                                   output_buffer->dataLenInBytes,
                                   rsa_len);
        break;
    case RSA_NO_PADDING:
        output_len =
            RSA_padding_check_none(to,
                                   rsa_len,
                                   output_buffer->pData,
                                   output_buffer->dataLenInBytes,
                                   rsa_len);
        break;
    default:
        break;
    }

    rsa_pub_dec_sts = qat_constant_time_select_int((output_len < 0), 0, output_len);
    rsa_encrypt_op_buf_free(enc_op_data, output_buffer, qat_svm);
    enc_op_data = NULL;
    output_buffer = NULL;
    select_ptr = qat_constant_time_select_ptr((rsa_pub_dec_sts == 0), to, temp_buf);
    OPENSSL_cleanse(select_ptr, rsa_len);

    return rsa_pub_dec_sts;

 exit:
    /* Free all the memory allocated in this function */
    rsa_encrypt_op_buf_free(enc_op_data, output_buffer, qat_svm);

    if (fallback) {
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
#ifdef ENABLE_QAT_SW_RSA
        if (qat_rsa_coexist) {
            DEBUG("- Switch to QAT_SW mode.\n");
            if (qat_sw_rsa_pub_req > 0)
                --qat_sw_rsa_pub_req;
            return multibuff_rsa_pub_dec(flen, from, to, rsa, padding);
        }
#endif
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        return RSA_meth_get_pub_dec(RSA_PKCS1_OpenSSL())
                                    (flen, from, to, rsa, padding);
    }

    if (!sts)
        OPENSSL_cleanse(to, rsa_len);
    return 0;
}

# ifndef QAT_BORINGSSL
/******************************************************************************
* function:
*         qat_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
*
* @param r0    [IN] - Result bignum of mod_exp
* @param I     [IN] - Base used for mod_exp
* @param rsa   [IN] - Exponent used for mod_exp
* @param ctx   [IN] - EVP context.
*
* description:
*             Returns sw implementation of rsa_mod_exp
*
*******************************************************************************/
int
qat_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    DEBUG("- Started\n");
    return RSA_meth_get_mod_exp(RSA_PKCS1_OpenSSL())
                                (r0, I, rsa, ctx);
}

/******************************************************************************
* function:
*         qat_rsa_init(RSA *rsa)
*
* @param rsa   [IN] - The RSA data structure
*
* description:
*             Returns sw implementation of rsa_init.
*             Needed to ensure correct caching occurs.
*
*******************************************************************************/
int
qat_rsa_init(RSA *rsa)
{
    return RSA_meth_get_init(RSA_PKCS1_OpenSSL())(rsa);
}

/******************************************************************************
* function:
*         qat_rsa_finish(RSA *rsa)
*
* @param rsa   [IN] - The RSA data structure
*
* description:
*             Returns sw implementation of rsa_finish.
*             Needed to ensure correct cleanup of cached data.
*
*******************************************************************************/
int
qat_rsa_finish(RSA *rsa)
{
    return RSA_meth_get_finish(RSA_PKCS1_OpenSSL())(rsa);
}
#else
/* Referred to boringssl/crypto/fipsmodule/rsa/rsa_impl.c*/
int qat_rsa_priv_sign(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                      const uint8_t *in, size_t in_len, int padding)
{
    int len = 0;
    const unsigned rsa_size = RSA_size(rsa);
    int __attribute__((unused)) _ret;

    if (max_out < rsa_size) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_OUTPUT_BUFFER_TOO_SMALL);
        _ret = ASYNC_current_job_last_check_and_get();
        return 0;
    }

    len = qat_rsa_priv_enc(in_len, in, out, rsa, padding);
    if(0 >= len) {
        _ret = ASYNC_current_job_last_check_and_get();
        return 0;
    }

    if (1 == len) { /* async mode */
        _ret = ASYNC_current_job_last_check_and_get();
        len = 0;
    }

    *out_len = len;
    return 1;
}

int qat_rsa_priv_decrypt(RSA *rsa, size_t *out_len, uint8_t *out,
                         size_t max_out, const uint8_t *in, size_t in_len,
                         int padding)
{
    int len = 0;
    const unsigned rsa_size = RSA_size(rsa);
    int __attribute__((unused)) _ret;

    if (max_out < rsa_size) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_OUTPUT_BUFFER_TOO_SMALL);
        _ret = ASYNC_current_job_last_check_and_get();
        return 0;
    }

    if (in_len != rsa_size) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_LEN_NOT_EQUAL_TO_MOD_LEN);
        _ret = ASYNC_current_job_last_check_and_get();
        return 0;
    }

    len = qat_rsa_priv_dec(in_len, in, out, rsa, padding);
    if(0 >= len) {
        _ret = ASYNC_current_job_last_check_and_get();
        return 0;
    }

    if (1 == len) { /* async mode */
        _ret = ASYNC_current_job_last_check_and_get();
        len = 0;
    }

    *out_len = len;
    return 1;
}
# endif /* QAT_BORINGSSL */

#endif /* ENABLE_QAT_HW_RSA */
