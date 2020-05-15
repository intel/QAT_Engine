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
 * @file qat_rsa.c
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
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#include <openssl/async.h>
#endif
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "cmn_mem_drv_inf.h"
#endif
#include "qat_utils.h"
#include "qat_init.h"
#include "qat_callback.h"
#include "qat_polling.h"
#include "qat_events.h"

#include "cpa.h"
#include "cpa_types.h"

#include "cpa_cy_rsa.h"
#include "cpa_cy_ln.h"
#include "qat_rsa.h"
#include "qat_rsa_aux.h"
#include "qat_asym_common.h"
#include "e_qat_err.h"
#include "icp_sal_poll.h"
#include "qat_rsa_crt.h"

#ifdef OPENSSL_ENABLE_QAT_RSA
# ifdef OPENSSL_DISABLE_QAT_RSA
#  undef OPENSSL_DISABLE_QAT_RSA
# endif
#endif

/* To specify the RSA op sizes supported by QAT engine */
#define RSA_QAT_RANGE_MIN 512
#define RSA_QAT_RANGE_MAX 4096

#define NO_PADDING 0
#define PADDING    1

#ifndef OPENSSL_DISABLE_QAT_RSA
/* Qat engine RSA methods declaration */
static int qat_rsa_priv_enc(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding);
static int qat_rsa_priv_dec(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding);
static int qat_rsa_pub_enc(int flen, const unsigned char *from,
                           unsigned char *to, RSA *rsa, int padding);
static int qat_rsa_pub_dec(int flen, const unsigned char *from,
                           unsigned char *to, RSA *rsa, int padding);
static int qat_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx);
static int qat_rsa_init(RSA *rsa);
static int qat_rsa_finish(RSA *rsa);
#endif

static RSA_METHOD *qat_rsa_method = NULL;

RSA_METHOD *qat_get_RSA_methods(void)
{
#ifndef OPENSSL_DISABLE_QAT_RSA
    int res = 1;
#endif

    if (qat_rsa_method != NULL)
        return qat_rsa_method;

#ifndef OPENSSL_DISABLE_QAT_RSA
    if ((qat_rsa_method = RSA_meth_new("QAT RSA method", 0)) == NULL) {
        WARN("Failed to allocate QAT RSA methods\n");
        QATerr(QAT_F_QAT_GET_RSA_METHODS, QAT_R_ALLOC_QAT_RSA_METH_FAILURE);
        return NULL;
    }

    res &= RSA_meth_set_pub_enc(qat_rsa_method, qat_rsa_pub_enc);
    res &= RSA_meth_set_pub_dec(qat_rsa_method, qat_rsa_pub_dec);
    res &= RSA_meth_set_priv_enc(qat_rsa_method, qat_rsa_priv_enc);
    res &= RSA_meth_set_priv_dec(qat_rsa_method, qat_rsa_priv_dec);
    res &= RSA_meth_set_mod_exp(qat_rsa_method, qat_rsa_mod_exp);
    res &= RSA_meth_set_bn_mod_exp(qat_rsa_method, BN_mod_exp_mont);
    res &= RSA_meth_set_init(qat_rsa_method, qat_rsa_init);
    res &= RSA_meth_set_finish(qat_rsa_method, qat_rsa_finish);

    if (res == 0) {
        WARN("Failed to set QAT RSA methods\n");
        QATerr(QAT_F_QAT_GET_RSA_METHODS, QAT_R_SET_QAT_RSA_METH_FAILURE);
        return NULL;
    }
#else
    qat_rsa_method = (RSA_METHOD *)RSA_get_default_method();
#endif

    return qat_rsa_method;
}

void qat_free_RSA_methods(void)
{
#ifndef OPENSSL_DISABLE_QAT_RSA
    if (qat_rsa_method != NULL) {
        RSA_meth_free(qat_rsa_method);
        qat_rsa_method = NULL;
    } else {
        WARN("qat_rsa_method is NULL\n");
        QATerr(QAT_F_QAT_FREE_RSA_METHODS, QAT_R_FREE_QAT_RSA_METH_FAILURE);
    }
#endif
}

#ifndef OPENSSL_DISABLE_QAT_RSA
/*
 * The RSA range check is performed so that if the op sizes are not in the
 * range supported by QAT engine then fall back to software
 */

static inline int qat_rsa_range_check(int plen)
{
    return ((plen >= RSA_QAT_RANGE_MIN) && (plen <= RSA_QAT_RANGE_MAX));
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
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_asym_requests_in_flight);
    }
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, CPA_TRUE);
}

static void
rsa_decrypt_op_buf_free(CpaCyRsaDecryptOpData * dec_op_data,
                        CpaFlatBuffer * out_buf)
{
    CpaCyRsaPrivateKeyRep2 *key = NULL;
    DEBUG("- Started\n");

    if (dec_op_data) {
        if (dec_op_data->inputData.pData) {
            qaeCryptoMemFreeNonZero(dec_op_data->inputData.pData);
        }
        if (dec_op_data->pRecipientPrivateKey) {
            key = &dec_op_data->pRecipientPrivateKey->privateKeyRep2;
            QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(key->prime1P);
            QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(key->prime2Q);
            QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(key->exponent1Dp);
            QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(key->exponent2Dq);
            QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(key->coefficientQInv);
            OPENSSL_free(dec_op_data->pRecipientPrivateKey);
        }
        OPENSSL_free(dec_op_data);
    }

    if (out_buf) {
        if (out_buf->pData) {
            qaeCryptoMemFreeNonZero(out_buf->pData);
        }
        OPENSSL_free(out_buf);
    }
    DEBUG("- Finished\n");
}


static int qat_rsa_decrypt(CpaCyRsaDecryptOpData * dec_op_data, int rsa_len,
                           CpaFlatBuffer * output_buf, int * fallback)
{
    /* Used for RSA Decrypt and RSA Sign */
    op_done_t op_done;
    CpaStatus sts = CPA_STATUS_FAIL;
    int inst_num = QAT_INVALID_INSTANCE;
    int job_ret = 0;
    int sync_mode_ret = 0;
    thread_local_variables_t *tlv = NULL;

    DEBUG("- Started\n");

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (pthread_kill(timer_poll_func_thread, SIGUSR1) != 0) {
                WARN("pthread_kill error\n");
                QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                return 0;
            }
        }
    }
    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failed to setup async event notifications\n");
            QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            return 0;
        }
    } else {
        /*
         *  Sync mode
         */
        qat_cleanup_op_done(&op_done);
        sync_mode_ret = qat_rsa_decrypt_CRT(dec_op_data, rsa_len, output_buf, fallback);
        QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
        return sync_mode_ret;
    }
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
        if ((inst_num = get_next_inst_num()) == QAT_INVALID_INSTANCE) {
            WARN("Failed to get an instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                *fallback = 1;
            } else {
                QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
            }
            qat_clear_async_event_notification();
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            return 0;
        }
        DUMP_RSA_DECRYPT(qat_instance_handles[inst_num], &op_done, dec_op_data, output_buf);
        sts = cpaCyRsaDecrypt(qat_instance_handles[inst_num], qat_rsaCallbackFn, &op_done,
                              dec_op_data, output_buf);
        if (sts == CPA_STATUS_RETRY) {
            if ((qat_wake_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0) ||
                (qat_pause_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0)) {
                WARN("qat_wake_job or qat_pause_job failed\n");
                break;
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
        } else {
            QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
        }
        qat_clear_async_event_notification();
        qat_cleanup_op_done(&op_done);
        QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
        return 0;
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
                     CpaFlatBuffer ** output_buffer, int alloc_pad)
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
        (padding != RSA_SSLV23_PADDING) &&
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
    if (qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.prime1P, p) != 1 ||
        qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.prime2Q, q) != 1 ||
        qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.exponent1Dp, dmp1) != 1 ||
        qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.exponent2Dq, dmq1) != 1 ||
        qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.coefficientQInv, iqmp) != 1) {
        WARN("Failed to convert privateKeyRep2 elements to flatbuffer\n");
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_P_Q_DMP_DMQ_CONVERT_TO_FB_FAILURE);
        return 0;
    }

    (*dec_op_data)->inputData.pData = (Cpa8U *) qaeCryptoMemAlloc(
        ((padding != RSA_NO_PADDING) && alloc_pad) ? rsa_len : flen,
         __FILE__,
         __LINE__);

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

    *output_buffer = OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (NULL == *output_buffer) {
        WARN("Failed to allocate output_buffer\n");
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_OUTPUT_BUF_MALLOC_FAILURE);
        return 0;
    }

    /*
     * Memory allocation for DecOpdata[IN] the size of outputBuffer
     * should big enough to contain RSA_size
     */
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
                        CpaFlatBuffer * out_buf)
{
    DEBUG("- Started\n");

    if (enc_op_data) {
        if (enc_op_data->pPublicKey) {
            if (enc_op_data->pPublicKey->modulusN.pData) {
                OPENSSL_cleanse(enc_op_data->pPublicKey->modulusN.pData, enc_op_data->pPublicKey->modulusN.dataLenInBytes);
                qaeCryptoMemFreeNonZero(enc_op_data->pPublicKey->modulusN.pData);
            }
            if (enc_op_data->pPublicKey->publicExponentE.pData) {
                OPENSSL_cleanse(enc_op_data->pPublicKey->publicExponentE.pData, enc_op_data->pPublicKey->publicExponentE.dataLenInBytes);
                qaeCryptoMemFreeNonZero(enc_op_data->pPublicKey->
                                 publicExponentE.pData);
            }
            OPENSSL_free(enc_op_data->pPublicKey);
        }
        if (enc_op_data->inputData.pData) {
            OPENSSL_cleanse(enc_op_data->inputData.pData, enc_op_data->inputData.dataLenInBytes);
            qaeCryptoMemFreeNonZero(enc_op_data->inputData.pData);
        }
        OPENSSL_free(enc_op_data);
    }

    if (out_buf) {
        if (out_buf->pData) {
            qaeCryptoMemFreeNonZero(out_buf->pData);
        }
        OPENSSL_free(out_buf);
    }
    DEBUG("- Finished\n");
}


static int qat_rsa_encrypt(CpaCyRsaEncryptOpData * enc_op_data,
                           CpaFlatBuffer * output_buf, int * fallback)
{
    /* Used for RSA Encrypt and RSA Verify */
    op_done_t op_done;
    CpaStatus sts = CPA_STATUS_FAIL;
    int qatPerformOpRetries = 0;
    int inst_num = QAT_INVALID_INSTANCE;
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

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (pthread_kill(timer_poll_func_thread, SIGUSR1) != 0) {
                WARN("pthread_kill error\n");
                QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                return 0;
            }
        }
    }
    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
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
        if ((inst_num = get_next_inst_num()) == QAT_INVALID_INSTANCE) {
            WARN("Failed to get an instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                *fallback = 1;
            } else {
                QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL) {
                qat_clear_async_event_notification();
            }
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            return 0;
        }

        DUMP_RSA_ENCRYPT(qat_instance_handles[inst_num], &op_done, enc_op_data, output_buf);
        sts = cpaCyRsaEncrypt(qat_instance_handles[inst_num], qat_rsaCallbackFn, &op_done,
                              enc_op_data, output_buf);
        if (sts == CPA_STATUS_RETRY) {
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
    while (sts == CPA_STATUS_RETRY);

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", sts);
        if (qat_get_sw_fallback_enabled() && (sts == CPA_STATUS_RESTARTING || sts == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            *fallback = 1;
        } else {
            QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
        }
        if (op_done.job != NULL) {
            qat_clear_async_event_notification();
        }
        qat_cleanup_op_done(&op_done);
        QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
        return 0;
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
                pthread_yield();
        } else {
            if(getEnableInlinePolling()) {
                icp_sal_CyPollInstance(qat_instance_handles[inst_num], 0);
            } else {
                pthread_yield();
            }
        }
    } while (!op_done.flag ||
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
                     CpaFlatBuffer ** output_buffer, int alloc_pad)
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
        (padding != RSA_X931_PADDING) &&
        (padding != RSA_SSLV23_PADDING)) {
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
    if (qat_BN_to_FB(&cpa_pub_key->modulusN, n) != 1 ||
        qat_BN_to_FB(&cpa_pub_key->publicExponentE, e) != 1) {
        WARN("Failed to convert cpa_pub_key elements to flatbuffer\n");
        QATerr(QAT_F_BUILD_ENCRYPT_OP_BUF, QAT_R_N_E_CONVERT_TO_FB_FAILURE);
        return 0;
    }

    (*enc_op_data)->inputData.pData = (Cpa8U *) qaeCryptoMemAlloc(
        ((padding != RSA_NO_PADDING) && alloc_pad) ? rsa_len : flen,
         __FILE__,
         __LINE__);

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
        case RSA_SSLV23_PADDING:
            padding_result =
                RSA_padding_add_SSLv23((*enc_op_data)->inputData.pData,
                                       rsa_len, from, flen);
            break;
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
        (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
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
    (*output_buffer)->pData = qaeCryptoMemAlloc(rsa_len, __FILE__, __LINE__);
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
    int sts = 1, fallback = 0;
#ifndef OPENSSL_DISABLE_QAT_LENSTRA_PROTECTION
    unsigned char *ver_msg = NULL;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
#endif

    DEBUG("- Started.\n");

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode\n");
        return RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())
                                     (flen, from, to, rsa, padding);
    }

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

    if (1 != build_decrypt_op_buf(flen, from, to, rsa, padding,
                                  &dec_op_data, &output_buffer, PADDING)) {
        WARN("Failure in build_decrypt_op_buf\n");
        /* Errors are already raised within build_decrypt_op_buf. */
        sts = 0;
        goto exit;
    }

    if (1 != qat_rsa_decrypt(dec_op_data, rsa_len, output_buffer, &fallback)) {
        WARN("Failure in qat_rsa_decrypt  fallback = %d\n", fallback);
        /* Errors are already raised within qat_rsa_decrypt. */
        sts = 0;
        goto exit;
    }
    memcpy(to, output_buffer->pData, rsa_len);

    rsa_decrypt_op_buf_free(dec_op_data, output_buffer);

#ifndef OPENSSL_DISABLE_QAT_LENSTRA_PROTECTION
    /* Lenstra vulnerability protection: Now call the s/w impl'n of public decrypt in order to
       verify the sign operation just carried out (cpaCyRsaDecrypt). */
    RSA_get0_key((const RSA*)rsa, &n, &e, &d);

    /* Note: not checking 'd' as it is not used */
    if (e != NULL) { /* then a public key exists and we can effect Lenstra attack protection*/
        ver_msg = OPENSSL_zalloc(flen);
        if (ver_msg == NULL) {
            WARN("ver_msg zalloc failed.\n");
            QATerr(QAT_F_QAT_RSA_PRIV_ENC, ERR_R_MALLOC_FAILURE);
            sts = 0;
            goto exit_lenstra;
        }
        if ((RSA_meth_get_pub_dec(RSA_PKCS1_OpenSSL())
             (rsa_len, (const unsigned char *)to, ver_msg, rsa, padding) <= 0)
            || (CRYPTO_memcmp(from, ver_msg, flen) != 0)) {
            WARN("- Verify failed - redoing sign operation in s/w\n");
            OPENSSL_free(ver_msg);
            return RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())(flen, from, to, rsa, padding);
        }
        OPENSSL_free(ver_msg);
    }
#endif

    DEBUG("- Finished\n");
    return rsa_len;

exit:
    /* Free all the memory allocated in this function */
    rsa_decrypt_op_buf_free(dec_op_data, output_buffer);
#ifndef OPENSSL_DISABLE_QAT_LENSTRA_PROTECTION
exit_lenstra:
#endif

    if (fallback) {
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
    int sts = 1, fallback = 0;
    CpaCyRsaDecryptOpData *dec_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;
#ifndef OPENSSL_DISABLE_QAT_LENSTRA_PROTECTION
    unsigned char *ver_msg = NULL;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
#endif

    DEBUG("- Started.\n");

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode\n");
        return RSA_meth_get_priv_dec(RSA_PKCS1_OpenSSL())
                                     (flen, from, to, rsa, padding);
    }

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

    if (1 != build_decrypt_op_buf(flen, from, to, rsa, padding,
                                  &dec_op_data, &output_buffer, NO_PADDING)) {
        WARN("Failure in build_decrypt_op_buf\n");
        /* Errors are already raised within build_decrypt_op_buf. */
        sts = 0;
        goto exit;
    }

    if (1 != qat_rsa_decrypt(dec_op_data, rsa_len, output_buffer, &fallback)) {
        WARN("Failure in qat_rsa_decrypt\n");
        if (fallback == 0) {
            /* Most but not all error cases are also raised within qat_rsa_decrypt. */
            QATerr(QAT_F_QAT_RSA_PRIV_DEC, ERR_R_INTERNAL_ERROR);
        }
        sts = 0;
        goto exit;
    }

#ifndef OPENSSL_DISABLE_QAT_LENSTRA_PROTECTION
    /* Lenstra vulnerability protection: Now call the s/w impl'n of public encrypt in order to
       verify the decrypt operation just carried out. */
    RSA_get0_key((const RSA*)rsa, &n, &e, &d);

    /* Note: not checking 'd' as it is not used */
    if (e != NULL) { /* then a public key exists and we can effect Lenstra attack protection*/
        ver_msg = OPENSSL_zalloc(flen);
        if (ver_msg == NULL) {
            WARN("ver_msg zalloc failed.\n");
            QATerr(QAT_F_QAT_RSA_PRIV_DEC, ERR_R_MALLOC_FAILURE);
            sts = 0;
            goto exit;
        }
        if ((RSA_meth_get_pub_enc(RSA_PKCS1_OpenSSL())
             (rsa_len, (const unsigned char *)output_buffer->pData, ver_msg, rsa, RSA_NO_PADDING) <= 0)
            || (CRYPTO_memcmp(from, ver_msg, flen) != 0)) {
            WARN("- Verify of offloaded decrypt operation failed - redoing decrypt operation in s/w\n");
            OPENSSL_free(ver_msg);
            rsa_decrypt_op_buf_free(dec_op_data, output_buffer);
            return RSA_meth_get_priv_dec(RSA_PKCS1_OpenSSL())(flen, from, to, rsa, padding);
        }
        OPENSSL_free(ver_msg);
    }
#endif

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
    case RSA_SSLV23_PADDING:
        output_len =
            RSA_padding_check_SSLv23(to,
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
        break; /* Do nothing as the error will be caught below. */
    }

    if (output_len < 0) {
        WARN("Failure in removing padding\n");
        QATerr(QAT_F_QAT_RSA_PRIV_DEC, ERR_R_INTERNAL_ERROR);
        sts = 0;
        goto exit;
    }

    rsa_decrypt_op_buf_free(dec_op_data, output_buffer);

    DEBUG("- Finished\n");
    return output_len;

 exit:
    /* Free all the memory allocated in this function */
    rsa_decrypt_op_buf_free(dec_op_data, output_buffer);

    if (fallback) {
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

    DEBUG("- Started\n");

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode\n");
        return RSA_meth_get_pub_enc(RSA_PKCS1_OpenSSL())
                                    (flen, from, to, rsa, padding);
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

    if (1 != build_encrypt_op_buf(flen, from, to, rsa, padding,
                                  &enc_op_data, &output_buffer, PADDING)) {
        WARN("Failure in build_encrypt_op_buf\n");
        /* Errors are already raised within build_encrypt_op_buf. */
        sts = 0;
        goto exit;
    }

    if (1 != qat_rsa_encrypt(enc_op_data, output_buffer, &fallback)) {
        WARN("Failure in qat_rsa_encrypt\n");
        /* Errors are already raised within qat_rsa_encrypt. */
        sts = 0;
        goto exit;

    } else {
        memcpy(to, output_buffer->pData, output_buffer->dataLenInBytes);
    }
    rsa_encrypt_op_buf_free(enc_op_data, output_buffer);

    DEBUG("- Finished\n");
    return rsa_len;
 exit:
    /* Free all the memory allocated in this function */
    rsa_encrypt_op_buf_free(enc_op_data, output_buffer);

    if (fallback) {
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

    DEBUG("- Started\n");

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode\n");
        return RSA_meth_get_pub_dec(RSA_PKCS1_OpenSSL())
                                    (flen, from, to, rsa, padding);
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

    if (1 != build_encrypt_op_buf(flen, from, to, rsa, padding,
                                  &enc_op_data, &output_buffer, NO_PADDING)) {
        WARN("Failure in build_encrypt_op_buf\n");
        /* Errors are already raised within build_encrypt_op_buf. */
        sts = 0;
        goto exit;
    }

    if (1 != qat_rsa_encrypt(enc_op_data, output_buffer, &fallback)) {
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
        break; /* Do nothing as the error will be caught below. */
    }

    if (output_len < 0) {
        WARN("Failure in removing padding\n");
        QATerr(QAT_F_QAT_RSA_PUB_DEC, ERR_R_INTERNAL_ERROR);
        sts = 0;
        goto exit;
    }

    rsa_encrypt_op_buf_free(enc_op_data, output_buffer);
    DEBUG("- Finished\n");
    return output_len;

 exit:
    /* Free all the memory allocated in this function */
    rsa_encrypt_op_buf_free(enc_op_data, output_buffer);

    if (fallback) {
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        return RSA_meth_get_pub_dec(RSA_PKCS1_OpenSSL())
                                    (flen, from, to, rsa, padding);
    }

    if (!sts)
        OPENSSL_cleanse(to, rsa_len);
    return 0;
}

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

#endif /* #ifndef OPENSSL_DISABLE_QAT_RSA */
