/* macros defined to allow use of the cpu get and set affinity functions */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifndef __USE_GNU
# define __USE_GNU
#endif

#ifdef ENABLE_QAT_HW_KPT

/* Standard Includes */
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include <fcntl.h>
# include <pthread.h>
# include <signal.h>
# include <time.h>
# include <sched.h>

/* Local Includes */
# include "qat_hw_kpt.h"
# include "qat_hw_callback.h"
# include "qat_hw_polling.h"
# include "qat_events.h"
# include "qat_hw_asym_common.h"

# define NO_PADDING 0
# define PADDING    1

pthread_t kpt_polling_thread;
int kpt_keep_polling = 0;
int kpt_enabled = 0;
int kpt_inited = 0;

int is_kpt_mode(void)
{
    /* 
     * kpt_enabled = 1 means WPK files are used and loaded successfully.
     * kpt_inited = 1 means KPT is provisioned successfully.
     * KPT mode needs to satisfy both of above conditions.
     */
    if (kpt_enabled) {
        if (kpt_inited) {
            return 1;
        } else {
            /* Init KPT for single-process app, e.g. OpenSSL. */
            if (!qat_hw_kpt_init()) {
                kpt_inited = 0;
                WARN("KPT initialization in KPT mode check failed.\n");
                return 0;
            }

            kpt_inited = 1;
            return 1;
        }
    }

    return 0;
}

EVP_PKEY *qat_hw_kpt_load_privkey(ENGINE *e, const char *wpk)
{
    return kpt_load_priv_key(e, wpk);
}

static void *kpt_poll_func(void *ih)
{
    CpaStatus status;
    int inst_idx;

    struct timespec req_time = { 0 };
    req_time.tv_nsec = qat_poll_interval;

    while (kpt_keep_polling) {
        for (inst_idx = 0; inst_idx < qat_num_instances; inst_idx++) {
            status = icp_sal_CyPollInstance(qat_instance_handles[inst_idx], 0);
            if (unlikely(status == CPA_STATUS_FAIL))
                WARN("Error in icp_sal_CyPollInstance\n");
        }
        nanosleep(&req_time, NULL);
    }
    return NULL;
}

int qat_hw_kpt_init()
{
    int inst_idx = 0;
    int pass = 0;

    /* create kpt polling thread */
    kpt_keep_polling = 1;
    if (qat_create_thread(&kpt_polling_thread, NULL, kpt_poll_func, NULL)) {
        WARN("Creation of kpt polling thread failed\n");
        return 0;
    }

    for (inst_idx = 0; inst_idx < qat_num_instances; inst_idx++) {
        if (kpt_init(inst_idx, qat_instance_handles[inst_idx])) {
            DEBUG("Instance %d Loads SWK Successfully\n", inst_idx);
            pass = 1;
        }
    }

    /* stop kpt polling thread */
    kpt_keep_polling = 0;
    if (qat_join_thread(kpt_polling_thread, NULL) != 0) {
        WARN("Error in kpt polling thread join\n");
        return 0;
    }

    if (!pass) {
        WARN("No Instance is provisioned successful\n");
        return 0;
    }

    return 1;
}

void qat_hw_kpt_finish()
{
    int inst_idx = 0;

    /* create kpt polling thread */
    kpt_keep_polling = 1;
    if (qat_create_thread(&kpt_polling_thread, NULL, kpt_poll_func, NULL)) {
        WARN("Creation of kpt polling thread failed\n");
        return;
    }

    for (inst_idx = 0; inst_idx < qat_num_instances; inst_idx++) {
        kpt_finish(inst_idx, qat_instance_handles[inst_idx]);
    }

    /* stop kpt polling thread */
    kpt_keep_polling = 0;
    if (qat_join_thread(kpt_polling_thread, NULL) != 0) {
        WARN("Error in kpt polling thread join\n");
        return;
    }
}

/**
 *****************************************************************************
 * 
 * KPT RSA Decryption and Sign implementation.
 *
 *****************************************************************************/

/******************************************************************************
* function:
*         kpt_rsaCallbackFn(void *pCallbackTag, CpaStatus status,
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

int qat_check_rsa_wpk(RSA *rsa)
{
    return kpt_check_rsa_wpk(rsa);
}

static void kpt_rsaCallbackFn(void *pCallbackTag, CpaStatus status,
                              void *pOpData, CpaFlatBuffer *pOut)
{
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_asym_requests_in_flight);
    }
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, CPA_TRUE);
}

static void kpt_sync_rsaCallbackFn(void *pCallbackTag, CpaStatus status,
                                   void *pOpData, CpaFlatBuffer *pOut)
{
    op_done_t *opDone = (op_done_t *) pCallbackTag;

    if (unlikely(opDone == NULL)) {
        WARN("opDone is NULL\n");
        return;
    }

    DEBUG("kpt_sync_rsaCallbackFn status %d\n", status);

    opDone->verifyResult = CPA_TRUE;
    opDone->status = status;
    opDone->flag = 0;
    opDone->job = NULL;

    return;
}

static int qat_hw_kpt_rsa_decrypt(CpaCyKptRsaDecryptOpData *dec_op_data,
                                  int rsa_len, CpaFlatBuffer *output_buf,
                                  int *fallback, int kpt_wpk_idx)
{
    /* Used for RSA Decrypt and RSA Sign */
    op_done_t op_done;
    CpaStatus sts = CPA_STATUS_FAIL;
    int inst_num = QAT_INVALID_INSTANCE;
    int job_ret = 0;
    thread_local_variables_t *tlv = NULL;

    DEBUG("- Started\n");

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        return 0;
    }

    tlv->kpt_wpk_in_use = kpt_wpk_idx;
    if ((inst_num =
         get_instance(QAT_INSTANCE_ASYM, QAT_INSTANCE_ANY)) ==
        QAT_INVALID_INSTANCE) {
        WARN("Failed to get an instance\n");
        tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;
        return 0;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (qat_kill_thread(qat_timer_poll_func_thread, SIGUSR1) != 0) {
                WARN("qat_kill_thread error\n");
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;
                return 0;
            }
        }
    }
    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failed to setup async event notifications\n");
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;
            return 0;
        }
    } else {
        /* Sync mode */
        CRYPTO_QAT_LOG("- RSA\n");
        DEBUG("RSA Decryption in Sync Mode\n");

        /* Inline polling mode, need to quickly return then polling the ring */
        if (getEnableInlinePolling()) {
            sts = kpt_rsa_decrypt(inst_num, kpt_sync_rsaCallbackFn, &op_done,
                                  dec_op_data, output_buf, kpt_wpk_idx);
        } else {
            /* Internal/External polling mode, block here until it returns */
            sts = kpt_rsa_decrypt(inst_num, NULL, NULL, dec_op_data,
                                  output_buf, kpt_wpk_idx);
        }

        if (sts != CPA_STATUS_SUCCESS) {
            WARN("Failed to submit request to qat - status = %d\n", sts);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;
            return 0;
        }

        /* wait for replies */
        do {
            if (getEnableInlinePolling())
                sts = icp_sal_CyPollInstance(qat_instance_handles[inst_num], 0);
            else
                sched_yield();
        } while (sts == CPA_STATUS_RETRY);

        if (sts != CPA_STATUS_SUCCESS) {
            WARN("Failed to poll the response - status = %d\n", sts);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;
            return 0;
        }

        DUMP_RSA_DECRYPT_OUTPUT(output_buf);
        qat_cleanup_op_done(&op_done);
        QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
        tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;
        DEBUG("- Finished\n");
        return 1;
    }

    CRYPTO_QAT_LOG("- RSA\n");
    do {
        sts = kpt_rsa_decrypt(inst_num, kpt_rsaCallbackFn, &op_done,
                              dec_op_data, output_buf, kpt_wpk_idx);
        if (sts == CPA_STATUS_RETRY) {
            tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;
            if ((qat_wake_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0) ||
                (qat_pause_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0)) {
                WARN("qat_wake_job or qat_pause_job failed\n");
                break;
            }
            tlv->kpt_wpk_in_use = kpt_wpk_idx;
        }
    }
    while (sts == CPA_STATUS_RETRY);

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", sts);
        qat_clear_async_event_notification(op_done.job);
        qat_cleanup_op_done(&op_done);
        QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
        tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;
        return 0;
    }

    if (enable_heuristic_polling) {
        QAT_ATOMIC_INC(num_asym_requests_in_flight);
    }

    do {
        tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;
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
        tlv->kpt_wpk_in_use = kpt_wpk_idx;
    }
    while (!op_done.flag || QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DUMP_RSA_DECRYPT_OUTPUT(output_buf);
    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;

    if (op_done.verifyResult != CPA_TRUE) {
        WARN("Verification of result failed\n");
        qat_cleanup_op_done(&op_done);
        return 0;
    }

    qat_cleanup_op_done(&op_done);

    DEBUG("- Finished\n");
    return 1;
}

int qat_hw_kpt_rsa_priv_enc(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding)
{
    int rsa_len = 0;
    int sts = 1, fallback = 0;
    CpaFlatBuffer *output_buffer = NULL;
# ifndef DISABLE_QAT_HW_LENSTRA_PROTECTION
    unsigned char *ver_msg = NULL;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    int lenstra_ret = 0;
# endif
    CpaCyKptRsaDecryptOpData *kpt_dec_op_data = NULL;
    int kpt_wpk_idx = KPT_INVALID_WPK_IDX;

    DEBUG("- Started.\n");

    if (qat_get_qat_offload_disabled()) {
        DEBUG("qat_get_qat_offload_disabled\n");
        return 0;
    }

    rsa_len = RSA_size(rsa);

    if (!kpt_rsa_prepare(flen, from, to, rsa, padding, &output_buffer,
                         &kpt_dec_op_data, PADDING, &kpt_wpk_idx)) {
        WARN("Failure in kpt_rsa_prepare\n");
        return 0;
    }

    if (1 != qat_hw_kpt_rsa_decrypt(kpt_dec_op_data, rsa_len, output_buffer,
                                    &fallback, kpt_wpk_idx)) {
        WARN("Failure in qat_hw_kpt_rsa_decrypt\n");
        sts = 0;
        goto exit;
    }

    memcpy(to, output_buffer->pData, rsa_len);

# ifndef DISABLE_QAT_HW_LENSTRA_PROTECTION
    /* Lenstra vulnerability protection: 
       Now call the s/w impl'n of public decrypt in order to
       verify the encrypt operation just carried out. */
    RSA_get0_key((const RSA *)rsa, &n, &e, &d);

    /* Note: not checking 'd' as it is not used */
    if (e != NULL) {
        /* then a public key exists and we can effect Lenstra attack protection */
        ver_msg = OPENSSL_zalloc(flen);
        if (ver_msg == NULL) {
            WARN("ver_msg zalloc failed.\n");
            sts = 0;
            goto exit;
        }
#  ifdef ENABLE_QAT_HW_LENSTRA_VERIFY_HW
        lenstra_ret = qat_rsa_pub_dec(rsa_len, (const unsigned char *)to,
                                      ver_msg, rsa, padding);
#  else
        lenstra_ret = RSA_meth_get_pub_dec(RSA_PKCS1_OpenSSL())
            (rsa_len, (const unsigned char *)to, ver_msg, rsa, padding);
#  endif
        if ((lenstra_ret <= 0) || (CRYPTO_memcmp(from, ver_msg, flen) != 0)) {
            WARN("- KPT RSA Sign failed - LENSTRA_PROTECTION\n");
            OPENSSL_free(ver_msg);
            return 0;
        }
        OPENSSL_free(ver_msg);
    }
# endif

    DEBUG("- Finished\n");
    return rsa_len;

 exit:
    /* Free all the memory allocated in this function */
    kpt_rsa_finish(kpt_dec_op_data, output_buffer, &kpt_wpk_idx);

    if (!sts)
        OPENSSL_cleanse(to, rsa_len);

    /* Return an error */
    return 0;
}

int qat_hw_kpt_rsa_priv_dec(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding)
{
    int rsa_len = 0;
    int output_len = -1;
    int sts = 1, fallback = 0;
    CpaFlatBuffer *output_buffer = NULL;
# ifndef DISABLE_QAT_HW_LENSTRA_PROTECTION
    unsigned char *ver_msg = NULL;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    int lenstra_ret = 0;
# endif
    CpaCyKptRsaDecryptOpData *kpt_dec_op_data = NULL;
    int kpt_wpk_idx = KPT_INVALID_WPK_IDX;

    DEBUG("- Started.\n");

    if (qat_get_qat_offload_disabled()) {
        DEBUG("qat_get_qat_offload_disabled\n");
        return 0;
    }

    rsa_len = RSA_size(rsa);

    if (!kpt_rsa_prepare(flen, from, to, rsa, padding, &output_buffer,
                         &kpt_dec_op_data, NO_PADDING, &kpt_wpk_idx)) {
        WARN("Failure in kpt_rsa_prepare\n");
        return 0;
    }

    if (1 != qat_hw_kpt_rsa_decrypt(kpt_dec_op_data, rsa_len, output_buffer,
                                    &fallback, kpt_wpk_idx)) {
        WARN("Failure in qat_hw_kpt_rsa_decrypt\n");
        sts = 0;
        goto exit;
    }
# ifndef DISABLE_QAT_HW_LENSTRA_PROTECTION
    /* Lenstra vulnerability protection: 
       Now call the s/w impl'n of public encrypt in order to
       verify the decrypt operation just carried out. */
    RSA_get0_key((const RSA *)rsa, &n, &e, &d);

    /* Note: not checking 'd' as it is not used */
    if (e != NULL) {
        /* then a public key exists and we can effect Lenstra attack protection */
        ver_msg = OPENSSL_zalloc(flen);
        if (ver_msg == NULL) {
            WARN("ver_msg zalloc failed.\n");
            sts = 0;
            goto exit;
        }
#  ifdef ENABLE_QAT_HW_LENSTRA_VERIFY_HW
        lenstra_ret = qat_rsa_pub_enc(rsa_len,
                                      (const unsigned char *)output_buffer->
                                      pData, ver_msg, rsa, RSA_NO_PADDING);
#  else
        lenstra_ret = RSA_meth_get_pub_enc(RSA_PKCS1_OpenSSL())
            (rsa_len,
             (const unsigned char *)output_buffer->pData,
             ver_msg, rsa, RSA_NO_PADDING);
#  endif
        if ((lenstra_ret <= 0) || (CRYPTO_memcmp(from, ver_msg, flen) != 0)) {
            WARN("- KPT RSA decryption failed - LENSTRA_PROTECTION\n");
            OPENSSL_free(ver_msg);
            kpt_rsa_finish(kpt_dec_op_data, output_buffer, &kpt_wpk_idx);
            return 0;
        }
        OPENSSL_free(ver_msg);
    }
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
                                         rsa_len, NULL, 0);
        break;
#ifndef QAT_OPENSSL_3
    /* RSA SSLv23 padding mode is remove in OpenSSL 3.0
     * https://github.com/openssl/openssl/issues/14283
     */
    case RSA_SSLV23_PADDING:
        output_len =
            RSA_padding_check_SSLv23(to,
                                     rsa_len,
                                     output_buffer->pData,
                                     output_buffer->dataLenInBytes, rsa_len);
        break;
#endif
    case RSA_NO_PADDING:
        output_len =
            RSA_padding_check_none(to,
                                   rsa_len,
                                   output_buffer->pData,
                                   output_buffer->dataLenInBytes, rsa_len);
        break;
    default:
        break;                  /* Do nothing as the error will be caught below. */
    }

    if (output_len < 0) {
        WARN("Failure in removing padding\n");
        sts = 0;
        goto exit;
    }

    kpt_rsa_finish(kpt_dec_op_data, output_buffer, &kpt_wpk_idx);

    DEBUG("- Finished\n");
    return output_len;

 exit:
    /* Free all the memory allocated in this function */
    kpt_rsa_finish(kpt_dec_op_data, output_buffer, &kpt_wpk_idx);

    if (!sts)
        OPENSSL_cleanse(to, rsa_len);

    /* Return an error */
    return 0;
}

/**
 *****************************************************************************
 * 
 * KPT ECDSA Sign implementation.
 *
 *****************************************************************************/

int qat_check_ec_wpk(EC_KEY *eckey)
{
    return kpt_check_ec_wpk(eckey);
}

/* Callback to indicate KPT completion of ECDSA Sign */
static void kpt_ecdsaSignCallbackFn(void *pCallbackTag, CpaStatus status,
                                    void *pOpData, CpaBoolean bEcdsaSignStatus,
                                    CpaFlatBuffer *pResultR,
                                    CpaFlatBuffer *pResultS)
{
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_asym_requests_in_flight);
    }
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, bEcdsaSignStatus);
}

ECDSA_SIG *qat_hw_kpt_ecdsa_do_sign(const unsigned char *dgst, int dgst_len,
                                    const BIGNUM *in_kinv, const BIGNUM *in_r,
                                    EC_KEY *eckey)
{
    int ok = 0, job_ret = 0;
    BN_CTX *ctx = NULL;
    ECDSA_SIG *ret = NULL;
    BIGNUM *ecdsa_sig_r = NULL, *ecdsa_sig_s = NULL;

    CpaFlatBuffer *pResultR = NULL;
    CpaFlatBuffer *pResultS = NULL;
    int inst_num = QAT_INVALID_INSTANCE;
    CpaCyKptEcdsaSignRSOpData *opData = NULL;
    CpaBoolean bEcdsaSignStatus;
    CpaStatus status;
    op_done_t op_done;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    thread_local_variables_t *tlv = NULL;
    int kpt_wpk_idx = KPT_INVALID_WPK_IDX;

    DEBUG("- Started\n");

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- QAT offload is disabled\n");
        return NULL;
    }

    if (!kpt_ecdsa_prepare(dgst, dgst_len, in_kinv, in_r, eckey, &ctx, &ret,
                           &pResultR, &pResultS, &ecdsa_sig_r, &ecdsa_sig_s,
                           &opData, &kpt_wpk_idx)) {
        WARN("Failure in kpt_ecdsa_prepare\n");
        return NULL;
    }

    /* perform ECDSA sign */

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        goto err;
    }

    tlv->kpt_wpk_in_use = kpt_wpk_idx;
    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (qat_kill_thread(qat_timer_poll_func_thread, SIGUSR1) != 0) {
                WARN("qat_kill_thread error\n");
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;
                goto err;
            }
        }
    }
    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failure to setup async event notifications\n");
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;
            goto err;
        }
    }

    CRYPTO_QAT_LOG("AU - %s\n", __func__);
    do {
        if ((inst_num =
             get_instance(QAT_INSTANCE_ASYM, QAT_INSTANCE_ANY)) ==
            QAT_INVALID_INSTANCE) {
            WARN("Failure to get another instance\n");
            if (op_done.job != NULL) {
                qat_clear_async_event_notification(op_done.job);
            }
            qat_cleanup_op_done(&op_done);
            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;
            goto err;
        }

        status = kpt_ecdsa_do_sign(inst_num, kpt_ecdsaSignCallbackFn, &op_done,
                                   opData, &bEcdsaSignStatus,
                                   pResultR, pResultS, kpt_wpk_idx);
        if (status == CPA_STATUS_RETRY) {
            if (op_done.job == NULL) {
                usleep(ulPollInterval +
                       (qatPerformOpRetries %
                        QAT_RETRY_BACKOFF_MODULO_DIVISOR));
                qatPerformOpRetries++;
                if (iMsgRetry != QAT_INFINITE_MAX_NUM_RETRIES) {
                    if (qatPerformOpRetries >= iMsgRetry) {
                        WARN("No. of retries exceeded max retry : %d\n",
                             iMsgRetry);
                        break;
                    }
                }
            } else {
                tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;
                if ((qat_wake_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0) ||
                    (qat_pause_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0)) {
                    WARN("qat_wake_job or qat_pause_job failed\n");
                    break;
                }
                tlv->kpt_wpk_in_use = kpt_wpk_idx;
            }
        }
    }
    while (status == CPA_STATUS_RETRY);

    if (status != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        if (op_done.job != NULL) {
            qat_clear_async_event_notification(op_done.job);
        }
        qat_cleanup_op_done(&op_done);
        QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
        tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;
        goto err;
    }

    if (enable_heuristic_polling) {
        QAT_ATOMIC_INC(num_asym_requests_in_flight);
    }

    do {
        if (op_done.job != NULL) {
            tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;
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
            tlv->kpt_wpk_in_use = kpt_wpk_idx;
        } else {
            sched_yield();
        }
    }
    while (!op_done.flag || QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DUMP_ECDSA_SIGN_OUTPUT(bEcdsaSignStatus, pResultR, pResultS);
    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;

    if (op_done.verifyResult != CPA_TRUE) {
        WARN("Verification of result failed\n");
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    qat_cleanup_op_done(&op_done);

    /* Convert the flatbuffer results back to a BN */
    BN_bin2bn(pResultR->pData, pResultR->dataLenInBytes, ecdsa_sig_r);
    BN_bin2bn(pResultS->pData, pResultS->dataLenInBytes, ecdsa_sig_s);

    ok = 1;

 err:
    if (!ok) {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }

    kpt_ecdsa_finish(pResultR, pResultS, opData, ctx, &kpt_wpk_idx);

    DEBUG("- Finished\n");
    return ret;
}

#endif
