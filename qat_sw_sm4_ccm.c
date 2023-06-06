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
 * @file qat_sw_sm4_ccm.c
 *
 * This file contains the engine implementation of SM4 CCM operations for
 * QAT SW
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define __USE_GNU

#include <pthread.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/* Local includes */
#include "e_qat.h"
#include "qat_utils.h"
#include "qat_events.h"
#include "qat_fork.h"
#include "qat_evp.h"
#include "qat_sw_request.h"
#include "qat_sw_sm4_ccm.h"

/* Crypto_mb includes */
#ifdef ENABLE_QAT_SW_SM4_CCM
 #include "crypto_mb/sm4_ccm.h"
#endif
#include "crypto_mb/cpu_features.h"

#ifdef ENABLE_QAT_SW_SM4_CCM

# define GET_SW_CIPHER(ctx) \
    sm4_cipher_sw_impl(EVP_CIPHER_CTX_nid((ctx)))

static inline const EVP_CIPHER *sm4_cipher_sw_impl(int nid)
{
    switch (nid) {
    case NID_sm4_ccm:
        return EVP_sm4_ccm();
    default:
        WARN("Invalid nid %d\n", nid);
        return NULL;
    }
}

int qat_sw_sm4_ccm_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
        const unsigned char *iv, int enc)
{
    QAT_SM4_CCM_CTX *qctx = NULL;
    void *sw_ctx_cipher_data = NULL;
    int sts = 0;

    DEBUG("started: ctx=%p key=%p iv=%p enc=%d \n", ctx, key, iv, enc);

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_CIPHER_CTX) is NULL \n");
        QATerr(QAT_F_QAT_SW_SM4_CCM_INIT, QAT_R_CTX_NULL);
        return sts;
    }

    qctx = (QAT_SM4_CCM_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (qctx == NULL) {
        WARN("qctx is NULL \n");
        QATerr(QAT_F_QAT_SW_SM4_CCM_INIT, QAT_R_QCTX_NULL);
        return sts;
    }

    if (iv == NULL && key == NULL) {
        DEBUG("iv is NULL and key is NULL \n");
        return 1;
    }

    /* Allocate ccm auth tag */
    if (!qctx->tag) {
        qctx->tag = OPENSSL_zalloc(EVP_CCM_TLS_TAG_LEN);

        if (qctx->tag) {
            qctx->tag_len = EVP_CCM_TLS_TAG_LEN;
            qctx->tag_set = 0;
        } else {
            qctx->tag_len = 0;
            WARN("Failed to allocate qctx->tag \n");
            QATerr(QAT_F_QAT_SW_SM4_CCM_INIT, QAT_R_ALLOC_TAG_FAILURE);
            return sts;
        }
    }

    /* Allocate ccm calculated_tag */
    if (!qctx->calculated_tag) {
        qctx->calculated_tag = OPENSSL_zalloc(EVP_CCM_TLS_TAG_LEN);

        if (qctx->calculated_tag) {
            qctx->tag_calculated = 0;
        } else {
            qctx->tag_len = 0;
            WARN("Failed to allocate qctx->calculated_tag \n");
            QATerr(QAT_F_QAT_SW_SM4_CCM_INIT, QAT_R_ALLOC_TAG_FAILURE);
            return sts;
        }
    }

    if (qctx->iv_len <=0) {
        qctx->iv_len = QAT_SM4_CCM_OP_VALUE - qctx->L;
        DEBUG("Setting IV length = %d \n", qctx->iv_len);
    } 

    /* If we have an IV passed in and have yet to allocate memory for the IV */
    qctx->iv = OPENSSL_realloc(qctx->iv, qctx->iv_len);
    DEBUG("Reallocated IV Buffer = %p, with size %d \n",
           qctx->iv, qctx->iv_len);

    qctx->next_iv = OPENSSL_realloc(qctx->next_iv, qctx->iv_len);
    DEBUG("Reallocated Next_IV Buffer = %p, with size %d \n",
           qctx->next_iv, qctx->iv_len);

    if (key != NULL) {
        qctx->key_len = EVP_CIPHER_CTX_key_length(ctx);

        if (!qctx->key)
            qctx->key = OPENSSL_zalloc(qctx->key_len);
        DEBUG("key=%p parameter for later use key_len=%lu \n",
              key, strlen((const char *)key));
        memcpy(qctx->key, key, qctx->key_len);
        qctx->key_set = 1;
    }

    if (iv != NULL) {
        DEBUG("iv=%p parameter for later use iv_len=%lu \n",
                  iv, strlen((const char *)iv));

        if (qctx->iv) {
            DEBUG("Copying iv to qctx->iv with qctx->iv_len %d \n",
                qctx->iv_len);
            memcpy(qctx->iv, iv, QAT_SM4_CCM_OP_VALUE - qctx->L );
            memcpy(qctx->next_iv, iv, QAT_SM4_CCM_OP_VALUE - qctx->L );
            qctx->iv_set = 1;
        }
    } 

    qctx->tls_aad_len = -1;
    qctx->init_flag = 0;

    if (ASYNC_get_current_job() != NULL) {
       qctx->init_flag = 1;
    } else {
        if (!qctx->sw_ctx_cipher_data) {
            /* cipher context init, used by sw_fallback */
            sw_ctx_cipher_data = OPENSSL_zalloc(sizeof(EVP_SM4_CCM_CTX));
            if (sw_ctx_cipher_data == NULL) {
                QATerr(QAT_F_QAT_SW_SM4_CCM_INIT, QAT_R_MALLOC_FAILURE);
                WARN("Unable to allocate memory for sw_ctx_cipher_data.\n");
                return sts;
            }
            qctx->sw_ctx_cipher_data = sw_ctx_cipher_data;
        }

        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
        sts = EVP_CIPHER_meth_get_init(GET_SW_CIPHER(ctx))(ctx, key, iv, enc);

        if (sts != 1) {
            QATerr(QAT_F_QAT_SW_SM4_CCM_INIT, QAT_R_FALLBACK_INIT_FAILURE);
            WARN("Failed to init the openssl sw cipher context.\n");
        }
        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
    }

    return 1;
}

static int qat_sw_sm4_ccm_encrypt(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                    const unsigned char *in, size_t len)
{
    QAT_SM4_CCM_CTX *qctx = NULL;
    void *sw_ctx_cipher_data = NULL;
    int sts = 0, job_ret = 0;
    ASYNC_JOB *job;
    sm4_ccm_encrypt_op_data *sm4_ccm_encrypt_req = NULL;
    mb_thread_data *tlv = NULL;
    static __thread int req_num = 0;
    int init_flag = 0;

    DEBUG("started: ctx=%p out=%p in=%p len=%lu \n", ctx, out, in, len);

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_CIPHER_CTX) is NULL \n");
        QATerr(QAT_F_QAT_SW_SM4_CCM_ENCRYPT, QAT_R_CTX_NULL);
        return sts;
    }

    qctx = (QAT_SM4_CCM_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (qctx == NULL) {
        WARN("qctx is NULL \n");
        QATerr(QAT_F_QAT_SW_SM4_CCM_ENCRYPT, QAT_R_QCTX_NULL);
        return sts;
    }

    init_flag = qctx->init_flag;

    /* Check if we are running asynchronously. If not use the SW method */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method \n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(job)) {
        DEBUG("Failed to setup async notifications, using sw method \n");
        goto use_sw_method;
    }

    tlv = mb_check_thread_local();
    if (NULL == tlv) {
        WARN("Could not create thread local variables \n");
        goto use_sw_method;
    }

    while ((sm4_ccm_encrypt_req =
            mb_flist_sm4_ccm_encrypt_pop(tlv->sm4_ccm_encrypt_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("QAT SW SM4_CCM encrypt Started %p \n", sm4_ccm_encrypt_req);
    START_RDTSC(&sm4_ccm_cycles_encrypt_setup);
    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */
    sm4_ccm_encrypt_req->state = &qctx->mb_ccmctx;
    sm4_ccm_encrypt_req->job = job;
    sm4_ccm_encrypt_req->sts = &sts;
    sm4_ccm_encrypt_req->sm4_in = in;
    sm4_ccm_encrypt_req->sm4_len = len;
    sm4_ccm_encrypt_req->sm4_out = out;
    sm4_ccm_encrypt_req->sm4_key = (sm4_key *)qctx->key;
    sm4_ccm_encrypt_req->sm4_iv = qctx->iv;
    sm4_ccm_encrypt_req->sm4_ivlen = qctx->iv_len;
    sm4_ccm_encrypt_req->sm4_tag = qctx->tag;
    sm4_ccm_encrypt_req->sm4_taglen = qctx->tag_len;
    sm4_ccm_encrypt_req->sm4_msglen = qctx->msg_len;
    if (qctx->init_flag == 1) {
        sm4_ccm_encrypt_req->sm4_aad = qctx->tls_aad;
        sm4_ccm_encrypt_req->sm4_aadlen = qctx->aad_len;
    }
    sm4_ccm_encrypt_req->init_flag = init_flag;
    mb_queue_sm4_ccm_encrypt_enqueue(tlv->sm4_ccm_encrypt_queue, sm4_ccm_encrypt_req);
    STOP_RDTSC(&sm4_ccm_cycles_encrypt_setup, 1, "[SM4_CCM:encrypt_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_SM4_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (sem_post(&tlv->mb_polling_thread_sem) != 0) {
            WARN("hw sem_post failed!, mb_polling_thread_sem address: %p.\n",
                  &tlv->mb_polling_thread_sem);
            /* If we fail the pthread_kill carry on as the timeout
             * will catch processing the request in the polling thread */
        }
    }

    DEBUG("Pausing: %p status = %d sm4ctx %p \n",
          sm4_ccm_encrypt_req, sts, sm4_ccm_encrypt_req->state);
    do {
        /* If we get a failure on qat_pause_job then we will
           not flag an error here and quit because we have
           an asynchronous request in flight.
           We don't want to start cleaning up data
           structures that are still being used. If
           qat_pause_job fails we will just yield and
           loop around and try again until the request
           completes and we can continue. */
        if ((job_ret = qat_pause_job(job, ASYNC_STATUS_OK)) == 0) {
            sched_yield();
        }
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    qctx->init_flag = 1;
    DEBUG("Finished: Encrypt %p status = %d \n", sm4_ccm_encrypt_req, sts);
    if (sts) {
       return sts;
    } else {
       WARN("Failure in SM4_CCM encrypt \n");
       return sts;
    }

use_sw_method:
    sw_ctx_cipher_data = qctx->sw_ctx_cipher_data;
    if (!sw_ctx_cipher_data)
        goto err;

    EVP_CIPHER_CTX_set_cipher_data(ctx, sw_ctx_cipher_data);
    sts = EVP_CIPHER_meth_get_do_cipher(GET_SW_CIPHER(ctx))(ctx, out, in, len);

    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
    DEBUG("SW Encryption Finished sts=%d\n", sts);

err:
    return sts;

}

static int qat_sw_sm4_ccm_decrypt(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                    const unsigned char *in, size_t len)
{

    QAT_SM4_CCM_CTX *qctx = NULL;
    void *sw_ctx_cipher_data = NULL;
    int sts = 0, job_ret = 0;
    ASYNC_JOB *job;
    sm4_ccm_decrypt_op_data *sm4_ccm_decrypt_req = NULL;
    mb_thread_data *tlv = NULL;
    static __thread int req_num = 0;
    int init_flag = 0;

    DEBUG("started: ctx=%p out=%p in=%p len=%lu \n", ctx, out, in, len);

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_CIPHER_CTX) is NULL \n");
        QATerr(QAT_F_QAT_SW_SM4_CCM_DECRYPT, QAT_R_CTX_NULL);
        return sts;
    }

    qctx = (QAT_SM4_CCM_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (qctx == NULL) {
        WARN("qctx is NULL \n");
        QATerr(QAT_F_QAT_SW_SM4_CCM_DECRYPT, QAT_R_QCTX_NULL);
        return sts;
    }

    init_flag = qctx->init_flag;

    /* Check if we are running asynchronously. If not use the SW method */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(job)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    tlv = mb_check_thread_local();
    if (NULL == tlv) {
        WARN("Could not create thread local variables \n");
        goto use_sw_method;
    }

    while ((sm4_ccm_decrypt_req =
            mb_flist_sm4_ccm_decrypt_pop(tlv->sm4_ccm_decrypt_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("QAT SW SM4_CCM cipher_decrypt Started %p", sm4_ccm_decrypt_req);
    START_RDTSC(&sm4_ccm_cycles_decrypt_setup);
    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */
    sm4_ccm_decrypt_req->state = &qctx->mb_ccmctx;
    sm4_ccm_decrypt_req->job = job;
    sm4_ccm_decrypt_req->sts = &sts;
    sm4_ccm_decrypt_req->sm4_in = in;
    sm4_ccm_decrypt_req->sm4_len = len;
    sm4_ccm_decrypt_req->sm4_out = out;
    sm4_ccm_decrypt_req->sm4_key = (sm4_key *)qctx->key;
    sm4_ccm_decrypt_req->sm4_iv = qctx->iv;
    sm4_ccm_decrypt_req->sm4_ivlen = qctx->iv_len;
    sm4_ccm_decrypt_req->sm4_tag = qctx->calculated_tag;
    sm4_ccm_decrypt_req->sm4_taglen = qctx->tag_len;
    sm4_ccm_decrypt_req->sm4_msglen = qctx->msg_len;
    if (qctx->init_flag == 1) {
        sm4_ccm_decrypt_req->sm4_aad = qctx->tls_aad;
        sm4_ccm_decrypt_req->sm4_aadlen = qctx->aad_len;
    }
    sm4_ccm_decrypt_req->init_flag = init_flag;
    mb_queue_sm4_ccm_decrypt_enqueue(tlv->sm4_ccm_decrypt_queue, sm4_ccm_decrypt_req);
    STOP_RDTSC(&sm4_ccm_cycles_decrypt_setup, 1, "[SM4_CCM:decrypt_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_SM4_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d \n", req_num);
        if (sem_post(&tlv->mb_polling_thread_sem) != 0) {
            WARN("hw sem_post failed!, mb_polling_thread_sem address: %p.\n",
                  &tlv->mb_polling_thread_sem);
            /* If we fail the pthread_kill carry on as the timeout
             * will catch processing the request in the polling thread */
        }
    }

    DEBUG("Pausing: %p status = %d sm4ctx %p \n",
          sm4_ccm_decrypt_req, sts, sm4_ccm_decrypt_req->state);
    do {
        /* If we get a failure on qat_pause_job then we will
           not flag an error here and quit because we have
           an asynchronous request in flight.
           We don't want to start cleaning up data
           structures that are still being used. If
           qat_pause_job fails we will just yield and
           loop around and try again until the request
           completes and we can continue. */
        if ((job_ret = qat_pause_job(job, ASYNC_STATUS_OK)) == 0) {
            sched_yield();
        }
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));
    DEBUG("Finished: Decrypt %p status = %d \n", sm4_ccm_decrypt_req, sts);
    qctx->init_flag = 1;

    if (sts) {
       return sts;
    } else {
       WARN("Failure in SM4_CCM decrypt \n");
       QATerr(QAT_F_QAT_SW_SM4_CCM_DECRYPT, QAT_R_SM4_CCM_DECRYPT_FAILURE);
       return sts;
    }

use_sw_method:
    sw_ctx_cipher_data = qctx->sw_ctx_cipher_data;
    if (!sw_ctx_cipher_data)
        goto err;

    EVP_CIPHER_CTX_set_cipher_data(ctx, sw_ctx_cipher_data);
    sts = EVP_CIPHER_meth_get_do_cipher(GET_SW_CIPHER(ctx))(ctx, out, in, len);

    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
    DEBUG("SW Decryption Finished sts=%d\n", sts);

err:
    return sts;
}

int qat_sw_sm4_ccm_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
        const unsigned char *in, size_t len)
{
    QAT_SM4_CCM_CTX *qctx = NULL;
    void *sw_ctx_cipher_data = NULL;
    int sts = 0;
    int enc = 0;
    unsigned char *out_text = NULL;

    DEBUG("started: ctx=%p out=%p in=%p len=%lu\n", ctx, out, in, len);

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_CIPHER_CTX) is NULL \n");
        QATerr(QAT_F_QAT_SW_SM4_CCM_DO_CIPHER, QAT_R_CTX_NULL);
        return sts;
    }

    qctx = (QAT_SM4_CCM_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (qctx == NULL) {
        WARN("qctx is NULL\n");
        QATerr(QAT_F_QAT_SW_SM4_CCM_DO_CIPHER, QAT_R_QCTX_NULL);
        return sts;
    }

    if (fallback_to_openssl)
        goto use_sw_method;

    if (ASYNC_get_current_job() == NULL) {
        DEBUG("SW Cipher Offload Started\n");
        goto use_sw_method;
    }

    if (!qctx->key_set) {
        WARN("key_set is not set \n");
        QATerr(QAT_F_QAT_SW_SM4_CCM_DO_CIPHER, QAT_R_KEY_NOTSET);
        return -1 ;
    }

    if ((in == NULL ) && (out != NULL)) {
        DEBUG("in is NULL while out is not NULL \n");
        return sts;
    }

    if (!qctx->iv_set) {
        WARN("iv_set is not set \n");
        QATerr(QAT_F_QAT_SW_SM4_CCM_DO_CIPHER, QAT_R_IV_NOTSET);
        return -1;
    }

    if (out == NULL) { 
        if (in == NULL) {
            memcpy(qctx->iv, qctx->next_iv, QAT_SM4_CCM_OP_VALUE - qctx->L);
            qctx->iv_len = QAT_SM4_CCM_OP_VALUE - qctx->L;
            qctx->msg_len = len;
            qctx->len_set = 1;
            return len;
        }

        /* If have AAD need message length */
        if (!qctx->len_set && len){
            WARN("Message length is not set \n");
            QATerr(QAT_F_QAT_SW_SM4_CCM_DO_CIPHER, QAT_R_MSGLEN_NOTSET);
            return -1;
        }

        qctx->tls_aad = OPENSSL_zalloc(len);
        if (qctx->tls_aad == NULL) {
            WARN("Failed to allocate qctx->aad\n");
            QATerr(QAT_F_QAT_SW_SM4_CCM_DO_CIPHER, QAT_R_MALLOC_FAILURE);
            return sts;
        }
        memcpy(qctx->tls_aad, in, len);
        qctx->aad_len = len;
        return len;
    }

    enc = EVP_CIPHER_CTX_encrypting(ctx);

    /* The tag must be set before actually decrypting data */
    if (!enc && !qctx->tag_set) {
        WARN("tag_set is not set \n");
        QATerr(QAT_F_QAT_SW_SM4_CCM_DO_CIPHER, QAT_R_TAG_NOTSET);
        return -1;
    }

    /* If not set length yet do it */
    if (!qctx->len_set) {
        memcpy(qctx->iv, qctx->next_iv, QAT_SM4_CCM_OP_VALUE - qctx->L);
        qctx->iv_len = QAT_SM4_CCM_OP_VALUE - qctx->L;
        qctx->len_set = 1;
    }

    if (enc) {
        qctx->msg_len = len;
        qctx->tag_set = 1;
        sts = qat_sw_sm4_ccm_encrypt(ctx, out, in, len);
        sts = 1;
    } else {
        qctx->tag_calculated = 1;
        out_text = OPENSSL_zalloc(len);
        qctx->msg_len = len;
        sts = qat_sw_sm4_ccm_decrypt(ctx, out_text, in, len);
        memcpy(out, out_text, len);
        if (qctx->tag_set) {
            if (memcmp(qctx->calculated_tag, qctx->tag, qctx->tag_len) == 0){
               DEBUG("Decrypt - CCM tag comparison success \n");
               sts = 1;
            } else{
                WARN("SM4-CCM calculated tag comparison failed \n");
                DUMPL("Expected   Tag:", (const unsigned char *)qctx->tag, qctx->tag_len);
                DUMPL("Calculated Tag:", (const unsigned char *)qctx->calculated_tag, qctx->tag_len);
                DUMPL("Decrypt - Calculated Tag",
                     (const unsigned char*)qctx->calculated_tag , qctx->tag_len);
                sts = -1;
            }
        }
        qctx->iv_set = 0;
        qctx->tag_set = 0;
        qctx->len_set = 0;
        qctx->msg_len = 0;
    }

    if (sts == 1)
        sts = len;
    if(sts == -1)
        OPENSSL_free(out_text);
    return sts;

use_sw_method:

    sw_ctx_cipher_data = qctx->sw_ctx_cipher_data;
    if (!sw_ctx_cipher_data)
        goto err;

    EVP_CIPHER_CTX_set_cipher_data(ctx, sw_ctx_cipher_data);
    sts = EVP_CIPHER_meth_get_do_cipher(GET_SW_CIPHER(ctx))(ctx, out, in, len);

    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
    DEBUG("SW Offload Finished sts=%d\n", sts);
err:
    return sts;
}

void process_mb_sm4_ccm_encrypt_reqs(mb_thread_data *tlv)
{
    sm4_ccm_encrypt_op_data *sm4_ccm_encrypt_req_array[MULTIBUFF_SM4_BATCH] = {0};
    SM4_CCM_CTX_mb16 sm4_ccm_ctx;
    int8u *sm4_data_out[MULTIBUFF_SM4_BATCH] = {0};
    const int8u *sm4_data_in[MULTIBUFF_SM4_BATCH] = {0};
    int sm4_data_len[MULTIBUFF_SM4_BATCH] = {0};
    const sm4_key *sm4_data_key[MULTIBUFF_SM4_BATCH] = {0};
    const int8u *sm4_data_iv[MULTIBUFF_SM4_BATCH] = {0};
    int sm4_data_ivlen[MULTIBUFF_SM4_BATCH] = {0};
    int64u sm4_data_msglen[MULTIBUFF_SM4_BATCH] = {0};    
    int8u *sm4_data_tag[MULTIBUFF_SM4_BATCH] = {0};
    int sm4_data_taglen[MULTIBUFF_SM4_BATCH] = {0};
    const int8u *sm4_data_aad[MULTIBUFF_SM4_BATCH] = {0};
    int sm4_data_aadlen[MULTIBUFF_SM4_BATCH] = {0};
    int sm4_init_flag[MULTIBUFF_SM4_BATCH] = {0};
    int local_request_no = 0;
    int req_num = 0;
    unsigned int sm4_ccm_sts = 0;

    START_RDTSC(&sm4_ccm_cycles_encrypt_execute);

    /* Build Arrays of pointers for call */
    while ((sm4_ccm_encrypt_req_array[req_num] =
            mb_queue_sm4_ccm_encrypt_dequeue(tlv->sm4_ccm_encrypt_queue)) != NULL) {
        sm4_init_flag[req_num] = sm4_ccm_encrypt_req_array[req_num]->init_flag;
        sm4_data_in[req_num] = sm4_ccm_encrypt_req_array[req_num]->sm4_in;
        sm4_data_len[req_num] = sm4_ccm_encrypt_req_array[req_num]->sm4_len;
        sm4_data_out[req_num] = sm4_ccm_encrypt_req_array[req_num]->sm4_out;
        sm4_data_key[req_num] = sm4_ccm_encrypt_req_array[req_num]->sm4_key;
        sm4_data_iv[req_num] = sm4_ccm_encrypt_req_array[req_num]->sm4_iv;
        sm4_data_ivlen[req_num] = sm4_ccm_encrypt_req_array[req_num]->sm4_ivlen;
        sm4_data_tag[req_num] = sm4_ccm_encrypt_req_array[req_num]->sm4_tag;
        sm4_data_taglen[req_num] = sm4_ccm_encrypt_req_array[req_num]->sm4_taglen;
        sm4_data_msglen[req_num] = sm4_ccm_encrypt_req_array[req_num]->sm4_msglen;
        if (sm4_init_flag[0] == 1) {
            sm4_data_aad[req_num] = sm4_ccm_encrypt_req_array[req_num]->sm4_aad;
            sm4_data_aadlen[req_num] = sm4_ccm_encrypt_req_array[req_num]->sm4_aadlen;
        }
        req_num++;

        if (req_num == MULTIBUFF_SM4_MIN_BATCH)
            break;
    }
    local_request_no = req_num;
    DEBUG("Submitting req_num %d SM4_CCM encrypt requests \n", local_request_no);

    START_RDTSC(&sm4_ccm_cycles_init_execute);
    mbx_sm4_ccm_init_mb16(sm4_data_key,
                        sm4_data_iv, sm4_data_ivlen, sm4_data_taglen, sm4_data_msglen, &sm4_ccm_ctx);
    STOP_RDTSC(&sm4_ccm_cycles_init_execute, 1, "[SM4_CCM:init_execute]");
    
    if (sm4_init_flag[0] == 1) {
    START_RDTSC(&sm4_ccm_cycles_update_aad_execute);
        mbx_sm4_ccm_update_aad_mb16(sm4_data_aad,
                   sm4_data_aadlen, &sm4_ccm_ctx);
    STOP_RDTSC(&sm4_ccm_cycles_update_aad_execute, 1, "[SM4_CCM:update_aad_execute]");
    }

    mbx_sm4_ccm_encrypt_mb16(sm4_data_out,
                       sm4_data_in, sm4_data_len, &sm4_ccm_ctx);

    START_RDTSC(&sm4_ccm_cycles_get_tag_execute);
    sm4_ccm_sts = mbx_sm4_ccm_get_tag_mb16(sm4_data_tag, sm4_data_taglen, &sm4_ccm_ctx);
    STOP_RDTSC(&sm4_ccm_cycles_get_tag_execute, 1, "[SM4_CCM:get_tag_execute]");

    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (MBX_GET_STS(sm4_ccm_sts, req_num) == MBX_STATUS_OK) {
            DEBUG("QAT_SW SM4_CCM encrypt request[%d] success \n", req_num);
            *sm4_ccm_encrypt_req_array[req_num]->sts = 1;
            sm4_ccm_encrypt_req_array[req_num]->sm4_tag = sm4_data_tag[req_num];
        } else {
            WARN("QAT_SW SM4 CCM encrypt request[%d] failure \n", req_num);
            *sm4_ccm_encrypt_req_array[req_num]->sts = 0;
            sm4_ccm_encrypt_req_array[req_num]->sm4_tag = sm4_data_tag[req_num];
        }

        if (sm4_ccm_encrypt_req_array[req_num]->job) {
            qat_wake_job(sm4_ccm_encrypt_req_array[req_num]->job, ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(sm4_ccm_encrypt_req_array[req_num], sizeof(sm4_ccm_encrypt_op_data));
        mb_flist_sm4_ccm_encrypt_push(tlv->sm4_ccm_encrypt_freelist,
                                     sm4_ccm_encrypt_req_array[req_num]);
    }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
    mb_sm4_ccm_encrypt_req_rates.req_this_period += local_request_no;
# endif
    STOP_RDTSC(&sm4_ccm_cycles_encrypt_execute, 1, "[SM4_CCM:encrypt_execute]");
    DEBUG("Processed SM4_CCM encrypt Request \n");
}

void process_mb_sm4_ccm_decrypt_reqs(mb_thread_data *tlv)
{
    sm4_ccm_decrypt_op_data *sm4_ccm_decrypt_req_array[MULTIBUFF_SM4_BATCH] = {0};
    SM4_CCM_CTX_mb16 sm4_ccm_ctx;
    int8u *sm4_data_out[MULTIBUFF_SM4_BATCH] = {0};
    const int8u *sm4_data_in[MULTIBUFF_SM4_BATCH] = {0};
    int sm4_data_len[MULTIBUFF_SM4_BATCH] = {0};
    const sm4_key *sm4_data_key[MULTIBUFF_SM4_BATCH] = {0};
    const int8u *sm4_data_iv[MULTIBUFF_SM4_BATCH] = {0};
    int sm4_data_ivlen[MULTIBUFF_SM4_BATCH] = {0};
    int8u *sm4_data_tag[MULTIBUFF_SM4_BATCH] = {0};
    int sm4_data_taglen[MULTIBUFF_SM4_BATCH] = {0};
    int64u sm4_data_msglen[MULTIBUFF_SM4_BATCH] = {0};    
    const int8u *sm4_data_aad[MULTIBUFF_SM4_BATCH] = {0};
    int sm4_data_aadlen[MULTIBUFF_SM4_BATCH] = {0};
    int sm4_init_flag[MULTIBUFF_SM4_BATCH] = {0};
    int local_request_no = 0;
    int req_num = 0;
    unsigned int sm4_ccm_sts = 0;

    START_RDTSC(&sm4_ccm_cycles_decrypt_execute);

    /* Build Arrays of pointers for call */
    while ((sm4_ccm_decrypt_req_array[req_num] =
            mb_queue_sm4_ccm_decrypt_dequeue(tlv->sm4_ccm_decrypt_queue)) != NULL) {
        sm4_init_flag[req_num] = sm4_ccm_decrypt_req_array[req_num]->init_flag;
        sm4_data_in[req_num] = sm4_ccm_decrypt_req_array[req_num]->sm4_in;
        sm4_data_len[req_num] = sm4_ccm_decrypt_req_array[req_num]->sm4_len;
        sm4_data_out[req_num] = sm4_ccm_decrypt_req_array[req_num]->sm4_out;
        sm4_data_key[req_num] = sm4_ccm_decrypt_req_array[req_num]->sm4_key;
        sm4_data_iv[req_num] = sm4_ccm_decrypt_req_array[req_num]->sm4_iv;
        sm4_data_ivlen[req_num] = sm4_ccm_decrypt_req_array[req_num]->sm4_ivlen;
        sm4_data_tag[req_num] = sm4_ccm_decrypt_req_array[req_num]->sm4_tag;
        sm4_data_taglen[req_num] = sm4_ccm_decrypt_req_array[req_num]->sm4_taglen;
        sm4_data_msglen[req_num] = sm4_ccm_decrypt_req_array[req_num]->sm4_msglen;
        if (sm4_init_flag[0] == 1) {
            sm4_data_aad[req_num] = sm4_ccm_decrypt_req_array[req_num]->sm4_aad;
            sm4_data_aadlen[req_num] = sm4_ccm_decrypt_req_array[req_num]->sm4_aadlen;
        }
        req_num++;

        if (req_num == MULTIBUFF_SM4_MIN_BATCH)
            break;
    }
    local_request_no = req_num;
    DEBUG("Submitting req_num %d SM4_CCM decrypt requests \n", local_request_no);

    mbx_sm4_ccm_init_mb16(sm4_data_key,
                        sm4_data_iv, sm4_data_ivlen, sm4_data_taglen, sm4_data_msglen, &sm4_ccm_ctx);
    if (sm4_init_flag[0] == 1) {
        mbx_sm4_ccm_update_aad_mb16(sm4_data_aad,
                                   sm4_data_aadlen, &sm4_ccm_ctx);
    }
    mbx_sm4_ccm_decrypt_mb16(sm4_data_out,
                       sm4_data_in, sm4_data_len, &sm4_ccm_ctx);
    sm4_ccm_sts = mbx_sm4_ccm_get_tag_mb16(sm4_data_tag, sm4_data_taglen, &sm4_ccm_ctx);

    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (MBX_GET_STS(sm4_ccm_sts, req_num) == MBX_STATUS_OK) {
            DEBUG("QAT_SW SM4_CCM decrypt request[%d] success \n", req_num);
            *sm4_ccm_decrypt_req_array[req_num]->sts = 1;
        } else {
            WARN("QAT_SW SM4 CCM decrypt request[%d] failure \n", req_num);
            *sm4_ccm_decrypt_req_array[req_num]->sts = 0;
        }

        if (sm4_ccm_decrypt_req_array[req_num]->job) {
            qat_wake_job(sm4_ccm_decrypt_req_array[req_num]->job, ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(sm4_ccm_decrypt_req_array[req_num], sizeof(sm4_ccm_decrypt_op_data));
        mb_flist_sm4_ccm_decrypt_push(tlv->sm4_ccm_decrypt_freelist,
                                     sm4_ccm_decrypt_req_array[req_num]);
    }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
    mb_sm4_ccm_decrypt_req_rates.req_this_period += local_request_no;
# endif
    STOP_RDTSC(&sm4_ccm_cycles_decrypt_execute, 1, "[SM4_CCM:decrypt_execute]");
    DEBUG("Processed SM4_CCM decrypt Request \n");
}

int qat_sw_sm4_ccm_cleanup(EVP_CIPHER_CTX *ctx)
{

    QAT_SM4_CCM_CTX *qctx;
    void *sw_ctx_cipher_data = NULL;
    int sts = 0;

    DEBUG("started: ctx=%p \n", ctx);

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_CIPHER_CTX) is NULL \n");
        QATerr(QAT_F_QAT_SW_SM4_CCM_CLEANUP, QAT_R_CTX_NULL);
        return sts;
    }

    qctx = (QAT_SM4_CCM_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (qctx == NULL) {
        WARN("qctx is NULL \n");
        QATerr(QAT_F_QAT_SW_SM4_CCM_CLEANUP, QAT_R_QCTX_NULL);
        return sts;
    }

    if (qctx->iv != NULL) {
        DEBUG("qctx->iv_len = %d \n", qctx->iv_len);
        OPENSSL_free(qctx->iv);
        qctx->iv = NULL;
        qctx->iv_len = 0;
        qctx->iv_set = 0;
        qctx->msg_len = 0;
    }

    if (qctx->next_iv != NULL) {
        OPENSSL_free(qctx->next_iv);
        qctx->next_iv = NULL;
    }

    if (qctx->key != NULL) {
        OPENSSL_free(qctx->key);
        qctx->key = NULL;
        qctx->key_set = 0;
    }

    if (qctx->tls_aad != NULL) {
        DEBUG("qctx->tls_aad_len = %d \n", qctx->tls_aad_len);
        OPENSSL_free(qctx->tls_aad);
        qctx->tls_aad = NULL;
        qctx->tls_aad_len = -1;
        qctx->tls_aad_set = 0;
    }

    if (qctx->tag != NULL) {
        DEBUG("qctx->tag_len = %d \n", qctx->tag_len);
        OPENSSL_free(qctx->tag);
        qctx->tag = NULL;
        qctx->tag_len = 0;
        qctx->tag_set = 0;
    }

    if (qctx->calculated_tag != NULL) {
        OPENSSL_free(qctx->calculated_tag);
        qctx->calculated_tag = NULL;
        qctx->tag_calculated = 0;
    }

    sw_ctx_cipher_data = qctx->sw_ctx_cipher_data;
    if (sw_ctx_cipher_data)
        OPENSSL_free(sw_ctx_cipher_data);

    qctx->iv_set = 0;
    qctx->tag_set = 0;
    qctx->len_set = 0;
    qctx->msg_len = 0;
    
    return 1;
}

int qat_sw_sm4_ccm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    QAT_SM4_CCM_CTX *qctx;
    void *sw_ctx_cipher_data = NULL;
    int ret_val = 0;
    int enc = 0;

    DEBUG("started: ctx=%p type=%x arg=%d ptr=%p \n",
          ctx, type, arg, ptr);

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_CIPHER_CTX) is NULL \n");
        QATerr(QAT_F_QAT_SW_SM4_CCM_CTRL, QAT_R_CTX_NULL);
        return -1;
    }

    qctx = (QAT_SM4_CCM_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (qctx == NULL) {
        WARN("qctx cannot be NULL \n");
        QATerr(QAT_F_QAT_SW_SM4_CCM_CTRL, QAT_R_QCTX_NULL);
        return -1;
    }

    if (ASYNC_get_current_job() == NULL ) {
        DEBUG("Inside ASYNC in CTRL \n");

       if( type == EVP_CTRL_INIT ){
            qctx->tls_aad_len = -1;
            qctx->L = QAT_SM4_CCM_L_VALUE;
            qctx->M = QAT_SM4_CCM_M_VALUE;
            qctx->iv_set = 0;
            qctx->len_set = 0;
            qctx->tag_set = 0;
            qctx->msg_len = 0;
            qctx->iv_len = 0;
        }

        if (!qctx->sw_ctx_cipher_data) {
            /* cipher context init, used by sw_fallback */
            sw_ctx_cipher_data = OPENSSL_zalloc(sizeof(EVP_SM4_CCM_CTX));
            if (sw_ctx_cipher_data == NULL) {
                QATerr(QAT_F_QAT_SW_SM4_CCM_CTRL, QAT_R_MALLOC_FAILURE);
                WARN("Unable to allocate memory for sw_ctx_cipher_data.\n");
                return ret_val;
            }
            qctx->sw_ctx_cipher_data = sw_ctx_cipher_data;
        }

        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
        ret_val = EVP_CIPHER_meth_get_ctrl(GET_SW_CIPHER(ctx))(ctx, type, arg, ptr);
        if (ret_val != 1) {
            QATerr(QAT_F_QAT_SW_SM4_CCM_CTRL, QAT_R_FALLBACK_INIT_FAILURE);
            WARN("Failed to init the openssl sw cipher context.\n");
            return ret_val;
        }

        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
        return ret_val;
    }

    enc = EVP_CIPHER_CTX_encrypting(ctx);

    switch (type) {
    case EVP_CTRL_INIT:
        qctx->tls_aad_len = -1;
        qctx->L = QAT_SM4_CCM_L_VALUE;
        qctx->M = QAT_SM4_CCM_M_VALUE;
        qctx->iv_set = 0;
        qctx->len_set = 0;
        qctx->tag_set = 0;
        qctx->msg_len = 0;
        qctx->iv_len = 0;
        ret_val = 1;
        break;

    case EVP_CTRL_GET_IVLEN:
        DEBUG("CTRL Type = EVP_CTRL_GET_IVLEN, ctx = %p, type = %d,"
              " arg = %d, ptr = %p \n", (void*)ctx, type, arg, ptr);
        *(int*)ptr = QAT_SM4_CCM_OP_VALUE - qctx->L;
        qctx->iv_len = QAT_SM4_CCM_OP_VALUE - qctx->L;
        ret_val = 1;
        break;

    case EVP_CTRL_AEAD_TLS1_AAD:
        DEBUG("CTRL Type = EVP_CTRL_AEAD_TLS1_AAD, ctx = %p, type = %d,"
              " arg = %d, ptr = %p \n", (void*)ctx, type, arg, ptr);

        if (arg != EVP_AEAD_TLS1_AAD_LEN) {
            WARN("AAD Length not valid %d \n", arg);
            ret_val = 0;
            break;
        }

        /* Check to see if tls_aad already allocated with correct size,
         * if so, reuse and save ourselves a free and malloc */
        if ((qctx->tls_aad_len == EVP_AEAD_TLS1_AAD_LEN) && qctx->tls_aad){
            memcpy(qctx->tls_aad, ptr, arg);
        } else {
            if (qctx->tls_aad) {
                OPENSSL_free(qctx->tls_aad);
                qctx->tls_aad_len = -1;
                qctx->tls_aad_set = 0;
            }

            qctx->tls_aad_len = EVP_AEAD_TLS1_AAD_LEN;

            qctx->tls_aad = OPENSSL_malloc(qctx->tls_aad_len);
            if (qctx->tls_aad) {
                /* Copy the header from payload into the buffer */
                memcpy(qctx->tls_aad, ptr, qctx->tls_aad_len);
            } else {
                WARN("AAD alloc failed \n");
                QATerr(QAT_F_QAT_SW_SM4_CCM_CTRL, QAT_R_MALLOC_FAILURE);
                ret_val = 0;
                break;
            }
        }

        /* Extract the length of the payload from the TLS header */
        unsigned int plen = qctx->tls_aad[arg - QAT_SM4_TLS_PAYLOADLENGTH_MSB_OFFSET]
                            << QAT_BYTE_SHIFT |
                            qctx->tls_aad[arg - QAT_SM4_TLS_PAYLOADLENGTH_LSB_OFFSET];

        /* Correct length for explicit IV */
        if (plen < EVP_CCM_TLS_EXPLICIT_IV_LEN)
            return 0;

        /* The payload contains the explicit IV -> correct the length */
        plen -= EVP_CCM_TLS_EXPLICIT_IV_LEN;

        /* If decrypting correct for tag too */
        if (!enc) {
            if (plen < qctx->M)
                return 0;
            plen -= qctx->M;
        }

        /* Fix the length like in the SW version of SM4 */
        qctx->tls_aad[EVP_AEAD_TLS1_AAD_LEN - QAT_SM4_TLS_PAYLOADLENGTH_MSB_OFFSET] =
            plen >> QAT_BYTE_SHIFT;
        qctx->tls_aad[EVP_AEAD_TLS1_AAD_LEN - QAT_SM4_TLS_PAYLOADLENGTH_LSB_OFFSET] =
            plen & 0xff;
        qctx->tls_aad_set = 1;

        ret_val = qctx->M;
        break;

    case EVP_CTRL_AEAD_SET_IVLEN:
        DEBUG("CTRL Type = EVP_CTRL_AEAD_SET_IVLEN, ctx = %p, type = %d,"
              " arg = %d, ptr = %p \n", (void*)ctx, type, arg, ptr);

        if (arg <= 0) {
            WARN("Invalid IV length provided\n");
            QATerr(QAT_F_QAT_SW_SM4_CCM_CTRL, QAT_R_INVALID_IVLEN);
            ret_val = 0;
            break;
        }
        arg = QAT_SM4_CCM_OP_VALUE - arg;

    /* fall thru */
    case EVP_CTRL_CCM_SET_L:
        DEBUG("CTRL Type = EVP_CTRL_CCM_SET_L, ctx = %p, type = %d,"
              " arg = %d, ptr = %p\n", (void*)ctx, type, arg, ptr);

        if(arg < 2 || arg > 8) {
            WARN("L value is out of expected range, L = %d\n", arg);
            QATerr(QAT_F_QAT_SW_SM4_CCM_CTRL, QAT_R_INVALID_L);
            ret_val = 0;
            break;
        }

        qctx->L = arg;
        ret_val = 1;
        break;

    case EVP_CTRL_CCM_SET_IV_FIXED:
        DEBUG("CTRL Type = EVP_CTRL_CCM_SET_IV_FIXED, ctx = %p, type = %d,"
              " arg = %d, ptr = %p \n", (void*)ctx, type, arg, ptr);

        if (arg != EVP_CCM_TLS_FIXED_IV_LEN) {
            WARN("IV length is not currently supported, iv_len = %d \n", arg);
            QATerr(QAT_F_QAT_SW_SM4_CCM_CTRL, QAT_R_INVALID_IVLEN);
            ret_val = 0;
            break;
        }

        if (!qctx->iv) {
            qctx->iv = OPENSSL_zalloc(arg);
            if (qctx->iv == NULL) {
                WARN("Failed to allocate %d bytes \n", arg);
                QATerr(QAT_F_QAT_SW_SM4_CCM_CTRL, QAT_R_IV_ALLOC_FAILURE);
                qctx->iv_len = 0;
                ret_val      = 0;
                break;
            } else {
                qctx->iv_len = arg;
            }
        }

        if (arg) {
            memcpy(qctx->iv, ptr, arg);
        }

        ret_val = 1;
        break;

    case EVP_CTRL_AEAD_SET_TAG:
        DEBUG("CTRL Type = EVP_CTRL_AEAD_SET_TAG, ctx = %p, type = %d,"
              " arg = %d, ptr = %p , enc =%d \n", (void*)ctx, type, arg, ptr, enc);

        DUMPL(" EVP_CTRL_AEAD_SET_TAG  ptr:", (void *)ptr, arg);

        if ((arg & 1) || arg <= 4 || arg > QAT_SM4_TAG_MAX_LEN) {
            WARN("Bad input parameters \n");
            QATerr(QAT_F_QAT_SW_SM4_CCM_CTRL, QAT_R_BAD_INPUT_PARAMS);
                ret_val = 0;
                break;
        }

        if (enc && ptr) {
            WARN("Bad input parameters \n");
            QATerr(QAT_F_QAT_SW_SM4_CCM_CTRL, QAT_R_BAD_INPUT_PARAMS);
            ret_val = 0;
            break;
        }

        if (qctx->tag) {
            OPENSSL_free(qctx->tag);
            qctx->tag = NULL;
        }

        if (ptr) {
            qctx->tag = OPENSSL_zalloc(arg);
            if (qctx->tag) {
                memcpy(qctx->tag, ptr, arg);
                qctx->tag_set = 1;
                qctx->tag_len = arg;
                DUMPL(" EVP_CTRL_AEAD_SET_TAG  Tag:", (const unsigned char *)qctx->tag, qctx->tag_len);
            } else {
                WARN("Tag alloc failure \n");
                QATerr(QAT_F_QAT_SW_SM4_CCM_CTRL, QAT_R_ALLOC_TAG_FAILURE);
            }
        }

        qctx->M = arg;
        ret_val = 1;
        break;

    case EVP_CTRL_AEAD_GET_TAG:
        DEBUG("CTRL Type = EVP_CTRL_AEAD_GET_TAG, ctx = %p, type = %d,"
              " arg = %d, ptr = %p, enc = %d \n", (void*)ctx, type, arg, ptr, enc);

        if ( !enc || ( ptr == NULL )) {
            WARN("Bad input parameters \n");
            QATerr(QAT_F_QAT_SW_SM4_CCM_CTRL, QAT_R_INVALID_TAG_LEN);
            ret_val = 0;
            break;
        }

        if (!qctx->tag_set ) {
            WARN("Tag not set \n");
            ret_val = 0;
            break;
        }

        memcpy(ptr, qctx->tag, arg);
        DEBUG("CTRL Type = EVP_CTRL_AEAD_GET_TAG, the tag is = %p \n", qctx->tag);

        qctx->iv_set = 0;
        qctx->len_set = 0;
        qctx->tag_set = 0;
        qctx->msg_len = 0;
        qctx->iv_len = 0;
        ret_val = 1;
        break;

    default:
        WARN("Invalid type %d \n", type);
        ret_val = -1;
        break;
    }
    return ret_val;
}
#endif
