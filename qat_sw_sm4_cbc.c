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
 * @file qat_sw_sm4_cbc.c
 *
 * This file contains the engine implementation for SM4-CBC operations
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
#include "qat_sw_ec.h"
#include "qat_sw_request.h"
#include "qat_sw_sm4_cbc.h"
#ifdef ENABLE_QAT_HW_SM4_CBC
#include "qat_hw_sm4_cbc.h"
#endif

/* Crypto_mb includes */
#include "crypto_mb/sm4.h"
#include "crypto_mb/cpu_features.h"

#ifdef ENABLE_QAT_SW_SM4_CBC

# define GET_SW_CIPHER(ctx) \
    sm4_cipher_sw_impl(EVP_CIPHER_CTX_nid((ctx)))

static inline const EVP_CIPHER *sm4_cipher_sw_impl(int nid)
{
    switch (nid) {
    case NID_sm4_cbc:
        return EVP_sm4_cbc();
    default:
        WARN("Invalid nid %d\n", nid);
        return NULL;
    }
}

static void process_mb_sm4_cbc_cipher_set_key(mbx_sm4_key_schedule *key_sched,
                                              const sm4_key **mb_key, int req_num)
{
    mbx_status16 sm4_cbc_sts;
    int i;

    sm4_cbc_sts = mbx_sm4_set_key_mb16(key_sched, (const sm4_key**)mb_key);
    DEBUG("QAT_SW SM4_CBC cipher set key, sm4_cbc_sts=%llu \n", sm4_cbc_sts);

    for (i = 0; i < req_num; i++) {
        if (MBX_GET_STS(sm4_cbc_sts, i) != MBX_STATUS_OK) {
            WARN("QAT_SW SM4_CBC cipher set key[%d] failure\n", i);
        }
    }
}

void process_mb_sm4_cbc_cipher_enc_reqs(mb_thread_data *tlv)
{
    sm4_cbc_cipher_op_data *sm4_cbc_cipher_req_array[MULTIBUFF_SM4_BATCH] = {0};
    int local_request_no = 0;
    int req_num = 0;
    mbx_status16 sm4_cbc_sts;
    /* MB input data */
    mbx_sm4_key_schedule key_sched __attribute__((aligned(64))) = {0};
    const sm4_key *mb_key[MULTIBUFF_SM4_BATCH] __attribute__((aligned(64))) = {0};
    const int8u *mb_iv[MULTIBUFF_SM4_BATCH] __attribute__((aligned(64))) = {0};
    int8u *mb_out[MULTIBUFF_SM4_BATCH] __attribute__((aligned(64))) = {0};
    const int8u *mb_in[MULTIBUFF_SM4_BATCH] __attribute__((aligned(64))) = {0};
    int mb_in_len[MULTIBUFF_SM4_BATCH] __attribute__((aligned(64))) = {0};

    START_RDTSC(&sm4_cbc_cycles_cipher_execute);

    /* Build Arrays of pointers for call */
    while ((sm4_cbc_cipher_req_array[req_num] =
            mb_queue_sm4_cbc_cipher_dequeue(tlv->sm4_cbc_cipher_queue)) != NULL) {
        mb_key[req_num] = &(sm4_cbc_cipher_req_array[req_num]->in_key);
        mb_iv[req_num] = sm4_cbc_cipher_req_array[req_num]->in_iv;
        mb_out[req_num] = sm4_cbc_cipher_req_array[req_num]->in_out;
        mb_in[req_num] = sm4_cbc_cipher_req_array[req_num]->in_txt;
        mb_in_len[req_num] = sm4_cbc_cipher_req_array[req_num]->in_txt_len;

        req_num++;
        if (req_num == MULTIBUFF_SM4_MIN_BATCH)
            break;
    }
    local_request_no = req_num;
    DEBUG("Submitting req_num %d SM4_CBC cipher requests\n", local_request_no);

    process_mb_sm4_cbc_cipher_set_key(&key_sched, mb_key, local_request_no);
    
    sm4_cbc_sts = mbx_sm4_encrypt_cbc_mb16(mb_out, mb_in, mb_in_len,
                                           &key_sched, mb_iv);
    DEBUG("mbx_sm4_encrypt_cbc_mb16 sm4_cbc_sts=%llu \n", sm4_cbc_sts);

    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (sm4_cbc_cipher_req_array[req_num]->sts != NULL) {
             if (MBX_GET_STS(sm4_cbc_sts, req_num) == MBX_STATUS_OK) {
                 DEBUG("QAT_SW SM4_CBC cipher request[%d] success\n", req_num);
                       *sm4_cbc_cipher_req_array[req_num]->sts = 1;
             } else {
                 WARN("QAT_SW SM4_CBC cipher request[%d] failure\n", req_num);
                      *sm4_cbc_cipher_req_array[req_num]->sts = 0;
             }
        }

        if (sm4_cbc_cipher_req_array[req_num]->job) {
            qat_wake_job(sm4_cbc_cipher_req_array[req_num]->job, ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(sm4_cbc_cipher_req_array[req_num], sizeof(sm4_cbc_cipher_op_data));
        mb_flist_sm4_cbc_cipher_push(tlv->sm4_cbc_cipher_freelist,
                                     sm4_cbc_cipher_req_array[req_num]);
    }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
    mb_sm4_cbc_cipher_req_rates.req_this_period += local_request_no;
# endif
    STOP_RDTSC(&sm4_cbc_cycles_cipher_execute, 1, "[SM4_CBC:cipher_execute]");
    DEBUG("Processed SM4_CBC cipher Request\n");
}

void process_mb_sm4_cbc_cipher_dec_reqs(mb_thread_data *tlv)
{
    sm4_cbc_cipher_op_data *sm4_cbc_cipher_req_array[MULTIBUFF_SM4_BATCH] = {0};
    int local_request_no = 0;
    int req_num = 0;
    mbx_status16 sm4_cbc_sts;
    /* MB input data */
    mbx_sm4_key_schedule key_sched __attribute__((aligned(64)));
    const sm4_key *mb_key[MULTIBUFF_SM4_BATCH] __attribute__((aligned(64))) = {0};
    const int8u *mb_iv[MULTIBUFF_SM4_BATCH] __attribute__((aligned(64))) = {0};
    int8u *mb_out[MULTIBUFF_SM4_BATCH] __attribute__((aligned(64))) = {0};
    const int8u *mb_in[MULTIBUFF_SM4_BATCH] __attribute__((aligned(64))) = {0};
    int mb_in_len[MULTIBUFF_SM4_BATCH] __attribute__((aligned(64))) = {0};

    START_RDTSC(&sm4_cbc_cycles_cipher_dec_execute);

    /* Build Arrays of pointers for call */
    while ((sm4_cbc_cipher_req_array[req_num] =
            mb_queue_sm4_cbc_cipher_dequeue(tlv->sm4_cbc_cipher_dec_queue)) != NULL) {
        mb_key[req_num] = &(sm4_cbc_cipher_req_array[req_num]->in_key);
        mb_iv[req_num] = sm4_cbc_cipher_req_array[req_num]->in_iv;
        mb_out[req_num] = sm4_cbc_cipher_req_array[req_num]->in_out;
        mb_in[req_num] = sm4_cbc_cipher_req_array[req_num]->in_txt;
        mb_in_len[req_num] = sm4_cbc_cipher_req_array[req_num]->in_txt_len;

        req_num++;
        if (req_num == MULTIBUFF_SM4_MIN_BATCH)
            break;
    }
    local_request_no = req_num;
    DEBUG("Submitting req_num %d SM4_CBC cipher requests\n", local_request_no);

    process_mb_sm4_cbc_cipher_set_key(&key_sched, mb_key, local_request_no);

    sm4_cbc_sts = mbx_sm4_decrypt_cbc_mb16(mb_out, mb_in, mb_in_len,
                                           &key_sched, mb_iv);
    DEBUG("mbx_sm4_decrypt_cbc_mb16 sts=%llu \n", sm4_cbc_sts);

    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (sm4_cbc_cipher_req_array[req_num]->sts != NULL) {
             if (MBX_GET_STS(sm4_cbc_sts, req_num) == MBX_STATUS_OK) {
                 DEBUG("QAT_SW SM4_CBC cipher request[%d] success\n", req_num);
                       *sm4_cbc_cipher_req_array[req_num]->sts = 1;
             } else {
                 WARN("QAT_SW SM4_CBC cipher request[%d] failure\n", req_num);
                      *sm4_cbc_cipher_req_array[req_num]->sts = 0;
             }
        }

        if (sm4_cbc_cipher_req_array[req_num]->job) {
            qat_wake_job(sm4_cbc_cipher_req_array[req_num]->job, ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(sm4_cbc_cipher_req_array[req_num], sizeof(sm4_cbc_cipher_op_data));
        mb_flist_sm4_cbc_cipher_push(tlv->sm4_cbc_cipher_dec_freelist,
                                     sm4_cbc_cipher_req_array[req_num]);
    }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
    mb_sm4_cbc_cipher_dec_req_rates.req_this_period += local_request_no;
# endif
    STOP_RDTSC(&sm4_cbc_cycles_cipher_dec_execute, 1, "[SM4_CBC:cipher_dec_execute]");
    DEBUG("Processed SM4_CBC cipher decryption Request\n");
}

int qat_sw_sm4_cbc_key_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                   const unsigned char *iv, int enc)
{
    SM4_CBC_CTX *sm4_cbc_ctx = NULL;
    void *sw_ctx_cipher_data = NULL;
    int sts = 0;
#ifdef ENABLE_QAT_HW_SM4_CBC
    sm4cbc_coexistence_ctx *sm4cbc_hw_sw_ctx = NULL;
#endif

    DEBUG("started: ctx=%p key=%p iv=%p enc=%d\n", ctx, key, iv, enc);

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_CIPHER_CTX) is NULL \n");
        QATerr(QAT_F_QAT_SW_SM4_CBC_KEY_INIT, QAT_R_CTX_NULL);
        return sts;
    }
#ifdef ENABLE_QAT_HW_SM4_CBC
    if (qat_sm4_cbc_coexist) {
        sm4cbc_hw_sw_ctx = (sm4cbc_coexistence_ctx *)(EVP_CIPHER_CTX_get_cipher_data(ctx));
        sm4_cbc_ctx = &(sm4cbc_hw_sw_ctx->sm4cbc_qat_sw_ctx);
    } else {
        sm4_cbc_ctx = (SM4_CBC_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    }
#else
    sm4_cbc_ctx = (SM4_CBC_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
#endif
    if (sm4_cbc_ctx == NULL) {
        WARN("SM4-CBC CTX is NULL\n");
        QATerr(QAT_F_QAT_SW_SM4_CBC_KEY_INIT, QAT_R_CIPHER_DATA_NULL);
        return sts;
    }
    sm4_cbc_ctx->enc = enc;

    if (key == NULL) {
        WARN("SM4-CBC key is NULL \n");
        QATerr(QAT_F_QAT_SW_SM4_CBC_KEY_INIT, QAT_R_KEY_NULL);
        return sts;
    } else {
        DEBUG("qat_sw_sm4_cbc_key_init: save key=%p parameter for later use key_len=%u\n",
               key, SM4_KEY_SIZE);
        memmove(sm4_cbc_ctx->key, key, SM4_KEY_SIZE);
    }

    if (iv) {
        DEBUG("qat_sw_sm4_cbc_key_init: save iv=%p parameter for later use\n", iv);
        memmove(sm4_cbc_ctx->iv, iv, SM4_IV_LEN);
        sm4_cbc_ctx->iv_set = 1;
    }

    /* cipher context init, used by sw_fallback */
    sw_ctx_cipher_data = OPENSSL_zalloc(sizeof(EVP_SM4_KEY));
    if (sw_ctx_cipher_data == NULL) {
        QATerr(QAT_F_QAT_SW_SM4_CBC_KEY_INIT, QAT_R_MALLOC_FAILURE);
        WARN("Unable to allocate memory for sw_ctx_cipher_data.\n");
        return sts;
    }

    EVP_CIPHER_CTX_set_cipher_data(ctx, sw_ctx_cipher_data);
    sts = EVP_CIPHER_meth_get_init(GET_SW_CIPHER(ctx))(ctx, key, iv, enc);
    if (sts != 1) {
        QATerr(QAT_F_QAT_SW_SM4_CBC_KEY_INIT, QAT_R_FALLBACK_INIT_FAILURE);
        WARN("Failed to init the openssl sw cipher context.\n");
        return sts;
    }
    sm4_cbc_ctx->sw_ctx_cipher_data = sw_ctx_cipher_data;
#ifdef ENABLE_QAT_HW_SM4_CBC
    if (qat_sm4_cbc_coexist) {
        EVP_CIPHER_CTX_set_cipher_data(ctx, sm4cbc_hw_sw_ctx);
    } else {
        EVP_CIPHER_CTX_set_cipher_data(ctx, sm4_cbc_ctx);
    }
#else
    EVP_CIPHER_CTX_set_cipher_data(ctx, sm4_cbc_ctx);
#endif
    /* Save key in ctx and return, key_init will be done in cipher operation. */
    return sts;
}

int qat_sw_sm4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    int sts = 0, job_ret = 0;
    ASYNC_JOB *job;
    sm4_cbc_cipher_op_data *sm4_cbc_cipher_req = NULL;
    SM4_CBC_CTX *sm4_cbc_ctx = NULL;
    void *sw_ctx_cipher_data = NULL;
    mb_thread_data *tlv = NULL;
    static __thread int req_num = 0;
    int8u *in_iv = NULL;
    sm4_key *in_key = NULL;
    int in_enc;
#ifdef ENABLE_QAT_HW_SM4_CBC
    sm4cbc_coexistence_ctx *sm4cbc_hw_sw_ctx = NULL;
#endif

    DEBUG("Started: ctx=%p out=%p in=%p len=%lu\n", ctx, out, in, len);

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_CIPHER_CTX) is NULL \n");
        QATerr(QAT_F_QAT_SW_SM4_CBC_CIPHER, QAT_R_CTX_NULL);
        return sts;
    }

#ifdef ENABLE_QAT_HW_SM4_CBC
    if (qat_sm4_cbc_coexist) {
        sm4cbc_hw_sw_ctx = (sm4cbc_coexistence_ctx *)(EVP_CIPHER_CTX_get_cipher_data(ctx));
        sm4_cbc_ctx = &(sm4cbc_hw_sw_ctx->sm4cbc_qat_sw_ctx);
    } else {
        sm4_cbc_ctx = (SM4_CBC_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    }
#else
    sm4_cbc_ctx = (SM4_CBC_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
#endif

    if (sm4_cbc_ctx == NULL) {
        WARN("SM4-CBC CTX is NULL\n");
        QATerr(QAT_F_QAT_SW_SM4_CBC_CIPHER, QAT_R_CIPHER_DATA_NULL);
        return sts;
    }

    in_key = &sm4_cbc_ctx->key;
    in_enc = sm4_cbc_ctx->enc;
    if (!sm4_cbc_ctx->iv_set)
        in_iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    else
        in_iv = sm4_cbc_ctx->iv;

#ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    if (len <=
        qat_pkt_threshold_table_get_threshold(EVP_CIPHER_CTX_nid(ctx)))
        goto use_sw_method;
#endif

    if (fallback_to_openssl)
        goto use_sw_method;

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
        WARN("Could not create thread local variables\n");
        goto use_sw_method;
    }

    if (in_enc) {
        while ((sm4_cbc_cipher_req =
                mb_flist_sm4_cbc_cipher_pop(tlv->sm4_cbc_cipher_freelist)) == NULL) {
            qat_wake_job(job, ASYNC_STATUS_EAGAIN);
            qat_pause_job(job, ASYNC_STATUS_EAGAIN);
        }
    }
    else { /* decryption */
        while ((sm4_cbc_cipher_req =
                mb_flist_sm4_cbc_cipher_pop(tlv->sm4_cbc_cipher_dec_freelist)) == NULL) {
            qat_wake_job(job, ASYNC_STATUS_EAGAIN);
            qat_pause_job(job, ASYNC_STATUS_EAGAIN);
        }
    }

    DEBUG("QAT SW SM4_CBC cipher Started %p\n", sm4_cbc_cipher_req);
    START_RDTSC(&sm4_cbc_cycles_cipher_setup);
    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */
    sm4_cbc_cipher_req->job = job;
    sm4_cbc_cipher_req->sts = &sts;
    sm4_cbc_cipher_req->in_enc = in_enc;
    memmove(sm4_cbc_cipher_req->in_key, *in_key, sizeof(sm4_key));
    memmove(sm4_cbc_cipher_req->in_iv, in_iv, SM4_IV_LEN);
    sm4_cbc_cipher_req->in_txt = in;
    sm4_cbc_cipher_req->in_txt_len = len;
    sm4_cbc_cipher_req->in_out = out;

    if (in_enc)
        mb_queue_sm4_cbc_cipher_enqueue(tlv->sm4_cbc_cipher_queue, sm4_cbc_cipher_req);
    else
        mb_queue_sm4_cbc_cipher_enqueue(tlv->sm4_cbc_cipher_dec_queue, sm4_cbc_cipher_req);

    STOP_RDTSC(&sm4_cbc_cycles_cipher_setup, 1, "[SM4_CBC:cipher_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_SM4_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (sem_post(&tlv->mb_polling_thread_sem) != 0) {
            WARN("hw sem_post failed!, mb_polling_thread_sem address: %p.\n",
                  &tlv->mb_polling_thread_sem);
            /* If we fail the pthread_kill carry on as the timeout
               will catch processing the request in the polling thread */
        }
     }

    DEBUG("Pausing: %p status = %d \n", sm4_cbc_cipher_req, sts);
    do {
        /* If we get a failure on qat_pause_job then we will
           not flag an error here and quit because we have
           an asynchronous request in flight.
           We don't want to start cleaning up data
           structures that are still being used. If
           qat_pause_job fails we will just yield and
           loop around and try again until the request
           completes and we can continue. */
        if ((job_ret = qat_pause_job(job, ASYNC_STATUS_OK)) == 0)
            sched_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));
    DEBUG("Finished: cipher %p status = %d\n", sm4_cbc_cipher_req, sts);
    num_sm4_cbc_sw_cipher_reqs++;
    return sts;

use_sw_method:
    sw_ctx_cipher_data = sm4_cbc_ctx->sw_ctx_cipher_data;
    if (!sw_ctx_cipher_data)
        goto err;

    EVP_CIPHER_CTX_set_cipher_data(ctx, sw_ctx_cipher_data);
    sts = EVP_CIPHER_meth_get_do_cipher(GET_SW_CIPHER(ctx))(ctx, out, in, len);
#ifdef ENABLE_QAT_HW_SM4_CBC
    if (qat_sm4_cbc_coexist) {
        EVP_CIPHER_CTX_set_cipher_data(ctx, sm4cbc_hw_sw_ctx);
    } else {
        EVP_CIPHER_CTX_set_cipher_data(ctx, sm4_cbc_ctx);
    }
#else
    EVP_CIPHER_CTX_set_cipher_data(ctx, sm4_cbc_ctx);
#endif

err:
    return sts;
}

int qat_sw_sm4_cbc_cleanup(EVP_CIPHER_CTX *ctx)
{
    int sts = 0;
    SM4_CBC_CTX *sm4_cbc_ctx = NULL;
    void *sw_ctx_cipher_data = NULL;
#ifdef ENABLE_QAT_HW_SM4_CBC
    sm4cbc_coexistence_ctx *sm4cbc_hw_sw_ctx = NULL;
#endif

    DEBUG("Started: ctx=%p\n", ctx);

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_CIPHER_CTX) is NULL \n");
        QATerr(QAT_F_QAT_SW_SM4_CBC_CLEANUP, QAT_R_CTX_NULL);
        return sts;
    }

#ifdef ENABLE_QAT_HW_SM4_CBC
    if (qat_sm4_cbc_coexist) {
        sm4cbc_hw_sw_ctx = (sm4cbc_coexistence_ctx *)(EVP_CIPHER_CTX_get_cipher_data(ctx));
        sm4_cbc_ctx = &(sm4cbc_hw_sw_ctx->sm4cbc_qat_sw_ctx);
    } else {
        sm4_cbc_ctx = (SM4_CBC_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    }
#else
    sm4_cbc_ctx = (SM4_CBC_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
#endif
    if (sm4_cbc_ctx == NULL) {
        WARN("SM4-CBC CTX is NULL\n");
        QATerr(QAT_F_QAT_SW_SM4_CBC_CLEANUP, QAT_R_CIPHER_DATA_NULL);
        return sts;
    }

    sw_ctx_cipher_data = sm4_cbc_ctx->sw_ctx_cipher_data;
    if (sw_ctx_cipher_data)
        OPENSSL_free(sw_ctx_cipher_data);

    sts = 1;
    return sts;
}
#endif
