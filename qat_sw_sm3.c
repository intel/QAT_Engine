/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020-2022 Intel Corporation.
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
 * @file qat_sw_sm3.c
 *
 * This file contains the engine implementation for SM3 QAT_SW operations
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

/* Local includes */
#include "e_qat.h"
#include "qat_utils.h"
#include "qat_events.h"
#include "qat_fork.h"
#include "qat_sw_sm3.h"
#include "qat_sw_request.h"

/* Crypto_mb includes */
#include "crypto_mb/sm3.h"

#ifdef ENABLE_QAT_SW_SM3
# ifdef DISABLE_QAT_SW_SM3
#  undef DISABLE_QAT_SW_SM3
# endif
#endif

/* SM3 nid */
int sm3_nid[] = {
    NID_sm3,
};

void process_sm3_init_reqs(mb_thread_data *tlv)
{
    sm3_init_op_data *sm3_init_req_array[MULTIBUFF_SM3_BATCH] = {0};
    SM3_CTX_mb16 *sm3_init_ctx = NULL;
    unsigned int sm3_sts = 0;
    int local_request_no = 0;
    int req_num = 0;

    START_RDTSC(&sm3_cycles_init_execute);

    /* Build Arrays of pointers for call */
    while ((sm3_init_req_array[req_num] =
            mb_queue_sm3_init_dequeue(tlv->sm3_init_queue)) != NULL) {
        sm3_init_ctx = sm3_init_req_array[req_num]->state;
        req_num++;
        if (req_num == MULTIBUFF_SM3_MIN_BATCH)
            break;
    }
    local_request_no = req_num;
    DEBUG("Submitting %d SM3 init requests\n", local_request_no);

    sm3_sts = mbx_sm3_init_mb16(sm3_init_ctx);

    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (sm3_init_req_array[req_num]->sts != NULL) {
             if (MBX_GET_STS(sm3_sts, req_num) == MBX_STATUS_OK) {
                 DEBUG("QAT_SW SM3 init request[%d] success\n", req_num);
                 *sm3_init_req_array[req_num]->sts = 1;
             } else {
                 WARN("QAT_SW SM3 init request[%d] failure\n", req_num);
                 *sm3_init_req_array[req_num]->sts = 0;
             }
        }

        if (sm3_init_req_array[req_num]->job) {
            qat_wake_job(sm3_init_req_array[req_num]->job, ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(sm3_init_req_array[req_num],
                        sizeof(sm3_init_op_data));
        mb_flist_sm3_init_push(tlv->sm3_init_freelist,
                                    sm3_init_req_array[req_num]);
    }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
    mb_sm3_init_req_rates.req_this_period += local_request_no;
# endif

    STOP_RDTSC(&sm3_cycles_init_execute, 1, "[SM3:init_execute]");
    DEBUG("Processed Final Request\n");
}

void process_sm3_update_reqs(mb_thread_data *tlv)
{
    sm3_update_op_data *sm3_update_req_array[MULTIBUFF_SM3_BATCH] = {0};
    SM3_CTX_mb16* sm3_update_ctx = NULL;
    int    sm3_data_len[MULTIBUFF_SM3_BATCH] = {0};
    int8u* sm3_data[MULTIBUFF_SM3_BATCH] = {0};
    unsigned int sm3_sts = 0;
    int local_request_no = 0;
    int req_num = 0;

    START_RDTSC(&sm3_cycles_update_execute);

    /* Build Arrays of pointers for call */
    while ((sm3_update_req_array[req_num] =
            mb_queue_sm3_update_dequeue(tlv->sm3_update_queue)) != NULL) {
        sm3_data_len[req_num] = sm3_update_req_array[req_num]->sm3_len;
        sm3_data[req_num] = (int8u *)sm3_update_req_array[req_num]->sm3_data;
        sm3_update_ctx = sm3_update_req_array[req_num]->state;

        req_num++;
        if (req_num == MULTIBUFF_SM3_MIN_BATCH)
            break;
    }
    local_request_no = req_num;
    DEBUG("Submitting %d SM3 Update requests\n", local_request_no);

    sm3_sts = mbx_sm3_update_mb16((const int8u **)sm3_data,
                                  sm3_data_len,
                                  sm3_update_ctx);

    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (MBX_GET_STS(sm3_sts, req_num) == MBX_STATUS_OK) {
            DEBUG("QAT_SW SM3 Update request[%d] success\n", req_num);
            *sm3_update_req_array[req_num]->sts = 1;
        } else {
            WARN("QAT_SW SM3 Update request[%d] Failure\n", req_num);
            *sm3_update_req_array[req_num]->sts = 0;
        }

        if (sm3_update_req_array[req_num]->job) {
            qat_wake_job(sm3_update_req_array[req_num]->job, ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(sm3_update_req_array[req_num],
                        sizeof(sm3_update_op_data));
        mb_flist_sm3_update_push(tlv->sm3_update_freelist,
                                    sm3_update_req_array[req_num]);
    }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
    mb_sm3_update_req_rates.req_this_period += local_request_no;
# endif

    STOP_RDTSC(&sm3_cycles_update_execute, 1, "[SM3:update_execute]");
    DEBUG("Processed Final Request\n");
}

void process_sm3_final_reqs(mb_thread_data *tlv)
{
    sm3_final_op_data *sm3_final_req_array[MULTIBUFF_SM3_BATCH] = {0};
    SM3_CTX_mb16 *sm3_final_ctx = NULL;
    int8u* sm3_hash[MULTIBUFF_SM3_BATCH] = {0};

    unsigned int sm3_sts = 0;
    int local_request_no = 0;
    int req_num = 0;

    START_RDTSC(&sm3_cycles_final_execute);

    /* Build Arrays of pointers for call */
    while ((sm3_final_req_array[req_num] =
            mb_queue_sm3_final_dequeue(tlv->sm3_final_queue)) != NULL) {
        sm3_hash[req_num] = (int8u *) sm3_final_req_array[req_num]->sm3_hash;
        sm3_final_ctx = sm3_final_req_array[req_num]->state;

        req_num++;
        if (req_num == MULTIBUFF_SM3_MIN_BATCH)
            break;
    }
    local_request_no = req_num;
    DEBUG("Submitting %d SM3 Final requests\n", local_request_no);

    sm3_sts = mbx_sm3_final_mb16(sm3_hash,
                             sm3_final_ctx);

    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (MBX_GET_STS(sm3_sts, req_num) == MBX_STATUS_OK) {
            DEBUG("QAT_SW SM3 Final request[%d] success\n", req_num);
            *sm3_final_req_array[req_num]->sts = 1;
        } else {
            WARN("QAT_SW SM3 Final request[%d] Failure\n", req_num);
            *sm3_final_req_array[req_num]->sts = 0;
        }

        if (sm3_final_req_array[req_num]->job) {
            qat_wake_job(sm3_final_req_array[req_num]->job, ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(sm3_final_req_array[req_num],
                        sizeof(sm3_final_op_data));
        mb_flist_sm3_final_push(tlv->sm3_final_freelist,
                                    sm3_final_req_array[req_num]);
    }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
    mb_sm3_final_req_rates.req_this_period += local_request_no;
# endif

    STOP_RDTSC(&sm3_cycles_final_execute, 1, "[SM3:final_execute]");
    DEBUG("Processed Final Request\n");
}

int qat_sw_sm3_init(EVP_MD_CTX *ctx)
{
    ASYNC_JOB *job;
    int sts = 0, job_ret = 0;
    sm3_init_op_data *sm3_init_req = NULL;
    int (*sw_fn_ptr)(EVP_MD_CTX *) = NULL;
    mb_thread_data *tlv = NULL;
    static __thread int req_num = 0;

    /* Check input parameters */
    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL.\n");
        QATerr(QAT_F_QAT_SW_SM3_INIT, QAT_R_CTX_NULL);
        return sts;
    }

    qat_sw_sm3_ctx *sm3_ctx = (qat_sw_sm3_ctx *) EVP_MD_CTX_md_data(ctx);
    if (unlikely(sm3_ctx == NULL)) {
        WARN("sm3_ctx (type qat_sw_sm3_ctx) is NULL.\n");
        QATerr(QAT_F_QAT_SW_SM3_INIT, QAT_R_CTX_NULL);
        return sts;
    }
    /* Check if we are running asynchronously. If not use the SW method */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(0)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    tlv = mb_check_thread_local();
    if (NULL == tlv) {
        WARN("Could not create thread local variables\n");
        goto use_sw_method;
    }

    while ((sm3_init_req =
            mb_flist_sm3_init_pop(tlv->sm3_init_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("QAT SW SM3 Init Started %p\n", sm3_init_req);
    START_RDTSC(&sm3_cycles_init_setup);

    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */
    sm3_ctx->sm3_state = OPENSSL_secure_malloc(sizeof(SM3_CTX_mb16));
    sm3_init_req->state = sm3_ctx->sm3_state;
    sm3_init_req->job = job;
    sm3_init_req->sts = &sts;
    mb_queue_sm3_init_enqueue(tlv->sm3_init_queue, sm3_init_req);
    STOP_RDTSC(&sm3_cycles_init_setup, 1, "[SM3:init_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_SM3_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (qat_kill_thread(tlv->polling_thread, SIGUSR1) != 0) {
            WARN("qat_kill_thread error\n");
            /* If we fail the pthread_kill carry on as the timeout
               will catch processing the request in the polling thread */
        }
     }

    DEBUG("Pausing: %p status = %d\n", sm3_init_req, sts);
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
            pthread_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("Finished: %p status = %d\n", sm3_init_req, sts);

    if (sts) {
        return sts;
    } else {
        WARN("Failure in Keygen\n");
        QATerr(QAT_F_QAT_SW_SM3_INIT, QAT_R_KEYGEN_FAILURE);
        goto err;
    }

err:
    if (sts == 0) {
        if (NULL != sm3_ctx->sm3_state) {
            OPENSSL_secure_free(sm3_ctx->sm3_state);
            sm3_ctx->sm3_state = NULL;
        }
    }
    return sts;

use_sw_method:

    sw_fn_ptr = EVP_MD_meth_get_init((EVP_MD *)EVP_sm3());
    sts = (*sw_fn_ptr)(ctx);
    DEBUG("SW Finished\n");
    return sts;

}

int qat_sw_sm3_update(EVP_MD_CTX *ctx, const void *in, size_t len)
{
    ASYNC_JOB *job;
    int sts = 0, job_ret = 0;
    sm3_update_op_data *sm3_update_req = NULL;
    int (*sw_fn_ptr)(EVP_MD_CTX *, const void *, size_t) = NULL;
    mb_thread_data *tlv = NULL;
    static __thread int req_num = 0;

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_MD_CTX) is NULL.\n");
        QATerr(QAT_F_QAT_SW_SM3_UPDATE, QAT_R_CTX_NULL);
        return 0;
    }

    qat_sw_sm3_ctx *sm3_ctx = (qat_sw_sm3_ctx *) EVP_MD_CTX_md_data(ctx);
    if (unlikely(sm3_ctx == NULL)) {
        WARN("sm3_ctx (type qat_sw_sm3_ctx) is NULL.\n");
        QATerr(QAT_F_QAT_SW_SM3_UPDATE, QAT_R_CTX_NULL);
        return sts;
    }

    /* Check if we are running asynchronously. If not use the SW method */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(0)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    tlv = mb_check_thread_local();
    if (NULL == tlv) {
        WARN("Could not create thread local variables\n");
        goto use_sw_method;
    }

    while ((sm3_update_req =
            mb_flist_sm3_update_pop(tlv->sm3_update_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("QAT SW SM3 Update Started %p\n", sm3_update_req);
    START_RDTSC(&sm3_cycles_update_setup);

    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */
    sm3_update_req->sm3_data = (int8u **)in;
    sm3_update_req->sm3_len = len;
    sm3_update_req->state = sm3_ctx->sm3_state;
    sm3_update_req->job = job;
    sm3_update_req->sts = &sts;

    mb_queue_sm3_update_enqueue(tlv->sm3_update_queue, sm3_update_req);
    STOP_RDTSC(&sm3_cycles_update_setup, 1, "[SM3:update_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_SM3_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (qat_kill_thread(tlv->polling_thread, SIGUSR1) != 0) {
            WARN("qat_kill_thread error\n");
            /* If we fail the pthread_kill carry on as the timeout
               will catch processing the request in the polling thread */
        }
     }

    DEBUG("Pausing: %p status = %d\n", sm3_update_req, sts);
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
            pthread_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("Finished: %p status = %d\n", sm3_update_req, sts);

    if (sts) {
       return sts;
    } else {
        WARN("Failure in update\n");
        QATerr(QAT_F_QAT_SW_SM3_UPDATE, QAT_R_DERIVE_FAILURE);
        return sts;
    }

use_sw_method:
    sw_fn_ptr = EVP_MD_meth_get_update((EVP_MD *)EVP_sm3());
    sts = (*sw_fn_ptr)(ctx, in, len);
    DEBUG("SW Finished\n");
    return sts;
}

int qat_sw_sm3_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    ASYNC_JOB *job;
    int sts = 0, job_ret = 0;
    sm3_final_op_data *sm3_final_req = NULL;
    int (*sw_fn_ptr)(EVP_MD_CTX *, unsigned char *) = NULL;
    mb_thread_data *tlv = NULL;
    static __thread int req_num = 0;

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL.\n");
        QATerr(QAT_F_QAT_SW_SM3_FINAL, QAT_R_CTX_NULL);
        return 0;
    }

    qat_sw_sm3_ctx *sm3_ctx = (qat_sw_sm3_ctx *) EVP_MD_CTX_md_data(ctx);
    if (unlikely(sm3_ctx == NULL)) {
        WARN("sm3_ctx (type qat_sw_sm3_ctx) is NULL.\n");
        QATerr(QAT_F_QAT_SW_SM3_FINAL, QAT_R_CTX_NULL);
        return sts;
    }

    /* Check if we are running asynchronously. If not use the SW method */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(0)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    tlv = mb_check_thread_local();
    if (NULL == tlv) {
        WARN("Could not create thread local variables\n");
        goto use_sw_method;
    }

    while ((sm3_final_req =
            mb_flist_sm3_final_pop(tlv->sm3_final_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("QAT SW SM3 Final Started %p\n", sm3_final_req);
    START_RDTSC(&sm3_cycles_final_setup);

    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */
    sm3_final_req->sm3_hash = (int8u **)md;
    sm3_final_req->state = sm3_ctx->sm3_state;
    sm3_final_req->job = job;
    sm3_final_req->sts = &sts;

    mb_queue_sm3_final_enqueue(tlv->sm3_final_queue, sm3_final_req);
    STOP_RDTSC(&sm3_cycles_final_setup, 1, "[SM3:final_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_SM3_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (qat_kill_thread(tlv->polling_thread, SIGUSR1) != 0) {
            WARN("qat_kill_thread error\n");
            /* If we fail the pthread_kill carry on as the timeout
               will catch processing the request in the polling thread */
        }
     }

    DEBUG("Pausing: %p status = %d\n", sm3_final_req, sts);
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
            pthread_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("Finished: %p status = %d\n", sm3_final_req, sts);

    if (sts) {
       return sts;
    } else {
        WARN("Failure in update\n");
        QATerr(QAT_F_QAT_SW_SM3_FINAL, QAT_R_DERIVE_FAILURE);
        return sts;
    }

use_sw_method:
    sw_fn_ptr = EVP_MD_meth_get_final((EVP_MD *)EVP_sm3());
    sts = (*sw_fn_ptr)(ctx, md);
    DEBUG("SW Finished\n");
    return sts;
}
