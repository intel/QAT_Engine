/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020-2023 Intel Corporation.
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

/* SM3 nid */
int sm3_nid[] = {
    NID_sm3,
};

void process_sm3_init_reqs(mb_thread_data *tlv)
{
    sm3_init_op_data *sm3_init_req_array[MULTIBUFF_SM3_BATCH] = {0};
    SM3_CTX_mb16 sm3_init_ctx = {0};
    unsigned int sm3_sts = 0;
    int local_request_no = 0;
    int req_num = 0, i = 0;

    START_RDTSC(&sm3_cycles_init_execute);

    /* Build Arrays of pointers for call */
    while ((sm3_init_req_array[req_num] =
            mb_queue_sm3_init_dequeue(tlv->sm3_init_queue)) != NULL) {
        req_num++;
        if (req_num == MULTIBUFF_SM3_MIN_BATCH)
            break;
    }
    local_request_no = req_num;
    DEBUG("Submitting %d SM3 init requests\n", local_request_no);

    sm3_sts = mbx_sm3_init_mb16(&sm3_init_ctx);

    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (sm3_init_req_array[req_num]->sts != NULL) {
             if (MBX_GET_STS(sm3_sts, req_num) == MBX_STATUS_OK) {
                 DEBUG("QAT_SW SM3 init request[%d] success\n", req_num);
                 *sm3_init_req_array[req_num]->sts = 1;
                 /* sm3_init_ctx->msg_buff_idx, msg_len and msg_buffer as it
                  * will be initialized to zero in cryto_mb as well */
                 /* Copying only msg_hash as crypto_mb initializes it to
                  * default hash values as per std instead of zero */
                 for (i=0; i < SM3_SIZE_IN_WORDS; i++)
                     sm3_init_req_array[req_num]->state->msg_hash[i] = sm3_init_ctx.msg_hash[i][req_num];
             } else {
                 WARN("QAT_SW SM3 init request[%d] failure\n", req_num);
                 *sm3_init_req_array[req_num]->sts = 0;
             }
        }

        if (sm3_init_req_array[req_num]->job) {
            qat_wake_job(sm3_init_req_array[req_num]->job, ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(sm3_init_req_array[req_num], sizeof(sm3_init_op_data));
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
    int  sm3_data_len[MULTIBUFF_SM3_BATCH] = {0};
    const unsigned char *sm3_data[MULTIBUFF_SM3_BATCH] = {0};
    SM3_CTX_mb16 sm3_update_ctx = {0};
    unsigned int sm3_sts = 0;
    int local_request_no = 0;
    int req_num = 0, i = 0;

    START_RDTSC(&sm3_cycles_update_execute);

    /* Build Arrays of pointers for call */
    while ((sm3_update_req_array[req_num] =
            mb_queue_sm3_update_dequeue(tlv->sm3_update_queue)) != NULL) {
        sm3_data_len[req_num] = sm3_update_req_array[req_num]->sm3_len;
        sm3_data[req_num] = sm3_update_req_array[req_num]->sm3_data;
        sm3_update_ctx.msg_buff_idx[req_num] = sm3_update_req_array[req_num]->state->msg_buff_idx;
        sm3_update_ctx.msg_len[req_num] = sm3_update_req_array[req_num]->state->msg_len;
        memcpy(sm3_update_ctx.msg_buffer[req_num], sm3_update_req_array[req_num]->state->msg_buffer,
               SM3_MSG_BLOCK_SIZE);
        for (i = 0; i < SM3_SIZE_IN_WORDS; i++)
            sm3_update_ctx.msg_hash[i][req_num] = sm3_update_req_array[req_num]->state->msg_hash[i];

        req_num++;
        if (req_num == MULTIBUFF_SM3_MIN_BATCH)
            break;
    }
    local_request_no = req_num;
    DEBUG("Submitting %d SM3 Update requests\n", local_request_no);

    sm3_sts = mbx_sm3_update_mb16(sm3_data,
                                  sm3_data_len,
                                  &sm3_update_ctx);

    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (MBX_GET_STS(sm3_sts, req_num) == MBX_STATUS_OK) {
            DEBUG("QAT_SW SM3 Update request[%d] success\n", req_num);
            *sm3_update_req_array[req_num]->sts = 1;
            sm3_update_req_array[req_num]->state->msg_buff_idx = sm3_update_ctx.msg_buff_idx[req_num];
            sm3_update_req_array[req_num]->state->msg_len = sm3_update_ctx.msg_len[req_num];
            memcpy(sm3_update_req_array[req_num]->state->msg_buffer, sm3_update_ctx.msg_buffer[req_num],
                   SM3_MSG_BLOCK_SIZE);
            for (i = 0; i < SM3_SIZE_IN_WORDS; i++)
                sm3_update_req_array[req_num]->state->msg_hash[i] = sm3_update_ctx.msg_hash[i][req_num];
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
    int8u *sm3_hash[MULTIBUFF_SM3_BATCH] = {0};
    SM3_CTX_mb16 sm3_final_ctx = {0};
    unsigned int sm3_sts = 0;
    int local_request_no = 0;
    int req_num = 0, i = 0;

    START_RDTSC(&sm3_cycles_final_execute);

    /* Build Arrays of pointers for call */
    while ((sm3_final_req_array[req_num] =
            mb_queue_sm3_final_dequeue(tlv->sm3_final_queue)) != NULL) {
        sm3_hash[req_num] = sm3_final_req_array[req_num]->sm3_hash;
        sm3_final_ctx.msg_buff_idx[req_num] = sm3_final_req_array[req_num]->state->msg_buff_idx;
        sm3_final_ctx.msg_len[req_num] = sm3_final_req_array[req_num]->state->msg_len;
        memcpy(sm3_final_ctx.msg_buffer[req_num], sm3_final_req_array[req_num]->state->msg_buffer,
               SM3_MSG_BLOCK_SIZE);
        for (i = 0; i < SM3_SIZE_IN_WORDS; i++)
            sm3_final_ctx.msg_hash[i][req_num] = sm3_final_req_array[req_num]->state->msg_hash[i];

        req_num++;
        if (req_num == MULTIBUFF_SM3_MIN_BATCH)
            break;
    }
    local_request_no = req_num;
    DEBUG("Submitting %d SM3 Final requests\n", local_request_no);

    sm3_sts = mbx_sm3_final_mb16(sm3_hash, &sm3_final_ctx);

    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (MBX_GET_STS(sm3_sts, req_num) == MBX_STATUS_OK) {
            DEBUG("QAT_SW SM3 Final request[%d] success\n", req_num);
            *sm3_final_req_array[req_num]->sts = 1;
            sm3_final_req_array[req_num]->state->msg_buff_idx = sm3_final_ctx.msg_buff_idx[req_num];
            sm3_final_req_array[req_num]->state->msg_len = sm3_final_ctx.msg_len[req_num];
            memcpy(sm3_final_req_array[req_num]->state->msg_buffer,sm3_final_ctx.msg_buffer[req_num],
                   SM3_MSG_BLOCK_SIZE);
            for (i = 0; i < SM3_SIZE_IN_WORDS; i++)
                sm3_final_req_array[req_num]->state->msg_hash[i] = sm3_final_ctx.msg_hash[i][req_num];
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

    SM3_CTX_mb *sm3_ctx = (SM3_CTX_mb *) EVP_MD_CTX_md_data(ctx);
    if (unlikely(sm3_ctx == NULL)) {
        WARN("sm3_ctx (type SM3_CTX_mb) is NULL.\n");
        QATerr(QAT_F_QAT_SW_SM3_INIT, QAT_R_CTX_NULL);
        return sts;
    }
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

    while ((sm3_init_req =
            mb_flist_sm3_init_pop(tlv->sm3_init_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("QAT SW SM3 Init Started %p\n", sm3_init_req);
    START_RDTSC(&sm3_cycles_init_setup);

    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */
    sm3_init_req->state = sm3_ctx;
    sm3_init_req->job = job;
    sm3_init_req->sts = &sts;
    mb_queue_sm3_init_enqueue(tlv->sm3_init_queue, sm3_init_req);
    STOP_RDTSC(&sm3_cycles_init_setup, 1, "[SM3:init_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_SM3_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (sem_post(&tlv->mb_polling_thread_sem) != 0) {
            WARN("hw sem_post failed!, mb_polling_thread_sem address: %p.\n",
                  &tlv->mb_polling_thread_sem);
            /* If we fail the pthread_kill carry on as the timeout
               will catch processing the request in the polling thread */
        }
     }

    DEBUG("Pausing: %p status = %d sm3_ctx %p\n", sm3_init_req, sts, sm3_init_req->state);
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

    DEBUG("Finished: %p status = %d\n", sm3_init_req, sts);

    if (sts) {
        return sts;
    } else {
        WARN("Failure in SM3 Init\n");
        QATerr(QAT_F_QAT_SW_SM3_INIT, QAT_R_SM3_INIT_FAILURE);
        return  sts;
    }

use_sw_method:
    sw_fn_ptr = EVP_MD_meth_get_init((EVP_MD *)EVP_sm3());
    sts = (*sw_fn_ptr)(ctx);
    DEBUG("SW Finished %p\n", ctx);
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

    SM3_CTX_mb *sm3_ctx = (SM3_CTX_mb *) EVP_MD_CTX_md_data(ctx);
    if (unlikely(sm3_ctx == NULL)) {
        WARN("sm3_ctx (type SM3_CTX_mb) is NULL.\n");
        QATerr(QAT_F_QAT_SW_SM3_UPDATE, QAT_R_CTX_NULL);
        return sts;
    }

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

    while ((sm3_update_req =
            mb_flist_sm3_update_pop(tlv->sm3_update_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("QAT SW SM3 Update Started %p len %zu\n", sm3_update_req, len);
    START_RDTSC(&sm3_cycles_update_setup);

    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */
    sm3_update_req->state = sm3_ctx;
    sm3_update_req->sm3_data = (const unsigned char *)in;
    sm3_update_req->sm3_len = len;
    sm3_update_req->job = job;
    sm3_update_req->sts = &sts;

    mb_queue_sm3_update_enqueue(tlv->sm3_update_queue, sm3_update_req);
    STOP_RDTSC(&sm3_cycles_update_setup, 1, "[SM3:update_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_SM3_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (sem_post(&tlv->mb_polling_thread_sem) != 0) {
            WARN("hw sem_post failed!, mb_polling_thread_sem address: %p.\n",
                  &tlv->mb_polling_thread_sem);
            /* If we fail the pthread_kill carry on as the timeout
               will catch processing the request in the polling thread */
        }
     }

    DEBUG("Pausing: %p status = %d sm3_ctx %p\n", sm3_update_req, sts, sm3_update_req->state);
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

    DEBUG("Finished: %p status = %d\n", sm3_update_req, sts);

    if (sts) {
       return sts;
    } else {
        WARN("Failure in SM3 Update\n");
        QATerr(QAT_F_QAT_SW_SM3_UPDATE, QAT_R_SM3_UPDATE_FAILURE);
        return sts;
    }

use_sw_method:
    sw_fn_ptr = EVP_MD_meth_get_update((EVP_MD *)EVP_sm3());
    sts = (*sw_fn_ptr)(ctx, in, len);
    DEBUG("SW Finished %p\n", ctx);
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

    SM3_CTX_mb *sm3_ctx = (SM3_CTX_mb *) EVP_MD_CTX_md_data(ctx);
    if (unlikely(sm3_ctx == NULL)) {
        WARN("sm3_ctx (type SM3_CTX_mb) is NULL.\n");
        QATerr(QAT_F_QAT_SW_SM3_FINAL, QAT_R_CTX_NULL);
        return sts;
    }

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

    while ((sm3_final_req =
            mb_flist_sm3_final_pop(tlv->sm3_final_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("QAT SW SM3 final Started %p\n", sm3_final_req);
    START_RDTSC(&sm3_cycles_final_setup);

    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */
    sm3_final_req->state = sm3_ctx;
    sm3_final_req->sm3_hash = md;
    sm3_final_req->job = job;
    sm3_final_req->sts = &sts;

    mb_queue_sm3_final_enqueue(tlv->sm3_final_queue, sm3_final_req);
    STOP_RDTSC(&sm3_cycles_final_setup, 1, "[SM3:final_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_SM3_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (sem_post(&tlv->mb_polling_thread_sem) != 0) {
            WARN("hw sem_post failed!, mb_polling_thread_sem address: %p.\n",
                  &tlv->mb_polling_thread_sem);
            /* If we fail the pthread_kill carry on as the timeout
               will catch processing the request in the polling thread */
        }
     }

    DEBUG("Pausing: %p status = %d sm3_ctx %p\n", sm3_final_req, sts, sm3_final_req->state);
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

    DEBUG("Finished: %p status = %d\n", sm3_final_req, sts);

    if (sts) {
       return sts;
    } else {
        WARN("Failure in SM3 Final\n");
        QATerr(QAT_F_QAT_SW_SM3_FINAL, QAT_R_SM3_FINAL_FAILURE);
        return sts;
    }

use_sw_method:
    sw_fn_ptr = EVP_MD_meth_get_final((EVP_MD *)EVP_sm3());
    sts = (*sw_fn_ptr)(ctx, md);
    DEBUG("SW Finished %p\n", ctx);
    return sts;
}
