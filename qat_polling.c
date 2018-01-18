/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2018 Intel Corporation.
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
 * @file qat_polling.c
 *
 * This file provides an implemenation for polling in QAT engine
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifndef __USE_GNU
# define __USE_GNU
#endif

/* Standard Includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

/* Local Includes */
#include "e_qat.h"
#include "qat_polling.h"
#include "qat_utils.h"
#include "e_qat_err.h"

/* OpenSSL Includes */
#include <openssl/err.h>

/* QAT includes */
#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "cmn_mem_drv_inf.h"
#endif
#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_types.h"
#include "icp_sal_user.h"
#include "icp_sal_poll.h"

struct epoll_event eng_epoll_events[MAX_CRYPTO_INSTANCES] = {{ 0 }};
int internal_efd = 0;
ENGINE_EPOLL_ST eng_poll_st[MAX_CRYPTO_INSTANCES] = {{ -1 }};

int getQatMsgRetryCount()
{
    return qat_max_retry_count;
}

useconds_t getQatPollInterval()
{
    return qat_poll_interval;
}

int getEnableInlinePolling()
{
    return enable_inline_polling;
}

int qat_create_thread(pthread_t *pThreadId, const pthread_attr_t *attr,
                      void *(*start_func) (void *), void *pArg)
{
    return pthread_create(pThreadId, attr, start_func,(void *)pArg);
}

int qat_join_thread(pthread_t threadId, void **retval)
{
    return pthread_join(threadId, retval);
}

int qat_adjust_thread_affinity(pthread_t threadptr)
{
#ifdef QAT_POLL_CORE_AFFINITY
    int coreID = 0;
    int sts = 1;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(coreID, &cpuset);

    sts = pthread_setaffinity_np(threadptr, sizeof(cpu_set_t), &cpuset);
    if (sts != 0) {
        WARN("pthread_setaffinity_np error, status = %d\n", sts);
        QATerr(QAT_F_QAT_ADJUST_THREAD_AFFINITY, QAT_R_PTHREAD_SETAFFINITY_FAILURE);
        return 0;
    }
    sts = pthread_getaffinity_np(threadptr, sizeof(cpu_set_t), &cpuset);
    if (sts != 0) {
        WARN("pthread_getaffinity_np error, status = %d\n", sts);
        QATerr(QAT_F_QAT_ADJUST_THREAD_AFFINITY, QAT_R_PTHREAD_GETAFFINITY_FAILURE);
        return 0;
    }

    if (CPU_ISSET(coreID, &cpuset)) {
        DEBUG("Polling thread assigned on CPU core %d\n", coreID);
    }
#endif
    return 1;
}

void *timer_poll_func(void *ih)
{
    CpaStatus status = 0;
    Cpa16U inst_num = 0;

    struct timespec req_time = { 0 };
    struct timespec rem_time = { 0 };
    unsigned int retry_count = 0; /* to prevent too much time drift */

    int ret_sigwait, sig;


    DEBUG("timer_poll_func started\n");
    timer_poll_func_thread = pthread_self();
    cleared_to_start = 1;

    DEBUG("timer_poll_func_thread = 0x%lx\n", timer_poll_func_thread);

    while (keep_polling) {
        if (num_requests_in_flight == 0) {
            ret_sigwait = sigwait((const sigset_t *)&set, &sig);
            if (ret_sigwait != 0) {
                WARN("sigwait error\n");
                return NULL;
            }
        }

        req_time.tv_nsec = qat_poll_interval;
        for (inst_num = 0; inst_num < qat_num_instances; ++inst_num) {
            if (num_requests_in_flight == 0)
                break;

            /* Poll for 0 means process all packets on the instance */
            status = icp_sal_CyPollInstance(qat_instance_handles[inst_num], 0);
            if (unlikely(CPA_STATUS_SUCCESS != status
                        && CPA_STATUS_RETRY != status)) {
                WARN("icp_sal_CyPollInstance returned status %d\n", status);
            }

            if (unlikely(!keep_polling))
                break;
        }

        retry_count = 0;
        do {
            retry_count++;
            nanosleep(&req_time, &rem_time);
            req_time.tv_sec = rem_time.tv_sec;
            req_time.tv_nsec = rem_time.tv_nsec;
            if (unlikely((errno < 0) && (EINTR != errno))) {
                WARN("nanosleep system call failed: errno %i\n", errno);
                break;
            }
        }
        while ((retry_count <= QAT_CRYPTO_NUM_POLLING_RETRIES)
               && (EINTR == errno));
    }
    DEBUG("timer_poll_func finishing\n");
    timer_poll_func_thread = 0;
    cleared_to_start = 0;
    return NULL;
}

void *event_poll_func(void *ih)
{
    CpaStatus status = 0;
    struct epoll_event *events = NULL;
    ENGINE_EPOLL_ST* epollst = NULL;

    /* Buffer where events are returned */
    events = OPENSSL_zalloc(sizeof(struct epoll_event) * MAX_EVENTS);
    if (NULL == events) {
        WARN("Error allocating events list\n");
        QATerr(QAT_F_EVENT_POLL_FUNC, QAT_R_EVENTS_MALLOC_FAILURE);
        goto end;
    }
    while (keep_polling) {
        int n = 0;
        int i = 0;

        n = epoll_wait(internal_efd, events, MAX_EVENTS, qat_epoll_timeout);
        for (i = 0; i < n; ++i) {
            if (events[i].events & EPOLLIN) {
                /*  poll for 0 means process all packets on the ET ring */
                epollst = (ENGINE_EPOLL_ST*)events[i].data.ptr;
                status = icp_sal_CyPollInstance(qat_instance_handles[epollst->inst_index], 0);
                if (CPA_STATUS_SUCCESS != status) {
                    WARN("icp_sal_CyPollInstance returned status %d\n", status);
                }
            }
        }
    }

    OPENSSL_free(events);
    events = 0;
end:
    return NULL;
}

CpaStatus poll_instances(void)
{
    unsigned int poll_loop;
    CpaInstanceHandle instance_handle = NULL;
    CpaStatus internal_status = CPA_STATUS_SUCCESS,
        ret_status = CPA_STATUS_SUCCESS;
    if (enable_instance_for_thread) {
        thread_local_variables_t *tlv = NULL;
        tlv = qat_check_create_local_variables();
        if (NULL == tlv) {
            WARN("could not create local variables\n");
            QATerr(QAT_F_POLL_INSTANCES, QAT_R_POLL_INSTANCE_FAILURE);
            return CPA_STATUS_FAIL;
        }
        instance_handle = tlv->qatInstanceForThread;
    }

    if (instance_handle) {
        ret_status = icp_sal_CyPollInstance(instance_handle, 0);
    } else {
        for (poll_loop = 0; poll_loop < qat_num_instances; poll_loop++) {
            if (qat_instance_handles[poll_loop] != NULL) {
                internal_status =
                    icp_sal_CyPollInstance(qat_instance_handles[poll_loop], 0);
                if (CPA_STATUS_SUCCESS == internal_status) {
                    /* Do nothing */
                } else if (CPA_STATUS_RETRY == internal_status) {
                    ret_status = internal_status;
                } else {
                    WARN("icp_sal_CyPollInstance failed - status %d\n", internal_status);
                    QATerr(QAT_F_POLL_INSTANCES, QAT_R_POLL_INSTANCE_FAILURE);
                    ret_status = internal_status;
                    break;
                }
            }
        }
    }

    return ret_status;
}
