/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2024 Intel Corporation.
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
 * @file qat_hw_polling.c
 *
 * This file provides an implementation for polling in QAT engine
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
#include <time.h>
#include <fcntl.h>

/* Local Includes */
#include "qat_hw_polling.h"
#include "qat_utils.h"
# include "e_qat.h"

/* OpenSSL Includes */
#include <openssl/err.h>

/* QAT includes */
#ifdef QAT_HW
# include "cpa.h"
# include "cpa_cy_im.h"
# include "cpa_types.h"
# include "icp_sal_user.h"
# include "icp_sal_poll.h"
#endif

#ifndef __FreeBSD__
struct epoll_event eng_epoll_events[QAT_MAX_CRYPTO_INSTANCES] = {{ 0 }};
ENGINE_EPOLL_ST eng_poll_st[QAT_MAX_CRYPTO_INSTANCES] = {{ -1 }};
#endif
int internal_efd = 0;
#ifndef __FreeBSD__
clock_t clock_id = CLOCK_MONOTONIC_RAW;
#else
clock_t clock_id = CLOCK_MONOTONIC_PRECISE;
#endif


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

static void qat_poll_heartbeat_timer_expiry(struct timespec *previous_time)
{
    struct timespec current_time = { 0 };
    struct timespec diff_time = { 0 };

    clock_gettime(clock_id, &current_time);

    /* Calculate time difference and poll every one second */
    if ((current_time.tv_nsec - previous_time->tv_nsec) < 0) {
        diff_time.tv_sec = current_time.tv_sec - previous_time->tv_sec - 1;
    } else {
        diff_time.tv_sec = current_time.tv_sec - previous_time->tv_sec;
    }
    if (diff_time.tv_sec > 0) {
        poll_heartbeat();
        previous_time->tv_sec = current_time.tv_sec;
        previous_time->tv_nsec = current_time.tv_nsec;
    }
}

void *qat_timer_poll_func(void *ih)
{
    CpaStatus status = 0;
    Cpa16U inst_num = 0;

    struct timespec req_time = { 0 };
    struct timespec rem_time = { 0 };
    struct timespec timeout_time = { 0 };
    unsigned int retry_count = 0; /* to prevent too much time drift */
    int sig = 0;
    unsigned int eintr_count = 0;
    struct timespec previous_time = { 0 };
    struct timespec hw_polling_abs_timeout;

    DEBUG("timer_poll_func started\n");
    qat_timer_poll_func_thread = pthread_self();
    cleared_to_start = 1;

    if (pthread_mutex_lock(&qat_poll_mutex) == 0) {
        pthread_cond_signal(&qat_poll_condition);
        if (pthread_mutex_unlock(&qat_poll_mutex) != 0)
            WARN("Failed to unlock conditional wait mutex \n");
    } else {
        WARN("Failed to lock conditional wait mutex \n");
    }

    DEBUG("qat_timer_poll_func_thread = 0x%lx\n", (unsigned long)qat_timer_poll_func_thread);

    if (qat_get_sw_fallback_enabled()) {
        clock_gettime(clock_id, &previous_time);
    }
    while (qat_hw_keep_polling) {
        if (num_requests_in_flight == 0) {
            if (qat_get_sw_fallback_enabled()) {
                qat_poll_heartbeat_timer_expiry(&previous_time);
            }

            timeout_time.tv_sec = QAT_EVENT_TIMEOUT_IN_SEC;
            timeout_time.tv_nsec = 0;
            get_sem_wait_abs_time(&hw_polling_abs_timeout, timeout_time);
            while ((sig = sem_timedwait(&hw_polling_thread_sem,
                    &hw_polling_abs_timeout)) == -1 && errno == EINTR &&
                    eintr_count < QAT_CRYPTO_NUM_EVENT_RETRIES) {
                eintr_count++;
            }
            eintr_count = 0;
            if (unlikely(sig == -1)) {
                if ((qat_get_sw_fallback_enabled())
                    && (errno == ETIMEDOUT || errno == EINTR)) {
                    clock_gettime(clock_id, &previous_time);
                    poll_heartbeat();
                }
                continue;
            }
        } else {
             if (qat_get_sw_fallback_enabled()) {
                 qat_poll_heartbeat_timer_expiry(&previous_time);
             }
        }

        req_time.tv_nsec = qat_poll_interval;
        for (inst_num = 0; inst_num < qat_num_instances; ++inst_num) {
            if (num_requests_in_flight == 0)
                break;

            /* Poll for 0 means process all packets on the instance */
            status = icp_sal_CyPollInstance(qat_instance_handles[inst_num], 0);
            if (unlikely(CPA_STATUS_SUCCESS != status
                         && CPA_STATUS_RESTARTING != status
                         && CPA_STATUS_RETRY != status)) {
                WARN("icp_sal_CyPollInstance returned status %d\n", status);
            }

            if (unlikely(!qat_hw_keep_polling))
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

    DEBUG("timer_poll_func finishing - pid = %d\n", getpid());
    qat_timer_poll_func_thread = 0;
    cleared_to_start = 0;
    pthread_cond_signal(&qat_poll_condition);
    return NULL;
}

#ifndef __FreeBSD__
void *event_poll_func(void *ih)
{
    CpaStatus status = 0;
    struct epoll_event *events = NULL;
    ENGINE_EPOLL_ST* epollst = NULL;
    struct timespec previous_time = { 0 };

    /* Buffer where events are returned */
    events = OPENSSL_zalloc(sizeof(struct epoll_event) * MAX_EVENTS);
    if (NULL == events) {
        WARN("Error allocating events list\n");
        QATerr(QAT_F_EVENT_POLL_FUNC, QAT_R_EVENTS_MALLOC_FAILURE);
        goto end;
    }

    if (qat_get_sw_fallback_enabled()) {
        clock_gettime(clock_id, &previous_time);
    }

    while (qat_hw_keep_polling) {
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
        if (qat_get_sw_fallback_enabled()) {
            qat_poll_heartbeat_timer_expiry(&previous_time);
        }
    }
    OPENSSL_free(events);
    events = NULL;
end:
    return NULL;
}
#endif

CpaStatus poll_instances(void)
{
    unsigned int poll_loop;
    int inst_asym;
    int inst_sym;
    int instance_polled = 0;

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
        inst_asym = qat_map_asym_inst[tlv->qatAsymInstanceNumForThread];
        inst_sym = qat_map_sym_inst[tlv->qatSymInstanceNumForThread];

        if (qat_instance_handles) {
            /* Asymmetric instance */
            if (QAT_INVALID_INSTANCE != inst_asym) {
                internal_status =
                    icp_sal_CyPollInstance(qat_instance_handles[inst_asym], 0);

                if (CPA_STATUS_SUCCESS != internal_status) {
                    WARN("Fail to poll Asymmetric instance\n");
                    QATerr(QAT_F_POLL_INSTANCES, QAT_R_POLL_INSTANCE_FAILURE);
                    ret_status = CPA_STATUS_FAIL;
                }
                instance_polled = 1;
            }

            /* Symmetric instance */
            if (QAT_INVALID_INSTANCE != inst_sym &&
                inst_asym != inst_sym) {
                internal_status =
                    icp_sal_CyPollInstance(qat_instance_handles[inst_sym], 0);

                if (CPA_STATUS_SUCCESS != internal_status) {
                    WARN("Fail to poll Symmetric instance\n");
                    QATerr(QAT_F_POLL_INSTANCES, QAT_R_POLL_INSTANCE_FAILURE);
                    ret_status = CPA_STATUS_FAIL;
                }
                instance_polled = 1;
            }

            if (instance_polled) {
                return ret_status;
            } else {
                WARN("neither asym nor sym instance is valid\n");
                QATerr(QAT_F_POLL_INSTANCES, QAT_R_POLL_INSTANCE_FAILURE);
                return CPA_STATUS_FAIL;
            }

        } else {
            WARN("could not get a valid instance to poll\n");
            QATerr(QAT_F_POLL_INSTANCES, QAT_R_POLL_INSTANCE_FAILURE);
            return CPA_STATUS_FAIL;
        }
    }

    if (NULL == qat_instance_handles) {
        WARN("qat_instance_handles is NULL\n");
        QATerr(QAT_F_POLL_INSTANCES, QAT_R_POLL_INSTANCE_FAILURE);
        return CPA_STATUS_FAIL;
    }

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

    return ret_status;
}

CpaStatus poll_heartbeat(void)
{
    CpaStatus ret_status = CPA_STATUS_SUCCESS;

    ret_status = icp_sal_poll_device_events();
    if (unlikely(CPA_STATUS_SUCCESS != ret_status)) {
        WARN("The call to icp_sal_poll_device_events failed\n");
    }
    return ret_status;
}
