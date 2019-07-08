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
 * @file qat_events.c
 *
 * This file provides implementation for async events in engine
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
#ifndef __FreeBSD__
# include <sys/epoll.h>
# include <sys/eventfd.h>
#else
# include <sys/types.h>
# include <sys/event.h>
#endif
#include <unistd.h>
#include <fcntl.h>

/* OpenSSL Includes */
#include <openssl/err.h>

/* QAT includes */
#ifndef OPENSSL_MULTIBUFF_OFFLOAD
# ifdef USE_QAT_CONTIG_MEM
#  include "qae_mem_utils.h"
# endif
# ifdef USE_QAE_MEM
#  include "cmn_mem_drv_inf.h"
# endif
# include "cpa.h"
# include "cpa_types.h"
# include "qat_init.h"
#else
# include "multibuff_init.h"
#endif

/* Local Includes */
#include "qat_events.h"
#include "qat_utils.h"
#include "e_qat_err.h"

#ifndef OPENSSL_MULTIBUFF_OFFLOAD
int qat_is_event_driven()
{
    return enable_event_driven_polling;
}
#endif

static void qat_fd_cleanup(ASYNC_WAIT_CTX *ctx, const void *key,
                           OSSL_ASYNC_FD readfd, void *custom)
{
#ifdef SSL_QAT_USE_ASYNC_CALLBACK
    int (*callback)(void *arg);
    void *args;

    if (ASYNC_WAIT_CTX_get_callback(ctx, &callback, &args)) {
        return;
    }
#endif
    if (close(readfd) != 0) {
        WARN("Failed to close readfd: %d - error: %d\n", readfd, errno);
        QATerr(QAT_F_QAT_FD_CLEANUP, QAT_R_CLOSE_READFD_FAILURE);
    }
}

int qat_setup_async_event_notification(int jobStatus)
{
    /* We will ignore jobStatus for the moment */
    ASYNC_JOB *job;
    ASYNC_WAIT_CTX *waitctx;
#ifdef SSL_QAT_USE_ASYNC_CALLBACK
    int (*callback)(void *arg);
    void *args;
#endif
    OSSL_ASYNC_FD efd;
    void *custom = NULL;

#ifdef __FreeBSD__
    struct kevent event;
#endif

    if ((job = ASYNC_get_current_job()) == NULL) {
        WARN("Could not obtain current job\n");
        return 0;
    }

    if ((waitctx = ASYNC_get_wait_ctx(job)) == NULL) {
        WARN("Could not obtain wait context for job\n");
        return 0;
    }

#ifdef SSL_QAT_USE_ASYNC_CALLBACK
    if (ASYNC_WAIT_CTX_get_callback(waitctx, &callback, &args)) {
        return 1;
    }
#endif

    if (ASYNC_WAIT_CTX_get_fd(waitctx, engine_qat_id, &efd,
                              &custom) == 0) {
#ifdef __FreeBSD__
        efd = kqueue();
        if (efd == -1) {
            WARN("Failed to get kqueue fd = %d\n", errno);
            return 0;
        }
        /* Initialize the event */
        EV_SET(&event, QAT_EVENT_NUM, EVFILT_USER, EV_ADD | EV_CLEAR, NOTE_WRITE,
               0, NULL);
        if (kevent(efd, &event, QAT_EVENT_NUM, NULL, 0, NULL) == -1) {
            WARN("Failed to register event for the fd = %d\n", efd);
            close(efd);
            return 0;
        }

#else
        efd = eventfd(0, EFD_NONBLOCK);
        if (efd == -1) {
            WARN("Failed to get eventfd = %d\n", errno);
            return 0;
        }
#endif

        if (ASYNC_WAIT_CTX_set_wait_fd(waitctx, engine_qat_id, efd,
                                       custom, qat_fd_cleanup) == 0) {
            WARN("failed to set the fd in the ASYNC_WAIT_CTX\n");
            qat_fd_cleanup(waitctx, engine_qat_id, efd, NULL);
            return 0;
        }
    }
    return 1;
}

int qat_clear_async_event_notification()
{
    ASYNC_JOB *job;
    ASYNC_WAIT_CTX *waitctx;
    size_t num_add_fds = 0;
    size_t num_del_fds = 0;
#ifdef SSL_QAT_USE_ASYNC_CALLBACK
    int (*callback)(void *arg);
    void *args;
#endif
    OSSL_ASYNC_FD efd;
    void *custom = NULL;

    if ((job = ASYNC_get_current_job()) == NULL) {
        WARN("Could not obtain current job\n");
        return 0;
    }

    if ((waitctx = ASYNC_get_wait_ctx(job)) == NULL) {
        WARN("Could not obtain wait context for job\n");
        return 0;
    }

#ifdef SSL_QAT_USE_ASYNC_CALLBACK
    if (ASYNC_WAIT_CTX_get_callback(waitctx, &callback, &args)) {
        return 1;
    }
#endif

    if (ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &num_add_fds, NULL,
                                       &num_del_fds) == 0) {
        WARN("Failure in ASYNC_WAIT_CTX_get_changed_async_fds\n");
        return 0;
    }

    if (num_add_fds > 0) {
        /* Only close the fd and remove it from the ASYNC_WAIT_CTX
           if it is a new fd. If it is an existing fd then leave it
           open and in the ASYNC_WAIT_CTX and it will be cleaned up
           when the ASYNC_WAIT_CTX is cleaned up.*/
        if (ASYNC_WAIT_CTX_get_fd(waitctx, engine_qat_id, &efd, &custom) == 0) {
            WARN("Failure in ASYNC_WAIT_CTX_get_fd\n");
            return 0;
        }

        qat_fd_cleanup(waitctx, engine_qat_id, efd, NULL);

        if (ASYNC_WAIT_CTX_clear_fd(waitctx, engine_qat_id) == 0) {
            WARN("Failure in ASYNC_WAIT_CTX_clear_fd\n");
            return 0;
        }
    }
    return 1;
}

int qat_pause_job(volatile ASYNC_JOB *job, int jobStatus)
{
    ASYNC_WAIT_CTX *waitctx;
    int ret = 0;
#ifdef SSL_QAT_USE_ASYNC_CALLBACK
    int callback_set = 0;
    int (*callback)(void *arg);
    void *args;
#endif
    OSSL_ASYNC_FD readfd;
    void *custom = NULL;
#ifdef __FreeBSD__
    struct kevent event;
#else
    uint64_t buf = 0;
#endif

    if ((waitctx = ASYNC_get_wait_ctx((ASYNC_JOB *)job)) == NULL) {
        WARN("waitctx == NULL\n");
        return ret;
    }

#ifdef SSL_QAT_USE_ASYNC_CALLBACK
    if (ASYNC_WAIT_CTX_get_callback(waitctx, &callback, &args)) {
        callback_set = 1;
        ASYNC_WAIT_CTX_set_status(waitctx, jobStatus);
    }
#endif

    if (ASYNC_pause_job() == 0) {
        WARN("Failed to pause the job\n");
        return ret;
    }

#ifdef SSL_QAT_USE_ASYNC_CALLBACK
    if (callback_set) {
        return 1;
    }
#endif
    if ((ret = ASYNC_WAIT_CTX_get_fd(waitctx, engine_qat_id, &readfd,
                                     &custom)) > 0) {
#ifndef __FreeBSD__
        if (read(readfd, &buf, sizeof(uint64_t)) == -1) {
            if (errno != EAGAIN) {
                WARN("Failed to read from fd: %d - error: %d\n", readfd, errno);
            }
            /* Not resumed by the expected qat_wake_job() */
            return QAT_JOB_RESUMED_UNEXPECTEDLY;
        }
#else
        if (kevent(readfd, NULL, 0, &event, QAT_EVENT_NUM, NULL) == -1) {
            WARN("Failed to get event from fd: %d - error: %d\n", readfd, errno);
            /* Not resumed by the expected qat_wake_job() */
            return QAT_JOB_RESUMED_UNEXPECTEDLY;
        }
#endif
    }
    return ret;
}

int qat_wake_job(volatile ASYNC_JOB *job, int jobStatus)
{
    ASYNC_WAIT_CTX *waitctx;
    int ret = 0;
#ifdef SSL_QAT_USE_ASYNC_CALLBACK
    int (*callback)(void *arg);
    void *args;
#endif
    OSSL_ASYNC_FD efd;
    void *custom = NULL;
#ifdef __FreeBSD__
    struct kevent event;
#else
    /* Arbitary value '1' to write down the pipe to trigger event */
    uint64_t buf = 1;
#endif

    if ((waitctx = ASYNC_get_wait_ctx((ASYNC_JOB *)job)) == NULL) {
        WARN("waitctx == NULL\n");
        return ret;
    }

#ifdef SSL_QAT_USE_ASYNC_CALLBACK
    if (ASYNC_WAIT_CTX_get_callback(waitctx, &callback, &args)) {
        /* We will go through callback mechanism */
        if (ASYNC_STATUS_OK == jobStatus)
        {
            (*callback)(args);
        } else {
            /* In this case, we assume that a possbile retry happened */
            ASYNC_WAIT_CTX_set_status(waitctx, jobStatus);
        }

        return 1;
    }
#endif

    if ((ret = ASYNC_WAIT_CTX_get_fd(waitctx, engine_qat_id, &efd,
                                     &custom)) > 0) {
#ifndef __FreeBSD__
        if (write(efd, &buf, sizeof(uint64_t)) == -1) {
            WARN("Failed to write to fd: %d - error: %d\n", efd, errno);
        }
#else
        EV_SET(&event, QAT_EVENT_NUM, EVFILT_USER, EV_ADD, NOTE_TRIGGER, 0, NULL);
        if (kevent(efd, &event, QAT_EVENT_NUM, NULL, 0, NULL) == -1) {
            WARN("Failed to trigger event to fd: %d - error: %d\n", efd, errno);
        }
#endif
    }
    return ret;
}
