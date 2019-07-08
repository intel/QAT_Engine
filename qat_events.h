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
 * @file qat_events.h
 *
 * This file provides an interface for async events in engine
 *
 *****************************************************************************/

#ifndef QAT_EVENTS_H
# define QAT_EVENTS_H

# include <sys/types.h>
# include <unistd.h>

# if OPENSSL_VERSION_NUMBER >= 0x10100000L
# include <openssl/async.h>
# endif

/* This value is defined as one possible return value
 * of qat_pause_job() which means paused async job is
 * not resumed by async event but some other events
 * such as socket events.
 * NOTE THAT the unexpected event will be thrown away
 * effectively and quietly. The application should be
 * aware of this case.
 */
#define QAT_JOB_RESUMED_UNEXPECTEDLY -1
#define QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(x) \
        (x == QAT_JOB_RESUMED_UNEXPECTEDLY)

/*
 * These #defines ensure backward compatibility with OpenSSL versions 1.1.0
 * and 1.1.1 which do not have asynchronous callback mode.
 */
#ifndef SSL_QAT_USE_ASYNC_CALLBACK
# define ASYNC_STATUS_UNSUPPORTED    0
# define ASYNC_STATUS_ERR            1
# define ASYNC_STATUS_OK             2
# define ASYNC_STATUS_EAGAIN         3
#endif

#ifdef __FreeBSD__
# define QAT_EVENT_NUM 1
#endif

int qat_is_event_driven();
int qat_setup_async_event_notification(int jobStatus);
int qat_clear_async_event_notification();
int qat_pause_job(volatile ASYNC_JOB *job, int jobStatus);
int qat_wake_job(volatile ASYNC_JOB *job, int jobStatus);

#endif   /* QAT_EVENTS_H */
