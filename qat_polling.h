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
 * @file qat_polling.h
 *
 * This file provides an interface for polling in QAT engine
 *
 *****************************************************************************/

#ifndef QAT_POLLING_H
# define QAT_POLLING_H

# ifndef OPENSSL_MULTIBUFF_OFFLOAD
#  include "cpa.h"
#  include "cpa_types.h"
#  include "e_qat.h"
# else
#  include "e_qat.h"
# endif

# ifndef __FreeBSD__
#  include <sys/epoll.h>
# endif
# define MAX_EVENTS 32

/* Globals */
typedef struct {
    int eng_fd;
    int inst_index;
} ENGINE_EPOLL_ST;

# ifndef __FreeBSD__
extern struct epoll_event eng_epoll_events[QAT_MAX_CRYPTO_INSTANCES];
extern ENGINE_EPOLL_ST eng_poll_st[QAT_MAX_CRYPTO_INSTANCES];
# endif
extern int internal_efd;

int getQatMsgRetryCount();
useconds_t getQatPollInterval();
int getEnableInlinePolling();
/******************************************************************************
 * function:
 *         int qat_create_thread(pthread_t *pThreadId,
 *                               const pthread_attr_t *attr,
 *                               void *(*start_func) (void *), void *pArg)
 *
 * @param pThreadId  [OUT] - Pointer to Thread ID
 * @param start_func [IN]  - Pointer to Thread Start routine
 * @param attr       [IN]  - Pointer to Thread attributes
 * @param pArg       [IN]  - Arguments to start routine
 *
 * description:
 *   Wrapper function for pthread_create
 ******************************************************************************/
int qat_create_thread(pthread_t *pThreadId, const pthread_attr_t *attr,
                      void *(*start_func) (void *), void *pArg);

/******************************************************************************
 * function:
 *         int qat_join_thread(pthread_t threadId, void **retval)
 *
 * @param pThreadId  [IN]  - Thread ID of the created thread
 * @param retval     [OUT] - Pointer that contains thread's exit status
 *
 * description:
 *   Wrapper function for pthread_create
 ******************************************************************************/
int qat_join_thread(pthread_t threadId, void **retval);

/******************************************************************************
 * function:
 *         int qat_kill_thread(pthread_t threadId, int sig)
 *
 * @param pThreadId  [IN] - Thread ID of the created thread
 * @param sig        [IN] - Signal number
 *
 * description:
 *   Wrapper function for pthread_kill
 ******************************************************************************/
int qat_kill_thread(pthread_t threadId, int sig);

/******************************************************************************
 * function:
 *         int qat_setspecific_thread(pthread_key_t key, const void *value)
 *
 * @param key   [IN] - key obtained from pthread_key_create()
 * @param value [IN] - Thread specific value
 *
 * description:
 *   Wrapper function for pthread_setspecific
 ******************************************************************************/
int qat_setspecific_thread(pthread_key_t key, const void *value);

/******************************************************************************
 * function:
 *         int qat_getspecific_thread(pthread_key_t key)
 *
 * @param key   [IN] - key obtained from pthread_key_create()
 *
 * description:
 *   Wrapper function for pthread_getspecific
 ******************************************************************************/
void *qat_getspecific_thread(pthread_key_t key);

/******************************************************************************
 * function:
 *         int qat_adjust_thread_affinity(pthread_t threadptr);
 *
 * @param threadptr[IN ] - Thread ID
 *
 * description:
 *    Sets the CPU affinity mask using pthread_setaffinity_np
 *    and returns the CPU affinity mask using pthread_getaffinity_np
 ******************************************************************************/
int qat_adjust_thread_affinity(pthread_t threadptr);

/******************************************************************************
 * function:
 *         void *qat_timer_poll_func(void *ih)
 *
 * @param ih [IN] - NULL
 *
 * description:
 *   Poll the QAT instances (nanosleep version)
 *     NB: Delay in this function is set by default at runtime by an engine
 *     specific message. If not set then the default is QAT_POLL_PERIOD_IN_NS.
 *     This function uses pthread signals to wait for a signal
 *     that there is traffic to process and therefore that QAT engine polling
 *     needs to be started/resumed.
 *
 ******************************************************************************/
void *qat_timer_poll_func(void *ih);

int qat_fcntl(int fd, int cmd, int arg);

# ifndef __FreeBSD__
void *event_poll_func(void *ih);
# endif
CpaStatus poll_instances(void);
CpaStatus poll_heartbeat(void);

#endif   /* QAT_POLLING_H */
