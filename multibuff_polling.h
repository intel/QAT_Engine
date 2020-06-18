/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020 Intel Corporation.
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
 * @file multibuff_polling.h
 *
 * This file provides an interface for multibuff polling in QAT engine
 *
 *****************************************************************************/

#ifndef MULIBUFF_POLLING_H
# define MULTIBUFF_POLLING_H

#include "e_qat.h"

/******************************************************************************
 * function:
 *         int multibuff_create_thread(pthread_t *pThreadId,
 *                                     const pthread_attr_t *attr,
 *                                     void *(*start_func) (void *), void *pArg)
 *
 * @param pThreadId  [OUT] - Pointer to Thread ID
 * @param start_func [IN]  - Pointer to Thread Start routine
 * @param attr       [IN]  - Pointer to Thread attributes
 * @param pArg       [IN]  - Arguments to start routine
 *
 * description:
 *   Wrapper function for pthread_create
 ******************************************************************************/
int multibuff_create_thread(pthread_t *pThreadId, const pthread_attr_t *attr,
                            void *(*start_func) (void *), void *pArg);

/******************************************************************************
 * function:
 *         int multibuff_join_thread(pthread_t threadId, void **retval)
 *
 * @param pThreadId  [IN ] - Thread ID of the created thread
 * @param retval     [OUT] - Pointer that contains thread's exit status
 *
 * description:
 *   Wrapper function for pthread_create
 ******************************************************************************/
int multibuff_join_thread(pthread_t threadId, void **retval);

/******************************************************************************
 * function:
 *         int multibuff_kill_thread(pthread_t threadId, int sig)
 *
 * @param pThreadId  [IN] - Thread ID of the created thread
 * @param sig        [IN] - Signal number
 *
 * description:
 *   Wrapper function for pthread_kill
 ******************************************************************************/
int multibuff_kill_thread(pthread_t threadId, int sig);

/******************************************************************************
 * function:
 *         int multibuff_adjust_thread_affinity(pthread_t threadptr);
 *
 * @param threadptr[IN ] - Thread ID
 *
 * description:
 *    Sets the CPU affinity mask using pthread_setaffinity_np
 *    and returns the CPU affinity mask using pthread_getaffinity_np
 ******************************************************************************/
int multibuff_adjust_thread_affinity(pthread_t threadptr);

/******************************************************************************
 * function:
 *         void *timer_poll_func(void *ih)
 *
 * @param ih [IN] - NULL
 *
 * description:
 *   Poll the multibuff request (nanosleep version)
 *   NB: Delay in this function is set by default at runtime by an engine
 *   specific message. If not set then the default is QAT_POLL_PERIOD_IN_NS.
 *
 ******************************************************************************/
void *multibuff_timer_poll_func(void *ih);

int multibuff_poll();

#endif   /* MULTIBUFF_POLLING_H */
