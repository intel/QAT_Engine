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
 * @file qat_fork.h
 *
 * This file provides an interface for forking in engine
 *
 *****************************************************************************/

#ifndef QAT_FORK_H
# define QAT_FORK_H

# include "e_qat.h"

int qat_fcntl(int fd, int cmd, int arg);

/******************************************************************************
 * function:
 *         void engine_init_child_at_fork_handler(void)
 *
 * description:
 *   This function is registered, by the call to pthread_atfork(), as
 *   a function to be invoked in the child process prior to fork() returning.
 ******************************************************************************/
void engine_init_child_at_fork_handler(void);

/******************************************************************************
 * function:
 *         void engine_finish_before_fork_handler(void)
 *
 * description:
 *   This function is registered, by the call to pthread_atfork(), as
 *   a function to be run (by the parent process) before a fork() function.
 ******************************************************************************/
void engine_finish_before_fork_handler(void);

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
 *         int qat_set_instance_for_thread(long instanceNum)
 *
 * @param instanceNum [IN] - logical instance number
 *
 * description:
 *   Bind the current thread to a particular logical Cy instance. Note that if
 *   instanceNum is greater than the number of configured instances, the
 *   modulus operation is used.
 *
 ******************************************************************************/
int qat_set_instance_for_thread(long instanceNum);

/******************************************************************************
 * function:
 *         void *qat_mem_alloc(size_t memsize, int inst_mem_type,
 *                             const char *file, int line)
 *
 * description:
 *   Wrapper funcation to memory allocation based on instance type (SVM or pinned
 *   contiguous memory)
 *
 ******************************************************************************/
void *qat_mem_alloc(size_t memsize, int inst_mem_type, const char *file, int line);
#endif   /* QAT_FORK_H */
