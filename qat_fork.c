/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2023 Intel Corporation.
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
 * @file e_qat.c
 *
 * This file provides an implementation for fork in QAT engine
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
#include <fcntl.h>

/* Local Includes */
#include "qat_fork.h"
#include "qat_utils.h"
#include "e_qat.h"

/* OpenSSL Includes */
#include <openssl/err.h>
#ifdef QAT_OPENSSL_PROVIDER
# include <openssl/provider.h>
#endif

/* QAT includes */
#ifdef QAT_HW
# ifdef USE_QAT_CONTIG_MEM
#  include "qae_mem_utils.h"
# endif
# ifdef USE_USDM_MEM
#  include "qat_hw_usdm_inf.h"
# endif
# include "cpa.h"
# include "cpa_types.h"

# ifndef __FreeBSD__
typedef  cpu_set_t qat_cpuset;
# else
#  include <pthread_np.h>
typedef  cpuset_t  qat_cpuset;
# endif
#endif
#ifdef QAT_OPENSSL_PROVIDER
# include "qat_provider.h"
#endif

void engine_init_child_at_fork_handler(void)
{
#ifndef DISABLE_QAT_AUTO_ENGINE_INIT_ON_FORK
# ifndef QAT_OPENSSL_PROVIDER
    /* Reinitialise the engine */
    ENGINE* e = ENGINE_by_id(engine_qat_id);
    if (NULL == e) {
        WARN("Engine pointer is NULL\n");
        QATerr(QAT_F_ENGINE_INIT_CHILD_AT_FORK_HANDLER, QAT_R_ENGINE_NULL);
        return;
    }

    if (qat_engine_init(e) != 1) {
        WARN("Failure in qat_engine_init function\n");
        QATerr(QAT_F_ENGINE_INIT_CHILD_AT_FORK_HANDLER, QAT_R_ENGINE_INIT_FAILURE);
    }
    ENGINE_free(e);
#ifdef QAT_BORINGSSL
    ENGINE_QAT_PTR_RESET();
#endif /* QAT_BORINGSSL */
# else
    QAT_PROV_CTX *ctx;
    OSSL_PROVIDER *prov;
    const char *prov_name = "qatprovider";
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    prov = OSSL_PROVIDER_load(prov_libctx_of(ctx),prov_name);
    if (NULL == prov) {
        WARN("Provider pointer is NULL\n");
        QATerr(QAT_F_ENGINE_INIT_CHILD_AT_FORK_HANDLER, QAT_R_ENGINE_NULL);
        return;
    }
    if (qat_engine_init(NULL) != 1) {
        WARN("Failure in qat_engine_init function\n");
        QATerr(QAT_F_ENGINE_INIT_CHILD_AT_FORK_HANDLER, QAT_R_ENGINE_INIT_FAILURE);
    }
    OPENSSL_free(ctx);
    OSSL_PROVIDER_unload(prov);
# endif
#endif
}

void engine_finish_before_fork_handler(void)
{
#ifndef QAT_OPENSSL_PROVIDER
    /* Reset the engine preserving the value of global variables */
    ENGINE* e = ENGINE_by_id(engine_qat_id);
    if (NULL == e) {
        WARN("Engine pointer is NULL\n");
        QATerr(QAT_F_ENGINE_FINISH_BEFORE_FORK_HANDLER, QAT_R_ENGINE_NULL);
        return;
    }

    qat_engine_finish_int(e, QAT_RETAIN_GLOBALS);
    ENGINE_free(e);
    ENGINE_QAT_PTR_RESET();

#else
    QAT_PROV_CTX *ctx;
    OSSL_PROVIDER *prov;
    const char *prov_name = "qatprovider";
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    prov = OSSL_PROVIDER_load(prov_libctx_of(ctx),prov_name);
    if (NULL == prov) {
        WARN("Provider pointer is NULL\n");
        QATerr(QAT_F_ENGINE_FINISH_BEFORE_FORK_HANDLER, QAT_R_ENGINE_NULL);
        return;
    }
    qat_engine_finish_int(NULL, QAT_RETAIN_GLOBALS);
    OPENSSL_free(ctx);
    OSSL_PROVIDER_unload(prov);
#endif
    qat_hw_keep_polling = 1;
    qat_sw_keep_polling = 1;
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

int qat_kill_thread(pthread_t threadId, int sig)
{
    return pthread_kill(threadId, sig);
}

int qat_setspecific_thread(pthread_key_t key, const void *value)
{
    return pthread_setspecific(key, value);
}

void *qat_getspecific_thread(pthread_key_t key)
{
    return pthread_getspecific(key);
}

#ifdef QAT_HW
int qat_adjust_thread_affinity(pthread_t threadptr)
{
# ifdef QAT_POLL_CORE_AFFINITY
    int coreID = 0;
    int sts = 1;
    qat_cpuset cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(coreID, &cpuset);

    sts = pthread_setaffinity_np(threadptr, sizeof(qat_cpuset), &cpuset);
    if (sts != 0) {
        WARN("pthread_setaffinity_np error, status = %d\n", sts);
        QATerr(QAT_F_QAT_ADJUST_THREAD_AFFINITY, QAT_R_PTHREAD_SETAFFINITY_FAILURE);
        return 0;
    }
    sts = pthread_getaffinity_np(threadptr, sizeof(qat_cpuset), &cpuset);
    if (sts != 0) {
        WARN("pthread_getaffinity_np error, status = %d\n", sts);
        QATerr(QAT_F_QAT_ADJUST_THREAD_AFFINITY, QAT_R_PTHREAD_GETAFFINITY_FAILURE);
        return 0;
    }

    if (CPU_ISSET(coreID, &cpuset)) {
        DEBUG("Polling thread assigned on CPU core %d\n", coreID);
    }
# endif
    return 1;
}

int qat_fcntl(int fd, int cmd, int arg)
{
    return fcntl(fd, cmd, arg);
}

int qat_set_instance_for_thread(long instanceNum)
{
    int inst_idx;
    thread_local_variables_t *tlv = NULL;
    tlv = qat_check_create_local_variables();
    if (NULL == tlv || 0 == qat_num_instances ||
        instanceNum < 0) {
        WARN("could not create local variables or no instances available\n");
        QATerr(QAT_F_QAT_SET_INSTANCE_FOR_THREAD, QAT_R_SET_INSTANCE_FAILURE);
        return 0;
    }

    tlv->qatAsymInstanceNumForThread = QAT_INVALID_INSTANCE;
    tlv->qatSymInstanceNumForThread = QAT_INVALID_INSTANCE;

    /* If asym can be supported */
    if (qat_asym_num_instance > 0) {
        inst_idx = instanceNum % qat_asym_num_instance;
        tlv->qatAsymInstanceNumForThread = qat_map_asym_inst[inst_idx];
    }

    /* If asym can be supported */
    if (qat_sym_num_instance > 0) {
        inst_idx = instanceNum % qat_sym_num_instance;
        tlv->qatSymInstanceNumForThread = qat_map_sym_inst[inst_idx];
    }

    enable_instance_for_thread = 1;
    return 1;
}

/* Wrapper for memory Allocation to use pinned contiguous memory or application memory
 * based on instance's SVM or contiguous mem capability  */
void *qat_mem_alloc(size_t memsize, int inst_mem_type, const char *file, int line)
{
    if (inst_mem_type == QAT_INSTANCE_SVM)
        return OPENSSL_zalloc(memsize);
    else
        return qaeCryptoMemAlloc(memsize, file, line);
}


#endif
