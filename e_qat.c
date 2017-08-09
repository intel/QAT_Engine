/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2017 Intel Corporation.
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
 * This file provides a OpenSSL engine for the  quick assist API
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifndef __USE_GNU
# define __USE_GNU
#endif

/* Defines */
#if defined(USE_QAT_CONTIG_MEM) && !defined(USE_QAE_MEM)
# define QAT_DEV "/dev/qat_contig_mem"
#elif defined(USE_QAE_MEM) && !defined(USE_QAT_CONTIG_MEM)
# define QAT_DEV "/dev/usdm_drv"
#elif defined(USE_QAE_MEM) && defined(USE_QAT_CONFIG_MEM)
# error "USE_QAT_CONTIG_MEM and USE_QAE_MEM both defined"
#else
# error "No memory driver type defined"
#endif

/* Standard Includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <signal.h>

/* Local Includes */
#include "e_qat.h"
#include "qat_fork.h"
#include "qat_events.h"
#include "qat_callback.h"
#include "qat_polling.h"
#include "qat_ciphers.h"
#include "qat_rsa.h"
#include "qat_dsa.h"
#include "qat_dh.h"
#include "qat_ec.h"
#include "qat_utils.h"
#include "e_qat_err.h"
#include "qat_prf.h"

/* OpenSSL Includes */
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#include <openssl/async.h>
#endif
#include <openssl/objects.h>
#include <openssl/crypto.h>

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
#include "qat_parseconf.h"

/* Macro used to handle errors in qat_engine_ctrl() */
#define BREAK_IF(cond, mesg) \
    if(unlikely(cond)) { retVal = 0; WARN(mesg); break; }


/* Qat engine id declaration */
const char *engine_qat_id = "qat";
const char *engine_qat_name =
    "Reference implementation of QAT crypto engine";

char *ICPConfigSectionName_libcrypto = "SHIM";

CpaInstanceHandle *qat_instance_handles = NULL;
Cpa16U qat_num_instances = 0;
pthread_key_t qatInstanceForThread;
pthread_t polling_thread;
int keep_polling = 1;
int enable_external_polling = 0;
int enable_inline_polling = 0;
int enable_event_driven_polling = 0;
int enable_instance_for_thread = 0;
int curr_inst = 0;
pthread_mutex_t qat_instance_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t qat_engine_mutex = PTHREAD_MUTEX_INITIALIZER;

unsigned int engine_inited = 0;
unsigned int instance_started[MAX_CRYPTO_INSTANCES] = {0};
useconds_t qat_poll_interval = QAT_POLL_PERIOD_IN_NS;
int qat_epoll_timeout = QAT_EPOLL_TIMEOUT_IN_MS;
int qat_max_retry_count = QAT_CRYPTO_NUM_POLLING_RETRIES;
int num_requests_in_flight = 0;
sigset_t set = {{0}};
pthread_t timer_poll_func_thread = 0;
int cleared_to_start = 0;


int qat_use_signals(void)
{
    return (int)timer_poll_func_thread;
}


/******************************************************************************
* function:
*         incr_curr_inst(void)
*
* description:
*   Increment the logical Cy instance number to use for the next operation.
*
******************************************************************************/
static inline void incr_curr_inst(void)
{
    pthread_mutex_lock(&qat_instance_mutex);
    curr_inst = (curr_inst + 1) % qat_num_instances;
    pthread_mutex_unlock(&qat_instance_mutex);
}

CpaInstanceHandle get_next_inst(void)
{
    CpaInstanceHandle instance_handle = NULL;
    ENGINE* e = NULL;

    if (1 == enable_instance_for_thread) {
        instance_handle = pthread_getspecific(qatInstanceForThread);
        /* If no thread specific data is found then return NULL
           as there should be as the flag is set */
        if (instance_handle == NULL) {
            WARN("No thread specific instance is available\n");
            return instance_handle;
        }
    }

    e = ENGINE_by_id(engine_qat_id);
    if(e == NULL) {
        WARN("Function ENGINE_by_id returned NULL\n");
        instance_handle = NULL;
        return instance_handle;
    }

    if(!qat_engine_init(e)){
        WARN("Failure in qat_engine_init function\n");
        instance_handle = NULL;
        ENGINE_free(e);
        return instance_handle;
    }

    ENGINE_free(e);

    /* Each call to get_next_inst will iterate through the array of instances
       if an instance was not retrieved already from thread specific data. */
    if (instance_handle == NULL)
    {
        if (qat_instance_handles) {
            instance_handle = qat_instance_handles[curr_inst];
            incr_curr_inst();
        } else {
            WARN("No instances are available\n");
            instance_handle = NULL;
        }
    }
    return instance_handle;
}

/******************************************************************************
* function:
*         virtualToPhysical(void *virtualAddr)
*
* @param virtualAddr [IN] - Virtual address.
*
* description:
*   Translates virtual address to hardware physical address. See the qae_mem
*   module for more details. The virtual to physical translator is required
*   by the QAT hardware to map from virtual addresses to physical locations
*   in pinned memory.
*
*   This function is designed to work with the allocator defined in
*   qae_mem_utils.c and qat_contig_mem/qat_contig_mem.c
*
******************************************************************************/
static CpaPhysicalAddr virtualToPhysical(void *virtualAddr)
{
    return qaeCryptoMemV2P(virtualAddr);
}

int qat_engine_init(ENGINE *e)
{
    int instNum, err;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBoolean limitDevAccess = CPA_FALSE;
    int ret_pthread_sigmask;

    pthread_mutex_lock(&qat_engine_mutex);
    if(engine_inited) {
        pthread_mutex_unlock(&qat_engine_mutex);
        return 1;
    }

    DEBUG("QAT Engine initialization:\n");
    DEBUG("- External polling: %s\n", enable_external_polling ? "ON": "OFF");
    DEBUG("- Inline polling: %s\n", enable_inline_polling ? "ON": "OFF");
    DEBUG("- Internal poll interval: %dns\n", qat_poll_interval);
    DEBUG("- Epoll timeout: %dms\n", qat_epoll_timeout);
    DEBUG("- Event driven polling mode: %s\n", enable_event_driven_polling ? "ON": "OFF");
    DEBUG("- Instance for thread: %s\n", enable_instance_for_thread ? "ON": "OFF");
    DEBUG("- Max retry count: %d\n", qat_max_retry_count);

    CRYPTO_INIT_QAT_LOG();

    polling_thread = pthread_self();

    if ((err = pthread_key_create(&qatInstanceForThread, NULL)) != 0) {
        WARN("pthread_key_create failed: %s\n", strerror(err));
        QATerr(QAT_F_QAT_ENGINE_INIT, QAT_R_PTHREAD_CREATE_FAILURE);
        pthread_mutex_unlock(&qat_engine_mutex);
        return 0;
    }

#ifndef OPENSSL_ENABLE_QAT_UPSTREAM_DRIVER
    /* limitDevAccess is passed as an input to icp_sal_userStartMultiProcess().
     * However, in upstream driver the value is ignored and read directly from
     * the configuration file -> No need to parse the file here.
     */
    if (!checkLimitDevAccessValue((int *)&limitDevAccess,
                                    ICPConfigSectionName_libcrypto)) {
        WARN("Could not load driver config file. Assuming LimitDevAccess = 0\n");
    }
#endif

    /* Initialise the QAT hardware */
    if (CPA_STATUS_SUCCESS !=
        icp_sal_userStartMultiProcess(ICPConfigSectionName_libcrypto,
                                      limitDevAccess)) {
        WARN("icp_sal_userStart failed\n");
        QATerr(QAT_F_QAT_ENGINE_INIT, QAT_R_ICP_SAL_USERSTART_FAIL);
        pthread_mutex_unlock(&qat_engine_mutex);
        return 0;
    }

    /* Get the number of available instances */
    status = cpaCyGetNumInstances(&qat_num_instances);
    if (CPA_STATUS_SUCCESS != status) {
        WARN("cpaCyGetNumInstances failed, status=%d\n", status);
        QATerr(QAT_F_QAT_ENGINE_INIT, QAT_R_GET_NUM_INSTANCE_FAILURE);
        pthread_mutex_unlock(&qat_engine_mutex);
        qat_engine_finish(e);
        return 0;
    }
    if (!qat_num_instances) {
        WARN("No crypto instances found\n");
        QATerr(QAT_F_QAT_ENGINE_INIT, QAT_R_INSTANCE_UNAVAILABLE);
        pthread_mutex_unlock(&qat_engine_mutex);
        qat_engine_finish(e);
        return 0;
    }

    DEBUG("Found %d Cy instances\n", qat_num_instances);

    /* Allocate memory for the instance handle array */
    qat_instance_handles =
        (CpaInstanceHandle *) OPENSSL_zalloc(((int)qat_num_instances) *
                                             sizeof(CpaInstanceHandle));
    if (NULL == qat_instance_handles) {
        WARN("OPENSSL_zalloc() failed for instance handles.\n");
        QATerr(QAT_F_QAT_ENGINE_INIT, QAT_R_INSTANCE_HANDLE_MALLOC_FAILURE);
        pthread_mutex_unlock(&qat_engine_mutex);
        qat_engine_finish(e);
        return 0;
    }

    /* Get the Cy instances */
    status = cpaCyGetInstances(qat_num_instances, qat_instance_handles);
    if (CPA_STATUS_SUCCESS != status) {
        WARN("cpaCyGetInstances failed, status=%d\n", status);
        QATerr(QAT_F_QAT_ENGINE_INIT, QAT_R_GET_INSTANCE_FAILURE);
        pthread_mutex_unlock(&qat_engine_mutex);
        qat_engine_finish(e);
        return 0;
    }

    if (!enable_external_polling && !enable_inline_polling) {
        if (qat_is_event_driven()) {
            CpaStatus status;
            int flags;
            int engine_fd;

            /*   Add the file descriptor to an epoll event list */
            internal_efd = epoll_create1(0);
            if (-1 == internal_efd) {
                WARN("Error creating epoll fd\n");
                QATerr(QAT_F_QAT_ENGINE_INIT, QAT_R_EPOLL_CREATE_FAILURE);
                pthread_mutex_unlock(&qat_engine_mutex);
                qat_engine_finish(e);
                return 0;
            }

            for (instNum = 0; instNum < qat_num_instances; instNum++) {
                /*   Get the file descriptor for the instance */
                status =
                    icp_sal_CyGetFileDescriptor(qat_instance_handles[instNum],
                                                &engine_fd);
                if (CPA_STATUS_FAIL == status) {
                    WARN("Error getting file descriptor for instance\n");
                    QATerr(QAT_F_QAT_ENGINE_INIT, QAT_R_GET_FILE_DESCRIPTOR_FAILURE);
                    pthread_mutex_unlock(&qat_engine_mutex);
                    qat_engine_finish(e);
                    return 0;
                }
                /*   Make the file descriptor non-blocking */
                eng_poll_st[instNum].eng_fd = engine_fd;
                eng_poll_st[instNum].inst_index = instNum;

                flags = fcntl(engine_fd, F_GETFL, 0);
                fcntl(engine_fd, F_SETFL, flags | O_NONBLOCK);

                eng_epoll_events[instNum].data.ptr = &eng_poll_st[instNum];
                eng_epoll_events[instNum].events = EPOLLIN | EPOLLET;
                if (-1 ==
                    epoll_ctl(internal_efd, EPOLL_CTL_ADD, engine_fd,
                              &eng_epoll_events[instNum])) {
                    WARN("Error adding fd to epoll\n");
                    QATerr(QAT_F_QAT_ENGINE_INIT, QAT_R_EPOLL_CTL_FAILURE);
                    pthread_mutex_unlock(&qat_engine_mutex);
                    qat_engine_finish(e);
                    return 0;
                }
            }
        }
    }

    /* Set translation function and start each instance */
    for (instNum = 0; instNum < qat_num_instances; instNum++) {
        /* Set the address translation function */
        status = cpaCySetAddressTranslation(qat_instance_handles[instNum],
                                            virtualToPhysical);
        if (CPA_STATUS_SUCCESS != status) {
            WARN("cpaCySetAddressTranslation failed, status=%d\n", status);
            QATerr(QAT_F_QAT_ENGINE_INIT, QAT_R_SET_ADDRESS_TRANSLATION_FAILURE);
            pthread_mutex_unlock(&qat_engine_mutex);
            qat_engine_finish(e);
            return 0;
        }

        /* Start the instances */
        status = cpaCyStartInstance(qat_instance_handles[instNum]);
        if (CPA_STATUS_SUCCESS != status) {
            WARN("cpaCyStartInstance failed, status=%d\n", status);
            QATerr(QAT_F_QAT_ENGINE_INIT, QAT_R_START_INSTANCE_FAILURE);
            pthread_mutex_unlock(&qat_engine_mutex);
            qat_engine_finish(e);
            return 0;
        }

        instance_started[instNum] = 1;
    }

    if (!enable_external_polling && !enable_inline_polling) {
        if (!qat_is_event_driven()) {
            sigemptyset(&set);
            sigaddset(&set, SIGUSR1);
            ret_pthread_sigmask = pthread_sigmask(SIG_BLOCK, &set, NULL);
            if (ret_pthread_sigmask != 0) {
                WARN("pthread_sigmask error\n");
                QATerr(QAT_F_QAT_ENGINE_INIT, QAT_R_POLLING_THREAD_SIGMASK_FAILURE);
                pthread_mutex_unlock(&qat_engine_mutex);
                qat_engine_finish(e);
                return 0;
            }
        }

        if (qat_create_thread(&polling_thread, NULL,
                    qat_is_event_driven() ? event_poll_func : timer_poll_func, NULL)) {
            WARN("Creation of polling thread failed\n");
            QATerr(QAT_F_QAT_ENGINE_INIT, QAT_R_POLLING_THREAD_CREATE_FAILURE);
            polling_thread = pthread_self();
            pthread_mutex_unlock(&qat_engine_mutex);
            qat_engine_finish(e);
            return 0;
        }
        if (qat_adjust_thread_affinity(polling_thread) == 0) {
            WARN("Setting polling thread affinity failed\n");
            QATerr(QAT_F_QAT_ENGINE_INIT, QAT_R_SET_POLLING_THREAD_AFFINITY_FAILURE);
            pthread_mutex_unlock(&qat_engine_mutex);
            qat_engine_finish(e);
            return 0;
        }
        if (!qat_is_event_driven()) {
            while (!cleared_to_start)
                sleep(1);
        }
    }
    /* Reset curr_inst */
    curr_inst = 0;
    engine_inited = 1;
    pthread_mutex_unlock(&qat_engine_mutex);
    return 1;
}

#define QAT_CMD_ENABLE_EXTERNAL_POLLING ENGINE_CMD_BASE
#define QAT_CMD_POLL (ENGINE_CMD_BASE + 1)
#define QAT_CMD_SET_INSTANCE_FOR_THREAD (ENGINE_CMD_BASE + 2)
#define QAT_CMD_GET_NUM_OP_RETRIES (ENGINE_CMD_BASE + 3)
#define QAT_CMD_SET_MAX_RETRY_COUNT (ENGINE_CMD_BASE + 4)
#define QAT_CMD_SET_INTERNAL_POLL_INTERVAL (ENGINE_CMD_BASE + 5)
#define QAT_CMD_GET_EXTERNAL_POLLING_FD (ENGINE_CMD_BASE + 6)
#define QAT_CMD_ENABLE_EVENT_DRIVEN_POLLING_MODE (ENGINE_CMD_BASE + 7)
#define QAT_CMD_GET_NUM_CRYPTO_INSTANCES (ENGINE_CMD_BASE + 8)
#define QAT_CMD_DISABLE_EVENT_DRIVEN_POLLING_MODE (ENGINE_CMD_BASE + 9)
#define QAT_CMD_SET_EPOLL_TIMEOUT (ENGINE_CMD_BASE + 10)
#define QAT_CMD_SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD (ENGINE_CMD_BASE + 11)
#define QAT_CMD_ENABLE_INLINE_POLLING (ENGINE_CMD_BASE + 12)

static const ENGINE_CMD_DEFN qat_cmd_defns[] = {
    {
     QAT_CMD_ENABLE_EXTERNAL_POLLING,
     "ENABLE_EXTERNAL_POLLING",
     "Enables the external polling interface to the engine.",
     ENGINE_CMD_FLAG_NO_INPUT},
    {
     QAT_CMD_POLL,
     "POLL",
     "Polls the engine for any completed requests",
     ENGINE_CMD_FLAG_NO_INPUT},
    {
     QAT_CMD_SET_INSTANCE_FOR_THREAD,
     "SET_INSTANCE_FOR_THREAD",
     "Set instance to be used by this thread",
     ENGINE_CMD_FLAG_NUMERIC},
    {
     QAT_CMD_GET_NUM_OP_RETRIES,
     "GET_NUM_OP_RETRIES",
     "Get number of retries",
     ENGINE_CMD_FLAG_NO_INPUT},
    {
     QAT_CMD_SET_MAX_RETRY_COUNT,
     "SET_MAX_RETRY_COUNT",
     "Set maximum retry count",
     ENGINE_CMD_FLAG_NUMERIC},
    {
     QAT_CMD_SET_INTERNAL_POLL_INTERVAL,
     "SET_INTERNAL_POLL_INTERVAL",
     "Set internal polling interval",
     ENGINE_CMD_FLAG_NUMERIC},
    {
     QAT_CMD_GET_EXTERNAL_POLLING_FD,
     "GET_EXTERNAL_POLLING_FD",
     "Returns non blocking fd for crypto engine",
     ENGINE_CMD_FLAG_NO_INPUT},
    {
     QAT_CMD_ENABLE_EVENT_DRIVEN_POLLING_MODE,
     "ENABLE_EVENT_DRIVEN_POLLING_MODE",
     "Set event driven polling mode",
     ENGINE_CMD_FLAG_NO_INPUT},
    {
     QAT_CMD_GET_NUM_CRYPTO_INSTANCES,
     "GET_NUM_CRYPTO_INSTANCES",
     "Get the number of crypto instances",
     ENGINE_CMD_FLAG_NO_INPUT},
    {
     QAT_CMD_DISABLE_EVENT_DRIVEN_POLLING_MODE,
     "DISABLE_EVENT_DRIVEN_POLLING_MODE",
     "Unset event driven polling mode",
     ENGINE_CMD_FLAG_NO_INPUT},
    {
     QAT_CMD_SET_EPOLL_TIMEOUT,
     "SET_EPOLL_TIMEOUT",
     "Set epoll_wait timeout",
     ENGINE_CMD_FLAG_NUMERIC},
    {
     QAT_CMD_SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD,
     "SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD",
     "Set QAT small packet threshold",
     ENGINE_CMD_FLAG_STRING},
    {
     QAT_CMD_ENABLE_INLINE_POLLING,
     "ENABLE_INLINE_POLLING",
     "Enables the inline polling mode.",
     ENGINE_CMD_FLAG_NO_INPUT},
    {0, NULL, NULL, 0}
};

/******************************************************************************
* function:
*         qat_engine_ctrl(ENGINE *e, int cmd, long i,
*                         void *p, void (*f)(void))
*
* @param e   [IN] - OpenSSL engine pointer
* @param cmd [IN] - Control Command
* @param i   [IN] - Unused
* @param p   [IN] - Parameters for the command
* @param f   [IN] - Callback function
*
* description:
*   Qat engine control functions.
*   Note: QAT_CMD_ENABLE_EXTERNAL_POLLING should be called at the following
*         point during startup:
*         ENGINE_load_qat
*         ENGINE_by_id
*    ---> ENGINE_ctrl_cmd(QAT_CMD_ENABLE_EXTERNAL_POLLING)
*         ENGINE_init
******************************************************************************/

static int
qat_engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    unsigned int retVal = 1;
    CpaStatus status = CPA_STATUS_SUCCESS;
    int flags = 0;
    int fd = 0;

    switch (cmd) {
    case QAT_CMD_POLL:
        BREAK_IF(!engine_inited, "POLL failed as engine is not initialized\n");
        BREAK_IF(qat_instance_handles == NULL, "POLL failed as no instances are available\n");
        BREAK_IF(!enable_external_polling, "POLL failed as external polling is not enabled\n");
        BREAK_IF(p == NULL, "POLL failed as the input parameter was NULL\n");

        *(int *)p = (int)poll_instances();
        break;

    case QAT_CMD_ENABLE_EXTERNAL_POLLING:
        BREAK_IF(engine_inited, \
                "ENABLE_EXTERNAL_POLLING failed as the engine is already initialized\n");
        DEBUG("Enabled external polling\n");
        enable_external_polling = 1;
        enable_inline_polling = 0;
        break;

    case QAT_CMD_ENABLE_INLINE_POLLING:
        BREAK_IF(engine_inited, \
                "ENABLE_INLINE_POLLING failed as the engine is already initialized\n");
        DEBUG("Enabled inline polling\n");
        enable_inline_polling = 1;
        enable_external_polling = 0;
        break;

    case QAT_CMD_GET_EXTERNAL_POLLING_FD:
        BREAK_IF(!enable_event_driven_polling || !enable_external_polling, \
                "GET_EXTERNAL_POLLING_FD failed as this engine message is only supported \
                when running in Event Driven Mode with External Polling enabled\n");
        BREAK_IF(!engine_inited, \
                "GET_EXTERNAL_POLLING_FD failed as the engine is not initialized\n");
        BREAK_IF(qat_instance_handles == NULL,                          \
                 "GET_EXTERNAL_POLLING_FD failed as no instances are available\n");
        BREAK_IF(p == NULL, "GET_EXTERNAL_POLLING_FD failed as the input parameter was NULL\n");
        BREAK_IF(i >= qat_num_instances, \
                "GET_EXTERNAL_POLLING_FD failed as the instance does not exist\n");

        /* Get the file descriptor for the instance */
        status = icp_sal_CyGetFileDescriptor(qat_instance_handles[i], &fd);
        BREAK_IF(CPA_STATUS_FAIL == status, \
                "GET_EXTERNAL_POLLING_FD failed as there was an error retrieving the fd\n");
        /* Make the file descriptor non-blocking */
        flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        DEBUG("External polling FD for instance[%ld] = %d\n", i, fd);
        *(int *)p = fd;
        break;

    case QAT_CMD_ENABLE_EVENT_DRIVEN_POLLING_MODE:
        DEBUG("Enabled event driven polling mode\n");
        BREAK_IF(engine_inited, \
                "ENABLE_EVENT_DRIVEN_POLLING_MODE failed as the engine is already initialized\n");
        enable_event_driven_polling = 1;
        break;

    case QAT_CMD_DISABLE_EVENT_DRIVEN_POLLING_MODE:
        DEBUG("Disabled event driven polling mode\n");
        BREAK_IF(engine_inited, \
                "DISABLE_EVENT_DRIVEN_POLLING_MODE failed as the engine is already initialized\n");
        enable_event_driven_polling = 0;
        break;

    case QAT_CMD_SET_INSTANCE_FOR_THREAD:
        BREAK_IF(!engine_inited, \
                "SET_INSTANCE_FOR_THREAD failed as the engine is not initialized\n");
        BREAK_IF(qat_instance_handles == NULL,                          \
                 "SET_INSTANCE_FOR_THREAD failed as no instances are available\n");
        DEBUG("Set instance for thread = %ld\n", i);
        qat_set_instance_for_thread(i);
        break;

    case QAT_CMD_GET_NUM_OP_RETRIES:
        BREAK_IF(p == NULL, "GET_NUM_OP_RETRIES failed as the input parameter was NULL\n");
        BREAK_IF(!engine_inited, "GET_NUM_OP_RETRIES failed as the engine is not initialized\n");
        *(int *)p = qatPerformOpRetries;
        break;

    case QAT_CMD_SET_MAX_RETRY_COUNT:
        BREAK_IF(i < -1 || i > 100000,
            "The Message retry count value is out of range, using default value\n");
        DEBUG("Set max retry counter = %ld\n", i);
        qat_max_retry_count = (int)i;
        break;

    case QAT_CMD_SET_INTERNAL_POLL_INTERVAL:
        BREAK_IF(i < 1 || i > 1000000,
               "The polling interval value is out of range, using default value\n");
        DEBUG("Set internal poll interval = %ld ns\n", i);
        qat_poll_interval = (useconds_t) i;
        break;

    case QAT_CMD_SET_EPOLL_TIMEOUT:
        BREAK_IF(i < 1 || i > 10000,
                "The epoll timeout value is out of range, using default value\n")
        DEBUG("Set epoll_wait timeout = %ld ms\n", i);
        qat_epoll_timeout = (int) i;
        break;

    case QAT_CMD_GET_NUM_CRYPTO_INSTANCES:
        BREAK_IF(p == NULL, \
                "GET_NUM_CRYPTO_INSTANCES failed as the input parameter was NULL\n");
        BREAK_IF(!engine_inited, \
                "GET_NUM_CRYPTO_INSTANCES failed as the engine is not initialized\n");
        BREAK_IF(qat_instance_handles == NULL,                          \
                 "GET_NUM_CRYPTO_INSTANCES failed as no instances are available\n");
        DEBUG("Get number of crypto instances = %d\n", qat_num_instances);
        *(int *)p = qat_num_instances;
        break;

    case QAT_CMD_SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        if(p) {
            char *token;
            char str_p[1024];
            char *itr = str_p;
            strncpy(str_p, (const char *)p, 1024);
            while((token = strsep(&itr, ","))) {
                char *name_token = strsep(&token,":");
                char *value_token = strsep(&token,":");
                if(name_token && value_token) {
                    retVal = qat_pkt_threshold_table_set_threshold(
                                name_token, atoi(value_token));
                } else {
                    WARN("Invalid name_token or value_token\n");
                    retVal = 0;
                }
            }
        } else {
            WARN("Invalid p parameter\n");
            retVal = 0;
        }
#else
        WARN("QAT_CMD_SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD is not supported\n");
        retVal = 0;
#endif
        break;

    default:
        WARN("CTRL command not implemented\n");
        retVal = 0;
        break;
    }
    if(!retVal) {
     QATerr(QAT_F_QAT_ENGINE_CTRL, QAT_R_ENGINE_CTRL_CMD_FAILURE);
    }
    return retVal;
}

int qat_engine_finish_int(ENGINE *e, int reset_globals)
{

    int i;
    int ret = 1;
    CpaStatus status = CPA_STATUS_SUCCESS;
    ENGINE_EPOLL_ST *epollst = NULL;
    int pthread_kill_ret;

    DEBUG("---- Engine Finishing...\n\n");

    pthread_mutex_lock(&qat_engine_mutex);
    keep_polling = 0;
    if (qat_use_signals()) {
        pthread_kill_ret = pthread_kill(timer_poll_func_thread, SIGUSR1);
        if (pthread_kill_ret != 0) {
            WARN("pthread_kill error\n");
            QATerr(QAT_F_QAT_ENGINE_FINISH_INT, QAT_R_PTHREAD_KILL_FAILURE);
            ret = 0;
        }
    }

    if (qat_instance_handles) {
        for (i = 0; i < qat_num_instances; i++) {
            if(instance_started[i]) {
                status = cpaCyStopInstance(qat_instance_handles[i]);

                if (CPA_STATUS_SUCCESS != status) {
                    WARN("cpaCyStopInstance failed, status=%d\n", status);
                    QATerr(QAT_F_QAT_ENGINE_FINISH_INT, QAT_R_STOP_INSTANCE_FAILURE);
                    ret = 0;
                }

                instance_started[i] = 0;
            }
        }
    }

    /* If polling thread is different from the main thread, wait for polling
     * thread to finish. pthread_equal returns 0 when threads are different.
     */
    if (!enable_external_polling && !enable_inline_polling &&
        pthread_equal(polling_thread, pthread_self()) == 0) {
        if (qat_join_thread(polling_thread, NULL) != 0) {
            WARN("Polling thread join failed with status: %d\n", ret);
            QATerr(QAT_F_QAT_ENGINE_FINISH_INT, QAT_R_PTHREAD_JOIN_FAILURE);
            ret = 0;
        }
    }

    polling_thread = pthread_self();

    if (qat_instance_handles) {
        OPENSSL_free(qat_instance_handles);
        qat_instance_handles = NULL;
    }

    if (!enable_external_polling && !enable_inline_polling &&
        qat_is_event_driven()) {
        for (i = 0; i < qat_num_instances; i++) {
            epollst = (ENGINE_EPOLL_ST*)eng_epoll_events[i].data.ptr;
            if (epollst) {
                if (-1 ==
                    epoll_ctl(internal_efd, EPOLL_CTL_DEL,
                              epollst->eng_fd,
                              &eng_epoll_events[i])) {
                    WARN("Error removing fd from epoll\n");
                    QATerr(QAT_F_QAT_ENGINE_FINISH_INT, QAT_R_EPOLL_CTL_FAILURE);
                    ret = 0;
                }
                close(epollst->eng_fd);
            }
        }
    }


    /* Reset global variables */
    qat_num_instances = 0;
    icp_sal_userStop();
    engine_inited = 0;
    internal_efd = 0;
    qat_instance_handles = NULL;
    keep_polling = 1;
    curr_inst = 0;
    qatPerformOpRetries = 0;

    /* Reset the configuration global variables (to their default values) only
     * if requested, i.e. when we are not re-initializing the engine after
     * forking
     */
    if (reset_globals) {
        enable_external_polling = 0;
        enable_inline_polling = 0;
        enable_event_driven_polling = 0;
        enable_instance_for_thread = 0;
        qat_poll_interval = QAT_POLL_PERIOD_IN_NS;
        qat_max_retry_count = QAT_CRYPTO_NUM_POLLING_RETRIES;
    }

    pthread_mutex_unlock(&qat_engine_mutex);

    CRYPTO_CLOSE_QAT_LOG();

    return ret;
}

int qat_engine_finish(ENGINE *e) {
    return qat_engine_finish_int(e, QAT_RESET_GLOBALS);
}

/******************************************************************************
* function:
*         qat_engine_destroy(ENGINE *e)
*
* @param e [IN] - OpenSSL engine pointer
*
* description:
*   Qat engine destroy function, required by Openssl engine API.
*   Cleanup all the method structures here.
*
******************************************************************************/
static int qat_engine_destroy(ENGINE *e)
{
    DEBUG("---- Destroying Engine...\n\n");
    qat_free_ciphers();
    qat_free_EC_methods();
    qat_free_DH_methods();
    qat_free_DSA_methods();
    qat_free_RSA_methods();
    QAT_DEBUG_LOG_CLOSE();
    ERR_unload_QAT_strings();
    return 1;
}

/******************************************************************************
* function:
*         bind_qat(ENGINE *e,
*                  const char *id)
*
* @param e  [IN] - OpenSSL engine pointer
* @param id [IN] - engine id
*
* description:
*    Connect Qat engine to OpenSSL engine library
******************************************************************************/
static int bind_qat(ENGINE *e, const char *id)
{
    int ret = 0;
#ifndef OPENSSL_ENABLE_QAT_UPSTREAM_DRIVER
    int upstream_flags = 0;
    unsigned int devmasks[] = { 0, 0, 0, 0, 0 };
#endif

    QAT_DEBUG_LOG_INIT();

    WARN("QAT Warnings enabled.\n");
    DEBUG("QAT Debug enabled.\n");
    DEBUG("id=%s\n", id);

    if (access(QAT_DEV, F_OK) != 0) {
        WARN("Qat memory driver not present\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_MEM_DRV_NOT_PRESENT);
        goto end;
    }

#ifndef OPENSSL_ENABLE_QAT_UPSTREAM_DRIVER
    if (!getDevices(devmasks, &upstream_flags)) {
        WARN("Qat device not present\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_QAT_DEV_NOT_PRESENT);
        goto end;
    }
#endif

    if (id && (strcmp(id, engine_qat_id) != 0)) {
        WARN("ENGINE_id defined already!\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_ID_ALREADY_DEFINED);
        goto end;
    }

    if (!ENGINE_set_id(e, engine_qat_id)) {
        WARN("ENGINE_set_id failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_ID_FAILURE);
        goto end;
    }

    if (!ENGINE_set_name(e, engine_qat_name)) {
        WARN("ENGINE_set_name failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_NAME_FAILURE);
        goto end;
    }

    /* Ensure the QAT error handling is set up */
    ERR_load_QAT_strings();

    /*
     * Create static structures for ciphers now
     * as this function will be called by a single thread.
     */
    qat_create_ciphers();

    if (!ENGINE_set_RSA(e, qat_get_RSA_methods())) {
        WARN("ENGINE_set_RSA failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_RSA_FAILURE);
        goto end;
    }

    if (!ENGINE_set_DSA(e, qat_get_DSA_methods())) {
        WARN("ENGINE_set_DSA failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_DSA_FAILURE);
        goto end;
    }

    if (!ENGINE_set_DH(e, qat_get_DH_methods())) {
        WARN("ENGINE_set_DH failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_DH_FAILURE);
        goto end;
    }

    if (!ENGINE_set_EC(e, qat_get_EC_methods())) {
        WARN("ENGINE_set_EC failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_EC_FAILURE);
        goto end;
    }

    if (!ENGINE_set_ciphers(e, qat_ciphers)) {
        WARN("ENGINE_set_ciphers failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_CIPHER_FAILURE);
        goto end;
    }

    if (!ENGINE_set_pkey_meths(e, qat_PRF_pkey_methods)) {
        WARN("ENGINE_set_pkey_meths failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_PKEY_FAILURE);
        goto end;
    }

    pthread_atfork(engine_finish_before_fork_handler, NULL,
                   engine_init_child_at_fork_handler);

    ret = 1;
    ret &= ENGINE_set_destroy_function(e, qat_engine_destroy);
    ret &= ENGINE_set_init_function(e, qat_engine_init);
    ret &= ENGINE_set_finish_function(e, qat_engine_finish);
    ret &= ENGINE_set_ctrl_function(e, qat_engine_ctrl);
    ret &= ENGINE_set_cmd_defns(e, qat_cmd_defns);
    if (ret == 0) {
        WARN("Engine failed to register init, finish or destroy functions\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_REGISTER_FUNC_FAILURE);
    }

 end:
    return ret;

}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
IMPLEMENT_DYNAMIC_BIND_FN(bind_qat)
    IMPLEMENT_DYNAMIC_CHECK_FN()
#endif                          /* ndef OPENSSL_NO_DYNAMIC_ENGINE */
/* initialize Qat Engine if OPENSSL_NO_DYNAMIC_ENGINE*/
#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_qat(void)
{
    ENGINE *ret = NULL;
    DEBUG("- Starting\n");

    ret = ENGINE_new();

    if (!ret) {
        WARN("Failed to create Engine\n");
        QATerr(QAT_F_ENGINE_QAT, QAT_R_QAT_CREATE_ENGINE_FAILURE);
        return NULL;
    }

    if (!bind_qat(ret, engine_qat_id)) {
        WARN("Qat engine bind failed\n");
        ENGINE_free(ret);
        return NULL;
    }

    return ret;
}

void ENGINE_load_qat(void)
{
    ENGINE *toadd;
    int error = 0;
    char error_string[QAT_MAX_ERROR_STRING] = { 0 };

    QAT_DEBUG_LOG_INIT();
    DEBUG("- Starting\n");

    toadd = engine_qat();
    if (toadd == NULL) {
        error = ERR_peek_error();
        ERR_error_string_n(error, error_string, QAT_MAX_ERROR_STRING);
        WARN("Error reported by engine load: %s\n", error_string);
        return;
    }

    DEBUG("adding engine\n");
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}

#endif
