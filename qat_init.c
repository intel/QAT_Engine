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
 * @file qat_init.c
 *
 * This file provides a QAT Engine initialization functions.
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifndef __USE_GNU
# define __USE_GNU
#endif

#define NANOSECONDS_TO_MICROSECONDS 1000

/* Standard Includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#ifndef __FreeBSD__
# include <sys/epoll.h>
# include <sys/types.h>
# include <sys/eventfd.h>
#endif
#include <unistd.h>
#include <signal.h>
#include <time.h>

/* Local Includes */
#include "qat_init.h"
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
#include "qat_evp.h"
#include "qat_parseconf.h"
#include "e_qat_err.h"

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
#include "cpa_cy_common.h"
#include "cpa_types.h"
#include "icp_sal_user.h"
#include "icp_sal_poll.h"

#define QAT_MAX_INPUT_STRING_LENGTH 1024

CpaInstanceHandle *qat_instance_handles = NULL;
Cpa16U qat_num_instances = 0;
Cpa32U qat_num_devices = 0;
pthread_key_t thread_local_variables;
pthread_t polling_thread;
int keep_polling = 1;
int enable_external_polling = 0;
int enable_inline_polling = 0;
int enable_event_driven_polling = 0;
int enable_heuristic_polling = 0;
int enable_instance_for_thread = 0;
int enable_sw_fallback = 0;
int disable_qat_offload = 0;
pthread_mutex_t qat_instance_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t qat_engine_mutex = PTHREAD_MUTEX_INITIALIZER;

unsigned int engine_inited = 0;
qat_instance_details_t qat_instance_details[QAT_MAX_CRYPTO_INSTANCES] = {{{0}}};
qat_accel_details_t qat_accel_details[QAT_MAX_CRYPTO_ACCELERATORS] = {{0}};

useconds_t qat_poll_interval = QAT_POLL_PERIOD_IN_NS;
int qat_epoll_timeout = QAT_EPOLL_TIMEOUT_IN_MS;
int qat_max_retry_count = QAT_CRYPTO_NUM_POLLING_RETRIES;
int num_requests_in_flight = 0;
int num_asym_requests_in_flight = 0;
int num_kdf_requests_in_flight = 0;
int num_cipher_pipeline_requests_in_flight = 0;
/* rsa queues not used in case of QAT offload */
int num_items_rsa_priv_queue = 0;
int num_items_rsa_pub_queue = 0;

sigset_t set = {{0}};
pthread_t timer_poll_func_thread = 0;
int cleared_to_start = 0;

int qat_get_qat_offload_disabled(void)
{
    if (disable_qat_offload ||
        (qat_get_sw_fallback_enabled() && !is_any_device_available()))
        return 1;
    else
        return 0;
}

int qat_get_sw_fallback_enabled(void)
{
    return enable_sw_fallback;
}


/******************************************************************************
 * function:
 *         qat_engine_finish(ENGINE *e)
 *
 * @param e [IN] - OpenSSL engine pointer
 *
 * description:
 *   Qat engine finish function with standard signature.
 *   This is a wrapper for qat_engine_finish_int that always resets all the
 *   global variables used to store the engine configuration.
 ******************************************************************************/
int qat_engine_finish(ENGINE *e);

static inline int qat_use_signals_no_engine_start(void)
{
    return (int) (intptr_t) timer_poll_func_thread;
}

int qat_use_signals(void)
{
    /* We check engine_inited outside of a mutex here because it is more
       efficient and we are only interested in the state if it hasn't been
       initialised. The usual case is that the engine will have been
       initialised and we can carry on without locking. If the engine hasn't
       been initialised then there will be a further check within
       qat_engine_init inside a mutex to prevent a race condition. */

    if (unlikely(!engine_inited)) {
        ENGINE* e = ENGINE_by_id(engine_qat_id);

        if (e == NULL) {
            WARN("Function ENGINE_by_id returned NULL\n");
            return 0;
        }

        if (!qat_engine_init(e)) {
            WARN("Failure in qat_engine_init function\n");
            ENGINE_free(e);
            return 0;
        }

        ENGINE_free(e);
    }

    return qat_use_signals_no_engine_start();
}

int validate_configuration_section_name(const char *name)
{
    int len = 0;

    if (name == NULL) {
        return 0;
    }

    len = strlen(name);

    if (len == 0 || len >= QAT_CONFIG_SECTION_NAME_SIZE) {
        WARN("Invalid section name length %d\n", len);
        return 0;
    }

    return 1;
}

int is_instance_available(int inst_num)
{
    if (inst_num > qat_num_instances)
        return 0;

    if (!qat_instance_details[inst_num].qat_instance_started)
        return 0;

    return !qat_accel_details[qat_instance_details[inst_num].
        qat_instance_info.
        physInstId.packageId].qat_accel_reset_status;
}

int is_any_device_available(void)
{
    int device_num = 0;

    if (qat_num_devices == 0)
        return 0;

    for (device_num = 0; device_num < qat_num_devices; device_num++) {
        if (qat_accel_details[device_num].qat_accel_reset_status == 0) {
            return 1;
        }
    }

    return 0;
}

int get_next_inst_num(void)
{
    int inst_num = QAT_INVALID_INSTANCE;
    unsigned int inst_count = 0;
    thread_local_variables_t * tlv = NULL;

    /* See qat_use_signals() above for more info on why it is safe to
       check engine_inited outside of a mutex in this case. */
    if (unlikely(!engine_inited)) {
        ENGINE* e = ENGINE_by_id(engine_qat_id);

        if (e == NULL) {
            WARN("Function ENGINE_by_id returned NULL\n");
            return inst_num;
        }

        if (!qat_engine_init(e)) {
            WARN("Failure in qat_engine_init function\n");
            ENGINE_free(e);
            return inst_num;
        }

        ENGINE_free(e);
    }

    tlv = qat_check_create_local_variables();
    if (unlikely(NULL == tlv)) {
        WARN("No local variables are available\n");
        return inst_num;
    }

    if (0 == enable_instance_for_thread) {
        if (likely(qat_instance_handles && qat_num_instances)) {
            do {
                inst_count++;
                tlv->qatInstanceNumForThread = (tlv->qatInstanceNumForThread + 1) %
                    qat_num_instances;
            } while (!is_instance_available(tlv->qatInstanceNumForThread) &&
                    inst_count <= qat_num_instances);
            if (likely(inst_count <= qat_num_instances)) {
                inst_num = tlv->qatInstanceNumForThread;
            }
        }
    } else {
        if (tlv->qatInstanceNumForThread != QAT_INVALID_INSTANCE) {
            if (is_instance_available(tlv->qatInstanceNumForThread)) {
                inst_num = tlv->qatInstanceNumForThread;
            }
        }
    }
    /* If no working instance could be found then flag a warning */
    if (unlikely(inst_num == QAT_INVALID_INSTANCE)) {
        WARN("No working instance is available\n");
    }

    return inst_num;
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

thread_local_variables_t * qat_check_create_local_variables(void)
{
    thread_local_variables_t * tlv =
        (thread_local_variables_t *)qat_getspecific_thread(thread_local_variables);
    if (tlv != NULL)
        return tlv;
    tlv = OPENSSL_zalloc(sizeof(thread_local_variables_t));
    if (tlv != NULL) {
        tlv->qatInstanceNumForThread = QAT_INVALID_INSTANCE;
        qat_setspecific_thread(thread_local_variables, (void *)tlv);
    }
    return tlv;
}


/******************************************************************************
 * function:
 *         qat_local_variable_destructor(void *tlv)
 *
 * description:
 *   This is a cleanup callback function registered when pthread_key_create()
 *   is called. It will get called when the thread is destroyed and will
 *   cleanup the thread local variables.
 *
 *****************************************************************************/
static void qat_local_variable_destructor(void *tlv)
{
    if (tlv)
        OPENSSL_free(tlv);
    qat_setspecific_thread(thread_local_variables, NULL);
}


#ifdef OPENSSL_ENABLE_QAT_UPSTREAM_DRIVER
# ifndef __FreeBSD__
void qat_instance_notification_callbackFn(const CpaInstanceHandle ih, void *callbackTag,
                                          const CpaInstanceEvent inst_ev)
{
    Cpa32U packageId;
    struct timespec ts = { 0 };

    switch (inst_ev) {
        case CPA_INSTANCE_EVENT_FATAL_ERROR:
            WARN("Received Callback that instance %ld is unavailable\n",
                    (intptr_t)callbackTag);
            packageId =
                qat_instance_details[(intptr_t)callbackTag].qat_instance_info.physInstId.packageId;
            qat_accel_details[packageId].qat_accel_reset_status = 1;
            clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
            CRYPTO_QAT_LOG("[%lld.%06ld] Instance: %ld Handle %p Device %d RESTARTING \n",
                    (long long)ts.tv_sec, ts.tv_nsec / NANOSECONDS_TO_MICROSECONDS,
                    (intptr_t)callbackTag, ih, packageId);
            break;
        case CPA_INSTANCE_EVENT_RESTARTING:
            WARN("Received Callback that instance %ld is restarting\n",
                    (intptr_t)callbackTag);
            break;
        case CPA_INSTANCE_EVENT_RESTARTED:
            WARN("Received Callback that instance %ld is available\n",
                    (intptr_t)callbackTag);
            packageId =
                qat_instance_details[(intptr_t)callbackTag].qat_instance_info.physInstId.packageId;
            qat_accel_details[packageId].qat_accel_reset_status = 0;
            clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
            CRYPTO_QAT_LOG("[%lld.%06ld] Instance: %ld Handle %p Device %d RESTARTED \n",
                    (long long)ts.tv_sec, ts.tv_nsec / NANOSECONDS_TO_MICROSECONDS,
                    (intptr_t)callbackTag, ih, packageId);
            break;
        default:
            WARN("Fatal Error detected for instance: %ld\n", (intptr_t)callbackTag);
            break;
    }
}
# endif
#endif

int qat_engine_init(ENGINE *e)
{
    int instNum, err;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBoolean limitDevAccess = CPA_FALSE;
    int ret_pthread_sigmask;
    Cpa32U package_id = 0;


    pthread_mutex_lock(&qat_engine_mutex);
    if (engine_inited) {
        pthread_mutex_unlock(&qat_engine_mutex);
        return 1;
    }

    DEBUG("QAT Engine initialization:\n");
    DEBUG("- External polling: %s\n", enable_external_polling ? "ON": "OFF");
    DEBUG("- SW Fallback: %s\n", enable_sw_fallback ? "ON": "OFF");
    DEBUG("- Inline polling: %s\n", enable_inline_polling ? "ON": "OFF");
    DEBUG("- Internal poll interval: %dns\n", qat_poll_interval);
    DEBUG("- Epoll timeout: %dms\n", qat_epoll_timeout);
    DEBUG("- Event driven polling mode: %s\n", enable_event_driven_polling ? "ON": "OFF");
    DEBUG("- Instance for thread: %s\n", enable_instance_for_thread ? "ON": "OFF");
    DEBUG("- Max retry count: %d\n", qat_max_retry_count);

    CRYPTO_INIT_QAT_LOG();

    polling_thread = pthread_self();

    if ((err = pthread_key_create(&thread_local_variables, qat_local_variable_destructor)) != 0) {
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
        pthread_key_delete(thread_local_variables);
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
#ifndef __FreeBSD__
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

                flags = qat_fcntl(engine_fd, F_GETFL, 0);
                if (qat_fcntl(engine_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
                    WARN("Failed to set engine_fd as NON BLOCKING\n");
                    QATerr(QAT_F_QAT_ENGINE_INIT,
                           QAT_R_SET_FILE_DESCRIPTOR_NONBLOCKING_FAILURE);
                    pthread_mutex_unlock(&qat_engine_mutex);
                    qat_engine_finish(e);
                    return 0;
                }

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
#endif
    }

    /* Set translation function and start each instance */
    for (instNum = 0; instNum < qat_num_instances; instNum++) {
        /* Retrieve CpaInstanceInfo2 structure for that instance */
        status = cpaCyInstanceGetInfo2(qat_instance_handles[instNum],
                                       &qat_instance_details[instNum].qat_instance_info);
        if (CPA_STATUS_SUCCESS != status ) {
            WARN("cpaCyInstanceGetInfo2 failed. status = %d\n", status);
            QATerr(QAT_F_QAT_ENGINE_INIT, QAT_R_GET_INSTANCE_INFO_FAILURE);
            pthread_mutex_unlock(&qat_engine_mutex);
            qat_engine_finish(e);
            return 0;
        }

        package_id = qat_instance_details[instNum].qat_instance_info.physInstId.packageId;
        qat_accel_details[package_id].qat_accel_present = 1;
        if (package_id >= qat_num_devices) {
            qat_num_devices = package_id + 1;
        }

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

        qat_instance_details[instNum].qat_instance_started = 1;
        DEBUG("Started Instance No: %d Located on Device: %d\n", instNum, package_id);

#ifdef OPENSSL_ENABLE_QAT_UPSTREAM_DRIVER
# ifndef __FreeBSD__
        if (enable_sw_fallback) {
            DEBUG("cpaCyInstanceSetNotificationCb instNum = %d\n", instNum);
            status = cpaCyInstanceSetNotificationCb(qat_instance_handles[instNum],
                                                    qat_instance_notification_callbackFn,
                                                    (void *)(intptr_t)instNum);
            if (CPA_STATUS_SUCCESS != status) {
                WARN("cpaCyInstanceSetNotificationCb failed, status=%d\n", status);
                QATerr(QAT_F_QAT_ENGINE_INIT, QAT_R_SET_NOTIFICATION_CALLBACK_FAILURE);
                pthread_mutex_unlock(&qat_engine_mutex);
                qat_engine_finish(e);
                return 0;
            }
        }
# endif
#endif
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
#ifndef __FreeBSD__
        if (qat_create_thread(&polling_thread, NULL, qat_is_event_driven() ?
                              event_poll_func : timer_poll_func, NULL)) {
#else
        if (qat_create_thread(&polling_thread, NULL, timer_poll_func, NULL)) {
#endif
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
    engine_inited = 1;
    pthread_mutex_unlock(&qat_engine_mutex);
    return 1;
}

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

int qat_engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    unsigned int retVal = 1;
#ifndef __FreeBSD__
    CpaStatus status = CPA_STATUS_SUCCESS;
    int flags = 0;
    int fd = 0;
    int fcntl_ret = -1;
#endif



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

#ifndef __FreeBSD__
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
        flags = qat_fcntl(fd, F_GETFL, 0);
        fcntl_ret = qat_fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        BREAK_IF(fcntl_ret == -1, \
                 "GET_EXTERNAL_POLLING_FD failed as there was an error in setting the fd as NONBLOCKING\n");

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
#endif

    case QAT_CMD_SET_INSTANCE_FOR_THREAD:
        BREAK_IF(!engine_inited, \
                "SET_INSTANCE_FOR_THREAD failed as the engine is not initialized\n");
        BREAK_IF(qat_instance_handles == NULL,                          \
                 "SET_INSTANCE_FOR_THREAD failed as no instances are available\n");
        DEBUG("Set instance for thread = %ld\n", i);
        retVal = qat_set_instance_for_thread(i);
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
        if (p != NULL) {
            char *token;
            char str_p[QAT_MAX_INPUT_STRING_LENGTH];
            char *itr = str_p;
            strncpy(str_p, (const char *)p, QAT_MAX_INPUT_STRING_LENGTH - 1);
            str_p[QAT_MAX_INPUT_STRING_LENGTH - 1] = '\0';
            while ((token = strsep(&itr, ","))) {
                char *name_token = strsep(&token,":");
                char *value_token = strsep(&token,":");
                if (name_token && value_token) {
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

    case QAT_CMD_ENABLE_HEURISTIC_POLLING:
        BREAK_IF(engine_inited,
                "ENABLE_HEURISTIC_POLLING failed as the engine is already initialized\n");
        BREAK_IF(!enable_external_polling,
                "ENABLE_HEURISTIC_POLLING failed as external polling is not enabled\n");
        DEBUG("Enabled heuristic polling\n");
        enable_heuristic_polling = 1;
        break;

    case QAT_CMD_GET_NUM_REQUESTS_IN_FLIGHT:
        BREAK_IF(p == NULL,
                "GET_NUM_REQUESTS_IN_FLIGHT failed as the input parameter was NULL\n");
        if (i == GET_NUM_ASYM_REQUESTS_IN_FLIGHT) {
            *(int **)p = &num_asym_requests_in_flight;
        } else if (i == GET_NUM_KDF_REQUESTS_IN_FLIGHT) {
            *(int **)p = &num_kdf_requests_in_flight;
        } else if (i == GET_NUM_CIPHER_PIPELINE_REQUESTS_IN_FLIGHT) {
            *(int **)p = &num_cipher_pipeline_requests_in_flight;
        } else if (i == GET_NUM_ITEMS_RSA_PRIV_QUEUE) {
            *(int **)p = &num_items_rsa_priv_queue;
        } else if (i == GET_NUM_ITEMS_RSA_PUB_QUEUE) {
            *(int **)p = &num_items_rsa_pub_queue;
        } else {
            WARN("Invalid i parameter\n");
            retVal = 0;
        }
        break;

    case QAT_CMD_INIT_ENGINE:
        DEBUG("Init engine\n");
        if ((retVal = qat_engine_init(e)) == 0) {
            WARN("Failure initializing engine\n");
        }
        break;

    case QAT_CMD_SET_CONFIGURATION_SECTION_NAME:
        BREAK_IF(engine_inited, \
                "QAT_CMD_SET_CONFIGURATION_SECTION_NAME failed as the engine is already initialized\n");
        if (p) {
            retVal = validate_configuration_section_name(p);
            if (retVal) {
                strncpy(qat_config_section_name, p, QAT_CONFIG_SECTION_NAME_SIZE - 1);
                qat_config_section_name[QAT_CONFIG_SECTION_NAME_SIZE - 1]   = '\0';
            } else  {
                WARN("Section name is NULL or invalid length\n");
                retVal = 0;
            }
        } else {
            WARN("Invalid p parameter\n");
            retVal = 0;
        }
        break;
#ifndef __FreeBSD__
    case QAT_CMD_ENABLE_SW_FALLBACK:
# ifdef OPENSSL_ENABLE_QAT_UPSTREAM_DRIVER
        DEBUG("Enabled SW Fallback\n");
        BREAK_IF(engine_inited, \
                "ENABLE_SW_FALLBACK failed as the engine is already initialized\n");
        enable_sw_fallback = 1;
        CRYPTO_QAT_LOG("SW Fallback enabled - %s\n", __func__);
# else
        WARN("QAT_CMD_ENABLE_SW_FALLBACK is not supported\n");
        retVal = 0;
# endif
        break;

    case QAT_CMD_HEARTBEAT_POLL:
# ifdef OPENSSL_ENABLE_QAT_UPSTREAM_DRIVER
        BREAK_IF(!engine_inited, "HEARTBEAT_POLL failed as engine is not initialized\n");
        BREAK_IF(qat_instance_handles == NULL,
                 "HEARTBEAT_POLL failed as no instances are available\n");
        BREAK_IF(!enable_external_polling,
                 "HEARTBEAT_POLL failed as external polling is not enabled\n");
        BREAK_IF(p == NULL, "HEARTBEAT_POLL failed as the input parameter was NULL\n");

        *(int *)p = (int)poll_heartbeat();
        CRYPTO_QAT_LOG("QAT Engine Heartbeat Poll - %s\n", __func__);
# else
        WARN("QAT_CMD_HEARTBEAT_POLL is not supported\n");
        retVal = 0;
# endif
        break;
#endif

    case QAT_CMD_DISABLE_QAT_OFFLOAD:
        DEBUG("Disabled qat offload\n");
        BREAK_IF(!engine_inited, \
                "DISABLE_QAT_OFFLOAD failed as the engine is not initialized\n");
        disable_qat_offload = 1;
        CRYPTO_QAT_LOG("QAT Engine Offload disabled - %s\n", __func__);
        break;

    default:
        WARN("CTRL command not implemented\n");
        retVal = 0;
        break;
    }

    if (!retVal) {
        QATerr(QAT_F_QAT_ENGINE_CTRL, QAT_R_ENGINE_CTRL_CMD_FAILURE);
    }
    return retVal;
}

int qat_engine_finish_int(ENGINE *e, int reset_globals)
{

    int i;
    int ret = 1;
    CpaStatus status = CPA_STATUS_SUCCESS;
#ifndef __FreeBSD__
    ENGINE_EPOLL_ST *epollst = NULL;
#endif

    DEBUG("---- Engine Finishing...\n\n");

    pthread_mutex_lock(&qat_engine_mutex);
    keep_polling = 0;
    if (qat_use_signals_no_engine_start()) {
        if (qat_kill_thread(timer_poll_func_thread, SIGUSR1) != 0) {
            WARN("qat_kill_thread error\n");
            QATerr(QAT_F_QAT_ENGINE_FINISH_INT, QAT_R_PTHREAD_KILL_FAILURE);
            ret = 0;
        }
    }

    if (qat_instance_handles) {
        for (i = 0; i < qat_num_instances; i++) {
            if (qat_instance_details[i].qat_instance_started) {
                status = cpaCyStopInstance(qat_instance_handles[i]);

                if (CPA_STATUS_SUCCESS != status) {
                    WARN("cpaCyStopInstance failed, status=%d\n", status);
                    QATerr(QAT_F_QAT_ENGINE_FINISH_INT, QAT_R_STOP_INSTANCE_FAILURE);
                    ret = 0;
                }

                qat_instance_details[i].qat_instance_started = 0;
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

    if (!enable_external_polling && !enable_inline_polling) {
#ifndef __FreeBSD__
        if (qat_is_event_driven()) {
            for (i = 0; i < qat_num_instances; i++) {
                epollst = (ENGINE_EPOLL_ST*)eng_epoll_events[i].data.ptr;
                if (epollst) {
                    if (-1 == epoll_ctl(internal_efd, EPOLL_CTL_DEL,
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
#endif
    }

    CRYPTO_QAT_LOG("Number of remaining in-flight requests = %d - %s\n",
                   num_requests_in_flight, __func__);

    /* Reset global variables */
    qat_num_instances = 0;
    qat_num_devices = 0;
    icp_sal_userStop();
    engine_inited = 0;
    internal_efd = 0;
    qat_instance_handles = NULL;
    keep_polling = 1;
    qatPerformOpRetries = 0;

    DEBUG("Calling pthread_key_delete()\n");
    pthread_key_delete(thread_local_variables);


    /* Reset the configuration global variables (to their default values) only
     * if requested, i.e. when we are not re-initializing the engine after
     * forking
     */
    if (reset_globals == 1) {
        enable_external_polling = 0;
        enable_inline_polling = 0;
        enable_event_driven_polling = 0;
        enable_instance_for_thread = 0;
        enable_sw_fallback = 0;
        disable_qat_offload = 0;
        qat_poll_interval = QAT_POLL_PERIOD_IN_NS;
        qat_max_retry_count = QAT_CRYPTO_NUM_POLLING_RETRIES;
        enable_heuristic_polling = 0;
    }

    pthread_mutex_unlock(&qat_engine_mutex);

    CRYPTO_CLOSE_QAT_LOG();

    return ret;
}

int qat_engine_finish(ENGINE *e) {
    return qat_engine_finish_int(e, QAT_RESET_GLOBALS);
}
