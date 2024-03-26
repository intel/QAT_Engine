/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020-2024 Intel Corporation.
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
 * @file qat_hw_init.c
 *
 * This file provides QAT Engine qat_hw initialization functions.
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
#include "e_qat.h"
#include "qat_fork.h"
#include "qat_events.h"
#include "qat_hw_callback.h"
#include "qat_hw_polling.h"
#include "qat_utils.h"

/* OpenSSL Includes */
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/crypto.h>

/* QAT includes */
#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_common.h"
#include "cpa_types.h"
#include "icp_sal_user.h"
#include "icp_sal_poll.h"

/* 1. QAT HW mode, Check if QAT Engine Offload disabled. If yes, fallback to OpenSSL.
   2. Co-Existence mode, if QAT HW initialization fail, fallback to QAT SW.
   3. Sw fallback on, if instance not available, fallback to OpenSSL.
 */
int qat_get_qat_offload_disabled(void)
{
    if (disable_qat_offload || fallback_to_qat_sw ||
        (qat_get_sw_fallback_enabled() && !is_any_device_available()))
        return 1;
    else
        return 0;
}

int qat_get_sw_fallback_enabled(void)
{
#ifdef ENABLE_QAT_FIPS
	return 0;
#else
    return enable_sw_fallback;
#endif
}

static inline int qat_use_signals_no_engine_start(void)
{
    return (int) (intptr_t) qat_timer_poll_func_thread;
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
            ENGINE_QAT_PTR_RESET();
            return 0;
        }

        ENGINE_free(e);
        ENGINE_QAT_PTR_RESET();
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

#ifdef ENABLE_QAT_HW_KPT
    thread_local_variables_t * tlv = NULL;

    tlv = qat_check_create_local_variables();
    if (unlikely(NULL == tlv)) {
        WARN("No local variables are available\n");
        return 0;
    }

    /* Return 0 if the KPT isn't initialized or provisioned
     * while using the WPK in the current request. */
    if (tlv->kpt_wpk_in_use > -1 &&
        (!is_kpt_mode() || 
            !kpt_instance_available(inst_num, tlv->kpt_wpk_in_use)))
        return 0;
#endif

    return !qat_accel_details[qat_instance_details[inst_num].
        qat_instance_info.physInstId.packageId].qat_accel_reset_status;
}

int is_any_device_available(void)
{
    int device_num = 0;

    if (qat_num_devices == 0)
        return 0;

    for (device_num = 0; device_num < qat_num_devices; device_num++) {
        if (qat_accel_details[device_num].qat_accel_reset_status == 0)
            return 1;
    }

    return 0;
}

int is_instance_svm(int inst_num)
{
    return !qat_instance_details[inst_num].qat_instance_info.requiresPhysicallyContiguousMemory;
}

int get_instance(int inst_type, int mem_type)
{
    int inst_num = QAT_INVALID_INSTANCE;
    int apl_inst_count; /* Applicable Instance Count */
    int *inst_idx;
    unsigned int *inst_map;

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
        ENGINE_QAT_PTR_RESET();
    }

    tlv = qat_check_create_local_variables();
    if (unlikely(NULL == tlv)) {
        WARN("No local variables are available\n");
        return inst_num;
    }

    if (0 == enable_instance_for_thread) {
        if (inst_type == QAT_INSTANCE_ASYM) { /* Asym Instance */
            apl_inst_count = qat_asym_num_instance;
            inst_idx = &tlv->qatAsymInstanceNumForThread;
            inst_map = qat_map_asym_inst;
        } else { /* Sym Instance */
            apl_inst_count = qat_sym_num_instance;
            inst_idx = &tlv->qatSymInstanceNumForThread;
            inst_map = qat_map_sym_inst;
        }

        if (likely(qat_instance_handles && apl_inst_count)) {
            switch (mem_type) {
            case QAT_INSTANCE_SVM:
                do {
                    inst_count++;
                    *inst_idx = (*inst_idx + 1) % apl_inst_count;
                } while (!is_instance_available(inst_map[*inst_idx]) && !is_instance_svm(inst_map[*inst_idx])
                        && inst_count <= apl_inst_count);
                break;
            case QAT_INSTANCE_CONTIGUOUS:
                do {
                    inst_count++;
                    *inst_idx = (*inst_idx + 1) % apl_inst_count;
                } while (!is_instance_available(inst_map[*inst_idx]) && is_instance_svm(inst_map[*inst_idx])
                        && inst_count <= apl_inst_count);
                break;
            default:
                do {
                    inst_count++;
                    *inst_idx = (*inst_idx + 1) % apl_inst_count;
                } while (!is_instance_available(inst_map[*inst_idx]) &&
                        inst_count <= apl_inst_count);
                 break;
        }


        if (likely(inst_count <= apl_inst_count))
                inst_num = inst_map[*inst_idx];
        }
    } else {
        if (inst_type == QAT_INSTANCE_ASYM) { /* Asym Instance */
            if (tlv->qatAsymInstanceNumForThread != QAT_INVALID_INSTANCE) {
                if (is_instance_available(tlv->qatAsymInstanceNumForThread))
                    inst_num = tlv->qatAsymInstanceNumForThread;
            }
        } else { /* Sym Instance */
            if (tlv->qatSymInstanceNumForThread != QAT_INVALID_INSTANCE) {
                if (is_instance_available(tlv->qatSymInstanceNumForThread))
                    inst_num = tlv->qatSymInstanceNumForThread;
            }
        }
    }
    /* If no working instance could be found then flag a warning */
    if (unlikely(inst_num == QAT_INVALID_INSTANCE)) {
        WARN("No working instance is available\n");
    }

    DEBUG("inst type: %s, inst_num = %d\n",
            inst_type == QAT_INSTANCE_ASYM ? "ASYM" : "SYM", inst_num);

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
#ifdef ENABLE_QAT_HW_KPT
        tlv->kpt_wpk_in_use = KPT_INVALID_WPK_IDX;
#endif

        tlv->qatAsymInstanceNumForThread = QAT_INVALID_INSTANCE;
        tlv->qatSymInstanceNumForThread = QAT_INVALID_INSTANCE;

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


#ifndef __FreeBSD__
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
#endif

static int qat_instance_sym_supported(CpaCyCapabilitiesInfo *pCapInfo)
{
    return pCapInfo->symSupported;
}

static int qat_instance_asym_supported(CpaCyCapabilitiesInfo *pCapInfo)
{
    /* For more detailed information about these flags
       go to check cpa_cy_im.h */
    if (pCapInfo->dhSupported ||
        pCapInfo->dsaSupported ||
        pCapInfo->rsaSupported ||
        pCapInfo->ecSupported ||
        pCapInfo->ecdhSupported ||
        pCapInfo->ecdsaSupported ||
        pCapInfo->keySupported ||
        pCapInfo->lnSupported ||
        pCapInfo->primeSupported) {
        return 1;
    } else {
        return 0;
    }
}

/******************************************************************************
 * function:
 *         qat_remap_instances()
 *
 * description:
 *   A instances classify function
 *   - put symmetric instance index into qat_map_sym_inst
 *   - put asymmetric instance index into qat_map_asym_inst
 *   - put both-support instance index into
 *     both qat_map_sym_inst and qat_map_asym_inst
 *
 *****************************************************************************/
static int qat_remap_instances()
{
    CpaCyCapabilitiesInfo instance_cap = {0};
    CpaCyCapabilitiesInfo *pCapInfo = &instance_cap;
    CpaStatus status;
    int instNum = 0, asym_idx = 0, sym_idx = 0;

    /* For each instance, get its capability. */
    for (instNum = 0; instNum < qat_num_instances; instNum++) {
        status = cpaCyQueryCapabilities(qat_instance_handles[instNum],
                                        pCapInfo);
        if (CPA_STATUS_SUCCESS != status ) {
            WARN("cpaCyQueryCapabilities failed. status = %d\n", status);
            QATerr(QAT_F_QAT_REMAP_INSTANCES, QAT_R_CAPABILITY_FAILURE);
            return 0;
        }

        /* If Asym supported */
        if (qat_instance_asym_supported(pCapInfo)) {
            qat_map_asym_inst[asym_idx] = instNum;
            asym_idx++;
        }

        /* If Sym supported */
        if (qat_instance_sym_supported(pCapInfo)) {
            qat_map_sym_inst[sym_idx] = instNum;
            sym_idx++;
        }
    }

    /* Set the global vars */
    qat_asym_num_instance = asym_idx;
    qat_sym_num_instance = sym_idx;

    DUMP_INSTANCE_MAPPING("Asymmetric instances sequence",
                          qat_map_asym_inst, qat_asym_num_instance);
    DUMP_INSTANCE_MAPPING("Symmetric instances sequence",
                          qat_map_sym_inst, qat_sym_num_instance);

    return 1;
}

int qat_hw_init(ENGINE *e)
{
    int instNum, err;
    CpaStatus status = CPA_STATUS_SUCCESS;
    int ret_pthread_sigmask;
    Cpa32U package_id = 0;

    DEBUG("QAT_HW initialization:\n");
    DEBUG("- External polling: %s\n", enable_external_polling ? "ON": "OFF");
    DEBUG("- Heuristic polling: %s\n", enable_heuristic_polling ? "ON": "OFF");
    DEBUG("- SW Fallback: %s\n", enable_sw_fallback ? "ON": "OFF");
    DEBUG("- Inline polling: %s\n", enable_inline_polling ? "ON": "OFF");
    DEBUG("- Internal poll interval: %dns\n", qat_poll_interval);
    DEBUG("- Epoll timeout: %dms\n", qat_epoll_timeout);
    DEBUG("- Event driven polling mode: %s\n", enable_event_driven_polling ? "ON": "OFF");
    DEBUG("- Instance for thread: %s\n", enable_instance_for_thread ? "ON": "OFF");
    DEBUG("- Max retry count: %d\n", qat_max_retry_count);

    qat_polling_thread = pthread_self();

    if ((err = pthread_key_create(&thread_local_variables, qat_local_variable_destructor)) != 0) {
        WARN("pthread_key_create failed: %s\n", strerror(err));
        QATerr(QAT_F_QAT_HW_INIT, QAT_R_PTHREAD_CREATE_FAILURE);
        return 0;
    }

    /* Initialise the QAT hardware */
    if (CPA_STATUS_SUCCESS !=
        icp_sal_userStart(ICPConfigSectionName_libcrypto)) {
        WARN("icp_sal_userStart failed\n");
# ifndef QAT_SW /* Co-Existence mode: Don't print error message. */
        QATerr(QAT_F_QAT_HW_INIT, QAT_R_ICP_SAL_USERSTART_FAIL);
# endif
        pthread_key_delete(thread_local_variables);
        return 0;
    }

	status = cpaCyGetNumInstances(&qat_num_instances);
    if (CPA_STATUS_SUCCESS != status) {
        WARN("cpaCyGetNumInstances failed, status=%d\n", status);
        QATerr(QAT_F_QAT_HW_INIT, QAT_R_GET_NUM_INSTANCE_FAILURE);
        qat_hw_finish_int(e, QAT_RESET_GLOBALS);
        return 0;
    }
    if (!qat_num_instances) {
        WARN("No crypto instances found\n");
# ifndef QAT_SW /* Co-Existence mode: Don't print error message. */
        QATerr(QAT_F_QAT_HW_INIT, QAT_R_INSTANCE_UNAVAILABLE);
# endif
        qat_hw_finish_int(e, QAT_RESET_GLOBALS);
        return 0;
    }

    DEBUG("Found %d Cy instances\n", qat_num_instances);

    /* Allocate memory for the instance handle array */
    qat_instance_handles =
        (CpaInstanceHandle *) OPENSSL_zalloc(((int)qat_num_instances) *
                                             sizeof(CpaInstanceHandle));
    if (NULL == qat_instance_handles) {
        WARN("OPENSSL_zalloc() failed for instance handles.\n");
        QATerr(QAT_F_QAT_HW_INIT, QAT_R_INSTANCE_HANDLE_MALLOC_FAILURE);
        qat_hw_finish_int(e, QAT_RESET_GLOBALS);
        return 0;
    }

    /* Get the Cy instances */
    status = cpaCyGetInstances(qat_num_instances, qat_instance_handles);
    if (CPA_STATUS_SUCCESS != status) {
        WARN("cpaCyGetInstances failed, status=%d\n", status);
        QATerr(QAT_F_QAT_HW_INIT, QAT_R_GET_INSTANCE_FAILURE);
        qat_hw_finish_int(e, QAT_RESET_GLOBALS);
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
                QATerr(QAT_F_QAT_HW_INIT, QAT_R_EPOLL_CREATE_FAILURE);
                qat_hw_finish_int(e, QAT_RESET_GLOBALS);
                return 0;
            }

            for (instNum = 0; instNum < qat_num_instances; instNum++) {
                /*   Get the file descriptor for the instance */
                status =
                    icp_sal_CyGetFileDescriptor(qat_instance_handles[instNum],
                                                &engine_fd);
                if (CPA_STATUS_FAIL == status) {
                    WARN("Error getting file descriptor for instance\n");
                    QATerr(QAT_F_QAT_HW_INIT, QAT_R_GET_FILE_DESCRIPTOR_FAILURE);
                    qat_hw_finish_int(e, QAT_RESET_GLOBALS);
                    return 0;
                }
                /*   Make the file descriptor non-blocking */
                eng_poll_st[instNum].eng_fd = engine_fd;
                eng_poll_st[instNum].inst_index = instNum;

                flags = qat_fcntl(engine_fd, F_GETFL, 0);
                if (qat_fcntl(engine_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
                    WARN("Failed to set engine_fd as NON BLOCKING\n");
                    QATerr(QAT_F_QAT_HW_INIT,
                           QAT_R_SET_FILE_DESCRIPTOR_NONBLOCKING_FAILURE);
                    qat_hw_finish_int(e, QAT_RESET_GLOBALS);
                    return 0;
                }

                eng_epoll_events[instNum].data.ptr = &eng_poll_st[instNum];
                eng_epoll_events[instNum].events = EPOLLIN | EPOLLET;
                if (-1 ==
                    epoll_ctl(internal_efd, EPOLL_CTL_ADD, engine_fd,
                              &eng_epoll_events[instNum])) {
                    WARN("Error adding fd to epoll\n");
                    QATerr(QAT_F_QAT_HW_INIT, QAT_R_EPOLL_CTL_FAILURE);
                    qat_hw_finish_int(e, QAT_RESET_GLOBALS);
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
            QATerr(QAT_F_QAT_HW_INIT, QAT_R_GET_INSTANCE_INFO_FAILURE);
            qat_hw_finish_int(e, QAT_RESET_GLOBALS);
            return 0;
        }

        package_id = qat_instance_details[instNum].qat_instance_info.physInstId.packageId;
        qat_accel_details[package_id].qat_accel_present = 1;
        if (package_id >= qat_num_devices)
            qat_num_devices = package_id + 1;

        if (!qat_instance_details[instNum].qat_instance_info.requiresPhysicallyContiguousMemory) {
            qat_map_svm_inst[qat_svm_num_instance] = instNum;
            ++qat_svm_num_instance;
        }

        /* Set the address translation function */
        status = cpaCySetAddressTranslation(qat_instance_handles[instNum],
                                            virtualToPhysical);
        if (CPA_STATUS_SUCCESS != status) {
            WARN("cpaCySetAddressTranslation failed, status=%d\n", status);
            QATerr(QAT_F_QAT_HW_INIT, QAT_R_SET_ADDRESS_TRANSLATION_FAILURE);
            qat_hw_finish_int(e, QAT_RESET_GLOBALS);
            return 0;
        }

        /* Start the instances */
        status = cpaCyStartInstance(qat_instance_handles[instNum]);
        if (CPA_STATUS_SUCCESS != status) {
            WARN("cpaCyStartInstance failed, status=%d\n", status);
            QATerr(QAT_F_QAT_HW_INIT, QAT_R_START_INSTANCE_FAILURE);
            qat_hw_finish_int(e, QAT_RESET_GLOBALS);
            return 0;
        }

        qat_instance_details[instNum].qat_instance_started = 1;
        DEBUG("Started Instance No: %d Located on Device: %d\n", instNum, package_id);

#if !defined(__FreeBSD__) && !defined(QAT_DRIVER_INTREE)
        if (enable_sw_fallback) {
            DEBUG("cpaCyInstanceSetNotificationCb instNum = %d\n", instNum);
            status = cpaCyInstanceSetNotificationCb(qat_instance_handles[instNum],
                                                    qat_instance_notification_callbackFn,
                                                    (void *)(intptr_t)instNum);
            if (CPA_STATUS_SUCCESS != status) {
                WARN("cpaCyInstanceSetNotificationCb failed, status=%d\n", status);
                QATerr(QAT_F_QAT_HW_INIT, QAT_R_SET_NOTIFICATION_CALLBACK_FAILURE);
                qat_hw_finish_int(e, QAT_RESET_GLOBALS);
                return 0;
            }
        }
#endif
    }

    if (!qat_remap_instances()) {
        qat_hw_finish_int(e, QAT_RESET_GLOBALS);
        return 0;
    }


    qat_contig_num_instance = qat_num_instances - qat_svm_num_instance;
    DEBUG("Instances %d, SVM instances %d, contig instances %d\n", qat_num_instances,
           qat_svm_num_instance, qat_contig_num_instance);
    DUMP_INSTANCE_MAPPING("Asym sequence for thread mapping",
                          qat_map_asym_inst, qat_asym_num_instance);
    DUMP_INSTANCE_MAPPING("Sym sequence for thread mapping",
                          qat_map_sym_inst, qat_sym_num_instance);

#ifdef QAT_CPU_CYCLES_COUNT
    rdtsc_prof_init(&qat_hw_rsa_dec_req_prepare, 0);
    rdtsc_prof_init(&qat_hw_rsa_dec_req_submit, 0);
    rdtsc_prof_init(&qat_hw_rsa_dec_req_retry, 0);
    rdtsc_prof_init(&qat_hw_rsa_dec_req_cleanup, 0);
    rdtsc_prof_init(&qat_hw_ecdsa_sign_req_prepare, 0);
    rdtsc_prof_init(&qat_hw_ecdsa_sign_req_submit, 0);
    rdtsc_prof_init(&qat_hw_ecdsa_sign_req_retry, 0);
    rdtsc_prof_init(&qat_hw_ecdsa_sign_req_cleanup, 0);
    rdtsc_prof_init(&qat_hw_ecdh_derive_req_prepare, 0);
    rdtsc_prof_init(&qat_hw_ecdh_derive_req_submit, 0);
    rdtsc_prof_init(&qat_hw_ecdh_derive_req_retry, 0);
    rdtsc_prof_init(&qat_hw_ecdh_derive_req_cleanup, 0);
    rdtsc_prof_init(&qat_hw_ecx_derive_req_prepare, 0);
    rdtsc_prof_init(&qat_hw_ecx_derive_req_submit, 0);
    rdtsc_prof_init(&qat_hw_ecx_derive_req_retry, 0);
    rdtsc_prof_init(&qat_hw_ecx_derive_req_cleanup, 0);
#endif

    if (!enable_external_polling && !enable_inline_polling) {
        if (!qat_is_event_driven()) {
            sigemptyset(&set);
            sigaddset(&set, SIGUSR1);
            ret_pthread_sigmask = pthread_sigmask(SIG_BLOCK, &set, NULL);
            if (ret_pthread_sigmask != 0) {
                WARN("pthread_sigmask error\n");
                QATerr(QAT_F_QAT_HW_INIT, QAT_R_POLLING_THREAD_SIGMASK_FAILURE);
                qat_hw_finish_int(e, QAT_RESET_GLOBALS);
                return 0;
            }
        }

        if (sem_init(&hw_polling_thread_sem, 0, 0) != 0) {
            WARN("hw sem_init failed!\n");
            QATerr(QAT_F_QAT_HW_INIT, QAT_R_POLLING_THREAD_SEM_INIT_FAILURE);
            qat_hw_finish_int(e, QAT_RESET_GLOBALS);
            return 0;
        }

#ifndef __FreeBSD__
        if (qat_create_thread(&qat_polling_thread, NULL, qat_is_event_driven() ?
                              event_poll_func : qat_timer_poll_func, NULL)) {
#else
        if (qat_create_thread(&qat_polling_thread, NULL, qat_timer_poll_func, NULL)) {
#endif
            WARN("Creation of polling thread failed\n");
            QATerr(QAT_F_QAT_HW_INIT, QAT_R_POLLING_THREAD_CREATE_FAILURE);
            qat_polling_thread = pthread_self();
            qat_hw_finish_int(e, QAT_RESET_GLOBALS);
            return 0;
        }
        if (qat_adjust_thread_affinity(qat_polling_thread) == 0) {
            WARN("Setting polling thread affinity failed\n");
            QATerr(QAT_F_QAT_HW_INIT, QAT_R_SET_POLLING_THREAD_AFFINITY_FAILURE);
            qat_hw_finish_int(e, QAT_RESET_GLOBALS);
            return 0;
        }
        if (!qat_is_event_driven()) {
            if (pthread_mutex_lock(&qat_poll_mutex) == 0) {
                while (!cleared_to_start){
                   if (pthread_cond_wait(&qat_poll_condition, &qat_poll_mutex) != 0) {
                       WARN("Failed to get conditional wait\n");
		   }
                   qat_cond_wait_started = 1;
                }
                if (pthread_mutex_unlock(&qat_poll_mutex) != 0) {
                    WARN("Failed to unlock conditional wait mutex \n");
		}
            } else {
                WARN("Failed to lock conditional wait mutex \n");
            }
        }
    }

#ifdef ENABLE_QAT_HW_KPT
    /* Init KPT if KPT is enabled and hasn't be inited */
    if (kpt_enabled && !kpt_inited) {
        if (!qat_hw_kpt_init()) {
            WARN("KPT init failed, please check\n");
            qat_pthread_mutex_unlock();
            qat_engine_finish(e);
            return 0;
        }
        kpt_inited = 1;
    }
#endif

    return 1;
}

int qat_hw_finish_int(ENGINE *e, int reset_globals)
{
    int i;
    int ret = 1;
    CpaStatus status = CPA_STATUS_SUCCESS;
#ifndef __FreeBSD__
    ENGINE_EPOLL_ST *epollst = NULL;
#endif

    DEBUG("---- QAT Finishing...\n\n");

#ifdef ENABLE_QAT_HW_KPT
    if (kpt_enabled) {
        /* Finish KPT before engine finish if KPT is inited */
        if (kpt_inited) {
            DEBUG("Start KPT Finishing.\n");
            qat_hw_kpt_finish();

            /* kpt_enabled can't be zeroed, otherwise child processes won't
             * do qat_hw_kpt_init while forking. 
             * kpt_inited should be zeroed as the process is terminated. */
            kpt_inited = 0;
        }

        DEBUG("Reset the loaded WPK file number.\n");
        if (kpt_reset_wpk_num()) {
            WARN("Failure in kpt_reset_wpk_num.\n");
        }
    }
#endif

    qat_hw_keep_polling = 0;
    if (qat_use_signals_no_engine_start()) {
        if (sem_post(&hw_polling_thread_sem) != 0) {
            WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n",
                  &hw_polling_thread_sem);
            QATerr(QAT_F_QAT_HW_FINISH_INT, QAT_R_SEM_POST_FAILURE);
            ret = 0;
        }
    }

    if (qat_instance_handles) {
        for (i = 0; i < qat_num_instances; i++) {
            if (qat_instance_details[i].qat_instance_started) {
                status = cpaCyStopInstance(qat_instance_handles[i]);

                if (CPA_STATUS_SUCCESS != status) {
                    WARN("cpaCyStopInstance failed, status=%d\n", status);
                    QATerr(QAT_F_QAT_HW_FINISH_INT, QAT_R_STOP_INSTANCE_FAILURE);
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
        pthread_equal(qat_polling_thread, pthread_self()) == 0) {
        if (qat_join_thread(qat_polling_thread, NULL) != 0) {
            WARN("Polling thread join failed with status: %d\n", ret);
            QATerr(QAT_F_QAT_HW_FINISH_INT, QAT_R_PTHREAD_JOIN_FAILURE);
            ret = 0;
        }
    }
    qat_polling_thread = pthread_self();

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
                        QATerr(QAT_F_QAT_HW_FINISH_INT, QAT_R_EPOLL_CTL_FAILURE);
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
    qat_asym_num_instance = 0;
    qat_sym_num_instance = 0;
    icp_sal_userStop();
    internal_efd = 0;
    qat_instance_handles = NULL;
    qat_hw_keep_polling = 1;
#ifndef QAT_BORINGSSL
    qatPerformOpRetries = 0;
#endif

    DEBUG("Calling pthread_key_delete()\n");
    pthread_key_delete(thread_local_variables);
    sem_destroy(&hw_polling_thread_sem); /* destroy qat hw semaphore: hw_polling_thread_sem. */

    if (!enable_external_polling && !enable_inline_polling) {
        if (!qat_is_event_driven()) {
            int res =0;
            if ((qat_cond_wait_started && (res = pthread_cond_destroy(&qat_poll_condition))) != 0) {
                WARN("Destroying of qat_poll_condition failed. %d\n", res);
            }
	}
    }

    /* Reset the configuration global variables (to their default values) only
     * if requested, i.e. when we are not re-initializing the engine after
     * forking
     */
    if (reset_globals == 1) {
#ifdef ENABLE_QAT_HW_KPT
        DEBUG("KPT reset globally\n");
        kpt_inited = 0;
        kpt_enabled = 0;
#endif

        enable_inline_polling = 0;
        enable_event_driven_polling = 0;
        enable_instance_for_thread = 0;
        enable_sw_fallback = 0;
        disable_qat_offload = 0;
        qat_poll_interval = QAT_POLL_PERIOD_IN_NS;
        qat_max_retry_count = QAT_CRYPTO_NUM_POLLING_RETRIES;
	qat_cond_wait_started = 0;
    }
    return ret;
}
