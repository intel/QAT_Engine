/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023-2024 Intel Corporation.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "cpa.h"
#include "cpa_cy_kpt.h"
#include "cpa_cy_im.h"
#include "icp_sal_user.h"
#include "icp_sal_poll.h"
#include "qae_mem.h"
#include "include/qae_mem_utils.h"

#include "kpt_dev_pp.h"

#define DEVCREDENTIAL_PUBKET_MODN (384)
#define DEVCREDENTIAL_PUBKET_MODE (8)

#ifndef BYTE_ALIGNMENT_64
#define BYTE_ALIGNMENT_64 (64)
#endif

#define QAT_MAX_CRYPTO_INSTANCES    (256)
#define QAT_MAX_CRYPTO_ACCELERATORS (512)

typedef struct {
    CpaInstanceInfo2  qat_instance_info;
    unsigned int qat_instance_started;
} qat_instance_details_t;

typedef struct {
    unsigned int qat_accel_present;
    unsigned int qat_accel_reset_status;
} qat_accel_details_t;

static pthread_t gPollingThread;
static int gPollingCy = 0;

kpt_per_part_context kpt_per_part_context_ptr[MAX_SOCKET] = {{{0}}};
int cpu_socket_num = 0;

static void hex_log(Cpa8U *pData, Cpa32U numBytes, const char* caption)
{
    int i = 0;

    if (NULL == pData) {
        return;
    }
    if (caption != NULL) {
        log_print("\n=== %s ===\n", caption);
    }

    for (i = 0; i < numBytes; i++) {
        log_print("%02X ", pData[i]);

        if (!((i + 1) % 16)) {
            log_print("\n");
        }
    }
    log_print("\n");
}

const char *log_level_str(int level)
{
    const char *level_str;

    switch (level) {
    case LOG_ERR:
        level_str  = "ERR";
        break;
    case LOG_DEBUG:
        level_str = "DEBUG";
        break;
    default:
        level_str = "UNKNOW";
        break;
    };

    return level_str;
}

int xlog(int level, const char *fmt, ...)
{
    char out_buff[256] = {0};
    int nsize;
    const char *level_str = NULL;
    va_list ap;

    va_start(ap, fmt);
    nsize = vsnprintf(out_buff, sizeof(out_buff) -1, fmt, ap);
    va_end(ap);
    if (nsize > 0) {
        if (level == LOG_PRINT) {
            return printf("%s", out_buff);
        } else {
            level_str = log_level_str(level);
            return printf("[%s] %s\n", level_str, out_buff);
        }
    }
    return -1;
}


/*
 * This function polls a crypto instance.
 *
 */
void *sal_polling(CpaInstanceHandle cyInstHandle)
{
    gPollingCy = 1;
    while (gPollingCy) {
        icp_sal_CyPollInstance(cyInstHandle, 0);
    }

    pthread_join(gPollingThread, NULL);
}

/*
 * This function checks the instance info. If the instance is
 * required to be polled then it starts a polling thread.
 */
void kptCyStartPolling(CpaInstanceHandle cyInstHandle)
{
    CpaInstanceInfo2 info2 = {0};
    CpaStatus status = CPA_STATUS_SUCCESS;

    status = cpaCyInstanceGetInfo2(cyInstHandle, &info2);
    if ((status == CPA_STATUS_SUCCESS) && (info2.isPolled == CPA_TRUE)) {
        /* Start thread to poll instance */
        pthread_create(&gPollingThread, NULL, sal_polling, cyInstHandle);
    }
}

/*
 * This function stops the polling of a crypto instance.
 */
void kptCyStopPolling(void)
{
    gPollingCy = 0;
}


static void copy_per_part_context(CpaCyKptValidationKey *DevCredential)
{
    memcpy(kpt_per_part_context_ptr[cpu_socket_num].sig, \
           DevCredential->signature, \
           KPT_PER_PART_SIG_LEN);
    kpt_per_part_context_ptr[cpu_socket_num].len_sig = KPT_PER_PART_SIG_LEN;
    memcpy(kpt_per_part_context_ptr[cpu_socket_num].pub_n, \
           DevCredential->publicKey.modulusN.pData, \
           DevCredential->publicKey.modulusN.dataLenInBytes);
    kpt_per_part_context_ptr[cpu_socket_num].len_pub_n = KPT_PER_PART_KEY_N_LEN;
    memcpy(kpt_per_part_context_ptr[cpu_socket_num].pub_e, \
           DevCredential->publicKey.publicExponentE.pData, \
           DevCredential->publicKey.publicExponentE.dataLenInBytes);
    kpt_per_part_context_ptr[cpu_socket_num].len_pub_e = KPT_PER_PART_KEY_E_LEN;

    cpu_socket_num++;
}

static int lookup_and_store(CpaCyKptValidationKey *DevCredential)
{
    int ret = 0;
    int i = 0;

    if (!cpu_socket_num) {
        copy_per_part_context(DevCredential);
        return cpu_socket_num;
    }

    for (; i < cpu_socket_num; i++){
        /* return if the same signature */
        ret = memcmp(DevCredential->signature, \
                     kpt_per_part_context_ptr[i].sig, \
                     KPT_PER_PART_SIG_LEN);
        if (!ret) {
            return 0;
        }
    }
    copy_per_part_context(DevCredential);
    return cpu_socket_num;
}

static CpaStatus kpt_get_op_perform(int instNum, CpaInstanceHandle cyInstHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyKptKeyManagementStatus kptStatus = CPA_CY_KPT_SUCCESS;
    Cpa32U node = 0;
    CpaInstanceInfo2 instanceInfo2;
    CpaCyKptValidationKey DevCredential;

    status = cpaCyInstanceGetInfo2(cyInstHandle, &instanceInfo2);
    if (status == CPA_STATUS_SUCCESS) {
         node = instanceInfo2.nodeAffinity;
    } else {
       return status;
    }

    DevCredential.publicKey.modulusN.pData = (Cpa8U *) qaeMemAllocNUMA(DEVCREDENTIAL_PUBKET_MODN,
         node, BYTE_ALIGNMENT_64);
    if (NULL == DevCredential.publicKey.modulusN.pData) {
        return CPA_STATUS_RESOURCE;
    }
    DevCredential.publicKey.modulusN.dataLenInBytes = DEVCREDENTIAL_PUBKET_MODN;

    DevCredential.publicKey.publicExponentE.pData = (Cpa8U *) qaeMemAllocNUMA(DEVCREDENTIAL_PUBKET_MODE,
         node, BYTE_ALIGNMENT_64);
    if (NULL == DevCredential.publicKey.publicExponentE.pData) {
        return CPA_STATUS_RESOURCE;
    }
    DevCredential.publicKey.publicExponentE.dataLenInBytes = DEVCREDENTIAL_PUBKET_MODE;

    status = cpaCyKptQueryDeviceCredentials(cyInstHandle, &DevCredential, &kptStatus);

    if (lookup_and_store(&DevCredential)) {
        log_print("-->Found new per-part key, total number: %d\n", cpu_socket_num);
    }

    return status;
}


int kpt_get_per_part_key(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa16U qat_num_instances = 0;
    CpaInstanceHandle *qat_instance_handles = NULL;
    int instNum = 0;
    qat_instance_details_t qat_instance_details[QAT_MAX_CRYPTO_INSTANCES] = {{{0}}};
    Cpa16U package_id = 0;
    CpaCyCapabilitiesInfo CapInfo;

    status = qaeMemInit();
    if (CPA_STATUS_SUCCESS != status) {
        log_err("Failed to initialise memory driver\n");
        return (int)status;
    }

    status = icp_sal_userStartMultiProcess("SHIM", CPA_FALSE);
    if (CPA_STATUS_SUCCESS != status) {
        log_err("Failed to start user process SHIM\n");
        qaeMemDestroy();
        return (int)status;
    }

    /* Get the number of available instances */
    status = cpaCyGetNumInstances(&qat_num_instances);
    if (CPA_STATUS_SUCCESS != status) {
        log_err("cpaCyGetNumInstances failed, status=%d\n", status);
        return (int)status;
    }
    if (!qat_num_instances) {
        log_err("No crypto instances found\n");
        return -1;
    }

    printf("Found %d Cy instances\n", qat_num_instances);

    /* Allocate memory for the instance handle array */
    qat_instance_handles =
        (CpaInstanceHandle *) malloc(((int)qat_num_instances) *
                                             sizeof(CpaInstanceHandle));
    memset(qat_instance_handles, 0, ((int)qat_num_instances) *
                                             sizeof(CpaInstanceHandle));

    /* Get the Cy instances */
    status = cpaCyGetInstances(qat_num_instances, qat_instance_handles);
    if (CPA_STATUS_SUCCESS != status) {
        log_err("cpaCyGetInstances failed, status=%d\n", status);
        return (int)status;
    }

    /* Set translation function and start each instance */
    for (instNum = 0; instNum < qat_num_instances; instNum++) {
        /* Retrieve CpaInstanceInfo2 structure for that instance */
        status = cpaCyInstanceGetInfo2(qat_instance_handles[instNum],
                                       &qat_instance_details[instNum].qat_instance_info);
        if (CPA_STATUS_SUCCESS != status ) {
            log_err("cpaCyInstanceGetInfo2 failed. status = %d\n", status);
            return (int)status;
        }
        status = cpaCyQueryCapabilities(qat_instance_handles[instNum], &CapInfo);
        if (CPA_STATUS_SUCCESS != status ) {
            log_err("cpaCyQueryCapabilities failed. status = %d\n", status);
            return (int)status;
        }

        if ( CPA_FALSE == CapInfo.kptSupported ||
            CPA_TRUE == CapInfo.symSupported) {
            log_print("Skiped Instance No: %d Located on Device: %d"
                "(non-kpt or sym instance)\n", instNum, package_id);
            qat_instance_details[instNum].qat_instance_started = 0;
            continue;
        }

        package_id = qat_instance_details[instNum].qat_instance_info.physInstId.packageId;

        /* Set the address translation function */
        status = cpaCySetAddressTranslation(qat_instance_handles[instNum],
                                            qaeVirtToPhysNUMA);
        if (CPA_STATUS_SUCCESS != status) {
            log_err("cpaCySetAddressTranslation failed, status=%d\n", status);
            return (int)status;
        }

        /* Start the instances */
        status = cpaCyStartInstance(qat_instance_handles[instNum]);
        if (CPA_STATUS_SUCCESS != status) {
            log_err("cpaCyStartInstance failed, status=%d\n", status);
            return (int)status;
        }

        qat_instance_details[instNum].qat_instance_started = 1;
        log_print("Started Instance No: %d Located on Device: %d\n", instNum, package_id);

        kptCyStartPolling(qat_instance_handles[instNum]);
        if (CPA_STATUS_SUCCESS != status)
            return (int)status;

        status = kpt_get_op_perform(instNum, qat_instance_handles[instNum]);

        kptCyStopPolling();

        if (qat_instance_details[instNum].qat_instance_started) {
            status = cpaCyStopInstance(qat_instance_handles[instNum]);

            if (CPA_STATUS_SUCCESS != status) {
                log_err("cpaCyStopInstance failed, status=%d\n", status);
            }

            qat_instance_details[instNum].qat_instance_started = 0;
        }
    }

    free(qat_instance_handles);
    icp_sal_userStop();
    qaeMemDestroy();

    return (int)status;
}
