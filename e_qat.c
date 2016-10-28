/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Intel Corporation.
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
# define QAT_DEV "/dev/qae_mem"
#elif defined(USE_QAE_MEM) && defined(USE_QAT_CONFIG_MEM)
# error "USE_QAT_CONTIG_MEM and USE_QAE_MEM both defined"
#else
# error "No memory driver type defined"
#endif


/*
 * The default interval in nanoseconds used for the internal polling thread
 */
#define QAT_POLL_PERIOD_IN_NS 10000

/*
 * The number of retries of the nanosleep if it gets interrupted during
 * waiting between polling.
 */
#define QAT_CRYPTO_NUM_POLLING_RETRIES (5)

/*
 * The number of seconds to wait for a response back after submitting a
 * request before raising an error.
 */
#define QAT_CRYPTO_RESPONSE_TIMEOUT (5)

/*
 * The default timeout in milliseconds used for epoll_wait when event driven
 * polling mode is enabled.
 */
#define QAT_EPOLL_TIMEOUT_IN_MS 1000



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

/* Local Includes */
#include "qat_ciphers.h"
#include "qat_rsa.h"
#include "qat_dsa.h"
#include "qat_dh.h"
#include "qat_ec.h"
#include "e_qat.h"
#include "qat_utils.h"
#include "e_qat_err.h"
#include "qat_prf.h"

/* OpenSSL Includes */
#include <openssl/err.h>
#include <openssl/async.h>
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

#define MAX_EVENTS 32
#define MAX_CRYPTO_INSTANCES 64

#define likely(x)   __builtin_expect (!!(x), 1)
#define unlikely(x) __builtin_expect (!!(x), 0)

/* Macro used to handle errors in qat_engine_ctrl() */
#define BREAK_IF(cond, mesg) \
    if(unlikely(cond)) { retVal = 0; WARN(mesg); break; }

/* Forward Declarations */
static int qat_engine_finish(ENGINE *e);

/* Qat engine id declaration */
static const char *engine_qat_id = "qat";
static const char *engine_qat_name =
    "Reference implementation of QAT crypto engine";

char *ICPConfigSectionName_libcrypto = "SHIM";

/* Globals */
typedef struct {
    int eng_fd;
    int inst_index;
} ENGINE_EPOLL_ST;

struct epoll_event eng_epoll_events[MAX_CRYPTO_INSTANCES] = { { 0, 0 } };
static int internal_efd = 0;
static ENGINE_EPOLL_ST eng_poll_st[MAX_CRYPTO_INSTANCES] = { {-1} };
CpaInstanceHandle *qatInstanceHandles = NULL;
static pthread_key_t qatInstanceForThread;
pthread_t *icp_polling_threads;
static int keep_polling = 1;
static int enable_external_polling = 0;
static int enable_event_driven_polling = 0;
static int enable_instance_for_thread = 0;
Cpa16U numInstances = 0;
int qatPerformOpRetries = 0;
static int currInst = 0;
static pthread_mutex_t qat_instance_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t qat_engine_mutex = PTHREAD_MUTEX_INITIALIZER;


static unsigned int engine_inited = 0;
static unsigned int instance_started[MAX_CRYPTO_INSTANCES] = {0};
static useconds_t qat_poll_interval = QAT_POLL_PERIOD_IN_NS;
static int qat_epoll_timeout = QAT_EPOLL_TIMEOUT_IN_MS;
static int qat_max_retry_count = QAT_CRYPTO_NUM_POLLING_RETRIES;
static int qat_engine_init(ENGINE *e);


int getQatMsgRetryCount()
{
    return qat_max_retry_count;
}

useconds_t getQatPollInterval()
{
    return qat_poll_interval;
}

int qat_is_event_driven()
{
    return enable_event_driven_polling;
}

#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
int setQatSmallPacketThreshold(unsigned char *cipher_name, int threshold)
{
    if(threshold < 0)
        threshold = 0;
    else if (threshold > 16384)
        threshold = 16384;
    return qat_pkt_threshold_table_set_threshold(OBJ_sn2nid(cipher_name),threshold);
}

#endif

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
    currInst = (currInst + 1) % numInstances;
    pthread_mutex_unlock(&qat_instance_mutex);
}

/******************************************************************************
* function:
*         get_next_inst(void)
*
* description:
*   Return the next instance handle to use for an operation.
*
******************************************************************************/
CpaInstanceHandle get_next_inst(void)
{
    CpaInstanceHandle instanceHandle = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    ENGINE* e = NULL;

    if (1 == enable_instance_for_thread) {
        instanceHandle = pthread_getspecific(qatInstanceForThread);
        /* If no thread specific data is found then return NULL
           as there should be as the flag is set */
        if (instanceHandle == NULL)
            return instanceHandle;
    }

    e = ENGINE_by_id(engine_qat_id);
    if(e == NULL) {
        instanceHandle = NULL;
        return instanceHandle;
    }

    if(!qat_engine_init(e)){
        instanceHandle = NULL;
        return instanceHandle;
    }

    /* Anytime we use external polling then we want to loop
       through the instances. Any time we are using internal polling
       then we also want to loop through the instances assuming
       one was not retrieved from thread specific data. */
    if (1 == enable_external_polling || instanceHandle == NULL)
    {
        if (qatInstanceHandles) {
            instanceHandle = qatInstanceHandles[currInst];
            incr_curr_inst();
        } else {
            instanceHandle = NULL;
        }
    }
    return instanceHandle;
}

static void engine_fork_handler(void)
{
    /*Reset engine*/
    ENGINE* e = ENGINE_by_id(engine_qat_id);
    if(e == NULL) {
        return;
    }
    qat_engine_finish(e);

    keep_polling = 1;
}

/******************************************************************************
* function:
*         qat_set_instance_for_thread(long instanceNum)
*
* @param instanceNum [IN] - logical instance number
*
* description:
*   Bind the current thread to a particular logical Cy instance. Note that if
*   instanceNum is greater than the number of configured instances, the
*   modulus operation is used.
*
******************************************************************************/
void qat_set_instance_for_thread(long instanceNum)
{
    int rc;

    if ((rc =
         pthread_setspecific(qatInstanceForThread,
                             qatInstanceHandles[instanceNum %
                                                numInstances])) != 0) {
        fprintf(stderr, "pthread_setspecific: %s\n", strerror(rc));
        return;
    }
    enable_instance_for_thread = 1;
}

/******************************************************************************
* function:
*         initOpDone(struct op_done *opDone)
*
* @param opDone [IN] - pointer to op done callback structure
*
* description:
*   Initialise the QAT operation "done" callback structure.
*
******************************************************************************/
void initOpDone(struct op_done *opDone)
{
    if (opDone == NULL) {
        return;
    }

    opDone->flag = 0;
    opDone->verifyResult = CPA_FALSE;

    opDone->job = ASYNC_get_current_job();

}

/******************************************************************************
* function:
*         cleanupOpDone(struct op_done *opDone)
*
* @param opDone [IN] - pointer to op done callback structure
*
* description:
*   Cleanup the data in the "done" callback structure.
*
******************************************************************************/
void cleanupOpDone(struct op_done *opDone)
{
    if (opDone == NULL) {
        return;
    }

    /*
     * op_done:verifyResult is used after return from this function
     * Donot change this value.
     */

    if (opDone->job) {
        opDone->job = NULL;
    }
}

/******************************************************************************
* function:
*         qat_crypto_callbackFn(void *callbackTag, CpaStatus status,
*                        const CpaCySymOp operationType, void *pOpData,
*                        CpaBufferList * pDstBuffer, CpaBoolean verifyResult)
*

* @param pCallbackTag  [IN] -  Opaque value provided by user while making
*                              individual function call. Cast to op_done.
* @param status        [IN] -  Status of the operation.
* @param operationType [IN] -  Identifies the operation type requested.
* @param pOpData       [IN] -  Pointer to structure with input parameters.
* @param pDstBuffer    [IN] -  Destination buffer to hold the data output.
* @param verifyResult  [IN] -  Used to verify digest result.
*
* description:
*   Callback function used by cpaCySymPerformOp to indicate completion.
*
******************************************************************************/
void qat_crypto_callbackFn(void *callbackTag, CpaStatus status,
                           const CpaCySymOp operationType, void *pOpData,
                           CpaBufferList * pDstBuffer,
                           CpaBoolean verifyResult)
{
    struct op_done *opDone = (struct op_done *)callbackTag;

    if (opDone == NULL) {
        return;
    }

    DEBUG("e_qat.%s: status %d verifyResult %d\n", __func__, status,
          verifyResult);
    opDone->verifyResult = (status == CPA_STATUS_SUCCESS) && verifyResult
                            ? CPA_TRUE : CPA_FALSE;

    if (opDone->job) {
        opDone->flag = 1;
        qat_wake_job(opDone->job, 0);
    } else {
        opDone->flag = 1;
    }
}

/******************************************************************************
* function:
*         CpaStatus myPerformOp(const CpaInstanceHandle  instanceHandle,
*                     void *                     pCallbackTag,
*                     const CpaCySymOpData      *pOpData,
*                     const CpaBufferList       *pSrcBuffer,
*                     CpaBufferList             *pDstBuffer,
*                     CpaBoolean                *pVerifyResult)
*
* @param ih [IN] - Instance handle
* @param instanceHandle [IN]  - Instance handle
* @param pCallbackTag   [IN]  - Pointer to op_done struct
* @param pOpData        [IN]  - Operation parameters
* @param pSrcBuffer     [IN]  - Source buffer list
* @param pDstBuffer     [OUT] - Destination buffer list
* @param pVerifyResult  [OUT] - Whether hash verified or not
*
* description:
*   Wrapper around cpaCySymPerformOp which handles retries for us.
*
******************************************************************************/
CpaStatus myPerformOp(const CpaInstanceHandle instanceHandle,
                      void *pCallbackTag,
                      const CpaCySymOpData * pOpData,
                      const CpaBufferList * pSrcBuffer,
                      CpaBufferList * pDstBuffer, CpaBoolean * pVerifyResult)
{
    CpaStatus status;
    struct op_done *opDone = (struct op_done *)pCallbackTag;
    unsigned int uiRetry = 0;
    do {
        status = cpaCySymPerformOp(instanceHandle,
                                   pCallbackTag,
                                   pOpData,
                                   pSrcBuffer, pDstBuffer, pVerifyResult);
        if (status == CPA_STATUS_RETRY) {
            if (opDone->job) {
                if ((qat_wake_job(opDone->job, 0) == 0) ||
                    (qat_pause_job(opDone->job, 0) == 0)) {
                    status = CPA_STATUS_FAIL;
                    break;
                }
            } else {
                qatPerformOpRetries++;
                if (uiRetry >= qat_max_retry_count
                    && qat_max_retry_count != QAT_INFINITE_MAX_NUM_RETRIES) {
                    break;
                }
                uiRetry++;
                usleep(qat_poll_interval +
                       (uiRetry % QAT_RETRY_BACKOFF_MODULO_DIVISOR));
            }
        }
    }
    while (status == CPA_STATUS_RETRY);
    return status;
}

static void qat_fd_cleanup(ASYNC_WAIT_CTX *ctx, const void *key,
                           OSSL_ASYNC_FD readfd, void *custom)
{
    close(readfd);
}

int qat_setup_async_event_notification(int notificationNo)
{
    /* We will ignore notificationNo for the moment */
    ASYNC_JOB *job;
    ASYNC_WAIT_CTX *waitctx;
    OSSL_ASYNC_FD efd;
    void *custom = NULL;
    int ret = 0;

    if ((job = ASYNC_get_current_job()) == NULL)
        return ret;

    if ((waitctx = ASYNC_get_wait_ctx(job)) == NULL)
        return ret;

    if (ASYNC_WAIT_CTX_get_fd(waitctx, engine_qat_id, &efd,
                              &custom)) {
        ret = 1;
    } else {
        efd = eventfd(0, 0);
        if (efd == -1) {
            WARN("Failed to get eventfd = %d\n", errno);
            return ret;
        }

        if ((ret = ASYNC_WAIT_CTX_set_wait_fd(waitctx, engine_qat_id, efd,
                                       custom, qat_fd_cleanup)) == 0) {
            qat_fd_cleanup(waitctx, engine_qat_id, efd, NULL);
        }
    }
    return ret;
}

int qat_pause_job(ASYNC_JOB *job, int notificationNo)
{
    /* We will ignore notificationNo for the moment */
    ASYNC_WAIT_CTX *waitctx;
    OSSL_ASYNC_FD efd;
    void *custom = NULL;
    uint64_t buf = 0;
    int ret = 0;

    if (ASYNC_pause_job() == 0)
        return ret;

    if ((waitctx = ASYNC_get_wait_ctx(job)) == NULL)
        return ret;

    if ((ret = ASYNC_WAIT_CTX_get_fd(waitctx, engine_qat_id, &efd,
                              &custom)) > 0) {
        read(efd, &buf, sizeof(uint64_t));
    }
    return ret;
}

int qat_wake_job(ASYNC_JOB *job, int notificationNo)
{
    /* We will ignore notificationNo for the moment */
    ASYNC_WAIT_CTX *waitctx;
    OSSL_ASYNC_FD efd;
    void *custom = NULL;
    /* Arbitary character 'X' to write down the pipe to trigger event */
    uint64_t buf = 1;
    int ret = 0;

    if ((waitctx = ASYNC_get_wait_ctx(job)) == NULL)
        return ret;

    if ((ret = ASYNC_WAIT_CTX_get_fd(waitctx, engine_qat_id, &efd,
                              &custom)) > 0) {
        write(efd, &buf, sizeof(uint64_t));
    }
    return ret;
}

/******************************************************************************
* function:
*         void *sendPoll_ns(void *ih)
*
* @param ih [IN] - Instance handle
*
* description:
*   Poll the QAT instances (nanosleep version)
*     NB: Delay in this function is set by default at runtime by an engine
*     specific message. If not set then the default is QAT_POLL_PERIOD_IN_NS.
*
******************************************************************************/
static void *sendPoll_ns(void *ih)
{
    CpaStatus status = 0;
    CpaInstanceHandle instanceHandle;

    struct timespec reqTime = { 0 };
    struct timespec remTime = { 0 };
    unsigned int retry_count = 0; /* to prevent too much time drift */

    instanceHandle = (CpaInstanceHandle) ih;
    if (NULL == instanceHandle) {
        WARN("WARNING sendPoll_ns - instanceHandle is NULL\n");
        return NULL;
    }

    while (keep_polling) {
        reqTime.tv_nsec = qat_poll_interval;
        /* Poll for 0 means process all packets on the instance */
        status = icp_sal_CyPollInstance(instanceHandle, 0);

        if (likely
            (CPA_STATUS_SUCCESS == status || CPA_STATUS_RETRY == status)) {
            /* Do nothing */
        } else {
            WARN("WARNING icp_sal_CyPollInstance returned status %d\n",
                 status);
        }

        retry_count = 0;
        do {
            retry_count++;
            nanosleep(&reqTime, &remTime);
            reqTime.tv_sec = remTime.tv_sec;
            reqTime.tv_nsec = remTime.tv_nsec;
            if (unlikely((errno < 0) && (EINTR != errno))) {
                WARN("WARNING nanosleep system call failed: errno %i\n",
                     errno);
                break;
            }
        }
        while ((retry_count <= QAT_CRYPTO_NUM_POLLING_RETRIES)
               && (EINTR == errno));
    }
end:
    return NULL;
}

static void *eventPoll_ns(void *ih)
{
    CpaStatus status = 0;
    struct epoll_event *events = NULL;
    ENGINE_EPOLL_ST* epollst = NULL;
    /* Buffer where events are returned */
    events = OPENSSL_zalloc(sizeof(struct epoll_event) * MAX_EVENTS);
    if (NULL == events) {
        WARN("Error allocating events list\n");
        goto end;
    }
    while (keep_polling) {
        int n = 0;
        int i = 0;

        n = epoll_wait(internal_efd, events, MAX_EVENTS, qat_epoll_timeout);
        for (i = 0; i < n; ++i) {
            if (events[i].events & EPOLLIN) {
                /*  poll for 0 means process all packets on the ET ring */
                epollst = (ENGINE_EPOLL_ST*)events[i].data.ptr;
                status = icp_sal_CyPollInstance(qatInstanceHandles[epollst->inst_index], 0);
                if (CPA_STATUS_SUCCESS == status) {
                    /*   do nothing */
                } else {
                    WARN("WARNING icp_sal_CyPollInstance returned status %d\n", status);
                }
            }
        }
    }

    OPENSSL_free(events);
    events = 0;
end:
    return NULL;
}

static CpaStatus poll_instances(void)
{
    unsigned int poll_loop;
    CpaInstanceHandle instanceHandle = NULL;
    CpaStatus internal_status = CPA_STATUS_SUCCESS,
        ret_status = CPA_STATUS_SUCCESS;
    if (enable_instance_for_thread)
        instanceHandle = pthread_getspecific(qatInstanceForThread);
    if (instanceHandle) {
        ret_status = icp_sal_CyPollInstance(instanceHandle, 0);
    } else {
        for (poll_loop = 0; poll_loop < numInstances; poll_loop++) {
            if (qatInstanceHandles[poll_loop] != NULL) {
                internal_status =
                    icp_sal_CyPollInstance(qatInstanceHandles[poll_loop], 0);
                if (CPA_STATUS_SUCCESS == internal_status) {
                    /* Do nothing */
                } else if (CPA_STATUS_RETRY == internal_status) {
                    ret_status = internal_status;
                } else {
                    WARN("WARNING icp_sal_CyPollInstance returned status %d\n", internal_status);
                    ret_status = internal_status;
                    break;
                }
            }
        }
    }

    return ret_status;
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


int qat_adjust_thread_affinity(pthread_t threadptr)
{
#ifdef QAT_POLL_CORE_AFFINITY
    int coreID = 0;
    int sts = 1;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(coreID, &cpuset);

    sts = pthread_setaffinity_np(threadptr, sizeof(cpu_set_t), &cpuset);
    if (sts != 0) {
        DEBUG("pthread_setaffinity_np error, status = %d \n", sts);
        return 0;
    }
    sts = pthread_getaffinity_np(threadptr, sizeof(cpu_set_t), &cpuset);
    if (sts != 0) {
        DEBUG("pthread_getaffinity_np error, status = %d \n", sts);
        return 0;
    }

    if (CPU_ISSET(coreID, &cpuset)) {
        DEBUG("Polling thread assigned on CPU core %d\n", coreID);
    }
#endif
    return 1;
}

/******************************************************************************
* function:
*         qat_engine_init(ENGINE *e)
*
* @param e [IN] - OpenSSL engine pointer
*
* description:
*   Qat engine init function, associated with Crypto memory setup
*   and cpaStartInstance setups.
******************************************************************************/
static int qat_engine_init(ENGINE *e)
{
    int instNum, err, checkLimitStatus;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBoolean limitDevAccess = CPA_FALSE;

    pthread_mutex_lock(&qat_engine_mutex);
    if(engine_inited) {
        pthread_mutex_unlock(&qat_engine_mutex);
        return 1;
    }

    DEBUG("[%s] ---- Engine Initing\n\n", __func__);
    CRYPTO_INIT_QAT_LOG();

    if ((err = pthread_key_create(&qatInstanceForThread, NULL)) != 0) {
        fprintf(stderr, "pthread_key_create: %s\n", strerror(err));
        pthread_mutex_unlock(&qat_engine_mutex);
        return 0;
    }

    checkLimitStatus =
        checkLimitDevAccessValue((int *)&limitDevAccess,
                                 ICPConfigSectionName_libcrypto);
    if (!checkLimitStatus) {
        WARN("Assuming LimitDevAccess = 0\n");
    }

    /* Initialise the QAT hardware */
    if (CPA_STATUS_SUCCESS !=
        icp_sal_userStartMultiProcess(ICPConfigSectionName_libcrypto,
                                      limitDevAccess)) {
        WARN("icp_sal_userStart failed\n");
        pthread_mutex_unlock(&qat_engine_mutex);
        return 0;
    }

    /* Get the number of available instances */
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status) {
        WARN("cpaCyGetNumInstances failed, status=%d\n", status);
        pthread_mutex_unlock(&qat_engine_mutex);
        qat_engine_finish(e);
        return 0;
    }
    if (!numInstances) {
        WARN("No crypto instances found\n");
        pthread_mutex_unlock(&qat_engine_mutex);
        qat_engine_finish(e);
        return 0;
    }

    DEBUG("%s: %d Cy instances got\n", __func__, numInstances);

    /* Allocate memory for the instance handle array */
    qatInstanceHandles =
        (CpaInstanceHandle *) OPENSSL_zalloc(((int)numInstances) *
                                             sizeof(CpaInstanceHandle));
    if (NULL == qatInstanceHandles) {
        WARN("OPENSSL_zalloc() failed for instance handles.\n");
        pthread_mutex_unlock(&qat_engine_mutex);
        qat_engine_finish(e);
        return 0;
    }

    /* Get the Cy instances */
    status = cpaCyGetInstances(numInstances, qatInstanceHandles);
    if (CPA_STATUS_SUCCESS != status) {
        WARN("cpaCyGetInstances failed, status=%d\n", status);
        pthread_mutex_unlock(&qat_engine_mutex);
        qat_engine_finish(e);
        return 0;
    }

    if (0 == enable_external_polling) {
        if (qat_is_event_driven()) {
            CpaStatus status;
            int flags;
            int engine_fd;

            /*   Add the file descriptor to an epoll event list */
            internal_efd = epoll_create1(0);
            if (-1 == internal_efd) {
                WARN("Error creating epoll fd\n");
                pthread_mutex_unlock(&qat_engine_mutex);
                return 0;
            }

            for (instNum = 0; instNum < numInstances; instNum++) {
                /*   Get the file descriptor for the instance */
                status =
                    icp_sal_CyGetFileDescriptor(qatInstanceHandles[instNum],
                                                &engine_fd);
                if (CPA_STATUS_FAIL == status) {
                    WARN("Error getting file descriptor for instance\n");
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
                    pthread_mutex_unlock(&qat_engine_mutex);
                    qat_engine_finish(e);
                    return 0;
                }
            }
            icp_polling_threads =
                (pthread_t *) OPENSSL_zalloc(sizeof(pthread_t));
        } else {
            icp_polling_threads =
                (pthread_t *) OPENSSL_zalloc(((int)numInstances) *
                                              sizeof(pthread_t));
        }
        if (NULL == icp_polling_threads) {
            WARN("OPENSSL_malloc() failed for icp_polling_threads.\n");
            pthread_mutex_unlock(&qat_engine_mutex);
            qat_engine_finish(e);
            return 0;
        }
    }

    /* Set translation function and start each instance */
    for (instNum = 0; instNum < numInstances; instNum++) {
        /* Set the address translation function */
        status = cpaCySetAddressTranslation(qatInstanceHandles[instNum],
                                            virtualToPhysical);
        if (CPA_STATUS_SUCCESS != status) {
            WARN("cpaCySetAddressTranslation failed, status=%d\n", status);
            pthread_mutex_unlock(&qat_engine_mutex);
            qat_engine_finish(e);
            return 0;
        }

        /* Start the instances */
        status = cpaCyStartInstance(qatInstanceHandles[instNum]);
        if (CPA_STATUS_SUCCESS != status) {
            WARN("cpaCyStartInstance failed, status=%d\n", status);
            pthread_mutex_unlock(&qat_engine_mutex);
            qat_engine_finish(e);
            return 0;
        }

        if (0 == enable_external_polling && !qat_is_event_driven()) {
            /* Create the polling threads */
            pthread_create(&icp_polling_threads[instNum], NULL, sendPoll_ns,
                           qatInstanceHandles[instNum]);

            if (qat_adjust_thread_affinity(icp_polling_threads[instNum]) == 0) {
                instance_started[instNum] = 1;
                pthread_mutex_unlock(&qat_engine_mutex);
                qat_engine_finish(e);
                return 0;
            }
        }
        instance_started[instNum] = 1;
    }

    if (0 == enable_external_polling && qat_is_event_driven()) {
        pthread_create(&icp_polling_threads[0], NULL, eventPoll_ns, NULL);

        if (qat_adjust_thread_affinity(icp_polling_threads[0]) == 0) {
            pthread_mutex_unlock(&qat_engine_mutex);
            qat_engine_finish(e);
            return 0;
        }
    }
    /* Reset currInst */
    currInst = 0;
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
        if (qatInstanceHandles == NULL) {
            /*
             * It is possible to call this ctrl function while the engine is
             * in a state where there are no instances available. This
             * happens for example immediately when the engine is waiting
             * for get_next_inst() to be called.
             *
             * To avoid this condition we call get_next_inst()
             */
            get_next_inst();
            BREAK_IF(qatInstanceHandles == NULL, "POLL failed as no instances are available\n");
        }

        BREAK_IF(!engine_inited, "POLL failed as engine is not initialized\n");
        BREAK_IF(!enable_external_polling, "POLL failed as external polling is not enabled\n");
        BREAK_IF(p == NULL, "POLL failed as the input parameter was NULL\n");

        *(int *)p = (int)poll_instances();
        break;

    case QAT_CMD_ENABLE_EXTERNAL_POLLING:
        BREAK_IF(engine_inited, \
                "ENABLE_EXTERNAL_POLLING failed as the engine is already initialized\n");
        DEBUG("[%s] Enabled external polling\n", __func__);
        enable_external_polling = 1;
        break;

    case QAT_CMD_GET_EXTERNAL_POLLING_FD:
        BREAK_IF(!enable_event_driven_polling || !enable_external_polling, \
                "GET_EXTERNAL_POLLING_FD failed as this engine message is only supported \
                when running in Event Driven Mode with External Polling enabled\n");
        if (qatInstanceHandles == NULL) {
            get_next_inst();
            BREAK_IF(qatInstanceHandles == NULL, \
                    "GET_EXTERNAL_POLLING_FD failed as no instances are available\n");
        }
        BREAK_IF(!engine_inited, \
                "GET_EXTERNAL_POLLING_FD failed as the engine is not initialized\n");
        BREAK_IF(p == NULL, "GET_EXTERNAL_POLLING_FD failed as the input parameter was NULL\n");
        BREAK_IF(i >= numInstances, \
                "GET_EXTERNAL_POLLING_FD failed as the instance does not exist\n");

        /* Get the file descriptor for the instance */
        status = icp_sal_CyGetFileDescriptor(qatInstanceHandles[i], &fd);
        BREAK_IF(CPA_STATUS_FAIL == status, \
                "GET_EXTERNAL_POLLING_FD failed as there was an error retrieving the fd\n");
        /* Make the file descriptor non-blocking */
        flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        DEBUG("[%s] External polling FD for instance[%d] = %d\n", __func__, i, fd);
        *(int *)p = fd;
        break;

    case QAT_CMD_ENABLE_EVENT_DRIVEN_POLLING_MODE:
        DEBUG("[%s] Enabled event driven polling mode\n", __func__);
        BREAK_IF(engine_inited, \
                "ENABLE_EVENT_DRIVEN_POLLING_MODE failed as the engine is already initialized\n");
        enable_event_driven_polling = 1;
        break;

    case QAT_CMD_DISABLE_EVENT_DRIVEN_POLLING_MODE:
        DEBUG("[%s] Disabled event driven polling mode\n", __func__);
        BREAK_IF(engine_inited, \
                "DISABLE_EVENT_DRIVEN_POLLING_MODE failed as the engine is already initialized\n");
        enable_event_driven_polling = 0;
        break;

    case QAT_CMD_SET_INSTANCE_FOR_THREAD:
        if (qatInstanceHandles == NULL) {
            get_next_inst();
            BREAK_IF(qatInstanceHandles == NULL, \
                    "SET_INSTANCE_FOR_THREAD failed as no instances are available\n");
        }
        BREAK_IF(!engine_inited, \
                "SET_INSTANCE_FOR_THREAD failed as the engine is not initialized\n");
        DEBUG("[%s] Set instance for thread = %d\n", __func__, i);
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
        DEBUG("[%s] Set max retry counter = %d\n", __func__, i);
        qat_max_retry_count = (int)i;
        break;

    case QAT_CMD_SET_INTERNAL_POLL_INTERVAL:
        BREAK_IF(i < 1 || i > 1000000,
               "The polling interval value is out of range, using default value\n");
        DEBUG("[%s] Set internal poll interval = %d ns\n", __func__, i);
        qat_poll_interval = (useconds_t) i;
        break;

    case QAT_CMD_SET_EPOLL_TIMEOUT:
        BREAK_IF(i < 1 || i > 10000,
                "The epoll timeout value is out of range, using default value\n")
        DEBUG("[%s] Set epoll_wait timeout = %d ms\n", __func__, i);
        qat_epoll_timeout = (int) i;
        break;

    case QAT_CMD_GET_NUM_CRYPTO_INSTANCES:
        BREAK_IF(p == NULL, \
                "GET_NUM_CRYPTO_INSTANCES failed as the input parameter was NULL\n");
        if (qatInstanceHandles == NULL) {
            get_next_inst();
            BREAK_IF(qatInstanceHandles == NULL, \
                    "GET_NUM_CRYPTO_INSTANCES failed as no instances are available\n");
        }
        BREAK_IF(!engine_inited, \
                "GET_NUM_CRYPTO_INSTANCES failed as the engine is not initialized\n");
        DEBUG("[%s] Get number of crypto instances = %d\n", __func__, numInstances);
        *(int *)p = numInstances;
        break;

    case QAT_CMD_SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD:
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        if(p) {
            char *token;
            while((token = strsep((char **)&p, ","))) {
                char *name_token = strsep(&token,":");
                char *value_token = strsep(&token,":");
                if(name_token && value_token) {
                    retVal = setQatSmallPacketThreshold(name_token, atoi(value_token));
                } else {
                    WARN("Invalid parameter!\n");
                    retVal = 0;
                }
            }
        } else {
            WARN("Invalid parameter!\n");
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
    return retVal;
}

/******************************************************************************
* function:
*         qat_engine_finish(ENGINE *e)
*
* @param e [IN] - OpenSSL engine pointer
*
* description:
*   Qat engine finish function.
******************************************************************************/
static int qat_engine_finish(ENGINE *e)
{

    int i;
    int ret = 1;
    CpaStatus status = CPA_STATUS_SUCCESS;
    ENGINE_EPOLL_ST *epollst = NULL;

    DEBUG("[%s] ---- Engine Finishing...\n\n", __func__);

    pthread_mutex_lock(&qat_engine_mutex);
    keep_polling = 0;

    if (qatInstanceHandles) {
        for (i = 0; i < numInstances; i++) {
            if(instance_started[i]) {
                status = cpaCyStopInstance(qatInstanceHandles[i]);

                if (CPA_STATUS_SUCCESS != status) {
                    WARN("cpaCyStopInstance failed, status=%d\n", status);
                    ret = 0;
                }

                if (0 == enable_external_polling && !qat_is_event_driven()) {
                    if ((pthread_t *) icp_polling_threads[i] != NULL) {
                        pthread_join(icp_polling_threads[i], NULL);
                    }
                }
                instance_started[i] = 0;
            }
        }
    }

    if (0 == enable_external_polling && qat_is_event_driven()) {
        if ((pthread_t *) icp_polling_threads[0] != NULL) {
            pthread_join(icp_polling_threads[0], NULL);
        }
    }

    if (qatInstanceHandles) {
        OPENSSL_free(qatInstanceHandles);
        qatInstanceHandles = NULL;
    }

    if (0 == enable_external_polling && qat_is_event_driven()) {
        for (i = 0; i < numInstances; i++) {
            epollst = (ENGINE_EPOLL_ST*)eng_epoll_events[i].data.ptr;
            if (epollst) {
                if (-1 ==
                    epoll_ctl(internal_efd, EPOLL_CTL_DEL,
                              epollst->eng_fd,
                              &eng_epoll_events[i])) {
                    WARN("Error removing fd from epoll\n");
                    ret = 0;
                }
                close(epollst->eng_fd);
            }
        }
    }

    if (0 == enable_external_polling) {
        if (icp_polling_threads) {
            OPENSSL_free(icp_polling_threads);
            icp_polling_threads = NULL;
        }
    }

    /* Reset global variables */
    numInstances = 0;
    icp_sal_userStop();
    engine_inited = 0;
    internal_efd = 0;
    qatInstanceHandles = NULL;
    keep_polling = 1;
    enable_external_polling = 0;
    enable_event_driven_polling = 0;
    enable_instance_for_thread = 0;
    qatPerformOpRetries = 0;
    currInst = 0;
    qat_poll_interval = QAT_POLL_PERIOD_IN_NS;
    qat_max_retry_count = QAT_CRYPTO_NUM_POLLING_RETRIES;
    pthread_mutex_unlock(&qat_engine_mutex);

    CRYPTO_CLOSE_QAT_LOG();

    return ret;
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
    DEBUG("[%s] ---- Destroying Engine...\n\n", __func__);
    qat_free_ciphers();
    qat_free_EC_methods();
    qat_free_DH_methods();
    qat_free_DSA_methods();
    qat_free_RSA_methods();
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
    CRYPTO_THREAD_cleanup_local(&qat_pkt_threshold_table_key);
#endif
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

    WARN("QAT Warnings enabled.\n");
    DEBUG("QAT Debug enabled.\n");
    DEBUG("[%s] id=%s\n", __func__, id);

    if (id && (strcmp(id, engine_qat_id) != 0)) {
        WARN("ENGINE_id defined already!\n");
        goto end;
    }

    if (!ENGINE_set_id(e, engine_qat_id)) {
        WARN("ENGINE_set_id failed\n");
        goto end;
    }

    if (!ENGINE_set_name(e, engine_qat_name)) {
        WARN("ENGINE_set_name failed\n");
        goto end;
    }

    /* Ensure the QAT error handling is set up */
    ERR_load_QAT_strings();

    /*
     * Create static structures for ciphers now
     * as this function will be called by a single thread.
     */
    qat_create_ciphers();
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
    CRYPTO_THREAD_run_once(&qat_pkt_threshold_table_once,qat_pkt_threshold_table_make_key);
#endif
    DEBUG("%s: About to set mem functions\n", __func__);

    if (!ENGINE_set_RSA(e, qat_get_RSA_methods())) {
        WARN("ENGINE_set_RSA failed\n");
        goto end;
    }

    if (!ENGINE_set_DSA(e, qat_get_DSA_methods())) {
        WARN("ENGINE_set_DSA failed\n");
        goto end;
    }

    if (!ENGINE_set_DH(e, qat_get_DH_methods())) {
        WARN("ENGINE_set_DH failed\n");
        goto end;
    }

    if (!ENGINE_set_EC(e, qat_get_EC_methods())) {
        WARN("ENGINE_set_EC failed\n");
        goto end;
    }

    if (!ENGINE_set_ciphers(e, qat_ciphers)) {
        WARN("ENGINE_set_ciphers failed\n");
        goto end;
    }

    if (!ENGINE_set_pkey_meths(e, qat_PRF_pkey_methods)) {
        WARN("ENGINE_set_pkey_meths failed\n");
        goto end;
    }

    pthread_atfork(engine_fork_handler, NULL, NULL);

    if (!ENGINE_set_destroy_function(e, qat_engine_destroy)
        || !ENGINE_set_init_function(e, qat_engine_init)
        || !ENGINE_set_finish_function(e, qat_engine_finish)
        || !ENGINE_set_ctrl_function(e, qat_engine_ctrl)
        || !ENGINE_set_cmd_defns(e, qat_cmd_defns)) {
        WARN("[%s] failed reg destroy, init or finish\n", __func__);

        goto end;
    }

    ret = 1;

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
    unsigned int devmasks[] = { 0, 0, 0 };
    DEBUG("[%s] engine_qat\n", __func__);

    if (access(QAT_DEV, F_OK) != 0) {
        QATerr(QAT_F_ENGINE_QAT, QAT_R_MEM_DRV_NOT_PRESENT);
        return ret;
    }

    if (!getDevices(devmasks)) {
        QATerr(QAT_F_ENGINE_QAT, QAT_R_QAT_DEV_NOT_PRESENT);
        return ret;
    }

    ret = ENGINE_new();

    if (!ret)
        return NULL;

    if (!bind_qat(ret, engine_qat_id)) {
        WARN("qat engine bind failed!\n");
        ENGINE_free(ret);
        return NULL;
    }

    return ret;
}

void ENGINE_load_qat(void)
{
    ENGINE *toadd = engine_qat();
    int error = 0;
    char error_string[120] = { 0 };

    DEBUG("[%s] engine_load_qat\n", __func__);

    if (toadd == NULL) {
        error = ERR_get_error();
        ERR_error_string(error, error_string);
        fprintf(stderr, "Error reported by engine load: %s\n", error_string);
        return;
    }

    DEBUG("[%s] engine_load_qat adding\n", __func__);
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}
#endif
