/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2022 Intel Corporation.
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
#ifdef QAT_HW
# ifdef QAT_HW_INTREE
#  define ENABLE_QAT_HW_SHA3
#  define ENABLE_QAT_HW_CHACHAPOLY
# endif
#endif

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
#include "qat_evp.h"
#include "qat_utils.h"

#ifdef QAT_HW
# include "qat_hw_ciphers.h"
# include "qat_hw_polling.h"
# include "qat_hw_rsa.h"
# include "qat_hw_dsa.h"
# include "qat_hw_dh.h"
# include "qat_hw_gcm.h"

/* QAT includes */
# include "cpa.h"
# include "cpa_cy_im.h"
# include "cpa_cy_common.h"
# include "cpa_types.h"
# include "icp_sal_user.h"
# include "icp_sal_poll.h"
#endif

#ifdef QAT_SW
# include "qat_sw_rsa.h"
# include "qat_sw_ecx.h"
# include "qat_sw_ec.h"
# include "qat_sw_polling.h"
# include "crypto_mb/cpu_features.h"
#endif

#ifdef QAT_SW_IPSEC
# include "qat_sw_gcm.h"
#endif

/* OpenSSL Includes */
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
# include <openssl/async.h>
#endif
#include <openssl/objects.h>
#include <openssl/crypto.h>

#ifdef QAT_SW_IPSEC
/* __cpuid(unsinged int info[4], unsigned int leaf, unsigned int subleaf); */
# define __cpuid(x, y, z) \
	        asm volatile("cpuid" : "=a"(x[0]), "=b"(x[1]), "=c"(x[2]), "=d"(x[3]) : "a"(y), "c"(z))

# define Genu 0x756e6547
# define ineI 0x49656e69
# define ntel 0x6c65746e

# define VAES_BIT 9
# define VPCLMULQDQ_BIT 10
# define AVX512F_BIT 16
#endif

#define QAT_MAX_INPUT_STRING_LENGTH 1024

#ifndef QAT_ENGINE_ID
# define QAT_ENGINE_ID qatengine
#endif

/* Qat engine id declaration */
const char *engine_qat_id = STR(QAT_ENGINE_ID);
#if defined(QAT_HW) && defined(QAT_SW)
const char *engine_qat_name =
    "Reference implementation of QAT crypto engine(qat_hw & qat_sw) v0.6.13";
#elif QAT_HW
const char *engine_qat_name =
    "Reference implementation of QAT crypto engine(qat_hw) v0.6.13";
#else
const char *engine_qat_name =
    "Reference implementation of QAT crypto engine(qat_sw) v0.6.13";
#endif
unsigned int engine_inited = 0;

int qat_hw_offload = 0;
int qat_sw_offload = 0;
int qat_hw_rsa_offload = 0;
int qat_hw_ecx_offload = 0;
int qat_hw_ecdh_offload = 0;
int qat_hw_ecdsa_offload = 0;
int qat_hw_prf_offload = 0;
int qat_hw_hkdf_offload = 0;
int qat_hw_gcm_offload = 0;
int qat_sw_rsa_offload = 0;
int qat_sw_ecx_offload = 0;
int qat_sw_ecdh_offload = 0;
int qat_sw_ecdsa_offload = 0;
int qat_sw_gcm_offload = 0;
int qat_hw_chacha_poly_offload = 0;
int qat_hw_aes_cbc_hmac_sha_offload = 0;
int qat_sw_sm2_offload = 0;
int qat_hw_sha_offload = 0;
int qat_sw_sm3_offload = 0;
int qat_keep_polling = 1;
int multibuff_keep_polling = 1;
int enable_external_polling = 0;
int enable_heuristic_polling = 0;
pthread_mutex_t qat_engine_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t qat_polling_thread;
sem_t hw_polling_thread_sem;

/* QAT number of inflight requests */
int num_requests_in_flight = 0;
int num_asym_requests_in_flight = 0;
int num_kdf_requests_in_flight = 0;
int num_cipher_pipeline_requests_in_flight = 0;
/* Multi-buffer number of items in queue */
int num_asym_mb_items_in_queue = 0;
int num_kdf_mb_items_in_queue = 0;
int num_cipher_mb_items_in_queue = 0;

sigset_t set = {{0}};
pthread_t qat_timer_poll_func_thread = 0;
int cleared_to_start = 0;
int qat_sw_ipsec = 0;

#ifdef QAT_HW
# define QAT_CONFIG_SECTION_NAME_SIZE 64
char qat_config_section_name[QAT_CONFIG_SECTION_NAME_SIZE] = "SHIM";
char *ICPConfigSectionName_libcrypto = qat_config_section_name;

int enable_inline_polling = 0;
int enable_event_driven_polling = 0;
int enable_instance_for_thread = 0;
int disable_qat_offload = 0;
int enable_sw_fallback = 0;
CpaInstanceHandle *qat_instance_handles = NULL;
Cpa16U qat_num_instances = 0;
Cpa32U qat_num_devices = 0;
pthread_key_t thread_local_variables;
pthread_mutex_t qat_instance_mutex = PTHREAD_MUTEX_INITIALIZER;
qat_instance_details_t qat_instance_details[QAT_MAX_CRYPTO_INSTANCES] = {{{0}}};
qat_accel_details_t qat_accel_details[QAT_MAX_CRYPTO_ACCELERATORS] = {{0}};
useconds_t qat_poll_interval = QAT_POLL_PERIOD_IN_NS;
int qat_epoll_timeout = QAT_EPOLL_TIMEOUT_IN_MS;
int qat_max_retry_count = QAT_CRYPTO_NUM_POLLING_RETRIES;
# ifdef QAT_HW_SET_INSTANCE_THREAD
unsigned int qat_map_inst[QAT_MAX_CRYPTO_INSTANCES] = {'\0'};
long int threadId[QAT_MAX_CRYPTO_THREADS] = {'\0'};
int threadCount = 0;
# endif
#endif

#ifdef QAT_SW
/* RSA */
BIGNUM *e_check = NULL;

mb_thread_data *mb_tlv = NULL;
pthread_key_t mb_thread_key;
#endif

#ifdef QAT_HW
uint64_t qat_hw_algo_enable_mask = 0xFFFF;
#else
uint64_t qat_hw_algo_enable_mask = 0;
#endif

#ifdef QAT_SW
uint64_t qat_sw_algo_enable_mask = 0xFFFF;
#else
uint64_t qat_sw_algo_enable_mask = 0;
#endif

static int bind_qat(ENGINE *e, const char *id);
/* Algorithm reload needs to free the previous method and reallocate it to
   exclude the impact of different offload modes, like QAT_HW -> QAT_SW.
   Use this flag to distinguish it from the other cases. */
int qat_reload_algo = 0;

const ENGINE_CMD_DEFN qat_cmd_defns[] = {
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
#ifdef QAT_HW
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
# ifndef __FreeBSD__
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
# endif
    {
        QAT_CMD_GET_NUM_CRYPTO_INSTANCES,
        "GET_NUM_CRYPTO_INSTANCES",
        "Get the number of crypto instances",
        ENGINE_CMD_FLAG_NO_INPUT},
# ifndef __FreeBSD__
    {
        QAT_CMD_DISABLE_EVENT_DRIVEN_POLLING_MODE,
        "DISABLE_EVENT_DRIVEN_POLLING_MODE",
        "Unset event driven polling mode",
        ENGINE_CMD_FLAG_NO_INPUT},
# endif
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
#endif
    {
        QAT_CMD_ENABLE_HEURISTIC_POLLING,
        "ENABLE_HEURISTIC_POLLING",
        "Enable the heuristic polling mode",
        ENGINE_CMD_FLAG_NO_INPUT},
    {
        QAT_CMD_GET_NUM_REQUESTS_IN_FLIGHT,
        "GET_NUM_REQUESTS_IN_FLIGHT",
        "Get the number of in-flight requests",
        ENGINE_CMD_FLAG_NUMERIC},
    {
        QAT_CMD_INIT_ENGINE,
        "INIT_ENGINE",
        "Initializes the engine if not already initialized",
        ENGINE_CMD_FLAG_NO_INPUT},
#ifdef QAT_HW
    {
        QAT_CMD_SET_CONFIGURATION_SECTION_NAME,
        "SET_CONFIGURATION_SECTION_NAME",
        "Set the configuration section to use in QAT driver configuration file",
        ENGINE_CMD_FLAG_STRING},
# ifndef __FreeBSD__
    {
        QAT_CMD_ENABLE_SW_FALLBACK,
        "ENABLE_SW_FALLBACK",
        "Enables the fallback to SW if the acceleration devices go offline",
        ENGINE_CMD_FLAG_NO_INPUT},
    {
        QAT_CMD_HEARTBEAT_POLL,
        "HEARTBEAT_POLL",
        "Check the acceleration devices are still functioning",
        ENGINE_CMD_FLAG_NO_INPUT},
# endif
    {
        QAT_CMD_DISABLE_QAT_OFFLOAD,
        "DISABLE_QAT_OFFLOAD",
        "Perform crypto operations on core",
        ENGINE_CMD_FLAG_NO_INPUT},
#endif

#ifdef QAT_HW
    {
        QAT_CMD_HW_ALGO_BITMAP,
        "HW_ALGO_BITMAP",
        "Set the HW algorithm bitmap and reload the algorithm registration",
        ENGINE_CMD_FLAG_STRING
    },
#endif

#ifdef QAT_SW
    {
        QAT_CMD_SW_ALGO_BITMAP,
        "SW_ALGO_BITMAP",
        "Set the SW algorithm bitmap and reload the algorithm registration",
        ENGINE_CMD_FLAG_STRING
    },
#endif

    {0, NULL, NULL, 0}
};

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
#ifdef QAT_HW
    qat_free_DH_methods();
    qat_free_DSA_methods();
#endif

#if defined(QAT_SW) || defined(QAT_HW)
    qat_free_EC_methods();
    qat_free_RSA_methods();
    qat_free_digest_meth();
#endif

#if defined(QAT_SW_IPSEC) || defined(QAT_HW)
    qat_free_ciphers();
#endif

#ifdef QAT_SW_IPSEC
# ifdef ENABLE_QAT_SW_GCM
    vaesgcm_free_ipsec_mb_mgr();
# endif
#endif

    qat_hw_ecx_offload = 0;
    qat_hw_prf_offload = 0;
    qat_hw_hkdf_offload = 0;
    qat_sw_ecx_offload = 0;
    qat_sw_sm2_offload = 0;
    qat_sw_sm3_offload = 0;
    QAT_DEBUG_LOG_CLOSE();
    ERR_unload_QAT_strings();
    return 1;
}

#ifdef QAT_SW_IPSEC
int hw_support(void) {

    unsigned int  info[4] = {0, 0, 0, 0};
    unsigned int *ebx, *ecx, *edx;

    ebx = &info[1];
    ecx = &info[2];
    edx = &info[3];

    /* Is this an Intel CPU? */
    __cpuid(info, 0x00, 0);
    if (*ebx != Genu || *ecx != ntel || *edx != ineI)
        return 0;

    __cpuid(info, 0x07, 0);

    unsigned int avx512f = 0;
    unsigned int vaes    = 0;
    unsigned int vpclmulqdq = 0;

    if (*ebx & (0x1 << AVX512F_BIT))
        avx512f = 1;

    if (*ecx & (0x1 << VAES_BIT))
        vaes = 1;

    if (*ecx & (0x1 << VPCLMULQDQ_BIT))
        vpclmulqdq = 1;

    DEBUG("Processor Support - AVX512F = %u, VAES = %u, VPCLMULQDQ = %u\n",
           avx512f, vaes, vpclmulqdq);

    if (avx512f && vaes && vpclmulqdq) {
        qat_sw_ipsec = 1;
        return 1;
    } else {
        fprintf(stderr, "Processor unsupported for QAT_SW - AVX512F = %u, VAES = %u, VPCLMULQDQ = %u\n",
                avx512f, vaes, vpclmulqdq);
        return 0;
    }
}
#endif

int qat_pthread_mutex_lock(void)
{
    int ret = 0;
    ret = pthread_mutex_lock(&qat_engine_mutex);
    if (ret != 0) {
        WARN("pthread mutex lock failure\n");
    }
    return ret;
}

int qat_pthread_mutex_unlock(void)
{
    int ret = 0;
    ret = pthread_mutex_unlock(&qat_engine_mutex);
    if (ret != 0) {
        WARN("pthread mutex unlock failure\n");
    }
    return ret;
}

int qat_engine_init(ENGINE *e)
{
    qat_pthread_mutex_lock();
    if (engine_inited) {
        qat_pthread_mutex_unlock();
        return 1;
    }

    CRYPTO_INIT_QAT_LOG();
    DEBUG("QAT Engine initialization:\n");

#ifdef QAT_HW
    if (qat_hw_offload) {
        if (!qat_init(e)) {
            fprintf(stderr, "QAT_HW initialization Failed\n");
            return 0;
        }
    }
#endif

#ifdef QAT_SW
    if (qat_sw_offload) {
        if (!multibuff_init(e)) {
            fprintf(stderr, "QAT_SW initialization Failed\n");
            return 0;
        }
    }
#endif

    engine_inited = 1;
    qat_pthread_mutex_unlock();

    return 1;
}

int qat_engine_finish_int(ENGINE *e, int reset_globals)
{
    int ret = 1;

    DEBUG("---- QAT Engine Finishing...\n\n");
    qat_pthread_mutex_lock();

#ifdef QAT_HW
    if (qat_hw_offload) {
        ret = qat_finish_int(e, reset_globals);
    }
#endif

#ifdef QAT_SW
    if (qat_sw_offload) {
       ret = multibuff_finish_int(e, reset_globals);
    }
#endif

    engine_inited = 0;

    if (reset_globals == QAT_RESET_GLOBALS) {
        enable_external_polling = 0;
        enable_heuristic_polling = 0;
        qat_hw_offload = 0;
        qat_sw_offload = 0;
    }
    qat_pthread_mutex_unlock();
    CRYPTO_CLOSE_QAT_LOG();
    return ret;
}

/******************************************************************************
 *  * function:
 *         qat_engine_finish(ENGINE *e)
 *
 * @param e [IN] - OpenSSL engine pointer
 *
 * description:
 *   Qat engine finish function with standard signature.
 *   This is a wrapper for qat_engine_finish_int that always resets all the
 *   global variables used to store the engine configuration.
 ******************************************************************************/
int qat_engine_finish(ENGINE *e)
{
    return qat_engine_finish_int(e, QAT_RESET_GLOBALS);
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
    char *temp = NULL;
    uint64_t val = 0; 
#ifdef QAT_HW
# ifndef __FreeBSD__
    CpaStatus status = CPA_STATUS_SUCCESS;
    int flags = 0;
    int fd = 0;
    int fcntl_ret = -1;
# endif
#endif

    switch (cmd) {
        case QAT_CMD_POLL:
            BREAK_IF(!engine_inited, "POLL failed as engine is not initialized\n");
            BREAK_IF(!enable_external_polling, "POLL failed as external polling is not enabled\n");
            BREAK_IF(p == NULL, "POLL failed as the input parameter was NULL\n");
#ifdef QAT_HW
            if (qat_hw_offload) {
                BREAK_IF(qat_instance_handles == NULL, "POLL failed as no instances are available\n");
                *(int *)p = (int)poll_instances();
            }
#endif

#ifdef QAT_SW
            *(int *)p = multibuff_poll();
#endif
        break;

        case QAT_CMD_ENABLE_EXTERNAL_POLLING:
        BREAK_IF(engine_inited, \
                "ENABLE_EXTERNAL_POLLING failed as the engine is already initialized\n");
        DEBUG("Enabled external polling\n");
        enable_external_polling = 1;
#ifdef QAT_HW
        enable_inline_polling = 0;
#endif
        break;

#ifdef QAT_HW
        case QAT_CMD_ENABLE_INLINE_POLLING:
        BREAK_IF(engine_inited, \
                "ENABLE_INLINE_POLLING failed as the engine is already initialized\n");
        DEBUG("Enabled inline polling\n");
        enable_inline_polling = 1;
        enable_external_polling = 0;
        break;

# ifndef __FreeBSD__
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
# endif

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
# ifndef ENABLE_QAT_HW_SMALL_PKT_OFFLOAD
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
# else
        WARN("QAT_CMD_SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD is not supported\n");
        retVal = 0;
# endif
        break;
#endif

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
        } else if (i == GET_NUM_ASYM_MB_ITEMS_IN_QUEUE) {
            *(int **)p = &num_asym_mb_items_in_queue;
        } else if (i == GET_NUM_KDF_MB_ITEMS_IN_QUEUE) {
            *(int **)p = &num_kdf_mb_items_in_queue;
        } else if (i == GET_NUM_SYM_MB_ITEMS_IN_QUEUE) {
            *(int **)p = &num_cipher_mb_items_in_queue;
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

#ifdef QAT_HW
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
        case QAT_CMD_ENABLE_SW_FALLBACK:
# if !defined(__FreeBSD__) && !defined(QAT_HW_INTREE)
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
# if !defined(__FreeBSD__) && !defined(QAT_HW_INTREE)
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

        case QAT_CMD_DISABLE_QAT_OFFLOAD:
        DEBUG("Disabled qat offload\n");
        BREAK_IF(!engine_inited, \
                "DISABLE_QAT_OFFLOAD failed as the engine is not initialized\n");
        disable_qat_offload = 1;
        CRYPTO_QAT_LOG("QAT Engine Offload disabled - %s\n", __func__);
        break;
#endif

#ifdef QAT_HW
        case QAT_CMD_HW_ALGO_BITMAP:
        BREAK_IF(NULL == p, "The CMD HW_ALGO_BITMAP needs a string input.\n");
        val = strtoul(p, &temp, 0);
        BREAK_IF(errno == ERANGE || temp == p || *temp != '\0',
                "The hardware enable mask is invalid.\n");
        BREAK_IF(val < 0 || val > 0xFFFF,
                "The hardware enable mask is out of the range.\n");
        DEBUG("QAT_CMD_HW_ALGO_BITMAP = 0x%lx\n", val);
        qat_hw_algo_enable_mask = val;
        qat_reload_algo = 1;
        BREAK_IF(!bind_qat(e, engine_qat_id), "QAT Engine bind failed\n");
        qat_reload_algo = 0;
        break;
#endif

#ifdef QAT_SW
        case QAT_CMD_SW_ALGO_BITMAP:
        BREAK_IF(NULL == p, "The CMD SW_ALGO_BITMAP needs a string input.\n");
        val = strtoul(p, &temp, 0);
        BREAK_IF(errno == ERANGE || temp == p || *temp != '\0',
                "The software enable mask is invalid.\n");
        BREAK_IF(val < 0 || val > 0xFFFF,
                "The software enable mask is out of the range.\n");
        DEBUG("QAT_CMD_SW_ALGO_BITMAP = 0x%lx\n", val);
        qat_sw_algo_enable_mask = val;
        qat_reload_algo = 1;
        BREAK_IF(!bind_qat(e, engine_qat_id), "QAT Engine bind failed\n");
        qat_reload_algo = 0;
        break;
#endif

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

#ifdef QAT_HW
    char *config_section = NULL;
#endif
    QAT_DEBUG_LOG_INIT();

    WARN("QAT Warnings enabled.\n");
    DEBUG("QAT Debug enabled.\n");
    WARN("%s - %s \n", id, engine_qat_name);

#ifdef QAT_HW
# ifdef QAT_HW_INTREE
    if (icp_sal_userIsQatAvailable() == CPA_TRUE) {
        qat_hw_offload = 1;
    } else {
#  ifndef QAT_SW
        fprintf(stderr, "Qat Intree device not available\n");
        goto end;
#  endif
    }
# else
    if (access(QAT_DEV, F_OK) == 0) {
        qat_hw_offload = 1;
        if (access(QAT_MEM_DEV, F_OK) != 0) {
            fprintf(stderr, "Qat memory driver not present\n");
            goto end;
        }
    } else {
#  ifndef QAT_SW
        fprintf(stderr, "Qat device not available\n");
        goto end;
#  endif
    }
# endif
#endif

    if (id && (strcmp(id, engine_qat_id) != 0)) {
        WARN("ENGINE_id defined already! %s - %s\n", id, engine_qat_id);
        goto end;
    }

    if (!ENGINE_set_id(e, engine_qat_id)) {
        fprintf(stderr, "ENGINE_set_id failed\n");
        goto end;
    }

    if (!ENGINE_set_name(e, engine_qat_name)) {
        fprintf(stderr, "ENGINE_set_name failed\n");
        goto end;
    }

    /* Ensure the QAT error handling is set up */
    ERR_load_QAT_strings();

    if (qat_hw_offload) {
#ifdef QAT_HW
        DEBUG("Registering QAT HW supported algorithms\n");

# ifdef ENABLE_QAT_HW_DSA
        if (!ENGINE_set_DSA(e, qat_get_DSA_methods())) {
            WARN("ENGINE_set_DSA QAT HW failed\n");
            goto end;
        }
# endif

# ifdef ENABLE_QAT_HW_DH
        if (!ENGINE_set_DH(e, qat_get_DH_methods())) {
            WARN("ENGINE_set_DH QAT HW failed\n");
            goto end;
        }
# endif

#endif
    }

#ifdef QAT_SW
# if defined(ENABLE_QAT_SW_RSA) || defined(ENABLE_QAT_SW_ECX)    \
  || defined(ENABLE_QAT_SW_ECDH) || defined(ENABLE_QAT_SW_ECDSA) \
  || defined(ENABLE_QAT_SW_SM2) || defined(ENABLE_QAT_SW_SM3)
        DEBUG("Registering QAT SW supported algorithms\n");
        qat_sw_offload = 1;
# endif
#endif

#if defined(QAT_HW) || defined(QAT_SW)
    if (!ENGINE_set_RSA(e, qat_get_RSA_methods())) {
        WARN("ENGINE_set_RSA QAT HW failed\n");
        goto end;
    }

     if (!ENGINE_set_EC(e, qat_get_EC_methods())) {
          WARN("ENGINE_set_EC failed\n");
          goto end;
     }

# ifndef QAT_OPENSSL_3
     if (!ENGINE_set_pkey_meths(e, qat_pkey_methods)) {
          WARN("ENGINE_set_pkey_meths failed\n");
          goto end;
     }
# endif

    qat_create_digest_meth();
    if (!ENGINE_set_digests(e, qat_digest_methods)) {
        WARN("ENGINE_set_digests failed\n");
        goto end;
    }

#endif

#ifdef QAT_SW_IPSEC
    if (hw_support()) {
# ifdef ENABLE_QAT_SW_GCM
        if (!vaesgcm_init_ipsec_mb_mgr()) {
            fprintf(stderr, "IPSec Multi-Buffer Manager Initialization failed\n");
            goto end;
        }
# endif
    }
#endif

     /* Create static structures for ciphers now
      * as this function will be called by a single thread. */
     qat_create_ciphers();

#if defined(QAT_HW) || defined(QAT_SW_IPSEC)
    if (!ENGINE_set_ciphers(e, qat_ciphers)) {
        WARN("ENGINE_set_ciphers failed\n");
        goto end;
    }
#endif

    pthread_atfork(engine_finish_before_fork_handler, NULL,
                   engine_init_child_at_fork_handler);

    ret = 1;
    ret &= ENGINE_set_destroy_function(e, qat_engine_destroy);
    ret &= ENGINE_set_init_function(e, qat_engine_init);
    ret &= ENGINE_set_ctrl_function(e, qat_engine_ctrl);
    ret &= ENGINE_set_finish_function(e, qat_engine_finish);
    ret &= ENGINE_set_cmd_defns(e, qat_cmd_defns);
    if (ret == 0) {
        fprintf(stderr, "Engine failed to register init, finish or destroy functions\n");
    }

    /*
     * If the QAT_SECTION_NAME environment variable is set, use that.
     * Similar setting made through engine ctrl command takes precedence
     * over this environment variable. It makes sense to use the environment
     * variable because the container orchestrators pass down this
     * configuration as environment variables.
     */

#ifdef QAT_HW
# ifdef __GLIBC_PREREQ
#  if __GLIBC_PREREQ(2, 17)
    config_section = secure_getenv("QAT_SECTION_NAME");
#  else
    config_section = getenv("QAT_SECTION_NAME");
#  endif
# else
    config_section = getenv("QAT_SECTION_NAME");
# endif
    if (validate_configuration_section_name(config_section)) {
        strncpy(qat_config_section_name, config_section, QAT_CONFIG_SECTION_NAME_SIZE - 1);
        qat_config_section_name[QAT_CONFIG_SECTION_NAME_SIZE - 1]   = '\0';
    }
#endif

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
        fprintf(stderr, "Failed to create Engine\n");
        QATerr(QAT_F_ENGINE_QAT, QAT_R_QAT_CREATE_ENGINE_FAILURE);
        return NULL;
    }

    if (!bind_qat(ret, engine_qat_id)) {
        fprintf(stderr, "Qat Engine bind failed\n");
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
