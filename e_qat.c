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
#ifdef OPENSSL_QAT_OFFLOAD
# if defined(USE_QAT_CONTIG_MEM) && !defined(USE_QAE_MEM)
#  define QAT_DEV "/dev/qat_contig_mem"
# elif defined(USE_QAE_MEM) && !defined(USE_QAT_CONTIG_MEM)
#  define QAT_DEV "/dev/usdm_drv"
# elif defined(USE_QAE_MEM) && defined(USE_QAT_CONFIG_MEM)
#  error "USE_QAT_CONTIG_MEM and USE_QAE_MEM both defined"
# else
#  error "No memory driver type defined"
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
#include "e_qat_err.h"
#ifdef OPENSSL_QAT_OFFLOAD
# include "qat_ciphers.h"
# include "qat_polling.h"
# include "qat_rsa.h"
# include "qat_dsa.h"
# include "qat_dh.h"
# include "qat_ec.h"

/* QAT includes */
# include "cpa.h"
# include "cpa_cy_im.h"
# include "cpa_cy_common.h"
# include "cpa_types.h"
# include "icp_sal_user.h"
# include "icp_sal_poll.h"
#endif

#ifdef OPENSSL_MULTIBUFF_OFFLOAD
# include "multibuff_rsa.h"
# include "multibuff_ecx.h"
# include "multibuff_polling.h"
# include "crypto_mb/cpu_features.h"
#endif

#ifdef OPENSSL_IPSEC_OFFLOAD
# include "vaes_gcm.h"
#endif

/* OpenSSL Includes */
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
# include <openssl/async.h>
#endif
#include <openssl/objects.h>
#include <openssl/crypto.h>

#ifdef OPENSSL_IPSEC_OFFLOAD
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
const char *engine_qat_name =
    "Reference implementation of QAT crypto engine v0.6.1";
unsigned int engine_inited = 0;

int qat_offload = 0;
int qat_keep_polling = 1;
int multibuff_keep_polling = 1;
int enable_external_polling = 0;
int enable_heuristic_polling = 0;
pthread_mutex_t qat_engine_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t qat_polling_thread;
pthread_t multibuff_polling_thread;

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
pthread_t multibuff_timer_poll_func_thread = 0;
int cleared_to_start = 0;

#ifdef OPENSSL_QAT_OFFLOAD
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
#endif

#ifdef OPENSSL_MULTIBUFF_OFFLOAD
/* RSA */
BIGNUM *e_check = NULL;
mb_flist_rsa_priv rsa_priv_freelist;
mb_flist_rsa_pub rsa_pub_freelist;
mb_queue_rsa_priv rsa_priv_queue;
mb_queue_rsa_pub rsa_pub_queue;

/* X25519 */
mb_flist_x25519_keygen x25519_keygen_freelist;
mb_flist_x25519_derive x25519_derive_freelist;
mb_queue_x25519_keygen x25519_keygen_queue;
mb_queue_x25519_derive x25519_derive_queue;

#endif

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
#ifdef OPENSSL_QAT_OFFLOAD
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
#ifdef OPENSSL_QAT_OFFLOAD
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
#ifdef OPENSSL_QAT_OFFLOAD
    qat_free_EC_methods();
    qat_free_DH_methods();
    qat_free_DSA_methods();
    qat_free_RSA_methods();
#endif

#ifdef OPENSSL_MULTIBUFF_OFFLOAD
    multibuff_free_RSA_methods();
#endif

#if defined(OPENSSL_IPSEC_OFFLOAD) || defined(OPENSSL_QAT_OFFLOAD)
    qat_free_ciphers();
#endif

#ifdef OPENSSL_IPSEC_OFFLOAD
# ifndef OPENSSL_DISABLE_VAES_GCM
    vaesgcm_free_ipsec_mb_mgr();
# endif
#endif

    qat_offload = 0;
    QAT_DEBUG_LOG_CLOSE();
    ERR_unload_QAT_strings();
    return 1;
}

#ifdef OPENSSL_IPSEC_OFFLOAD
static int hw_support(void) {

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
	return 1;
    } else {
        WARN("Processor unsupported - AVX512F = %u, VAES = %u, VPCLMULQDQ = %u\n",
             avx512f, vaes, vpclmulqdq);
	return 0;
    }
}
#endif

int qat_engine_init(ENGINE *e)
{
    pthread_mutex_lock(&qat_engine_mutex);
    if (engine_inited) {
        pthread_mutex_unlock(&qat_engine_mutex);
        return 1;
    }

    DEBUG("QAT Engine initialization:\n");
    CRYPTO_INIT_QAT_LOG();

#ifdef OPENSSL_QAT_OFFLOAD
    if (qat_offload) {
        if (!qat_init(e)) {
            WARN("QAT initialization Failed\n");
            return 0;
        }
    }
#endif

#ifdef OPENSSL_MULTIBUFF_OFFLOAD
    if (!qat_offload) {
        if (!multibuff_init(e)) {
            WARN("Multibuff initialization Failed\n");
            return 0;
        }
    }
#endif

    engine_inited = 1;
    pthread_mutex_unlock(&qat_engine_mutex);

    return 1;
}

int qat_engine_finish_int(ENGINE *e, int reset_globals)
{
    int ret = 1;

    DEBUG("---- QAT Engine Finishing...\n\n");
    pthread_mutex_lock(&qat_engine_mutex);

#ifdef OPENSSL_QAT_OFFLOAD
    if (qat_offload) {
        ret = qat_finish_int(e, reset_globals);
    }
#endif

#ifdef OPENSSL_MULTIBUFF_OFFLOAD
    if (!qat_offload) {
       ret = multibuff_finish_int(e, reset_globals);
    }
#endif

    engine_inited = 0;

    if (reset_globals == QAT_RESET_GLOBALS) {
        enable_external_polling = 0;
        enable_heuristic_polling = 0;
    }

    pthread_mutex_unlock(&qat_engine_mutex);

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
#ifdef OPENSSL_QAT_OFFLOAD
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
#ifdef OPENSSL_QAT_OFFLOAD
            BREAK_IF(qat_instance_handles == NULL, "POLL failed as no instances are available\n");

            *(int *)p = (int)poll_instances();
#endif

#ifdef OPENSSL_MULTIBUFF_OFFLOAD
            *(int *)p = multibuff_poll();
#endif
        break;

        case QAT_CMD_ENABLE_EXTERNAL_POLLING:
        BREAK_IF(engine_inited, \
                "ENABLE_EXTERNAL_POLLING failed as the engine is already initialized\n");
        DEBUG("Enabled external polling\n");
        enable_external_polling = 1;
#ifdef OPENSSL_QAT_OFFLOAD
        enable_inline_polling = 0;
#endif
        break;

#ifdef OPENSSL_QAT_OFFLOAD
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
# ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
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

#ifdef OPENSSL_QAT_OFFLOAD
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
# if !defined(__FreeBSD__) && !defined(QAT_DRIVER_INTREE)
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
# if !defined(__FreeBSD__) && !defined(QAT_DRIVER_INTREE)
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

#ifdef OPENSSL_QAT_OFFLOAD
    char *config_section = NULL;
#endif
    QAT_DEBUG_LOG_INIT();

    WARN("QAT Warnings enabled.\n");
    DEBUG("QAT Debug enabled.\n");
    WARN("%s - %s \n", id, engine_qat_name);

#if defined(OPENSSL_QAT_OFFLOAD) && !defined(QAT_DRIVER_INTREE)
    if (access(QAT_DEV, F_OK) != 0) {
        WARN("Qat memory driver not present\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_MEM_DRV_NOT_PRESENT);
        goto end;
    }
#endif

    if (id && (strcmp(id, engine_qat_id) != 0)) {
        WARN("ENGINE_id defined already! %s - %s\n", id, engine_qat_id);
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

#ifdef OPENSSL_QAT_OFFLOAD

# ifdef QAT_INTREE
    if (icp_sal_userIsQatAvailable() == CPA_TRUE) {
# endif
        DEBUG("Registering QAT supported algorithms\n");
        qat_offload = 1;

        /* Create static structures for ciphers now
         * as this function will be called by a single thread. */
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

        if (!ENGINE_set_pkey_meths(e, qat_pkey_methods)) {
            WARN("ENGINE_set_pkey_meths failed\n");
            QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_PKEY_FAILURE);
            goto end;
        }
# ifdef QAT_INTREE
    }
# endif
#endif

#ifdef OPENSSL_MULTIBUFF_OFFLOAD
    if (!qat_offload) {
        if (mbx_get_algo_info(MBX_ALGO_RSA_2K)) {
            DEBUG("Multibuffer RSA Supported\n");
            if (!ENGINE_set_RSA(e, multibuff_get_RSA_methods())) {
                WARN("ENGINE_set_RSA failed\n");
                QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_RSA_FAILURE);
                goto end;
            }
        }
        if (mbx_get_algo_info(MBX_ALGO_X25519)) {
            DEBUG("Multibuffer X25519 Supported\n");
            if (!ENGINE_set_pkey_meths(e, multibuff_x25519_pkey_methods)) {
                WARN("ENGINE_set_pkey_meths failed\n");
                QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_X25519_FAILURE);
                goto end;
            }
        }
    }
#endif

#ifdef OPENSSL_IPSEC_OFFLOAD
    if (!hw_support()) {
        WARN("The Processor does not support the features needed for VAES.\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_HW_NOT_SUPPORTED);
        goto end;
    }
# ifndef OPENSSL_DISABLE_VAES_GCM
    if (!vaesgcm_init_ipsec_mb_mgr()) {
        WARN("IPSec Multi-Buffer Manager Initialization failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_GCM_CIPHERS_FAILURE);
        goto end;
    }
# endif
#endif

#if defined(OPENSSL_QAT_OFFLOAD) || defined(OPENSSL_IPSEC_OFFLOAD)
    if (!ENGINE_set_ciphers(e, qat_ciphers)) {
        WARN("ENGINE_set_ciphers failed\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_CIPHER_FAILURE);
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
        WARN("Engine failed to register init, finish or destroy functions\n");
        QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_REGISTER_FUNC_FAILURE);
    }

    /*
     * If the QAT_SECTION_NAME environment variable is set, use that.
     * Similar setting made through engine ctrl command takes precedence
     * over this environment variable. It makes sense to use the environment
     * variable because the container orchestrators pass down this
     * configuration as environment variables.
     */

#ifdef OPENSSL_QAT_OFFLOAD
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
