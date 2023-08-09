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
#ifndef QAT_BORINGSSL
# include "qat_hw_ciphers.h"
#endif /* QAT_BORINGSSL */
# include "qat_hw_polling.h"
# include "qat_hw_rsa.h"
#ifndef QAT_BORINGSSL
# include "qat_hw_dsa.h"
# include "qat_hw_dh.h"
# include "qat_hw_gcm.h"
#endif /* QAT_BORINGSSL */

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
# ifdef ENABLE_QAT_SW_SM4_GCM
#  include "crypto_mb/sm4_gcm.h"
# endif
# ifdef ENABLE_QAT_SW_SM4_CCM
#  include "crypto_mb/sm4_ccm.h"
# endif
#endif

#ifdef ENABLE_QAT_SW_GCM
#ifndef QAT_BORINGSSL
# include "qat_sw_gcm.h"
#endif /* QAT_BORINGSSL */
#endif

#ifdef QAT_SW_IPSEC
# if defined(ENABLE_QAT_FIPS) && defined(ENABLE_QAT_SW_SHA2)
#  include "qat_sw_sha2.h"
# endif
#endif

/* OpenSSL Includes */
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/crypto.h>

#if defined(QAT_SW) || defined(QAT_SW_IPSEC)
/* __cpuid(unsigned int info[4], unsigned int leaf, unsigned int subleaf); */
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

#ifdef ENABLE_QAT_FIPS
int qat_fips_key_zeroize;
int qat_fips_kat_test;
#endif

/* Qat engine id declaration */
const char *engine_qat_id = STR(QAT_ENGINE_ID);
#if defined(QAT_HW) && defined(QAT_SW)
const char *engine_qat_name =
    "Reference implementation of QAT crypto engine(qat_hw & qat_sw) v1.2.0";
#elif QAT_HW
const char *engine_qat_name =
    "Reference implementation of QAT crypto engine(qat_hw) v1.2.0";
#else
const char *engine_qat_name =
    "Reference implementation of QAT crypto engine(qat_sw) v1.2.0";
#endif
unsigned int engine_inited = 0;
int fallback_to_openssl = 0;
int fallback_to_qat_sw = 0; /* QAT HW initialize fail, offload to QAT SW. */
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
int qat_hw_sm4_cbc_offload = 0;
int qat_sw_sm2_offload = 0;
int qat_hw_sm2_offload = 0;
int qat_hw_sha_offload = 0;
int qat_hw_sm3_offload = 0;
# ifdef ENABLE_QAT_FIPS
int qat_sw_sha_offload = 0;
# endif
# ifdef QAT_OPENSSL_PROVIDER
int qat_hw_dsa_offload = 0;
int qat_hw_dh_offload = 0;
int qat_hw_ecx_448_offload = 0;
# endif
int qat_sw_sm3_offload = 0;
int qat_sw_sm4_cbc_offload = 0;
int qat_sw_sm4_gcm_offload = 0;
int qat_sw_sm4_ccm_offload = 0;
int qat_hw_keep_polling = 1;
int qat_sw_keep_polling = 1;
int enable_external_polling = 0;
int enable_heuristic_polling = 0;
pthread_mutex_t qat_engine_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t qat_polling_thread;
sem_t hw_polling_thread_sem;

/* QAT number of in-flight requests */
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
pthread_mutex_t qat_poll_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t qat_poll_condition = PTHREAD_COND_INITIALIZER;
int qat_cond_wait_started = 0;

#ifdef QAT_HW
# define QAT_CONFIG_SECTION_NAME_SIZE 64
char qat_config_section_name[QAT_CONFIG_SECTION_NAME_SIZE] = "SHIM";
char *ICPConfigSectionName_libcrypto = qat_config_section_name;
int enable_inline_polling = 0;
int enable_event_driven_polling = 0;
int enable_instance_for_thread = 0;
int disable_qat_offload = 0;
/* By default Software fallback disabled in QAT FIPs mode.
 * Always enable_sw_fallback is zero in QAT FIPs mode.
 */
int enable_sw_fallback = 0;
CpaInstanceHandle *qat_instance_handles = NULL;
Cpa16U qat_num_instances = 0;
Cpa16U qat_asym_num_instance = 0;
Cpa16U qat_sym_num_instance = 0;
Cpa32U qat_num_devices = 0;
pthread_key_t thread_local_variables;
pthread_mutex_t qat_instance_mutex = PTHREAD_MUTEX_INITIALIZER;
qat_instance_details_t qat_instance_details[QAT_MAX_CRYPTO_INSTANCES] = {{{0}}};
qat_accel_details_t qat_accel_details[QAT_MAX_CRYPTO_ACCELERATORS] = {{0}};
useconds_t qat_poll_interval = QAT_POLL_PERIOD_IN_NS;
int qat_epoll_timeout = QAT_EPOLL_TIMEOUT_IN_MS;
int qat_max_retry_count = QAT_CRYPTO_NUM_POLLING_RETRIES;
unsigned int qat_map_sym_inst[QAT_MAX_CRYPTO_INSTANCES] = {'\0'};
unsigned int qat_map_asym_inst[QAT_MAX_CRYPTO_INSTANCES] = {'\0'};
# ifdef QAT_HW_SET_INSTANCE_THREAD
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
uint64_t qat_hw_algo_enable_mask = 0xFFFFF;
#else
uint64_t qat_hw_algo_enable_mask = 0;
#endif

#if defined(QAT_SW) || defined(QAT_SW_IPSEC)
uint64_t qat_sw_algo_enable_mask = 0xFFFFF;
#else
uint64_t qat_sw_algo_enable_mask = 0;
#endif

/* Algorithm reload needs to free the previous method and reallocate it to
   exclude the impact of different offload modes, like QAT_HW -> QAT_SW.
   Use this flag to distinguish it from the other cases. */
int qat_reload_algo = 0;

/* For QAT_HW & QAT_SW co-existence submission. */
int qat_rsa_coexist = 0;
int qat_ecdh_coexist = 0;
int qat_ecdsa_coexist = 0;
int qat_ecx_coexist = 0;
int qat_sm4_cbc_coexist = 0;
__thread unsigned int qat_sw_rsa_priv_req = 0;
__thread unsigned int qat_sw_rsa_pub_req = 0;
__thread unsigned int qat_sw_ecdsa_sign_req = 0;
__thread unsigned int qat_sw_ecdh_keygen_req = 0;
__thread unsigned int qat_sw_ecdh_derive_req = 0;
__thread unsigned int qat_sw_ecx_keygen_req = 0;
__thread unsigned int qat_sw_ecx_derive_req = 0;
__thread unsigned int qat_sw_sm4_cbc_cipher_req;
__thread int num_rsa_priv_retry = 0;
__thread int num_rsa_pub_retry = 0;
__thread int num_ecdsa_sign_retry = 0;
__thread int num_ecdh_keygen_retry = 0;
__thread int num_ecdh_derive_retry = 0;
__thread int num_ecx_keygen_retry = 0;
__thread int num_ecx_derive_retry = 0;
__thread int num_sm4_cbc_cipher_retry = 0;
__thread unsigned long long num_rsa_hw_priv_reqs = 0;
__thread unsigned long long num_rsa_sw_priv_reqs = 0;
__thread unsigned long long num_rsa_hw_pub_reqs = 0;
__thread unsigned long long num_rsa_sw_pub_reqs = 0;
__thread unsigned long long num_ecdsa_hw_sign_reqs = 0;
__thread unsigned long long num_ecdsa_sw_sign_reqs = 0;
__thread unsigned long long num_ecdh_hw_keygen_reqs = 0;
__thread unsigned long long num_ecdh_sw_keygen_reqs = 0;
__thread unsigned long long num_ecdh_hw_derive_reqs = 0;
__thread unsigned long long num_ecdh_sw_derive_reqs = 0;
__thread unsigned long long num_ecx_hw_keygen_reqs = 0;
__thread unsigned long long num_ecx_sw_keygen_reqs = 0;
__thread unsigned long long num_ecx_hw_derive_reqs = 0;
__thread unsigned long long num_ecx_sw_derive_reqs = 0;
__thread unsigned long long num_sm4_cbc_hw_cipher_reqs = 0;
__thread unsigned long long num_sm4_cbc_sw_cipher_reqs = 0;

#ifndef QAT_BORINGSSL
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
#endif /* QAT_BORINGSSL */

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
#if !defined(QAT_OPENSSL_PROVIDER)
static int qat_engine_destroy(ENGINE *e)
{
    DEBUG("---- Destroying Engine...\n\n");
# ifdef QAT_HW
#  ifndef QAT_BORINGSSL
    qat_free_DH_methods();
    qat_free_DSA_methods();
#  endif /* QAT_BORINGSSL */
# endif

# if defined(QAT_SW) || defined(QAT_HW)
    qat_free_EC_methods();
    qat_free_RSA_methods();
#  ifndef QAT_BORINGSSL
    qat_free_digest_meth();
    qat_free_ciphers();
#  endif /* QAT_BORINGSSL */
# endif

# ifdef ENABLE_QAT_SW_GCM
    vaesgcm_free_ipsec_mb_mgr();
# endif

    qat_hw_ecx_offload = 0;
    qat_ecx_coexist = 0;
    qat_hw_prf_offload = 0;
    qat_hw_hkdf_offload = 0;
    qat_sw_ecx_offload = 0;
    qat_sw_sm2_offload = 0;
    qat_hw_sm2_offload = 0;
    qat_sw_sm3_offload = 0;
    qat_sw_sm4_cbc_offload = 0;
    qat_sw_sm4_gcm_offload = 0;
    qat_sw_sm4_ccm_offload = 0;
    qat_hw_sm3_offload = 0;
    QAT_DEBUG_LOG_CLOSE();
    ERR_unload_QAT_strings();
    return 1;
}
#endif

#if defined(QAT_SW) || defined(QAT_SW_IPSEC)
int qat_sw_cpu_support(void)
{
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

    DEBUG("QAT_SW - Processor supported: AVX512F = %u, VAES = %u, VPCLMULQDQ = %u\n",
           avx512f, vaes, vpclmulqdq);

    if (avx512f && vaes && vpclmulqdq) {
        return 1;
    } else {
        fprintf(stderr, "QAT_SW - Processor unsupported: AVX512F = %u, VAES = %u, VPCLMULQDQ = %u\n",
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
        if (!qat_hw_init(e)) {
# ifdef ENABLE_QAT_FIPS
            fprintf(stderr, "QAT_HW initialization Failed\n");
            return 0;
# else
#  ifdef QAT_SW /* Co-Existence mode: Don't return failure when QAT HW initialization Failed. */
            fallback_to_qat_sw = 1;
            WARN("QAT HW initialization Failed, switching to QAT SW.\n");
#  else
            fprintf(stderr, "QAT HW initialization Failed.\n");
            qat_pthread_mutex_unlock();
            return 0;
#  endif
# endif
        }
    }
#endif

#ifdef QAT_SW
    if (qat_sw_offload) {
        if (!qat_sw_init(e)) {
# ifdef ENABLE_QAT_FIPS
            fprintf(stderr, "QAT_SW initialization Failed\n");
            return 0;
# else
            WARN("QAT SW initialization Failed, switching to OpenSSL.\n");
            fallback_to_openssl = 1;
# endif
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
    DEBUG("RSA Priv retries: %d, HW requests: %lld, SW requests: %lld\n",
          num_rsa_priv_retry, num_rsa_hw_priv_reqs, num_rsa_sw_priv_reqs);
    DEBUG("RSA Pub retries: %d, HW requests: %lld, SW requests: %lld\n",
          num_rsa_pub_retry, num_rsa_hw_pub_reqs, num_rsa_sw_pub_reqs);
    DEBUG("ECDH keygen retries: %d, HW requests: %lld, SW requests: %lld\n",
          num_ecdh_keygen_retry, num_ecdh_hw_keygen_reqs,
          num_ecdh_sw_keygen_reqs);
    DEBUG("ECDH derive retries: %d, HW requests: %lld, SW requests: %lld\n",
          num_ecdh_derive_retry, num_ecdh_hw_derive_reqs,
          num_ecdh_sw_derive_reqs);
    DEBUG("ECX keygen retries: %d, HW requests: %lld, SW requests: %lld\n",
          num_ecx_keygen_retry, num_ecx_hw_keygen_reqs, num_ecx_sw_keygen_reqs);
    DEBUG("ECX derive retries: %d, HW requests: %lld, SW requests: %lld\n",
          num_ecx_derive_retry, num_ecx_hw_derive_reqs, num_ecx_sw_derive_reqs);
    DEBUG("ECDSA sign retries: %d, HW requests: %lld, SW requests: %lld\n",
          num_ecdsa_sign_retry, num_ecdsa_hw_sign_reqs, num_ecdsa_sw_sign_reqs);
    DEBUG("SM4-CBC retries: %d, HW requests: %lld, SW requests: %lld\n",
          num_sm4_cbc_cipher_retry, num_sm4_cbc_hw_cipher_reqs,
          num_sm4_cbc_sw_cipher_reqs);

    qat_pthread_mutex_lock();

#ifdef QAT_HW
    if (qat_hw_offload)
        ret = qat_hw_finish_int(e, reset_globals);
#endif

#ifdef QAT_SW
    if (qat_sw_offload)
       ret = qat_sw_finish_int(e, reset_globals);
#endif
    engine_inited = 0;

    if (reset_globals == QAT_RESET_GLOBALS) {
        enable_external_polling = 0;
        enable_heuristic_polling = 0;
        qat_hw_offload = 0;
        qat_sw_offload = 0;
        fallback_to_openssl = 0;
        fallback_to_qat_sw = 0;
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
            *(int *)p = qat_sw_poll();
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

/* qatPerformOpRetries and qat_pkt_threshold_table_set_threshold undefined */
#ifndef QAT_BORINGSSL
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
#endif

        case QAT_CMD_SET_INTERNAL_POLL_INTERVAL:
        BREAK_IF(i < 1 || i > 1000000,
                "The polling interval value is out of range, using default value\n");
        DEBUG("Set internal poll interval = %ld ns\n", i);
        qat_poll_interval = (useconds_t) i;
        break;
#ifndef QAT_BORINGSSL
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
#endif /* QAT_BORINGSSL */
#endif

#ifndef QAT_BORINGSSL
        case QAT_CMD_SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD:
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
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
#endif /* QAT_BORINGSSL */

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
        BREAK_IF(val > 0xFFFFF,
                "The hardware enable mask is out of the range.\n");
        DEBUG("QAT_CMD_HW_ALGO_BITMAP = 0x%lx\n", val);
        qat_hw_algo_enable_mask = val;
        qat_reload_algo = 1;
        BREAK_IF(!bind_qat(e, engine_qat_id), "QAT Engine bind failed\n");
        qat_reload_algo = 0;
        break;
#endif

#if defined(QAT_SW) || defined(QAT_SW_IPSEC)
        case QAT_CMD_SW_ALGO_BITMAP:
        BREAK_IF(NULL == p, "The CMD SW_ALGO_BITMAP needs a string input.\n");
        val = strtoul(p, &temp, 0);
        BREAK_IF(errno == ERANGE || temp == p || *temp != '\0',
                "The software enable mask is invalid.\n");
        BREAK_IF(val > 0xFFFFF,
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
int bind_qat(ENGINE *e, const char *id)
{
   int ret = 0;
#ifdef QAT_HW
    char *config_section = NULL;
# if defined(QAT20_OOT) || defined(__FreeBSD__)
    Cpa32U dev_count = 0;
# endif
#endif
    QAT_DEBUG_LOG_INIT();

    WARN("QAT Warnings enabled.\n");
    DEBUG("QAT Debug enabled.\n");
    WARN("%s - %s \n", id, engine_qat_name);

    /* Ensure the QAT error handling is set up */
    ERR_load_QAT_strings();

    /* For QAT_HW, Check if the QAT_HW device is available */
#ifdef QAT_HW
# if !defined(QAT_HW_INTREE) && (defined(QAT20_OOT) || defined(__FreeBSD__))
    if (icp_adf_get_numDevices(&dev_count) == CPA_STATUS_SUCCESS) {
        if (dev_count > 0) {
            qat_hw_offload = 1;
            DEBUG("%d QAT HW device available\n", dev_count);
        }
    }
# else
    if (icp_sal_userIsQatAvailable() == CPA_TRUE) {
        qat_hw_offload = 1;
        DEBUG("QAT HW device available\n");
    }
#endif
    if (!qat_hw_offload) {
# ifndef QAT_SW
        fprintf(stderr, "QAT_HW device not available & QAT_SW not enabled. Using OpenSSL_SW!\n");
# endif
    }
#endif

#if defined(QAT_SW) || defined(QAT_SW_IPSEC)
    /* For QAT_SW, check if we are running only on Intel CPU &
     * has the instruction set needed */
    qat_sw_offload = qat_sw_cpu_support();
#endif

#ifdef ENABLE_QAT_SW_GCM
    if (qat_sw_offload && !vaesgcm_init_ipsec_mb_mgr()) {
        fprintf(stderr, "QAT_SW IPSec_mb manager iInitialization failed\n");
        return ret;
    }
#endif

#ifndef QAT_OPENSSL_PROVIDER
    if (id && (strcmp(id, engine_qat_id) != 0)) {
        WARN("ENGINE_id defined already! %s - %s\n", id, engine_qat_id);
        return ret;
    }

    if (!ENGINE_set_id(e, engine_qat_id)) {
        fprintf(stderr, "ENGINE_set_id failed\n");
        return ret;
    }

    if (!ENGINE_set_name(e, engine_qat_name)) {
        fprintf(stderr, "ENGINE_set_name failed\n");
        return ret;
    }

    if (qat_hw_offload) {
# ifdef ENABLE_QAT_HW_DSA
        if (!ENGINE_set_DSA(e, qat_get_DSA_methods())) {
            WARN("ENGINE_set_DSA QAT HW failed\n");
            return ret;
        }
# endif

# ifdef ENABLE_QAT_HW_DH
        if (!ENGINE_set_DH(e, qat_get_DH_methods())) {
            WARN("ENGINE_set_DH QAT HW failed\n");
            return ret;
        }
# endif
    }

# if defined(QAT_HW) || defined(QAT_SW)
    if (!ENGINE_set_RSA(e, qat_get_RSA_methods())) {
        WARN("ENGINE_set_RSA QAT HW failed\n");
        return ret;
    }

    if (!ENGINE_set_EC(e, qat_get_EC_methods())) {
        WARN("ENGINE_set_EC failed\n");
        return ret;
    }

     if (!ENGINE_set_pkey_meths(e, qat_pkey_methods)) {
          WARN("ENGINE_set_pkey_meths failed\n");
          return ret;
     }

#  ifndef QAT_BORINGSSL
    qat_create_digest_meth();
    if (!ENGINE_set_digests(e, qat_digest_methods)) {
        WARN("ENGINE_set_digests failed\n");
        return ret;
    }

    /* Create static structures for ciphers now
     * as this function will be called by a single thread. */
    qat_create_ciphers();

    if (!ENGINE_set_ciphers(e, qat_ciphers)) {
        WARN("ENGINE_set_ciphers failed\n");
        return ret;
    }
#  endif /* QAT_BORINGSSL */

    ret = 1;
    ret &= ENGINE_set_destroy_function(e, qat_engine_destroy);
    ret &= ENGINE_set_init_function(e, qat_engine_init);
    ret &= ENGINE_set_ctrl_function(e, qat_engine_ctrl);
    ret &= ENGINE_set_finish_function(e, qat_engine_finish);
    ret &= ENGINE_set_cmd_defns(e, qat_cmd_defns);
    if (ret == 0) {
        fprintf(stderr, "Engine failed to register init, finish or destroy functions\n");
        return ret;
    }
# endif
#endif /* QAT_OPENSSL_PROVIDER */

#ifdef QAT_OPENSSL_PROVIDER
   /* Set the corresponding algorithms offload for provider */
    if (qat_hw_offload) {
# ifdef ENABLE_QAT_HW_RSA
        qat_hw_rsa_offload = 1;
        INFO("QAT_HW RSA for Provider Enabled\n");
# endif
# ifdef ENABLE_QAT_HW_ECDSA
        qat_hw_ecdsa_offload = 1;
        INFO("QAT_HW ECDSA for Provider Enabled\n");
# endif
# ifdef ENABLE_QAT_HW_ECDH
        qat_hw_ecdh_offload = 1;
        INFO("QAT_HW ECDH for Provider Enabled\n");
# endif
# ifdef ENABLE_QAT_HW_DSA
        qat_hw_dsa_offload = 1;
        INFO("QAT_HW DSA for Provider Enabled\n");
# endif
# ifdef ENABLE_QAT_HW_DH
        qat_hw_dh_offload = 1;
        INFO("QAT_HW DH for Provider Enabled\n");
# endif
# ifdef ENABLE_QAT_HW_ECX
        qat_hw_ecx_offload = 1;
        INFO("QAT_HW ECX25519 for Provider Enabled\n");
# endif
# ifdef ENABLE_QAT_HW_ECX
        qat_hw_ecx_448_offload = 1;
        INFO("QAT_HW ECX448 for Provider Enabled\n");
# endif
# ifdef ENABLE_QAT_HW_PRF
        qat_hw_prf_offload = 1;
        INFO("QAT_HW PRF for Provider Enabled\n");
# endif
# ifdef ENABLE_QAT_HW_HKDF
        qat_hw_hkdf_offload = 1;
        INFO("QAT_HW HKDF for Provider Enabled\n");
# endif
# ifdef ENABLE_QAT_HW_SHA3
        qat_hw_sha_offload = 1;
        INFO("QAT_HW SHA3 for Provider Enabled\n");
# endif
# ifdef ENABLE_QAT_HW_GCM
        if (!qat_sw_gcm_offload) {
            qat_hw_gcm_offload = 1;
            DEBUG("QAT_HW GCM for Provider Enabled\n");
        }
# endif
    }

    if (qat_sw_offload) {
# ifdef ENABLE_QAT_SW_RSA
        if (!qat_hw_rsa_offload &&
            mbx_get_algo_info(MBX_ALGO_RSA_2K) &&
            mbx_get_algo_info(MBX_ALGO_RSA_3K) &&
            mbx_get_algo_info(MBX_ALGO_RSA_4K)) {
            qat_sw_rsa_offload = 1;
            INFO("QAT_SW RSA for Provider Enabled\n");
        }
# endif

# ifdef ENABLE_QAT_SW_ECDSA
        if (!qat_hw_ecdsa_offload &&
            mbx_get_algo_info(MBX_ALGO_ECDSA_NIST_P256) &&
            mbx_get_algo_info(MBX_ALGO_ECDSA_NIST_P384)) {
            qat_sw_ecdsa_offload = 1;
            INFO("QAT_SW ECDSA for Provider Enabled\n");
        }
# endif

# ifdef ENABLE_QAT_SW_ECDH
        if (!qat_hw_ecdh_offload &&
            mbx_get_algo_info(MBX_ALGO_ECDHE_NIST_P256) &&
            mbx_get_algo_info(MBX_ALGO_ECDHE_NIST_P384)) {
            qat_sw_ecdh_offload = 1;
            INFO("QAT_SW ECDH for Provider Enabled\n");
        }
# endif

# ifdef ENABLE_QAT_SW_ECX
        if (!qat_hw_ecx_offload &&
            mbx_get_algo_info(MBX_ALGO_X25519)) {
            qat_sw_ecx_offload = 1;
            INFO("QAT_SW X25519 for Provider Enabled\n");
        }
# endif

# ifdef ENABLE_QAT_SW_GCM
        qat_sw_gcm_offload = 1;
        DEBUG("QAT_SW GCM for Provider Enabled\n");
# endif
# if defined(ENABLE_QAT_FIPS) && defined (ENABLE_QAT_SW_SHA2)
        qat_sw_sha_offload = 1;
        INFO("QAT_SW SHA2 for Provider Enabled\n");

        if(!sha_init_ipsec_mb_mgr()) {
            WARN("SHA IPSec_Mb Manager Initialization failed\n");
            return 0;
        }
# endif
    }
    /* Create static structures for ciphers now
     * as this function will be called by a single thread. */
    qat_create_ciphers();
# ifndef QAT_DEBUG
    if (qat_sw_gcm_offload && !qat_hw_gcm_offload)
        INFO("QAT_SW GCM for Provider Enabled\n");

    if (qat_hw_gcm_offload && !qat_sw_gcm_offload)
        INFO("QAT_HW GCM for Provider Enabled\n");
# endif
#endif

#ifndef QAT_BORINGSSL
    pthread_atfork(engine_finish_before_fork_handler, NULL,
                   engine_init_child_at_fork_handler);
#else /* QAT_BORINGSSL */
    /* Set handler to ENGINE_unload_qat and ENGINE_load_qat */
    pthread_atfork(ENGINE_unload_qat, NULL, ENGINE_load_qat);
#endif /* QAT_BORINGSSL */

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
    ret = 1;
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

    /* For boringssl enabled, no API like ENGINE_add to add a new engine to
     * engine list, so just return existing global engine pointer
     */
    if (ENGINE_QAT_PTR_GET()) {
        return ENGINE_QAT_PTR_GET();
    }

    ret = ENGINE_new();
    /* qat_engine_ptr points the new engine */
    ENGINE_QAT_PTR_SET(ret);

    if (!ret) {
        fprintf(stderr, "Failed to create Engine\n");
        QATerr(QAT_F_ENGINE_QAT, QAT_R_QAT_CREATE_ENGINE_FAILURE);
        return NULL;
    }

    if (!bind_qat(ret, engine_qat_id)) {
        fprintf(stderr, "Qat Engine bind failed\n");
        ENGINE_free(ret);
        ENGINE_QAT_PTR_RESET();
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
    /* For boringssl enabled, no API like ENGINE_add to add a new engine to
     * engine list, so here ENGINE_add was redefined to do nothing. And also
     * not free the engine using ENGINE_free
     */
    ENGINE_add(toadd);
#ifndef QAT_BORINGSSL
    ENGINE_free(toadd);
#endif /* QAT_BORINGSSL */
    ERR_clear_error();
}

#ifdef QAT_BORINGSSL
void ENGINE_unload_qat(void)
{
    ENGINE *todel;
    DEBUG("- Stopping\n");

    todel = ENGINE_QAT_PTR_GET();
    if (todel != NULL) {
        qat_engine_destroy(todel);
        qat_engine_finish(todel);
        ENGINE_free(todel);
        ENGINE_QAT_PTR_RESET();
    }
}
#endif /* QAT_BORINGSSL */
#endif
