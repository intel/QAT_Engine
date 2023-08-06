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
 * @file e_qat.h
 *
 * This file provides and interface for an OpenSSL QAT engine implementation
 *
 *****************************************************************************/

#ifndef E_QAT_H
# define E_QAT_H

# include <openssl/engine.h>
# include <sys/types.h>
# include <unistd.h>
# include <string.h>
# include <semaphore.h>
# include <sched.h>

#ifndef QAT_BORINGSSL
# include <openssl/async.h>
#endif

#ifdef QAT_BORINGSSL
# include "qat_bssl.h"
#endif /* QAT_BORINGSSL */

# ifdef QAT_OPENSSL_3
#  include "qat_prov_err.h"
# elif defined(QAT_BORINGSSL)
#  include "qat_bssl_err.h"
# else
#  include "e_qat_err.h"
# endif

# ifdef QAT_HW
#  include "cpa.h"
#  include "cpa_types.h"
#  include "cpa_cy_common.h"
# endif

# ifdef QAT_SW
#  include "qat_sw_queue.h"
#  include "qat_sw_freelist.h"
# endif

# ifndef ERR_R_RETRY
#  define ERR_R_RETRY 57
# endif

# define likely(x)   __builtin_expect (!!(x), 1)
# define unlikely(x) __builtin_expect (!!(x), 0)

# define XSTR(x) #x
# define STR(x) XSTR(x)

/* Macro used to handle errors in qat_engine_ctrl() */
# define BREAK_IF(cond, mesg) \
    if (unlikely(cond)) { retVal = 0; WARN(mesg); break; }

/*
 * Max Length (bytes) of error string in human readable format
 */
# define QAT_MAX_ERROR_STRING 256

/*
 * Different values passed in as param 3 for the message
 * QAT_CMD_GET_NUM_REQUESTS_IN_FLIGHT to retrieve the number of different kinds
 * of in-flight requests and number of items in queue for Multi-buffer
 */
# define GET_NUM_ASYM_REQUESTS_IN_FLIGHT 1
# define GET_NUM_KDF_REQUESTS_IN_FLIGHT 2
# define GET_NUM_CIPHER_PIPELINE_REQUESTS_IN_FLIGHT 3
# define GET_NUM_ASYM_MB_ITEMS_IN_QUEUE 4
# define GET_NUM_KDF_MB_ITEMS_IN_QUEUE 5
# define GET_NUM_SYM_MB_ITEMS_IN_QUEUE 6

/* Behavior of qat_engine_finish_int */
# define QAT_RETAIN_GLOBALS 0
# define QAT_RESET_GLOBALS 1

# define QAT_ATOMIC_INC(qat_int)              \
            (__sync_add_and_fetch(&(qat_int), 1))

# define QAT_ATOMIC_DEC(qat_int)              \
            (__sync_sub_and_fetch(&(qat_int), 1))

# ifdef QAT_HW
typedef struct {
    int qatAsymInstanceNumForThread;
    int qatSymInstanceNumForThread;
    unsigned int localOpsInFlight;
# ifdef QAT_HW_SET_INSTANCE_THREAD
    long int threadId;
# endif
} thread_local_variables_t;

typedef struct {
    CpaInstanceInfo2  qat_instance_info;
    unsigned int qat_instance_started;
} qat_instance_details_t;

typedef struct {
    unsigned int qat_accel_present;
    unsigned int qat_accel_reset_status;
} qat_accel_details_t;

# define INSTANCE_TYPE_CRYPTO 1
# define INSTANCE_TYPE_CRYPTO_ASYM 8
# define INSTANCE_TYPE_CRYPTO_SYM 16

# define QAT_RETRY_BACKOFF_MODULO_DIVISOR 8
# define QAT_INFINITE_MAX_NUM_RETRIES -1
# define QAT_INVALID_INSTANCE -1

# define QAT_INC_IN_FLIGHT_REQS(qat_int, tlv) \
            do {                              \
                if (qat_use_signals()) {      \
                    QAT_ATOMIC_INC(qat_int);  \
                    tlv->localOpsInFlight++;  \
                }                             \
            } while(0)

# define QAT_DEC_IN_FLIGHT_REQS(qat_int, tlv)  \
            do {                               \
                if (qat_use_signals()) {       \
                    tlv->localOpsInFlight--;   \
                    QAT_ATOMIC_DEC(qat_int);   \
                }                              \
            } while(0)

# define QAT_QMEMFREE_BUFF(b)                 \
            do {                              \
                if (b != NULL) {              \
                    qaeCryptoMemFree(b);      \
                    b = NULL;                 \
                }                             \
            } while(0)

# define QAT_CLEANSE_FREE_BUFF(b,len)        \
            do {                             \
                if (b != NULL) {             \
                    OPENSSL_cleanse(b, len); \
                    OPENSSL_free(b);         \
                    b = NULL;                \
                }                            \
            } while(0)

# define QAT_CLEANSE_QMEMFREE_BUFF(b,len)    \
            do {                             \
                if (b != NULL) {             \
                    OPENSSL_cleanse(b, len); \
                    qaeCryptoMemFree(b);     \
                    b = NULL;                \
                }                            \
            } while(0)

# define QAT_CLEANSE_FLATBUFF(b) \
            OPENSSL_cleanse((b).pData, (b).dataLenInBytes)

# define QAT_QMEM_FREE_FLATBUFF(b) \
            qaeCryptoMemFree((b).pData)

# define QAT_QMEM_FREE_NONZERO_FLATBUFF(b) \
            qaeCryptoMemFreeNonZero((b).pData)

# define QAT_CLEANSE_QMEMFREE_FLATBUFF(b)  \
            do {                           \
                QAT_CLEANSE_FLATBUFF(b);   \
                QAT_QMEM_FREE_FLATBUFF(b); \
            } while(0)

# define QAT_CLEANSE_QMEMFREE_NONZERO_FLATBUFF(b)  \
            do {                                   \
                QAT_CLEANSE_FLATBUFF(b);           \
                QAT_QMEM_FREE_NONZERO_FLATBUFF(b); \
            } while(0)

# define QAT_CHK_CLNSE_QMFREE_NONZERO_FLATBUFF(b)             \
            do {                                              \
                if ((b).pData != NULL)                        \
                    QAT_CLEANSE_QMEMFREE_NONZERO_FLATBUFF(b); \
            } while(0)

# define QAT_CHK_CLNSE_QMFREE_FLATBUFF(b)             \
            do {                                      \
                if ((b).pData != NULL)                \
                    QAT_CLEANSE_QMEMFREE_FLATBUFF(b); \
            } while(0)

# define QAT_CHK_QMFREE_FLATBUFF(b)            \
            do {                               \
                if ((b).pData != NULL)         \
                    QAT_QMEM_FREE_FLATBUFF(b); \
            } while(0)

# define QAT_CHK_QMFREE_NONZERO_FLATBUFF(b)            \
            do {                                       \
                if ((b).pData != NULL)                 \
                    QAT_QMEM_FREE_NONZERO_FLATBUFF(b); \
            } while(0)

# define FLATBUFF_ALLOC_AND_CHAIN(b1, b2, len) \
            do { \
                (b1).pData = qaeCryptoMemAlloc(len, __FILE__, __LINE__); \
                (b2).pData = (b1).pData; \
                (b1).dataLenInBytes = len; \
                (b2).dataLenInBytes = len; \
            } while(0)

# define QAT_CONFIG_SECTION_NAME_SIZE 64
# define QAT_MAX_CRYPTO_INSTANCES 256
# define QAT_MAX_CRYPTO_ACCELERATORS 512

# ifdef QAT_HW_SET_INSTANCE_THREAD
# define QAT_MAX_CRYPTO_THREADS 256
# endif
/*
 * The default interval in nanoseconds used for the internal polling thread
 */
# define QAT_POLL_PERIOD_IN_NS 10000

/*
 * The number of retries of the nanosleep if it gets interrupted during
 * waiting between polling.
 */
# define QAT_CRYPTO_NUM_POLLING_RETRIES 5

/*
 * The number of retries of the sigtimedwait if it gets interrupted during
 * waiting for a signal.
 */
# define QAT_CRYPTO_NUM_EVENT_RETRIES 2

/*
 * The number of seconds to wait for a response back after submitting a
 * request before raising an error.
 */
# define QAT_CRYPTO_RESPONSE_TIMEOUT 5

/*
 * The default timeout in milliseconds used for epoll_wait when event driven
 * polling mode is enabled.
 */
# define QAT_EPOLL_TIMEOUT_IN_MS 1000

/*
 * The default timeout in seconds used when waiting for events that requests
 * are in-flight.
 */
# define QAT_EVENT_TIMEOUT_IN_SEC 1
#endif

#ifdef QAT_SW
/*
 * Used to size the freelist and queue as it represents how many
 * requests can be in-flight at once.
 */
# ifndef MULTIBUFF_MAX_INFLIGHTS
#  define MULTIBUFF_MAX_INFLIGHTS 128
# endif

/*
 * The maximum amount of iterations we will continue to submit
 * batches of requests for. This is to prevent getting stuck in
 * a continuous loop in the situation where requests are getting
 * submitted faster than they are getting processed.
 */
# define MULTIBUFF_MAX_SUBMISSIONS 4

/*
 * Additional define just for the prototype to force batching
 * of requests less than MULTIBUFF_BATCH.
 */
# ifndef MULTIBUFF_MIN_BATCH
#  define MULTIBUFF_MIN_BATCH 8
# endif

/*
 * Number of multi-buffer requests to wait until are queued before
 * attempting to process them.
 */
# ifndef MULTIBUFF_MAX_BATCH
#  define MULTIBUFF_MAX_BATCH 8
# endif

/*
 * Number of multi-buffer requests to submit to the crypto_mb library
 * for processing in one go.
 */
# define MULTIBUFF_BATCH 8

/*
 * SM3 can handle processing up to 16 requests while others can handle
 * up to 8 requests only */
# ifndef MULTIBUFF_SM3_BATCH
#  define MULTIBUFF_SM3_BATCH 16
# endif

# ifndef MULTIBUFF_SM3_MIN_BATCH
#  define MULTIBUFF_SM3_MIN_BATCH 16
# endif

# ifndef MULTIBUFF_SM3_MAX_BATCH
#  define MULTIBUFF_SM3_MAX_BATCH 16
# endif

/*
 * SM4 can handle processing up to 16 requests while others can handle
 * up to 8 requests only
 */
# ifndef MULTIBUFF_SM4_BATCH
#  define MULTIBUFF_SM4_BATCH 16
# endif

# ifndef MULTIBUFF_SM4_MIN_BATCH
#  define MULTIBUFF_SM4_MIN_BATCH 16
# endif

# ifndef MULTIBUFF_SM4_MAX_BATCH
#  define MULTIBUFF_SM4_MAX_BATCH 16
# endif

/*
 * Max number of multi-buffer Polling threads
 */
# define NUM_POLL_THREADS 128

/* Macro that does queue cleanup based on the algorithm
 * request in (x) */
# define QAT_SW_CLEANUP(x, opdata, ptr)             \
    opdata *req_##x = NULL;                         \
    mb_queue_##x##_disable(ptr);                    \
    if (ptr) {                                      \
        while ((req_##x =                           \
            mb_queue_##x##_dequeue(ptr)) != NULL) { \
            *req_##x->sts = -1;                     \
            qat_wake_job(req_##x->job, 0);          \
            OPENSSL_free(req_##x);                  \
        }                                           \
        mb_queue_##x##_cleanup(ptr);                \
    }
#endif

/* Qat engine id declaration */
extern const char *engine_qat_id;
extern const char *engine_qat_name;
extern unsigned int engine_inited;
extern int fallback_to_openssl;
extern int fallback_to_qat_sw; /* QAT HW initialization fail, offload to QAT SW. */
extern int qat_hw_offload;
extern int qat_sw_offload;
extern int qat_hw_rsa_offload;
extern int qat_hw_ecx_offload;
extern int qat_hw_ecdh_offload;
extern int qat_hw_ecdsa_offload;
extern int qat_hw_prf_offload;
extern int qat_hw_hkdf_offload;
extern int qat_hw_gcm_offload;
extern int qat_hw_chacha_poly_offload;
extern int qat_hw_aes_cbc_hmac_sha_offload;
extern int qat_hw_sm4_cbc_offload;
extern int qat_sw_rsa_offload;
extern int qat_sw_ecx_offload;
extern int qat_sw_ecdh_offload;
extern int qat_sw_ecdsa_offload;
extern int qat_sw_gcm_offload;
extern int qat_sw_sm2_offload;
extern int qat_hw_sm2_offload;
extern int qat_hw_sha_offload;
extern int qat_hw_sm3_offload;
# ifdef ENABLE_QAT_FIPS
extern int qat_sw_sha_offload;
# endif
# ifdef QAT_OPENSSL_PROVIDER
extern int qat_hw_dsa_offload;
extern int qat_hw_dh_offload;
extern int qat_hw_ecx_448_offload;
# endif
extern int qat_sw_sm3_offload;
extern int qat_sw_sm4_cbc_offload;
extern int qat_sw_sm4_gcm_offload;
extern int qat_sw_sm4_ccm_offload;
extern int qat_hw_keep_polling;
extern int qat_sw_keep_polling;
extern int enable_external_polling;
extern int enable_heuristic_polling;
extern pthread_mutex_t qat_engine_mutex;
extern pthread_t qat_polling_thread;
extern sem_t hw_polling_thread_sem;

extern int num_requests_in_flight;
extern int num_asym_requests_in_flight;
extern int num_kdf_requests_in_flight;
extern int num_cipher_pipeline_requests_in_flight;
extern int num_asym_mb_items_in_queue;
extern int num_kdf_mb_items_in_queue;
extern int num_cipher_mb_items_in_queue;

extern sigset_t set;
extern pthread_t qat_timer_poll_func_thread;
extern int cleared_to_start;
extern pthread_mutex_t qat_poll_mutex;
extern pthread_cond_t qat_poll_condition;
extern int qat_cond_wait_started;
#ifdef ENABLE_QAT_FIPS
extern int integrity_status;
extern int qat_fips_service_indicator;
#endif

#define ALGO_ENABLE_MASK_RSA                0x00001
#define ALGO_ENABLE_MASK_DSA                0x00002
#define ALGO_ENABLE_MASK_DH                 0x00004
#define ALGO_ENABLE_MASK_ECDSA              0x00008
#define ALGO_ENABLE_MASK_ECDH               0x00010
#define ALGO_ENABLE_MASK_ECX25519           0x00020
#define ALGO_ENABLE_MASK_ECX448             0x00040
#define ALGO_ENABLE_MASK_PRF                0x00080
#define ALGO_ENABLE_MASK_HKDF               0x00100
#define ALGO_ENABLE_MASK_SM2                0x00200
#define ALGO_ENABLE_MASK_AES_GCM            0x00400
#define ALGO_ENABLE_MASK_AES_CBC_HMAC_SHA   0x00800
#define ALGO_ENABLE_MASK_SM4_CBC            0x01000
#define ALGO_ENABLE_MASK_CHACHA_POLY        0x02000
#define ALGO_ENABLE_MASK_SHA3               0x04000
#define ALGO_ENABLE_MASK_SM3                0x08000
#define ALGO_ENABLE_MASK_SM4_GCM            0x10000
#define ALGO_ENABLE_MASK_SM4_CCM            0x20000

extern int qat_reload_algo;
extern uint64_t qat_hw_algo_enable_mask;
extern uint64_t qat_sw_algo_enable_mask;

extern int qat_rsa_coexist;
extern int qat_ecdh_coexist;
extern int qat_ecdsa_coexist;
extern int qat_ecx_coexist;
extern int qat_sm4_cbc_coexist;
extern __thread unsigned int qat_sw_rsa_priv_req;
extern __thread unsigned int qat_sw_rsa_pub_req;
extern __thread unsigned int qat_sw_ecdsa_sign_req;
extern __thread unsigned int qat_sw_ecdh_keygen_req;
extern __thread unsigned int qat_sw_ecdh_derive_req;
extern __thread unsigned int qat_sw_ecx_keygen_req;
extern __thread unsigned int qat_sw_ecx_derive_req;
extern __thread unsigned int qat_sw_sm4_cbc_cipher_req;
extern __thread int num_rsa_priv_retry;
extern __thread int num_rsa_pub_retry;
extern __thread int num_ecdsa_sign_retry;
extern __thread int num_ecdh_keygen_retry;
extern __thread int num_ecdh_derive_retry;
extern __thread int num_ecx_keygen_retry;
extern __thread int num_ecx_derive_retry;
extern __thread int num_sm4_cbc_cipher_retry;
extern __thread unsigned long long num_rsa_hw_priv_reqs;
extern __thread unsigned long long num_rsa_sw_priv_reqs;
extern __thread unsigned long long num_rsa_hw_pub_reqs;
extern __thread unsigned long long num_rsa_sw_pub_reqs;
extern __thread unsigned long long num_ecdsa_hw_sign_reqs;
extern __thread unsigned long long num_ecdsa_sw_sign_reqs;
extern __thread unsigned long long num_ecdh_hw_keygen_reqs;
extern __thread unsigned long long num_ecdh_sw_keygen_reqs;
extern __thread unsigned long long num_ecdh_hw_derive_reqs;
extern __thread unsigned long long num_ecdh_sw_derive_reqs;
extern __thread unsigned long long num_ecx_hw_keygen_reqs;
extern __thread unsigned long long num_ecx_sw_keygen_reqs;
extern __thread unsigned long long num_ecx_hw_derive_reqs;
extern __thread unsigned long long num_ecx_sw_derive_reqs;
extern __thread unsigned long long num_sm4_cbc_hw_cipher_reqs;
extern __thread unsigned long long num_sm4_cbc_sw_cipher_reqs;
#define QAT_SW_SWITCH_MB8 8
#define QAT_SW_SWITCH_MB16 16

# ifdef QAT_HW
extern char qat_config_section_name[QAT_CONFIG_SECTION_NAME_SIZE];
extern char *ICPConfigSectionName_libcrypto;
extern int enable_inline_polling;
extern int enable_event_driven_polling;
extern int enable_instance_for_thread;
extern int qatPerformOpRetries;
extern int disable_qat_offload;
extern int enable_sw_fallback;
extern CpaInstanceHandle *qat_instance_handles;
extern Cpa16U qat_num_instances;
extern Cpa16U qat_asym_num_instance;
extern Cpa16U qat_sym_num_instance;
extern Cpa32U qat_num_devices;
extern pthread_key_t thread_local_variables;
extern pthread_mutex_t qat_instance_mutex;
extern qat_instance_details_t qat_instance_details[QAT_MAX_CRYPTO_INSTANCES];
extern qat_accel_details_t qat_accel_details[QAT_MAX_CRYPTO_ACCELERATORS];
extern useconds_t qat_poll_interval;
extern int qat_epoll_timeout;
extern int qat_max_retry_count;
extern unsigned int qat_map_sym_inst[QAT_MAX_CRYPTO_INSTANCES];
extern unsigned int qat_map_asym_inst[QAT_MAX_CRYPTO_INSTANCES];
# ifdef QAT_HW_SET_INSTANCE_THREAD
extern long int threadId[QAT_MAX_CRYPTO_THREADS];
extern int threadCount;
# endif
# endif

# ifdef QAT_SW
/* RSA */
extern BIGNUM *e_check;
extern mb_thread_data *mb_tlv;
extern pthread_key_t mb_thread_key;

typedef struct _mb_req_rates {
    int req_this_period;
    struct timespec previous_time;
    struct timespec current_time;
} mb_req_rates;

extern mb_req_rates mb_rsa2k_priv_req_rates;
extern mb_req_rates mb_rsa2k_pub_req_rates;
extern mb_req_rates mb_rsa3k_priv_req_rates;
extern mb_req_rates mb_rsa3k_pub_req_rates;
extern mb_req_rates mb_rsa4k_priv_req_rates;
extern mb_req_rates mb_rsa4k_pub_req_rates;
extern mb_req_rates mb_x25519_keygen_req_rates;
extern mb_req_rates mb_x25519_derive_req_rates;
extern mb_req_rates mb_ecdsap256_sign_req_rates;
extern mb_req_rates mb_ecdsap256_sign_setup_req_rates;
extern mb_req_rates mb_ecdsap256_sign_sig_req_rates;
extern mb_req_rates mb_ecdsap256_verify_req_rates;
extern mb_req_rates mb_ecdsap384_sign_req_rates;
extern mb_req_rates mb_ecdsap384_sign_setup_req_rates;
extern mb_req_rates mb_ecdsap384_sign_sig_req_rates;
extern mb_req_rates mb_ecdsap384_verify_req_rates;
extern mb_req_rates mb_ecdhp256_keygen_req_rates;
extern mb_req_rates mb_ecdhp256_compute_req_rates;
extern mb_req_rates mb_ecdhp384_keygen_req_rates;
extern mb_req_rates mb_ecdhp384_compute_req_rates;
extern mb_req_rates mb_sm2ecdh_keygen_req_rates;
extern mb_req_rates mb_sm2ecdh_compute_req_rates;
extern mb_req_rates mb_sm3_init_req_rates;
extern mb_req_rates mb_sm3_update_req_rates;
extern mb_req_rates mb_sm3_final_req_rates;
# endif

# define QAT_CMD_ENABLE_EXTERNAL_POLLING ENGINE_CMD_BASE
# define QAT_CMD_POLL (ENGINE_CMD_BASE + 1)
# define QAT_CMD_SET_INSTANCE_FOR_THREAD (ENGINE_CMD_BASE + 2)
# define QAT_CMD_GET_NUM_OP_RETRIES (ENGINE_CMD_BASE + 3)
# define QAT_CMD_SET_MAX_RETRY_COUNT (ENGINE_CMD_BASE + 4)
# define QAT_CMD_SET_INTERNAL_POLL_INTERVAL (ENGINE_CMD_BASE + 5)
# define QAT_CMD_GET_EXTERNAL_POLLING_FD (ENGINE_CMD_BASE + 6)
# define QAT_CMD_ENABLE_EVENT_DRIVEN_POLLING_MODE (ENGINE_CMD_BASE + 7)
# define QAT_CMD_GET_NUM_CRYPTO_INSTANCES (ENGINE_CMD_BASE + 8)
# define QAT_CMD_DISABLE_EVENT_DRIVEN_POLLING_MODE (ENGINE_CMD_BASE + 9)
# define QAT_CMD_SET_EPOLL_TIMEOUT (ENGINE_CMD_BASE + 10)
# define QAT_CMD_SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD (ENGINE_CMD_BASE + 11)
# define QAT_CMD_ENABLE_INLINE_POLLING (ENGINE_CMD_BASE + 12)
# define QAT_CMD_ENABLE_HEURISTIC_POLLING (ENGINE_CMD_BASE + 13)
# define QAT_CMD_GET_NUM_REQUESTS_IN_FLIGHT (ENGINE_CMD_BASE + 14)
# define QAT_CMD_INIT_ENGINE (ENGINE_CMD_BASE + 15)
# define QAT_CMD_SET_CONFIGURATION_SECTION_NAME (ENGINE_CMD_BASE + 16)
# define QAT_CMD_ENABLE_SW_FALLBACK (ENGINE_CMD_BASE + 17)
# define QAT_CMD_HEARTBEAT_POLL (ENGINE_CMD_BASE + 18)
# define QAT_CMD_DISABLE_QAT_OFFLOAD (ENGINE_CMD_BASE + 19)
# define QAT_CMD_HW_ALGO_BITMAP (ENGINE_CMD_BASE + 20)
# define QAT_CMD_SW_ALGO_BITMAP (ENGINE_CMD_BASE + 21)

#ifndef QAT_BORINGSSL
#ifndef ENGINE_QAT_PTR_DEFINE
# define ENGINE_QAT_PTR_RESET()
# define ENGINE_QAT_PTR_SET(pt)
# define ENGINE_QAT_PTR_GET()       NULL
#endif
#endif /* QAT_BORINGSSL */

# ifdef QAT_HW
extern CpaStatus icp_adf_get_numDevices(Cpa32U *);
/******************************************************************************
 * function:
 *         qat_get_qat_offload_disabled(void)
 *
 * description:
 *   This function indicates whether offloading to the QuickAssist hardware
 *   has been disabled. If it has then we can still perform crypto oncore.
 *
 ******************************************************************************/
int qat_get_qat_offload_disabled(void);

/******************************************************************************
 * function:
 *         qat_use_signals(void)
 *
 * description:
 *   This function indicates whether pthread signals are being used for thread
 *   synchronisation.  If so, then a non-zero value is returned, else zero is
 *   returned.
 *
 ******************************************************************************/
int qat_use_signals(void);


/******************************************************************************
 * function:
 *         qat_get_sw_fallback_enabled(void)
 *
 * description:
 *   Return the flag which indicates if QAT engine is enabled to fall back to
 *   software calculation.
 *
 ******************************************************************************/
int qat_get_sw_fallback_enabled(void);

/******************************************************************************
 * function:
 *         int validate_configuration_section_name(const char *name)
 *
 * description:
 *   This function validates whether the section name has valid length and
 *   address. If so, then one is returned else zero is returned.
 *
 ******************************************************************************/

int validate_configuration_section_name(const char *name);

/******************************************************************************
 * function:
 *         is_instance_available(int inst_num)
 *
 * description:
 *   Return whether the instance number passed in is a currently available
 *   instance. Returns 1 if available, 0 otherwise.
 *
 ******************************************************************************/
int is_instance_available(int inst_num);


/******************************************************************************
 * function:
 *         is_any_device_available(void)
 *
 * description:
 *   Return whether any devices are currently available.
 *   Returns 1 if at least one device is detected and up, 0 otherwise.
 *
 ******************************************************************************/
int is_any_device_available(void);


/******************************************************************************
 * function:
 *         get_next_inst_num(int inst_type)
 *
 * description:
 *   Return the next instance number to use for an operation.
 *
 ******************************************************************************/
int get_next_inst_num(int inst_type);


/******************************************************************************
 * function:
 *         qat_check_create_local_variables(void)
 *
 * description:
 *   This function checks whether local variables exist in the current thread.
 *   If not, then it will attempt to create them. It returns NULL if the local
 *   variables could not be created, otherwise it returns a pointer to the
 *   local variables data structure.
 *
 ******************************************************************************/
thread_local_variables_t * qat_check_create_local_variables(void);

/*****************************************************************************
 *  * function:
 *         qat_hw_init(ENGINE *e)
 *
 * @param e [IN] - OpenSSL engine pointer
 *
 * description:
 *   qat_hw init function, associated with
 *   Crypto memory setup and cpaStartInstance setups.
 ******************************************************************************/
int qat_hw_init(ENGINE *e);
# endif

/*****************************************************************************
 *  * function:
 *        bind_qat(ENGINE *e, const char *id)
 *
 * @param e [IN]  - OpenSSL engine pointer
 * @param id [IN] - engine id pointer
 *
 * description:
 *   bind function for registering algorithms that are supported in qatngine
 *   and other qat_hw and qat_sw intializaton.
 *
 *****************************************************************************/
int bind_qat(ENGINE *e, const char *id);

/******************************************************************************
 * function:
 *         qat_engine_init(ENGINE *e)
 *
 * @param e [IN] - OpenSSL engine pointer
 *
 * description:
 *   Qat Engine initialization
 ******************************************************************************/
int qat_engine_init(ENGINE *e);

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

int qat_engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void));

/******************************************************************************
 * function:
 *         qat_hw_finish_int(ENGINE *e)
 *
 * @param e [IN] - OpenSSL engine pointer
 *
 * description:
 *   Qat finish function associated with qat crypto memory free
 ******************************************************************************/

int qat_hw_finish_int(ENGINE *e, int reset_globals);

/******************************************************************************
 * function:
 *         qat_engine_finish(ENGINE *e)
 *
 * @param e [IN] - OpenSSL engine pointer
 *
 * description:
 *   Qat engine finish function.
 ******************************************************************************/

int qat_engine_finish(ENGINE *e);


/******************************************************************************
 * function:
 *         qat_engine_finish_int(ENGINE *e, int reset_globals)
 *
 * @param e [IN] - OpenSSL engine pointer
 * @param reset_globals [IN] - Whether reset the global configuration variables
 *
 * description:
 *   Internal Qat engine finish function.
 *   The value of reset_globals should be either QAT_RESET_GLOBALS or
 *   QAT_RETAIN_GLOBALS
 ******************************************************************************/
int qat_engine_finish_int(ENGINE *e, int reset_globals);

/*****************************************************************************
 * function:
 *          int qat_pthread_mutex_lock(void)
 *
 *  description:
 *  Wrapper function to pthread_mutex with return values checked.
 *
 ******************************************************************************/
int qat_pthread_mutex_lock(void);

/*****************************************************************************
 * function:
 *          int qat_pthread_mutex_unlock(void)
 *
 *  description:
 *  Wrapper function to pthread_mutex with return values checked.
 *
 ******************************************************************************/
int qat_pthread_mutex_unlock(void);

# ifdef QAT_SW
/*****************************************************************************
 *  * function:
 *         qat_sw_init(ENGINE *e)
 *
 * @param e [IN] - OpenSSL engine pointer
 *
 * description:
 *   QAT_SW init function, associated with memory setup.
 ******************************************************************************/
int qat_sw_init(ENGINE *e);

/******************************************************************************
 * function:
 *         qat_sw_finish_int(ENGINE *e, int reset_globals)
 *
 * @param e [IN] - OpenSSL engine pointer
 * @param reset_globals [IN] - Whether reset the global configuration variables
 *
 * description:
 *   Internal QAT_SW finish function.
 *   The value of reset_globals should be either QAT_RESET_GLOBALS or
 *   QAT_RETAIN_GLOBALS
 ******************************************************************************/
int qat_sw_finish_int(ENGINE *e, int reset_globals);

/******************************************************************************
 * function:
 *         mb_check_thread_local(void)
 *
 * description:
 *   Check if the thread has thread local pointer created using the key
 *   if not thread local memory polling thread will be created and stored on the
 *   Heap.
 ******************************************************************************/
mb_thread_data *mb_check_thread_local(void);

# endif

/******************************************************************************
 * function:
 *     qat_sw_cpu_support(void)
 *
 * description:
 *   Checks if we are running on Intel CPU and has the instruction set needed
 *   for crypto_mb and ipsec_mb (QAT_SW) offload.
 ******************************************************************************/
# if defined(QAT_SW) || defined(QAT_SW_IPSEC)
int qat_sw_cpu_support(void);
# endif

# ifdef QAT_OPENSSL_PROVIDER
static __inline__ int CRYPTO_UP_REF(int *val, int *ret, ossl_unused void *lock)
{
    *ret = __atomic_fetch_add(val, 1, __ATOMIC_RELAXED) + 1;
    return 1;
}

static __inline__ int CRYPTO_DOWN_REF(int *val, int *ret,
		                      ossl_unused void *lock)
{
    *ret = __atomic_fetch_sub(val, 1, __ATOMIC_RELAXED) - 1;
    if (*ret == 0)
	__atomic_thread_fence(__ATOMIC_ACQUIRE);
    return 1;
}
# endif

#endif   /* E_QAT_H */
