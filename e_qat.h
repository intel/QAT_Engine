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
 * @file e_qat.h
 *
 * This file provides and interface for an OpenSSL QAT engine implemenation
 *
 *****************************************************************************/

#ifndef E_QAT_H
# define E_QAT_H

# include <openssl/engine.h>
# include <sys/types.h>
# include <unistd.h>
# include <string.h>

# ifdef OPENSSL_QAT_OFFLOAD
#  include "cpa.h"
#  include "cpa_types.h"
# endif

# ifdef OPENSSL_MULTIBUFF_OFFLOAD
#  include "multibuff_queue.h"
#  include "multibuff_freelist.h"
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

# ifdef OPENSSL_QAT_OFFLOAD
typedef struct {
    int qatInstanceNumForThread;
    unsigned int localOpsInFlight;
} thread_local_variables_t;

typedef struct {
    CpaInstanceInfo2  qat_instance_info;
    unsigned int qat_instance_started;
} qat_instance_details_t;

typedef struct {
    unsigned int qat_accel_present;
    unsigned int qat_accel_reset_status;
} qat_accel_details_t;

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

# define QAT_QMEMFREE_BUFF(b)            \
            do {                         \
                if (b != NULL) {         \
                    qaeCryptoMemFree(b); \
                    b = NULL;            \
                }                        \
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

# define QAT_CONFIG_SECTION_NAME_SIZE 64
# define QAT_MAX_CRYPTO_INSTANCES 256
# define QAT_MAX_CRYPTO_ACCELERATORS 512

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
 * are inflight.
 */
# define QAT_EVENT_TIMEOUT_IN_SEC 1
#endif

#ifdef OPENSSL_MULTIBUFF_OFFLOAD
/*
 * Used to size the freelist and queue as it represents how many
 * requests can be inflight at once.
 */
# define MULTIBUFF_MAX_INFLIGHTS 128

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
#endif

/* Qat engine id declaration */
extern const char *engine_qat_id;
extern const char *engine_qat_name;
extern unsigned int engine_inited;

extern int qat_keep_polling;
extern int multibuff_keep_polling;
extern int enable_external_polling;
extern int enable_heuristic_polling;
extern pthread_mutex_t qat_engine_mutex;
extern pthread_t qat_polling_thread;
extern pthread_t multibuff_polling_thread;

extern int num_requests_in_flight;
extern int num_asym_requests_in_flight;
extern int num_kdf_requests_in_flight;
extern int num_cipher_pipeline_requests_in_flight;
extern int num_asym_mb_items_in_queue;
extern int num_kdf_mb_items_in_queue;
extern int num_cipher_mb_items_in_queue;

extern sigset_t set;
extern pthread_t qat_timer_poll_func_thread;
extern pthread_t multibuff_timer_poll_func_thread;
extern int cleared_to_start;

# ifdef OPENSSL_QAT_OFFLOAD
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
extern Cpa32U qat_num_devices;
extern pthread_key_t thread_local_variables;
extern pthread_mutex_t qat_instance_mutex;
extern qat_instance_details_t qat_instance_details[QAT_MAX_CRYPTO_INSTANCES];
extern qat_accel_details_t qat_accel_details[QAT_MAX_CRYPTO_ACCELERATORS];
extern useconds_t qat_poll_interval;
extern int qat_epoll_timeout;
extern int qat_max_retry_count;
# endif

# ifdef OPENSSL_MULTIBUFF_OFFLOAD
/* RSA */
extern BIGNUM *e_check;
extern mb_flist_rsa_priv rsa_priv_freelist;
extern mb_flist_rsa_pub rsa_pub_freelist;
extern mb_queue_rsa_priv rsa_priv_queue;
extern mb_queue_rsa_pub rsa_pub_queue;

/* X25519 */
extern mb_flist_x25519_keygen x25519_keygen_freelist;
extern mb_flist_x25519_derive x25519_derive_freelist;
extern mb_queue_x25519_keygen x25519_keygen_queue;
extern mb_queue_x25519_derive x25519_derive_queue;

typedef struct _mb_req_rates {
    int req_this_period;
    struct timespec previous_time;
    struct timespec current_time;
} mb_req_rates;

extern mb_req_rates mb_rsa_priv_req_rates;
extern mb_req_rates mb_rsa_pub_req_rates;
extern mb_req_rates mb_x25519_keygen_req_rates;
extern mb_req_rates mb_x25519_derive_req_rates;
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

# ifdef OPENSSL_QAT_OFFLOAD
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
 *         get_next_inst_num(void)
 *
 * description:
 *   Return the next instance number to use for an operation.
 *
 ******************************************************************************/
int get_next_inst_num(void);


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
 *         qat_init(ENGINE *e)
 *
 * @param e [IN] - OpenSSL engine pointer
 *
 * description:
 *   qat init function, associated with
 *   Crypto memory setup and cpaStartInstance setups.
 ******************************************************************************/
int qat_init(ENGINE *e);

# endif
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
 *         qat_finish_int(ENGINE *e)
 *
 * @param e [IN] - OpenSSL engine pointer
 *
 * description:
 *   Qat finish function associated with qat crypto memory free
 ******************************************************************************/

int qat_finish_int(ENGINE *e, int reset_globals);

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

#ifdef OPENSSL_MULTIBUFF_OFFLOAD
/*****************************************************************************
 *  * function:
 *         multibuff_init(ENGINE *e)
 *
 * @param e [IN] - OpenSSL engine pointer
 *
 * description:
 *   Multibuff init function, associated with memory setup.
 ******************************************************************************/
int multibuff_init(ENGINE *e);

/******************************************************************************
 * function:
 *         multibuff_engine_finish_int(ENGINE *e, int reset_globals)
 *
 * @param e [IN] - OpenSSL engine pointer
 * @param reset_globals [IN] - Whether reset the global configuration variables
 *
 * description:
 *   Internal Multibuff engine finish function.
 *   The value of reset_globals should be either QAT_RESET_GLOBALS or
 *   QAT_RETAIN_GLOBALS
 ******************************************************************************/
int multibuff_finish_int(ENGINE *e, int reset_globals);

#endif
#endif   /* E_QAT_H */
