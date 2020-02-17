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
 * @file multibuff_init.h
 *
 * This file provides an interface for Multibuff initialization.
 *
 *****************************************************************************/

#ifndef MULTIBUFF_INIT_H
# define MULTIBUFF_INIT_H

# include <openssl/engine.h>
# include <openssl/async.h>
# include <sys/types.h>
# include <unistd.h>
# include <string.h>
# include <time.h>
# include "multibuff_request.h"
# include "multibuff_freelist.h"
# include "multibuff_queue.h"

# ifndef ERR_R_RETRY
#  define ERR_R_RETRY 57
# endif

#define likely(x)   __builtin_expect (!!(x), 1)
#define unlikely(x) __builtin_expect (!!(x), 0)

#define XSTR(x) #x
#define STR(x) XSTR(x)

/* Macro used to handle errors in multibuff_engine_ctrl() */
#define BREAK_IF(cond, mesg) \
    if (unlikely(cond)) { retVal = 0; WARN(mesg); break; }


/* Behavior of multibuff_engine_finish_int */
#define QAT_RETAIN_GLOBALS 0
#define QAT_RESET_GLOBALS 1

/*
 * Max Length (bytes) of error string in human readable format
 */
#define MULTIBUFF_MAX_ERROR_STRING 256

/*
 * Used to size the freelist and queue as it represents how many
 * requests can be inflight at once.
 */
#define MULTIBUFF_MAX_INFLIGHTS 128

/*
 * The maximum amount of iterations we will continue to submit
 * batches of requests for. This is to prevent getting stuck in
 * a continuous loop in the situation where requests are getting
 * submitted faster than they are getting processed.
 */
#define MULTIBUFF_RSA_MAX_SUBMISSIONS 4

/*
 * Additional define just for the prototype to force batching
 * of requests less than MULTIBUFF_RSA_BATCH.
 */
#ifndef MULTIBUFF_RSA_MIN_BATCH
# define MULTIBUFF_RSA_MIN_BATCH 8
#endif

/*
 * Number of RSA Requests to wait until are queued before
 * attempting to process them.
 */
#ifndef MULTIBUFF_RSA_MAX_BATCH
# define MULTIBUFF_RSA_MAX_BATCH 8
#endif

/*
 * Number of RSA Requests to submit to the ifma rsa library
 * for processing in one go.
 */
#define MULTIBUFF_RSA_BATCH 8

#define MULTIBUFF_CMD_ENABLE_EXTERNAL_POLLING ENGINE_CMD_BASE
#define MULTIBUFF_CMD_POLL (ENGINE_CMD_BASE + 1)
#define MULTIBUFF_CMD_ENABLE_HEURISTIC_POLLING (ENGINE_CMD_BASE + 2)
#define MULTIBUFF_CMD_GET_NUM_REQUESTS_IN_FLIGHT (ENGINE_CMD_BASE + 3)

/*
 * Different values passed in as param 3 for the message
 * MULTIBUFF_CMD_GET_NUM_REQUESTS_IN_FLIGHT to retrieve the number of different kinds
 * of in-flight requests
 */
#define GET_NUM_ASYM_REQUESTS_IN_FLIGHT 1
#define GET_NUM_KDF_REQUESTS_IN_FLIGHT 2
#define GET_NUM_CIPHER_PIPELINE_REQUESTS_IN_FLIGHT 3
#define GET_NUM_ITEMS_RSA_PRIV_QUEUE 4
#define GET_NUM_ITEMS_RSA_PUB_QUEUE 5

/* Multibuff engine id declaration */
extern const char *engine_qat_id;
extern const char *engine_qat_name;
extern int enable_external_polling;
extern unsigned int engine_inited;
extern BIGNUM *e_check;

extern pthread_t timer_poll_func_thread;
extern int keep_polling;
extern sigset_t set;
extern volatile int cleared_to_start;

extern int *num_items_rsa_priv_queue;
extern int *num_items_rsa_pub_queue;

extern mb_flist_rsa_priv rsa_priv_freelist;
extern mb_flist_rsa_pub rsa_pub_freelist;
extern mb_queue_rsa_priv rsa_priv_queue;
extern mb_queue_rsa_pub rsa_pub_queue;

extern int mb_rsa_priv_req_this_period;
extern int mb_rsa_pub_req_this_period;

typedef struct _mb_req_rates {
    int req_this_period;
    unsigned int timeout_level;
    struct timespec timeout_time;
    struct timespec previous_time;
    struct timespec current_time;
} mb_req_rates;

extern mb_req_rates mb_rsa_priv_req_rates;
extern mb_req_rates mb_rsa_pub_req_rates;

/* Macro used to handle errors in multibuff_engine_ctrl() */
#define BREAK_IF(cond, mesg) \
    if (unlikely(cond)) { retVal = 0; WARN(mesg); break; }

/*****************************************************************************
 * function:
 *         multibuff_engine_init(ENGINE *e)
 *
 * @param e [IN] - OpenSSL engine pointer
 *
 * description:
 *   Multibuff engine init function, associated with memory setup.
 ******************************************************************************/
int multibuff_engine_init(ENGINE *e);

/******************************************************************************
 * function:
 *         multibuff_engine_finish(ENGINE *e)
 *
 * @param e [IN] - OpenSSL engine pointer
 *
 * description:
 *   Multibuff engine finish function with standard signature.
 *   This is a wrapper for multibuff_engine_finish_int that always resets all
 *   the global variables used to store the engine configuration.
 ******************************************************************************/
int multibuff_engine_finish(ENGINE *e);

/******************************************************************************
 * function:
 *         multibuff_engine_finish_int(ENGINE *e, int reset_globals)
 *
 * @param e [IN] - OpenSSL engine pointer
 * @param reset_globals [IN] - Whether reset the global configuration variables
 *
 * description:
 *   Internal RSA Multibuff engine finish function.
 *   The value of reset_globals should be either QAT_RESET_GLOBALS or
 *   QAT_RETAIN_GLOBALS
 ******************************************************************************/
int multibuff_engine_finish_int(ENGINE *e, int reset_globals);

/******************************************************************************
* function:
*         multibuff_engine_ctrl(ENGINE *e, int cmd, long i,
*                               void *p, void (*f)(void))
*
* @param e   [IN] - OpenSSL engine pointer
* @param cmd [IN] - Control Command
* @param i   [IN] - Unused
* @param p   [IN] - Parameters for the command
* @param f   [IN] - Callback function
*
* description:
*   Multibuff engine control functions.
******************************************************************************/

int multibuff_engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void));

#endif   /* MULTIBUFF_INIT_H */
