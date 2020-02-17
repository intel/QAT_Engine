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
 * @file multibuff_init.c
 *
 * This file provides an Multibuff initialization functions.
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifndef __USE_GNU
# define __USE_GNU
#endif

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
#include <signal.h>
#include <time.h>

/* Local Includes */
#include "multibuff_init.h"
#include "multibuff_polling.h"
#include "multibuff_rsa.h"
#include "multibuff_request.h"
#include "multibuff_freelist.h"
#include "multibuff_queue.h"
#include "qat_utils.h"
#include "qat_events.h"
#include "e_qat_err.h"

/* OpenSSL Includes */
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/crypto.h>

#define MULTIBUFF_NUM_EVENT_RETRIES 5
#define MULTIBUFF_NSEC_PER_SEC	1000000000L
#define MULTIBUFF_TIMEOUT_LEVEL_1 1
#define MULTIBUFF_TIMEOUT_LEVEL_2 2
#define MULTIBUFF_TIMEOUT_LEVEL_3 3
#define MULTIBUFF_TIMEOUT_LEVEL_4 4
#define MULTIBUFF_TIMEOUT_LEVEL_5 5
#define MULTIBUFF_TIMEOUT_LEVEL_6 6
#define MULTIBUFF_TIMEOUT_LEVEL_7 7
#define MULTIBUFF_TIMEOUT_LEVEL_MIN MULTIBUFF_TIMEOUT_LEVEL_1
#define MULTIBUFF_TIMEOUT_LEVEL_MAX MULTIBUFF_TIMEOUT_LEVEL_7
#define MULTIBUFF_NSEC_TIMEOUT_TIME_L1 200000000
#define MULTIBUFF_NSEC_TIMEOUT_TIME_L2 100000000
#define MULTIBUFF_NSEC_TIMEOUT_TIME_L3 50000000
#define MULTIBUFF_NSEC_TIMEOUT_TIME_L4 25000000
#define MULTIBUFF_NSEC_TIMEOUT_TIME_L5 16666667
#define MULTIBUFF_NSEC_TIMEOUT_TIME_L6 12500000
#define MULTIBUFF_NSEC_TIMEOUT_TIME_L7 10000000

pthread_t polling_thread;
int keep_polling = 1;
sigset_t set = {{0}};
pthread_t timer_poll_func_thread = 0;
volatile int cleared_to_start = 0;

mb_flist_rsa_priv rsa_priv_freelist;
mb_flist_rsa_pub rsa_pub_freelist;
mb_queue_rsa_priv rsa_priv_queue;
mb_queue_rsa_pub rsa_pub_queue;

int enable_external_polling = 0;
int enable_heuristic_polling = 0;
unsigned int engine_inited = 0;
int num_asym_requests_in_flight = 0;
int num_kdf_requests_in_flight = 0;
int num_cipher_pipeline_requests_in_flight = 0;
int *num_items_rsa_priv_queue = 0;
int *num_items_rsa_pub_queue = 0;
pthread_mutex_t multibuff_engine_mutex = PTHREAD_MUTEX_INITIALIZER;
BIGNUM *e_check = NULL;

int multibuff_engine_init(ENGINE *e)
{
    int ret_pthread_sigmask;

    pthread_mutex_lock(&multibuff_engine_mutex);
    if (engine_inited) {
        pthread_mutex_unlock(&multibuff_engine_mutex);
        return 1;
    }

    DEBUG("QAT Engine Multibuff initialization\n");
    DEBUG("- External polling: %s\n", enable_external_polling ? "ON": "OFF");
    DEBUG("- Heuristic polling: %s\n", enable_heuristic_polling ? "ON": "OFF");

    CRYPTO_INIT_QAT_LOG();

    INITIALISE_RDTSC_CLOCKS();

    e_check = BN_new();
    if (NULL == e_check) {
        WARN("Failure to allocate e_check\n");
        QATerr(QAT_F_MULTIBUFF_ENGINE_INIT,
                     QAT_R_ALLOC_E_CHECK_FAILURE);
        pthread_mutex_unlock(&multibuff_engine_mutex);
        multibuff_engine_finish(e);
        return 0;
    }
    BN_add_word(e_check, 65537);

    if ((mb_flist_rsa_priv_create(&rsa_priv_freelist, MULTIBUFF_MAX_INFLIGHTS) != 0) ||
        (mb_flist_rsa_pub_create(&rsa_pub_freelist, MULTIBUFF_MAX_INFLIGHTS) != 0) ||
        (mb_queue_rsa_priv_create(&rsa_priv_queue) != 0) ||
        (mb_queue_rsa_pub_create(&rsa_pub_queue) != 0)) {
        WARN("Failure to allocate req arrays\n");
        QATerr(QAT_F_MULTIBUFF_ENGINE_INIT,
                     QAT_R_CREATE_FREELIST_QUEUE_FAILURE);
        pthread_mutex_unlock(&multibuff_engine_mutex);
        multibuff_engine_finish(e);
        return 0;
    }
    if (enable_heuristic_polling == 1) {
        num_items_rsa_priv_queue = &rsa_priv_queue.num_items;
        num_items_rsa_pub_queue = &rsa_pub_queue.num_items;
    }

    polling_thread = pthread_self();

    if (enable_external_polling == 0) {
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        ret_pthread_sigmask = pthread_sigmask(SIG_BLOCK, &set, NULL);
        if (ret_pthread_sigmask != 0) {
            WARN("pthread_sigmask error\n");
            QATerr(QAT_F_MULTIBUFF_ENGINE_INIT,
                         QAT_R_POLLING_THREAD_SIGMASK_FAILURE);
            pthread_mutex_unlock(&multibuff_engine_mutex);
            multibuff_engine_finish(e);
            return 0;
        }

        if (multibuff_create_thread(&polling_thread, NULL, timer_poll_func, NULL)) {
            WARN("Creation of polling thread failed\n");
            QATerr(QAT_F_MULTIBUFF_ENGINE_INIT,
                         QAT_R_POLLING_THREAD_CREATE_FAILURE);
            polling_thread = pthread_self();
            pthread_mutex_unlock(&multibuff_engine_mutex);
            multibuff_engine_finish(e);
            return 0;
        }

        while (!cleared_to_start)
            sleep(1);
    }

    engine_inited = 1;
    pthread_mutex_unlock(&multibuff_engine_mutex);
    return 1;
}

int multibuff_engine_finish_int(ENGINE *e, int reset_globals)
{

    int ret = 1;
    rsa_priv_op_data *rsa_priv_req = NULL;
    rsa_pub_op_data *rsa_pub_req = NULL;

    DEBUG("---- RSA Multibuff Engine Finishing...\n\n");

    pthread_mutex_lock(&multibuff_engine_mutex);

    keep_polling = 0;

    if (enable_external_polling == 0) {
        if (pthread_equal(polling_thread, pthread_self()) == 0) {
            if (multibuff_join_thread(polling_thread, NULL) != 0) {
                WARN("Polling thread join failed with status: %d\n", ret);
                QATerr(QAT_F_MULTIBUFF_ENGINE_FINISH_INT,
                             QAT_R_PTHREAD_JOIN_FAILURE);
                ret = 0;
            }
        }
    }

    polling_thread = pthread_self();

    mb_queue_rsa_priv_disable(&rsa_priv_queue);
    mb_queue_rsa_pub_disable(&rsa_pub_queue);

    while ((rsa_priv_req = mb_queue_rsa_priv_dequeue(&rsa_priv_queue)) != NULL) {
        *rsa_priv_req->sts = -1;
        qat_wake_job(rsa_priv_req->job, 0);
        OPENSSL_free(rsa_priv_req);
    }
    mb_queue_rsa_priv_cleanup(&rsa_priv_queue);

    while ((rsa_pub_req = mb_queue_rsa_pub_dequeue(&rsa_pub_queue)) != NULL) {
        *rsa_pub_req->sts = -1;
        qat_wake_job(rsa_pub_req->job, 0);
        OPENSSL_free(rsa_pub_req);
    }
    mb_queue_rsa_pub_cleanup(&rsa_pub_queue);

    mb_flist_rsa_priv_cleanup(&rsa_priv_freelist);
    mb_flist_rsa_pub_cleanup(&rsa_pub_freelist);

    if (e_check != NULL) {
        BN_free(e_check);
        e_check = NULL;
    }

    if (reset_globals == QAT_RESET_GLOBALS) {
        enable_external_polling = 0;
        enable_heuristic_polling = 0;
    }

    engine_inited = 0;

    pthread_mutex_unlock(&multibuff_engine_mutex);

    PRINT_RDTSC_AVERAGES();

    CRYPTO_CLOSE_QAT_LOG();

    return ret;
}

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
*   RSA Multibuff engine control functions.
******************************************************************************/
int multibuff_engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    unsigned int retVal = 1;

    switch (cmd) {
        case MULTIBUFF_CMD_POLL:
            BREAK_IF(!engine_inited, "POLL failed as engine is not initialized\n");
            BREAK_IF(!enable_external_polling, "POLL failed as external polling is not enabled\n");
            BREAK_IF(p == NULL, "POLL failed as the input parameter was NULL\n");
            *(int *)p = multibuff_poll();
            break;

        case MULTIBUFF_CMD_ENABLE_EXTERNAL_POLLING:
            BREAK_IF(engine_inited, \
                    "ENABLE_EXTERNAL_POLLING failed as the engine is already initialized\n");
            DEBUG("Enabled external polling\n");
            enable_external_polling = 1;
            break;

        case MULTIBUFF_CMD_ENABLE_HEURISTIC_POLLING:
            BREAK_IF(engine_inited,
                    "ENABLE_HEURISTIC_POLLING failed as the engine is already initialized\n");
            BREAK_IF(!enable_external_polling,
                    "ENABLE_HEURISTIC_POLLING failed as external polling is not enabled\n");
            DEBUG("Enabled heuristic polling\n");
            enable_heuristic_polling = 1;
            break;

        case MULTIBUFF_CMD_GET_NUM_REQUESTS_IN_FLIGHT:
            DEBUG("GET_NUM_REQUESTS_IN_FLIGHT\n");
            BREAK_IF(p == NULL,
                    "GET_NUM_REQUESTS_IN_FLIGHT failed as the input parameter was NULL\n");
            if (i == GET_NUM_ASYM_REQUESTS_IN_FLIGHT) {
                *(int **)p = &num_asym_requests_in_flight;
            } else if (i == GET_NUM_KDF_REQUESTS_IN_FLIGHT) {
                *(int **)p = &num_kdf_requests_in_flight;
            } else if (i == GET_NUM_CIPHER_PIPELINE_REQUESTS_IN_FLIGHT) {
                *(int **)p = &num_cipher_pipeline_requests_in_flight;
            } else if (i == GET_NUM_ITEMS_RSA_PRIV_QUEUE) {
                *(int **)p = num_items_rsa_priv_queue;
            } else if (i == GET_NUM_ITEMS_RSA_PUB_QUEUE) {
                *(int **)p = num_items_rsa_pub_queue;
            } else {
                WARN("Invalid i parameter\n");
                retVal = 0;
            }
            break;

        default:
            WARN("CTRL command not implemented\n");
            retVal = 0;
            break;
    }
    if (!retVal) {
        QATerr(QAT_F_MULTIBUFF_ENGINE_CTRL, QAT_R_ENGINE_CTRL_CMD_FAILURE);
    }
    return retVal;
}

int multibuff_engine_finish(ENGINE *e) {
    return multibuff_engine_finish_int(e, QAT_RESET_GLOBALS);
}
