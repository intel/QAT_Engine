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
#include "e_qat.h"
#include "multibuff_polling.h"
#include "multibuff_rsa.h"
#include "multibuff_ecx.h"
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

int multibuff_init(ENGINE *e)
{
    int ret_pthread_sigmask;

    DEBUG("Multibuff initialization\n");
    DEBUG("- External polling: %s\n", enable_external_polling ? "ON": "OFF");
    DEBUG("- Heuristic polling: %s\n", enable_heuristic_polling ? "ON": "OFF");

    INITIALISE_RDTSC_CLOCKS();

    e_check = BN_new();
    if (NULL == e_check) {
        WARN("Failure to allocate e_check\n");
        QATerr(QAT_F_MULTIBUFF_INIT, QAT_R_ALLOC_E_CHECK_FAILURE);
        pthread_mutex_unlock(&qat_engine_mutex);
        qat_engine_finish(e);
        return 0;
    }
    BN_add_word(e_check, 65537);

    if ((mb_flist_rsa_priv_create(&rsa_priv_freelist,
                                  MULTIBUFF_MAX_INFLIGHTS) != 0) ||
        (mb_flist_rsa_pub_create(&rsa_pub_freelist,
                                 MULTIBUFF_MAX_INFLIGHTS) != 0) ||
        (mb_queue_rsa_priv_create(&rsa_priv_queue) != 0) ||
        (mb_queue_rsa_pub_create(&rsa_pub_queue) != 0) ||
        (mb_flist_x25519_keygen_create(&x25519_keygen_freelist,
                                       MULTIBUFF_MAX_INFLIGHTS) != 0) ||
        (mb_flist_x25519_derive_create(&x25519_derive_freelist,
                                       MULTIBUFF_MAX_INFLIGHTS) != 0) ||
        (mb_queue_x25519_keygen_create(&x25519_keygen_queue) != 0) ||
        (mb_queue_x25519_derive_create(&x25519_derive_queue) != 0)) {
        WARN("Failure to allocate req arrays\n");
        QATerr(QAT_F_MULTIBUFF_INIT,
                     QAT_R_CREATE_FREELIST_QUEUE_FAILURE);
        pthread_mutex_unlock(&qat_engine_mutex);
        qat_engine_finish(e);
        return 0;
    }

    multibuff_polling_thread = pthread_self();

    if (enable_external_polling == 0) {
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        ret_pthread_sigmask = pthread_sigmask(SIG_BLOCK, &set, NULL);
        if (ret_pthread_sigmask != 0) {
            WARN("pthread_sigmask error\n");
            QATerr(QAT_F_MULTIBUFF_INIT,
                         QAT_R_POLLING_THREAD_SIGMASK_FAILURE);
            pthread_mutex_unlock(&qat_engine_mutex);
            qat_engine_finish(e);
            return 0;
        }

        if (multibuff_create_thread(&multibuff_polling_thread,
                                    NULL, multibuff_timer_poll_func, NULL)) {
            WARN("Creation of polling thread failed\n");
            QATerr(QAT_F_MULTIBUFF_INIT,
                         QAT_R_POLLING_THREAD_CREATE_FAILURE);
            multibuff_polling_thread = pthread_self();
            pthread_mutex_unlock(&qat_engine_mutex);
            qat_engine_finish(e);
            return 0;
        }

        while (!cleared_to_start)
            sleep(1);
    }

    return 1;
}

int multibuff_finish_int(ENGINE *e, int reset_globals)
{
    int ret = 1;
    rsa_priv_op_data *rsa_priv_req = NULL;
    rsa_pub_op_data *rsa_pub_req = NULL;
    x25519_keygen_op_data *x25519_keygen_req = NULL;
    x25519_derive_op_data *x25519_derive_req = NULL;

    DEBUG("---- Multibuff Finishing...\n\n");

    multibuff_keep_polling = 0;

    if (enable_external_polling == 0) {
        if (pthread_equal(multibuff_polling_thread, pthread_self()) == 0) {
            if (multibuff_join_thread(multibuff_polling_thread, NULL) != 0) {
                WARN("Polling thread join failed with status: %d\n", ret);
                QATerr(QAT_F_MULTIBUFF_FINISH_INT, QAT_R_PTHREAD_JOIN_FAILURE);
                ret = 0;
            }
        }
    }

    multibuff_polling_thread = pthread_self();

    mb_queue_rsa_priv_disable(&rsa_priv_queue);
    mb_queue_rsa_pub_disable(&rsa_pub_queue);
    mb_queue_x25519_keygen_disable(&x25519_keygen_queue);
    mb_queue_x25519_derive_disable(&x25519_derive_queue);

    while ((rsa_priv_req =
           mb_queue_rsa_priv_dequeue(&rsa_priv_queue)) != NULL) {
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

    while ((x25519_keygen_req =
           mb_queue_x25519_keygen_dequeue(&x25519_keygen_queue)) != NULL) {
        *x25519_keygen_req->sts = -1;
        qat_wake_job(x25519_keygen_req->job, 0);
        OPENSSL_free(x25519_keygen_req);
    }
    mb_queue_x25519_keygen_cleanup(&x25519_keygen_queue);

    while ((x25519_derive_req =
           mb_queue_x25519_derive_dequeue(&x25519_derive_queue)) != NULL) {
        *x25519_derive_req->sts = -1;
        qat_wake_job(x25519_derive_req->job, 0);
        OPENSSL_free(x25519_derive_req);
    }
    mb_queue_x25519_derive_cleanup(&x25519_derive_queue);

    mb_flist_rsa_priv_cleanup(&rsa_priv_freelist);
    mb_flist_rsa_pub_cleanup(&rsa_pub_freelist);
    mb_flist_x25519_keygen_cleanup(&x25519_keygen_freelist);
    mb_flist_x25519_derive_cleanup(&x25519_derive_freelist);

    if (e_check != NULL) {
        BN_free(e_check);
        e_check = NULL;
    }

    PRINT_RDTSC_AVERAGES();

    return ret;
}
