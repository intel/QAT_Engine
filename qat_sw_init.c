/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020-2021 Intel Corporation.
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
 * @file qat_sw_init.c
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
#include "qat_sw_polling.h"
#include "qat_sw_rsa.h"
#include "qat_sw_ecx.h"
#include "qat_sw_ec.h"
#include "qat_sw_request.h"
#include "qat_sw_freelist.h"
#include "qat_sw_queue.h"
#include "qat_utils.h"
#include "qat_events.h"
#include "qat_fork.h"

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
        qat_pthread_mutex_unlock();
        qat_engine_finish(e);
        return 0;
    }
    BN_add_word(e_check, 65537);

    if ((mb_flist_rsa_priv_create(&rsa_priv_freelist,
                                  MULTIBUFF_MAX_INFLIGHTS) != 0) ||
        (mb_flist_rsa_pub_create(&rsa_pub_freelist,
                                 MULTIBUFF_MAX_INFLIGHTS) != 0) ||
        (mb_queue_rsa2k_priv_create(&rsa2k_priv_queue) != 0) ||
        (mb_queue_rsa2k_pub_create(&rsa2k_pub_queue) != 0) ||
        (mb_queue_rsa3k_priv_create(&rsa3k_priv_queue) != 0) ||
        (mb_queue_rsa3k_pub_create(&rsa3k_pub_queue) != 0) ||
        (mb_queue_rsa4k_priv_create(&rsa4k_priv_queue) != 0) ||
        (mb_queue_rsa4k_pub_create(&rsa4k_pub_queue) != 0) ||
        (mb_flist_x25519_keygen_create(&x25519_keygen_freelist,
                                       MULTIBUFF_MAX_INFLIGHTS) != 0) ||
        (mb_flist_x25519_derive_create(&x25519_derive_freelist,
                                       MULTIBUFF_MAX_INFLIGHTS) != 0) ||
        (mb_queue_x25519_keygen_create(&x25519_keygen_queue) != 0) ||
        (mb_queue_x25519_derive_create(&x25519_derive_queue) != 0) ||
        (mb_flist_ecdsa_sign_create(&ecdsa_sign_freelist,
                                        MULTIBUFF_MAX_INFLIGHTS) != 0) ||
        (mb_flist_ecdsa_sign_setup_create(&ecdsa_sign_setup_freelist,
                                              MULTIBUFF_MAX_INFLIGHTS) != 0) ||
        (mb_flist_ecdsa_sign_sig_create(&ecdsa_sign_sig_freelist,
                                            MULTIBUFF_MAX_INFLIGHTS) != 0) ||
        (mb_queue_ecdsap256_sign_create(&ecdsap256_sign_queue) != 0) ||
        (mb_queue_ecdsap256_sign_setup_create(&ecdsap256_sign_setup_queue) != 0) ||
        (mb_queue_ecdsap256_sign_sig_create(&ecdsap256_sign_sig_queue) != 0) ||
        (mb_queue_ecdsap384_sign_create(&ecdsap384_sign_queue) != 0) ||
        (mb_queue_ecdsap384_sign_setup_create(&ecdsap384_sign_setup_queue) != 0) ||
        (mb_queue_ecdsap384_sign_sig_create(&ecdsap384_sign_sig_queue) != 0) ||
        (mb_flist_ecdh_keygen_create(&ecdh_keygen_freelist,
                                         MULTIBUFF_MAX_INFLIGHTS) != 0) ||
        (mb_flist_ecdh_compute_create(&ecdh_compute_freelist,
                                          MULTIBUFF_MAX_INFLIGHTS) != 0) ||
        (mb_queue_ecdhp256_keygen_create(&ecdhp256_keygen_queue) != 0) ||
        (mb_queue_ecdhp256_compute_create(&ecdhp256_compute_queue) != 0) ||
        (mb_queue_ecdhp384_keygen_create(&ecdhp384_keygen_queue) != 0) ||
        (mb_queue_ecdhp384_compute_create(&ecdhp384_compute_queue) != 0)) {
        WARN("Failure to allocate req arrays\n");
        QATerr(QAT_F_MULTIBUFF_INIT, QAT_R_CREATE_FREELIST_QUEUE_FAILURE);
        qat_pthread_mutex_unlock();
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
            qat_pthread_mutex_unlock();
            qat_engine_finish(e);
            return 0;
        }

        if (qat_create_thread(&multibuff_polling_thread,
                              NULL, multibuff_timer_poll_func, NULL)) {
            WARN("Creation of polling thread failed\n");
            QATerr(QAT_F_MULTIBUFF_INIT,
                         QAT_R_POLLING_THREAD_CREATE_FAILURE);
            multibuff_polling_thread = pthread_self();
            qat_pthread_mutex_unlock();
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
    rsa_priv_op_data *rsa2k_priv_req = NULL;
    rsa_pub_op_data *rsa2k_pub_req = NULL;
    rsa_priv_op_data *rsa3k_priv_req = NULL;
    rsa_pub_op_data *rsa3k_pub_req = NULL;
    rsa_priv_op_data *rsa4k_priv_req = NULL;
    rsa_pub_op_data *rsa4k_pub_req = NULL;
    x25519_keygen_op_data *x25519_keygen_req = NULL;
    x25519_derive_op_data *x25519_derive_req = NULL;
    ecdsa_sign_op_data *ecdsap256_sign_req = NULL;
    ecdsa_sign_setup_op_data *ecdsap256_sign_setup_req = NULL;
    ecdsa_sign_sig_op_data *ecdsap256_sign_sig_req = NULL;
    ecdsa_sign_op_data *ecdsap384_sign_req = NULL;
    ecdsa_sign_setup_op_data *ecdsap384_sign_setup_req = NULL;
    ecdsa_sign_sig_op_data *ecdsap384_sign_sig_req = NULL;
    ecdh_keygen_op_data *ecdhp256_keygen_req = NULL;
    ecdh_compute_op_data *ecdhp256_compute_req = NULL;
    ecdh_keygen_op_data *ecdhp384_keygen_req = NULL;
    ecdh_compute_op_data *ecdhp384_compute_req = NULL;

    DEBUG("---- Multibuff Finishing...\n\n");

    multibuff_keep_polling = 0;

    if (enable_external_polling == 0) {
        if (pthread_equal(multibuff_polling_thread, pthread_self()) == 0) {
            if (qat_join_thread(multibuff_polling_thread, NULL) != 0) {
                WARN("Polling thread join failed with status: %d\n", ret);
                QATerr(QAT_F_MULTIBUFF_FINISH_INT, QAT_R_PTHREAD_JOIN_FAILURE);
                ret = 0;
            }
        }
    }

    multibuff_polling_thread = pthread_self();

    mb_queue_rsa2k_priv_disable(&rsa2k_priv_queue);
    mb_queue_rsa2k_pub_disable(&rsa2k_pub_queue);
    mb_queue_rsa3k_priv_disable(&rsa3k_priv_queue);
    mb_queue_rsa3k_pub_disable(&rsa3k_pub_queue);
    mb_queue_rsa4k_priv_disable(&rsa4k_priv_queue);
    mb_queue_rsa4k_pub_disable(&rsa4k_pub_queue);
    mb_queue_x25519_keygen_disable(&x25519_keygen_queue);
    mb_queue_x25519_derive_disable(&x25519_derive_queue);
    mb_queue_ecdsap256_sign_disable(&ecdsap256_sign_queue);
    mb_queue_ecdsap256_sign_setup_disable(&ecdsap256_sign_setup_queue);
    mb_queue_ecdsap256_sign_sig_disable(&ecdsap256_sign_sig_queue);
    mb_queue_ecdhp256_keygen_disable(&ecdhp256_keygen_queue);
    mb_queue_ecdhp256_compute_disable(&ecdhp256_compute_queue);

    while ((rsa2k_priv_req =
           mb_queue_rsa2k_priv_dequeue(&rsa2k_priv_queue)) != NULL) {
        *rsa2k_priv_req->sts = -1;
        qat_wake_job(rsa2k_priv_req->job, 0);
        OPENSSL_free(rsa2k_priv_req);
    }
    mb_queue_rsa2k_priv_cleanup(&rsa2k_priv_queue);

    while ((rsa2k_pub_req = mb_queue_rsa2k_pub_dequeue(&rsa2k_pub_queue)) != NULL) {
        *rsa2k_pub_req->sts = -1;
        qat_wake_job(rsa2k_pub_req->job, 0);
        OPENSSL_free(rsa2k_pub_req);
    }
    mb_queue_rsa2k_pub_cleanup(&rsa2k_pub_queue);

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

    while ((ecdsap256_sign_req =
           mb_queue_ecdsap256_sign_dequeue(&ecdsap256_sign_queue)) != NULL) {
        *ecdsap256_sign_req->sts = -1;
        qat_wake_job(ecdsap256_sign_req->job, 0);
        OPENSSL_free(ecdsap256_sign_req);
    }
    mb_queue_ecdsap256_sign_cleanup(&ecdsap256_sign_queue);

    while ((ecdsap256_sign_setup_req =
           mb_queue_ecdsap256_sign_setup_dequeue(&ecdsap256_sign_setup_queue)) != NULL) {
        *ecdsap256_sign_setup_req->sts = -1;
        qat_wake_job(ecdsap256_sign_setup_req->job, 0);
        OPENSSL_free(ecdsap256_sign_setup_req);
    }
    mb_queue_ecdsap256_sign_setup_cleanup(&ecdsap256_sign_setup_queue);

    while ((ecdsap256_sign_sig_req =
           mb_queue_ecdsap256_sign_sig_dequeue(&ecdsap256_sign_sig_queue)) != NULL) {
        *ecdsap256_sign_sig_req->sts = -1;
        qat_wake_job(ecdsap256_sign_sig_req->job, 0);
        OPENSSL_free(ecdsap256_sign_sig_req);
    }
    mb_queue_ecdsap256_sign_sig_cleanup(&ecdsap256_sign_sig_queue);

    while ((ecdsap384_sign_req =
           mb_queue_ecdsap384_sign_dequeue(&ecdsap384_sign_queue)) != NULL) {
        *ecdsap384_sign_req->sts = -1;
        qat_wake_job(ecdsap384_sign_req->job, 0);
        OPENSSL_free(ecdsap384_sign_req);
    }
    mb_queue_ecdsap384_sign_cleanup(&ecdsap384_sign_queue);

    while ((ecdsap384_sign_setup_req =
           mb_queue_ecdsap384_sign_setup_dequeue(&ecdsap384_sign_setup_queue)) != NULL) {
        *ecdsap384_sign_setup_req->sts = -1;
        qat_wake_job(ecdsap384_sign_setup_req->job, 0);
        OPENSSL_free(ecdsap384_sign_setup_req);
    }
    mb_queue_ecdsap384_sign_setup_cleanup(&ecdsap384_sign_setup_queue);

    while ((ecdsap384_sign_sig_req =
           mb_queue_ecdsap384_sign_sig_dequeue(&ecdsap384_sign_sig_queue)) != NULL) {
        *ecdsap384_sign_sig_req->sts = -1;
        qat_wake_job(ecdsap384_sign_sig_req->job, 0);
        OPENSSL_free(ecdsap384_sign_sig_req);
    }
    mb_queue_ecdsap384_sign_sig_cleanup(&ecdsap384_sign_sig_queue);

    while ((ecdhp256_keygen_req =
           mb_queue_ecdhp256_keygen_dequeue(&ecdhp256_keygen_queue)) != NULL) {
        *ecdhp256_keygen_req->sts = -1;
        qat_wake_job(ecdhp256_keygen_req->job, 0);
        OPENSSL_free(ecdhp256_keygen_req);
    }
    mb_queue_ecdhp256_keygen_cleanup(&ecdhp256_keygen_queue);

    while ((ecdhp256_compute_req =
           mb_queue_ecdhp256_compute_dequeue(&ecdhp256_compute_queue)) != NULL) {
        *ecdhp256_compute_req->sts = -1;
        qat_wake_job(ecdhp256_compute_req->job, 0);
        OPENSSL_free(ecdhp256_compute_req);
    }
    mb_queue_ecdhp256_compute_cleanup(&ecdhp256_compute_queue);

    while ((ecdhp384_keygen_req =
           mb_queue_ecdhp384_keygen_dequeue(&ecdhp384_keygen_queue)) != NULL) {
        *ecdhp384_keygen_req->sts = -1;
        qat_wake_job(ecdhp384_keygen_req->job, 0);
        OPENSSL_free(ecdhp384_keygen_req);
    }
    mb_queue_ecdhp384_keygen_cleanup(&ecdhp384_keygen_queue);

    while ((ecdhp384_compute_req =
           mb_queue_ecdhp384_compute_dequeue(&ecdhp384_compute_queue)) != NULL) {
        *ecdhp384_compute_req->sts = -1;
        qat_wake_job(ecdhp384_compute_req->job, 0);
        OPENSSL_free(ecdhp384_compute_req);
    }
    mb_queue_ecdhp384_compute_cleanup(&ecdhp384_compute_queue);

    while ((rsa3k_priv_req =
           mb_queue_rsa3k_priv_dequeue(&rsa3k_priv_queue)) != NULL) {
        *rsa3k_priv_req->sts = -1;
        qat_wake_job(rsa3k_priv_req->job, 0);
        OPENSSL_free(rsa3k_priv_req);
    }
    mb_queue_rsa3k_priv_cleanup(&rsa3k_priv_queue);

    while ((rsa3k_pub_req =
           mb_queue_rsa3k_pub_dequeue(&rsa3k_pub_queue)) != NULL) {
        *rsa3k_pub_req->sts = -1;
        qat_wake_job(rsa3k_pub_req->job, 0);
        OPENSSL_free(rsa3k_pub_req);
    }
    mb_queue_rsa3k_pub_cleanup(&rsa3k_pub_queue);

    while ((rsa4k_priv_req =
           mb_queue_rsa4k_priv_dequeue(&rsa4k_priv_queue)) != NULL) {
        *rsa4k_priv_req->sts = -1;
        qat_wake_job(rsa4k_priv_req->job, 0);
        OPENSSL_free(rsa4k_priv_req);
    }
    mb_queue_rsa4k_priv_cleanup(&rsa4k_priv_queue);

    while ((rsa4k_pub_req =
           mb_queue_rsa4k_pub_dequeue(&rsa4k_pub_queue)) != NULL) {
        *rsa4k_pub_req->sts = -1;
        qat_wake_job(rsa4k_pub_req->job, 0);
        OPENSSL_free(rsa4k_pub_req);
    }
    mb_queue_rsa4k_pub_cleanup(&rsa4k_pub_queue);

    mb_flist_rsa_priv_cleanup(&rsa_priv_freelist);
    mb_flist_rsa_pub_cleanup(&rsa_pub_freelist);
    mb_flist_x25519_keygen_cleanup(&x25519_keygen_freelist);
    mb_flist_x25519_derive_cleanup(&x25519_derive_freelist);
    mb_flist_ecdsa_sign_cleanup(&ecdsa_sign_freelist);
    mb_flist_ecdsa_sign_setup_cleanup(&ecdsa_sign_setup_freelist);
    mb_flist_ecdsa_sign_sig_cleanup(&ecdsa_sign_sig_freelist);
    mb_flist_ecdh_keygen_cleanup(&ecdh_keygen_freelist);
    mb_flist_ecdh_compute_cleanup(&ecdh_compute_freelist);

    if (e_check != NULL) {
        BN_free(e_check);
        e_check = NULL;
    }

    PRINT_RDTSC_AVERAGES();

    return ret;
}
