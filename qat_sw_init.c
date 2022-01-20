/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020-2022 Intel Corporation.
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
#include "qat_sw_sm3.h"
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

mb_thread_data* mb_check_thread_local(void)
{
    mb_thread_data *tlv = (mb_thread_data *)pthread_getspecific(mb_thread_key);

    if (tlv != NULL) {
        return tlv;
    }

    tlv = OPENSSL_zalloc(sizeof(mb_thread_data));
    if (tlv != NULL) {
        DEBUG("TLV NULL allocate memory and create polling thread\n");
        /* Create Multibuffer Freelists and Queues*/

#ifdef ENABLE_QAT_SW_RSA
        if (((tlv->rsa_priv_freelist = mb_flist_rsa_priv_create()) == NULL) ||
           ((tlv->rsa_pub_freelist = mb_flist_rsa_pub_create()) == NULL) ||
           ((tlv->rsa2k_priv_queue = mb_queue_rsa2k_priv_create()) == NULL) ||
           ((tlv->rsa2k_pub_queue = mb_queue_rsa2k_pub_create()) == NULL) ||
           ((tlv->rsa3k_priv_queue = mb_queue_rsa3k_priv_create()) == NULL) ||
           ((tlv->rsa3k_pub_queue = mb_queue_rsa3k_pub_create()) == NULL) ||
           ((tlv->rsa4k_priv_queue = mb_queue_rsa4k_priv_create()) == NULL) ||
           ((tlv->rsa4k_pub_queue = mb_queue_rsa4k_pub_create()) == NULL)) {
            WARN("Failure to allocate RSA Freelist and Queues\n");
            return NULL;
        }
#endif

#ifdef ENABLE_QAT_SW_ECX
        if (((tlv->x25519_keygen_freelist = mb_flist_x25519_keygen_create())
                 == NULL) ||
           ((tlv->x25519_derive_freelist = mb_flist_x25519_derive_create())
                 == NULL) ||
           ((tlv->x25519_keygen_queue = mb_queue_x25519_keygen_create())
                 == NULL) ||
           ((tlv->x25519_derive_queue = mb_queue_x25519_derive_create())
                 == NULL)) {
            WARN("Failure to allocate X25519 Freelists and Queues\n");
            return NULL;
        }
#endif

#ifdef ENABLE_QAT_SW_ECDSA
        if(((tlv->ecdsa_sign_freelist = mb_flist_ecdsa_sign_create())
                 == NULL) ||
           ((tlv->ecdsa_sign_setup_freelist = mb_flist_ecdsa_sign_setup_create())
                 == NULL) ||
           ((tlv->ecdsa_sign_sig_freelist = mb_flist_ecdsa_sign_sig_create())
                 == NULL) ||
           ((tlv->ecdsap256_sign_queue= mb_queue_ecdsap256_sign_create())
                 == NULL) ||
           ((tlv->ecdsap256_sign_setup_queue= mb_queue_ecdsap256_sign_setup_create())
                 == NULL) ||
           ((tlv->ecdsap256_sign_sig_queue= mb_queue_ecdsap256_sign_sig_create())
                 == NULL) ||
           ((tlv->ecdsap384_sign_queue= mb_queue_ecdsap384_sign_create())
                 == NULL) ||
           ((tlv->ecdsap384_sign_setup_queue= mb_queue_ecdsap384_sign_setup_create())
                 == NULL) ||
           ((tlv->ecdsap384_sign_sig_queue= mb_queue_ecdsap384_sign_sig_create())
                 == NULL)) {
            WARN("Failure to allocate ECDSA P256/P384 Freelists and Queues\n");
            return NULL;
        }
#endif

#ifdef ENABLE_QAT_SW_ECDH
        if(((tlv->ecdh_keygen_freelist = mb_flist_ecdh_keygen_create())
                 == NULL) ||
           ((tlv->ecdh_compute_freelist = mb_flist_ecdh_compute_create())
                 == NULL) ||
           ((tlv->ecdhp256_keygen_queue= mb_queue_ecdhp256_keygen_create())
                 == NULL) ||
           ((tlv->ecdhp256_compute_queue= mb_queue_ecdhp256_compute_create())
                 == NULL) ||
           ((tlv->ecdhp384_keygen_queue= mb_queue_ecdhp384_keygen_create())
                 == NULL) ||
           ((tlv->ecdhp384_compute_queue= mb_queue_ecdhp384_compute_create())
                 == NULL) ||
           ((tlv->sm2ecdh_keygen_queue= mb_queue_sm2ecdh_keygen_create())
                 == NULL) ||
           ((tlv->sm2ecdh_compute_queue= mb_queue_sm2ecdh_compute_create())
                 == NULL)) {
            WARN("Failure to allocate ECDH P256/P384/SM2 Freelists and Queues\n");
            return NULL;
        }
#endif

#ifdef ENABLE_QAT_SW_SM2
        if(((tlv->ecdsa_sm2_sign_freelist = mb_flist_ecdsa_sm2_sign_create())
                 == NULL) ||
           ((tlv->ecdsa_sm2_verify_freelist = mb_flist_ecdsa_sm2_verify_create())
                 == NULL) ||
           ((tlv->ecdsa_sm2_sign_queue= mb_queue_ecdsa_sm2_sign_create())
                 == NULL) ||
           ((tlv->ecdsa_sm2_verify_queue= mb_queue_ecdsa_sm2_verify_create())
                 == NULL)) {
            WARN("Failure to allocate ECDSA SM2 Freelists and Queues\n");
            return NULL;
        }
#endif

#ifdef ENABLE_QAT_SW_SM3
        if(((tlv->sm3_init_freelist = mb_flist_sm3_init_create())
                 == NULL) ||
           ((tlv->sm3_update_freelist = mb_flist_sm3_update_create())
                 == NULL) ||
           ((tlv->sm3_final_freelist = mb_flist_sm3_final_create())
                 == NULL) ||
           ((tlv->sm3_init_queue= mb_queue_sm3_init_create())
                 == NULL) ||
           ((tlv->sm3_update_queue= mb_queue_sm3_update_create())
                 == NULL) ||
           ((tlv->sm3_final_queue= mb_queue_sm3_final_create())
                 == NULL) ) {
            WARN("Failure to allocate SM3 Freelists and Queues\n");
            return NULL;
        }
#endif

        /* Sig set for Signalling via pthread_kill */
        if (!enable_external_polling) {
            tlv->keep_polling = 1;
            sigemptyset(&tlv->set);
            sigaddset(&tlv->set, SIGUSR1);
            if (pthread_sigmask(SIG_BLOCK, &tlv->set, NULL) != 0)
                WARN("pthread_sigmask error\n");
            /* Create Polling thread */
            if (qat_create_thread(&tlv->polling_thread,
                        NULL, multibuff_timer_poll_func, tlv)) {
                WARN("Creation of polling thread failed\n");
                return NULL;
            }
            DEBUG("Polling thread created %lx, tlv %p\n",
                  tlv->polling_thread, tlv);
        } else {
            /* External Polling assign it to the global pointer */
            mb_tlv = tlv;
        }
        pthread_setspecific(mb_thread_key, (void *)tlv);
    }

    return tlv;
}

void mb_thread_local_destructor(void *tlv_ptr)
{
#ifdef ENABLE_QAT_SW_RSA
    rsa_priv_op_data *rsa2k_priv_req = NULL;
    rsa_pub_op_data *rsa2k_pub_req = NULL;
    rsa_priv_op_data *rsa3k_priv_req = NULL;
    rsa_pub_op_data *rsa3k_pub_req = NULL;
    rsa_priv_op_data *rsa4k_priv_req = NULL;
    rsa_pub_op_data *rsa4k_pub_req = NULL;
#endif
#ifdef ENABLE_QAT_SW_ECX
    x25519_keygen_op_data *x25519_keygen_req = NULL;
    x25519_derive_op_data *x25519_derive_req = NULL;
#endif
#ifdef ENABLE_QAT_SW_ECDSA
    ecdsa_sign_op_data *ecdsap256_sign_req = NULL;
    ecdsa_sign_setup_op_data *ecdsap256_sign_setup_req = NULL;
    ecdsa_sign_sig_op_data *ecdsap256_sign_sig_req = NULL;
    ecdsa_sign_op_data *ecdsap384_sign_req = NULL;
    ecdsa_sign_setup_op_data *ecdsap384_sign_setup_req = NULL;
    ecdsa_sign_sig_op_data *ecdsap384_sign_sig_req = NULL;
#endif
#ifdef ENABLE_QAT_SW_ECDH
    ecdh_keygen_op_data *ecdhp256_keygen_req = NULL;
    ecdh_compute_op_data *ecdhp256_compute_req = NULL;
    ecdh_keygen_op_data *ecdhp384_keygen_req = NULL;
    ecdh_compute_op_data *ecdhp384_compute_req = NULL;
    ecdh_keygen_op_data *sm2ecdh_keygen_req= NULL;
    ecdh_compute_op_data *sm2ecdh_compute_req= NULL;
#endif
#ifdef ENABLE_QAT_SW_SM2
    ecdsa_sm2_sign_op_data *ecdsa_sm2_sign_req = NULL;
    ecdsa_sm2_verify_op_data *ecdsa_sm2_verify_req = NULL;
#endif
#ifdef ENABLE_QAT_SW_SM3
    sm3_init_op_data *sm3_init_req = NULL;
    sm3_update_op_data *sm3_update_req = NULL;
    sm3_final_op_data *sm3_final_req = NULL;
#endif

    mb_thread_data *tlv = (mb_thread_data *)tlv_ptr;

    DEBUG("Thread local Destructor\n");
    if (tlv) {
        tlv->keep_polling = 0;

        if (enable_external_polling == 0) {
            if (qat_join_thread(tlv->polling_thread, NULL) != 0)
                WARN("Polling thread join failed\n");
        }

#ifdef ENABLE_QAT_SW_RSA
        mb_queue_rsa2k_priv_disable(tlv->rsa2k_priv_queue);
        mb_queue_rsa2k_pub_disable(tlv->rsa2k_pub_queue);
        while ((rsa2k_priv_req =
                mb_queue_rsa2k_priv_dequeue(tlv->rsa2k_priv_queue)) != NULL) {
            *rsa2k_priv_req->sts = -1;
            qat_wake_job(rsa2k_priv_req->job, 0);
            OPENSSL_free(rsa2k_priv_req);
        }
        mb_queue_rsa2k_priv_cleanup(tlv->rsa2k_priv_queue);

        while ((rsa2k_pub_req =
                mb_queue_rsa2k_pub_dequeue(tlv->rsa2k_pub_queue)) != NULL) {
            *rsa2k_pub_req->sts = -1;
            qat_wake_job(rsa2k_pub_req->job, 0);
            OPENSSL_free(rsa2k_pub_req);
        }
        mb_queue_rsa2k_pub_cleanup(tlv->rsa2k_pub_queue);

        while ((rsa3k_priv_req =
                mb_queue_rsa3k_priv_dequeue(tlv->rsa3k_priv_queue)) != NULL) {
            *rsa3k_priv_req->sts = -1;
            qat_wake_job(rsa3k_priv_req->job, 0);
            OPENSSL_free(rsa3k_priv_req);
        }
        mb_queue_rsa3k_priv_cleanup(tlv->rsa3k_priv_queue);

        while ((rsa3k_pub_req =
                mb_queue_rsa3k_pub_dequeue(tlv->rsa3k_pub_queue)) != NULL) {
            *rsa3k_pub_req->sts = -1;
            qat_wake_job(rsa3k_pub_req->job, 0);
            OPENSSL_free(rsa3k_pub_req);
        }
        mb_queue_rsa3k_pub_cleanup(tlv->rsa3k_pub_queue);

        while ((rsa4k_priv_req =
                mb_queue_rsa4k_priv_dequeue(tlv->rsa4k_priv_queue)) != NULL) {
            *rsa4k_priv_req->sts = -1;
            qat_wake_job(rsa4k_priv_req->job, 0);
            OPENSSL_free(rsa4k_priv_req);
        }
        mb_queue_rsa4k_priv_cleanup(tlv->rsa4k_priv_queue);

        while ((rsa4k_priv_req =
                mb_queue_rsa4k_priv_dequeue(tlv->rsa4k_priv_queue)) != NULL) {
            *rsa4k_priv_req->sts = -1;
            qat_wake_job(rsa4k_priv_req->job, 0);
            OPENSSL_free(rsa4k_priv_req);
        }
        mb_queue_rsa4k_priv_cleanup(tlv->rsa4k_priv_queue);

        while ((rsa4k_pub_req =
                mb_queue_rsa4k_pub_dequeue(tlv->rsa4k_pub_queue)) != NULL) {
            *rsa4k_pub_req->sts = -1;
            qat_wake_job(rsa4k_pub_req->job, 0);
            OPENSSL_free(rsa4k_pub_req);
        }
        mb_queue_rsa4k_pub_cleanup(tlv->rsa4k_pub_queue);

        mb_flist_rsa_priv_cleanup(tlv->rsa_priv_freelist);
        mb_flist_rsa_pub_cleanup(tlv->rsa_pub_freelist);
#endif

#ifdef ENABLE_QAT_SW_ECX
        mb_queue_x25519_keygen_disable(tlv->x25519_keygen_queue);
        mb_queue_x25519_derive_disable(tlv->x25519_derive_queue);
        while ((x25519_keygen_req =
                mb_queue_x25519_keygen_dequeue(tlv->x25519_keygen_queue)) != NULL) {
            *x25519_keygen_req->sts = -1;
            qat_wake_job(x25519_keygen_req->job, 0);
            OPENSSL_free(x25519_keygen_req);
        }
        mb_queue_x25519_keygen_cleanup(tlv->x25519_keygen_queue);

        while ((x25519_derive_req =
                mb_queue_x25519_derive_dequeue(tlv->x25519_derive_queue)) != NULL) {
            *x25519_derive_req->sts = -1;
            qat_wake_job(x25519_derive_req->job, 0);
            OPENSSL_free(x25519_derive_req);
        }
        mb_queue_x25519_derive_cleanup(tlv->x25519_derive_queue);

        mb_flist_x25519_keygen_cleanup(tlv->x25519_keygen_freelist);
        mb_flist_x25519_derive_cleanup(tlv->x25519_derive_freelist);
#endif

#ifdef ENABLE_QAT_SW_ECDSA
        while ((ecdsap256_sign_req =
                    mb_queue_ecdsap256_sign_dequeue(tlv->ecdsap256_sign_queue)) != NULL) {
            *ecdsap256_sign_req->sts = -1;
            qat_wake_job(ecdsap256_sign_req->job, 0);
            OPENSSL_free(ecdsap256_sign_req);
        }
        mb_queue_ecdsap256_sign_cleanup(tlv->ecdsap256_sign_queue);

        while ((ecdsap256_sign_setup_req =
                mb_queue_ecdsap256_sign_setup_dequeue(tlv->ecdsap256_sign_setup_queue)) != NULL) {
            *ecdsap256_sign_setup_req->sts = -1;
            qat_wake_job(ecdsap256_sign_setup_req->job, 0);
            OPENSSL_free(ecdsap256_sign_setup_req);
        }
        mb_queue_ecdsap256_sign_setup_cleanup(tlv->ecdsap256_sign_setup_queue);

        while ((ecdsap256_sign_sig_req =
                mb_queue_ecdsap256_sign_sig_dequeue(tlv->ecdsap256_sign_sig_queue)) != NULL) {
            *ecdsap256_sign_sig_req->sts = -1;
            qat_wake_job(ecdsap256_sign_sig_req->job, 0);
            OPENSSL_free(ecdsap256_sign_sig_req);
        }
        mb_queue_ecdsap256_sign_sig_cleanup(tlv->ecdsap256_sign_sig_queue);

        while ((ecdsap384_sign_req =
                mb_queue_ecdsap384_sign_dequeue(tlv->ecdsap384_sign_queue)) != NULL) {
            *ecdsap384_sign_req->sts = -1;
            qat_wake_job(ecdsap384_sign_req->job, 0);
            OPENSSL_free(ecdsap384_sign_req);
        }
        mb_queue_ecdsap384_sign_cleanup(tlv->ecdsap384_sign_queue);

        while ((ecdsap384_sign_setup_req =
                mb_queue_ecdsap384_sign_setup_dequeue(tlv->ecdsap384_sign_setup_queue)) != NULL) {
            *ecdsap384_sign_setup_req->sts = -1;
            qat_wake_job(ecdsap384_sign_setup_req->job, 0);
            OPENSSL_free(ecdsap384_sign_setup_req);
        }
        mb_queue_ecdsap384_sign_setup_cleanup(tlv->ecdsap384_sign_setup_queue);

        while ((ecdsap384_sign_sig_req =
                mb_queue_ecdsap384_sign_sig_dequeue(tlv->ecdsap384_sign_sig_queue)) != NULL) {
            *ecdsap384_sign_sig_req->sts = -1;
            qat_wake_job(ecdsap384_sign_sig_req->job, 0);
            OPENSSL_free(ecdsap384_sign_sig_req);
        }
        mb_queue_ecdsap384_sign_sig_cleanup(tlv->ecdsap384_sign_sig_queue);

        mb_flist_ecdsa_sign_cleanup(tlv->ecdsa_sign_freelist);
        mb_flist_ecdsa_sign_setup_cleanup(tlv->ecdsa_sign_setup_freelist);
        mb_flist_ecdsa_sign_sig_cleanup(tlv->ecdsa_sign_sig_freelist);
#endif

#ifdef ENABLE_QAT_SW_SM2
        while ((ecdsa_sm2_sign_req =
                mb_queue_ecdsa_sm2_sign_dequeue(tlv->ecdsa_sm2_sign_queue)) != NULL) {
            *ecdsa_sm2_sign_req->sts = -1;
            qat_wake_job(ecdsa_sm2_sign_req->job, 0);
            OPENSSL_free(ecdsa_sm2_sign_req);
        }
        mb_queue_ecdsa_sm2_sign_cleanup(tlv->ecdsa_sm2_sign_queue);

        while ((ecdsa_sm2_verify_req =
                mb_queue_ecdsa_sm2_verify_dequeue(tlv->ecdsa_sm2_verify_queue)) != NULL) {
            *ecdsa_sm2_verify_req->sts = -1;
            qat_wake_job(ecdsa_sm2_verify_req->job, 0);
            OPENSSL_free(ecdsa_sm2_verify_req);
        }
        mb_queue_ecdsa_sm2_verify_cleanup(tlv->ecdsa_sm2_verify_queue);

        mb_flist_ecdsa_sm2_sign_cleanup(tlv->ecdsa_sm2_sign_freelist);
        mb_flist_ecdsa_sm2_verify_cleanup(tlv->ecdsa_sm2_verify_freelist);
#endif

#ifdef ENABLE_QAT_SW_ECDH
        while ((ecdhp256_keygen_req =
                mb_queue_ecdhp256_keygen_dequeue(tlv->ecdhp256_keygen_queue)) != NULL) {
            *ecdhp256_keygen_req->sts = -1;
            qat_wake_job(ecdhp256_keygen_req->job, 0);
            OPENSSL_free(ecdhp256_keygen_req);
        }
        mb_queue_ecdhp256_keygen_cleanup(tlv->ecdhp256_keygen_queue);

        while ((ecdhp256_compute_req =
                mb_queue_ecdhp256_compute_dequeue(tlv->ecdhp256_compute_queue)) != NULL) {
            *ecdhp256_compute_req->sts = -1;
            qat_wake_job(ecdhp256_compute_req->job, 0);
            OPENSSL_free(ecdhp256_compute_req);
        }
        mb_queue_ecdhp256_compute_cleanup(tlv->ecdhp256_compute_queue);

        while ((ecdhp384_keygen_req =
                mb_queue_ecdhp384_keygen_dequeue(tlv->ecdhp384_keygen_queue)) != NULL) {
            *ecdhp384_keygen_req->sts = -1;
            qat_wake_job(ecdhp384_keygen_req->job, 0);
            OPENSSL_free(ecdhp384_keygen_req);
        }
        mb_queue_ecdhp384_keygen_cleanup(tlv->ecdhp384_keygen_queue);

        while ((ecdhp384_compute_req =
                mb_queue_ecdhp384_compute_dequeue(tlv->ecdhp384_compute_queue)) != NULL) {
            *ecdhp384_compute_req->sts = -1;
            qat_wake_job(ecdhp384_compute_req->job, 0);
            OPENSSL_free(ecdhp384_compute_req);
        }
        mb_queue_ecdhp384_compute_cleanup(tlv->ecdhp384_compute_queue);

        while ((sm2ecdh_keygen_req =
                mb_queue_sm2ecdh_keygen_dequeue(tlv->sm2ecdh_keygen_queue)) != NULL) {
            *sm2ecdh_keygen_req->sts = -1;
            qat_wake_job(sm2ecdh_keygen_req->job, 0);
            OPENSSL_free(sm2ecdh_keygen_req);
        }
        mb_queue_sm2ecdh_keygen_cleanup(tlv->sm2ecdh_keygen_queue);

        while ((sm2ecdh_compute_req =
                mb_queue_sm2ecdh_compute_dequeue(tlv->sm2ecdh_compute_queue)) != NULL) {
            *sm2ecdh_compute_req->sts = -1;
            qat_wake_job(sm2ecdh_compute_req->job, 0);
            OPENSSL_free(sm2ecdh_compute_req);
        }
        mb_queue_sm2ecdh_compute_cleanup(tlv->sm2ecdh_compute_queue);

        mb_flist_ecdh_keygen_cleanup(tlv->ecdh_keygen_freelist);
        mb_flist_ecdh_compute_cleanup(tlv->ecdh_compute_freelist);
#endif
#ifdef ENABLE_QAT_SW_SM3
        mb_queue_sm3_init_disable(tlv->sm3_init_queue);
        mb_queue_sm3_update_disable(tlv->sm3_update_queue);
        mb_queue_sm3_final_disable(tlv->sm3_final_queue);
        while ((sm3_init_req =
                mb_queue_sm3_init_dequeue(tlv->sm3_init_queue)) != NULL) {
            *sm3_init_req->sts = -1;
            qat_wake_job(sm3_init_req->job, 0);
            OPENSSL_free(sm3_init_req);
        }
        mb_queue_sm3_init_cleanup(tlv->sm3_init_queue);

        while ((sm3_update_req =
                mb_queue_sm3_update_dequeue(tlv->sm3_update_queue)) != NULL) {
            *sm3_update_req->sts = -1;
            qat_wake_job(sm3_update_req->job, 0);
            OPENSSL_free(sm3_update_req);
        }
        mb_queue_sm3_update_cleanup(tlv->sm3_update_queue);

        while ((sm3_final_req =
                mb_queue_sm3_final_dequeue(tlv->sm3_final_queue)) != NULL) {
            *sm3_final_req->sts = -1;
            qat_wake_job(sm3_final_req->job, 0);
            OPENSSL_free(sm3_final_req);
        }
        mb_queue_sm3_final_cleanup(tlv->sm3_final_queue);

        mb_flist_sm3_init_cleanup(tlv->sm3_init_freelist);
        mb_flist_sm3_update_cleanup(tlv->sm3_update_freelist);
        mb_flist_sm3_final_cleanup(tlv->sm3_final_freelist);
#endif

        OPENSSL_free(tlv);
    } else {
        DEBUG("tlv NULL\n");
    }
}

int multibuff_init(ENGINE *e)
{
    int err = 0;

    DEBUG("QAT_SW initialization\n");
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

    if ((err = pthread_key_create(&mb_thread_key, mb_thread_local_destructor)) != 0) {
        WARN("pthread_key_create failed %s\n", strerror(err));
        qat_pthread_mutex_unlock();
        qat_engine_finish(e);
        return 0;
    }

    return 1;
}

int multibuff_finish_int(ENGINE *e, int reset_globals)
{
    int ret = 1;

    DEBUG("---- Multibuff Finishing...\n\n");

    if (e_check != NULL) {
        BN_free(e_check);
        e_check = NULL;
    }

    PRINT_RDTSC_AVERAGES();

    ret = pthread_key_delete(mb_thread_key) == 0;

    return ret;
}
