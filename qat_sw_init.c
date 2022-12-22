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

void mb_thread_local_destructor(void *tlv_ptr)
{
    mb_thread_data *tlv = (mb_thread_data *)tlv_ptr;
    if (tlv == NULL)
        return;

    DEBUG("Thread local Destructor\n");
    tlv->keep_polling = 0;

    if (!enable_external_polling) {
        if (qat_join_thread(tlv->polling_thread, NULL) != 0)
            WARN("Polling thread join failed\n");
    }

#ifdef ENABLE_QAT_SW_RSA
    QAT_SW_CLEANUP(rsa2k_priv, rsa_priv_op_data, tlv->rsa2k_priv_queue);
    QAT_SW_CLEANUP(rsa2k_pub, rsa_pub_op_data, tlv->rsa2k_pub_queue);
    QAT_SW_CLEANUP(rsa3k_priv, rsa_priv_op_data, tlv->rsa3k_priv_queue);
    QAT_SW_CLEANUP(rsa3k_pub, rsa_pub_op_data, tlv->rsa3k_pub_queue);
    QAT_SW_CLEANUP(rsa4k_priv, rsa_priv_op_data, tlv->rsa4k_priv_queue);
    QAT_SW_CLEANUP(rsa4k_pub, rsa_pub_op_data, tlv->rsa4k_pub_queue);
    if (tlv->rsa_priv_freelist)
        mb_flist_rsa_priv_cleanup(tlv->rsa_priv_freelist);
    if (tlv->rsa_pub_freelist)
        mb_flist_rsa_pub_cleanup(tlv->rsa_pub_freelist);
#endif

#ifdef ENABLE_QAT_SW_ECX
    QAT_SW_CLEANUP(x25519_keygen, x25519_keygen_op_data, tlv->x25519_keygen_queue);
    QAT_SW_CLEANUP(x25519_derive, x25519_derive_op_data, tlv->x25519_derive_queue);
    if (tlv->x25519_keygen_freelist)
        mb_flist_x25519_keygen_cleanup(tlv->x25519_keygen_freelist);
    if (tlv->x25519_derive_freelist)
        mb_flist_x25519_derive_cleanup(tlv->x25519_derive_freelist);
#endif

#ifdef ENABLE_QAT_SW_ECDSA
    QAT_SW_CLEANUP(ecdsap256_sign, ecdsa_sign_op_data, tlv->ecdsap256_sign_queue);
    QAT_SW_CLEANUP(ecdsap256_sign_setup, ecdsa_sign_setup_op_data,tlv->ecdsap256_sign_setup_queue);
    QAT_SW_CLEANUP(ecdsap256_sign_sig, ecdsa_sign_sig_op_data, tlv->ecdsap256_sign_sig_queue);
    QAT_SW_CLEANUP(ecdsap384_sign, ecdsa_sign_op_data, tlv->ecdsap384_sign_queue);
    QAT_SW_CLEANUP(ecdsap384_sign_setup, ecdsa_sign_setup_op_data,  tlv->ecdsap384_sign_setup_queue);
    QAT_SW_CLEANUP(ecdsap384_sign_sig, ecdsa_sign_sig_op_data,tlv->ecdsap384_sign_sig_queue);
    if (tlv->ecdsa_sign_freelist)
        mb_flist_ecdsa_sign_cleanup(tlv->ecdsa_sign_freelist);
    if (tlv->ecdsa_sign_setup_freelist)
        mb_flist_ecdsa_sign_setup_cleanup(tlv->ecdsa_sign_setup_freelist);
    if (tlv->ecdsa_sign_sig_freelist)
        mb_flist_ecdsa_sign_sig_cleanup(tlv->ecdsa_sign_sig_freelist);
#endif

#ifdef ENABLE_QAT_SW_SM2
    QAT_SW_CLEANUP(ecdsa_sm2_sign, ecdsa_sm2_sign_op_data, tlv->ecdsa_sm2_sign_queue);
    QAT_SW_CLEANUP(ecdsa_sm2_verify, ecdsa_sm2_verify_op_data, tlv->ecdsa_sm2_verify_queue);
    if (tlv->ecdsa_sm2_sign_freelist)
        mb_flist_ecdsa_sm2_sign_cleanup(tlv->ecdsa_sm2_sign_freelist);
    if (tlv->ecdsa_sm2_verify_freelist)
        mb_flist_ecdsa_sm2_verify_cleanup(tlv->ecdsa_sm2_verify_freelist);
#endif

#ifdef ENABLE_QAT_SW_ECDH
    QAT_SW_CLEANUP(ecdhp256_keygen, ecdh_keygen_op_data, tlv->ecdhp256_keygen_queue);
    QAT_SW_CLEANUP(ecdhp256_compute, ecdh_compute_op_data, tlv->ecdhp256_compute_queue);
    QAT_SW_CLEANUP(ecdhp384_keygen, ecdh_keygen_op_data, tlv->ecdhp384_keygen_queue);
    QAT_SW_CLEANUP(ecdhp384_compute, ecdh_compute_op_data, tlv->ecdhp384_compute_queue);
    QAT_SW_CLEANUP(sm2ecdh_keygen, ecdh_keygen_op_data, tlv->sm2ecdh_keygen_queue);
    QAT_SW_CLEANUP(sm2ecdh_compute, ecdh_compute_op_data, tlv->sm2ecdh_compute_queue);
    if (tlv->ecdh_keygen_freelist)
        mb_flist_ecdh_keygen_cleanup(tlv->ecdh_keygen_freelist);
    if (tlv->ecdh_compute_freelist)
        mb_flist_ecdh_compute_cleanup(tlv->ecdh_compute_freelist);

#endif

#ifdef ENABLE_QAT_SW_SM3
    QAT_SW_CLEANUP(sm3_init, sm3_init_op_data, tlv->sm3_init_queue);
    QAT_SW_CLEANUP(sm3_update, sm3_update_op_data, tlv->sm3_update_queue);
    QAT_SW_CLEANUP(sm3_final, sm3_final_op_data, tlv->sm3_final_queue);
    if (tlv->sm3_init_freelist)
        mb_flist_sm3_init_cleanup(tlv->sm3_init_freelist);
    if (tlv->sm3_update_freelist)
        mb_flist_sm3_update_cleanup(tlv->sm3_update_freelist);
    if (tlv->sm3_final_freelist)
        mb_flist_sm3_final_cleanup(tlv->sm3_final_freelist);
#endif

    sem_destroy(&tlv->mb_polling_thread_sem);
    OPENSSL_free(tlv);

    if (pthread_key_delete(mb_thread_key) != 0) {
        WARN("Failed to delete pthread key.\n");
    }
}

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
            goto err;
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
            goto err;
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
            goto err;
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
            goto err;
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
            goto err;
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
            goto err;
        }
#endif

        if (!enable_external_polling) {
            /* Qat SW semaphore init. */
            if (sem_init(&tlv->mb_polling_thread_sem, 0, 0) == -1) {
                WARN("sem_init failed!\n");
                goto err;
            }

            tlv->keep_polling = 1;
            /* Create Polling thread */
            if (qat_create_thread(&tlv->polling_thread,
                        NULL, multibuff_timer_poll_func, tlv)) {
                WARN("Creation of polling thread failed\n");
                goto err;
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

err:
    mb_thread_local_destructor(tlv);
    return NULL;
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
    mb_thread_data *tlv;

    DEBUG("---- QAT_SW Finishing...\n\n");

    if (e_check != NULL) {
        BN_free(e_check);
        e_check = NULL;
    }

    PRINT_RDTSC_AVERAGES();
    tlv = (mb_thread_data *)pthread_getspecific(mb_thread_key);
    mb_thread_local_destructor(tlv);

    return ret;
}
