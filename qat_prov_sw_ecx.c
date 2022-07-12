/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022 Intel Corporation.
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
 * @qat_prov_sw_ecx.c
 *
 * This file contains the qatprovider implementation for X25519 MultiBuffer
 * operations
 *
 *****************************************************************************/

#ifdef ENABLE_QAT_SW_ECX
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define __USE_GNU

#include <pthread.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/* Local includes */
#include "e_qat.h"
#include "qat_utils.h"
#include "qat_events.h"
#include "qat_fork.h"
#include "qat_sw_ecx.h"
#include "qat_sw_request.h"
#include "qat_prov_ecx.h"
#include "openssl/types.h"

/* Crypto_mb includes */
#include "crypto_mb/x25519.h"

#ifdef QAT_OPENSSL_PROVIDER
void* multibuff_x25519_keygen(void *genctx, OSSL_CALLBACK *osslcb,
                              void *cbarg)
{
    ASYNC_JOB *job;
    int sts = 0, job_ret = 0;
    x25519_keygen_op_data *x25519_keygen_req = NULL;
    ECX_KEY *key = NULL;
    unsigned char *privkey = NULL, *pubkey = NULL;
    mb_thread_data *tlv = NULL;
    static __thread int req_num = 0;

    /* Check input parameters */

    /* Check if we are running asynchronously. If not use the SW method */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(job)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    tlv = mb_check_thread_local();
    if (NULL == tlv) {
        WARN("Could not create thread local variables\n");
        goto use_sw_method;
    }

    while ((x25519_keygen_req =
            mb_flist_x25519_keygen_pop(tlv->x25519_keygen_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("QAT SW ECX Started %p\n", x25519_keygen_req);
    START_RDTSC(&x25519_cycles_keygen_setup);

    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */
    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        WARN("Cannot allocate key.\n");
        QATerr(QAT_F_MULTIBUFF_X25519_KEYGEN, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    key->keylen = X25519_KEYLEN;
    key->references = 1;
    pubkey = key->pubkey;
    privkey = key->privkey = OPENSSL_secure_malloc(X25519_KEYLEN);
    if (privkey == NULL) {
        WARN("Cannot allocate privkey.\n");
        QATerr(QAT_F_MULTIBUFF_X25519_KEYGEN, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(key);
        key = NULL;
        return NULL;
    }

    if (RAND_priv_bytes(privkey, X25519_KEYLEN) <= 0) {
        WARN("RAND function failed for privkey.\n");
        QATerr(QAT_F_MULTIBUFF_X25519_KEYGEN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    x25519_keygen_req->privkey =  privkey;
    x25519_keygen_req->pubkey =  pubkey;
    x25519_keygen_req->job = job;
    x25519_keygen_req->sts = &sts;

    mb_queue_x25519_keygen_enqueue(tlv->x25519_keygen_queue, x25519_keygen_req);
    STOP_RDTSC(&x25519_cycles_keygen_setup, 1, "[X25519:keygen_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (sem_post(&tlv->mb_polling_thread_sem) != 0) {
            WARN("hw sem_post failed!, mb_polling_thread_sem address: %p.\n",
                  &tlv->mb_polling_thread_sem);
            /* If we fail the pthread_kill carry on as the timeout
               will catch processing the request in the polling thread */
        }
     }

    DEBUG("Pausing: %p status = %d\n", x25519_keygen_req, sts);
    do {
        /* If we get a failure on qat_pause_job then we will
           not flag an error here and quit because we have
           an asynchronous request in flight.
           We don't want to start cleaning up data
           structures that are still being used. If
           qat_pause_job fails we will just yield and
           loop around and try again until the request
           completes and we can continue. */
        if ((job_ret = qat_pause_job(job, ASYNC_STATUS_OK)) == 0)
            pthread_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("Finished: %p status = %d\n", x25519_keygen_req, sts);

    if (sts) {
         return key;
    } else {
        WARN("Failure in Keygen\n");
        QATerr(QAT_F_MULTIBUFF_X25519_KEYGEN, QAT_R_KEYGEN_FAILURE);
        goto err;
    }

err:
    if (sts == 0) {
        if (NULL != privkey) {
            OPENSSL_secure_free(privkey);
            if (NULL != key) {
                key->privkey = NULL;
                OPENSSL_free(key);
                key = NULL;
            }
        }
    }
    return NULL;

use_sw_method: ;
    typedef void* (*fun_ptr)(void *,OSSL_CALLBACK*,void*);
    fun_ptr fun = get_default_x25519_keymgmt().gen;
    DEBUG("SW Finished\n");
    return fun(genctx,osslcb,cbarg);

}

static int multibuff_validate_ecx_derive(void *vecxctx,
                                         const unsigned char **privkey,
                                         const unsigned char **pubkey)
{
    QAT_ECX_CTX *ecxctx = (QAT_ECX_CTX *)vecxctx;

    if (ecxctx == NULL || ecxctx->key->privkey == NULL) {
        WARN("ecxctx or ecxctx->key->privkey is NULL\n");
        QATerr(QAT_F_MULTIBUFF_VALIDATE_ECX_DERIVE, QAT_R_INVALID_PRIVATE_KEY);
        return 0;
    }
    if (ecxctx->peerkey->pubkey == NULL) {
        WARN("ecxctx->peerkey->pubkey is NULL\n");
        QATerr(QAT_F_MULTIBUFF_VALIDATE_ECX_DERIVE, QAT_R_INVALID_PEER_KEY);
        return 0;
    }
    *privkey = ecxctx->key->privkey;
    *pubkey = ecxctx->peerkey->pubkey;

    return 1;
}

int multibuff_x25519_derive(void *vecxctx, unsigned char *secret,
                            size_t *secretlen, size_t outlen)
{
    ASYNC_JOB *job;
    int sts = 0, job_ret = 0;
    x25519_derive_op_data *x25519_derive_req = NULL;
    const unsigned char *privkey, *pubkey;
    mb_thread_data *tlv = NULL;
    static __thread int req_num = 0;


    if (secret == NULL) {
        *secretlen = X25519_KEYLEN;
        return 1;
    }

    /* Check if we are running asynchronously. If not use the SW method */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(job)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    tlv = mb_check_thread_local();
    if (NULL == tlv) {
        WARN("Could not create thread local variables\n");
        goto use_sw_method;
    }

    while ((x25519_derive_req =
            mb_flist_x25519_derive_pop(tlv->x25519_derive_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("QAT SW ECX Started %p\n", x25519_derive_req);
    START_RDTSC(&x25519_cycles_derive_setup);

    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */
    if (!multibuff_validate_ecx_derive(vecxctx, &privkey, &pubkey))
        return sts;

    x25519_derive_req->key = secret;
    x25519_derive_req->privkey = privkey;
    x25519_derive_req->pubkey = pubkey;
    x25519_derive_req->job = job;
    x25519_derive_req->sts = &sts;

    mb_queue_x25519_derive_enqueue(tlv->x25519_derive_queue, x25519_derive_req);
    STOP_RDTSC(&x25519_cycles_derive_setup, 1, "[X25519:derive_setup]");

    if (!enable_external_polling && (++req_num % MULTIBUFF_MAX_BATCH) == 0) {
        DEBUG("Signal Polling thread, req_num %d\n", req_num);
        if (sem_post(&tlv->mb_polling_thread_sem) != 0) {
            WARN("hw sem_post failed!, mb_polling_thread_sem address: %p.\n",
                  &tlv->mb_polling_thread_sem);
            /* If we fail the pthread_kill carry on as the timeout
               will catch processing the request in the polling thread */
        }
     }

    DEBUG("Pausing: %p status = %d\n", x25519_derive_req, sts);
    do {
        /* If we get a failure on qat_pause_job then we will
           not flag an error here and quit because we have
           an asynchronous request in flight.
           We don't want to start cleaning up data
           structures that are still being used. If
           qat_pause_job fails we will just yield and
           loop around and try again until the request
           completes and we can continue. */
        if ((job_ret = qat_pause_job(job, ASYNC_STATUS_OK)) == 0)
            pthread_yield();
    } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DEBUG("Finished: %p status = %d\n", x25519_derive_req, sts);

    if (sts) {
       *secretlen = X25519_KEYLEN;
       return sts;
    } else {
        WARN("Failure in derive\n");
        QATerr(QAT_F_MULTIBUFF_X25519_DERIVE, QAT_R_DERIVE_FAILURE);
        return sts;
    }

use_sw_method: ;
    typedef int (*fun_ptr)(void *,unsigned char*,size_t*,size_t);
    fun_ptr fun = get_default_x25519_keyexch().derive;
    DEBUG("SW Finished\n");
    return fun(vecxctx,secret,secretlen,outlen);
}
#endif
#endif
