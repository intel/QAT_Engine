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
 * @file multibuff_ecx.c
 *
 * This file contains the engine implementation for X25519 MultiBuffer operations
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */

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
#include "e_qat_err.h"
#include "qat_utils.h"
#include "qat_events.h"
#include "multibuff_ecx.h"
#include "multibuff_request.h"
#include "multibuff_polling.h"

/* Crypto_mb includes */
#include "crypto_mb/ed25519_ifma.h"

#ifdef OPENSSL_ENABLE_MULTIBUFF_ECX
# ifdef OPENSSL_DISABLE_MULTIBUFF_ECX
#  undef OPENSSL_DISABLE_MULTIBUFF_ECX
# endif
#endif

/* X25519 nid */
int x25519_nid[] = {
    EVP_PKEY_X25519
};

static EVP_PKEY_METHOD *_hidden_x25519_pmeth = NULL;

#ifndef OPENSSL_DISABLE_MULTIBUFF_ECX

#define X25519_MULTIBUFF_BIT_DEPTH 2048
#define X25519_MULTIBUFF_KEYGEN 1
#define X25519_MULTIBUFF_DERIVE 2

/* Have a store of the s/w EVP_PKEY_METHOD for software fallback purposes. */
static const EVP_PKEY_METHOD *sw_x25519_pmeth = NULL;
static int multibuff_x25519_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
static int multibuff_x25519_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
static int multibuff_x25519_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
#endif /* OPENSSL_DISABLE_MULTIBUFF_ECX */

/* Multibuff X25519 methods declaration */
static EVP_PKEY_METHOD *multibuff_x25519_pmeth(void)
{
#ifdef OPENSSL_DISABLE_MULTIBUFF_ECX
    const EVP_PKEY_METHOD *current_x25519_pmeth = NULL;
#endif
    if (_hidden_x25519_pmeth)
        return _hidden_x25519_pmeth;
#ifdef OPENSSL_DISABLE_MULTIBUFF_ECX
    if ((current_x25519_pmeth = EVP_PKEY_meth_find(EVP_PKEY_X25519)) == NULL) {
        QATerr(QAT_F_MULTIBUFF_X25519_PMETH, ERR_R_INTERNAL_ERROR);
        return NULL;
    }
#endif
    if ((_hidden_x25519_pmeth =
                EVP_PKEY_meth_new(EVP_PKEY_X25519, 0)) == NULL) {
        QATerr(QAT_F_MULTIBUFF_X25519_PMETH, ERR_R_INTERNAL_ERROR);
        return NULL;
    }

#ifdef OPENSSL_DISABLE_MULTIBUFF_ECX
    EVP_PKEY_meth_copy(_hidden_x25519_pmeth, current_x25519_pmeth);
#else
    /* Now save the current (non-offloaded) x25519 pmeth to sw_x25519_pmeth */
    /* for software fallback purposes */
    if ((sw_x25519_pmeth = EVP_PKEY_meth_find(EVP_PKEY_X25519)) == NULL) {
        QATerr(QAT_F_MULTIBUFF_X25519_PMETH, ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    EVP_PKEY_meth_set_keygen(_hidden_x25519_pmeth, NULL, multibuff_x25519_keygen);
    EVP_PKEY_meth_set_derive(_hidden_x25519_pmeth, NULL, multibuff_x25519_derive);
    EVP_PKEY_meth_set_ctrl(_hidden_x25519_pmeth, multibuff_x25519_ctrl, NULL);
#endif
    return _hidden_x25519_pmeth;
}

int multibuff_x25519_pkey_methods(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                                  const int **nids, int nid)
{
    if (pmeth == NULL) {
        if (unlikely(nids == NULL)) {
            WARN("Invalid input params.\n");
            return 0;
        }
        *nids = x25519_nid;
        return 1;
    }

    *pmeth = multibuff_x25519_pmeth();
    return 1;
}

#ifndef OPENSSL_DISABLE_MULTIBUFF_ECX

void process_x25519_keygen_reqs()
{
    x25519_keygen_op_data *x25519_keygen_req_array[MULTIBUFF_BATCH] = {0};
    const unsigned char *x25519_keygen_privkey[MULTIBUFF_BATCH] = {0};
    unsigned char *x25519_keygen_pubkey[MULTIBUFF_BATCH] = {0};
    unsigned int x25519_sts = 0;
    int local_request_no = 0;
    int req_num = 0;

    START_RDTSC(&x25519_cycles_keygen_execute);

    /* Build Arrays of pointers for call */
    while ((x25519_keygen_req_array[req_num] =
            mb_queue_x25519_keygen_dequeue(&x25519_keygen_queue)) != NULL) {
        x25519_keygen_privkey[req_num] = x25519_keygen_req_array[req_num]->privkey;
        x25519_keygen_pubkey[req_num] = x25519_keygen_req_array[req_num]->pubkey;

        req_num++;
        if (req_num == MULTIBUFF_MIN_BATCH)
            break;
    }
    local_request_no = req_num;
    DEBUG("Submitting %d keygen requests\n", local_request_no);

    x25519_sts = x25519_public_key_mb8(x25519_keygen_pubkey,
                                       x25519_keygen_privkey);

    for (req_num = 0; req_num < local_request_no; req_num++) {
	    if (x25519_keygen_req_array[req_num]->sts != NULL) {
             if (IFMA_GET_STS(x25519_sts, req_num) == IFMA_STATUS_OK) {
                 DEBUG("Multibuffer Keygen request[%d] success\n", req_num);
                 *x25519_keygen_req_array[req_num]->sts = 1;
             } else {
                 WARN("Multibuffer Keygen request[%d] failure\n", req_num);
                 *x25519_keygen_req_array[req_num]->sts = 0;
             }
        }

        if (x25519_keygen_req_array[req_num]->job) {
            qat_wake_job(x25519_keygen_req_array[req_num]->job, ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(x25519_keygen_req_array[req_num],
                        sizeof(x25519_keygen_op_data));
        mb_flist_x25519_keygen_push(&x25519_keygen_freelist,
                                    x25519_keygen_req_array[req_num]);
    }
# ifdef MULTIBUFF_HEURISTIC_TIMEOUT
    mb_x25519_keygen_req_rates.req_this_period += local_request_no;
# endif

    STOP_RDTSC(&x25519_cycles_keygen_execute, 1, "[X25519:keygen_execute]");
    DEBUG("Processed Final Request\n");
}

void process_x25519_derive_reqs()
{
    x25519_derive_op_data *x25519_derive_req_array[MULTIBUFF_BATCH] = {0};
    const unsigned char *x25519_derive_privkey[MULTIBUFF_BATCH] = {0};
    const unsigned char *x25519_derive_pubkey[MULTIBUFF_BATCH] = {0};
    unsigned char *x25519_derive_sharedkey[MULTIBUFF_BATCH] = {0};
    unsigned int x25519_sts = 0;
    int local_request_no = 0;
    int req_num = 0;

    START_RDTSC(&x25519_cycles_derive_execute);

    /* Build Arrays of pointers for call */
    while ((x25519_derive_req_array[req_num] =
            mb_queue_x25519_derive_dequeue(&x25519_derive_queue)) != NULL) {
        x25519_derive_privkey[req_num] = x25519_derive_req_array[req_num]->privkey;
        x25519_derive_pubkey[req_num] = x25519_derive_req_array[req_num]->pubkey;
        x25519_derive_sharedkey[req_num] = x25519_derive_req_array[req_num]->key;

        req_num++;
        if (req_num == MULTIBUFF_MIN_BATCH)
            break;
    }
    local_request_no = req_num;
    DEBUG("Submitting %d derive requests\n", local_request_no);

    x25519_sts = x25519_mb8(x25519_derive_sharedkey,
                            x25519_derive_privkey,
                            x25519_derive_pubkey);

    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (IFMA_GET_STS(x25519_sts, req_num) == IFMA_STATUS_OK) {
            DEBUG("Multibuffer Derive request[%d] success\n", req_num);
            *x25519_derive_req_array[req_num]->sts = 1;
        } else {
            WARN("Multibuffer Derive request[%d] Failure\n", req_num);
            *x25519_derive_req_array[req_num]->sts = 0;
        }

        if (x25519_derive_req_array[req_num]->job) {
            qat_wake_job(x25519_derive_req_array[req_num]->job, ASYNC_STATUS_OK);
        }
        OPENSSL_cleanse(x25519_derive_req_array[req_num],
                        sizeof(x25519_derive_op_data));
        mb_flist_x25519_derive_push(&x25519_derive_freelist,
                                    x25519_derive_req_array[req_num]);
    }
# ifdef MULTIBUFF_HEURISTIC_TIMEOUT
    mb_x25519_derive_req_rates.req_this_period += local_request_no;
# endif

    STOP_RDTSC(&x25519_cycles_derive_execute, 1, "[X25519:derive_execute]");
    DEBUG("Processed Final Request\n");
}

int multibuff_x25519_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int sts = 0;
    ASYNC_JOB *job;
    x25519_keygen_op_data *x25519_keygen_req = NULL;
    int (*sw_fn_ptr)(EVP_PKEY_CTX *, EVP_PKEY *) = NULL;
    ECX_KEY *key = NULL;
    unsigned char *privkey = NULL;
    unsigned char *pubkey = NULL;
    int job_ret = 0;

    /* Check input parameters */
    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL.\n");
        QATerr(QAT_F_MULTIBUFF_X25519_KEYGEN, QAT_R_CTX_NULL);
        return sts;
    }

    /* Check if we are running asynchronously. If not use the SW method */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(0)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    while ((x25519_keygen_req =
            mb_flist_x25519_keygen_pop(&x25519_keygen_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("Started request: %p\n", x25519_keygen_req);
    START_RDTSC(&x25519_cycles_keygen_setup);

    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */
    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        WARN("Cannot allocate key.\n");
        QATerr(QAT_F_MULTIBUFF_X25519_KEYGEN, ERR_R_MALLOC_FAILURE);
        return sts;
    }
    pubkey = key->pubkey;
    privkey = key->privkey = OPENSSL_secure_malloc(X25519_KEYLEN);
    if (privkey == NULL) {
        WARN("Cannot allocate privkey.\n");
        QATerr(QAT_F_MULTIBUFF_X25519_KEYGEN, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(key);
        key = NULL;
        return sts;
    }

    if (RAND_priv_bytes(privkey, X25519_KEYLEN) <= 0) {
        WARN("RAND function failed for privkey.\n");
        QATerr(QAT_F_MULTIBUFF_X25519_KEYGEN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    x25519_keygen_req->ctx = ctx;
    x25519_keygen_req->pkey = pkey;
    x25519_keygen_req->privkey =  privkey;
    x25519_keygen_req->pubkey =  pubkey;
    x25519_keygen_req->job = job;
    x25519_keygen_req->sts = &sts;
    mb_queue_x25519_keygen_enqueue(&x25519_keygen_queue, x25519_keygen_req);
    STOP_RDTSC(&x25519_cycles_keygen_setup, 1, "[X25519:keygen_setup]");

    if (0 == enable_external_polling) {
        if (multibuff_kill_thread(multibuff_timer_poll_func_thread,
                                  SIGUSR1) != 0) {
            WARN("multibuff_kill_thread error\n");
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
       EVP_PKEY_assign(pkey, EVP_PKEY_X25519, key);
       return sts;
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
    return sts;

use_sw_method:
    EVP_PKEY_meth_get_keygen((EVP_PKEY_METHOD *)sw_x25519_pmeth,
                             NULL, &sw_fn_ptr);
    sts = (*sw_fn_ptr)(ctx, pkey);
    DEBUG("SW Finished\n");
    return sts;

}

static int multibuff_validate_ecx_derive(EVP_PKEY_CTX *ctx,
                                         const unsigned char **privkey,
                                         const unsigned char **pubkey)
{
    const ECX_KEY *ecxkey, *peerecxkey;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *peerkey = NULL;

    if ((pkey = EVP_PKEY_CTX_get0_pkey(ctx)) == NULL ||
        (peerkey = EVP_PKEY_CTX_get0_peerkey(ctx)) == NULL) {
        DEBUG("ctx->pkey or ctx->peerkey is NULL\n");
        QATerr(QAT_F_MULTIBUFF_VALIDATE_ECX_DERIVE, QAT_R_KEYS_NOT_SET);
        return 0;
    }

    ecxkey = (const ECX_KEY *)EVP_PKEY_get0((const EVP_PKEY *)pkey);
    peerecxkey = (const ECX_KEY *)EVP_PKEY_get0((const EVP_PKEY *)peerkey);

    if (ecxkey == NULL || ecxkey->privkey == NULL) {
        DEBUG("ecxkey or ecxkey->privkey is NULL\n");
        QATerr(QAT_F_MULTIBUFF_VALIDATE_ECX_DERIVE, QAT_R_INVALID_PRIVATE_KEY);
        return 0;
    }
    if (peerecxkey == NULL) {
        DEBUG("peerecxkey is NULL\n");
        QATerr(QAT_F_MULTIBUFF_VALIDATE_ECX_DERIVE, QAT_R_INVALID_PEER_KEY);
        return 0;
    }
    *privkey = ecxkey->privkey;
    *pubkey = peerecxkey->pubkey;

    return 1;
}

int multibuff_x25519_derive(EVP_PKEY_CTX *ctx,
                            unsigned char *key,
                            size_t *keylen)
{
    int sts = 0;
    ASYNC_JOB *job;
    x25519_derive_op_data *x25519_derive_req = NULL;
    int (*sw_fn_ptr)(EVP_PKEY_CTX *, unsigned char *, size_t *) = NULL;
    const unsigned char *privkey, *pubkey;
    int job_ret = 0;

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL.\n");
        QATerr(QAT_F_MULTIBUFF_X25519_DERIVE, QAT_R_CTX_NULL);
        return 0;
    }

    if (key == NULL) {
        *keylen = X25519_KEYLEN;
        return 1;
    }

    /* Check if we are running asynchronously. If not use the SW method */
    if ((job = ASYNC_get_current_job()) == NULL) {
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
    }

    /* Setup asynchronous notifications */
    if (!qat_setup_async_event_notification(0)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }

    while ((x25519_derive_req =
            mb_flist_x25519_derive_pop(&x25519_derive_freelist)) == NULL) {
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
    }

    DEBUG("Started request: %p\n", x25519_derive_req);
    START_RDTSC(&x25519_cycles_derive_setup);

    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */
    if (!multibuff_validate_ecx_derive(ctx, &privkey, &pubkey))
        return sts;

    x25519_derive_req->ctx = ctx;
    x25519_derive_req->key = key;
    x25519_derive_req->keylen = keylen;
    x25519_derive_req->privkey = privkey;
    x25519_derive_req->pubkey = pubkey;
    x25519_derive_req->job = job;
    x25519_derive_req->sts = &sts;
    mb_queue_x25519_derive_enqueue(&x25519_derive_queue, x25519_derive_req);
    STOP_RDTSC(&x25519_cycles_derive_setup, 1, "[X25519:derive_setup]");

    if (0 == enable_external_polling) {
        if (multibuff_kill_thread(multibuff_timer_poll_func_thread, SIGUSR1) != 0) {
            WARN("pthread_kill error\n");
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
       *keylen = X25519_KEYLEN;
       return sts;
    } else {
        WARN("Failure in derive\n");
        QATerr(QAT_F_MULTIBUFF_X25519_DERIVE, QAT_R_DERIVE_FAILURE);
        return sts;
    }

use_sw_method:
    EVP_PKEY_meth_get_derive((EVP_PKEY_METHOD *)sw_x25519_pmeth, NULL, &sw_fn_ptr);
    sts = (*sw_fn_ptr)(ctx, key, keylen);
    DEBUG("SW Finished\n");
    return sts;
}

static int multibuff_x25519_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    /* Only need to handle peer key for derivation */
    if (type == EVP_PKEY_CTRL_PEER_KEY)
        return 1;
    return -2;
}

#endif /* #ifndef OPENSSL_DISABLE_MULTIBUFF_ECX */
