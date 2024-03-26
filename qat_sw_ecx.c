/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020-2024 Intel Corporation.
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
 * @file qat_sw_ecx.c
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
#include "qat_utils.h"
#include "qat_events.h"
#include "qat_fork.h"
#ifdef QAT_OPENSSL_PROVIDER
#include "qat_prov_ecx.h"
#else
#include "qat_evp.h"
#endif
#include "qat_sw_ecx.h"
#include "qat_sw_request.h"

/* Crypto_mb includes */
#include "crypto_mb/x25519.h"

#define X25519_MULTIBUFF_BIT_DEPTH 2048
#define X25519_MULTIBUFF_KEYGEN 1
#define X25519_MULTIBUFF_DERIVE 2


/* X25519 nid */
int x25519_nid[] = {
    EVP_PKEY_X25519
};

#ifdef ENABLE_QAT_SW_ECX
void process_x25519_keygen_reqs(mb_thread_data *tlv)
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
            mb_queue_x25519_keygen_dequeue(tlv->x25519_keygen_queue)) != NULL) {
        x25519_keygen_privkey[req_num] = x25519_keygen_req_array[req_num]->privkey;
        x25519_keygen_pubkey[req_num] = x25519_keygen_req_array[req_num]->pubkey;

        req_num++;
        if (req_num == MULTIBUFF_MIN_BATCH)
            break;
    }
    local_request_no = req_num;
    DEBUG("Submitting %d keygen requests\n", local_request_no);
    num_ecx_sw_keygen_reqs += local_request_no;

    x25519_sts = mbx_x25519_public_key_mb8(x25519_keygen_pubkey,
                                           x25519_keygen_privkey);

    for (req_num = 0; req_num < local_request_no; req_num++) {
	    if (x25519_keygen_req_array[req_num]->sts != NULL) {
             if (MBX_GET_STS(x25519_sts, req_num) == MBX_STATUS_OK) {
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
        mb_flist_x25519_keygen_push(tlv->x25519_keygen_freelist,
                                    x25519_keygen_req_array[req_num]);
    }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
    mb_x25519_keygen_req_rates.req_this_period += local_request_no;
# endif

    STOP_RDTSC(&x25519_cycles_keygen_execute, 1, "[X25519:keygen_execute]");
    DEBUG("Processed Final Request\n");
}

void process_x25519_derive_reqs(mb_thread_data *tlv)
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
            mb_queue_x25519_derive_dequeue(tlv->x25519_derive_queue)) != NULL) {
        x25519_derive_privkey[req_num] = x25519_derive_req_array[req_num]->privkey;
        x25519_derive_pubkey[req_num] = x25519_derive_req_array[req_num]->pubkey;
        x25519_derive_sharedkey[req_num] = x25519_derive_req_array[req_num]->key;

        req_num++;
        if (req_num == MULTIBUFF_MIN_BATCH)
            break;
    }
    local_request_no = req_num;
    DEBUG("Submitting %d derive requests\n", local_request_no);
    num_ecx_sw_derive_reqs += local_request_no;

    x25519_sts = mbx_x25519_mb8(x25519_derive_sharedkey,
                                x25519_derive_privkey,
                                x25519_derive_pubkey);

    for (req_num = 0; req_num < local_request_no; req_num++) {
        if (MBX_GET_STS(x25519_sts, req_num) == MBX_STATUS_OK) {
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
        mb_flist_x25519_derive_push(tlv->x25519_derive_freelist,
                                    x25519_derive_req_array[req_num]);
    }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
    mb_x25519_derive_req_rates.req_this_period += local_request_no;
# endif

    STOP_RDTSC(&x25519_cycles_derive_execute, 1, "[X25519:derive_execute]");
    DEBUG("Processed Final Request\n");
}

#ifdef QAT_OPENSSL_PROVIDER
void* multibuff_x25519_keygen(void *ctx, OSSL_CALLBACK *osslcb,
                              void *cbarg)
#else
int multibuff_x25519_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
#endif
{
    ASYNC_JOB *job;
    int sts = 0, job_ret = 0;
    x25519_keygen_op_data *x25519_keygen_req = NULL;
#ifdef QAT_OPENSSL_PROVIDER
    typedef void* (*sw_prov_fn_ptr)(void *, OSSL_CALLBACK*, void*);
    sw_prov_fn_ptr sw_fn_ptr = get_default_x25519_keymgmt().gen;
    ECX_KEY *key = NULL;
#else
    int (*sw_fn_ptr)(EVP_PKEY_CTX *, EVP_PKEY *) = NULL;
    QAT_SW_ECX_KEY *key = NULL;
#endif
    unsigned char *privkey = NULL, *pubkey = NULL;
    mb_thread_data *tlv = NULL;
    static __thread int req_num = 0;

    /* Check input parameters */
    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL.\n");
        QATerr(QAT_F_MULTIBUFF_X25519_KEYGEN, QAT_R_CTX_NULL);
#ifdef QAT_OPENSSL_PROVIDER
        return NULL;
#else
        return sts;
#endif
    }

    /* QAT SW initialization fail, switching to OpenSSL. */
    if (fallback_to_openssl)
        goto use_sw_method;

    /* Check if we are running asynchronously. If not use the SW method */
    if ((job = ASYNC_get_current_job()) == NULL) {
#ifndef ENABLE_QAT_FIPS
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
#endif
    }

    /* Setup asynchronous notifications */
#ifdef ENABLE_QAT_FIPS
    if (job != NULL && !qat_setup_async_event_notification(job)) {
        DEBUG("Failed to setup async notifications.\n");
        return NULL;
    }
#else
    if (!qat_setup_async_event_notification(job)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }
#endif

    tlv = mb_check_thread_local();
    if (NULL == tlv) {
        WARN("Could not create thread local variables\n");
#ifdef ENABLE_QAT_FIPS
        return NULL;
#else
        goto use_sw_method;
#endif
    }

    while ((x25519_keygen_req =
            mb_flist_x25519_keygen_pop(tlv->x25519_keygen_freelist)) == NULL) {
#ifndef ENABLE_QAT_FIPS
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
#else
        if (job != NULL) {
            qat_wake_job(job, ASYNC_STATUS_EAGAIN);
            qat_pause_job(job, ASYNC_STATUS_EAGAIN);
        }
#endif
    }

    DEBUG("QAT SW ECX Started %p\n", x25519_keygen_req);
    START_RDTSC(&x25519_cycles_keygen_setup);

    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */
    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        WARN("Cannot allocate key.\n");
        QATerr(QAT_F_MULTIBUFF_X25519_KEYGEN, ERR_R_MALLOC_FAILURE);
#ifdef QAT_OPENSSL_PROVIDER
        return NULL;
#else
        return sts;
#endif
    }
#ifdef QAT_OPENSSL_3
    key->keylen = X25519_KEYLEN;
# if OPENSSL_VERSION_NUMBER < 0x30200000
    key->references = 1;
# else
    key->references.val = 1;
# endif
#endif
    pubkey = key->pubkey;
    privkey = key->privkey = OPENSSL_secure_malloc(X25519_KEYLEN);
    if (privkey == NULL) {
        WARN("Cannot allocate privkey.\n");
        QATerr(QAT_F_MULTIBUFF_X25519_KEYGEN, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(key);
        key = NULL;
#ifdef QAT_OPENSSL_PROVIDER
        return NULL;
#else
        return sts;
#endif
    }

    if (RAND_priv_bytes(privkey, X25519_KEYLEN) <= 0) {
        WARN("RAND function failed for privkey.\n");
        QATerr(QAT_F_MULTIBUFF_X25519_KEYGEN, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#ifndef QAT_OPENSSL_PROVIDER
    x25519_keygen_req->pkey = pkey;
#endif
    x25519_keygen_req->privkey =  privkey;
    x25519_keygen_req->pubkey =  pubkey;
    x25519_keygen_req->job = job;
    x25519_keygen_req->sts = &sts;

    mb_queue_x25519_keygen_enqueue(tlv->x25519_keygen_queue, x25519_keygen_req);
    STOP_RDTSC(&x25519_cycles_keygen_setup, 1, "[X25519:keygen_setup]");

#ifdef ENABLE_QAT_FIPS
    if (job == NULL)
        process_x25519_keygen_reqs(tlv);
#endif

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
#ifdef ENABLE_QAT_FIPS
    if (job != NULL) {
#endif
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
                sched_yield();
        } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

        DEBUG("Finished: %p status = %d\n", x25519_keygen_req, sts);
#ifdef ENABLE_QAT_FIPS
    }
#endif

    if (sts) {
#ifdef QAT_OPENSSL_PROVIDER
       return key;
#else
       EVP_PKEY_assign(pkey, EVP_PKEY_X25519, key);
       return sts;
#endif
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
#ifdef QAT_OPENSSL_PROVIDER
    return NULL;
#else
    return sts;
#endif

use_sw_method:
# ifdef QAT_OPENSSL_PROVIDER
    DEBUG("SW Finished\n");
    return sw_fn_ptr(ctx, osslcb, cbarg);
# else
    EVP_PKEY_meth_get_keygen((EVP_PKEY_METHOD *)sw_x25519_pmeth,
                             NULL, &sw_fn_ptr);
    sts = (*sw_fn_ptr)(ctx, pkey);
    DEBUG("SW Finished\n");
    return sts;
# endif
}

#ifdef QAT_OPENSSL_PROVIDER
static int multibuff_validate_ecx_derive(void *ctx,
                                         const unsigned char **privkey,
                                         const unsigned char **pubkey)
#else
static int multibuff_validate_ecx_derive(EVP_PKEY_CTX *ctx,
                                         const unsigned char **privkey,
                                         const unsigned char **pubkey)
#endif
{
#ifdef QAT_OPENSSL_PROVIDER
    QAT_ECX_CTX *ecxctx = (QAT_ECX_CTX *)ctx;

    if (ecxctx == NULL || ecxctx->key->privkey == NULL) {
        WARN("ecxctx or ecxctx->key->privkey is NULL\n");
        QATerr(QAT_F_MULTIBUFF_VALIDATE_ECX_DERIVE, QAT_R_INVALID_PRIVATE_KEY);
        return 0;
    }

    *privkey = ecxctx->key->privkey;
    *pubkey = ecxctx->peerkey->pubkey;
#else
    const QAT_SW_ECX_KEY *ecxkey, *peerecxkey;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *peerkey = NULL;

    if ((pkey = EVP_PKEY_CTX_get0_pkey(ctx)) == NULL ||
        (peerkey = EVP_PKEY_CTX_get0_peerkey(ctx)) == NULL) {
        DEBUG("ctx->pkey or ctx->peerkey is NULL\n");
        QATerr(QAT_F_MULTIBUFF_VALIDATE_ECX_DERIVE, QAT_R_KEYS_NOT_SET);
        return 0;
    }
    ecxkey = (const QAT_SW_ECX_KEY *)EVP_PKEY_get0((const EVP_PKEY *)pkey);
    peerecxkey = (const QAT_SW_ECX_KEY *)EVP_PKEY_get0((const EVP_PKEY *)peerkey);
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
#endif
    return 1;
}

#ifdef QAT_OPENSSL_PROVIDER
int multibuff_x25519_derive(void *ctx, unsigned char *key,
                            size_t *keylen, size_t outlen)
#else
int multibuff_x25519_derive(EVP_PKEY_CTX *ctx,
                            unsigned char *key,
                            size_t *keylen)
#endif
{
    ASYNC_JOB *job;
    int sts = 0, job_ret = 0;
    x25519_derive_op_data *x25519_derive_req = NULL;
#ifdef QAT_OPENSSL_PROVIDER
    typedef int (*sw_prov_fn_ptr)(void *, unsigned char*, size_t*, size_t);
    sw_prov_fn_ptr sw_fn_ptr = get_default_x25519_keyexch().derive;
#else
    int (*sw_fn_ptr)(EVP_PKEY_CTX *, unsigned char *, size_t *) = NULL;
#endif
    const unsigned char *privkey = NULL, *pubkey = NULL;
    mb_thread_data *tlv = NULL;
    static __thread int req_num = 0;

    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL.\n");
        QATerr(QAT_F_MULTIBUFF_X25519_DERIVE, QAT_R_CTX_NULL);
        return 0;
    }

    if (key == NULL) {
        *keylen = X25519_KEYLEN;
        return 1;
    }

    /* QAT SW initialization fail, switching to OpenSSL. */
    if (fallback_to_openssl)
       goto use_sw_method;

    /* Check if we are running asynchronously. If not use the SW method */
    if ((job = ASYNC_get_current_job()) == NULL) {
#ifndef ENABLE_QAT_FIPS
        DEBUG("Running synchronously using sw method\n");
        goto use_sw_method;
#endif
    }

    /* Setup asynchronous notifications */
#ifdef ENABLE_QAT_FIPS
    if (job != NULL && !qat_setup_async_event_notification(job)) {
        DEBUG("Failed to setup async notifications.\n");
        return sts;
    }
#else
    if (!qat_setup_async_event_notification(job)) {
        DEBUG("Failed to setup async notifications, using sw method\n");
        goto use_sw_method;
    }
#endif

    tlv = mb_check_thread_local();
    if (NULL == tlv) {
        WARN("Could not create thread local variables\n");
#ifndef ENABLE_QAT_FIPS
        goto use_sw_method;
#else
        return sts;
#endif
    }

    while ((x25519_derive_req =
            mb_flist_x25519_derive_pop(tlv->x25519_derive_freelist)) == NULL) {
#ifndef ENABLE_QAT_FIPS
        qat_wake_job(job, ASYNC_STATUS_EAGAIN);
        qat_pause_job(job, ASYNC_STATUS_EAGAIN);
#else
        if (job != NULL) {
            qat_wake_job(job, ASYNC_STATUS_EAGAIN);
            qat_pause_job(job, ASYNC_STATUS_EAGAIN);
        }
#endif
    }

    DEBUG("QAT SW ECX Started %p\n", x25519_derive_req);
    START_RDTSC(&x25519_cycles_derive_setup);

    /* Buffer up the requests and call the new functions when we have enough
       requests buffered up */
    if (!multibuff_validate_ecx_derive(ctx, &privkey, &pubkey))
        return sts;

    x25519_derive_req->key = key;
    x25519_derive_req->privkey = privkey;
    x25519_derive_req->pubkey = pubkey;
    x25519_derive_req->job = job;
    x25519_derive_req->sts = &sts;

    mb_queue_x25519_derive_enqueue(tlv->x25519_derive_queue, x25519_derive_req);
    STOP_RDTSC(&x25519_cycles_derive_setup, 1, "[X25519:derive_setup]");

#ifdef ENABLE_QAT_FIPS
    if (job == NULL)
        process_x25519_derive_reqs(tlv);
#endif

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
#ifdef ENABLE_QAT_FIPS
    if (job != NULL) {
#endif
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
                sched_yield();
        } while (QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

        DEBUG("Finished: %p status = %d\n", x25519_derive_req, sts);
#ifdef ENABLE_QAT_FIPS
    }
#endif

    if (sts) {
       *keylen = X25519_KEYLEN;
       return sts;
    } else {
        WARN("Failure in derive\n");
        QATerr(QAT_F_MULTIBUFF_X25519_DERIVE, QAT_R_DERIVE_FAILURE);
        return sts;
    }

use_sw_method:
# ifdef QAT_OPENSSL_PROVIDER
    DEBUG("SW Finished\n");
    return sw_fn_ptr(ctx, key, keylen, outlen);
# else
    EVP_PKEY_meth_get_derive((EVP_PKEY_METHOD *)sw_x25519_pmeth, NULL, &sw_fn_ptr);
    sts = (*sw_fn_ptr)(ctx, key, keylen);
    DEBUG("SW Finished\n");
    return sts;
# endif
}

# ifndef QAT_OPENSSL_PROVIDER
int multibuff_x25519_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    /* Only need to handle peer key for derivation */
    if (type == EVP_PKEY_CTRL_PEER_KEY)
        return 1;
    return -2;
}
# endif
#endif /*ENABLE_QAT_HW_ECX*/
