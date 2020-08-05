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
 * @file multibuff_polling.c
 *
 * This file provides an implementation for multibuff polling in QAT engine
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
#include <signal.h>
#include <time.h>

/* Local Includes */
#include "e_qat.h"
#include "multibuff_polling.h"
#include "multibuff_rsa.h"
#include "multibuff_ecx.h"
#include "qat_utils.h"
#include "e_qat_err.h"

/* OpenSSL Includes */
#include <openssl/err.h>

#define MULTIBUFF_NUM_EVENT_RETRIES 5
#define MULTIBUFF_NSEC_PER_SEC  1000000000L
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

struct timespec mb_poll_timeout_time = { 0, 10000000 }; /* default 100th sec */
unsigned int mb_timeout_level = MULTIBUFF_TIMEOUT_LEVEL_MAX;

/* RSA */
struct timespec rsa_priv_previous_time = { 0 };
struct timespec rsa_pub_previous_time = { 0 };
mb_req_rates mb_rsa_priv_req_rates = { 0 };
mb_req_rates mb_rsa_pub_req_rates = { 0 };

/* X25519 */
struct timespec x25519_keygen_previous_time = { 0 };
struct timespec x25519_derive_previous_time = { 0 };
mb_req_rates mb_x25519_keygen_req_rates = { 0 };
mb_req_rates mb_x25519_derive_req_rates = { 0 };

int multibuff_create_thread(pthread_t *pThreadId, const pthread_attr_t *attr,
                      void *(*start_func) (void *), void *pArg)
{
    return pthread_create(pThreadId, attr, start_func,(void *)pArg);
}

int multibuff_join_thread(pthread_t threadId, void **retval)
{
    return pthread_join(threadId, retval);
}

int multibuff_kill_thread(pthread_t threadId, int sig)
{
    return pthread_kill(threadId, sig);
}

#if defined(OPENSSL_ENABLE_MULTIBUFF_RSA) || defined(OPENSSL_ENABLE_MULTIBUFF_ECX)
void multibuff_set_normalized_timespec(struct timespec *ts, time_t sec, long long  nsec)
{
    while (nsec >= MULTIBUFF_NSEC_PER_SEC) {
    /*
     * The following asm() prevents the compiler from
     * optimising this loop into a modulo operation. See
     * also __iter_div_u64_rem() in include/linux/time.h
     */
        asm("" : "+rm"(nsec));
        nsec -= MULTIBUFF_NSEC_PER_SEC;
        ++sec;
     }
     while (nsec < 0) {
         asm("" : "+rm"(nsec));
         nsec += MULTIBUFF_NSEC_PER_SEC;
         --sec;
     }
     ts->tv_sec = sec;
    ts->tv_nsec = nsec;
}

static int multibuff_timespec_compare(const struct timespec *lhs,
                                      const struct timespec *rhs)
{
    if (lhs->tv_sec < rhs->tv_sec)
        return -1;
    if (lhs->tv_sec > rhs->tv_sec)
        return 1;
    return lhs->tv_nsec - rhs->tv_nsec;
}

static struct timespec multibuff_timespec_sub(struct timespec lhs,
                                              struct timespec rhs)
{
    struct timespec ts_delta;
    multibuff_set_normalized_timespec(&ts_delta, lhs.tv_sec - rhs.tv_sec,
                            lhs.tv_nsec - rhs.tv_nsec);
    return ts_delta;
}

static int multibuff_poll_check_for_timeout(struct timespec timeout_time,
                                            struct timespec previous_time,
                                            struct timespec current_time)
{
    struct timespec diff_time;

    /* If someone has changed the system time so the current time
       is smaller than the previous time or we have wrapped round then
       flag a timeout regardless */
    if (multibuff_timespec_compare(&current_time, &previous_time) < 0)
        return 1;

    /* Calculate the difference between the current time and previous
       time */
    diff_time = multibuff_timespec_sub(current_time, previous_time);

    /* Check whether the difference is bigger than or equal to
       the timeout time if it is we have timed out */
    if (multibuff_timespec_compare(&diff_time, &timeout_time) >= 0)
        return 1;

   return 0;
}
#endif

void multibuff_get_timeout_time(struct timespec *timeout_time,
                                unsigned int timeout_level)
{
    timeout_time->tv_sec = 0;
    switch (timeout_level) {
        case MULTIBUFF_TIMEOUT_LEVEL_1:
            timeout_time->tv_nsec = MULTIBUFF_NSEC_TIMEOUT_TIME_L1;
            break;
        case MULTIBUFF_TIMEOUT_LEVEL_2:
            timeout_time->tv_nsec = MULTIBUFF_NSEC_TIMEOUT_TIME_L2;
            break;
        case MULTIBUFF_TIMEOUT_LEVEL_3:
            timeout_time->tv_nsec = MULTIBUFF_NSEC_TIMEOUT_TIME_L3;
            break;
        case MULTIBUFF_TIMEOUT_LEVEL_4:
            timeout_time->tv_nsec = MULTIBUFF_NSEC_TIMEOUT_TIME_L4;
            break;
        case MULTIBUFF_TIMEOUT_LEVEL_5:
            timeout_time->tv_nsec = MULTIBUFF_NSEC_TIMEOUT_TIME_L5;
            break;
        case MULTIBUFF_TIMEOUT_LEVEL_6:
            timeout_time->tv_nsec = MULTIBUFF_NSEC_TIMEOUT_TIME_L6;
            break;
        case MULTIBUFF_TIMEOUT_LEVEL_7:
            timeout_time->tv_nsec = MULTIBUFF_NSEC_TIMEOUT_TIME_L7;
            break;
        default:
            timeout_time->tv_nsec = MULTIBUFF_NSEC_TIMEOUT_TIME_L7;
            break;
    }
}

void multibuff_init_req_rates(mb_req_rates * req_rates)
{
    req_rates->req_this_period = 0;
    multibuff_get_timeout_time(&mb_poll_timeout_time, mb_timeout_level);
    clock_gettime(CLOCK_MONOTONIC_RAW, &req_rates->previous_time);
    req_rates->current_time = req_rates->previous_time;
}

#ifdef MULTIBUFF_HEURISTIC_TIMEOUT
unsigned int multibuff_calc_timeout_level(unsigned int timeout_level)
{
    if (((mb_rsa_priv_req_rates.req_this_period < MULTIBUFF_MIN_BATCH) ||
        (mb_rsa_pub_req_rates.req_this_period < MULTIBUFF_MIN_BATCH) ||
        (mb_x25519_keygen_req_rates.req_this_period < MULTIBUFF_MIN_BATCH) ||
        (mb_x25519_derive_req_rates.req_this_period < MULTIBUFF_MIN_BATCH)) &&
        (timeout_level > MULTIBUFF_TIMEOUT_LEVEL_MIN))
        return timeout_level-1;

    if (((mb_rsa_priv_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_rsa_pub_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_x25519_keygen_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_x25519_derive_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2)) &&
        (timeout_level < MULTIBUFF_TIMEOUT_LEVEL_MAX))
        return timeout_level+1;

    return timeout_level;
}

void multibuff_update_req_timeout(mb_req_rates * req_rates)
{
    unsigned int existing_timeout_level;

    clock_gettime(CLOCK_MONOTONIC_RAW, &req_rates->current_time);
    if (multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                         req_rates->previous_time,
                                         req_rates->current_time) == 0) {
        DEBUG("Currently a timeout period has not elapsed\n");
        return;
    }
    existing_timeout_level = mb_timeout_level;
    mb_timeout_level = multibuff_calc_timeout_level(mb_timeout_level);
    if (mb_timeout_level != existing_timeout_level) {
        multibuff_get_timeout_time(&mb_poll_timeout_time, mb_timeout_level);
        DEBUG("Adjusting timeout level to: %d\n", mb_timeout_level);
    }
    req_rates->req_this_period = 0;
    req_rates->previous_time = req_rates->current_time;
}
#endif

void *multibuff_timer_poll_func(void *ih)
{
    int sig = 0;
    unsigned int eintr_count = 0;
#if defined(OPENSSL_ENABLE_MULTIBUFF_RSA) || defined(OPENSSL_ENABLE_MULTIBUFF_ECX)
    unsigned int submission_count = 0;
#endif

    multibuff_timer_poll_func_thread = pthread_self();
    cleared_to_start = 1;
    multibuff_init_req_rates(&mb_rsa_priv_req_rates);
    multibuff_init_req_rates(&mb_rsa_pub_req_rates);
    multibuff_init_req_rates(&mb_x25519_keygen_req_rates);
    multibuff_init_req_rates(&mb_x25519_derive_req_rates);

    DEBUG("timer_poll_func_thread = 0x%lx\n", multibuff_timer_poll_func_thread);

    while (multibuff_keep_polling) {
        while ((sig = sigtimedwait((const sigset_t *)&set, NULL, &mb_poll_timeout_time)) == -1 &&
                errno == EINTR &&
                eintr_count < MULTIBUFF_NUM_EVENT_RETRIES) {
            eintr_count++;
        }
        eintr_count = 0;
        if (unlikely(sig == -1)) {
            if (errno == EAGAIN || errno == EINTR) {
                /* Deal with requests less than 8 */

#ifndef OPENSSL_DISABLE_MULTIBUFF_RSA
                if (mb_queue_rsa_priv_get_size(&rsa_priv_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_RSA_priv_reqs();
                    submission_count--;
                    while ((mb_queue_rsa_priv_get_size(&rsa_priv_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_RSA_priv_reqs();
                        submission_count--;
                    }
                }
# ifdef MULTIBUFF_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_rsa_priv_req_rates);
# endif
                if (mb_queue_rsa_pub_get_size(&rsa_pub_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_RSA_pub_reqs();
                    submission_count--;
                    while ((mb_queue_rsa_pub_get_size(&rsa_pub_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_RSA_pub_reqs();
                        submission_count--;
                    }
                }
# ifdef MULTIBUFF_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_rsa_pub_req_rates);
# endif
#endif

#ifndef OPENSSL_DISABLE_MULTIBUFF_ECX
                if (mb_queue_x25519_keygen_get_size(&x25519_keygen_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_x25519_keygen_reqs();
                    submission_count--;
                    while ((mb_queue_x25519_keygen_get_size(&x25519_keygen_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_x25519_keygen_reqs();
                        submission_count--;
                    }
                }
# ifdef MULTIBUFF_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_x25519_keygen_req_rates);
# endif
                if (mb_queue_x25519_derive_get_size(&x25519_derive_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_x25519_derive_reqs();
                    submission_count--;
                    while ((mb_queue_x25519_derive_get_size(&x25519_derive_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_x25519_derive_reqs();
                        submission_count--;
                    }
                }
# ifdef MULTIBUFF_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_x25519_derive_req_rates);
# endif
#endif
                continue;
            }
        }
        DEBUG("Checking whether we have enough requests to process\n");
#ifndef OPENSSL_DISABLE_MULTIBUFF_RSA
        if (mb_queue_rsa_priv_get_size(&rsa_priv_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 private key requests */
                DEBUG("8 RSA private key requests in flight, process them\n");
                process_RSA_priv_reqs();
                submission_count--;
            } while ((mb_queue_rsa_priv_get_size(&rsa_priv_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef MULTIBUFF_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_rsa_priv_req_rates);
# endif
        }
        if (mb_queue_rsa_pub_get_size(&rsa_pub_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 public key requests */
                DEBUG("8 RSA public key requests in flight, process them\n");
                process_RSA_pub_reqs();
                submission_count--;
            } while ((mb_queue_rsa_pub_get_size(&rsa_pub_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef MULTIBUFF_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_rsa_pub_req_rates);
# endif
        }
#endif

#ifndef OPENSSL_DISABLE_MULTIBUFF_ECX
        if (mb_queue_x25519_keygen_get_size(&x25519_keygen_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 X25519 keygen requests */
                DEBUG("8 X25519 keygen requests in flight, process them\n");
                process_x25519_keygen_reqs();
                submission_count--;
            } while ((mb_queue_x25519_keygen_get_size(&x25519_keygen_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef MULTIBUFF_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_x25519_keygen_req_rates);
# endif
        }
        if (mb_queue_x25519_derive_get_size(&x25519_derive_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 X25519 derive requests */
                DEBUG("8 X25519 derive requests in flight, process them\n");
                process_x25519_derive_reqs();
                submission_count--;
            } while ((mb_queue_x25519_derive_get_size(&x25519_derive_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef MULTIBUFF_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_x25519_derive_req_rates);
# endif
        }
#endif
        DEBUG("Finished loop in the Polling Thread\n");
    }

    DEBUG("timer_poll_func finishing - pid = %d\n", getpid());
    multibuff_timer_poll_func_thread = 0;
    cleared_to_start = 0;
    return NULL;
}

int multibuff_poll()
{
    struct timespec current_time = { 0 };
#if defined(OPENSSL_ENABLE_MULTIBUFF_RSA) || defined(OPENSSL_ENABLE_MULTIBUFF_ECX)
    int snapshot_num_reqs = 0;
#endif

    if (enable_external_polling == 0) {
        WARN("External Polling is not enabled\n");
        return 0;
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, &current_time);

#ifndef OPENSSL_DISABLE_MULTIBUFF_RSA
    /* Deal with rsa private key requests */
    snapshot_num_reqs = mb_queue_rsa_priv_get_size(&rsa_priv_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_RSA_priv_reqs();
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &rsa_priv_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
            snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
            multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                             rsa_priv_previous_time,
                                             current_time) == 1) {
            process_RSA_priv_reqs();
            clock_gettime(CLOCK_MONOTONIC_RAW, &rsa_priv_previous_time);
        }
    }
    /* Deal with rsa public key requests */
    snapshot_num_reqs = mb_queue_rsa_pub_get_size(&rsa_pub_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_RSA_pub_reqs();
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &rsa_pub_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
            snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
            multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                             rsa_pub_previous_time,
                                             current_time) == 1) {
            process_RSA_pub_reqs();
            clock_gettime(CLOCK_MONOTONIC_RAW, &rsa_pub_previous_time);
        }
    }
#endif

#ifndef OPENSSL_DISABLE_MULTIBUFF_ECX
    /* Deal with X25519 Keygen requests */
    snapshot_num_reqs = mb_queue_x25519_keygen_get_size(&x25519_keygen_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_x25519_keygen_reqs();
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &x25519_keygen_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
                snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
                multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                                 x25519_keygen_previous_time,
                                                 current_time) == 1) {
            process_x25519_keygen_reqs();
            clock_gettime(CLOCK_MONOTONIC_RAW, &x25519_keygen_previous_time);
        }
    }

    /* Deal with X25519 Derive requests */
    snapshot_num_reqs = mb_queue_x25519_derive_get_size(&x25519_derive_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_x25519_derive_reqs();
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &x25519_derive_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
                snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
                multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                                 x25519_derive_previous_time,
                                                 current_time) == 1) {
            process_x25519_derive_reqs();
            clock_gettime(CLOCK_MONOTONIC_RAW, &x25519_derive_previous_time);
        }
    }
#endif

    return 1;
}
