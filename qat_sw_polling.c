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
 * @file qat_sw_polling.c
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
#include "qat_sw_polling.h"
#include "qat_sw_rsa.h"
#include "qat_sw_ecx.h"
#include "qat_sw_ec.h"
#include "qat_utils.h"

/* OpenSSL Includes */
#include <openssl/err.h>

#define QAT_SW_NUM_EVENT_RETRIES 5
#define QAT_SW_NSEC_PER_SEC  1000000000L
#define QAT_SW_TIMEOUT_LEVEL_1 1
#define QAT_SW_TIMEOUT_LEVEL_2 2
#define QAT_SW_TIMEOUT_LEVEL_3 3
#define QAT_SW_TIMEOUT_LEVEL_4 4
#define QAT_SW_TIMEOUT_LEVEL_5 5
#define QAT_SW_TIMEOUT_LEVEL_6 6
#define QAT_SW_TIMEOUT_LEVEL_7 7
#define QAT_SW_TIMEOUT_LEVEL_MIN QAT_SW_TIMEOUT_LEVEL_1
#define QAT_SW_TIMEOUT_LEVEL_MAX QAT_SW_TIMEOUT_LEVEL_7
#define QAT_SW_POLL_TIMEOUT_NSEC_L1 200000000
#define QAT_SW_POLL_TIMEOUT_NSEC_L2 100000000
#define QAT_SW_POLL_TIMEOUT_NSEC_L3 50000000
#define QAT_SW_POLL_TIMEOUT_NSEC_L4 25000000
#define QAT_SW_POLL_TIMEOUT_NSEC_L5 16666667
#define QAT_SW_POLL_TIMEOUT_NSEC_L6 12500000
#define QAT_SW_POLL_TIMEOUT_NSEC_L7 10000000

/* default 100th sec */
#ifndef QAT_SW_POLL_TIMEOUT_NSEC
# define QAT_SW_POLL_TIMEOUT_NSEC QAT_SW_POLL_TIMEOUT_NSEC_L7
#endif

struct timespec mb_poll_timeout_time = { 0, QAT_SW_POLL_TIMEOUT_NSEC };
unsigned int mb_timeout_level = QAT_SW_TIMEOUT_LEVEL_MAX;

/* RSA */
struct timespec rsa2k_priv_previous_time = { 0 };
struct timespec rsa2k_pub_previous_time = { 0 };
struct timespec rsa3k_priv_previous_time = { 0 };
struct timespec rsa3k_pub_previous_time = { 0 };
struct timespec rsa4k_priv_previous_time = { 0 };
struct timespec rsa4k_pub_previous_time = { 0 };
mb_req_rates mb_rsa2k_priv_req_rates = { 0 };
mb_req_rates mb_rsa2k_pub_req_rates = { 0 };
mb_req_rates mb_rsa3k_priv_req_rates = { 0 };
mb_req_rates mb_rsa3k_pub_req_rates = { 0 };
mb_req_rates mb_rsa4k_priv_req_rates = { 0 };
mb_req_rates mb_rsa4k_pub_req_rates = { 0 };

/* X25519 */
struct timespec x25519_keygen_previous_time = { 0 };
struct timespec x25519_derive_previous_time = { 0 };
mb_req_rates mb_x25519_keygen_req_rates = { 0 };
mb_req_rates mb_x25519_derive_req_rates = { 0 };

/* ECDSA p256 */
struct timespec ecdsap256_sign_previous_time = { 0 };
struct timespec ecdsap256_sign_setup_previous_time = { 0 };
struct timespec ecdsap256_sign_sig_previous_time = { 0 };
mb_req_rates mb_ecdsap256_sign_req_rates = { 0 };
mb_req_rates mb_ecdsap256_sign_setup_req_rates = { 0 };
mb_req_rates mb_ecdsap256_sign_sig_req_rates = { 0 };

/* ECDSA p384 */
struct timespec ecdsap384_sign_previous_time = { 0 };
struct timespec ecdsap384_sign_setup_previous_time = { 0 };
struct timespec ecdsap384_sign_sig_previous_time = { 0 };
mb_req_rates mb_ecdsap384_sign_req_rates = { 0 };
mb_req_rates mb_ecdsap384_sign_setup_req_rates = { 0 };
mb_req_rates mb_ecdsap384_sign_sig_req_rates = { 0 };

/* ECDH p256 */
struct timespec ecdhp256_keygen_previous_time = { 0 };
struct timespec ecdhp256_compute_previous_time = { 0 };
mb_req_rates mb_ecdhp256_keygen_req_rates = { 0 };
mb_req_rates mb_ecdhp256_compute_req_rates = { 0 };

/* ECDH p384 */
struct timespec ecdhp384_keygen_previous_time = { 0 };
struct timespec ecdhp384_compute_previous_time = { 0 };
mb_req_rates mb_ecdhp384_keygen_req_rates = { 0 };
mb_req_rates mb_ecdhp384_compute_req_rates = { 0 };

#if defined(ENABLE_QAT_SW_RSA) || defined(ENABLE_QAT_SW_ECX) || defined(ENABLE_QAT_SW_ECDSA) || defined(ENABLE_QAT_SW_ECDH)
void multibuff_set_normalized_timespec(struct timespec *ts, time_t sec, long long  nsec)
{
    while (nsec >= QAT_SW_NSEC_PER_SEC) {
    /*
     * The following asm() prevents the compiler from
     * optimising this loop into a modulo operation. See
     * also __iter_div_u64_rem() in include/linux/time.h
     */
        asm("" : "+rm"(nsec));
        nsec -= QAT_SW_NSEC_PER_SEC;
        ++sec;
     }
     while (nsec < 0) {
         asm("" : "+rm"(nsec));
         nsec += QAT_SW_NSEC_PER_SEC;
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
        case QAT_SW_TIMEOUT_LEVEL_1:
            timeout_time->tv_nsec = QAT_SW_POLL_TIMEOUT_NSEC_L1;
            break;
        case QAT_SW_TIMEOUT_LEVEL_2:
            timeout_time->tv_nsec = QAT_SW_POLL_TIMEOUT_NSEC_L2;
            break;
        case QAT_SW_TIMEOUT_LEVEL_3:
            timeout_time->tv_nsec = QAT_SW_POLL_TIMEOUT_NSEC_L3;
            break;
        case QAT_SW_TIMEOUT_LEVEL_4:
            timeout_time->tv_nsec = QAT_SW_POLL_TIMEOUT_NSEC_L4;
            break;
        case QAT_SW_TIMEOUT_LEVEL_5:
            timeout_time->tv_nsec = QAT_SW_POLL_TIMEOUT_NSEC_L5;
            break;
        case QAT_SW_TIMEOUT_LEVEL_6:
            timeout_time->tv_nsec = QAT_SW_POLL_TIMEOUT_NSEC_L6;
            break;
        case QAT_SW_TIMEOUT_LEVEL_7:
            timeout_time->tv_nsec = QAT_SW_POLL_TIMEOUT_NSEC_L7;
            break;
        default:
            timeout_time->tv_nsec = QAT_SW_POLL_TIMEOUT_NSEC_L7;
            break;
    }
}

#ifdef QAT_SW_HEURISTIC_TIMEOUT
void multibuff_init_req_rates(mb_req_rates * req_rates)
{
    req_rates->req_this_period = 0;
    multibuff_get_timeout_time(&mb_poll_timeout_time, mb_timeout_level);
    clock_gettime(CLOCK_MONOTONIC_RAW, &req_rates->previous_time);
    req_rates->current_time = req_rates->previous_time;
}

unsigned int multibuff_calc_timeout_level(unsigned int timeout_level)
{
    if (((mb_rsa2k_priv_req_rates.req_this_period < MULTIBUFF_MIN_BATCH) ||
        (mb_rsa2k_pub_req_rates.req_this_period < MULTIBUFF_MIN_BATCH) ||
        (mb_rsa3k_priv_req_rates.req_this_period < MULTIBUFF_MIN_BATCH) ||
        (mb_rsa3k_pub_req_rates.req_this_period < MULTIBUFF_MIN_BATCH) ||
        (mb_rsa4k_priv_req_rates.req_this_period < MULTIBUFF_MIN_BATCH) ||
        (mb_rsa4k_pub_req_rates.req_this_period < MULTIBUFF_MIN_BATCH) ||
        (mb_x25519_keygen_req_rates.req_this_period < MULTIBUFF_MIN_BATCH) ||
        (mb_x25519_derive_req_rates.req_this_period < MULTIBUFF_MIN_BATCH) ||
        (mb_ecdsap256_sign_req_rates.req_this_period  < MULTIBUFF_MIN_BATCH) ||
        (mb_ecdsap256_sign_setup_req_rates.req_this_period  < MULTIBUFF_MIN_BATCH) ||
        (mb_ecdsap256_sign_sig_req_rates.req_this_period  < MULTIBUFF_MIN_BATCH) ||
        (mb_ecdsap384_sign_req_rates.req_this_period  < MULTIBUFF_MIN_BATCH) ||
        (mb_ecdsap384_sign_setup_req_rates.req_this_period  < MULTIBUFF_MIN_BATCH) ||
        (mb_ecdsap384_sign_sig_req_rates.req_this_period  < MULTIBUFF_MIN_BATCH) ||
        (mb_ecdhp256_keygen_req_rates.req_this_period  < MULTIBUFF_MIN_BATCH) ||
        (mb_ecdhp256_compute_req_rates.req_this_period  < MULTIBUFF_MIN_BATCH)||
        (mb_ecdhp384_keygen_req_rates.req_this_period  < MULTIBUFF_MIN_BATCH) ||
        (mb_ecdhp384_compute_req_rates.req_this_period  < MULTIBUFF_MIN_BATCH)) &&
        (timeout_level > MULTIBUFF_TIMEOUT_LEVEL_MIN))
        return timeout_level-1;

    if (((mb_rsa2k_priv_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_rsa2k_pub_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_rsa3k_priv_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_rsa3k_pub_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_rsa4k_priv_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_rsa4k_pub_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_x25519_keygen_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_x25519_derive_req_rates.req_this_period > MULTIBUFF_MAX_BATCH*2) ||
        (mb_ecdsap256_sign_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_ecdsap256_sign_setup_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_ecdsap256_sign_sig_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_ecdhp256_keygen_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_ecdhp256_compute_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_ecdsap384_sign_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_ecdsap384_sign_setup_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_ecdsap384_sign_sig_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_ecdhp256_keygen_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_ecdhp256_compute_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2)||
        (mb_ecdhp384_keygen_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2) ||
        (mb_ecdhp384_compute_req_rates.req_this_period  > MULTIBUFF_MAX_BATCH*2)) &&
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

void *multibuff_timer_poll_func(void *thread_ptr)
{
    int sig = 0;
    unsigned int eintr_count = 0;
    mb_thread_data *tlv = (mb_thread_data *)thread_ptr;
#if defined(ENABLE_QAT_SW_RSA) || defined(ENABLE_QAT_SW_ECX) || defined(ENABLE_QAT_SW_ECDSA) || defined(ENABLE_QAT_SW_ECDH)
    unsigned int submission_count = 0;
#endif

    cleared_to_start = 1;
#ifdef QAT_SW_HEURISTIC_TIMEOUT
    multibuff_init_req_rates(&mb_rsa2k_priv_req_rates);
    multibuff_init_req_rates(&mb_rsa2k_pub_req_rates);
    multibuff_init_req_rates(&mb_x25519_keygen_req_rates);
    multibuff_init_req_rates(&mb_x25519_derive_req_rates);
    multibuff_init_req_rates(&mb_ecdsap256_sign_req_rates);
    multibuff_init_req_rates(&mb_ecdsap256_sign_setup_req_rates);
    multibuff_init_req_rates(&mb_ecdsap256_sign_sig_req_rates);
    multibuff_init_req_rates(&mb_ecdsap384_sign_req_rates);
    multibuff_init_req_rates(&mb_ecdsap384_sign_setup_req_rates);
    multibuff_init_req_rates(&mb_ecdsap384_sign_sig_req_rates);
    multibuff_init_req_rates(&mb_ecdhp256_keygen_req_rates);
    multibuff_init_req_rates(&mb_ecdhp256_compute_req_rates);
    multibuff_init_req_rates(&mb_ecdhp384_keygen_req_rates);
    multibuff_init_req_rates(&mb_ecdhp384_compute_req_rates);
    multibuff_init_req_rates(&mb_rsa3k_priv_req_rates);
    multibuff_init_req_rates(&mb_rsa3k_pub_req_rates);
    multibuff_init_req_rates(&mb_rsa4k_priv_req_rates);
    multibuff_init_req_rates(&mb_rsa4k_pub_req_rates);
#endif

    DEBUG("Polling Timeout %ld tlv %p\n", mb_poll_timeout_time.tv_nsec, tlv);

    while (multibuff_keep_polling) {
        while ((sig = sigtimedwait((const sigset_t *)&tlv->set, NULL, &mb_poll_timeout_time)) == -1 &&
                errno == EINTR &&
                eintr_count < QAT_SW_NUM_EVENT_RETRIES) {
            eintr_count++;
        }
        eintr_count = 0;
        if (unlikely(sig == -1)) {
            if (errno == EAGAIN || errno == EINTR) {
                /* Deal with requests less than 8 */

#ifdef ENABLE_QAT_SW_RSA
                if (mb_queue_rsa2k_priv_get_size(tlv->rsa2k_priv_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_RSA_priv_reqs(tlv, RSA_2K_LENGTH);
                    submission_count--;
                    while ((mb_queue_rsa2k_priv_get_size(tlv->rsa2k_priv_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_RSA_priv_reqs(tlv, RSA_2K_LENGTH);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_rsa2k_priv_req_rates);
# endif
                if (mb_queue_rsa2k_pub_get_size(tlv->rsa2k_pub_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_RSA_pub_reqs(tlv, RSA_2K_LENGTH);
                    submission_count--;
                    while ((mb_queue_rsa2k_pub_get_size(tlv->rsa2k_pub_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_RSA_pub_reqs(tlv, RSA_2K_LENGTH);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_rsa2k_pub_req_rates);
# endif
                if (mb_queue_rsa3k_priv_get_size(tlv->rsa3k_priv_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_RSA_priv_reqs(tlv, RSA_3K_LENGTH);
                    submission_count--;
                    while ((mb_queue_rsa3k_priv_get_size(tlv->rsa3k_priv_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_RSA_priv_reqs(tlv, RSA_3K_LENGTH);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_rsa3k_priv_req_rates);
# endif
                if (mb_queue_rsa3k_pub_get_size(tlv->rsa3k_pub_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_RSA_pub_reqs(tlv, RSA_3K_LENGTH);
                    submission_count--;
                    while ((mb_queue_rsa3k_pub_get_size(tlv->rsa3k_pub_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_RSA_pub_reqs(tlv, RSA_3K_LENGTH);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_rsa3k_pub_req_rates);
# endif
                if (mb_queue_rsa4k_priv_get_size(tlv->rsa4k_priv_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_RSA_priv_reqs(tlv, RSA_4K_LENGTH);
                    submission_count--;
                    while ((mb_queue_rsa4k_priv_get_size(tlv->rsa4k_priv_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_RSA_priv_reqs(tlv, RSA_4K_LENGTH);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_rsa4k_priv_req_rates);
# endif
                if (mb_queue_rsa4k_pub_get_size(tlv->rsa4k_pub_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_RSA_pub_reqs(tlv, RSA_4K_LENGTH);
                    submission_count--;
                    while ((mb_queue_rsa4k_pub_get_size(tlv->rsa4k_pub_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_RSA_pub_reqs(tlv, RSA_4K_LENGTH);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_rsa4k_pub_req_rates);
# endif
#endif

#ifdef ENABLE_QAT_SW_ECX
                if (mb_queue_x25519_keygen_get_size(tlv->x25519_keygen_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_x25519_keygen_reqs(tlv);
                    submission_count--;
                    while ((mb_queue_x25519_keygen_get_size(tlv->x25519_keygen_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_x25519_keygen_reqs(tlv);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_x25519_keygen_req_rates);
# endif
                if (mb_queue_x25519_derive_get_size(tlv->x25519_derive_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_x25519_derive_reqs(tlv);
                    submission_count--;
                    while ((mb_queue_x25519_derive_get_size(tlv->x25519_derive_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_x25519_derive_reqs(tlv);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_x25519_derive_req_rates);
# endif
#endif

#ifdef ENABLE_QAT_SW_ECDSA
                if (mb_queue_ecdsap256_sign_get_size(tlv->ecdsap256_sign_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_ecdsa_sign_reqs(tlv, EC_P256_LENGTH);
                    submission_count--;
                    while ((mb_queue_ecdsap256_sign_get_size(tlv->ecdsap256_sign_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_ecdsa_sign_reqs(tlv, EC_P256_LENGTH);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_ecdsap256_sign_req_rates);
# endif
                if (mb_queue_ecdsap256_sign_setup_get_size(tlv->ecdsap256_sign_setup_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_ecdsa_sign_setup_reqs(tlv, EC_P256_LENGTH);
                    submission_count--;
                    while ((mb_queue_ecdsap256_sign_setup_get_size(tlv->ecdsap256_sign_setup_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_ecdsa_sign_setup_reqs(tlv, EC_P256_LENGTH);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_ecdsap256_sign_setup_req_rates);
# endif
                if (mb_queue_ecdsap256_sign_sig_get_size(tlv->ecdsap256_sign_sig_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_ecdsa_sign_sig_reqs(tlv, EC_P256_LENGTH);
                    submission_count--;
                    while ((mb_queue_ecdsap256_sign_sig_get_size(tlv->ecdsap256_sign_sig_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_ecdsa_sign_sig_reqs(tlv, EC_P256_LENGTH);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_ecdsap256_sign_sig_req_rates);
# endif
                if (mb_queue_ecdsap384_sign_get_size(tlv->ecdsap384_sign_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_ecdsa_sign_reqs(tlv, EC_P384_LENGTH);
                    submission_count--;
                    while ((mb_queue_ecdsap384_sign_get_size(tlv->ecdsap384_sign_queue) >= MULTIBUFF_MIN_BATCH) &&
                            (submission_count > 0)) {
                        process_ecdsa_sign_reqs(tlv, EC_P384_LENGTH);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_ecdsap384_sign_req_rates);
# endif
                if (mb_queue_ecdsap384_sign_setup_get_size(tlv->ecdsap384_sign_setup_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_ecdsa_sign_setup_reqs(tlv, EC_P384_LENGTH);
                    submission_count--;
                    while ((mb_queue_ecdsap384_sign_setup_get_size(tlv->ecdsap384_sign_setup_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_ecdsa_sign_setup_reqs(tlv, EC_P384_LENGTH);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_ecdsap384_sign_setup_req_rates);
# endif
                if (mb_queue_ecdsap384_sign_sig_get_size(tlv->ecdsap384_sign_sig_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_ecdsa_sign_sig_reqs(tlv, EC_P384_LENGTH);
                    submission_count--;
                    while ((mb_queue_ecdsap384_sign_sig_get_size(tlv->ecdsap384_sign_sig_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_ecdsa_sign_sig_reqs(tlv, EC_P384_LENGTH);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_ecdsap384_sign_sig_req_rates);
# endif
#endif

#ifdef ENABLE_QAT_SW_ECDH
                if (mb_queue_ecdhp256_keygen_get_size(tlv->ecdhp256_keygen_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_ecdh_keygen_reqs(tlv, EC_P256_LENGTH);
                    submission_count--;
                    while ((mb_queue_ecdhp256_keygen_get_size(tlv->ecdhp256_keygen_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_ecdh_keygen_reqs(tlv, EC_P256_LENGTH);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_ecdhp256_keygen_req_rates);
# endif
                if (mb_queue_ecdhp256_compute_get_size(tlv->ecdhp256_compute_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_ecdh_compute_reqs(tlv, EC_P256_LENGTH);
                    submission_count--;
                    while ((mb_queue_ecdhp256_compute_get_size(tlv->ecdhp256_compute_queue) >= MULTIBUFF_MIN_BATCH) &&
                           (submission_count > 0)) {
                        process_ecdh_compute_reqs(tlv, EC_P256_LENGTH);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_ecdhp256_compute_req_rates);
# endif
                if (mb_queue_ecdhp384_keygen_get_size(tlv->ecdhp384_keygen_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_ecdh_keygen_reqs(tlv, EC_P384_LENGTH);
                    submission_count--;
                    while ((mb_queue_ecdhp384_keygen_get_size(tlv->ecdhp384_keygen_queue) >= MULTIBUFF_MIN_BATCH) &&
                            (submission_count > 0)) {
                        process_ecdh_keygen_reqs(tlv, EC_P384_LENGTH);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_ecdhp384_keygen_req_rates);
# endif
                if (mb_queue_ecdhp384_compute_get_size(tlv->ecdhp384_compute_queue) > 0) {
                    submission_count = MULTIBUFF_MAX_SUBMISSIONS;
                    process_ecdh_compute_reqs(tlv, EC_P384_LENGTH);
                    submission_count--;
                    while ((mb_queue_ecdhp384_compute_get_size(tlv->ecdhp384_compute_queue) >= MULTIBUFF_MIN_BATCH) &&
                            (submission_count > 0)) {
                        process_ecdh_compute_reqs(tlv, EC_P384_LENGTH);
                        submission_count--;
                    }
                }
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_ecdhp384_compute_req_rates);
# endif
#endif
                continue;
            }
        }

        DEBUG("Checking whether we have enough requests to process\n");
#ifdef ENABLE_QAT_SW_ECX
        if (mb_queue_x25519_keygen_get_size(tlv->x25519_keygen_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 X25519 keygen requests */
                DEBUG("8 X25519 keygen requests in flight, process them\n");
                process_x25519_keygen_reqs(tlv);
                submission_count--;
            } while ((mb_queue_x25519_keygen_get_size(tlv->x25519_keygen_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_x25519_keygen_req_rates);
# endif
        }

        if (mb_queue_x25519_derive_get_size(tlv->x25519_derive_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 X25519 derive requests */
                DEBUG("8 X25519 derive requests in flight, process them\n");
                process_x25519_derive_reqs(tlv);
                submission_count--;
            } while ((mb_queue_x25519_derive_get_size(tlv->x25519_derive_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_x25519_derive_req_rates);
# endif
        }
#endif

#ifdef ENABLE_QAT_SW_ECDSA
        if (mb_queue_ecdsap256_sign_get_size(tlv->ecdsap256_sign_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 ECDSA p256 Sign requests */
                DEBUG("8 ECDSA p256 Sign requests in flight, process them\n");
                process_ecdsa_sign_reqs(tlv, EC_P256_LENGTH);
                submission_count--;
            } while ((mb_queue_ecdsap256_sign_get_size(tlv->ecdsap256_sign_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_ecdsap256_sign_req_rates);
# endif
        }
        if (mb_queue_ecdsap256_sign_setup_get_size(tlv->ecdsap256_sign_setup_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 ECDSA p256 sign setup requests */
                DEBUG("8 ECDSA p256 sign setup requests in flight, process them\n");
                process_ecdsa_sign_setup_reqs(tlv, EC_P256_LENGTH);
                submission_count--;
            } while ((mb_queue_ecdsap256_sign_setup_get_size(tlv->ecdsap256_sign_setup_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_ecdsap256_sign_setup_req_rates);
# endif
        }
        if (mb_queue_ecdsap256_sign_sig_get_size(tlv->ecdsap256_sign_sig_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 ECDSA p256 sign sig requests */
                DEBUG("8 ECDSA p256 sign sig requests in flight, process them\n");
                process_ecdsa_sign_sig_reqs(tlv, EC_P256_LENGTH);
                submission_count--;
            } while ((mb_queue_ecdsap256_sign_sig_get_size(tlv->ecdsap256_sign_sig_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_ecdsap256_sign_sig_req_rates);
# endif
        }
        if (mb_queue_ecdsap384_sign_get_size(tlv->ecdsap384_sign_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 ECDSA p384 Sign requests */
                DEBUG("8 ECDSA p384 Sign requests in flight, process them\n");
                process_ecdsa_sign_reqs(tlv, EC_P384_LENGTH);
                submission_count--;
                } while ((mb_queue_ecdsap384_sign_get_size(tlv->ecdsap384_sign_queue) >= MULTIBUFF_MIN_BATCH) &&
                        (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_ecdsap384_sign_req_rates);
# endif
        }
        if (mb_queue_ecdsap384_sign_setup_get_size(tlv->ecdsap384_sign_setup_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 ECDSA p384 sign setup requests */
                DEBUG("8 ECDSA p384 sign setup requests in flight, process them\n");
                process_ecdsa_sign_setup_reqs(tlv, EC_P384_LENGTH);
                submission_count--;
                } while ((mb_queue_ecdsap384_sign_setup_get_size(tlv->ecdsap384_sign_setup_queue) >= MULTIBUFF_MIN_BATCH) &&
                        (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_ecdsap384_sign_setup_req_rates);
# endif
        }
        if (mb_queue_ecdsap384_sign_sig_get_size(tlv->ecdsap384_sign_sig_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 ECDSA p384 sign sig requests */
                DEBUG("8 ECDSA p384 sign sig requests in flight, process them\n");
                process_ecdsa_sign_sig_reqs(tlv, EC_P384_LENGTH);
                submission_count--;
                } while ((mb_queue_ecdsap384_sign_sig_get_size(tlv->ecdsap384_sign_sig_queue) >= MULTIBUFF_MIN_BATCH) &&
                        (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
                multibuff_update_req_timeout(&mb_ecdsap384_sign_sig_req_rates);
# endif
        }
#endif

#ifdef ENABLE_QAT_SW_ECDH
        if (mb_queue_ecdhp256_keygen_get_size(tlv->ecdhp256_keygen_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 ECDH p256 keygen requests */
                DEBUG("8 ECDH p256 keygen requests in flight, process them\n");
                process_ecdh_keygen_reqs(tlv, EC_P256_LENGTH);
                submission_count--;
            } while ((mb_queue_ecdhp256_keygen_get_size(tlv->ecdhp256_keygen_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_ecdhp256_keygen_req_rates);
# endif
        }
        if (mb_queue_ecdhp256_compute_get_size(tlv->ecdhp256_compute_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 ECDH p256 compute requests */
                DEBUG("8 ECDH p256 compute requests in flight, process them\n");
                process_ecdh_compute_reqs(tlv, EC_P256_LENGTH);
                submission_count--;
            } while ((mb_queue_ecdhp256_compute_get_size(tlv->ecdhp256_compute_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_ecdhp256_compute_req_rates);
# endif
        }
        if (mb_queue_ecdhp384_keygen_get_size(tlv->ecdhp384_keygen_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 ECDH p384 keygen requests */
                DEBUG("8 ECDH p384 keygen requests in flight, process them\n");
                process_ecdh_keygen_reqs(tlv, EC_P384_LENGTH);
                submission_count--;
            } while ((mb_queue_ecdhp384_keygen_get_size(tlv->ecdhp384_keygen_queue) >= MULTIBUFF_MIN_BATCH) &&
                    (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_ecdhp384_keygen_req_rates);
# endif
        }
        if (mb_queue_ecdhp384_compute_get_size(tlv->ecdhp384_compute_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 ECDH p384 compute requests */
                DEBUG("8 ECDH p384 compute requests in flight, process them\n");
                process_ecdh_compute_reqs(tlv, EC_P384_LENGTH);
                submission_count--;
            } while ((mb_queue_ecdhp384_compute_get_size(tlv->ecdhp384_compute_queue) >= MULTIBUFF_MIN_BATCH) &&
                    (submission_count > 0));

# ifdef QAT_SW_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_ecdhp384_compute_req_rates);
#endif
        }
#endif

#ifdef ENABLE_QAT_SW_RSA
        if (mb_queue_rsa2k_priv_get_size(tlv->rsa2k_priv_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 private key requests */
                DEBUG("8 RSA2K private key requests in flight, process them\n");
                process_RSA_priv_reqs(tlv, RSA_2K_LENGTH);
                submission_count--;
            } while ((mb_queue_rsa2k_priv_get_size(tlv->rsa2k_priv_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_rsa2k_priv_req_rates);
# endif
        }
        if (mb_queue_rsa2k_pub_get_size(tlv->rsa2k_pub_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 public key requests */
                DEBUG("8 RSA2K public key requests in flight, process them\n");
                process_RSA_pub_reqs(tlv, RSA_2K_LENGTH);
                submission_count--;
            } while ((mb_queue_rsa2k_pub_get_size(tlv->rsa2k_pub_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_rsa2k_pub_req_rates);
# endif
        }
        if (mb_queue_rsa3k_priv_get_size(tlv->rsa3k_priv_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 private key requests */
                DEBUG("8 RSA3k private key requests in flight, process them\n");
                process_RSA_priv_reqs(tlv, RSA_3K_LENGTH);
                submission_count--;
            } while ((mb_queue_rsa3k_priv_get_size(tlv->rsa3k_priv_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_rsa3k_priv_req_rates);
# endif
        }
        if (mb_queue_rsa3k_pub_get_size(tlv->rsa3k_pub_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 public key requests */
                DEBUG("8 RSA3k public key requests in flight, process them\n");
                process_RSA_pub_reqs(tlv, RSA_3K_LENGTH);
                submission_count--;
            } while ((mb_queue_rsa3k_pub_get_size(tlv->rsa3k_pub_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_rsa3k_pub_req_rates);
# endif
        }
        if (mb_queue_rsa4k_priv_get_size(tlv->rsa4k_priv_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 private key requests */
                DEBUG("8 RSA4k private key requests in flight, process them\n");
                process_RSA_priv_reqs(tlv, RSA_4K_LENGTH);
                submission_count--;
            } while ((mb_queue_rsa4k_priv_get_size(tlv->rsa4k_priv_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_rsa4k_priv_req_rates);
# endif
        }
        if (mb_queue_rsa4k_pub_get_size(tlv->rsa4k_pub_queue) >= MULTIBUFF_MAX_BATCH) {
            submission_count = MULTIBUFF_MAX_SUBMISSIONS;
            do {
                /* Deal with 8 public key requests */
                DEBUG("8 RSA4k public key requests in flight, process them\n");
                process_RSA_pub_reqs(tlv, RSA_4K_LENGTH);
                submission_count--;
            } while ((mb_queue_rsa4k_pub_get_size(tlv->rsa4k_pub_queue) >= MULTIBUFF_MIN_BATCH) &&
                     (submission_count > 0));
# ifdef QAT_SW_HEURISTIC_TIMEOUT
            multibuff_update_req_timeout(&mb_rsa4k_pub_req_rates);
# endif
        }
#endif

        DEBUG("Finished loop in the Polling Thread\n");
    }

    DEBUG("timer_poll_func finishing - pid = %d\n", getpid());
    cleared_to_start = 0;
    return NULL;
}

int multibuff_poll()
{
    struct timespec current_time = { 0 };
#if defined(ENABLE_QAT_SW_RSA) || defined(ENABLE_QAT_SW_ECX) || defined(ENABLE_QAT_SW_ECDSA) || defined(ENABLE_QAT_SW_ECDH)
    int snapshot_num_reqs = 0;
#endif

    if (enable_external_polling == 0) {
        WARN("External Polling is not enabled\n");
        return 0;
    }

    if (mb_tlv == NULL)
        return 1; /* Do nothing as there are no QAT_SW Requests */

    clock_gettime(CLOCK_MONOTONIC_RAW, &current_time);

#ifdef ENABLE_QAT_SW_ECX
    /* Deal with X25519 Keygen requests */
    snapshot_num_reqs = mb_queue_x25519_keygen_get_size(mb_tlv->x25519_keygen_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_x25519_keygen_reqs(mb_tlv);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &x25519_keygen_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
                snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
                multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                                 x25519_keygen_previous_time,
                                                 current_time) == 1) {
            process_x25519_keygen_reqs(mb_tlv);
            clock_gettime(CLOCK_MONOTONIC_RAW, &x25519_keygen_previous_time);
        }
    }

    /* Deal with X25519 Derive requests */
    snapshot_num_reqs = mb_queue_x25519_derive_get_size(mb_tlv->x25519_derive_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_x25519_derive_reqs(mb_tlv);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &x25519_derive_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
                snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
                multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                                 x25519_derive_previous_time,
                                                 current_time) == 1) {
            process_x25519_derive_reqs(mb_tlv);
            clock_gettime(CLOCK_MONOTONIC_RAW, &x25519_derive_previous_time);
        }
    }
#endif

#ifdef ENABLE_QAT_SW_ECDSA
    /* Deal with ECDSA p256 sign requests */
    snapshot_num_reqs = mb_queue_ecdsap256_sign_get_size(mb_tlv->ecdsap256_sign_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_ecdsa_sign_reqs(mb_tlv, EC_P256_LENGTH);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &ecdsap256_sign_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
                snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
                multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                                 ecdsap256_sign_previous_time,
                                                 current_time) == 1) {
            process_ecdsa_sign_reqs(mb_tlv, EC_P256_LENGTH);
            clock_gettime(CLOCK_MONOTONIC_RAW, &ecdsap256_sign_previous_time);
        }
    }

    /* Deal with ECDSA p256 sign setup requests */
    snapshot_num_reqs = mb_queue_ecdsap256_sign_setup_get_size(mb_tlv->ecdsap256_sign_setup_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_ecdsa_sign_setup_reqs(mb_tlv, EC_P256_LENGTH);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &ecdsap256_sign_setup_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
                snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
                multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                                 ecdsap256_sign_setup_previous_time,
                                                 current_time) == 1) {
            process_ecdsa_sign_setup_reqs(mb_tlv, EC_P256_LENGTH);
            clock_gettime(CLOCK_MONOTONIC_RAW, &ecdsap256_sign_setup_previous_time);
        }
    }

    /* Deal with ECDSA p256 sign sig requests */
    snapshot_num_reqs = mb_queue_ecdsap256_sign_sig_get_size(mb_tlv->ecdsap256_sign_sig_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_ecdsa_sign_sig_reqs(mb_tlv, EC_P256_LENGTH);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &ecdsap256_sign_sig_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
                snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
                multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                                 ecdsap256_sign_sig_previous_time,
                                                 current_time) == 1) {
            process_ecdsa_sign_sig_reqs(mb_tlv, EC_P256_LENGTH);
            clock_gettime(CLOCK_MONOTONIC_RAW, &ecdsap256_sign_sig_previous_time);
        }
    }

    /* Deal with ECDSA p384 sign requests */
    snapshot_num_reqs = mb_queue_ecdsap384_sign_get_size(mb_tlv->ecdsap384_sign_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_ecdsa_sign_reqs(mb_tlv, EC_P384_LENGTH);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &ecdsap384_sign_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
                snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
                multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                                 ecdsap384_sign_previous_time,
                                                 current_time) == 1) {
            process_ecdsa_sign_reqs(mb_tlv, EC_P384_LENGTH);
            clock_gettime(CLOCK_MONOTONIC_RAW, &ecdsap384_sign_previous_time);
        }
    }

    /* Deal with ECDSA p384 sign setup requests */
    snapshot_num_reqs = mb_queue_ecdsap384_sign_setup_get_size(mb_tlv->ecdsap384_sign_setup_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_ecdsa_sign_setup_reqs(mb_tlv, EC_P384_LENGTH);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
         }
         clock_gettime(CLOCK_MONOTONIC_RAW, &ecdsap384_sign_setup_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
                snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
                multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                                 ecdsap384_sign_setup_previous_time,
                                                 current_time) == 1) {
            process_ecdsa_sign_setup_reqs(mb_tlv, EC_P384_LENGTH);
            clock_gettime(CLOCK_MONOTONIC_RAW, &ecdsap384_sign_setup_previous_time);
        }
    }

    /* Deal with ECDSA p384 sign sig requests */
    snapshot_num_reqs = mb_queue_ecdsap384_sign_sig_get_size(mb_tlv->ecdsap384_sign_sig_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
         while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
             process_ecdsa_sign_sig_reqs(mb_tlv, EC_P384_LENGTH);
             snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &ecdsap384_sign_sig_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
                snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
                multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                                 ecdsap384_sign_sig_previous_time,
                                                 current_time) == 1) {
            process_ecdsa_sign_setup_reqs(mb_tlv, EC_P384_LENGTH);
            clock_gettime(CLOCK_MONOTONIC_RAW, &ecdsap384_sign_sig_previous_time);
        }
    }
#endif

#ifdef ENABLE_QAT_SW_ECDH
    /* Deal with ECDH p256 Keygen requests */
    snapshot_num_reqs = mb_queue_ecdhp256_keygen_get_size(mb_tlv->ecdhp256_keygen_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_ecdh_keygen_reqs(mb_tlv, EC_P256_LENGTH);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &ecdhp256_keygen_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
                snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
                multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                                 ecdhp256_keygen_previous_time,
                                                 current_time) == 1) {
            process_ecdh_keygen_reqs(mb_tlv, EC_P256_LENGTH);
            clock_gettime(CLOCK_MONOTONIC_RAW, &ecdhp256_keygen_previous_time);
        }
    }

    /* Deal with ECDH p256 compute requests */
    snapshot_num_reqs = mb_queue_ecdhp256_compute_get_size(mb_tlv->ecdhp256_compute_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_ecdh_compute_reqs(mb_tlv, EC_P256_LENGTH);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &ecdhp256_compute_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
                snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
                multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                                 ecdhp256_compute_previous_time,
                                                 current_time) == 1) {
            process_ecdh_compute_reqs(mb_tlv, EC_P256_LENGTH);
            clock_gettime(CLOCK_MONOTONIC_RAW, &ecdhp256_compute_previous_time);
        }
    }

   /* Deal with ECDH p384 Keygen requests */
   snapshot_num_reqs = mb_queue_ecdhp384_keygen_get_size(mb_tlv->ecdhp384_keygen_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_ecdh_keygen_reqs(mb_tlv, EC_P384_LENGTH);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &ecdhp384_keygen_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
                snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
                multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                                 ecdhp384_keygen_previous_time,
                                                 current_time) == 1) {
            process_ecdh_keygen_reqs(mb_tlv, EC_P384_LENGTH);
            clock_gettime(CLOCK_MONOTONIC_RAW, &ecdhp384_keygen_previous_time);
        }
    }

    /* Deal with ECDH p384 compute requests */
    snapshot_num_reqs = mb_queue_ecdhp384_compute_get_size(mb_tlv->ecdhp384_compute_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_ecdh_compute_reqs(mb_tlv, EC_P384_LENGTH);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &ecdhp384_compute_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
                snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
                multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                                 ecdhp384_compute_previous_time,
                                                 current_time) == 1) {
            process_ecdh_compute_reqs(mb_tlv, EC_P384_LENGTH);
            clock_gettime(CLOCK_MONOTONIC_RAW, &ecdhp384_compute_previous_time);
        }
    }
#endif

#ifdef ENABLE_QAT_SW_RSA
    /* Deal with rsa private key requests */
    snapshot_num_reqs = mb_queue_rsa2k_priv_get_size(mb_tlv->rsa2k_priv_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_RSA_priv_reqs(mb_tlv, RSA_2K_LENGTH);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &rsa2k_priv_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
            snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
            multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                             rsa2k_priv_previous_time,
                                             current_time) == 1) {
            process_RSA_priv_reqs(mb_tlv, RSA_2K_LENGTH);
            clock_gettime(CLOCK_MONOTONIC_RAW, &rsa2k_priv_previous_time);
        }
    }
    /* Deal with rsa public key requests */
    snapshot_num_reqs = mb_queue_rsa2k_pub_get_size(mb_tlv->rsa2k_pub_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_RSA_pub_reqs(mb_tlv, RSA_2K_LENGTH);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &rsa2k_pub_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
            snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
            multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                             rsa2k_pub_previous_time,
                                             current_time) == 1) {
            process_RSA_pub_reqs(mb_tlv, RSA_2K_LENGTH);
            clock_gettime(CLOCK_MONOTONIC_RAW, &rsa2k_pub_previous_time);
        }
    }
    /* Deal with rsa3k private key requests */
    snapshot_num_reqs = mb_queue_rsa3k_priv_get_size(mb_tlv->rsa3k_priv_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_RSA_priv_reqs(mb_tlv, RSA_3K_LENGTH);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &rsa3k_priv_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
            snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
            multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                             rsa3k_priv_previous_time,
                                             current_time) == 1) {
            process_RSA_priv_reqs(mb_tlv, RSA_3K_LENGTH);
            clock_gettime(CLOCK_MONOTONIC_RAW, &rsa3k_priv_previous_time);
        }
    }
    /* Deal with rsa3k public key requests */
    snapshot_num_reqs = mb_queue_rsa3k_pub_get_size(mb_tlv->rsa3k_pub_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_RSA_pub_reqs(mb_tlv, RSA_3K_LENGTH);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &rsa3k_pub_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
            snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
            multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                             rsa3k_pub_previous_time,
                                             current_time) == 1) {
            process_RSA_pub_reqs(mb_tlv, RSA_3K_LENGTH);
            clock_gettime(CLOCK_MONOTONIC_RAW, &rsa3k_pub_previous_time);
        }
    }
    /* Deal with rsa4k private key requests */
    snapshot_num_reqs = mb_queue_rsa4k_priv_get_size(mb_tlv->rsa4k_priv_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_RSA_priv_reqs(mb_tlv, RSA_4K_LENGTH);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &rsa4k_priv_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
            snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
            multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                             rsa4k_priv_previous_time,
                                             current_time) == 1) {
            process_RSA_priv_reqs(mb_tlv, RSA_4K_LENGTH);
            clock_gettime(CLOCK_MONOTONIC_RAW, &rsa4k_priv_previous_time);
        }
    }
    /* Deal with rsa4k public key requests */
    snapshot_num_reqs = mb_queue_rsa4k_pub_get_size(mb_tlv->rsa4k_pub_queue);
    if (snapshot_num_reqs >= MULTIBUFF_MAX_BATCH) {
        while (snapshot_num_reqs >= MULTIBUFF_MIN_BATCH) {
            process_RSA_pub_reqs(mb_tlv, RSA_4K_LENGTH);
            snapshot_num_reqs -= MULTIBUFF_MIN_BATCH;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &rsa4k_pub_previous_time);
    } else {
        if (snapshot_num_reqs > 0 &&
            snapshot_num_reqs < MULTIBUFF_MAX_BATCH &&
            multibuff_poll_check_for_timeout(mb_poll_timeout_time,
                                             rsa4k_pub_previous_time,
                                             current_time) == 1) {
            process_RSA_pub_reqs(mb_tlv, RSA_4K_LENGTH);
            clock_gettime(CLOCK_MONOTONIC_RAW, &rsa4k_pub_previous_time);
        }
    }
#endif

    return 1;
}
