/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2024 Intel Corporation.
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
 * @file qat_utils.c
 *
 * This file provides an implementation of utilities for an OpenSSL engine
 *
 *****************************************************************************/

#include <stdio.h>
#include <pthread.h>
#include "qat_utils.h"
#include "e_qat.h"

#ifdef QAT_HW
# include "cpa.h"
#endif

FILE *qatDebugLogFile = NULL;
#ifdef QAT_TESTS_LOG
FILE *cryptoQatLogger = NULL;
pthread_mutex_t test_file_mutex = PTHREAD_MUTEX_INITIALIZER;
int test_file_ref_count = 0;
char test_file_name[QAT_MAX_TEST_FILE_NAME_LENGTH];
#endif /* QAT_TESTS_LOG */

#ifdef QAT_CPU_CYCLES_COUNT
rdtsc_prof_t rsa_cycles_priv_enc_setup;
rdtsc_prof_t rsa_cycles_priv_dec_setup;
rdtsc_prof_t rsa_cycles_priv_execute;
rdtsc_prof_t rsa_cycles_pub_enc_setup;
rdtsc_prof_t rsa_cycles_pub_dec_setup;
rdtsc_prof_t rsa_cycles_pub_execute;
rdtsc_prof_t x25519_cycles_keygen_setup;
rdtsc_prof_t x25519_cycles_keygen_execute;
rdtsc_prof_t x25519_cycles_derive_setup;
rdtsc_prof_t x25519_cycles_derive_execute;
rdtsc_prof_t ecdsa_cycles_sign_setup;
rdtsc_prof_t ecdsa_cycles_sign_execute;
rdtsc_prof_t ecdsa_cycles_sign_setup_setup;
rdtsc_prof_t ecdsa_cycles_sign_setup_execute;
rdtsc_prof_t ecdsa_cycles_sign_sig_setup;
rdtsc_prof_t ecdsa_cycles_sign_sig_execute;
rdtsc_prof_t ecdh_cycles_keygen_setup;
rdtsc_prof_t ecdh_cycles_keygen_execute;
rdtsc_prof_t ecdh_cycles_compute_setup;
rdtsc_prof_t ecdh_cycles_compute_execute;
rdtsc_prof_t sm2ecdh_cycles_keygen_setup;
rdtsc_prof_t sm2ecdh_cycles_keygen_execute;
rdtsc_prof_t sm2ecdh_cycles_compute_setup;
rdtsc_prof_t sm2ecdh_cycles_compute_execute;
rdtsc_prof_t sm3_cycles_init_setup;
rdtsc_prof_t sm3_cycles_init_execute;
rdtsc_prof_t sm3_cycles_update_setup;
rdtsc_prof_t sm3_cycles_update_execute;
rdtsc_prof_t sm3_cycles_final_setup;
rdtsc_prof_t sm3_cycles_final_execute;
rdtsc_prof_t ecdsa_cycles_verify_setup;
rdtsc_prof_t ecdsa_cycles_verify_execute;
rdtsc_prof_t sm4_gcm_cycles_init_setup;
rdtsc_prof_t sm4_gcm_cycles_init_execute;
rdtsc_prof_t sm4_gcm_cycles_encrypt_setup;
rdtsc_prof_t sm4_gcm_cycles_encrypt_execute;
rdtsc_prof_t sm4_gcm_cycles_decrypt_setup;
rdtsc_prof_t sm4_gcm_cycles_decrypt_execute;
rdtsc_prof_t sm4_gcm_cycles_get_tag_setup;
rdtsc_prof_t sm4_gcm_cycles_get_tag_execute;
rdtsc_prof_t sm4_gcm_cycles_update_iv_setup;
rdtsc_prof_t sm4_gcm_cycles_update_iv_execute;
rdtsc_prof_t sm4_gcm_cycles_update_aad_setup;
rdtsc_prof_t sm4_gcm_cycles_update_aad_execute;
rdtsc_prof_t sm4_gcm_cycles_cipher_setup;
rdtsc_prof_t sm4_gcm_cycles_cipher_execute;
rdtsc_prof_t sm4_gcm_cycles_ctrl_setup;
rdtsc_prof_t sm4_gcm_cycles_ctrl_execute;
rdtsc_prof_t sm4_gcm_cycles_cleanup_setup;
rdtsc_prof_t sm4_gcm_cycles_cleanup_execute;
rdtsc_prof_t sm4_cbc_cycles_cipher_execute;
rdtsc_prof_t sm4_cbc_cycles_cipher_dec_execute;
rdtsc_prof_t sm4_ccm_cycles_init_setup;
rdtsc_prof_t sm4_ccm_cycles_init_execute;
rdtsc_prof_t sm4_ccm_cycles_encrypt_setup;
rdtsc_prof_t sm4_ccm_cycles_encrypt_execute;
rdtsc_prof_t sm4_ccm_cycles_decrypt_setup;
rdtsc_prof_t sm4_ccm_cycles_decrypt_execute;
rdtsc_prof_t sm4_ccm_cycles_get_tag_setup;
rdtsc_prof_t sm4_ccm_cycles_get_tag_execute;
rdtsc_prof_t sm4_ccm_cycles_update_aad_setup;
rdtsc_prof_t sm4_ccm_cycles_update_aad_execute;
rdtsc_prof_t sm4_ccm_cycles_ctrl_setup;
rdtsc_prof_t sm4_ccm_cycles_ctrl_execute;
rdtsc_prof_t sm4_ccm_cycles_cleanup_setup;
rdtsc_prof_t sm4_ccm_cycles_cleanup_execute;
rdtsc_prof_t qat_hw_rsa_dec_req_prepare;
rdtsc_prof_t qat_hw_rsa_dec_req_submit;
rdtsc_prof_t qat_hw_rsa_dec_req_retry;
rdtsc_prof_t qat_hw_rsa_dec_req_cleanup;
rdtsc_prof_t qat_hw_ecdsa_sign_req_prepare;
rdtsc_prof_t qat_hw_ecdsa_sign_req_submit;
rdtsc_prof_t qat_hw_ecdsa_sign_req_retry;
rdtsc_prof_t qat_hw_ecdsa_sign_req_cleanup;
rdtsc_prof_t qat_hw_ecdh_derive_req_prepare;
rdtsc_prof_t qat_hw_ecdh_derive_req_submit;
rdtsc_prof_t qat_hw_ecdh_derive_req_retry;
rdtsc_prof_t qat_hw_ecdh_derive_req_cleanup;
rdtsc_prof_t qat_hw_ecx_derive_req_prepare;
rdtsc_prof_t qat_hw_ecx_derive_req_submit;
rdtsc_prof_t qat_hw_ecx_derive_req_retry;
rdtsc_prof_t qat_hw_ecx_derive_req_cleanup;

volatile static double rdtsc_prof_cost = 0.0; /* cost of measurement */
int print_cycle_count = 1;
#endif

#ifdef QAT_DEBUG_FILE_PATH
pthread_mutex_t debug_file_mutex = PTHREAD_MUTEX_INITIALIZER;
int debug_file_ref_count = 0;

void crypto_qat_debug_init_log()
{
    pthread_mutex_lock(&debug_file_mutex);
    if (!debug_file_ref_count) {
        qatDebugLogFile = fopen(STR(QAT_DEBUG_FILE_PATH), "w");

        if (NULL == qatDebugLogFile) {
            qatDebugLogFile = stderr;
            WARN("unable to open %s\n", STR(QAT_DEBUG_FILE_PATH));
        } else {
            debug_file_ref_count++;
        }
    }
    pthread_mutex_unlock(&debug_file_mutex);
}

void crypto_qat_debug_close_log()
{
    pthread_mutex_lock(&debug_file_mutex);
    if (debug_file_ref_count) {
        if (qatDebugLogFile != NULL) {
            fclose(qatDebugLogFile);
            debug_file_ref_count--;
            qatDebugLogFile = stderr;
        }
    }
    pthread_mutex_unlock(&debug_file_mutex);
}
#endif /* QAT_DEBUG_FILE_PATH */

#ifdef QAT_TESTS_LOG
char *crypto_qat_testing_get_log_filename()
{
    snprintf(test_file_name, QAT_MAX_TEST_FILE_NAME_LENGTH,
             "/opt/qat-crypto-%d.log", getpid());
    return test_file_name;
}

void crypto_qat_testing_init_log()
{
    pthread_mutex_lock(&test_file_mutex);
    if (!test_file_ref_count) {
        cryptoQatLogger = fopen(crypto_qat_testing_get_log_filename(), "w");

        if (NULL == cryptoQatLogger) {
            WARN("unable to open %s\n", test_file_name);
            pthread_mutex_unlock(&test_file_mutex);
            exit(1);
        } else {
            test_file_ref_count++;
        }
    }
    pthread_mutex_unlock(&test_file_mutex);
}

void crypto_qat_testing_close_log()
{
    pthread_mutex_lock(&test_file_mutex);
    if (test_file_ref_count) {
        if (cryptoQatLogger != NULL) {
            fclose(cryptoQatLogger);
            test_file_ref_count--;
        }
    }
    pthread_mutex_unlock(&test_file_mutex);
}
#endif /* QAT_TESTS_LOG */

#ifdef QAT_DEBUG
void qat_hex_dump(const char *func, const char *var, const unsigned char p[],
                  int l)
{

    fprintf(qatDebugLogFile, "%s: %s: Length %d, Address %p\n", func, var, l, p);
# ifdef QAT_HEX_DUMP
    int i;
    if (NULL != p && l > 0) {
        for (i = 0; i < l; i++) {
            if (i != 0 && i % 32 == 0)
                fputc('\n', qatDebugLogFile);
            else if (i != 0 && i % 8 == 0)
                fputs("- ", qatDebugLogFile);
            fprintf(qatDebugLogFile, "%02x ", p[i]);
        }
    }
    fputc('\n', qatDebugLogFile);
    fflush(qatDebugLogFile);
# endif
}
#endif

#ifdef QAT_CPU_CYCLES_COUNT
void rdtsc_prof_init(rdtsc_prof_t *p, const uint32_t bytes)
{
    p->bytes = bytes;
    p->clk_start = 0;
    p->clk_avg = 0.0;
    p->clk_avgc = 0;
    p->clk_diff_cost_adjusted = 0.0;
    p->started = 0;
    p->cost = rdtsc_prof_cost;
}

void rdtsc_prof_print(rdtsc_prof_t *p, char *name)
{
    if (p == NULL) {
        fprintf(qatDebugLogFile, "%s\tavg\n", "    ");
    } else {
        if (p->clk_avgc > 0) {
            double avg_c = (p->clk_avg / ((double)p->clk_avgc));

# ifdef QAT_CPU_CYCLE_MEASUREMENT_COST
            fprintf(qatDebugLogFile,
                    "\n%s - avg cycles per job (mca ENABLED):  %.1f - number of samples = %ld\n",
                    name, avg_c, p->clk_avgc);
# else
            fprintf(qatDebugLogFile, "%s,%.1f,%ld\n", name, avg_c, p->clk_avgc);
# endif
            if (p->bytes > 0) {
                double avg_pb = avg_c / ((double)p->bytes);
                fprintf(qatDebugLogFile, " - avg cycles per byte: %.1f\n",
                        avg_pb);
            }
        }
    }
}

void rdtsc_initialize(void)
{
    rdtsc_prof_t p;
    unsigned i;

    /* Figure out cost of measurement */
    rdtsc_prof_init(&p, 0);
    print_cycle_count = 0;
    for (i = 0; i < 10000; i++) {
        rdtsc_prof_start(&p);
        rdtsc_prof_end(&p, 1, "Measurement cost");
    }
# ifdef QAT_CPU_CYCLE_COUNT_DEBUG
    print_cycle_count = 1;
# endif
    rdtsc_prof_print(&p, "Cost of CPU cycle measurement ");
    rdtsc_prof_cost = p.clk_avg / (double)p.clk_avgc;
    fprintf(qatDebugLogFile,
            "[%s] - cost of measurement is subtracted from subsequent tests if build flag QAT_CPU_CYCLE_MEASUREMENT_COST is set\n\n",
            __func__);
}

#endif /* QAT_CPU_CYCLES_COUNT */

/* Get absolute time by relative time. */
void get_sem_wait_abs_time(struct timespec *polling_abs_timeout,
                           const struct timespec polling_timeout)
{
    clock_gettime(CLOCK_REALTIME, polling_abs_timeout); /* Get current real time. */
    polling_abs_timeout->tv_sec += polling_timeout.tv_sec;
    polling_abs_timeout->tv_nsec += polling_timeout.tv_nsec;
    polling_abs_timeout->tv_sec += polling_abs_timeout->tv_nsec / NSEC_TO_SEC;
    polling_abs_timeout->tv_nsec = polling_abs_timeout->tv_nsec % NSEC_TO_SEC;
}
