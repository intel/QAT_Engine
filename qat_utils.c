/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2020 Intel Corporation.
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
#include "cpa.h"
#include "qat_utils.h"
#include "e_qat.h"

#ifdef QAT_TESTS_LOG

FILE *cryptoQatLogger = NULL;
pthread_mutex_t test_file_mutex = PTHREAD_MUTEX_INITIALIZER;
int test_file_ref_count = 0;
char test_file_name[QAT_MAX_TEST_FILE_NAME_LENGTH];

#endif  /* QAT_TESTS_LOG */

FILE *qatDebugLogFile = NULL;

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
            WARN("unable to open %s\n",
                 STR(QAT_DEBUG_FILE_PATH));
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

#endif  /* QAT_DEBUG_FILE_PATH */

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

#endif  /* QAT_TESTS_LOG */

#ifdef QAT_DEBUG

void qat_hex_dump(const char *func, const char *var, const unsigned char p[],
             int l)
{
    int i;

    fprintf(qatDebugLogFile, "%s: %s: Length %d, Address %p", func, var, l, p);
    if (NULL != p && l > 0) {
        for (i = 0; i < l; i++) {
            if (i % 16 == 0)
                fputc('\n', qatDebugLogFile);
            else if (i % 8 == 0)
                fputs("- ", qatDebugLogFile);
            fprintf(qatDebugLogFile, "%02x ", p[i]);
        }
    }
    fputc('\n', qatDebugLogFile);
}

#endif
