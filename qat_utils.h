/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2017 Intel Corporation.
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
 * @file qat_utils.h
 *
 * This file provides an interface to utilities for the QAT engine in OpenSSL
 *
 *****************************************************************************/

#ifndef QAT_UTILS_H
# define QAT_UTILS_H

# include <stdio.h>
# include <pthread.h>
# include "cpa.h"
# include "cpa_cy_sym.h"

# define QAT_BYTE_ALIGNMENT 64
/* For best performance data buffers should be 64-byte aligned */
# define QAT_CONTIG_MEM_ALIGN(x)                              \
         (void *)(((uintptr_t)(x) + QAT_BYTE_ALIGNMENT - 1) & \
         (~(uintptr_t)(QAT_BYTE_ALIGNMENT-1)))

/*
 * Add -DQAT_TESTS_LOG to ./config to enable debug logging to the
 * CRYPTO_QAT_LOG_FILE
 */
# ifdef QAT_TESTS_LOG

#  define CRYPTO_QAT_LOG_FILE "/opt/qat-crypto.log"

extern FILE *cryptoQatLogger;
extern pthread_mutex_t debug_file_mutex;
extern int debug_file_ref_count;

void crypto_qat_debug_init_log();
void crypto_qat_debug_close_log();

#  define CRYPTO_INIT_QAT_LOG() crypto_qat_debug_init_log()

#  define CRYPTO_CLOSE_QAT_LOG() crypto_qat_debug_close_log()

#  define CRYPTO_QAT_LOG(...)                       \
do {                                                \
    pthread_mutex_lock(&debug_file_mutex);          \
    if (debug_file_ref_count) {                     \
        if (cryptoQatLogger != NULL) {              \
            fprintf (cryptoQatLogger, __VA_ARGS__); \
            fflush(cryptoQatLogger);                \
        }                                           \
    }                                               \
    pthread_mutex_unlock(&debug_file_mutex);        \
} while(0)

# else

#  define CRYPTO_QAT_LOG(...)
#  define CRYPTO_CLOSE_QAT_LOG()
#  define CRYPTO_INIT_QAT_LOG()

# endif

/* Debug and warning messages for the QAT engine */
# ifdef QAT_DEBUG
void hexDump(const char *func, const char *var, const unsigned char p[],
             int l);
void dumpRequest(const CpaInstanceHandle instance_handle, void *pCallbackTag,
                 const CpaCySymOpData * pOpData,
                 const CpaCySymSessionSetupData * sessionData,
                 const CpaBufferList * pSrcBuffer,
                 CpaBufferList * pDstBuffer);
#  define DEBUG(fmt_str, ...)                                                \
          fprintf(stderr, "[DEBUG][%s:%d:%s()] "fmt_str, __FILE__, __LINE__, \
                  __func__, ##__VA_ARGS__)
#  define DUMPL(var,p,l) hexDump(__func__,var,p,l);
#  define DUMPREQ(inst, cb, opD, sess, src, dst) \
          dumpRequest(inst, cb, opD, sess, src, dst);
# else
#  define DEBUG(...)
#  define DUMPL(...)
#  define DUMPREQ(...)
# endif

# if defined(QAT_WARN) || defined(QAT_DEBUG)
#  define WARN(fmt_str, ...)                                          \
          fprintf (stderr, "[WARNING][%s:%d:%s()] "fmt_str, __FILE__, \
                   __LINE__, __func__, ##__VA_ARGS__)
# else
#  define WARN(...)
# endif

#endif                          /* QAT_UTILS_H */
