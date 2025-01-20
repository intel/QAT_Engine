/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2025 Intel Corporation.
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
 * @file qat_prf.h
 *
 * This file provides an interface of the PRF operations for an
 * OpenSSL engine
 *
 *****************************************************************************/

#ifndef QAT_HW_PRF_H
#define QAT_HW_PRF_H

#include <pthread.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>

#include "openssl/ossl_typ.h"
#include "openssl/kdf.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "qat_evp.h"
#include "qat_utils.h"
#include "qat_hw_asym_common.h"
#include "e_qat.h"
#include "qat_hw_callback.h"
#include "qat_hw_polling.h"
#include "qat_events.h"

/* These limits are based on QuickAssist limits.
 * OpenSSL is more generous but better to restrict and fail
 * early on here if they are exceeded rather than later on
 * down in the driver.
 */
# ifdef ENABLE_QAT_HW_PRF
#  define QAT_TLS1_PRF_SECRET_MAXBUF 1024
#  define QAT_TLS1_PRF_SEED_MAXBUF 64
#  define QAT_TLS1_PRF_LABEL_MAXBUF 136

/* QAT TLS  pkey context structure */
typedef struct {
    /* Buffer of concatenated seeds from seed2 to seed5 data */
    unsigned char qat_seed[QAT_TLS1_PRF_SEED_MAXBUF];
    size_t qat_seedlen;
    unsigned char *qat_userLabel;
    size_t qat_userLabel_len;
    /* Digest to use for PRF */
    const EVP_MD *qat_md;
    /* Secret value to use for PRF */
    unsigned char *qat_sec;
    size_t qat_seclen;
    void *sw_prf_ctx_data;
    int qat_svm;
} QAT_TLS1_PRF_CTX;

/* Function Declarations */
int qat_tls1_prf_init(EVP_PKEY_CTX *ctx);
void qat_prf_cleanup(EVP_PKEY_CTX *ctx);
int qat_prf_tls_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                                size_t *olen);
int qat_tls1_prf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
# endif /* ENABLE_QAT_HW_PRF */

#endif /* QAT_HW_PRF_H */
