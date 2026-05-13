/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2026 Intel Corporation.
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
 * @file qat_prov_rsa.c
 *
 * This file provides an implementation to qatprovider RSA operations
 *
 *****************************************************************************/
#include<openssl/rsa.h>
#include<openssl/bn.h>
#include<openssl/crypto.h>
#include "qat_utils.h"
#include "qat_prov_rsa.h"
#include "e_qat.h"

#if defined(ENABLE_QAT_HW_RSA) || defined(ENABLE_QAT_SW_RSA)
#ifdef ENABLE_QAT_FIPS
# include "qat_prov_cmvp.h"
extern int qat_fips_key_zeroize;
#endif

/* Ex data index for PSS params */
static int qat_rsa_pss_ex_data_idx = -1;
static CRYPTO_ONCE qat_rsa_pss_ex_data_once = CRYPTO_ONCE_STATIC_INIT;

static void qat_rsa_pss_ex_data_free(void *parent, void *ptr,
                                     CRYPTO_EX_DATA *ad, int idx,
                                     long argl, void *argp)
{
    (void)parent;
    (void)ad;
    (void)idx;
    (void)argl;
    (void)argp;
    OPENSSL_free(ptr);
}

static int qat_rsa_pss_ex_data_dup(CRYPTO_EX_DATA *to,
                                   const CRYPTO_EX_DATA *from,
                                   void **pptr, int idx, long argl, void *argp)
{
    (void)to;
    (void)from;
    (void)idx;
    (void)argl;
    (void)argp;
    QAT_RSA_PSS_PARAMS_30 *src = *pptr;
    if (src != NULL) {
        QAT_RSA_PSS_PARAMS_30 *dst = OPENSSL_memdup(src, sizeof(*src));
        if (dst == NULL)
            return 0;
        *pptr = dst;
    }
    return 1;
}

static void qat_rsa_pss_ex_data_init_once(void)
{
    qat_rsa_pss_ex_data_idx = RSA_get_ex_new_index(0, NULL, NULL,
                                                    qat_rsa_pss_ex_data_dup,
                                                    qat_rsa_pss_ex_data_free);
}

void qat_rsa_pss_params_ex_init(void)
{
    CRYPTO_THREAD_run_once(&qat_rsa_pss_ex_data_once, qat_rsa_pss_ex_data_init_once);
}

int qat_rsa_pss_params_ex_idx(void)
{
    return qat_rsa_pss_ex_data_idx;
}

void QAT_RSA_free(RSA *r)
{
#ifdef ENABLE_QAT_FIPS
    qat_fips_key_zeroize = 0;
#endif
    RSA_free(r);
#ifdef ENABLE_QAT_FIPS
    qat_fips_key_zeroize = 1;
    qat_fips_get_key_zeroize_status();
#endif
}
#endif
