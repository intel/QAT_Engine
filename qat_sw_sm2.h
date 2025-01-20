/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021-2025 Intel Corporation.
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
 * @file qat_sw_sm2.h
 *
 * This file provides multibuffer support interface for SM2 ECDSA
 *
 *****************************************************************************/
#ifndef QAT_SW_SM2_H
# define QAT_SW_SM2_H

# include <pthread.h>
# include <openssl/err.h>
# include <string.h>
# include <unistd.h>
# include <signal.h>

/* Local includes */
# include "e_qat.h"
# include "qat_utils.h"
# include "qat_events.h"
# include "qat_fork.h"
# include "qat_evp.h"
# include "qat_sw_request.h"
# include "qat_sw_ec.h"
# if defined(QAT_OPENSSL_3) || defined(QAT_OPENSSL_PROVIDER)
#  include "qat_prov_sign_sm2.h"
# endif

/* Crypto_mb includes */
# include "crypto_mb/ec_sm2.h"
# include "crypto_mb/cpu_features.h"

/* The default user id as specified in GM/T 0009-2012 */
# define SM2_DEFAULT_USERID "1234567812345678"
# define SM2_DEFAULT_USERID_LEN sizeof(SM2_DEFAULT_USERID) - 1
# define SM3_DIGEST_LENGTH 32


# ifdef ENABLE_QAT_SW_SM2

int qat_sm2_compute_z_digest(uint8_t *out,
                              const EVP_MD *digest,
                              const uint8_t *id,
                              const size_t id_len,
                              const EC_KEY *key);

#  ifdef QAT_OPENSSL_PROVIDER
int mb_ecdsa_sm2_sign(QAT_PROV_SM2_CTX *ctx,
                             unsigned char *sig, size_t *siglen,
                             size_t sigsize, const unsigned char *tbs,
                             size_t tbslen);
int mb_ecdsa_sm2_verify(QAT_PROV_SM2_CTX *ctx,
                               const unsigned char *sig, size_t siglen,
                               const unsigned char *tbs,
                               size_t tbslen);

#  else
int mb_ecdsa_sm2_sign(EVP_MD_CTX *ctx,
                             unsigned char *sig, size_t *siglen,
                             const unsigned char *tbs,
                             size_t tbslen);
int mb_ecdsa_sm2_verify(EVP_MD_CTX *ctx,
                               const unsigned char *sig, size_t siglen,
                               const unsigned char *tbs,
                               size_t tbslen);
#  endif /* QAT_OPENSSL_PROVIDER */

#ifndef QAT_OPENSSL_PROVIDER
# ifdef ENABLE_QAT_SW_SM2
int mb_sm2_init(EVP_PKEY_CTX *ctx);
int mb_sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
void mb_sm2_cleanup(EVP_PKEY_CTX *ctx);
int mb_digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
# endif
#endif

# endif /* ENABLE_QAT_SW_SM2 */

#endif /* QAT_SW_SM2_H */
