/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023-2024 Intel Corporation.
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
 * @file qat_hw_sm2.h
 *
 * This file provides HW driver support interface for SM2 ECDSA
 *
 *****************************************************************************/
#ifndef QAT_HW_SM2_H
# define QAT_HW_SM2_H

# include <pthread.h>
# include <openssl/err.h>
# include <string.h>
# include <unistd.h>
# include <signal.h>
# include <openssl/ec.h>
# include <openssl/obj_mac.h>
# include <openssl/bn.h>
# include <openssl/rand.h>

/* Local includes */
# include "e_qat.h"
# include "qat_utils.h"
# include "qat_events.h"
# include "qat_fork.h"
# include "qat_evp.h"
# include "qat_hw_callback.h"
# include "qat_hw_polling.h"
# include "qat_hw_asym_common.h"
# if defined(QAT_OPENSSL_3)|| defined(QAT_OPENSSL_PROVIDER)
#  include "qat_prov_sign_sm2.h"
# endif

# include "cpa.h"
# include "cpa_types.h"
# include "cpa_cy_ec.h"
# if defined(ENABLE_QAT_HW_SM2) && !defined( __FreeBSD__)
#  include "cpa_cy_ecsm2.h"
# endif
# include "cpa_dev.h"

/* The default user id as specified in GM/T 0009-2012 */
# define SM2_DEFAULT_USERID "1234567812345678"
# define SM2_DEFAULT_USERID_LEN sizeof(SM2_DEFAULT_USERID) - 1
# define SM3_DIGEST_LENGTH 32
# define QAT_GFP_SM2_SIZE_IN_BITS 32

# ifdef ENABLE_QAT_HW_SM2
#  ifdef QAT_OPENSSL_PROVIDER
int qat_hw_sm2_compute_z_digest(uint8_t *out,
                              const EVP_MD *digest,
                              const uint8_t *id,
                              const size_t id_len, const EC_KEY *key);

int qat_sm2_sign(QAT_PROV_SM2_CTX * ctx,
                 unsigned char *sig, size_t *siglen,
                 size_t sigsize, const unsigned char *tbs, size_t tbslen);
int qat_sm2_verify(QAT_PROV_SM2_CTX * ctx,
                   const unsigned char *sig, size_t siglen,
                   const unsigned char *tbs, size_t tbslen);
#  else

/*
 * SM2 signature operation. Computes Z and then signs H(Z || msg) using SM2
 */
ECDSA_SIG *qat_sm2_do_sign(const EC_KEY *key,
                           const EVP_MD *digest,
                           const uint8_t *id,
                           const size_t id_len,
                           const uint8_t *msg, size_t msg_len);

int qat_sm2_do_verify(const EC_KEY *key,
                      const EVP_MD *digest,
                      const ECDSA_SIG *signature,
                      const uint8_t *id,
                      const size_t id_len, const uint8_t *msg, size_t msg_len);

/*
 * SM2 signature generation.
 */
int qat_sm2_sign(EVP_PKEY_CTX *ctx,
                 unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen);

/*
 * SM2 signature verification.
 */
int qat_sm2_verify(EVP_PKEY_CTX *ctx,
                   const unsigned char *sig, size_t siglen,
                   const unsigned char *tbs, size_t tbslen);

#  endif
#  ifndef QAT_OPENSSL_PROVIDER
int qat_sm2_init(EVP_PKEY_CTX *ctx);
#   ifdef QAT_OPENSSL_3
int qat_sm2_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src);
#   else
int qat_sm2_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
#   endif
int qat_sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
void qat_sm2_cleanup(EVP_PKEY_CTX *ctx);
int qat_sm2_digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
#  endif

# endif                         /* ENABLE_QAT_HW_SM2 */

#endif                          /* QAT_HW_SM2_H */
