/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021-2023 Intel Corporation.
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

/* Crypto_mb includes */
# include "crypto_mb/ec_sm2.h"
# include "crypto_mb/cpu_features.h"

/* The default user id as specified in GM/T 0009-2012 */
# define SM2_DEFAULT_USERID "1234567812345678"
# define SM2_DEFAULT_USERID_LEN sizeof(SM2_DEFAULT_USERID) - 1
# define SM3_DIGEST_LENGTH 32


# ifdef ENABLE_QAT_SW_SM2
#  ifdef QAT_OPENSSL_PROVIDER

# define OSSL_MAX_NAME_SIZE           50 /* Algorithm name */
# define OSSL_MAX_PROPQUERY_SIZE     256 /* Property query strings */
# define OSSL_MAX_ALGORITHM_ID_SIZE  256 /* AlgorithmIdentifier DER */

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes EC structures, so
 * we use that here too.
 */
typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    EC_KEY *ec;

    /*
     * Flag to termine if the 'z' digest needs to be computed and fed to the
     * hash function.
     * This flag should be set on initialization and the compuation should
     * be performed only once, on first update.
     */
    unsigned int flag_compute_z_digest : 1;

    char mdname[OSSL_MAX_NAME_SIZE];

    /* The Algorithm Identifier of the combined signature algorithm */
    unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
    unsigned char *aid;
    size_t  aid_len;

    /* main digest */
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    size_t mdsize;

    /* SM2 ID used for calculating the Z value */
    unsigned char *id;
    size_t id_len;

    const unsigned char *tbs;
    size_t tbs_len;
} QAT_PROV_SM2_CTX;

int mb_ecdsa_sm2_sign(QAT_PROV_SM2_CTX *ctx,
                             unsigned char *sig, size_t *siglen,
                             size_t sigsize, const unsigned char *tbs,
                             size_t tbslen);
int mb_ecdsa_sm2_verify(QAT_PROV_SM2_CTX *ctx,
                               const unsigned char *sig, size_t siglen,
                               const unsigned char *tbs,
                               size_t tbslen);
#  else
int ossl_sm2_compute_z_digest(uint8_t *out,
                              const EVP_MD *digest,
                              const uint8_t *id,
                              const size_t id_len,
                              const EC_KEY *key);
                              
int mb_ecdsa_sm2_sign(EVP_MD_CTX *ctx,
                             unsigned char *sig, size_t *siglen,
                             const unsigned char *tbs,
                             size_t tbslen);
int mb_ecdsa_sm2_verify(EVP_MD_CTX *ctx,
                               const unsigned char *sig, size_t siglen,
                               const unsigned char *tbs,
                               size_t tbslen);
#  endif /* QAT_OPENSSL_PROVIDER */
# endif /* ENABLE_QAT_SW_SM2 */

#endif /* QAT_SW_SM2_H */
