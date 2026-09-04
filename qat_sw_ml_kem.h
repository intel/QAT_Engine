/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2026 Intel Corporation.
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
 * @file qat_sw_ml_kem.h
 *
 * This file provides an interface for ML-KEM (FIPS 203) operations
 * offloaded to Software (Intel IPsec Multi-Buffer library)
 *
 ****************************************************************************/

#ifndef QAT_SW_ML_KEM_H
# define QAT_SW_ML_KEM_H

# include <openssl/core.h>
# include <openssl/crypto.h>
# include <intel-ipsec-mb.h>
# include "qat_common.h"

# define QAT_ML_KEM_IKME_BYTES  32

/* QAT_ML_KEM_KEY holds the encoded key material only; the IMB_ML_KEM
 * handle that caches the decoded key lives in the per-operation KEM ctx. */
typedef struct qat_ml_kem_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    IMB_ML_KEM_ALG alg;
    unsigned int haspubkey:1;
    unsigned int hasprivkey:1;
    size_t pubkeylen;
    size_t privkeylen;
    QAT_CRYPTO_REF_COUNT references;
    unsigned char pubkey[IMB_ML_KEM_1024_PUBKEY_BYTES];
    unsigned char privkey[IMB_ML_KEM_1024_PRIVKEY_BYTES];
} QAT_ML_KEM_KEY;

size_t qat_sw_ml_kem_pubkey_bytes(IMB_ML_KEM_ALG alg);
size_t qat_sw_ml_kem_privkey_bytes(IMB_ML_KEM_ALG alg);
size_t qat_sw_ml_kem_ciphertext_bytes(IMB_ML_KEM_ALG alg);
int qat_sw_ml_kem_bits(IMB_ML_KEM_ALG alg);
int qat_sw_ml_kem_security_bits(IMB_ML_KEM_ALG alg);

int qat_sw_ml_kem_init_ipsec_mb_mgr(void);
void qat_sw_ml_kem_free_ipsec_mb_mgr(void);
IMB_ML_KEM *qat_sw_ml_kem_ctx_new(IMB_ML_KEM_ALG alg);
void qat_sw_ml_kem_ctx_free(IMB_ML_KEM *ctx);

QAT_ML_KEM_KEY *qat_sw_ml_kem_key_new(OSSL_LIB_CTX *libctx, IMB_ML_KEM_ALG alg,
                                   const char *propq);
void qat_sw_ml_kem_key_free(QAT_ML_KEM_KEY *key);
int qat_sw_ml_kem_key_up_ref(QAT_ML_KEM_KEY *key);

extern const OSSL_DISPATCH qat_ml_kem_512_keymgmt_functions[];
extern const OSSL_DISPATCH qat_ml_kem_768_keymgmt_functions[];
extern const OSSL_DISPATCH qat_ml_kem_1024_keymgmt_functions[];
extern const OSSL_DISPATCH qat_ml_kem_functions[];

#endif /* QAT_SW_ML_KEM_H */
