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
 * @file qat_sw_ml_dsa.h
 *
 * This file provides an interface for ML-DSA (FIPS 204) operations
 * offloaded to Software (Intel IPsec Multi-Buffer library)
 *
 ****************************************************************************/

#ifndef QAT_SW_ML_DSA_H
# define QAT_SW_ML_DSA_H

# include <openssl/core.h>
# include <openssl/crypto.h>
# include <intel-ipsec-mb.h>
# include "qat_common.h"

# define QAT_ML_DSA_MAX_CONTEXT_STRING_BYTES 255

/* QAT_ML_DSA_KEY holds the encoded key material only; the IMB_ML_DSA
 * handle that caches the decoded key lives in the sign/verify context. */
typedef struct qat_ml_dsa_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    IMB_ML_DSA_ALG alg;
    unsigned int haspubkey:1;
    unsigned int hasprivkey:1;
    size_t pubkeylen;
    size_t privkeylen;
    QAT_CRYPTO_REF_COUNT references;
    unsigned char pubkey[IMB_ML_DSA_87_PUBKEY_BYTES];
    unsigned char privkey[IMB_ML_DSA_87_PRIVKEY_BYTES];
} QAT_ML_DSA_KEY;

size_t qat_sw_ml_dsa_pubkey_bytes(IMB_ML_DSA_ALG alg);
size_t qat_sw_ml_dsa_privkey_bytes(IMB_ML_DSA_ALG alg);
size_t qat_sw_ml_dsa_sig_bytes(IMB_ML_DSA_ALG alg);
int qat_sw_ml_dsa_bits(IMB_ML_DSA_ALG alg);
int qat_sw_ml_dsa_security_bits(IMB_ML_DSA_ALG alg);

int qat_sw_ml_dsa_init_ipsec_mb_mgr(void);
void qat_sw_ml_dsa_free_ipsec_mb_mgr(void);
IMB_ML_DSA *qat_sw_ml_dsa_ctx_new(IMB_ML_DSA_ALG alg);
void qat_sw_ml_dsa_ctx_free(IMB_ML_DSA *ctx);

QAT_ML_DSA_KEY *qat_sw_ml_dsa_key_new(OSSL_LIB_CTX *libctx, IMB_ML_DSA_ALG alg,
                                       const char *propq);
void qat_sw_ml_dsa_key_free(QAT_ML_DSA_KEY *key);
int qat_sw_ml_dsa_key_up_ref(QAT_ML_DSA_KEY *key);

extern const OSSL_DISPATCH qat_ml_dsa_44_keymgmt_functions[];
extern const OSSL_DISPATCH qat_ml_dsa_65_keymgmt_functions[];
extern const OSSL_DISPATCH qat_ml_dsa_87_keymgmt_functions[];
extern const OSSL_DISPATCH qat_ml_dsa_signature_functions[];

#endif /* QAT_SW_ML_DSA_H */
