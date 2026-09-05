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
 * @file qat_sw_ml_dsa.c
 *
 * This file provides an implementation of ML-DSA (FIPS 204) operations
 * offloaded to Software (Intel IPsec Multi-Buffer library)
 *
 *****************************************************************************/
#ifdef ENABLE_QAT_SW_ML_DSA
# include <openssl/crypto.h>
# include "e_qat.h"
# include "qat_utils.h"
# include "qat_sw_ml_dsa.h"

/* Dedicated IMB_MGR for ML-DSA, initialized eagerly at provider load.
 * Written once (single-threaded, before *provctx is published) and only
 * read afterwards; imb_ml_dsa_new() is re-entrant on a shared mgr, so no
 * lock is needed for concurrent sign/verify/keygen from multiple threads. */
static IMB_MGR *ml_dsa_mgr = NULL;

int qat_sw_ml_dsa_init_ipsec_mb_mgr(void)
{
    if (ml_dsa_mgr != NULL)
        return 1;
    ml_dsa_mgr = alloc_mb_mgr(0);
    if (ml_dsa_mgr == NULL) {
        WARN("Error allocating IMB_MGR for ML-DSA\n");
        return 0;
    }
    init_mb_mgr_auto(ml_dsa_mgr, NULL);
    if (imb_get_errno(ml_dsa_mgr) != 0) {
        WARN("init_mb_mgr_auto error %d for ML-DSA: %s\n",
             imb_get_errno(ml_dsa_mgr),
             imb_get_strerror(imb_get_errno(ml_dsa_mgr)));
        free_mb_mgr(ml_dsa_mgr);
        ml_dsa_mgr = NULL;
        return 0;
    }
    return 1;
}

/* Caller must ensure no live IMB_ML_DSA handles remain before this runs. */
void qat_sw_ml_dsa_free_ipsec_mb_mgr(void)
{
    if (ml_dsa_mgr != NULL) {
        free_mb_mgr(ml_dsa_mgr);
        ml_dsa_mgr = NULL;
    }
}

IMB_ML_DSA *qat_sw_ml_dsa_ctx_new(IMB_ML_DSA_ALG alg)
{
    IMB_ML_DSA *ctx = NULL;

    if (ml_dsa_mgr == NULL) {
        WARN("ML-DSA IMB_MGR not initialized\n");
        return NULL;
    }
    if (imb_ml_dsa_new(ml_dsa_mgr, alg, &ctx) != 0 || ctx == NULL) {
        WARN("imb_ml_dsa_new failed for alg %d\n", (int)alg);
        return NULL;
    }
    return ctx;
}

void qat_sw_ml_dsa_ctx_free(IMB_ML_DSA *ctx)
{
    if (ctx != NULL)
        imb_ml_dsa_free(ctx);
}

size_t qat_sw_ml_dsa_pubkey_bytes(IMB_ML_DSA_ALG alg)
{
    switch (alg) {
    case IMB_ML_DSA_44: return IMB_ML_DSA_44_PUBKEY_BYTES;
    case IMB_ML_DSA_65: return IMB_ML_DSA_65_PUBKEY_BYTES;
    case IMB_ML_DSA_87: return IMB_ML_DSA_87_PUBKEY_BYTES;
    default: return 0;
    }
}

size_t qat_sw_ml_dsa_privkey_bytes(IMB_ML_DSA_ALG alg)
{
    switch (alg) {
    case IMB_ML_DSA_44: return IMB_ML_DSA_44_PRIVKEY_BYTES;
    case IMB_ML_DSA_65: return IMB_ML_DSA_65_PRIVKEY_BYTES;
    case IMB_ML_DSA_87: return IMB_ML_DSA_87_PRIVKEY_BYTES;
    default: return 0;
    }
}

size_t qat_sw_ml_dsa_sig_bytes(IMB_ML_DSA_ALG alg)
{
    switch (alg) {
    case IMB_ML_DSA_44: return IMB_ML_DSA_44_SIG_BYTES;
    case IMB_ML_DSA_65: return IMB_ML_DSA_65_SIG_BYTES;
    case IMB_ML_DSA_87: return IMB_ML_DSA_87_SIG_BYTES;
    default: return 0;
    }
}

/* NIST security strength category, see FIPS 204 Section 4 (Table 1/2) */
int qat_sw_ml_dsa_security_bits(IMB_ML_DSA_ALG alg)
{
    switch (alg) {
    case IMB_ML_DSA_44: return 128;
    case IMB_ML_DSA_65: return 192;
    case IMB_ML_DSA_87: return 256;
    default: return 0;
    }
}

int qat_sw_ml_dsa_bits(IMB_ML_DSA_ALG alg)
{
    return (int)(qat_sw_ml_dsa_pubkey_bytes(alg) * 8);
}

QAT_ML_DSA_KEY *qat_sw_ml_dsa_key_new(OSSL_LIB_CTX *libctx, IMB_ML_DSA_ALG alg,
                                   const char *propq)
{
    QAT_ML_DSA_KEY *key = OPENSSL_zalloc(sizeof(*key));

    if (key == NULL)
        return NULL;

    key->libctx = libctx;
    key->alg = alg;
    QAT_CRYPTO_NEW_REF(&key->references, 1);

    if (propq != NULL) {
        key->propq = OPENSSL_strdup(propq);
        if (key->propq == NULL) {
            OPENSSL_free(key);
            return NULL;
        }
    }
    return key;
}

void qat_sw_ml_dsa_key_free(QAT_ML_DSA_KEY *key)
{
    int ref = 0;

    if (key == NULL)
        return;

    QAT_CRYPTO_DOWN_REF(&key->references, &ref);
    if (ref > 0)
        return;

    OPENSSL_free(key->propq);
    OPENSSL_cleanse(key->privkey, sizeof(key->privkey));
    OPENSSL_free(key);
}

int qat_sw_ml_dsa_key_up_ref(QAT_ML_DSA_KEY *key)
{
    int ref = 0;

    if (QAT_CRYPTO_UP_REF(&key->references, &ref) <= 0)
        return 0;
    return 1;
}
#endif /* ENABLE_QAT_SW_ML_DSA */
