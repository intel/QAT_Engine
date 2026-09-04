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
 * @file qat_prov_kem_ml_kem.c
 *
 * This file contains the qatprovider KEM implementation for ML-KEM
 * (FIPS 203) offloaded to Software (Intel IPsec Multi-Buffer library)
 *
 *****************************************************************************/

#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include "qat_provider.h"
#include "qat_utils.h"
#include "e_qat.h"

#ifdef ENABLE_QAT_SW_ML_KEM
# include "qat_sw_ml_kem.h"

typedef struct {
    QAT_ML_KEM_KEY *key;
    int op; /* EVP_PKEY_OP_ENCAPSULATE or EVP_PKEY_OP_DECAPSULATE */

    /* Optional deterministic encapsulation randomness (FIPS 203 "m"),
     * settable via OSSL_KEM_PARAM_IKME - used for ACVP-style conformance
     * testing. NULL means fresh-random encapsulation (the default).
     * Cleared after each encapsulate call (one-shot). */
    unsigned char ikme[QAT_ML_KEM_IKME_BYTES];
    int has_ikme;

    /* IMB_ML_KEM handle with ctx->key already bound, cached across calls
     * so repeated encapsulate/decapsulate on the same key don't pay the
     * decode/validate cost every time. Never shared with other contexts
     * (e.g. via dupctx) since IMB_ML_KEM is not thread-safe. */
    IMB_ML_KEM *imb_ctx;
    int imb_bound_op; /* op that imb_ctx was bound for; 0 if unbound */
} QAT_ML_KEM_CTX;

static void *qat_ml_kem_newctx(ossl_unused void *provctx)
{
    QAT_ML_KEM_CTX *ctx;

    if (!qat_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    return ctx;
}

static void qat_ml_kem_freectx(void *vctx)
{
    QAT_ML_KEM_CTX *ctx = vctx;

    if (ctx == NULL)
        return;
    qat_sw_ml_kem_ctx_free(ctx->imb_ctx);
    qat_sw_ml_kem_key_free(ctx->key);
    OPENSSL_cleanse(ctx->ikme, sizeof(ctx->ikme));
    OPENSSL_free(ctx);
}

static void *qat_ml_kem_dupctx(void *vctx)
{
    QAT_ML_KEM_CTX *src = vctx;
    QAT_ML_KEM_CTX *dst;

    if (src == NULL)
        return NULL;

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;

    dst->op = src->op;
    if (src->key != NULL) {
        if (!qat_sw_ml_kem_key_up_ref(src->key))
            goto err;
        dst->key = src->key;
    }
    memcpy(dst->ikme, src->ikme, sizeof(dst->ikme));
    dst->has_ikme = src->has_ikme;
    /* dst->imb_ctx intentionally left NULL: IMB_ML_KEM is not thread-safe
     * for concurrent use, so each ctx lazily builds its own on first use. */
    return dst;
err:
    qat_ml_kem_freectx(dst);
    return NULL;
}

static int qat_ml_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int qat_ml_kem_init(void *vctx, void *vkey, int op,
                           const OSSL_PARAM params[])
{
    QAT_ML_KEM_CTX *ctx = vctx;

    if (!qat_prov_is_running() || ctx == NULL || vkey == NULL)
        return 0;

    if (!qat_sw_ml_kem_key_up_ref((QAT_ML_KEM_KEY *)vkey))
        return 0;
    if (ctx->key != vkey) {
        qat_sw_ml_kem_ctx_free(ctx->imb_ctx);
        ctx->imb_ctx = NULL;
    }
    qat_sw_ml_kem_key_free(ctx->key);
    ctx->key = vkey;
    ctx->op = op;

    if (params != NULL)
        return qat_ml_kem_set_ctx_params(ctx, params);
    return 1;
}

static int qat_ml_kem_encapsulate_init(void *vctx, void *vkey,
                                       const OSSL_PARAM params[])
{
    return qat_ml_kem_init(vctx, vkey, EVP_PKEY_OP_ENCAPSULATE, params);
}

static int qat_ml_kem_decapsulate_init(void *vctx, void *vkey,
                                       const OSSL_PARAM params[])
{
    QAT_ML_KEM_CTX *ctx = vctx;

    /* ikmE is only valid for encapsulation; clear stale value on decap init */
    if (ctx != NULL && ctx->has_ikme) {
        OPENSSL_cleanse(ctx->ikme, sizeof(ctx->ikme));
        ctx->has_ikme = 0;
    }
    return qat_ml_kem_init(vctx, vkey, EVP_PKEY_OP_DECAPSULATE, params);
}

/* Lazily build (or reuse) the IMB_ML_KEM handle for ctx->key, binding
 * pubkey for encapsulate or privkey for decapsulate. */
static IMB_ML_KEM *qat_ml_kem_get_imb_ctx(QAT_ML_KEM_CTX *ctx)
{
    /* Rebind if the cached context was bound for a different operation */
    if (ctx->imb_ctx != NULL && ctx->imb_bound_op != ctx->op) {
        qat_sw_ml_kem_ctx_free(ctx->imb_ctx);
        ctx->imb_ctx = NULL;
    }
    if (ctx->imb_ctx != NULL)
        return ctx->imb_ctx;

    ctx->imb_ctx = qat_sw_ml_kem_ctx_new(ctx->key->alg);
    if (ctx->imb_ctx == NULL)
        return NULL;

    if (ctx->op == EVP_PKEY_OP_ENCAPSULATE) {
        if (!ctx->key->haspubkey
                || imb_ml_kem_set_pubkey(ctx->imb_ctx, ctx->key->pubkey,
                                         ctx->key->pubkeylen) != 0) {
            WARN("imb_ml_kem_set_pubkey failed for encap\n");
            goto err;
        }
    } else {
        if (!ctx->key->hasprivkey
                || imb_ml_kem_set_privkey(ctx->imb_ctx, ctx->key->privkey,
                                         ctx->key->privkeylen) != 0) {
            WARN("imb_ml_kem_set_privkey failed for decap\n");
            goto err;
        }
    }
    ctx->imb_bound_op = ctx->op;
    return ctx->imb_ctx;
err:
    qat_sw_ml_kem_ctx_free(ctx->imb_ctx);
    ctx->imb_ctx = NULL;
    return NULL;
}

static int qat_ml_kem_encapsulate(void *vctx, unsigned char *out,
                                  size_t *outlen, unsigned char *secret,
                                  size_t *secretlen)
{
    QAT_ML_KEM_CTX *ctx = vctx;
    IMB_ML_KEM *imb_ctx;
    IMB_ML_KEM_ENCAP_PARAMS encap_params;
    size_t ct_needed, secret_needed;
    int ret = 0;

    if (ctx == NULL || ctx->key == NULL || !ctx->key->haspubkey) {
        QATerr(ERR_LIB_PROV, QAT_R_MISSING_KEY);
        return 0;
    }

    ct_needed = qat_sw_ml_kem_ciphertext_bytes(ctx->key->alg);
    secret_needed = IMB_ML_KEM_SHARED_SECRET_BYTES;

    if (out == NULL) {
        if (outlen != NULL)
            *outlen = ct_needed;
        if (secretlen != NULL)
            *secretlen = secret_needed;
        return 1;
    }
    if (secret == NULL) {
        QATerr(ERR_LIB_PROV, QAT_R_MISSING_SECRET);
        return 0;
    }
    if (outlen == NULL) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    if (secretlen == NULL) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    if (*outlen < ct_needed) {
        QATerr(ERR_LIB_PROV, QAT_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    if (*secretlen < secret_needed) {
        QATerr(ERR_LIB_PROV, QAT_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

#ifdef ENABLE_QAT_FIPS
    qat_fips_service_indicator = 1;
#endif

    imb_ctx = qat_ml_kem_get_imb_ctx(ctx);
    if (imb_ctx == NULL)
        goto end;

    /* size must be set for the library's struct-layout validation to pass */
    IMB_ML_KEM_ENCAP_PARAMS_INIT(&encap_params);
    if (ctx->has_ikme) {
        encap_params.m_32 = ctx->ikme;
        encap_params.m_len = sizeof(ctx->ikme);
    }

    if (imb_ml_kem_encap(imb_ctx, out, *outlen, secret, *secretlen, &encap_params) != 0) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GENERATE_KEY);
        WARN("imb_ml_kem_encap failed\n");
        goto end;
    }
    *outlen = ct_needed;
    *secretlen = secret_needed;
    ret = 1;
end:
    /* ikmE is one-shot: clear after each use so next call gets fresh entropy */
    if (ctx->has_ikme) {
        OPENSSL_cleanse(ctx->ikme, sizeof(ctx->ikme));
        ctx->has_ikme = 0;
    }
#ifdef ENABLE_QAT_FIPS
    qat_fips_service_indicator = 0;
#endif
    return ret;
}

static int qat_ml_kem_decapsulate(void *vctx, unsigned char *out,
                                  size_t *outlen, const unsigned char *in,
                                  size_t inlen)
{
    QAT_ML_KEM_CTX *ctx = vctx;
    IMB_ML_KEM *imb_ctx;
    size_t secret_needed;
    int ret = 0;

    if (ctx == NULL || ctx->key == NULL || !ctx->key->hasprivkey) {
        QATerr(ERR_LIB_PROV, QAT_R_MISSING_KEY);
        return 0;
    }

    secret_needed = IMB_ML_KEM_SHARED_SECRET_BYTES;
    if (out == NULL) {
        if (outlen != NULL)
            *outlen = secret_needed;
        return 1;
    }
    if (outlen == NULL) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    if (*outlen < secret_needed) {
        QATerr(ERR_LIB_PROV, QAT_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    if (inlen != qat_sw_ml_kem_ciphertext_bytes(ctx->key->alg)) {
        QATerr(ERR_LIB_PROV, QAT_R_INVALID_INPUT_LENGTH);
        return 0;
    }

#ifdef ENABLE_QAT_FIPS
    qat_fips_service_indicator = 1;
#endif

    imb_ctx = qat_ml_kem_get_imb_ctx(ctx);
    if (imb_ctx == NULL)
        goto end;

    if (imb_ml_kem_decap(imb_ctx, out, *outlen, in, inlen, NULL) != 0) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_DECRYPT);
        WARN("imb_ml_kem_decap failed\n");
        goto end;
    }
    *outlen = secret_needed;
    ret = 1;
end:
#ifdef ENABLE_QAT_FIPS
    qat_fips_service_indicator = 0;
#endif
    return ret;
}

static int qat_ml_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    QAT_ML_KEM_CTX *ctx = vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    /* ikmE is only meaningful for encapsulation */
    if (ctx->op != EVP_PKEY_OP_ENCAPSULATE)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_IKME);
    if (p != NULL) {
        void *buf = ctx->ikme;
        size_t len = 0;

        if (p->data_size != sizeof(ctx->ikme)) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_SEED_LENGTH);
            return 0;
        }
        if (!OSSL_PARAM_get_octet_string(p, &buf, sizeof(ctx->ikme), &len)
            || len != sizeof(ctx->ikme)) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_SEED_LENGTH);
            return 0;
        }
        ctx->has_ikme = 1;
    }
    return 1;
}

static const OSSL_PARAM qat_ml_kem_settable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_KEM_PARAM_IKME, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *qat_ml_kem_settable_ctx_params_fn(void *vctx,
                                                           void *provctx)
{
    return qat_ml_kem_settable_ctx_params;
}

static int qat_ml_kem_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    return 1;
}

static const OSSL_PARAM qat_ml_kem_gettable_ctx_params[] = {
    OSSL_PARAM_END
};

static const OSSL_PARAM *qat_ml_kem_gettable_ctx_params_fn(void *vctx,
                                                           void *provctx)
{
    return qat_ml_kem_gettable_ctx_params;
}

const OSSL_DISPATCH qat_ml_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))qat_ml_kem_newctx },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))qat_ml_kem_freectx },
    { OSSL_FUNC_KEM_DUPCTX, (void (*)(void))qat_ml_kem_dupctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
      (void (*)(void))qat_ml_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))qat_ml_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
      (void (*)(void))qat_ml_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))qat_ml_kem_decapsulate },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS, (void (*)(void))qat_ml_kem_get_ctx_params },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS,
      (void (*)(void))qat_ml_kem_gettable_ctx_params_fn },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS, (void (*)(void))qat_ml_kem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
      (void (*)(void))qat_ml_kem_settable_ctx_params_fn },
    { 0, NULL }
};

#endif /* ENABLE_QAT_SW_ML_KEM */
