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
 * @file qat_prov_sign_ml_dsa.c
 *
 * This file contains the qatprovider signature implementation for ML-DSA
 * (FIPS 204) offloaded to Software (Intel IPsec Multi-Buffer library)
 *
 *****************************************************************************/

#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "qat_provider.h"
#include "qat_utils.h"
#include "e_qat.h"

#ifdef ENABLE_QAT_SW_ML_DSA
# include "qat_sw_ml_dsa.h"

/* DER encoding of AlgorithmIdentifier { algorithm OBJECT IDENTIFIER }
 * for id-ml-dsa-44/65/87 = 2.16.840.1.101.3.4.3.{17,18,19}, per FIPS 204 /
 * draft-ietf-lamps-dilithium-certificates. */
static const unsigned char qat_ml_dsa_44_alg_id[] = {
    0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11
};
static const unsigned char qat_ml_dsa_65_alg_id[] = {
    0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12
};
static const unsigned char qat_ml_dsa_87_alg_id[] = {
    0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13
};

static const unsigned char *qat_ml_dsa_alg_id(IMB_ML_DSA_ALG alg, size_t *len)
{
    switch (alg) {
    case IMB_ML_DSA_44:
        *len = sizeof(qat_ml_dsa_44_alg_id);
        return qat_ml_dsa_44_alg_id;
    case IMB_ML_DSA_65:
        *len = sizeof(qat_ml_dsa_65_alg_id);
        return qat_ml_dsa_65_alg_id;
    case IMB_ML_DSA_87:
        *len = sizeof(qat_ml_dsa_87_alg_id);
        return qat_ml_dsa_87_alg_id;
    default:
        *len = 0;
        return NULL;
    }
}

typedef struct {
    QAT_ML_DSA_KEY *key;
    OSSL_LIB_CTX *libctx;

    /* EVP_PKEY_OP_SIGN or EVP_PKEY_OP_VERIFY; used to bind imb_ctx to the
     * cheaper of pubkey/privkey below. */
    int op;

    unsigned char *context_string;
    size_t context_string_len;

    /* msg_encode: 1 = pure FIPS 204 encoding (default); 0 = raw/pre-encoded. */
    int msg_encode;

    /* Buffer accumulated across EVP_DigestSign/VerifyUpdate() calls, since
     * the IPsec MB API is one-shot (no incremental hashing exposed).
     * tbscap tracks the allocated capacity so update() can grow it
     * geometrically instead of realloc'ing on every call. */
    unsigned char *tbs;
    size_t tbslen;
    size_t tbscap;

    /* Set via OSSL_SIGNATURE_PARAM_DETERMINISTIC, used for FIPS 204
     * deterministic (rnd = 0) signing, e.g. for KAT self-tests. */
    int deterministic;

    /* Optional fixed 32-byte randomizer for ACVP/FIPS KAT testing. */
    unsigned char test_entropy[32];
    int has_test_entropy;

    /* When set, msg is treated as a pre-computed \mu (exactly 64 bytes). */
    int mu;

    /* Signature stored via OSSL_SIGNATURE_PARAM_SIGNATURE for verify_message_final. */
    unsigned char *stored_sig;
    size_t stored_siglen;

    /* IMB_ML_DSA handle with ctx->key already bound, cached across calls
     * so repeated sign/verify on the same key don't pay the decode/validate
     * cost every time. Never shared with other contexts (e.g. via dupctx)
     * since IMB_ML_DSA is not thread-safe. */
    IMB_ML_DSA *imb_ctx;
    int imb_bound_op; /* op that imb_ctx was bound for; 0 if unbound */
} QAT_ML_DSA_SIGCTX;

static void *qat_ml_dsa_newctx(void *provctx, ossl_unused const char *propq)
{
    QAT_ML_DSA_SIGCTX *ctx;

    if (!qat_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->libctx = prov_libctx_of(provctx);
    ctx->msg_encode = 1; /* FIPS 204 pure encoding by default */
    return ctx;
}

static void qat_ml_dsa_freectx(void *vctx)
{
    QAT_ML_DSA_SIGCTX *ctx = vctx;

    if (ctx == NULL)
        return;
    qat_sw_ml_dsa_ctx_free(ctx->imb_ctx);
    qat_sw_ml_dsa_key_free(ctx->key);
    OPENSSL_free(ctx->context_string);
    OPENSSL_clear_free(ctx->tbs, ctx->tbscap);
    OPENSSL_free(ctx->stored_sig);
    OPENSSL_cleanse(ctx->test_entropy, sizeof(ctx->test_entropy));
    OPENSSL_free(ctx);
}

static void *qat_ml_dsa_dupctx(void *vctx)
{
    QAT_ML_DSA_SIGCTX *src = vctx;
    QAT_ML_DSA_SIGCTX *dst;

    if (src == NULL)
        return NULL;

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;

    if (src->key != NULL) {
        if (!qat_sw_ml_dsa_key_up_ref(src->key))
            goto err;
        dst->key = src->key;
    }
    dst->libctx = src->libctx;
    dst->op = src->op;
    if (src->context_string != NULL) {
        dst->context_string = OPENSSL_memdup(src->context_string,
                                              src->context_string_len);
        if (dst->context_string == NULL)
            goto err;
        dst->context_string_len = src->context_string_len;
    }
    if (src->tbs != NULL) {
        dst->tbs = OPENSSL_memdup(src->tbs, src->tbslen);
        if (dst->tbs == NULL)
            goto err;
        dst->tbslen = src->tbslen;
        dst->tbscap = src->tbslen;
    }
    dst->deterministic = src->deterministic;
    dst->msg_encode = src->msg_encode;
    dst->mu = src->mu;
    memcpy(dst->test_entropy, src->test_entropy, sizeof(dst->test_entropy));
    dst->has_test_entropy = src->has_test_entropy;
    if (src->stored_sig != NULL) {
        dst->stored_sig = OPENSSL_memdup(src->stored_sig, src->stored_siglen);
        if (dst->stored_sig == NULL)
            goto err;
        dst->stored_siglen = src->stored_siglen;
    }
    /* dst->imb_ctx intentionally left NULL: IMB_ML_DSA is not thread-safe
     * for concurrent use, so each ctx lazily builds its own on first use. */
    return dst;
err:
    qat_ml_dsa_freectx(dst);
    return NULL;
}

static int qat_ml_dsa_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int qat_ml_dsa_signverify_init(void *vctx, void *vkey,
                                      const OSSL_PARAM params[], int op)
{
    QAT_ML_DSA_SIGCTX *ctx = vctx;

    if (!qat_prov_is_running() || ctx == NULL)
        return 0;
    /* Allow re-init with NULL key when one is already bound */
    if (vkey == NULL && ctx->key == NULL) {
        QATerr(ERR_LIB_PROV, QAT_R_NO_KEY_SET);
        return 0;
    }

    ctx->op = op;

    if (vkey != NULL) {
        if (!qat_sw_ml_dsa_key_up_ref((QAT_ML_DSA_KEY *)vkey))
            return 0;
        if (ctx->key != vkey) {
            qat_sw_ml_dsa_ctx_free(ctx->imb_ctx);
            ctx->imb_ctx = NULL;
        }
        qat_sw_ml_dsa_key_free(ctx->key);
        ctx->key = vkey;
    }

    OPENSSL_clear_free(ctx->tbs, ctx->tbscap);
    ctx->tbs = NULL;
    ctx->tbslen = 0;
    ctx->tbscap = 0;
    ctx->mu = 0;
    OPENSSL_free(ctx->stored_sig);
    ctx->stored_sig = NULL;
    ctx->stored_siglen = 0;

    if (params != NULL && !qat_ml_dsa_set_ctx_params(ctx, params))
        return 0;

    return 1;
}

static int qat_ml_dsa_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return qat_ml_dsa_signverify_init(vctx, vkey, params, EVP_PKEY_OP_SIGN);
}

static int qat_ml_dsa_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return qat_ml_dsa_signverify_init(vctx, vkey, params, EVP_PKEY_OP_VERIFY);
}

/* Maximum message buffer for streaming update; prevents unbounded growth.
 * This is a per-context bound, not process-wide - a caller with many
 * concurrent contexts can still buffer O(contexts * this) bytes. */
#define QAT_ML_DSA_MAX_MSG_BYTES (64U * 1024U * 1024U)

static int qat_ml_dsa_digest_signverify_update(void *vctx,
                                               const unsigned char *data,
                                               size_t datalen)
{
    QAT_ML_DSA_SIGCTX *ctx = vctx;
    unsigned char *tmp;

    if (ctx == NULL)
        return 0;
    if (datalen == 0)
        return 1;
    if (datalen > QAT_ML_DSA_MAX_MSG_BYTES - ctx->tbslen) {
        QATerr(ERR_LIB_PROV, QAT_R_INVALID_INPUT_LENGTH);
        return 0;
    }

    if (ctx->tbslen + datalen > ctx->tbscap) {
        size_t newcap = ctx->tbscap ? ctx->tbscap * 2 : 4096;

        while (newcap < ctx->tbslen + datalen)
            newcap *= 2;
        tmp = OPENSSL_realloc(ctx->tbs, newcap);
        if (tmp == NULL)
            return 0;
        ctx->tbs = tmp;
        ctx->tbscap = newcap;
    }
    memcpy(ctx->tbs + ctx->tbslen, data, datalen);
    ctx->tbslen += datalen;
    return 1;
}

/* Lazily build (or reuse) the IMB_ML_DSA handle for ctx->key, binding
 * pubkey for verify or privkey for sign. */
static IMB_ML_DSA *qat_ml_dsa_get_imb_ctx(QAT_ML_DSA_SIGCTX *ctx)
{
    /* Rebind if the cached context was bound for a different operation */
    if (ctx->imb_ctx != NULL && ctx->imb_bound_op != ctx->op) {
        qat_sw_ml_dsa_ctx_free(ctx->imb_ctx);
        ctx->imb_ctx = NULL;
    }
    if (ctx->imb_ctx != NULL)
        return ctx->imb_ctx;

    ctx->imb_ctx = qat_sw_ml_dsa_ctx_new(ctx->key->alg);
    if (ctx->imb_ctx == NULL)
        return NULL;

    if (ctx->op == EVP_PKEY_OP_VERIFY) {
        if (!ctx->key->haspubkey
                || imb_ml_dsa_set_pubkey(ctx->imb_ctx, ctx->key->pubkey,
                                        ctx->key->pubkeylen) != 0) {
            WARN("imb_ml_dsa_set_pubkey failed\n");
            goto err;
        }
    } else {
        if (!ctx->key->hasprivkey
                || imb_ml_dsa_set_privkey(ctx->imb_ctx, ctx->key->privkey,
                                         ctx->key->privkeylen) != 0) {
            WARN("imb_ml_dsa_set_privkey failed\n");
            goto err;
        }
    }
    ctx->imb_bound_op = ctx->op;
    return ctx->imb_ctx;
err:
    qat_sw_ml_dsa_ctx_free(ctx->imb_ctx);
    ctx->imb_ctx = NULL;
    return NULL;
}

static int qat_ml_dsa_sign(void *vctx, unsigned char *sig, size_t *siglen,
                           size_t sigsize, const unsigned char *tbs,
                           size_t tbslen)
{
    QAT_ML_DSA_SIGCTX *ctx = vctx;
    IMB_ML_DSA *imb_ctx;
    IMB_ML_DSA_SIGN_PARAMS sign_params;
    unsigned char rnd[IMB_ML_DSA_SIGN_RND_BYTES] = { 0 };
    size_t needed;
    int ret = 0;

    if (ctx == NULL || ctx->key == NULL || !ctx->key->hasprivkey)
        return 0;
    if (ctx->mu && tbslen != IMB_ML_DSA_MU_BYTES) {
        QATerr(ERR_LIB_PROV, QAT_R_INVALID_INPUT_LENGTH);
        return 0;
    }

    needed = qat_sw_ml_dsa_sig_bytes(ctx->key->alg);
    if (sig == NULL) {
        if (siglen == NULL) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        *siglen = needed;
        return 1;
    }
    if (sigsize < needed) {
        QATerr(ERR_LIB_PROV, QAT_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

#ifdef ENABLE_QAT_FIPS
    qat_fips_service_indicator = 1;
#endif

    imb_ctx = qat_ml_dsa_get_imb_ctx(ctx);
    if (imb_ctx == NULL)
        goto end;

    /* size must be set for the library's struct-layout validation to pass */
    IMB_ML_DSA_SIGN_PARAMS_INIT(&sign_params);
    if (ctx->mu) {
        sign_params.msg_is_mu = 1;
    } else {
        sign_params.ctx = ctx->context_string;
        sign_params.ctx_len = ctx->context_string_len;
    }
    if (ctx->has_test_entropy) {
        sign_params.rnd_32 = ctx->test_entropy;
        sign_params.rnd_len = sizeof(ctx->test_entropy);
    } else if (ctx->deterministic) {
        static const unsigned char zero_rnd_32[32] = { 0 };
        sign_params.rnd_32 = zero_rnd_32;
        sign_params.rnd_len = sizeof(zero_rnd_32);
    } else {
        /* Hedged signing: draw the randomizer from OpenSSL's own DRBG
         * (matches the default provider's ml_dsa_sign()) instead of
         * relying solely on IPsec-MB's internal RNG, which sits outside
         * the FIPS module boundary and ignores libctx-scoped RAND. */
        if (RAND_priv_bytes_ex(ctx->libctx, rnd, sizeof(rnd), 0) <= 0) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SIGN);
            goto end;
        }
        sign_params.rnd_32 = rnd;
        sign_params.rnd_len = sizeof(rnd);
    }

    /* sig_len is now [in,out]: library rejects entry values below sig_bytes */
    *siglen = sigsize;
    if (imb_ml_dsa_sign(imb_ctx, sig, siglen, tbs, tbslen, &sign_params) != 0) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SIGN);
        WARN("imb_ml_dsa_sign failed\n");
        goto end;
    }
    ret = 1;
end:
    OPENSSL_cleanse(rnd, sizeof(rnd));
#ifdef ENABLE_QAT_FIPS
    qat_fips_service_indicator = 0;
#endif
    return ret;
}

static int qat_ml_dsa_verify(void *vctx, const unsigned char *sig,
                             size_t siglen, const unsigned char *tbs,
                             size_t tbslen)
{
    QAT_ML_DSA_SIGCTX *ctx = vctx;
    IMB_ML_DSA *imb_ctx;
    IMB_ML_DSA_VERIFY_PARAMS verify_params;
    int ret = 0;

    if (ctx == NULL || ctx->key == NULL || !ctx->key->haspubkey)
        return 0;
    if (ctx->mu && tbslen != IMB_ML_DSA_MU_BYTES) {
        QATerr(ERR_LIB_PROV, QAT_R_INVALID_INPUT_LENGTH);
        return 0;
    }

#ifdef ENABLE_QAT_FIPS
    qat_fips_service_indicator = 1;
#endif

    imb_ctx = qat_ml_dsa_get_imb_ctx(ctx);
    if (imb_ctx == NULL)
        goto end;

    /* size must be set for the library's struct-layout validation to pass */
    IMB_ML_DSA_VERIFY_PARAMS_INIT(&verify_params);
    if (ctx->mu) {
        verify_params.msg_is_mu = 1;
    } else {
        verify_params.ctx = ctx->context_string;
        verify_params.ctx_len = ctx->context_string_len;
    }

    if (imb_ml_dsa_verify(imb_ctx, tbs, tbslen, sig, siglen,
                          &verify_params) != 0) {
        goto end;
    }
    ret = 1;
end:
#ifdef ENABLE_QAT_FIPS
    qat_fips_service_indicator = 0;
#endif
    return ret;
}

static int qat_ml_dsa_digest_sign_final(void *vctx, unsigned char *sig,
                                        size_t *siglen, size_t sigsize)
{
    QAT_ML_DSA_SIGCTX *ctx = vctx;

    if (ctx == NULL)
        return 0;
    return qat_ml_dsa_sign(ctx, sig, siglen, sigsize,
                           ctx->tbs, ctx->tbslen);
}

static int qat_ml_dsa_digest_verify_final(void *vctx, const unsigned char *sig,
                                          size_t siglen)
{
    QAT_ML_DSA_SIGCTX *ctx = vctx;

    if (ctx == NULL)
        return 0;
    return qat_ml_dsa_verify(ctx, sig, siglen, ctx->tbs, ctx->tbslen);
}

static int qat_ml_dsa_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    QAT_ML_DSA_SIGCTX *ctx = vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL && ctx->key != NULL) {
        size_t len = 0;
        const unsigned char *aid = qat_ml_dsa_alg_id(ctx->key->alg, &len);

        if (aid == NULL || !OSSL_PARAM_set_octet_string(p, aid, len))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p != NULL
        && !OSSL_PARAM_set_octet_string(p, ctx->context_string,
                                        ctx->context_string_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC);
    if (p != NULL && !OSSL_PARAM_set_int(p, ctx->deterministic))
        return 0;

    return 1;
}

static const OSSL_PARAM qat_ml_dsa_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *qat_ml_dsa_gettable_ctx_params_fn(void *vctx,
                                                           void *provctx)
{
    return qat_ml_dsa_gettable_ctx_params;
}

static int qat_ml_dsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    QAT_ML_DSA_SIGCTX *ctx = vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p != NULL) {
        void *buf = NULL;
        size_t len = 0;

        if (p->data_size > QAT_ML_DSA_MAX_CONTEXT_STRING_BYTES)
            return 0;
        OPENSSL_free(ctx->context_string);
        ctx->context_string = NULL;
        ctx->context_string_len = 0;
        if (p->data_size > 0) {
            if (!OSSL_PARAM_get_octet_string(p, &buf, 0, &len))
                return 0;
            ctx->context_string = buf;
            ctx->context_string_len = len;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC);
    if (p != NULL && !OSSL_PARAM_get_int(p, &ctx->deterministic))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_TEST_ENTROPY);
    if (p != NULL) {
        void *vp = ctx->test_entropy;
        size_t len = 0;

        if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(ctx->test_entropy), &len)
            || len != sizeof(ctx->test_entropy)) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_SEED_LENGTH);
            return 0;
        }
        ctx->has_test_entropy = 1;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MU);
    if (p != NULL && !OSSL_PARAM_get_int(p, &ctx->mu))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_SIGNATURE);
    if (p != NULL) {
        void *buf = NULL;
        size_t len = 0;

        if (!OSSL_PARAM_get_octet_string(p, &buf, 0, &len))
            return 0;
        OPENSSL_free(ctx->stored_sig);
        ctx->stored_sig = buf;
        ctx->stored_siglen = len;
    }

    /* ML-DSA signing in this provider is always "pure" (no prehash).
     * message-encoding=0 would require a raw/ExternalMu path not exposed
     * by the current IPsec-MB API; reject it rather than mismap to MU. */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING);
    if (p != NULL) {
        int encoding = 0;

        if (!OSSL_PARAM_get_int(p, &encoding) || encoding != 1) {
            QATerr(ERR_LIB_PROV, QAT_R_NOT_SUPPORTED);
            return 0;
        }
        /* Stored for round-trip/validation only: this provider only ever
         * signs "pure" (encoding=1), so nothing else reads msg_encode. */
        ctx->msg_encode = encoding;
    }
    return 1;
}

static const OSSL_PARAM qat_ml_dsa_settable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, NULL),
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, NULL, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MU, NULL),
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *qat_ml_dsa_settable_ctx_params_fn(void *vctx,
                                                           void *provctx)
{
    return qat_ml_dsa_settable_ctx_params;
}

static int qat_ml_dsa_digest_sign_init(void *vctx, const char *mdname,
                                       void *vkey, const OSSL_PARAM params[])
{
    if (mdname != NULL && mdname[0] != '\0') {
        QATerr(ERR_LIB_PROV, QAT_R_INVALID_DIGEST);
        return 0;
    }
    return qat_ml_dsa_sign_init(vctx, vkey, params);
}

static int qat_ml_dsa_digest_verify_init(void *vctx, const char *mdname,
                                         void *vkey, const OSSL_PARAM params[])
{
    if (mdname != NULL && mdname[0] != '\0') {
        QATerr(ERR_LIB_PROV, QAT_R_INVALID_DIGEST);
        return 0;
    }
    return qat_ml_dsa_verify_init(vctx, vkey, params);
}

static int qat_ml_dsa_digest_sign(void *vctx, unsigned char *sig, size_t *siglen,
                                  size_t sigsize, const unsigned char *tbs,
                                  size_t tbslen)
{
    return qat_ml_dsa_sign(vctx, sig, siglen, sigsize, tbs, tbslen);
}

static int qat_ml_dsa_digest_verify(void *vctx, const unsigned char *sig,
                                    size_t siglen, const unsigned char *tbs,
                                    size_t tbslen)
{
    return qat_ml_dsa_verify(vctx, sig, siglen, tbs, tbslen);
}

/* verify_message_final: signature supplied earlier via OSSL_SIGNATURE_PARAM_SIGNATURE */
static int qat_ml_dsa_verify_message_final(void *vctx)
{
    QAT_ML_DSA_SIGCTX *ctx = vctx;

    if (ctx == NULL || ctx->stored_sig == NULL)
        return 0;
    return qat_ml_dsa_verify(ctx, ctx->stored_sig, ctx->stored_siglen,
                             ctx->tbs, ctx->tbslen);
}

const OSSL_DISPATCH qat_ml_dsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))qat_ml_dsa_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))qat_ml_dsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))qat_ml_dsa_dupctx },
    /* OpenSSL 3.5+ primary entry points for ML-DSA */
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
      (void (*)(void))qat_ml_dsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,
      (void (*)(void))qat_ml_dsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,
      (void (*)(void))qat_ml_dsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
      (void (*)(void))qat_ml_dsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,
      (void (*)(void))qat_ml_dsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,
      (void (*)(void))qat_ml_dsa_verify_message_final },
    /* Legacy sign_init/verify_init kept for EVP_PKEY_sign_init() callers */
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))qat_ml_dsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))qat_ml_dsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))qat_ml_dsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))qat_ml_dsa_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))qat_ml_dsa_digest_sign_init },
    /* One-shot digest_sign/verify (canonical for ML-DSA) */
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))qat_ml_dsa_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))qat_ml_dsa_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))qat_ml_dsa_digest_verify },
    /* Streaming update/final kept for callers that use the update API */
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))qat_ml_dsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))qat_ml_dsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))qat_ml_dsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))qat_ml_dsa_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
      (void (*)(void))qat_ml_dsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))qat_ml_dsa_gettable_ctx_params_fn },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
      (void (*)(void))qat_ml_dsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))qat_ml_dsa_settable_ctx_params_fn },
    { 0, NULL }
};

#endif /* ENABLE_QAT_SW_ML_DSA */
