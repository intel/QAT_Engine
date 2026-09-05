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
 * @file qat_prov_kmgmt_ml_dsa.c
 *
 * This file contains the qatprovider key management implementation for
 * ML-DSA (FIPS 204) offloaded to Software (Intel IPsec Multi-Buffer library)
 *
 *****************************************************************************/

#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include "qat_provider.h"
#include "qat_utils.h"
#include "e_qat.h"

#ifdef ENABLE_QAT_SW_ML_DSA
# include "qat_sw_ml_dsa.h"

static void *qat_ml_dsa_new_key(void *provctx, IMB_ML_DSA_ALG alg)
{
    if (!qat_prov_is_running())
        return NULL;
    return qat_sw_ml_dsa_key_new(prov_libctx_of(provctx), alg, NULL);
}

static void *qat_ml_dsa_44_new_key(void *provctx)
{
    return qat_ml_dsa_new_key(provctx, IMB_ML_DSA_44);
}

static void *qat_ml_dsa_65_new_key(void *provctx)
{
    return qat_ml_dsa_new_key(provctx, IMB_ML_DSA_65);
}

static void *qat_ml_dsa_87_new_key(void *provctx)
{
    return qat_ml_dsa_new_key(provctx, IMB_ML_DSA_87);
}

static void qat_ml_dsa_free_key(void *keydata)
{
    qat_sw_ml_dsa_key_free((QAT_ML_DSA_KEY *)keydata);
}

static int qat_ml_dsa_has(const void *keydata, int selection)
{
    const QAT_ML_DSA_KEY *key = keydata;
    int ok = 0;

    if (qat_prov_is_running() && key != NULL) {
        ok = 1;
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && key->haspubkey;
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && key->hasprivkey;
    }
    return ok;
}

static int qat_ml_dsa_validate(void *keydata, int selection, ossl_unused int checktype)
{
    QAT_ML_DSA_KEY *key = keydata;
    IMB_ML_DSA *ctx;
    int ret = 0;

    if (!qat_prov_is_running() || key == NULL) {
        QATerr(ERR_LIB_PROV, QAT_R_NO_KEY_SET);
        return 0;
    }
    if (!qat_ml_dsa_has(key, selection)) {
        QATerr(ERR_LIB_PROV, QAT_R_NO_KEY_SET);
        return 0;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 1;

    ctx = qat_sw_ml_dsa_ctx_new(key->alg);
    if (ctx == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && key->hasprivkey) {
        if (imb_ml_dsa_privkey_validate(ctx, key->privkey, key->privkeylen) != 0) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_KEY);
            goto err;
        }
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key->haspubkey) {
        if (imb_ml_dsa_pubkey_validate(ctx, key->pubkey, key->pubkeylen) != 0) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_KEY);
            goto err;
        }
    }
    /* For a keypair, verify that the private key encodes the same public key */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR
            && key->hasprivkey && key->haspubkey) {
        unsigned char derived_pub[IMB_ML_DSA_87_PUBKEY_BYTES];

        if (imb_ml_dsa_pubkey_from_privkey(ctx, key->privkey, key->privkeylen,
                                           derived_pub, sizeof(derived_pub)) != 0
                || CRYPTO_memcmp(derived_pub, key->pubkey,
                                 qat_sw_ml_dsa_pubkey_bytes(key->alg)) != 0) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_KEY);
            goto err;
        }
    }
    ret = 1;
err:
    qat_sw_ml_dsa_ctx_free(ctx);
    return ret;
}

static int qat_ml_dsa_match(const void *keydata1, const void *keydata2,
                            int selection)
{
    const QAT_ML_DSA_KEY *key1 = keydata1;
    const QAT_ML_DSA_KEY *key2 = keydata2;

    if (!qat_prov_is_running())
        return 0;
    if (key1 == NULL || key2 == NULL)
        return key1 == key2;
    if (key1->alg != key2->alg)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (key1->haspubkey != key2->haspubkey)
            return 0;
        if (key1->haspubkey
            && (key1->pubkeylen != key2->pubkeylen
                || memcmp(key1->pubkey, key2->pubkey, key1->pubkeylen) != 0))
            return 0;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (key1->hasprivkey != key2->hasprivkey)
            return 0;
        if (key1->hasprivkey
            && (key1->privkeylen != key2->privkeylen
                || CRYPTO_memcmp(key1->privkey, key2->privkey, key1->privkeylen) != 0))
            return 0;
    }
    return 1;
}

static void *qat_ml_dsa_load(const void *reference, size_t reference_sz)
{
    QAT_ML_DSA_KEY *key = NULL;

    if (qat_prov_is_running() && reference_sz == sizeof(key)) {
        key = *(QAT_ML_DSA_KEY **)reference;
        *(QAT_ML_DSA_KEY **)reference = NULL;
        return key;
    }
    return NULL;
}

static void *qat_ml_dsa_dup(const void *keydata_from, int selection)
{
    const QAT_ML_DSA_KEY *src = keydata_from;
    QAT_ML_DSA_KEY *dst;

    if (!qat_prov_is_running() || src == NULL)
        return NULL;

    dst = qat_sw_ml_dsa_key_new(src->libctx, src->alg, src->propq);
    if (dst == NULL)
        return NULL;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && src->haspubkey) {
        memcpy(dst->pubkey, src->pubkey, src->pubkeylen);
        dst->pubkeylen = src->pubkeylen;
        dst->haspubkey = 1;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && src->hasprivkey) {
        memcpy(dst->privkey, src->privkey, src->privkeylen);
        dst->privkeylen = src->privkeylen;
        dst->hasprivkey = 1;
    }
    return dst;
}

static int qat_ml_dsa_get_params(void *key, OSSL_PARAM params[])
{
    QAT_ML_DSA_KEY *dsakey = key;
    OSSL_PARAM *p;

    if (!qat_prov_is_running() || dsakey == NULL)
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, qat_sw_ml_dsa_bits(dsakey->alg)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, qat_sw_ml_dsa_security_bits(dsakey->alg)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, (int)qat_sw_ml_dsa_sig_bytes(dsakey->alg)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL
        && dsakey->haspubkey
        && !OSSL_PARAM_set_octet_string(p, dsakey->pubkey, dsakey->pubkeylen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL
        && dsakey->hasprivkey
        && !OSSL_PARAM_set_octet_string(p, dsakey->privkey, dsakey->privkeylen))
        return 0;
    return 1;
}

static const OSSL_PARAM qat_ml_dsa_gettable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *qat_ml_dsa_gettable_params_fn(void *provctx)
{
    return qat_ml_dsa_gettable_params;
}

static const OSSL_PARAM qat_ml_dsa_key_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *qat_ml_dsa_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return qat_ml_dsa_key_types;
    return NULL;
}

static int qat_ml_dsa_import(void *keydata, int selection,
                             const OSSL_PARAM params[])
{
    QAT_ML_DSA_KEY *key = keydata;
    const OSSL_PARAM *p;
    void *buf;
    size_t len;
    int imported = 0;

    if (key == NULL || params == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {
            buf = key->pubkey;
            len = qat_sw_ml_dsa_pubkey_bytes(key->alg);
            if (!OSSL_PARAM_get_octet_string(p, &buf, sizeof(key->pubkey), &len)
                || len != qat_sw_ml_dsa_pubkey_bytes(key->alg)) {
                QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GET_PARAMETER);
                return 0;
            }
            key->pubkeylen = len;
            key->haspubkey = 1;
            imported = 1;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL) {
            buf = key->privkey;
            len = qat_sw_ml_dsa_privkey_bytes(key->alg);
            if (!OSSL_PARAM_get_octet_string(p, &buf, sizeof(key->privkey), &len)
                || len != qat_sw_ml_dsa_privkey_bytes(key->alg)) {
                QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GET_PARAMETER);
                return 0;
            }
            key->privkeylen = len;
            key->hasprivkey = 1;
            imported = 1;

            /* Always derive the public key from the private key; it is the
             * source of truth and rejects any mismatched separately-supplied key. */
            {
                IMB_ML_DSA *dctx = qat_sw_ml_dsa_ctx_new(key->alg);
                unsigned char derived_pub[sizeof(key->pubkey)];
                int had_pubkey = key->haspubkey;
                size_t had_pubkeylen = key->pubkeylen;

                if (dctx == NULL)
                    return 0;
                len = qat_sw_ml_dsa_pubkey_bytes(key->alg);
                if (imb_ml_dsa_pubkey_from_privkey(dctx, key->privkey, key->privkeylen,
                                                    derived_pub, sizeof(derived_pub)) != 0) {
                    QATerr(ERR_LIB_PROV, QAT_R_INVALID_KEY);
                    qat_sw_ml_dsa_ctx_free(dctx);
                    return 0;
                }
                qat_sw_ml_dsa_ctx_free(dctx);
                if (had_pubkey
                        && (had_pubkeylen != len
                            || CRYPTO_memcmp(derived_pub, key->pubkey, len) != 0)) {
                    QATerr(ERR_LIB_PROV, QAT_R_INVALID_KEY);
                    return 0;
                }
                memcpy(key->pubkey, derived_pub, len);
                key->pubkeylen = len;
                key->haspubkey = 1;
            }
        }
    }
    if (!imported) {
        QATerr(ERR_LIB_PROV, QAT_R_MISSING_KEY);
        return 0;
    }
    return 1;
}

static int qat_ml_dsa_export(void *keydata, int selection,
                             OSSL_CALLBACK *param_cb, void *cbarg)
{
    QAT_ML_DSA_KEY *key = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    if (!qat_prov_is_running() || key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
        && key->haspubkey
        && !OSSL_PARAM_BLD_push_octet_string(tmpl, OSSL_PKEY_PARAM_PUB_KEY,
                                              key->pubkey, key->pubkeylen))
        goto err;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && key->hasprivkey
        && !OSSL_PARAM_BLD_push_octet_string(tmpl, OSSL_PKEY_PARAM_PRIV_KEY,
                                              key->privkey, key->privkeylen))
        goto err;

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);
    OSSL_PARAM_free(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    return ret;
}

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    IMB_ML_DSA_ALG alg;
} QAT_ML_DSA_GENCTX;

static int qat_ml_dsa_gen_set_params(void *genctx, const OSSL_PARAM params[]);

static void *qat_ml_dsa_gen_init(void *provctx, int selection,
                                 const OSSL_PARAM params[], IMB_ML_DSA_ALG alg)
{
    QAT_ML_DSA_GENCTX *gctx;

    if (!qat_prov_is_running())
        return NULL;

    gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx == NULL)
        return NULL;
    gctx->libctx = prov_libctx_of(provctx);
    gctx->alg = alg;

    if (params != NULL && !qat_ml_dsa_gen_set_params(gctx, params)) {
        OPENSSL_free(gctx);
        return NULL;
    }
    return gctx;
}

static void *qat_ml_dsa_44_gen_init(void *provctx, int selection,
                                    const OSSL_PARAM params[])
{
    return qat_ml_dsa_gen_init(provctx, selection, params, IMB_ML_DSA_44);
}

static void *qat_ml_dsa_65_gen_init(void *provctx, int selection,
                                    const OSSL_PARAM params[])
{
    return qat_ml_dsa_gen_init(provctx, selection, params, IMB_ML_DSA_65);
}

static void *qat_ml_dsa_87_gen_init(void *provctx, int selection,
                                    const OSSL_PARAM params[])
{
    return qat_ml_dsa_gen_init(provctx, selection, params, IMB_ML_DSA_87);
}

/* No algorithm-specific keygen params are supported yet, but a NULL dispatch
 * entry makes EVP_PKEY_CTX_set_params() fail even for an empty params list
 * (e.g. via EVP_PKEY_Q_keygen()), so accept an empty/properties-only list
 * like qat_ecx does. */
static int qat_ml_dsa_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    QAT_ML_DSA_GENCTX *gctx = genctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        OPENSSL_free(gctx->propq);
        gctx->propq = OPENSSL_strdup(p->data);
        if (gctx->propq == NULL)
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *qat_ml_dsa_gen_settable_params(ossl_unused void *genctx,
                                                        ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END
    };
    return settable;
}

static void *qat_ml_dsa_gen(void *genctx, ossl_unused OSSL_CALLBACK *osslcb, ossl_unused void *cbarg)
{
    QAT_ML_DSA_GENCTX *gctx = genctx;
    QAT_ML_DSA_KEY *key;
    IMB_ML_DSA *ctx;

    if (gctx == NULL)
        return NULL;

    key = qat_sw_ml_dsa_key_new(gctx->libctx, gctx->alg, gctx->propq);
    if (key == NULL)
        return NULL;

    ctx = qat_sw_ml_dsa_ctx_new(gctx->alg);
    if (ctx == NULL) {
        qat_sw_ml_dsa_key_free(key);
        return NULL;
    }

    if (imb_ml_dsa_keypair(ctx, key->pubkey, sizeof(key->pubkey),
                           key->privkey, sizeof(key->privkey), NULL) != 0) {
        WARN("imb_ml_dsa_keypair failed\n");
        qat_sw_ml_dsa_ctx_free(ctx);
        qat_sw_ml_dsa_key_free(key);
        return NULL;
    }
    /* ctx kept alive for FIPS PCT: keypair() leaves it ready for sign and verify */

#ifdef ENABLE_QAT_FIPS
    /* FIPS 140-3 IG 10.3.A: pairwise consistency test - sign/verify must round-trip */
    {
        static const unsigned char pct_msg[] = "QAT ML-DSA PCT";
        static const unsigned char zero_rnd_32[32] = { 0 };
        IMB_ML_DSA_SIGN_PARAMS sign_params;
        IMB_ML_DSA_VERIFY_PARAMS verify_params;
        unsigned char *sig = NULL;
        size_t siglen = qat_sw_ml_dsa_sig_bytes(gctx->alg);
        int pct_ok = 0;

        sig = OPENSSL_malloc(siglen);
        if (sig == NULL)
            goto pct_fail;

        IMB_ML_DSA_SIGN_PARAMS_INIT(&sign_params);
        sign_params.rnd_32 = zero_rnd_32;
        sign_params.rnd_len = sizeof(zero_rnd_32);
        if (imb_ml_dsa_sign(ctx, sig, &siglen, pct_msg, sizeof(pct_msg) - 1,
                            &sign_params) != 0)
            goto pct_fail;

        IMB_ML_DSA_VERIFY_PARAMS_INIT(&verify_params);
        pct_ok = (imb_ml_dsa_verify(ctx, pct_msg, sizeof(pct_msg) - 1,
                                    sig, siglen, &verify_params) == 0);
    pct_fail:
        qat_sw_ml_dsa_ctx_free(ctx);
        OPENSSL_free(sig);
        if (!pct_ok) {
            WARN("ML-DSA PCT failed\n");
            QATerr(ERR_LIB_PROV, QAT_R_KEYGEN_FAILURE);
            qat_sw_ml_dsa_key_free(key);
            return NULL;
        }
    }
#else
    qat_sw_ml_dsa_ctx_free(ctx);
#endif /* ENABLE_QAT_FIPS */

    key->pubkeylen = qat_sw_ml_dsa_pubkey_bytes(gctx->alg);
    key->privkeylen = qat_sw_ml_dsa_privkey_bytes(gctx->alg);
    key->haspubkey = 1;
    key->hasprivkey = 1;
    return key;
}

static void qat_ml_dsa_gen_cleanup(void *genctx)
{
    QAT_ML_DSA_GENCTX *gctx = genctx;

    if (gctx == NULL)
        return;
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

# define QAT_ML_DSA_KEYMGMT_FUNCTIONS(bits, ALG)                             \
const OSSL_DISPATCH qat_ml_dsa_##bits##_keymgmt_functions[] = {              \
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))qat_ml_dsa_##bits##_new_key },  \
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))qat_ml_dsa_free_key },         \
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))qat_ml_dsa_has },               \
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))qat_ml_dsa_validate },     \
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))qat_ml_dsa_match },           \
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))qat_ml_dsa_load },             \
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))qat_ml_dsa_dup },               \
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))qat_ml_dsa_get_params }, \
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                    \
      (void (*)(void))qat_ml_dsa_gettable_params_fn },                      \
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))qat_ml_dsa_import },         \
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,                                       \
      (void (*)(void))qat_ml_dsa_imexport_types },                          \
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))qat_ml_dsa_export },         \
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,                                       \
      (void (*)(void))qat_ml_dsa_imexport_types },                          \
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))qat_ml_dsa_##bits##_gen_init }, \
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))qat_ml_dsa_gen },               \
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                     \
      (void (*)(void))qat_ml_dsa_gen_set_params },                          \
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                                \
      (void (*)(void))qat_ml_dsa_gen_settable_params },                     \
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))qat_ml_dsa_gen_cleanup }, \
    { 0, NULL }                                                             \
}

QAT_ML_DSA_KEYMGMT_FUNCTIONS(44, IMB_ML_DSA_44);
QAT_ML_DSA_KEYMGMT_FUNCTIONS(65, IMB_ML_DSA_65);
QAT_ML_DSA_KEYMGMT_FUNCTIONS(87, IMB_ML_DSA_87);

#endif /* ENABLE_QAT_SW_ML_DSA */
