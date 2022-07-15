/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022 Intel Corporation.
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
 * @file qat_prov_prf.c
 *
 * This file contains qatprovider implementation of PRF.
 *
 *****************************************************************************/

#include "qat_prov_prf.h"

#ifdef ENABLE_QAT_HW_PRF

static OSSL_FUNC_kdf_newctx_fn qat_tls_prf_new;
static OSSL_FUNC_kdf_freectx_fn qat_tls_prf_free;
static OSSL_FUNC_kdf_reset_fn qat_tls_prf_reset;
static OSSL_FUNC_kdf_derive_fn qat_tls_prf_derive;
static OSSL_FUNC_kdf_settable_ctx_params_fn qat_tls_prf_settable_ctx_params;
static OSSL_FUNC_kdf_set_ctx_params_fn qat_tls_prf_set_ctx_params;
static OSSL_FUNC_kdf_gettable_ctx_params_fn qat_tls_prf_gettable_ctx_params;
static OSSL_FUNC_kdf_get_ctx_params_fn qat_tls_prf_get_ctx_params;

static const EVP_MD *qat_prov_digest_md(const PROV_DIGEST *pd)
{
    return pd->md;
}

static int load_common(const OSSL_PARAM params[], const char **propquery,
                       ENGINE **engine)
{
    const OSSL_PARAM *p;

    *propquery = NULL;
    p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        *propquery = p->data;
    }

    *engine = NULL;

    return 1;
}

static const EVP_MD *qat_prov_digest_fetch(PROV_DIGEST *pd, OSSL_LIB_CTX *libctx,
                           const char *mdname, const char *propquery)
{
    EVP_MD_free(pd->alloc_md);
    pd->md = pd->alloc_md = EVP_MD_fetch(libctx, mdname, propquery);

    return pd->md;
}

static int qat_prov_digest_load_from_params(PROV_DIGEST *pd,
                                      const OSSL_PARAM params[],
                                      OSSL_LIB_CTX *ctx)
{
    const OSSL_PARAM *p;
    const char *propquery;

    if (params == NULL)
        return 1;

    if (!load_common(params, &propquery, &pd->engine))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST);
    if (p == NULL)
        return 1;
    if (p->data_type != OSSL_PARAM_UTF8_STRING)
        return 0;

    ERR_set_mark();
    qat_prov_digest_fetch(pd, ctx, p->data, propquery);

    if (pd->md != NULL)
        ERR_pop_to_mark();
    else
        ERR_clear_last_mark();
    return pd->md != NULL;
}

static void *qat_tls_prf_new(void *provctx)
{
    QAT_TLS_PRF *ctx;

    if (!qat_prov_is_running())
        return NULL;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    else
        ctx->provctx = provctx;
    ctx->pctx = OPENSSL_zalloc(sizeof(EVP_PKEY_CTX));
    if (ctx->pctx == NULL){
        WARN("Malloc for EVP_PKEY_CTX error.\n");
        return NULL;
    }
    if (!qat_tls1_prf_init(ctx->pctx)){
        WARN("EVP_PKEY_CTX init failed.\n");
        return NULL;
    }
    return ctx;
}

static void qat_tls_prf_free(void *vctx)
{
    QAT_TLS_PRF *ctx = (QAT_TLS_PRF *)vctx;

    if (ctx != NULL) {
        qat_prf_cleanup(ctx->pctx);
        OPENSSL_free(ctx->pctx);
        ctx->pctx = NULL;
        qat_tls_prf_reset(ctx);
        OPENSSL_free(ctx);
    }
}

static void qat_tls_prf_reset(void *vctx)
{
    QAT_TLS_PRF *ctx = (QAT_TLS_PRF *)vctx;
    void *provctx = ctx->provctx;

    EVP_MAC_CTX_free(ctx->P_hash);
    EVP_MAC_CTX_free(ctx->P_sha1);
    OPENSSL_clear_free(ctx->sec, ctx->seclen);
    OPENSSL_cleanse(ctx->seed, ctx->seedlen);
    OPENSSL_cleanse(ctx->qat_userLabel, ctx->qat_userLabel_len);
    memset(ctx, 0, sizeof(*ctx));
    ctx->provctx = provctx;
}

static int qat_tls_prf_derive(void *vctx, unsigned char *key, size_t keylen,
                               const OSSL_PARAM params[])
{
    QAT_TLS_PRF *ctx = (QAT_TLS_PRF *)vctx;
    QAT_TLS1_PRF_CTX *qat_prf_ctx = (QAT_TLS1_PRF_CTX *)EVP_PKEY_CTX_get_data(
                                                            ctx->pctx);
    const EVP_MD *md;

    if (!qat_prov_is_running() || !qat_tls_prf_set_ctx_params(ctx, params))
        return 0;

    md = qat_prov_digest_md(&ctx->digest);
    if (md == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }

    if (ctx->P_hash == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    if (ctx->sec == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SECRET);
        return 0;
    }
    if (ctx->seedlen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SEED);
        return 0;
    }
    if (keylen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }

    qat_prf_ctx->qat_md = md;
    if (!qat_tls1_prf_ctrl(ctx->pctx, EVP_PKEY_CTRL_TLS_SEED,
                               ctx->qat_userLabel_len, ctx->qat_userLabel)){
        WARN("Failed in setting prf userLabel.\n");
        return 0;
    }
    if (!qat_tls1_prf_ctrl(ctx->pctx, EVP_PKEY_CTRL_TLS_SEED,
                            ctx->seedlen, ctx->seed)) {
        WARN("Failed in setting prf seed.\n");
        return 0;
    }

    return qat_prf_tls_derive(ctx->pctx, key, &keylen);
}

static int qat_prf_common_set_ctx_params(QAT_TLS_PRF *ctx, const OSSL_PARAM params[])
{
    OSSL_LIB_CTX *libctx = prov_libctx_of(ctx->provctx);

    if (params == NULL)
        return 1;

    if (!qat_prov_digest_load_from_params(&ctx->digest, params, libctx))
        return 0;

    return 1;
}

static int qat_prov_set_macctx(EVP_MAC_CTX *macctx,
                         const OSSL_PARAM params[],
                         const char *ciphername,
                         const char *mdname,
                         const char *engine,
                         const char *properties,
                         const unsigned char *key,
                         size_t keylen)
{
    const OSSL_PARAM *p;
    OSSL_PARAM mac_params[6], *mp = mac_params;

    if (params != NULL) {
        if (mdname == NULL) {
            if ((p = OSSL_PARAM_locate_const(params,
                                            OSSL_ALG_PARAM_DIGEST)) != NULL) {
                if (p->data_type != OSSL_PARAM_UTF8_STRING)
                    return 0;
                mdname = p->data;
            }
        }
        if (ciphername == NULL) {
            if ((p = OSSL_PARAM_locate_const(params,
                                            OSSL_ALG_PARAM_CIPHER)) != NULL) {
                if (p->data_type != OSSL_PARAM_UTF8_STRING)
                    return 0;
                ciphername = p->data;
            }
        }
        if (engine == NULL) {
            if ((p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_ENGINE))
                    != NULL) {
                if (p->data_type != OSSL_PARAM_UTF8_STRING)
                    return 0;
                engine = p->data;
            }
        }
    }

    if (mdname != NULL)
        *mp++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 (char *)mdname, 0);
    if (ciphername != NULL)
        *mp++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                                 (char *)ciphername, 0);
    if (properties != NULL)
        *mp++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_PROPERTIES,
                                                 (char *)properties, 0);

#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODULE)
    if (engine != NULL)
        *mp++ = OSSL_PARAM_construct_utf8_string(OSSL_ALG_PARAM_ENGINE,
                                                 (char *) engine, 0);
#endif

    if (key != NULL)
        *mp++ = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                                                  (unsigned char *)key,
                                                  keylen);

    *mp = OSSL_PARAM_construct_end();

    return EVP_MAC_CTX_set_params(macctx, mac_params);

}

static int qat_prov_macctx_load_from_params(EVP_MAC_CTX **macctx,
                                      const OSSL_PARAM params[],
                                      const char *macname,
                                      const char *ciphername,
                                      const char *mdname,
                                      OSSL_LIB_CTX *libctx)
{
    const OSSL_PARAM *p;
    const char *properties = NULL;

    if (macname == NULL
        && (p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_MAC)) != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        macname = p->data;
    }
    if ((p = OSSL_PARAM_locate_const(params,
                                     OSSL_ALG_PARAM_PROPERTIES)) != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        properties = p->data;
    }

    /* If we got a new mac name, we make a new EVP_MAC_CTX */
    if (macname != NULL) {
        EVP_MAC *mac = EVP_MAC_fetch(libctx, macname, properties);

        EVP_MAC_CTX_free(*macctx);
        *macctx = mac == NULL ? NULL : EVP_MAC_CTX_new(mac);
        /* The context holds on to the MAC */
        EVP_MAC_free(mac);
        if (*macctx == NULL)
            return 0;
    }

    /*
     * If there is no MAC yet (and therefore, no MAC context), we ignore
     * all other parameters.
     */
    if (*macctx == NULL)
        return 1;

    if (qat_prov_set_macctx(*macctx, params, ciphername, mdname, NULL,
                             properties, NULL, 0))
        return 1;

    EVP_MAC_CTX_free(*macctx);
    *macctx = NULL;
    return 0;
}

static int qat_tls_prf_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    QAT_TLS_PRF *ctx = vctx;
    OSSL_LIB_CTX *libctx = prov_libctx_of(ctx->provctx);

    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST)) != NULL) {
        if (!qat_prf_common_set_ctx_params(ctx, params))
            return 0;
        if (strcasecmp(p->data, SN_md5_sha1) == 0) {
            if (!qat_prov_macctx_load_from_params(&ctx->P_hash, params,
                                                   OSSL_MAC_NAME_HMAC,
                                                   NULL, SN_md5, libctx)
                || !qat_prov_macctx_load_from_params(&ctx->P_sha1, params,
                                                      OSSL_MAC_NAME_HMAC,
                                                      NULL, SN_sha1, libctx))
                return 0;
        } else {
            EVP_MAC_CTX_free(ctx->P_sha1);
            if (!qat_prov_macctx_load_from_params(&ctx->P_hash, params,
                                                   OSSL_MAC_NAME_HMAC,
                                                   NULL, NULL, libctx))
                return 0;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SECRET)) != NULL) {
        OPENSSL_clear_free(ctx->sec, ctx->seclen);
        ctx->sec = NULL;
        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->sec, 0, &ctx->seclen))
            return 0;
        if (!qat_tls1_prf_ctrl(ctx->pctx, EVP_PKEY_CTRL_TLS_SECRET, 
                               ctx->seclen, ctx->sec)){
            WARN("Failed in setting prf secret.\n");
            return 0;
        }
    }
    /* The seed fields concatenate, so process them all */
    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SEED)) != NULL) {
        for (; p != NULL; p = OSSL_PARAM_locate_const(p + 1, OSSL_KDF_PARAM_SEED)) {
            if (ctx->qat_userLabel_len == 0){
                ctx->qat_userLabel = OPENSSL_zalloc(p->data_size + 1);
                if (ctx->qat_userLabel == NULL){
                    WARN("Zalloc error in qat_tls_prf_set_ctx_params\n");
                    return 0;
                }
                const void *q = ctx->qat_userLabel;
                size_t sz = 0;
                if (p->data_size != 0
                    && p->data != NULL
                    && !OSSL_PARAM_get_octet_string(p, (void **)&q,
                                                    TLS1_PRF_MAXBUF - ctx->seedlen,
                                                    &sz)){
                    OPENSSL_clear_free(ctx->qat_userLabel, ctx->qat_userLabel_len);
                    return 0;
                }
                ctx->qat_userLabel_len = sz;
            }
            else{
                const void *q = ctx->seed + ctx->seedlen;
                size_t sz = 0;
                if (p->data_size != 0
                    && p->data != NULL
                    && !OSSL_PARAM_get_octet_string(p, (void **)&q,
                                                    TLS1_PRF_MAXBUF - ctx->seedlen,
                                                    &sz))
                    return 0;
                ctx->seedlen += sz;
            }     
        }
    }
    return 1;
}

static const OSSL_PARAM *qat_tls_prf_settable_ctx_params(
        ossl_unused void *ctx, ossl_unused void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SEED, NULL, 0),
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int qat_tls_prf_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL)
        return OSSL_PARAM_set_size_t(p, SIZE_MAX);
    return -2;
}

static const OSSL_PARAM *qat_tls_prf_gettable_ctx_params(
        ossl_unused void *ctx, ossl_unused void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

const OSSL_DISPATCH qat_tls_prf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void(*)(void))qat_tls_prf_new },
    { OSSL_FUNC_KDF_FREECTX, (void(*)(void))qat_tls_prf_free },
    { OSSL_FUNC_KDF_RESET, (void(*)(void))qat_tls_prf_reset },
    { OSSL_FUNC_KDF_DERIVE, (void(*)(void))qat_tls_prf_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
      (void(*)(void))qat_tls_prf_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS,
      (void(*)(void))qat_tls_prf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
      (void(*)(void))qat_tls_prf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS,
      (void(*)(void))qat_tls_prf_get_ctx_params },
    { 0, NULL }
};

#endif /* ENABLE_QAT_HW_PRF */
