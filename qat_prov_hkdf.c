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
 * @file qat_prov_hkdf.c
 *
 * This file contains qatprovider implementation of HKDF.
 *
 *****************************************************************************/

#include "qat_prov_hkdf.h"
#include "e_qat.h"

#ifdef ENABLE_QAT_HW_HKDF

static OSSL_FUNC_kdf_newctx_fn qat_kdf_hkdf_new;
static OSSL_FUNC_kdf_freectx_fn qat_kdf_hkdf_free;
static OSSL_FUNC_kdf_reset_fn qat_kdf_hkdf_reset;
static OSSL_FUNC_kdf_derive_fn qat_kdf_hkdf_derive;
static OSSL_FUNC_kdf_settable_ctx_params_fn qat_kdf_hkdf_settable_ctx_params;
static OSSL_FUNC_kdf_set_ctx_params_fn qat_kdf_hkdf_set_ctx_params;
static OSSL_FUNC_kdf_gettable_ctx_params_fn qat_kdf_hkdf_gettable_ctx_params;
static OSSL_FUNC_kdf_get_ctx_params_fn qat_kdf_hkdf_get_ctx_params;

static void qat_prov_digest_reset(PROV_DIGEST *pd)
{
    EVP_MD_free(pd->alloc_md);
    pd->alloc_md = NULL;
    pd->md = NULL;
    pd->engine = NULL;
}

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


/* Settable context parameters that are common across HKDF and the TLS KDF */
#define HKDF_COMMON_SETTABLES                                           \
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),           \
        OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),                      \
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),     \
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),         \
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),           \
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0)

static void *qat_kdf_hkdf_new(void *provctx)
{
    QAT_KDF_HKDF *ctx;

    if (!qat_prov_is_running())
        return NULL;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) {
        QATerr(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    else
        ctx->provctx = provctx;

    ctx->evp_pkey_ctx = OPENSSL_zalloc(sizeof(EVP_PKEY_CTX));
    if (ctx->evp_pkey_ctx == NULL){
        WARN("Not enough memory for hkdf contex.\n");
        OPENSSL_free(ctx);
        ctx = NULL;
        return NULL;
    }
    if (!qat_hkdf_init(ctx->evp_pkey_ctx)){
        WARN("qat_hkdf_init failed\n");
    }
    return ctx;
}

static void qat_kdf_hkdf_free(void *vctx)
{
    QAT_KDF_HKDF *ctx = (QAT_KDF_HKDF *)vctx;

    if (ctx != NULL) {
        qat_hkdf_cleanup(ctx->evp_pkey_ctx);
        OPENSSL_free(ctx->evp_pkey_ctx);
        ctx->evp_pkey_ctx = NULL;
        qat_kdf_hkdf_reset(ctx);
        OPENSSL_free(ctx);
    }
}

static void qat_kdf_hkdf_reset(void *vctx)
{
    QAT_KDF_HKDF *ctx = (QAT_KDF_HKDF *)vctx;
    void *provctx = ctx->provctx;

    qat_prov_digest_reset(&ctx->digest);
    OPENSSL_free(ctx->salt);
    OPENSSL_free(ctx->prefix);
    OPENSSL_free(ctx->label);
    OPENSSL_clear_free(ctx->data, ctx->data_len);
    OPENSSL_clear_free(ctx->key, ctx->key_len);
    OPENSSL_cleanse(ctx->info, ctx->info_len);
    memset(ctx, 0, sizeof(*ctx));
    ctx->provctx = provctx;
}

static size_t qat_kdf_hkdf_size(QAT_KDF_HKDF *ctx)
{
    int sz;
    const EVP_MD *md = qat_prov_digest_md(&ctx->digest);

    if (ctx->mode != EVP_KDF_HKDF_MODE_EXTRACT_ONLY)
        return SIZE_MAX;

    if (md == NULL) {
        QATerr(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    sz = EVP_MD_get_size(md);
    if (sz < 0)
        return 0;

    return sz;
}

static int qat_kdf_hkdf_derive(void *vctx, unsigned char *key, size_t keylen,
                           const OSSL_PARAM params[])
{
    QAT_KDF_HKDF *ctx = (QAT_KDF_HKDF *)vctx;
    QAT_HKDF_CTX *qat_hkdf_ctx = (QAT_HKDF_CTX *)EVP_PKEY_CTX_get_data(
                                                    ctx->evp_pkey_ctx);
    const EVP_MD *md;

    if (!qat_prov_is_running() || !qat_kdf_hkdf_set_ctx_params(ctx, params))
        return 0;

    md = qat_prov_digest_md(&ctx->digest);
    if (md == NULL) {
        QATerr(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    if (ctx->key == NULL) {
        QATerr(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    if (keylen == 0) {
        QATerr(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }
    qat_hkdf_ctx->qat_md = md;

    return qat_hkdf_derive(ctx->evp_pkey_ctx, key, &keylen);
}

static int qat_hkdf_common_set_ctx_params(QAT_KDF_HKDF *ctx, const OSSL_PARAM params[])
{
    OSSL_LIB_CTX *libctx = prov_libctx_of(ctx->provctx);
    const OSSL_PARAM *p;
    int n;

    if (params == NULL)
        return 1;

    if (!qat_prov_digest_load_from_params(&ctx->digest, params, libctx))
        return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE)) != NULL) {
        if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            if (strcasecmp(p->data, "EXTRACT_AND_EXPAND") == 0) {
                ctx->mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
            } else if (strcasecmp(p->data, "EXTRACT_ONLY") == 0) {
                ctx->mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
            } else if (strcasecmp(p->data, "EXPAND_ONLY") == 0) {
                ctx->mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
            } else {
                QATerr(ERR_LIB_PROV, PROV_R_INVALID_MODE);
                return 0;
            }
        } else if (OSSL_PARAM_get_int(p, &n)) {
            if (n != EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
                && n != EVP_KDF_HKDF_MODE_EXTRACT_ONLY
                && n != EVP_KDF_HKDF_MODE_EXPAND_ONLY) {
                QATerr(ERR_LIB_PROV, PROV_R_INVALID_MODE);
                return 0;
            }
            ctx->mode = n;
        } else {
            QATerr(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            return 0;
        }
        if (!qat_hkdf_ctrl(ctx->evp_pkey_ctx, EVP_PKEY_CTRL_HKDF_MODE,
                           ctx->mode, NULL)){
            WARN("Failed in setting hkdf mode.\n");
            return 0;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY)) != NULL) {
        OPENSSL_clear_free(ctx->key, ctx->key_len);
        ctx->key = NULL;
        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->key, 0,
                                         &ctx->key_len))
            return 0;
        if (!qat_hkdf_ctrl(ctx->evp_pkey_ctx, EVP_PKEY_CTRL_HKDF_KEY,
                           ctx->key_len, ctx->key)){
            WARN("Failed in setting hkdf key.\n");
            return 0;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT)) != NULL) {
        if (p->data_size != 0 && p->data != NULL) {
            OPENSSL_free(ctx->salt);
            ctx->salt = NULL;
            if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->salt, 0,
                                             &ctx->salt_len))
                return 0;
            if (!qat_hkdf_ctrl(ctx->evp_pkey_ctx, EVP_PKEY_CTRL_HKDF_SALT,
                               ctx->salt_len, ctx->salt)) {
                WARN("Failed in setting hkdf salt.\n");
                return 0;
            }
        }
    }

    return 1;
}

static int qat_kdf_hkdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    QAT_KDF_HKDF *ctx = vctx;

    if (params == NULL)
        return 1;

    if (!qat_hkdf_common_set_ctx_params(ctx, params))
        return 0;

    /* The info fields concatenate, so process them all */
    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO)) != NULL) {
        ctx->info_len = 0;
        for (; p != NULL; p = OSSL_PARAM_locate_const(p + 1,
                                                      OSSL_KDF_PARAM_INFO)) {
            const void *q = ctx->info + ctx->info_len;
            size_t sz = 0;

            if (p->data_size != 0
                && p->data != NULL
                && !OSSL_PARAM_get_octet_string(p, (void **)&q,
                                                HKDF_MAXBUF - ctx->info_len,
                                                &sz))
                return 0;
            ctx->info_len += sz;
        }
        if (!qat_hkdf_ctrl(ctx->evp_pkey_ctx, EVP_PKEY_CTRL_HKDF_INFO,
                           ctx->info_len, ctx->info)){
            WARN("Failed in setting hkdf info.\n");
            return 0;
        }
    }
    return 1;
}

static const OSSL_PARAM *qat_kdf_hkdf_settable_ctx_params(ossl_unused void *ctx,
                                                      ossl_unused void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        HKDF_COMMON_SETTABLES,
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int qat_kdf_hkdf_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    QAT_KDF_HKDF *ctx = (QAT_KDF_HKDF *)vctx;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL) {
        size_t sz = qat_kdf_hkdf_size(ctx);

        if (sz == 0)
            return 0;
        return OSSL_PARAM_set_size_t(p, sz);
    }
    return -2;
}

static const OSSL_PARAM *qat_kdf_hkdf_gettable_ctx_params(ossl_unused void *ctx,
                                                      ossl_unused void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}


const OSSL_DISPATCH qat_kdf_hkdf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void(*)(void))qat_kdf_hkdf_new },
    { OSSL_FUNC_KDF_FREECTX, (void(*)(void))qat_kdf_hkdf_free },
    { OSSL_FUNC_KDF_RESET, (void(*)(void))qat_kdf_hkdf_reset },
    { OSSL_FUNC_KDF_DERIVE, (void(*)(void))qat_kdf_hkdf_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
      (void(*)(void))qat_kdf_hkdf_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void(*)(void))qat_kdf_hkdf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
      (void(*)(void))qat_kdf_hkdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void(*)(void))qat_kdf_hkdf_get_ctx_params },
    { 0, NULL }
};

#endif /* ENABLE_QAT_HW_HKDF */
