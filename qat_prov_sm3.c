/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023 Intel Corporation.
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
 * @file qat_prov_sm3.c
 *
 * This file provides an implementation to qatprovider SM3 operations
 *
 *****************************************************************************/
#if defined(ENABLE_QAT_HW_SM3) || defined (ENABLE_QAT_SW_SM3)

# include <string.h>
# include <openssl/core_names.h>
# include <openssl/crypto.h>
# include <openssl/evp.h>
# include <openssl/params.h>
# include <openssl/err.h>
# include <openssl/proverr.h>
# ifdef ENABLE_QAT_HW_SM3
#  include "qat_hw_sm3.h"
# endif
# include "qat_provider.h"
# include "qat_utils.h"
# include "qat_evp.h"
# include "e_qat.h"

# define QAT_PROV_DIGEST_FLAG_XOF             0x0001
# define QAT_PROV_DIGEST_FLAG_ALGID_ABSENT    0x0002
# define SM3_DIGEST_LENGTH 32
# define SM3_CBLOCK      64

static OSSL_FUNC_digest_newctx_fn qat_sm3_newctx;
static OSSL_FUNC_digest_freectx_fn qat_sm3_freectx;
static OSSL_FUNC_digest_dupctx_fn qat_sm3_dupctx;

static const OSSL_PARAM qat_digest_default_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL),
    OSSL_PARAM_END
};

const OSSL_PARAM *qat_sm3_digest_default_gettable_params(void *provctx)
{
    return qat_digest_default_known_gettable_params;
}

int qat_sm3_digest_default_get_params(OSSL_PARAM params[], size_t blksz,
                                   size_t paramsz, unsigned long flags)
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blksz)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, paramsz)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & QAT_PROV_DIGEST_FLAG_XOF) != 0)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & QAT_PROV_DIGEST_FLAG_ALGID_ABSENT) != 0)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

static void *qat_sm3_newctx(void *prov_ctc)
{
# ifdef ENABLE_QAT_HW_SM3
    QAT_SM3_CTX *ctx = qat_prov_is_running() ? OPENSSL_zalloc(sizeof(*ctx)) : NULL;
# endif
# ifdef ENABLE_QAT_SW_SM3
    QAT_SM3_CTX_mb *ctx = qat_prov_is_running() ? OPENSSL_zalloc(sizeof(*ctx)) : NULL;
# endif
    return ctx;
}

static void qat_sm3_freectx(void *vctx)
{
# ifdef ENABLE_QAT_HW_SM3
    QAT_SM3_CTX *ctx = (QAT_SM3_CTX *)vctx;
    if (!qat_hw_sm3_cleanup(ctx)){
        WARN("qat sm3 ctx cleanup failed.\n");
    }
#  ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    EVP_MD_CTX_free(ctx->sw_md_ctx);
    EVP_MD_free(ctx->sw_md);
    ctx->sw_md_ctx = NULL;
    ctx->sw_md = NULL;
#  endif
# endif
# ifdef ENABLE_QAT_SW_SM3
    QAT_SM3_CTX_mb *ctx = (QAT_SM3_CTX_mb *)vctx;
# endif
    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *qat_sm3_dupctx(void *ctx)
{
# ifdef ENABLE_QAT_HW_SM3
    QAT_SM3_CTX *in = (QAT_SM3_CTX *)ctx;
    QAT_SM3_CTX *ret = qat_prov_is_running() ? OPENSSL_malloc(sizeof(*ret)) : NULL;
    qat_hw_sm3_copy(ret, in);
# endif
# ifdef ENABLE_QAT_SW_SM3
    QAT_SM3_CTX_mb *in = (QAT_SM3_CTX_mb *)ctx;
    QAT_SM3_CTX_mb *ret = qat_prov_is_running() ? OPENSSL_malloc(sizeof(*ret)) : NULL;
# endif
    if (ret != NULL)
        *ret = *in;
    return ret;
}

#define QAT_PROV_FUNC_DIGEST_GET_PARAM(name, blksize, dgstsize, flags)             \
static OSSL_FUNC_digest_get_params_fn qat_name##_get_params;                       \
static int qat_name##_get_params(OSSL_PARAM params[])                              \
{                                                                                  \
    return qat_sm3_digest_default_get_params(params, blksize, dgstsize, flags);    \
}

#define QAT_PROV_DISPATCH_FUNC_DIGEST_GET_PARAMS(name)                             \
{ OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))qat_name##_get_params },            \
{ OSSL_FUNC_DIGEST_GETTABLE_PARAMS,                                                \
  (void (*)(void))qat_sm3_digest_default_gettable_params }

# define QAT_PROV_FUNC_DIGEST_FINAL(name, dgstsize, fin)                           \
static OSSL_FUNC_digest_final_fn qat_##name##_internal_final;                      \
static int qat_##name##_internal_final(void *ctx, unsigned char *out, size_t *outl,\
                                 size_t outsz)                                     \
{                                                                                  \
    if (qat_prov_is_running() && outsz >= dgstsize && fin(ctx, out)) {             \
        *outl = dgstsize;                                                          \
        return 1;                                                                  \
    }                                                                              \
    return 0;                                                                      \
}

# define QAT_PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_START(                            \
    name, CTX, blksize, dgstsize, flags, upd, fin)                                 \
QAT_PROV_FUNC_DIGEST_FINAL(name, dgstsize, fin)                                    \
QAT_PROV_FUNC_DIGEST_GET_PARAM(name, blksize, dgstsize, flags)                     \
const OSSL_DISPATCH qat_##name##_functions[] = {                                   \
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))qat_##name##_newctx },              \
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))upd },                              \
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))qat_##name##_internal_final },       \
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))qat_##name##_freectx },            \
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))qat_##name##_dupctx },              \
    QAT_PROV_DISPATCH_FUNC_DIGEST_GET_PARAMS(name)

# define QAT_PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_END                               \
    { 0, NULL }                                                                    \
};


# define QAT_PROV_IMPLEMENT_digest_functions(                                      \
    name, CTX, blksize, dgstsize, flags, init, upd, fin)                           \
static OSSL_FUNC_digest_init_fn qat_##name##_internal_init;                        \
static int qat_##name##_internal_init(void *ctx,                                   \
                                ossl_unused const OSSL_PARAM params[])             \
{                                                                                  \
    return qat_prov_is_running() && init(ctx);                                     \
}                                                                                  \
QAT_PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_START(name, CTX, blksize, dgstsize, flags, \
                                          upd, fin),                               \
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))qat_##name##_internal_init },         \
QAT_PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_END

/* qat_sm3_functions */
# ifdef ENABLE_QAT_HW_SM3
QAT_PROV_IMPLEMENT_digest_functions(sm3, QAT_SM3_CTX,
                                    SM3_CBLOCK, SM3_DIGEST_LENGTH, 0,
                                    qat_hw_sm3_init, qat_hw_sm3_update, qat_hw_sm3_final)
# endif
# ifdef ENABLE_QAT_SW_SM3
QAT_PROV_IMPLEMENT_digest_functions(sm3, QAT_SM3_CTX_mb,
                                    SM3_CBLOCK, SM3_DIGEST_LENGTH, 0,
                                    qat_sw_sm3_init, qat_sw_sm3_update, qat_sw_sm3_final)
# endif
#endif /* ENABLE_QAT_HW_SM3 || ENABLE_QAT_SW_SM3 */
