/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2024 Intel Corporation.
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
 * @file qat_prov_sha3.c
 *
 * This file provides an implementation to qatprovider SHA3 operations
 *
 *****************************************************************************/
#ifdef ENABLE_QAT_HW_SHA3

# include <string.h>
# include <openssl/core_names.h>
# include <openssl/crypto.h>
# include <openssl/evp.h>
# include <openssl/params.h>
# include <openssl/err.h>
# include <openssl/proverr.h>

# include "qat_hw_sha3.h"
# include "qat_provider.h"
# include "qat_utils.h"
# include "qat_evp.h"
# include "e_qat.h"


# define SHA3_FLAGS PROV_DIGEST_FLAG_ALGID_ABSENT
# define PROV_DIGEST_FLAG_XOF             0x0001
#define PROV_DIGEST_FLAG_ALGID_ABSENT    0x0002

# define SHA3_MDSIZE(bitlen)     (bitlen / 8)
# define SHA3_BLOCKSIZE(bitlen)  (KECCAK1600_WIDTH - bitlen * 2) / 8
/*
 * Forward declaration of any unique methods implemented here. This is not strictly
 * necessary for the compiler, but provides an assurance that the signatures
 * of the functions in the dispatch table are correct.
 */
static OSSL_FUNC_digest_init_fn qat_keccak_init;
static OSSL_FUNC_digest_update_fn qat_keccak_update;
static OSSL_FUNC_digest_final_fn qat_keccak_final;
static OSSL_FUNC_digest_freectx_fn qat_keccak_freectx;
static OSSL_FUNC_digest_dupctx_fn qat_keccak_dupctx;


static int qat_keccak_init(void *vctx, ossl_unused const OSSL_PARAM params[])
{
    QAT_KECCAK1600_CTX *ctx = (QAT_KECCAK1600_CTX *)vctx;

    if (!qat_prov_is_running())
        return 0;

#ifdef ENABLE_QAT_FIPS
    memset(ctx->qctx, 0, sizeof(qat_sha3_ctx));
#endif

    /* The newctx() handles most of the ctx fixed setup. */
    memset(ctx->A, 0, sizeof(ctx->A));
    ctx->bufsz = 0;
#ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    if (!EVP_MD_up_ref(ctx->sw_md))
        return 0;
#endif
    if (!qat_sha3_init(ctx)){
        WARN("QAT sha3 ctx init failed!\n");
        return 0;
    }
    return 1;
}

static int qat_keccak_update(void *vctx, const unsigned char *inp, size_t len)
{
#ifdef ENABLE_QAT_FIPS
    qat_fips_service_indicator = 1;
#endif
    int ret = 0;
    QAT_KECCAK1600_CTX *ctx = vctx;

    if (!qat_prov_is_running())
        goto end;

    ret = qat_sha3_update(ctx, inp, len);

end:
#ifdef ENABLE_QAT_FIPS
    qat_fips_service_indicator = 0;
#endif
    return ret;
}

static int qat_keccak_final(void *vctx, unsigned char *out, size_t *outl,
                        size_t outsz)
{
#ifdef ENABLE_QAT_FIPS
    qat_fips_service_indicator = 1;
#endif
    int ret = 1;
    QAT_KECCAK1600_CTX *ctx = vctx;

    if (!qat_prov_is_running()) {
        ret = 0;
        goto end;
    }

    *outl = ctx->md_size;
    if (outsz > 0){
        ret = qat_sha3_final(ctx, out);
    }

end:
#ifdef ENABLE_QAT_FIPS
    qat_fips_service_indicator = 0;
#endif
    return ret;
}

static QAT_PROV_SHA3_METHOD sha3_generic_md ={ NULL, NULL };

static void set_ctx_md_type(QAT_KECCAK1600_CTX *ctx, int bitlen){
    switch (bitlen){
    case 224:
        ctx->md_type = NID_sha3_224;
        break;
    case 256:
        ctx->md_type = NID_sha3_256;
        break;
    case 384:
        ctx->md_type = NID_sha3_384;
        break;
    case 512:
        ctx->md_type = NID_sha3_512;
        break;
    }
}

static void qat_keccak_freectx(void *vctx)
{
    QAT_KECCAK1600_CTX *ctx = (QAT_KECCAK1600_CTX *)vctx;

    if (!qat_sha3_cleanup(ctx)){
        WARN("qat sha3 ctx cleanup failed.\n");
    }
#ifndef ENABLE_QAT_HW_SMALL_PKT_OFFLOAD
    EVP_MD_CTX_free(ctx->sw_md_ctx);
    EVP_MD_free(ctx->sw_md);
    ctx->sw_md_ctx = NULL;
    ctx->sw_md = NULL;
#endif
    OPENSSL_clear_free(ctx->qctx, sizeof(qat_sha3_ctx));
    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *qat_keccak_dupctx(void *ctx)
{
    QAT_KECCAK1600_CTX *in = (QAT_KECCAK1600_CTX *)ctx;
    QAT_KECCAK1600_CTX *ret = qat_prov_is_running() ?
                                OPENSSL_malloc(sizeof(*ret))
                                : NULL;

    qat_sha3_copy(ret, in);

    if (ret != NULL)
        *ret = *in;
    return ret;
}

static const OSSL_PARAM qat_digest_default_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL),
    OSSL_PARAM_END
};

const OSSL_PARAM *qat_digest_default_gettable_params(void *provctx)
{
    return qat_digest_default_known_gettable_params;
}

static int qat_digest_default_get_params(OSSL_PARAM params[], size_t blksz,
                                   size_t paramsz, unsigned long flags)
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blksz)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, paramsz)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_DIGEST_FLAG_XOF) != 0)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_DIGEST_FLAG_ALGID_ABSENT) != 0)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

# define PROV_DISPATCH_FUNC_DIGEST_GET_PARAMS(name)                                \
{ OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))qat_##name##_get_params },          \
{ OSSL_FUNC_DIGEST_GETTABLE_PARAMS,                                                \
  (void (*)(void))qat_digest_default_gettable_params }


# define PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_END                                   \
    { 0, NULL }                                                                    \
};

# define PROV_FUNC_DIGEST_GET_PARAM(name, blksize, dgstsize, flags)                \
static OSSL_FUNC_digest_get_params_fn qat_##name##_get_params;                     \
static int qat_##name##_get_params(OSSL_PARAM params[])                            \
{                                                                                  \
    return qat_digest_default_get_params(params, blksize, dgstsize, flags);        \
}

# define PROV_FUNC_SHA3_DIGEST_COMMON(name, bitlen, blksize, dgstsize, flags)      \
PROV_FUNC_DIGEST_GET_PARAM(name, blksize, dgstsize, flags)                         \
const OSSL_DISPATCH qat_##name##_functions[] = {                                   \
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))qat_##name##_newctx },              \
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))qat_keccak_update },                \
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))qat_keccak_final },                  \
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))qat_keccak_freectx },              \
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))qat_keccak_dupctx },                \
    PROV_DISPATCH_FUNC_DIGEST_GET_PARAMS(name)

# define PROV_FUNC_SHA3_DIGEST(name, bitlen, blksize, dgstsize, flags)             \
    PROV_FUNC_SHA3_DIGEST_COMMON(name, bitlen, blksize, dgstsize, flags),          \
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))qat_keccak_init },                    \
    PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_END

#ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
# define SHA3_NEW_CTX(name, bitlen, pad_val, sha_name)                             \
static OSSL_FUNC_digest_newctx_fn qat_##name##_newctx;                             \
static void *qat_##name##_newctx(void *provctx)                                    \
{                                                                                  \
    QAT_KECCAK1600_CTX *ctx = qat_prov_is_running() ? OPENSSL_zalloc(sizeof(*ctx)) \
                                                : NULL;                            \
    size_t bsz = SHA3_BLOCKSIZE(bitlen);                                           \
                                                                                   \
    if (ctx == NULL)                                                               \
        return NULL;                                                               \
    if (bsz <= sizeof(ctx->buf)) {                                                 \
        memset(ctx->A, 0, sizeof(ctx->A));                                         \
        ctx->bufsz = 0;                                                            \
        ctx->block_size = bsz;                                                     \
        ctx->md_size = bitlen / 8;                                                 \
        ctx->pad = pad_val;                                                        \
    }                                                                              \
    set_ctx_md_type(ctx, bitlen);                                                  \
    ctx->qctx = OPENSSL_malloc(sizeof(qat_sha3_ctx));                              \
    if (ctx->qctx == NULL)                                                         \
        WARN("malloc failed.\n");                                                  \
    ctx->meth = sha3_generic_md;                                                   \
    ctx->sw_md_ctx = EVP_MD_CTX_new();                                             \
    if (ctx->sw_md_ctx == NULL)                                                    \
        WARN("EVP_MD_CTX_new failed.\n");                                          \
    ctx->sw_md = EVP_MD_fetch(NULL, sha_name, "provider=default");                 \
    if (ctx->sw_md == NULL)                                                        \
        WARN("EVP_MD_fetch failed.\n");                                            \
    if (!EVP_MD_up_ref(ctx->sw_md))                                                \
        return NULL;                                                               \
    return ctx;                                                                    \
}
#else
# define SHA3_NEW_CTX(name, bitlen, pad_val, sha_name)                             \
static OSSL_FUNC_digest_newctx_fn qat_##name##_newctx;                             \
static void *qat_##name##_newctx(void *provctx)                                    \
{                                                                                  \
    QAT_KECCAK1600_CTX *ctx = qat_prov_is_running() ? OPENSSL_zalloc(sizeof(*ctx)) \
                                                : NULL;                            \
    size_t bsz = SHA3_BLOCKSIZE(bitlen);                                           \
                                                                                   \
    if (ctx == NULL)                                                               \
        return NULL;                                                               \
    if (bsz <= sizeof(ctx->buf)) {                                                 \
        memset(ctx->A, 0, sizeof(ctx->A));                                         \
        ctx->bufsz = 0;                                                            \
        ctx->block_size = bsz;                                                     \
        ctx->md_size = bitlen / 8;                                                 \
        ctx->pad = pad_val;                                                        \
    }                                                                              \
    set_ctx_md_type(ctx, bitlen);                                                  \
    ctx->qctx = OPENSSL_malloc(sizeof(qat_sha3_ctx));                              \
    if (ctx->qctx == NULL)                                                         \
        WARN("malloc failed.\n");                                                  \
    ctx->meth = sha3_generic_md;                                                   \
    return ctx;                                                                    \
}
#endif


# define QAT_PROVIDER_SHA3_IMPLEMENTATION(bitlen, sha_name)                        \
SHA3_NEW_CTX(sha3_##bitlen, bitlen, '\x06', sha_name)                              \
PROV_FUNC_SHA3_DIGEST(sha3_##bitlen, bitlen,                                       \
                        SHA3_BLOCKSIZE(bitlen), SHA3_MDSIZE(bitlen),               \
                        SHA3_FLAGS)

/* qat_sha3_224 functions */
QAT_PROVIDER_SHA3_IMPLEMENTATION(224, "SHA3-224")
/* qat_sha3_256 functions */
QAT_PROVIDER_SHA3_IMPLEMENTATION(256, "SHA3-256")
/* qat_sha3_384 functions */
QAT_PROVIDER_SHA3_IMPLEMENTATION(384, "SHA3-384")
/* qat_sha3_512 functions */
QAT_PROVIDER_SHA3_IMPLEMENTATION(512, "SHA3-512")

#endif /* ENABLE_QAT_HW_SHA3 */
