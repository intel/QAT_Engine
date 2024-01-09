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

#include "qat_prov_cbc.h"
#include "qat_provider.h"
#include "e_qat.h"

# ifdef QAT_HW

# define AES_CBC_HMAC_SHA_FLAGS (PROV_CIPHER_FLAG_AEAD                         \
                                 | PROV_CIPHER_FLAG_TLS1_MULTIBLOCK)

static OSSL_FUNC_cipher_encrypt_init_fn qat_aes_einit;
static OSSL_FUNC_cipher_decrypt_init_fn qat_aes_dinit;
static OSSL_FUNC_cipher_freectx_fn qat_aes_cbc_hmac_sha1_freectx;
static OSSL_FUNC_cipher_freectx_fn qat_aes_cbc_hmac_sha256_freectx;
static OSSL_FUNC_cipher_get_ctx_params_fn qat_aes_get_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn qat_aes_gettable_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn qat_aes_set_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn qat_aes_settable_ctx_params;

# define qat_aes_gettable_params qat_cipher_generic_gettable_params
# define qat_aes_update qat_cipher_generic_stream_update
# define qat_aes_final qat_cipher_generic_stream_final
# define qat_aes_cipher qat_aes_cbc_cipher_do_cipher

# define ossl_assert(x) ((x) != 0)

static int qat_cipher_generic_initiv(PROV_CIPHER_CTX *ctx, const unsigned char *iv,
                               size_t ivlen)
{
    if (ivlen != ctx->ivlen
        || ivlen > sizeof(ctx->iv)) {
        QATerr(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
        return 0;
    }
    ctx->iv_set = 1;
    memcpy(ctx->iv, iv, ivlen);
    memcpy(ctx->oiv, iv, ivlen);
    return 1;
}

static int qat_aes_einit(void *vctx, const unsigned char *key, size_t keylen,
                          const unsigned char *iv, size_t ivlen,
                          const OSSL_PARAM params[])
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    ctx->num = 0;
    ctx->bufsz = 0;
    ctx->updated = 0;
    ctx->enc = 1;

    if (!qat_prov_is_running())
        return 0;

    if (key != NULL && !qat_chained_ciphers_init(ctx, key, keylen, iv, ivlen, 1)){
        WARN("qat_chained_ciphers_init failed\n");
        return 0;
    }

    if (iv != NULL && ctx->mode != EVP_CIPH_ECB_MODE) {
        if (!qat_cipher_generic_initiv(ctx, iv, ivlen))
            return 0;
    }
    if (iv == NULL && ctx->iv_set
        && (ctx->mode == EVP_CIPH_CBC_MODE
            || ctx->mode == EVP_CIPH_CFB_MODE
            || ctx->mode == EVP_CIPH_OFB_MODE))
        /* reset IV for these modes to keep compatibility with 1.1.1 */
        memcpy(ctx->iv, ctx->oiv, ctx->ivlen);

    if (key != NULL) {
        if (ctx->variable_keylength == 0) {
            if (keylen != ctx->keylen) {
                QATerr(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
                return 0;
            }
        } else {
            ctx->keylen = keylen;
        }
    }

    return qat_aes_set_ctx_params(ctx, params);
}

static int qat_aes_dinit(void *vctx, const unsigned char *key, size_t keylen,
                          const unsigned char *iv, size_t ivlen,
                          const OSSL_PARAM params[])
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    ctx->num = 0;
    ctx->bufsz = 0;
    ctx->updated = 0;
    ctx->enc = 0;

    if (!qat_prov_is_running())
        return 0;

    if (key != NULL && !qat_chained_ciphers_init(ctx, key, keylen, iv, ivlen, 0)){
        WARN("qat_chained_ciphers_init failed\n");
        return 0;
    }

    if (iv != NULL && ctx->mode != EVP_CIPH_ECB_MODE) {
        if (!qat_cipher_generic_initiv(ctx, iv, ivlen))
            return 0;
    }
    if (iv == NULL && ctx->iv_set
        && (ctx->mode == EVP_CIPH_CBC_MODE
            || ctx->mode == EVP_CIPH_CFB_MODE
            || ctx->mode == EVP_CIPH_OFB_MODE))
        /* reset IV for these modes to keep compatibility with 1.1.1 */
        memcpy(ctx->iv, ctx->oiv, ctx->ivlen);

    if (key != NULL) {
        if (ctx->variable_keylength == 0) {
            if (keylen != ctx->keylen) {
                QATerr(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
                return 0;
            }
        } else {
            ctx->keylen = keylen;
        }
    }

    return qat_aes_set_ctx_params(ctx, params);
}

static const OSSL_PARAM cipher_aes_known_settable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
# if !defined(OPENSSL_NO_MULTIBLOCK)
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN, NULL, 0),
# endif /* !defined(OPENSSL_NO_MULTIBLOCK) */
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_END
};
const OSSL_PARAM *qat_aes_settable_ctx_params(ossl_unused void *cctx,
                                          ossl_unused void *provctx)
{
    return cipher_aes_known_settable_ctx_params;
}

static int qat_aes_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_AES_HMAC_SHA_CTX *ctx = (PROV_AES_HMAC_SHA_CTX *)vctx;
    const OSSL_PARAM *p;
    int ret = 1;
# if !defined(OPENSSL_NO_MULTIBLOCK)
    EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM mb_param;
# endif

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_MAC_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (!qat_chained_ciphers_ctrl(ctx,
                                        EVP_CTRL_AEAD_SET_MAC_KEY,
                                        p->data_size, p->data)){
            WARN("Failed in setting ctx mac key.\n");
            return 0;
        }
    }

# if !defined(OPENSSL_NO_MULTIBLOCK)
    p = OSSL_PARAM_locate_const(params,
            OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT);
    if (p != NULL
            && !OSSL_PARAM_get_size_t(p, &ctx->multiblock_max_send_fragment)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }
    /*
     * The inputs to tls1_multiblock_aad are:
     *   mb_param->inp
     *   mb_param->len
     *   mb_param->interleave
     * The outputs of tls1_multiblock_aad are written to:
     *   ctx->multiblock_interleave
     *   ctx->multiblock_aad_packlen
     */
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD);
    if (p != NULL) {
        const OSSL_PARAM *p1 = OSSL_PARAM_locate_const(params,
                                   OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE);
        if (p->data_type != OSSL_PARAM_OCTET_STRING
            || p1 == NULL
            || !OSSL_PARAM_get_uint(p1, &mb_param.interleave)) {
            QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        mb_param.inp = p->data;
        mb_param.len = p->data_size;
    }

    /*
     * The inputs to tls1_multiblock_encrypt are:
     *   mb_param->inp
     *   mb_param->len
     *   mb_param->interleave
     *   mb_param->out
     * The outputs of tls1_multiblock_encrypt are:
     *   ctx->multiblock_encrypt_len
     */
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC);
    if (p != NULL) {
        const OSSL_PARAM *p1 = OSSL_PARAM_locate_const(params,
                                   OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE);
        const OSSL_PARAM *pin = OSSL_PARAM_locate_const(params,
                                    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN);

        if (p->data_type != OSSL_PARAM_OCTET_STRING
            || pin == NULL
            || pin->data_type != OSSL_PARAM_OCTET_STRING
            || p1 == NULL
            || !OSSL_PARAM_get_uint(p1, &mb_param.interleave)) {
            QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        mb_param.out = p->data;
        mb_param.inp = pin->data;
        mb_param.len = pin->data_size;
    }
# endif /* !defined(OPENSSL_NO_MULTIBLOCK) */

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (!qat_chained_ciphers_ctrl(ctx, 
                                        EVP_CTRL_AEAD_TLS1_AAD, 
                                        p->data_size, p->data)){
            WARN("Failed in setting ctx TLS1_ADD.\n");
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t keylen;

        if (!OSSL_PARAM_get_size_t(p, &keylen)) {
            QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (ctx->base.keylen != keylen) {
            QATerr(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_VERSION);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint(p, &ctx->base.tlsversion)) {
            QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (ctx->base.tlsversion == SSL3_VERSION
                || ctx->base.tlsversion == TLS1_VERSION) {
            if (!ossl_assert(ctx->base.removetlsfixed >= AES_BLOCK_SIZE)) {
                QATerr(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                return 0;
            }
            /*
             * There is no explicit IV with these TLS versions, so don't attempt
             * to remove it.
             */
            ctx->base.removetlsfixed -= AES_BLOCK_SIZE;
        }
    }
    return ret;
}

static int qat_aes_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_AES_HMAC_SHA_CTX *ctx = (PROV_AES_HMAC_SHA_CTX *)vctx;
    OSSL_PARAM *p;

# if !defined(OPENSSL_NO_MULTIBLOCK)
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE);
    if (p != NULL) {
        WARN("Do not support OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE\n");
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->multiblock_interleave)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->multiblock_aad_packlen)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->multiblock_encrypt_len)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
# endif /* !defined(OPENSSL_NO_MULTIBLOCK) */

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tls_aad_pad)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->base.keylen)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->base.ivlen)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_string(p, ctx->base.oiv, ctx->base.ivlen)
        && !OSSL_PARAM_set_octet_ptr(p, &ctx->base.oiv, ctx->base.ivlen)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_string(p, ctx->base.iv, ctx->base.ivlen)
        && !OSSL_PARAM_set_octet_ptr(p, &ctx->base.iv, ctx->base.ivlen)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

static const OSSL_PARAM cipher_aes_known_gettable_ctx_params[] = {
# if !defined(OPENSSL_NO_MULTIBLOCK)
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN, NULL),
# endif /* !defined(OPENSSL_NO_MULTIBLOCK) */
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_END
};
const OSSL_PARAM *qat_aes_gettable_ctx_params(ossl_unused void *cctx,
                                          ossl_unused void *provctx)
{
    return cipher_aes_known_gettable_ctx_params;
}

static void *qat_aes_cbc_hmac_sha1_newctx(void *provctx, size_t kbits,
                                      size_t blkbits, size_t ivbits,
                                      uint64_t flags, int nid)
{
    PROV_AES_HMAC_SHA1_CTX *ctx = NULL;
    PROV_CIPHER_CTX *base_ctx = NULL;

    if (!qat_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL){
        base_ctx = &ctx->base_ctx.base;

        base_ctx->nid = nid;
        base_ctx->qat_cipher_ctx = OPENSSL_zalloc(sizeof(qat_chained_ctx));
        if (base_ctx->qat_cipher_ctx == NULL){
            WARN("qat_cipher_ctx zalloc failed.\n");
            goto err;
        }
#ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
        base_ctx->sw_ctx = EVP_CIPHER_CTX_new();
        if (base_ctx->sw_ctx == NULL){
            WARN("base_ctx->sw_ctx zalloc failed.\n");
            goto err;
        }
#else
        if (enable_sw_fallback){
            base_ctx->sw_ctx = EVP_CIPHER_CTX_new();
            if (base_ctx->sw_ctx == NULL){
                WARN("base_ctx->sw_ctx zalloc failed.\n");
                goto err;
            }
        }
#endif

        if ((flags & PROV_CIPHER_FLAG_INVERSE_CIPHER) != 0)
            base_ctx->inverse_cipher = 1;
        if ((flags & PROV_CIPHER_FLAG_VARIABLE_LENGTH) != 0)
            base_ctx->variable_keylength = 1;

        base_ctx->pad = 1;
        base_ctx->keylen = ((kbits) / 8);
        base_ctx->ivlen = ((ivbits) / 8);
        base_ctx->mode = EVP_CIPH_CBC_MODE;
        base_ctx->blocksize = blkbits / 8;
        if (provctx != NULL)
            base_ctx->libctx = prov_libctx_of(provctx); /* used for rand */
    }

    return ctx;
err:
    if (base_ctx->sw_ctx != NULL)
        OPENSSL_free(base_ctx->sw_ctx);
    if (base_ctx->qat_cipher_ctx != NULL)
        OPENSSL_free(base_ctx->qat_cipher_ctx);
    OPENSSL_free(ctx);
    return NULL;
}

static void *qat_aes_cbc_hmac_sha256_newctx(void *provctx, size_t kbits,
                                      size_t blkbits, size_t ivbits,
                                      uint64_t flags, int nid)
{
    PROV_AES_HMAC_SHA256_CTX *ctx = NULL;
    PROV_CIPHER_CTX *base_ctx = NULL;

    if (!qat_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL){
        base_ctx = &ctx->base_ctx.base;

        base_ctx->nid = nid;
        base_ctx->qat_cipher_ctx = OPENSSL_zalloc(sizeof(qat_chained_ctx));
        if (base_ctx->qat_cipher_ctx == NULL){
            WARN("qat_cipher_ctx zalloc failed.\n");
            goto err;
        }
#ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
        base_ctx->sw_ctx = EVP_CIPHER_CTX_new();
        if (base_ctx->sw_ctx == NULL){
            WARN("base_ctx->sw_ctx zalloc failed.\n");
            goto err;
        }
        EVP_CIPHER_CTX_init(base_ctx->sw_ctx);
#else
        if (enable_sw_fallback){
            base_ctx->sw_ctx = EVP_CIPHER_CTX_new();
            if (base_ctx->sw_ctx == NULL){
                WARN("base_ctx->sw_ctx zalloc failed.\n");
                goto err;
            }
            EVP_CIPHER_CTX_init(base_ctx->sw_ctx);
        }
#endif

        if ((flags & PROV_CIPHER_FLAG_INVERSE_CIPHER) != 0)
            base_ctx->inverse_cipher = 1;
        if ((flags & PROV_CIPHER_FLAG_VARIABLE_LENGTH) != 0)
            base_ctx->variable_keylength = 1;

        base_ctx->pad = 1;
        base_ctx->keylen = ((kbits) / 8);
        base_ctx->ivlen = ((ivbits) / 8);
        base_ctx->mode = EVP_CIPH_CBC_MODE;
        base_ctx->blocksize = blkbits / 8;
        if (provctx != NULL)
            base_ctx->libctx = prov_libctx_of(provctx); /* used for rand */
    }

    return ctx;
err:
    if (base_ctx->sw_ctx != NULL)
        OPENSSL_free(base_ctx->sw_ctx);
    if (base_ctx->qat_cipher_ctx != NULL)
        OPENSSL_free(base_ctx->qat_cipher_ctx);
    OPENSSL_free(ctx);
    return NULL;
}

static void qat_aes_cbc_hmac_sha1_freectx(void *vctx)
{
    PROV_AES_HMAC_SHA1_CTX *ctx = (PROV_AES_HMAC_SHA1_CTX *)vctx;
    PROV_CIPHER_CTX *base_ctx = (PROV_CIPHER_CTX *)vctx;

    if (ctx != NULL) {
        if (base_ctx != NULL){
            if (!qat_chained_ciphers_cleanup(base_ctx)){
                WARN("Failed clean up the base_ctx!\n");
            }
            OPENSSL_clear_free(base_ctx->qat_cipher_ctx,
                                sizeof(qat_chained_ctx));
        }
        if (base_ctx != NULL && base_ctx->alloced) {
            OPENSSL_free(base_ctx->tlsmac);
            base_ctx->alloced = 0;
            base_ctx->tlsmac = NULL;
        }
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

static void qat_aes_cbc_hmac_sha256_freectx(void *vctx)
{
    PROV_AES_HMAC_SHA256_CTX *ctx = (PROV_AES_HMAC_SHA256_CTX *)vctx;
    PROV_CIPHER_CTX *base_ctx = (PROV_CIPHER_CTX *)vctx;

    if (ctx != NULL) {
        if (base_ctx != NULL){
            if (!qat_chained_ciphers_cleanup(base_ctx)){
                WARN("Failed clean up the base_ctx!\n");
            }
            OPENSSL_clear_free(base_ctx->qat_cipher_ctx,
                                sizeof(qat_chained_ctx));
        }
        if (base_ctx != NULL && base_ctx->alloced) {
            OPENSSL_free(base_ctx->tlsmac);
            base_ctx->alloced = 0;
            base_ctx->tlsmac = NULL;
        }
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

int qat_aes_cbc_cipher_do_cipher(void *vctx, unsigned char *out, size_t *outl,
                               size_t outsize, const unsigned char *in,
                               size_t inl)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;

    if (!qat_prov_is_running())
        return 0;

    if (outsize < inl) {
        QATerr(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (qat_chained_ciphers_do_cipher(ctx, out, in, inl) <= 0) {
        QATerr(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    *outl = inl;
    return 1;
}

int qat_cipher_generic_stream_final(void *vctx, unsigned char *out,
                                     size_t *outl, size_t outsize)
{
    if (!qat_prov_is_running())
        return 0;

    *outl = 0;
    return 1;
}

int qat_cipher_generic_stream_update(void *vctx, unsigned char *out,
                                      size_t *outl, size_t outsize,
                                      const unsigned char *in, size_t inl)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        QATerr(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (qat_chained_ciphers_do_cipher(ctx, out, in, inl) <= 0){
        QATerr(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    *outl = inl;
    if (!ctx->enc && ctx->tlsversion > 0) {
        /*
        * Remove any TLS padding. Only used by cipher_aes_cbc_hmac_sha1_hw.c and
        * cipher_aes_cbc_hmac_sha256_hw.c
        */
        if (ctx->removetlspad) {
            /*
             * We should have already failed in the cipher() call above if this
             * isn't true.
             */
            if (!ossl_assert(*outl >= (size_t)(out[inl - 1] + 1)))
                return 0;
            /* The actual padding length */
            *outl -= out[inl - 1] + 1;
        }

        /* TLS MAC and explicit IV if relevant. We should have already failed
         * in the cipher() call above if *outl is too short.
         */
        if (!ossl_assert(*outl >= ctx->removetlsfixed))
            return 0;
        *outl -= ctx->removetlsfixed;

        /* Extract the MAC if there is one */
        if (ctx->tlsmacsize > 0) {
            if (*outl < ctx->tlsmacsize)
                return 0;

            ctx->tlsmac = out + *outl - ctx->tlsmacsize;
            *outl -= ctx->tlsmacsize;
        }
    }

    return 1;
}

static const OSSL_PARAM cipher_known_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *qat_cipher_generic_gettable_params(ossl_unused void *provctx)
{
    return cipher_known_gettable_params;
}

static int ossl_cipher_generic_get_params(OSSL_PARAM params[], unsigned int md,
                                   uint64_t flags,
                                   size_t kbits, size_t blkbits, size_t ivbits)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, md)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_AEAD) != 0)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CUSTOM_IV) != 0)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CTS) != 0)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_TLS1_MULTIBLOCK) != 0)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_RAND_KEY) != 0)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits / 8)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits / 8)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits / 8)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}


# define IMPLEMENT_CIPHER(nm, sub, kbits, blkbits, ivbits, flags, nid)                  \
static OSSL_FUNC_cipher_newctx_fn qat_##nm##_##kbits##_##sub##_newctx;                  \
static void *qat_##nm##_##kbits##_##sub##_newctx(void *provctx)                         \
{                                                                                       \
    return qat_##nm##_##sub##_newctx(provctx, kbits, blkbits, ivbits, flags, nid);      \
}                                                                                       \
static OSSL_FUNC_cipher_get_params_fn qat_##nm##_##kbits##_##sub##_get_params;          \
static int qat_##nm##_##kbits##_##sub##_get_params(OSSL_PARAM params[])                 \
{                                                                                       \
    return ossl_cipher_generic_get_params(params, EVP_CIPH_CBC_MODE,                    \
                                          flags, kbits, blkbits, ivbits);               \
}                                                                                       \
const OSSL_DISPATCH qat_##nm##kbits##sub##_functions[] = {                              \
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))qat_##nm##_##kbits##_##sub##_newctx },   \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))qat_##nm##_##sub##_freectx },           \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))qat_##nm##_einit },                \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))qat_##nm##_dinit },                \
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))qat_##nm##_update },                     \
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))qat_##nm##_final },                       \
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))qat_##nm##_cipher },                     \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                                      \
        (void (*)(void))qat_##nm##_##kbits##_##sub##_get_params },                      \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                                 \
        (void (*)(void))qat_##nm##_gettable_params },                                   \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                                  \
         (void (*)(void))qat_##nm##_get_ctx_params },                                   \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                             \
        (void (*)(void))qat_##nm##_gettable_ctx_params },                               \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                                  \
        (void (*)(void))qat_##nm##_set_ctx_params },                                    \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                             \
        (void (*)(void))qat_##nm##_settable_ctx_params },                               \
    { 0, NULL }                                                                         \
};

IMPLEMENT_CIPHER(aes, cbc_hmac_sha1, 128, 128, 128, AES_CBC_HMAC_SHA_FLAGS, NID_aes_128_cbc_hmac_sha1)

IMPLEMENT_CIPHER(aes, cbc_hmac_sha1, 256, 128, 128, AES_CBC_HMAC_SHA_FLAGS, NID_aes_256_cbc_hmac_sha1)

IMPLEMENT_CIPHER(aes, cbc_hmac_sha256, 128, 128, 128, AES_CBC_HMAC_SHA_FLAGS, NID_aes_128_cbc_hmac_sha256)

IMPLEMENT_CIPHER(aes, cbc_hmac_sha256, 256, 128, 128, AES_CBC_HMAC_SHA_FLAGS, NID_aes_256_cbc_hmac_sha256)

#endif /* QAT_HW */
