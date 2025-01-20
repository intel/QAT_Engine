/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2025 Intel Corporation.
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
 * @file qat_prov_chachapoly.c
 *
 * This file provides an implementation of CHACHAPOLY operations for OpenSSL
 * 3.0 qatprovider.
 *
 *****************************************************************************/
#include <openssl/proverr.h>

#ifdef QAT_HW_INTREE
# ifndef ENABLE_QAT_HW_CHACHAPOLY
#  define ENABLE_QAT_HW_CHACHAPOLY
# endif
#endif

#ifdef ENABLE_QAT_HW_CHACHAPOLY
#include "qat_prov_chachapoly.h"
#include "e_qat.h"
#include "qat_utils.h"
#include "qat_evp.h"

#define CHACHA20_POLY1305_KEYLEN 32
#define CHACHA20_POLY1305_BLKLEN 1
#define CHACHA20_POLY1305_MAX_IVLEN 12
#define CHACHA20_POLY1305_MODE 0
#define CHACHA20_POLY1305_FLAGS (PROV_CIPHER_FLAG_AEAD                         \
                                 | PROV_CIPHER_FLAG_CUSTOM_IV)

static OSSL_FUNC_cipher_newctx_fn qat_chacha20_poly1305_newctx;
static OSSL_FUNC_cipher_freectx_fn qat_chacha20_poly1305_freectx;
static OSSL_FUNC_cipher_encrypt_init_fn qat_chacha20_poly1305_einit;
static OSSL_FUNC_cipher_decrypt_init_fn qat_chacha20_poly1305_dinit;
static OSSL_FUNC_cipher_get_params_fn qat_chacha20_poly1305_get_params;
static OSSL_FUNC_cipher_get_ctx_params_fn qat_chacha20_poly1305_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn qat_chacha20_poly1305_set_ctx_params;
static OSSL_FUNC_cipher_cipher_fn qat_chacha20_poly1305_cipher;
static OSSL_FUNC_cipher_final_fn qat_chacha20_poly1305_final;
static OSSL_FUNC_cipher_gettable_ctx_params_fn qat_chacha20_poly1305_gettable_ctx_params;
static OSSL_FUNC_cipher_gettable_params_fn qat_cipher_generic_gettable_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn qat_cipher_aead_settable_ctx_params;
#define qat_chacha20_poly1305_update qat_chacha20_poly1305_cipher

static void qat_cipher_generic_reset_ctx(QAT_PROV_CIPHER_CTX *ctx)
{
    if (ctx != NULL && ctx->alloced) {
        OPENSSL_free(ctx->tlsmac);
        ctx->alloced = 0;
        ctx->tlsmac = NULL;
    }
}

QAT_EVP_CIPHER get_default_cipher_chachapoly()
{
    static QAT_EVP_CIPHER chachapoly_cipher;
    static int initialized = 0;
    if (!initialized) {
        QAT_EVP_CIPHER *cipher =
            (QAT_EVP_CIPHER *) EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305",
                                                "provider=default");
        if (cipher) {
            chachapoly_cipher = *cipher;
            EVP_CIPHER_free((EVP_CIPHER *)cipher);
            initialized = 1;
        } else {
            WARN("EVP_CIPHER_fetch from default provider failed");
        }
    }
    return chachapoly_cipher;
}

static int qat_cipher_generic_get_params(OSSL_PARAM params[], unsigned int md,
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

static void qat_cipher_generic_initkey(void *vctx, size_t kbits, size_t blkbits,
                                 size_t ivbits, unsigned int mode,
                                 uint64_t flags, void *provctx)
{
    QAT_PROV_CIPHER_CTX *ctx = (QAT_PROV_CIPHER_CTX *)vctx;

    if ((flags & PROV_CIPHER_FLAG_INVERSE_CIPHER) != 0)
        ctx->inverse_cipher = 1;
    if ((flags & PROV_CIPHER_FLAG_VARIABLE_LENGTH) != 0)
        ctx->variable_keylength = 1;

    ctx->pad = 1;
    ctx->keylen = ((kbits) / 8);
    ctx->ivlen = ((ivbits) / 8);
    ctx->mode = mode;
    ctx->blocksize = blkbits / 8;
    if (provctx != NULL)
        ctx->libctx = prov_libctx_of(provctx); /* used for rand */
}

static void *qat_chacha20_poly1305_newctx(void *provctx)
{
    PROV_CHACHA20_POLY1305_CTX *ctx;

    if (!qat_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {
        qat_cipher_generic_initkey(&ctx->base, CHACHA20_POLY1305_KEYLEN * 8,
                                    CHACHA20_POLY1305_BLKLEN * 8,
                                    CHACHA20_POLY1305_IVLEN * 8,
                                    CHACHA20_POLY1305_MODE,
                                    CHACHA20_POLY1305_FLAGS,
                                    NULL);
        ctx->nonce_len = CHACHA20_POLY1305_IVLEN;
        ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
        qat_cipher_generic_initkey(&ctx->chacha, CHACHA20_KEYLEN * 8,
                                   CHACHA20_BLKLEN * 8,
                                   CHACHA20_IVLEN * 8,
                                   0, CHACHA20_FLAGS,
                                   NULL);
        ctx->base.nid = NID_chacha20_poly1305;
        ctx->base.nonce_len = CHACHA20_POLY1305_IVLEN;
        ctx->base.tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
    }
    return ctx;
}

static void qat_chacha20_poly1305_freectx(void *vctx)
{
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)vctx;

    if (ctx != NULL) {
        EVP_CIPHER_free((EVP_CIPHER *)ctx->base.sw_cipher);
        /* Free the memory of qat chachapoly context structure. */
        qat_chacha20_poly1305_cleanup(&ctx->base);
        qat_cipher_generic_reset_ctx((QAT_PROV_CIPHER_CTX *)vctx);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

static int qat_chacha20_poly1305_get_params(OSSL_PARAM params[])
{
    return qat_cipher_generic_get_params(params, 0, CHACHA20_POLY1305_FLAGS,
                                          CHACHA20_POLY1305_KEYLEN * 8,
                                          CHACHA20_POLY1305_BLKLEN * 8,
                                          CHACHA20_POLY1305_IVLEN * 8);
}

static int qat_chacha20_poly1305_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)vctx;
    OSSL_PARAM *p;
    int ret = 1;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_set_size_t(p, ctx->nonce_len)) {
            QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CHACHA20_POLY1305_KEYLEN)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tag_len)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tls_aad_pad_sz)) {
        QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        if (!ctx->base.enc) {
            QATerr(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
            return 0;
        }
        if (p->data_size == 0 || p->data_size > QAT_POLY1305_BLOCK_SIZE) {
            if (ctx->base.tag_set)
                QATerr(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            ret = 0;
            ctx->base.tag_set = 0;
            goto end;
        }
        memcpy(p->data, ctx->base.tag, p->data_size);
        if (ctx->base.tag_set) {
            ctx->base.tag_set = 0;
            return 1;
        }
    }

end:
    if (ctx->base.sw_ctx) {
        QAT_EVP_CIPHER sw_chachapoly_cipher = get_default_cipher_chachapoly();
        sw_chachapoly_cipher.get_ctx_params(ctx->base.sw_ctx, params);
    }
    return ret;
}

static const OSSL_PARAM chacha20_poly1305_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *qat_chacha20_poly1305_gettable_ctx_params
    (ossl_unused void *cctx, ossl_unused void *provctx)
{
    return chacha20_poly1305_known_gettable_ctx_params;
}

static int qat_chacha20_poly1305_set_ctx_params(void *vctx,
                                            const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    size_t len;
    PROV_CHACHA20_POLY1305_CTX *ctx = (PROV_CHACHA20_POLY1305_CTX *)vctx;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != CHACHA20_POLY1305_KEYLEN) {
            QATerr(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len == 0 || len > CHACHA20_POLY1305_MAX_IVLEN) {
            QATerr(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        ctx->nonce_len = len;
        qat_chacha20_poly1305_ctrl(&ctx->base, EVP_CTRL_AEAD_SET_IVLEN, len, NULL);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (p->data_size == 0 || p->data_size > QAT_POLY1305_BLOCK_SIZE) {
            QATerr(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return 0;
        }
        if (p->data != NULL) {
            if (ctx->base.enc) {
                QATerr(ERR_LIB_PROV, PROV_R_TAG_NOT_NEEDED);
                return 0;
            }
            memcpy(ctx->base.tag, p->data, p->data_size);
            ctx->base.tag_set = 1;
        }
        ctx->base.tag_len = p->data_size;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        len = qat_chacha20_poly1305_ctrl(&ctx->base, EVP_CTRL_AEAD_TLS1_AAD, 
                                         p->data_size, p->data);
        if (len == 0) {
            QATerr(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            return 0;
        }
        ctx->tls_aad_pad_sz = len;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            QATerr(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (qat_chacha20_poly1305_ctrl(&ctx->base, EVP_CTRL_AEAD_SET_IV_FIXED, 
                                       p->data_size, p->data) == 0) {
            QATerr(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
    }

    if (ctx->base.sw_ctx) {
        QAT_EVP_CIPHER sw_chachapoly_cipher = get_default_cipher_chachapoly();
        sw_chachapoly_cipher.set_ctx_params(ctx->base.sw_ctx, params);
    }
    /* ignore OSSL_CIPHER_PARAM_AEAD_MAC_KEY */
    return 1;
}

static int qat_cipher_generic_initiv(QAT_PROV_CIPHER_CTX *ctx, const unsigned char *iv,
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

static int qat_chacha20_poly1305_einit(void *vctx, const unsigned char *key,
                                  size_t keylen, const unsigned char *iv,
                                  size_t ivlen, const OSSL_PARAM params[])
{
    QAT_PROV_CIPHER_CTX *ctx = (QAT_PROV_CIPHER_CTX *)vctx;
    int ret;

    ctx->num = 0;
    ctx->bufsz = 0;
    ctx->updated = 0;
    ctx->enc = 1;

    if (!qat_prov_is_running())
        return 0;

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
    
    ret = qat_chacha20_poly1305_init(ctx, key, keylen, iv, ivlen, 1);

    if (ret && !qat_chacha20_poly1305_set_ctx_params(vctx, params))
        ret = 0;
    return ret;
}

static int qat_chacha20_poly1305_dinit(void *vctx, const unsigned char *key,
                                  size_t keylen, const unsigned char *iv,
                                  size_t ivlen, const OSSL_PARAM params[])
{
    QAT_PROV_CIPHER_CTX *ctx = (QAT_PROV_CIPHER_CTX *)vctx;
    PROV_CHACHA20_POLY1305_CTX *cp_ctx = (PROV_CHACHA20_POLY1305_CTX *)vctx;
    int ret;

    ctx->num = 0;
    ctx->bufsz = 0;
    ctx->updated = 0;
    ctx->enc = 0;

    if (!qat_prov_is_running())
        return 0;

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

    ret = qat_chacha20_poly1305_init(ctx, key, keylen, iv, ivlen, 0);
    if (ret && !qat_chacha20_poly1305_set_ctx_params(vctx, params))
        ret = 0;

    memcpy(cp_ctx->tag, ctx->tag, ctx->tag_len);
    return ret;
}

static int qat_chacha20_poly1305_cipher(void *vctx, unsigned char *out,
                                    size_t *outl, size_t outsize,
                                    const unsigned char *in, size_t inl)
{
    QAT_PROV_CIPHER_CTX *ctx = (QAT_PROV_CIPHER_CTX *)vctx;

    if (!qat_prov_is_running())
        return 0;

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        QATerr(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!qat_chacha20_poly1305_do_cipher(ctx, out, outl, outsize, in, inl))
        return 0;

    return 1;
}

static int qat_chacha20_poly1305_final(void *vctx, unsigned char *out, size_t *outl,
                                   size_t outsize)
{
    QAT_PROV_CIPHER_CTX *ctx = (QAT_PROV_CIPHER_CTX *)vctx;

    if (!qat_prov_is_running())
        return 0;

    if (qat_chacha20_poly1305_do_cipher(ctx, out, outl, outsize, NULL, 0) <= 0)
        return 0;

    *outl = 0;
    return 1;
}

static const OSSL_PARAM qat_cipher_known_gettable_params[] = {
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

static const OSSL_PARAM *qat_cipher_generic_gettable_params(void *provctx)
{
    return qat_cipher_known_gettable_params;
}

static const OSSL_PARAM qat_cipher_aead_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *qat_cipher_aead_settable_ctx_params(
        ossl_unused void *cctx, ossl_unused void *provctx
    )
{
    return qat_cipher_aead_known_settable_ctx_params;
}

/* qat_chacha20_poly1305_functions */
const OSSL_DISPATCH qat_chacha20_poly1305_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))qat_chacha20_poly1305_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))qat_chacha20_poly1305_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))qat_chacha20_poly1305_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))qat_chacha20_poly1305_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))qat_chacha20_poly1305_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))qat_chacha20_poly1305_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))qat_chacha20_poly1305_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS,
        (void (*)(void))qat_chacha20_poly1305_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
        (void (*)(void))qat_cipher_generic_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
         (void (*)(void))qat_chacha20_poly1305_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        (void (*)(void))qat_chacha20_poly1305_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
        (void (*)(void))qat_chacha20_poly1305_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        (void (*)(void))qat_cipher_aead_settable_ctx_params },
    { 0, NULL }
};

#endif /* ENABLE_QAT_HW_CHACHAPOLY */
