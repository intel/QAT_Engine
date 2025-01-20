/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023-2025 Intel Corporation.
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
 * @qat_prov_sm4_gcm.c
 *
 * This file contains the qatprovider implementation for SM4-GCM operations
 *
 *****************************************************************************/

#include "qat_provider.h"
#include "qat_prov_sm4_gcm.h"
#include "qat_utils.h"
#include "e_qat.h"

#ifdef ENABLE_QAT_SW_SM4_GCM
# include "qat_sw_sm4_gcm.h"
#endif

#define SM4_GCM_IV_MIN_SIZE     (64 / 8)

#define UNINITIALISED_SIZET ((int)-1)

#define AEAD_FLAGS (PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV)

#ifdef ENABLE_QAT_SW_SM4_GCM
void qat_sm4_gcm_initctx(void *provctx, QAT_PROV_GCM_CTX *ctx, size_t keybits,
                         size_t ivlen_min)
{
    ctx->pad = 1;
    ctx->mode = EVP_CIPH_GCM_MODE;
    ctx->tag_len = UNINITIALISED_SIZET;
    ctx->tls_aad_len = UNINITIALISED_SIZET;
    ctx->ivlen_min = ivlen_min;
    ctx->iv_len = (EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN);
    ctx->key_len = keybits / 8;
    ctx->libctx = prov_libctx_of(provctx);
}

static void *qat_sm4_gcm_newctx(void *provctx, size_t keybits, int nid)
{
    QAT_EVP_CIPHER_SM4_GCM *cipher = NULL;
    QAT_SM4GCM_CTX *ctx;
    QAT_EVP_CIPHER_SM4_GCM sm4_gcm_cipher = get_default_cipher_sm4_gcm();
    if (!qat_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    cipher = OPENSSL_zalloc(sizeof(QAT_EVP_CIPHER_SM4_GCM));

    cipher->nid = nid;
    ctx->cipher = cipher;
    if (!ctx->base.sw_ctx)
        ctx->base.sw_ctx = sm4_gcm_cipher.newctx(ctx);
    if (ctx != NULL)
        qat_sm4_gcm_initctx(provctx, &ctx->base, keybits, SM4_GCM_IV_MIN_SIZE);
    return ctx;
}

int qat_sm4_gcm_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    QAT_PROV_GCM_CTX *ctx = (QAT_PROV_GCM_CTX *) vctx;
    OSSL_PARAM *p;
    size_t sz;

    if (qat_sw_sm4_gcm_offload != 1) {
        QAT_EVP_CIPHER_SM4_GCM sm4_gcm_cipher = get_default_cipher_sm4_gcm();
        return sm4_gcm_cipher.get_ctx_params(ctx->sw_ctx, params);
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->iv_len)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->key_len)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL) {
        size_t taglen = (ctx->tag_len != UNINITIALISED_SIZET) ? ctx->tag_len :
            SM4_GCM_TAG_MAX_SIZE;

        if (!OSSL_PARAM_set_size_t(p, taglen)) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL) {
        if (ctx->iv_set == IV_STATE_UNINITIALISED)
            return 0;
        if (ctx->iv_len > p->data_size) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->iv_len)
            && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->iv_len)) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL) {
        if (ctx->iv_set == IV_STATE_UNINITIALISED)
            return 0;
        if (ctx->iv_len > p->data_size) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->iv_len)
            && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->iv_len)) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tls_aad_pad_sz)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        sz = p->data_size;

        if (sz == 0
            || sz > EVP_GCM_TLS_TAG_LEN
            || !ctx->enc || ctx->tag_len == UNINITIALISED_SIZET) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_TAG);
            return 0;
        }

        if (!OSSL_PARAM_set_octet_string(p, ctx->buf, sz)) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    return 1;
}

int qat_sm4_gcm_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    QAT_PROV_GCM_CTX *ctx = (QAT_PROV_GCM_CTX *) vctx;
    const OSSL_PARAM *p;
    size_t sz = 0;
    void *vp;

    if (params == NULL)
        return 1;

    if (qat_sw_sm4_gcm_offload != 1) {
        QAT_EVP_CIPHER_SM4_GCM sm4_gcm_cipher = get_default_cipher_sm4_gcm();
        return sm4_gcm_cipher.set_ctx_params(ctx->sw_ctx, params);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        vp = ctx->buf;
        if (!OSSL_PARAM_get_octet_string(p, &vp, EVP_GCM_TLS_TAG_LEN, &sz)) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (sz == 0 || ctx->enc) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_TAG);
            return 0;
        }
        ctx->tag_len = sz;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &sz)) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (sz == 0 || sz > ctx->iv_len) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_IV_LENGTH);
            return 0;
        }
        ctx->iv_len = sz;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
# ifdef ENABLE_QAT_SW_SM4_GCM
        if (qat_sw_sm4_gcm_offload)
            sz = qat_sw_sm4_gcm_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, p->data_size,
                                     p->data);
# endif
        if (sz == 0) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_AAD);
            return 0;
        }
        ctx->tls_aad_pad_sz = sz;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
# ifdef ENABLE_QAT_SW_SM4_GCM
        if (qat_sw_sm4_gcm_ctrl
            (ctx, EVP_CTRL_GCM_SET_IV_FIXED, p->data_size, p->data) == 0) {
# endif
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV);
    if (p != NULL) {
        if (p->data == NULL || p->data_type != OSSL_PARAM_OCTET_STRING
# ifdef ENABLE_QAT_SW_SM4_GCM
            || !qat_sw_sm4_gcm_ctrl(ctx, EVP_CTRL_GCM_SET_IV_INV, p->data_size,
                                    p->data))
# endif
            return 0;
    }

    return 1;
}

int qat_sm4_gcm_einit(void *ctx, const unsigned char *inkey,
                      int keylen, const unsigned char *iv, int ivlen, int enc)
{
    int sts = 0;
# ifdef ENABLE_QAT_SW_SM4_GCM
    if (qat_sw_sm4_gcm_offload) {
        sts = qat_sw_sm4_gcm_init(ctx, inkey, keylen, iv, ivlen, 1);
    } else {
      QAT_PROV_GCM_CTX *qctx = (QAT_PROV_GCM_CTX *) ctx;
      OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
      QAT_EVP_CIPHER_SM4_GCM sm4_gcm_cipher = get_default_cipher_sm4_gcm();
      sts = sm4_gcm_cipher.einit(qctx->sw_ctx, inkey, keylen, iv, ivlen,
                                 params);
    }
# endif
    return sts;
}

int qat_sm4_gcm_dinit(void *ctx, const unsigned char *inkey,
                      int keylen, const unsigned char *iv, int ivlen, int enc)
{
    int sts = 0;
# ifdef ENABLE_QAT_SW_SM4_GCM
    if (qat_sw_sm4_gcm_offload) {
        sts = qat_sw_sm4_gcm_init(ctx, inkey, keylen, iv, ivlen, 0);
    } else {
      QAT_PROV_GCM_CTX *qctx = (QAT_PROV_GCM_CTX *) ctx;
      OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
      QAT_EVP_CIPHER_SM4_GCM sm4_gcm_cipher = get_default_cipher_sm4_gcm();
      sts = sm4_gcm_cipher.dinit(qctx->sw_ctx, inkey, keylen, iv, ivlen,
                                 params);
    }
# endif
    return sts;
}

int qat_sm4_gcm_stream_update(void *vctx, unsigned char *out,
                              size_t *outl, size_t outsize,
                              const unsigned char *in, size_t inl)
{
    int ret = 0;
# ifdef ENABLE_QAT_SW_SM4_GCM
    QAT_PROV_GCM_CTX *ctx = (QAT_PROV_GCM_CTX *) vctx;
# endif

    if (outsize < inl) {
        QATerr(ERR_LIB_PROV, QAT_R_OUTPUT_BUFFER_TOO_SMALL);
        goto end;
    }
# ifdef ENABLE_QAT_SW_SM4_GCM
    if (qat_sw_sm4_gcm_offload) {
        if ((ret =
             qat_sw_sm4_gcm_cipher(ctx, out, outl, outsize, in, inl)) <= 0) {
            QATerr(ERR_LIB_PROV, QAT_R_CIPHER_OPERATION_FAILED);
            goto end;
        }
    } else {
        QAT_EVP_CIPHER_SM4_GCM sm4_gcm_cipher = get_default_cipher_sm4_gcm();
        if (sm4_gcm_cipher.cupdate == NULL)
            return 0;
        if (sm4_gcm_cipher.cupdate(ctx->sw_ctx, out, outl,
                                   outsize, in, inl) <= 0) {
            return 0;
        }
    }
# endif
    ret = 1;

 end:
    return ret;
}

int qat_sm4_gcm_stream_final(void *vctx, unsigned char *out,
                             size_t *outl, size_t outsize)
{
    int ret = 0;

# ifdef ENABLE_QAT_SW_SM4_GCM
    QAT_PROV_GCM_CTX *ctx = (QAT_PROV_GCM_CTX *) vctx;
# endif
    int i = 0;

    if (!qat_prov_is_running())
        goto end;
# ifdef ENABLE_QAT_SW_SM4_GCM
    if (qat_sw_sm4_gcm_offload) {
        i = qat_sw_sm4_gcm_cipher(ctx, out, outl, outsize, NULL, 0);
    } else {
      QAT_EVP_CIPHER_SM4_GCM sm4_gcm_cipher = get_default_cipher_sm4_gcm();
      if (sm4_gcm_cipher.cfinal == NULL)
          return 0;
      i = sm4_gcm_cipher.cfinal(ctx->sw_ctx, out, outl, outsize);
    }
# endif

    if (i <= 0)
        goto end;

    *outl = 0;
    ret = 1;

 end:
    return ret;
}

int qat_sm4_gcm_cipher(void *vctx, unsigned char *out,
                       size_t *outl, size_t outsize,
                       const unsigned char *in, size_t inl)
{
    int ret = 0;
# ifdef ENABLE_QAT_SW_SM4_GCM
    QAT_PROV_GCM_CTX *ctx = (QAT_PROV_GCM_CTX *) vctx;
# endif

    if (!qat_prov_is_running())
        goto end;

    if (outsize < inl) {
        QATerr(ERR_LIB_PROV, QAT_R_OUTPUT_BUFFER_TOO_SMALL);
        goto end;
    }
# ifdef ENABLE_QAT_SW_SM4_GCM
    if (qat_sw_sm4_gcm_offload) {
        if (qat_sw_sm4_gcm_cipher(ctx, out, outl, outsize, in, inl) <= 0)
            goto end;
    } else {
        QAT_EVP_CIPHER_SM4_GCM sm4_gcm_cipher = get_default_cipher_sm4_gcm();
        if (sm4_gcm_cipher.cupdate == NULL)
            return 0;
        if (sm4_gcm_cipher.cupdate(ctx->sw_ctx, out, outl,
                                   outsize, in, inl) <= 0) {
            return 0;
        }
    }
# endif

    *outl = inl;
    ret = 1;

 end:
    return ret;
}

static void qat_sm4_gcm_freectx(void *vctx)
{
    QAT_SM4GCM_CTX *ctx = (QAT_SM4GCM_CTX *) vctx;
    if (ctx->cipher) {
        OPENSSL_free(ctx->cipher);
        ctx->cipher = NULL;
    }
# ifdef ENABLE_QAT_SW_SM4_GCM
    if (qat_sw_sm4_gcm_offload)
        qat_sw_sm4_gcm_cleanup((QAT_PROV_GCM_CTX *) ctx);
# endif
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static const OSSL_PARAM qat_sm4_gcm_known_gettable_params[] = {
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

const OSSL_PARAM *qat_sm4_gcm_generic_gettable_params(ossl_unused void *provctx)
{
    return qat_sm4_gcm_known_gettable_params;
}

int qat_sm4_gcm_generic_get_params(OSSL_PARAM params[], unsigned int md,
                                   uint64_t flags, size_t kbits,
                                   size_t blkbits, size_t ivbits)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, md)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_AEAD) != 0)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CUSTOM_IV) != 0)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CTS) != 0)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK);
    if (p != NULL
        && !OSSL_PARAM_set_int(p,
                               (flags & PROV_CIPHER_FLAG_TLS1_MULTIBLOCK) !=
                               0)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_RAND_KEY) != 0)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits / 8)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits / 8)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits / 8)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

static const OSSL_PARAM qat_sm4_gcm_aead_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN, NULL, 0),
    OSSL_PARAM_END
};

const OSSL_PARAM *qat_sm4_gcm_aead_gettable_ctx_params
    (ossl_unused void *cctx, ossl_unused void *provctx) {
    return qat_sm4_gcm_aead_known_gettable_ctx_params;
}

static const OSSL_PARAM qat_sm4_gcm_aead_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, NULL, 0),
    OSSL_PARAM_END
};

const OSSL_PARAM *qat_sm4_gcm_aead_settable_ctx_params
    (ossl_unused void *cctx, ossl_unused void *provctx) {
    return qat_sm4_gcm_aead_known_settable_ctx_params;
}

/* qat_sm4gcm_functions */
QAT_sm4_gcm_cipher(qat_sm4, gcm, GCM, AEAD_FLAGS, 128, 8, 96, NID_sm4_gcm);
#endif
