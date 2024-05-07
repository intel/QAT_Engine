/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2024 Intel Corporation.
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
 * @qat_prov_aes_ccm.c
 *
 * This file contains the qatprovider implementation for AES-CCM operations
 *
 *****************************************************************************/

#include "qat_provider.h"
#include "qat_prov_aes_ccm.h"
#include "qat_utils.h"
#include "e_qat.h"
#include "qat_evp.h"
#ifdef ENABLE_QAT_HW_CCM
# include "qat_hw_ccm.h"
#endif

#define AES_CCM_IV_MIN_SIZE     (64 / 8)
#define AEAD_FLAGS (PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV)
#define QAT_AES_CCM_OP_VALUE 15

#ifdef ENABLE_QAT_HW_CCM
static OSSL_FUNC_cipher_freectx_fn qat_aes_ccm_freectx;

void qat_aes_ccm_init_ctx(void *provctx, QAT_PROV_CCM_CTX * ctx, size_t keybits,
                          size_t ivlen_min)
{
    ctx->keylen = keybits / 8;
    ctx->key_set = 0;
    ctx->iv_set = 0;
    ctx->tag_set = 0;
    ctx->len_set = 0;
    ctx->L = 8;
    ctx->M = 12;
    ctx->tls_aad_len = -1;
    ctx->pad = 1;
    ctx->mode = EVP_CIPH_CCM_MODE;
    ctx->tag_len = -1;
    ctx->ivlen_min = ivlen_min;
    ctx->libctx = prov_libctx_of(provctx);
    ctx->iv_len = (EVP_CCM_TLS_FIXED_IV_LEN + EVP_CCM_TLS_EXPLICIT_IV_LEN);
}

const char *qat_ccm_cipher_name(int nid)
{
    switch (nid) {
    case NID_aes_128_ccm:
        return LN_aes_128_ccm;
    case NID_aes_192_ccm:
        return LN_aes_192_ccm;
    case NID_aes_256_ccm:
        return LN_aes_256_ccm;
    default:
        WARN("Invalid nid %d\n", nid);
        return NULL;
    }
}

QAT_EVP_CIPHER get_default_cipher_aes_ccm(int nid)
{
    static QAT_EVP_CIPHER ccm_cipher;
    static int initialized = 0;
    if (!initialized) {
        QAT_EVP_CIPHER *cipher =
            (QAT_EVP_CIPHER *) EVP_CIPHER_fetch(NULL, qat_ccm_cipher_name(nid),
                                                "provider=default");
        if (cipher) {
            ccm_cipher = *cipher;
            EVP_CIPHER_free((EVP_CIPHER *)cipher);
            initialized = 1;
        } else {
            WARN("EVP_CIPHER_fetch from default provider failed");
        }
    }
    return ccm_cipher;
}

static void *qat_aes_ccm_newctx(void *provctx, size_t keybits, int nid)
{
    QAT_PROV_AES_CCM_CTX *ctx = NULL;
    QAT_EVP_CIPHER *cipher;

    if (!qat_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    cipher = OPENSSL_zalloc(sizeof(QAT_EVP_CIPHER));

    cipher->nid = nid;
    ctx->cipher = cipher;
    ctx->base.nid = nid;

    if (ctx != NULL) {
        qat_aes_ccm_init_ctx(provctx, &ctx->base, keybits, AES_CCM_IV_MIN_SIZE);
    }

    return ctx;
}

size_t qat_aes_ccm_get_ivlen(QAT_PROV_CCM_CTX * ctx)
{
    return QAT_AES_CCM_OP_VALUE - ctx->L;
}

int qat_aes_ccm_einit(void *ctx, const unsigned char *inkey, size_t keylen,
                      const unsigned char *iv, size_t ivlen, int enc)
{
    int sts = 0;
# if !defined(QAT20_OOT) && !defined(QAT_HW_INTREE) \
     && !defined(QAT_HW_FBSD_OOT) && !defined(QAT_HW_FBSD_INTREE)
    QAT_PROV_CCM_CTX *qctx = (QAT_PROV_CCM_CTX *) ctx;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    QAT_EVP_CIPHER sw_aes_ccm_cipher = get_default_cipher_aes_ccm(qctx->nid);

    if (qctx->nid == NID_aes_192_ccm || qctx->nid == NID_aes_256_ccm) {
        if (!qctx->sw_ctx)
            qctx->sw_ctx = sw_aes_ccm_cipher.newctx(ctx);

        sts =
            sw_aes_ccm_cipher.einit(qctx->sw_ctx, inkey, keylen, iv, ivlen,
                                    params);
        if (sts != 1)
            return 0;

        return sts;
    }
# endif
    if (qat_hw_aes_ccm_offload)
        sts = qat_aes_ccm_init(ctx, inkey, keylen, iv, ivlen, 1);

    return sts;
}

int qat_aes_ccm_dinit(void *ctx, const unsigned char *inkey, size_t keylen,
                      const unsigned char *iv, size_t ivlen, int enc)
{
    int sts = 0;
# if !defined(QAT20_OOT) && !defined(QAT_HW_INTREE) \
     && !defined(QAT_HW_FBSD_OOT) && !defined(QAT_HW_FBSD_INTREE)
    QAT_PROV_CCM_CTX *qctx = (QAT_PROV_CCM_CTX *) ctx;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    QAT_EVP_CIPHER sw_aes_ccm_cipher = get_default_cipher_aes_ccm(qctx->nid);
    if (qctx->nid == NID_aes_192_ccm || qctx->nid == NID_aes_256_ccm) {
        if (!qctx->sw_ctx)
            qctx->sw_ctx = sw_aes_ccm_cipher.newctx(ctx);

        unsigned int pad = 0;
        params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &pad);
        sts =
            sw_aes_ccm_cipher.dinit(qctx->sw_ctx, inkey, keylen, iv, ivlen,
                                    params);
        if (sts != 1)
            return 0;

        return sts;
    }
# endif
    if (qat_hw_aes_ccm_offload)
        sts = qat_aes_ccm_init(ctx, inkey, keylen, iv, ivlen, 0);

    return sts;
}

int qat_aes_ccm_stream_update(void *vctx, unsigned char *out,
                              size_t *outl, size_t outsize,
                              const unsigned char *in, size_t inl)
{
    QAT_PROV_CCM_CTX *ctx = (QAT_PROV_CCM_CTX *) vctx;
# if !defined(QAT20_OOT) && !defined(QAT_HW_INTREE) \
     && !defined(QAT_HW_FBSD_OOT) && !defined(QAT_HW_FBSD_INTREE)
    QAT_EVP_CIPHER sw_aes_ccm_cipher;
# endif

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        QATerr(ERR_LIB_PROV, QAT_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
# if !defined(QAT20_OOT) && !defined(QAT_HW_INTREE) \
     && !defined(QAT_HW_FBSD_OOT) && !defined(QAT_HW_FBSD_INTREE)
    if (ctx->nid == NID_aes_192_ccm || ctx->nid == NID_aes_256_ccm) {
        sw_aes_ccm_cipher = get_default_cipher_aes_ccm(ctx->nid);
        if (sw_aes_ccm_cipher.cupdate == NULL)
            return 0;

        if (sw_aes_ccm_cipher.cupdate(ctx->sw_ctx, out, outl,
                                             outsize, in, inl) <= 0) {
            return 0;
        }

        return 1;
    }
# endif

    if (qat_hw_aes_ccm_offload) {
        if ((qat_aes_ccm_cipher(ctx, out, outl, outsize, in, inl)) <= 0) {
            QATerr(ERR_LIB_PROV, QAT_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
    }

    return 1;

}

int qat_aes_ccm_stream_final(void *vctx, unsigned char *out,
                             size_t *outl, size_t outsize)
{
    int i = 0;
    QAT_PROV_CCM_CTX *ctx = (QAT_PROV_CCM_CTX *) vctx;
# if !defined(QAT20_OOT) && !defined(QAT_HW_INTREE) \
     && !defined(QAT_HW_FBSD_OOT) && !defined(QAT_HW_FBSD_INTREE)
    QAT_EVP_CIPHER sw_aes_ccm_cipher;
# endif

    if (!qat_prov_is_running())
        return 0;

# if !defined(QAT20_OOT) && !defined(QAT_HW_INTREE) \
     && !defined(QAT_HW_FBSD_OOT) && !defined(QAT_HW_FBSD_INTREE)
    if (ctx->nid == NID_aes_192_ccm || ctx->nid == NID_aes_256_ccm) {
        sw_aes_ccm_cipher = get_default_cipher_aes_ccm(ctx->nid);
        if (sw_aes_ccm_cipher.cfinal == NULL)
            return 0;
        i = sw_aes_ccm_cipher.cfinal(ctx->sw_ctx, out, outl, outsize);
        *outl = 0;
        return 1;
    }
# endif

    if (qat_hw_aes_ccm_offload)
        i = qat_aes_ccm_cipher(ctx, out, outl, outsize, NULL, 0);

    if (i <= 0)
        return 0;

    *outl = 0;
    return 1;
}

int qat_aes_ccm_do_cipher(void *vctx, unsigned char *out,
                          size_t *outl, size_t outsize,
                          const unsigned char *in, size_t inl)
{
    QAT_PROV_CCM_CTX *ctx = (QAT_PROV_CCM_CTX *) vctx;
# if !defined(QAT20_OOT) && !defined(QAT_HW_INTREE) \
     && !defined(QAT_HW_FBSD_OOT) && !defined(QAT_HW_FBSD_INTREE)
    QAT_EVP_CIPHER sw_aes_ccm_cipher;
# endif

    if (!qat_prov_is_running())
        return 0;

    if (outsize < inl) {
        QATerr(ERR_LIB_PROV, QAT_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
# if !defined(QAT20_OOT) && !defined(QAT_HW_INTREE) \
     && !defined(QAT_HW_FBSD_OOT) && !defined(QAT_HW_FBSD_INTREE)
    if (ctx->nid == NID_aes_192_ccm || ctx->nid == NID_aes_256_ccm) {
        sw_aes_ccm_cipher = get_default_cipher_aes_ccm(ctx->nid);
        if (sw_aes_ccm_cipher.cupdate == NULL)
            return 0;

        if (sw_aes_ccm_cipher.cupdate(ctx->sw_ctx, out, outl,
                                             outsize, in, inl) <= 0) {
            return 0;
        }

        return 1;
    }
# endif
    if (qat_hw_aes_ccm_offload) {
        if (qat_aes_ccm_cipher(ctx, out, outl, outsize, in, inl) <= 0) {
            return 0;
        }
    }

    *outl = inl;
    return 1;
}

int qat_aes_ccm_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    QAT_PROV_CCM_CTX *ctx = (QAT_PROV_CCM_CTX *) vctx;
    OSSL_PARAM *p;

# if !defined(QAT20_OOT) && !defined(QAT_HW_INTREE) \
     && !defined(QAT_HW_FBSD_OOT) && !defined(QAT_HW_FBSD_INTREE)
    if (ctx->nid == NID_aes_192_ccm || ctx->nid == NID_aes_256_ccm) {
        if (ctx->sw_ctx) {
            QAT_EVP_CIPHER sw_aes_ccm_cipher =
                get_default_cipher_aes_ccm(ctx->nid);
            return sw_aes_ccm_cipher.get_ctx_params(ctx->sw_ctx, params);
        }
    }
# endif

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, qat_aes_ccm_get_ivlen(ctx))) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen)) {
        QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL) {
        size_t m = ctx->M;
        if (!OSSL_PARAM_set_size_t(p, m)) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL) {
        if (qat_aes_ccm_get_ivlen(ctx) > p->data_size) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, ctx->iv, p->data_size)
            && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, p->data_size)) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL) {
        if (ctx->iv_set == IV_STATE_UNINITIALISED)
            return 0;
        if (qat_aes_ccm_get_ivlen(ctx) > p->data_size) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, ctx->iv, p->data_size)
            && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, p->data_size)) {
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
        if (!ctx->enc) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_TAG);
            return 0;
        }
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }

        memcpy(p->data, ctx->buf, p->data_size);

        ctx->iv_set = 0;
        ctx->len_set = 0;
        if (ctx->tag_set) {
            ctx->tag_set = 0;
            return 1;
        }

    }

    if (ctx->sw_ctx) {
        QAT_EVP_CIPHER sw_aes_ccm_cipher = get_default_cipher_aes_ccm(ctx->nid);
        sw_aes_ccm_cipher.get_ctx_params(ctx->sw_ctx, params);
    }
    return 1;
}

int qat_aes_ccm_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    QAT_PROV_CCM_CTX *ctx = (QAT_PROV_CCM_CTX *) vctx;
    const OSSL_PARAM *p;
    size_t sz = 0;

    if (params == NULL)
        return 1;

# if !defined(QAT20_OOT) && !defined(QAT_HW_INTREE) \
     && !defined(QAT_HW_FBSD_OOT) && !defined(QAT_HW_FBSD_INTREE)
    if (ctx->nid == NID_aes_192_ccm || ctx->nid == NID_aes_256_ccm) {
        if (ctx->sw_ctx) {
            QAT_EVP_CIPHER sw_aes_ccm_cipher =
                get_default_cipher_aes_ccm(ctx->nid);
            return sw_aes_ccm_cipher.set_ctx_params(ctx->sw_ctx, params);
        }
    }
# endif
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if ((p->data_size & 1) || (p->data_size < 4) || p->data_size > 16) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_TAG);
            return 0;
        }

        if (p->data != NULL) {
            if (ctx->enc) {
                QATerr(ERR_LIB_PROV, QAT_R_TAG_NOT_NEEDED);
                return 0;
            }
            memcpy(ctx->buf, p->data, p->data_size);
            ctx->tag_set = 1;
        }

        ctx->M = p->data_size;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
    if (p != NULL) {
        size_t ivlen;

        if (!OSSL_PARAM_get_size_t(p, &sz)) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ivlen = QAT_AES_CCM_OP_VALUE - sz;
        if (ivlen < 2 || ivlen > 8) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (ctx->L != ivlen) {
            ctx->L = ivlen;
            ctx->iv_set = 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (qat_hw_aes_ccm_offload)
            sz = qat_aes_ccm_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, p->data_size,
                                  p->data);

        if (sz == 0) {
            QATerr(ERR_LIB_PROV, QAT_R_INVALID_DATA);
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
        if (qat_hw_aes_ccm_offload) {
            if (qat_aes_ccm_ctrl
                (ctx, EVP_CTRL_CCM_SET_IV_FIXED, p->data_size, p->data) == 0) {
                QATerr(ERR_LIB_PROV, QAT_R_FAILED_TO_GET_PARAMETER);
                return 0;
            }
        }
    }

    if (ctx->sw_ctx) {
        QAT_EVP_CIPHER sw_aes_ccm_cipher = get_default_cipher_aes_ccm(ctx->nid);
        sw_aes_ccm_cipher.set_ctx_params(ctx->sw_ctx, params);
    }
    return 1;
}

int qat_aes_ccm_generic_get_params(OSSL_PARAM params[], unsigned int md,
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

static void qat_aes_ccm_freectx(void *vctx)
{
    QAT_PROV_AES_CCM_CTX *ctx = (QAT_PROV_AES_CCM_CTX *) vctx;
    if (ctx != NULL) {
        if (ctx->cipher) {
            OPENSSL_free(ctx->cipher);
            ctx->cipher = NULL;
        }

        if (qat_hw_aes_ccm_offload)
            qat_aes_ccm_cleanup(&ctx->base);

        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

static const OSSL_PARAM qat_aes_ccm_known_gettable_params[] = {
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

const OSSL_PARAM *qat_aes_ccm_generic_gettable_params(ossl_unused void *provctx)
{
    return qat_aes_ccm_known_gettable_params;
}

static const OSSL_PARAM qat_aes_ccm_aead_known_gettable_ctx_params[] = {
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

const OSSL_PARAM *qat_aes_ccm_aead_gettable_ctx_params
    (ossl_unused void *cctx, ossl_unused void *provctx) {
    return qat_aes_ccm_aead_known_gettable_ctx_params;
}

static const OSSL_PARAM qat_aes_ccm_aead_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, NULL, 0),
    OSSL_PARAM_END
};

const OSSL_PARAM *qat_aes_ccm_aead_settable_ctx_params
    (ossl_unused void *cctx, ossl_unused void *provctx) {
    return qat_aes_ccm_aead_known_settable_ctx_params;
}

/* qat_aes_128_ccm_functions */
QAT_aes_cipher(qat_aes, ccm, CCM, AEAD_FLAGS, 128, 8, 96, NID_aes_128_ccm);
/* qat_aes_192_ccm_functions */
QAT_aes_cipher(qat_aes, ccm, CCM, AEAD_FLAGS, 192, 8, 96, NID_aes_192_ccm);
/* qat_aes_256_ccm_functions */
QAT_aes_cipher(qat_aes, ccm, CCM, AEAD_FLAGS, 256, 8, 96, NID_aes_256_ccm);
#endif /* ENABLE_QAT_HW_CCM */
