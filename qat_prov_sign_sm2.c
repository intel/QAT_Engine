/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2023 Intel Corporation.
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
 * @file qat_prov_sign_sm2.c
 *
 * This file provides an implementation to qatprovider SM2 operations
 *
 *****************************************************************************/
#include <string.h> /* memcpy */
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/dsa.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/proverr.h>

#include "qat_provider.h"
#include "qat_prov_hkdf_packet.h"
#include "e_qat.h"

#ifdef ENABLE_QAT_HW_SM2
# include "qat_hw_sm2.h"
#endif

#ifdef ENABLE_QAT_SW_SM2
#include "qat_prov_ec.h"
# include "qat_sw_sm2.h"
#endif

#if defined(ENABLE_QAT_HW_SM2) || defined(ENABLE_QAT_SW_SM2)

static OSSL_FUNC_signature_newctx_fn qat_sm2sig_newctx;
static OSSL_FUNC_signature_sign_init_fn qat_sm2sig_signature_init;
static OSSL_FUNC_signature_verify_init_fn qat_sm2sig_signature_init;
static OSSL_FUNC_signature_sign_fn qat_sm2sig_sign;
static OSSL_FUNC_signature_verify_fn qat_sm2sig_verify;
static OSSL_FUNC_signature_digest_sign_init_fn qat_sm2sig_digest_signverify_init;
# ifdef ENABLE_QAT_SW_SM2
static OSSL_FUNC_signature_digest_sign_fn qat_sm2sig_digest_sign;
static OSSL_FUNC_signature_digest_verify_fn qat_sm2sig_digest_verify;
# endif
# ifdef ENABLE_QAT_HW_SM2
static OSSL_FUNC_signature_digest_sign_update_fn qat_sm2sig_digest_signverify_update;
static OSSL_FUNC_signature_digest_sign_final_fn qat_sm2sig_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_update_fn qat_sm2sig_digest_signverify_update;
static OSSL_FUNC_signature_digest_verify_final_fn qat_sm2sig_digest_verify_final;
# endif
static OSSL_FUNC_signature_digest_verify_init_fn qat_sm2sig_digest_signverify_init;
static OSSL_FUNC_signature_freectx_fn qat_sm2sig_freectx;
static OSSL_FUNC_signature_dupctx_fn qat_sm2sig_dupctx;
static OSSL_FUNC_signature_get_ctx_params_fn qat_sm2sig_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn qat_sm2sig_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn qat_sm2sig_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn qat_sm2sig_settable_ctx_params;
static OSSL_FUNC_signature_get_ctx_md_params_fn qat_sm2sig_get_ctx_md_params;
static OSSL_FUNC_signature_gettable_ctx_md_params_fn qat_sm2sig_gettable_ctx_md_params;
static OSSL_FUNC_signature_set_ctx_md_params_fn qat_sm2sig_set_ctx_md_params;
static OSSL_FUNC_signature_settable_ctx_md_params_fn qat_sm2sig_settable_ctx_md_params;

typedef struct evp_signature_st {
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;
    int refcnt;
    void *lock;

    OSSL_FUNC_signature_newctx_fn *newctx;
    OSSL_FUNC_signature_sign_init_fn *sign_init;
    OSSL_FUNC_signature_sign_fn *sign;
    OSSL_FUNC_signature_verify_init_fn *verify_init;
    OSSL_FUNC_signature_verify_fn *verify;
    OSSL_FUNC_signature_verify_recover_init_fn *verify_recover_init;
    OSSL_FUNC_signature_verify_recover_fn *verify_recover;
    OSSL_FUNC_signature_digest_sign_init_fn *digest_sign_init;
    OSSL_FUNC_signature_digest_sign_update_fn *digest_sign_update;
    OSSL_FUNC_signature_digest_sign_final_fn *digest_sign_final;
    OSSL_FUNC_signature_digest_sign_fn *digest_sign;
    OSSL_FUNC_signature_digest_verify_init_fn *digest_verify_init;
    OSSL_FUNC_signature_digest_verify_update_fn *digest_verify_update;
    OSSL_FUNC_signature_digest_verify_final_fn *digest_verify_final;
    OSSL_FUNC_signature_digest_verify_fn *digest_verify;
    OSSL_FUNC_signature_freectx_fn *freectx;
    OSSL_FUNC_signature_dupctx_fn *dupctx;
    OSSL_FUNC_signature_get_ctx_params_fn *get_ctx_params;
    OSSL_FUNC_signature_gettable_ctx_params_fn *gettable_ctx_params;
    OSSL_FUNC_signature_set_ctx_params_fn *set_ctx_params;
    OSSL_FUNC_signature_settable_ctx_params_fn *settable_ctx_params;
    OSSL_FUNC_signature_get_ctx_md_params_fn *get_ctx_md_params;
    OSSL_FUNC_signature_gettable_ctx_md_params_fn *gettable_ctx_md_params;
    OSSL_FUNC_signature_set_ctx_md_params_fn *set_ctx_md_params;
    OSSL_FUNC_signature_settable_ctx_md_params_fn *settable_ctx_md_params;
} QAT_EVP_SIGNATURE /* EVP_SIGNATURE for QAT Provider sm2 */;

# ifdef ENABLE_QAT_HW_SM2
static QAT_EVP_SIGNATURE get_default_signature_sm2()
{
    static QAT_EVP_SIGNATURE s_signature;
    static int initilazed = 0;
    if (!initilazed)
    {
        QAT_EVP_SIGNATURE *signature = (QAT_EVP_SIGNATURE *)EVP_SIGNATURE_fetch(NULL, "SM2", "provider=default");
        if (signature)
        {
            s_signature = *signature;
            EVP_SIGNATURE_free((QAT_EVP_SIGNATURE *)signature);
            initilazed = 1;
        }
        else
        {
            WARN("EVP_SIGNATURE_fetch from default provider failed");
        }
    }
    return s_signature;
}
# endif

static int qat_sm2sig_set_mdname(QAT_PROV_SM2_CTX *psm2ctx, const char *mdname)
{
    if (psm2ctx->md == NULL) /* We need an SM3 md to compare with */
        psm2ctx->md = EVP_MD_fetch(psm2ctx->libctx, psm2ctx->mdname,
                                   psm2ctx->propq);
    if (psm2ctx->md == NULL)
        return 0;

    if (mdname == NULL)
        return 1;

    if (strlen(mdname) >= sizeof(psm2ctx->mdname)
        || !EVP_MD_is_a(psm2ctx->md, mdname)) {
        QATerr(ERR_LIB_PROV, QAT_R_INVALID_DIGEST);
        return 0;
    }

    OPENSSL_strlcpy(psm2ctx->mdname, mdname, sizeof(psm2ctx->mdname));
    return 1;
}

static void *qat_sm2sig_newctx(void *provctx, const char *propq)
{
    QAT_PROV_SM2_CTX *ctx = OPENSSL_zalloc(sizeof(QAT_PROV_SM2_CTX));

    if (ctx == NULL)
        return NULL;

    ctx->libctx = prov_libctx_of(provctx);
    if (propq != NULL && (ctx->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(ctx);
        QATerr(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ctx->mdsize = SM3_DIGEST_LENGTH;
    strcpy(ctx->mdname, OSSL_DIGEST_NAME_SM3);
    return ctx;
}

static int qat_sm2sig_signature_init(void *vpsm2ctx, void *ec,
                                 const OSSL_PARAM params[])
{
    QAT_PROV_SM2_CTX *psm2ctx = (QAT_PROV_SM2_CTX *)vpsm2ctx;

    if (!qat_prov_is_running()
            || psm2ctx == NULL)
        return 0;

    if (ec == NULL && psm2ctx->ec == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (ec != NULL) {
        if (!EC_KEY_up_ref(ec))
            return 0;
        EC_KEY_free(psm2ctx->ec);
        psm2ctx->ec = ec;
    }

    return qat_sm2sig_set_ctx_params(psm2ctx, params);
}

static int qat_sm2sig_sign(void *vpsm2ctx, unsigned char *sig, size_t *siglen,
                           size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    QAT_PROV_SM2_CTX *ctx = (QAT_PROV_SM2_CTX *)vpsm2ctx;
    int ret;
    /* SM2 uses ECDSA_size as well */
    size_t ecsize = ECDSA_size(ctx->ec);

    if (sig == NULL) {
        *siglen = ecsize;
        return 1;
    }

    if (sigsize < (size_t)ecsize)
        return 0;

    if (ctx->mdsize != 0 && tbslen != ctx->mdsize)
        return 0;
# ifdef ENABLE_QAT_SW_SM2
    ret = mb_ecdsa_sm2_sign(ctx, sig, siglen, sigsize, tbs, tbslen);
# endif

# ifdef ENABLE_QAT_HW_SM2
    ret = qat_sm2_sign(ctx, sig, siglen, sigsize, tbs, tbslen);
# endif
    if (ret <= 0)
        return 0;

    *siglen = tbslen;
    return 1;
}

static int qat_sm2sig_verify(void *vpsm2ctx, const unsigned char *sig, size_t siglen,
                             const unsigned char *tbs, size_t tbslen)
{
    QAT_PROV_SM2_CTX *ctx = (QAT_PROV_SM2_CTX *)vpsm2ctx;

    if (ctx->mdsize != 0 && tbslen != ctx->mdsize)
        return 0;

# ifdef ENABLE_QAT_SW_SM2
    return mb_ecdsa_sm2_verify(ctx, sig, siglen, tbs, tbslen);
# endif

# ifdef ENABLE_QAT_HW_SM2
    return qat_sm2_verify(ctx, sig, siglen, tbs, tbslen);
# endif
}

static void free_md(QAT_PROV_SM2_CTX *ctx)
{
    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    ctx->mdctx = NULL;
    ctx->md = NULL;
}

int qat_sm2sig_compute_z_digest(QAT_PROV_SM2_CTX *ctx)
{
    uint8_t *z = NULL;
    int ret = 1;

    if (ctx->flag_compute_z_digest) {
        /* Only do this once */
        ctx->flag_compute_z_digest = 0;
        if ((z = OPENSSL_zalloc(ctx->mdsize)) == NULL
# ifdef ENABLE_QAT_HW_SM2
            /* get hashed prefix 'z' of tbs message */
            || !qat_sm2_compute_z_digest(z, ctx->md, ctx->id, ctx->id_len,
                                          ctx->ec)
# endif

# ifdef ENABLE_QAT_SW_SM2
	    || !qat_sm2_compute_z_digest(z, ctx->md, ctx->id, ctx->id_len,
                                          ctx->ec)
# endif
            || !EVP_DigestUpdate(ctx->mdctx, z, ctx->mdsize))
            ret = 0;
        OPENSSL_free(z);
    }
    return ret;
}

int qat_sm2sig_digest_signverify_update(void *vpsm2ctx, const unsigned char *data,
                                    size_t datalen)
{
    QAT_PROV_SM2_CTX *psm2ctx = (QAT_PROV_SM2_CTX *)vpsm2ctx;

    if (psm2ctx == NULL || psm2ctx->mdctx == NULL)
        return 0;

    return qat_sm2sig_compute_z_digest(psm2ctx)
        && EVP_DigestUpdate(psm2ctx->mdctx, data, datalen);
}

# ifdef ENABLE_QAT_HW_SM2
int qat_sm2sig_digest_sign_final(void *vpsm2ctx, unsigned char *sig, size_t *siglen,
                             size_t sigsize)
{
    typedef int (*fun_ptr)(void *, unsigned char *, size_t *, size_t);
    fun_ptr fun = get_default_signature_sm2().digest_sign_final;
    if (!fun)
        return 0;
    return fun(vpsm2ctx, sig, siglen, sigsize);
}
# endif

static int qat_sm2sig_digest_signverify_init(void *vpsm2ctx, const char *mdname,
                                         void *ec, const OSSL_PARAM params[])
{
    QAT_PROV_SM2_CTX *ctx = (QAT_PROV_SM2_CTX *)vpsm2ctx;
    int md_nid;
    qat_WPACKET pkt;
    int ret = 0;

    /* This default value must be assigned before it may be overridden */
    ctx->flag_compute_z_digest = 1;

    if (!qat_sm2sig_signature_init(vpsm2ctx, ec, params)
        || !qat_sm2sig_set_mdname(ctx, mdname))
        return ret;

    if (ctx->mdctx == NULL) {
        ctx->mdctx = EVP_MD_CTX_new();
        if (ctx->mdctx == NULL)
            goto error;
    }

    md_nid = EVP_MD_get_type(ctx->md);

    /*
     * We do not care about DER writing errors.
     * All it really means is that for some reason, there's no
     * AlgorithmIdentifier to be had, but the operation itself is
     * still valid, just as long as it's not used to construct
     * anything that needs an AlgorithmIdentifier.
     */
    ctx->aid_len = 0;
    /*WPACKET code implementation kept in qat_prov_hkdf_packet.c*/
    if (QAT_WPACKET_init_der(&pkt, ctx->aid_buf, sizeof(ctx->aid_buf))
        && qat_DER_w_algorithmIdentifier_SM2_with_MD(&pkt, -1, ctx->ec, md_nid)
        && QAT_WPACKET_finish(&pkt)) {
        QAT_WPACKET_get_total_written(&pkt, &ctx->aid_len);
        ctx->aid = QAT_WPACKET_get_curr(&pkt);
    }
    QAT_WPACKET_cleanup(&pkt);

    if (!EVP_DigestInit_ex2(ctx->mdctx, ctx->md, params))
        goto error;

    ret = 1;

 error:
    return ret;

}
# ifdef ENABLE_QAT_SW_SM2
static int qat_sm2sig_digest_sign(void *vpsm2ctx, unsigned char *sig, size_t *siglen,
                           size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    QAT_PROV_SM2_CTX *ctx = (QAT_PROV_SM2_CTX *)vpsm2ctx;
    int ret;
    size_t ecsize;

    if (ctx == NULL) {
        return 0;
    }
     /* SM2 uses ECDSA_size as well */
    ecsize = ECDSA_size(ctx->ec);
    if (sig == NULL) {
        *siglen = ecsize;
        return 1;
    }

    if (sigsize < (size_t)ecsize)
        return 0;
    ret = mb_ecdsa_sm2_sign(ctx, sig, siglen, sigsize, tbs, tbslen);
    if (ret <= 0)
        return 0;

    return 1;
}

static int qat_sm2sig_digest_verify(void *vpsm2ctx, const unsigned char *sig, size_t siglen,
                             const unsigned char *tbs, size_t tbslen)
{
    int ret = 0;
    QAT_PROV_SM2_CTX *ctx = (QAT_PROV_SM2_CTX *)vpsm2ctx;

    if (vpsm2ctx == NULL) {
        return 0;
    }
    ret = mb_ecdsa_sm2_verify(ctx, sig, siglen, tbs, tbslen);
    if (ret <= 0)
        return 0;

    return ret;

}
# endif

# ifdef ENABLE_QAT_HW_SM2
int qat_sm2sig_digest_verify_final(void *vpsm2ctx, const unsigned char *sig,
                               size_t siglen)
{
    QAT_PROV_SM2_CTX *psm2ctx = (QAT_PROV_SM2_CTX *)vpsm2ctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (psm2ctx == NULL
        || psm2ctx->mdctx == NULL
        || EVP_MD_get_size(psm2ctx->md) > (int)sizeof(digest))
        return 0;

    if (!(qat_sm2sig_compute_z_digest(psm2ctx)
          && EVP_DigestFinal_ex(psm2ctx->mdctx, digest, &dlen)))
        return 0;

    return qat_sm2sig_verify(vpsm2ctx, sig, siglen, digest, (size_t)dlen);

}
# endif

static void qat_sm2sig_freectx(void *vpsm2ctx)
{
    QAT_PROV_SM2_CTX *ctx = (QAT_PROV_SM2_CTX *)vpsm2ctx;

    free_md(ctx);
    EC_KEY_free(ctx->ec);
    OPENSSL_free(ctx->id);
    OPENSSL_free(ctx);
}

static void *qat_sm2sig_dupctx(void *vpsm2ctx)
{
    QAT_PROV_SM2_CTX *srcctx = (QAT_PROV_SM2_CTX *)vpsm2ctx;
    QAT_PROV_SM2_CTX *dstctx;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    dstctx->ec = NULL;
    dstctx->md = NULL;
    dstctx->mdctx = NULL;

    if (srcctx->ec != NULL && !EC_KEY_up_ref(srcctx->ec))
        goto err;
    dstctx->ec = srcctx->ec;

    if (srcctx->md != NULL && !EVP_MD_up_ref(srcctx->md))
        goto err;
    dstctx->md = srcctx->md;

    if (srcctx->mdctx != NULL) {
        dstctx->mdctx = EVP_MD_CTX_new();
        if (dstctx->mdctx == NULL
                || !EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx))
            goto err;
    }

    if (srcctx->id != NULL) {
        dstctx->id = OPENSSL_malloc(srcctx->id_len);
        if (dstctx->id == NULL)
            goto err;
        dstctx->id_len = srcctx->id_len;
        memcpy(dstctx->id, srcctx->id, srcctx->id_len);
    }

    return dstctx;
 err:
    qat_sm2sig_freectx(dstctx);
    return NULL;
}

static int qat_sm2sig_get_ctx_params(void *vpsm2ctx, OSSL_PARAM *params)
{
    QAT_PROV_SM2_CTX *psm2ctx = (QAT_PROV_SM2_CTX *)vpsm2ctx;
    OSSL_PARAM *p;

    if (psm2ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL
        && !OSSL_PARAM_set_octet_string(p, psm2ctx->aid, psm2ctx->aid_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, psm2ctx->mdsize))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, psm2ctx->md == NULL
                                                    ? psm2ctx->mdname
                                                    : EVP_MD_get0_name(psm2ctx->md)))
        return 0;

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *qat_sm2sig_gettable_ctx_params(ossl_unused void *vpsm2ctx,
                                                    ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

static int qat_sm2sig_set_ctx_params(void *vpsm2ctx, const OSSL_PARAM params[])
{
    QAT_PROV_SM2_CTX *psm2ctx = (QAT_PROV_SM2_CTX *)vpsm2ctx;
    const OSSL_PARAM *p;
    size_t mdsize;

    if (psm2ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DIST_ID);
    if (p != NULL) {
        void *tmp_id = NULL;
        size_t tmp_idlen = 0;

        /*
         * If the 'z' digest has already been computed, the ID is set too late
         */
        if (!psm2ctx->flag_compute_z_digest)
            return 0;

        if (p->data_size != 0
            && !OSSL_PARAM_get_octet_string(p, &tmp_id, 0, &tmp_idlen))
            return 0;
	if (psm2ctx->id != NULL)
            OPENSSL_free(psm2ctx->id);
        psm2ctx->id = tmp_id;
        psm2ctx->id_len = tmp_idlen;
    }

    /*
     * The following code checks that the size is the same as the SM3 digest
     * size returning an error otherwise.
     * If there is ever any different digest algorithm allowed with SM2
     * this needs to be adjusted accordingly.
     */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && (!OSSL_PARAM_get_size_t(p, &mdsize)
                      || mdsize != psm2ctx->mdsize))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        char *mdname = NULL;

        if (!OSSL_PARAM_get_utf8_string(p, &mdname, 0))
            return 0;
        if (!qat_sm2sig_set_mdname(psm2ctx, mdname)) {
            OPENSSL_free(mdname);
            return 0;
        }
	if (mdname != NULL)
            OPENSSL_free(mdname);
    }

    return 1;

}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_DIST_ID, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *qat_sm2sig_settable_ctx_params(ossl_unused void *vpsm2ctx,
                                                    ossl_unused void *provctx)
{
    return known_settable_ctx_params;
}

static int qat_sm2sig_get_ctx_md_params(void *vpsm2ctx, OSSL_PARAM *params)
{
    QAT_PROV_SM2_CTX *psm2ctx = (QAT_PROV_SM2_CTX *)vpsm2ctx;

    if (psm2ctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_get_params(psm2ctx->mdctx, params);
}

static const OSSL_PARAM *qat_sm2sig_gettable_ctx_md_params(void *vpsm2ctx)
{
    QAT_PROV_SM2_CTX *psm2ctx = (QAT_PROV_SM2_CTX *)vpsm2ctx;

    if (psm2ctx->md == NULL)
        return 0;

    return EVP_MD_gettable_ctx_params(psm2ctx->md);
}

static int qat_sm2sig_set_ctx_md_params(void *vpsm2ctx, const OSSL_PARAM params[])
{
    QAT_PROV_SM2_CTX *psm2ctx = (QAT_PROV_SM2_CTX *)vpsm2ctx;

    if (psm2ctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_set_params(psm2ctx->mdctx, params);
}

static const OSSL_PARAM *qat_sm2sig_settable_ctx_md_params(void *vpsm2ctx)
{
    QAT_PROV_SM2_CTX *psm2ctx = (QAT_PROV_SM2_CTX *)vpsm2ctx;

    if (psm2ctx->md == NULL)
        return 0;

    return EVP_MD_settable_ctx_params(psm2ctx->md);
}

const OSSL_DISPATCH qat_sm2_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))qat_sm2sig_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))qat_sm2sig_signature_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))qat_sm2sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))qat_sm2sig_signature_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))qat_sm2sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))qat_sm2sig_digest_signverify_init },
# ifdef ENABLE_QAT_SW_SM2
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
      (void (*)(void))qat_sm2sig_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))qat_sm2sig_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
      (void (*)(void))qat_sm2sig_digest_verify },
# endif
# ifdef ENABLE_QAT_HW_SM2
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))qat_sm2sig_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))qat_sm2sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))qat_sm2sig_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))qat_sm2sig_digest_verify_final },
# endif
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))qat_sm2sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))qat_sm2sig_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))qat_sm2sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))qat_sm2sig_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))qat_sm2sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))qat_sm2sig_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))qat_sm2sig_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))qat_sm2sig_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))qat_sm2sig_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))qat_sm2sig_settable_ctx_md_params },
    { 0, NULL }
};

#endif
