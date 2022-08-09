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
 * @file qat_prov_dsa.c
 *
 * This file contains the Qat Provider implementation for DSA operations
 *
 *****************************************************************************/

#include "e_qat.h"
#include "qat_evp.h"
#include "qat_utils.h"
#include "qat_hw_dsa.h"
#include "qat_provider.h"
#include "qat_prov_dsa.h"

#ifdef ENABLE_QAT_HW_DSA
static OSSL_FUNC_signature_newctx_fn qat_dsa_newctx;
static OSSL_FUNC_signature_sign_init_fn qat_dsa_sign_init;
static OSSL_FUNC_signature_verify_init_fn qat_dsa_verify_init;
static OSSL_FUNC_signature_sign_fn qat_dsa_sign;
static OSSL_FUNC_signature_verify_fn qat_dsa_verify;
static OSSL_FUNC_signature_freectx_fn qat_dsa_freectx;
static OSSL_FUNC_signature_set_ctx_params_fn qat_dsa_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn qat_dsa_settable_ctx_params;

typedef int CRYPTO_REF_COUNT;

struct evp_signature_st {
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;

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
} /* EVP_SIGNATURE */;

static EVP_SIGNATURE get_default_dsa_signature()
{
    static EVP_SIGNATURE s_signature;
    static int initialized = 0;
    if (!initialized) {
        EVP_SIGNATURE *signature = (EVP_SIGNATURE *)EVP_SIGNATURE_fetch(NULL, "DSA", "provider=default");
        if (signature) {
            s_signature = *signature;
            EVP_SIGNATURE_free((EVP_SIGNATURE *)signature);
            initialized = 1;
        } else {
            WARN("EVP_SIGNATURE_fetch from default provider failed");
        }
    }
    return s_signature;
}

static void qat_ffc_params_init(FFC_PARAMS *params)
{
    memset(params, 0, sizeof(*params));
    params->pcounter = -1;
    params->gindex = FFC_UNVERIFIABLE_GINDEX;
    params->flags = FFC_PARAM_FLAG_VALIDATE_PQG;
}

static void qat_ffc_params_cleanup(FFC_PARAMS *params)
{
    BN_free(params->p);
    BN_free(params->q);
    BN_free(params->g);
    BN_free(params->j);
    OPENSSL_free(params->seed);
    qat_ffc_params_init(params);
}

static int qat_DSA_up_ref(DSA *r)
{
    int i;

    if (CRYPTO_UP_REF(&r->references, &i, r->lock) <= 0)
        return 0;

    if (i < 2)
    {
        WARN("refcount error.\n");
        return 0;
    }
    return ((i > 1) ? 1 : 0);
}

static void qat_DSA_free(DSA *r)
{
    int i;

    if (r == NULL)
        return;

    CRYPTO_DOWN_REF(&r->references, &i, r->lock);
    if (i > 0)
        return;
    if (i < 0)
    {
        WARN("refcount error.\n");
    }

    if (r->meth != NULL && r->meth->finish != NULL)
        r->meth->finish(r);

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DSA, r, &r->ex_data);

    CRYPTO_THREAD_lock_free(r->lock);

    qat_ffc_params_cleanup(&r->params);
    BN_clear_free(r->pub_key);
    BN_clear_free(r->priv_key);
    OPENSSL_free(r);
}

static int qat_DSA_size(const DSA *dsa)
{
    int ret = -1;
    DSA_SIG sig;

    if (dsa->params.q != NULL)
    {
        sig.r = sig.s = dsa->params.q;
        ret = i2d_DSA_SIG(&sig, NULL);

        if (ret < 0)
            ret = 0;
    }
    return ret;
}

static int qat_dsa_check_key(OSSL_LIB_CTX *ctx, const DSA *dsa, int sign)
{
#if !defined(OPENSSL_NO_FIPS_SECURITYCHECKS)
    if (ossl_securitycheck_enabled(ctx))
    {
        size_t L, N;
        const BIGNUM *p, *q;

        if (dsa == NULL)
            return 0;

        p = DSA_get0_p(dsa);
        q = DSA_get0_q(dsa);
        if (p == NULL || q == NULL)
            return 0;

        L = BN_num_bits(p);
        N = BN_num_bits(q);

        /*
         * For Digital signature verification DSA keys with < 112 bits of
         * security strength (i.e L < 2048 bits), are still allowed for legacy
         * use. The bounds given in SP800 131Ar2 - Table 2 are
         * (512 <= L < 2048 and 160 <= N < 224)
         */
        if (!sign && L < 2048)
            return (L >= 512 && N >= 160 && N < 224);

        /* Valid sizes for both sign and verify */
        if (L == 2048 && (N == 224 || N == 256))
            return 1;
        return (L == 3072 && N == 256);
    }
#endif /* OPENSSL_NO_FIPS_SECURITYCHECKS */
    return 1;
}

static int qat_digest_md_to_nid(const EVP_MD *md, const OSSL_ITEM *it, size_t it_len)
{
    size_t i;

    if (md == NULL)
        return NID_undef;

    for (i = 0; i < it_len; i++)
        if (EVP_MD_is_a(md, it[i].ptr))
            return (int)it[i].id;
    return NID_undef;
}

/*
 * Retrieve one of the FIPS approved hash algorithms by nid.
 * See FIPS 180-4 "Secure Hash Standard" and FIPS 202 - SHA-3.
 */
static int qat_digest_get_approved_nid(const EVP_MD *md)
{
    static const OSSL_ITEM name_to_nid[] = {
        {NID_sha1, OSSL_DIGEST_NAME_SHA1},
        {NID_sha224, OSSL_DIGEST_NAME_SHA2_224},
        {NID_sha256, OSSL_DIGEST_NAME_SHA2_256},
        {NID_sha384, OSSL_DIGEST_NAME_SHA2_384},
        {NID_sha512, OSSL_DIGEST_NAME_SHA2_512},
        {NID_sha512_224, OSSL_DIGEST_NAME_SHA2_512_224},
        {NID_sha512_256, OSSL_DIGEST_NAME_SHA2_512_256},
        {NID_sha3_224, OSSL_DIGEST_NAME_SHA3_224},
        {NID_sha3_256, OSSL_DIGEST_NAME_SHA3_256},
        {NID_sha3_384, OSSL_DIGEST_NAME_SHA3_384},
        {NID_sha3_512, OSSL_DIGEST_NAME_SHA3_512},
    };

    return qat_digest_md_to_nid(md, name_to_nid, OSSL_NELEM(name_to_nid));
}

static int qat_digest_get_approved_nid_with_sha1(OSSL_LIB_CTX *ctx, const EVP_MD *md,
                                                 int sha1_allowed)
{
    int mdnid = qat_digest_get_approved_nid(md);

    return mdnid;
}

static size_t dsa_get_md_size(const QAT_PROV_DSA_CTX *pdsactx)
{
    if (pdsactx->md != NULL)
        return EVP_MD_get_size(pdsactx->md);
    return 0;
}

static void *qat_dsa_newctx(void *provctx, const char *propq)
{
    QAT_PROV_DSA_CTX *pdsactx;
    DEBUG("qat_dsa_newctx\n");
    if (!qat_prov_is_running())
        return NULL;

    pdsactx = OPENSSL_zalloc(sizeof(QAT_PROV_DSA_CTX));
    if (pdsactx == NULL)
        return NULL;

    pdsactx->libctx = prov_libctx_of(provctx);
    pdsactx->flag_allow_md = 1;
    if (propq != NULL && (pdsactx->propq = OPENSSL_strdup(propq)) == NULL)
    {
        OPENSSL_free(pdsactx);
        pdsactx = NULL;
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    }
    return pdsactx;
}

static int dsa_setup_md(QAT_PROV_DSA_CTX *ctx,
                        const char *mdname, const char *mdprops)
{
    if (mdprops == NULL)
        mdprops = ctx->propq;

    if (mdname != NULL)
    {
        int sha1_allowed = (ctx->operation != EVP_PKEY_OP_SIGN);
        EVP_MD *md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
        int md_nid = qat_digest_get_approved_nid_with_sha1(ctx->libctx, md,
                                                           sha1_allowed);
        size_t mdname_len = strlen(mdname);

        if (md == NULL || md_nid < 0)
        {
            if (md == NULL)
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                               "%s could not be fetched", mdname);
            if (md_nid < 0)
                ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                               "digest=%s", mdname);
            if (mdname_len >= sizeof(ctx->mdname))
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                               "%s exceeds name buffer length", mdname);
            EVP_MD_free(md);
            return 0;
        }

        if (!ctx->flag_allow_md)
        {
            if (ctx->mdname[0] != '\0' && !EVP_MD_is_a(md, ctx->mdname))
            {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                               "digest %s != %s", mdname, ctx->mdname);
                EVP_MD_free(md);
                return 0;
            }
            EVP_MD_free(md);
            return 1;
        }

        EVP_MD_CTX_free(ctx->mdctx);
        EVP_MD_free(ctx->md);

        /*
         * We do not care about DER writing errors.
         * All it really means is that for some reason, there's no
         * AlgorithmIdentifier to be had, but the operation itself is
         * still valid, just as long as it's not used to construct
         * anything that needs an AlgorithmIdentifier.
         */
        ctx->aid_len = 0;
        ctx->mdctx = NULL;
        ctx->md = md;
        OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
    }
    return 1;
}

static int dsa_signverify_init(void *vpdsactx, void *vdsa,
                               const OSSL_PARAM params[], int operation)
{
    QAT_PROV_DSA_CTX *pdsactx = (QAT_PROV_DSA_CTX *)vpdsactx;

    if (!qat_prov_is_running() || pdsactx == NULL)
        return 0;

    if (vdsa == NULL && pdsactx->dsa == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (vdsa != NULL)
    {
        if (!qat_dsa_check_key(pdsactx->libctx, vdsa,
                               operation == EVP_PKEY_OP_SIGN))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        if (!qat_DSA_up_ref(vdsa))
            return 0;
        qat_DSA_free(pdsactx->dsa);
        pdsactx->dsa = vdsa;
    }

    pdsactx->operation = operation;

    if (!qat_dsa_set_ctx_params(pdsactx, params))
        return 0;

    return 1;
}
static int qat_dsa_sign_int(int type, const unsigned char *dgst, int dlen,
                            unsigned char *sig, unsigned int *siglen, DSA *dsa)
{
    DSA_SIG *s;
    /* We use the dsa methods provided by qat */
    dsa->meth = qat_get_DSA_methods();
    if (dsa->libctx == NULL)
        s = qat_dsa_do_sign(dgst, dlen, dsa);
    else
    {
        WARN("qat_dsa_sign_int failed, dsa->libctx is not NULL\n");
        s = NULL;
    }
    if (s == NULL)
    {
        *siglen = 0;
        return 0;
    }
    *siglen = i2d_DSA_SIG(s, &sig);
    DSA_SIG_free(s);
    return 1;
}
static int qat_dsa_sign_init(void *vpdsactx, void *vdsa, const OSSL_PARAM params[])
{
    return dsa_signverify_init(vpdsactx, vdsa, params, EVP_PKEY_OP_SIGN);
}

static int qat_dsa_verify_init(void *vpdsactx, void *vdsa,
                               const OSSL_PARAM params[])
{
    return dsa_signverify_init(vpdsactx, vdsa, params, EVP_PKEY_OP_VERIFY);
}

static int qat_dsa_sign(void *vpdsactx, unsigned char *sig, size_t *siglen,
                        size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    QAT_PROV_DSA_CTX *pdsactx = (QAT_PROV_DSA_CTX *)vpdsactx;
    int ret;
    unsigned int sltmp;
    size_t dsasize = qat_DSA_size(pdsactx->dsa);
    size_t mdsize = dsa_get_md_size(pdsactx);

    if (!qat_prov_is_running())
        return 0;

    if (sig == NULL)
    {
        *siglen = dsasize;
        return 1;
    }

    if (sigsize < (size_t)dsasize)
        return 0;

    if (mdsize != 0 && tbslen != mdsize)
        return 0;

    ret = qat_dsa_sign_int(0, tbs, tbslen, sig, &sltmp, pdsactx->dsa);
    if (ret <= 0)
        return 0;

    *siglen = sltmp;
    return 1;
}

static int qat_DSA_verify(int type, const unsigned char *dgst, int dgst_len,
                          const unsigned char *sigbuf, int siglen, DSA *dsa)
{
    DSA_SIG *s;
    const unsigned char *p = sigbuf;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = DSA_SIG_new();
    if (s == NULL)
        return ret;
    if (d2i_DSA_SIG(&s, &p, siglen) == NULL)
        goto err;
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_DSA_SIG(s, &der);
    if (derlen != siglen || memcmp(sigbuf, der, derlen))
        goto err;
    ret = qat_dsa_do_verify(dgst, dgst_len, s, dsa);
err:
    OPENSSL_clear_free(der, derlen);
    DSA_SIG_free(s);
    return ret;
}

static int qat_dsa_verify(void *vpdsactx, const unsigned char *sig, size_t siglen,
                          const unsigned char *tbs, size_t tbslen)
{
    QAT_PROV_DSA_CTX *pdsactx = (QAT_PROV_DSA_CTX *)vpdsactx;
    size_t mdsize = dsa_get_md_size(pdsactx);

    if (!qat_prov_is_running() || (mdsize != 0 && tbslen != mdsize))
        return 0;

    return qat_DSA_verify(0, tbs, tbslen, sig, siglen, pdsactx->dsa);
}

static void qat_dsa_freectx(void *vpdsactx)
{
    QAT_PROV_DSA_CTX *ctx = (QAT_PROV_DSA_CTX *)vpdsactx;

    OPENSSL_free(ctx->propq);
    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    ctx->propq = NULL;
    ctx->mdctx = NULL;
    ctx->md = NULL;
    qat_DSA_free(ctx->dsa);
    OPENSSL_free(ctx);
}

static int qat_dsa_set_ctx_params(void *vpdsactx, const OSSL_PARAM params[])
{
    QAT_PROV_DSA_CTX *pdsactx = (QAT_PROV_DSA_CTX *)vpdsactx;
    const OSSL_PARAM *p;

    if (pdsactx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL)
    {
        char mdname[OSSL_MAX_NAME_SIZE] = "", *pmdname = mdname;
        char mdprops[OSSL_MAX_PROPQUERY_SIZE] = "", *pmdprops = mdprops;
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_PROPERTIES);

        if (!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))
            return 0;
        if (propsp != NULL && !OSSL_PARAM_get_utf8_string(propsp, &pmdprops, sizeof(mdprops)))
            return 0;
        if (!dsa_setup_md(pdsactx, mdname, mdprops))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM settable_ctx_params_no_digest[] = {
    OSSL_PARAM_END};

static const OSSL_PARAM *qat_dsa_settable_ctx_params(void *vpdsactx,
                                                     ossl_unused void *provctx)
{
    QAT_PROV_DSA_CTX *pdsactx = (QAT_PROV_DSA_CTX *)vpdsactx;

    if (pdsactx != NULL && !pdsactx->flag_allow_md)
        return settable_ctx_params_no_digest;
    return settable_ctx_params;
}

static int qat_dsa_digest_sign_init(void *vpdsactx, const char *mdname,
                                    void *vdsa, const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *vpdsactx, const char *mdname,
                                          void *vdsa, const OSSL_PARAM params[]);
    fun_ptr fun = get_default_dsa_signature().digest_sign_init;
    if (!fun)
        return 0;
    return fun(vpdsactx, mdname, vdsa, params);
}

int qat_dsa_digest_signverify_update(void *vpdsactx, const unsigned char *data,
                                 size_t datalen)
{
    QAT_PROV_DSA_CTX *pdsactx = (QAT_PROV_DSA_CTX *)vpdsactx;

    if (pdsactx == NULL || pdsactx->mdctx == NULL)
        return 0;

    return EVP_DigestUpdate(pdsactx->mdctx, data, datalen);
}


int qat_dsa_digest_sign_final(void *vpdsactx, unsigned char *sig, size_t *siglen,
                              size_t sigsize)
{
    QAT_PROV_DSA_CTX *pdsactx = (QAT_PROV_DSA_CTX *)vpdsactx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!qat_prov_is_running() || pdsactx == NULL || pdsactx->mdctx == NULL)
        return 0;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to dsa_sign.
     */
    if (sig != NULL) {
        /*
         * There is the possibility that some externally provided
         * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
         * but that problem is much larger than just in DSA.
         */
        if (!EVP_DigestFinal_ex(pdsactx->mdctx, digest, &dlen))
            return 0;
    }

    pdsactx->flag_allow_md = 1;

    return qat_dsa_sign(vpdsactx, sig, siglen, sigsize, digest, (size_t)dlen);
}


static int qat_dsa_digest_verify_init(void *vpdsactx, const char *mdname,
                                      void *vdsa, const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *vpdsactx, const char *mdname,
                           void *vdsa, const OSSL_PARAM params[]);
    fun_ptr fun = get_default_dsa_signature().digest_verify_init;
    if (!fun)
        return 0;
    return fun(vpdsactx, mdname, vdsa, params);
}


int qat_dsa_digest_verify_final(void *vpdsactx, const unsigned char *sig,
                                size_t siglen)
{
    QAT_PROV_DSA_CTX *pdsactx = (QAT_PROV_DSA_CTX *)vpdsactx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!qat_prov_is_running() || pdsactx == NULL || pdsactx->mdctx == NULL)
        return 0;

    /*
     * There is the possibility that some externally provided
     * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
     * but that problem is much larger than just in DSA.
     */
    if (!EVP_DigestFinal_ex(pdsactx->mdctx, digest, &dlen))
        return 0;

    pdsactx->flag_allow_md = 1;

    return qat_dsa_verify(vpdsactx, sig, siglen, digest, (size_t)dlen);
}


static void *qat_dsa_dupctx(void *vpdsactx)
{
    typedef void * (*fun_ptr)(void *vpdsactx);
    fun_ptr fun = get_default_dsa_signature().dupctx;
    if (!fun)
        return NULL;
    return fun(vpdsactx);
}


static int qat_dsa_get_ctx_params(void *vpdsactx, OSSL_PARAM *params)
{
    typedef int (*fun_ptr)(void *vpdsactx, OSSL_PARAM *params);
    fun_ptr fun = get_default_dsa_signature().get_ctx_params;
    if (!fun)
        return 0;
    return fun(vpdsactx, params);
}


static const OSSL_PARAM *qat_dsa_gettable_ctx_params(ossl_unused void *ctx,
                                                     ossl_unused void *provctx)
{
    typedef const OSSL_PARAM * (*fun_ptr)(ossl_unused void *ctx,
                                          ossl_unused void *provctx);
    fun_ptr fun = get_default_dsa_signature().gettable_ctx_params;
    if (!fun)
        return NULL;
    return fun(ctx, provctx);
}


static int qat_dsa_get_ctx_md_params(void *vpdsactx, OSSL_PARAM *params)
{
    typedef int (*fun_ptr)(void *vpdsactx, OSSL_PARAM *params);
    fun_ptr fun = get_default_dsa_signature().get_ctx_md_params;
    if (!fun)
        return 0;
    return fun(vpdsactx, params);
}

static const OSSL_PARAM *qat_dsa_gettable_ctx_md_params(void *vpdsactx)
{
    typedef const OSSL_PARAM * (*fun_ptr)(void *vpdsactx);
    fun_ptr fun = get_default_dsa_signature().gettable_ctx_md_params;
    if (!fun)
        return NULL;
    return fun(vpdsactx);
}

static int qat_dsa_set_ctx_md_params(void *vpdsactx, const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *vpdsactx, const OSSL_PARAM params[]);
    fun_ptr fun = get_default_dsa_signature().set_ctx_md_params;
    if (!fun)
        return 0;
    return fun(vpdsactx, params);
}

static const OSSL_PARAM *qat_dsa_settable_ctx_md_params(void *vpdsactx)
{
    typedef const OSSL_PARAM * (*fun_ptr)(void *vpdsactx);
    fun_ptr fun = get_default_dsa_signature().settable_ctx_md_params;
    if (!fun)
        return NULL;
    return fun(vpdsactx);
}


const OSSL_DISPATCH qat_dsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))qat_dsa_newctx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))qat_dsa_sign_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))qat_dsa_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))qat_dsa_verify_init},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))qat_dsa_verify},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))qat_dsa_freectx},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))qat_dsa_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))qat_dsa_settable_ctx_params},
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))qat_dsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))qat_dsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))qat_dsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))qat_dsa_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))qat_dsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))qat_dsa_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))qat_dsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))qat_dsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))qat_dsa_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))qat_dsa_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))qat_dsa_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))qat_dsa_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))qat_dsa_settable_ctx_md_params },
    {0, NULL}};

#endif
