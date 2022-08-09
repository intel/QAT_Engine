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
 * @file qat_prov_dh.c
 *
 * This file contains the Qat Provider implementation for DH operations
 *
 *****************************************************************************/

#include "e_qat.h"
#include "qat_utils.h"
#include "qat_hw_dh.h"
#include "qat_provider.h"
#include "qat_prov_dh.h"

#ifdef ENABLE_QAT_HW_DH
static OSSL_FUNC_keyexch_newctx_fn qat_dh_newctx;
static OSSL_FUNC_keyexch_init_fn qat_dh_init;
static OSSL_FUNC_keyexch_set_peer_fn qat_dh_set_peer;
static OSSL_FUNC_keyexch_derive_fn qat_dh_derive;
static OSSL_FUNC_keyexch_freectx_fn qat_dh_freectx;
static OSSL_FUNC_keyexch_dupctx_fn qat_dh_dupctx;
static OSSL_FUNC_keyexch_set_ctx_params_fn qat_dh_set_ctx_params;
static OSSL_FUNC_keyexch_settable_ctx_params_fn qat_dh_settable_ctx_params;
static OSSL_FUNC_keyexch_get_ctx_params_fn qat_dh_get_ctx_params;
static OSSL_FUNC_keyexch_gettable_ctx_params_fn qat_dh_gettable_ctx_params;

static int qat_DH_up_ref(DH *r)
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

static void qat_DH_free(DH *r)
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

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DH, r, &r->ex_data);

    CRYPTO_THREAD_lock_free(r->lock);

    qat_ffc_params_cleanup(&r->params);
    BN_clear_free(r->pub_key);
    BN_clear_free(r->priv_key);
    OPENSSL_free(r);
}

static int qat_DH_size(const DH *dh)
{
    if (dh->params.p != NULL)
        return BN_num_bytes(dh->params.p);
    return -1;
}

static void qat_DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = dh->pub_key;
    if (priv_key != NULL)
        *priv_key = dh->priv_key;
}

FFC_PARAMS *qat_dh_get0_params(DH *dh)
{
    return &dh->params;
}

int qat_dh_get0_nid(const DH *dh)
{
    return dh->params.nid;
}

int qat_ffc_params_cmp(const FFC_PARAMS *a, const FFC_PARAMS *b, int ignore_q)
{
    return BN_cmp(a->p, b->p) == 0 && BN_cmp(a->g, b->g) == 0 && (ignore_q || BN_cmp(a->q, b->q) == 0); /* Note: q may be NULL */
}

int qat_dh_check_key(OSSL_LIB_CTX *ctx, const DH *dh)
{
#if !defined(OPENSSL_NO_FIPS_SECURITYCHECKS)
    if (ossl_securitycheck_enabled(ctx))
    {
        size_t L, N;
        const BIGNUM *p, *q;

        if (dh == NULL)
            return 0;

        p = DH_get0_p(dh);
        q = DH_get0_q(dh);
        if (p == NULL || q == NULL)
            return 0;

        L = BN_num_bits(p);
        if (L < 2048)
            return 0;

        /* If it is a safe prime group then it is ok */
        if (DH_get_nid(dh))
            return 1;

        /* If not then it must be FFC, which only allows certain sizes. */
        N = BN_num_bits(q);

        return (L == 2048 && (N == 224 || N == 256));
    }
#endif /* OPENSSL_NO_FIPS_SECURITYCHECKS */
    return 1;
}

static void *qat_dh_newctx(void *provctx)
{
    QAT_PROV_DH_CTX *pdhctx;

    if (!qat_prov_is_running())
        return NULL;

    pdhctx = OPENSSL_zalloc(sizeof(QAT_PROV_DH_CTX));
    if (pdhctx == NULL)
        return NULL;
    pdhctx->libctx = prov_libctx_of(provctx);
    pdhctx->kdf_type = PROV_DH_KDF_NONE;
    return pdhctx;
}

static int qat_dh_init(void *vpdhctx, void *vdh, const OSSL_PARAM params[])
{
    QAT_PROV_DH_CTX *pdhctx = (QAT_PROV_DH_CTX *)vpdhctx;

    if (!qat_prov_is_running() || pdhctx == NULL || vdh == NULL || !qat_DH_up_ref(vdh))
        return 0;
    qat_DH_free(pdhctx->dh);
    pdhctx->dh = vdh;
    pdhctx->kdf_type = PROV_DH_KDF_NONE;
    return qat_dh_set_ctx_params(pdhctx, params) && qat_dh_check_key(pdhctx->libctx, vdh);
}

/* The 2 parties must share the same domain parameters */
static int qat_dh_match_params(DH *priv, DH *peer)
{
    int ret;
    FFC_PARAMS *dhparams_priv = qat_dh_get0_params(priv);
    FFC_PARAMS *dhparams_peer = qat_dh_get0_params(peer);

    ret = dhparams_priv != NULL && dhparams_peer != NULL && qat_ffc_params_cmp(dhparams_priv, dhparams_peer, 1);
    if (!ret)
        ERR_raise(ERR_LIB_PROV, PROV_R_MISMATCHING_DOMAIN_PARAMETERS);
    return ret;
}

static int qat_dh_set_peer(void *vpdhctx, void *vdh)
{
    QAT_PROV_DH_CTX *pdhctx = (QAT_PROV_DH_CTX *)vpdhctx;

    if (!qat_prov_is_running() || pdhctx == NULL || vdh == NULL || !qat_dh_match_params(vdh, pdhctx->dh) || !qat_DH_up_ref(vdh))
        return 0;
    qat_DH_free(pdhctx->dhpeer);
    pdhctx->dhpeer = vdh;
    return 1;
}

static int qat_dh_plain_derive(void *vpdhctx,
                               unsigned char *secret, size_t *secretlen,
                               size_t outlen)
{
    QAT_PROV_DH_CTX *pdhctx = (QAT_PROV_DH_CTX *)vpdhctx;
    int ret;
    size_t dhsize;
    const BIGNUM *pub_key = NULL;

    if (pdhctx->dh == NULL || pdhctx->dhpeer == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    dhsize = (size_t)qat_DH_size(pdhctx->dh);
    if (secret == NULL)
    {
        *secretlen = dhsize;
        return 1;
    }
    if (outlen < dhsize)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    qat_DH_get0_key(pdhctx->dhpeer, &pub_key, NULL);

    ret = qat_dh_compute_key(secret, pub_key, pdhctx->dh);

    if (ret <= 0)
        return 0;

    *secretlen = ret;
    return 1;
}

int qat_dh_kdf_X9_42_asn1(unsigned char *out, size_t outlen,
                          const unsigned char *Z, size_t Zlen,
                          const char *cek_alg,
                          const unsigned char *ukm, size_t ukmlen,
                          const EVP_MD *md,
                          OSSL_LIB_CTX *libctx, const char *propq)
{
    int ret = 0;
    EVP_KDF_CTX *kctx = NULL;
    EVP_KDF *kdf = NULL;
    OSSL_PARAM params[5], *p = params;
    const char *mdname = EVP_MD_get0_name(md);

    kdf = EVP_KDF_fetch(libctx, OSSL_KDF_NAME_X942KDF_ASN1, propq);
    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL)
        goto err;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            (char *)mdname, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                             (unsigned char *)Z, Zlen);
    if (ukm != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_UKM,
                                                 (unsigned char *)ukm, ukmlen);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG,
                                            (char *)cek_alg, 0);
    *p = OSSL_PARAM_construct_end();
    ret = EVP_KDF_derive(kctx, out, outlen, params) > 0;
err:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

static int qat_dh_X9_42_kdf_derive(void *vpdhctx, unsigned char *secret,
                                   size_t *secretlen, size_t outlen)
{
    QAT_PROV_DH_CTX *pdhctx = (QAT_PROV_DH_CTX *)vpdhctx;
    unsigned char *stmp = NULL;
    size_t stmplen;
    int ret = 0;

    if (secret == NULL)
    {
        *secretlen = pdhctx->kdf_outlen;
        return 1;
    }

    if (pdhctx->kdf_outlen > outlen)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    if (!qat_dh_plain_derive(pdhctx, NULL, &stmplen, 0))
        return 0;
    if ((stmp = OPENSSL_secure_malloc(stmplen)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!qat_dh_plain_derive(pdhctx, stmp, &stmplen, stmplen))
        goto err;

    /* Do KDF stuff */
    if (pdhctx->kdf_type == PROV_DH_KDF_X9_42_ASN1)
    {
        if (!qat_dh_kdf_X9_42_asn1(secret, pdhctx->kdf_outlen,
                                   stmp, stmplen,
                                   pdhctx->kdf_cekalg,
                                   pdhctx->kdf_ukm,
                                   pdhctx->kdf_ukmlen,
                                   pdhctx->kdf_md,
                                   pdhctx->libctx, NULL))
            goto err;
    }
    *secretlen = pdhctx->kdf_outlen;
    ret = 1;
err:
    OPENSSL_secure_clear_free(stmp, stmplen);
    return ret;
}

static int qat_dh_derive(void *vpdhctx, unsigned char *secret,
                         size_t *psecretlen, size_t outlen)
{
    QAT_PROV_DH_CTX *pdhctx = (QAT_PROV_DH_CTX *)vpdhctx;

    if (!qat_prov_is_running())
        return 0;

    switch (pdhctx->kdf_type)
    {
    case PROV_DH_KDF_NONE:
        return qat_dh_plain_derive(pdhctx, secret, psecretlen, outlen);
    case PROV_DH_KDF_X9_42_ASN1:
        return qat_dh_X9_42_kdf_derive(pdhctx, secret, psecretlen, outlen);
    default:
        break;
    }
    return 0;
}

static void qat_dh_freectx(void *vpdhctx)
{
    QAT_PROV_DH_CTX *pdhctx = (QAT_PROV_DH_CTX *)vpdhctx;

    OPENSSL_free(pdhctx->kdf_cekalg);
    qat_DH_free(pdhctx->dh);
    qat_DH_free(pdhctx->dhpeer);
    EVP_MD_free(pdhctx->kdf_md);
    OPENSSL_clear_free(pdhctx->kdf_ukm, pdhctx->kdf_ukmlen);

    OPENSSL_free(pdhctx);
}

static void *qat_dh_dupctx(void *vpdhctx)
{
    QAT_PROV_DH_CTX *srcctx = (QAT_PROV_DH_CTX *)vpdhctx;
    QAT_PROV_DH_CTX *dstctx;

    if (!qat_prov_is_running())
        return NULL;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    dstctx->dh = NULL;
    dstctx->dhpeer = NULL;
    dstctx->kdf_md = NULL;
    dstctx->kdf_ukm = NULL;
    dstctx->kdf_cekalg = NULL;

    if (srcctx->dh != NULL && !qat_DH_up_ref(srcctx->dh))
        goto err;
    else
        dstctx->dh = srcctx->dh;

    if (srcctx->dhpeer != NULL && !qat_DH_up_ref(srcctx->dhpeer))
        goto err;
    else
        dstctx->dhpeer = srcctx->dhpeer;

    if (srcctx->kdf_md != NULL && !EVP_MD_up_ref(srcctx->kdf_md))
        goto err;
    else
        dstctx->kdf_md = srcctx->kdf_md;

    /* Duplicate UKM data if present */
    if (srcctx->kdf_ukm != NULL && srcctx->kdf_ukmlen > 0)
    {
        dstctx->kdf_ukm = OPENSSL_memdup(srcctx->kdf_ukm,
                                         srcctx->kdf_ukmlen);
        if (dstctx->kdf_ukm == NULL)
            goto err;
    }

    if (srcctx->kdf_cekalg != NULL)
    {
        dstctx->kdf_cekalg = OPENSSL_strdup(srcctx->kdf_cekalg);
        if (dstctx->kdf_cekalg == NULL)
            goto err;
    }

    return dstctx;
err:
    qat_dh_freectx(dstctx);
    return NULL;
}

static int qat_dh_set_ctx_params(void *vpdhctx, const OSSL_PARAM params[])
{
    QAT_PROV_DH_CTX *pdhctx = (QAT_PROV_DH_CTX *)vpdhctx;
    const OSSL_PARAM *p;
    unsigned int pad;
    char name[80] = {'\0'}; /* should be big enough */
    char *str = NULL;

    if (pdhctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p != NULL)
    {
        str = name;
        if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(name)))
            return 0;

        if (name[0] == '\0')
            pdhctx->kdf_type = PROV_DH_KDF_NONE;
        else if (strcmp(name, OSSL_KDF_NAME_X942KDF_ASN1) == 0)
            pdhctx->kdf_type = PROV_DH_KDF_X9_42_ASN1;
        else
            return 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if (p != NULL)
    {
        char mdprops[80] = {'\0'}; /* should be big enough */

        str = name;
        if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(name)))
            return 0;

        str = mdprops;
        p = OSSL_PARAM_locate_const(params,
                                    OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS);

        if (p != NULL)
        {
            if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(mdprops)))
                return 0;
        }

        EVP_MD_free(pdhctx->kdf_md);
        pdhctx->kdf_md = EVP_MD_fetch(pdhctx->libctx, name, mdprops);

        if (pdhctx->kdf_md == NULL)
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p != NULL)
    {
        size_t outlen;

        if (!OSSL_PARAM_get_size_t(p, &outlen))
            return 0;
        pdhctx->kdf_outlen = outlen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p != NULL)
    {
        void *tmp_ukm = NULL;
        size_t tmp_ukmlen;

        OPENSSL_free(pdhctx->kdf_ukm);
        pdhctx->kdf_ukm = NULL;
        pdhctx->kdf_ukmlen = 0;
        /* ukm is an optional field so it can be NULL */
        if (p->data != NULL && p->data_size != 0)
        {
            if (!OSSL_PARAM_get_octet_string(p, &tmp_ukm, 0, &tmp_ukmlen))
                return 0;
            pdhctx->kdf_ukm = tmp_ukm;
            pdhctx->kdf_ukmlen = tmp_ukmlen;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_PAD);
    if (p != NULL)
    {
        if (!OSSL_PARAM_get_uint(p, &pad))
            return 0;
        pdhctx->pad = pad ? 1 : 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_CEK_ALG);
    if (p != NULL)
    {
        str = name;

        OPENSSL_free(pdhctx->kdf_cekalg);
        pdhctx->kdf_cekalg = NULL;
        if (p->data != NULL && p->data_size != 0)
        {
            if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(name)))
                return 0;
            pdhctx->kdf_cekalg = OPENSSL_strdup(name);
            if (pdhctx->kdf_cekalg == NULL)
                return 0;
        }
    }
    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_PAD, NULL),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CEK_ALG, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *qat_dh_settable_ctx_params(ossl_unused void *vpdhctx,
                                                    ossl_unused void *provctx)
{
    return known_settable_ctx_params;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_DEFN(OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_PTR,
                    NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CEK_ALG, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *qat_dh_gettable_ctx_params(ossl_unused void *vpdhctx,
                                                    ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

static int qat_dh_get_ctx_params(void *vpdhctx, OSSL_PARAM params[])
{
    QAT_PROV_DH_CTX *pdhctx = (QAT_PROV_DH_CTX *)vpdhctx;
    OSSL_PARAM *p;

    if (pdhctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p != NULL)
    {
        const char *kdf_type = NULL;

        switch (pdhctx->kdf_type)
        {
        case PROV_DH_KDF_NONE:
            kdf_type = "";
            break;
        case PROV_DH_KDF_X9_42_ASN1:
            kdf_type = OSSL_KDF_NAME_X942KDF_ASN1;
            break;
        default:
            return 0;
        }

        if (!OSSL_PARAM_set_utf8_string(p, kdf_type))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, pdhctx->kdf_md == NULL
                                                        ? ""
                                                        : EVP_MD_get0_name(pdhctx->kdf_md)))
    {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, pdhctx->kdf_outlen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, pdhctx->kdf_ukm, pdhctx->kdf_ukmlen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_CEK_ALG);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, pdhctx->kdf_cekalg == NULL
                                                        ? ""
                                                        : pdhctx->kdf_cekalg))
        return 0;

    return 1;
}

const OSSL_DISPATCH qat_dh_keyexch_functions[] = {
    {OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))qat_dh_newctx},
    {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))qat_dh_init},
    {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))qat_dh_derive},
    {OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))qat_dh_set_peer},
    {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))qat_dh_freectx},
    {OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))qat_dh_dupctx},
    {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))qat_dh_set_ctx_params},
    {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
     (void (*)(void))qat_dh_settable_ctx_params},
    {OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))qat_dh_get_ctx_params},
    {OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
     (void (*)(void))qat_dh_gettable_ctx_params},
    {0, NULL}};

#endif /* ENABLE_QAT_HW_DH */
