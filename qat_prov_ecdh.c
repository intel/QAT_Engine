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
 * @file qat_prov_ecdh.c
 *
 * This file contains the qatprovider implementation for QAT_HW & QAT_SW
 * ECDH operations
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define __USE_GNU

#include <openssl/e_os2.h>
#include "qat_provider.h"
#include "qat_prov_ec.h"
#include "qat_utils.h"
#include "qat_evp.h"
#include "e_qat.h"

#ifdef ENABLE_QAT_HW_ECDH
# include "qat_hw_ec.h"
#endif
#ifdef ENABLE_QAT_SW_ECDH
# include "qat_sw_ec.h"
#endif

#ifdef ENABLE_QAT_FIPS
# include "qat_prov_cmvp.h"
#endif

#if defined(ENABLE_QAT_HW_ECDH) || defined(ENABLE_QAT_SW_ECDH)
enum kdf_type {
    PROV_ECDH_KDF_NONE = 0,
    PROV_ECDH_KDF_X9_63
};

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes EC_KEY structures, so
 * we use that here too.
 */
typedef struct {
    OSSL_LIB_CTX *libctx;

    EC_KEY *k;
    EC_KEY *peerk;

    /*
     * ECDH cofactor mode:
     *
     *  . 0  disabled
     *  . 1  enabled
     *  . -1 use cofactor mode set for k
     */
    int cofactor_mode;

    /************
     * ECDH KDF *
     ************/
    /* KDF (if any) to use for ECDH */
    enum kdf_type kdf_type;
    /* Message digest to use for key derivation */
    EVP_MD *kdf_md;
    /* User key material */
    unsigned char *kdf_ukm;
    size_t kdf_ukmlen;
    /* KDF output length */
    size_t kdf_outlen;
} QAT_PROV_ECDH_CTX;

static OSSL_FUNC_keyexch_newctx_fn qat_keyexch_ecdh_newctx;
static OSSL_FUNC_keyexch_init_fn qat_keyexch_ecdh_init;
static OSSL_FUNC_keyexch_set_peer_fn qat_keyexch_ecdh_set_peer;
static OSSL_FUNC_keyexch_derive_fn qat_keyexch_ecdh_derive;
static OSSL_FUNC_keyexch_freectx_fn qat_keyexch_ecdh_freectx;
static OSSL_FUNC_keyexch_set_ctx_params_fn qat_keyexch_ecdh_set_ctx_params;
static OSSL_FUNC_keyexch_settable_ctx_params_fn qat_keyexch_ecdh_settable_ctx_params;
static OSSL_FUNC_keyexch_get_ctx_params_fn qat_keyexch_ecdh_get_ctx_params;
static OSSL_FUNC_keyexch_gettable_ctx_params_fn qat_keyexch_ecdh_gettable_ctx_params;

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_DEFN(OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_PTR,
                    NULL, 0),
    OSSL_PARAM_END
};

static int QAT_ECDH_KEY_up_ref(EC_KEY *r)
{
    int i;

    if (CRYPTO_UP_REF(&r->references, &i, r->lock) <= 0)
        return 0;

    if(i < 2){
        WARN("refcount error");
        return 0;
    }
    return i > 1 ? 1 : 0;
}

static void QAT_ECDH_KEY_free(EC_KEY *r)
{
    int i;

    if (r == NULL)
        return;

    CRYPTO_DOWN_REF(&r->references, &i, r->lock);

    if (i > 0)
        return;

    if(i < 0){
        WARN("refcount error");
        return;
    }

    if (r->meth != NULL && r->meth->finish != NULL)
        r->meth->finish(r);

    if (r->group && r->group->meth->keyfinish)
        r->group->meth->keyfinish(r);

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_EC_KEY, r, &r->ex_data);

    CRYPTO_THREAD_lock_free(r->lock);

    EC_GROUP_free(r->group);
    EC_POINT_free(r->pub_key);
    BN_clear_free(r->priv_key);
    OPENSSL_free(r->propq);

    OPENSSL_clear_free((void *)r, sizeof(EC_KEY));
}

static int qat_ecdh_check_key(OSSL_LIB_CTX *ctx, const EC_KEY *ec, int protect)
{
# if !defined(OPENSSL_NO_FIPS_SECURITYCHECKS)
    if (qat_securitycheck_enabled(ctx)) {
        int nid, strength;
        const char *curve_name;
        const EC_GROUP *group = EC_KEY_get0_group(ec);

        if (group == NULL) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_CURVE, "No group");
            return 0;
        }
        nid = EC_GROUP_get_curve_name(group);
        if (nid == NID_undef) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_CURVE,
                           "Explicit curves are not allowed in fips mode");
            return 0;
        }

        curve_name = EC_curve_nid2nist(nid);
        if (curve_name == NULL) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_CURVE,
                           "Curve %s is not approved in FIPS mode", curve_name);
            return 0;
        }

        /*
         * For EC the security strength is the (order_bits / 2)
         * e.g. P-224 is 112 bits.
         */
        strength = EC_GROUP_order_bits(group) / 2;
        /* The min security strength allowed for legacy verification is 80 bits */
        if (strength < 80) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
            return 0;
        }

        /*
         * For signing or key agreement only allow curves with at least 112 bits of
         * security strength
         */
        if (protect && strength < 112) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_CURVE,
                           "Curve %s cannot be used for signing", curve_name);
            return 0;
        }
    }
# endif /* OPENSSL_NO_FIPS_SECURITYCHECKS */
    return 1;
}

static void *qat_keyexch_ecdh_newctx(void *provctx)
{
    QAT_PROV_ECDH_CTX *pectx;

    if (!qat_prov_is_running())
        return NULL;

    pectx = OPENSSL_zalloc(sizeof(*pectx));
    if (pectx == NULL)
        return NULL;

    pectx->libctx = prov_libctx_of(provctx);
    pectx->cofactor_mode = -1;
    pectx->kdf_type = PROV_ECDH_KDF_NONE;

    return (void *)pectx;

}

static int qat_keyexch_ecdh_init(void *vpecdhctx, void *vecdh, const OSSL_PARAM params[])
{
    QAT_PROV_ECDH_CTX *pecdhctx = (QAT_PROV_ECDH_CTX *)vpecdhctx;

    if (!qat_prov_is_running()
            || pecdhctx == NULL
            || vecdh == NULL
            || !QAT_ECDH_KEY_up_ref(vecdh))
        return 0;
    QAT_ECDH_KEY_free(pecdhctx->k);
    pecdhctx->k = vecdh;
    pecdhctx->cofactor_mode = -1;
    pecdhctx->kdf_type = PROV_ECDH_KDF_NONE;
    return qat_keyexch_ecdh_set_ctx_params(pecdhctx, params)
           && qat_ecdh_check_key(pecdhctx->libctx, vecdh, 1);
}

OSSL_LIB_CTX *qat_ec_key_get_libctx(const EC_KEY *key)
{
    return key->libctx;
}

static int qat_keyexch_ecdh_match_params(const EC_KEY *priv, const EC_KEY *peer)
{
    int ret;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group_priv = EC_KEY_get0_group(priv);
    const EC_GROUP *group_peer = EC_KEY_get0_group(peer);

    ctx = BN_CTX_new_ex(qat_ec_key_get_libctx(priv));
    if (ctx == NULL) {
        QATerr(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ret = group_priv != NULL
          && group_peer != NULL
          && EC_GROUP_cmp(group_priv, group_peer, ctx) == 0;
    if (!ret)
        QATerr(ERR_LIB_PROV, PROV_R_MISMATCHING_DOMAIN_PARAMETERS);
    BN_CTX_free(ctx);
    return ret;
}

static int qat_keyexch_ecdh_set_peer(void *vpecdhctx, void *vecdh)
{
    QAT_PROV_ECDH_CTX *pecdhctx = (QAT_PROV_ECDH_CTX *)vpecdhctx;

    if (!qat_prov_is_running()
            || pecdhctx == NULL
            || vecdh == NULL
            || !qat_keyexch_ecdh_match_params(pecdhctx->k, vecdh)
            || !qat_ecdh_check_key(pecdhctx->libctx, vecdh, 1)
            || !QAT_ECDH_KEY_up_ref(vecdh))
        return 0;

    QAT_ECDH_KEY_free(pecdhctx->peerk);
    pecdhctx->peerk = vecdh;
    return 1;
}

static void qat_keyexch_ecdh_freectx(void *vpecdhctx)
{
    QAT_PROV_ECDH_CTX *pecdhctx = (QAT_PROV_ECDH_CTX *)vpecdhctx;

    QAT_ECDH_KEY_free(pecdhctx->k);
    QAT_ECDH_KEY_free(pecdhctx->peerk);

    EVP_MD_free(pecdhctx->kdf_md);
    OPENSSL_clear_free(pecdhctx->kdf_ukm, pecdhctx->kdf_ukmlen);

    OPENSSL_free(pecdhctx);
}

static void *qat_keyexch_ecdh_dupctx(void *vpecdhctx)
{
    QAT_PROV_ECDH_CTX *srcctx = (QAT_PROV_ECDH_CTX *)vpecdhctx;
    QAT_PROV_ECDH_CTX *dstctx;

    if (!qat_prov_is_running())
        return NULL;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;

    /* clear all pointers */

    dstctx->k = NULL;
    dstctx->peerk = NULL;
    dstctx->kdf_md = NULL;
    dstctx->kdf_ukm = NULL;

    /* up-ref all ref-counted objects referenced in dstctx */

    if (srcctx->k != NULL && !QAT_ECDH_KEY_up_ref(srcctx->k))
        goto err;
    else
        dstctx->k = srcctx->k;

    if (srcctx->peerk != NULL && !QAT_ECDH_KEY_up_ref(srcctx->peerk))
        goto err;
    else
        dstctx->peerk = srcctx->peerk;

    if (srcctx->kdf_md != NULL && !EVP_MD_up_ref(srcctx->kdf_md))
        goto err;
    else
        dstctx->kdf_md = srcctx->kdf_md;

    /* Duplicate UKM data if present */
    if (srcctx->kdf_ukm != NULL && srcctx->kdf_ukmlen > 0) {
        dstctx->kdf_ukm = OPENSSL_memdup(srcctx->kdf_ukm,
                                         srcctx->kdf_ukmlen);
        if (dstctx->kdf_ukm == NULL)
            goto err;
    }

    return dstctx;

 err:
    qat_keyexch_ecdh_freectx(dstctx);
    return NULL;
}

static int qat_keyexch_digest_is_allowed(OSSL_LIB_CTX *ctx, const EVP_MD *md)
{
    return 1;
}

static int qat_keyexch_ecdh_set_ctx_params(void *vpecdhctx, const OSSL_PARAM params[])
{
    char name[80] = { '\0' }; /* should be big enough */
    char *str = NULL;
    QAT_PROV_ECDH_CTX *pectx = (QAT_PROV_ECDH_CTX *)vpecdhctx;
    const OSSL_PARAM *p;

    if (pectx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE);
    if (p != NULL) {
        int mode;

        if (!OSSL_PARAM_get_int(p, &mode))
            return 0;

        if (mode < -1 || mode > 1)
            return 0;

        pectx->cofactor_mode = mode;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p != NULL) {
        str = name;
        if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(name)))
            return 0;

        if (name[0] == '\0')
            pectx->kdf_type = PROV_ECDH_KDF_NONE;
        else if (strcmp(name, OSSL_KDF_NAME_X963KDF) == 0)
            pectx->kdf_type = PROV_ECDH_KDF_X9_63;
        else
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if (p != NULL) {
        char mdprops[80] = { '\0' }; /* should be big enough */

        str = name;
        if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(name)))
            return 0;

        str = mdprops;
        p = OSSL_PARAM_locate_const(params,
                                    OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS);

        if (p != NULL) {
            if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(mdprops)))
                return 0;
        }

        EVP_MD_free(pectx->kdf_md);
        pectx->kdf_md = EVP_MD_fetch(pectx->libctx, name, mdprops);
        if (!qat_keyexch_digest_is_allowed(pectx->libctx, pectx->kdf_md)) {
            EVP_MD_free(pectx->kdf_md);
            pectx->kdf_md = NULL;
        }
        if (pectx->kdf_md == NULL)
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p != NULL) {
        size_t outlen;

        if (!OSSL_PARAM_get_size_t(p, &outlen))
            return 0;
        pectx->kdf_outlen = outlen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p != NULL) {
        void *tmp_ukm = NULL;
        size_t tmp_ukmlen;

        if (!OSSL_PARAM_get_octet_string(p, &tmp_ukm, 0, &tmp_ukmlen))
            return 0;
        OPENSSL_free(pectx->kdf_ukm);
        pectx->kdf_ukm = tmp_ukm;
        pectx->kdf_ukmlen = tmp_ukmlen;
    }

    return 1;
}

static const OSSL_PARAM *qat_keyexch_ecdh_settable_ctx_params(
             ossl_unused void *vpecdhctx, ossl_unused void *provctx)
{
    return known_settable_ctx_params;
}

static int qat_keyexch_ecdh_get_ctx_params(void *vpecdhctx, OSSL_PARAM params[])
{
    QAT_PROV_ECDH_CTX *pectx = (QAT_PROV_ECDH_CTX *)vpecdhctx;
    OSSL_PARAM *p;

    if (pectx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE);
    if (p != NULL) {
        int mode = pectx->cofactor_mode;

        if (mode == -1) {
            /* check what is the default for pecdhctx->k */
            mode = EC_KEY_get_flags(pectx->k) & EC_FLAG_COFACTOR_ECDH ? 1 : 0;
        }

        if (!OSSL_PARAM_set_int(p, mode))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p != NULL) {
        const char *kdf_type = NULL;

        switch (pectx->kdf_type) {
        case PROV_ECDH_KDF_NONE:
            kdf_type = "";
            break;
        case PROV_ECDH_KDF_X9_63:
            kdf_type = OSSL_KDF_NAME_X963KDF;
            break;
        default:
            return 0;
        }

        if (!OSSL_PARAM_set_utf8_string(p, kdf_type))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if (p != NULL
            && !OSSL_PARAM_set_utf8_string(p, pectx->kdf_md == NULL
                                           ? ""
                                           : EVP_MD_get0_name(pectx->kdf_md))){
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, pectx->kdf_outlen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p != NULL &&
        !OSSL_PARAM_set_octet_ptr(p, pectx->kdf_ukm, pectx->kdf_ukmlen))
        return 0;

    return 1;
}

static const OSSL_PARAM *qat_keyexch_ecdh_gettable_ctx_params(
             ossl_unused void *vpecdhctx, ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

size_t qat_keyexch_ecdh_size(const EC_KEY *k)
{
    size_t degree = 0;
    const EC_GROUP *group;

    if (k == NULL
            || (group = EC_KEY_get0_group(k)) == NULL)
        return 0;

    degree = EC_GROUP_get_degree(group);

    return (degree + 7) / 8;
}

int QAT_ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
                         const EC_KEY *eckey, void *(*KDF) (const void *in,
                         size_t inlen, void *out, size_t *outlen))
{
    unsigned char *sec = NULL;
    size_t seclen;
    if (eckey->meth->compute_key == NULL) {
        QATerr(ERR_LIB_EC, EC_R_OPERATION_NOT_SUPPORTED);
        return 0;
    }
    if (outlen > INT_MAX) {
        QATerr(ERR_LIB_EC, EC_R_INVALID_OUTPUT_LENGTH);
        return 0;
    }
#ifdef ENABLE_QAT_HW_ECDH
    if (qat_hw_ecdh_offload) {
        if(!qat_engine_ecdh_compute_key(&sec, &seclen, pub_key, eckey))
            return 0;
    }
#endif
#ifdef ENABLE_QAT_SW_ECDH
    if (qat_sw_ecdh_offload) {
        if(!mb_ecdh_compute_key(&sec, &seclen, pub_key, eckey))
            return 0;
    }
#endif
    if (KDF != NULL) {
        KDF(sec, seclen, out, &outlen);
    } else {
        if (outlen > seclen)
            outlen = seclen;
        memcpy(out, sec, outlen);
    }
    OPENSSL_clear_free(sec, seclen);
    return outlen;
}

static ossl_inline int qat_keyexch_ecdh_plain_derive(void *vpecdhctx,
            unsigned char *secret, size_t *psecretlen, size_t outlen)
{
    QAT_PROV_ECDH_CTX *pecdhctx = (QAT_PROV_ECDH_CTX *)vpecdhctx;
    int retlen, ret = 0;
    size_t ecdhsize, size;
    const EC_POINT *ppubkey = NULL;
    EC_KEY *privk = NULL;
    const EC_GROUP *group;
    const BIGNUM *cofactor;
    int key_cofactor_mode;

    if (pecdhctx->k == NULL || pecdhctx->peerk == NULL) {
        QATerr(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    ecdhsize = qat_keyexch_ecdh_size(pecdhctx->k);
    if (secret == NULL) {
        *psecretlen = ecdhsize;
        return 1;
    }

    if ((group = EC_KEY_get0_group(pecdhctx->k)) == NULL
            || (cofactor = EC_GROUP_get0_cofactor(group)) == NULL )
        return 0;

    /*
     * NB: unlike PKCS#3 DH, if outlen is less than maximum size this is not
     * an error, the result is truncated.
     */
    size = outlen < ecdhsize ? outlen : ecdhsize;
    /*
     * The ctx->cofactor_mode flag has precedence over the
     * cofactor_mode flag set on ctx->k.
     *
     * - if ctx->cofactor_mode == -1, use ctx->k directly
     * - if ctx->cofactor_mode == key_cofactor_mode, use ctx->k directly
     * - if ctx->cofactor_mode != key_cofactor_mode:
     *     - if ctx->k->cofactor == 1, the cofactor_mode flag is irrelevant, use
     *          ctx->k directly
     *     - if ctx->k->cofactor != 1, use a duplicate of ctx->k with the flag
     *          set to ctx->cofactor_mode
     */

    key_cofactor_mode =
        (EC_KEY_get_flags(pecdhctx->k) & EC_FLAG_COFACTOR_ECDH) ? 1 : 0;
    if (pecdhctx->cofactor_mode != -1
            && pecdhctx->cofactor_mode != key_cofactor_mode
            && !BN_is_one(cofactor)) {
        if ((privk = EC_KEY_dup(pecdhctx->k)) == NULL)
            return 0;

        if (pecdhctx->cofactor_mode == 1)
            EC_KEY_set_flags(privk, EC_FLAG_COFACTOR_ECDH);
        else
            EC_KEY_clear_flags(privk, EC_FLAG_COFACTOR_ECDH);
    } else {
        privk = pecdhctx->k;
    }

    ppubkey = EC_KEY_get0_public_key(pecdhctx->peerk);

    retlen = QAT_ECDH_compute_key(secret, size, ppubkey, privk, NULL);

    if (retlen <= 0)
        goto end;

    *psecretlen = retlen;
    ret = 1;

 end:
    if (privk != pecdhctx->k)
        EC_KEY_free(privk);
    return ret;
}

/* Key derivation function from X9.63/SECG */
static int qat_keyexch_ecdh_kdf_X9_63(unsigned char *out, size_t outlen,
                        const unsigned char *Z, size_t Zlen,
                        const unsigned char *sinfo, size_t sinfolen,
                        const EVP_MD *md,
                        OSSL_LIB_CTX *libctx, const char *propq)
{
    int ret = 0;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[4], *p = params;
    const char *mdname = EVP_MD_get0_name(md);
    EVP_KDF *kdf = EVP_KDF_fetch(libctx, OSSL_KDF_NAME_X963KDF, propq);

    if ((kctx = EVP_KDF_CTX_new(kdf)) != NULL) {
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                (char *)mdname, 0);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                 (void *)Z, Zlen);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                 (void *)sinfo, sinfolen);
        *p = OSSL_PARAM_construct_end();

        ret = EVP_KDF_derive(kctx, out, outlen, params) > 0;
        EVP_KDF_CTX_free(kctx);
    }
    EVP_KDF_free(kdf);
    return ret;
}

static ossl_inline int qat_keyexch_ecdh_X9_63_kdf_derive(void *vpecdhctx,
                unsigned char *secret, size_t *psecretlen, size_t outlen)
{
    QAT_PROV_ECDH_CTX *pecdhctx = (QAT_PROV_ECDH_CTX *)vpecdhctx;
    unsigned char *stmp = NULL;
    size_t stmplen;
    int ret = 0;

    if (secret == NULL) {
        *psecretlen = pecdhctx->kdf_outlen;
        return 1;
    }
    if (pecdhctx->kdf_outlen > outlen) {
        QATerr(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    if (!qat_keyexch_ecdh_plain_derive(vpecdhctx, NULL, &stmplen, 0))
        return 0;
    if ((stmp = OPENSSL_secure_malloc(stmplen)) == NULL) {
        QATerr(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!qat_keyexch_ecdh_plain_derive(vpecdhctx, stmp, &stmplen, stmplen))
        goto err;

    /* Do KDF stuff */
    if (!qat_keyexch_ecdh_kdf_X9_63(secret, pecdhctx->kdf_outlen,
                             stmp, stmplen,
                             pecdhctx->kdf_ukm,
                             pecdhctx->kdf_ukmlen,
                             pecdhctx->kdf_md,
                             pecdhctx->libctx, NULL))
        goto err;
    *psecretlen = pecdhctx->kdf_outlen;
    ret = 1;

 err:
    OPENSSL_secure_clear_free(stmp, stmplen);
    return ret;
}

static int qat_keyexch_ecdh_derive(void *vpecdhctx, unsigned char *secret,
                size_t *psecretlen, size_t outlen)
{
    int ret = 0;
    QAT_PROV_ECDH_CTX *pecdhctx = (QAT_PROV_ECDH_CTX *)vpecdhctx;
#ifdef ENABLE_QAT_FIPS
    if (!qat_fips_ec_check_approved_curve(pecdhctx->k))
        goto end;

    qat_fips_service_indicator = 1;
#endif
    switch (pecdhctx->kdf_type) {
    case PROV_ECDH_KDF_NONE:
        ret = qat_keyexch_ecdh_plain_derive(vpecdhctx, secret, psecretlen, outlen);
        goto end;
    case PROV_ECDH_KDF_X9_63:
        ret = qat_keyexch_ecdh_X9_63_kdf_derive(vpecdhctx, secret, psecretlen, outlen);
        goto end;
    default:
        break;
    }

end:
#ifdef ENABLE_QAT_FIPS
    qat_fips_service_indicator = 0;
#endif

    return ret;
}

const OSSL_DISPATCH qat_ecdh_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))qat_keyexch_ecdh_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))qat_keyexch_ecdh_init },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))qat_keyexch_ecdh_derive },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))qat_keyexch_ecdh_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))qat_keyexch_ecdh_freectx },
    { OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))qat_keyexch_ecdh_dupctx },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))qat_keyexch_ecdh_set_ctx_params },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
      (void (*)(void))qat_keyexch_ecdh_settable_ctx_params },
    { OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))qat_keyexch_ecdh_get_ctx_params },
    { OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
      (void (*)(void))qat_keyexch_ecdh_gettable_ctx_params },
    { 0, NULL }
};

#endif
