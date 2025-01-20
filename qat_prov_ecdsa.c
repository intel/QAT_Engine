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
 * @file qat_provider_ecdsa.c
 *
 * This file contains the qatprovider implementation for QAT_HW and QAT_SW
 * ECDSA operations.
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define __USE_GNU

#include "qat_provider.h"
#include "qat_prov_hkdf_packet.h"
#include "qat_prov_ec.h"
#include "qat_utils.h"
#include "qat_evp.h"
#include "e_qat.h"

#ifdef ENABLE_QAT_FIPS
#include "qat_prov_cmvp.h"
#endif

#ifdef ENABLE_QAT_HW_ECDSA
# include "qat_hw_ec.h"
#endif
#ifdef ENABLE_QAT_SW_ECDSA
# include "qat_sw_ec.h"
#endif

#if defined(ENABLE_QAT_HW_ECDSA) || defined(ENABLE_QAT_SW_ECDSA)
#ifdef ENABLE_QAT_FIPS
extern int qat_fips_key_zeroize;
#endif

typedef struct evp_signature_st {
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;
    CRYPTO_REF_COUNT references;
#if OPENSSL_VERSION_NUMBER < 0x30200000
    CRYPTO_RWLOCK *lock;
#endif
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
} QAT_EVP_SIGNATURE /* EVP_SIGNATURE for QAT Provider ECDSA */;

static QAT_EVP_SIGNATURE get_default_ECDSA_signature()
{
    static QAT_EVP_SIGNATURE s_signature;
    static int initilazed = 0;
    if (!initilazed) {
        QAT_EVP_SIGNATURE *signature = (QAT_EVP_SIGNATURE *)EVP_SIGNATURE_fetch(NULL, "ECDSA", "provider=default");
        if (signature) {
            s_signature = *signature;
            EVP_SIGNATURE_free((EVP_SIGNATURE *)signature);
            initilazed = 1;
        } else {
            WARN("EVP_SIGNATURE_fetch from default provider failed");
        }
    }
    return s_signature;
}


static const OSSL_PARAM settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_KAT, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM settable_ctx_params_no_digest[] = {
    OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_KAT, NULL),
    OSSL_PARAM_END
};

int QAT_EC_KEY_up_ref(EC_KEY *r)
{
    int i;
# if OPENSSL_VERSION_NUMBER < 0x30200000
    if (CRYPTO_UP_REF(&r->references, &i, r->lock) <= 0)
        return 0;
# else
    if (QAT_CRYPTO_UP_REF(&r->references, &i) <= 0)
        return 0;
# endif

    if(i < 2){
        WARN("refcount error");
        return 0;
    }
    return i > 1 ? 1 : 0;
}

void QAT_EC_KEY_free(EC_KEY *r)
{
#ifdef ENABLE_QAT_FIPS
    qat_fips_key_zeroize = 0;
#endif
    int i;

    if (r == NULL)
        return;
# if OPENSSL_VERSION_NUMBER < 0x30200000
    CRYPTO_DOWN_REF(&r->references, &i, r->lock);
# else
    QAT_CRYPTO_DOWN_REF(&r->references, &i);
# endif

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
# if OPENSSL_VERSION_NUMBER < 0x30200000
    CRYPTO_THREAD_lock_free(r->lock);
# endif
    EC_GROUP_free(r->group);
    EC_POINT_free(r->pub_key);
    BN_clear_free(r->priv_key);
    OPENSSL_free(r->propq);

    OPENSSL_clear_free((void *)r, sizeof(EC_KEY));
#ifdef ENABLE_QAT_FIPS
    qat_fips_key_zeroize = 1;
    qat_fips_get_key_zeroize_status();
#endif

}

/* Disable the security checks in the default provider and qat provider */
int qat_securitycheck_enabled(OSSL_LIB_CTX *libctx)
{
    return 0;
}

#ifndef OPENSSL_NO_EC
/*
 * In FIPS mode:
 * protect should be 1 for any operations that need 112 bits of security
 * strength (such as signing, and key exchange), or 0 for operations that allow
 * a lower security strength (such as verify).
 *
 * For ECDH key agreement refer to SP800-56A
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
 * "Appendix D"
 *
 * For ECDSA signatures refer to
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
 * "Table 2"
 */
int qat_ec_check_key(OSSL_LIB_CTX *ctx, const EC_KEY *ec, int protect)
{
#ifdef ENABLE_QAT_FIPS
    if (!qat_fips_ec_check_approved_curve(ec)) {
        return 0;
    }
    if (!qat_fips_ec_key_simple_check_key(ec)) {
        INFO("Invalid pub_key\n");
        return 0;
    }
#endif

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
            QATerr(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
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
#endif /* OPENSSL_NO_EC */

/*
 * Internal library code deals with NIDs, so we need to translate from a name.
 * We do so using EVP_MD_is_a(), and therefore need a name to NID map.
 */
int qat_digest_ecdsa_md_to_nid(const EVP_MD *md, const OSSL_ITEM *it, size_t it_len)
{
    size_t i;

    if (md == NULL)
        return NID_undef;

    for (i = 0; i < it_len; i++)
        if (EVP_MD_is_a(md, it[i].ptr))
            return (int)it[i].id;
    return NID_undef;
}

int qat_digest_ecdsa_get_approved_nid(const EVP_MD *md)
{
    static const OSSL_ITEM name_to_nid[] = {
        { NID_sha1,      OSSL_DIGEST_NAME_SHA1      },
        { NID_sha224,    OSSL_DIGEST_NAME_SHA2_224  },
        { NID_sha256,    OSSL_DIGEST_NAME_SHA2_256  },
        { NID_sha384,    OSSL_DIGEST_NAME_SHA2_384  },
        { NID_sha512,    OSSL_DIGEST_NAME_SHA2_512  },
        { NID_sha512_224, OSSL_DIGEST_NAME_SHA2_512_224 },
        { NID_sha512_256, OSSL_DIGEST_NAME_SHA2_512_256 },
        { NID_sha3_224,  OSSL_DIGEST_NAME_SHA3_224  },
        { NID_sha3_256,  OSSL_DIGEST_NAME_SHA3_256  },
        { NID_sha3_384,  OSSL_DIGEST_NAME_SHA3_384  },
        { NID_sha3_512,  OSSL_DIGEST_NAME_SHA3_512  },
    };

    return qat_digest_ecdsa_md_to_nid(md, name_to_nid, OSSL_NELEM(name_to_nid));
}

int qat_digest_ecdsa_get_approved_nid_with_sha1(OSSL_LIB_CTX *ctx, const EVP_MD *md,
                                           int sha1_allowed)
{
    int mdnid = qat_digest_ecdsa_get_approved_nid(md);
    return mdnid;
}

static int qat_ecdsa_setup_md(QAT_PROV_ECDSA_CTX *ctx, const char *mdname,
                          const char *mdprops)
{
    EVP_MD *md = NULL;
    size_t mdname_len;
    int md_nid, sha1_allowed;
    qat_WPACKET pkt;

    if (mdname == NULL)
        return 1;

    mdname_len = strlen(mdname);
    if (mdname_len >= sizeof(ctx->mdname)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                       "%s exceeds name buffer length", mdname);
        return 0;
    }

    if (mdprops == NULL)
        mdprops = ctx->propq;

    md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
    if (md == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                       "%s could not be fetched", mdname);
        return 0;
    }
    sha1_allowed = (ctx->operation != EVP_PKEY_OP_SIGN);
    md_nid = qat_digest_ecdsa_get_approved_nid_with_sha1(ctx->libctx, md,
                                                    sha1_allowed);
    if (md_nid < 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                       "digest=%s", mdname);
        EVP_MD_free(md);
        return 0;
    }

    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);

    ctx->aid_len = 0;
    if (QAT_WPACKET_init_der(&pkt, ctx->aid_buf, sizeof(ctx->aid_buf))
        && qat_DER_w_algorithmIdentifier_ECDSA_with_MD(&pkt, -1, ctx->ec,
                                                        md_nid)
        && QAT_WPACKET_finish(&pkt)) {
        QAT_WPACKET_get_total_written(&pkt, &ctx->aid_len);
        ctx->aid = QAT_WPACKET_get_curr(&pkt);
    }
    QAT_WPACKET_cleanup(&pkt);
    ctx->mdctx = NULL;
    ctx->md = md;
    ctx->mdsize = EVP_MD_get_size(ctx->md);
    OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));

    return 1;

}
static void *qat_signature_ecdsa_newctx(void *provctx, const char *propq)
{
    QAT_PROV_ECDSA_CTX *ctx;

    if (!qat_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(QAT_PROV_ECDSA_CTX));
    if (ctx == NULL)
        return NULL;

    ctx->flag_allow_md = 1;
    ctx->libctx = prov_libctx_of(provctx);
    if (propq != NULL && (ctx->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(ctx);
        ctx = NULL;
        QATerr(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    }
    return ctx;
}

static int qat_signature_ecdsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    QAT_PROV_ECDSA_CTX *ctx = (QAT_PROV_ECDSA_CTX *)vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    /* Not allowed during certain operations */
    if (p != NULL && !ctx->flag_allow_md)
        return 0;
    if (p != NULL) {
        char mdname[OSSL_MAX_NAME_SIZE] = "", *pmdname = mdname;
        char mdprops[OSSL_MAX_PROPQUERY_SIZE] = "", *pmdprops = mdprops;
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_PROPERTIES);

        if (!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))
            return 0;
        if (propsp != NULL
            && !OSSL_PARAM_get_utf8_string(propsp, &pmdprops, sizeof(mdprops)))
            return 0;
        if (!qat_ecdsa_setup_md(ctx, mdname, mdprops))
            return 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL
        && (!ctx->flag_allow_md
            || !OSSL_PARAM_get_size_t(p, &ctx->mdsize)))
        return 0;

    return 1;
}

static int qat_signature_ecdsa_signverify_init(void *vctx, void *ec,
                                 const OSSL_PARAM params[], int operation)
{
    QAT_PROV_ECDSA_CTX *ctx = (QAT_PROV_ECDSA_CTX *)vctx;

    if (!qat_prov_is_running()
            || ctx == NULL
            || ec == NULL
            || !QAT_EC_KEY_up_ref(ec))
        return 0;
    QAT_EC_KEY_free(ctx->ec);
    ctx->ec = ec;
    ctx->operation = operation;
    if (!qat_signature_ecdsa_set_ctx_params(ctx, params))
        return 0;
    return qat_ec_check_key(ctx->libctx, ec, operation == EVP_PKEY_OP_SIGN);
}

static int qat_signature_ecdsa_sign_init(void *vctx, void *ec, const OSSL_PARAM params[])
{
    DEBUG("qat_signature_ecdsa_sign_init\n");
    return qat_signature_ecdsa_signverify_init(vctx, ec, params, EVP_PKEY_OP_SIGN);
}

static int qat_signature_ecdsa_verify_init(void *vctx, void *ec, const OSSL_PARAM params[])
{
    DEBUG("qat_signature_ecdsa_verify_init\n");
    return qat_signature_ecdsa_signverify_init(vctx, ec, params, EVP_PKEY_OP_VERIFY);
}

static int qat_signature_ecdsa_sign(void *vctx, unsigned char *sig, size_t *siglen,
                      size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    QAT_PROV_ECDSA_CTX *ctx = (QAT_PROV_ECDSA_CTX *)vctx;
    int ret = 0;
    unsigned int sltmp;
    size_t ecsize = ECDSA_size(ctx->ec);
#ifdef ENABLE_QAT_FIPS
    if (!qat_fips_ec_check_approved_curve(ctx->ec))
        goto end;

    qat_fips_service_indicator = 1;
#endif

    if (!qat_prov_is_running())
        goto end;

    if (sig == NULL) {
        *siglen = ecsize;
        ret = 1;
        goto end;
    }
    if (sigsize < (size_t)ecsize)
        goto end;

    if (ctx->mdsize != 0 && tbslen != ctx->mdsize)
        goto end;
#ifdef ENABLE_QAT_HW_ECDSA
    if (qat_hw_ecdsa_offload) {
        ret = qat_ecdsa_sign(0, tbs, tbslen, sig, &sltmp, ctx->kinv, ctx->r, ctx->ec);
        if (ret <= 0)
            goto end;
    }
#endif
#ifdef ENABLE_QAT_SW_ECDSA
    if (qat_sw_ecdsa_offload) {
        ret = mb_ecdsa_sign(0, tbs, tbslen, sig, &sltmp, ctx->kinv, ctx->r, ctx->ec);
        if (ret <= 0)
            goto end;
    } else {
        typedef int (*fun_ptr)(void *, unsigned char *, size_t *,
                               size_t , const unsigned char *, size_t);
        fun_ptr fun = get_default_ECDSA_signature().sign;
        if (!fun)
            return 0;
        return fun(vctx, sig, siglen, sigsize, tbs, tbslen);
    }
#endif
    *siglen = sltmp;
    ret = 1;
end:
#ifdef ENABLE_QAT_FIPS
    qat_fips_service_indicator = 0;
#endif
    return ret;
}

static int qat_signature_ecdsa_verify(void *vctx, const unsigned char *sig, size_t siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    int ret = 0;
    QAT_PROV_ECDSA_CTX *ctx = (QAT_PROV_ECDSA_CTX *)vctx;

#ifdef ENABLE_QAT_FIPS
    if (!qat_fips_ec_check_approved_curve(ctx->ec))
        goto end;

    qat_fips_service_indicator = 1;
#endif
    if (!qat_prov_is_running() || (ctx->mdsize != 0 && tbslen != ctx->mdsize))
        goto end;

#ifdef ENABLE_QAT_HW_ECDSA
    if (qat_hw_ecdsa_offload)
        ret = qat_ecdsa_verify(0, tbs, tbslen, sig, siglen, ctx->ec);
#endif
#ifdef ENABLE_QAT_SW_ECDSA
    if (qat_sw_ecdsa_offload) {
        ret = mb_ecdsa_verify(0, tbs, tbslen, sig, siglen, ctx->ec);
    } else {
        typedef int (*fun_ptr)(void *, const unsigned char *, size_t,
                               const unsigned char *, size_t);
        fun_ptr fun = get_default_ECDSA_signature().verify;
        if (!fun)
            return 0;
        return fun(vctx, sig, siglen, tbs, tbslen);
    }
#endif

end:
#ifdef ENABLE_QAT_FIPS
    qat_fips_service_indicator = 0;
#endif

    return ret;
}

static void qat_signature_ecdsa_freectx(void *vctx)
{
    QAT_PROV_ECDSA_CTX *ctx = (QAT_PROV_ECDSA_CTX *)vctx;

    OPENSSL_free(ctx->propq);
    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    ctx->propq = NULL;
    ctx->mdctx = NULL;
    ctx->md = NULL;
    ctx->mdsize = 0;
    QAT_EC_KEY_free(ctx->ec);
    BN_clear_free(ctx->kinv);
    BN_clear_free(ctx->r);
    OPENSSL_free(ctx);
}

static const OSSL_PARAM *qat_signature_ecdsa_settable_ctx_params(void *vctx,
                                                   ossl_unused void *provctx)
{
    QAT_PROV_ECDSA_CTX *ctx = (QAT_PROV_ECDSA_CTX *)vctx;

    if (ctx != NULL && !ctx->flag_allow_md)
        return settable_ctx_params_no_digest;
    return settable_ctx_params;
}

static int qat_ecdsa_signverify_init(void *vctx, void *ec,
                                     const OSSL_PARAM params[], int operation)
{
    QAT_PROV_ECDSA_CTX *ctx = (QAT_PROV_ECDSA_CTX *)vctx;

    if (!qat_prov_is_running()
            || ctx == NULL)
        return 0;

    if (ec == NULL && ctx->ec == NULL) {
        QATerr(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (ec != NULL) {
        if (!qat_ec_check_key(ctx->libctx, ec, operation == EVP_PKEY_OP_SIGN))
            return 0;
        if (!EC_KEY_up_ref(ec))
            return 0;
        EC_KEY_free(ctx->ec);
        ctx->ec = ec;
    }

    ctx->operation = operation;

    if (!qat_signature_ecdsa_set_ctx_params(ctx, params))
        return 0;

    return 1;
}

static int qat_ecdsa_digest_signverify_init(void *vctx, const char *mdname,
                                            void *ec, const OSSL_PARAM params[],
                                            int operation)
{
    QAT_PROV_ECDSA_CTX *ctx = (QAT_PROV_ECDSA_CTX *)vctx;

    if (!qat_prov_is_running())
        return 0;

    if (!qat_ecdsa_signverify_init(vctx, ec, params, operation)
        || !qat_ecdsa_setup_md(ctx, mdname, NULL))
        return 0;

    ctx->flag_allow_md = 0;

    if (ctx->mdctx == NULL) {
        ctx->mdctx = EVP_MD_CTX_new();
        if (ctx->mdctx == NULL)
            goto error;
    }

    if (!EVP_DigestInit_ex2(ctx->mdctx, ctx->md, params))
        goto error;
    return 1;
error:
    EVP_MD_CTX_free(ctx->mdctx);
    ctx->mdctx = NULL;
    return 0;
}

static int qat_ecdsa_digest_sign_init(void *vctx, const char *mdname, void *ec,
                                  const OSSL_PARAM params[])
{
    return qat_ecdsa_digest_signverify_init(vctx, mdname, ec, params,
                                            EVP_PKEY_OP_SIGN);
}

int qat_ecdsa_digest_signverify_update(void *vctx, const unsigned char *data,
                                   size_t datalen)
{
    QAT_PROV_ECDSA_CTX *ctx = (QAT_PROV_ECDSA_CTX *)vctx;

    if (ctx == NULL || ctx->mdctx == NULL)
        return 0;

    return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

int qat_ecdsa_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen,
                            size_t sigsize)
{
    QAT_PROV_ECDSA_CTX *ctx = (QAT_PROV_ECDSA_CTX *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!qat_prov_is_running() || ctx == NULL || ctx->mdctx == NULL)
        return 0;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to ecdsa_sign.
     */
    if (sig != NULL
        && !EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
        return 0;
    ctx->flag_allow_md = 1;
    return qat_signature_ecdsa_sign(vctx, sig, siglen, sigsize, digest, (size_t)dlen);
}

static int qat_ecdsa_digest_verify_init(void *vctx, const char *mdname, void *ec,
                                    const OSSL_PARAM params[])
{
    return qat_ecdsa_digest_signverify_init(vctx, mdname, ec, params,
                                        EVP_PKEY_OP_VERIFY);
}

int qat_ecdsa_digest_verify_final(void *vctx, const unsigned char *sig,
                              size_t siglen)
{
    QAT_PROV_ECDSA_CTX *ctx = (QAT_PROV_ECDSA_CTX *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!qat_prov_is_running() || ctx == NULL || ctx->mdctx == NULL)
        return 0;

    if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
        return 0;
    ctx->flag_allow_md = 1;
    return qat_signature_ecdsa_verify(ctx, sig, siglen, digest, (size_t)dlen);
}

static void *qat_ecdsa_dupctx(void *vctx)
{
    QAT_PROV_ECDSA_CTX *srcctx = (QAT_PROV_ECDSA_CTX *)vctx;
    QAT_PROV_ECDSA_CTX *dstctx;

    if (!qat_prov_is_running())
        return NULL;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    dstctx->ec = NULL;
    dstctx->md = NULL;
    dstctx->mdctx = NULL;
    dstctx->propq = NULL;

    if (srcctx->ec != NULL && !EC_KEY_up_ref(srcctx->ec))
        goto err;
    /* Test KATS should not need to be supported */
    if (srcctx->kinv != NULL || srcctx->r != NULL)
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

    if (srcctx->propq != NULL) {
        dstctx->propq = OPENSSL_strdup(srcctx->propq);
        if (dstctx->propq == NULL)
            goto err;
    }

    return dstctx;
 err:
    qat_signature_ecdsa_freectx(dstctx);
    return NULL;
}

static int qat_ecdsa_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    typedef int (*fun_ptr)(void *vctx, OSSL_PARAM *params);
    fun_ptr fun = get_default_ECDSA_signature().get_ctx_params;
    if (!fun)
        return 0;
    return fun(vctx, params);
}

static const OSSL_PARAM *qat_ecdsa_gettable_ctx_params(void *vctx,
                                                   void *provctx)
{
    typedef const OSSL_PARAM * (*fun_ptr)(void *vctx,
                                          void *provctx);
    fun_ptr fun = get_default_ECDSA_signature().gettable_ctx_params;
    if (!fun)
        return NULL;
    return fun(vctx, provctx);
}

static const OSSL_PARAM *qat_ecdsa_settable_ctx_params(void *vctx,
                                                   void *provctx)
{
    typedef const OSSL_PARAM * (*fun_ptr)(void *vctx,
                                          void *provctx);
    fun_ptr fun = get_default_ECDSA_signature().settable_ctx_params;
    if (!fun)
        return NULL;
    return fun(vctx, provctx);
}

static int qat_ecdsa_get_ctx_md_params(void *vctx, OSSL_PARAM *params)
{
    typedef int (*fun_ptr)(void *vctx, OSSL_PARAM *params);
    fun_ptr fun = get_default_ECDSA_signature().get_ctx_md_params;
    if (!fun)
        return 0;
    return fun(vctx, params);
}

static const OSSL_PARAM *qat_ecdsa_gettable_ctx_md_params(void *vctx)
{
    typedef const OSSL_PARAM * (*fun_ptr)(void *vctx);
    fun_ptr fun = get_default_ECDSA_signature().gettable_ctx_md_params;
    if (!fun)
        return NULL;
    return fun(vctx);
}

static int qat_ecdsa_set_ctx_md_params(void *vctx, const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *vctx, const OSSL_PARAM params[]);
    fun_ptr fun = get_default_ECDSA_signature().set_ctx_md_params;
    if (!fun)
        return 0;
    return fun(vctx, params);
}

static const OSSL_PARAM *qat_ecdsa_settable_ctx_md_params(void *vctx)
{
    typedef const OSSL_PARAM * (*fun_ptr)(void *vctx);
    fun_ptr fun = get_default_ECDSA_signature().settable_ctx_md_params;
    if (!fun)
        return 0;
    return fun(vctx);
}

const OSSL_DISPATCH qat_ecdsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))qat_signature_ecdsa_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))qat_signature_ecdsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))qat_signature_ecdsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))qat_signature_ecdsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))qat_signature_ecdsa_verify },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))qat_signature_ecdsa_freectx },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))qat_signature_ecdsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))qat_signature_ecdsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))qat_ecdsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))qat_ecdsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))qat_ecdsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))qat_ecdsa_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))qat_ecdsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))qat_ecdsa_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))qat_ecdsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))qat_ecdsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))qat_ecdsa_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))qat_ecdsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))qat_ecdsa_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))qat_ecdsa_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))qat_ecdsa_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))qat_ecdsa_settable_ctx_md_params },
    {0, NULL}
};

#endif
