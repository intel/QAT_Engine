/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2026 Intel Corporation.
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
 * @file qat_prov_kmgmt_ec_utils.c
 *
 * This file contains the Qat provider EC Key Management implementation for
 * QAT_SW and QAT_HW operations
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define __USE_GNU

#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <assert.h>

#include "qat_provider.h"
#include "qat_prov_ec.h"
#include "qat_utils.h"
#include "qat_evp.h"
#include "e_qat.h"

#include "qat_prov_kmgmt_ec_utils.h"

#if defined(ENABLE_QAT_HW_ECDH) || defined(ENABLE_QAT_SW_ECDH)
static const OSSL_ITEM format_nameid_map[] = {
    { (int)POINT_CONVERSION_UNCOMPRESSED, OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED },
    { (int)POINT_CONVERSION_COMPRESSED, OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED },
    { (int)POINT_CONVERSION_HYBRID, OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID },
};

static const OSSL_ITEM encoding_nameid_map[] = {
    { OPENSSL_EC_EXPLICIT_CURVE, OSSL_PKEY_EC_ENCODING_EXPLICIT },
    { OPENSSL_EC_NAMED_CURVE, OSSL_PKEY_EC_ENCODING_GROUP },
};

static const OSSL_ITEM check_group_type_nameid_map[] = {
    { 0, OSSL_PKEY_EC_GROUP_CHECK_DEFAULT },
    { EC_FLAG_CHECK_NAMED_GROUP, OSSL_PKEY_EC_GROUP_CHECK_NAMED },
    { EC_FLAG_CHECK_NAMED_GROUP_NIST, OSSL_PKEY_EC_GROUP_CHECK_NAMED_NIST },
};

/* Mapping between a flag and a name */
static const OSSL_ITEM qat_encoding_nameid_map[] = {
    { OPENSSL_EC_EXPLICIT_CURVE, OSSL_PKEY_EC_ENCODING_EXPLICIT },
    { OPENSSL_EC_NAMED_CURVE, OSSL_PKEY_EC_ENCODING_GROUP },
};

static const OSSL_ITEM qat_check_group_type_nameid_map[] = {
    { 0, OSSL_PKEY_EC_GROUP_CHECK_DEFAULT },
    { EC_FLAG_CHECK_NAMED_GROUP, OSSL_PKEY_EC_GROUP_CHECK_NAMED },
    { EC_FLAG_CHECK_NAMED_GROUP_NIST, OSSL_PKEY_EC_GROUP_CHECK_NAMED_NIST },
};

static const OSSL_ITEM qat_format_nameid_map[] = {
    { (int)POINT_CONVERSION_UNCOMPRESSED,
           OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED },
    { (int)POINT_CONVERSION_COMPRESSED,
           OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED },
    { (int)POINT_CONVERSION_HYBRID, OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID },
};


OSSL_LIB_CTX *qat_keymgmt_ec_key_get_libctx(const EC_KEY *key)
{
    /*
     * EC_KEY_get0_libctx() is an internal OpenSSL API, not available in the
     * public headers.  Return NULL so callers fall back to the default library
     * context.
     *
     * TODO: wrap EC_KEY in a provider-owned keydata struct that carries
     * libctx/propq (similar to how the ECX keymgmt uses ECX_KEY) so that
     * operations on keys created in a non-default OSSL_LIB_CTX work correctly.
     */
    (void)key;
    return NULL;
}

const char *qat_ec_key_get0_propq(const EC_KEY *key)
{
    /* See comment in qat_keymgmt_ec_key_get_libctx(). */
    (void)key;
    return NULL;
}

int qat_ec_gen_set_group(void *genctx, const EC_GROUP *src)
{
    QAT_EC_GEN_CTX *gctx = genctx;
    EC_GROUP *group;

    group = EC_GROUP_dup(src);
    if (group == NULL) {
        QATerr(ERR_LIB_PROV, QAT_R_INVALID_CURVE);
        return 0;
    }
    EC_GROUP_free(gctx->gen_group);
    gctx->gen_group = group;
    return 1;
}

int qat_ec_gen_assign_group(EC_KEY *ec, EC_GROUP *group)
{
    if (group == NULL) {
        QATerr(ERR_LIB_PROV, QAT_R_NO_PARAMETERS_SET);
        return 0;
    }
    return EC_KEY_set_group(ec, group) > 0;
}

int qat_ec_encoding_name2id(const char *name)
{
    size_t i, sz;

    /* Return the default value if there is no name */
    if (name == NULL)
        return OPENSSL_EC_NAMED_CURVE;

    for (i = 0, sz = OSSL_NELEM(qat_encoding_nameid_map); i < sz; i++) {
        if (OPENSSL_strcasecmp(name, qat_encoding_nameid_map[i].ptr) == 0)
            return qat_encoding_nameid_map[i].id;
    }
    return -1;
}

int qat_ec_pt_format_name2id(const char *name)
{
    size_t i, sz;

    /* Return the default value if there is no name */
    if (name == NULL)
        return (int)POINT_CONVERSION_UNCOMPRESSED;

    for (i = 0, sz = OSSL_NELEM(qat_format_nameid_map); i < sz; i++) {
        if (OPENSSL_strcasecmp(name, qat_format_nameid_map[i].ptr) == 0)
            return qat_format_nameid_map[i].id;
    }
    return -1;
}

int qat_ec_check_group_type_name2id(const char *name)
{
    size_t i, sz;

    /* Return the default value if there is no name */
    if (name == NULL)
        return 0;

    for (i = 0, sz = OSSL_NELEM(qat_check_group_type_nameid_map); i < sz; i++) {
        if (OPENSSL_strcasecmp(name, qat_check_group_type_nameid_map[i].ptr) == 0)
            return qat_check_group_type_nameid_map[i].id;
    }
    return -1;
}

int qat_ec_gen_set_group_from_params(QAT_EC_GEN_CTX *gctx)
{
    int ret = 0;
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM *params = NULL;
    EC_GROUP *group = NULL;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
        return 0;

    if (gctx->encoding != NULL
        && !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_ENCODING,
                                            gctx->encoding, 0))
        goto err;

    if (gctx->pt_format != NULL
        && !OSSL_PARAM_BLD_push_utf8_string(bld,
                                            OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                            gctx->pt_format, 0))
        goto err;

    if (gctx->group_name != NULL) {
        if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                             gctx->group_name, 0))
            goto err;
        /* Ignore any other parameters if there is a group name */
        goto build;
    } else if (gctx->field_type != NULL) {
        if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_FIELD_TYPE,
                                             gctx->field_type, 0))
            goto err;
    } else {
        goto err;
    }
    if (gctx->p == NULL
        || gctx->a == NULL
        || gctx->b == NULL
        || gctx->order == NULL
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_P, gctx->p)
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_A, gctx->a)
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_B, gctx->b)
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_ORDER, gctx->order))
        goto err;

    if (gctx->cofactor != NULL
        && !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_COFACTOR,
                                   gctx->cofactor))
        goto err;

    if (gctx->seed != NULL
        && !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_EC_SEED,
                                             gctx->seed, gctx->seed_len))
        goto err;

    if (gctx->gen == NULL
        || !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_EC_GENERATOR,
                                             gctx->gen, gctx->gen_len))
        goto err;
build:
    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL)
        goto err;
    group = EC_GROUP_new_from_params(params, gctx->libctx, NULL);
    if (group == NULL)
        goto err;

    EC_GROUP_free(gctx->gen_group);
    gctx->gen_group = group;

    ret = 1;
err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

int qat_ec_set_ecdh_cofactor_mode(EC_KEY *ec, int mode)
{
    const EC_GROUP *ecg = EC_KEY_get0_group(ec);
    const BIGNUM *cofactor;
    /*
     * mode can be only 0 for disable, or 1 for enable here.
     *
     * This is in contrast with the same parameter on an ECDH EVP_PKEY_CTX that
     * also supports mode == -1 with the meaning of "reset to the default for
     * the associated key".
     */
    if (mode < 0 || mode > 1)
        return 0;

    if ((cofactor = EC_GROUP_get0_cofactor(ecg)) == NULL )
        return 0;

    /* ECDH cofactor mode has no effect if cofactor is 1 */
    if (BN_is_one(cofactor))
        return 1;

    if (mode == 1)
        EC_KEY_set_flags(ec, EC_FLAG_COFACTOR_ECDH);
    else if (mode == 0)
        EC_KEY_clear_flags(ec, EC_FLAG_COFACTOR_ECDH);

    return 1;
}

int qat_ec_set_check_group_type_from_name(EC_KEY *ec, const char *name)
{
    int flags = qat_ec_check_group_type_name2id(name);

    if (flags == -1)
        return 0;
    EC_KEY_clear_flags(ec, EC_FLAG_CHECK_NAMED_GROUP_MASK);
    EC_KEY_set_flags(ec, flags);
    return 1;
}

int qat_param_build_set_int(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                             const char *key, int num)
{
    if (bld != NULL)
        return OSSL_PARAM_BLD_push_int(bld, key, num);
    p = OSSL_PARAM_locate(p, key);
    if (p != NULL)
        return OSSL_PARAM_set_int(p, num);
    return 1;
}

int qat_param_build_set_utf8_string(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                     const char *key, const char *buf)
{
    if (bld != NULL)
        return OSSL_PARAM_BLD_push_utf8_string(bld, key, buf, 0);
    p = OSSL_PARAM_locate(p, key);
    if (p != NULL)
        return OSSL_PARAM_set_utf8_string(p, buf);
    return 1;
}

/*
 * Below two functions have dummy implementation
 * to support system openssl build as these functions
 * are not enabled to support binary field elliptic curves.
 * For source openssl, these curves will be off-loaded
 * to native openssl.
 */
int QAT_EC_GROUP_get_trinomial_basis(const EC_GROUP *group, unsigned int *k)
{
    return 1;
}

int QAT_EC_GROUP_get_pentanomial_basis(const EC_GROUP *group, unsigned int *k1,
                                   unsigned int *k2, unsigned int *k3)
{
    return 1;
}


int qat_ec_get_ecm_params(const EC_GROUP *group, OSSL_PARAM params[])
{
    int ret = 0, m;
    unsigned int k1 = 0, k2 = 0, k3 = 0;
    int basis_nid;
    const char *basis_name = NULL;
    int fid = EC_GROUP_get_field_type(group);

    if (fid != NID_X9_62_characteristic_two_field)
        return 1;

    basis_nid = EC_GROUP_get_basis_type(group);
    if (basis_nid == NID_X9_62_tpBasis)
        basis_name = SN_X9_62_tpBasis;
    else if (basis_nid == NID_X9_62_ppBasis)
        basis_name = SN_X9_62_ppBasis;
    else
        goto err;

    m = EC_GROUP_get_degree(group);
    if (!qat_param_build_set_int(NULL, params, OSSL_PKEY_PARAM_EC_CHAR2_M, m)
        || !qat_param_build_set_utf8_string(NULL, params,
                                             OSSL_PKEY_PARAM_EC_CHAR2_TYPE,
                                             basis_name))
        goto err;

    if (basis_nid == NID_X9_62_tpBasis) {
        if (!QAT_EC_GROUP_get_trinomial_basis(group, &k1)
            || !qat_param_build_set_int(NULL, params,
                                         OSSL_PKEY_PARAM_EC_CHAR2_TP_BASIS,
                                         (int)k1))
            goto err;
    } else {
        if (!QAT_EC_GROUP_get_pentanomial_basis(group, &k1, &k2, &k3)
            || !qat_param_build_set_int(NULL, params,
                                         OSSL_PKEY_PARAM_EC_CHAR2_PP_K1, (int)k1)
            || !qat_param_build_set_int(NULL, params,
                                         OSSL_PKEY_PARAM_EC_CHAR2_PP_K2, (int)k2)
            || !qat_param_build_set_int(NULL, params,
                                         OSSL_PKEY_PARAM_EC_CHAR2_PP_K3, (int)k3))
            goto err;
    }
    ret = 1;
err:
    return ret;
}

char *qat_ec_pt_format_id2name(int id)
{
    size_t i, sz;

    for (i = 0, sz = OSSL_NELEM(format_nameid_map); i < sz; i++) {
        if (id == (int)format_nameid_map[i].id)
            return format_nameid_map[i].ptr;
    }
    return NULL;
}

char *qat_ec_param_encoding_id2name(int id)
{
    size_t i, sz;

    for (i = 0, sz = OSSL_NELEM(encoding_nameid_map); i < sz; i++) {
        if (id == (int)encoding_nameid_map[i].id)
            return encoding_nameid_map[i].ptr;
    }
    return NULL;
}

int qat_param_build_set_bn(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                            const char *key, const BIGNUM *bn)
{
    if (bld != NULL)
        return OSSL_PARAM_BLD_push_BN(bld, key, bn);

    p = OSSL_PARAM_locate(p, key);
    if (p != NULL)
        return OSSL_PARAM_set_BN(p, bn) > 0;
    return 1;
}

int qat_param_build_set_octet_string(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                      const char *key,
                                      const unsigned char *data,
                                      size_t data_len)
{
    if (bld != NULL)
        return OSSL_PARAM_BLD_push_octet_string(bld, key, data, data_len);

    p = OSSL_PARAM_locate(p, key);
    if (p != NULL)
        return OSSL_PARAM_set_octet_string(p, data, data_len);
    return 1;
}

int qat_ec_group_explicit_todata(const EC_GROUP *group, OSSL_PARAM_BLD *tmpl,
                                    OSSL_PARAM params[], BN_CTX *bnctx,
                                    unsigned char **genbuf)
{
    int ret = 0, fid;
    const char *field_type;
    const OSSL_PARAM *param = NULL;
    const OSSL_PARAM *param_p = NULL;
    const OSSL_PARAM *param_a = NULL;
    const OSSL_PARAM *param_b = NULL;

    fid = EC_GROUP_get_field_type(group);

    if (fid == NID_X9_62_prime_field) {
        field_type = SN_X9_62_prime_field;
    } else if (fid == NID_X9_62_characteristic_two_field) {
        field_type = SN_X9_62_characteristic_two_field;
    } else {
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_FIELD);
        return 0;
    }

    param_p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_P);
    param_a = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_A);
    param_b = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_B);
    if (tmpl != NULL || param_p != NULL || param_a != NULL || param_b != NULL) {
        BIGNUM *p = BN_CTX_get(bnctx);
        BIGNUM *a = BN_CTX_get(bnctx);
        BIGNUM *b = BN_CTX_get(bnctx);

        if (b == NULL) {
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            goto err;
        }

        if (!EC_GROUP_get_curve(group, p, a, b, bnctx)) {
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_CURVE);
                        goto err;
        }
        if (!qat_param_build_set_bn(tmpl, params, OSSL_PKEY_PARAM_EC_P, p)
            || !qat_param_build_set_bn(tmpl, params, OSSL_PKEY_PARAM_EC_A, a)
            || !qat_param_build_set_bn(tmpl, params, OSSL_PKEY_PARAM_EC_B, b)) {
            ERR_raise(ERR_LIB_EC, ERR_R_CRYPTO_LIB);
            goto err;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_ORDER);
    if (tmpl != NULL || param != NULL) {
        const BIGNUM *order = EC_GROUP_get0_order(group);

        if (order == NULL) {
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_GROUP_ORDER);
            goto err;
        }
        if (!qat_param_build_set_bn(tmpl, params, OSSL_PKEY_PARAM_EC_ORDER,
                                    order)) {
            ERR_raise(ERR_LIB_EC, ERR_R_CRYPTO_LIB);
            goto err;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_FIELD_TYPE);
    if (tmpl != NULL || param != NULL) {
        if (!qat_param_build_set_utf8_string(tmpl, params,
                                              OSSL_PKEY_PARAM_EC_FIELD_TYPE,
                                              field_type)) {
            ERR_raise(ERR_LIB_EC, ERR_R_CRYPTO_LIB);
            goto err;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_GENERATOR);
    if (tmpl != NULL || param != NULL) {
        size_t genbuf_len;
        const EC_POINT *genpt = EC_GROUP_get0_generator(group);
        point_conversion_form_t genform = EC_GROUP_get_point_conversion_form(group);

        if (genpt == NULL) {
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_GENERATOR);
            goto err;
        }
        genbuf_len = EC_POINT_point2buf(group, genpt, genform, genbuf, bnctx);
        if (genbuf_len == 0) {
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_GENERATOR);
            goto err;
        }
        if (!qat_param_build_set_octet_string(tmpl, params,
                                               OSSL_PKEY_PARAM_EC_GENERATOR,
                                               *genbuf, genbuf_len)) {
            ERR_raise(ERR_LIB_EC, ERR_R_CRYPTO_LIB);
            goto err;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_COFACTOR);
    if (tmpl != NULL || param != NULL) {
        const BIGNUM *cofactor = EC_GROUP_get0_cofactor(group);

        if (cofactor != NULL
            && !qat_param_build_set_bn(tmpl, params,
                                        OSSL_PKEY_PARAM_EC_COFACTOR, cofactor)) {
            ERR_raise(ERR_LIB_EC, ERR_R_CRYPTO_LIB);
            goto err;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_SEED);
    if (tmpl != NULL || param != NULL) {
        unsigned char *seed = EC_GROUP_get0_seed(group);
        size_t seed_len = EC_GROUP_get_seed_len(group);

        if (seed != NULL
            && seed_len > 0
            && !qat_param_build_set_octet_string(tmpl, params,
                                                  OSSL_PKEY_PARAM_EC_SEED,
                                                  seed, seed_len)) {
            ERR_raise(ERR_LIB_EC, ERR_R_CRYPTO_LIB);
            goto err;
        }
    }
    ret = 1;
err:
    return ret;
}

int qat_ec_group_todata(const EC_GROUP *group, OSSL_PARAM_BLD *tmpl,
                         OSSL_PARAM params[], OSSL_LIB_CTX *libctx,
                         const char *propq,
                         BN_CTX *bnctx, unsigned char **genbuf)
{
    int ret = 0, curve_nid, encoding_flag;
    const char *encoding_name, *pt_form_name;
    point_conversion_form_t genform;

    if (group == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    genform = EC_GROUP_get_point_conversion_form(group);
    pt_form_name = qat_ec_pt_format_id2name(genform);
    if (pt_form_name == NULL
        || !qat_param_build_set_utf8_string(
                tmpl, params,
                OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, pt_form_name)) {
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_FORM);
        return 0;
    }
    encoding_flag = EC_GROUP_get_asn1_flag(group) & OPENSSL_EC_NAMED_CURVE;
    encoding_name = qat_ec_param_encoding_id2name(encoding_flag);
    if (encoding_name == NULL
        || !qat_param_build_set_utf8_string(tmpl, params,
                                             OSSL_PKEY_PARAM_EC_ENCODING,
                                             encoding_name)) {
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
        return 0;
    }

    if (!qat_param_build_set_int(tmpl, params,
                                  OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS,
                                  EC_GROUP_get_curve_name(group) == NID_undef ? 1 : 0))
        return 0;

    curve_nid = EC_GROUP_get_curve_name(group);

    /*
     * Get the explicit parameters in these two cases:
     * - We do not have a template, i.e. specific parameters are requested
     * - The curve is not a named curve
     */
    if (tmpl == NULL || curve_nid == NID_undef)
        if (!qat_ec_group_explicit_todata(group, tmpl, params, bnctx, genbuf))
            goto err;

    if (curve_nid != NID_undef) {
        /* Named curve */
        const char *curve_name = OSSL_EC_curve_nid2name(curve_nid);

        if (curve_name == NULL
            || !qat_param_build_set_utf8_string(tmpl, params,
                                                 OSSL_PKEY_PARAM_GROUP_NAME,
                                                 curve_name)) {
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_CURVE);
            goto err;
        }
    }
    ret = 1;
err:
    return ret;
}

int qat_param_build_set_bn_pad(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                const char *key, const BIGNUM *bn,  size_t sz)
{
    if (bld != NULL)
        return OSSL_PARAM_BLD_push_BN_pad(bld, key, bn, sz);
    p = OSSL_PARAM_locate(p, key);
    if (p != NULL) {
        if (sz > p->data_size) {
            ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_SMALL_BUFFER);
            return 0;
        }
        p->data_size = sz;
        return OSSL_PARAM_set_BN(p, bn);
    }
    return 1;
}

/*
 * Callers of qat_key_to_params MUST make sure that domparams_to_params is also
 * called!
 *
 * This function only exports the bare keypair, domain parameters and other
 * parameters are exported separately.
 */
int qat_key_to_params(const EC_KEY *eckey, OSSL_PARAM_BLD *tmpl,
                  OSSL_PARAM params[], int include_private,
                  unsigned char **pub_key)
{
    BIGNUM *x = NULL, *y = NULL;
    const BIGNUM *priv_key = NULL;
    const EC_POINT *pub_point = NULL;
    const EC_GROUP *ecg = NULL;
    size_t pub_key_len = 0;
    int ret = 0;
    BN_CTX *bnctx = NULL;

    if (eckey == NULL
        || (ecg = EC_KEY_get0_group(eckey)) == NULL)
        return 0;

    priv_key = EC_KEY_get0_private_key(eckey);
    pub_point = EC_KEY_get0_public_key(eckey);

    if (pub_point != NULL) {
        OSSL_PARAM *p = NULL, *px = NULL, *py = NULL;
        /*
         * EC_POINT_point2buf() can generate random numbers in some
         * implementations so we need to ensure we use the correct libctx.
         */
        bnctx = BN_CTX_new_ex(qat_keymgmt_ec_key_get_libctx(eckey));
        if (bnctx == NULL)
            goto err;


        /* If we are doing a get then check first before decoding the point */
        if (tmpl == NULL) {
            p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
            px = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_PUB_X);
            py = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_PUB_Y);
        }

        if (p != NULL || tmpl != NULL) {
            /* convert pub_point to a octet string according to the SECG standard */
            point_conversion_form_t format = EC_KEY_get_conv_form(eckey);

            if ((pub_key_len = EC_POINT_point2buf(ecg, pub_point,
                                                  format,
                                                  pub_key, bnctx)) == 0
                || !qat_param_build_set_octet_string(tmpl, p,
                                                      OSSL_PKEY_PARAM_PUB_KEY,
                                                      *pub_key, pub_key_len))
                goto err;
        }
        if (px != NULL || py != NULL) {
            if (px != NULL) {
                x = BN_CTX_get(bnctx);
                if (x == NULL)
                    goto err;
            }
            if (py != NULL) {
                y = BN_CTX_get(bnctx);
                if (y == NULL)
                    goto err;
            }

            if (!EC_POINT_get_affine_coordinates(ecg, pub_point, x, y, bnctx))
                goto err;
            if (px != NULL
                && !qat_param_build_set_bn(tmpl, px,
                                            OSSL_PKEY_PARAM_EC_PUB_X, x))
                goto err;
            if (py != NULL
                && !qat_param_build_set_bn(tmpl, py,
                                            OSSL_PKEY_PARAM_EC_PUB_Y, y))
                goto err;
        }
    }

    if (priv_key != NULL && include_private) {
        size_t sz;
        int ecbits;

        /*
         * Key import/export should never leak the bit length of the secret
         * scalar in the key.
         *
         * For this reason, on export we use padded BIGNUMs with fixed length.
         *
         * When importing we also should make sure that, even if short lived,
         * the newly created BIGNUM is marked with the BN_FLG_CONSTTIME flag as
         * soon as possible, so that any processing of this BIGNUM might opt for
         * constant time implementations in the backend.
         *
         * Setting the BN_FLG_CONSTTIME flag alone is never enough, we also have
         * to preallocate the BIGNUM internal buffer to a fixed public size big
         * enough that operations performed during the processing never trigger
         * a realloc which would leak the size of the scalar through memory
         * accesses.
         *
         * Fixed Length
         * ------------
         *
         * The order of the large prime subgroup of the curve is our choice for
         * a fixed public size, as that is generally the upper bound for
         * generating a private key in EC cryptosystems and should fit all valid
         * secret scalars.
         *
         * For padding on export we just use the bit length of the order
         * converted to bytes (rounding up).
         *
         * For preallocating the BIGNUM storage we look at the number of "words"
         * required for the internal representation of the order, and we
         * preallocate 2 extra "words" in case any of the subsequent processing
         * might temporarily overflow the order length.
         */
        ecbits = EC_GROUP_order_bits(ecg);
        if (ecbits <= 0)
            goto err;
        sz = (ecbits + 7) / 8;

        if (!qat_param_build_set_bn_pad(tmpl, params,
                                         OSSL_PKEY_PARAM_PRIV_KEY,
                                         priv_key, sz))
            goto err;
    }
    ret = 1;
 err:
    BN_CTX_free(bnctx);
    return ret;
}

char *qat_ec_check_group_type_id2name(int id)
{
    size_t i, sz;

    for (i = 0, sz = OSSL_NELEM(check_group_type_nameid_map); i < sz; i++) {
        if (id == (int)check_group_type_nameid_map[i].id)
            return check_group_type_nameid_map[i].ptr;
    }
    return NULL;
}

int qat_otherparams_to_params(const EC_KEY *ec, OSSL_PARAM_BLD *tmpl,
                          OSSL_PARAM params[])
{
    int ecdh_cofactor_mode = 0, group_check = 0;
    const char *name = NULL;
    point_conversion_form_t format;

    if (ec == NULL)
        return 0;

    format = EC_KEY_get_conv_form(ec);
    name = qat_ec_pt_format_id2name((int)format);
    if (name != NULL
        && !qat_param_build_set_utf8_string(tmpl, params,
                                             OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                             name))
        return 0;

    group_check = EC_KEY_get_flags(ec) & EC_FLAG_CHECK_NAMED_GROUP_MASK;
    name = qat_ec_check_group_type_id2name(group_check);
    if (name != NULL
        && !qat_param_build_set_utf8_string(tmpl, params,
                                             OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE,
                                             name))
        return 0;

    if ((EC_KEY_get_enc_flags(ec) & EC_PKEY_NO_PUBKEY) != 0
            && !qat_param_build_set_int(tmpl, params,
                                         OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, 0))
        return 0;

    ecdh_cofactor_mode =
        (EC_KEY_get_flags(ec) & EC_FLAG_COFACTOR_ECDH) ? 1 : 0;
    return qat_param_build_set_int(tmpl, params,
                                    OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
                                    ecdh_cofactor_mode);
}

int qat_ec_encoding_param2id(const OSSL_PARAM *p, int *id)
{
    const char *name = NULL;
    int status = 0;

    switch (p->data_type) {
    case OSSL_PARAM_UTF8_STRING:
        /* The OSSL_PARAM functions have no support for this */
        name = p->data;
        status = (name != NULL);
        break;
    case OSSL_PARAM_UTF8_PTR:
        status = OSSL_PARAM_get_utf8_ptr(p, &name);
        break;
    }
    if (status) {
        int i = qat_ec_encoding_name2id(name);

        if (i >= 0) {
            *id = i;
            return 1;
        }
    }
    return 0;
}

int qat_ec_pt_format_param2id(const OSSL_PARAM *p, int *id)
{
    const char *name = NULL;
    int status = 0;

    switch (p->data_type) {
    case OSSL_PARAM_UTF8_STRING:
        /* The OSSL_PARAM functions have no support for this */
        name = p->data;
        status = (name != NULL);
        break;
    case OSSL_PARAM_UTF8_PTR:
        status = OSSL_PARAM_get_utf8_ptr(p, &name);
        break;
    }
    if (status) {
        int i = qat_ec_pt_format_name2id(name);

        if (i >= 0) {
            *id = i;
            return 1;
        }
    }
    return 0;
}

int qat_ec_group_set_params(EC_GROUP *group, const OSSL_PARAM params[])
{
    int encoding_flag = -1, format = -1;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT);
    if (p != NULL) {
        if (!qat_ec_pt_format_param2id(p, &format)) {
            return 0;
        }
        EC_GROUP_set_point_conversion_form(group, format);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_ENCODING);
    if (p != NULL) {
        if (!qat_ec_encoding_param2id(p, &encoding_flag)) {
            return 0;
        }
        EC_GROUP_set_asn1_flag(group, encoding_flag);
    }
    /* Optional seed */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_SEED);
    if (p != NULL) {
        /* The seed is allowed to be NULL */
        if (p->data_type != OSSL_PARAM_OCTET_STRING
            || !EC_GROUP_set_seed(group, p->data, p->data_size)) {
            return 0;
        }
    }
    return 1;
}

int qat_ec_set_check_group_type_from_param(EC_KEY *ec, const OSSL_PARAM *p)
{
    const char *name = NULL;
    int status = 0;

    switch (p->data_type) {
    case OSSL_PARAM_UTF8_STRING:
        name = p->data;
        status = (name != NULL);
        break;
    case OSSL_PARAM_UTF8_PTR:
        status = OSSL_PARAM_get_utf8_ptr(p, &name);
        break;
    }
    if (status)
        return qat_ec_set_check_group_type_from_name(ec, name);
    return 0;
}

int qat_ec_key_group_check_fromdata(EC_KEY *ec, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE);
    if (p != NULL)
        return qat_ec_set_check_group_type_from_param(ec, p);
    return 1;
}

int qat_ec_key_point_format_fromdata(EC_KEY *ec, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    int format = -1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT);
    if (p != NULL) {
        if (!qat_ec_pt_format_param2id(p, &format)) {
            return 0;
        }
        EC_KEY_set_conv_form(ec, format);
    }
    return 1;
}

int qat_ec_set_include_public(EC_KEY *ec, int include)
{
    int flags = EC_KEY_get_enc_flags(ec);

    if (!include)
        flags |= EC_PKEY_NO_PUBKEY;
    else
        flags &= ~EC_PKEY_NO_PUBKEY;
    EC_KEY_set_enc_flags(ec, flags);
    return 1;
}

int qat_ec_key_otherparams_fromdata(EC_KEY *ec, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if (ec == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH);
    if (p != NULL) {
        int mode;

        if (!OSSL_PARAM_get_int(p, &mode)
            || !qat_ec_set_ecdh_cofactor_mode(ec, mode))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC);
    if (p != NULL) {
        int include = 1;

        if (!OSSL_PARAM_get_int(p, &include)
            || !qat_ec_set_include_public(ec, include))
            return 0;
    }
    if (!qat_ec_key_point_format_fromdata(ec, params))
        return 0;
    if (!qat_ec_key_group_check_fromdata(ec, params))
        return 0;
    return 1;
}

int qat_common_check_sm2(const EC_KEY *ec, int sm2_wanted)
{
    const EC_GROUP *ecg = NULL;

    /*
     * sm2_wanted: import the keys or domparams only on SM2 Curve
     * !sm2_wanted: import the keys or domparams only not on SM2 Curve
     */
    if ((ecg = EC_KEY_get0_group(ec)) == NULL
        || (sm2_wanted ^ (EC_GROUP_get_curve_name(ecg) == NID_sm2)))
        return 0;
    return 1;
}

int qat_ec_group_fromdata(EC_KEY *ec, const OSSL_PARAM params[])
{
    int ok = 0;
    EC_GROUP *group = NULL;

    if (ec == NULL)
        return 0;

     group = EC_GROUP_new_from_params(params, qat_keymgmt_ec_key_get_libctx(ec),
                                      qat_ec_key_get0_propq(ec));

    if (!EC_KEY_set_group(ec, group))
        goto err;
    ok = 1;
err:
    EC_GROUP_free(group);
    return ok;
}

int qat_bn_get_top(const BIGNUM *a)
{
    return a->top;
}

/* This is used by qat_bn_expand2() */
/* The caller MUST check that words > b->dmax before calling this */
BN_ULONG *qat_bn_expand_internal(const BIGNUM *b, int words)
{
    BN_ULONG *a = NULL;

    if (words > (INT_MAX / (4 * BN_BITS2))) {
        ERR_raise(ERR_LIB_BN, BN_R_BIGNUM_TOO_LONG);
        return NULL;
    }
    if (BN_get_flags(b, BN_FLG_STATIC_DATA)) {
        ERR_raise(ERR_LIB_BN, BN_R_EXPAND_ON_STATIC_BIGNUM_DATA);
        return NULL;
    }
    if (BN_get_flags(b, BN_FLG_SECURE))
        a = OPENSSL_secure_zalloc(words * sizeof(*a));
    else
        a = OPENSSL_zalloc(words * sizeof(*a));
    if (a == NULL)
        return NULL;

    assert(b->top <= words);
    if (b->top > 0)
        memcpy(a, b->d, sizeof(*a) * b->top);

    return a;
}

void qat_bn_free_d(BIGNUM *a, int clear)
{
    if (BN_get_flags(a, BN_FLG_SECURE))
        OPENSSL_secure_clear_free(a->d, a->dmax * sizeof(a->d[0]));
    else if (clear != 0)
        OPENSSL_clear_free(a->d, a->dmax * sizeof(a->d[0]));
    else
        OPENSSL_free(a->d);
}

/*
 * This is an internal function that should not be used in applications. It
 * ensures that 'b' has enough room for a 'words' word number and initialises
 * any unused part of b->d with leading zeros. It is mostly used by the
 * various BIGNUM routines. If there is an error, NULL is returned. If not,
 * 'b' is returned.
 */
BIGNUM *qat_bn_expand2(BIGNUM *b, int words)
{
    if (words > b->dmax) {
        BN_ULONG *a = qat_bn_expand_internal(b, words);
        if (!a)
            return NULL;
        if (b->d != NULL)
            qat_bn_free_d(b, 1);
        b->d = a;
        b->dmax = words;
    }

    return b;
}

BIGNUM *qat_bn_wexpand(BIGNUM *a, int words)
{
    return (words <= a->dmax) ? a : qat_bn_expand2(a, words);
}

/*
 * Callers of qat_ec_key_fromdata MUST make sure that ec_key_params_fromdata has
 * been called before!
 *
 * This function only gets the bare keypair, domain parameters and other
 * parameters are treated separately, and domain parameters are required to
 * define a keypair.
 */

int qat_ec_key_fromdata(EC_KEY *ec, const OSSL_PARAM params[], int include_private)
{
    if (ec == NULL)
        return 0;

    const EC_GROUP *ecg = EC_KEY_get0_group(ec);
    if (ecg == NULL)
        return 0;

    const OSSL_PARAM *param_pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    const OSSL_PARAM *param_priv_key = include_private
        ? OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY)
        : NULL;

    BN_CTX *ctx = BN_CTX_new_ex(qat_keymgmt_ec_key_get_libctx(ec));
    if (ctx == NULL)
        return 0;

    EC_POINT *pub_point = NULL;
    BIGNUM *priv_key = NULL;
    unsigned char *pub_key = NULL;
    size_t pub_key_len = 0;
    int ok = 0;

    /* Handle public key */
    if (param_pub_key != NULL) {
        if (!OSSL_PARAM_get_octet_string(param_pub_key, (void **)&pub_key, 0, &pub_key_len) ||
            (pub_point = EC_POINT_new(ecg)) == NULL ||
            !EC_POINT_oct2point(ecg, pub_point, pub_key, pub_key_len, ctx)) {
            goto cleanup;
        }
    }

    /* Handle private key */
    if (param_priv_key != NULL && include_private) {
        const BIGNUM *order = EC_GROUP_get0_order(ecg);
        if (order == NULL || BN_is_zero(order))
            goto cleanup;

        int fixed_words = qat_bn_get_top(order) + 2;

        priv_key = BN_secure_new();
        if (priv_key == NULL || qat_bn_wexpand(priv_key, fixed_words) == NULL) {
            goto cleanup;
        }
        BN_set_flags(priv_key, BN_FLG_CONSTTIME);

        if (!OSSL_PARAM_get_BN(param_priv_key, &priv_key))
            goto cleanup;
    }

    /* Set private key */
    if (priv_key != NULL && !EC_KEY_set_private_key(ec, priv_key))
        goto cleanup;

    /* Set public key */
    if (pub_point != NULL && !EC_KEY_set_public_key(ec, pub_point))
        goto cleanup;

    ok = 1;

cleanup:
    BN_CTX_free(ctx);
    BN_clear_free(priv_key);
    OPENSSL_free(pub_key);
    EC_POINT_free(pub_point);
    return ok;
}


/*
 * Check the range of the EC public key.
 * See SP800-56A R3 Section 5.6.2.3.3 (Part 2)
 * i.e.
 *  - If q = odd prime p: Verify that xQ and yQ are integers in the
 *    interval[0, p - 1], OR
 *  - If q = 2m: Verify that xQ and yQ are bit strings of length m bits.
 * Returns 1 if the public key has a valid range, otherwise it returns 0.
 */
int qat_ec_key_public_range_check(BN_CTX *ctx, const EC_KEY *key)
{
    int ret = 0;
    BIGNUM *x, *y;

    if (key == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *pub_key = EC_KEY_get0_public_key(key);

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (y == NULL)
        goto err;

    if (!EC_POINT_get_affine_coordinates(group, pub_key, x, y, ctx))
        goto err;

    if (EC_GROUP_get_field_type(group) == NID_X9_62_prime_field) {
        const BIGNUM *field = EC_GROUP_get0_field(group);
        if (BN_is_negative(x)
            || BN_cmp(x, field) >= 0
            || BN_is_negative(y)
            || BN_cmp(y, field) >= 0) {
            goto err;
        }
    } else {
        int m = EC_GROUP_get_degree(group);
        if (BN_num_bits(x) > m || BN_num_bits(y) > m) {
            goto err;
        }
    }
    ret = 1;
err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * ECC Partial Public-Key Validation as specified in SP800-56A R3
 * Section 5.6.2.3.4 ECC Partial Public-Key Validation Routine.
 */
int qat_ec_key_public_check_quick(const EC_KEY *eckey, BN_CTX *ctx)
{
    if (eckey == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    const EC_POINT *pub_key = EC_KEY_get0_public_key(eckey);

    if (group == NULL || pub_key == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* 5.6.2.3.3 (Step 1): Q != infinity */
    if (EC_POINT_is_at_infinity(group, pub_key)) {
        ERR_raise(ERR_LIB_EC, EC_R_POINT_AT_INFINITY);
        return 0;
    }

    /* 5.6.2.3.3 (Step 2) Test if the public key is in range */
    if (!qat_ec_key_public_range_check(ctx, eckey)) {
        ERR_raise(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        return 0;
    }

    /* 5.6.2.3.3 (Step 3) is the pub_key on the elliptic curve */
    if (EC_POINT_is_on_curve(group, pub_key, ctx) <= 0) {
        ERR_raise(ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE);
        return 0;
    }
    return 1;
}

/*
 * ECC Key validation as specified in SP800-56A R3.
 * Section 5.6.2.3.3 ECC Full Public-Key Validation Routine.
 */
int qat_ec_key_public_check(const EC_KEY *eckey, BN_CTX *ctx)
{
    int ret = 0;
    EC_POINT *point = NULL;
    const BIGNUM *order = NULL;
    const EC_GROUP *group = NULL;
    const EC_POINT *pub_key = NULL;
    const BIGNUM *cofactor = NULL;

    if (!qat_ec_key_public_check_quick(eckey, ctx))
        return 0;

    /* eckey is non-NULL after the quick check above. */
    group = EC_KEY_get0_group(eckey);
    pub_key = EC_KEY_get0_public_key(eckey);
    cofactor = EC_GROUP_get0_cofactor(group);

    if (cofactor != NULL && BN_is_one(cofactor)) {
        /* Skip the unnecessary expensive computation for curves with cofactor of 1. */
        return 1;
    }

    point = EC_POINT_new(group);
    if (point == NULL)
        return 0;

    order = EC_GROUP_get0_order(group);
    if (BN_is_zero(order)) {
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_GROUP_ORDER);
        goto err;
    }
    /* 5.6.2.3.3 (Step 4) : pub_key * order is the point at infinity. */
    if (!EC_POINT_mul(group, point, NULL, pub_key, order, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }
    if (!EC_POINT_is_at_infinity(group, point)) {
        ERR_raise(ERR_LIB_EC, EC_R_WRONG_ORDER);
        goto err;
    }
    ret = 1;
err:
    EC_POINT_free(point);
    return ret;
}

/*
 * ECC Key validation as specified in SP800-56A R3.
 * Section 5.6.2.1.2 Owner Assurance of Private-Key Validity
 * The private key is in the range [1, order-1]
 */
int qat_ec_key_private_check(const EC_KEY *eckey)
{
    const EC_GROUP *group = NULL;
    const BIGNUM *priv_key = NULL;

    if (eckey == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    group = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);

    if (group == NULL || priv_key == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (BN_cmp(priv_key, BN_value_one()) < 0
        || BN_cmp(priv_key, EC_GROUP_get0_order(group)) >= 0) {
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_PRIVATE_KEY);
        return 0;
    }
    return 1;
}

/*
 * ECC Key validation as specified in SP800-56A R3.
 * Section 5.6.2.1.4 Owner Assurance of Pair-wise Consistency (b)
 * Check if generator * priv_key = pub_key
 */
int qat_ec_key_pairwise_check(const EC_KEY *eckey, BN_CTX *ctx)
{
    int ret = 0;
    EC_POINT *point = NULL;
    const EC_GROUP *group = NULL;
    const EC_POINT *pub_key = NULL;
    const BIGNUM *priv_key = NULL;

    if (eckey == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    group = EC_KEY_get0_group(eckey);
    pub_key = EC_KEY_get0_public_key(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);

    if (group == NULL || pub_key == NULL || priv_key == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    point = EC_POINT_new(group);
    if (point == NULL)
        goto err;

    if (!EC_POINT_mul(group, point, priv_key, NULL, NULL, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }
    if (EC_POINT_cmp(group, point, pub_key, ctx) != 0) {
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_PRIVATE_KEY);
        goto err;
    }
    ret = 1;
err:
    EC_POINT_free(point);
    return ret;
}
#endif /* defined(ENABLE_QAT_HW_ECDH) || defined(ENABLE_QAT_SW_ECDH) */
