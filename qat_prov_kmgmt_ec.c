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

/*****************************************************************************
 * @file qat_provider_kmgmt_ec.c
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
#include "qat_provider.h"
#include "qat_prov_ec.h"
#include "qat_utils.h"
#include "qat_evp.h"
#include "e_qat.h"

#ifdef QAT_HW
# include "qat_hw_ec.h"
#endif

#ifdef QAT_SW
# include "qat_sw_ec.h"
#endif

#define COPY_INT_PARAM(params, key, val)                                       \
p = OSSL_PARAM_locate_const(params, key);                                      \
if (p != NULL && !OSSL_PARAM_get_int(p, &val))                                 \
    goto err;

#define COPY_UTF8_PARAM(params, key, val)                                      \
p = OSSL_PARAM_locate_const(params, key);                                      \
if (p != NULL) {                                                               \
    if (p->data_type != OSSL_PARAM_UTF8_STRING)                                \
        goto err;                                                              \
    OPENSSL_free(val);                                                         \
    val = OPENSSL_strdup(p->data);                                             \
    if (val == NULL)                                                           \
        goto err;                                                              \
}

#define COPY_OCTET_PARAM(params, key, val, len)                                \
p = OSSL_PARAM_locate_const(params, key);                                      \
if (p != NULL) {                                                               \
    if (p->data_type != OSSL_PARAM_OCTET_STRING)                               \
        goto err;                                                              \
    OPENSSL_free(val);                                                         \
    len = p->data_size;                                                        \
    val = OPENSSL_memdup(p->data, p->data_size);                               \
    if (val == NULL)                                                           \
        goto err;                                                              \
}

#define COPY_BN_PARAM(params, key, bn)                                         \
p = OSSL_PARAM_locate_const(params, key);                                      \
if (p != NULL) {                                                               \
    if (bn == NULL)                                                            \
        bn = BN_new();                                                         \
    if (bn == NULL || !OSSL_PARAM_get_BN(p, &bn))                              \
        goto err;                                                              \
}

typedef struct{
    int id; /* libcrypto internal */
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;

    CRYPTO_REF_COUNT references;
#if OPENSSL_VERSION_NUMBER < 0x30200000
    CRYPTO_RWLOCK *lock;
#endif
    /* Constructor(s), destructor, information */
    OSSL_FUNC_keymgmt_new_fn *new;
    OSSL_FUNC_keymgmt_free_fn *free;
    OSSL_FUNC_keymgmt_get_params_fn *get_params;
    OSSL_FUNC_keymgmt_gettable_params_fn *gettable_params;
    OSSL_FUNC_keymgmt_set_params_fn *set_params;
    OSSL_FUNC_keymgmt_settable_params_fn *settable_params;

    /* Generation, a complex constructor */
    OSSL_FUNC_keymgmt_gen_init_fn *gen_init;
    OSSL_FUNC_keymgmt_gen_set_template_fn *gen_set_template;
    OSSL_FUNC_keymgmt_gen_set_params_fn *gen_set_params;
    OSSL_FUNC_keymgmt_gen_settable_params_fn *gen_settable_params;
    OSSL_FUNC_keymgmt_gen_fn *gen;
    OSSL_FUNC_keymgmt_gen_cleanup_fn *gen_cleanup;
    OSSL_FUNC_keymgmt_load_fn *load;

    /* Key object checking */
    OSSL_FUNC_keymgmt_query_operation_name_fn *query_operation_name;
    OSSL_FUNC_keymgmt_has_fn *has;
    OSSL_FUNC_keymgmt_validate_fn *validate;
    OSSL_FUNC_keymgmt_match_fn *match;

    /* Import and export routines */
    OSSL_FUNC_keymgmt_import_fn *import;
    OSSL_FUNC_keymgmt_import_types_fn *import_types;
# if OPENSSL_VERSION_NUMBER >= 0x30200000
    OSSL_FUNC_keymgmt_import_types_ex_fn *import_types_ex;
# endif
    OSSL_FUNC_keymgmt_export_fn *export;
    OSSL_FUNC_keymgmt_export_types_fn *export_types;
# if OPENSSL_VERSION_NUMBER >= 0x30200000
    OSSL_FUNC_keymgmt_export_types_ex_fn *export_types_ex;
# endif
    OSSL_FUNC_keymgmt_dup_fn *dup;

} QAT_EC_KEYMGMT;

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *group_name;
    char *encoding;
    char *pt_format;
    char *group_check;
    char *field_type;
    BIGNUM *p, *a, *b, *order, *cofactor;
    unsigned char *gen, *seed;
    size_t gen_len, seed_len;
    int selection;
    int ecdh_mode;
    EC_GROUP *gen_group;
}QAT_EC_GEN_CTX;

#if defined(ENABLE_QAT_HW_ECDH) || defined(ENABLE_QAT_SW_ECDH)
static QAT_EC_KEYMGMT get_default_keymgmt()
{
    static QAT_EC_KEYMGMT s_keymgmt;
    static int initialized = 0;
    if (!initialized) {
        QAT_EC_KEYMGMT *keymgmt = (QAT_EC_KEYMGMT *)EVP_KEYMGMT_fetch(NULL, "EC", "provider=default");
        if (keymgmt) {
            s_keymgmt = *keymgmt;
            EVP_KEYMGMT_free((EVP_KEYMGMT *)keymgmt);
            initialized = 1;
        } else {
            WARN("EVP_KEYMGMT_fetch from default provider failed");
        }
    }
    return s_keymgmt;
}

EC_KEY *qat_ec_key_new(OSSL_LIB_CTX *libctx, const char *propq)
{
    EC_KEY *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        QATerr(ERR_LIB_EC, QAT_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->libctx = libctx;
    if (propq != NULL) {
        ret->propq = OPENSSL_strdup(propq);
        if (ret->propq == NULL) {
            QATerr(ERR_LIB_EC, QAT_R_MALLOC_FAILURE);
            goto err;
        }
    }
# if OPENSSL_VERSION_NUMBER < 0x30200000
    ret->references = 1;

    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        QATerr(ERR_LIB_EC, QAT_R_MALLOC_FAILURE);
        goto err;
    }
# else
    ret->references.val = 1;
# endif
    ret->meth = EC_KEY_get_default_method();

    ret->conv_form = POINT_CONVERSION_UNCOMPRESSED;

    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_EC_KEY, ret, &ret->ex_data)) {
        goto err;
    }

    if (ret->meth->init != NULL && ret->meth->init(ret) == 0) {
        QATerr(ERR_LIB_EC, QAT_R_INIT_FAIL);
        goto err;
    }
    return ret;

 err:
    EC_KEY_free(ret);
    return NULL;
}

static void *qat_keymgmt_ec_newdata(void *provctx)
{
    if (!qat_prov_is_running())
        return NULL;
    return qat_ec_key_new(prov_libctx_of(provctx), NULL);
}

static const char *qat_keymgmt_ec_query_operation_name(int operation_id)
{
    typedef const char* (*fun_ptr)(int);
    fun_ptr fun = get_default_keymgmt().query_operation_name;
    if (!fun)
        return NULL;
    return fun(operation_id);
}

static int qat_keymgmt_ec_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    int ret = 0;
    QAT_EC_GEN_CTX *gctx = genctx;
    const OSSL_PARAM *p;

    COPY_INT_PARAM(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, gctx->ecdh_mode);

    COPY_UTF8_PARAM(params, OSSL_PKEY_PARAM_GROUP_NAME, gctx->group_name);
    COPY_UTF8_PARAM(params, OSSL_PKEY_PARAM_EC_FIELD_TYPE, gctx->field_type);
    COPY_UTF8_PARAM(params, OSSL_PKEY_PARAM_EC_ENCODING, gctx->encoding);
    COPY_UTF8_PARAM(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                    gctx->pt_format);
    COPY_UTF8_PARAM(params, OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE,
                    gctx->group_check);

    COPY_BN_PARAM(params, OSSL_PKEY_PARAM_EC_P, gctx->p);
    COPY_BN_PARAM(params, OSSL_PKEY_PARAM_EC_A, gctx->a);
    COPY_BN_PARAM(params, OSSL_PKEY_PARAM_EC_B, gctx->b);
    COPY_BN_PARAM(params, OSSL_PKEY_PARAM_EC_ORDER, gctx->order);
    COPY_BN_PARAM(params, OSSL_PKEY_PARAM_EC_COFACTOR, gctx->cofactor);

    COPY_OCTET_PARAM(params, OSSL_PKEY_PARAM_EC_SEED, gctx->seed,
                     gctx->seed_len);
    COPY_OCTET_PARAM(params, OSSL_PKEY_PARAM_EC_GENERATOR, gctx->gen,
                     gctx->gen_len);

    ret = 1;
err:
    return ret;
}

static void *qat_keymgmt_ec_gen_init(void *provctx, int selection,
                         const OSSL_PARAM params[])
{
    OSSL_LIB_CTX *libctx = prov_libctx_of(provctx);
    QAT_EC_GEN_CTX *gctx = NULL;

    if (!qat_prov_is_running() || (selection & (OSSL_KEYMGMT_SELECT_ALL)) == 0)
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->libctx = libctx;
        gctx->selection = selection;
        gctx->ecdh_mode = 0;

        if (!qat_keymgmt_ec_gen_set_params(gctx, params)) {
            OPENSSL_free(gctx);
            gctx = NULL;
        }
    }
    return gctx;
}

static int qat_ec_gen_set_group(void *genctx, const EC_GROUP *src)
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

static int qat_keymgmt_ec_gen_set_template(void *genctx, void *templ)
{
    QAT_EC_GEN_CTX *gctx = genctx;
    EC_KEY *ec = templ;
    const EC_GROUP *ec_group;

    if (!qat_prov_is_running() || gctx == NULL || ec == NULL)
        return 0;
    if ((ec_group = EC_KEY_get0_group(ec)) == NULL)
        return 0;
    return qat_ec_gen_set_group(gctx, ec_group);
}

static const OSSL_PARAM *qat_keymgmt_ec_gen_settable_params(ossl_unused void *genctx,
                                                ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
			       NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}

static int qat_ec_gen_assign_group(EC_KEY *ec, EC_GROUP *group)
{
    if (group == NULL) {
        QATerr(ERR_LIB_PROV, QAT_R_NO_PARAMETERS_SET);
        return 0;
    }
    return EC_KEY_set_group(ec, group) > 0;
}

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

static int qat_ec_check_group_type_name2id(const char *name)
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

static int qat_ec_gen_set_group_from_params(QAT_EC_GEN_CTX *gctx)
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

static void *qat_keymgmt_ec_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    QAT_EC_GEN_CTX *gctx = genctx;
    EC_KEY *ec = NULL;
    int ret = 0;

    if (!qat_prov_is_running()
        || gctx == NULL
        || (ec = qat_ec_key_new(gctx->libctx, NULL)) == NULL)
        return NULL;

    if (gctx->gen_group == NULL) {
        if (!qat_ec_gen_set_group_from_params(gctx))
            goto err;
    } else {
        if (gctx->encoding != NULL) {
            int flags = qat_ec_encoding_name2id(gctx->encoding);

            if (flags < 0)
                goto err;
            EC_GROUP_set_asn1_flag(gctx->gen_group, flags);
        }
        if (gctx->pt_format != NULL) {
            int format = qat_ec_pt_format_name2id(gctx->pt_format);

            if (format < 0)
                goto err;
            EC_GROUP_set_point_conversion_form(gctx->gen_group, format);
        }
    }

    /* We must always assign a group, no matter what */
    ret = qat_ec_gen_assign_group(ec, gctx->gen_group);

#if ENABLE_QAT_HW_ECDH
    ret = ret && qat_ecdh_generate_key(ec);
#endif

#if ENABLE_QAT_SW_ECDH
    ret = ret && mb_ecdh_generate_key(ec);
#endif
    if (gctx->ecdh_mode != -1)
        ret = ret && qat_ec_set_ecdh_cofactor_mode(ec, gctx->ecdh_mode);

    if (gctx->group_check != NULL)
        ret = ret && qat_ec_set_check_group_type_from_name(ec, gctx->group_check);

    if (ret)
        return ec;
err:
    /* Something went wrong, throw the key away */
    EC_KEY_free(ec);
    return NULL;
}

static int qat_keymgmt_ec_get_params(void *key, OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *, OSSL_PARAM *);
    fun_ptr fun = get_default_keymgmt().get_params;
    if (!fun)
        return 0;
    return fun(key, params);
}

static const OSSL_PARAM *qat_keymgmt_ec_gettable_params(void *provctx)
{
    typedef const OSSL_PARAM* (*fun_ptr)(void *);
    fun_ptr fun = get_default_keymgmt().gettable_params;
    if (!fun)
        return NULL;
    return fun(provctx);
}

static const OSSL_PARAM *qat_keymgmt_ec_settable_params(void *provctx)
{
    typedef const OSSL_PARAM* (*fun_ptr)(void *);
    fun_ptr fun = get_default_keymgmt().settable_params;
    if (!fun)
        return NULL;
    return fun(provctx);
}

static int qat_keymgmt_ec_set_params(void *key, const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *,const OSSL_PARAM *);
    fun_ptr fun = get_default_keymgmt().set_params;
    if (!fun)
        return 0;
    return fun(key,params);
}

static void qat_keymgmt_ec_freedata(void *keydata)
{
#ifdef ENABLE_QAT_FIPS
    QAT_EC_KEY_free(keydata);
#else
    typedef void (*fun_ptr)(void *);
    fun_ptr fun = get_default_keymgmt().free;
    if (!fun)
        return;
    fun(keydata);
#endif
}

static int qat_keymgmt_ec_has(const void *keydata, int selection)
{
    typedef int (*fun_ptr)(const void *,int);
    fun_ptr fun = get_default_keymgmt().has;
    if (!fun)
        return 0;
    return fun(keydata,selection);
}

static int qat_keymgmt_ec_import(void *keydata, int selection,
                                 const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *, int, const OSSL_PARAM*);
    fun_ptr fun = get_default_keymgmt().import;
    if (!fun)
        return 0;
    return fun(keydata,selection,params);
}

static const OSSL_PARAM *qat_keymgmt_ec_import_types(int selection)
{
    typedef const OSSL_PARAM* (*fun_ptr)(int);
    fun_ptr fun = get_default_keymgmt().import_types;
    if (!fun)
        return NULL;
    return fun(selection);
}

static int qat_keymgmt_ec_export(void *keydata, int selection,
              OSSL_CALLBACK *param_cb, void *cbarg)
{
    typedef int (*fun_ptr)(void *, int, OSSL_CALLBACK *, void *);
    fun_ptr fun = get_default_keymgmt().export;
    if (!fun)
        return 0;
    return fun(keydata,selection,param_cb,cbarg);
}

static const OSSL_PARAM *qat_keymgmt_ec_export_types(int selection)
{
    typedef const OSSL_PARAM* (*fun_ptr)(int);
    fun_ptr fun = get_default_keymgmt().export_types;
    if (!fun)
        return NULL;
    return fun(selection);
}

static void qat_keymgmt_ec_gen_cleanup(void *genctx)
{
    QAT_EC_GEN_CTX *gctx = genctx;

    if (gctx == NULL)
        return;

    EC_GROUP_free(gctx->gen_group);
    BN_free(gctx->p);
    BN_free(gctx->a);
    BN_free(gctx->b);
    BN_free(gctx->order);
    BN_free(gctx->cofactor);
    OPENSSL_free(gctx->group_name);
    OPENSSL_free(gctx->field_type);
    OPENSSL_free(gctx->pt_format);
    OPENSSL_free(gctx->encoding);
    OPENSSL_free(gctx->seed);
    OPENSSL_free(gctx->gen);
    OPENSSL_free(gctx);
}

static void *qat_keymgmt_ec_load(const void *reference, size_t reference_sz)
{
    typedef void* (*fun_ptr)(const void *, size_t);
    fun_ptr fun = get_default_keymgmt().load;
    if (!fun)
        return NULL;
    return fun(reference,reference_sz);

}

static void *qat_keymgmt_ec_dup(const void *keydata_from, int selection)
{
    typedef void* (*fun_ptr)(const void *, int);
    fun_ptr fun = get_default_keymgmt().dup;
    if (!fun)
        return NULL;
    return fun(keydata_from, selection);

}

static int qat_keymgmt_ec_validate(const void *keydata, int selection,
                                   int checktype)
{
    typedef int (*fun_ptr)(const void *, int, int);
    fun_ptr fun = get_default_keymgmt().validate;
    if (!fun)
	return 0;
    return fun(keydata, selection, checktype);

}

static int qat_keymgmt_ec_match(const void *keydata1, const void *keydata2,
                                int selection)
{
    typedef int (*fun_ptr)(const void *, const void *, int);
    fun_ptr fun = get_default_keymgmt().match;
    if (!fun)
        return 0;
    return fun(keydata1, keydata2, selection);

}

#endif

#if defined(ENABLE_QAT_HW_ECDH) || defined(ENABLE_QAT_SW_ECDH)
const OSSL_DISPATCH qat_ecdh_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))qat_keymgmt_ec_newdata },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))qat_keymgmt_ec_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
      (void (*)(void))qat_keymgmt_ec_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))qat_keymgmt_ec_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))qat_keymgmt_ec_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))qat_keymgmt_ec_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))qat_keymgmt_ec_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))qat_keymgmt_ec_load },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))qat_keymgmt_ec_freedata},
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))qat_keymgmt_ec_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))qat_keymgmt_ec_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))qat_keymgmt_ec_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))qat_keymgmt_ec_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))qat_keymgmt_ec_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))qat_keymgmt_ec_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))qat_keymgmt_ec_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))qat_keymgmt_ec_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))qat_keymgmt_ec_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))qat_keymgmt_ec_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))qat_keymgmt_ec_export_types },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))qat_keymgmt_ec_dup },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))qat_keymgmt_ec_query_operation_name },
    {0, NULL }
};
#endif /* defined(ENABLE_QAT_HW_ECDH) || defined(ENABLE_QAT_SW_ECDH) */

#if defined(ENABLE_QAT_HW_SM2) || defined(ENABLE_QAT_SW_SM2)
static QAT_EC_KEYMGMT sm2_get_default_keymgmt()
{
    static QAT_EC_KEYMGMT s_keymgmt;
    static int initialized = 0;
    if (!initialized) {
        QAT_EC_KEYMGMT *keymgmt = (QAT_EC_KEYMGMT *)EVP_KEYMGMT_fetch(NULL, "SM2", "provider=default");
        if (keymgmt) {
            s_keymgmt = *keymgmt;
            EVP_KEYMGMT_free((EVP_KEYMGMT *)keymgmt);
            initialized = 1;
        } else {
            WARN("EVP_KEYMGMT_fetch from default provider failed");
        }
    }
    return s_keymgmt;
}

static void *qat_sm2_keymgmt_ec_newdata(void *provctx)
{
    typedef void* (*fun_ptr)(void *);
    fun_ptr fun = sm2_get_default_keymgmt().new;
    if (!fun)
        return NULL;
    return fun(provctx);
}

static const char *qat_sm2_keymgmt_ec_query_operation_name(int operation_id)
{
    typedef const char* (*fun_ptr)(int);
    fun_ptr fun = sm2_get_default_keymgmt().query_operation_name;
    if (!fun)
        return NULL;
    return fun(operation_id);
}

static void *qat_sm2_keymgmt_ec_gen_init(void *provctx, int selection,
                         const OSSL_PARAM params[])
{
    typedef void* (*fun_ptr)(void *, int, const OSSL_PARAM *);
    fun_ptr fun = sm2_get_default_keymgmt().gen_init;
    if (!fun)
        return NULL;
    return fun(provctx, selection, params);
}

static int qat_sm2_keymgmt_ec_gen_set_template(void *genctx, void *templ)
{
    typedef int (*fun_ptr)(void *, void *);
    fun_ptr fun = sm2_get_default_keymgmt().gen_set_template;
    if (!fun)
        return 0;
    return fun(genctx,templ);
}

static int qat_sm2_keymgmt_ec_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *, const OSSL_PARAM *);
    fun_ptr fun = sm2_get_default_keymgmt().gen_set_params;
    if (!fun)
        return 0;
    return fun(genctx,params);
}

static const OSSL_PARAM *qat_sm2_keymgmt_ec_gen_settable_params(ossl_unused void *genctx,
                                                ossl_unused void *provctx)
{
    typedef const OSSL_PARAM* (*fun_ptr)(void *, void *);
    fun_ptr fun = sm2_get_default_keymgmt().gen_settable_params;
    if (!fun)
        return NULL;
    return fun(genctx,provctx);
}

static void *qat_sm2_keymgmt_ec_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    typedef void* (*fun_ptr)(void *, OSSL_CALLBACK *, void *);
    fun_ptr fun = sm2_get_default_keymgmt().gen;
    if (!fun)
        return NULL;
    return fun(genctx,osslcb,cbarg);
}

static int qat_sm2_keymgmt_ec_get_params(void *key, OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *, OSSL_PARAM *);
    fun_ptr fun = sm2_get_default_keymgmt().get_params;
    if (!fun)
        return 0;
    return fun(key, params);
}

static const OSSL_PARAM *qat_sm2_keymgmt_ec_gettable_params(void *provctx)
{
    typedef const OSSL_PARAM* (*fun_ptr)(void *);
    fun_ptr fun = sm2_get_default_keymgmt().gettable_params;
    if (!fun)
        return NULL;
    return fun(provctx);
}

static const OSSL_PARAM *qat_sm2_keymgmt_ec_settable_params(void *provctx)
{
    typedef const OSSL_PARAM* (*fun_ptr)(void *);
    fun_ptr fun = sm2_get_default_keymgmt().settable_params;
    if (!fun)
        return NULL;
    return fun(provctx);
}

static int qat_sm2_keymgmt_ec_set_params(void *key, const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *,const OSSL_PARAM *);
    fun_ptr fun = sm2_get_default_keymgmt().set_params;
    if (!fun)
        return 0;
    return fun(key,params);
}

static void qat_sm2_keymgmt_ec_freedata(void *keydata)
{
    typedef void (*fun_ptr)(void *);
    fun_ptr fun = sm2_get_default_keymgmt().free;
    if (!fun)
        return;
    fun(keydata);
}

static int qat_sm2_keymgmt_ec_has(const void *keydata, int selection)
{
    typedef int (*fun_ptr)(const void *,int);
    fun_ptr fun = sm2_get_default_keymgmt().has;
    if (!fun)
        return 0;
    return fun(keydata,selection);
}

static int qat_sm2_keymgmt_ec_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *, int, const OSSL_PARAM*);
    fun_ptr fun = sm2_get_default_keymgmt().import;
    if (!fun)
        return 0;
    return fun(keydata,selection,params);
}

static const OSSL_PARAM *qat_sm2_keymgmt_ec_import_types(int selection)
{
    typedef const OSSL_PARAM* (*fun_ptr)(int);
    fun_ptr fun = sm2_get_default_keymgmt().import_types;
    if (!fun)
        return NULL;
    return fun(selection);
}

static int qat_sm2_keymgmt_ec_export(void *keydata, int selection,
              OSSL_CALLBACK *param_cb, void *cbarg)
{
    typedef int (*fun_ptr)(void *, int, OSSL_CALLBACK *, void *);
    fun_ptr fun = sm2_get_default_keymgmt().export;
    if (!fun)
        return 0;
    return fun(keydata,selection,param_cb,cbarg);
}

static const OSSL_PARAM *qat_sm2_keymgmt_ec_export_types(int selection)
{
    typedef const OSSL_PARAM* (*fun_ptr)(int);
    fun_ptr fun = sm2_get_default_keymgmt().export_types;
    if (!fun)
        return NULL;
    return fun(selection);
}

static void qat_sm2_keymgmt_ec_gen_cleanup(void *genctx)
{
    typedef void (*fun_ptr)(void *);
    fun_ptr fun = sm2_get_default_keymgmt().gen_cleanup;
    if (!fun)
        return;
    fun(genctx);
}

static void *qat_sm2_keymgmt_ec_load(const void *reference, size_t reference_sz)
{
    typedef void* (*fun_ptr)(const void *, size_t);
    fun_ptr fun = sm2_get_default_keymgmt().load;
    if (!fun)
        return NULL;
    return fun(reference,reference_sz);

}

static int qat_sm2_keymgmt_match(const void *keydata1, const void *keydata2, int selection)
{
    typedef int (*fun_ptr)(const void *, const void *, int);
    fun_ptr fun = sm2_get_default_keymgmt().match;
    if (!fun)
        return 0;
    return fun(keydata1, keydata2, selection);
}

int qat_sm2_keymgmt_validate(const void *keydata, int selection, int checktype)
{
    typedef int (*fun_ptr)(const void *, int, int);
    fun_ptr fun = sm2_get_default_keymgmt().validate;
    if (!fun)
        return 0;
    return fun(keydata, selection, checktype);
}


static void *qat_sm2_keymgmt_ec_dup(const void *keydata_from, int selection)
{
    typedef void * (*fun_ptr)(const void *, int);
    fun_ptr fun = sm2_get_default_keymgmt().dup;
    if (!fun)
        return NULL;
    return fun(keydata_from, selection);
}


const OSSL_DISPATCH qat_sm2_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))qat_sm2_keymgmt_ec_newdata },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))qat_sm2_keymgmt_ec_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))qat_sm2_keymgmt_ec_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))qat_sm2_keymgmt_ec_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))qat_sm2_keymgmt_ec_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))qat_sm2_keymgmt_ec_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))qat_sm2_keymgmt_ec_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))qat_sm2_keymgmt_ec_load },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))qat_sm2_keymgmt_ec_freedata},
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))qat_sm2_keymgmt_ec_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))qat_sm2_keymgmt_ec_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))qat_sm2_keymgmt_ec_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))qat_sm2_keymgmt_ec_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))qat_sm2_keymgmt_ec_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))qat_sm2_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))qat_sm2_keymgmt_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))qat_sm2_keymgmt_ec_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))qat_sm2_keymgmt_ec_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))qat_sm2_keymgmt_ec_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))qat_sm2_keymgmt_ec_export_types },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))qat_sm2_keymgmt_ec_query_operation_name },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))qat_sm2_keymgmt_ec_dup },
    {0, NULL }
};
# endif /* ENABLE_QAT_SW_SM2 */
