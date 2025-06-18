/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2025 Intel Corporation.
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
 * @file qat_prov_kmgmt_ec_utils.h
 *
 * This file contains the Qat provider EC Key Management implementation for
 * QAT_SW and QAT_HW operations
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#if defined(ENABLE_QAT_HW_ECDH) || defined(ENABLE_QAT_SW_ECDH)
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

#define EC_DEFAULT_MD "SHA256"
#define EC_POSSIBLE_SELECTIONS                                                 \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
#define SM2_DEFAULT_MD "SM3"

typedef struct{
    int id; /* libcrypto internal */
    int name_id;
# if OPENSSL_VERSION_NUMBER >= 0x30300000
    /* NID for the legacy alg if there is one */
    int legacy_alg;
# endif
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;

    QAT_CRYPTO_REF_COUNT references;
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
# if OPENSSL_VERSION_NUMBER >= 0x30400000
    OSSL_FUNC_keymgmt_gen_get_params_fn *gen_get_params;
    OSSL_FUNC_keymgmt_gen_gettable_params_fn *gen_gettable_params;
# endif
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
    unsigned char *dhkem_ikm;
    size_t dhkem_ikmlen;
}QAT_EC_GEN_CTX;

struct bignum_st {
    BN_ULONG *d;                /*
                                 * Pointer to an array of 'BN_BITS2' bit
                                 * chunks. These chunks are organised in
                                 * a least significant chunk first order.
                                 */
    int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;                   /* Size of the d array. */
    int neg;                    /* one if the number is negative */
    int flags;
};

/*
 * This prints the engine's pointer address, "struct" or "funct" to
 * indicate the reference type, the before and after reference count, and
 * the file:line-number pair. The "ENGINE_REF_PRINT" statements must come
 * *after* the change.
 */
# define ENGINE_REF_PRINT(e, isfunct, diff)                             \
    OSSL_TRACE6(ENGINE_REF_COUNT,                                       \
               "engine: %p %s from %d to %d (%s:%d)\n",                 \
               (void *)(e), (isfunct ? "funct" : "struct"),             \
               ((isfunct)                                               \
                ? ((e)->funct_ref - (diff))                             \
                : (eng_struct_ref(e) - (diff))),                        \
               ((isfunct) ? (e)->funct_ref : eng_struct_ref(e)),        \
               (OPENSSL_FILE), (OPENSSL_LINE))


/* Use custom formats for EC_GROUP, EC_POINT and EC_KEY */
#define EC_FLAGS_CUSTOM_CURVE   0x2

# define EC2M_GETTABLE_DOM_PARAMS                                              \
        OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_CHAR2_M, NULL),                      \
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_CHAR2_TYPE, NULL, 0),        \
        OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_CHAR2_TP_BASIS, NULL),               \
        OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_CHAR2_PP_K1, NULL),                  \
        OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_CHAR2_PP_K2, NULL),                  \
        OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_CHAR2_PP_K3, NULL),


# define EC_IMEXPORTABLE_DOM_PARAMETERS                                        \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),               \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),              \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),\
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, NULL, 0),            \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, NULL, 0),                              \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, NULL, 0),                              \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, NULL, 0),                              \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, NULL, 0),            \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, NULL, 0),                          \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, NULL, 0),                       \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, NULL, 0),                 \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, NULL)

# define EC_IMEXPORTABLE_PUBLIC_KEY                                            \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0)
# define EC_IMEXPORTABLE_PRIVATE_KEY                                           \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)
# define EC_IMEXPORTABLE_OTHER_PARAMETERS                                      \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),                   \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL)

static const OSSL_PARAM ec_private_key_types[] = {
    EC_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_public_key_types[] = {
    EC_IMEXPORTABLE_PUBLIC_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_key_types[] = {
    EC_IMEXPORTABLE_PRIVATE_KEY,
    EC_IMEXPORTABLE_PUBLIC_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_dom_parameters_types[] = {
    EC_IMEXPORTABLE_DOM_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_5_types[] = {
    EC_IMEXPORTABLE_PRIVATE_KEY,
    EC_IMEXPORTABLE_DOM_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_6_types[] = {
    EC_IMEXPORTABLE_PUBLIC_KEY,
    EC_IMEXPORTABLE_DOM_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_key_domp_types[] = {
    EC_IMEXPORTABLE_PRIVATE_KEY,
    EC_IMEXPORTABLE_PUBLIC_KEY,
    EC_IMEXPORTABLE_DOM_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_other_parameters_types[] = {
    EC_IMEXPORTABLE_OTHER_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_9_types[] = {
    EC_IMEXPORTABLE_PRIVATE_KEY,
    EC_IMEXPORTABLE_OTHER_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_10_types[] = {
    EC_IMEXPORTABLE_PUBLIC_KEY,
    EC_IMEXPORTABLE_OTHER_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_11_types[] = {
    EC_IMEXPORTABLE_PRIVATE_KEY,
    EC_IMEXPORTABLE_PUBLIC_KEY,
    EC_IMEXPORTABLE_OTHER_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_all_parameters_types[] = {
    EC_IMEXPORTABLE_DOM_PARAMETERS,
    EC_IMEXPORTABLE_OTHER_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_13_types[] = {
    EC_IMEXPORTABLE_PRIVATE_KEY,
    EC_IMEXPORTABLE_DOM_PARAMETERS,
    EC_IMEXPORTABLE_OTHER_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_14_types[] = {
    EC_IMEXPORTABLE_PUBLIC_KEY,
    EC_IMEXPORTABLE_DOM_PARAMETERS,
    EC_IMEXPORTABLE_OTHER_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_all_types[] = {
    EC_IMEXPORTABLE_PRIVATE_KEY,
    EC_IMEXPORTABLE_PUBLIC_KEY,
    EC_IMEXPORTABLE_DOM_PARAMETERS,
    EC_IMEXPORTABLE_OTHER_PARAMETERS,
    OSSL_PARAM_END
};

static ossl_unused const OSSL_PARAM *ec_types[] = {
    NULL,
    ec_private_key_types,
    ec_public_key_types,
    ec_key_types,
    ec_dom_parameters_types,
    ec_5_types,
    ec_6_types,
    ec_key_domp_types,
    ec_other_parameters_types,
    ec_9_types,
    ec_10_types,
    ec_11_types,
    ec_all_parameters_types,
    ec_13_types,
    ec_14_types,
    ec_all_types
};

OSSL_LIB_CTX *qat_keymgmt_ec_key_get_libctx(const EC_KEY *key);

# if OPENSSL_VERSION_NUMBER >= 0x30200000
ossl_unused int CRYPTO_NEW_REF(QAT_CRYPTO_REF_COUNT *refcnt, int n);
# endif

const char *qat_ec_key_get0_propq(const EC_KEY *key);

int qat_ec_gen_set_group(void *genctx, const EC_GROUP *src);

int qat_ec_gen_assign_group(EC_KEY *ec, EC_GROUP *group);

int qat_ec_encoding_name2id(const char *name);

int qat_ec_pt_format_name2id(const char *name);

int qat_ec_check_group_type_name2id(const char *name);

int qat_ec_gen_set_group_from_params(QAT_EC_GEN_CTX *gctx);

int qat_ec_set_ecdh_cofactor_mode(EC_KEY *ec, int mode);

int qat_ec_set_check_group_type_from_name(EC_KEY *ec, const char *name);

int qat_param_build_set_int(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                             const char *key, int num);

int qat_param_build_set_utf8_string(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                     const char *key, const char *buf);

int qat_ec_get_ecm_params(const EC_GROUP *group, OSSL_PARAM params[]);

char *qat_ec_pt_format_id2name(int id);

char *qat_ec_param_encoding_id2name(int id);

int qat_param_build_set_bn(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                            const char *key, const BIGNUM *bn);

int qat_param_build_set_octet_string(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                      const char *key,
                                      const unsigned char *data,
                                      size_t data_len);

int qat_ec_group_explicit_todata(const EC_GROUP *group, OSSL_PARAM_BLD *tmpl,
                                    OSSL_PARAM params[], BN_CTX *bnctx,
                                    unsigned char **genbuf);

int qat_ec_group_todata(const EC_GROUP *group, OSSL_PARAM_BLD *tmpl,
                         OSSL_PARAM params[], OSSL_LIB_CTX *libctx,
                         const char *propq,
                         BN_CTX *bnctx, unsigned char **genbuf);

int qat_param_build_set_bn_pad(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                const char *key, const BIGNUM *bn,  size_t sz);

int qat_key_to_params(const EC_KEY *eckey, OSSL_PARAM_BLD *tmpl,
                  OSSL_PARAM params[], int include_private,
                  unsigned char **pub_key);

char *qat_ec_check_group_type_id2name(int id);

int qat_otherparams_to_params(const EC_KEY *ec, OSSL_PARAM_BLD *tmpl,
                          OSSL_PARAM params[]);

int qat_ec_encoding_param2id(const OSSL_PARAM *p, int *id);

int qat_ec_pt_format_param2id(const OSSL_PARAM *p, int *id);

int qat_ec_group_set_params(EC_GROUP *group, const OSSL_PARAM params[]);

int qat_ec_set_check_group_type_from_param(EC_KEY *ec, const OSSL_PARAM *p);

int qat_ec_key_group_check_fromdata(EC_KEY *ec, const OSSL_PARAM params[]);

void QAT_EC_KEY_set_conv_form(EC_KEY *key, point_conversion_form_t cform);

int qat_ec_key_point_format_fromdata(EC_KEY *ec, const OSSL_PARAM params[]);

int qat_ec_set_include_public(EC_KEY *ec, int include);

int qat_ec_key_otherparams_fromdata(EC_KEY *ec, const OSSL_PARAM params[]);

int qat_common_check_sm2(const EC_KEY *ec, int sm2_wanted);

int qat_ec_group_fromdata(EC_KEY *ec, const OSSL_PARAM params[]);

int qat_bn_get_top(const BIGNUM *a);

BN_ULONG *qat_bn_expand_internal(const BIGNUM *b, int words);

void qat_bn_free_d(BIGNUM *a, int clear);

BIGNUM *qat_bn_expand2(BIGNUM *b, int words);

BIGNUM *qat_bn_wexpand(BIGNUM *a, int words);

int qat_ec_key_fromdata(EC_KEY *ec, const OSSL_PARAM params[], int include_private);

EC_KEY *qat_ec_key_new_method_int(OSSL_LIB_CTX *libctx, const char *propq);

EC_GROUP *qat_ec_group_new_ex(OSSL_LIB_CTX *libctx, const char *propq,
                               const EC_METHOD *meth);

int qat_ec_key_public_range_check(BN_CTX *ctx, const EC_KEY *key);

int qat_ec_key_public_check_quick(const EC_KEY *eckey, BN_CTX *ctx);

int qat_ec_key_public_check(const EC_KEY *eckey, BN_CTX *ctx);

int qat_ec_key_private_check(const EC_KEY *eckey);

int qat_ec_key_pairwise_check(const EC_KEY *eckey, BN_CTX *ctx);
#endif /* defined(ENABLE_QAT_HW_ECDH) || defined(ENABLE_QAT_SW_ECDH) */
