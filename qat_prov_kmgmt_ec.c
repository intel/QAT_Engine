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
#include <assert.h>

#include "qat_provider.h"
#include "qat_prov_ec.h"
#include "qat_utils.h"
#include "qat_evp.h"
#include "e_qat.h"
#include "qat_prov_kmgmt_ec_utils.h"

#ifdef QAT_HW
# include "qat_hw_ec.h"
#endif

#ifdef QAT_SW
# include "qat_sw_ec.h"
#endif

#if defined(ENABLE_QAT_HW_ECDH) || defined(ENABLE_QAT_SW_ECDH)

static void *qat_keymgmt_ec_newdata(void *provctx)
{
    if (!qat_prov_is_running())
        return NULL;
    return EC_KEY_new_ex(prov_libctx_of(provctx), NULL);
}

static
const char *qat_keymgmt_ec_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_KEYEXCH:
        return "ECDH";
    case OSSL_OP_SIGNATURE:
        return "ECDSA";
    }
    return NULL;
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
# if OPENSSL_VERSION_NUMBER >= 0x30200000
    COPY_OCTET_PARAM(params, OSSL_PKEY_PARAM_DHKEM_IKM, gctx->dhkem_ikm,
                     gctx->dhkem_ikmlen);
# endif

    ret = 1;
err:
    return ret;
}

static void *qat_keymgmt_ec_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    if (!qat_prov_is_running() || (selection & EC_POSSIBLE_SELECTIONS) == 0)
        return NULL;

    QAT_EC_GEN_CTX *gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx == NULL)
        return NULL;

    gctx->libctx = prov_libctx_of(provctx);
    gctx->selection = selection;
    gctx->ecdh_mode = 0;

    if (!qat_keymgmt_ec_gen_set_params(gctx, params)) {
        OPENSSL_free(gctx);
        return NULL;
    }

    return gctx;
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
# if OPENSSL_VERSION_NUMBER >= 0x30200000
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM, NULL, 0),
# endif
        OSSL_PARAM_END
    };

    return settable;
}

static void *qat_keymgmt_ec_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    QAT_EC_GEN_CTX *gctx = genctx;
    EC_KEY *ec = NULL;
    int ret = 0;

    if (!qat_prov_is_running()
        || gctx == NULL
        || (ec = EC_KEY_new_ex(gctx->libctx, NULL)) == NULL)
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

    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
#if defined(ENABLE_QAT_HW_ECDH)
        if (qat_hw_ecdh_offload) {
            ret = ret && qat_ecdh_generate_key(ec);
	}
#endif
#ifdef ENABLE_QAT_SW_ECDH
        if (qat_sw_ecdh_offload) {
            ret = ret && mb_ecdh_generate_key(ec);
	}
#endif
        if (!qat_hw_ecdh_offload && !qat_sw_ecdh_offload) {
            ret = ret && EC_KEY_generate_key(ec);
        }    
    }

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

static int common_get_params(void *key, OSSL_PARAM params[], int sm2)
{
    if (key == NULL || params == NULL)
        return 0;

    EC_KEY *eck = key;
    const EC_GROUP *ecg = EC_KEY_get0_group(eck);
    if (ecg == NULL)
        return 0;

    OSSL_LIB_CTX *libctx = qat_keymgmt_ec_key_get_libctx(eck);
    const char *propq = qat_ec_key_get0_propq(eck);
    BN_CTX *bnctx = BN_CTX_new_ex(libctx);
    if (bnctx == NULL)
        return 0;

    BN_CTX_start(bnctx);
    int ret = 0;

    /* Set maximum size */
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_int(p, ECDSA_size(eck)))
        goto cleanup;

    /* Set key bits */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, EC_GROUP_order_bits(ecg)))
        goto cleanup;

    /* Set security bits */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL) {
        int ecbits = EC_GROUP_order_bits(ecg);
        int sec_bits = (ecbits >= 512) ? 256 :
                       (ecbits >= 384) ? 192 :
                       (ecbits >= 256) ? 128 :
                       (ecbits >= 224) ? 112 :
                       (ecbits >= 160) ? 80 : ecbits / 2;

        if (!OSSL_PARAM_set_int(p, sec_bits))
            goto cleanup;
    }

    /* Set explicit parameters flag */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS);
    if (p != NULL) {
        int explicitparams = EC_KEY_decoded_from_explicit_params(eck);
        if (explicitparams < 0 || !OSSL_PARAM_set_int(p, explicitparams))
            goto cleanup;
    }

    /* Set default digest */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST);
    if (p != NULL) {
        const char *default_md = sm2 ? SM2_DEFAULT_MD : EC_DEFAULT_MD;
        if (!OSSL_PARAM_set_utf8_string(p, default_md))
            goto cleanup;
    }

    /* Set cofactor ECDH mode (if not SM2) */
    if (!sm2) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH);
        if (p != NULL) {
            int ecdh_cofactor_mode = (EC_KEY_get_flags(eck) & EC_FLAG_COFACTOR_ECDH) ? 1 : 0;
            if (!OSSL_PARAM_set_int(p, ecdh_cofactor_mode))
                goto cleanup;
        }
    }

    /* Set encoded public key */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        const EC_POINT *ecp = EC_KEY_get0_public_key(eck);
        if (ecp == NULL)
            goto cleanup;

        p->return_size = EC_POINT_point2oct(ecg, ecp, POINT_CONVERSION_UNCOMPRESSED,
                                            p->data, p->data_size, bnctx);
        if (p->return_size == 0)
            goto cleanup;
    }

    /* Get additional parameters */
    ret = qat_ec_get_ecm_params(ecg, params) &&
          qat_ec_group_todata(ecg, NULL, params, libctx, propq, bnctx, NULL) &&
          qat_key_to_params(eck, NULL, params, 1, NULL) &&
          qat_otherparams_to_params(eck, NULL, params);

cleanup:
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);
    return ret;
}

static int qat_keymgmt_ec_get_params(void *key, OSSL_PARAM params[])
{
    return common_get_params(key, params, 0);
}

static const OSSL_PARAM qat_keymgmt_ec_gettable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),                   \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, NULL),
    EC_IMEXPORTABLE_DOM_PARAMETERS,
    EC2M_GETTABLE_DOM_PARAMS
    EC_IMEXPORTABLE_PUBLIC_KEY,
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
    EC_IMEXPORTABLE_PRIVATE_KEY,
    EC_IMEXPORTABLE_OTHER_PARAMETERS,
    OSSL_PARAM_END
};

static const OSSL_PARAM qat_keymgmt_ec_settable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE, NULL, 0),
    OSSL_PARAM_END
};

static
int qat_keymgmt_ec_set_params(void *key, const OSSL_PARAM params[])
{
    EC_KEY *eck = key;
    const OSSL_PARAM *p;

    if (key == NULL)
        return 0;
    if (params == NULL)
        return 1;


    if (!qat_ec_group_set_params((EC_GROUP *)EC_KEY_get0_group(key), params))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        BN_CTX *ctx = BN_CTX_new_ex(qat_keymgmt_ec_key_get_libctx(key));
        int ret = 1;

        if (ctx == NULL
                || p->data_type != OSSL_PARAM_OCTET_STRING
                || !EC_KEY_oct2key(key, p->data, p->data_size, ctx))
            ret = 0;
        BN_CTX_free(ctx);
        if (!ret)
            return 0;
    }

    return qat_ec_key_otherparams_fromdata(eck, params);
}

static void qat_keymgmt_ec_freedata(void *keydata)
{
#ifdef ENABLE_QAT_FIPS
    QAT_EC_KEY_free(keydata);
#else
    EC_KEY_free(keydata);
#endif
}

static
int qat_keymgmt_ec_has(const void *keydata, int selection)
{
    const EC_KEY *ec = keydata;
    int ok = 1;

    if (!qat_prov_is_running() || ec == NULL)
        return 0;
    if ((selection & EC_POSSIBLE_SELECTIONS) == 0)
        return 1; /* the selection is not missing */

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (EC_KEY_get0_public_key(ec) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (EC_KEY_get0_private_key(ec) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && (EC_KEY_get0_group(ec) != NULL);
    /*
     * We consider OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS to always be
     * available, so no extra check is needed other than the previous one
     * against EC_POSSIBLE_SELECTIONS.
     */
    return ok;
}

static int common_import(void *keydata, int selection, const OSSL_PARAM params[], int sm2_wanted)
{
    if (!qat_prov_is_running() || keydata == NULL || (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
        return 0;

    EC_KEY *ec = keydata;
    int include_private = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    int ok = 1;

    /* Import domain parameters */
    ok = ok && qat_ec_group_fromdata(ec, params);

    /* Check if key is SM2 and matches the expected type */
    if (!qat_common_check_sm2(ec, sm2_wanted))
        return 0;

    /* Import keypair if requested */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && qat_ec_key_fromdata(ec, params, include_private);

    /* Import other parameters if requested */
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        ok = ok && qat_ec_key_otherparams_fromdata(ec, params);

    return ok;
}

static
int qat_keymgmt_ec_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    return common_import(keydata, selection, params, 0);
}

static ossl_inline
const OSSL_PARAM *qat_ec_imexport_types(int selection)
{
    int type_select = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        type_select += 1;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        type_select += 2;
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        type_select += 4;
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        type_select += 8;
    return ec_types[type_select];
}

static const OSSL_PARAM *qat_keymgmt_ec_import_types(int selection)
{
    return qat_ec_imexport_types(selection);
}

static
int qat_keymgmt_ec_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    if (!qat_prov_is_running() || keydata == NULL)
        return 0;

    EC_KEY *ec = keydata;
    int ok = 1;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
    unsigned char *pub_key = NULL, *genbuf = NULL;
    BN_CTX *bnctx = NULL;

    /* Validate selection: must always have domain parameters, and private key requires public key */
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
        (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    /* Export domain parameters */
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        bnctx = BN_CTX_new_ex(qat_keymgmt_ec_key_get_libctx(ec));
        if (bnctx == NULL) {
            ok = 0;
            goto cleanup;
        }
        BN_CTX_start(bnctx);
        ok = qat_ec_group_todata(EC_KEY_get0_group(ec), tmpl, NULL,
                                 qat_keymgmt_ec_key_get_libctx(ec),
                                 qat_ec_key_get0_propq(ec),
                                 bnctx, &genbuf);
        if (!ok)
            goto cleanup;
    }

    /* Export keypair (public/private) */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ? 1 : 0;
        ok = qat_key_to_params(ec, tmpl, NULL, include_private, &pub_key);
        if (!ok)
            goto cleanup;
    }

    /* Export other parameters */
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0) {
        ok = qat_otherparams_to_params(ec, tmpl, NULL);
        if (!ok)
            goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL) {
        ok = 0;
        goto cleanup;
    }

    ok = param_cb(params, cbarg);
    OSSL_PARAM_free(params);

cleanup:
    OSSL_PARAM_BLD_free(tmpl);
    OPENSSL_free(pub_key);
    OPENSSL_free(genbuf);
    if (bnctx) {
        BN_CTX_end(bnctx);
        BN_CTX_free(bnctx);
    }
    return ok;
}

static const OSSL_PARAM *qat_keymgmt_ec_export_types(int selection)
{
    return qat_ec_imexport_types(selection);
}

static void qat_keymgmt_ec_gen_cleanup(void *genctx)
{
    QAT_EC_GEN_CTX *gctx = genctx;

    if (gctx == NULL)
        return;

    OPENSSL_clear_free(gctx->dhkem_ikm, gctx->dhkem_ikmlen);
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

static void *common_load(const void *reference, size_t reference_sz,
                         int sm2_wanted)
{
    EC_KEY *ec = NULL;

    if (reference_sz == sizeof(ec)) {
        /* The contents of the reference is the address to our object */
        ec = *(EC_KEY **)reference;

        if (!qat_common_check_sm2(ec, sm2_wanted))
            return NULL;

        /* We grabbed, so we detach it */
        *(EC_KEY **)reference = NULL;
        return ec;
    }
    return NULL;
}

static void *qat_keymgmt_ec_load(const void *reference, size_t reference_sz)
{
    return common_load(reference, reference_sz, 0);
}

EC_KEY *qat_ec_key_dup(const EC_KEY *src, int selection)
{
    EC_KEY *ret;

    if (src == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if ((ret = qat_ec_key_new_method_int(src->libctx, src->propq)) == NULL)
        return NULL;

    /* copy the parameters */
    if (src->group != NULL
        && (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        ret->group = qat_ec_group_new_ex(src->libctx, src->propq,
                                          src->group->meth);
        if (ret->group == NULL
            || !EC_GROUP_copy(ret->group, src->group))
            goto err;

        if (src->meth != NULL)
            ret->meth = src->meth;
    }

    /*  copy the public key */
    if (src->pub_key != NULL
        && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (ret->group == NULL)
            /* no parameter-less keys allowed */
            goto err;
        ret->pub_key = EC_POINT_new(ret->group);
        if (ret->pub_key == NULL
            || !EC_POINT_copy(ret->pub_key, src->pub_key))
                goto err;
    }

    /* copy the private key */
    if (src->priv_key != NULL
        && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (ret->group == NULL)
            /* no parameter-less keys allowed */
            goto err;
        ret->priv_key = BN_new();
        if (ret->priv_key == NULL || !BN_copy(ret->priv_key, src->priv_key))
            goto err;
        if (ret->group->meth->keycopy
            && ret->group->meth->keycopy(ret, src) == 0)
            goto err;
    }

    /* copy the rest */
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0) {
        ret->enc_flag = src->enc_flag;
        ret->conv_form = src->conv_form;
    }

    ret->version = src->version;
    ret->flags = src->flags;

    if (!CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_EC_KEY,
                            &ret->ex_data, &src->ex_data))
        goto err;

    if (ret->meth != NULL && ret->meth->copy != NULL) {
        if ((selection
             & OSSL_KEYMGMT_SELECT_KEYPAIR) != OSSL_KEYMGMT_SELECT_KEYPAIR)
            goto err;
        if (ret->meth->copy(ret, src) == 0)
            goto err;
    }

    return ret;
 err:
    EC_KEY_free(ret);
    return NULL;
}

static void *qat_keymgmt_ec_dup(const void *keydata_from, int selection)
{
    if (qat_prov_is_running())
        return qat_ec_key_dup(keydata_from, selection);
    return NULL;
}

static
int qat_keymgmt_ec_validate(const void *keydata, int selection, int checktype)
{
    const EC_KEY *eck = keydata;
    int ok = 1;
    BN_CTX *ctx = NULL;

    if (!qat_prov_is_running())
        return 0;

    if ((selection & EC_POSSIBLE_SELECTIONS) == 0)
        return 1; /* nothing to validate */

    ctx = BN_CTX_new_ex(qat_keymgmt_ec_key_get_libctx(eck));
    if  (ctx == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        int flags = EC_KEY_get_flags(eck);

        if ((flags & EC_FLAG_CHECK_NAMED_GROUP) != 0)
            ok = ok && EC_GROUP_check_named_curve(EC_KEY_get0_group(eck),
                           (flags & EC_FLAG_CHECK_NAMED_GROUP_NIST) != 0, ctx) > 0;
        else
            ok = ok && EC_GROUP_check(EC_KEY_get0_group(eck), ctx);
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (checktype == OSSL_KEYMGMT_VALIDATE_QUICK_CHECK)
            ok = ok && qat_ec_key_public_check_quick(eck, ctx);
        else
            ok = ok && qat_ec_key_public_check(eck, ctx);
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && qat_ec_key_private_check(eck);

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR)
        ok = ok && qat_ec_key_pairwise_check(eck, ctx);

    BN_CTX_free(ctx);
    return ok;
}

static int qat_keymgmt_ec_match(const void *keydata1, const void *keydata2, int selection)
{
    const EC_KEY *ec1 = keydata1;
    const EC_KEY *ec2 = keydata2;
    const EC_GROUP *group_a = EC_KEY_get0_group(ec1);
    const EC_GROUP *group_b = EC_KEY_get0_group(ec2);
    BN_CTX *ctx = NULL;
    int ok = 1;

    if (!qat_prov_is_running())
        return 0;

    ctx = BN_CTX_new_ex(qat_keymgmt_ec_key_get_libctx(ec1));
    if (ctx == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && group_a != NULL && group_b != NULL
            && EC_GROUP_cmp(group_a, group_b, ctx) == 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int key_checked = 0;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
            const EC_POINT *pa = EC_KEY_get0_public_key(ec1);
            const EC_POINT *pb = EC_KEY_get0_public_key(ec2);

            if (pa != NULL && pb != NULL) {
                ok = ok && EC_POINT_cmp(group_b, pa, pb, ctx) == 0;
                key_checked = 1;
            }
        }
        if (!key_checked
            && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            const BIGNUM *pa = EC_KEY_get0_private_key(ec1);
            const BIGNUM *pb = EC_KEY_get0_private_key(ec2);

            if (pa != NULL && pb != NULL) {
                ok = ok && BN_cmp(pa, pb) == 0;
                key_checked = 1;
            }
        }
        ok = ok && key_checked;
    }
    BN_CTX_free(ctx);
    return ok;
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
