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
 * @file qat_prov_kmgmt_ecx.c
 *
 * This file contains X25519 qatprovider key management implementation
 * for QAT_HW & QAT_SW
 *
 *****************************************************************************/

#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include "qat_provider.h"
#include "qat_prov_ecx.h"
#include "qat_utils.h"
#include "e_qat.h"

#if defined(ENABLE_QAT_HW_ECX) || defined(ENABLE_QAT_SW_ECX)
QAT_ECX_KEYMGMT get_default_x25519_keymgmt()
{
    static QAT_ECX_KEYMGMT s_keymgmt;
    static int initialized = 0;
    if (!initialized) {
        QAT_ECX_KEYMGMT *keymgmt = (QAT_ECX_KEYMGMT *)EVP_KEYMGMT_fetch(NULL,"X25519","provider=default");
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

ECX_KEY *qat_ecx_key_new(OSSL_LIB_CTX *libctx, ECX_KEY_TYPE type, int haspubkey,
                         const char *propq)
{
    ECX_KEY *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL)
        return NULL;

    ret->libctx = libctx;
    ret->haspubkey = haspubkey;
    switch (type) {
    case ECX_KEY_TYPE_X25519:
         ret->keylen = X25519_KEYLEN;
         break;
    case ECX_KEY_TYPE_X448:
         ret->keylen = X448_KEYLEN;
         break;
    }
    ret->type = type;
    ret->references.val = 1;

    if (propq != NULL) {
        ret->propq = OPENSSL_strdup(propq);
        if (ret->propq == NULL)
            goto err;
    }
    return ret;
err:
    QATerr(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
    OPENSSL_free(ret);
    return NULL;
}

static void *qat_x25519_new_key(void *provctx)
{
    if (!qat_prov_is_running())
        return 0;
    return qat_ecx_key_new(prov_libctx_of(provctx), ECX_KEY_TYPE_X25519, 0,
                           NULL);
}

static int qat_ecx_has(const void *keydata, int selection)
{
    const ECX_KEY *key = keydata;
    int ok = 0;

    if (qat_prov_is_running() && key != NULL) {
        ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
             ok = ok && key->haspubkey;

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
             ok = ok && key->privkey != NULL;
    }
        return ok;
}

void *qat_ecx_load(const void *reference, size_t reference_sz)
{
    ECX_KEY *key = NULL;

    if (qat_prov_is_running() && reference_sz == sizeof(key)) {
        /* The contents of the reference is the address to our object */
        key = *(ECX_KEY **)reference;
        /* We grabbed, so we detach it */
        *(ECX_KEY **)reference = NULL;
        return key;
    }
    return NULL;
}

static void *qat_ecx_gen_init(void *provctx, int selection,
                              const OSSL_PARAM params[], ECX_KEY_TYPE type)
{
    OSSL_LIB_CTX *libctx = prov_libctx_of(provctx);
    QAT_GEN_CTX *gctx = NULL;

    if (!qat_prov_is_running())
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->libctx = libctx;
        gctx->type = type;
        gctx->selection = selection;
    }
    return gctx;
}

static void *qat_x25519_gen_init(void *provctx, int selection,
                                 const OSSL_PARAM params[])
{
    return qat_ecx_gen_init(provctx, selection, params, ECX_KEY_TYPE_X25519);
}

static void *qat_x25519_gen(void *genctx, OSSL_CALLBACK *osslcb,
                            void *cbarg)
{
#ifdef ENABLE_QAT_HW_ECX
    if (qat_hw_ecx_offload)
        return qat_pkey_ecx25519_keygen(genctx,osslcb,cbarg);
#endif
#ifdef ENABLE_QAT_SW_ECX
    if (qat_sw_ecx_offload) {
        return multibuff_x25519_keygen(genctx,osslcb,cbarg);
    } else {
      typedef void* (*fun_ptr)(void *genctx, OSSL_CALLBACK *osslcb,
                               void *cbarg);
      fun_ptr fun = get_default_x25519_keymgmt().gen;
      if (!fun)
          return NULL;
      return fun(genctx, osslcb, cbarg);
    }

#endif
    return 0;
}

#ifdef ENABLE_QAT_HW_ECX
static void *qat_x448_gen_init(void *provctx, int selection,
                               const OSSL_PARAM params[])
{
    return qat_ecx_gen_init(provctx, selection, params, ECX_KEY_TYPE_X448);
}

static void *qat_x448_gen(void *genctx, OSSL_CALLBACK *osslcb,
                          void *cbarg)
{
    return qat_pkey_ecx448_keygen(genctx,osslcb,cbarg);
}
#endif

static void qat_ecx_gen_cleanup(void *genctx)
{
    QAT_GEN_CTX *gctx = genctx;
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

static int qat_param_build_set_octet_string(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
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

static int qat_key_to_params(ECX_KEY *key, OSSL_PARAM_BLD *tmpl,
                         OSSL_PARAM params[], int include_private)
{
    if (key == NULL)
        return 0;

    if (!qat_param_build_set_octet_string(tmpl, params,
                                           OSSL_PKEY_PARAM_PUB_KEY,
                                           key->pubkey, key->keylen))
        return 0;

    if (include_private
        && key->privkey != NULL
        && !qat_param_build_set_octet_string(tmpl, params,
                                              OSSL_PKEY_PARAM_PRIV_KEY,
                                              key->privkey, key->keylen))
        return 0;

    return 1;
}

static int qat_ecx_get_params(void *key, OSSL_PARAM params[], int bits, int secbits,
                          int size)
{
    ECX_KEY *ecx = key;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, bits))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, secbits))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, size))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL
            && (ecx->type == ECX_KEY_TYPE_X25519
                || ecx->type == ECX_KEY_TYPE_X448)) {
        if (!OSSL_PARAM_set_octet_string(p, ecx->pubkey, ecx->keylen))
            return 0;
    }
    return qat_key_to_params(ecx, NULL, params, 1);
}

static int qat_x25519_get_params(void *key, OSSL_PARAM params[])
{
    return qat_ecx_get_params(key, params, X25519_BITS, X25519_SECURITY_BITS,
                          X25519_KEYLEN);
}

static const OSSL_PARAM qat_kmgmt_ecx_gettable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    QAT_ECX_KEY_TYPES(),
    OSSL_PARAM_END
};

static const OSSL_PARAM *qat_ecx_gettable_params(void *provctx)
{
    return qat_kmgmt_ecx_gettable_params;
}

static int qat_set_property_query(ECX_KEY *ecxkey, const char *propq)
{
    OPENSSL_free(ecxkey->propq);
    ecxkey->propq = NULL;
    if (propq != NULL) {
        ecxkey->propq = OPENSSL_strdup(propq);
        if (ecxkey->propq == NULL)
            return 0;
    }
    return 1;
}

static int qat_ecx_set_params(void *key, const OSSL_PARAM params[])
{
    ECX_KEY *ecxkey = key;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        void *buf = ecxkey->pubkey;

        if (p->data_size != ecxkey->keylen
                || !OSSL_PARAM_get_octet_string(p, &buf, sizeof(ecxkey->pubkey),
                                                NULL))
            return 0;
        OPENSSL_clear_free(ecxkey->privkey, ecxkey->keylen);
        ecxkey->privkey = NULL;
        ecxkey->haspubkey = 1;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING
            || !qat_set_property_query(ecxkey, p->data))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM qat_kmgmt_ecx_settable_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *qat_ecx_settable_params(void *provctx)
{
    return qat_kmgmt_ecx_settable_params;
}

#ifdef ENABLE_QAT_HW_ECX
QAT_ECX_KEYMGMT get_default_x448_keymgmt()
{
    static QAT_ECX_KEYMGMT s_keymgmt;
    static int initialized = 0;
    if (!initialized) {
        QAT_ECX_KEYMGMT *keymgmt = (QAT_ECX_KEYMGMT *)EVP_KEYMGMT_fetch(NULL,"X448","provider=default");
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

static void *qat_x448_new_key(void *provctx)
{
    if (!qat_prov_is_running())
        return 0;
    return qat_ecx_key_new(prov_libctx_of(provctx), ECX_KEY_TYPE_X448, 0,
                           NULL);

}

static int qat_x448_get_params(void *key, OSSL_PARAM params[])
{
    return qat_ecx_get_params(key, params, X448_BITS, X448_SECURITY_BITS,
                          X448_KEYLEN);
}

#endif

static int qat_ecx_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    QAT_GEN_CTX *gctx = genctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL) {
        const char *groupname = NULL;

        /*
         * We optionally allow setting a group name - but each algorithm only
         * support one such name, so all we do is verify that it is the one we
         * expected.
         */
        switch (gctx->type) {
            case ECX_KEY_TYPE_X25519:
                groupname = "x25519";
                break;
            case ECX_KEY_TYPE_X448:
                groupname = "x448";
                break;
            default:
                /* We only support this for key exchange at the moment */
                break;
        }
        if (p->data_type != OSSL_PARAM_UTF8_STRING
                || groupname == NULL
                || OPENSSL_strcasecmp(p->data, groupname) != 0) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        OPENSSL_free(gctx->propq);
        gctx->propq = OPENSSL_strdup(p->data);
        if (gctx->propq == NULL)
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *qat_ecx_gen_settable_params(ossl_unused void *genctx,
                                                     ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END
    };
    return settable;
}

static int qat_ecx_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                          void *cbarg)
{
    ECX_KEY *key = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    if (!qat_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private = ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);

        if (!qat_key_to_params(key, tmpl, NULL, include_private))
            goto err;
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);
    OSSL_PARAM_free(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    return ret;
}

static const OSSL_PARAM qat_ecx_key_types[] = {
    QAT_ECX_KEY_TYPES(),
    OSSL_PARAM_END
};

static const OSSL_PARAM *qat_ecx_export_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return qat_ecx_key_types;
    return NULL;
}


unsigned char *qat_ecx_key_allocate_privkey(ECX_KEY *key)
{
    key->privkey = OPENSSL_secure_zalloc(key->keylen);

    return key->privkey;
}

ECX_KEY *qat_ecx_key_dup(const ECX_KEY *key, int selection)
{
    ECX_KEY *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        QATerr(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->libctx = key->libctx;
    ret->haspubkey = key->haspubkey;
    ret->keylen = key->keylen;
    ret->type = key->type;
    ret->references.val = 1;

    if (key->propq != NULL) {
        ret->propq = OPENSSL_strdup(key->propq);
        if (ret->propq == NULL)
            goto err;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        memcpy(ret->pubkey, key->pubkey, sizeof(ret->pubkey));

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && key->privkey != NULL) {
        if (qat_ecx_key_allocate_privkey(ret) == NULL)
            goto err;
        memcpy(ret->privkey, key->privkey, ret->keylen);
    }

    return ret;

err:
    qat_ecx_key_free(ret);
    QATerr(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
    return NULL;
}

static void *qat_ecx_dup(const void *keydata_from, int selection)
{
    if (qat_prov_is_running())
        return qat_ecx_key_dup(keydata_from, selection);
    return NULL;
}

const OSSL_DISPATCH qat_X25519_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))qat_x25519_new_key},
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))qat_ecx_key_free},
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))qat_ecx_has },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))qat_x25519_gen_init},
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))qat_x25519_gen},
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) qat_ecx_gen_cleanup},
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void)) qat_ecx_load},
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))qat_x25519_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))qat_ecx_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))qat_ecx_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))qat_ecx_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))qat_ecx_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        (void (*)(void))qat_ecx_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))qat_ecx_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))qat_ecx_export_types },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))qat_ecx_dup },
    { 0, NULL }};
#endif

#ifdef ENABLE_QAT_HW_ECX
const OSSL_DISPATCH qat_X448_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))qat_x448_new_key},
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))qat_ecx_key_free},
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))qat_ecx_has },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))qat_x448_gen_init},
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))qat_x448_gen},
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) qat_ecx_gen_cleanup},
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void)) qat_ecx_load},
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))qat_x448_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))qat_ecx_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))qat_ecx_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))qat_ecx_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))qat_ecx_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        (void (*)(void))qat_ecx_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))qat_ecx_dup },
    { 0, NULL }};
#endif
