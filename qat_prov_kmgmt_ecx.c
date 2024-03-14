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
#if OPENSSL_VERSION_NUMBER < 0x30200000
    ret->references = 1;
#else
    ret->references.val = 1;
#endif

    if (propq != NULL) {
        ret->propq = OPENSSL_strdup(propq);
        if (ret->propq == NULL)
            goto err;
    }
#if OPENSSL_VERSION_NUMBER < 0x30200000
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL)
        goto err;
#endif
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
    if (qat_sw_ecx_offload)
        return multibuff_x25519_keygen(genctx,osslcb,cbarg);
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

static int qat_x25519_get_params(void *key, OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *key, OSSL_PARAM params[]);
    fun_ptr fun = get_default_x25519_keymgmt().get_params;
    if (!fun)
        return 0;
    return fun(key, params);
}

static const OSSL_PARAM *qat_x25519_gettable_params(void *provctx)
{
    typedef const OSSL_PARAM * (*fun_ptr)(void *provctx);
    fun_ptr fun = get_default_x25519_keymgmt().gettable_params;
    if (!fun)
        return NULL;
    return fun(provctx);
}

static int qat_x25519_set_params(void *key, const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *key, const OSSL_PARAM params[]);
    fun_ptr fun = get_default_x25519_keymgmt().set_params;
    if (!fun)
        return 0;
    return fun(key, params);
}

static const OSSL_PARAM *qat_x25519_settable_params(void *provctx)
{
    typedef const OSSL_PARAM * (*fun_ptr)(void *provctx);
    fun_ptr fun = get_default_x25519_keymgmt().settable_params;
    if (!fun)
        return NULL;
    return fun(provctx);
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
    typedef int (*fun_ptr)(void *key, OSSL_PARAM params[]);
    fun_ptr fun = get_default_x448_keymgmt().get_params;
    if (!fun)
        return 0;
    return fun(key, params);
}

static const OSSL_PARAM *qat_x448_gettable_params(void *provctx)
{
    typedef const OSSL_PARAM * (*fun_ptr)(void *provctx);
    fun_ptr fun = get_default_x448_keymgmt().gettable_params;
    if (!fun)
        return NULL;
    return fun(provctx);
}

static int qat_x448_set_params(void *key, const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *key, const OSSL_PARAM params[]);
    fun_ptr fun = get_default_x448_keymgmt().set_params;
    if (!fun)
        return 0;
    return fun(key, params);
}

static const OSSL_PARAM *qat_x448_settable_params(void *provctx)
{
    typedef const OSSL_PARAM * (*fun_ptr)(void *provctx);
    fun_ptr fun = get_default_x448_keymgmt().settable_params;
    if (!fun)
        return NULL;
    return fun(provctx);
}
#endif

static int qat_ecx_match(const void *keydata1, const void *keydata2, int selection)
{
    typedef int (*fun_ptr)(const void *keydata1, const void *keydata2, int selection);
    fun_ptr fun = get_default_x25519_keymgmt().match;
    if (!fun)
        return 0;
    return fun(keydata1, keydata2, selection);
}

static int qat_ecx_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *keydata, int selection, const OSSL_PARAM params[]);
    fun_ptr fun = get_default_x25519_keymgmt().import;
    if (!fun)
        return 0;
    return fun(keydata, selection, params);
}

static const OSSL_PARAM *qat_ecx_import_types(int selection)
{
    typedef const OSSL_PARAM * (*fun_ptr)(int selection);
    fun_ptr fun = get_default_x25519_keymgmt().import_types;
    if (!fun)
        return NULL;
    return fun(selection);
}

static const OSSL_PARAM *qat_ecx_export_types(int selection)
{
    typedef const OSSL_PARAM * (*fun_ptr)(int selection);
    fun_ptr fun = get_default_x25519_keymgmt().export_types;
    if (!fun)
        return NULL;
    return fun(selection);
}

static int qat_ecx_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                          void *cbarg)
{
    typedef int (*fun_ptr)(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                           void *cbarg);
    fun_ptr fun = get_default_x25519_keymgmt().export;
    if (!fun)
        return 0;
    return fun(keydata, selection, param_cb, cbarg);
}

static int qat_ecx_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *genctx, const OSSL_PARAM params[]);
    fun_ptr fun = get_default_x25519_keymgmt().gen_set_params;
    if (!fun)
        return 0;
    return fun(genctx, params);
}

static const OSSL_PARAM *qat_ecx_gen_settable_params(ossl_unused void *genctx,
                                                     ossl_unused void *provctx)
{
    typedef const OSSL_PARAM * (*fun_ptr)(ossl_unused void *genctx, 
                                          ossl_unused void *provctx);
    fun_ptr fun = get_default_x25519_keymgmt().gen_settable_params;
    if (!fun)
        return NULL;
    return fun(genctx, provctx);
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
#if OPENSSL_VERSION_NUMBER < 0x30200000
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        OPENSSL_free(ret);
        return NULL;
    }
#endif
    ret->libctx = key->libctx;
    ret->haspubkey = key->haspubkey;
    ret->keylen = key->keylen;
    ret->type = key->type;
#if OPENSSL_VERSION_NUMBER < 0x30200000
    ret->references = 1;
#else
    ret->references.val = 1;
#endif

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
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))qat_x25519_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))qat_x25519_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))qat_x25519_settable_params },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))qat_ecx_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))qat_ecx_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))qat_ecx_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))qat_ecx_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))qat_ecx_export_types },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))qat_ecx_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        (void (*)(void))qat_ecx_gen_settable_params },
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
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))qat_x448_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))qat_x448_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))qat_x448_settable_params },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))qat_ecx_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))qat_ecx_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))qat_ecx_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))qat_ecx_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))qat_ecx_export_types },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))qat_ecx_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        (void (*)(void))qat_ecx_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))qat_ecx_dup },
    { 0, NULL }};
#endif
