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
    ret->references = 1;

    if (propq != NULL) {
        ret->propq = OPENSSL_strdup(propq);
        if (ret->propq == NULL)
            goto err;
    }

    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL)
        goto err;
    return ret;
err:
    ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
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

#ifdef QAT_HW
static void *qat_x448_new_key(void *provctx)
{
    if (!qat_prov_is_running())
        return 0;
    return qat_ecx_key_new(prov_libctx_of(provctx), ECX_KEY_TYPE_X448, 0,
                           NULL);

}
#endif

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
#ifdef QAT_HW
    return qat_pkey_ecx_keygen(genctx,osslcb,cbarg);
#endif
#ifdef QAT_SW
    return multibuff_x25519_keygen(genctx,osslcb,cbarg);
#endif
}

#ifdef QAT_HW
static void *qat_x448_gen_init(void *provctx, int selection,
                               const OSSL_PARAM params[])
{
    return qat_ecx_gen_init(provctx, selection, params, ECX_KEY_TYPE_X448);
}

static void *qat_x448_gen(void *genctx, OSSL_CALLBACK *osslcb,
                          void *cbarg)
{
    return qat_pkey_ecx_keygen(genctx,osslcb,cbarg);
}
#endif

static void qat_ecx_gen_cleanup(void *genctx)
{
    QAT_GEN_CTX *gctx = genctx;
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

const OSSL_DISPATCH qat_X25519_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))qat_x25519_new_key},
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))qat_ecx_key_free},
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))qat_ecx_has },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))qat_x25519_gen_init},
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))qat_x25519_gen},
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) qat_ecx_gen_cleanup},
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void)) qat_ecx_load},
    { 0, NULL }};

#ifdef QAT_HW
const OSSL_DISPATCH qat_X448_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))qat_x448_new_key},
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))qat_ecx_key_free},
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))qat_ecx_has },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))qat_x448_gen_init},
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))qat_x448_gen},
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) qat_ecx_gen_cleanup},
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void)) qat_ecx_load},
    { 0, NULL }};
#endif
