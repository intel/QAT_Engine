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
 * @file qat_prov_exch_ecx.c
 *
 * This file contains the qatprovider implementation for X25519 and X448
 * QAT_HW & QAT_SW key exchange operations
 *
 *****************************************************************************/

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>
#include "qat_provider.h"
#include "qat_prov_ecx.h"
#include "qat_utils.h"
#include "e_qat.h"

QAT_EVP_KEYEXCH get_default_x25519_keyexch()
{
    static QAT_EVP_KEYEXCH s_keyexch;
    static int initialized = 0;
    if (!initialized) {
        QAT_EVP_KEYEXCH *keyexch = (QAT_EVP_KEYEXCH *)EVP_KEYEXCH_fetch(NULL,"X25519","provider=default");
        if (keyexch) {
           s_keyexch = *keyexch;
           EVP_KEYEXCH_free((EVP_KEYEXCH *)keyexch);
           initialized = 1;
        } else {
           WARN("EVP_KEYEXCH_fetch from default provider failed");
        }
    }
    return s_keyexch;
}

QAT_EVP_KEYEXCH get_default_x448_keyexch()
{
    static QAT_EVP_KEYEXCH s_keyexch;
    static int initialized = 0;
    if (!initialized) {
        QAT_EVP_KEYEXCH *keyexch = (QAT_EVP_KEYEXCH *)EVP_KEYEXCH_fetch(NULL,"X448","provider=default");
        if (keyexch) {
           s_keyexch = *keyexch;
           EVP_KEYEXCH_free((EVP_KEYEXCH *)keyexch);
           initialized = 1;
        } else {
           WARN("EVP_KEYEXCH_fetch from default provider failed");
        }
    }
    return s_keyexch;
}

static int qat_ecx_derive25519(void *vecxctx, unsigned char *secret,
                               size_t *secretlen, size_t outlen)
{
#ifdef QAT_HW
    return qat_pkey_ecx_derive25519(vecxctx,secret,secretlen,outlen);
#endif
#ifdef QAT_SW
    return multibuff_x25519_derive(vecxctx,secret,secretlen,outlen);
#endif
}

#ifdef QAT_HW
static int qat_ecx_derive448(void *vecxctx, unsigned char *secret,
                             size_t *secretlen, size_t outlen)
{
    return qat_pkey_ecx_derive448(vecxctx,secret,secretlen,outlen);
}
#endif

static void *qat_ecx_newctx(void *provctx, size_t keylen)
{
    QAT_ECX_CTX *ctx;

    if (!qat_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(QAT_ECX_CTX));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->keylen = keylen;
    return ctx;
}

static void *qat_x25519_newctx(void *provctx)
{
    return qat_ecx_newctx(provctx, X25519_KEYLEN);
}

#ifdef QAT_HW
static void *qat_x448_newctx(void *provctx)
{
    return qat_ecx_newctx(provctx, X448_KEYLEN);
}
#endif

static __inline__ int CRYPTO_UP_REF(int *val, int *ret, ossl_unused void *lock)
{
    *ret = __atomic_fetch_add(val, 1, __ATOMIC_RELAXED) + 1;
    return 1;
}

static __inline__ int CRYPTO_DOWN_REF(int *val, int *ret,
                                      ossl_unused void *lock)
{
    *ret = __atomic_fetch_sub(val, 1, __ATOMIC_RELAXED) - 1;
    if (*ret == 0)
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
    return 1;
}

int qat_ecx_key_up_ref(ECX_KEY *key)
{
    int i;

    if (CRYPTO_UP_REF(&key->references, &i, key->lock) <= 0)
        return 0;

    if(i < 2) {
        WARN("refcount error");
        return 0;
    }

    return ((i >1) ? 1 : 0);
}

void qat_ecx_key_free(ECX_KEY *key)
{
    int i;

    if (key == NULL)
        return;

    CRYPTO_DOWN_REF(&key->references, &i, key->lock);

    if (i > 0)
        return;

    if(i < 0) {
        WARN("refcount error");
        return;
    }

    OPENSSL_free(key->propq);
    OPENSSL_secure_clear_free(key->privkey, key->keylen);
    CRYPTO_THREAD_lock_free(key->lock);
    OPENSSL_free(key);
}

static int qat_ecx_init(void *vecxctx, void *vkey,
                        ossl_unused const OSSL_PARAM params[])
{
    QAT_ECX_CTX *ecxctx = (QAT_ECX_CTX *)vecxctx;
    ECX_KEY *key = vkey;

    if (!qat_prov_is_running())
        return 0;

    if (ecxctx == NULL
        || key == NULL
        || key->keylen != ecxctx->keylen
        || !qat_ecx_key_up_ref(key)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    qat_ecx_key_free(ecxctx->key);
    ecxctx->key = key;

    return 1;
}

static int qat_ecx_set_peer(void *vecxctx, void *vkey)
{
    QAT_ECX_CTX *ecxctx = (QAT_ECX_CTX *)vecxctx;
    ECX_KEY *key = vkey;

    if (!qat_prov_is_running())
        return 0;

    if (ecxctx == NULL
        || key == NULL
        || key->keylen != ecxctx->keylen
        || !qat_ecx_key_up_ref(key)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    qat_ecx_key_free(ecxctx->peerkey);
    ecxctx->peerkey = key;

    return 1;
}

static void qat_ecx_freectx(void *vecxctx)
{
    QAT_ECX_CTX *ecxctx = (QAT_ECX_CTX *)vecxctx;
    qat_ecx_key_free(ecxctx->key);
    qat_ecx_key_free(ecxctx->peerkey);
    OPENSSL_free(ecxctx);
}

static void *qat_ecx_dupctx(void *vecxctx)
{
    typedef void * (*fun_ptr)(void *vecxctx);
    fun_ptr fun = get_default_x25519_keyexch().dupctx;
    if (!fun)
        return NULL;
    return fun(vecxctx);
}

const OSSL_DISPATCH qat_X25519_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))qat_x25519_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))qat_ecx_init },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))qat_ecx_derive25519 },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))qat_ecx_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))qat_ecx_freectx },
    { OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))qat_ecx_dupctx },
    { 0, NULL }
};

#ifdef QAT_HW
const OSSL_DISPATCH qat_X448_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))qat_x448_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))qat_ecx_init },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))qat_ecx_derive448 },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))qat_ecx_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))qat_ecx_freectx },
    {0, NULL }
};
#endif
