/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2026 Intel Corporation.
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

#if defined(ENABLE_QAT_HW_ECX) || defined(ENABLE_QAT_SW_ECX)
#ifdef ENABLE_QAT_FIPS
# include "qat_prov_cmvp.h"
extern int qat_fips_key_zeroize;
#endif

ECX_KEY *ecx_sw_keygen(OSSL_LIB_CTX *libctx, const char *propq,
                            ECX_KEY_TYPE type)
{
    const char *algname = (type == ECX_KEY_TYPE_X25519) ? "X25519" : "X448";
    size_t keylen = (type == ECX_KEY_TYPE_X25519) ? X25519_KEYLEN : X448_KEYLEN;
    /* Explicitly use the default provider to avoid re-entering qatprovider. */
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(libctx, "provider=default", algname);
    if (pkey == NULL)
        return NULL;

    ECX_KEY *key = qat_ecx_key_new(libctx, type, 1, propq);
    if (key == NULL)
        goto err;

    size_t pub_len = keylen, priv_len = keylen;
    if (!EVP_PKEY_get_raw_public_key(pkey, key->pubkey, &pub_len))
        goto err;
    if ((key->privkey = OPENSSL_secure_zalloc(keylen)) == NULL)
        goto err;
    if (!EVP_PKEY_get_raw_private_key(pkey, key->privkey, &priv_len))
        goto err;

    EVP_PKEY_free(pkey);
    return key;
err:
    qat_ecx_key_free(key);
    EVP_PKEY_free(pkey);
    return NULL;
}

int ecx_sw_derive(QAT_ECX_CTX *ecxctx, unsigned char *secret,
                      size_t *secretlen, size_t outlen, ECX_KEY_TYPE type)
{
    if (ecxctx == NULL || ecxctx->key == NULL || ecxctx->key->privkey == NULL
        || ecxctx->peerkey == NULL)
        return 0;

    const char *algname = (type == ECX_KEY_TYPE_X25519) ? "X25519" : "X448";
    OSSL_LIB_CTX *libctx = ecxctx->key->libctx;
    /* Explicitly use the default provider to avoid re-entering qatprovider. */
    EVP_PKEY *priv = EVP_PKEY_new_raw_private_key_ex(libctx, algname, "provider=default",
                                                     ecxctx->key->privkey,
                                                     ecxctx->key->keylen);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key_ex(libctx, algname, "provider=default",
                                                    ecxctx->peerkey->pubkey,
                                                    ecxctx->peerkey->keylen);
    EVP_PKEY_CTX *pctx = NULL;
    int ret = 0;

    if (priv == NULL || peer == NULL)
        goto err;
    pctx = EVP_PKEY_CTX_new_from_pkey(libctx, priv, "provider=default");
    if (pctx == NULL
        || EVP_PKEY_derive_init(pctx) <= 0
        || EVP_PKEY_derive_set_peer(pctx, peer) <= 0)
        goto err;
    /* Size query: let EVP_PKEY_derive fill *secretlen */
    if (secret == NULL) {
        if (EVP_PKEY_derive(pctx, NULL, secretlen) <= 0)
            goto err;
    } else {
        /* outlen is the caller's buffer size; pass it as *secretlen */
        *secretlen = outlen;
        if (EVP_PKEY_derive(pctx, secret, secretlen) <= 0)
            goto err;
    }
    ret = 1;
err:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(peer);
    return ret;
}

static int qat_ecx_derive25519(void *vecxctx, unsigned char *secret,
                               size_t *secretlen, size_t outlen)
{
    int ret = 0;
#ifdef ENABLE_QAT_HW_ECX
    if (qat_hw_ecx_offload)
        return qat_pkey_ecx_derive25519(vecxctx,secret,secretlen,outlen);
#endif
#ifdef ENABLE_QAT_SW_ECX
    if (qat_sw_ecx_offload) {
        ret = multibuff_x25519_derive(vecxctx, secret, secretlen, outlen);
    }
#endif

    return ret;
}

#ifdef ENABLE_QAT_HW_ECX
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
        QATerr(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->keylen = keylen;
    return ctx;
}

static void *qat_x25519_newctx(void *provctx)
{
    return qat_ecx_newctx(provctx, X25519_KEYLEN);
}

#ifdef ENABLE_QAT_HW_ECX
static void *qat_x448_newctx(void *provctx)
{
    return qat_ecx_newctx(provctx, X448_KEYLEN);
}
#endif

int qat_ecx_key_up_ref(ECX_KEY *key)
{
    int i;

    if (QAT_CRYPTO_UP_REF(&key->references, &i) <= 0)
        return 0;

    if (i < 2) {
        WARN("refcount error");
        return 0;
    }

    return 1;
}

void qat_ecx_key_free(ECX_KEY *key)
{
#ifdef ENABLE_QAT_FIPS
    qat_fips_key_zeroize = 0;
#endif
    int i;

    if (key == NULL)
        return;
    QAT_CRYPTO_DOWN_REF(&key->references, &i);

    if (i > 0)
        return;

    if(i < 0) {
        WARN("refcount error");
        return;
    }

    OPENSSL_free(key->propq);
    OPENSSL_secure_clear_free(key->privkey, key->keylen);
    OPENSSL_free(key);
#ifdef ENABLE_QAT_FIPS
    qat_fips_key_zeroize = 1;
    qat_fips_get_key_zeroize_status();
#endif
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
        QATerr(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
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
        QATerr(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
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
    QAT_ECX_CTX *srcctx = (QAT_ECX_CTX *)vecxctx;
    QAT_ECX_CTX *dstctx;

    if (!qat_prov_is_running())
        return NULL;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    if (dstctx->key != NULL && !qat_ecx_key_up_ref(dstctx->key)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        OPENSSL_free(dstctx);
        return NULL;
    }

    if (dstctx->peerkey != NULL && !qat_ecx_key_up_ref(dstctx->peerkey)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        qat_ecx_key_free(dstctx->key);
        OPENSSL_free(dstctx);
        return NULL;
    }

    return dstctx;
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
#endif

#ifdef QAT_HW
# ifdef ENABLE_QAT_HW_ECX
const OSSL_DISPATCH qat_X448_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))qat_x448_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))qat_ecx_init },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))qat_ecx_derive448 },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))qat_ecx_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))qat_ecx_freectx },
    {0, NULL }
};
# endif
#endif
