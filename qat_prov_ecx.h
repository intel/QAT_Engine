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
 * @file qat_prov_ecx.h
 *
 * This file provides an interface to qatprovider X25519 and X448 operations
 *
 *****************************************************************************/
#ifndef QAT_PROV_ECX_H
# define QAT_PROV_ECX_H

# include <openssl/core.h>
# include <openssl/provider.h>
# include <openssl/crypto.h>
# include "e_qat.h"

# define X25519_KEYLEN         32
# define X448_KEYLEN           56
# define ED448_KEYLEN          57
# define MAX_KEYLEN            57

#define QAT_ECX_KEY_TYPES()                                                        \
OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),                     \
OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)

typedef enum {
    ECX_KEY_TYPE_X25519,
    ECX_KEY_TYPE_X448,
}ECX_KEY_TYPE;

typedef void CRYPTO_RWLOCK;

typedef struct qat_ecx_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    unsigned int haspubkey:1;
    unsigned char pubkey[MAX_KEYLEN];
    unsigned char *privkey;
    size_t keylen;
    ECX_KEY_TYPE type;
    QAT_CRYPTO_REF_COUNT references;
}ECX_KEY;

typedef struct {
    size_t keylen;
    ECX_KEY *key;
    ECX_KEY *peerkey;
} QAT_ECX_CTX;

typedef struct ecx_gen_ctx {
    OSSL_LIB_CTX *libctx;
    char *propq;
    ECX_KEY_TYPE type;
    int selection;
# if OPENSSL_VERSION_NUMBER >= 0x30200000
    unsigned char *dhkem_ikm;
    size_t dhkem_ikmlen;
# endif
}QAT_GEN_CTX;

ECX_KEY *qat_ecx_key_new(OSSL_LIB_CTX *libctx, ECX_KEY_TYPE type, int haspubkey,
                         const char *propq);
int qat_ecx_key_up_ref(ECX_KEY *key);
void qat_ecx_key_free(ECX_KEY *key);
ECX_KEY *ecx_sw_keygen(OSSL_LIB_CTX *libctx, const char *propq,
                       ECX_KEY_TYPE type);
int ecx_sw_derive(QAT_ECX_CTX *ecxctx, unsigned char *secret,
                      size_t *secretlen, size_t outlen, ECX_KEY_TYPE type);
int qat_pkey_ecx_derive25519(void *ctx, unsigned char *key, size_t *keylen,
                             size_t outlen);
int qat_pkey_ecx_derive448(void *ctx, unsigned char *key, size_t *keylen,
                           size_t outlen);
void *qat_pkey_ecx25519_keygen(void *ctx, OSSL_CALLBACK *osslcb, void *cbarg);
void *qat_pkey_ecx448_keygen(void *ctx, OSSL_CALLBACK *osslcb, void *cbarg);
void* multibuff_x25519_keygen(void *ctx, OSSL_CALLBACK *osslcb,
                              void *cbarg);
int multibuff_x25519_derive(void *ctx, unsigned char *key,
                            size_t *keylen,size_t outlen);

#endif /* QAT_PROV_ECX_H */
