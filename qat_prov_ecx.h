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

# define X25519_KEYLEN         32
# define X448_KEYLEN           56
# define ED448_KEYLEN          57
# define MAX_KEYLEN            57

typedef struct{
    int id; /* libcrypto internal */
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;
    int refcnt;
    void *lock;
    OSSL_FUNC_keymgmt_new_fn *new;
    OSSL_FUNC_keymgmt_free_fn *free;
    OSSL_FUNC_keymgmt_get_params_fn *get_params;
    OSSL_FUNC_keymgmt_gettable_params_fn *gettable_params;
    OSSL_FUNC_keymgmt_set_params_fn *set_params;
    OSSL_FUNC_keymgmt_settable_params_fn *settable_params;
    OSSL_FUNC_keymgmt_gen_init_fn *gen_init;
    OSSL_FUNC_keymgmt_gen_set_template_fn *gen_set_template;
    OSSL_FUNC_keymgmt_gen_set_params_fn *gen_set_params;
    OSSL_FUNC_keymgmt_gen_settable_params_fn *gen_settable_params;
    OSSL_FUNC_keymgmt_gen_fn *gen;
    OSSL_FUNC_keymgmt_gen_cleanup_fn *gen_cleanup;
    OSSL_FUNC_keymgmt_load_fn *load;
    OSSL_FUNC_keymgmt_query_operation_name_fn *query_operation_name;
    OSSL_FUNC_keymgmt_has_fn *has;
    OSSL_FUNC_keymgmt_validate_fn *validate;
    OSSL_FUNC_keymgmt_match_fn *match;
    OSSL_FUNC_keymgmt_import_fn *import;
    OSSL_FUNC_keymgmt_import_types_fn *import_types;
    OSSL_FUNC_keymgmt_export_fn *export;
    OSSL_FUNC_keymgmt_export_types_fn *export_types;
    OSSL_FUNC_keymgmt_dup_fn *dup;
} QAT_ECX_KEYMGMT;

typedef struct evp_keyexch_st {
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;
    int refcnt;
    void *lock;
    OSSL_FUNC_keyexch_newctx_fn *newctx;
    OSSL_FUNC_keyexch_init_fn *init;
    OSSL_FUNC_keyexch_set_peer_fn *set_peer;
    OSSL_FUNC_keyexch_derive_fn *derive;
    OSSL_FUNC_keyexch_freectx_fn *freectx;
    OSSL_FUNC_keyexch_dupctx_fn *dupctx;
    OSSL_FUNC_keyexch_set_ctx_params_fn *set_ctx_params;
    OSSL_FUNC_keyexch_settable_ctx_params_fn *settable_ctx_params;
    OSSL_FUNC_keyexch_get_ctx_params_fn *get_ctx_params;
    OSSL_FUNC_keyexch_gettable_ctx_params_fn *gettable_ctx_params;
} QAT_EVP_KEYEXCH;

QAT_ECX_KEYMGMT get_default_x25519_keymgmt();
QAT_ECX_KEYMGMT get_default_x448_keymgmt();
QAT_EVP_KEYEXCH get_default_x25519_keyexch();
QAT_EVP_KEYEXCH get_default_x448_keyexch();

typedef enum {
    ECX_KEY_TYPE_X25519,
    ECX_KEY_TYPE_X448,
}ECX_KEY_TYPE;

typedef int CRYPTO_REF_COUNT;
typedef void CRYPTO_RWLOCK;

typedef struct qat_ecx_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    unsigned int haspubkey:1;
    unsigned char pubkey[MAX_KEYLEN];
    unsigned char *privkey;
    size_t keylen;
    ECX_KEY_TYPE type;
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;
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
}QAT_GEN_CTX;

int qat_ecx_key_up_ref(ECX_KEY *key);
void qat_ecx_key_free(ECX_KEY *key);
int qat_pkey_ecx_derive25519(void *vecxctx, unsigned char *secret, size_t *secretlen,
                             size_t outlen);
int qat_pkey_ecx_derive448(void *vecxctx, unsigned char *secret, size_t *secretlen,
                           size_t outlen);
void *qat_pkey_ecx_keygen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg);
void* multibuff_x25519_keygen(void *genctx, OSSL_CALLBACK *osslcb,
                              void *cbarg);
int multibuff_x25519_derive(void *vecxctx, unsigned char *secret,
                            size_t *secretlen,size_t outlen);
#endif /* QAT_PROV_ECX_H */
