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
 * @file qat_prov_hkdf.h
 *
 * This file contains qatprovider interface of HKDF.
 *
 *****************************************************************************/

#ifndef QAT_PROV_HKDF_H
# define QAT_PROV_HKDF_H

# ifdef ENABLE_QAT_HW_HKDF

# include <stdlib.h>
# include <stdarg.h>
# include <string.h>
# include <openssl/core_dispatch.h>
# include <openssl/core_names.h>
# include <openssl/err.h>
# include <openssl/hmac.h>
# include <openssl/evp.h>
# include <openssl/kdf.h>
# include <openssl/core_names.h>
# include <openssl/proverr.h>

# include "qat_provider.h"
# include "qat_hw_hkdf.h"
# include "e_qat.h"
# include "qat_prov_hkdf_packet.h"
# define HKDF_MAXBUF 1024

typedef _Atomic int CRYPTO_REF_COUNT;
typedef void CRYPTO_RWLOCK;

struct kdf_data_st {
    OSSL_LIB_CTX *libctx;
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;
};

typedef struct kdf_data_st QAT_KDF_DATA;

typedef struct {
    /*
     * References to the underlying digest implementation.  |md| caches
     * the digest, always.  |alloc_md| only holds a reference to an explicitly
     * fetched digest.
     */
    const EVP_MD *md;           /* digest */
    EVP_MD *alloc_md;           /* fetched digest */

    /* Conditions for legacy EVP_MD uses */
    ENGINE *engine;             /* digest engine */
} PROV_DIGEST;

typedef struct {
    void *provctx;
    int mode;
    PROV_DIGEST digest;
    unsigned char *salt;
    size_t salt_len;
    unsigned char *key;
    size_t key_len;
    unsigned char *prefix;
    size_t prefix_len;
    unsigned char *label;
    size_t label_len;
    unsigned char *data;
    size_t data_len;
    unsigned char info[QAT_HKDF_INFO_MAXBUF];
    size_t info_len;
    EVP_PKEY_CTX *evp_pkey_ctx;
} QAT_KDF_HKDF;

struct evp_kdf_st {
    OSSL_PROVIDER *prov;
    int name_id;
    char *type_name;
    const char *description;
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;

    OSSL_FUNC_kdf_newctx_fn *newctx;
    OSSL_FUNC_kdf_dupctx_fn *dupctx;
    OSSL_FUNC_kdf_freectx_fn *freectx;
    OSSL_FUNC_kdf_reset_fn *reset;
    OSSL_FUNC_kdf_derive_fn *derive;
    OSSL_FUNC_kdf_gettable_params_fn *gettable_params;
    OSSL_FUNC_kdf_gettable_ctx_params_fn *gettable_ctx_params;
    OSSL_FUNC_kdf_settable_ctx_params_fn *settable_ctx_params;
    OSSL_FUNC_kdf_get_params_fn *get_params;
    OSSL_FUNC_kdf_get_ctx_params_fn *get_ctx_params;
    OSSL_FUNC_kdf_set_ctx_params_fn *set_ctx_params;
};
typedef struct evp_kdf_st EVP_KDF;

struct evp_pkey_ctx_st {
    /* Actual operation */
    int operation;

    /*
     * Library context, property query, keytype and keymgmt associated with
     * this context
     */
    OSSL_LIB_CTX *libctx;
    char *propquery;
    const char *keytype;
    /* If |pkey| below is set, this field is always a reference to its keymgmt */
    EVP_KEYMGMT *keymgmt;

    union {
        struct {
            void *genctx;
        } keymgmt;

        struct {
            EVP_KEYEXCH *exchange;
            /*
             * Opaque ctx returned from a providers exchange algorithm
             * implementation OSSL_FUNC_keyexch_newctx()
             */
            void *algctx;
        } kex;

        struct {
            EVP_SIGNATURE *signature;
            /*
             * Opaque ctx returned from a providers signature algorithm
             * implementation OSSL_FUNC_signature_newctx()
             */
            void *algctx;
        } sig;

        struct {
            EVP_ASYM_CIPHER *cipher;
            /*
             * Opaque ctx returned from a providers asymmetric cipher algorithm
             * implementation OSSL_FUNC_asym_cipher_newctx()
             */
            void *algctx;
        } ciph;
        struct {
            EVP_KEM *kem;
            /*
             * Opaque ctx returned from a providers KEM algorithm
             * implementation OSSL_FUNC_kem_newctx()
             */
            void *algctx;
        } encap;
    } op;

    /*
     * Cached parameters.  Inits of operations that depend on these should
     * call evp_pkey_ctx_use_delayed_data() when the operation has been set
     * up properly.
     */
    struct {
        /* Distinguishing Identifier, ISO/IEC 15946-3, FIPS 196 */
        char *dist_id_name; /* The name used with EVP_PKEY_CTX_ctrl_str() */
        void *dist_id;      /* The distinguishing ID itself */
        size_t dist_id_len; /* The length of the distinguishing ID */

        /* Indicators of what has been set.  Keep them together! */
        unsigned int dist_id_set : 1;
    } cached_parameters;

    /* Application specific data, usually used by the callback */
    void *app_data;
    /* Keygen callback */
    EVP_PKEY_gen_cb *pkey_gencb;
    /* implementation specific keygen data */
    int *keygen_info;
    int keygen_info_count;

    /* Legacy fields below */

    /* EVP_PKEY identity */
    int legacy_keytype;
    /* Method associated with this operation */
    const EVP_PKEY_METHOD *pmeth;
    /* Engine that implements this method or NULL if builtin */
    ENGINE *engine;
    /* Key: may be NULL */
    EVP_PKEY *pkey;
    /* Peer key for key agreement, may be NULL */
    EVP_PKEY *peerkey;
    /* Algorithm specific data */
    void *data;
    /* Indicator if digest_custom needs to be called */
    unsigned int flag_call_digest_custom:1;
    /*
     * Used to support taking custody of memory in the case of a provider being
     * used with the deprecated EVP_PKEY_CTX_set_rsa_keygen_pubexp() API. This
     * member should NOT be used for any other purpose and should be removed
     * when said deprecated API is excised completely.
     */
    BIGNUM *rsa_pubexp;
} /* EVP_PKEY_CTX */ ;

int qat_get_cipher_suite(QAT_HKDF_CTX * qat_hkdf_ctx);
# endif /* ENABLE_QAT_HW_HKDF */
#endif /* QAT_PROV_HKDF_H */
