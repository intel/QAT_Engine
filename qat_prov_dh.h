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
 * @file qat_prov_dh.h
 *
 * This file provides an interface to Qat Provider DH operations
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif

#ifndef QAT_PROV_DH_H
#define QAT_PROV_DH_H

#include <string.h>
#include <stdio.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/params.h>

typedef int CRYPTO_REF_COUNT;
#define FFC_UNVERIFIABLE_GINDEX -1
#define FFC_PARAM_FLAG_VALIDATE_PQ 0x01
#define FFC_PARAM_FLAG_VALIDATE_G 0x02
#define FFC_PARAM_FLAG_VALIDATE_PQG \
    (FFC_PARAM_FLAG_VALIDATE_PQ | FFC_PARAM_FLAG_VALIDATE_G)
typedef struct ffc_params_st
{
    /* Primes */
    BIGNUM *p;
    BIGNUM *q;
    /* Generator */
    BIGNUM *g;
    /* DH X9.42 Optional Subgroup factor j >= 2 where p = j * q + 1 */
    BIGNUM *j;

    /* Required for FIPS186_4 validation of p, q and optionally canonical g */
    unsigned char *seed;
    /* If this value is zero the hash size is used as the seed length */
    size_t seedlen;
    /* Required for FIPS186_4 validation of p and q */
    int pcounter;
    int nid; /* The identity of a named group */

    /*
     * Required for FIPS186_4 generation & validation of canonical g.
     * It uses unverifiable g if this value is -1.
     */
    int gindex;
    int h; /* loop counter for unverifiable g */

    unsigned int flags;
    /*
     * The digest to use for generation or validation. If this value is NULL,
     * then the digest is chosen using the value of N.
     */
    const char *mdname;
    const char *mdprops;
} FFC_PARAMS;

struct dh_st
{
    /*
     * This first argument is used to pick up errors when a DH is passed
     * instead of a EVP_PKEY
     */
    int pad;
    int version;
    FFC_PARAMS params;
    /* max generated private key length (can be less than len(q)) */
    int32_t length;
    BIGNUM *pub_key;  /* g^x % p */
    BIGNUM *priv_key; /* x */
    int flags;
    BN_MONT_CTX *method_mont_p;
    CRYPTO_REF_COUNT references;
#ifndef FIPS_MODULE
    CRYPTO_EX_DATA ex_data;
    ENGINE *engine;
#endif
    OSSL_LIB_CTX *libctx;
    const DH_METHOD *meth;
    CRYPTO_RWLOCK *lock;

    /* Provider data */
    size_t dirty_cnt; /* If any key material changes, increment this */
};

struct dh_method
{
    char *name;
    /* Methods here */
    int (*generate_key)(DH *dh);
    int (*compute_key)(unsigned char *key, const BIGNUM *pub_key, DH *dh);

    /* Can be null */
    int (*bn_mod_exp)(const DH *dh, BIGNUM *r, const BIGNUM *a,
                      const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                      BN_MONT_CTX *m_ctx);
    int (*init)(DH *dh);
    int (*finish)(DH *dh);
    int flags;
    char *app_data;
    /* If this is non-NULL, it will be used to generate parameters */
    int (*generate_params)(DH *dh, int prime_len, int generator,
                           BN_GENCB *cb);
};

/*
 * This type is only really used to handle some legacy related functionality.
 * If you need to use other KDF's (such as SSKDF) just use PROV_DH_KDF_NONE
 * here and then create and run a KDF after the key is derived.
 * Note that X942 has 2 variants of key derivation:
 *   (1) DH_KDF_X9_42_ASN1 - which contains an ANS1 encoded object that has
 *   the counter embedded in it.
 *   (2) DH_KDF_X941_CONCAT - which is the same as ECDH_X963_KDF (which can be
 *       done by creating a "X963KDF".
 */
enum kdf_type
{
    PROV_DH_KDF_NONE = 0,
    PROV_DH_KDF_X9_42_ASN1
};

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes DH structures, so
 * we use that here too.
 */

typedef struct
{
    OSSL_LIB_CTX *libctx;
    DH *dh;
    DH *dhpeer;
    unsigned int pad : 1;

    /* DH KDF */
    /* KDF (if any) to use for DH */
    enum kdf_type kdf_type;
    /* Message digest to use for key derivation */
    EVP_MD *kdf_md;
    /* User key material */
    unsigned char *kdf_ukm;
    size_t kdf_ukmlen;
    /* KDF output length */
    size_t kdf_outlen;
    char *kdf_cekalg;
} QAT_PROV_DH_CTX;

#endif /* QAT_PROVIDER_DH_H */