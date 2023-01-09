/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2023 Intel Corporation.
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
 * @file qat_prov_dsa.h
 *
 * This file provides an interface to Qat Provider DSA operations
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif

#ifndef QAT_PROV_DSA_H
#define QAT_PROV_DSA_H

#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include <openssl/dsa.h>
#include <stdio.h>
#include <string.h>

#define OSSL_MAX_NAME_SIZE 50          /* Algorithm name */
#define OSSL_MAX_PROPQUERY_SIZE 256    /* Property query strings */
#define OSSL_MAX_ALGORITHM_ID_SIZE 256 /* AlgorithmIdentifier DER */

typedef int CRYPTO_REF_COUNT;
#define FFC_UNVERIFIABLE_GINDEX -1
#define FFC_PARAM_FLAG_VALIDATE_PQ 0x01
#define FFC_PARAM_FLAG_VALIDATE_G 0x02
#define FFC_PARAM_FLAG_VALIDATE_PQG \
    (FFC_PARAM_FLAG_VALIDATE_PQ | FFC_PARAM_FLAG_VALIDATE_G)

struct DSA_SIG_st
{
    BIGNUM *r;
    BIGNUM *s;
};

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
#if OPENSSL_VERSION_NUMBER >= 0x30000060
    /* Default key length for known named groups according to RFC7919 */
    int keylength;
#endif
} FFC_PARAMS;

struct dsa_st
{
    /*
     * This first variable is used to pick up errors where a DSA is passed
     * instead of of a EVP_PKEY
     */
    int pad;
    int32_t version;
    FFC_PARAMS params;
    BIGNUM *pub_key;  /* y public key */
    BIGNUM *priv_key; /* x private key */
    int flags;
    /* Normally used to cache montgomery values */
    BN_MONT_CTX *method_mont_p;
    CRYPTO_REF_COUNT references;
#ifndef FIPS_MODULE
    CRYPTO_EX_DATA ex_data;
#endif
    const DSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    CRYPTO_RWLOCK *lock;
    OSSL_LIB_CTX *libctx;

    /* Provider data */
    size_t dirty_cnt; /* If any key material changes, increment this */
};

typedef struct
{
    OSSL_LIB_CTX *libctx;
    char *propq;
    DSA *dsa;

    /*
     * Flag to determine if the hash function can be changed (1) or not (0)
     * Because it's dangerous to change during a DigestSign or DigestVerify
     * operation, this flag is cleared by their Init function, and set again
     * by their Final function.
     */
    unsigned int flag_allow_md : 1;

    char mdname[OSSL_MAX_NAME_SIZE];

    /* The Algorithm Identifier of the combined signature algorithm */
    unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
    unsigned char *aid;
    size_t aid_len;

    /* main digest */
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    int operation;
} QAT_PROV_DSA_CTX;

struct dsa_method
{
    char *name;
    DSA_SIG *(*dsa_do_sign)(const unsigned char *dgst, int dlen, DSA *dsa);
    int (*dsa_sign_setup)(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp,
                          BIGNUM **rp);
    int (*dsa_do_verify)(const unsigned char *dgst, int dgst_len,
                         DSA_SIG *sig, DSA *dsa);
    int (*dsa_mod_exp)(DSA *dsa, BIGNUM *rr, const BIGNUM *a1,
                       const BIGNUM *p1, const BIGNUM *a2, const BIGNUM *p2,
                       const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont);
    /* Can be null */
    int (*bn_mod_exp)(DSA *dsa, BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                      const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
    int (*init)(DSA *dsa);
    int (*finish)(DSA *dsa);
    int flags;
    void *app_data;
    /* If this is non-NULL, it is used to generate DSA parameters */
    int (*dsa_paramgen)(DSA *dsa, int bits,
                        const unsigned char *seed, int seed_len,
                        int *counter_ret, unsigned long *h_ret,
                        BN_GENCB *cb);
    /* If this is non-NULL, it is used to generate DSA keys */
    int (*dsa_keygen)(DSA *dsa);
};

#endif /* QAT_PROVIDER_DSA_H */
