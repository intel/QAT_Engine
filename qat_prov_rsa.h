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
 * @file qat_prov_rsa.h
 *
 * This file provides an interface to qatprovider RSA operations
 *
 *****************************************************************************/
#ifndef QAT_PROVIDER_RSA_H
# define QAT_PROVIDER_RSA_H

#include <openssl/core.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include "e_qat.h"

typedef struct{
    int hash_algorithm_nid;
    struct {
        int algorithm_nid;       /* Currently always NID_mgf1 */
        int hash_algorithm_nid;
    } mask_gen;
    int salt_len;
    int trailer_field;
} QAT_RSA_PSS_PARAMS_30;

/*
 * QAT_RSA is a typedef for OpenSSL's opaque RSA type.
 * PSS parameters are stored separately using RSA ex_data.
 * This avoids replicating OpenSSL's internal rsa_st structure
 * which changes across versions.
 */

/* Ex data index for storing QAT_RSA_PSS_PARAMS_30 in RSA objects */
int qat_rsa_pss_params_ex_idx(void);
void qat_rsa_pss_params_ex_init(void);

struct qat_rsa_gen_ctx {
    OSSL_LIB_CTX *libctx;
    const char *propq;

    int rsa_type;

    size_t nbits;
    BIGNUM *pub_exp;
    size_t primes;

    /* For PSS */
    QAT_RSA_PSS_PARAMS_30 pss_params;
    int pss_defaults_set;

    /* For generation callback */
    OSSL_CALLBACK *cb;
    void *cbarg;
};
typedef struct qat_rsa_gen_ctx QAT_RSA_GEN_CTX;

extern const QAT_RSA_PSS_PARAMS_30 default_RSASSA_PSS_params;

typedef struct {
    OSSL_LIB_CTX *libctx;
    RSA *rsa;
    int pad_mode;
    int operation;
    /* OAEP message digest */
    EVP_MD *oaep_md;
    /* message digest for MGF1 */
    EVP_MD *mgf1_md;
    /* OAEP label */
    unsigned char *oaep_label;
    size_t oaep_labellen;
    /* TLS padding */
    unsigned int client_version;
    unsigned int alt_version;
    /* PKCS#1 v1.5 decryption mode */
# if OPENSSL_VERSION_NUMBER >= 0x30200000
    unsigned int implicit_rejection;
# endif
} QAT_PROV_RSA_ENC_DEC_CTX;

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    RSA *rsa;
    int operation;

    /*Unused but retained to remain compatible with OpenSSL */
    unsigned int flag_sigalg : 1;

    /*
     * Flag to determine if the hash function can be changed (1) or not (0)
     * Because it's dangerous to change during a DigestSign or DigestVerify
     * operation, this flag is cleared by their Init function, and set again
     * by their Final function.
     */
    unsigned int flag_allow_md : 1;
    unsigned int mgf1_md_set : 1;

    unsigned int flag_allow_update : 1;
    unsigned int flag_allow_final : 1;
    unsigned int flag_allow_oneshot : 1;

    /* main digest */
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    int mdnid;
    char mdname[50]; /* Purely informational */

    /* RSA padding mode */
    int pad_mode;
    /* message digest for MGF1 */
    EVP_MD *mgf1_md;
    int mgf1_mdnid;
    char mgf1_mdname[50];
    /* PSS salt length */
    int saltlen;
    /* Minimum salt length or -1 if no PSS parameter restriction */
    int min_saltlen;

    unsigned char *sig;
    size_t siglen;

    /* Temp buffer */
    unsigned char *tbuf;
    /* OAEP message digest */
    EVP_MD *oaep_md;
    /* OAEP label */
    unsigned char *oaep_label;
    size_t oaep_labellen;
    unsigned int client_version;
    unsigned int alt_version;
} QAT_PROV_RSA_CTX;

void QAT_RSA_free(RSA *r);
int QAT_PKCS1_MGF1(unsigned char *mask, long len,
                   const unsigned char *seed, long seedlen, const EVP_MD *dgst);
#endif /* QAT_PROVIDER_RSA_H */
