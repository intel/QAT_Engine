/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2026 Intel Corporation.
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
 * @file qat_prov_kmgmt_rsa_utils.h
 *
 * This file provides an interface to qatprovider RSA key management
 * operations
 *
 *****************************************************************************/
#ifndef QAT_PROVIDER_KMGMT_RSA_UTILS_H
#define QAT_PROVIDER_KMGMT_RSA_UTILS_H

#define RSA_KEY_TYPES()                                                        \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),                                 \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),                                 \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),                                 \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),

QAT_RSA *qat_rsa_new_with_ctx(OSSL_LIB_CTX *libctx);
int qat_pss_params_fromdata(QAT_RSA_PSS_PARAMS_30 *pss_params, int *defaults_set,
                            const OSSL_PARAM params[], int rsa_type,
                            OSSL_LIB_CTX *libctx);
int qat_rsa_todata(QAT_RSA *rsa, OSSL_PARAM_BLD *bld, OSSL_PARAM params[],
                   int include_private);
int qat_rsa_pss_params_30_todata(const QAT_RSA_PSS_PARAMS_30 *pss,
                                 OSSL_PARAM_BLD *bld, OSSL_PARAM params[]);
int qat_rsa_pss_params_30_hashalg(const QAT_RSA_PSS_PARAMS_30 *rsa_pss_params);
const char *qat_rsa_oaeppss_nid2name(int md);
int qat_rsa_oaeppss_md2nid(const EVP_MD *md);
int qat_rsa_pss_params_30_copy(QAT_RSA_PSS_PARAMS_30 *to,
                                const QAT_RSA_PSS_PARAMS_30 *from);
int import_rsa_private_key(QAT_RSA *rsa, const OSSL_PARAM params[], int include_private);
OSSL_LIB_CTX *qat_rsa_get0_libctx(QAT_RSA *r);
QAT_RSA_PSS_PARAMS_30 *qat_rsa_get0_pss_params_30(QAT_RSA *r);
const char *nid2name(int meth, const OSSL_ITEM *items, size_t items_n);
int qat_rsa_pss_params_30_is_unrestricted(const QAT_RSA_PSS_PARAMS_30 *rsa_pss_params);
int qat_rsa_gen_set_params(void *genctx, const OSSL_PARAM params[]);
int qat_rsa_gencb(int p, int n, BN_GENCB *cb);
int qat_rsa_pss_params_30_maskgenhashalg(const QAT_RSA_PSS_PARAMS_30 *rsa_pss_params);
int qat_rsa_pss_params_30_saltlen(const QAT_RSA_PSS_PARAMS_30 *rsa_pss_params);
int QAT_RSA_set0_factors(QAT_RSA *r, BIGNUM *p, BIGNUM *q);
int QAT_RSA_set0_crt_params(QAT_RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);
const OSSL_PARAM *qat_rsa_imexport_types(int selection);
int RSA_generate_swkey(QAT_RSA *rsa, int nbits, BIGNUM *efixed, BN_GENCB *cb);

#endif /*QAT_PROVIDER_KMGMT_RSA_UTILS_H*/
