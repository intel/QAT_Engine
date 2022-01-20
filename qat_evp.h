/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2019-2022 Intel Corporation.
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
 * @file qat_evp.h
 *
 * This file provides an interface for PRF and HKDF operations
 *
 *****************************************************************************/

#ifndef QAT_EVP_H
# define QAT_EVP_H

# include <openssl/engine.h>
# include <openssl/ossl_typ.h>

# define AES_KEY_SIZE_128    16
# define AES_KEY_SIZE_192    24
# define AES_KEY_SIZE_256    32
# define AES_GCM_BLOCK_SIZE  1

# define CHACHA_KEY_SIZE     32

typedef int (*PFUNC_COMP_KEY)(unsigned char **,
                              size_t *,
                              const EC_POINT *,
                              const EC_KEY *);

typedef int (*PFUNC_GEN_KEY)(EC_KEY *);

typedef int (*PFUNC_SIGN)(int,
                          const unsigned char *,
                          int,
                          unsigned char *,
                          unsigned int *,
                          const BIGNUM *,
                          const BIGNUM *,
                          EC_KEY *);

typedef int (*PFUNC_SIGN_SETUP)(EC_KEY *,
                                BN_CTX *,
                                BIGNUM **,
                                BIGNUM **);

typedef ECDSA_SIG *(*PFUNC_SIGN_SIG)(const unsigned char *,
                                     int,
                                     const BIGNUM *,
                                     const BIGNUM *,
                                     EC_KEY *);

typedef int (*PFUNC_VERIFY)(int,
                            const unsigned char *,
                            int,
                            const unsigned char *,
                            int,
                            EC_KEY *);

typedef int (*PFUNC_VERIFY_SIG)(const unsigned char *,
                                int,
                                const ECDSA_SIG *,
                                EC_KEY *eckey);
extern const EVP_PKEY_METHOD *sw_x25519_pmeth;
extern const EVP_PKEY_METHOD *sw_x448_pmeth;

# ifdef ENABLE_QAT_HW_ECX
int qat_pkey_ecx_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
int qat_pkey_ecx_derive25519(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
int qat_pkey_ecx_derive448(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
int qat_pkey_ecx_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
# endif

# ifdef ENABLE_QAT_SW_ECX
int multibuff_x25519_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
int multibuff_x25519_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
int multibuff_x25519_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
# endif

# ifdef ENABLE_QAT_SW_SM3
int qat_sw_sm3_init(EVP_MD_CTX *ctx);
int qat_sw_sm3_update(EVP_MD_CTX *ctx, const void *in, size_t len);
int qat_sw_sm3_final(EVP_MD_CTX *ctx, unsigned char *md);
# endif

int qat_pkey_methods(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                     const int **nids, int nid);
int qat_digest_methods(ENGINE *e, const EVP_MD **md,
                     const int **nids, int nid);
EVP_PKEY_METHOD *qat_prf_pmeth(void);
EVP_PKEY_METHOD *qat_hkdf_pmeth(void);
EVP_PKEY_METHOD *qat_x25519_pmeth(void);
EVP_PKEY_METHOD *qat_x448_pmeth(void);


void qat_create_ciphers(void);
void qat_free_ciphers(void);
int qat_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids,
                int nid);
const EVP_CIPHER *qat_create_gcm_cipher_meth(int nid, int keylen);
# ifndef ENABLE_QAT_HW_SMALL_PKT_OFFLOAD
#  define CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT 2048
int qat_pkt_threshold_table_set_threshold(const char *cn , int threshold);
int qat_pkt_threshold_table_get_threshold(int nid);
# endif

EC_KEY_METHOD *qat_get_EC_methods(void);

void qat_free_EC_methods(void);

#endif /* QAT_EVP_H */
