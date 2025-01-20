/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2019-2025 Intel Corporation.
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


# include <openssl/ossl_typ.h>
# include "e_qat.h"

# define AES_KEY_SIZE_128    16
# define AES_KEY_SIZE_192    24
# define AES_KEY_SIZE_256    32
# define AES_GCM_BLOCK_SIZE  1
# define AES_CCM_BLOCK_SIZE  1

# define CHACHA_KEY_SIZE     32

typedef int (*PFUNC_COMP_KEY)(unsigned char **,
                              size_t *,
                              const EC_POINT *,
                              const EC_KEY *);

typedef int (*PFUNC_GEN_KEY)(EC_KEY *);

#ifdef QAT_BORINGSSL
typedef int (*PFUNC_SIGN)(const uint8_t *,
                        size_t,
                        uint8_t *,
                        unsigned int *,
                        EC_KEY *);
#else /* QAT_BORINGSSL */
typedef int (*PFUNC_SIGN)(int,
                          const unsigned char *,
                          int,
                          unsigned char *,
                          unsigned int *,
                          const BIGNUM *,
                          const BIGNUM *,
                          EC_KEY *);
#endif /* QAT_BORINGSSL */

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
#ifndef QAT_BORINGSSL
extern const EVP_PKEY_METHOD *sw_x25519_pmeth;
extern const EVP_PKEY_METHOD *sw_x448_pmeth;

# ifdef ENABLE_QAT_HW_ECX
#  ifndef QAT_OPENSSL_PROVIDER
int qat_pkey_ecx25519_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
int qat_pkey_ecx448_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
int qat_pkey_ecx_derive25519(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
int qat_pkey_ecx_derive448(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
int qat_pkey_ecx_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
#  else
void *qat_pkey_ecx25519_keygen(void *ctx, OSSL_CALLBACK *osslcb, void *cbarg);
void *qat_pkey_ecx448_keygen(void *ctx, OSSL_CALLBACK *osslcb, void *cbarg);
int qat_pkey_ecx_derive25519(void *ctx, unsigned char *key, size_t *keylen,
                             size_t outlen);
int qat_pkey_ecx_derive448(void *ctx, unsigned char *key, size_t *keylen,
                           size_t outlen);
#  endif
# endif

# ifdef ENABLE_QAT_SW_ECX
#  ifndef QAT_OPENSSL_PROVIDER
int multibuff_x25519_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
int multibuff_x25519_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
int multibuff_x25519_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
#  else
void* multibuff_x25519_keygen(void *ctx, OSSL_CALLBACK *osslcb,
                              void *cbarg);
int multibuff_x25519_derive(void *ctx, unsigned char *key,
                            size_t *keylen, size_t outlen);
#  endif
# endif

# ifdef ENABLE_QAT_SW_SM3
#  ifndef QAT_OPENSSL_PROVIDER
int qat_sw_sm3_init(EVP_MD_CTX *ctx);
int qat_sw_sm3_update(EVP_MD_CTX *ctx, const void *in, size_t len);
int qat_sw_sm3_final(EVP_MD_CTX *ctx, unsigned char *md);
#  else
int qat_sw_sm3_init(QAT_SM3_CTX_mb *ctx);
int qat_sw_sm3_update(QAT_SM3_CTX_mb *ctx, const void *in, size_t len);
int qat_sw_sm3_final(QAT_SM3_CTX_mb *ctx, unsigned char *md);
#  endif
# endif

# if defined(ENABLE_QAT_SW_SM2) || defined(ENABLE_QAT_HW_SM2)
extern const EVP_PKEY_METHOD *sw_sm2_pmeth;
EVP_PKEY_METHOD *qat_create_sm2_pmeth(void);
# endif

int qat_pkey_methods(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                     const int **nids, int nid);
EVP_PKEY_METHOD *qat_prf_pmeth(void);
EVP_PKEY_METHOD *qat_hkdf_pmeth(void);
EVP_PKEY_METHOD *qat_x25519_pmeth(void);
EVP_PKEY_METHOD *qat_x448_pmeth(void);

void qat_create_digest_meth(void);
void qat_free_digest_meth(void);
int qat_digest_methods(ENGINE *e, const EVP_MD **md,
                       const int **nids, int nid);

void qat_create_ciphers(void);
void qat_free_ciphers(void);
int qat_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids,
                int nid);
const EVP_CIPHER *qat_create_gcm_cipher_meth(int nid, int keylen);
const EVP_CIPHER *qat_create_ccm_cipher_meth(int nid, int keylen);
const EVP_CIPHER *qat_gcm_cipher_sw_impl(int nid);
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  define CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT 2048
#  define CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_SM4_CBC 64
#  define CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_HW_SM3 1024
int qat_pkt_threshold_table_set_threshold(const char *cn , int threshold);
int qat_pkt_threshold_table_get_threshold(int nid);
# endif
#endif /* QAT_BORINGSSL */

EC_KEY_METHOD *qat_get_EC_methods(void);
void qat_free_EC_methods(void);

RSA_METHOD *qat_get_RSA_methods(void);
void qat_free_RSA_methods(void);

#ifdef QAT_BORINGSSL
EC_KEY_METHOD *bssl_get_default_EC_methods(void);

RSA_METHOD *bssl_get_default_RSA_methods(void);

int RSA_private_encrypt_default(size_t flen, const uint8_t *from, uint8_t *to,
                                RSA *rsa, int padding);

int RSA_private_decrypt_default(size_t flen, const uint8_t *from, uint8_t *to,
                                RSA *rsa, int padding);

#endif /* QAT_BORINGSSL */
#ifdef ENABLE_QAT_HW_CCM
const EVP_CIPHER *qat_ccm_cipher_sw_impl(int nid);
#endif /* ENABLE_QAT_HW_CCM */

#endif /* QAT_EVP_H */

