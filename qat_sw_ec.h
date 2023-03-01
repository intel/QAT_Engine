/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021-2023 Intel Corporation.
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
 * @file qat_sw_ec.h
 *
 * This file provides an interface to ECDH & ECDSA Multi-buffer operations
 *
 *****************************************************************************/

#ifndef QAT_SW_EC_H
# define QAT_SW_EC_H

# define EC_P256 1
# define EC_P384 2
# define EC_SM2  3

# include <openssl/ossl_typ.h>

# ifdef ENABLE_QAT_SW_SM2
EVP_PKEY_METHOD *mb_sm2_pmeth(void);
void process_ecdsa_sm2_sign_reqs(mb_thread_data *tlv);
void process_ecdsa_sm2_verify_reqs(mb_thread_data *tlv);
# endif

# ifdef ENABLE_QAT_SW_ECDSA
int mb_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                  unsigned char *sig, unsigned int *siglen,
                  const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);
int mb_ecdsa_do_verify(const unsigned char *dgst,
                    int dlen, const ECDSA_SIG *sig,
                    EC_KEY *eckey);
int mb_ecdsa_verify(int type, const unsigned char *dgst,
                    int dgst_len, const unsigned char *sigbuf,
                    int sig_len, EC_KEY *eckey);
#ifndef QAT_BORINGSSL
int mb_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in,
                        BIGNUM **kinvp, BIGNUM **rp);
ECDSA_SIG *mb_ecdsa_sign_sig(const unsigned char *dgst, int dlen,
                             const BIGNUM *in_kinv, const BIGNUM *in_r,
                             EC_KEY *eckey);
#else /* QAT_BORINGSSL */
int mb_ecdsa_sign_bssl(const uint8_t *digest, size_t digest_len, uint8_t *sig,
                        unsigned int *sig_len, EC_KEY *eckey);
#endif /* QAT_BORINGSSL */
void process_ecdsa_sign_reqs(mb_thread_data *tlv, int bits);
void process_ecdsa_sign_setup_reqs(mb_thread_data *tlv, int bits);
void process_ecdsa_sign_sig_reqs(mb_thread_data *tlv, int bits);
void process_ecdsa_verify_reqs(mb_thread_data *tlv, int bits);
# endif

# ifdef ENABLE_QAT_SW_ECDH
int mb_ecdh_compute_key(unsigned char **out, size_t *outlen,
                        const EC_POINT *pub_key, const EC_KEY *ecdh);
int mb_ecdh_generate_key(EC_KEY *ecdh);
void process_ecdh_keygen_reqs(mb_thread_data *tlv, int bits);
void process_ecdh_compute_reqs(mb_thread_data *tlv, int bits);
# endif

#endif /* QAT_SW_EC_H */
