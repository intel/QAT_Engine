/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2021 Intel Corporation.
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
 * @file qat_hw_ec.h
 *
 * This file provides an interface to ECDH & ECDSA operations
 *
 *****************************************************************************/

#ifndef QAT_HW_EC_H
# define QAT_HW_EC_H

# include <openssl/ossl_typ.h>

# ifdef ENABLE_QAT_HW_ECDSA
int qat_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                   unsigned char *sig, unsigned int *siglen,
                   const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);
ECDSA_SIG *qat_ecdsa_do_sign(const unsigned char *dgst, int dlen,
                             const BIGNUM *in_kinv, const BIGNUM *in_r,
                             EC_KEY *eckey);
int qat_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
                     const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);
int qat_ecdsa_do_verify(const unsigned char *dgst, int dgst_len,
                        const ECDSA_SIG *sig, EC_KEY *eckey);
# endif

# ifdef ENABLE_QAT_HW_ECDH
/* Qat engine ECDH methods declaration */
int qat_ecdh_compute_key(unsigned char **outX, size_t *outlenX,
                         unsigned char **outY, size_t *outlenY,
                         const EC_POINT *pub_key, const EC_KEY *ecdh,
                         int *fallback);
int qat_engine_ecdh_compute_key(unsigned char **out, size_t *outlen,
                                const EC_POINT *pub_key, const EC_KEY *ecdh);
int qat_ecdh_generate_key(EC_KEY *ecdh);
# endif
#endif /* QAT_HW_EC_H */
