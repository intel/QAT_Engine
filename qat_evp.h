/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2019-2021 Intel Corporation.
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

# define AES_KEY_SIZE_128           16
# define AES_KEY_SIZE_192           24
# define AES_KEY_SIZE_256           32

# define CHACHA_KEY_SIZE           32

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
#ifndef ENABLE_QAT_HW_SMALL_PKT_OFFLOAD
# define CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT 2048
int qat_pkt_threshold_table_set_threshold(const char *cn , int threshold);
int qat_pkt_threshold_table_get_threshold(int nid);
#endif

#endif
