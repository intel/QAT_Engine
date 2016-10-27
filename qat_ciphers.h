/* ====================================================================
 *
 * 
 *   BSD LICENSE
 * 
 *   Copyright(c) 2016 Intel Corporation.
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
 * @file qat_ciphers.h
 *
 * This file provides an interface for engine cipher operations
 *
 *****************************************************************************/

#ifndef QAT_CIPHERS_H
# define QAT_CIPHERS_H

# include <openssl/engine.h>
# include <openssl/crypto.h>

# define AES_BLOCK_SIZE      16
# define AES_IV_LEN          16
# define AES_KEY_SIZE_256    32
# define AES_KEY_SIZE_128    16

# define qat_chained_data(ctx) (EVP_CIPHER_CTX_get_cipher_data(ctx))

# define HMAC_KEY_SIZE       64
# define TLS_VIRT_HDR_SIZE   13

# define NO_PAYLOAD_LENGTH_SPECIFIED ((size_t)-1)

/* How long to wait for inflight messages before cleanup */
# define QAT_CIPHER_CLEANUP_RETRY_COUNT 10
# define QAT_CIPHER_CLEANUP_WAIT_TIME_NS 1000000

# define qat_common_cipher_flags EVP_CIPH_FLAG_DEFAULT_ASN1
# define qat_common_cbc_flags    (qat_common_cipher_flags | EVP_CIPH_CBC_MODE \
                                | EVP_CIPH_CUSTOM_IV)

# define QAT_TLS_PAYLOADLENGTH_MSB_OFFSET 2
# define QAT_TLS_PAYLOADLENGTH_LSB_OFFSET 1
# define QAT_TLS_VERSION_MSB_OFFSET       4
# define QAT_TLS_VERSION_LSB_OFFSET       3
# define QAT_BYTE_SHIFT                   8

void qat_create_ciphers(void);
void qat_free_ciphers(void);
int qat_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids,
                      int nid);
# ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
extern CRYPTO_ONCE qat_pkt_threshold_table_once;
extern CRYPTO_THREAD_LOCAL qat_pkt_threshold_table_key;
void qat_pkt_threshold_table_make_key(void );
LHASH_OF(PKT_THRESHOLD) *qat_create_pkt_threshold_table(void);
void qat_free_pkt_threshold_table(void *);
int qat_pkt_threshold_table_set_threshold(int nid, int threshold);
int qat_pkt_threshold_table_get_threshold(int nid);
# endif
#endif                          /* QAT_CIPHERS_H */
