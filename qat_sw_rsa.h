/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020-2022 Intel Corporation.
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
 * @file qat_sw_rsa.h
 *
 * This file provides an RSA interface for Multi-buffer implemention of an
 * OpenSSL engine
 *
 *****************************************************************************/

#ifndef QAT_SW_RSA_H
# define QAT_SW_RSA_H

# include <openssl/rsa.h>

/* RSA key sizes */
# define RSA_2K_LENGTH 2048
# define RSA_3K_LENGTH 3072
# define RSA_4K_LENGTH 4096

#ifdef ENABLE_QAT_SW_RSA
void process_RSA_priv_reqs(mb_thread_data *tlv, int rsa_bits);
void process_RSA_pub_reqs(mb_thread_data *tlv, int rsa_bits);

int multibuff_rsa_priv_enc(int flen, const unsigned char *from,
                                  unsigned char *to, RSA *rsa, int padding);
int multibuff_rsa_priv_dec(int flen, const unsigned char *from,
                                  unsigned char *to, RSA *rsa, int padding);
int multibuff_rsa_pub_enc(int flen, const unsigned char *from,
                                 unsigned char *to, RSA *rsa, int padding);
int multibuff_rsa_pub_dec(int flen, const unsigned char *from,
                                 unsigned char *to, RSA *rsa, int padding);
int multibuff_rsa_init(RSA *rsa);
int multibuff_rsa_finish(RSA *rsa);
#endif

#endif /* QAT_SW_RSA_H */
