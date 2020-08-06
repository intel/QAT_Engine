/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2020 Intel Corporation.
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
 * @file multibuff_request.h
 *
 * This file provides the data structure for buffering mulibuff requests
 *
 *****************************************************************************/

#ifndef MULTIBUFF_REQUEST_H
# define MULTIBUFF_REQUEST_H

# include <stdio.h>
# include <stdint.h>
# include <openssl/async.h>
# include <openssl/bn.h>
# include <openssl/rsa.h>
# include <openssl/kdf.h>
# include <openssl/evp.h>

#define X25519_KEYLEN 32
#define MAX_KEYLEN  57

typedef struct {
    unsigned char pubkey[MAX_KEYLEN];
    unsigned char *privkey;
} MB_ECX_KEY;

typedef struct _rsa_priv_op_data {
    struct _rsa_priv_op_data *next;
    struct _rsa_priv_op_data *prev;
    int type;
    int flen;
    const unsigned char * from;
    unsigned char padded_buf[512];
    unsigned char *to;
    unsigned char lenstra_to[512];
    const BIGNUM *d;
    const BIGNUM *e;
    const BIGNUM *n;
    const BIGNUM *p;
    const BIGNUM *q;
    const BIGNUM *dmp1;
    const BIGNUM *dmq1;
    const BIGNUM *iqmp;
    RSA *rsa;
    int padding;
    ASYNC_JOB *job;
    int *sts;
    int disable_lenstra_check;
} rsa_priv_op_data;

typedef struct _rsa_pub_op_data {
    struct _rsa_pub_op_data *next;
    struct _rsa_pub_op_data *prev;
    int type;
    int flen;
    const unsigned char *from;
    unsigned char padded_buf[512];
    unsigned char *to;
    const BIGNUM *e;
    const BIGNUM *n;
    RSA *rsa;
    int padding;
    ASYNC_JOB *job;
    int *sts;
} rsa_pub_op_data;

typedef struct _x25519_keygen_op_data {
    struct _x25519_keygen_op_data *next;
    struct _x25519_keygen_op_data *prev;
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey;
    const unsigned char *privkey;
    unsigned char *pubkey;
    MB_ECX_KEY *key;
    ASYNC_JOB *job;
    int *sts;
} x25519_keygen_op_data;

typedef struct _x25519_derive_op_data {
    struct _x25519_derive_op_data *next;
    struct _x25519_derive_op_data *prev;
    EVP_PKEY_CTX *ctx;
    unsigned char *key;
    const unsigned char *privkey;
    const unsigned char *pubkey;
    size_t *keylen;
    ASYNC_JOB *job;
    int *sts;
} x25519_derive_op_data;

#endif /* MULTIBUFF_REQUEST_H */
