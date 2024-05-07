/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023-2024 Intel Corporation.
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
 * @file qat_common.h
 *
 * This file provides the common data structure for QAT_HW & QAT_SW
 *
 *****************************************************************************/
#ifndef QAT_COMMON_H
# define QAT_COMMON_H

/* Begin of ECX common data structures */
# define X25519_KEYLEN          32
# define X448_KEYLEN            56
# define QAT_X448_DATALEN       64
# define X448_DATA_KEY_DIFF      8
# define ED448_KEYLEN           57/* This is used for OpenSSL 3.0 ECX_KEY */

# define MAX_KEYLEN  57

# if OPENSSL_VERSION_NUMBER < 0x30200000
typedef int CRYPTO_REF_COUNT;
# else
typedef struct {
    int val;
} CRYPTO_REF_COUNT;
# endif

/* Only for QAT_HW built with OpenSSL 1.1.1 Engine */
# ifndef QAT_OPENSSL_3
typedef struct {
    unsigned char pubkey[QAT_X448_DATALEN];
    unsigned char *privkey;
} ECX_KEY;
# endif

# if defined(QAT_OPENSSL_3) && !defined(QAT_OPENSSL_PROVIDER)
typedef enum {
    ECX_KEY_TYPE_X25519,
    ECX_KEY_TYPE_X448,
    ECX_KEY_TYPE_ED25519,
    ECX_KEY_TYPE_ED448
} ECX_KEY_TYPE;

typedef struct ecx_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    unsigned int haspubkey:1;
    unsigned char pubkey[ED448_KEYLEN];
    unsigned char *privkey;
    size_t keylen;
    ECX_KEY_TYPE type;
    CRYPTO_REF_COUNT references;
#if OPENSSL_VERSION_NUMBER < 0x30200000
    CRYPTO_RWLOCK *lock;
#endif
} QAT_SW_ECX_KEY, ECX_KEY;
# else
typedef struct {
    unsigned char pubkey[MAX_KEYLEN];
    unsigned char *privkey;
} QAT_SW_ECX_KEY;
# endif
/* End of ECX common data structures */

#endif
