/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022 Intel Corporation.
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

#ifndef QAT_PROV_CBC_H
# define QAT_PROV_CBC_H

# ifdef QAT_HW

# include <string.h>
# include <openssl/core.h>
# include <openssl/provider.h>
# include <openssl/modes.h>
# include <openssl/types.h>
# include <openssl/core_dispatch.h>
# include <openssl/params.h>
# include <openssl/err.h>
# include <openssl/proverr.h>
# include <openssl/core_names.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# include <openssl/sha.h>
# include <openssl/prov_ssl.h>

# include <openssl/aes.h>
# include <openssl/sha.h>

#include "qat_hw_ciphers.h"

# include "cpa.h"
# include "cpa_types.h"
# include "cpa_cy_sym.h"
# include "cpa_cy_drbg.h"
# include "qat_utils.h"

#define MAXCHUNK    ((size_t)1 << (sizeof(long) * 8 - 2))
#define MAXBITCHUNK ((size_t)1 << (sizeof(size_t) * 8 - 4))

#define GENERIC_BLOCK_SIZE 16
#define IV_STATE_UNINITIALISED 0  /* initial state is not initialized */
#define IV_STATE_BUFFERED      1  /* iv has been copied to the iv buffer */
#define IV_STATE_COPIED        2  /* iv has been copied from the iv buffer */
#define IV_STATE_FINISHED      3  /* the iv has been used - so don't reuse it */

#define PROV_CIPHER_FUNC(type, name, args) typedef type (* OSSL_##name##_fn)args

typedef struct prov_cipher_ctx_st PROV_CIPHER_CTX;

/* Internal flags that can be queried */
#define PROV_CIPHER_FLAG_AEAD             0x0001
#define PROV_CIPHER_FLAG_CUSTOM_IV        0x0002
#define PROV_CIPHER_FLAG_CTS              0x0004
#define PROV_CIPHER_FLAG_TLS1_MULTIBLOCK  0x0008
#define PROV_CIPHER_FLAG_RAND_KEY         0x0010
/* Internal flags that are only used within the provider */
#define PROV_CIPHER_FLAG_VARIABLE_LENGTH  0x0100
#define PROV_CIPHER_FLAG_INVERSE_CIPHER   0x0200

struct prov_cipher_ctx_st {
    int nid;

    block128_f block;
    union {
        cbc128_f cbc;
        ctr128_f ctr;
        ecb128_f ecb;
    } stream;

    unsigned int mode;
    size_t keylen;           /* key size (in bytes) */
    size_t ivlen;
    size_t blocksize;
    size_t bufsz;            /* Number of bytes in buf */
    unsigned int cts_mode;   /* Use to set the type for CTS modes */
    unsigned int pad : 1;    /* Whether padding should be used or not */
    unsigned int enc : 1;    /* Set to 1 for encrypt, or 0 otherwise */
    unsigned int iv_set : 1; /* Set when the iv is copied to the iv/oiv buffers */
    unsigned int updated : 1; /* Set to 1 during update for one shot ciphers */
    unsigned int variable_keylength : 1;
    unsigned int inverse_cipher : 1; /* set to 1 to use inverse cipher */
    unsigned int use_bits : 1; /* Set to 0 for cfb1 to use bits instead of bytes */

    unsigned int tlsversion; /* If TLS padding is in use the TLS version number */
    unsigned char *tlsmac;   /* tls MAC extracted from the last record */
    int alloced;             /*
                              * Whether the tlsmac data has been allocated or
                              * points into the user buffer.
                              */
    size_t tlsmacsize;       /* Size of the TLS MAC */
    int removetlspad;        /* Whether TLS padding should be removed or not */
    size_t removetlsfixed;   /*
                              * Length of the fixed size data to remove when
                              * processing TLS data (equals mac size plus
                              * IV size if applicable)
                              */

    /*
     * num contains the number of bytes of |iv| which are valid for modes that
     * manage partial blocks themselves.
     */
    unsigned int num;

    /* The original value of the iv */
    unsigned char oiv[GENERIC_BLOCK_SIZE];
    /* Buffer of partial blocks processed via update calls */
    unsigned char buf[GENERIC_BLOCK_SIZE];
    unsigned char iv[GENERIC_BLOCK_SIZE];
    const void *ks; /* Pointer to algorithm specific key data */
    OSSL_LIB_CTX *libctx;

    void *qat_cipher_ctx;
    EVP_CIPHER_CTX *sw_ctx;
    EVP_CIPHER *sw_cipher;
};


typedef struct prov_aes_hmac_sha_ctx_st {
    PROV_CIPHER_CTX base;
    AES_KEY ks;
    size_t payload_length;      /* AAD length in decrypt case */
    union {
        unsigned int tls_ver;
        unsigned char tls_aad[16]; /* 13 used */
    } aux;
    /* some value that are setup by set methods - that can be retrieved */
    unsigned int multiblock_interleave;
    unsigned int multiblock_aad_packlen;
    size_t multiblock_max_send_fragment;
    size_t multiblock_encrypt_len;
    size_t tls_aad_pad;
} PROV_AES_HMAC_SHA_CTX;

typedef struct prov_aes_hmac_sha1_ctx_st {
    PROV_AES_HMAC_SHA_CTX base_ctx;
    SHA_CTX head, tail, md;
} PROV_AES_HMAC_SHA1_CTX;

typedef struct prov_aes_hmac_sha256_ctx_st {
    PROV_AES_HMAC_SHA_CTX base_ctx;
    SHA256_CTX head, tail, md;
} PROV_AES_HMAC_SHA256_CTX;

# endif /* QAT_HW */
#endif /* QAT_PROV_CBC_H */
