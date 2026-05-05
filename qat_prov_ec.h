/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2026 Intel Corporation.
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
 * @file qat_prov_ec.h
 *
 * This file provides an interface to qatprovider ECDSA & ECDH operations
 *
 *****************************************************************************/
#ifndef QAT_PROV_EC_H
# define QAT_PROV_EC_H

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <openssl/core.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/types.h>
#include <openssl/trace.h>
#include <openssl/obj_mac.h>
#include <openssl/configuration.h>
#include <openssl/kdf.h>
#include "e_qat.h"

# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))

# define OSSL_MAX_NAME_SIZE           50 /* Algorithm name */
# define OSSL_MAX_PROPQUERY_SIZE     256 /* Property query strings */
# define OSSL_MAX_ALGORITHM_ID_SIZE  256 /* AlgorithmIdentifier DER */

typedef struct wpacket_sub WPACKET_SUB;
struct wpacket_sub {
    /* The parent WPACKET_SUB if we have one or NULL otherwise */
    WPACKET_SUB *parent;

    /*
     * Offset into the buffer where the length of this WPACKET goes. We use an
     * offset in case the buffer grows and gets reallocated.
     */
    size_t packet_len;

    /* Number of bytes in the packet_len or 0 if we don't write the length */
    size_t lenbytes;

    /* Number of bytes written to the buf prior to this packet starting */
    size_t pwritten;

    /* Flags for this sub-packet */
    unsigned int flags;
};

typedef struct wpacket_st WPACKET;
struct wpacket_st {
    /* The buffer where we store the output data */
    BUF_MEM *buf;

    /* Fixed sized buffer which can be used as an alternative to buf */
    unsigned char *staticbuf;

    /*
     * Offset into the buffer where we are currently writing. We use an offset
     * in case the buffer grows and gets reallocated.
     */
    size_t curr;

    /* Number of bytes written so far */
    size_t written;

    /* Maximum number of bytes we will allow to be written to this WPACKET */
    size_t maxsize;

    /* Our sub-packets (always at least one if not finished) */
    WPACKET_SUB *subs;

    /* Writing from the end first? */
    unsigned int endfirst : 1;
};

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    EC_KEY *ec;
    char mdname[OSSL_MAX_NAME_SIZE];

    /*
     * Flag to determine if the hash function can be changed (1) or not (0)
     * Because it's dangerous to change during a DigestSign or DigestVerify
     * operation, this flag is cleared by their Init function, and set again
     * by their Final function.
     */
    unsigned int flag_allow_md : 1;

    /* The Algorithm Identifier of the combined signature algorithm */
    unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
    unsigned char *aid;
    size_t  aid_len;
    size_t mdsize;
    int operation;

    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    /*
     * Internally used to cache the results of calling the EC group
     * sign_setup() methods which are then passed to the sign operation.
     * This is used by CAVS failure tests to terminate a loop if the signature
     * is not valid.
     * This could of also been done with a simple flag.
     */
    BIGNUM *kinv;
    BIGNUM *r;
# if !defined(OPENSSL_NO_ACVP_TESTS)
    /*
     * This indicates that KAT (CAVS) test is running. Externally an app will
     * override the random callback such that the generated private key and k
     * are known.
     * Normal operation will loop to choose a new k if the signature is not
     * valid - but for this mode of operation it forces a failure instead.
     */
    unsigned int kattest;
# endif
    /* If this is set then the generated k is not random */
    unsigned int nonce_type;
} QAT_PROV_ECDSA_CTX;

void QAT_EC_KEY_free(EC_KEY *r);

/* With security check enabled it can return -1 to indicate disallowed md */
int qat_digest_ecdsa_get_approved_nid_with_sha1(OSSL_LIB_CTX *ctx,
                                     const EVP_MD *md, int sha1_allowed);
int qat_digest_ecdsa_md_to_nid(const EVP_MD *md, const OSSL_ITEM *it,
                                                          size_t it_len);
int qat_digest_ecdsa_get_approved_nid(const EVP_MD *md);
int qat_ec_check_key(OSSL_LIB_CTX *ctx, const EC_KEY *ec, int protect);

OSSL_LIB_CTX *qat_ec_key_get_libctx(const EC_KEY *key);

#endif  /* QAT_PROV_EC_H */
