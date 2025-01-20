/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023-2025 Intel Corporation.
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

#ifndef __KPT_SWK_H__
#define __KPT_SWK_H__
#include <openssl/asn1t.h>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>

#define MAX_KPT1_PUB_LEN (2048)
#define MAX_KPT1_PRIV_LEN (2048)

typedef struct e_swk{
    ASN1_OCTET_STRING *devSig;
    ASN1_OCTET_STRING *secSWK;
} ESWK;
DEFINE_STACK_OF(ESWK)
DECLARE_ASN1_FUNCTIONS(ESWK)

typedef struct wrapping_metadata {
    ASN1_OCTET_STRING *aesNonce;
    ASN1_OBJECT *wrappingAlg;
    STACK_OF(ESWK) *eSWKs;
} WRAPPINGMETADATA;
DECLARE_ASN1_FUNCTIONS(WRAPPINGMETADATA)

#define AES_GCM_256_KEY_SIZE (32)
#define AES_GCM_IV_SIZE (12)
#define AES_GCM_TAG_SIZE (16)
#define RSA3K_ENCRYPTION_OUTPUT_SIZE (384)
int wrap_key_with_gcm256(unsigned char *ck, int ck_len, unsigned char *pk,
                         int *pk_len, unsigned char *swk, unsigned char *iv,
                         int iv_len, unsigned char *aad, int aad_len);

int encrypt_swk_with_per_part_key(unsigned char *swk, unsigned char *eswk,
                           unsigned char *n, int n_len,
                           unsigned char *e, int e_len);

int seal_swk_with_ptt_srk(unsigned char *swk, unsigned char *priv,
                          unsigned int *priv_len, unsigned char *pub,
                          unsigned int *pub_len);

#endif
