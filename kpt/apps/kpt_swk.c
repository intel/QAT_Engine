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

#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "kpt_swk.h"
#ifdef KPT1
#include "kpttool.h"
#endif

#define  MAX_KPT_PRIVATE_KEY_SIZE (4096)

ASN1_SEQUENCE(ESWK) = {
    ASN1_SIMPLE(ESWK, devSig, ASN1_OCTET_STRING),
    ASN1_SIMPLE(ESWK, secSWK, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(ESWK)
IMPLEMENT_ASN1_FUNCTIONS(ESWK)

ASN1_SEQUENCE(WRAPPINGMETADATA) = {
    ASN1_SIMPLE(WRAPPINGMETADATA, aesNonce, ASN1_OCTET_STRING),
    ASN1_SIMPLE(WRAPPINGMETADATA, wrappingAlg, ASN1_OBJECT),
    ASN1_SEQUENCE_OF(WRAPPINGMETADATA, eSWKs, ESWK)
}ASN1_SEQUENCE_END(WRAPPINGMETADATA)
IMPLEMENT_ASN1_FUNCTIONS(WRAPPINGMETADATA)

int wrap_key_with_gcm256(unsigned char *ck,  int ck_len,
                         unsigned char *pk,  int *pk_len,
                         unsigned char *swk,
                         unsigned char *iv,  int iv_len,
                         unsigned char *aad, int aad_len)
{
    unsigned char out_buf[MAX_KPT_PRIVATE_KEY_SIZE];
    int out_len = 0;

    if ((!ck) || (!pk) || (!swk) || (!iv)) {
        return -1;
    }
    if (AES_GCM_IV_SIZE != iv_len) {
        return -1;
    }

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

    /* Set IV length if default 96 bits is not appropriate */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len,
                        NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, swk, iv);

    /* Zero or more calls to specify any AAD */
    if (aad && aad_len > 0) {
        EVP_EncryptUpdate(ctx, NULL, &out_len, aad, aad_len);
    }

    /* Encrypt plaintext */
    EVP_EncryptUpdate(ctx, out_buf, &out_len, ck, ck_len);

    memcpy(pk, out_buf, out_len);
    *pk_len = out_len;

    /* Finalise: note get no out_put for GCM */
    EVP_EncryptFinal_ex(ctx, out_buf, &out_len);

    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AES_GCM_TAG_SIZE, out_buf);

    /* Pad the gcm tag*/
    memcpy(pk + *pk_len, out_buf, AES_GCM_TAG_SIZE);
    *pk_len += AES_GCM_TAG_SIZE;

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

int encrypt_swk_with_per_part_key(unsigned char *swk, unsigned char *eswk,
                           unsigned char *n, int n_len,
                           unsigned char *e, int e_len)
{
    int ret = -1;
    BIGNUM *bn = NULL;
    BIGNUM *be = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t  eswk_len = RSA3K_ENCRYPTION_OUTPUT_SIZE;
    unsigned char dataOut[1024] = {0};
    EVP_PKEY *pubKey = NULL;
    RSA *rsa = NULL;

    if (!swk || !eswk || !n  || !e) {
        return -1;
    }

    if ((pubKey =  EVP_PKEY_new()) == NULL) {
        goto err;
    }
    if ((rsa = RSA_new()) == NULL) {
        goto err;
    }

    bn = BN_bin2bn(n, n_len, NULL);
    be = BN_bin2bn(e, e_len, NULL);

    RSA_set0_key(rsa, bn, be, NULL);

    EVP_PKEY_assign_RSA(pubKey, rsa);
    ctx = EVP_PKEY_CTX_new(pubKey, NULL);
    if (ctx) {
        if (EVP_PKEY_encrypt_init(ctx) > 0) {
            EVP_PKEY_CTX_ctrl_str(ctx, "rsa_padding_mode", "oaep");
            EVP_PKEY_CTX_ctrl_str(ctx, "rsa_oaep_md", "sha256");
            EVP_PKEY_CTX_ctrl_str(ctx, "rsa_mgf1_md", "sha256");

            ret = EVP_PKEY_encrypt(ctx, eswk, &eswk_len, swk, AES_GCM_256_KEY_SIZE);
        }
    }

err:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    if (pubKey) {
        EVP_PKEY_free(pubKey);
    }
    return ret;
}
