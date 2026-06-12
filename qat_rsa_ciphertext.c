/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2026 Intel Corporation.
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
 * @file qat_rsa_ciphertext.c
 *
 * Shared RSA PKCS#1 v1.5 implicit-rejection.
 * Used by both the QAT HW and QAT SW RSA paths.
 *
 *****************************************************************************/

#include <string.h>

#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>

#include "qat_rsa_ciphertext.h"
#include "qat_constant_time.h"

/******************************************************************************
 * qat_rsa_pkcs1_type2_check
 *
 * Four-step Marvin implicit-rejection workaround for RSA PKCS#1 v1.5
 * decryption.
 *
 * When implicit_rejection == 0 the function is a thin wrapper around
 * RSA_padding_check_PKCS1_type_2() — no behaviour change for callers that
 * do not request implicit rejection.
 *
 *****************************************************************************/
int qat_rsa_pkcs1_type2_check(const unsigned char *from, int flen,
                              unsigned char *to, RSA *rsa, int rsa_len,
                              const unsigned char *padded_buf, int padded_len,
                              int implicit_rejection)
{
    if (!implicit_rejection)
        return RSA_padding_check_PKCS1_type_2(to, rsa_len,
                                              padded_buf, padded_len,
                                              rsa_len);

    const BIGNUM *d_bn = NULL;
    unsigned char *d_buf = NULL;
    unsigned char kdk[SHA256_DIGEST_LENGTH];
    unsigned char synthetic[QAT_RSA_MAX_MODLEN];
    unsigned char actual_out[QAT_RSA_MAX_MODLEN];
    memset(actual_out, 0, sizeof(actual_out));
    int synth_off, actual_len, copy_len;
    unsigned char counter[4] = {0, 0, 0, 0};
    unsigned int good;
    EVP_MD_CTX *md_ctx;
    int output_len = -1;

    /* Step 1: Derive KDK unconditionally before the padding check to
     * avoid timing-observable branching on private exponent access.
     * Use BN_bn2binpad with a fixed rsa_len-sized buffer so that the
     * HMAC key length does not vary with the effective bit-length of d,
     * which would otherwise leak information about d. */
    RSA_get0_key((const RSA *)rsa, NULL, NULL, &d_bn);
    if (!d_bn)
        return -1;
    d_buf = OPENSSL_secure_malloc(rsa_len);
    if (!d_buf)
        return -1;
    if (BN_bn2binpad(d_bn, d_buf, rsa_len) < 0) {
        OPENSSL_cleanse(d_buf, rsa_len);
        OPENSSL_secure_free(d_buf);
        return -1;
    }
    if (!HMAC(EVP_sha256(), d_buf, rsa_len, from, flen, kdk, NULL)) {
        OPENSSL_cleanse(d_buf, rsa_len);
        OPENSSL_secure_free(d_buf);
        return -1;
    }
    OPENSSL_cleanse(d_buf, rsa_len);
    OPENSSL_secure_free(d_buf);

    /* Step 2: Expand KDK to rsa_len bytes of synthetic plaintext
     * using counter-mode SHA-256. */
    synth_off = 0;
    while (synth_off < rsa_len) {
        unsigned char block[SHA256_DIGEST_LENGTH];
        md_ctx = EVP_MD_CTX_new();
        if (!md_ctx ||
            !EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) ||
            !EVP_DigestUpdate(md_ctx, kdk, sizeof(kdk)) ||
            !EVP_DigestUpdate(md_ctx, counter, sizeof(counter)) ||
            !EVP_DigestFinal_ex(md_ctx, block, NULL)) {
            EVP_MD_CTX_free(md_ctx);
            OPENSSL_cleanse(kdk, sizeof(kdk));
            OPENSSL_cleanse(synthetic, rsa_len);
            return -1;
        }
        EVP_MD_CTX_free(md_ctx);
        copy_len = (rsa_len - synth_off < SHA256_DIGEST_LENGTH)
                    ? rsa_len - synth_off : SHA256_DIGEST_LENGTH;
        memcpy(synthetic + synth_off, block, copy_len);
        synth_off += copy_len;
        /* Increment counter as a 32-bit big-endian integer so that it
         * wraps correctly for keys larger than 256*32 = 8192 bits and
         * never produces duplicate counter values within one expansion. */
        if (++counter[3] == 0)
            if (++counter[2] == 0)
                if (++counter[1] == 0)
                    ++counter[0];
    }
    OPENSSL_cleanse(kdk, sizeof(kdk));

    /* Step 3: Run actual padding check unconditionally — skipping it on
     * any code path would itself be a timing signal. */
    actual_len = RSA_padding_check_PKCS1_type_2(
                     actual_out, rsa_len, padded_buf, padded_len, rsa_len);

    /* good = 0xFFFFFFFF on valid padding, 0x00000000 on failure */
    good = ~qat_constant_time_msb((unsigned int)actual_len);

    /* Step 4: Constant-time select; return a fixed length on failure to
     * prevent length-as-oracle. */
    output_len = qat_constant_time_select_int(good, actual_len,
                                              48 /* synthetic_msg_len */);
    for (int i = 0; i < rsa_len; i++) {
        to[i] = qat_constant_time_select_8(
                     (unsigned char)(good & 0xff),
                     actual_out[i],
                     synthetic[i]);
    }
    OPENSSL_cleanse(synthetic, rsa_len);
    OPENSSL_cleanse(actual_out, rsa_len);
    return output_len;
}
