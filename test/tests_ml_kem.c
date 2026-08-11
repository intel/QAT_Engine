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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/async.h>
#include <openssl/evp.h>

#include "tests.h"
#include "../qat_utils.h"

/* ML-KEM (FIPS 203) is offloaded to Software (Intel IPsec Multi-Buffer
 * library) and is only registered by the qatprovider, never by qatengine. */
#ifdef ENABLE_QAT_SW_ML_KEM

static const char *ml_kem_alg_name(int variant)
{
    switch (variant) {
    case 512:
        return "ML-KEM-512";
    case 768:
        return "ML-KEM-768";
    case 1024:
        return "ML-KEM-1024";
    default:
        return NULL;
    }
}

/******************************************************************************
* function:
*       test_ml_kem (int count, int variant, int print_output)
*
* @param count [IN] - number of iterations
* @param variant [IN] - ML-KEM parameter set (512, 768 or 1024)
* @param print_output [IN] - print hex output flag
*
* description:
*       ML-KEM Keygen, Encapsulate and Decapsulate Test
*
******************************************************************************/
static int test_ml_kem(int count, int variant, int print_output)
{
    const char *alg_name = ml_kem_alg_name(variant);
    int ret = 0, i;
    EVP_PKEY *ml_kem_key = NULL;
    EVP_PKEY_CTX *keygen_ctx = NULL;
    EVP_PKEY_CTX *encaps_ctx = NULL;
    EVP_PKEY_CTX *decaps_ctx = NULL;
    unsigned char *ct = NULL, *bad_ct = NULL;
    unsigned char *secret = NULL, *secret2 = NULL;
    size_t ct_len = 0, secret_len = 0, secret2_len = 0;

    if (alg_name == NULL) {
        WARN("# FAIL: Unknown ML-KEM parameter set '%d'\n", variant);
        return -1;
    }

    /* Keygen */
    keygen_ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    if (keygen_ctx == NULL
        || EVP_PKEY_keygen_init(keygen_ctx) <= 0
        || EVP_PKEY_keygen(keygen_ctx, &ml_kem_key) <= 0) {
        WARN("# FAIL: %s keygen failed\n", alg_name);
        ret = -1;
        goto err;
    }

    for (i = 0; i < count; i++) {
        encaps_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ml_kem_key, NULL);
        if (encaps_ctx == NULL
            || EVP_PKEY_encapsulate_init(encaps_ctx, NULL) <= 0) {
            WARN("# FAIL: %s encapsulate init failed\n", alg_name);
            ret = -1;
            goto err;
        }

        /* Query the required ciphertext/secret buffer sizes, then encapsulate. */
        if (EVP_PKEY_encapsulate(encaps_ctx, NULL, &ct_len, NULL, &secret_len) <= 0) {
            WARN("# FAIL: %s encapsulate size query failed\n", alg_name);
            ret = -1;
            goto err;
        }

        {
            unsigned char *new_ct = OPENSSL_realloc(ct, ct_len);
            unsigned char *new_secret = OPENSSL_realloc(secret, secret_len);

            if (new_ct != NULL)
                ct = new_ct;
            if (new_secret != NULL)
                secret = new_secret;
            if (new_ct == NULL || new_secret == NULL) {
                WARN("# FAIL: failed to malloc ciphertext/secret\n");
                ret = -1;
                goto err;
            }
        }

        if (EVP_PKEY_encapsulate(encaps_ctx, ct, &ct_len, secret, &secret_len) <= 0) {
            WARN("# FAIL: %s encapsulate failed\n", alg_name);
            ret = -1;
            goto err;
        }

        if (print_output) {
            tests_hexdump("ML-KEM ciphertext:", ct, ct_len);
            tests_hexdump("ML-KEM shared secret (encaps):", secret, secret_len);
        }

        decaps_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ml_kem_key, NULL);
        if (decaps_ctx == NULL
            || EVP_PKEY_decapsulate_init(decaps_ctx, NULL) <= 0) {
            WARN("# FAIL: %s decapsulate init failed\n", alg_name);
            ret = -1;
            goto err;
        }

        if (EVP_PKEY_decapsulate(decaps_ctx, NULL, &secret2_len, ct, ct_len) <= 0) {
            WARN("# FAIL: %s decapsulate size query failed\n", alg_name);
            ret = -1;
            goto err;
        }

        {
            unsigned char *new_secret2 = OPENSSL_realloc(secret2, secret2_len);

            if (new_secret2 == NULL) {
                WARN("# FAIL: failed to malloc secret2\n");
                ret = -1;
                goto err;
            }
            secret2 = new_secret2;
        }

        if (EVP_PKEY_decapsulate(decaps_ctx, secret2, &secret2_len, ct, ct_len) <= 0) {
            WARN("# FAIL: %s decapsulate failed\n", alg_name);
            ret = -1;
            goto err;
        }

        if (print_output)
            tests_hexdump("ML-KEM shared secret (decaps):", secret2, secret2_len);

        if (secret_len != secret2_len || memcmp(secret, secret2, secret_len) != 0) {
            WARN("# FAIL: %s decapsulated secret does not match encapsulated secret\n",
                 alg_name);
            ret = -1;
            goto err;
        }

        /* Negative test: a corrupted ciphertext must derive a different
         * shared secret via FIPS 203 implicit rejection, not an error. */
        {
            unsigned char *new_bad_ct = OPENSSL_realloc(bad_ct, ct_len);

            if (new_bad_ct == NULL) {
                WARN("# FAIL: failed to malloc corrupted ciphertext\n");
                ret = -1;
                goto err;
            }
            bad_ct = new_bad_ct;
        }
        memcpy(bad_ct, ct, ct_len);
        bad_ct[0] ^= 0xFF;

        if (EVP_PKEY_decapsulate(decaps_ctx, secret2, &secret2_len, bad_ct, ct_len) <= 0) {
            WARN("# FAIL: %s decapsulate of corrupted ciphertext failed\n", alg_name);
            ret = -1;
            goto err;
        }

        if (secret_len == secret2_len && memcmp(secret, secret2, secret_len) == 0) {
            WARN("# FAIL: %s corrupted ciphertext unexpectedly derived original secret\n",
                 alg_name);
            ret = -1;
            goto err;
        }

        EVP_PKEY_CTX_free(encaps_ctx);
        encaps_ctx = NULL;
        EVP_PKEY_CTX_free(decaps_ctx);
        decaps_ctx = NULL;
    }

 err:
    if (ct)
        OPENSSL_free(ct);
    if (bad_ct)
        OPENSSL_free(bad_ct);
    if (secret)
        OPENSSL_free(secret);
    if (secret2)
        OPENSSL_free(secret2);
    if (encaps_ctx)
        EVP_PKEY_CTX_free(encaps_ctx);
    if (decaps_ctx)
        EVP_PKEY_CTX_free(decaps_ctx);
    if (keygen_ctx)
        EVP_PKEY_CTX_free(keygen_ctx);
    if (ml_kem_key)
        EVP_PKEY_free(ml_kem_key);

    if (0 == ret)
        INFO("# PASS %s Keygen/Encapsulate/Decapsulate\n", alg_name ? alg_name : "ML-KEM");
    else
        INFO("# FAIL %s Keygen/Encapsulate/Decapsulate\n", alg_name ? alg_name : "ML-KEM");

    return ret;
}

/******************************************************************************
* function:
*       run_ml_kem (void *args)
*
* @param args [IN] - the test parameters
*
* description:
*   specify a test case
*
******************************************************************************/
static int run_ml_kem(void *args)
{
    int ret = 1;
    TEST_PARAMS *temp_args = (TEST_PARAMS *) args;
    int count = *(temp_args->count);
    int variant = temp_args->size;

    if (test_ml_kem(count, variant, temp_args->print_output) < 0)
        ret = 0;

    return ret;
}

/******************************************************************************
* function:
*       tests_run_ml_kem (TEST_PARAMS *args)
*
* @param args [IN] - the test parameters
*
* description:
*   specify a test case
*
******************************************************************************/
void tests_run_ml_kem(TEST_PARAMS *args)
{
    args->additional_args = NULL;

    if (!args->enable_async)
        run_ml_kem(args);
    else
        start_async_job(args, run_ml_kem);
}

#endif /* ENABLE_QAT_SW_ML_KEM */
