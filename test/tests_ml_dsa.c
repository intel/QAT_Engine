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

/* ML-DSA (FIPS 204) is offloaded to Software (Intel IPsec Multi-Buffer
 * library) and is only registered by the qatprovider, never by qatengine. */
#ifdef ENABLE_QAT_SW_ML_DSA

#define ML_DSA_MSG_LEN 32

static const char rnd_seed[] =
    "string to make the random number generator think it has entropy";

static const char *ml_dsa_alg_name(int variant)
{
    switch (variant) {
    case 44:
        return "ML-DSA-44";
    case 65:
        return "ML-DSA-65";
    case 87:
        return "ML-DSA-87";
    default:
        return NULL;
    }
}

/******************************************************************************
* function:
*       test_ml_dsa (int count, int variant, int print_output)
*
* @param count [IN] - number of iterations
* @param variant [IN] - ML-DSA parameter set (44, 65 or 87)
* @param print_output [IN] - print hex output flag
*
* description:
*       ML-DSA Keygen, Sign and Verify Test
*
******************************************************************************/
static int test_ml_dsa(int count, int variant, int print_output)
{
    const char *alg_name = ml_dsa_alg_name(variant);
    int ret = 0, i, status;
    unsigned char msg[ML_DSA_MSG_LEN], wrong_msg[ML_DSA_MSG_LEN];
    unsigned char *signature = NULL;
    size_t sig_len = 0;
    EVP_PKEY *ml_dsa_key = NULL;
    EVP_PKEY_CTX *keygen_ctx = NULL;
    EVP_PKEY_CTX *sign_ctx = NULL;
    EVP_PKEY_CTX *verify_ctx = NULL;

    if (alg_name == NULL) {
        WARN("# FAIL: Unknown ML-DSA parameter set '%d'\n", variant);
        return -1;
    }

    if ((RAND_bytes(msg, sizeof(msg)) <= 0)
        || (RAND_bytes(wrong_msg, sizeof(wrong_msg)) <= 0)) {
        WARN("# FAIL: unable to get random data\n");
        return -1;
    }

    /* Keygen */
    keygen_ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    if (keygen_ctx == NULL
        || EVP_PKEY_keygen_init(keygen_ctx) <= 0
        || EVP_PKEY_keygen(keygen_ctx, &ml_dsa_key) <= 0) {
        WARN("# FAIL: %s keygen failed\n", alg_name);
        ret = -1;
        goto err;
    }

    for (i = 0; i < count; i++) {
        sign_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ml_dsa_key, NULL);
        if (sign_ctx == NULL || EVP_PKEY_sign_init(sign_ctx) <= 0) {
            WARN("# FAIL: %s sign init failed\n", alg_name);
            ret = -1;
            goto err;
        }

        /* Query the required signature buffer size, then sign. */
        if (EVP_PKEY_sign(sign_ctx, NULL, &sig_len, msg, sizeof(msg)) <= 0) {
            WARN("# FAIL: %s sign size query failed\n", alg_name);
            ret = -1;
            goto err;
        }

        {
            unsigned char *new_signature = OPENSSL_realloc(signature, sig_len);

            if (new_signature == NULL) {
                WARN("# FAIL: failed to malloc signature\n");
                ret = -1;
                goto err;
            }
            signature = new_signature;
        }

        status = EVP_PKEY_sign(sign_ctx, signature, &sig_len, msg, sizeof(msg));
        if (status <= 0) {
            WARN("# FAIL: %s sign failed\n", alg_name);
            ret = -1;
            goto err;
        }

        if (print_output)
            tests_hexdump("ML-DSA signature:", signature, sig_len);

        verify_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ml_dsa_key, NULL);
        if (verify_ctx == NULL || EVP_PKEY_verify_init(verify_ctx) <= 0) {
            WARN("# FAIL: %s verify init failed\n", alg_name);
            ret = -1;
            goto err;
        }

        status = EVP_PKEY_verify(verify_ctx, signature, sig_len, msg, sizeof(msg));
        if (status != 1) {
            WARN("# FAIL: %s verify failed\n", alg_name);
            ret = -1;
            goto err;
        }

        /* Negative test: verify must fail on a tampered message. */
        status = EVP_PKEY_verify(verify_ctx, signature, sig_len,
                                 wrong_msg, sizeof(wrong_msg));
        if (status == 1) {
            WARN("# FAIL: %s verify unexpectedly succeeded with wrong message\n",
                 alg_name);
            ret = -1;
            goto err;
        }

        EVP_PKEY_CTX_free(sign_ctx);
        sign_ctx = NULL;
        EVP_PKEY_CTX_free(verify_ctx);
        verify_ctx = NULL;
    }

 err:
    if (signature)
        OPENSSL_free(signature);
    if (sign_ctx)
        EVP_PKEY_CTX_free(sign_ctx);
    if (verify_ctx)
        EVP_PKEY_CTX_free(verify_ctx);
    if (keygen_ctx)
        EVP_PKEY_CTX_free(keygen_ctx);
    if (ml_dsa_key)
        EVP_PKEY_free(ml_dsa_key);

    if (0 == ret)
        INFO("# PASS %s Keygen/Sign/Verify\n", alg_name ? alg_name : "ML-DSA");
    else
        INFO("# FAIL %s Keygen/Sign/Verify\n", alg_name ? alg_name : "ML-DSA");

    return ret;
}

/******************************************************************************
* function:
*       run_ml_dsa (void *args)
*
* @param args [IN] - the test parameters
*
* description:
*   specify a test case
*
******************************************************************************/
static int run_ml_dsa(void *args)
{
    int ret = 1;
    TEST_PARAMS *temp_args = (TEST_PARAMS *) args;
    int count = *(temp_args->count);
    int variant = temp_args->size;

    RAND_seed(rnd_seed, sizeof(rnd_seed));

    if (test_ml_dsa(count, variant, temp_args->print_output) < 0)
        ret = 0;

    return ret;
}

/******************************************************************************
* function:
*       tests_run_ml_dsa (TEST_PARAMS *args)
*
* @param args [IN] - the test parameters
*
* description:
*   specify a test case
*
******************************************************************************/
void tests_run_ml_dsa(TEST_PARAMS *args)
{
    args->additional_args = NULL;

    if (!args->enable_async)
        run_ml_dsa(args);
    else
        start_async_job(args, run_ml_dsa);
}

#endif /* ENABLE_QAT_SW_ML_DSA */
