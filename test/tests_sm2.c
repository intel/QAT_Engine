/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021-2023 Intel Corporation.
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
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/async.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <openssl/engine.h>

#include "tests.h"
#include "../qat_utils.h"

#define SM2_ID        "TLSv1.3+GM+Cipher+Suite"
#define SM2_ID_LEN    sizeof("TLSv1.3+GM+Cipher+Suite") - 1

static const char rnd_seed[] =
    "string to make the random number generator think it has entropy";

EVP_PKEY *get_sm2_key(const int nid)
{
    EVP_PKEY *sm2_key = NULL;
    EVP_PKEY_CTX *kctx = NULL;

    kctx = EVP_PKEY_CTX_new_id(nid, NULL);

    if (kctx == NULL) {
        EVP_PKEY_CTX *pctx = NULL;
        EVP_PKEY *params = NULL;

        /* Create the context for parameter generation */
#ifdef QAT_OPENSSL_3
        pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
#else
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
#endif
        if ((pctx == NULL)
            || EVP_PKEY_paramgen_init(pctx) <= 0
            || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                                                      nid) <= 0
            || EVP_PKEY_paramgen(pctx, &params) <= 0) {
            fprintf(stderr, "SM2 params init failure.\n");
            EVP_PKEY_CTX_free(pctx);
            return NULL;
        }
        EVP_PKEY_CTX_free(pctx);

        /* Create the context for the key generation */
        kctx = EVP_PKEY_CTX_new(params, NULL);
        EVP_PKEY_free(params);
    }

    if (kctx == NULL
        || EVP_PKEY_keygen_init(kctx) <= 0
        || EVP_PKEY_keygen(kctx, &sm2_key) <= 0) {
        fprintf(stderr, "# FAIL SM2 keygen init failed\n");
        sm2_key = NULL;
    }
    EVP_PKEY_CTX_free(kctx);
    return sm2_key;
}

#ifndef QAT_OPENSSL_3
static int test_sm2_sign_verify(int count, int size, ENGINE *e,
                                int print_output, int verify, int nid,
                                const char *curveName)
{
    unsigned char digest[size], wrong_digest[size];
    unsigned char *signature = NULL;
    BIO *out = NULL;
    int ret = 0, i;
    char buf[256];
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *sm2_pctx = NULL;
    EVP_PKEY_CTX *sm2_vfy_pctx = NULL;
    EVP_PKEY *sm2_pkey = NULL;
    EVP_MD_CTX *sm2_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX *sm2_vfy_ctx = EVP_MD_CTX_new();
    size_t sigsize = 0;
    out = BIO_new(BIO_s_file());
    if (out == NULL) {
        WARN("# FAIL: Unable to create BIO\n");
        exit(1);
    }
    BIO_set_fp(out, stdout, BIO_NOCLOSE);

    /* fill digest values with some random data */
    if ((RAND_bytes(digest, size) <= 0) ||
        (RAND_bytes(wrong_digest, size) <= 0)) {
        WARN("# FAIL: unable to get random data\n");
        ret = -1;
        goto builtin_err;
    }

    /* SM2 keys are generated as normal EC keys with a special curve */
    if (((pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL)
        || (EVP_PKEY_keygen_init(pctx) <= 0)
        || (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0)
        || EVP_PKEY_keygen(pctx, &sm2_pkey) <= 0) {
        ret = -1;
        EVP_PKEY_CTX_free(pctx);
        goto builtin_err;
    }
    EVP_PKEY_CTX_free(pctx);

    sigsize = ECDSA_size(EVP_PKEY_get0_EC_KEY(sm2_pkey));

    if (!EVP_PKEY_set_alias_type(sm2_pkey, EVP_PKEY_SM2)) {
        ret = -1;
        WARN("# FAIL: EVP_PKEY set allias type Failed\n");
        goto builtin_err;
    }

    sm2_pctx = EVP_PKEY_CTX_new(sm2_pkey, NULL);
    if (sm2_pctx == NULL) {
        ret = -1;
        WARN("# FAIL: EVP_PKEY_CTX Alloc Failure\n");
        goto builtin_err;
    }
    sm2_vfy_pctx = EVP_PKEY_CTX_new(sm2_pkey, NULL);
    if (sm2_vfy_pctx == NULL) {
        ret = -1;
        WARN("# FAIL: EVP_PKEY_CTX Alloc Failure\n");
        goto builtin_err;
    }
    if (EVP_PKEY_CTX_set1_id(sm2_pctx, SM2_ID, SM2_ID_LEN) != 1) {
        ret = -1;
        WARN("# FAIL: EVP_PKEY_CTX_set1_id Failure\n");
        goto builtin_err;
    }
    if (EVP_PKEY_CTX_set1_id(sm2_vfy_pctx, SM2_ID, SM2_ID_LEN) != 1) {
        ret = -1;
        WARN("# FAIL: EVP_PKEY_CTX_set1_id Failure\n");
        goto builtin_err;
    }

    EVP_MD_CTX_set_pkey_ctx(sm2_ctx, sm2_pctx);
    EVP_MD_CTX_set_pkey_ctx(sm2_vfy_ctx, sm2_vfy_pctx);

    if (!EVP_DigestSignInit(sm2_ctx, NULL, EVP_sm3(), NULL, sm2_pkey)) {
        ret = -1;
        WARN("# FAIL: EVP_DigestSignInit Failed\n");
        goto builtin_err;
    }
    if (!EVP_DigestVerifyInit(sm2_vfy_ctx, NULL, EVP_sm3(), NULL, sm2_pkey)) {
        ret = -1;
        WARN("# FAIL: EVP_DigestVerifyInit Failed\n");
        goto builtin_err;
    }

    if ((signature = OPENSSL_malloc(sigsize)) == NULL) {
        ret = -1;
        WARN("# FAIL: failed to malloc signature\n");
        goto builtin_err;
    }

    if (print_output)
        printf("%s\n", OBJ_nid2sn(nid));

    for (i = 0; i < count; ++i) {
        if (!EVP_DigestSign(sm2_ctx, signature, &sigsize, digest, 20)) {
            WARN("# FAIL: Failed to Sign\n");
            ret = -1;
            goto builtin_err;
        }
        if (print_output) {
            BIO_puts(out, "SM2_sign signature: ");
            for (i = 0; i < sigsize; i++) {
                sprintf(buf, "%02X ", signature[i]);
                BIO_puts(out, buf);
            }
            BIO_puts(out, "\n");
        }

        /* Verify Signature */
        if (EVP_DigestVerify(sm2_vfy_ctx, signature, sigsize, digest, 20) != 1) {
            WARN("# FAIL: Failed to verify\n");
            ret = -1;
            goto builtin_err;
        }
    }

    /* Verify Signature with a wrong digest */
    if (EVP_DigestVerify(sm2_vfy_ctx, signature, sigsize,
                         wrong_digest, 20) == 1) {
        WARN("# FAIL: Verified with wrong digest\n");
        ret = -1;
        goto builtin_err;
    }

 builtin_err:
    if (sm2_pkey)
        EVP_PKEY_free(sm2_pkey);
    if (sm2_pctx)
        EVP_PKEY_CTX_free(sm2_pctx);
    if (sm2_vfy_pctx)
        EVP_PKEY_CTX_free(sm2_vfy_pctx);
    if (sm2_ctx)
        EVP_MD_CTX_free(sm2_ctx);
    if (sm2_vfy_ctx)
        EVP_MD_CTX_free(sm2_vfy_ctx);
    if (signature)
        OPENSSL_free(signature);
    BIO_free(out);

    if (0 == ret)
        INFO("# PASS SM2 Sign/Verify for nid %s\n", curveName);
    else
        INFO("# FAIL SM2 Sign/Verify for nid %s\n", curveName);
    return ret;
}
#else
static int test_sm2_sign_verify(int count, int size, ENGINE *e,
                                int print_output, int verify, int nid,
                                const char *curveName)
{
    unsigned char digest[size], wrong_digest[size];
    unsigned char *signature = NULL;
    BIO *out = NULL;
    int ret = 0, i;
    char buf[256];
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *sm2_pctx = NULL;
    EVP_PKEY_CTX *sm2_vfy_pctx = NULL;
    EVP_PKEY *sm2_pkey = NULL;
    EVP_MD_CTX *sm2_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX *sm2_vfy_ctx = EVP_MD_CTX_new();
    size_t sigsize = 0;

    out = BIO_new(BIO_s_file());
    if (out == NULL) {
        WARN("# FAIL: Unable to create BIO\n");
        exit(1);
    }
    BIO_set_fp(out, stdout, BIO_NOCLOSE);

    /* fill digest values with some random data */
    if ((RAND_bytes(digest, size) <= 0) ||
        (RAND_bytes(wrong_digest, size) <= 0)) {
        WARN("# FAIL: unable to get random data\n");
        ret = -1;
        goto builtin_err;
    }

    /* SM2 keys are generated as normal EC keys with a special curve */
    if (((pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL)) == NULL)
        || (EVP_PKEY_keygen_init(pctx) <= 0)
        || (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0)
        || EVP_PKEY_keygen(pctx, &sm2_pkey) <= 0) {
        ret = -1;
        EVP_PKEY_CTX_free(pctx);
        goto builtin_err;
    }
    EVP_PKEY_CTX_free(pctx);

    sigsize = EVP_PKEY_get_size(sm2_pkey);

    sm2_pctx = EVP_PKEY_CTX_new(sm2_pkey, NULL);
    if (sm2_pctx == NULL) {
        ret = -1;
        WARN("# FAIL: EVP_PKEY_CTX Alloc Failure\n");
        goto builtin_err;
    }
    sm2_vfy_pctx = EVP_PKEY_CTX_new(sm2_pkey, NULL);
    if (sm2_vfy_pctx == NULL) {
        ret = -1;
        WARN("# FAIL: EVP_PKEY_CTX Alloc Failure\n");
        goto builtin_err;
    }
    if (EVP_PKEY_CTX_set1_id(sm2_pctx, SM2_ID, SM2_ID_LEN) != 1) {
        ret = -1;
        WARN("# FAIL: EVP_PKEY_CTX_set1_id Failure\n");
        goto builtin_err;
    }
    if (EVP_PKEY_CTX_set1_id(sm2_vfy_pctx, SM2_ID, SM2_ID_LEN) != 1) {
        ret = -1;
        WARN("# FAIL: EVP_PKEY_CTX_set1_id Failure\n");
        goto builtin_err;
    }

    EVP_MD_CTX_set_pkey_ctx(sm2_ctx, sm2_pctx);
    EVP_MD_CTX_set_pkey_ctx(sm2_vfy_ctx, sm2_vfy_pctx);

    if (!EVP_DigestSignInit(sm2_ctx, NULL, EVP_sm3(), NULL, sm2_pkey)) {
        ret = -1;
        WARN("# FAIL: EVP_DigestSignInit Failed\n");
        goto builtin_err;
    }
    if (!EVP_DigestVerifyInit(sm2_vfy_ctx, NULL, EVP_sm3(), NULL, sm2_pkey)) {
        ret = -1;
        WARN("# FAIL: EVP_DigestVerifyInit Failed\n");
        goto builtin_err;
    }

    if ((signature = OPENSSL_malloc(sigsize)) == NULL) {
        ret = -1;
        WARN("# FAIL: failed to malloc signature\n");
        goto builtin_err;
    }

    if (print_output)
        printf("%s\n", OBJ_nid2sn(nid));

    for (i = 0; i < count; ++i) {
        if (!EVP_DigestSign(sm2_ctx, signature, &sigsize, digest, 20)) {
            WARN("# FAIL: Failed to Sign\n");
            ret = -1;
            goto builtin_err;
        }
        if (print_output) {
            BIO_puts(out, "SM2_sign signature: ");
            for (i = 0; i < sigsize; i++) {
                sprintf(buf, "%02X ", signature[i]);
                BIO_puts(out, buf);
            }
            BIO_puts(out, "\n");
        }

        /* Verify Signature */
        if (EVP_DigestVerify(sm2_vfy_ctx, signature, sigsize, digest, 20) != 1) {
            WARN("# FAIL: Failed to verify\n");
            ret = -1;
            goto builtin_err;
        }
    }

    /* Verify Signature with a wrong digest */
    if (EVP_DigestVerify(sm2_vfy_ctx, signature, sigsize,
                         wrong_digest, 20) == 1) {
        WARN("# FAIL: Verified with wrong digest\n");
        ret = -1;
        goto builtin_err;
    }

 builtin_err:
    if (sm2_pkey)
        EVP_PKEY_free(sm2_pkey);
    if (sm2_pctx)
        EVP_PKEY_CTX_free(sm2_pctx);
    if (sm2_vfy_pctx)
        EVP_PKEY_CTX_free(sm2_vfy_pctx);
    if (sm2_ctx)
        EVP_MD_CTX_free(sm2_ctx);
    if (sm2_vfy_ctx)
        EVP_MD_CTX_free(sm2_vfy_ctx);
    if (signature)
        OPENSSL_free(signature);
    BIO_free(out);

    if (0 == ret)
        INFO("# PASS SM2 Sign/Verify for nid %s\n", curveName);
    else
        INFO("# FAIL SM2 Sign/Verify for nid %s\n", curveName);
    return ret;
}
#endif

/******************************************************************************
 * function:
 *       test_sm2 (int count,
 *                   int size,
 *                   engine *e,
 *                   int print_output,
 *                   int verify,
 *                   int curveType,
 *                   int ne)
 *
 * @param count [IN] - number of iterations
 * @param size [IN] - the length of input message
 * @param e [IN] - OpenSSL engine pointer
 * @param print_output [IN] - print hex output flag
 * @param verify [IN] - verify flag
 * @param nid [IN] - nid to be used
 * @param curveName [IN] - curve name to be used
 *
 * description:
 *       SM2 Sign and Verify Test
 *
******************************************************************************/
static int test_sm2(int count, int size, ENGINE *e, int print_output,
                    int verify, int curveType, int ne)
{
    BIO *out = NULL;
    int nid = NID_sm2;
    const char *curveName = "SM2 Curve";

    out = BIO_new(BIO_s_file());
    if (out == NULL) {
        WARN("# FAIL: Unable to create BIO\n");
        exit(1);
    }
    BIO_set_fp(out, stdout, BIO_NOCLOSE);

    return test_sm2_sign_verify(count, size, e, print_output, verify, nid,
                                curveName);
}

/******************************************************************************
* function:
*       tests_run_sm2(void *args)
*
* @param args [IN] - the test parameters
*
* description:
*   specify a test case
*
******************************************************************************/
static int run_sm2(void *args)
{
    int i = 0;
    int ret = 1;

    TEST_PARAMS *temp_args = (TEST_PARAMS *) args;
    int count = *(temp_args->count);
    int size = temp_args->size;
    /*
     * If temp_args->explicit_engine is not set then set the
     * engine to NULL to allow fallback to software if
     * that engine under test does not support this operation.
     * This relies on the engine we are testing being
     * set as the default engine.
     */
    ENGINE *e = temp_args->explicit_engine ? temp_args->e : NULL;
    int print = temp_args->print_output;
    int verify = temp_args->verify;
    int curve = temp_args->curve;
    int ne = 0;

#if CPA_CY_API_VERSION_NUM_MAJOR < 3
    ne = temp_args->enable_negative;
#endif

    RAND_seed(rnd_seed, sizeof(rnd_seed));

    if (!curve) {
        for (i = 1; i < CURVE_TYPE_MAX; i++) {
            if (test_sm2(count, size, e, print, verify, i, ne) < 0)
                ret = 0;
        }
    } else if (test_sm2(count, size, e, print, verify, curve, ne) < 0) {
        ret = 0;
    }
    return ret;
}

/******************************************************************************
* function:
*       tests_run_sm2(TEST_PARAMS *args)
*
* @param args [IN] - the test parameters
*
* description:
*   specify a test case
*
******************************************************************************/
void tests_run_sm2(TEST_PARAMS *args)
{
    args->additional_args = NULL;

    if (!args->enable_async)
        run_sm2(args);
    else
        start_async_job(args, run_sm2);
}
