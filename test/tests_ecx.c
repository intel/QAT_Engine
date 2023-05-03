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
#include <openssl/err.h>
#include <openssl/async.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#include "tests.h"
#include "../qat_utils.h"

#define NUM_OF_ECX_OPERATIONS 2
#define MAX_ECX_SIZE 128

/******************************************************************************
* function:
*       test_ecx_curve (int nid,
*                       const char *text,
*                       int count,
*                       int print_output,
*                       int verify,
*                       BIO *out)
*
* @param nid [IN] - curve object identifier
* @param text [IN] - curve names
* @param count [IN] - number of iterations
* @param print_output [IN] - print hex output flag
* @param verify [IN] - verify flag
* @param out [IN] - for printf debug messages
*
* description:
*       perform ECX generate key & derive key.
*
******************************************************************************/

static int test_ecx_curve(int nid,
                          const char *text,
                          int count,
                          int print_output,
                          int verify,
                          BIO *out)
{
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *comparison_ctx = NULL;
    EVP_PKEY *key_A = NULL;
    EVP_PKEY *key_B = NULL;
    size_t outlen = 0;
    size_t comparison_outlen = 0;
    unsigned char *outbuf = NULL, *comparison_outbuf = NULL;
    char buf[12];
    int i = 0, ret = 0;

    kctx = EVP_PKEY_CTX_new_id(nid, NULL); /* keygen ctx from NID */
    if (kctx == NULL) {
        WARN("# FAIL ECX - Initial mallocs failed\n");
        ret = -1;
        goto err;
    }

    if (print_output) {
        BIO_puts(out, "\nTesting ECX key generation with ");
        BIO_puts(out, text);
        BIO_puts(out, "\n");
    }

#ifdef QAT_OPENSSL_PROVIDER
    if ((key_A = EVP_PKEY_new()) <= 0 ||
        (key_B = EVP_PKEY_new()) <= 0) {
        fprintf(stderr, "EVP_PKEY_new failed. \n");
        ret = -1;
        goto err;
    }
#endif

    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        WARN("# FAIL ECX - keygen_init failed\n");
        ret = -1;
        goto err;
    }

    if (EVP_PKEY_keygen(kctx, &key_A) <= 0) {
        WARN("# FAIL ECX - keygen key_A failed\n");
        ret = -1;
        goto err;
    }

    if (EVP_PKEY_keygen(kctx, &key_B) <= 0) {
        WARN("# FAIL ECX - keygen key_B failed\n");
        ret = -1;
        goto err;
    }


    for (i = 0; i < count; i++) {
        /* Positive scenario */
        if (print_output)
            BIO_puts(out,"Positive test \n");

        if ((ctx = EVP_PKEY_CTX_new(key_A, NULL)) == NULL ||
            EVP_PKEY_derive_init(ctx) <= 0 ||
            EVP_PKEY_derive_set_peer(ctx, key_B) <= 0 ||
            EVP_PKEY_derive(ctx, NULL, &outlen) <= 0 || /* determine max length */
            outlen == 0 ||
            outlen > MAX_ECX_SIZE) {
            WARN("# FAIL ECX - ECX derive failed.\n");
            ret = -1;
            goto err;
        }

        outbuf = (unsigned char *)OPENSSL_zalloc(MAX_ECX_SIZE);
        if (outbuf == NULL) {
            WARN("#FAIL ECX - memory allocation failed.\n");
            ret = -1;
            goto err;
        }

        /*
         * Here we multiply the private key of key_A with the public key of
         * key_B, the peerkey.
         */
        if ((EVP_PKEY_derive(ctx, outbuf, &outlen)) <= 0) {
            WARN("# FAIL ECX - ECX derive failed.\n");
            ret = -1;
            goto err;
        }
        if (print_output) {
            BIO_puts(out," derived key = ");
            for (i = 0; i < outlen; i++) {
                sprintf(buf, "%02X ", outbuf[i]);
                BIO_puts(out, buf);
            }
            BIO_puts(out, "\n");
        }

        if (verify) {
            if ((comparison_ctx = EVP_PKEY_CTX_new(key_B, NULL)) == NULL ||
                EVP_PKEY_derive_init(comparison_ctx) <= 0 ||
                EVP_PKEY_derive_set_peer(comparison_ctx, key_A) <= 0 ||
                EVP_PKEY_derive(comparison_ctx, NULL, &comparison_outlen) <= 0 || /* determine max length */
                comparison_outlen == 0 ||
                comparison_outlen > MAX_ECX_SIZE) {
                WARN("# FAIL ECX - ECX derive failed.\n");
                ret = -1;
                goto err;
            }

            comparison_outbuf = (unsigned char *)OPENSSL_zalloc(MAX_ECX_SIZE);
            if (comparison_outbuf == NULL) {
                WARN("#FAIL ECX - memory allocation failed.\n");
                ret = -1;
                goto err;
            }

            /*
             * Here we multiply the private key of key_B with the public key of
             * key_A, the peerkey.
             */
            if ((EVP_PKEY_derive(comparison_ctx, comparison_outbuf,
                                 &comparison_outlen)) <= 0) {
                WARN("# FAIL ECX - ECX derive failed.\n");
                ret = -1;
                goto err;
            }

            if (print_output) {
                BIO_puts(out," comparison derived key = ");
                for (i = 0; i < comparison_outlen; i++) {
                    sprintf(buf, "%02X ", comparison_outbuf[i]);
                    BIO_puts(out, buf);
                }
                BIO_puts(out, "\n");
            }

            if ((comparison_outlen != outlen) ||
                (memcmp(outbuf, comparison_outbuf, outlen) != 0)) {
                WARN("#FAIL ECX - buffer comparison failed.\n");
                ret = -1;
            }
        }
        if (ctx != NULL) {
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
        }
        if (comparison_ctx != NULL) {
            EVP_PKEY_CTX_free(comparison_ctx);
            comparison_ctx = NULL;
        }

        if (outbuf != NULL) {
            OPENSSL_free(outbuf);
            outbuf = NULL;
        }
        if (comparison_outbuf != NULL) {
            OPENSSL_free(comparison_outbuf);
            comparison_outbuf = NULL;
        }
    }
    if (ret == 0)
        INFO("# PASS verify for ECDH%s.\n", text);
    else
        INFO("# FAIL verify for ECDH%s.\n", text);

err:
    if (ret != 0)
        ERR_print_errors_fp(stderr);

    EVP_PKEY_free(key_A);
    EVP_PKEY_free(key_B);
    if (kctx != NULL) {
        EVP_PKEY_CTX_free(kctx);
        kctx = NULL;
    }
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    }
    if (comparison_ctx != NULL) {
        EVP_PKEY_CTX_free(comparison_ctx);
        comparison_ctx = NULL;
    }
    if (outbuf != NULL) {
        OPENSSL_free(outbuf);
        outbuf = NULL;
    }
    if (comparison_outbuf != NULL) {
        OPENSSL_free(comparison_outbuf);
        comparison_outbuf = NULL;
    }

    return ret;
}


/******************************************************************************
* function:
*       run_ecx (void *args)
*
* @param args [IN] - the test parameters
*
* description:
*   specify a test case
*
******************************************************************************/
static int run_ecx(void *args)
{
    TEST_PARAMS *local_args = (TEST_PARAMS *)args;
    int count = *(local_args->count);
    int print_output = local_args->print_output;
    int verify = local_args->verify;
    BIO *out = NULL;
    int ret = 1;

    out = BIO_new(BIO_s_file());
    if (out == NULL) {
        WARN("# FAIL: Unable to create BIO\n");
        exit(1);
    }
    BIO_set_fp(out, stdout, BIO_NOCLOSE);

    if (local_args->curve == X_CURVE_448)
        ret = test_ecx_curve(EVP_PKEY_X448, "X448", count, print_output, verify, out);
    else
        ret = test_ecx_curve(EVP_PKEY_X25519, "X25519", count, print_output, verify, out);

    if (ret < 0)
        ERR_print_errors_fp(stderr);
    else
        ret = 1;
    BIO_free(out);

    return ret;
}

/******************************************************************************
* function:
*       tests_run_ecx (TEST_PARAMS *args)
*
* @param args [IN] - the test parameters
*
* description:
*   specify a test case
*
******************************************************************************/
void tests_run_ecx(TEST_PARAMS *args)
{
    if (!args->enable_async)
        run_ecx(args);
    else
        start_async_job(args, run_ecx);
}
