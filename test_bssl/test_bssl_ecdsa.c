/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2023 Intel Corporation.
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
 * @file test_bssl_ecdsa.c
 *
 * This file provides a QAT Engine test functions.
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifndef __USE_GNU
# define __USE_GNU
#endif

/* Local Includes */
#include "qat_bssl.h"
#include "qat_utils.h"
#include "test_bssl_utils.h"
#include "test_bssl_ecdsa.h"

/* OpenSSL Includes */
#include <openssl/ssl.h>

# define EVP_MAX_MD_SIZE                 64
# define TEST_ECDSA_CURVE                NID_X9_62_prime256v1

static pthread_t    async_poll_thread;
static uint8_t     *sig_data = NULL;
static size_t       max_len = 0;
static unsigned int sig_len = 0;
static const char   in_data[] = "Intel® QuickAssist Technology (Intel® QAT)";

static void qat_ecdsa_handle_async_ctx(async_ctx *ctx)
{
    if (NULL == sig_data) {
        T_ERROR("sig_data is NULL\n");
        goto err;
    }
    /* Copy data from async_ctx */
    if (bssl_qat_async_ctx_copy_result(ctx, sig_data, (size_t *)&sig_len, max_len)) {
        T_ERROR("Fail to get output results\n");
        goto err;
    }

err:
    bssl_qat_async_finish_job(ctx);
}

static void *qat_ecdsa_polling_async_ctx(void *args)
{
    async_ctx *ctx = (async_ctx *)args;
    T_DEBUG("ECDSA test polling result thread start\n");
    while (*ctx->currjob_status != ASYNC_JOB_COMPLETE) {
        usleep(10);
    }
    T_DEBUG("ECDSA test polling result thread detect data ready\n");

    qat_ecdsa_handle_async_ctx(ctx);
    T_DEBUG("ECDSA test polling result thread finished\n");

    return (void*)0;
}

static async_ctx *qat_ecdsa_init_async_ctx(void) {

    async_ctx *ctx = bssl_qat_async_start_job();
    ASYNC_JOB *job = ctx->currjob;
    T_DEBUG("ECDSA init async_ctx async ctx:%p, job:%p, job->status:%d \n",
             ctx, job, job->status);
    pthread_create(&async_poll_thread, NULL, qat_ecdsa_polling_async_ctx, ctx);

    return ctx;
}

static void qat_ecdsa_wait_async_ctx()
{
    pthread_join(async_poll_thread, NULL);
}

int qat_ecdsa_test(const EVP_PKEY *pkey, int flag)
{
    unsigned int  mdlen = 0;
    unsigned char md[EVP_MAX_MD_SIZE];
    EVP_MD_CTX   *ctx;
    ECDSA_SIG    *signature = NULL;
    EC_KEY       *eckey = NULL;
    EC_KEY       *defult_eckey = NULL;
    const EVP_PKEY *lpkey = pkey;
    EC_GROUP *group = NULL;
    int type;

    if (flag & ECDSA_ASYNC_MODE) {
        qat_ecdsa_init_async_ctx();
    }

    if ((ctx = EVP_MD_CTX_new()) == NULL) {
        return -1;
    }

    if (!EVP_DigestInit(ctx, EVP_sha256())
        || !EVP_DigestUpdate(ctx, (const void*)in_data, 3)
        || !EVP_DigestFinal(ctx, md, &mdlen)) {
        goto err;
    }

    /* create the eckey if local pkey is NULL*/
    if (!lpkey && (eckey = EC_KEY_new_by_curve_name(
        TEST_ECDSA_CURVE)) == NULL) {
        T_ERROR("Failed to get EC key by curve name\n");
        goto err;
    }

    if (!lpkey && !EC_KEY_generate_key(eckey)) {
        T_ERROR("Failed to generate new EC key\n");
        goto err;
    }

    if (pkey) {
        defult_eckey = EVP_PKEY_get0_EC_KEY(lpkey);
        if (defult_eckey) {
            group = EC_GROUP_dup(EC_KEY_get0_group(defult_eckey));
            if (group) {
                type = EC_GROUP_get_curve_name(group);
            }
        }
    }

    if (!group) {
        type = TEST_ECDSA_CURVE;
        if((group = EC_GROUP_new_by_curve_name(type)) == NULL) {
            T_ERROR("Failed to generate new EC group\n");
            goto err;
        }
    }

    if (lpkey && NULL == (eckey =  EC_KEY_new_method(ENGINE_QAT_PTR_GET()))) {
        T_ERROR("Failed to load local private key\n");
        goto err;
    }

    if (!EC_KEY_set_group(eckey, group)) {
        T_ERROR("Failed to EC_KEY_set_group\n");
        goto err;
    }
    if (!EC_KEY_generate_key(eckey)) {
        T_ERROR("Failed to EC_KEY_generate_key\n");
        goto err;
    }

    max_len = ECDSA_size(eckey);
    if ((sig_data = (uint8_t *)OPENSSL_zalloc(max_len)) == NULL) {
        T_ERROR("Failed to allocate sig buffer\n");
        return -1;
    }

    T_DUMP_ECDSA_SIGN_INPUT(in_data, strlen(in_data));
    if (!ECDSA_sign(type, md, mdlen, sig_data, &sig_len, eckey)) {
         T_ERROR("ECDSA Sign: Failed\n");
        goto err;
    } else {
        if (flag & ECDSA_ASYNC_MODE) {
            qat_ecdsa_wait_async_ctx();
        }
        T_DEBUG("ECDSA Sign: OK\n");
        T_DUMP_ECDSA_SIGN_OUTPUT(sig_data, sig_len);
    }

    /* Verify */
    signature = ECDSA_SIG_from_bytes(sig_data, sig_len);
    if (ECDSA_do_verify(md, mdlen, signature, eckey) != 1) {\
        T_ERROR("ECDSA Verify: Failed\n");
        goto err;
    } else {
        T_DEBUG("ECDSA Verify: OK\n");
    }

err:
    if (!signature) {
        sig_len = 0;
    }
    if (sig_data) {
        OPENSSL_free(sig_data);
    }
    if (eckey)
        EC_KEY_free(eckey);
    EVP_MD_CTX_cleanup(ctx);

    return sig_len;
}
