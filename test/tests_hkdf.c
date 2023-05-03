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

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <openssl/kdf.h>
#include "tests.h"
#include "../qat_utils.h"

#define OUTPUT_LEN 32
#define SEED_LEN 13
#define SECRET_LEN 22
#define INFO_LEN 10
#define HASH_SIZE_SHA256 32
#define HASH_SIZE_SHA384 48

static const unsigned char hkdf_salt[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c
};

static const unsigned char hkdf_secret[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

unsigned char info[] = {
    0xf0, 0xf1 ,0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9
};

static const unsigned char hkdf_expand_sha256[] = {
    0x3C, 0xB2, 0x5F, 0x25, 0xFA, 0xAC, 0xD5, 0x7A,
    0x90, 0x43, 0x4F, 0x64, 0xD0, 0x36, 0x2F, 0x2A,
    0x2D, 0x2D, 0x0A, 0x90, 0xCF, 0x1A, 0x5A, 0x4C,
    0x5D, 0xB0, 0x2D, 0x56, 0xEC, 0xC4, 0xC5, 0xBF,
};

static const unsigned char hkdf_expand_sha384[] = {
    0x9B, 0x50, 0x97, 0xA8, 0x60, 0x38, 0xB8, 0x05,
    0x30, 0x90, 0x76, 0xA4, 0x4B, 0x3A, 0x9F, 0x38,
    0x06, 0x3E, 0x25, 0xB5, 0x16, 0xDC, 0xBF, 0x36,
    0x9F, 0x39, 0x4C, 0xFA, 0xB4, 0x36, 0x85, 0xF7,
};

static const unsigned char hkdf_extract_sha256[] = {
    0x07, 0x77, 0x09, 0x36, 0x2C, 0x2E, 0x32, 0xDF,
    0x0D, 0xDC, 0x3F, 0x0D, 0xC4, 0x7B, 0xBA, 0x63,
    0x90, 0xB6, 0xC7, 0x3B, 0xB5, 0x0F, 0x9C, 0x31,
    0x22, 0xEC, 0x84, 0x4A, 0xD7, 0xC2, 0xB3, 0xE5
};

static const unsigned char hkdf_extract_sha384[] = {
    0x70, 0x4B, 0x39, 0x99, 0x07, 0x79, 0xCE, 0x1D,
    0xC5, 0x48, 0x05, 0x2C, 0x7D, 0xC3, 0x9F, 0x30,
    0x35, 0x70, 0xDD, 0x13, 0xFB, 0x39, 0xF7, 0xAC,
    0xC5, 0x64, 0x68, 0x0B, 0xEF, 0x80, 0xE8, 0xDE,
    0xC7, 0x0E, 0xE9, 0xA7, 0xE1, 0xF3, 0xE2, 0x93,
    0xEF, 0x68, 0xEC, 0xEB, 0x07, 0x2A, 0x5A, 0xDE
};

static void populate_HKDF(char *digest_kdf, int operation,
                          unsigned char **salt, int *salt_len,
                          unsigned char **secret, int *secret_len,
                          unsigned char **expectedMasterSecret,
                          size_t *masterSecretSize)
{
    *salt = (unsigned char *)&hkdf_salt;
    *secret = (unsigned char *)&hkdf_secret;
    *secret_len = SECRET_LEN;
    *salt_len = SEED_LEN;
    *masterSecretSize = OUTPUT_LEN;

    switch(operation) {
    case EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND:
        WARN("# HKDF mode EXTRACT_AND_EXPAND.\n");
        if (!strcmp(digest_kdf, "SHA256"))
            *expectedMasterSecret = (unsigned char *)hkdf_expand_sha256;
        else if (!strcmp(digest_kdf, "SHA384"))
            *expectedMasterSecret = (unsigned char *)hkdf_expand_sha384;
        break;
    case EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY:
        WARN("# HKDF mode EXTRACT.\n");
        if (!strcmp(digest_kdf, "SHA256")) {
            *expectedMasterSecret = (unsigned char *)hkdf_extract_sha256;
            *masterSecretSize = HASH_SIZE_SHA256;
        } else if (!strcmp(digest_kdf, "SHA384")) {
            *expectedMasterSecret = (unsigned char *)hkdf_extract_sha384;
            *masterSecretSize = HASH_SIZE_SHA384;
        }
        break;
    case EVP_PKEY_HKDEF_MODE_EXPAND_ONLY:
        WARN("# HKDF mode EXPAND.\n");
        if (!strcmp(digest_kdf, "SHA256")) {
            *secret = (unsigned char *)&hkdf_extract_sha256;
            *expectedMasterSecret = (unsigned char *)hkdf_expand_sha256;
            *secret_len = HASH_SIZE_SHA256;
        } else if (!strcmp(digest_kdf, "SHA384")) {
            *secret = (unsigned char *)&hkdf_extract_sha384;
            *expectedMasterSecret = (unsigned char *)hkdf_expand_sha384;
            *secret_len = HASH_SIZE_SHA384;
        }
        break;
    }
}

static int qat_HKDF(const EVP_MD *md, int mode,
                    unsigned char *salt, int *salt_len,
                    unsigned char *secret, int *secret_len,
                    unsigned char *out, size_t out_len)
{
    EVP_PKEY_CTX *pctx = NULL;
    int ret = 0;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (pctx == NULL || EVP_PKEY_derive_init(pctx) <= 0)
        goto err;
    if (EVP_PKEY_CTX_hkdf_mode(pctx, mode) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, *salt_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, *secret_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, INFO_LEN) <= 0)
        goto err;

    if (EVP_PKEY_derive(pctx, out, &out_len) <= 0)
        goto err;
    ret = 1;

err:
    if (ret == 0)
        WARN("# FAIL: performing qat_HKDF operations\n");
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

static int runHkdfOps(void *args)
{
    TEST_PARAMS *temp_args = (TEST_PARAMS *)args;
    int operation = temp_args->hkdf_op;
    int print_output = temp_args->print_output;
    int verify = temp_args->verify;
    char *digest_kdf = temp_args->digest_kdf;
    const EVP_MD *md = NULL;

    unsigned char *salt = NULL;
    unsigned char *secret = NULL, *expectedMasterSecret = NULL;
    unsigned char *masterSecret = NULL;
    int res = 0;
    size_t masterSecretSize = OUTPUT_LEN;
    int salt_len = 0, secret_len = 0;
    int count = 0;

    if (!strcmp(digest_kdf, "SHA256"))
        md = EVP_sha256();
    else if (!strcmp(digest_kdf, "SHA384"))
        md = EVP_sha384();
    else {
        WARN("# FAIL: message digest is not supported!!\n");
        return res;
    }

    for (count = 0; count < *(temp_args->count); count++) {
        masterSecret = OPENSSL_zalloc(sizeof(hkdf_extract_sha384));

        populate_HKDF(digest_kdf, operation,
                      &salt, &salt_len,
                      &secret, &secret_len,
                      &expectedMasterSecret,
                      &masterSecretSize);

        res = qat_HKDF(md, operation,
                       salt, &salt_len,
                       secret, &secret_len,
                       masterSecret, masterSecretSize);

        if ((verify && count == 0) || res == 0) {
            if (memcmp(masterSecret, expectedMasterSecret, masterSecretSize)) {
                INFO("# FAIL verify for HKDF mode.\n");
                tests_hexdump("HKDF actual  :", masterSecret, masterSecretSize);
                tests_hexdump("HKDF expected:", expectedMasterSecret,
                              masterSecretSize);
                res = 0;
            }
            else
                INFO("# PASS verify for HKDF.\n");

            if (print_output)
                tests_hexdump("HKDF master secret:", masterSecret,
                              masterSecretSize);
        }
        if (masterSecret) {
            OPENSSL_free(masterSecret);
            masterSecret = NULL;
        }
    }
    return res;
}

/******************************************************************************
* function:
*   tests_run_hkdf    (TEST_PARAMS *args)
*
*
* @param args         [IN] - the test parameters
*
* Description:
*  This is a function to test the HKDF (Hash-based Key Derivation Function).
******************************************************************************/

void tests_run_hkdf(TEST_PARAMS *args)
{
    int op = 0;

    if (args->performance || args->hkdf_op != -1 ) {
        /* Operation if not specified for performance tests */
        if (args->hkdf_op != -1)
            args->hkdf_op = 0;
        if (!args->enable_async)
            runHkdfOps(args);
        else
            start_async_job(args, runHkdfOps);
        return;
    }
    if (!args->enable_async) {
        for (op = 0; op <= EVP_PKEY_HKDEF_MODE_EXPAND_ONLY ; op++) {
             args->hkdf_op = op;
             runHkdfOps(args);
        }
    } else {
        for (op = 0; op <= EVP_PKEY_HKDEF_MODE_EXPAND_ONLY ; op++) {
             args->hkdf_op = op;
             start_async_job(args, runHkdfOps);
        }
    }
}
