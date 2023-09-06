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

# include <stdio.h>
# include <stdlib.h>
# include <string.h>

# include <openssl/evp.h>
# include <openssl/engine.h>
# include <openssl/ssl.h>
# include <openssl/kdf.h>
# include <openssl/core_names.h>
# include "tests.h"
# include "../qat_utils.h"

# define OUTPUT_LEN 32
# define SEED_LEN 13
# define SECRET_LEN 22
# define INFO_LEN 10
# define HASH_SIZE_SHA256 32
# define HASH_SIZE_SHA384 48

/* HKDF data */
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
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
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

#ifdef QAT_OPENSSL_3
/* TLS13_KDF data */
static const unsigned char tls13_kdf_key[] = {
    0xF8, 0xAF, 0x6A, 0xEA, 0x2D, 0x39, 0x7B, 0xAF,
    0x29, 0x48, 0xA2, 0x5B, 0x28, 0x34, 0x20, 0x06,
    0x92, 0xCF, 0xF1, 0x7E, 0xEE, 0x91, 0x65, 0xE4,
    0xE2, 0x7B, 0xAB, 0xEE, 0x9E, 0xDE, 0xFD, 0x05
};

static const unsigned char tls13_kdf_extract_out[] = {
    0x15, 0x3B, 0x63, 0x94, 0xA9, 0xC0, 0x3C, 0xF3,
    0xF5, 0xAC, 0xCC, 0x6E, 0x45, 0x5A, 0x76, 0x93,
    0x28, 0x11, 0x38, 0xA1, 0xBC, 0xFA, 0x38, 0x03,
    0xC2, 0x67, 0x35, 0xDD, 0x11, 0x94, 0xD2, 0x16
};

static const unsigned char tls13_kdf_prefix[] = {
    0x74, 0x6C, 0x73, 0x31, 0x33, 0x20 /* "tls13 " */
};

/* client_hello_hash tls13_kdf_data*/
static const unsigned char tls13_kdf_data[] = {
    0x7c, 0x92, 0xf6, 0x8b, 0xd5, 0xbf, 0x36, 0x38,
    0xea, 0x33, 0x8a, 0x64, 0x94, 0x72, 0x2e, 0x1b,
    0x44, 0x12, 0x7e, 0x1b, 0x7e, 0x8a, 0xad, 0x53,
    0x5f, 0x23, 0x22, 0xa6, 0x44, 0xff, 0x22, 0xb3
};

static const unsigned char tls13_kdf_label[] = {
    0x63, 0x20, 0x65, 0x20, 0x74, 0x72, 0x61, 0x66,
    0x66, 0x69, 0x63            /* "c e traffic" */
};

/* tls13_kdf_client_early_traffic_secret */
static const unsigned char tls13_kdf_expand_secret[] = {
    0xC8, 0x05, 0x83, 0xA9, 0x0E, 0x99, 0x5C, 0x48,
    0x96, 0x00, 0x49, 0x2A, 0x5D, 0xA6, 0x42, 0xE6,
    0xB1, 0xF6, 0x79, 0xBA, 0x67, 0x48, 0x28, 0x79,
    0x2D, 0xF0, 0x87, 0xB9, 0x39, 0x63, 0x61, 0x71
};

static int qat_extract_expand(const EVP_MD *md, int mode,
                              unsigned char *key, size_t key_len,
                              unsigned char *out, size_t out_len)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    int ret = 0;
    OSSL_PARAM params[8], *p = params;
    kdf = EVP_KDF_fetch(NULL, "TLS13-KDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL)
        return 0;
    EVP_KDF_free(kdf);
    size_t mdlen = (size_t)EVP_MD_get_size(md);
    const char *mdname = EVP_MD_get0_name(md);

    if (mode == EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) {
        *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                (char *)mdname, 0);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                 (unsigned char *)key, key_len);
        *p++ = OSSL_PARAM_construct_end();

        ret = EVP_KDF_derive(kctx, out, mdlen, params);

        if (ret != 0)
            EVP_KDF_CTX_free(kctx);
    }

    if (mode == EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) {
        *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                (char *)mdname, 0);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                 (unsigned char *)key, key_len);

        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_DATA,
                                                 (unsigned char *)
                                                 tls13_kdf_data,
                                                 (size_t)
                                                 sizeof(tls13_kdf_data));

        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PREFIX,
                                                 (unsigned char *)
                                                 tls13_kdf_prefix,
                                                 (size_t)
                                                 sizeof(tls13_kdf_prefix));

        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL,
                                                 (unsigned char *)
                                                 tls13_kdf_label,
                                                 (size_t)
                                                 sizeof(tls13_kdf_label));
        *p++ = OSSL_PARAM_construct_end();

        ret = EVP_KDF_derive(kctx, out, mdlen, params);

        if (ret != 0)
            EVP_KDF_CTX_free(kctx);
    }
    return ret;
}

static int runTls13KdfOps(void *args)
{
    TEST_PARAMS *temp_args = (TEST_PARAMS *) args;
    int print_output = temp_args->print_output;
    char *digest_kdf = temp_args->digest_kdf;
    const EVP_MD *md = NULL;
    size_t mdlen;
    int res = 0;

    if (!strcmp(digest_kdf, "SHA256"))
        md = EVP_sha256();
    else if (!strcmp(digest_kdf, "SHA384"))
        md = EVP_sha384();
    else {
        WARN("# FAIL: message digest is not supported!!\n");
        return res;
    }

    mdlen = (size_t)EVP_MD_get_size(md);

    /*extract output will store in tls13_kdf_early_secret */
    unsigned char *tls13_kdf_early_secret = OPENSSL_zalloc(mdlen);

    /*expand output will store in tls13_kdf_master_secret */
    unsigned char *tls13_kdf_master_secret = OPENSSL_zalloc(mdlen);

    res = qat_extract_expand(md, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY,
                             (unsigned char *)tls13_kdf_key,
                             (size_t)sizeof(tls13_kdf_key),
                             tls13_kdf_early_secret, mdlen);

    if (!memcmp(tls13_kdf_early_secret, tls13_kdf_extract_out, mdlen)) {
        res = qat_extract_expand(md, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY,
                                 tls13_kdf_early_secret, mdlen,
                                 tls13_kdf_master_secret, mdlen);
    }

    if (memcmp(tls13_kdf_master_secret, tls13_kdf_expand_secret,
               sizeof(tls13_kdf_expand_secret))) {
        INFO("# FAIL verify for TLS13-KDF extract & expand.\n");
        tests_hexdump("TLS13-KDF expand actual  :",
                      tls13_kdf_master_secret, mdlen);
        tests_hexdump("TLS13-KDF expand expected:",
                      tls13_kdf_expand_secret, sizeof(tls13_kdf_expand_secret));

        res = 0;
    } else {
        INFO("# PASS verify for TLS13-KDF extract & expand.\n");
    }

    if (print_output) {
        tests_hexdump("TLS13-KDF extract key:", tls13_kdf_early_secret, mdlen);
        tests_hexdump("TLS13-KDF expand key:", tls13_kdf_master_secret, mdlen);
    }

    if (tls13_kdf_master_secret) {
        OPENSSL_free(tls13_kdf_master_secret);
        tls13_kdf_master_secret = NULL;
    }

    if (tls13_kdf_early_secret) {
        OPENSSL_free(tls13_kdf_early_secret);
        tls13_kdf_early_secret = NULL;
    }
    return res;
}
#endif

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

    switch (operation) {
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
    TEST_PARAMS *temp_args = (TEST_PARAMS *) args;
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
                      &expectedMasterSecret, &masterSecretSize);

        res = qat_HKDF(md, operation,
                       salt, &salt_len,
                       secret, &secret_len, masterSecret, masterSecretSize);

        if ((verify && count == 0) || res == 0) {
            if (memcmp(masterSecret, expectedMasterSecret, masterSecretSize)) {
                INFO("# FAIL verify for HKDF mode.\n");
                tests_hexdump("HKDF actual  :", masterSecret, masterSecretSize);
                tests_hexdump("HKDF expected:", expectedMasterSecret,
                              masterSecretSize);
                res = 0;
            } else {
                switch(operation) {
                case EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND:
                    INFO("# PASS verify for HKDF extract & expand.\n");
                    break;
                case EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY:
                    INFO("# PASS verify for HKDF extract.\n");
                    break;
                case EVP_PKEY_HKDEF_MODE_EXPAND_ONLY:
                    INFO("# PASS verify for HKDF expand.\n");
                    break;
                }
            }

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

    if (args->performance || args->hkdf_op != -1) {
        /* Operation if not specified for performance tests */
        if (args->hkdf_op == -1)
            args->hkdf_op = 0;
        if (!args->enable_async) {
            runHkdfOps(args);
#ifdef QAT_OPENSSL_3
            if (args->hkdf_op != EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND)
                runTls13KdfOps(args);
#endif
        } else {
            start_async_job(args, runHkdfOps);
#ifdef QAT_OPENSSL_3
            if (args->hkdf_op != EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND)
                start_async_job(args, runTls13KdfOps);
#endif
        }
        return;
    }
    if (!args->enable_async) {
        for (op = 0; op <= EVP_PKEY_HKDEF_MODE_EXPAND_ONLY; op++) {
            args->hkdf_op = op;
            runHkdfOps(args);
        }
#ifdef QAT_OPENSSL_3
        if (args->hkdf_op != EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND)
            runTls13KdfOps(args);
#endif
    } else {
        for (op = 0; op <= EVP_PKEY_HKDEF_MODE_EXPAND_ONLY; op++) {
            args->hkdf_op = op;
            start_async_job(args, runHkdfOps);
        }
#ifdef QAT_OPENSSL_3
        if (args->hkdf_op != EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND)
            start_async_job(args, runTls13KdfOps);
#endif
    }
}
