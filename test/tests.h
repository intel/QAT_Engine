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

#ifndef __TESTS_H
#define __TESTS_H

#include <openssl/async.h>
#ifdef QAT_OPENSSL_PROVIDER
#include <openssl/provider.h>
#endif

enum {
    R_RSA_512, R_RSA_1024, R_RSA_2048, R_RSA_3072, R_RSA_4096, R_RSA_7680,
    R_RSA_15360, RSA_NUM
};

struct test_params_t {
    char *engine_id;
    int *count;
    int type;
    int size;
    ENGINE * e;
    int print_output;
    int verify;
    int performance;
    int enable_external_polling;
    int enable_event_driven_polling;
    int enable_async;
    const char *prov_id;
#ifdef QAT_OPENSSL_PROVIDER
    OSSL_PROVIDER *prov;
#endif
    EVP_PKEY_CTX *rsa_sign_ctx[RSA_NUM];
    EVP_PKEY_CTX *rsa_verify_ctx[RSA_NUM];
    EVP_PKEY_CTX *enc_ctx[RSA_NUM];
    EVP_PKEY_CTX *dec_ctx[RSA_NUM];
#ifdef QAT_OPENSSL_3
    int use_callback_mode;
#endif
    int enable_negative;
    int curve;
    int kdf;
    char *tls_version;
    char *digest_kdf;
    int prf_op;
    int hkdf_op;
    int ecx_op;
    int explicit_engine;
    int sign_only;
    int verify_only;
    int encrypt_only;
    int decrypt_only;
    int rsa_all;
    int async_jobs;
    ASYNC_JOB **jobs;
    ASYNC_WAIT_CTX **awcs;
    void *additional_args;
};
typedef struct test_params_t TEST_PARAMS;

struct async_additional_args_dsa {
    int local_verify;
};

struct async_additional_args_rsa {
    int sign_only;
    int verify_only;
    int encrypt_only;
    int decrypt_only;
    int rsa_all;
    int padding;
};

struct async_additional_args_kdf {
    int operation;
};

#ifdef QAT_OPENSSL_3
struct async_args_callback {
    int job_ready;
    int i;
};
#endif

ENGINE * tests_initialise_engine(char *engine_id, int enable_external_polling,
                                 int enable_event_driven_polling,
                                 int enable_async, int zero_copy,
                                 int sw_fallback);
void tests_cleanup_engine(ENGINE *e, char *engine_id, int enable_async,
                          int enable_external_polling,
                          int enable_event_driven_polling,
                          int sw_fallback);

#ifdef QAT_OPENSSL_PROVIDER
OSSL_PROVIDER *tests_initialise_provider(const char *prov_id);
void tests_cleanup_provider(OSSL_PROVIDER *prov);
#endif

void tests_hexdump(const char *title, const unsigned char *s,int l);
void tests_run(TEST_PARAMS *args, int id);
void tests_run_rsa(TEST_PARAMS *args);
void tests_run_dsa(TEST_PARAMS *args);
void tests_run_dh(TEST_PARAMS *args);
void tests_run_aes_cbc_hmac_sha(TEST_PARAMS *args);
void tests_run_ecdh(TEST_PARAMS *args);
void tests_run_ecdsa(TEST_PARAMS *args);
void tests_run_prf(TEST_PARAMS *args);
void tests_run_hkdf(TEST_PARAMS *args);
void tests_run_ecx(TEST_PARAMS *args);
void tests_run_aes128_gcm(TEST_PARAMS *args);
void tests_run_aes256_gcm(TEST_PARAMS *args);
void tests_run_sha3(TEST_PARAMS *args);
void tests_run_sm3(TEST_PARAMS *args);
void tests_run_chacha20_poly1305(TEST_PARAMS *args);
void tests_run_sm4_cbc(TEST_PARAMS *args);
void tests_run_sm4_gcm(TEST_PARAMS *args);

char *ecdh_curve_name(int type);
char *test_name(int test);

int start_async_job(TEST_PARAMS *args, int (*func)(void *));

enum test_algorithms {
    TEST_RSA = 1,
    TEST_ECDH,
    TEST_ECDSA,
    TEST_ECX,
    TEST_DSA,
    TEST_DH,
    TEST_AES128_CBC_HMAC_SHA1,
    TEST_AES256_CBC_HMAC_SHA1,
    TEST_AES128_CBC_HMAC_SHA256,
    TEST_AES256_CBC_HMAC_SHA256,
    TEST_PRF,
    TEST_HKDF,
    TEST_AES128_GCM,
    TEST_AES256_GCM,
    TEST_SHA3_224,
    TEST_SHA3_256,
    TEST_SHA3_384,
    TEST_SHA3_512,
    TEST_CHACHA20_POLY1305,
    TEST_SM2,
    TEST_SM3,
    TEST_SM4_CBC,
    TEST_SM4_GCM,
    TEST_TYPE_MAX,
};

enum curve_name {
    P_CURVE_192 = 1,
    P_CURVE_224,
    P_CURVE_256,
    P_CURVE_384,
    P_CURVE_521,
    K_CURVE_163,
    K_CURVE_233,
    K_CURVE_283,
    K_CURVE_409,
    K_CURVE_571,
    B_CURVE_163,
    B_CURVE_233,
    B_CURVE_283,
    B_CURVE_409,
    B_CURVE_571,
    P_CURVE_SM2,
    CURVE_TYPE_MAX
};

#define SSL_MAX_DIGEST 6

enum ssl_version {
    SSLv3 = 1,
    TLSv1,
    TLSv1_1,
    TLSv1_2
};

#endif
