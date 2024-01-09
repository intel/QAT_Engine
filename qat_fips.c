/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023-2024 Intel Corporation.
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
 * @file qat_fips.c
 *
 * This file provides an implementation to perform qat fips test
 *
 *****************************************************************************/

#include "qat_fips.h"
#define ENABLE_FIPS 1
#define ASYNC_JOBS 8
#define BUFFERSIZE 8192
#define SM_KEY 0x00102F

#ifdef ENABLE_QAT_FIPS
char *prov_id = "qatprovider";
static OSSL_PROVIDER *provider = NULL;
OSSL_LIB_CTX *provctx = NULL;
OSSL_SELF_TEST *st = NULL;
OSSL_CALLBACK *cb = self_test_events;
void *cbarg;
static int enable_ondemand = 0;
static int enable_async = 0;
static int async_jobs = 1;
static int sign_only = 0;
static int verify_only = 0;
static int encrypt_only = 0;
static int decrypt_only = 0;
int integrity_status = 1;

void *smem_ptr;
int smem_id;

static char *self_test_corrupt_desc = NULL;
static char *self_test_corrupt_type = NULL;

QAT_SELF_TEST_RESULT *qat_signature_result;
QAT_SELF_TEST_RESULT *qat_kas_result;
QAT_SELF_TEST_RESULT *qat_cipher_result;
QAT_SELF_TEST_RESULT *qat_digest_result;
QAT_SELF_TEST_RESULT *qat_kdf_result;

QAT_SELF_TEST_RESULT *qat_async_signature_result;
QAT_SELF_TEST_RESULT *qat_async_kas_result;
QAT_SELF_TEST_RESULT *qat_async_cipher_result;
QAT_SELF_TEST_RESULT *qat_async_digest_result;
QAT_SELF_TEST_RESULT *qat_async_kdf_result;

void fips_result(void)
{
    int i;
# ifdef QAT_DEBUG
    INFO("\nQAT Provider FIPS Self Test Application");
    if (enable_ondemand)
        INFO("\n=================== On-demand self tests result ===========\n");
    INFO("\nOperation type:       %s\n\n", "Synchronous");
# endif
    for (i = 0; i < (int)OSSL_NELEM(st_kat_sign_tests); ++i) {
        /* To skip self test when particular algorithm support is disabled */
        if (qat_hw_offload) {
            if ((qat_hw_dsa_offload == 0
                 && !strcmp(st_kat_sign_tests[i].desc, "DSA"))
                || (qat_hw_rsa_offload == 0
                    && !strcmp(st_kat_sign_tests[i].desc, "RSA"))
                || (qat_hw_ecdsa_offload == 0
                    && !strcmp(st_kat_sign_tests[i].desc, "ECDSAP256"))
                || (qat_hw_ecdsa_offload == 0
                    && !strcmp(st_kat_sign_tests[i].desc, "ECDSAP384")))
                continue;
        } else {
            if ((qat_hw_dsa_offload == 0
                 && !strcmp(st_kat_sign_tests[i].desc, "DSA"))
                || (qat_sw_rsa_offload == 0
                    && !strcmp(st_kat_sign_tests[i].desc, "RSA"))
                || (qat_sw_ecdsa_offload == 0
                    && !strcmp(st_kat_sign_tests[i].desc, "ECDSAP256"))
                || (qat_sw_ecdsa_offload == 0
                    && !strcmp(st_kat_sign_tests[i].desc, "ECDSAP384")))
                continue;
        }
# ifdef QAT_DEBUG
        INFO("\t%s   : (%s)  :  %s\n", qat_signature_result->desc[i],
             qat_signature_result->type[i],
             qat_signature_result->result[i] ? "PASS" : "FAIL");
# endif
        if (!qat_signature_result->result[i])
            integrity_status = 0;
    }

    for (i = 0; i < (int)OSSL_NELEM(st_kat_kas_tests); ++i) {
        /* To skip self test when particular algorithm support is disabled */
        if (qat_hw_offload) {
            if ((qat_hw_dh_offload == 0
                 && !strcmp(st_kat_kas_tests[i].desc, "DH"))
                || (qat_hw_ecdh_offload == 0
                    && !strcmp(st_kat_kas_tests[i].desc, "ECDHP256"))
                || (qat_hw_ecdh_offload == 0
                    && !strcmp(st_kat_kas_tests[i].desc, "ECDHP384"))
                || (qat_hw_ecx_offload == 0
                    && !strcmp(st_kat_kas_tests[i].desc, "ECX25519"))
                || (qat_hw_ecx_448_offload == 0
                    && !strcmp(st_kat_kas_tests[i].desc, "ECX448")))
                continue;
        } else {
            if ((qat_hw_dh_offload == 0
                 && !strcmp(st_kat_kas_tests[i].desc, "DH"))
                || (qat_sw_ecdh_offload == 0
                    && !strcmp(st_kat_kas_tests[i].desc, "ECDHP256"))
                || (qat_sw_ecdh_offload == 0
                    && !strcmp(st_kat_kas_tests[i].desc, "ECDHP384"))
                || (qat_sw_ecx_offload == 0
                    && !strcmp(st_kat_kas_tests[i].desc, "ECX25519"))
                || (qat_hw_ecx_448_offload == 0
                    && !strcmp(st_kat_kas_tests[i].desc, "ECX448")))
                continue;
        }
# ifdef QAT_DEBUG
        INFO("\t%s   : (%s)  :  %s\n", qat_kas_result->desc[i],
             qat_kas_result->type[i],
             qat_kas_result->result[i] ? "PASS" : "FAIL");
# endif
        if (!qat_kas_result->result[i])
            integrity_status = 0;
    }

    for (i = 0; i < (int)OSSL_NELEM(st_kat_cipher_tests); ++i) {
        /* To skip self test when particular algorithm support is disabled */
        if (qat_hw_offload) {
            if ((qat_hw_gcm_offload == 0
                 && !strcmp(st_kat_cipher_tests[i].base.desc, "AES_GCM")))
                continue;
        } else {
            if ((qat_sw_gcm_offload == 0
                 && !strcmp(st_kat_cipher_tests[i].base.desc, "AES_GCM")))
                continue;
        }
# ifdef QAT_DEBUG
        INFO("\t%s   : (%s)  :  %s\n", qat_cipher_result->desc[i],
             qat_cipher_result->type[i],
             qat_cipher_result->result[i] ? "PASS" : "FAIL");
# endif
        if (!qat_cipher_result->result[i])
            integrity_status = 0;
    }

    for (i = 0; i < (int)OSSL_NELEM(st_kat_kdf_tests); ++i) {
        if ((qat_hw_hkdf_offload == 0
             && !strcmp(st_kat_kdf_tests[i].desc, "TLS13_KDF_EXTRACT_256"))
            || (qat_hw_hkdf_offload == 0
                && !strcmp(st_kat_kdf_tests[i].desc, "TLS13_KDF_EXPAND_256"))
            || (qat_hw_hkdf_offload == 0
                && !strcmp(st_kat_kdf_tests[i].desc, "TLS13_KDF_EXTRACT_384"))
            || (qat_hw_hkdf_offload == 0
                && !strcmp(st_kat_kdf_tests[i].desc, "TLS13_KDF_EXPAND_384"))
            || (qat_hw_prf_offload == 0
                && !strcmp(st_kat_kdf_tests[i].desc, "TLS12_PRF_256"))
            || (qat_hw_prf_offload == 0
                && !strcmp(st_kat_kdf_tests[i].desc, "TLS12_PRF_384")))
            continue;

# ifdef QAT_DEBUG
        INFO("\t%s   : (%s)  :  %s\n", qat_kdf_result->desc[i],
             qat_kdf_result->type[i],
             qat_kdf_result->result[i] ? "PASS" : "FAIL");
# endif
        if (!qat_kdf_result->result[i])
            integrity_status = 0;
    }

    for (i = 0; i < (int)OSSL_NELEM(st_kat_digest_tests); ++i) {
        if (qat_hw_sha_offload == 0
            && !strcmp(st_kat_digest_tests[i].desc, "SHA3"))
            continue;
        if (qat_sw_sha_offload == 0
            && !strcmp(st_kat_digest_tests[i].desc, "SHA256"))
            continue;
        if (qat_sw_sha_offload == 0
            && !strcmp(st_kat_digest_tests[i].desc, "SHA512"))
            continue;
# ifdef QAT_DEBUG
        INFO("\t%s   : (%s)  :  %s\n", qat_digest_result->desc[i],
             qat_digest_result->type[i],
             qat_digest_result->result[i] ? "PASS" : "FAIL");
# endif
        if (!qat_digest_result->result[i])
            integrity_status = 0;
    }

    if (enable_async) {
# ifdef QAT_DEBUG
        INFO("\nOperation type:       %s\n", "Asynchronous");
        INFO("Number of jobs:       %d\n\n", async_jobs);
# endif
        for (i = 0; i < (int)OSSL_NELEM(st_kat_sign_tests); ++i) {
            /* To skip self test when particular algorithm support is disabled */
            if (qat_hw_offload) {
                if ((qat_hw_dsa_offload == 0
                     && !strcmp(st_kat_sign_tests[i].desc, "DSA"))
                    || (qat_hw_rsa_offload == 0
                        && !strcmp(st_kat_sign_tests[i].desc, "RSA"))
                    || (qat_hw_ecdsa_offload == 0
                        && !strcmp(st_kat_sign_tests[i].desc, "ECDSAP256"))
                    || (qat_hw_ecdsa_offload == 0
                        && !strcmp(st_kat_sign_tests[i].desc, "ECDSAP384")))
                    continue;
            } else {
                if ((qat_hw_dsa_offload == 0
                     && !strcmp(st_kat_sign_tests[i].desc, "DSA"))
                    || (qat_sw_rsa_offload == 0
                        && !strcmp(st_kat_sign_tests[i].desc, "RSA"))
                    || (qat_sw_ecdsa_offload == 0
                        && !strcmp(st_kat_sign_tests[i].desc, "ECDSAP256"))
                    || (qat_sw_ecdsa_offload == 0
                        && !strcmp(st_kat_sign_tests[i].desc, "ECDSAP384")))
                    continue;
            }
# ifdef QAT_DEBUG
            INFO("\t%s   : (%s)  :  %s\n", qat_async_signature_result->desc[i],
                 qat_async_signature_result->type[i],
                 qat_async_signature_result->result[i] ? "PASS" : "FAIL");
# endif
            if (!qat_async_signature_result->result[i])
                integrity_status = 0;
        }

        for (i = 0; i < (int)OSSL_NELEM(st_kat_kas_tests); ++i) {
            /* To skip self test when particular algorithm support is disabled */
            if (qat_hw_offload) {
                if ((qat_hw_dh_offload == 0
                     && !strcmp(st_kat_kas_tests[i].desc, "DH"))
                    || (qat_hw_ecdh_offload == 0
                        && !strcmp(st_kat_kas_tests[i].desc, "ECDHP256"))
                    || (qat_hw_ecdh_offload == 0
                        && !strcmp(st_kat_kas_tests[i].desc, "ECDHP384"))
                    || (qat_hw_ecx_offload == 0
                        && !strcmp(st_kat_kas_tests[i].desc, "ECX25519"))
                    || (qat_hw_ecx_448_offload == 0
                        && !strcmp(st_kat_kas_tests[i].desc, "ECX448")))
                    continue;
            } else {
                if ((qat_hw_dh_offload == 0
                     && !strcmp(st_kat_kas_tests[i].desc, "DH"))
                    || (qat_sw_ecdh_offload == 0
                        && !strcmp(st_kat_kas_tests[i].desc, "ECDHP256"))
                    || (qat_sw_ecdh_offload == 0
                        && !strcmp(st_kat_kas_tests[i].desc, "ECDHP384"))
                    || (qat_sw_ecx_offload == 0
                        && !strcmp(st_kat_kas_tests[i].desc, "ECX25519"))
                    || (qat_hw_ecx_448_offload == 0
                        && !strcmp(st_kat_kas_tests[i].desc, "ECX448")))
                    continue;
            }
# ifdef QAT_DEBUG
            INFO("\t%s   : (%s)  :  %s\n", qat_async_kas_result->desc[i],
                 qat_async_kas_result->type[i],
                 qat_async_kas_result->result[i] ? "PASS" : "FAIL");
# endif
            if (!qat_async_kas_result->result[i])
                integrity_status = 0;
        }

        for (i = 0; i < (int)OSSL_NELEM(st_kat_cipher_tests); ++i) {
            /* To skip self test when particular algorithm support is disabled */
            if (qat_hw_offload) {
                if ((qat_hw_gcm_offload == 0
                     && !strcmp(st_kat_cipher_tests[i].base.desc, "AES_GCM")))
                    continue;
            } else {
                if ((qat_sw_gcm_offload == 0
                     && !strcmp(st_kat_cipher_tests[i].base.desc, "AES_GCM")))
                    continue;
            }
# ifdef QAT_DEBUG
            INFO("\t%s   : (%s)  :  %s\n", qat_async_cipher_result->desc[i],
                 qat_async_cipher_result->type[i],
                 qat_async_cipher_result->result[i] ? "PASS" : "FAIL");
# endif
            if (!qat_async_cipher_result->result[i])
                integrity_status = 0;
        }

        for (i = 0; i < (int)OSSL_NELEM(st_kat_kdf_tests); ++i) {
            if ((qat_hw_hkdf_offload == 0
                 && !strcmp(st_kat_kdf_tests[i].desc, "TLS13_KDF_EXTRACT_256"))
                || (qat_hw_hkdf_offload == 0
                    && !strcmp(st_kat_kdf_tests[i].desc,
                               "TLS13_KDF_EXPAND_256"))
                || (qat_hw_hkdf_offload == 0
                    && !strcmp(st_kat_kdf_tests[i].desc,
                               "TLS13_KDF_EXTRACT_384"))
                || (qat_hw_hkdf_offload == 0
                    && !strcmp(st_kat_kdf_tests[i].desc,
                               "TLS13_KDF_EXPAND_384"))
                || (qat_hw_prf_offload == 0
                    && !strcmp(st_kat_kdf_tests[i].desc, "TLS12_PRF_256"))
                || (qat_hw_prf_offload == 0
                    && !strcmp(st_kat_kdf_tests[i].desc, "TLS12_PRF_384")))
                continue;

# ifdef QAT_DEBUG
            INFO("\t%s   : (%s)  :  %s\n", qat_async_kdf_result->desc[i],
                 qat_async_kdf_result->type[i],
                 qat_async_kdf_result->result[i] ? "PASS" : "FAIL");
# endif
            if (!qat_async_kdf_result->result[i])
                integrity_status = 0;
        }

        for (i = 0; i < (int)OSSL_NELEM(st_kat_digest_tests); ++i) {
            if (qat_hw_sha_offload == 0
                && !strcmp(st_kat_digest_tests[i].desc, "SHA3"))
                continue;
            if (qat_sw_sha_offload == 0
                && !strcmp(st_kat_digest_tests[i].desc, "SHA256"))
                continue;
            if (qat_sw_sha_offload == 0
                && !strcmp(st_kat_digest_tests[i].desc, "SHA512"))
                continue;
# ifdef QAT_DEBUG
            INFO("\t%s   : (%s)  :  %s\n", qat_async_digest_result->desc[i],
                 qat_async_digest_result->type[i],
                 qat_async_digest_result->result[i] ? "PASS" : "FAIL");
# endif
            if (!qat_async_digest_result->result[i])
                integrity_status = 0;
        }
    }
# ifdef QAT_DEBUG
    if (!enable_ondemand)
        INFO("\n===================QAT_SELF_TEST RESULT=====================\n");
    else
        INFO("\n=================== On-demand self tests completed===========\n");
# endif

    free(qat_signature_result);
    free(qat_kas_result);
    free(qat_cipher_result);
    free(qat_digest_result);
    free(qat_kdf_result);
    if (enable_async) {
        free(qat_async_signature_result);
        free(qat_async_kas_result);
        free(qat_async_cipher_result);
        free(qat_async_digest_result);
        free(qat_async_kdf_result);
    }
    enable_async = 0;
    async_jobs = 1;
    ERR_clear_error();
}

void removeChar(char *s, char c)
{
    int j, n = strlen(s);
    for (int i = j = 0; i < n; i++) {
        if (s[i] != c)
            s[j++] = s[i];
    }

    s[j] = '\0';
}

int readFileToHexString(char **hex_string, const char *filepath, int *len)
{
    FILE *fp = fopen(filepath, "r");
    if (fp == NULL) {
        WARN("Input file:%s don't exist \n", filepath);
        return 1;
    }
    if (fseek(fp, 0L, SEEK_END) == 0) {
        /* Set position at end of file */
        long hex_string_size = ftell(fp);
        if (hex_string_size == -1) {
            WARN("Input file corrupted\n");
            return 2;
        }
        (*hex_string) = (char *)malloc(sizeof(char) * (hex_string_size + 1));

        /* Set position at befining of file */
        fseek(fp, 0L, SEEK_SET);

        size_t newLen =
            fread((*hex_string), sizeof(unsigned char), hex_string_size, fp);
        if (ferror(fp) != 0) {
            WARN("Error while reading file\n");
            return 3;
        }
        (*hex_string)[newLen] = '\0'; /* to make sure it's NULL-terminated */
        *len = hex_string_size;
    }
    fclose(fp);
    return 0;
}

int get_pub_key_from_file(char *in_name, unsigned char *out)
{
    FILE *in_file = NULL, *fp = NULL;
    char word[500];
    char pub_fname[16] = "pub.txt";
    int flag = 0;
    int i = 0, msg_len = 0, result = 0, size;;
    char *msg;
    int sys_ret = 0;

    in_file = fopen(in_name, "r");

    if (in_file == NULL)
        WARN("Can't open %s for reading.\n", in_name);
    else {
        while (fscanf(in_file, "%s", word) != EOF) {
            if (!strcmp(word, "pub:")) {
                flag = 1;
                fp = fopen(pub_fname, "w+");
            }
            if (!strcmp(word, "ASN1")) {
                flag = 0;
                if (fp)
                    fclose(fp);
            }
            if (flag && strcmp(word, "pub:")) {
                removeChar(word, ':');
                fprintf(fp, "%s", word);
            }

        }
        fclose(in_file);
    }

    result = readFileToHexString(&msg, pub_fname, &msg_len);
    sys_ret = remove("pub.txt");
    if (sys_ret != 0)
        WARN("System process failure\n");

    if (result != 0)
        return result;

    size = (msg_len + 1) / 2;

    for (i = 0; i < size; i++) {
        sscanf(msg, "%02hhx", &out[i]);
        msg = msg + 2;
    }

    return 1;
}

int self_test_events(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *p = NULL;
    const char *phase = NULL, *type = NULL, *desc = NULL;
    int ret = 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_PHASE);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
        goto err;
    phase = (const char *)p->data;

    p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_DESC);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
        goto err;
    desc = (const char *)p->data;

    p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_TYPE);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
        goto err;
    type = (const char *)p->data;

    if (strcmp(phase, OSSL_SELF_TEST_PHASE_START) == 0)
        DEBUG("Self test start phase %s : (%s)\n", desc, type);
    else if (strcmp(phase, OSSL_SELF_TEST_PHASE_PASS) == 0
             || strcmp(phase, OSSL_SELF_TEST_PHASE_FAIL) == 0)
        DEBUG("Self test phase : %s \n", phase);

    /*
     * The self test code will internally corrupt the KAT test result if an
     * error is returned during the corrupt phase.
     */
    if (strcmp(phase, OSSL_SELF_TEST_PHASE_CORRUPT) == 0
        && (self_test_corrupt_desc != NULL || self_test_corrupt_type != NULL)) {
        if (self_test_corrupt_desc != NULL
            && strcmp(self_test_corrupt_desc, desc) != 0)
            goto end;
        if (self_test_corrupt_type != NULL
            && strcmp(self_test_corrupt_type, type) != 0)
            goto end;
        WARN("Error in oncorrupt phase : %s \n", phase);
        goto err;
    }
 end:
    ret = 1;
 err:
    return ret;
}

int FMT_istext(int format)
{
    return (format & B_FORMAT_TEXT) == B_FORMAT_TEXT;
}

BIO *dup_bio_in(int format)
{
    return BIO_new_fp(stdin,
                      BIO_NOCLOSE | (FMT_istext(format) ? BIO_FP_TEXT : 0));
}

BIO *dup_bio_out(int format)
{
    BIO *b = BIO_new_fp(stdout,
                        BIO_NOCLOSE | (FMT_istext(format) ? BIO_FP_TEXT : 0));
    void *prefix = NULL;

    if (FMT_istext(format)
        && (prefix = getenv("HARNESS_OSSL_PREFIX")) != NULL) {
        b = BIO_push(BIO_new(BIO_f_prefix()), b);
        BIO_set_prefix(b, prefix);
    }

    return b;
}

static const char *modestr(char mode, int format)
{
    OPENSSL_assert(mode == 'a' || mode == 'r' || mode == 'w');

    switch (mode) {
    case 'a':
        return FMT_istext(format) ? "a" : "ab";
    case 'r':
        return FMT_istext(format) ? "r" : "rb";
    case 'w':
        return FMT_istext(format) ? "w" : "wb";
    }
    /* The assert above should make sure we never reach this point */
    return NULL;
}

static BIO *bio_open_default_(const char *filename, char mode, int format,
                              int quiet)
{
    BIO *ret;

    if (filename == NULL || strcmp(filename, "-") == 0) {
        ret = mode == 'r' ? dup_bio_in(format) : dup_bio_out(format);
        if (quiet) {
            ERR_clear_error();
            return ret;
        }
        if (ret != NULL)
            return ret;
    } else {
        ret = BIO_new_file(filename, modestr(mode, format));
        if (quiet) {
            return ret;
        }
        if (ret != NULL)
            return ret;
    }
    return NULL;
}

BIO *bio_open_default(const char *filename, char mode, int format)
{
    return bio_open_default_(filename, mode, format, 0);
}

static int test_callback(void *arg)
{
    struct async_args_callback *args = (struct async_args_callback *)arg;

    DEBUG("test_callback start for async_job %d - job_ready = %d\n",
          args->i, args->job_ready);

    args->job_ready = 1;

    DEBUG("test_callback finish for async_job %d - job_ready = %d\n",
          args->i, args->job_ready);
    return 1;
}

int start_async_job(TEST_PARAMS *args, int (*func)(void *))
{
    int ret = 0;
    int jobs_inprogress = 0;
    int i = 0;
    OSSL_ASYNC_FD job_fd = 0;
    OSSL_ASYNC_FD max_fd = 0;
    int select_result = 0;
    size_t numfds;
    fd_set waitfdset;
    struct timeval select_timeout;
    FD_ZERO(&waitfdset);
    select_timeout.tv_sec = 0;
    select_timeout.tv_usec = 0;
    struct async_args_callback **ptr_async_args_callback = NULL;

    DEBUG("start_async_job() - start\n");
    if (args->use_callback_mode == 1) {
        ptr_async_args_callback = (struct async_args_callback **)
            OPENSSL_zalloc(sizeof(struct async_args_callback *) *
                           args->async_jobs);
        if (ptr_async_args_callback == NULL) {
            WARN("Error allocating memory for ptr_async_args_callback.\n");
            return ret;
        }

        for (i = 0; i < args->async_jobs; i++) {
            ptr_async_args_callback[i] = (struct async_args_callback *)
                OPENSSL_zalloc(sizeof(struct async_args_callback));
            if (ptr_async_args_callback[i] == NULL) {
                WARN("Error allocating memory for ptr_async_args_callback.\n");
                return ret;
            }
        }
    }

    for (i = 0; i < args->async_jobs; i++) {
        if (args->use_callback_mode == 1) {
            ptr_async_args_callback[i]->i = i;

            if (ASYNC_WAIT_CTX_set_callback(args->awcs[i],
                                            test_callback,
                                            (void *)ptr_async_args_callback[i])
                != 1) {
                WARN("# FAIL: Error setting callback.\n");
                return ret;
            }
        }
        switch (ASYNC_start_job(&args->jobs[i], args->awcs[i], &ret, func, args,
                                sizeof(TEST_PARAMS))) {
        case ASYNC_ERR:
        case ASYNC_NO_JOBS:
            DEBUG("ASYNC_ERR \n");
            break;
        case ASYNC_PAUSE:
            ++jobs_inprogress;
            DEBUG("ASYNC_PAUSE \n");
            break;
        case ASYNC_FINISH:
            DEBUG("ASYNC_FINISH \n");
            break;
        }
    }

    while (jobs_inprogress > 0) {
        if (args->use_callback_mode != 1) { /* Not callback mode so use fd's */
            for (i = 0; i < args->async_jobs && jobs_inprogress > 0; i++) {
                if (args->jobs[i] == NULL)
                    continue;

                if (!ASYNC_WAIT_CTX_get_all_fds(args->awcs[i], NULL, &numfds)
                    || numfds > 1) {
                    WARN("# FAIL: Too Many FD's in Use\n");
                    break;
                }
                ASYNC_WAIT_CTX_get_all_fds(args->awcs[i], &job_fd, &numfds);
                FD_SET(job_fd, &waitfdset);
                if (job_fd > max_fd)
                    max_fd = job_fd;
            }

            if (max_fd >= (OSSL_ASYNC_FD)FD_SETSIZE) {
                WARN("# FAIL: Too many FD's in use in the system already\n");
                break;
            }

            select_result = select(max_fd + 1, &waitfdset, NULL, NULL,
                                   &select_timeout);

            if (select_result == -1 && errno == EINTR)
                continue;

            if (select_result == -1) {
                WARN("# FAIL: Select Failure \n");
                break;
            }
        }
        for (i = 0; i < args->async_jobs; i++) {
            if (args->jobs[i] == NULL)
                continue;
            if (args->use_callback_mode != 1) { /* Not callback mode so use fd's */
                if (!ASYNC_WAIT_CTX_get_all_fds(args->awcs[i], NULL, &numfds)
                    || numfds > 1) {
                    WARN("# FAIL: Too Many FD's in Use\n");
                    break;
                }
                ASYNC_WAIT_CTX_get_all_fds(args->awcs[i], &job_fd, &numfds);

                if (numfds == 1 && !FD_ISSET(job_fd, &waitfdset))
                    continue;
            } else {            /* in callback mode */
                if (ptr_async_args_callback[i]->job_ready == 0)
                    continue;
            }
            if (args->use_callback_mode == 1) {
                /* reset the jobs_ready flag */
                DEBUG("Resetting job_ready flag for async_job %d\n", i);
                ptr_async_args_callback[i]->job_ready = 0;
            }
            switch (ASYNC_start_job(&args->jobs[i], args->awcs[i], &ret, func,
                                    args, sizeof(TEST_PARAMS))) {
            case ASYNC_PAUSE:
                break;
            case ASYNC_FINISH:
                --jobs_inprogress;
                args->jobs[i] = NULL;
                break;
            case ASYNC_NO_JOBS:
            case ASYNC_ERR:
                --jobs_inprogress;
                args->jobs[i] = NULL;
                break;
            }
        }
    }                           /* while (jobs_inprogress > 0) */
    if (ptr_async_args_callback != NULL) {
        for (i = 0; i < args->async_jobs; i++) {
            if (ptr_async_args_callback[i] != NULL)
                OPENSSL_free(ptr_async_args_callback[i]);
        }
        OPENSSL_free(ptr_async_args_callback);
    }
    DEBUG("start_async_job() returning status = %d\n", ret);
    return ret;
}

void kat_tests_run(TEST_PARAMS *args)
{
    struct async_additional_args_rsa extra_args;
    args->additional_args = &extra_args;
    extra_args.sign_only = sign_only;
    extra_args.verify_only = verify_only;
    extra_args.encrypt_only = encrypt_only;
    extra_args.decrypt_only = decrypt_only;

    st = (OSSL_SELF_TEST *) calloc(1, sizeof(OSSL_SELF_TEST));
    if (st == NULL) {
        WARN("Error in OSSL_SELF_TEST memory creation\n");
    }

    st->cb = cb;
    st->cb_arg = cbarg;
    st->phase = "start";
    args->st = st;
    if (!args->ondemand) {
        if (!args->enable_async)
            QAT_SELF_TEST_kats(args);
        else
            start_async_job(args, QAT_SELF_TEST_kats);
    }

    if (args->ondemand || integrity_status == 0) {
        if (!(args->enable_async)) {
            if (!QAT_SELF_TEST_kats(args)) {
                INFO("\nQAT On-demand Synch KAT tests failure\n");
            }
        } else {
            if ((!start_async_job(args, QAT_SELF_TEST_kats))) {
                INFO("\nQAT On-demand Asynch KAT tests failure\n");
            }
        }
    }
}

void kat_self_test_init(int ondemand, int co_existence)
{
    int i;
    TEST_PARAMS args;
    args.prov_id = prov_id;
    args.enable_async = enable_async;
    args.prov = provider;
    args.async_jobs = async_jobs;
    args.cb = cb;
    args.cb_arg = cbarg;
    args.phase = "start";
    args.provctx = provctx;
    args.sign_only = sign_only;
    args.verify_only = verify_only;
    args.encrypt_only = encrypt_only;
    args.decrypt_only = decrypt_only;
    args.ondemand = ondemand;
    args.co_existence = co_existence;

    args.jobs = OPENSSL_malloc(sizeof(ASYNC_JOB *) * async_jobs);
    if (args.jobs == NULL) {
        WARN("# FAIL: Unable to allocate args.jobs\n");
        exit(EXIT_FAILURE);
    }
    args.awcs = OPENSSL_malloc(sizeof(ASYNC_WAIT_CTX *) * async_jobs);
    if (args.awcs == NULL) {
        WARN("# FAIL: Unable to allocate args.awcs\n");
        exit(EXIT_FAILURE);
    }
    memset(args.jobs, 0, sizeof(ASYNC_JOB *) * async_jobs);
    memset(args.awcs, 0, sizeof(ASYNC_WAIT_CTX *) * async_jobs);
    for (i = 0; i < async_jobs; i++) {
        args.awcs[i] = ASYNC_WAIT_CTX_new();
        if (args.awcs[i] == NULL) {
            WARN("# FAIL: Unable to allocate args.awcs[%d]\n", i);
            exit(EXIT_FAILURE);
        }
    }

    kat_tests_run(&args);

    for (i = 0; i < async_jobs; i++)
        ASYNC_WAIT_CTX_free(args.awcs[i]);

    OPENSSL_free(args.awcs);
    OPENSSL_free(args.jobs);
    free(args.st);
}

int qat_fips_self_test(void *qatctx, int ondemand, int co_ex_enabled)
{
    int i, j, sys_ret = 0;
    BIO *module_bio = NULL, *sig_bio = NULL;
    char pubkey_file[256] = "public_key.txt";
    sys_ret =
        system
        ("cp -f /usr/lib64/ossl-modules/qatprovider.so qatprovider_temp.so");
    sys_ret =
        system
        ("objcopy --dump-section .pub_key=public_key.txt qatprovider_temp.so");
    sys_ret = system("objcopy --remove-section .pub_key qatprovider_temp.so");

    EVP_MD *md = NULL;
    int nfile = 0;
    char *src_files[10] = { 0 };
    char *sig_files[10] = { 0 };
    char *dump_cmd[10] = { 0 };
    char *rmv_cmd[10] = { 0 };
# ifdef QAT_HW
    char *srmv_cmd[7] = { 0 };
# endif
    if (co_ex_enabled) {
        nfile = 10;
        src_files[0] = "/usr/lib64/build/qat_4xxx.ko";
        src_files[1] = "/usr/lib64/build/usdm_drv.ko";
        src_files[2] = "/usr/lib64/build/intel_qat.ko";
        src_files[3] = "/usr/lib64/libusdm_drv_s.so";
        src_files[4] = "/usr/lib64/libqat_s.so";
        src_files[5] = "/lib/firmware/qat_4xxx.bin";
        src_files[6] = "/lib/firmware/qat_4xxx_mmp.bin";
        src_files[7] = "/usr/lib64/libIPSec_MB.so";
        src_files[8] = "/usr/lib64/libcrypto_mb.so";
        src_files[9] = "qatprovider_temp.so";

        sig_files[0] = "qat_4xxx_signature.bin";
        sig_files[1] = "usdm_drv_signature.bin";
        sig_files[2] = "intel_qat_signature.bin";
        sig_files[3] = "usdm_signature.bin";
        sig_files[4] = "libqat_signature.bin";
        sig_files[5] = "qat_4xxx_bin_signature.bin";
        sig_files[6] = "qat_4xxx_mmp_signature.bin";
        sig_files[7] = "ipsec_mb_signature.bin";
        sig_files[8] = "libcrypto_mb_signature.bin";
        sig_files[9] = "qat_signature.bin";

        dump_cmd[0] =
            "objcopy --dump-section .qat_4xxx_sig=qat_4xxx_signature.bin qatprovider_temp.so";
        dump_cmd[1] =
            "objcopy --dump-section .usdm_drv_sig=usdm_drv_signature.bin qatprovider_temp.so";
        dump_cmd[2] =
            "objcopy --dump-section .iqat_sig=intel_qat_signature.bin qatprovider_temp.so";
        dump_cmd[3] =
            "objcopy --dump-section .usdm_sig=usdm_signature.bin qatprovider_temp.so";
        dump_cmd[4] =
            "objcopy --dump-section .libqat_sig=libqat_signature.bin qatprovider_temp.so";
        dump_cmd[5] =
            "objcopy --dump-section .qat_4xxx_bin_sig=qat_4xxx_bin_signature.bin qatprovider_temp.so";
        dump_cmd[6] =
            "objcopy --dump-section .qat_4xxx_mmp_sig=qat_4xxx_mmp_signature.bin qatprovider_temp.so";
        dump_cmd[7] =
            "objcopy --dump-section .ipsec_mb_sig=ipsec_mb_signature.bin qatprovider_temp.so";
        dump_cmd[8] =
            "objcopy --dump-section .libcrypto_mb_sig=libcrypto_mb_signature.bin qatprovider_temp.so";
        dump_cmd[9] =
            "objcopy --dump-section .qat_sig=qat_signature.bin qatprovider_temp.so";

        rmv_cmd[0] =
            "objcopy --remove-section .qat_4xxx_sig qatprovider_temp.so";
        rmv_cmd[1] =
            "objcopy --remove-section .usdm_drv_sig qatprovider_temp.so";
        rmv_cmd[2] = "objcopy --remove-section .iqat_sig qatprovider_temp.so";
        rmv_cmd[3] = "objcopy --remove-section .usdm_sig qatprovider_temp.so";
        rmv_cmd[4] = "objcopy --remove-section .libqat_sig qatprovider_temp.so";
        rmv_cmd[5] =
            "objcopy --remove-section .qat_4xxx_bin_sig qatprovider_temp.so";
        rmv_cmd[6] =
            "objcopy --remove-section .qat_4xxx_mmp_sig qatprovider_temp.so";
        rmv_cmd[7] =
            "objcopy --remove-section .ipsec_mb_sig qatprovider_temp.so";
        rmv_cmd[8] =
            "objcopy --remove-section .libcrypto_mb_sig qatprovider_temp.so";
        rmv_cmd[9] = "objcopy --remove-section .qat_sig qatprovider_temp.so";
    } else {
        if (qat_hw_offload) {
            nfile = 8;

            src_files[0] = "/usr/lib64/build/qat_4xxx.ko";
            src_files[1] = "/usr/lib64/build/usdm_drv.ko";
            src_files[2] = "/usr/lib64/build/intel_qat.ko";
            src_files[3] = "/usr/lib64/libusdm_drv_s.so";
            src_files[4] = "/usr/lib64/libqat_s.so";
            src_files[5] = "/lib/firmware/qat_4xxx.bin";
            src_files[6] = "/lib/firmware/qat_4xxx_mmp.bin";
            src_files[7] = "qatprovider_temp.so";

            sig_files[0] = "qat_4xxx_signature.bin";
            sig_files[1] = "usdm_drv_signature.bin";
            sig_files[2] = "intel_qat_signature.bin";
            sig_files[3] = "usdm_signature.bin";
            sig_files[4] = "libqat_signature.bin";
            sig_files[5] = "qat_4xxx_bin_signature.bin";
            sig_files[6] = "qat_4xxx_mmp_signature.bin";
            sig_files[7] = "qat_signature.bin";

            dump_cmd[0] =
                "objcopy --dump-section .qat_4xxx_sig=qat_4xxx_signature.bin qatprovider_temp.so";
            dump_cmd[1] =
                "objcopy --dump-section .usdm_drv_sig=usdm_drv_signature.bin qatprovider_temp.so";
            dump_cmd[2] =
                "objcopy --dump-section .iqat_sig=intel_qat_signature.bin qatprovider_temp.so";
            dump_cmd[3] =
                "objcopy --dump-section .usdm_sig=usdm_signature.bin qatprovider_temp.so";
            dump_cmd[4] =
                "objcopy --dump-section .libqat_sig=libqat_signature.bin qatprovider_temp.so";
            dump_cmd[5] =
                "objcopy --dump-section .qat_4xxx_bin_sig=qat_4xxx_bin_signature.bin qatprovider_temp.so";
            dump_cmd[6] =
                "objcopy --dump-section .qat_4xxx_mmp_sig=qat_4xxx_mmp_signature.bin qatprovider_temp.so";
            dump_cmd[7] =
                "objcopy --dump-section .qat_sig=qat_signature.bin qatprovider_temp.so";

            rmv_cmd[0] =
                "objcopy --remove-section .qat_4xxx_sig qatprovider_temp.so";
            rmv_cmd[1] =
                "objcopy --remove-section .usdm_drv_sig qatprovider_temp.so";
            rmv_cmd[2] =
                "objcopy --remove-section .iqat_sig qatprovider_temp.so";
            rmv_cmd[3] =
                "objcopy --remove-section .usdm_sig qatprovider_temp.so";
            rmv_cmd[4] =
                "objcopy --remove-section .libqat_sig qatprovider_temp.so";
            rmv_cmd[5] =
                "objcopy --remove-section .qat_4xxx_bin_sig qatprovider_temp.so";
            rmv_cmd[6] =
                "objcopy --remove-section .qat_4xxx_mmp_sig qatprovider_temp.so";
            rmv_cmd[7] =
                "objcopy --remove-section .qat_sig qatprovider_temp.so";
        } else {
            nfile = 3;

            src_files[0] = "/usr/lib64/libIPSec_MB.so";
            src_files[1] = "/usr/lib64/libcrypto_mb.so";
            src_files[2] = "qatprovider_temp.so";

            sig_files[0] = "ipsec_mb_signature.bin";
            sig_files[1] = "libcrypto_mb_signature.bin";
            sig_files[2] = "qat_signature.bin";

            dump_cmd[0] =
                "objcopy --dump-section .ipsec_mb_sig=ipsec_mb_signature.bin qatprovider_temp.so";
            dump_cmd[1] =
                "objcopy --dump-section .libcrypto_mb_sig=libcrypto_mb_signature.bin qatprovider_temp.so";
            dump_cmd[2] =
                "objcopy --dump-section .qat_sig=qat_signature.bin qatprovider_temp.so";

            rmv_cmd[0] =
                "objcopy --remove-section .ipsec_mb_sig qatprovider_temp.so";
            rmv_cmd[1] =
                "objcopy --remove-section .libcrypto_mb_sig qatprovider_temp.so";
            rmv_cmd[2] =
                "objcopy --remove-section .qat_sig qatprovider_temp.so";
        }
    }
# ifdef QAT_HW
    srmv_cmd[0] = "objcopy --remove-section .qat_4xxx_sig qatprovider_temp.so";
    srmv_cmd[1] = "objcopy --remove-section .usdm_drv_sig qatprovider_temp.so";
    srmv_cmd[2] = "objcopy --remove-section .iqat_sig qatprovider_temp.so";
    srmv_cmd[3] = "objcopy --remove-section .usdm_sig qatprovider_temp.so";
    srmv_cmd[4] = "objcopy --remove-section .libqat_sig qatprovider_temp.so";
    srmv_cmd[5] =
        "objcopy --remove-section .qat_4xxx_bin_sig qatprovider_temp.so";
    srmv_cmd[6] =
        "objcopy --remove-section .qat_4xxx_mmp_sig qatprovider_temp.so";
# endif
    static unsigned char pubkey[INTEGRITY_PUB_KEYLENGTH];
    unsigned char *read_buffer = NULL;
    enable_ondemand = ondemand;
    EVP_MD_CTX *ctx = NULL;
    unsigned int bufflen = 0;
    int siglen = INTEGRITY_SIGLEN;
    unsigned char *sigbuf = NULL, *buf = NULL;
    OSSL_PARAM *params = NULL, *params_sig = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    EVP_PKEY_CTX *kctx = NULL, *sctx = NULL;
    EVP_PKEY *pkey = NULL;
    BN_CTX *bnctx = NULL;
    get_pub_key_from_file(pubkey_file, pubkey);
    DUMPL("Pubkey", pubkey, INTEGRITY_PUB_KEYLENGTH);
    ST_KAT_SIGN *t = NULL;
    static const ST_KAT_PARAM ecdsa_prime_key_1[] = {
        ST_KAT_PARAM_UTF8STRING(OSSL_PKEY_PARAM_GROUP_NAME, ecdh_curve_name),
        ST_KAT_PARAM_OCTET(OSSL_PKEY_PARAM_PUB_KEY, pubkey),
        ST_KAT_PARAM_END()
    };
    static ST_KAT_SIGN st_kat_sign_tests_1[] = {
        {
         QAT_SELF_TEST_DESC_SIGN_ECDSAP256,
         "EC",
         "SHA3-256",
         ecdsa_prime_key_1,
         },
        {
         QAT_SELF_TEST_DESC_SIGN_ECDSAP256,
         "EC",
         "SHA-256",
         ecdsa_prime_key_1,
         },
    };

    if (co_ex_enabled) {
        t = &st_kat_sign_tests_1[1];
    } else {
        if (qat_hw_offload)
            t = &st_kat_sign_tests_1[0];
        else
            t = &st_kat_sign_tests_1[1];
    }

    if (co_ex_enabled) {
        /* To make symmetric algorithms run in HW Platform
         * when co-existence is enabled */
# ifdef ENABLE_QAT_HW_GCM
        qat_hw_gcm_offload = 1;
        qat_sw_gcm_offload = 0;
# endif
# ifdef ENABLE_QAT_SW_SHA2
        qat_sw_sha_offload = 0;
# endif

        for (i = 0; i < 2; i++) {
            if (i == 1) {
                if (ASYNC_get_current_job() != NULL)
                    break;
                enable_async = ENABLE_FIPS;
                async_jobs = ASYNC_JOBS;
            }
            kat_self_test_init(ondemand, co_ex_enabled);
        }

        DEBUG("\n=================== QAT HW self tests result ===========\n");
        fips_result();

        /* Reset the values to make symmetric algorithms run in SW Platform
         * when co-existence is enabled */
# ifdef ENABLE_QAT_SW_GCM
        qat_hw_gcm_offload = 0;
        qat_sw_gcm_offload = 1;
# endif
# ifdef ENABLE_QAT_SW_SHA2
        qat_sw_sha_offload = 1;
# endif
        /* To make asymmetric algorithms run in SW Platform
         * when co-existence is enabled */
# ifdef ENABLE_QAT_SW_RSA
        qat_hw_rsa_offload = 0;
        qat_sw_rsa_offload = 1;
# endif
# ifdef ENABLE_QAT_SW_ECDSA
        qat_hw_ecdsa_offload = 0;
        qat_sw_ecdsa_offload = 1;
# endif
# ifdef ENABLE_QAT_SW_ECDH
        qat_hw_ecdh_offload = 0;
        qat_sw_ecdh_offload = 1;
# endif
# ifdef ENABLE_QAT_SW_ECX
        qat_hw_ecx_offload = 0;
        qat_sw_ecx_offload = 1;
# endif
        qat_hw_dsa_offload = 0;
        qat_hw_dh_offload = 0;
        qat_hw_ecx_448_offload = 0;
        qat_hw_hkdf_offload = 0;
        qat_hw_prf_offload = 0;
# ifdef ENABLE_QAT_SW_SHA2
        qat_hw_sha_offload = 0;
        qat_sw_sha_offload = 1;
# endif
        qat_hw_offload = 0;

        for (i = 0; i < 2; i++) {
            if (i == 1) {
                if (ASYNC_get_current_job() != NULL)
                    break;
                enable_async = ENABLE_FIPS;
                async_jobs = ASYNC_JOBS;
            }
            kat_self_test_init(ondemand, co_ex_enabled);
        }

        DEBUG("\n=================== QAT SW self tests result ===========\n");
        fips_result();

        /* Reset the values to make asymmetric algorithms run in HW Platform
         * when co-existence is enabled */
# ifdef ENABLE_QAT_HW_RSA
        qat_hw_rsa_offload = 1;
        qat_sw_rsa_offload = 0;
# endif
# ifdef ENABLE_QAT_HW_ECDSA
        qat_hw_ecdsa_offload = 1;
        qat_sw_ecdsa_offload = 0;
# endif
# ifdef ENABLE_QAT_HW_ECDH
        qat_hw_ecdh_offload = 1;
        qat_sw_ecdh_offload = 0;
# endif
# ifdef ENABLE_QAT_HW_ECX
        qat_hw_ecx_offload = 1;
        qat_sw_ecx_offload = 0;
# endif
# ifdef ENABLE_QAT_HW_DSA
        qat_hw_dsa_offload = 1;
# endif
# ifdef ENABLE_QAT_HW_DH
        qat_hw_dh_offload = 1;
# endif
# ifdef ENABLE_QAT_HW_ECX
        qat_hw_ecx_448_offload = 1;
# endif
# ifdef ENABLE_QAT_HW_HKDF
        qat_hw_hkdf_offload = 1;
# endif
# ifdef ENABLE_QAT_HW_PRF
        qat_hw_prf_offload = 1;
# endif
# ifdef ENABLE_QAT_HW_SHA3
        qat_hw_sha_offload = 1;
        qat_sw_sha_offload = 0;
# endif
# ifdef QAT_HW
        qat_hw_offload = 1;
# endif
    } else {
        for (i = 0; i < 2; i++) {
            if (i == 1) {
                if (ASYNC_get_current_job() != NULL)
                    break;
                enable_async = ENABLE_FIPS;
                async_jobs = ASYNC_JOBS;
            }
            kat_self_test_init(ondemand, co_ex_enabled);
        }
        fips_result();
    }

    if (!integrity_status) {
        INFO("QAT FIPS self-tests(KAT) result: FAIL.\n");
        sys_ret = remove("qatprovider_temp.so");
        sys_ret = remove("public_key.txt");
        return 0;
    }
# ifdef QAT_HW
    if (qat_hw_offload == 0) {
        for (i = 0; i < 7; i++)
            sys_ret = system(srmv_cmd[i]);
    }
# endif

    for (j = 0; j < nfile; j++) {
        ctx = EVP_MD_CTX_new();
        if (co_ex_enabled) {
            md = EVP_MD_fetch(NULL, "SHA-256", NULL);
        } else {
            if (qat_hw_offload)
                md = EVP_MD_fetch(NULL, "SHA3-256", NULL);
            else
                md = EVP_MD_fetch(NULL, "SHA-256", NULL);
        }

        sys_ret = system(dump_cmd[j]);
        sys_ret = system(rmv_cmd[j]);

        DEBUG("QAT Provider Path %s len %ld\n", src_files[j],
              strlen(src_files[j]));

        module_bio = bio_open_default(src_files[j], 'r', FORMAT_BINARY);
        if (module_bio == NULL)
            WARN("Error @module_bio creation\n");

        sig_bio = BIO_new_file(sig_files[j], "rb");
        if (sig_bio == NULL)
            WARN("Error @sig_bio creation\n");
        sigbuf = OPENSSL_zalloc(siglen);
        if (sigbuf == NULL)
            WARN("Error memory allocation for sigbuf");

        siglen = BIO_read(sig_bio, sigbuf, siglen);
        BIO_free(sig_bio);

        buf = OPENSSL_zalloc(BUFFERSIZE);

        EVP_DigestInit_ex(ctx, md, NULL);
        while (BIO_pending(module_bio) || !BIO_eof(module_bio)) {
            i = BIO_read(module_bio, (char *)buf, BUFFERSIZE);
            EVP_DigestUpdate(ctx, buf, i);
            if (i < 0) {
                WARN("Read Error\n");
            }
            if (i == 0)
                break;
        }
        read_buffer = OPENSSL_zalloc(INTEGRITY_BUF_SIZE);
        if (read_buffer == NULL)
            WARN("Error @read_buffer memory allocation failed\n");

        EVP_DigestFinal(ctx, read_buffer, &bufflen);

        bnctx = BN_CTX_new_ex(NULL);
        if (bnctx == NULL)
            WARN("Error in memory creation for BN_CTX\n");

        bld = OSSL_PARAM_BLD_new();
        if (bld == NULL)
            WARN("Error in memory creation for OSSL_PARAM_BLD\n");

        if (!add_params(bld, t->key, bnctx))
            WARN("Error in add_params API\n");

        params = OSSL_PARAM_BLD_to_param(bld);

        kctx = EVP_PKEY_CTX_new_from_name(NULL, t->algorithm, "");
        if (kctx == NULL || params == NULL)
            WARN("Error in kctx creation..\n");

        if (EVP_PKEY_fromdata_init(kctx) <= 0
            || EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
            WARN("Error in EVP_PKEY_fromdata_init || EVP_PKEY_fromdata \n");

        /* Create a EVP_PKEY_CTX to use for the signing operation */
        sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);

        if (sctx == NULL)
            WARN("Error in EVP_PKEY_CTX_new_from_pkey\n");

        /* set signature parameters */
        if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_SIGNATURE_PARAM_DIGEST,
                                             t->mdalgorithm,
                                             strlen(t->mdalgorithm) + 1))
            WARN("Error in OSSL_PARAM_BLD_push_utf8_string\n");

        params_sig = OSSL_PARAM_BLD_to_param(bld);

        if (EVP_PKEY_verify_init(sctx) <= 0)
            WARN("Error: Failed at EVP_PKEY_verify_init API!!..\n");

        if (EVP_PKEY_CTX_set_params(sctx, params_sig) <= 0)
            WARN("Error in EVP_PKEY_CTX_set_params..\n");

        if (EVP_PKEY_verify(sctx, sigbuf, siglen, read_buffer, bufflen) <= 0) {
            WARN("Error: Failed at EVP_PKEY_verify..\n");
            integrity_status = 0;
        }

        BIO_free(module_bio);
        OPENSSL_free(sigbuf);
        siglen = INTEGRITY_SIGLEN;
        OPENSSL_free(buf);
        OPENSSL_free(read_buffer);
        EVP_MD_CTX_free(ctx);
        EVP_MD_free(md);
        md = NULL;
        BN_CTX_free(bnctx);
        EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_CTX_free(sctx);
        EVP_PKEY_free(pkey);
        pkey = NULL;
        OSSL_PARAM_free(params);
        OSSL_PARAM_free(params_sig);
        OSSL_PARAM_BLD_free(bld);
        sys_ret = remove(sig_files[j]);
    }

    sys_ret = remove("qatprovider_temp.so");
    sys_ret = remove("public_key.txt");

    if (sys_ret != 0)
        WARN("System process failure\n");

    smem_id = shmget((key_t) SM_KEY, 16, 0666);
    smem_ptr = shmat(smem_id, NULL, 0);

    if (integrity_status) {
        INFO("QAT FIPS self-tests(KAT) and integrity test result: PASS\n");
        strcpy(smem_ptr, "KAT_PASS");
    } else {
        INFO("QAT FIPS Integrity test result: FAIL\n");
        strcpy(smem_ptr, "KAT_FAIL");
        return 0;
    }

    return 1;
}
#endif
