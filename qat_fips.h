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
 * @file qat_fips.h
 *
 * This file provides an interface to perform qat fips test
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */
#ifndef QAT_FIPS_H
# define QAT_FIPS_H

# ifndef _GNU_SOURCE
#  define _GNU_SOURCE
# endif
# ifndef __USE_GNU
#  define __USE_GNU
# endif

# include <stdlib.h>
# include <string.h>
# include <pthread.h>
# ifndef __FreeBSD__
#  include <sched.h>
# else
#  include <pthread_np.h>
#  include <sys/types.h>
#  include <sys/sysctl.h>
#  include <unistd.h>
#  include <errno.h>
# endif
# include <sys/time.h>
# include <signal.h>
# include <sys/ipc.h>
# include <sys/shm.h>
# include <sys/types.h>

# include <openssl/async.h>
# include <openssl/provider.h>
# include <openssl/self_test.h>
# include <openssl/types.h>
# include <openssl/core.h>
# include <openssl/core_dispatch.h>
# include <openssl/types.h>
# include <openssl/params.h>
# include <openssl/core_names.h>
# include <openssl/rsa.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# include <openssl/sha.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/async.h>
# include <openssl/e_os2.h>
# include <openssl/bio.h>
# include <openssl/x509.h>
# include <openssl/conf.h>
# include <openssl/txt_db.h>
# include <openssl/ocsp.h>
# include <openssl/http.h>
# include <openssl/safestack.h>
# include <openssl/store.h>
# include <openssl/param_build.h>

# include "e_qat.h"
# include "qat_utils.h"
# include "qat_provider.h"
# include "qat_prov_rsa.h"

# define OPENSSL_NO_DES
# include <openssl/kdf.h>
# include "qat_self_test_data.inc"

# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))
# define EVP_MAX_MD_SIZE                 64/* longest known is SHA512 */
# define FIPS_KEY_STRING "f4556650ac31d35461610bac4ed81b1a181b2d8a43ea2854cbae22ca74560813"
# define FORMAT_BINARY   2      /* Generic binary */
# define BUFSIZE 4096
# define INSTALL_STATUS_VAL "INSTALL_QAT_SELF_TEST_KATS_RUN"
# define INTEGRITY_SIGLEN 72
# define INTEGRITY_PUB_KEYLENGTH 65
# define INTEGRITY_BUF_SIZE 32
# define OSSL_PROV_FIPS_PARAM_INSTALL_VERSION "install-version"
# define VERSION_VAL  "1"
# define OSSL_PROV_FIPS_PARAM_CONDITIONAL_ERRORS "conditional-errors"
# define OSSL_PROV_FIPS_PARAM_SECURITY_CHECKS "security-checks"
# define OSSL_PROV_FIPS_PARAM_MODULE_MAC      "module-mac"
# define OSSL_PROV_FIPS_PARAM_INSTALL_MAC     "install-mac"
# define OSSL_PROV_FIPS_PARAM_INSTALL_STATUS  "install-status"

# define B_FORMAT_TEXT   0x8000
# define FORMAT_UNDEF    0
# define FORMAT_TEXT    (1 | B_FORMAT_TEXT)/* Generic text */
# define FORMAT_BINARY   2      /* Generic binary */
# define FORMAT_BASE64  (3 | B_FORMAT_TEXT)/* Base64 */
# define FORMAT_ASN1     4      /* ASN.1/DER */
# define FORMAT_PEM     (5 | B_FORMAT_TEXT)
# define FORMAT_PKCS12   6
# define FORMAT_SMIME   (7 | B_FORMAT_TEXT)
# define FORMAT_ENGINE   8      /* Not really a file format */
# define FORMAT_PEMRSA  (9 | B_FORMAT_TEXT)/* PEM RSAPublicKey format */
# define FORMAT_ASN1RSA  10     /* DER RSAPublicKey format */
# define FORMAT_MSBLOB   11     /* MS Key blob format */
# define FORMAT_PVK      12     /* MS PVK file format */
# define FORMAT_HTTP     13     /* Download using HTTP */
# define FORMAT_NSS      14     /* NSS keylog format */

struct async_args_callback {
    int job_ready;
    int i;
};

struct qat_self_test_result {
    const char *type[10];
    const char *desc[10];
    int result[10];
};

typedef struct qat_self_test_result QAT_SELF_TEST_RESULT;

extern QAT_SELF_TEST_RESULT *qat_signature_result;
extern QAT_SELF_TEST_RESULT *qat_kas_result;
extern QAT_SELF_TEST_RESULT *qat_cipher_result;
extern QAT_SELF_TEST_RESULT *qat_digest_result;
extern QAT_SELF_TEST_RESULT *qat_mac_result;
extern QAT_SELF_TEST_RESULT *qat_kdf_result;

extern QAT_SELF_TEST_RESULT *qat_async_signature_result;
extern QAT_SELF_TEST_RESULT *qat_async_kas_result;
extern QAT_SELF_TEST_RESULT *qat_async_cipher_result;
extern QAT_SELF_TEST_RESULT *qat_async_digest_result;
extern QAT_SELF_TEST_RESULT *qat_async_mac_result;
extern QAT_SELF_TEST_RESULT *qat_async_kdf_result;

struct ossl_self_test_st {
    /* local state variables */
    const char *phase;
    const char *type;
    const char *desc;
    OSSL_CALLBACK *cb;

    /* callback related variables used to pass the state back to the user */
    OSSL_PARAM params[4];
    void *cb_arg;
};

typedef struct ossl_self_test_st OSSL_SELF_TEST;

struct test_params_t {
    char *engine_id;
    int *count;
    const char *type;
    int size;
    ENGINE *e;
    int print_output;
    int verify;
    int performance;
    int enable_external_polling;
    int enable_event_driven_polling;
    int enable_async;
    const char *prov_id;
    OSSL_PROVIDER *prov;
    size_t sigsize;
    int use_callback_mode;
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
    int async_jobs;
    ASYNC_JOB **jobs;
    ASYNC_WAIT_CTX **awcs;
    void *additional_args;
    OSSL_LIB_CTX *provctx;
    const char *phase;
    const char *desc;
    OSSL_CALLBACK *cb;
    OSSL_SELF_TEST *st;

    /* callback related variables used to pass the state back to the user */
    OSSL_PARAM params[4];
    void *cb_arg;
    int ondemand;
    int co_existence;
};

typedef struct test_params_t TEST_PARAMS;

int QAT_SELF_TEST_kats(void *args);

struct async_additional_args_rsa {
    int sign_only;
    int verify_only;
    int encrypt_only;
    int decrypt_only;
    int padding;
};

struct qat_evp_pkey_ctx_st {
    /* Actual operation */
    int operation;

    /*
     * Library context, property query, keytype and keymgmt associated with
     * this context
     */
    OSSL_LIB_CTX *libctx;
    char *propquery;
    const char *keytype;
    /* If |pkey| below is set, this field is always a reference to keymgmt */
    EVP_KEYMGMT *keymgmt;

    union {
        struct {
            void *genctx;
        } keymgmt;

        struct {
            EVP_KEYEXCH *exchange;
            /*
             * Opaque ctx returned from a providers exchange algorithm
             * implementation OSSL_FUNC_keyexch_newctx()
             */
            void *algctx;
        } kex;

        struct {
            EVP_SIGNATURE *signature;
            /*
             * Opaque ctx returned from a providers signature algorithm
             * implementation OSSL_FUNC_signature_newctx()
             */
            void *algctx;
        } sig;

        struct {
            EVP_ASYM_CIPHER *cipher;
            /*
             * Opaque ctx returned from a providers asymmetric cipher algorithm
             * implementation OSSL_FUNC_asym_cipher_newctx()
             */
            void *algctx;
        } ciph;
        struct {
            EVP_KEM *kem;
            /*
             * Opaque ctx returned from a providers KEM algorithm
             * implementation OSSL_FUNC_kem_newctx()
             */
            void *algctx;
        } encap;
    } op;

    /*
     * Cached parameters.  Inits of operations that depend on these should
     * call evp_pkey_ctx_use_delayed_data() when the operation has been set
     * up properly.
     */
    struct {
        /* Distinguishing Identifier, ISO/IEC 15946-3, FIPS 196 */
        char *dist_id_name;     /* The name used with EVP_PKEY_CTX_ctrl_str() */
        void *dist_id;          /* The distinguishing ID itself */
        size_t dist_id_len;     /* The length of the distinguishing ID */

        /* Indicators of what has been set.  Keep them together! */
        unsigned int dist_id_set:1;
    } cached_parameters;

    /* Application specific data, usually used by the callback */
    void *app_data;
    /* Keygen callback */
    EVP_PKEY_gen_cb *pkey_gencb;
    /* implementation specific keygen data */
    int *keygen_info;
    int keygen_info_count;

    /* Legacy fields below */

    /* EVP_PKEY identity */
    int legacy_keytype;
    /* Method associated with this operation */
    const EVP_PKEY_METHOD *pmeth;
    /* Engine that implements this method or NULL if builtin */
    ENGINE *engine;
    /* Key: may be NULL */
    EVP_PKEY *pkey;
    /* Peer key for key agreement, may be NULL */
    EVP_PKEY *peerkey;
    /* Algorithm specific data */
    void *data;
    /* Indicator if digest_custom needs to be called */
    unsigned int flag_call_digest_custom:1;
    /*
     * Used to support taking custody of memory in the case of a provider being
     * used with the deprecated EVP_PKEY_CTX_set_rsa_keygen_pubexp() API. This
     * member should NOT be used for any other purpose and should be removed
     * when said deprecated API is excised completely.
     */
    BIGNUM *rsa_pubexp;
} /* QAT_EVP_PKEY_CTX */ ;

typedef struct qat_evp_pkey_ctx_st QAT_EVP_PKEY_CTX;

int qat_fips_self_test(void *qatctx, int ondemand, int co_ex_enabled);
void kat_self_test_init(int ondemand, int co_existence);
void fips_result(void);
int self_test_events(const OSSL_PARAM params[], void *arg);
int QAT_TlsPrf_Ops(void *args, unsigned char *out, size_t outlen,
                   const char *desc);
int add_params(OSSL_PARAM_BLD * bld, const ST_KAT_PARAM * params, BN_CTX *ctx);
int get_pub_key_from_file(char *in_name, unsigned char *out);
#endif
