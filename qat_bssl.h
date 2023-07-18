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
 * @file qat_bssl.h
 *
 * This file provides and interface for undefined OpenSSL APIs in BoringSSL
 *
 *****************************************************************************/
#ifndef QAT_BSSL_H
# define QAT_BSSL_H

/* Standard Includes */
# include <pthread.h>
# include <errno.h>

/* OpenSSL Includes */
# include <openssl/mem.h>
# include <openssl/bn.h>
# include <openssl/err.h>
#ifdef BSSL_SOURCE
#include "../crypto/fipsmodule/ec/internal.h"
#else
# include <openssl/ec_key.h>
#endif /* BSSL_SOURCE */

/* From engine.h in OpenSSL */
# define ENGINE_CMD_BASE                        200
# define ENGINE_CMD_INVALD                      -1

# define ENGINE_QAT_PTR_DEFINE                  ENGINE *qat_engine_ptr = NULL;
# define ENGINE_QAT_PTR_RESET()                 qat_engine_ptr = NULL
# define ENGINE_QAT_PTR_SET(pt)                 qat_engine_ptr = pt
# define ENGINE_QAT_PTR_GET()                   qat_engine_ptr
# define ENGINE_QAT_PTR_EXPORT                  extern ENGINE *qat_engine_ptr;

ENGINE_QAT_PTR_EXPORT

# define SSL_MAX_PIPELINES					 32

/* Copy from openssl/include/openssl/async.h */
#if defined(_WIN32)
# if defined(BASETYPES) || defined(_WINDEF_H)
/* application has to include <windows.h> to use this */
#define OSSL_ASYNC_FD                           HANDLE
#define OSSL_BAD_ASYNC_FD                       INVALID_HANDLE_VALUE
# endif
#else
#define OSSL_ASYNC_FD                           int
#define OSSL_BAD_ASYNC_FD                       -1
#endif

typedef struct async_wait_ctx_st ASYNC_WAIT_CTX;
typedef struct async_job_st ASYNC_JOB;
typedef struct async_ctx_st async_ctx;

/* Copy from openssl/crypto/async/async_local.h */
struct fd_lookup_st {
    const void *key;
    OSSL_ASYNC_FD fd;
    void *custom_data;
    void (*cleanup)(ASYNC_WAIT_CTX *, const void *, OSSL_ASYNC_FD, void *);
    int add;
    int del;
    struct fd_lookup_st *next;
};
struct async_wait_ctx_st {
    struct fd_lookup_st *fds;
    size_t numadd;
    size_t numdel;
    int init;
    int status;
    int fds_reset;
    void *data;
};
struct async_job_st {
    int status;
    ASYNC_WAIT_CTX *waitctx;
    void (*op_buf_free)(void *, void *);
    int (*tlv_destructor)(void *);
    void (*free_op_done)(void *);
    void *(*copy_op_done)(const void *, unsigned int, void (*)(void *, void *));
};
struct async_ctx_st {;
    ASYNC_JOB *currjob;
    int *currjob_status;
};

#ifndef BSSL_SOURCE
struct ec_key_st {
  /* porting from boringssl/crypto/fipsmodule/ec/internal.h */
  EC_GROUP *group;

  /* Ideally |pub_key| would be an |EC_AFFINE| so serializing it does not pay an
     inversion each time, but the |EC_KEY_get0_public_key| API implies public
     keys are stored in an |EC_POINT|-compatible form. */
  EC_POINT *pub_key;
  void *priv_key;  /* EC_WRAPPED_SCALAR *priv_key; */

  unsigned int enc_flag;
  point_conversion_form_t conv_form;

  CRYPTO_refcount_t references;

  ECDSA_METHOD *ecdsa_meth;

  CRYPTO_EX_DATA ex_data;
} /* EC_KEY */;
#endif /* BSSL_SOURCE */

typedef pthread_once_t bssl_once_t;
#define BSSL_ONCE_INIT PTHREAD_ONCE_INIT
#define bssl_memcpy(dst, src, n) (n == 0 ? dst : memcpy(dst, src, n))

/* These all AYNC macros used to instead of the APIs that defined in OpenSSL but
 * no definition in BoringSSL
 */
/* Status of Async Jobs */
#define ASYNC_JOB_OPER_COMPLETE                 5  /* OPERATION has completed */
#define ASYNC_JOB_COMPLETE                      4
#define ASYNC_JOB_RUNNING                       3
#define ASYNC_JOB_ABORT                         2  /* unused */
#define ASYNC_JOB_PAUSED                        1  /* unused */
#define ASYNC_JOB_STOPPED                       0

#define ASYNC_DEFAULT_VAL                       1
#define ASYNC_get_current_job                   bssl_qat_async_load_current_job
#define ASYNC_mode_is_enabled                   ASYNC_get_current_job
#define ASYNC_current_job_last_check_and_get()  (ASYNC_get_current_job() &&    \
    ((ASYNC_JOB*)ASYNC_get_current_job())->tlv_destructor(NULL))
#define ASYNC_get_wait_ctx(job)                 (((ASYNC_JOB*)job)->waitctx)
#define ASYNC_WAIT_CTX_get_fd                   bssl_async_wait_ctx_get_fd
#define ASYNC_WAIT_CTX_set_wait_fd              bssl_async_wait_ctx_set_wait_fd

#define ASYNC_WAIT_CTX_get_changed_fds          \
    bssl_async_wait_ctx_get_changed_fds
#define ASYNC_WAIT_CTX_clear_fd                 bssl_async_wait_ctx_clear_fd

#define ASYNC_pause_job(void)                   ASYNC_DEFAULT_VAL
#define ASYNC_job_is_running(async_ctx)         \
    (*async_ctx->currjob_status != ASYNC_JOB_COMPLETE && \
     *async_ctx->currjob_status != ASYNC_JOB_STOPPED && \
     *async_ctx->currjob_status != ASYNC_JOB_OPER_COMPLETE)
#define ASYNC_job_is_stopped(async_ctx)         \
    (*async_ctx->currjob_status == ASYNC_JOB_STOPPED)

/* These all macros used to instead of the APIs that defined in OpenSSL but
 * no definition in BoringSSL
 */
# define ENGINE_DEFAULT                         (1)
# define ENGINE_set_id(e, id)                   ENGINE_DEFAULT
# define ENGINE_set_name(e, name)               ENGINE_DEFAULT
# define ENGINE_set_RSA(e, rsa_get_method)      \
    ENGINE_set_RSA_method(e, rsa_get_method, sizeof(RSA_METHOD))
# define ENGINE_set_DSA(e, rsa)                 ENGINE_DEFAULT
# define ENGINE_set_DH(e, dh)                   ENGINE_DEFAULT
# define ENGINE_set_EC(e, ec_get_mothod)        \
    ENGINE_set_ECDSA_method(e, ec_get_mothod, sizeof(ECDSA_METHOD))
# define ENGINE_set_pkey_meths(e, pkey)         ENGINE_DEFAULT
# define ENGINE_set_ciphers(e, ciphers)         ENGINE_DEFAULT
# define qat_create_ciphers()

# define ENGINE_set_destroy_function(e, des)    ENGINE_DEFAULT
/* Called qat_engine_init in ENGINE_set_init_function when binding engine */
# define ENGINE_set_init_function(e, init)      (init(e))
# define ENGINE_set_ctrl_function(e, ctrl)      ENGINE_DEFAULT
# define ENGINE_set_finish_function(e, finish)  ENGINE_DEFAULT
# define ENGINE_set_cmd_defns(e, cmd_defns)     ENGINE_DEFAULT

# define ENGINE_by_id(id)                       (qat_engine_ptr)
# define ENGINE_add(add)                        {}

# define EC_KEY_can_sign(ec_key)                        (1)

# define bssl_engine_get_rsa_method()           \
    ENGINE_get_RSA_method(ENGINE_QAT_PTR_GET())
# define bssl_engine_get_ecdsa_method()         \
    ENGINE_get_ECDSA_method(ENGINE_QAT_PTR_GET())

/* Defined a function as variant memory allocation interface with memset used
 * for no OPENSSL_zalloc() in BoringSSL
 */
# define OPENSSL_zalloc                         bssl_openssl_malloc

/* Redefine all functions related to RSA methods that defined in OpenSSL but 
 * not in BoringSSL
 */

/* No effect, just to pass compilation when BoringSSL enabled */
# define RSA_SSLV23_PADDING      2
# define RSA_X931_PADDING        5

# define RSA_METH_RET_DEFAULT (1)
# define RSA_meth_set_mod_exp(meth, exp)    RSA_METH_RET_DEFAULT
# define RSA_meth_set_bn_mod_exp(meth, exp) RSA_METH_RET_DEFAULT
# define RSA_meth_set_init(meth, init)      RSA_METH_RET_DEFAULT
# define RSA_meth_set_finish(meth, finish)  RSA_METH_RET_DEFAULT
# define RSA_get_default_method()           bssl_get_default_RSA_methods()
# define RSA_meth_new                       bssl_rsa_meth_new
# define RSA_meth_free                      bssl_rsa_meth_free
# define RSA_meth_get_pub_enc(meth)         RSA_public_encrypt
# define RSA_meth_get_pub_dec(meth)         RSA_public_decrypt
# define RSA_meth_get_priv_enc(meth)        RSA_private_encrypt_default
# define RSA_meth_get_priv_dec(meth)        RSA_private_decrypt_default
/* Do nothing */
# define RSA_METH_SET_NULL(method, func)    \
    RSA_METH_RET_DEFAULT;                   \
    do {                                    \
        if (method->app_data == NULL) {     \
            method->app_data = func;        \
            method->app_data = NULL;        \
        }                                   \
    } while(0)
# define RSA_meth_set_pub_enc(meth, func)   RSA_METH_SET_NULL(meth, func)
# define RSA_meth_set_pub_dec(meth, func)   RSA_METH_SET_NULL(meth, func)
# define RSA_meth_set_priv_enc(meth, func)  RSA_METH_SET_NULL(meth, func)
# define RSA_meth_set_priv_dec(meth, func)  RSA_METH_SET_NULL(meth, func)
# define RSA_meth_set_priv_bssl             bssl_rsa_set_priv_meth
# define RSA_padding_add_none               bssl_rsa_padding_add_none
# define RSA_padding_check_none             bssl_rsa_padding_check_none
# define RSA_padding_add_PKCS1_type_1       bssl_rsa_padding_add_pkcs1_type_1
# define RSA_padding_check_PKCS1_type_1     bssl_rsa_padding_check_pkcs1_type_1
# define RSA_padding_add_PKCS1_type_2       bssl_rsa_padding_add_pkcs1_type_2
# define RSA_padding_check_PKCS1_type_2     bssl_rsa_padding_check_pkcs1_type_2
# define RSA_padding_check_PKCS1_OAEP       bssl_rsa_padding_check_pkcs1_OAEP
# define RSA_padding_add_SSLv23             bssl_rsa_padding_add_sslv23
# define RSA_padding_check_SSLv23           bssl_rsa_padding_check_sslv23
# define RSA_padding_add_X931               bssl_rsa_padding_add_x931
# define RSA_padding_check_X931             bssl_rsa_padding_check_x931

/* Redefine all functions related to ECDSA methods that defined in OpenSSL but 
 * not in BoringSSL
 */
# define EC_KEY_METHOD                      ECDSA_METHOD
# define EC_KEY_get_default_method()        bssl_get_default_EC_methods()
# define EC_KEY_OpenSSL()                   bssl_get_default_EC_methods()

# define EC_KEY_METHOD_new                  bssl_ec_key_method_new
# define EC_KEY_METHOD_free                 bssl_ec_key_method_free
/* Do nothing */
# define EC_KEY_NULL_METHOD(meth, k, m, n)  \
    do {                                    \
        if (meth->app_data == NULL) {       \
            meth->app_data = k;             \
            meth->app_data = m;             \
            meth->app_data = n;             \
            meth->common.is_static = 1;     \
            meth->app_data = NULL;          \
        }                                   \
    } while(0)
# define EC_KEY_METHOD_get_sign(meth,       \
    sign_pfunc, sign_setup_pfunc,           \
    sign_sig_pfunc)                         \
    bssl_ec_key_method_get_sign(meth, sign_pfunc, sign_sig_pfunc)
# define EC_KEY_METHOD_set_sign(meth,       \
    sign_pfunc, sign_setup_pfunc,           \
    sign_sig_pfunc)                         \
    bssl_ecdsa_meth_set_do_sign(meth, sign_pfunc)
/* Ignored ECDSA get verify method */
# define EC_KEY_METHOD_get_verify(meth,     \
    verify_pfunc, verify_sig_pfunc)         \
    *(verify_sig_pfunc) = bssl_default_ecdsa_verify
# define EC_KEY_METHOD_set_verify(meth,     \
    verify_pfunc, verify_sig_pfunc)         \
    EC_KEY_NULL_METHOD(meth, verify_pfunc, NULL, NULL)

/* Ignored ECDH methods by redefining invalid methods */
# define EC_KEY_METHOD_get_keygen(meth, pfunc)      \
    EC_KEY_NULL_METHOD(meth, pfunc, NULL, NULL)
# define EC_KEY_METHOD_set_keygen(meth, pfunc)      \
    EC_KEY_NULL_METHOD(meth, pfunc, NULL, NULL)
# define EC_KEY_METHOD_get_compute_key(meth, pfunc) \
    EC_KEY_NULL_METHOD(meth, pfunc, NULL, NULL)
# define EC_KEY_METHOD_set_compute_key(meth, pfunc) \
    EC_KEY_NULL_METHOD(meth, pfunc, NULL, NULL)

/*
 * The default interval in microseconds used for the inline polling thread
 */
# define QAT_INLINE_POLL_PERIOD_IN_US 1
/*
 * Used to sleep for QAT_INLINE_POLL_PERIOD_IN_US microseconds after one time
 * inline polling, purpose to reduce the high CPU usage in performance tests
 */
# define QAT_INLINE_POLLING_USLEEP()           \
    do {                                       \
        usleep(QAT_INLINE_POLL_PERIOD_IN_US);  \
    } while(0)
# define RSA_INLINE_POLLING_USLEEP             QAT_INLINE_POLLING_USLEEP
# define ECDSA_INLINE_POLLING_USLEEP           QAT_INLINE_POLLING_USLEEP

void ENGINE_load_qat(void);

void ENGINE_unload_qat(void);

int bssl_qat_send_ctrl_cmd(ENGINE *e, const char *cmd_name,
                           long i, void *p, void (*f)(void), int cmd_optional);

void *bssl_openssl_malloc(size_t size);

int bssl_qat_async_save_current_job(ASYNC_JOB *job);

ASYNC_JOB *bssl_qat_async_load_current_job(void);

int bssl_qat_before_wake_job(volatile ASYNC_JOB *job, int status, void *in_buf,
                             void *out_buf, void *op_done);

RSA_METHOD *bssl_rsa_meth_new(const char *name, int flags);

void bssl_rsa_meth_free(RSA_METHOD *meth);

int bssl_rsa_set_priv_meth(RSA_METHOD *meth,
                           int (*sign_raw)(RSA *rsa, size_t *out_len,
                                           uint8_t *out, size_t max_out,
                                           const uint8_t *in, size_t in_len,
                                           int padding),
                           int (*decrypt)(RSA *rsa, size_t *out_len,
                                          uint8_t *out, size_t max_out,
                                          const uint8_t *in, size_t in_len,
                                          int padding));

int bssl_rsa_padding_add_none(uint8_t *to, size_t to_len, const uint8_t *from,
                              size_t from_len);

int bssl_rsa_padding_check_none(unsigned char *to, int tlen,
                                const unsigned char *f, int fl, int rsa_len);

int bssl_rsa_padding_add_pkcs1_type_1(uint8_t *to, size_t to_len,
                                      const uint8_t *from, size_t from_len);

int bssl_rsa_padding_check_pkcs1_type_1(unsigned char *to, int tlen,
                                        const unsigned char *from, int flen,
                                        int num);

int bssl_rsa_padding_add_pkcs1_type_2(uint8_t *to, size_t to_len,
                                      const uint8_t *from, size_t from_len);

/* RSA_padding_add_PKCS1_OAEP defined in boring/decrepit/rsa/rsa_decrepit.c,
 * but built into boringssl/build/decrepit/libdecrepit not libcrypto or libssl
 * One option is to redefine this or link to libdecrepit.so in built system
 */
/* int RSA_padding_add_PKCS1_OAEP(uint8_t *to, size_t to_len,
 *                              const uint8_t *from, size_t from_len,
 *                              const uint8_t *param, size_t param_len);
 */

/* Not porting */
int bssl_rsa_padding_check_pkcs1_type_2(unsigned char *to, int tlen,
                                        const unsigned char *f, int fl,
                                        int rsa_len);
int bssl_rsa_padding_check_pkcs1_OAEP(unsigned char *to, int tlen,
                                      const unsigned char *f, int fl,
                                      int rsa_len, const unsigned char *p,
                                      int pl);
int bssl_rsa_padding_add_sslv23(unsigned char *to, int tlen,
                                const unsigned char *f, int fl);
int bssl_rsa_padding_check_sslv23(unsigned char *to, int tlen,
                                  const unsigned char *f, int fl, int rsa_len);
int bssl_rsa_padding_add_x931(unsigned char *to, int tlen,
                              const unsigned char *f, int fl);
int bssl_rsa_padding_check_x931(unsigned char *to, int tlen,
                                const unsigned char *f, int fl, int rsa_len);

EC_KEY_METHOD *bssl_ec_key_method_new(const EC_KEY_METHOD *meth);

void bssl_ec_key_method_free(EC_KEY_METHOD *meth);

ECDSA_SIG *bssl_default_ecdsa_sign(const unsigned char *dgst,
                                   int dgst_len, const BIGNUM *in_kinv,
                                   const BIGNUM *in_r, EC_KEY *eckey);
#ifdef QAT_SW
int bssl_ecdsa_sign(const uint8_t *digest, size_t digest_len,
        uint8_t *sig, unsigned int *sig_len, EC_KEY *eckey);
#endif /* QAT_SW */

int bssl_default_ecdsa_verify(const unsigned char *dgst, int dgst_len,
                              const ECDSA_SIG *sig, EC_KEY *eckey);

void bssl_ecdsa_meth_set_do_sign(EC_KEY_METHOD *meth,
                                int (*sign)(const uint8_t *digest,
                                            size_t digest_len, uint8_t *sig,
                                            unsigned int *sig_len,
                                            EC_KEY *eckey));

int bssl_private_key_method_update(EVP_PKEY *pkey);

/* Optional 'name': RSA, EC_KEY, SSL; 'type' set arbitrarily by user */
# define BSSL_DEFINE_EXDATA_OF(name, type)                                  \
    static bssl_once_t name##_##type##_index_once = BSSL_ONCE_INIT;     \
    static int name##_##type##_index = 0;                                   \
                                                                            \
    static void bssl_##name##_##type##_free(void *parent, void *ptr,        \
                                            CRYPTO_EX_DATA *ad, int index,  \
                                            long argl, void *argp)          \
    {                                                                       \
        if (ptr) OPENSSL_free((type *)ptr);                                 \
    }                                                                       \
                                                                            \
    static void bssl_##name##_##type##_index_init_once()                    \
    {                                                                       \
        name##_##type##_index =                                             \
            name##_get_ex_new_index(0, NULL, NULL, NULL,                    \
                                    bssl_##name##_##type##_free);           \
        if (name##_##type##_index < 0) {                                    \
            abort();                                                        \
        }                                                                   \
    }                                                                       \
                                                                            \
    static int bssl_##name##_set_##type (name *n, type *t)                  \
    {                                                                       \
        bssl_once(&name##_##type##_index_once,                            \
                    bssl_##name##_##type##_index_init_once);                \
        if (name##_set_ex_data(n, name##_##type##_index, t) != 1) {         \
            return 1; /* Fail */                                            \
        }                                                                   \
        return 0; /* Success */                                             \
    }                                                                       \
                                                                            \
    static type *bssl_##name##_get_##type (const name *n)                   \
    {                                                                       \
        bssl_once(&name##_##type##_index_once,                            \
                    bssl_##name##_##type##_index_init_once);                \
        return (type *) name##_get_ex_data(n, name##_##type##_index);       \
    }

# define BSSL_SET_EXDATA_OF(name, type, n, t)                               \
        bssl_##name##_set_##type (n, t)
# define BSSL_GET_EXDATA_OF(name, type, n)                                  \
        bssl_##name##_get_##type (n)

/* Define a group of variables and functions with type async_ctx */
# define BSSL_DEFINE_ASYNC_CTX_INIT_EXDATA(name)                            \
        BSSL_DEFINE_EXDATA_OF(name, async_ctx);
/* Set ASYNC_CTX st to RSA/EC_KEY/SSL exdata */
# define BSSL_SET_ASYNC_CTX_TO_EXDATA(name, n, t)                           \
        BSSL_SET_EXDATA_OF(name, async_ctx, n, t)
/* Get ASYNC_CTX st from RSA/EC_KEY/SSL exdata */
# define BSSL_GET_ASYNC_CTX_FM_EXDATA(name, n)                              \
        BSSL_GET_EXDATA_OF(name, async_ctx, n)

/* Define a group of variables and functions with type async_enable
 * Note that this type async_enable needs to be defined externally
 */
# define BSSL_DEFINE_ASYNC_CFG_INIT_EXDATA(name)                            \
        BSSL_DEFINE_EXDATA_OF(name, async_enable);
/* Set async_enable to RSA/EC_KEY/SSL exdata */
# define BSSL_SET_ASYNC_CFG_TO_EXDATA(name, n, t)                           \
        BSSL_SET_EXDATA_OF(name, async_enable, n, t)
/* Get async_enable from RSA/EC_KEY/SSL exdata */
# define BSSL_GET_ASYNC_CFG_FM_EXDATA(name, n)                              \
        BSSL_GET_EXDATA_OF(name, async_enable, n)

# define BSSL_QAT_INIT_DEBUG_LOG               "INIT_DEBUG_QAT_LOG"

/* Declaration on operation interfaces of ASYNC_WAIT_CTX */
int bssl_async_wait_ctx_set_wait_fd(ASYNC_WAIT_CTX *ctx, const void *key,
                                    OSSL_ASYNC_FD fd, void *custom_data,
                                    void (*cleanup)(ASYNC_WAIT_CTX *,
                                                    const void *,
                                                    OSSL_ASYNC_FD, void *));

int bssl_async_wait_ctx_get_fd(ASYNC_WAIT_CTX *ctx, const void *key,
                               OSSL_ASYNC_FD *fd, void **custom_data);

int bssl_async_wait_ctx_get_changed_fds(ASYNC_WAIT_CTX *ctx,
                                        OSSL_ASYNC_FD *addfd, size_t *numaddfds,
                                        OSSL_ASYNC_FD *delfd, size_t *numdelfds);

int bssl_async_wait_ctx_clear_fd(ASYNC_WAIT_CTX *ctx, const void *key);

/* Declaration on operation interfaces of async_ctx */
async_ctx *bssl_qat_async_start_job(void);

void bssl_qat_async_finish_job(const async_ctx *ctx);

int bssl_qat_async_ctx_copy_result(const async_ctx *ctx, unsigned char *buffer,
                                   unsigned long *size, unsigned long max_size);

int bssl_qat_async_ctx_get_changed_fds(async_ctx *ctx,
                                       OSSL_ASYNC_FD *addfd, size_t *numaddfds,
                                       OSSL_ASYNC_FD *delfd, size_t *numdelfds);
int bssl_qat_set_default_string(const char *def_list);

void bssl_once(bssl_once_t *once, void (*init)(void));

typedef int (*PFUNC_EC_SIGN)(const uint8_t *,
                        size_t,
                        uint8_t *,
                        unsigned int *,
                        EC_KEY *);
typedef ECDSA_SIG *(*PFUNC_EC_SIGN_SIG)(const unsigned char *,
                                     int,
                                     const BIGNUM *,
                                     const BIGNUM *,
                                     EC_KEY *);
void bssl_ec_key_method_get_sign(EC_KEY_METHOD *meth, PFUNC_EC_SIGN *sig_func,
                                    PFUNC_EC_SIGN_SIG *sig_sig_func);

#ifdef QAT_SW
typedef void (*mb_async_callback_func) (void *ctx, unsigned char *out_buffer,
                                        unsigned long *size,
                                        unsigned long max_size);

typedef struct _mb_async_ctx {
    mb_async_callback_func callback_func;
    void *ctx;
} mb_async_ctx;

void bssl_mb_async_job_finish_wait(volatile ASYNC_JOB *job, int job_status, int waitctx_status);

#endif /* QAT_SW */
#endif
