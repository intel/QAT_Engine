/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022 Intel Corporation.
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
 * @file qat_bssl.c
 *
 * This file provides and interface for undefined OpenSSL APIs in BoringSSL
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifndef __USE_GNU
# define __USE_GNU
#endif

#ifdef QAT_BORINGSSL
# include "qat_bssl.h"
# include "e_qat.h"
# include "qat_fork.h"
# include "qat_utils.h"
# ifdef QAT_HW
# include "qat_hw_callback.h"
# endif /* QAT_HW */
# ifdef QAT_SW
# include "qat_events.h"
# include "qat_sw_rsa.h"
# include "qat_evp.h"
#endif /* QAT_SW */
# include "qat_events.h"

# include <openssl/rsa.h>
# include <openssl/base.h>
# include <openssl/ssl.h>
# include <openssl/rand.h>
# include <openssl/conf.h>
# include <ctype.h>

ENGINE_QAT_PTR_DEFINE
typedef pthread_key_t  ASYNC_JOB_THREAD_KEY;

# define BSSL_RUN_ONCE   bssl_once
# define BSSL_THREAD_LOCAL_KEY(name)                                           \
    bssl_thread_local_##name##_key
# define BSSL_THREAD_LOCAL_INIT_ONCE(name)                                     \
    bssl_thread_local_##name##_init_once
# define BSSL_THREAD_LOCAL_KEY_CREATED(name)                                   \
    bssL_thread_local_##name##_key_created
# define BSSL_THREAD_LOCAL_INIT_FUNC(name)                                     \
    bssl_qat_##name##_thread_local_init
# define BSSL_THREAD_LOCAL_DESTROY_FUNC(name)                                  \
    bssl_qat_##name##_thread_local_destructor

# define BSSL_DEFINE_THREAD_LOCAL_INIT_OF(name, destructor)                    \
    static pthread_key_t BSSL_THREAD_LOCAL_KEY(name);                          \
    static pthread_once_t BSSL_THREAD_LOCAL_INIT_ONCE(name) =PTHREAD_ONCE_INIT;\
    static int BSSL_THREAD_LOCAL_KEY_CREATED(name) = 0;                        \
    static void BSSL_THREAD_LOCAL_DESTROY_FUNC(name) (void *tlv) {             \
        if (tlv) {                                                             \
            OPENSSL_free(tlv);                                                 \
        }                                                                      \
    }                                                                          \
    static void BSSL_THREAD_LOCAL_INIT_FUNC(name) (void) {                     \
        BSSL_THREAD_LOCAL_KEY_CREATED(name) =                                  \
            pthread_key_create(&BSSL_THREAD_LOCAL_KEY(name),                   \
            destructor == NULL?NULL:BSSL_THREAD_LOCAL_DESTROY_FUNC(name)) == 0;\
    }

# define BSSL_QAT_METHOD_RSA               (unsigned int)0x0001
# define BSSL_QAT_METHOD_ECDSA             (unsigned int)0x0020

unsigned int default_algorithm_conf_flags = 0;

typedef struct bssl_qat_cmd_lookup_st{
    const char* cmd_name;
    const int   cmd_flag;
} BSSL_QAT_CTL_CMD;;

static const BSSL_QAT_CTL_CMD bssl_qat_cmds_table[] ={
    {"ENABLE_INLINE_POLLING",      QAT_CMD_ENABLE_INLINE_POLLING},
    {"SET_INTERNAL_POLL_INTERVAL", QAT_CMD_SET_INTERNAL_POLL_INTERVAL},
    {"ENABLE_SW_FALLBACK",         QAT_CMD_ENABLE_SW_FALLBACK},
    {BSSL_QAT_INIT_DEBUG_LOG,      ENGINE_CMD_INVALD},
    {NULL,                         ENGINE_CMD_INVALD}
};

/* To be compatible with the jobs' behaviors or interfaces designed in OpenSSL,
 * we used the thread local storage(TLS) to save the async_job on the
 * application side, such as the bssl qat module that we added to Nginx-QUIC,
 * and then to load the async_job in QATEngine by calling ASYNC_get_current_job
 * or other similar actions.
 */
BSSL_DEFINE_THREAD_LOCAL_INIT_OF(async_job, NULL);

int bssl_qat_send_ctrl_cmd(ENGINE *e, const char *cmd_name,
                           long i, void *p, void (*f)(void), int cmd_optional)
{
    const BSSL_QAT_CTL_CMD *tbl = bssl_qat_cmds_table;

    while (tbl && tbl->cmd_name) {
        if (strcmp(cmd_name, BSSL_QAT_INIT_DEBUG_LOG) == 0) {
            /* For previous scenario, log initialized when calling
             * qat_engine_init()
             * Currently, init log may be essential before calling
             * ENGINE_load_qat()
             */
            QAT_DEBUG_LOG_INIT();
            return 1;/* Success */
        }
        if (strcmp(cmd_name, tbl->cmd_name) == 0) {
            return qat_engine_ctrl(e, tbl->cmd_flag, i, p, f);
        }
        tbl++;
    }

    return 0;/* Fail */
}

/* Referred to the similar interfaces in qat_hw_init.c */
static void *bssl_qat_async_check_create_local_variables(void *new,
                                                    ASYNC_JOB_THREAD_KEY key)
{
    void *tlv =
        (void *)qat_getspecific_thread(key);
    if (tlv != NULL) {
        return tlv;
    }

    tlv = new;
    if (tlv != NULL) {
        qat_setspecific_thread(key, (void *)tlv);
    }
    return tlv;
}

int bssl_qat_async_local_variable_destructor(void *tlv)
{
    if (tlv) {
        OPENSSL_free(tlv);
    }
    qat_setspecific_thread(BSSL_THREAD_LOCAL_KEY(async_job), NULL);
    return 1; /* Success */
}

int bssl_qat_async_save_current_job(ASYNC_JOB *job)
{
    BSSL_RUN_ONCE(&BSSL_THREAD_LOCAL_INIT_ONCE(async_job),
                  BSSL_THREAD_LOCAL_INIT_FUNC(async_job));
    /* Set local_variable_destructor in ASYNC_JOB */
    job->tlv_destructor = bssl_qat_async_local_variable_destructor;
    if (bssl_qat_async_check_create_local_variables(job,
                                        BSSL_THREAD_LOCAL_KEY(async_job))) {
        return 0;
    }

    return 1;
}

ASYNC_JOB *bssl_qat_async_load_current_job(void)
{
    BSSL_RUN_ONCE(&BSSL_THREAD_LOCAL_INIT_ONCE(async_job),
                  BSSL_THREAD_LOCAL_INIT_FUNC(async_job));
    return (ASYNC_JOB *)bssl_qat_async_check_create_local_variables(NULL,
                                            BSSL_THREAD_LOCAL_KEY(async_job));
}

#ifdef QAT_HW
/* Duplicate op_done_t structure and set op_buf_free */
static void *bssl_qat_copy_op_done(const void *op_done, unsigned int size,
                            void (*buffers_free)(void *in_buf, void *out_buf))
{
    op_done_t *op_done_dup = OPENSSL_memdup(op_done, size);
    volatile ASYNC_JOB *job = op_done_dup->job;
    job->op_buf_free = buffers_free;

    return op_done_dup;
}
/* Free memory for op_done_t structure */
static void bssl_qat_free_op_done(void *op_done)
{
    /* Clean op_done before free memory */
    qat_cleanup_op_done((op_done_t *)op_done);

    if (op_done) {
        OPENSSL_free(op_done);
    }
}
#endif /* QAT_HW */

/* All bssl_async_wait_ctx*() copied from openssl/crypto/async/async_wait.c */
static ASYNC_WAIT_CTX *bssl_async_wait_ctx_new(void)
{
    return OPENSSL_zalloc(sizeof(ASYNC_WAIT_CTX));
}

static void bssl_async_wait_ctx_free(ASYNC_WAIT_CTX *ctx)
{
    struct fd_lookup_st *curr;
    struct fd_lookup_st *next;

    if (ctx == NULL)
        return;

    curr = ctx->fds;
    while (curr != NULL) {
        /* Only try and cleanup if it hasn't been marked deleted */
        if (curr->cleanup != NULL)
            curr->cleanup(ctx, curr->key, curr->fd, curr->custom_data);

        /* Always free the fd_lookup_st */
        next = curr->next;
        OPENSSL_free(curr);
        curr = next;
    }

    if (ctx->data) {
        OPENSSL_free(ctx->data);
    }

    OPENSSL_free(ctx);
}
int bssl_async_wait_ctx_set_wait_fd(ASYNC_WAIT_CTX *ctx, const void *key,
                                    OSSL_ASYNC_FD fd, void *custom_data,
                                    void (*cleanup)(ASYNC_WAIT_CTX *,
                                                    const void *,
                                                    OSSL_ASYNC_FD, void *))
{
    struct fd_lookup_st *fdlookup;

    if ((fdlookup = OPENSSL_zalloc(sizeof(*fdlookup))) == NULL) {
        return 0;
    }

    fdlookup->key = key;
    fdlookup->fd = fd;
    fdlookup->custom_data = custom_data;
    fdlookup->cleanup = cleanup;
    fdlookup->add = 1;
    fdlookup->next = ctx->fds;
    ctx->fds = fdlookup;
    ctx->numadd++;
    return 1;
}

int bssl_async_wait_ctx_get_fd(ASYNC_WAIT_CTX *ctx, const void *key,
                               OSSL_ASYNC_FD *fd, void **custom_data)
{
    struct fd_lookup_st *curr;

    curr = ctx->fds;
    while (curr != NULL) {
        if (curr->del) {
            /* This one has been marked deleted so do nothing */
            curr = curr->next;
            continue;
        }
        if (curr->key == key) {
            *fd = curr->fd;
            *custom_data = curr->custom_data;
            return 1;
        }
        curr = curr->next;
    }
    return 0;
}

int bssl_async_wait_ctx_get_all_fds(ASYNC_WAIT_CTX *ctx, OSSL_ASYNC_FD *fd,
                                    size_t *numfds)
{
    struct fd_lookup_st *curr;

    curr = ctx->fds;
    *numfds = 0;
    while (curr != NULL) {
        if (curr->del) {
            /* This one has been marked deleted so do nothing */
            curr = curr->next;
            continue;
        }
        if (fd != NULL) {
            *fd = curr->fd;
            fd++;
        }
        (*numfds)++;
        curr = curr->next;
    }
    return 1;
}

int bssl_async_wait_ctx_get_changed_fds(ASYNC_WAIT_CTX *ctx,
                                        OSSL_ASYNC_FD *addfd, size_t *numaddfds,
                                        OSSL_ASYNC_FD *delfd, size_t *numdelfds)
{
    struct fd_lookup_st *curr;

    *numaddfds = ctx->numadd;
    *numdelfds = ctx->numdel;
    if (addfd == NULL && delfd == NULL)
        return 1;

    curr = ctx->fds;

    while (curr != NULL) {
        /* We ignore fds that have been marked as both added and deleted */
        if (curr->del && !curr->add && (delfd != NULL)) {
            *delfd = curr->fd;
            delfd++;
        }
        if (curr->add && !curr->del && (addfd != NULL)) {
            *addfd = curr->fd;
            addfd++;
        }
        curr = curr->next;
    }

    return 1;
}

int bssl_qat_async_ctx_get_changed_fds(async_ctx *ctx,
                                       OSSL_ASYNC_FD *addfd, size_t *numaddfds,
                                       OSSL_ASYNC_FD *delfd, size_t *numdelfds)
{
    if (ctx &&
        ctx->currjob &&
        ctx->currjob->waitctx) {
        return bssl_async_wait_ctx_get_changed_fds(ctx->currjob->waitctx,
                                                   addfd, numaddfds,
                                                   delfd, numdelfds);

    }
    return 0;/* Fail */
}

int bssl_async_wait_ctx_clear_fd(ASYNC_WAIT_CTX *ctx, const void *key)
{
    struct fd_lookup_st *curr, *prev;

    curr = ctx->fds;
    prev = NULL;
    while (curr != NULL) {
        if (curr->del == 1) {
            /* This one has been marked deleted already so do nothing */
            prev = curr;
            curr = curr->next;
            continue;
        }
        if (curr->key == key) {
            /* If fd has just been added, remove it from the list */
            if (curr->add == 1) {
                if (ctx->fds == curr) {
                    ctx->fds = curr->next;
                } else {
                    prev->next = curr->next;
                }

                /* It is responsibility of the caller to cleanup before calling
                 * ASYNC_WAIT_CTX_clear_fd
                 */
                OPENSSL_free(curr);
                ctx->numadd--;
                return 1;
            }

            /*
             * Mark it as deleted. We don't call cleanup if explicitly asked
             * to clear an fd. We assume the caller is going to do that (if
             * appropriate).
             */
            curr->del = 1;
            ctx->numdel++;
            return 1;
        }
        prev = curr;
        curr = curr->next;
    }
    return 0;
}

void bssl_async_wait_ctx_reset_counts(ASYNC_WAIT_CTX *ctx)
{
    struct fd_lookup_st *curr, *prev = NULL;

    ctx->numadd = 0;
    ctx->numdel = 0;

    curr = ctx->fds;

    while (curr != NULL) {
        if (curr->del) {
            if (prev == NULL)
                ctx->fds = curr->next;
            else
                prev->next = curr->next;
            OPENSSL_free(curr);
            if (prev == NULL)
                curr = ctx->fds;
            else
                curr = prev->next;
            continue;
        }
        if (curr->add) {
            curr->add = 0;
        }
        prev = curr;
        curr = curr->next;
    }
}

/* Called in ssl private sign function of SSL_PRIVATE_KEY_METHOD */
async_ctx *bssl_qat_async_start_job(void)
{
    async_ctx *ctx = NULL;
    ASYNC_JOB *job = NULL;
    ASYNC_WAIT_CTX *wctx = NULL;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL ||
        (job = OPENSSL_zalloc(sizeof(*job))) == NULL ||
        (wctx = bssl_async_wait_ctx_new()) == NULL) {
        goto err;
    }
    /* Config waitctx */
    wctx->init = 1; /* Set init to non-zero */
    /* Config job */
    job->waitctx = wctx;
    job->status = ASYNC_JOB_RUNNING;

#ifdef QAT_HW
    job->copy_op_done = bssl_qat_copy_op_done;
    job->free_op_done = bssl_qat_free_op_done;
#endif /* QAT_HW */

#ifdef QAT_SW
    job->copy_op_done = NULL;
    job->free_op_done = NULL;
#endif /* QAT_SW */

    /* Config async_ctx */
    ctx->currjob = job;
    ctx->currjob_status = &ctx->currjob->status;
    bssl_qat_async_save_current_job(ctx->currjob);

    return ctx;

err:
    if (ctx) {
        OPENSSL_free(ctx);
    }

    if (job) {
        OPENSSL_free(job);
    }
    return NULL;
}

void bssl_qat_async_finish_job(const async_ctx *ctx)
{
    if (ctx) {
        if (ctx->currjob) {
            bssl_async_wait_ctx_free(ctx->currjob->waitctx);
            OPENSSL_free(ctx->currjob);
        }
        OPENSSL_free((async_ctx *)ctx);
    }
}

static void bssl_qat_async_reset_fds(const async_ctx *ctx)
{
    ASYNC_WAIT_CTX *wctx = NULL;

    if (ctx &&
        ctx->currjob) {
        wctx = ctx->currjob->waitctx;
        if (wctx->fds_reset == 0) {
            bssl_async_wait_ctx_reset_counts(wctx);
            bssl_async_wait_ctx_clear_fd(wctx, wctx->fds->key);
            wctx->fds_reset = 1;
        }
    }
}

#ifdef QAT_SW
static void mb_async_callback(mb_async_ctx *async_ctx,
                              unsigned char *out_buffer, unsigned long *size,
                              unsigned long max_size)
{
    if (async_ctx && async_ctx->callback_func) {
        async_ctx->callback_func(async_ctx->ctx, out_buffer, size, max_size);
    }
}
#endif /* QAT_SW */

int bssl_qat_async_ctx_copy_result(const async_ctx *ctx, unsigned char *buffer,
                                   unsigned long *size, unsigned long max_size)
{
    unsigned long bytes_len = 0;
#ifdef QAT_HW
    CpaFlatBuffer *from;

    /* Decrease num_requests_in_flight by 1 to
     * avoid high cpu load from polling thread
     */
    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight,
                           qat_check_create_local_variables());
 #endif /* QAT_HW */

    /* Change fds state from add to del */
    bssl_qat_async_reset_fds(ctx);

    if (ctx && ctx->currjob && ctx->currjob->waitctx) {
        /* complete to operation with async, need to copy data to buffer. */
        if (ctx->currjob->waitctx->data &&
            ctx->currjob->status == ASYNC_JOB_COMPLETE) {
#ifdef QAT_HW
            from = (CpaFlatBuffer *)ctx->currjob->waitctx->data;
            bytes_len = from->dataLenInBytes;
            bssl_memcpy(buffer, from->pData, bytes_len);

            /* Free output buffers allocated from build_decrypt_op_buf */
            ctx->currjob->op_buf_free(NULL, from);
#endif /* QAT_HW */

#ifdef QAT_SW
            mb_async_callback((mb_async_ctx *)ctx->currjob->waitctx->data,
                              buffer, &bytes_len, max_size);
#endif /* QAT_SW */
            ctx->currjob->waitctx->data = NULL;
            ctx->currjob->status = ASYNC_JOB_STOPPED;
        } else if (ctx->currjob->status == ASYNC_JOB_OPER_COMPLETE) {
            if (ctx->currjob->waitctx->data) {
                bytes_len = (unsigned long)ctx->currjob->waitctx->data;
            }
            ctx->currjob->waitctx->data = NULL;
            ctx->currjob->status = ASYNC_JOB_STOPPED;
        }
    }

    if (bytes_len == 0 || bytes_len > max_size) {
        return 1; /* Data not ready, return fail */
    }

    *size = bytes_len;

    return 0; /* Copied valid data, return success */
}

int bssl_qat_before_wake_job(volatile ASYNC_JOB *job, int status, void *in_buf,
                             void *out_buf, void *op_done)
{
    ASYNC_WAIT_CTX *waitctx = ASYNC_get_wait_ctx(job);

    /* Free op_done allocated in qat_rsa_decrypt */
    job->free_op_done(op_done);
    /* Free input buffers allocated from build_decrypt_op_buf or
     * build_encrypt_op_buf, pointing to dec_op_data or enc_op_data
     */
    job->op_buf_free(in_buf, NULL);

    if (waitctx && waitctx->init && out_buf) {
        waitctx->data = out_buf;
        waitctx->status = status; /* Set waitctx->status to status */
        job->status = ASYNC_JOB_COMPLETE;
        return 0; /* Success */
    }
    job->status = ASYNC_JOB_STOPPED;

    /* Free output buffers allocated from build_decrypt_op_buf or
     * build_encrypt_op_buf, pointing to output_buffer
     */
    job->op_buf_free(NULL, out_buf);
    return 1; /* Fail */
}

void bssl_mb_async_job_finish_wait(volatile ASYNC_JOB *job, int job_status, int waitctx_status)
{
    ASYNC_WAIT_CTX *waitctx = ASYNC_get_wait_ctx(job);

    if (waitctx && waitctx->init) {
        waitctx->status = waitctx_status; /* Set waitctx->status to status */
    }
    job->status = job_status;
}

/* Refers to openssl/crypto/rsa/rsa_local.h */
RSA_METHOD *bssl_rsa_meth_new(const char *name, int flags)
{
    RSA_METHOD *meth = OPENSSL_zalloc(sizeof(*meth));

    if (meth) {
        meth->flags = flags;
    }

    return meth;
}

void bssl_rsa_meth_free(RSA_METHOD *meth)
{
    if (meth) {
        OPENSSL_free(meth);
    }
}

int bssl_rsa_set_priv_meth(RSA_METHOD *meth,
                           int (*sign_raw)(RSA *rsa, size_t *out_len,
                                           uint8_t *out, size_t max_out,
                                           const uint8_t *in, size_t in_len,
                                           int padding),
                           int (*decrypt)(RSA *rsa, size_t *out_len,
                                          uint8_t *out, size_t max_out,
                                          const uint8_t *in, size_t in_len,
                                          int padding))
{
    if (!meth || !sign_raw || !decrypt) {
        return 0;
    }

    meth->common.is_static = 1;
    meth->sign_raw = sign_raw;
    meth->decrypt = decrypt;

    return 1;
}

/* Copy from OpenSSL or BoringSSL  because of these functions not exported
 * using OPENSSL_EXPORT  or not defined in BoringSSL
 */
#define RSA_PKCS1_PADDING_SIZE 11

static int rand_nonzero(uint8_t *out, size_t len) {
  if (!RAND_bytes(out, len)) {
    return 0;
  }

  for (size_t i = 0; i < len; i++) {
    while (out[i] == 0) {
      if (!RAND_bytes(out + i, 1)) {
        return 0;
      }
    }
  }

  return 1;
}

/* OpenSSL declaration
 *int RSA_padding_add_none(unsigned char *to, int tlen, const unsigned char *f,
 *                        int fl);
 * BoringSSL declaration
 *int RSA_padding_add_none(uint8_t *to, size_t to_len, const uint8_t *from,
 *                        size_t from_len);
 * Ported from boringssl/crypto/fipsmodule/rsa/padding.c
 */
int bssl_rsa_padding_add_none(uint8_t *to, size_t to_len, const uint8_t *from,
                              size_t from_len) {
    if (from_len > to_len) {
        return 0;
    }

    if (from_len < to_len) {
        return 0;
    }

    memcpy(to, from, from_len);
    return 1;
}

/* Ported from openssl/crypto/rsa/rsa_none.c */
int bssl_rsa_padding_check_none(unsigned char *to, int tlen,
                                const unsigned char *from, int flen, int num)
{

    if (flen > tlen) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE);
        return -1;
    }

    memset(to, 0, tlen - flen);
    memcpy(to + tlen - flen, from, flen);
    return tlen;
}

/* OpenSSL declaration
 *int RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen,
 *                                const unsigned char *f, int fl);
 * BoringSSL declaration
 *int RSA_padding_add_PKCS1_type_1(uint8_t *to, size_t to_len,
 *                                const uint8_t *from, size_t from_len);
 * Ported from boringssl/crypto/fipsmodule/rsa/padding.c
 */
int bssl_rsa_padding_add_pkcs1_type_1(uint8_t *to, size_t to_len,
                                      const uint8_t *from, size_t from_len) {
    /* See RFC 8017, section 9.2. */
    if (to_len < RSA_PKCS1_PADDING_SIZE) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_KEY_SIZE_TOO_SMALL);
        return 0;
    }

    if (from_len > to_len - RSA_PKCS1_PADDING_SIZE) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
        return 0;
    }

    to[0] = 0;
    to[1] = 1;
    memset(to + 2, 0xff, to_len - 3 - from_len);
    to[to_len - from_len - 1] = 0;
    memcpy(to + to_len - from_len, from, from_len);
    return 1;
}

/* OpenSSL declaration
 *int RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen,
 *                                  const unsigned char *f, int fl,
 *                                  int rsa_len);
 * BoringSSL declaration
 *int RSA_padding_check_PKCS1_type_1(uint8_t *out, size_t *out_len,
 *                                  size_t max_out, const uint8_t *from,
 *                                  size_t from_len);
 * Ported from openssl openssl/crypto/rsa/rsa_pk1.c but replace RSAerr by 
 * OPENSSL_PUT_ERROR
 */
int bssl_rsa_padding_check_pkcs1_type_1(unsigned char *to, int tlen,
                                        const unsigned char *from, int flen,
                                        int num)
{
    int i, j;
    const unsigned char *p;

    p = from;

    /*
     * The format is
     * 00 || 01 || PS || 00 || D
     * PS - padding string, at least 8 bytes of FF
     * D  - data.
     */

    if (num < RSA_PKCS1_PADDING_SIZE)
        return -1;

    /* Accept inputs with and without the leading 0-byte. */
    if (num == flen) {
        if ((*p++) != 0x00) {
            return -1;
        }
        flen--;
    }

    if ((num != (flen + 1)) || (*(p++) != 0x01)) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_BLOCK_TYPE_IS_NOT_01);
        return -1;
    }

    /* scan over padding data */
    j = flen - 1;               /* one for type. */
    for (i = 0; i < j; i++) {
        if (*p != 0xff) {       /* should decrypt to 0xff */
            if (*p == 0) {
                p++;
                break;
            } else {
                OPENSSL_PUT_ERROR(RSA, RSA_R_BAD_FIXED_HEADER_DECRYPT);
                return -1;
            }
        }
        p++;
    }

    if (i == j) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_NULL_BEFORE_BLOCK_MISSING);
        return -1;
    }

    if (i < 8) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_BAD_PAD_BYTE_COUNT);
        return -1;
    }
    i++;                        /* Skip over the '\0' */
    j -= i;
    if (j > tlen) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE);
        return -1;
    }
    memcpy(to, p, (unsigned int)j);

    return j;
}

/* OpenSSL declaration
 *int RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen,
 *                                const unsigned char *f, int fl);
 * BoringSSL declaration
 *int RSA_padding_add_PKCS1_type_2(uint8_t *to, size_t to_len,
 *                                const uint8_t *from, size_t from_len);
 * Ported from boringssl/crypto/fipsmodule/rsa/padding.c
 */
int bssl_rsa_padding_add_pkcs1_type_2(uint8_t *to, size_t to_len,
                                      const uint8_t *from, size_t from_len) {
    // See RFC 8017, section 7.2.1.
    if (to_len < RSA_PKCS1_PADDING_SIZE) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_KEY_SIZE_TOO_SMALL);
        return 0;
    }

    if (from_len > to_len - RSA_PKCS1_PADDING_SIZE) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        return 0;
    }

    to[0] = 0;
    to[1] = 2;

    size_t padding_len = to_len - 3 - from_len;
    if (!rand_nonzero(to + 2, padding_len)) {
        return 0;
    }

    to[2 + padding_len] = 0;
    memcpy(to + to_len - from_len, from, from_len);
    return 1;
}

/* Although OpenSSL or BoringSSL implemented parts of these functions ,
 * we still decide to not port them because it's pretty complex to port
 * Do nothing currently
 */
int bssl_rsa_padding_check_pkcs1_type_2(unsigned char *to, int tlen,
                                        const unsigned char *f, int fl,
                                        int rsa_len) { return 0; }

int bssl_rsa_padding_check_pkcs1_OAEP(unsigned char *to, int tlen,
                                      const unsigned char *f, int fl,
                                      int rsa_len, const unsigned char *p,
                                      int pl) { return 0; }

int bssl_rsa_padding_add_sslv23(unsigned char *to, int tlen,
                                const unsigned char *f, int fl)
                                { return 1; }

int bssl_rsa_padding_check_sslv23(unsigned char *to, int tlen,
                                  const unsigned char *f, int fl, int rsa_len)
                                  { return 0; }

int bssl_rsa_padding_add_x931(unsigned char *to, int tlen,
                              const unsigned char *f, int fl) { return 1; }

int bssl_rsa_padding_check_x931(unsigned char *to, int tlen,
                                const unsigned char *f, int fl, int rsa_len)
                                { return 0; }

void *bssl_openssl_malloc(size_t size) {
     void *addr = NULL;
     if ((addr = OPENSSL_malloc(size)) != NULL)
        memset(addr, 0, size);
     return addr;
}

EC_KEY_METHOD *bssl_ec_key_method_new(const EC_KEY_METHOD *meth)
{
    EC_KEY_METHOD *ret = OPENSSL_zalloc(sizeof(*meth));

    return ret;
}

void bssl_ec_key_method_free(EC_KEY_METHOD *meth)
{
    if (meth) {
        OPENSSL_free(meth);
    }
}

ECDSA_SIG *bssl_default_ecdsa_sign(const unsigned char *dgst,
                                   int dgst_len, const BIGNUM *in_kinv,
                                   const BIGNUM *in_r, EC_KEY *eckey)
{
    return ECDSA_do_sign(dgst, dgst_len, eckey);
}

#ifdef QAT_SW
int bssl_ecdsa_sign(const uint8_t *digest, size_t digest_len,
        uint8_t *sig, unsigned int *sig_len, EC_KEY *eckey)
{
    EC_KEY *default_eckey  = NULL;
    const EC_GROUP *ecgroup = NULL;
    int ret = 0;
    int type = 0;

    if (eckey && (ecgroup = EC_KEY_get0_group(eckey))) {
        type = EC_GROUP_get_curve_name(ecgroup);
    }

    default_eckey = EC_KEY_dup(eckey);
    if (!default_eckey) {
        return ret;
    }
    ret = ECDSA_sign(type, digest, digest_len, sig, sig_len, default_eckey);
    EC_KEY_free(default_eckey);
    return ret;
}
#endif /* QAT_SW */

int bssl_default_ecdsa_verify(const unsigned char *dgst, int dgst_len,
                              const ECDSA_SIG *sig, EC_KEY *eckey)
{
    return ECDSA_do_verify(dgst, dgst_len, sig, eckey);
}

void bssl_ecdsa_meth_set_do_sign(EC_KEY_METHOD *meth,
                                int (*sign)(const uint8_t *digest,
                                            size_t digest_len, uint8_t *sig,
                                            unsigned int *sig_len,
                                            EC_KEY *eckey))
{
    if (meth && sign) {
        meth->sign = sign;
        meth->common.is_static = 1;
    }
}

int bssl_private_key_method_update(EVP_PKEY *pkey)
{
    RSA_METHOD *rsa_method = NULL;
    ECDSA_METHOD *ec_method = NULL;
    EVP_PKEY *privkey = pkey;

    switch (EVP_PKEY_id(privkey)) {
        case EVP_PKEY_RSA:
            if (!(default_algorithm_conf_flags & BSSL_QAT_METHOD_RSA)) {
                return 1;
            }
            rsa_method = bssl_engine_get_rsa_method();
            if (!rsa_method || !rsa_method->sign_raw || !rsa_method->decrypt) {
                return 1;
            }

            privkey->pkey.rsa->meth->sign_raw = rsa_method->sign_raw;
            privkey->pkey.rsa->meth->decrypt = rsa_method->decrypt;
            break;
        case EVP_PKEY_EC:
            if (!(default_algorithm_conf_flags & BSSL_QAT_METHOD_ECDSA)) {
                return 1;
            }
            ec_method = bssl_engine_get_ecdsa_method();
            if (!ec_method || !ec_method->sign) {
                return 1;
            }
            privkey->pkey.ec->ecdsa_meth = ec_method;
            break;
        default:
            return 1;
    }

    return 0;
}

/* Port from openssl/crypto/engine/eng_fat.c */
static int bssl_int_def_cb(const char *alg, int len, void *arg)
{
    unsigned int *pflags = arg;

    if (alg == NULL)
        return 0;
    if (strncmp(alg, "RSA", len) == 0)
        *pflags |= BSSL_QAT_METHOD_RSA;
    else if (strncmp(alg, "EC", len) == 0) /* Only support ECDSA */
        *pflags |= BSSL_QAT_METHOD_ECDSA;
    else
        return 0; /* Not supported */

    return 1; /* Success */
}

/* Port from boringssl/crypto/conf/conf.c, since it not exported */
static int bssl_conf_parse_list(const char *list, char sep,
                                int remove_whitespace,
                                int (*list_cb)(const char *elem,
                                               int len, void *usr),
                                void *arg)
{
  int ret;
  const char *lstart, *tmpend, *p;

  if (list == NULL) {
    OPENSSL_PUT_ERROR(CONF, CONF_R_LIST_CANNOT_BE_NULL);
    return 0;
  }

  lstart = list;
  for (;;) {
    if (remove_whitespace) {
      while (*lstart && isspace((unsigned char)*lstart)) {
        lstart++;
      }
    }
    p = strchr(lstart, sep);
    if (p == lstart || !*lstart) {
      ret = list_cb(NULL, 0, arg);
    } else {
      if (p) {
        tmpend = p - 1;
      } else {
        tmpend = lstart + strlen(lstart) - 1;
      }
      if (remove_whitespace) {
        while (isspace((unsigned char)*tmpend)) {
          tmpend--;
        }
      }
      ret = list_cb(lstart, tmpend - lstart + 1, arg);
    }
    if (ret <= 0) {
      return ret;
    }
    if (p == NULL) {
      return 1;
    }
    lstart = p + 1;
  }
}

int bssl_qat_set_default_string(const char *def_list)
{
    return bssl_conf_parse_list(def_list, ',', 1, bssl_int_def_cb,
                                &default_algorithm_conf_flags);
}

void bssl_once(bssl_once_t *once, void (*init)(void))
{
  if (pthread_once(once, init) != 0) {
    abort();
  }
}
void bssl_ec_key_method_get_sign(EC_KEY_METHOD *meth, PFUNC_EC_SIGN *sig_func,
                                   PFUNC_EC_SIGN_SIG *sig_sig_func)
{
    if (meth) {
        if (sig_func) {
            *sig_func = meth->sign;
        }
    }
    if (sig_sig_func) {
        *sig_sig_func = bssl_default_ecdsa_sign;
    }
}

#endif /* QAT_BORINGSSL */
