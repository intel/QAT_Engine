/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2017 Intel Corporation.
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
 * @file qat_prf.c
 *
 * This file provides an implementaion of the PRF operations for an
 * OpenSSL engine
 *
 *****************************************************************************/
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <pthread.h>
#include <string.h>
#include <signal.h>

#include "openssl/ossl_typ.h"
#include "openssl/async.h"
#include "openssl/kdf.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "qat_prf.h"
#include "qat_utils.h"
#include "qat_asym_common.h"
#include "e_qat.h"
#include "qat_callback.h"
#include "qat_polling.h"
#include "qat_events.h"

#include "e_qat_err.h"

#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "cmn_mem_drv_inf.h"
#endif

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_key.h"

#ifdef OPENSSL_ENABLE_QAT_PRF
# ifdef OPENSSL_DISABLE_QAT_PRF
#  undef OPENSSL_DISABLE_QAT_PRF
# endif
#endif

/* These limits are based on QuickAssist limits.
 * OpenSSL is more generous but better to restrict and fail
 * early on here if they are exceeded rather than later on
 * down in the driver.
 */
#define QAT_TLS1_PRF_SECRET_MAXBUF 512
#define QAT_TLS1_PRF_SEED_MAXBUF 64
#define QAT_TLS1_PRF_LABEL_MAXBUF 136

/* PRF nid */
int qat_prf_nids[] = {
    EVP_PKEY_TLS1_PRF
};

#ifndef OPENSSL_DISABLE_QAT_PRF
/* QAT TLS  pkey context structure */
typedef struct {
    /* Buffer of concatenated seeds from seed2 to seed5 data */
    unsigned char seed[QAT_TLS1_PRF_SEED_MAXBUF];
    size_t seedlen;
    unsigned char *userLabel;
    size_t userLabel_len;
    /* Digest to use for PRF */
    const EVP_MD *md;
    /* Secret value to use for PRF */
    unsigned char *sec;
    size_t seclen;
} QAT_TLS1_PRF_CTX;

/* Function Declarations */
static int qat_tls1_prf_init(EVP_PKEY_CTX *ctx);
static void qat_prf_cleanup(EVP_PKEY_CTX *ctx);
static int qat_prf_tls_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                                size_t *olen);
static int qat_tls1_prf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
#endif /* OPENSSL_DISABLE_QAT_PRF */

static EVP_PKEY_METHOD *_hidden_prf_pmeth = NULL;

static EVP_PKEY_METHOD *qat_prf_pmeth(void)
{
#ifdef OPENSSL_DISABLE_QAT_PRF
    const EVP_PKEY_METHOD *current_prf_pmeth = NULL;
#endif
    if(_hidden_prf_pmeth)
        return _hidden_prf_pmeth;
#ifdef OPENSSL_DISABLE_QAT_PRF
    if ((current_prf_pmeth = EVP_PKEY_meth_find(EVP_PKEY_TLS1_PRF)) == NULL) {
        QATerr(QAT_F_QAT_PRF_PMETH, ERR_R_INTERNAL_ERROR);
        return NULL;
    }
#endif
    if ((_hidden_prf_pmeth =
         EVP_PKEY_meth_new(EVP_PKEY_TLS1_PRF, 0)) == NULL) {
        QATerr(QAT_F_QAT_PRF_PMETH, ERR_R_INTERNAL_ERROR);
        return NULL;
    }
#ifdef OPENSSL_DISABLE_QAT_PRF
    EVP_PKEY_meth_copy(_hidden_prf_pmeth, current_prf_pmeth);
#else
    EVP_PKEY_meth_set_init(_hidden_prf_pmeth, qat_tls1_prf_init);
    EVP_PKEY_meth_set_cleanup(_hidden_prf_pmeth, qat_prf_cleanup);
    EVP_PKEY_meth_set_derive(_hidden_prf_pmeth, NULL,
                             qat_prf_tls_derive);
    EVP_PKEY_meth_set_ctrl(_hidden_prf_pmeth, qat_tls1_prf_ctrl, NULL);
#endif
    return _hidden_prf_pmeth;
}

/******************************************************************************
* function:
*         qat_PRF_pkey_methods(ENGINE *e,
*                              const EVP_PKEY_METHOD **pmeth,
*                              const int **nids,
*                              int nid)
*
* @param e      [IN] - OpenSSL engine pointer
* @param pmeth  [IN] - PRF methods structure pointer
* @param nids   [IN] - PRF functions nids
* @param nid    [IN] - PRF operation id
*
* description:
*   Qat engine digest operations registrar
******************************************************************************/
int qat_PRF_pkey_methods(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                         const int **nids, int nid)
{
    if (pmeth == NULL) {
        *nids = qat_prf_nids;
        return 1;
    }

    if (pmeth)
        *pmeth = qat_prf_pmeth();

    return 1;
}

#ifndef OPENSSL_DISABLE_QAT_PRF
/******************************************************************************
* function:
*        qat_tls1_prf_init(EVP_PKEY_CTX *ctx)
*
* @param ctx   [IN] - PKEY Context structure pointer
*
* @param       [OUT] - Status
*
* description:
*   Qat PRF init function
******************************************************************************/
int qat_tls1_prf_init(EVP_PKEY_CTX *ctx)
{
    QAT_TLS1_PRF_CTX *qat_prf_ctx = NULL;

    qat_prf_ctx = OPENSSL_zalloc(sizeof(*qat_prf_ctx));
    if (qat_prf_ctx == NULL) {
        WARN("Cannot allocate qat_prf_ctx\n");
        return 0;
    }

    EVP_PKEY_CTX_set_data(ctx, qat_prf_ctx);
    return 1;
}

/******************************************************************************
* function:
*         qat_prf_cleanup(EVP_PKEY_CTX *ctx)
*
* @param ctx    [IN] - PKEY Context structure pointer
*
* description:
*   Clear the QAT specific data stored in qat_prf_ctx
******************************************************************************/
void qat_prf_cleanup(EVP_PKEY_CTX *ctx)
{
    QAT_TLS1_PRF_CTX *qat_prf_ctx = NULL;

    if (ctx == NULL) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL \n");
        return;
    }

    qat_prf_ctx = (QAT_TLS1_PRF_CTX *) EVP_PKEY_CTX_get_data(ctx);
    if (qat_prf_ctx == NULL) {
        WARN("qat_prf_ctx is NULL\n");
        return;
    }

    if (qat_prf_ctx->sec != NULL) {
        OPENSSL_cleanse(qat_prf_ctx->sec, qat_prf_ctx->seclen);
        qaeCryptoMemFree(qat_prf_ctx->sec);
    }
    if (qat_prf_ctx->seedlen)
        OPENSSL_cleanse(qat_prf_ctx->seed, qat_prf_ctx->seedlen);
    if (qat_prf_ctx->userLabel != NULL)
        qaeCryptoMemFree(qat_prf_ctx->userLabel);
    OPENSSL_free(qat_prf_ctx);
    EVP_PKEY_CTX_set_data(ctx, NULL);
}

/******************************************************************************
* function:
*        qat_tls1_prf_ctrl(EVP_PKEY_CTX *ctx,
*                          int type,
*                          int p1,
*                          void *p2)
*
* @param ctx    [IN] - PKEY Context structure pointer
* @param type   [IN] - Type
* @param p1     [IN] - Length/Size
* @param *p2    [IN] - Data
*
* @param       [OUT] - Status
*
* description:
*   Qat PRF control function
******************************************************************************/
int qat_tls1_prf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    QAT_TLS1_PRF_CTX *qat_prf_ctx = (QAT_TLS1_PRF_CTX *) EVP_PKEY_CTX_get_data(ctx);
    if (qat_prf_ctx == NULL) {
         WARN("qat_prf_ctx cannot be NULL\n");
         return 0;
    }

    switch (type) {
    case EVP_PKEY_CTRL_TLS_MD:
        qat_prf_ctx->md = p2;
        return 1;

    case EVP_PKEY_CTRL_TLS_SECRET:
        if (p1 < 0 || p1 > QAT_TLS1_PRF_SECRET_MAXBUF || p2 == NULL) {
            WARN("Either p1 is invalid or p2 is NULL\n");
            return 0;
        }
        if (qat_prf_ctx->sec != NULL) {
            OPENSSL_cleanse(qat_prf_ctx->sec, qat_prf_ctx->seclen);
            qaeCryptoMemFree(qat_prf_ctx->sec);
            qat_prf_ctx->seclen = 0;
        }
        OPENSSL_cleanse(qat_prf_ctx->seed, qat_prf_ctx->seedlen);
        qat_prf_ctx->seedlen = 0;
        qat_prf_ctx->userLabel_len = 0;

        /*-
         * Allocate and copy the secret data
         * In case of zero length secret key (for example EXP cipher),
         * allocate minimum byte aligned size buffer when common memory
         * driver is used.
         */
        qat_prf_ctx->sec = copyAllocPinnedMemory(p2, p1 ? p1 : 1,
                                                 __FILE__, __LINE__);
        if (qat_prf_ctx->sec == NULL) {
            WARN("secret data malloc failed\n");
            return 0;
        }
        qat_prf_ctx->seclen = p1;
        return 1;

    case EVP_PKEY_CTRL_TLS_SEED:
        if (p1 == 0 || p2 == NULL)
            return 1;
        if (qat_prf_ctx->userLabel_len == 0) {
            if (p1 < 0 || p1 > QAT_TLS1_PRF_LABEL_MAXBUF) {
                WARN("userLabel p1 %d is out of range\n", p1);
                return 0;
            } else {
                if (qat_prf_ctx->userLabel != NULL) {
                    qaeCryptoMemFree(qat_prf_ctx->userLabel);
                }
                qat_prf_ctx->userLabel = copyAllocPinnedMemory(p2, p1,
                                                               __FILE__, __LINE__);
                if (qat_prf_ctx->userLabel == NULL) {
                    WARN("userLabel malloc failed\n");
                    return 0;
                }
                qat_prf_ctx->userLabel_len = p1;
            }
        } else {
            if (p1 < 0 || p1 > (QAT_TLS1_PRF_SEED_MAXBUF - qat_prf_ctx->seedlen)) {
                WARN("p1 %d is out of range\n", p1);
                return 0;
            } else {
                memcpy(qat_prf_ctx->seed + qat_prf_ctx->seedlen, p2, p1);
                qat_prf_ctx->seedlen += p1;
            }
        }
        return 1;
    default:
        WARN("Invalid type %d\n", type);
        return -2;

    }
}

/******************************************************************************
 * function:
 *         void qat_prf_cb(
 *                   void *pCallbackTag,
 *                   CpaStatus status,
 *                   void *pOpdata,
 *                   CpaFlatBuffer *pOut)
 *
 * @param pCallbackTag   [IN]  - Pointer to user data
 * @param status         [IN]  - Status of the operation
 * @param pOpData        [IN]  - Pointer to operation data of the request
 * @param out            [IN]  - Pointer to the output buffer
 *
 * description:
 *   Callback to indicate the completion of PRF
 ******************************************************************************/
void qat_prf_cb(void *pCallbackTag, CpaStatus status,
                     void *pOpData, CpaFlatBuffer * pOut)
{
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, CPA_TRUE);
}


/******************************************************************************
* function:
*         qat_get_hash_algorithm(
*                   PRF *qat_prf_ctx
*                   CpaCySymHashAlgorithm *hash_algorithm)
*
* @param qat_prf_ctx    [IN]  - PRF context
* @param hash_algorithm [OUT] - Ptr to hash algorithm in CPA format
*
* description:
*   Retrieve the hash algorithm from the prf context and convert it to
*   the CPA format
******************************************************************************/
static int qat_get_hash_algorithm(QAT_TLS1_PRF_CTX * qat_prf_ctx,
                                  CpaCySymHashAlgorithm * hash_algorithm)
{
    if (qat_prf_ctx == NULL || hash_algorithm == NULL) {
        WARN("Either qat_prf_ctx %p or  hash_algorithm %p is NULL\n",
              qat_prf_ctx, hash_algorithm);
        return 0;
    }

    const EVP_MD *md = qat_prf_ctx->md;
    if (md == NULL) {
        WARN("md is NULL.\n");
        return 0;
    }

    switch (EVP_MD_type(md)) {
    case NID_sha224:
        *hash_algorithm = CPA_CY_SYM_HASH_SHA224;
        break;
    case NID_sha256:
        *hash_algorithm = CPA_CY_SYM_HASH_SHA256;
        break;
    case NID_sha384:
        *hash_algorithm = CPA_CY_SYM_HASH_SHA384;
        break;
    case NID_sha512:
        *hash_algorithm = CPA_CY_SYM_HASH_SHA512;
        break;
    case NID_md5:
        *hash_algorithm = CPA_CY_SYM_HASH_MD5;
        break;
    default:
        WARN("unsupported PRF hash type\n");
        return 0;
    }

    return 1;
}

/******************************************************************************
* function:
*         build_tls_prf_op_data(
*                   PRF *qat_prf_ctx,
*                   CpaCyKeyGenTlsOpData *prf_op_data)
*
* @param qat_prf_ctx    [IN]  - PRF context
* @param prf_op_data    [OUT] - Ptr to TlsOpData used as destination
*
* description:
*   Build the TlsOpData based on the values stored in the PRF context
*   Note: prf_op_data must be allocated outside this function
******************************************************************************/
static int build_tls_prf_op_data(QAT_TLS1_PRF_CTX * qat_prf_ctx,
                                 CpaCyKeyGenTlsOpData * prf_op_data)
{
    if (qat_prf_ctx == NULL || prf_op_data == NULL) {
        WARN("Either qat_prf_ctx %p or prf_op_data %p is NULL\n", qat_prf_ctx, prf_op_data);
        return 0;
    }

    prf_op_data->secret.pData = (Cpa8U *) qat_prf_ctx->sec;
    prf_op_data->secret.dataLenInBytes = qat_prf_ctx->seclen;

    /*-
     * The label is stored in userLabel as a string Conversion from string to CPA
     * constant
     */
    const void *label = qat_prf_ctx->userLabel;
    DEBUG("Value of label = %s\n", (char *)label);

    prf_op_data->userLabel.pData = NULL;
    prf_op_data->userLabel.dataLenInBytes = 0;
    prf_op_data->seed.pData = NULL;

    if (0 ==
        strncmp(label, TLS_MD_MASTER_SECRET_CONST,
                TLS_MD_MASTER_SECRET_CONST_SIZE)) {
        prf_op_data->tlsOp = CPA_CY_KEY_SSL_OP_MASTER_SECRET_DERIVE;
    } else if (0 ==
               strncmp(label, TLS_MD_KEY_EXPANSION_CONST,
                       TLS_MD_KEY_EXPANSION_CONST_SIZE)) {
        prf_op_data->tlsOp = CPA_CY_KEY_TLS_OP_KEY_MATERIAL_DERIVE;
    } else if (0 ==
               strncmp(label, TLS_MD_CLIENT_FINISH_CONST,
                       TLS_MD_CLIENT_FINISH_CONST_SIZE)) {
        prf_op_data->tlsOp = CPA_CY_KEY_TLS_OP_CLIENT_FINISHED_DERIVE;
    } else if (0 ==
               strncmp(label, TLS_MD_SERVER_FINISH_CONST,
                       TLS_MD_SERVER_FINISH_CONST_SIZE)) {
        prf_op_data->tlsOp = CPA_CY_KEY_TLS_OP_SERVER_FINISHED_DERIVE;
    } else {
        /* Allocate and copy the user label contained in userLabel */
        /* TODO we must test this case to see if it works OK */
        DEBUG("Using USER_DEFINED label = %s\n", (char*)label);
        prf_op_data->tlsOp = CPA_CY_KEY_TLS_OP_USER_DEFINED;
        prf_op_data->userLabel.pData = (Cpa8U *) qat_prf_ctx->userLabel;
        prf_op_data->userLabel.dataLenInBytes = qat_prf_ctx->userLabel_len;
    }

    /*-
     * The seed for prf_op_data is obtained by concatenating seed2...5 in the
     * context.
     * The client and server randoms are reversed on the QAT API for Key
     * Derive. This is not be a problem because OpenSSL calls the function
     * with the variables in the correct order
     */
    if (qat_prf_ctx->seedlen) {
        prf_op_data->seed.pData = copyAllocPinnedMemory(qat_prf_ctx->seed,
                                                        qat_prf_ctx->seedlen,
                                                        __FILE__, __LINE__);
        if (prf_op_data->seed.pData == NULL) {
            /* On failure WARN and Error are flagged at the next level up.*/
            return 0;
        }

        prf_op_data->seed.dataLenInBytes = qat_prf_ctx->seedlen;
    }

    return 1;
}

/******************************************************************************
* function:
*         qat_prf_tls_derive(
*                   QAT_TLS1_PRF_CTX *qat_prf_ctx,
*                   unsigned char *key,
*                   size_t *olen)
*
*
* @param qat_prf_ctx    [IN]  - PRF context
* @param key            [OUT] - Ptr to the key that will be generated
* @param olen           [IN]  - Length of the key
*
* description:
*   PRF derive function for TLS case
******************************************************************************/
int qat_prf_tls_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                              size_t *olen)
{
    int ret = 0, job_ret = 0;
    CpaCyKeyGenTlsOpData prf_op_data;
    CpaFlatBuffer *generated_key = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    QAT_TLS1_PRF_CTX *qat_prf_ctx = NULL;

    memset(&prf_op_data, 0, sizeof(CpaCyKeyGenTlsOpData));

    if (NULL == ctx || NULL == key || NULL == olen) {
        WARN("Either ctx %p, key %p or olen %p is NULL\n", ctx, key, olen);
        QATerr(QAT_F_QAT_PRF_TLS_DERIVE, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    qat_prf_ctx = (QAT_TLS1_PRF_CTX *) EVP_PKEY_CTX_get_data(ctx);
    if (qat_prf_ctx == NULL) {
        WARN("qat_prf_ctx is NULL\n");
        QATerr(QAT_F_QAT_PRF_TLS_DERIVE, ERR_R_INTERNAL_ERROR);
        return ret;
    }

    /* ---- Hash algorithm ---- */
    CpaCySymHashAlgorithm hash_algo = CPA_CY_SYM_HASH_NONE;

    /*
     * Only required for TLS1.2 as previous versions always use MD5 and SHA-1
     */
    if (EVP_MD_type(qat_prf_ctx->md) != NID_md5_sha1) {
        if (!qat_get_hash_algorithm(qat_prf_ctx, &hash_algo)) {
            WARN("Failed to get hash algorithm\n");
            QATerr(QAT_F_QAT_PRF_TLS_DERIVE, ERR_R_INTERNAL_ERROR);
            return ret;
        }
    }

    /* ---- Tls Op Data ---- */
    if (!build_tls_prf_op_data(qat_prf_ctx, &prf_op_data)) {
        WARN("Error building TlsOpdata\n");
        QATerr(QAT_F_QAT_PRF_TLS_DERIVE, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* ---- Generated Key ---- */
    int key_length = *olen;
    prf_op_data.generatedKeyLenInBytes = key_length;

    generated_key =
        (CpaFlatBuffer *) qaeCryptoMemAlloc(sizeof(CpaFlatBuffer), __FILE__,
                                            __LINE__);
    if (NULL == generated_key) {
        WARN("Failed to allocate memory for generated_key\n");
        QATerr(QAT_F_QAT_PRF_TLS_DERIVE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    generated_key->pData =
        (Cpa8U *) qaeCryptoMemAlloc(key_length, __FILE__, __LINE__);
    if (NULL == generated_key->pData) {
        WARN("Failed to allocate memory for generated_key data\n");
        QATerr(QAT_F_QAT_PRF_TLS_DERIVE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    generated_key->dataLenInBytes = key_length;

    /* ---- Perform the operation ---- */
    op_done_t op_done;
    int qatPerformOpRetries = 0;
    int iMsgRetry = getQatMsgRetryCount();
    unsigned long int ulPollInterval = getQatPollInterval();
    CpaInstanceHandle instance_handle = NULL;

    DUMP_PRF_OP_DATA(prf_op_data);

    instance_handle = get_next_inst();
    if (qat_use_signals()) {
        qat_atomic_inc(num_requests_in_flight);
        if (pthread_kill(timer_poll_func_thread, SIGUSR1) != 0) {
            WARN("pthread_kill error\n");
            QATerr(QAT_F_QAT_PRF_TLS_DERIVE, ERR_R_INTERNAL_ERROR);
            qat_atomic_dec(num_requests_in_flight);
            goto err;
        }
    }
    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_PRF_TLS_DERIVE, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            qat_atomic_dec_if_polling(num_requests_in_flight);
            goto err;
        }
    }

    do {
        if (NULL == (instance_handle = get_next_inst())) {
            WARN("Failed to get an instance\n");
            QATerr(QAT_F_QAT_PRF_TLS_DERIVE, ERR_R_INTERNAL_ERROR);
            if (op_done.job != NULL) {
                qat_clear_async_event_notification();
            }
            qat_cleanup_op_done(&op_done);
            qat_atomic_dec_if_polling(num_requests_in_flight);
            goto err;
        }

        DUMP_KEYGEN_TLS(instance_handle, generated_key);
        /* Call the function of CPA according the to the version of TLS */
        if (EVP_MD_type(qat_prf_ctx->md) != NID_md5_sha1) {
            DEBUG("Calling cpaCyKeyGenTls2 \n");
            status =
                cpaCyKeyGenTls2(instance_handle, qat_prf_cb,
                                &op_done, &prf_op_data, hash_algo,
                                generated_key);
        } else {
            DEBUG("Calling cpaCyKeyGenTls \n");
            status =
                cpaCyKeyGenTls(instance_handle, qat_prf_cb, &op_done,
                               &prf_op_data, generated_key);
        }

        if (status == CPA_STATUS_RETRY) {
            if (op_done.job == NULL) {
                usleep(ulPollInterval +
                       (qatPerformOpRetries %
                        QAT_RETRY_BACKOFF_MODULO_DIVISOR));
                qatPerformOpRetries++;
                if (iMsgRetry != QAT_INFINITE_MAX_NUM_RETRIES) {
                    if (qatPerformOpRetries >= iMsgRetry) {
                        WARN("No. of retries exceeded max retry : %d\n", iMsgRetry);
                        break;
                    }
                }
            } else {
                if ((qat_wake_job(op_done.job, 0) == 0) ||
                    (qat_pause_job(op_done.job, 0) == 0)) {
                    WARN("qat_wake_job or qat_pause_job failed\n");
                    break;
                }
            }
        }

    } while (status == CPA_STATUS_RETRY);

    if (CPA_STATUS_SUCCESS != status) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        QATerr(QAT_F_QAT_PRF_TLS_DERIVE, ERR_R_INTERNAL_ERROR);
        if (op_done.job != NULL) {
            qat_clear_async_event_notification();
        }
        qat_cleanup_op_done(&op_done);
        qat_atomic_dec_if_polling(num_requests_in_flight);
        goto err;
    }

    do {
        if(op_done.job != NULL) {
            /* If we get a failure on qat_pause_job then we will
               not flag an error here and quit because we have
               an asynchronous request in flight.
               We don't want to start cleaning up data
               structures that are still being used. If
               qat_pause_job fails we will just yield and
               loop around and try again until the request
               completes and we can continue. */
            if ((job_ret = qat_pause_job(op_done.job, 0)) == 0)
                pthread_yield();
        } else {
            pthread_yield();
        }
    }
    while (!op_done.flag ||
           QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DUMP_KEYGEN_TLS_OUTPUT(generated_key);
    qat_cleanup_op_done(&op_done);
    qat_atomic_dec_if_polling(num_requests_in_flight);

    if (op_done.verifyResult != CPA_TRUE) {
        WARN("Verification of result failed\n");
        QATerr(QAT_F_QAT_PRF_TLS_DERIVE, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    DUMPL("Generated key", generated_key->pData, key_length);
    memcpy(key, generated_key->pData, key_length);
    ret = 1;

 err:

    /* Free the memory  */
    if (prf_op_data.seed.pData) {
         OPENSSL_cleanse(prf_op_data.seed.pData, prf_op_data.seed.dataLenInBytes);
         qaeCryptoMemFree(prf_op_data.seed.pData);
    }
    if (NULL != generated_key) {
        if (NULL != generated_key->pData) {
            OPENSSL_cleanse(generated_key->pData, key_length);
            qaeCryptoMemFree(generated_key->pData);
        }
        qaeCryptoMemFree(generated_key);
    }
    return ret;
}
#endif /* OPENSSL_DISABLE_QAT_PRF */
