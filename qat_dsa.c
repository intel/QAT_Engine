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
 * @file qat_dsa.c
 *
 * This file provides an implementation of DSA operations for an OpenSSL
 * engine
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <pthread.h>
#include <signal.h>
#include "qat_dsa.h"
#include "qat_utils.h"
#include "cpa_cy_dsa.h"
#include "qat_asym_common.h"

#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_dh.h"
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

#include <string.h>
#include <unistd.h>

#ifdef OPENSSL_ENABLE_QAT_DSA
# ifdef OPENSSL_DISABLE_QAT_DSA
#  undef OPENSSL_DISABLE_QAT_DSA
# endif
#endif

#ifndef OPENSSL_DISABLE_QAT_DSA
static DSA_SIG *qat_dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa);
static int qat_dsa_do_verify(const unsigned char *dgst, int dgst_len,
                             DSA_SIG *sig, DSA *dsa);
static int qat_dsa_sign_setup(DSA *dsa, BN_CTX *ctx_in,
                              BIGNUM **kinvp, BIGNUM **rp);
static int qat_dsa_bn_mod_exp(DSA *dsa, BIGNUM *r, const BIGNUM *a, const
                              BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                              BN_MONT_CTX *m_ctx);
#endif

/* Qat DSA method structure declaration. */
static DSA_METHOD *qat_dsa_method = NULL;

DSA_METHOD *qat_get_DSA_methods(void)
{
#ifndef OPENSSL_DISABLE_QAT_DSA
    int res = 1;
#endif

    if (qat_dsa_method != NULL)
        return qat_dsa_method;

#ifndef OPENSSL_DISABLE_QAT_DSA
    if ((qat_dsa_method = DSA_meth_new("QAT DSA method", 0)) == NULL) {
        WARN("Failed to allocate DSA methods\n");
        QATerr(QAT_F_QAT_GET_DSA_METHODS, QAT_R_ALLOC_QAT_DSA_METH_FAILURE);
        return NULL;
    }

    res &= DSA_meth_set_sign(qat_dsa_method, qat_dsa_do_sign);
    res &= DSA_meth_set_sign_setup(qat_dsa_method, qat_dsa_sign_setup);
    res &= DSA_meth_set_verify(qat_dsa_method, qat_dsa_do_verify);
    res &= DSA_meth_set_bn_mod_exp(qat_dsa_method, qat_dsa_bn_mod_exp);

    if (res == 0) {
        WARN("Failed to set DSA methods\n");
        QATerr(QAT_F_QAT_GET_DSA_METHODS, QAT_R_SET_QAT_DSA_METH_FAILURE);
        return NULL;
    }
#else
    qat_dsa_method = (DSA_METHOD *)DSA_get_default_method();
#endif

    return qat_dsa_method;
}

void qat_free_DSA_methods(void)
{
#ifndef OPENSSL_DISABLE_QAT_DSA
    if (qat_dsa_method != NULL) {
        DSA_meth_free(qat_dsa_method);
        qat_dsa_method = NULL;
    } else {
        WARN("Failed to free DSA methods\n");
        QATerr(QAT_F_QAT_FREE_DSA_METHODS, QAT_R_FREE_QAT_DSA_METH_FAILURE);
    }
#endif
}


#ifndef OPENSSL_DISABLE_QAT_DSA
/*
 * DSA range Supported in QAT {L,N} = {1024, 160}, {2048, 224} {2048, 256},
 * {3072, 256}
 */
int dsa_qat_range[4][2] = {
    {1024, 160},
    {2048, 224},
    {2048, 256},
    {3072, 256}
};

/*
 * DSA range check is performed so that if the sizes of P and Q are not in
 * the range supported by QAT engine then fall back to software
 */

int dsa_range_check(int plen, int qlen)
{
    int i, j, range = 0;

    for (i = 0, j = 0; i < 4; i++) {
        if ((plen == dsa_qat_range[i][j])
            && (qlen == dsa_qat_range[i][j + 1])) {
            range = 1;
            break;
        }
    }
    return range;
}

/* Callback to indicate QAT completion of DSA Sign */
void qat_dsaSignCallbackFn(void *pCallbackTag, CpaStatus status,
                           void *pOpData, CpaBoolean bDsaSignStatus,
                           CpaFlatBuffer * pResultR, CpaFlatBuffer * pResultS)
{
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, bDsaSignStatus);
}

/* Callback to indicate QAT completion of DSA Verify */
void qat_dsaVerifyCallbackFn(void *pCallbackTag, CpaStatus status,
                             void *pOpData, CpaBoolean bDsaVerifyStatus)
{
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, bDsaVerifyStatus);
}

/******************************************************************************
* function:
*         qat_dsa_bn_mod_exp(DSA *dsa, BIGNUM *r, const BIGNUM *a,
*                            const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
*                            BN_MONT_CTX *m_ctx)
*
* @param dsa   [IN] - Pointer to a OpenSSL DSA struct.
* @param r     [IN] - Result bignum of mod_exp
* @param a     [IN] - Base used for mod_exp
* @param p     [IN] - Exponent used for mod_exp
* @param m     [IN] - Modulus used for mod_exp
* @param ctx   [IN] - EVP context.
* @param m_ctx [IN] - EVP context for Montgomery multiplication.
*
* description:
*   Overridden modular exponentiation function used in DSA.
*
******************************************************************************/
int qat_dsa_bn_mod_exp(DSA *dsa, BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    DEBUG("- Started\n");
    CRYPTO_QAT_LOG("AU - %s\n", __func__);
    return qat_mod_exp(r, a, p, m);
}

/******************************************************************************
* function:
*         qat_dsa_do_sign(const unsigned char *dgst, int dlen,
*                         DSA *dsa)
*
* description:
*   Generate DSA R and S Signatures.
******************************************************************************/
DSA_SIG *qat_dsa_do_sign(const unsigned char *dgst, int dlen,
                         DSA *dsa)
{
    BIGNUM *r = NULL, *s = NULL;
    BIGNUM *k = NULL;
    const BIGNUM *p = NULL, *q = NULL;
    const BIGNUM *g = NULL;
    const BIGNUM *pub_key = NULL, *priv_key = NULL;
    BN_CTX *ctx = NULL;
    DSA_SIG *sig = NULL;
    CpaFlatBuffer *pResultR = NULL;
    CpaFlatBuffer *pResultS = NULL;
    CpaInstanceHandle instance_handle;
    CpaCyDsaRSSignOpData *opData = NULL;
    CpaBoolean bDsaSignStatus;
    CpaStatus status;
    size_t buflen;
    op_done_t op_done;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    const DSA_METHOD *default_dsa_method = DSA_OpenSSL();
    int i = 0, job_ret = 0;

    DEBUG("- Started\n");

    if (dsa == NULL || dgst == NULL) {
         WARN("Either dsa %p or dgst %p are NULL\n", dsa, dgst);
         QATerr(QAT_F_QAT_DSA_DO_SIGN, QAT_R_DSA_DGST_NULL);
         return NULL;
    }

    DSA_get0_pqg(dsa, &p, &q, &g);

    if (p == NULL || q == NULL || g == NULL) {
         WARN("Either p %p, q %p, or g %p are NULL\n", p, q, g);
         QATerr(QAT_F_QAT_DSA_DO_SIGN, QAT_R_P_Q_G_NULL);
         return sig;
    }

    i = BN_num_bits(q);

    /*
     * If the sizes of P and Q are not in the range supported by QAT engine
     * then fall back to software
     */

    if (!dsa_range_check(BN_num_bits(p), i)) {
        if (default_dsa_method == NULL) {
            WARN("Failed to get default_dsa_method for bits p = %d & q = %d\n",
                  BN_num_bits(p), i);
            QATerr(QAT_F_QAT_DSA_DO_SIGN, QAT_R_SW_METHOD_NULL);
            return NULL;
        }
        return DSA_meth_get_sign(default_dsa_method)(dgst, dlen, dsa);
    }

    opData = (CpaCyDsaRSSignOpData *)
        OPENSSL_malloc(sizeof(CpaCyDsaRSSignOpData));
    if (opData == NULL) {
        WARN("Failed to allocate memory for opData\n");
        QATerr(QAT_F_QAT_DSA_DO_SIGN, QAT_R_OPDATA_MALLOC_FAILURE);
        return sig;
    }

    memset(opData, 0, sizeof(CpaCyDsaRSSignOpData));

    if ((ctx = BN_CTX_new()) == NULL) {
        WARN("Failed to allocate memory for ctx\n");
        QATerr(QAT_F_QAT_DSA_DO_SIGN, QAT_R_CTX_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);

    if ((k = BN_CTX_get(ctx)) == NULL) {
        WARN("Failed  to allocate k\n");
        QATerr(QAT_F_QAT_DSA_DO_SIGN, QAT_R_K_ALLOCATE_FAILURE);
        goto err;
    }

    buflen = BN_num_bytes(q);

    if (dlen > buflen)
        /*
         * if the digest length is greater than the size of q use the
         * BN_num_bits(q) leftmost bits of the digest, see fips 186-3,
         * 4.2
         */
        dlen = buflen;
    do {
        if (!BN_rand_range(k, q)) {
            WARN("Failed to generate random number for the range %d\n", dlen);
            QATerr(QAT_F_QAT_DSA_DO_SIGN, QAT_R_K_RAND_GENERATE_FAILURE);
            goto err;
        }
    }
    while (BN_is_zero(k));

    pResultR = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (!pResultR) {
        WARN("Failed to allocate memory for pResultR\n");
        QATerr(QAT_F_QAT_DSA_DO_SIGN, QAT_R_PRESULTR_MALLOC_FAILURE);
        goto err;
    }
    pResultR->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (!pResultR->pData) {
        WARN("Failed to allocate memory for pResultR data\n");
        QATerr(QAT_F_QAT_DSA_DO_SIGN, QAT_R_PRESULTR_PDATA_MALLOC_FAILURE);
        goto err;
    }
    pResultR->dataLenInBytes = (Cpa32U) buflen;
    pResultS = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (!pResultS) {
        WARN("Failed to allocate memory for pResultS\n");
        QATerr(QAT_F_QAT_DSA_DO_SIGN, QAT_R_PRESULTS_MALLOC_FAILURE);
        goto err;
    }
    pResultS->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (!pResultS->pData) {
        WARN("Failed to allocate memory for pResultS data\n");
        QATerr(QAT_F_QAT_DSA_DO_SIGN, QAT_R_PRESULTS_PDATA_MALLOC_FAILURE);
        goto err;
    }
    pResultS->dataLenInBytes = (Cpa32U) buflen;

    DSA_get0_key(dsa, &pub_key, &priv_key);

    if (priv_key == NULL) {
        WARN("Unable to get private key\n");
        QATerr(QAT_F_QAT_DSA_DO_SIGN, QAT_R_PRIV_KEY_NULL);
        goto err;
    }

    if ((qat_BN_to_FB(&(opData->P), p) != 1) ||
        (qat_BN_to_FB(&(opData->Q), q) != 1) ||
        (qat_BN_to_FB(&(opData->G), g) != 1) ||
        (qat_BN_to_FB(&(opData->X), priv_key) != 1) ||
        (qat_BN_to_FB(&(opData->K), k) != 1)) {
        WARN("Failed to convert p, q, g, priv_key or k to a flat buffer\n");
        QATerr(QAT_F_QAT_DSA_DO_SIGN, QAT_R_P_Q_G_X_K_CONVERT_TO_FB_FAILURE);
        goto err;
    }

    opData->Z.pData = qaeCryptoMemAlloc(dlen, __FILE__, __LINE__);
    if (!opData->Z.pData) {
        WARN("Failed to allocate memory for opData pData\n");
        QATerr(QAT_F_QAT_DSA_DO_SIGN, QAT_R_OPDATA_ZPDATA_MALLOC_FAILURE);
        goto err;
    }
    opData->Z.dataLenInBytes = (Cpa32U) dlen;

    memcpy(opData->Z.pData, dgst, dlen);

    sig = DSA_SIG_new();
    if (sig == NULL) {
        WARN("Failed to allocate memory for sig\n");
        QATerr(QAT_F_QAT_DSA_DO_SIGN, QAT_R_SIG_MALLOC_FAILURE);
        goto err;
    }

    r = BN_new();
    s = BN_new();
    /* NULL checking of r & s done in DSA_SIG_set0() */
    if (DSA_SIG_set0(sig, r, s) == 0) {
        WARN("Unable to set r and s\n");
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    instance_handle = get_next_inst();
    if (qat_use_signals()) {
        qat_atomic_inc(num_requests_in_flight);
        if (pthread_kill(timer_poll_func_thread, SIGUSR1) != 0) {
            WARN("pthread_kill error\n");
            QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            qat_atomic_dec(num_requests_in_flight);
            DSA_SIG_free(sig);
            sig = NULL;
            goto err;
        }
    }
    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            qat_atomic_dec_if_polling(num_requests_in_flight);
            DSA_SIG_free(sig);
            sig = NULL;
            goto err;
        }
    }
    CRYPTO_QAT_LOG("AU - %s\n", __func__);

    do {
        if ((instance_handle = get_next_inst()) == NULL) {
            WARN("Failed to get an instance\n");
            QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            if (op_done.job != NULL) {
                qat_clear_async_event_notification();
            }
            qat_cleanup_op_done(&op_done);
            qat_atomic_dec_if_polling(num_requests_in_flight);
            DSA_SIG_free(sig);
            sig = NULL;
            goto err;
        }

        CRYPTO_QAT_LOG("AU - %s\n", __func__);
        DUMP_DSA_SIGN(instance_handle, &op_done, opData, &bDsaSignStatus,
                      pResultR, pResultS);

        status = cpaCyDsaSignRS(instance_handle,
                                qat_dsaSignCallbackFn,
                                &op_done,
                                opData,
                                &bDsaSignStatus, pResultR, pResultS);

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
    }
    while (status == CPA_STATUS_RETRY);

    if (status != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        if (op_done.job != NULL) {
            qat_clear_async_event_notification();
        }
        qat_cleanup_op_done(&op_done);
        qat_atomic_dec_if_polling(num_requests_in_flight);
        DSA_SIG_free(sig);
        sig = NULL;
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
    } while (!op_done.flag ||
             QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DUMP_DSA_SIGN_OUTPUT(bDsaSignStatus, pResultR, pResultS);
    qat_cleanup_op_done(&op_done);
    qat_atomic_dec_if_polling(num_requests_in_flight);

    if (op_done.verifyResult != CPA_TRUE) {
        WARN("Verification of result failed\n");
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        DSA_SIG_free(sig);
        sig = NULL;
        goto err;
    }

    /* Convert the flatbuffer results back to a BN */
    BN_bin2bn(pResultR->pData, pResultR->dataLenInBytes, r);
    BN_bin2bn(pResultS->pData, pResultS->dataLenInBytes, s);
 err:
    if (pResultR) {
        QAT_CHK_QMFREE_FLATBUFF(*pResultR);
        OPENSSL_free(pResultR);
    }
    if (pResultS) {
        QAT_CHK_QMFREE_FLATBUFF(*pResultS);
        OPENSSL_free(pResultS);
    }

    if (opData) {
        QAT_CHK_QMFREE_FLATBUFF(opData->P);
        QAT_CHK_QMFREE_FLATBUFF(opData->Q);
        QAT_CHK_QMFREE_FLATBUFF(opData->G);
        QAT_CHK_QMFREE_FLATBUFF(opData->Z);
        QAT_CHK_CLNSE_QMFREE_FLATBUFF(opData->X);
        QAT_CHK_CLNSE_QMFREE_FLATBUFF(opData->K);
        OPENSSL_free(opData);
    }

    if (ctx) {
        if (k)
            BN_clear(k);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return sig;
}

/******************************************************************************
* function:
*         qat_dsa_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp,
*                            BIGNUM **rp)
*
* description:
*   Wrapper around the default OpenSSL DSA dsa_sign_setup() function to avoid
*   a null function pointer.
*   See the OpenSSL documentation for parameters.
******************************************************************************/
int qat_dsa_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)
{
    const DSA_METHOD *default_dsa_method = DSA_OpenSSL();
    DEBUG("%s been called \n", __func__);

    return DSA_meth_get_sign_setup(default_dsa_method)(dsa, ctx_in, kinvp, rp);
}

/******************************************************************************
* function:
*         qat_dsa_do_verify(const unsigned char *dgst, int dgst_len,
*                           DSA_SIG *sig, DSA *dsa)
*
* description:
*   Verify DSA R and S Signatures.
******************************************************************************/
int qat_dsa_do_verify(const unsigned char *dgst, int dgst_len,
                      DSA_SIG *sig, DSA *dsa)
{
    BN_CTX *ctx;
    const BIGNUM *r = NULL, *s = NULL;
    BIGNUM *z = NULL;
    const BIGNUM *p = NULL, *q = NULL;
    const BIGNUM *g = NULL;
    const BIGNUM *pub_key = NULL, *priv_key = NULL;
    int ret = -1, i = 0, job_ret = 0;
    CpaInstanceHandle instance_handle;
    CpaCyDsaVerifyOpData *opData = NULL;
    CpaBoolean bDsaVerifyStatus;
    CpaStatus status;
    op_done_t op_done;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    const DSA_METHOD *default_dsa_method = DSA_OpenSSL();

    DEBUG("- Started\n");

    if (dsa == NULL || dgst == NULL || sig == NULL) {
        WARN("Either dsa = %p, dgst = %p or sig = %p are NULL\n", dsa, dgst, sig);
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, QAT_R_DSA_DGST_SIG_NULL);
        return -1;
    }

    DSA_get0_pqg(dsa, &p, &q, &g);

    if (p == NULL || q == NULL || g == NULL) {
        WARN("Either p = %p, q = %p or g = %p are NULL\n", p, q, g);
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, QAT_R_GET_PQG_FAILURE);
        return ret;
    }

    i = BN_num_bits(q);

    /*
     * If the sizes of P and Q are not in the range supported by QAT engine
     * then fall back to software
     */

    if (!dsa_range_check(BN_num_bits(p), i)) {
        if (default_dsa_method == NULL) {
            WARN("Failed to get default_dsa_method for bits p = %d & q = %d\n",
                  BN_num_bits(p), i);
            QATerr(QAT_F_QAT_DSA_DO_VERIFY, QAT_R_SW_METHOD_NULL);
            return -1;
        }
        return DSA_meth_get_verify(default_dsa_method)(dgst, dgst_len, sig, dsa);
    }

    opData = (CpaCyDsaVerifyOpData *)
        OPENSSL_malloc(sizeof(CpaCyDsaVerifyOpData));
    if (opData == NULL) {
        WARN("Failed to allocate memory for opData\n");
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, QAT_R_OPDATA_MALLOC_FAILURE);
        return ret;
    }

    memset(opData, 0, sizeof(CpaCyDsaVerifyOpData));

    if ((ctx = BN_CTX_new()) == NULL) {
        WARN("Failed to allocate memory for ctx\n");
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, QAT_R_CTX_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);

    if ((z = BN_CTX_get(ctx)) == NULL) {
        WARN("Failed to allocate z\n");
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, QAT_R_Z_ALLOCATE_FAILURE);
        goto err;
    }

    DSA_SIG_get0(sig, &r, &s);

    if (r == NULL || s == NULL) {
        WARN("Failed to get r or s\n");
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, QAT_R_SIG_GET_R_S_FAILURE);
        goto err;
    }

    if (BN_is_zero(r) || BN_is_negative(r) ||
        BN_ucmp(r, q) >= 0) {
        WARN("r and q not equal after compare\n");
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, QAT_R_R_Q_COMPARE_FAILURE);
        goto err;
    }
    if (BN_is_zero(s) || BN_is_negative(s) ||
        BN_ucmp(s, q) >= 0) {
        WARN("s and q not equal after compare\n");
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, QAT_R_S_Q_COMPARE_FAILURE);
        goto err;
    }

    if (dgst_len > (i >> 3))
        /*
         * if the digest length is greater than the size of q use the
         * BN_num_bits(q) leftmost bits of the digest, see fips 186-3,
         * 4.2
         */
        dgst_len = (i >> 3);
    if (BN_bin2bn(dgst, dgst_len, z) == NULL) {
        WARN("Failed to convert dgst to big number\n");
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, QAT_R_DGST_BN_CONV_FAILURE);
        goto err;
    }

    DSA_get0_key(dsa, &pub_key, &priv_key);

    if (pub_key == NULL) {
        WARN("pub_key is NULL\n");
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, QAT_R_PUB_KEY_NULL);
        goto err;
    }

    if ((qat_BN_to_FB(&(opData->P), p) != 1) ||
        (qat_BN_to_FB(&(opData->Q), q) != 1) ||
        (qat_BN_to_FB(&(opData->G), g) != 1) ||
        (qat_BN_to_FB(&(opData->Y), pub_key) != 1) ||
        (qat_BN_to_FB(&(opData->Z), z) != 1) ||
        (qat_BN_to_FB(&(opData->R), r) != 1) ||
        (qat_BN_to_FB(&(opData->S), s) != 1)) {
        WARN("Failed to convert p, q, g, pub_key, z, r or s to a flat buffer\n");
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, QAT_R_P_Q_G_Y_Z_R_S_CONVERT_TO_FB_FAILURE);
        goto err;
    }

    instance_handle = get_next_inst();
    if (qat_use_signals()) {
        qat_atomic_inc(num_requests_in_flight);
        if (pthread_kill(timer_poll_func_thread, SIGUSR1) != 0) {
            WARN("pthread_kill error\n");
            QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
            qat_atomic_dec(num_requests_in_flight);
            goto err;
        }
    }
    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            qat_atomic_dec_if_polling(num_requests_in_flight);
            goto err;
        }
    }

    CRYPTO_QAT_LOG("AU - %s\n", __func__);
    do {
        if ((instance_handle = get_next_inst()) == NULL) {
            WARN("Failed to get an instance\n");
            QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
            if (op_done.job != NULL) {
                qat_clear_async_event_notification();
            }
            qat_cleanup_op_done(&op_done);
            qat_atomic_dec_if_polling(num_requests_in_flight);
            goto err;
        }

        CRYPTO_QAT_LOG("AU - %s\n", __func__);
        DUMP_DSA_VERIFY(instance_handle, &op_done, opData, &bDsaVerifyStatus);

        status = cpaCyDsaVerify(instance_handle,
                                qat_dsaVerifyCallbackFn,
                                &op_done, opData, &bDsaVerifyStatus);

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

    if (status != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
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

    if (op_done.verifyResult == CPA_TRUE)
        ret = 1;

    DEBUG("bDsaVerifyStatus = %u\n", bDsaVerifyStatus);
    qat_cleanup_op_done(&op_done);
    qat_atomic_dec_if_polling(num_requests_in_flight);

 err:
    if (opData) {
        QAT_CHK_QMFREE_FLATBUFF(opData->P);
        QAT_CHK_QMFREE_FLATBUFF(opData->Q);
        QAT_CHK_QMFREE_FLATBUFF(opData->G);
        QAT_CHK_QMFREE_FLATBUFF(opData->Y);
        QAT_CHK_QMFREE_FLATBUFF(opData->Z);
        QAT_CHK_QMFREE_FLATBUFF(opData->R);
        QAT_CHK_QMFREE_FLATBUFF(opData->S);
        OPENSSL_free(opData);
    }

    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return (ret);
}
#endif /* #ifndef OPENSSL_DISABLE_QAT_DSA */

