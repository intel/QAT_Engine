/* ====================================================================
 *
 * 
 *   BSD LICENSE
 * 
 *   Copyright(c) 2016 Intel Corporation.
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

static DSA_SIG *qat_dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa);
static int qat_dsa_do_verify(const unsigned char *dgst, int dgst_len,
                             DSA_SIG *sig, DSA *dsa);
static int qat_dsa_sign_setup(DSA *dsa, BN_CTX *ctx_in, 
                              BIGNUM **kinvp, BIGNUM **rp);
static int qat_dsa_bn_mod_exp(DSA *dsa, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
                              const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);

/* Qat DSA method structure declaration. */
static DSA_METHOD *qat_dsa_method = NULL;

DSA_METHOD *qat_get_DSA_methods(void)
{
    if (qat_dsa_method != NULL)
        return qat_dsa_method;

#ifndef OPENSSL_DISABLE_QAT_DSA
    if ((qat_dsa_method = DSA_meth_new("QAT DSA method", 0)) == NULL
        || DSA_meth_set_sign(qat_dsa_method, qat_dsa_do_sign) == 0
        || DSA_meth_set_sign_setup(qat_dsa_method, qat_dsa_sign_setup) == 0
        || DSA_meth_set_verify(qat_dsa_method, qat_dsa_do_verify) == 0
        || DSA_meth_set_bn_mod_exp(qat_dsa_method, qat_dsa_bn_mod_exp) == 0 ) {
        QATerr(QAT_F_QAT_GET_DSA_METHODS, ERR_R_INTERNAL_ERROR);
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
        QATerr(QAT_F_QAT_FREE_DSA_METHODS, ERR_R_INTERNAL_ERROR);
    }
#endif
}

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
*         qat_dsa_bn_mod_exp(DSA *dsa, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
*                            const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
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
int qat_dsa_bn_mod_exp(DSA *dsa, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    DEBUG("%s been called \n", __func__);
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
    BIGNUM *p = NULL, *q = NULL;
    BIGNUM *g = NULL;
    BIGNUM *pub_key = NULL, *priv_key = NULL;
    BN_CTX *ctx = NULL;
    DSA_SIG *ret = NULL;
    CpaFlatBuffer *pResultR = NULL;
    CpaFlatBuffer *pResultS = NULL;
    CpaInstanceHandle instanceHandle;
    CpaCyDsaRSSignOpData *opData = NULL;
    CpaBoolean bDsaSignStatus;
    CpaStatus status;
    size_t buflen;
    struct op_done op_done;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    const DSA_METHOD *default_dsa_method = DSA_OpenSSL();


    DEBUG("[%s] --- called.\n", __func__);

    if (dsa == NULL) {
         QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
         return NULL;
    }

    DSA_get0_pqg(dsa, &p, &q, &g);

    if (p == NULL || q == NULL || g == NULL) {
         QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
         return ret;
    }

    /*
     * If the sizes of P and Q are not in the range supported by QAT engine
     * then fall back to software
     */

    if (!dsa_range_check(BN_num_bits(p), BN_num_bits(q))) {
        if (default_dsa_method == NULL) {
            QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            return NULL;
        }
        return DSA_meth_get_sign(default_dsa_method)(dgst, dlen, dsa);
    }

    opData = (CpaCyDsaRSSignOpData *)
        OPENSSL_malloc(sizeof(CpaCyDsaRSSignOpData));
    if (opData == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        return ret;
    }

    memset(opData, 0, sizeof(CpaCyDsaRSSignOpData));

    if ((ctx = BN_CTX_new()) == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);

    if ((k = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (dlen > BN_num_bytes(q))
        /*
         * if the digest length is greater than the size of q use the
         * BN_num_bits(q) leftmost bits of the digest, see fips 186-3,
         * 4.2
         */
        dlen = BN_num_bytes(q);
    do {
        if (!BN_rand_range(k, q)) {
            QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    while (BN_is_zero(k));

    buflen = BN_num_bytes(q);
    pResultR = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (!pResultR) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pResultR->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (!pResultR->pData) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pResultR->dataLenInBytes = (Cpa32U) buflen;
    pResultS = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (!pResultS) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pResultS->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (!pResultS->pData) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pResultS->dataLenInBytes = (Cpa32U) buflen;

    DSA_get0_key(dsa, &pub_key, &priv_key);

    if ((qat_BN_to_FB(&(opData->P), p) != 1) ||
        (qat_BN_to_FB(&(opData->Q), q) != 1) ||
        (qat_BN_to_FB(&(opData->G), g) != 1) ||
        (qat_BN_to_FB(&(opData->X), priv_key) != 1) ||
        (qat_BN_to_FB(&(opData->K), k) != 1)) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    opData->Z.pData = qaeCryptoMemAlloc(dlen, __FILE__, __LINE__);
    if (!opData->Z.pData) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    opData->Z.dataLenInBytes = (Cpa32U) dlen;

    memcpy(opData->Z.pData, dgst, dlen);

    ret = DSA_SIG_new();
    if (ret == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    initOpDone(&op_done);
    if (op_done.job) {
        if (qat_setup_async_event_notification(0) == 0) {
            QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            DSA_SIG_free(ret);
            ret = NULL;
            goto err;
        }
    }
    CRYPTO_QAT_LOG("AU - %s\n", __func__);

    do {
        if ((instanceHandle = get_next_inst()) == NULL) {
            QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            DSA_SIG_free(ret);
            ret = NULL;
            goto err;
        }

        CRYPTO_QAT_LOG("AU - %s\n", __func__);
        status = cpaCyDsaSignRS(instanceHandle,
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
                        break;
                    }
                }
            } else {
                if ((qat_wake_job(op_done.job, 0) == 0) ||
                    (qat_pause_job(op_done.job, 0) == 0)) {
                    status = CPA_STATUS_FAIL;
                    break;
                }
            }
        }
    }
    while (status == CPA_STATUS_RETRY);

    if (status != CPA_STATUS_SUCCESS) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        cleanupOpDone(&op_done);
        DSA_SIG_free(ret);
        ret = NULL;
        goto err;
    }

    do {
        if(op_done.job) {
           /* If we get a failure on qat_pause_job then we will
               not flag an error here and quit because we have
               an asynchronous request in flight.
               We don't want to start cleaning up data
               structures that are still being used. If
               qat_pause_job fails we will just yield and
               loop around and try again until the request
               completes and we can continue. */
            if (qat_pause_job(op_done.job, 0) == 0)
                pthread_yield();
        } else {
            pthread_yield();
        }
    } while (!op_done.flag);

    cleanupOpDone(&op_done);

    if (op_done.verifyResult != CPA_TRUE) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        DSA_SIG_free(ret);
        ret = NULL;
        goto err;
    }

    DSA_SIG_get0(&r, &s, ret);

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
    return (ret);
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
    BIGNUM *r = NULL, *s = NULL;
    BIGNUM *z = NULL;
    BIGNUM *p = NULL, *q = NULL;
    BIGNUM *g = NULL;
    BIGNUM *pub_key = NULL, *priv_key = NULL;
    int ret = -1, i = 0;
    CpaInstanceHandle instanceHandle;
    CpaCyDsaVerifyOpData *opData = NULL;
    CpaBoolean bDsaVerifyStatus;
    CpaStatus status;
    struct op_done op_done;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    const DSA_METHOD *default_dsa_method = DSA_OpenSSL();

    DEBUG("[%s] --- called.\n", __func__);

    if (dsa == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    DSA_get0_pqg(dsa, &p, &q, &g);

    if (p == NULL || q == NULL || g == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        return ret;
    }

    /*
     * If the sizes of P and Q are not in the range supported by QAT engine
     * then fall back to software
     */

    if (!dsa_range_check(BN_num_bits(p), BN_num_bits(q))) {
        if (default_dsa_method == NULL) {
            QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
            return -1;
        }
        return DSA_meth_get_verify(default_dsa_method)(dgst, dgst_len, sig, dsa);
    }

    i = BN_num_bits(q);
    /* fips 186-3 allows only different sizes for q */
    if (i != 160 && i != 224 && i != 256) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        return ret;
    }

    opData = (CpaCyDsaVerifyOpData *)
        OPENSSL_malloc(sizeof(CpaCyDsaVerifyOpData));
    if (opData == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        return ret;
    }

    memset(opData, 0, sizeof(CpaCyDsaVerifyOpData));

    if ((ctx = BN_CTX_new()) == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);

    if ((z = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    DSA_SIG_get0(&r, &s, sig);

    if (BN_is_zero(r) || BN_is_negative(r) ||
        BN_ucmp(r, q) >= 0) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (BN_is_zero(s) || BN_is_negative(s) ||
        BN_ucmp(s, q) >= 0) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
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
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    DSA_get0_key(dsa, &pub_key, &priv_key);

    if ((qat_BN_to_FB(&(opData->P), p) != 1) ||
        (qat_BN_to_FB(&(opData->Q), q) != 1) ||
        (qat_BN_to_FB(&(opData->G), g) != 1) ||
        (qat_BN_to_FB(&(opData->Y), pub_key) != 1) ||
        (qat_BN_to_FB(&(opData->Z), z) != 1) ||
        (qat_BN_to_FB(&(opData->R), r) != 1) ||
        (qat_BN_to_FB(&(opData->S), s) != 1)) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    initOpDone(&op_done);
    if (op_done.job) {
        if (qat_setup_async_event_notification(0) == 0) {
            QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            goto err;
        }
    }

    CRYPTO_QAT_LOG("AU - %s\n", __func__);
    do {
        if ((instanceHandle = get_next_inst()) == NULL) {
            QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            goto err;
        }

        CRYPTO_QAT_LOG("AU - %s\n", __func__);
        status = cpaCyDsaVerify(instanceHandle,
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
                        break;
                    }
                }
            } else {
                if ((qat_wake_job(op_done.job, 0) == 0) ||
                    (qat_pause_job(op_done.job, 0) == 0)) {
                    status = CPA_STATUS_FAIL;
                    break;
                }
            }
        }
    } while (status == CPA_STATUS_RETRY);

    if (status != CPA_STATUS_SUCCESS) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        cleanupOpDone(&op_done);
        goto err;
    }

    do {
        if(op_done.job) {
            /* If we get a failure on qat_pause_job then we will
               not flag an error here and quit because we have
               an asynchronous request in flight.
               We don't want to start cleaning up data
               structures that are still being used. If
               qat_pause_job fails we will just yield and
               loop around and try again until the request
               completes and we can continue. */
            if (qat_pause_job(op_done.job, 0) == 0)
                pthread_yield();
        } else {
            pthread_yield();
        }
    }
    while (!op_done.flag);

    if (op_done.verifyResult == CPA_TRUE)
        ret = 1;

    cleanupOpDone(&op_done);

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

