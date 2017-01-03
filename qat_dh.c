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
 * @file qat_dh.c
 *
 * This file provides implementaiotns for Diffie Hellman operations through an
 * OpenSSL engine
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <pthread.h>
#include "qat_dh.h"
#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "cmn_mem_drv_inf.h"
#endif
#include <openssl/async.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include "qat_asym_common.h"
#include "qat_utils.h"
#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_dh.h"
#include "e_qat.h"
#include "e_qat_err.h"
#include <unistd.h>
#include <string.h>

#ifdef OPENSSL_ENABLE_QAT_DH
# ifdef OPENSSL_DISABLE_QAT_DH
#  undef OPENSSL_DISABLE_QAT_DH
# endif
#endif

/* To specify the DH op sizes supported by QAT engine */
#define DH_QAT_RANGE_MIN 768
#define DH_QAT_RANGE_MAX 4096

static int qat_dh_generate_key(DH *dh);
static int qat_dh_compute_key(unsigned char *key, const BIGNUM *pub_key,
                              DH *dh);
static int qat_dh_mod_exp(const DH *dh, BIGNUM *r, const BIGNUM *a,
                          const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                          BN_MONT_CTX *m_ctx);

static DH_METHOD *qat_dh_method = NULL;

DH_METHOD *qat_get_DH_methods(void)
{
    if (qat_dh_method != NULL)
        return qat_dh_method;

#ifndef OPENSSL_DISABLE_QAT_DH
    if ((qat_dh_method = DH_meth_new("QAT DH method", 0)) == NULL
        || DH_meth_set_generate_key(qat_dh_method, qat_dh_generate_key) == 0
        || DH_meth_set_compute_key(qat_dh_method, qat_dh_compute_key) == 0
        || DH_meth_set_bn_mod_exp(qat_dh_method, qat_dh_mod_exp) == 0) {
        QATerr(QAT_F_QAT_GET_DH_METHODS, ERR_R_INTERNAL_ERROR);
        return NULL;
    }
#else
    qat_dh_method = (DH_METHOD *)DH_get_default_method();
#endif

    return qat_dh_method;
}

void qat_free_DH_methods(void)
{
#ifndef OPENSSL_DISABLE_QAT_DH
    if (qat_dh_method != NULL) {
        DH_meth_free(qat_dh_method);
        qat_dh_method = NULL;
    } else {
        QATerr(QAT_F_QAT_FREE_DH_METHODS, ERR_R_INTERNAL_ERROR);
    }
#endif
}


/*
 * The DH range check is performed so that if the op sizes are not in the
 * range supported by QAT engine then fall back to software
 */

int dh_range_check(int plen)
{
    int range = 0;

    if ((plen >= DH_QAT_RANGE_MIN) && (plen <= DH_QAT_RANGE_MAX))
        range = 1;

    return range;
}

/* Callback to indicate QAT completion of DH generate & compute key */
void qat_dhCallbackFn(void *pCallbackTag, CpaStatus status, void *pOpData,
                      CpaFlatBuffer * pPV)
{
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, CPA_TRUE);
}

/******************************************************************************
* function:
*         qat_dh_generate_key(DH * dh)
*
* description:
*   Implement Diffie-Hellman phase 1 operations.
******************************************************************************/
int qat_dh_generate_key(DH *dh)
{
    int ok = 0;
    int generate_new_priv_key = 0;
    int generate_new_pub_key = 0;
    unsigned length = 0;
    const BIGNUM *p = NULL, *q = NULL;
    const BIGNUM *g = NULL;
    BIGNUM *pub_key = NULL, *priv_key = NULL;
    const BIGNUM *temp_pub_key = NULL, *temp_priv_key = NULL;
    CpaInstanceHandle instanceHandle;
    CpaCyDhPhase1KeyGenOpData *opData = NULL;
    CpaFlatBuffer *pPV = NULL;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    CpaStatus status;
    struct op_done op_done;
    size_t buflen;
    const DH_METHOD *sw_dh_method = DH_OpenSSL();

    DEBUG("%s been called \n", __func__);

    if (dh == NULL) {
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    DH_get0_pqg(dh, &p, &q, &g);
    if (p == NULL || g == NULL) {
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * If the op sizes are not in the range supported by QAT engine then fall
     * back to software
     */

    if (!dh_range_check(BN_num_bits(p))) {
        if (sw_dh_method == NULL) {
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        return DH_meth_get_generate_key(sw_dh_method)(dh);
    }

    DH_get0_key(dh, &temp_pub_key, &temp_priv_key);

    opData = (CpaCyDhPhase1KeyGenOpData *)
        OPENSSL_malloc(sizeof(CpaCyDhPhase1KeyGenOpData));
    if (opData == NULL) {
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_MALLOC_FAILURE);
        return ok;
    }

    opData->primeP.pData = NULL;
    opData->baseG.pData = NULL;
    opData->privateValueX.pData = NULL;

    if (temp_priv_key == NULL) {
        if ((priv_key = BN_new()) == NULL) {
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        generate_new_priv_key = 1;
    } else {
       if ((priv_key = BN_dup(temp_priv_key)) == NULL) {
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
       }
    }

    if (pub_key == NULL) {
        if ((pub_key = BN_new()) == NULL) {
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        generate_new_pub_key = 1;
    } else {
       if ((pub_key = BN_dup(temp_pub_key)) == NULL) {
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
       }
    }

    if (generate_new_priv_key) {
        if (q) {
            do {
                if (!BN_rand_range(priv_key, q)) {
                    QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_BN_LIB);
                    goto err;
                }
            }
            while (BN_is_zero(priv_key) || BN_is_one(priv_key));
        } else {
            /* secret exponent length */
            length = DH_get_length(dh) ? DH_get_length(dh) : BN_num_bits(p) - 1;
            if (!BN_rand(priv_key, length, 0, 0)) {
                QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_BN_LIB);
                goto err;
            }
        }
    }

    buflen = BN_num_bytes(p);
    pPV = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (pPV == NULL) {
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pPV->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (pPV->pData == NULL) {
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pPV->dataLenInBytes = (Cpa32U) buflen;

    if ((qat_BN_to_FB(&(opData->primeP), (BIGNUM *)p) != 1) ||
        (qat_BN_to_FB(&(opData->baseG), (BIGNUM *)g) != 1) ||
        (qat_BN_to_FB(&(opData->privateValueX), (BIGNUM *)priv_key) != 1)) {
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    initOpDone(&op_done);
    if (op_done.job) {
        if (qat_setup_async_event_notification(0) == 0) {
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            goto err;
        }
    }

    CRYPTO_QAT_LOG("KX - %s\n", __func__);
    do {
        if ((instanceHandle = get_next_inst()) == NULL) {
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            goto err;
        }

        CRYPTO_QAT_LOG("KX - %s\n", __func__);
        status = cpaCyDhKeyGenPhase1(instanceHandle,
                qat_dhCallbackFn,
                &op_done, opData, pPV);

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
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
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

    cleanupOpDone(&op_done);

    if (op_done.verifyResult != CPA_TRUE) {
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Convert the flatbuffer result back to a BN */
    BN_bin2bn(pPV->pData, pPV->dataLenInBytes, pub_key);

    if (!DH_set0_key(dh, pub_key, priv_key)) {
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ok = 1;
 err:
    if (pPV) {
        if (pPV->pData) {
            qaeCryptoMemFree(pPV->pData);
        }
        OPENSSL_free(pPV);
    }

    if (opData) {
        if (opData->primeP.pData)
            qaeCryptoMemFree(opData->primeP.pData);
        if (opData->baseG.pData)
            qaeCryptoMemFree(opData->baseG.pData);
        QAT_CHK_CLNSE_QMFREE_FLATBUFF(opData->privateValueX);
        OPENSSL_free(opData);
    }

    if (!ok) {
        if (generate_new_pub_key)
            BN_free(pub_key);
        if (generate_new_priv_key)
            BN_clear_free(priv_key);
    }
    return (ok);
}

/******************************************************************************
* function:
*         qat_dh_compute_key(unsigned char *key,
*                            const BIGNUM * in_pub_key, DH * dh)
*
* description:
*   Implement Diffie-Hellman phase 2 operations.
******************************************************************************/
int qat_dh_compute_key(unsigned char *key, const BIGNUM *in_pub_key, DH *dh)
{
    int ret = -1;
    int check_result;
    CpaInstanceHandle instanceHandle;
    CpaCyDhPhase2SecretKeyGenOpData *opData = NULL;
    CpaFlatBuffer *pSecretKey = NULL;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    CpaStatus status;
    struct op_done op_done;
    size_t buflen;
    int index = 1;
    const BIGNUM *p = NULL, *q = NULL;
    const BIGNUM *g = NULL;
    const BIGNUM *pub_key = NULL, *priv_key = NULL;
    const DH_METHOD *sw_dh_method = DH_OpenSSL();

    DEBUG("%s been called \n", __func__);

    if (!dh) {
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    DH_get0_pqg(dh, &p, &q, &g);
    DH_get0_key(dh, &pub_key, &priv_key);
    if (p == NULL || priv_key == NULL) {
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    /*
     * If the op sizes are not in the range supported by QAT engine then fall
     * back to software
     */

    if (!dh_range_check(BN_num_bits(p))) {
        if (sw_dh_method == NULL) {
            QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            return -1;
        }
        return DH_meth_get_compute_key(sw_dh_method)(key, in_pub_key, dh);
    }

    if (BN_num_bits(p) > OPENSSL_DH_MAX_MODULUS_BITS) {
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    if (!DH_check_pub_key(dh, in_pub_key, &check_result) || check_result) {
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    opData = (CpaCyDhPhase2SecretKeyGenOpData *)
        OPENSSL_malloc(sizeof(CpaCyDhPhase2SecretKeyGenOpData));
    if (opData == NULL) {
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        return ret;
    }

    opData->primeP.pData = NULL;
    opData->remoteOctetStringPV.pData = NULL;
    opData->privateValueX.pData = NULL;

    buflen = BN_num_bytes(p);
    pSecretKey = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (pSecretKey == NULL) {
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pSecretKey->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (pSecretKey->pData == NULL) {
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pSecretKey->dataLenInBytes = (Cpa32U) buflen;

    if ((qat_BN_to_FB(&(opData->primeP), (BIGNUM *)p) != 1) ||
        (qat_BN_to_FB(&(opData->remoteOctetStringPV), (BIGNUM *)in_pub_key) != 1)
        || (qat_BN_to_FB(&(opData->privateValueX), (BIGNUM *)priv_key) !=
            1)) {
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    initOpDone(&op_done);
    if (op_done.job) {
        if (qat_setup_async_event_notification(0) == 0) {
            QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            goto err;
        }
    }

    CRYPTO_QAT_LOG("KX - ?%s\n", __func__);
    do {
        if ((instanceHandle = get_next_inst()) == NULL) {
            QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            goto err;
        }

        CRYPTO_QAT_LOG("KX - %s\n", __func__);
        status = cpaCyDhKeyGenPhase2Secret(instanceHandle,
                qat_dhCallbackFn,
                &op_done, opData, pSecretKey);

        if (status == CPA_STATUS_RETRY) {
            if (!op_done.job) {
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
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
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

    cleanupOpDone(&op_done);

    if (op_done.verifyResult != CPA_TRUE) {
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Remove leading zeros */
    if (!pSecretKey->pData[0]) {
        while (index < pSecretKey->dataLenInBytes && !pSecretKey->pData[index])
            index++;
        pSecretKey->dataLenInBytes = pSecretKey->dataLenInBytes - index;
        memcpy(key, &pSecretKey->pData[index],
                pSecretKey->dataLenInBytes);
    } else {
        memcpy(key, pSecretKey->pData, pSecretKey->dataLenInBytes);
    }
    ret = pSecretKey->dataLenInBytes;

 err:
    if (pSecretKey) {
        QAT_CHK_CLNSE_QMFREE_FLATBUFF(*pSecretKey);
        OPENSSL_free(pSecretKey);
    }

    if (opData) {
        if (opData->primeP.pData)
            qaeCryptoMemFree(opData->primeP.pData);
        if (opData->remoteOctetStringPV.pData)
            qaeCryptoMemFree(opData->remoteOctetStringPV.pData);
        QAT_CHK_CLNSE_QMFREE_FLATBUFF(opData->privateValueX);
        OPENSSL_free(opData);
    }

    return (ret);
}

/******************************************************************************
* function:
*         qat_dh_mod_exp(const DH * dh, BIGNUM * r, const BIGNUM * a,
*                        const BIGNUM * p, const BIGNUM * m, BN_CTX * ctx,
*                        BN_MONT_CTX * m_ctx)
*
* @param dh    [IN] - Pointer to a OpenSSL DH struct.
* @param r     [IN] - Result bignum of mod_exp
* @param a     [IN] - Base used for mod_exp
* @param p     [IN] - Exponent used for mod_exp
* @param m     [IN] - Modulus used for mod_exp
* @param ctx   [IN] - EVP context.
* @param m_ctx [IN] - EVP context for Montgomery multiplication.
*
* description:
*   Overridden modular exponentiation function used in DH.
*
******************************************************************************/
int qat_dh_mod_exp(const DH *dh, BIGNUM *r, const BIGNUM *a,
                   const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                   BN_MONT_CTX *m_ctx)
{
    DEBUG("%s been called \n", __func__);
    CRYPTO_QAT_LOG("KX - %s\n", __func__);
    return qat_mod_exp(r, a, p, m);
}
