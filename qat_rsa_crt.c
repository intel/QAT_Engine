/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2020 Intel Corporation.
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
 * @file qat_rsa_crt.c
 *
 * This file provides interfaces for CRT-based RSA sync optimization for
 * an OpenSSL engine.
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define __USE_GNU

#include <pthread.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>
#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "cmn_mem_drv_inf.h"
#endif
#include "qat_utils.h"
#include "e_qat.h"
#include "qat_callback.h"
#include "qat_polling.h"
#include "qat_events.h"


#include "cpa.h"
#include "cpa_types.h"

#include "cpa_cy_rsa.h"
#include "cpa_cy_ln.h"
#include "qat_aux.h"
#include "qat_rsa.h"
#include "qat_rsa_crt.h"
#include "qat_asym_common.h"
#include "e_qat_err.h"
#include "icp_sal_poll.h"

#ifdef OPENSSL_ENABLE_QAT_RSA
# ifdef OPENSSL_DISABLE_QAT_RSA
#  undef OPENSSL_DISABLE_QAT_RSA
# endif
#endif

#ifndef OPENSSL_DISABLE_QAT_RSA
static void qat_rsaCallbackFn_CRT(void *pCallbackTag, CpaStatus status, void *pOpData,
                                  CpaFlatBuffer * pOut)
{
    op_done_rsa_crt_t *op_done = (op_done_rsa_crt_t *)pCallbackTag;
    op_done->resp++;
    op_done->opDone.verifyResult *= (status == CPA_STATUS_SUCCESS);
    if (op_done->opDone.status == CPA_STATUS_SUCCESS)
        op_done->opDone.status = status;
}

static inline int
CRT_prepare(CpaFlatBuffer *crt_out1, CpaFlatBuffer *crt_out2,
             int rsa_len, CpaCyRsaDecryptOpData * dec_op_data,
             CpaCyLnModExpOpData *crt_op1_data, CpaCyLnModExpOpData *crt_op2_data)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *c = NULL, *p = NULL, *q = NULL, *cp = NULL, *cq = NULL;
    unsigned char *cp_buf = NULL, *cq_buf = NULL;
    CpaCyRsaPrivateKey *cpa_prv_key = dec_op_data->pRecipientPrivateKey;

    if ((ctx = BN_CTX_new()) == NULL) {
        WARN("Failed to allocate memory for ctx\n");
        QATerr(QAT_F_CRT_PREPARE, QAT_R_CTX_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);

    c = BN_CTX_get(ctx);
    p = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    cp = BN_CTX_get(ctx);
    cq = BN_CTX_get(ctx);

    if (cq == NULL) {
        WARN("Failed to allocate c, p, q, cp or cq\n");
        QATerr(QAT_F_CRT_PREPARE, QAT_R_C_P_Q_CP_CQ_MALLOC_FAILURE);
        goto err;
    }

    /*
     * reduce base (c mod p and c mod q) in advance
     * make sure firmwre to use modulus of expected length
     */
    c = BN_bin2bn(dec_op_data->inputData.pData,
                dec_op_data->inputData.dataLenInBytes, c);
    p = BN_bin2bn(cpa_prv_key->privateKeyRep2.prime1P.pData,
                cpa_prv_key->privateKeyRep2.prime1P.dataLenInBytes, p);
    q = BN_bin2bn(cpa_prv_key->privateKeyRep2.prime2Q.pData,
                cpa_prv_key->privateKeyRep2.prime2Q.dataLenInBytes, q);

    if (!BN_mod(cp, c, p, ctx)) {
        WARN("Failed to calculate (c mod p)\n");
        QATerr(QAT_F_CRT_PREPARE, QAT_R_C_MODULO_P_FAILURE);
        goto err;
    }
    if (!BN_mod(cq, c, q, ctx)) {
        WARN("Failed to calculate (c mod q)\n");
        QATerr(QAT_F_CRT_PREPARE, QAT_R_C_MODULO_Q_FAILURE);
        goto err;
    }

    cp_buf = OPENSSL_malloc(rsa_len/2);
    if (cp_buf == NULL) {
        WARN("Failure to allocate cp_buf\n");
        QATerr(QAT_F_CRT_PREPARE, QAT_R_CP_BUF_MALLOC_FAILURE);
        goto err;
    }
    cq_buf = OPENSSL_malloc(rsa_len/2);
    if (cq_buf == NULL) {
        WARN("Failure to allocate cq_buf\n");
        QATerr(QAT_F_CRT_PREPARE, QAT_R_CQ_BUF_MALLOC_FAILURE);
        goto err;
    }
    BN_bn2bin(cp, cp_buf);
    BN_bn2bin(cq, cq_buf);

    crt_op1_data->base.pData = qaeCryptoMemAlloc(rsa_len/2, __FILE__, __LINE__);
    if (crt_op1_data->base.pData == NULL) {
        WARN("Failure to allocate crt_op1_data->base.pData\n");
        QATerr(QAT_F_CRT_PREPARE, QAT_R_OP1_BASE_PDATA_MALLOC_FAILURE);
        goto err;
    }
    crt_op1_data->base.dataLenInBytes = rsa_len/2;
    memset(crt_op1_data->base.pData, 0, rsa_len/2);
    memcpy(crt_op1_data->base.pData + rsa_len/2 - BN_num_bytes(cp),
            &cp_buf[0], BN_num_bytes(cp));

    crt_op2_data->base.pData = qaeCryptoMemAlloc(rsa_len/2, __FILE__, __LINE__);
    if (crt_op2_data->base.pData == NULL) {
        WARN("Failure to allocate crt_op2_data->base.pData\n");
        QATerr(QAT_F_CRT_PREPARE, QAT_R_OP2_BASE_PDATA_MALLOC_FAILURE);
        goto err;
    }
    crt_op2_data->base.dataLenInBytes = rsa_len/2;
    memset(crt_op2_data->base.pData, 0, rsa_len/2);
    memcpy(crt_op2_data->base.pData + rsa_len/2 - BN_num_bytes(cq),
            &cq_buf[0], BN_num_bytes(cq));

    memcpy(&crt_op1_data->modulus,
            &cpa_prv_key->privateKeyRep2.prime1P,
            sizeof(cpa_prv_key->privateKeyRep2.prime1P));
    memcpy(&crt_op2_data->modulus,
            &cpa_prv_key->privateKeyRep2.prime2Q,
            sizeof(cpa_prv_key->privateKeyRep2.prime2Q));

    memcpy(&crt_op1_data->exponent,
            &cpa_prv_key->privateKeyRep2.exponent1Dp,
            sizeof(cpa_prv_key->privateKeyRep2.exponent1Dp));

    memcpy(&crt_op2_data->exponent,
            &cpa_prv_key->privateKeyRep2.exponent2Dq,
            sizeof(cpa_prv_key->privateKeyRep2.exponent2Dq));


    crt_out1->pData = qaeCryptoMemAlloc(rsa_len/2, __FILE__, __LINE__);
    if (crt_out1->pData == NULL) {
        WARN("Failure to allocate crt_out1->pData\n");
        QATerr(QAT_F_CRT_PREPARE, QAT_R_OUT1_PDATA_MALLOC_FAILURE);
        goto err;
    }
    crt_out1->dataLenInBytes = rsa_len/2;
    crt_out2->pData = qaeCryptoMemAlloc(rsa_len/2, __FILE__, __LINE__);
    if (crt_out2->pData == NULL) {
        WARN("Failure to allocate crt_out2->pData\n");
        QATerr(QAT_F_CRT_PREPARE, QAT_R_OUT2_PDATA_MALLOC_FAILURE);
        goto err;
    }
    crt_out2->dataLenInBytes = rsa_len/2;

    ret = 1;

err:

    /*
     * Normally these pinned memory allocations are
     * freed in qat_rsa_decrypt_CRT().
     */

    if (cp_buf)
        OPENSSL_free(cp_buf);
    if (cq_buf)
        OPENSSL_free(cq_buf);
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

static inline int
CRT_combine(CpaFlatBuffer *crt_out1, CpaFlatBuffer *crt_out2, int rsa_len,
             CpaFlatBuffer *output_buf, CpaCyRsaPrivateKey *cpa_prv_key)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *m1 = NULL, *m2 = NULL, *p = NULL, *q = NULL;
    BIGNUM *qinv = NULL, *tmp = NULL;

    if ((ctx = BN_CTX_new()) == NULL) {
        WARN("Failed to allocate memory for ctx\n");
        QATerr(QAT_F_CRT_COMBINE, QAT_R_CTX_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);

    m1 = BN_CTX_get(ctx);
    m2 = BN_CTX_get(ctx);
    p = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    qinv = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);

    if (tmp == NULL) {
        WARN("Failed to allocate m1, m2, p, q, qinv or tmp\n");
        QATerr(QAT_F_CRT_COMBINE, QAT_R_M1_M2_P_Q_QINV_TMP_MALLOC_FAILURE);
        goto err;
    }

    m1 = BN_bin2bn(crt_out1->pData, crt_out1->dataLenInBytes, m1);
    m2 = BN_bin2bn(crt_out2->pData, crt_out2->dataLenInBytes, m2);
    p = BN_bin2bn(cpa_prv_key->privateKeyRep2.prime1P.pData,
                    cpa_prv_key->privateKeyRep2.prime1P.dataLenInBytes, p);
    q = BN_bin2bn(cpa_prv_key->privateKeyRep2.prime2Q.pData,
                    cpa_prv_key->privateKeyRep2.prime2Q.dataLenInBytes, q);
    qinv = BN_bin2bn(cpa_prv_key->privateKeyRep2.coefficientQInv.pData,
                    cpa_prv_key->privateKeyRep2.coefficientQInv.dataLenInBytes, qinv);

    /* m1 - m2 */
    if (!BN_sub(m1, m1, m2)) {
        WARN("Failed to calculate (m1 - m2)\n");
        QATerr(QAT_F_CRT_COMBINE, QAT_R_M1_DEDUCT_M2_FAILURE);
        goto err;
    }
    /* make sure a positive result */
    if (BN_is_negative(m1))
        if (!BN_add(m1, m1, p)) {
            WARN("Failed to adjust (m1 - m2)\n");
            QATerr(QAT_F_CRT_COMBINE, QAT_R_ADJUST_DELTA_M1_M2_FAILURE);
            goto err;
        }

    /* h = qinv * (m1-m2) mod p */
    if (!BN_mul(tmp, m1, qinv, ctx)) {
        WARN("Failed to calculate (qinv *(m1 - m2))\n");
        QATerr(QAT_F_CRT_COMBINE, QAT_R_MULTIPLY_QINV_FAILURE);
        goto err;
    }
    if (!BN_mod(m1, tmp, p, ctx)) {
        WARN("Failed to calculate ((qinv *(m1 - m2)) mod p)\n");
        QATerr(QAT_F_CRT_COMBINE, QAT_R_MODULO_P_FAILURE);
        goto err;
    }
    if (BN_is_negative(m1))
        if (!BN_add(m1, m1, p))
            goto err;

    /* h*q */
    if (!BN_mul(tmp, m1, q, ctx)) {
        WARN("Failed to calculate (q *((qinv *(m1 - m2)) mod p))\n");
        QATerr(QAT_F_CRT_COMBINE, QAT_R_COMPUTE_H_MULTIPLY_Q_FAILURE);
        goto err;
    }

    /* m2 + h*q */
    if (!BN_add(m1, tmp, m2)) {
        WARN("Failed to calculate ((q *((qinv *(m1 - m2)) mod p)) + m2)\n");
        QATerr(QAT_F_CRT_COMBINE, QAT_R_ADD_M2_FAILURE);
        goto err;
    }

    /* NOTE: BN convert to Bin function will omit the most left zeros
     * which is part of RSA padding partten, we need to keep these zeros
     */
    memset(output_buf->pData, 0, rsa_len);
    output_buf->dataLenInBytes = BN_bn2bin(m1, &output_buf->pData[rsa_len - BN_num_bytes(m1)]);
    output_buf->dataLenInBytes += rsa_len - BN_num_bytes(m1);

    ret = 1;

err:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;
}

int qat_rsa_decrypt_CRT(CpaCyRsaDecryptOpData * dec_op_data, int rsa_len,
                        CpaFlatBuffer * output_buf, int * fallback)
{
    CpaCyLnModExpOpData crt_op1_data = {{0}}, crt_op2_data = {{0}};
    CpaFlatBuffer crt_out1 = {0}, crt_out2 = {0};
    op_done_rsa_crt_t op_done;
    CpaStatus sts = CPA_STATUS_FAIL;
    int qatPerformOpRetries = 0;
    int inst_num = QAT_INVALID_INSTANCE;
    CpaCyRsaPrivateKey *cpa_prv_key = NULL;

    int iMsgRetry = getQatMsgRetryCount();
    useconds_t ulPollInterval = getQatPollInterval();
    int ret = 0, rv = 0;

    DEBUG("- Started\n");

    if (unlikely(rsa_len < 0)) { /* dec_op_data and output_buf are
                                  * already checked by calling function.
                                  */
        WARN("Invalid input param.\n");
        QATerr(QAT_F_QAT_RSA_DECRYPT_CRT, QAT_R_INPUT_PARAM_INVALID);
        return 0;
    }
    if (qat_init_op_done_rsa_crt(&op_done) != 1) {
        WARN("failed to init opdone for rsa crt\n");
        return 0;
    }

    CRYPTO_QAT_LOG("RSA - %s\n", __func__);

    if ((inst_num = get_next_inst_num()) == QAT_INVALID_INSTANCE) {
        WARN("Failure to get an instance\n");
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
            *fallback = 1;
        }
        else
            QATerr(QAT_F_QAT_RSA_DECRYPT_CRT, ERR_R_INTERNAL_ERROR);
        qat_cleanup_op_done_rsa_crt(&op_done);
        return 0;
    }

    DUMP_RSA_DECRYPT(qat_instance_handles[inst_num], &op_done, dec_op_data, output_buf);

    rv = CRT_prepare(&crt_out1, &crt_out2, rsa_len, dec_op_data,
                     &crt_op1_data, &crt_op2_data);
    if(rv == 0) {
        WARN("failed to execute CRT_prepare\n");
        QATerr(QAT_F_QAT_RSA_DECRYPT_CRT, ERR_R_INTERNAL_ERROR);
        qat_cleanup_op_done_rsa_crt(&op_done);
        goto err;
    }

    /* send the 1st ModExp request */
    do {
        sts = cpaCyLnModExp(qat_instance_handles[inst_num], qat_rsaCallbackFn_CRT, &op_done,
                            &crt_op1_data, &crt_out1);
        if (sts == CPA_STATUS_RETRY) {
            usleep(ulPollInterval +
                   (qatPerformOpRetries % QAT_RETRY_BACKOFF_MODULO_DIVISOR));
            qatPerformOpRetries++;
            if (iMsgRetry != QAT_INFINITE_MAX_NUM_RETRIES) {
                if (qatPerformOpRetries >= iMsgRetry) {
                    WARN("No. of retries exceeded max retry : %d\n", iMsgRetry);
                    break;
                }
            }
        }
    }
    while (sts == CPA_STATUS_RETRY);

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("sending 1st cpaCyLnModExp failed, sts=%d.\n", sts);
        if (qat_get_sw_fallback_enabled() && (sts == CPA_STATUS_RESTARTING || sts == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            *fallback = 1;
        }
        else
            QATerr(QAT_F_QAT_RSA_DECRYPT_CRT, ERR_R_INTERNAL_ERROR);
        qat_cleanup_op_done_rsa_crt(&op_done);
        goto err;
    } else {
        op_done.req++;
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
        }
    }

    /* send the 2nd ModExp request */
    do {
        sts = cpaCyLnModExp(qat_instance_handles[inst_num], qat_rsaCallbackFn_CRT, &op_done,
                            &crt_op2_data, &crt_out2);
        if (sts == CPA_STATUS_RETRY) {
            usleep(ulPollInterval +
                   (qatPerformOpRetries % QAT_RETRY_BACKOFF_MODULO_DIVISOR));
            qatPerformOpRetries++;
            if (iMsgRetry != QAT_INFINITE_MAX_NUM_RETRIES) {
                if (qatPerformOpRetries >= iMsgRetry) {
                    WARN("No. of retries exceeded max retry : %d\n", iMsgRetry);
                    break;
                }
            }
        }
    }
    while (sts == CPA_STATUS_RETRY);

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("sending 2nd cpaCyLnModExp failed, sts=%d.\n", sts);
        if (qat_get_sw_fallback_enabled() && (sts == CPA_STATUS_RESTARTING || sts == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            *fallback = 1;
        }
        else
            QATerr(QAT_F_QAT_RSA_DECRYPT_CRT, ERR_R_INTERNAL_ERROR);
    } else {
        op_done.req++;
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
        }
    }

    /* wait for replies */
    do {
        if(getEnableInlinePolling()) {
            icp_sal_CyPollInstance(qat_instance_handles[inst_num], 0);
        }
        else
            pthread_yield();
    } while(op_done.req != op_done.resp);

    /* discard results if the 2nd request sending failed */
    if (op_done.req != 2) {
        WARN("failed to send 2 ModExp requests\n");
        QATerr(QAT_F_QAT_RSA_DECRYPT_CRT, ERR_R_INTERNAL_ERROR);
        qat_cleanup_op_done_rsa_crt(&op_done);
        goto err;
    }

    if (op_done.opDone.verifyResult != CPA_TRUE) {
        WARN("Verification of result failed\n");
        if (qat_get_sw_fallback_enabled() && op_done.opDone.status == CPA_STATUS_FAIL) {
            CRYPTO_QAT_LOG("Verification of result failed for qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            *fallback = 1;
        }
        else
            QATerr(QAT_F_QAT_RSA_DECRYPT_CRT, ERR_R_INTERNAL_ERROR);
        qat_cleanup_op_done_rsa_crt(&op_done);
        goto err;
    }

    qat_cleanup_op_done_rsa_crt(&op_done);
    cpa_prv_key = dec_op_data->pRecipientPrivateKey;
    rv = CRT_combine(&crt_out1, &crt_out2, rsa_len, output_buf, cpa_prv_key);
    if (rv  == 0) {
        WARN("failed to execute CRT_combine\n");
        QATerr(QAT_F_QAT_RSA_DECRYPT_CRT, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    DUMP_RSA_DECRYPT_OUTPUT(output_buf);

    ret = 1;

err:
    QAT_CHK_CLNSE_QMFREE_FLATBUFF(crt_op1_data.base);
    QAT_CHK_CLNSE_QMFREE_FLATBUFF(crt_op2_data.base);
    QAT_CHK_CLNSE_QMFREE_FLATBUFF(crt_out1);
    QAT_CHK_CLNSE_QMFREE_FLATBUFF(crt_out2);

    DEBUG("- Finished\n");
    return ret;
}
#endif /* #ifndef OPENSSL_DISABLE_QAT_RSA */
