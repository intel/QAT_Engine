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
 * @file qat_rsa.c
 *
 * This file contains the engine implementations for RSA operations
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define __USE_GNU

#include <pthread.h>
#include <openssl/rsa.h>
#include <openssl/async.h>
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

#include "cpa.h"
#include "cpa_types.h"

#include "cpa_cy_rsa.h"
#include "qat_rsa.h"
#include "qat_asym_common.h"
#include "e_qat_err.h"

#ifdef OPENSSL_ENABLE_QAT_RSA
# ifdef OPENSSL_DISABLE_QAT_RSA
#  undef OPENSSL_DISABLE_QAT_RSA
# endif
#endif

/* To specify the RSA op sizes supported by QAT engine */
#define RSA_QAT_RANGE_MIN 512
#define RSA_QAT_RANGE_MAX 4096

#define NO_PADDING 0
#define PADDING    1

#ifndef OPENSSL_DISABLE_QAT_RSA
/* Qat engine RSA methods declaration */
static int qat_rsa_priv_enc(int flen, const unsigned char *from,
                           unsigned char *to, RSA *rsa, int padding);
static int qat_rsa_priv_dec(int flen, const unsigned char *from,
                           unsigned char *to, RSA *rsa, int padding);
static int qat_rsa_pub_enc(int flen, const unsigned char *from,
                          unsigned char *to, RSA *rsa, int padding);
static int qat_rsa_pub_dec(int flen, const unsigned char *from,
                          unsigned char *to, RSA *rsa, int padding);
static int qat_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx);
static int qat_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                   const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);

/* Callback to indicate QAT completion of RSA. */
void qat_rsaCallbackFn(void *pCallbackTag,
                       CpaStatus status, void *pOpData, CpaFlatBuffer * pOut);
#endif

static RSA_METHOD *qat_rsa_method = NULL;

RSA_METHOD *qat_get_RSA_methods(void)
{
    if (qat_rsa_method != NULL)
        return qat_rsa_method;

#ifndef OPENSSL_DISABLE_QAT_RSA
    if ((qat_rsa_method = RSA_meth_new("QAT RSA method", 0)) == NULL
        || RSA_meth_set_pub_enc(qat_rsa_method, qat_rsa_pub_enc) == 0
        || RSA_meth_set_pub_dec(qat_rsa_method, qat_rsa_pub_dec) == 0
        || RSA_meth_set_priv_enc(qat_rsa_method, qat_rsa_priv_enc) == 0
        || RSA_meth_set_priv_dec(qat_rsa_method, qat_rsa_priv_dec) == 0
        || RSA_meth_set_mod_exp(qat_rsa_method, qat_rsa_mod_exp) == 0
        || RSA_meth_set_bn_mod_exp(qat_rsa_method, qat_bn_mod_exp) == 0) {
        WARN("Failed to set QAT RSA methods\n");
        QATerr(QAT_F_QAT_GET_RSA_METHODS, QAT_R_SET_QAT_RSA_METH_FAILURE);
        return NULL;
    }
#else
    qat_rsa_method = (RSA_METHOD *)RSA_get_default_method();
#endif

    return qat_rsa_method;
}

void qat_free_RSA_methods(void)
{
#ifndef OPENSSL_DISABLE_QAT_RSA
    if (qat_rsa_method != NULL) {
        RSA_meth_free(qat_rsa_method);
        qat_rsa_method = NULL;
    } else {
        WARN("qat_rsa_method is NULL\n");
        QATerr(QAT_F_QAT_FREE_RSA_METHODS, QAT_R_FREE_QAT_RSA_METH_FAILURE);
    }
#endif
}

#ifndef OPENSSL_DISABLE_QAT_RSA
/*
 * The RSA range check is performed so that if the op sizes are not in the
 * range supported by QAT engine then fall back to software
 */

static inline int qat_rsa_range_check(int plen)
{
    return ((plen >= RSA_QAT_RANGE_MIN) && (plen <= RSA_QAT_RANGE_MAX));
}

/******************************************************************************
* function:
*         qat_alloc_pad(unsigned char *in,
*                       int len,
*                       int rLen,
*                       int sign)
*
* @param in   [IN] - pointer to Flat Buffer
* @param len  [IN] - length of input data (hash)
* @param rLen [IN] - length of RSA
* @param sign [IN] - 1 for sign operation and 0 for decryption
*
* description:
*   This function is used to add PKCS#1 padding into input data buffer
*   before it pass to cpaCyRsaDecrypt() function.
*   The function returns a pointer to unsigned char buffer
******************************************************************************/
static unsigned char *qat_alloc_pad(unsigned char *in, int len,
                                    int rLen, int sign)
{
    int i = 0;

    /* out data buffer should have fix length */
    unsigned char *out = qaeCryptoMemAlloc(rLen, __FILE__, __LINE__);

    DEBUG("- Started\n");

    if (NULL == out) {
        WARN("out buffer malloc failed\n");
        QATerr(QAT_F_QAT_ALLOC_PAD, QAT_R_OUT_MALLOC_FAILURE);
        return NULL;
    }

    /* First two char are (0x00, 0x01) or (0x00, 0x02) */
    out[0] = 0x00;

    if (sign) {
        out[1] = 0x01;
    } else {
        out[1] = 0x02;
    }

    /*
     * Fill 0xff and end up with 0x00 in out buffer until the length of
     * actual data space left
     */
    for (i = 2; i < (rLen - len - 1); i++) {
        out[i] = 0xff;
    }
    /*
     * i has been incremented on beyond the last padding byte to exit for
     * loop
     */
    out[i] = 0x00;

    /* shift actual data to the end of out buffer */
    memcpy((out + rLen - len), in, len);

    DEBUG("- Finished\n");
    return out;
}

/******************************************************************************
* function:
*         qat_data_len(unsigned char *in
*                      int  rLen, int sign)
*
* @param in   [IN] - pointer to Flat Buffer
* @param rLen [IN] - length of RSA
* @param sign [IN] - 1 for sign operation and 0 for decryption
*
* description:
*   This function is used to calculate the length of actual data
*   and padding size inside of outputBuffer returned from cpaCyRsaEncrypt() function.
*   The function counts the padding length (i) and return the length
*   of actual data (dLen) contained in the outputBuffer
******************************************************************************/
static int qat_data_len(unsigned char *in, int rLen, int sign)
{
    /* first two bytes are 0x00, 0x01 */
    int i = 0;
    int dLen = 0;
    int pLen = 0;

    DEBUG("- Started\n");

    /* First two char of padding should be 0x00, 0x01 */
    if (sign) {
        /* First two char of padding should be 0x00, 0x01 */
        if (in[0] != 0x00 || in[1] != 0x01) {
            WARN("Sign: Padding format unknown\n");
            QATerr(QAT_F_QAT_DATA_LEN, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else {
        /* First two char of padding should be 0x00, 0x02 for decryption */
        if (in[0] != 0x00 || in[1] != 0x02) {
            WARN("Decryption: Padding format unknown\n");
            QATerr(QAT_F_QAT_DATA_LEN, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    /*
     * while loop is design to reach the 0x00 value and count all the 0xFF
     * value where filled by PKCS#1 padding
     */
    while (in[i + 2] != 0x00 && i < rLen)
        i++;

    /* padding length = 2 + length of 0xFF + 0x00 */
    pLen = 2 + i + 1;
    dLen = rLen - pLen;

    if (dLen < 0) {
        dLen = 0;
    }

    DEBUG("- Finished\n");
    return dLen;
}

/******************************************************************************
* function:
*         qat_remove_pad(unsigned char *out
*                        unsigned char *in,
*                        int r_len,
*                        int out_len,
*                        int sign,
*                        int padding)
*
* @param out     [OUT] - pointer to a Flat Buffer
* @param in      [IN] -  pointer to a Flat Buffer
* @param r_len   [IN] -  length of the RSA data
* @param out_len [OUT] - length of the output data after the padding has
                         been removed
* @param sign    [IN] -  1 for sign operation and 0 for decryption
* @param padding [IN] -  type of padding
*
* description:
*   This function is used to remove PKCS#1 padding from outputBuffer
*   after cpaCyRsaEncrypt() function during RSA verify if that is the type of
*   padding passed in.  However, if the type of padding is RSA_NO_PADDING, then
*   all the data in the 'in' buffer is copied to the 'out' buffer.
******************************************************************************/
static int qat_remove_pad(unsigned char *out, unsigned char *in,
                          int r_len, int *out_len, int sign, int padding)
{
    int p_len = 0;
    int d_len = 0;

    DEBUG("- Started\n");

    if (padding == RSA_NO_PADDING) {
        memcpy(out, in, r_len);
        *out_len = r_len;
    }
    else { /* should be RSA_PKCS1_PADDING */
        if (0 == (d_len = qat_data_len(in, r_len, sign))) {
            WARN("Unable to get Data Length\n");
            QATerr(QAT_F_QAT_REMOVE_PAD, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        p_len = r_len - d_len;

        /* shift actual data to the beginning of out buffer */
        memcpy(out, in + p_len, d_len);
        *out_len = d_len;
    }

    DEBUG("- Finished\n");
    return 1;
}

/******************************************************************************
* function:
*         qat_rsaCallbackFn(void *pCallbackTag, CpaStatus status,
*                           void *pOpData, CpaFlatBuffer * pOut)
*
* @param pCallbackTag   [IN]  - Opaque User Data for this specific call. Will
*                               be returned unchanged in the callback.
* @param status         [IN]  - Status result of the RSA operation.
* @param pOpData        [IN]  - Structure containing all the data needed to
*                               perform the RSA encryption operation.
* @param pOut           [IN]  - Pointer to buffer into which the result of
*                               the RSA encryption is written.
* description:
*   Callback function used by RSA operations to indicate completion.
*   Calls back to qat_crypto_callbackFn() as functionally it does the same.
*
******************************************************************************/
void qat_rsaCallbackFn(void *pCallbackTag, CpaStatus status, void *pOpData,
                       CpaFlatBuffer * pOut)
{
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, CPA_TRUE);
}

static void
rsa_decrypt_op_buf_free(CpaCyRsaDecryptOpData * dec_op_data,
                        CpaFlatBuffer * out_buf, int padding)
{
    CpaCyRsaPrivateKeyRep2 *key = NULL;
    DEBUG("- Started\n");

    if (dec_op_data) {
        if (dec_op_data->inputData.pData)
            qaeCryptoMemFree(dec_op_data->inputData.pData);

        if (dec_op_data->pRecipientPrivateKey) {
            key = &dec_op_data->pRecipientPrivateKey->privateKeyRep2;
            QAT_CHK_CLNSE_QMFREE_FLATBUFF(key->prime1P);
            QAT_CHK_CLNSE_QMFREE_FLATBUFF(key->prime2Q);
            QAT_CHK_CLNSE_QMFREE_FLATBUFF(key->exponent1Dp);
            QAT_CHK_CLNSE_QMFREE_FLATBUFF(key->exponent2Dq);
            QAT_CHK_CLNSE_QMFREE_FLATBUFF(key->coefficientQInv);
            OPENSSL_free(dec_op_data->pRecipientPrivateKey);
        }
        OPENSSL_free(dec_op_data);
    }

    if (out_buf) {
        if (out_buf->pData)
            qaeCryptoMemFree(out_buf->pData);
        OPENSSL_free(out_buf);
    }
    DEBUG("- Finished\n");
}

int
qat_rsa_decrypt(CpaCyRsaDecryptOpData * dec_op_data,
                CpaFlatBuffer * output_buf)
{
    /* Used for RSA Decrypt and RSA Sign */
    struct op_done op_done;
    CpaStatus sts = CPA_STATUS_FAIL;
    int qatPerformOpRetries = 0;
    CpaInstanceHandle instance_handle = NULL;

    int iMsgRetry = getQatMsgRetryCount();
    useconds_t ulPollInterval = getQatPollInterval();

    DEBUG("- Started\n");

    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failed to setup async event notifications\n");
            QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            return 0;
        }
    }
    /*
     * cpaCyRsaDecrypt() is the function called for RSA verify in API, the
     * DecOpData [IN] contains both private key value and input file (hash)
     * value, the outputBuffer [OUT] stores the signature as the output
     * message, the sts value return 0 if successful
     */
    CRYPTO_QAT_LOG("- RSA\n");
    do {
        if (NULL == (instance_handle = get_next_inst())) {
            WARN("Failed to get an instance\n");
            QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
            if (op_done.job != NULL) {
                qat_clear_async_event_notification();
            }
            qat_cleanup_op_done(&op_done);
            return 0;
        }
        sts = cpaCyRsaDecrypt(instance_handle, qat_rsaCallbackFn, &op_done,
                              dec_op_data, output_buf);
        if (sts == CPA_STATUS_RETRY) {
            if (op_done.job == NULL) {
                usleep(ulPollInterval +
                       (qatPerformOpRetries % QAT_RETRY_BACKOFF_MODULO_DIVISOR));
                qatPerformOpRetries++;
                if (iMsgRetry != QAT_INFINITE_MAX_NUM_RETRIES) {
                    if (qatPerformOpRetries >= iMsgRetry) {
                        WARN("No. of retries exceeded max retry : %d\n", iMsgRetry);
						QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
                        break;
                    }
                }
            } else {
                if ((qat_wake_job(op_done.job, 0) == 0) ||
                    (qat_pause_job(op_done.job, 0) == 0)) {
                    WARN("qat_wake_job or qat_pause_job failed\n");
                    QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
                    sts = CPA_STATUS_FAIL;
                    break;
                }
            }
        }
    }
    while (sts == CPA_STATUS_RETRY);

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", sts);
        QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
        if (op_done.job != NULL) {
            qat_clear_async_event_notification();
        }
        qat_cleanup_op_done(&op_done);
        return 0;
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
            if (qat_pause_job(op_done.job, 0) == 0)
                pthread_yield();
        } else {
            pthread_yield();
        }
    }
    while (!op_done.flag);

    qat_cleanup_op_done(&op_done);

    if (op_done.verifyResult != CPA_TRUE) {
        WARN("Verification of result failed\n");
        QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    DEBUG("- Finished\n");
    return 1;
}

static int
build_decrypt_op_buf(int flen, const unsigned char *from, unsigned char *to,
                     RSA *rsa, int padding,
                     CpaCyRsaDecryptOpData ** dec_op_data,
                     CpaFlatBuffer ** output_buffer, int alloc_pad)
{
    int rsa_len = 0;
    CpaCyRsaPrivateKey *cpa_prv_key = NULL;
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *dmp1 = NULL;
    const BIGNUM *dmq1 = NULL;
    const BIGNUM *iqmp = NULL;

    DEBUG("- Started\n");

    RSA_get0_factors((const RSA*)rsa, &p, &q);
    RSA_get0_crt_params((const RSA*)rsa, &dmp1, &dmq1, &iqmp);

    if (p == NULL || q == NULL || dmp1 == NULL || dmq1 == NULL || iqmp == NULL) {
        WARN("Either p %p, q %p, dmp1 %p, dmq1 %p, iqmp %p are NULL\n",
              p, q, dmp1, dmq1, iqmp);
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_P_Q_DMP_DMQ_IQMP_NULL);
        return 0;
    }

    /* Padding check */
    if ((padding != RSA_NO_PADDING) && (padding != RSA_PKCS1_PADDING)) {
        WARN("Unknown Padding %d\n", padding);
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_PADDING_UNKNOWN);
        return 0;
    }

    cpa_prv_key =
        (CpaCyRsaPrivateKey *) OPENSSL_zalloc(sizeof(CpaCyRsaPrivateKey));
    if (NULL == cpa_prv_key) {
        WARN("Failed to allocate cpa_prv_key\n");
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_PRIV_KEY_MALLOC_FAILURE);
        return 0;
    }

    DEBUG("flen =%d, padding = %d \n", flen, padding);
    /* output signature should have same length as RSA(128) */
    rsa_len = RSA_size(rsa);

    /* output and input data MUST allocate memory for sign process */
    /* memory allocation for DecOpdata[IN] */
    *dec_op_data = OPENSSL_zalloc(sizeof(CpaCyRsaDecryptOpData));
    if (NULL == *dec_op_data) {
        WARN("Failed to allocate dec_op_data\n");
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_DEC_OP_DATA_MALLOC_FAILURE);
        OPENSSL_free(cpa_prv_key);
        return 0;
    }

    /* Setup the DecOpData structure */
    (*dec_op_data)->pRecipientPrivateKey = cpa_prv_key;

    cpa_prv_key->version = CPA_CY_RSA_VERSION_TWO_PRIME;

    /* Setup the private key rep type 2 structure */
    cpa_prv_key->privateKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2;
    if (qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.prime1P, p) != 1 ||
        qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.prime2Q, q) != 1 ||
        qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.exponent1Dp, dmp1) != 1 ||
        qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.exponent2Dq, dmq1) != 1 ||
        qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.coefficientQInv, iqmp) != 1) {
        WARN("Failed to convert privateKeyRep2 elements to flatbuffer\n");
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_P_Q_DMP_DMQ_CONVERT_TO_FB_FAILURE);
        return 0;
    }

    if (alloc_pad) {
        (*dec_op_data)->inputData.pData =
            qat_alloc_pad((Cpa8U *) from, flen, rsa_len, 1);
    } else {
        (*dec_op_data)->inputData.pData =
            (Cpa8U *) copyAllocPinnedMemory((void *)from, flen, __FILE__,
                                            __LINE__);
    }

    if (NULL == (*dec_op_data)->inputData.pData) {
        WARN("Failed to allocate (*dec_op_data)->inputData.pData\n");
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_INPUT_DATA_MALLOC_FAILURE);
        return 0;
    }

    if (alloc_pad)
        (*dec_op_data)->inputData.dataLenInBytes = rsa_len;
    else
        (*dec_op_data)->inputData.dataLenInBytes = flen;

    *output_buffer = OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (NULL == *output_buffer) {
        WARN("Failed to allocate output_buffer\n");
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_OUTPUT_BUF_MALLOC_FAILURE);
        return 0;
    }

    /*
     * Memory allocation for DecOpdata[IN] the size of outputBuffer
     * should big enough to contain RSA_size
     */
    (*output_buffer)->pData =
        (Cpa8U *) qaeCryptoMemAlloc(rsa_len, __FILE__, __LINE__);

    if (NULL == (*output_buffer)->pData) {
        WARN("Failed to allocate output_buffer->pData\n");
        QATerr(QAT_F_BUILD_DECRYPT_OP_BUF, QAT_R_RSA_OUTPUT_BUF_PDATA_MALLOC_FAILURE);
        return 0;
    }
    (*output_buffer)->dataLenInBytes = rsa_len;

    DEBUG("- Finished\n");
    return 1;
}

static void
rsa_encrypt_op_buf_free(CpaCyRsaEncryptOpData * enc_op_data,
                        CpaFlatBuffer * out_buf, int padding)
{
    DEBUG("- Started\n");

    if (enc_op_data) {
        if (enc_op_data->pPublicKey) {
            if (enc_op_data->pPublicKey->modulusN.pData)
                qaeCryptoMemFree(enc_op_data->pPublicKey->modulusN.pData);
            if (enc_op_data->pPublicKey->publicExponentE.pData)
                qaeCryptoMemFree(enc_op_data->pPublicKey->
                                 publicExponentE.pData);
            OPENSSL_free(enc_op_data->pPublicKey);
        }
        if (enc_op_data->inputData.pData)
            qaeCryptoMemFree(enc_op_data->inputData.pData);
        OPENSSL_free(enc_op_data);
    }

    if (out_buf) {
        if (out_buf->pData)
            qaeCryptoMemFree(out_buf->pData);
        OPENSSL_free(out_buf);
    }
    DEBUG("- Finished\n");
}

int
qat_rsa_encrypt(CpaCyRsaEncryptOpData * enc_op_data,
                CpaFlatBuffer * output_buf)
{
    /* Used for RSA Encrypt and RSA Verify */
    struct op_done op_done;
    CpaStatus sts = CPA_STATUS_FAIL;
    int qatPerformOpRetries = 0;
    CpaInstanceHandle instance_handle = NULL;

    int iMsgRetry = getQatMsgRetryCount();
    useconds_t ulPollInterval = getQatPollInterval();

    DEBUG("- Started\n");

    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(0) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            return 0;
        }
    }
    /*
     * cpaCyRsaEncrypt() is the function called for RSA verify in API, the
     * DecOpData [IN] contains both private key value and input file (hash)
     * value, the outputBuffer [OUT] stores the signature as the output
     * message, the sts value return 0 if successful
     */
    CRYPTO_QAT_LOG("RSA - %s\n", __func__);
    do {
        if (NULL == (instance_handle = get_next_inst())) {
            WARN("Failed to get an instance\n");
            QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
            if (op_done.job != NULL) {
                qat_clear_async_event_notification();
            }
            qat_cleanup_op_done(&op_done);
            return 0;
        }

        sts = cpaCyRsaEncrypt(instance_handle, qat_rsaCallbackFn, &op_done,
                              enc_op_data, output_buf);
        if (sts == CPA_STATUS_RETRY) {
            if (op_done.job == NULL) {
                usleep(ulPollInterval +
                       (qatPerformOpRetries % QAT_RETRY_BACKOFF_MODULO_DIVISOR));
                qatPerformOpRetries++;
                if (iMsgRetry != QAT_INFINITE_MAX_NUM_RETRIES) {
                    if (qatPerformOpRetries >= iMsgRetry) {
                        WARN("No. of retries exceeded max retry : %d\n", iMsgRetry);
                        QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
                        break;
                    }
                }
            } else {
                if ((qat_wake_job(op_done.job, 0) == 0) ||
                    (qat_pause_job(op_done.job, 0) == 0)) {
                    sts = CPA_STATUS_FAIL;
                    WARN("qat_wake_job or qat_pause_job failed\n");
                    QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
                    break;
                }
            }
        }
    }
    while (sts == CPA_STATUS_RETRY);

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("Failed to submit request to qat - status = %d\n", sts);
        QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
        if (op_done.job != NULL) {
            qat_clear_async_event_notification();
        }
        qat_cleanup_op_done(&op_done);
        return 0;
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
            if (qat_pause_job(op_done.job, 0) == 0)
                pthread_yield();
        } else {
            pthread_yield();
        }
    } while (!op_done.flag);

    qat_cleanup_op_done(&op_done);

    if (op_done.verifyResult != CPA_TRUE) {
        WARN("Verification of result failed\n");
        QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
build_encrypt_op(int flen, const unsigned char *from, unsigned char *to,
                 RSA *rsa, int padding,
                 CpaCyRsaEncryptOpData ** enc_op_data,
                 CpaFlatBuffer ** output_buffer, int alloc_pad)
{
    CpaCyRsaPublicKey *cpa_pub_key = NULL;
    int rsa_len = 0;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;

    DEBUG("- Started\n");

    RSA_get0_key((const RSA*)rsa, &n, &e, &d);

    /* Note: not checking 'd' as it is not used */
    if (n == NULL || e == NULL) {
        WARN("RSA key values n = %p or e = %p are NULL\n", n, e);
        QATerr(QAT_F_BUILD_ENCRYPT_OP, QAT_R_N_E_NULL);
        return 0;
    }

    if (padding != RSA_PKCS1_PADDING) {
        WARN("Unknown Padding %d\n", padding);
        QATerr(QAT_F_BUILD_ENCRYPT_OP, QAT_R_UNKNOWN_PADDING);
        return 0;
    }

    cpa_pub_key = OPENSSL_zalloc(sizeof(CpaCyRsaPublicKey));
    if (NULL == cpa_pub_key) {
        WARN("Public Key zalloc failed\n");
        QATerr(QAT_F_BUILD_ENCRYPT_OP, QAT_R_PUB_KEY_MALLOC_FAILURE);
        return 0;
    }

    rsa_len = RSA_size(rsa);

    /* Output and input data MUST allocate memory for RSA verify process */
    /* Memory allocation for EncOpData[IN] */
    *enc_op_data = OPENSSL_zalloc(sizeof(CpaCyRsaEncryptOpData));
    if (NULL == *enc_op_data) {
        WARN("Failed to allocate enc_op_data\n");
        QATerr(QAT_F_BUILD_ENCRYPT_OP, QAT_R_ENC_OP_DATA_MALLOC_FAILURE);
        OPENSSL_free(cpa_pub_key);
        return 0;
    }

    /* Setup the Encrypt operation Data structure */
    (*enc_op_data)->pPublicKey = cpa_pub_key;

    DEBUG("flen=%d padding=%d\n", flen, padding);

    /* Passing Public key from big number format to big endian order binary */
    if (qat_BN_to_FB(&cpa_pub_key->modulusN, n) != 1 ||
        qat_BN_to_FB(&cpa_pub_key->publicExponentE, e) != 1) {
        WARN("Failed to convert cpa_pub_key elements to flatbuffer\n");
        QATerr(QAT_F_BUILD_ENCRYPT_OP, QAT_R_N_E_CONVERT_TO_FB_FAILURE);
        return 0;
    }

    if (alloc_pad) {
        (*enc_op_data)->inputData.pData =
            qat_alloc_pad((Cpa8U *) from, flen, rsa_len, 0);
    } else {
        (*enc_op_data)->inputData.pData =
            (Cpa8U *) copyAllocPinnedMemory((void *)from, flen, __FILE__,
                                            __LINE__);
    }

    if (NULL == (*enc_op_data)->inputData.pData) {
        WARN("Failed to allocate (*enc_op_data)->inputData.pData\n");
        QATerr(QAT_F_BUILD_ENCRYPT_OP, QAT_R_INPUT_DATA_MALLOC_FAILURE);
        return 0;
    }

    if (alloc_pad)
        (*enc_op_data)->inputData.dataLenInBytes = rsa_len;
    else
        (*enc_op_data)->inputData.dataLenInBytes = flen;

    /*
     * Memory allocation for outputBuffer[OUT] OutputBuffer size initialize
     * as the size of rsa size
     */
    (*output_buffer) =
        (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (NULL == (*output_buffer)) {
        WARN("Failed to allocate output_buffer\n");
        QATerr(QAT_F_BUILD_ENCRYPT_OP, QAT_R_OUTPUT_BUF_MALLOC_FAILURE);
        return 0;
    }

    /*
     * outputBuffer size should large enough to hold the Hash value but
     * smaller than (RSA_size(rsa)-11)
     */
    (*output_buffer)->dataLenInBytes = rsa_len;
    (*output_buffer)->pData = qaeCryptoMemAlloc(rsa_len, __FILE__, __LINE__);
    if (NULL == (*output_buffer)->pData) {
        WARN("Failed to allocate (*output_buffer)->pData\n");
        QATerr(QAT_F_BUILD_ENCRYPT_OP, QAT_R_OUTPUT_BUF_PDATA_MALLOC_FAILURE);
        return 0;;
    }

    DEBUG("- Finished\n");
    return 1;
}

/******************************************************************************
* function:
*         qat_rsa_priv_enc (int flen,
*                           const unsigned char *from,
*                           unsigned char *to,
*                           RSA *rsa,
*                           int padding)
*
* @param flen    [IN]  - length in bytes of input file
* @param from    [IN]  - pointer to the input file
* @param to      [OUT] - pointer to output signature
* @param rsa     [IN]  - pointer to private key structure
* @param padding [IN]  - Padding scheme
*
* description: Perform an RSA private encrypt (RSA Sign)
*              We use the decrypt implementation to achieve this.
******************************************************************************/
int
qat_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to,
                 RSA *rsa, int padding)
{
    int rsa_len = 0;
    CpaCyRsaDecryptOpData *dec_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;
    int sts = 1;

    DEBUG("- Started.\n");

    /* Parameter Checking */
    /*
     * The input message length should less than RSA size and also have
     * minimum space of PKCS1 padding(4 bytes)
     */
    if (rsa == NULL || from == NULL || to == NULL ||
        (flen > ((rsa_len = RSA_size(rsa)) - 4))
        || flen == 0) {
        WARN("RSA key, input or output is NULL or invalid length, \
              flen = %d, rsa_len = %d\n", flen, rsa_len);
        QATerr(QAT_F_QAT_RSA_PRIV_ENC, QAT_R_RSA_FROM_TO_NULL);
        goto exit;
    }

    /*
    * If the op sizes are not in the range supported by QAT engine then fall
    * back to software
    */

    if (!qat_rsa_range_check(RSA_bits((const RSA*)rsa)))
        return RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())
                                     (flen, from, to, rsa, padding);

    if (1 != build_decrypt_op_buf(flen, from, to, rsa, padding,
                                  &dec_op_data, &output_buffer, PADDING)) {
        WARN("Failure in build_decrypt_op_buf\n");
        QATerr(QAT_F_QAT_RSA_PRIV_ENC, ERR_R_INTERNAL_ERROR);
        sts = 0;
        goto exit;
    }

    if (1 != qat_rsa_decrypt(dec_op_data, output_buffer)) {
        WARN("Failure in qat_rsa_decrypt\n");
        QATerr(QAT_F_QAT_RSA_PRIV_ENC, ERR_R_INTERNAL_ERROR);
        sts = 0;
        goto exit;
    }
    memcpy(to, output_buffer->pData, rsa_len);

    rsa_decrypt_op_buf_free(dec_op_data, output_buffer, PADDING);

    DEBUG("- Finished\n");
    return rsa_len;

 exit:

    /* Free all the memory allocated in this function */
    rsa_decrypt_op_buf_free(dec_op_data, output_buffer, PADDING);

    /* set output all 0xff if failed */
    if (!sts)
        memset(to, 0xff, rsa_len);

    /* Return an error */
    return 0;
}

/******************************************************************************
* function:
*         qat_rsa_priv_dec(int flen,
*                          const unsigned char *from,
*                          unsigned char *to,
*                          RSA * rsa,
*                          int padding)
*
* @param flen    [IN]  - length in bytes of input
* @param from    [IN]  - pointer to the input
* @param to      [OUT] - pointer to output
* @param rsa     [IN]  - pointer to the private key structure
* @param padding [IN]  - Padding scheme
*
* description:
* description: Perform an RSA private decrypt. (RSA Decrypt)
******************************************************************************/
int qat_rsa_priv_dec(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding)
{
    int rsa_len = 0;
    int output_len = 0;
    int sts = 1;
    CpaCyRsaDecryptOpData *dec_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;

    DEBUG("- Started.\n");

    /* parameter checks */
    if (rsa == NULL || from == NULL || to == NULL ||
        (flen != (rsa_len = RSA_size(rsa)))) {
        WARN("RSA key, input or output is NULL or invalid length, \
              flen = %d, rsa_len = %d\n", flen, rsa_len);
        QATerr(QAT_F_QAT_RSA_PRIV_DEC, QAT_R_RSA_FROM_TO_NULL);
        return 0;
    }

    /*
    * If the op sizes are not in the range supported by QAT engine then fall
    * back to software
    */

    if (!qat_rsa_range_check(RSA_bits((const RSA*)rsa)))
        return RSA_meth_get_priv_dec(RSA_PKCS1_OpenSSL())
                                     (flen, from, to, rsa, padding);

    if (1 != build_decrypt_op_buf(flen, from, to, rsa, padding,
                                  &dec_op_data, &output_buffer, NO_PADDING)) {
        WARN("Failure in build_decrypt_op_buf\n");
        QATerr(QAT_F_QAT_RSA_PRIV_DEC, ERR_R_INTERNAL_ERROR);
        sts = 0;
        goto exit;
    }

    if (1 != qat_rsa_decrypt(dec_op_data, output_buffer)) {
        WARN("Failure in qat_rsa_decrypt\n");
        QATerr(QAT_F_QAT_RSA_PRIV_DEC, ERR_R_INTERNAL_ERROR);
        sts = 0;
        goto exit;
    }
    /* Copy output to output buffer */
    if (qat_remove_pad(to, output_buffer->pData, rsa_len, &output_len,
                       0, padding) != 1) {
        WARN("Failure in qat_remove_pad\n");
        QATerr(QAT_F_QAT_RSA_PRIV_DEC, ERR_R_INTERNAL_ERROR);
        sts = 0;
        goto exit;
    }

    rsa_decrypt_op_buf_free(dec_op_data, output_buffer, NO_PADDING);

    DEBUG("- Finished\n");
    return output_len;

 exit:
    /* Free all the memory allocated in this function */
    rsa_decrypt_op_buf_free(dec_op_data, output_buffer, NO_PADDING);

    /* set output all 0xff if failed */
    if (!sts && to)
        memset(to, 0xff, rsa_len);
    return 0;
}

/******************************************************************************
* function:
*         qat_rsa_pub_enc(int flen,
*                         const unsigned char *from,
*                         unsigned char *to,
*                         RSA *rsa,
*                         int padding)
*
* @param flen    [IN]  - size in bytes of input
* @param from    [IN]  - pointer to the input
* @param to      [OUT] - pointer to output data
* @param rsa     [IN]  - pointer to public key structure
* @param padding [IN]  - Padding scheme
*
*
* description:
*   This function is rewrite of OpenSSL RSA_pub_enc() function. (RSA Encrypt)
*   All the inputs are pass form the above OpenSSL layer to the corresponding
*   API RSA sign function cpaCyRsaEncrypt().
******************************************************************************/
int qat_rsa_pub_enc(int flen, const unsigned char *from,
                           unsigned char *to, RSA *rsa, int padding)
{
    int rsa_len = 0;
    CpaCyRsaEncryptOpData *enc_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;
    int sts = 1;

    DEBUG("- Started\n");

    /* parameter checks */
    if (rsa == NULL || from == NULL || to == NULL ||
        (flen > (rsa_len = RSA_size(rsa)) - 11)) {
        WARN("RSA key %p, input %p or output %p are NULL or invalid length, \
              flen = %d, rsa_len = %d\n", rsa, from, to, flen, rsa_len);
        QATerr(QAT_F_QAT_RSA_PUB_ENC, QAT_R_RSA_FROM_TO_NULL);
        goto exit;
    }

    /*
    * If the op sizes are not in the range supported by QAT engine then fall
    * back to software
    */

    if (!qat_rsa_range_check(RSA_bits((const RSA*)rsa)))
        return RSA_meth_get_pub_enc(RSA_PKCS1_OpenSSL())
                                    (flen, from, to, rsa, padding);

    if (1 != build_encrypt_op(flen, from, to, rsa, padding,
                              &enc_op_data, &output_buffer, PADDING)) {
        WARN("Failure in build_encrypt_op\n");
        QATerr(QAT_F_QAT_RSA_PUB_ENC, ERR_R_INTERNAL_ERROR);
        sts = 0;
        goto exit;
    }

    if (1 != qat_rsa_encrypt(enc_op_data, output_buffer)) {
        WARN("Failure in qat_rsa_encrypt\n");
        QATerr(QAT_F_QAT_RSA_PUB_ENC, ERR_R_INTERNAL_ERROR);
        sts = 0;
        goto exit;

    } else {
        memcpy(to, output_buffer->pData, output_buffer->dataLenInBytes);
    }
    rsa_encrypt_op_buf_free(enc_op_data, output_buffer, PADDING);

    DEBUG("- Finished\n");
    return rsa_len;
 exit:
    /* Free all the memory allocated in this function */
    rsa_encrypt_op_buf_free(enc_op_data, output_buffer, PADDING);

    /* set output all 0xff if failed */
    if (!sts)
        memset(to, 0xff, rsa_len);
    return 0;
}

/******************************************************************************
* function:
*         qat_rsa_pub_dec(int flen,
*                         const unsigned char *from,
*                         unsigned char *to,
*                         RSA *rsa,
*                         int padding)
*
* @param flen    [IN]  - size in bytes of input
* @param from    [IN]  - pointer to the input
* @param to      [OUT] - pointer to output data
* @param rsa     [IN]  - pointer to public key structure
* @param padding [IN]  - Padding scheme
*
* description:
*   This function is rewrite of OpenSSL RSA_pub_dec() function (RSA Verify)
*   All the inputs are pass form the above OpenSSL layer to the corresponding
*   API RSA verify function cpaCyRsaEncrypt().
*   The function returns the RSA recovered message output.
*   We use the encrypt implementation to achieve this.
******************************************************************************/
int
qat_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to,
                RSA *rsa, int padding)
{
    int rsa_len = 0;
    int output_len = 0;
    CpaCyRsaEncryptOpData *enc_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;
    int sts = 1;

    DEBUG("- Started\n");

    /* parameter checking */
    if (rsa == NULL || from == NULL || to == NULL ||
        (flen != (rsa_len = RSA_size(rsa)))) {
        WARN("RSA key %p, input %p or output %p are NULL or invalid length, \
              flen = %d, rsa_len = %d\n", rsa, from, to, flen, rsa_len);
        QATerr(QAT_F_QAT_RSA_PUB_DEC, QAT_R_RSA_FROM_TO_NULL);
        goto exit;
    }

    /*
    * If the op sizes are not in the range supported by QAT engine then fall
    * back to software
    */

    if (!qat_rsa_range_check(RSA_bits((const RSA*)rsa)))
        return RSA_meth_get_pub_dec(RSA_PKCS1_OpenSSL())
                                    (flen, from, to, rsa, padding);

    if (1 != build_encrypt_op(flen, from, to, rsa, padding,
                              &enc_op_data, &output_buffer, NO_PADDING)) {
        WARN("Failure in build_encrypt_op\n");
        QATerr(QAT_F_QAT_RSA_PUB_DEC, ERR_R_INTERNAL_ERROR);
        sts = 0;
        goto exit;
    }

    if (1 != qat_rsa_encrypt(enc_op_data, output_buffer)) {
        WARN("Failure in qat_rsa_encrypt\n");
        QATerr(QAT_F_QAT_RSA_PUB_DEC, ERR_R_INTERNAL_ERROR);
        sts = 0;
        goto exit;
    }

    /* remove the padding from outputBuffer if padding != RSA_NO_PADDING */
    if (qat_remove_pad(to, output_buffer->pData, rsa_len, &output_len,
                       1, padding) != 1) {
        WARN("Failure in qat_remove_pad\n");
        QATerr(QAT_F_QAT_RSA_PUB_DEC, ERR_R_INTERNAL_ERROR);
        sts = 0;
        goto exit;
    }

    rsa_encrypt_op_buf_free(enc_op_data, output_buffer, NO_PADDING);
    DEBUG("- Finished\n");
    return output_len;

 exit:
    /* Free all the memory allocated in this function */
    rsa_encrypt_op_buf_free(enc_op_data, output_buffer, NO_PADDING);

    /* set output all 0xff if failed */
    if (!sts)
        memset(to, 0xff, rsa_len);
    return 0;
}

/******************************************************************************
* function:
*         qat_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
*
* @param r0    [IN] - Result bignum of mod_exp
* @param I     [IN] - Base used for mod_exp
* @param rsa   [IN] - Exponent used for mod_exp
* @param ctx   [IN] - EVP context.
*
* description:
*             Returns sw implementation of rsa_mod_exp
*
*******************************************************************************/

int
qat_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    DEBUG("- Started\n");
    return RSA_meth_get_mod_exp(RSA_PKCS1_OpenSSL())
                                (r0, I, rsa, ctx);
}

/******************************************************************************
 * function:
 *         qat_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
 *                        const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
 *
 * @param r     [IN] - Result bignum of mod_exp
 * @param a     [IN] - Base used for mod_exp
 * @param p     [IN] - Exponent used for mod_exp
 * @param m     [IN] - Modulus used for mod_exp
 * @param ctx   [IN] - EVP context.
 * @param m_ctx [IN] - EVP context for Montgomery multiplication.
 *
 * description:
 *             Returns sw implementation of bn_mod_exp
 *
 ******************************************************************************/

int
qat_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
               const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    DEBUG("- Started\n");
    return RSA_meth_get_bn_mod_exp(RSA_PKCS1_OpenSSL())
                                   (r, a, p, m, ctx, m_ctx);
}
#endif /* #ifndef OPENSSL_DISABLE_QAT_RSA */
