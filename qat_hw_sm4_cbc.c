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
 * @file qat_hw_sm4_cbc.c
 *
 * This file contains the engine implementations for SM4-CBC operations
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifdef ENABLE_QAT_HW_SM4_CBC

#include <pthread.h>
#include <signal.h>
#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_USDM_MEM
# include "qat_hw_usdm_inf.h"
#endif

#include "qat_utils.h"
#include "e_qat.h"
#include "qat_hw_callback.h"
#include "qat_hw_polling.h"
#include "qat_events.h"
#include "qat_evp.h"
#include "qat_hw_sm4_cbc.h"

/* Setup template for Session Setup Data as most of the fields
 * are constant. The constant values of some of the fields are
 * chosen for Encryption operation.
 */
static const CpaCySymSessionSetupData template_ssd = {
    .sessionPriority = CPA_CY_PRIORITY_HIGH,
    .symOperation = CPA_CY_SYM_OP_CIPHER,
    .digestIsAppended = CPA_FALSE,
    .verifyDigest = CPA_FALSE,
    .partialsNotRequired = CPA_TRUE,
    .cipherSetupData = {
        .cipherAlgorithm = CPA_CY_SYM_CIPHER_SM4_CBC,
        .cipherKeyLenInBytes = 0,
        .pCipherKey = NULL,
        .cipherDirection = CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT,
    },
};

static const CpaCySymOpData template_opData = {
    .sessionCtx = NULL,
    .packetType = CPA_CY_SYM_PACKET_TYPE_FULL,
    .pIv = NULL,
    .ivLenInBytes = 0,
    .cryptoStartSrcOffsetInBytes = 0,
    .messageLenToCipherInBytes = 0,
    .hashStartSrcOffsetInBytes = 0,
    .messageLenToHashInBytes = 0,
    .pDigestResult = NULL,
    .pAdditionalAuthData = NULL
};

const EVP_CIPHER *qat_create_sm4_cipher_meth(int nid, int keylen)
{
    EVP_CIPHER *c = NULL;
    int res = 1;

    if (qat_hw_offload &&
        (qat_hw_algo_enable_mask & ALGO_ENABLE_MASK_SM4)) {
        if ((c = EVP_CIPHER_meth_new(nid, SM4_BLOCK_SIZE, keylen)) == NULL) {
            WARN("Failed to allocate cipher methods for nid %d\n", nid);
            QATerr(QAT_F_QAT_CREATE_SM4_CIPHER_METH, QAT_R_SM4_MALLOC_FAILED);
            return NULL;
        }

        res &= EVP_CIPHER_meth_set_iv_length(c, SM4_CBC_IV_LEN);
        res &= EVP_CIPHER_meth_set_flags(c, QAT_CBC_FLAGS);
        res &= EVP_CIPHER_meth_set_init(c, qat_sm4_cbc_init);
        res &= EVP_CIPHER_meth_set_do_cipher(c, qat_sm4_cbc_do_cipher);
        res &= EVP_CIPHER_meth_set_cleanup(c, qat_sm4_cbc_cleanup);
        res &= EVP_CIPHER_meth_set_impl_ctx_size(c, sizeof(qat_sm4_ctx));
        res &= EVP_CIPHER_meth_set_set_asn1_params(c, EVP_CIPH_FLAG_DEFAULT_ASN1 ?
                                                NULL : EVP_CIPHER_set_asn1_iv);
        res &= EVP_CIPHER_meth_set_get_asn1_params(c, EVP_CIPH_FLAG_DEFAULT_ASN1 ?
                                                NULL : EVP_CIPHER_get_asn1_iv);
        /* SM4 CBC has no ctrl function. */
        res &= EVP_CIPHER_meth_set_ctrl(c, NULL);

        if (res == 0) {
            WARN("Failed to set SM4 methods for nid %d\n", nid);
            QATerr(QAT_F_QAT_CREATE_SM4_CIPHER_METH, QAT_R_SM4_SET_METHODS_FAILED);
            EVP_CIPHER_meth_free(c);
            c = NULL;
        }

        qat_hw_sm4_cbc_offload = 1;
        DEBUG("QAT HW SM4_CBC registration succeeded\n");
        return c;
    }
    else {
        qat_hw_sm4_cbc_offload = 0;
        DEBUG("QAT HW SM4_CBC is disabled, using OpenSSL SW\n");
        return EVP_sm4_cbc();
    }
}

static inline void qat_sm4_cbc_free_op(qat_sm4_op_params *op)
{
    if (op == NULL) return;
    QAT_CHK_QMFREE_FLATBUFF(op->src_fbuf);
    QAT_QMEMFREE_BUFF(op->src_sgl.pPrivateMetaData);
    QAT_QMEMFREE_BUFF(op->dst_sgl.pPrivateMetaData);
    QAT_QMEMFREE_BUFF(op->op_data.pIv);
    OPENSSL_free(op);
    op = NULL;
}

static int qat_setup_op_params(EVP_CIPHER_CTX *ctx)
{
    CpaCySymOpData *opd = NULL;
    Cpa32U msize = 0;
    qat_sm4_ctx *qctx = qat_sm4_get_cipher_data(ctx);
    size_t iv_len = EVP_CIPHER_CTX_iv_length(ctx);

    if (qctx->op != NULL) {
        qat_sm4_cbc_free_op(qctx->op);
        DEBUG("[%p] qop memory freed\n", ctx);
    }

    qctx->op = (qat_sm4_op_params *) OPENSSL_zalloc(sizeof(qat_sm4_op_params));
    if (qctx->op == NULL) {
        WARN("Unable to allocate memory[%lu bytes] for qat op params\n",
              sizeof(qat_sm4_op_params));
        QATerr(QAT_F_QAT_SETUP_OP_PARAMS, QAT_R_SM4_MALLOC_FAILED);
        return 0;
    }

    qctx->op->src_fbuf.pData = NULL;
    qctx->op->dst_fbuf.pData = NULL;
    qctx->op->src_fbuf.dataLenInBytes = 0;
    qctx->op->dst_fbuf.dataLenInBytes = 0;

    qctx->op->src_sgl.numBuffers = 1;
    qctx->op->src_sgl.pBuffers = &qctx->op->src_fbuf;
    qctx->op->src_sgl.pUserData = NULL;
    qctx->op->src_sgl.pPrivateMetaData = NULL;

    qctx->op->dst_sgl.numBuffers = 1;
    qctx->op->dst_sgl.pBuffers = &qctx->op->dst_fbuf;
    qctx->op->dst_sgl.pUserData = NULL;
    qctx->op->dst_sgl.pPrivateMetaData = NULL;

    /* setup meta data for buffer lists */
    if (cpaCyBufferListGetMetaSize(qat_instance_handles[qctx->inst_num],
                                   qctx->op->src_sgl.numBuffers,
                                   &msize) != CPA_STATUS_SUCCESS) {
        WARN("cpaCyBufferListGetBufferSize failed.\n");
        QATerr(QAT_F_QAT_SETUP_OP_PARAMS, QAT_R_SM4_SETUP_META_DATA_FAILED);
        goto err;
    }

    DEBUG("Size of meta data = %d\n", msize);

    if (msize) {
        qctx->op->src_sgl.pPrivateMetaData =
            qaeCryptoMemAlloc(msize, __FILE__, __LINE__);
        qctx->op->dst_sgl.pPrivateMetaData =
            qaeCryptoMemAlloc(msize, __FILE__, __LINE__);
        if (qctx->op->src_sgl.pPrivateMetaData == NULL ||
            qctx->op->dst_sgl.pPrivateMetaData == NULL) {
            WARN("QMEM alloc failed for PrivateData\n");
            QATerr(QAT_F_QAT_SETUP_OP_PARAMS, QAT_R_SM4_MALLOC_FAILED);
            goto err;
        }
    }

    opd = &qctx->op->op_data;

    /* Copy the opData template */
    memcpy(opd, &template_opData, sizeof(template_opData));

    /* Update Opdata */
    opd->sessionCtx = qctx->session_ctx;
    opd->pIv = qaeCryptoMemAlloc(iv_len,
                                 __FILE__, __LINE__);

    if (opd->pIv == NULL) {
        WARN("QMEM Mem Alloc failed for pIv.\n");
        QATerr(QAT_F_QAT_SETUP_OP_PARAMS, QAT_R_SM4_MALLOC_FAILED);
        goto err;
    }
    opd->ivLenInBytes = (Cpa32U)iv_len;

    DEBUG("[%p] op setup done.\n", ctx);
    return 1;

 err:
    qat_sm4_cbc_free_op(qctx->op);
    return 0;
}

static void qat_sm4_cbc_cb(void *pCallbackTag, CpaStatus status,
                       const CpaCySymOp operationType,
                       void *pOpData, CpaBufferList *pDstBuffer,
                       CpaBoolean verifyResult)
{
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_cipher_pipeline_requests_in_flight);
    }
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, CPA_TRUE);
}

int qat_sm4_cbc_init(EVP_CIPHER_CTX *ctx,
                     const unsigned char *inkey,
                     const unsigned char *iv, int enc)
{
    CpaCySymSessionSetupData *ssd = NULL;
    Cpa32U sctx_size = 0;
    CpaCySymSessionCtx sctx = NULL;
    CpaStatus sts = 0;
    qat_sm4_ctx *qctx = NULL;
    unsigned char *ckey = NULL;
    int ckeylen;
    int ret = 0;

    if (ctx == NULL || inkey == NULL) {
        WARN("ctx or inkey is NULL.\n");
        QATerr(QAT_F_QAT_SM4_CBC_INIT, QAT_R_SM4_NULL_CTX_OR_KEY);
        return 0;
    }

    qctx = qat_sm4_get_cipher_data(ctx);

    if (qctx == NULL) {
        WARN("qctx is NULL.\n");
        QATerr(QAT_F_QAT_SM4_CBC_INIT, QAT_R_SM4_NULL_QCTX);
        return 0;
    }

    DEBUG("QAT HW SM4 CBC Started\n");
    INIT_SM4_CLEAR_ALL_FLAGS(qctx);

    if (iv != NULL)
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv,
               EVP_CIPHER_CTX_iv_length(ctx));
    else
        memset(EVP_CIPHER_CTX_iv_noconst(ctx), 0,
               EVP_CIPHER_CTX_iv_length(ctx));

    ckeylen = EVP_CIPHER_CTX_key_length(ctx);
    ckey = OPENSSL_malloc(ckeylen);
    if (ckey == NULL) {
        WARN("Unable to allocate memory for Cipher key.\n");
        QATerr(QAT_F_QAT_SM4_CBC_INIT, QAT_R_SM4_NULL_CKEY);
        return 0;
    }
    memcpy(ckey, inkey, ckeylen);

    qctx->fallback = 0;

    const EVP_CIPHER *sw_cipher = EVP_sm4_cbc();
    unsigned int sw_size = EVP_CIPHER_impl_ctx_size(sw_cipher);
    if (sw_size != 0) {
        qctx->sw_ctx_cipher_data = OPENSSL_zalloc(sw_size);
        if (qctx->sw_ctx_cipher_data == NULL) {
            WARN("Unable to allocate memory [%u bytes] for sw_ctx_cipher_data\n",
                 sw_size);
            QATerr(QAT_F_QAT_SM4_CBC_INIT, QAT_R_SM4_MALLOC_FAILED);
            goto err;
        }
    }

    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
    /* Run the software init function */
    ret = EVP_CIPHER_meth_get_init(sw_cipher)(ctx, inkey, iv, enc);
    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
    if (ret != 1)
        goto err;

    if (qat_get_qat_offload_disabled()) {
        /*
         * Setting qctx->fallback as a flag for the other functions.
         * This means in the other functions (and in the err section in this function)
         * we no longer need to check qat_get_qat_offload_disabled() but just check
         * the fallback flag instead.  This has the added benefit that even if
         * the engine control message to enable HW offload is sent it will not affect
         * requests that have already been init'd, they will continue to use SW until
         * the request is complete, i.e. no race condition.
         */
        qctx->fallback = 1;
        goto err;
    }

    ssd = OPENSSL_malloc(sizeof(CpaCySymSessionSetupData));
    if (ssd == NULL) {
        WARN("Failed to allocate session setup data\n");
        QATerr(QAT_F_QAT_SM4_CBC_INIT, QAT_R_SM4_MALLOC_FAILED);
        goto err;
    }
    qctx->session_data = ssd;

    /* Copy over the template for most of the values */
    memcpy(ssd, &template_ssd, sizeof(template_ssd));

    /* Change constant values for decryption */
    if (!enc) {
        ssd->cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;
        ssd->algChainOrder = CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH;
        ssd->verifyDigest = CPA_FALSE;
    }

    ssd->cipherSetupData.cipherKeyLenInBytes = ckeylen;
    ssd->cipherSetupData.pCipherKey = ckey;

    qctx->inst_num = get_next_inst_num(INSTANCE_TYPE_CRYPTO_SYM);
    if (qctx->inst_num == QAT_INVALID_INSTANCE) {
        WARN("Failed to get a QAT instance.\n");
        QATerr(QAT_F_QAT_SM4_CBC_INIT, QAT_R_SM4_GET_INSTANCE_FAILED);
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
            qctx->fallback = 1;
        }
        goto err;
    }

    DUMP_SESSION_SETUP_DATA(ssd);
    sts = cpaCySymSessionCtxGetSize(qat_instance_handles[qctx->inst_num], ssd, &sctx_size);

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("Failed to get SessionCtx size.\n");
        QATerr(QAT_F_QAT_SM4_CBC_INIT,QAT_R_SM4_GET_SESSIONCTX_SIZE_FAILED);
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           qctx->inst_num,
                           qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            qctx->fallback = 1;
        }
        goto err;
    }

    DEBUG("Size of session ctx = %d\n", sctx_size);
    sctx = (CpaCySymSessionCtx) qaeCryptoMemAlloc(sctx_size, __FILE__,
                                                  __LINE__);
    if (sctx == NULL) {
        WARN("QMEM alloc failed for session ctx!\n");
        QATerr(QAT_F_QAT_SM4_CBC_INIT, QAT_R_SM4_MALLOC_FAILED);
        goto err;
    }

    qctx->session_ctx = sctx;

    qctx->op = NULL;

    INIT_SM4_SET_FLAG(qctx, INIT_SM4_QAT_CTX_INIT);

    DEBUG("[%p] qat chained cipher ctx %p initialised\n",ctx, qctx);
    return 1;

 err:
/* NOTE: no init seq flags will have been set if this 'err:' label code section is entered. */
    QAT_CLEANSE_FREE_BUFF(ckey, ckeylen);
    if (ssd != NULL)
        OPENSSL_free(ssd);
    qctx->session_data = NULL;
    QAT_QMEMFREE_BUFF(qctx->session_ctx);
    if ((qctx->fallback == 1) && (qctx->sw_ctx_cipher_data != NULL) && (ret == 1)) {
        DEBUG("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        return ret; /* result returned from running software init function */
    }
    if (qctx->sw_ctx_cipher_data != NULL) {
        OPENSSL_free(qctx->sw_ctx_cipher_data);
        qctx->sw_ctx_cipher_data = NULL;
    }
    return 0;
}

int qat_sm4_cbc_cleanup(EVP_CIPHER_CTX *ctx)
{
    qat_sm4_ctx *qctx = NULL;
    CpaStatus sts = 0;
    CpaCySymSessionSetupData *ssd = NULL;
    int retVal = 1;

    if (ctx == NULL) {
        WARN("ctx parameter is NULL.\n");
        QATerr(QAT_F_QAT_SM4_CBC_CLEANUP, QAT_R_SM4_NULL_POINTER);
        return 0;
    }

    qctx = qat_sm4_get_cipher_data(ctx);
    if (qctx == NULL) {
        WARN("qctx parameter is NULL.\n");
        QATerr(QAT_F_QAT_SM4_CBC_CLEANUP, QAT_R_SM4_NULL_POINTER);
        return 0;
    }

    if (qctx->sw_ctx_cipher_data != NULL) {
        OPENSSL_free(qctx->sw_ctx_cipher_data);
        qctx->sw_ctx_cipher_data = NULL;
    }

    /* ctx may be cleaned before it gets a chance to allocate qop */
    qat_sm4_cbc_free_op(qctx->op);

    ssd = qctx->session_data;
    if (ssd) {
        if (INIT_SM4_IS_FLAG_SET(qctx, INIT_SM4_QAT_SESSION_INIT)) {
            if (is_instance_available(qctx->inst_num)) {
                /* Clean up session if hardware available regardless of whether in */
                /* fallback or not, if in INIT_SM4_QAT_SESSION_INIT */
                sts = cpaCySymRemoveSession(qat_instance_handles[qctx->inst_num],
                                            qctx->session_ctx);
                if (sts != CPA_STATUS_SUCCESS) {
                    WARN("cpaCySymRemoveSession FAILED, sts = %d\n", sts);
                    QATerr(QAT_F_QAT_SM4_CBC_CLEANUP, QAT_R_SM4_REMOVE_SESSION_FAILED);
                    retVal = 0;
                }
            }
        }
        QAT_QMEMFREE_BUFF(qctx->session_ctx);
        QAT_CLEANSE_FREE_BUFF(ssd->hashSetupData.authModeSetupData.authKey,
                              ssd->hashSetupData.authModeSetupData.
                              authKeyLenInBytes);
        QAT_CLEANSE_FREE_BUFF(ssd->cipherSetupData.pCipherKey,
                              ssd->cipherSetupData.cipherKeyLenInBytes);
        OPENSSL_free(ssd);
    }

    qctx->fallback = 0;
    INIT_SM4_CLEAR_ALL_FLAGS(qctx);
    DEBUG("[%p] EVP CTX cleaned up\n", ctx);
    return retVal;
}

int qat_sm4_cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    CpaStatus sts = 0;
    CpaCySymOpData *opd = NULL;
    CpaBufferList *s_sgl = NULL;
    CpaBufferList *d_sgl = NULL;
    CpaFlatBuffer *s_fbuf = NULL;
    CpaFlatBuffer *d_fbuf = NULL;
    int retVal = 0, job_ret = 0;
    op_done_t op_done;
    qat_sm4_ctx *qctx = NULL;
    unsigned int ivlen = 0;
    int enc;
    int error = 0;
    int outlen = -1;
    thread_local_variables_t *tlv = NULL;

    if (ctx == NULL) {
        WARN("CTX parameter is NULL.\n");
        QATerr(QAT_F_QAT_SM4_CBC_DO_CIPHER, QAT_R_SM4_NULL_POINTER);
        return -1;
    }

    qctx = qat_sm4_get_cipher_data(ctx);

    if (qctx == NULL) {
        WARN("QAT CTX NULL\n");
        QATerr(QAT_F_QAT_SM4_CBC_DO_CIPHER, QAT_R_SM4_NULL_POINTER);
        return -1;
    }

    if (qctx->fallback == 1)
        goto fallback;

    if (!(is_instance_available(qctx->inst_num))) {
        WARN("No QAT instance available.\n");
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
            qctx->fallback = 1;
            goto fallback;
        } else {
            WARN("Fail - No QAT instance available and s/w fallback is not enabled.\n");
            QATerr(QAT_F_QAT_SM4_CBC_DO_CIPHER, QAT_R_SM4_NO_QAT_INSTANCE_AVAILABLE);
            return -1; /* Fail if software fallback not enabled. */
        }
    } else {
        if (!INIT_SM4_IS_FLAG_SET(qctx, INIT_SM4_QAT_CTX_INIT)) {
            WARN("QAT Context not initialised");
            QATerr(QAT_F_QAT_SM4_CBC_DO_CIPHER, QAT_R_SM4_QAT_CONTEXT_NOT_INITIALISED);
            return -1;
        }
    }

    enc = EVP_CIPHER_CTX_encrypting(ctx);

    /* If we are encrypting and EVP_EncryptFinal_ex is called with a NULL
       input buffer then return 0. Note: we don't actually support partial
       requests in the engine but this workaround avoids an error from OpenSSL
       speed on the last request when measuring cipher performance. Speed is
       written to measure performance using partial requests.*/
    if (in == NULL && out != NULL && enc) {
        DEBUG("QAT partial requests work-around: NULL input buffer passed.\n");
        return 0;
    } else if (in == NULL || out == NULL) {
        WARN("in and out cannot be NULL pointer!\n");
        QATerr(QAT_F_QAT_SM4_CBC_DO_CIPHER, QAT_R_SM4_NULL_POINTER);
        return -1;
    }

    if (!INIT_SM4_IS_FLAG_SET(qctx, INIT_SM4_QAT_SESSION_INIT)) {
        DEBUG("inst_num = %d\n", qctx->inst_num);
        DUMP_SESSION_SETUP_DATA(qctx->session_data);
        DEBUG("session_ctx = %p\n", qctx->session_ctx);

        if (!(is_instance_available(qctx->inst_num))) {
            WARN("No QAT instance available so not initialising session.\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                qctx->fallback = 1;
                goto fallback;
            }
            WARN("Fail - No QAT instance available and s/w fallback is not enabled.\n");
            QATerr(QAT_F_QAT_SM4_CBC_DO_CIPHER, QAT_R_SM4_NO_QAT_INSTANCE_AVAILABLE);
            return -1; /* Fail if software fallback not enabled. */
        }

        sts = cpaCySymInitSession(qat_instance_handles[qctx->inst_num], qat_sm4_cbc_cb,
                                  qctx->session_data, qctx->session_ctx);
        if (sts != CPA_STATUS_SUCCESS) {
            WARN("cpaCySymInitSession failed! Status = %d\n", sts);
            if (qat_get_sw_fallback_enabled() &&
                ((sts == CPA_STATUS_RESTARTING) || (sts == CPA_STATUS_FAIL))) {
                CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                                qctx->inst_num,
                                qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                                __func__);
                qctx->fallback = 1;
                goto fallback;
            }
            WARN("cpaCySymInitSession failed and cannot fallback to SW\n");
            QATerr(QAT_F_QAT_SM4_CBC_DO_CIPHER, QAT_R_SM4_QAT_INITSESSION_FAILED);
            return -1;
        }
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n",
                            qctx->inst_num,
                            qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                            __func__);
        }
        INIT_SM4_SET_FLAG(qctx, INIT_SM4_QAT_SESSION_INIT);
    }
    ivlen = EVP_CIPHER_CTX_iv_length(ctx);

#ifndef ENABLE_QAT_HW_SMALL_PKT_OFFLOAD
    if (len <= qat_pkt_threshold_table_get_threshold(EVP_CIPHER_CTX_nid(ctx))) {
        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
        retVal = EVP_CIPHER_meth_get_do_cipher(EVP_sm4_cbc())(ctx, out, in, len);
        if (retVal)
            outlen = len;
        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
        goto cleanup;
    }
#endif

    DEBUG("[%p] Start Cipher operation.\n", ctx);

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        QATerr(QAT_F_QAT_SM4_CBC_DO_CIPHER, QAT_R_SM4_NULL_POINTER);
        return -1;
    }

    if (qat_setup_op_params(ctx) != 1) {
        WARN("Failure in qat_setup_op_params.\n");
        return -1;
    }
    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failure to setup async event notifications\n");
            QATerr(QAT_F_QAT_SM4_CBC_DO_CIPHER, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            return -1;
        }
    }

    opd = &qctx->op->op_data;
    s_fbuf = &qctx->op->src_fbuf;
    d_fbuf = &qctx->op->dst_fbuf;
    s_sgl = &qctx->op->src_sgl;
    d_sgl = &qctx->op->dst_sgl;

    memcpy(opd->pIv, EVP_CIPHER_CTX_iv(ctx), ivlen);
    opd->messageLenToCipherInBytes = len;

    FLATBUFF_ALLOC_AND_CHAIN(*s_fbuf, *d_fbuf, len);
    if ((s_fbuf->pData) == NULL) {
        WARN("Src buffer is not allocated.\n");
        error = 1;
        goto end;
    }

    memcpy(d_fbuf->pData, in, len);

    DUMP_SYM_PERFORM_OP(qat_instance_handles[qctx->inst_num], opd, s_sgl, d_sgl);

    sts = qat_sym_perform_op(qctx->inst_num, &op_done, opd, s_sgl, d_sgl, NULL);

    if (sts != CPA_STATUS_SUCCESS) {
        if (qat_get_sw_fallback_enabled() &&
            ((sts == CPA_STATUS_RESTARTING) || (sts == CPA_STATUS_FAIL))) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                            qctx->inst_num,
                            qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                            __func__);
            qctx->fallback = 1;
        }
        WARN("Failed to submit request to qat - status = %d\n", sts);
        QATerr(QAT_F_QAT_SM4_CBC_DO_CIPHER, QAT_R_SM4_QAT_SUBMIT_REQUEST_FAILED);
        error = 1;
        goto end;
    }
    if (qat_get_sw_fallback_enabled()) {
        CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n",
                        qctx->inst_num,
                        qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                        __func__);
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n",
                      &hw_polling_thread_sem);
                QATerr(QAT_F_QAT_SM4_CBC_DO_CIPHER, QAT_R_SM4_QAT_SUBMIT_REQUEST_FAILED);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                return -1;
            }
        }
    }

    if (enable_heuristic_polling) {
        QAT_ATOMIC_INC(num_cipher_pipeline_requests_in_flight);
    }

    do {
        if (op_done.job != NULL) {
            /* If we get a failure on qat_pause_job then we will
               not flag an error here and quit because we have
               an asynchronous request in flight.
               We don't want to start cleaning up data
               structures that are still being used. If
               qat_pause_job fails we will just yield and
               loop around and try again until the request
               completes and we can continue. */
            if ((job_ret = qat_pause_job(op_done.job, ASYNC_STATUS_OK)) == 0)
                sched_yield();
        } else {
            sched_yield();
        }
    } while (!op_done.flag || QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

 end:
    DUMP_SYM_PERFORM_OP_OUTPUT(&(qctx->session_data->verifyDigest), d_sgl);

    if (error == 0) {
        retVal = 1;
        outlen = len;
        memcpy(out, qctx->op->dst_fbuf.pData, len);
    } else {
        if (qat_get_sw_fallback_enabled() && op_done.verifyResult == CPA_FALSE) {
            CRYPTO_QAT_LOG("Verification of result failed for qat \
                           inst_num %d device_id %d - fallback to SW - %s\n",
                           qctx->inst_num,
                           qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            qctx->fallback = 1; /* Probably already set anyway */
        }
        if (op_done.job != NULL) {
            qat_clear_async_event_notification(op_done.job);
        }
    }
    qat_cleanup_op_done(&op_done);
    qaeCryptoMemFreeNonZero(qctx->op->src_fbuf.pData);
    qctx->op->src_fbuf.pData = NULL;
    qctx->op->dst_fbuf.pData = NULL;

    if (enc) {
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx),
               out + len - ivlen, ivlen);
        DEBUG("Encryption succeeded.\n");
    } else {
        DEBUG("Decryption succeeded.\n");
    }

#ifndef ENABLE_QAT_HW_SMALL_PKT_OFFLOAD
cleanup:
#endif
fallback:
    if (qctx->fallback == 1) {
        DEBUG("- Switched to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
        retVal = EVP_CIPHER_meth_get_do_cipher(EVP_sm4_cbc())(ctx, out, in, len);
        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
        if (retVal)
            outlen = len;
    }
    return outlen;
}

#endif /* ENABLE_QAT_HW_SM4_CBC */
