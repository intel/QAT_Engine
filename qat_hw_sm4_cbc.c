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
#ifdef ENABLE_QAT_SW_SM4_CBC
# include "qat_sw_sm4_cbc.h"
#endif

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

#ifdef QAT_OPENSSL_PROVIDER
static QAT_EVP_CIPHER_SM4_CBC get_default_cipher_sm4_cbc()
{
    static QAT_EVP_CIPHER_SM4_CBC sm4_cipher;
    static int initilazed = 0;
    if (!initilazed) {
        QAT_EVP_CIPHER_SM4_CBC *cipher = (QAT_EVP_CIPHER_SM4_CBC *)EVP_CIPHER_fetch(NULL, "SM4-CBC", "provider=default");
        if (cipher) {
            sm4_cipher = *cipher;
            EVP_CIPHER_free((EVP_CIPHER *)cipher);
            initilazed = 1;
        } else {
            WARN("EVP_CIPHER_fetch from default provider failed");
        }
    }
    return sm4_cipher;
}
#endif

static inline void qat_sm4_cbc_free_op(qat_sm4_op_params *op, int qat_svm)
{
    if (op == NULL) return;
    if (!qat_svm)
        qaeCryptoMemFree(op->src_fbuf.pData);
    QAT_MEM_FREE_BUFF(op->src_sgl.pPrivateMetaData, qat_svm);
    QAT_MEM_FREE_BUFF(op->dst_sgl.pPrivateMetaData, qat_svm);
    QAT_MEM_FREE_BUFF(op->op_data.pIv, qat_svm);
    OPENSSL_free(op);
    op = NULL;
}

#ifdef QAT_OPENSSL_PROVIDER
static int qat_setup_op_params(QAT_PROV_CBC_CTX *ctx)
#else
static int qat_setup_op_params(EVP_CIPHER_CTX *ctx)
#endif
{
    CpaCySymOpData *opd = NULL;
    Cpa32U msize = 0;
#ifndef QAT_OPENSSL_PROVIDER
    qat_sm4_ctx *qctx = qat_sm4_get_cipher_data(ctx);
    size_t iv_len = EVP_CIPHER_CTX_iv_length(ctx);
#else
    qat_sm4_ctx *qctx = (qat_sm4_ctx *)ctx->qat_cipher_ctx;
    size_t iv_len = ctx->ivlen;
#endif

    if (qctx->op != NULL) {
        qat_sm4_cbc_free_op(qctx->op, qctx->qat_svm);
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
                qat_mem_alloc(msize, qctx->qat_svm, __FILE__, __LINE__);
        qctx->op->dst_sgl.pPrivateMetaData =
                qat_mem_alloc(msize, qctx->qat_svm, __FILE__, __LINE__);
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
    opd->pIv = qat_mem_alloc(iv_len, qctx->qat_svm, __FILE__, __LINE__);
    if (opd->pIv == NULL) {
        WARN("QMEM Mem Alloc failed for pIv.\n");
        QATerr(QAT_F_QAT_SETUP_OP_PARAMS, QAT_R_SM4_MALLOC_FAILED);
        goto err;
    }
    opd->ivLenInBytes = (Cpa32U)iv_len;

    DEBUG("[%p] op setup done.\n", ctx);
    return 1;

 err:
    qat_sm4_cbc_free_op(qctx->op, qctx->qat_svm);
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

#ifdef QAT_OPENSSL_PROVIDER
int qat_sm4_cbc_init(QAT_PROV_CBC_CTX *ctx, const unsigned char *inkey,
                     int keylen, const unsigned char *iv,
                     int ivlen, int enc)
#else
int qat_sm4_cbc_init(EVP_CIPHER_CTX *ctx,
                     const unsigned char *inkey,
                     const unsigned char *iv, int enc)
#endif
{
    CpaCySymSessionSetupData *ssd = NULL;
    Cpa32U sctx_size = 0;
    CpaCySymSessionCtx sctx = NULL;
    CpaStatus sts = 0;
    qat_sm4_ctx *qctx = NULL;
#ifdef QAT_OPENSSL_PROVIDER
    QAT_EVP_CIPHER_SM4_CBC sw_sm4_cbc_cipher;
#endif
    int ret = 0;
    unsigned char *ckey = NULL;
    int ckeylen;
#if defined(ENABLE_QAT_SW_SM4_CBC) && !defined(QAT_OPENSSL_PROVIDER)
    sm4cbc_coexistence_ctx *sm4cbc_hw_sw_ctx = NULL;
#endif

#ifndef QAT_OPENSSL_PROVIDER
    if (ctx == NULL || inkey == NULL) {
        WARN("ctx or inkey is NULL.\n");
        QATerr(QAT_F_QAT_SM4_CBC_INIT, QAT_R_SM4_NULL_CTX_OR_KEY);
        return 0;
    }
#else
    if (ctx == NULL) {
        WARN("ctx is NULL.\n");
        QATerr(QAT_F_QAT_SM4_CBC_INIT, QAT_R_SM4_NULL_CTX);
        return 0;
    }
#endif

#ifndef QAT_OPENSSL_PROVIDER
# ifdef ENABLE_QAT_SW_SM4_CBC
    if (qat_sm4_cbc_coexist) {
        (void)qat_sw_sm4_cbc_key_init(ctx, inkey, iv, enc); /* Saving qat sw sm4cbc cipher data for coexistence. */
        sm4cbc_hw_sw_ctx = (sm4cbc_coexistence_ctx *)(EVP_CIPHER_CTX_get_cipher_data(ctx));
        qctx = &(sm4cbc_hw_sw_ctx->sm4cbc_qat_hw_ctx);
    } else {
        qctx = qat_sm4_get_cipher_data(ctx);
    }
# else
    qctx = qat_sm4_get_cipher_data(ctx);
# endif
#else
    qctx = (qat_sm4_ctx *)ctx->qat_cipher_ctx;
#endif

    if (qctx == NULL) {
        WARN("qctx is NULL.\n");
        QATerr(QAT_F_QAT_SM4_CBC_INIT, QAT_R_SM4_NULL_QCTX);
        return 0;
    }

    DEBUG("QAT HW SM4 CBC Started\n");
    INIT_SM4_CLEAR_ALL_FLAGS(qctx);
#ifndef QAT_OPENSSL_PROVIDER
    if (iv != NULL)
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv,
               EVP_CIPHER_CTX_iv_length(ctx));
    else
        memset(EVP_CIPHER_CTX_iv_noconst(ctx), 0,
               EVP_CIPHER_CTX_iv_length(ctx));

    ckeylen = EVP_CIPHER_CTX_key_length(ctx);
#else
    if (iv != NULL)
        memcpy(ctx->iv, iv, ivlen);
    else
        memset(ctx->iv, 0, ivlen);

    ctx->enc = enc;
    ckeylen = ctx->keylen;
#endif
    ckey = OPENSSL_malloc(ckeylen);
    if (ckey == NULL) {
        WARN("Unable to allocate memory for Cipher key.\n");
        QATerr(QAT_F_QAT_SM4_CBC_INIT, QAT_R_SM4_NULL_CKEY);
        return 0;
    }
    if (inkey != NULL)
        memcpy(ckey, inkey, ckeylen);
    else
        WARN("SM4-CBC key is NULL \n");

    qctx->fallback = 0;
#ifndef QAT_OPENSSL_PROVIDER
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
# ifdef ENABLE_QAT_SW_SM4_CBC
    if (qat_sm4_cbc_coexist) {
        EVP_CIPHER_CTX_set_cipher_data(ctx, sm4cbc_hw_sw_ctx);
    } else {
        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
    }
# else
    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
# endif
    if (ret != 1)
        goto err;
#else
    OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};
    sw_sm4_cbc_cipher = get_default_cipher_sm4_cbc();

    if (enc) {
        if (!ctx->sw_ctx)
            ctx->sw_ctx = sw_sm4_cbc_cipher.newctx(ctx);
        ret = sw_sm4_cbc_cipher.einit(ctx->sw_ctx, inkey, keylen, iv, ivlen, params);
    } else {
        if (!ctx->sw_ctx)
            ctx->sw_ctx = sw_sm4_cbc_cipher.newctx(ctx);

        unsigned int pad = 0;
        params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &pad);
        ret = sw_sm4_cbc_cipher.dinit(ctx->sw_ctx, inkey, keylen, iv, ivlen, params);
    }
    if (ret != 1)
        goto err;
#endif
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

    qctx->inst_num = get_instance(QAT_INSTANCE_SYM, QAT_INSTANCE_ANY);
    if (qctx->inst_num == QAT_INVALID_INSTANCE) {
        WARN("Failed to get a QAT instance.\n");
        QATerr(QAT_F_QAT_SM4_CBC_INIT, QAT_R_SM4_GET_INSTANCE_FAILED);
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
            qctx->fallback = 1;
        }
        goto err;
    }
    DEBUG("inst_num = %d inst mem type \n", qctx->inst_num, qctx->qat_svm);

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
    sctx = (CpaCySymSessionCtx) qat_mem_alloc(sctx_size, qctx->qat_svm,
                                              __FILE__, __LINE__);
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
    QAT_MEM_FREE_BUFF(qctx->session_ctx, qctx->qat_svm);
    if (qctx->fallback == 1) {
#ifndef QAT_OPENSSL_PROVIDER
        if ((qctx->sw_ctx_cipher_data != NULL) && (ret == 1)) {
#else
        if (ret == 1) {
#endif
            DEBUG("- Fallback to software mode.\n");
            CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
            return ret; /* result returned from running software init function */
        }
#ifndef QAT_OPENSSL_PROVIDER
        if (qctx->sw_ctx_cipher_data != NULL) {
            OPENSSL_free(qctx->sw_ctx_cipher_data);
            qctx->sw_ctx_cipher_data = NULL;
        }
#endif
    }
    return 0;
}

#ifdef QAT_OPENSSL_PROVIDER
int qat_sm4_cbc_cleanup(QAT_PROV_CBC_CTX *ctx)
#else
int qat_sm4_cbc_cleanup(EVP_CIPHER_CTX *ctx)
#endif
{
    qat_sm4_ctx *qctx = NULL;
    CpaStatus sts = 0;
    CpaCySymSessionSetupData *ssd = NULL;
    int retVal = 1;
#if defined(ENABLE_QAT_SW_SM4_CBC) && !defined(QAT_OPENSSL_PROVIDER)
    sm4cbc_coexistence_ctx *sm4cbc_hw_sw_ctx = NULL;
#endif

    if (ctx == NULL) {
        WARN("ctx parameter is NULL.\n");
        QATerr(QAT_F_QAT_SM4_CBC_CLEANUP, QAT_R_SM4_NULL_POINTER);
        return 0;
    }
#ifndef QAT_OPENSSL_PROVIDER
# ifdef ENABLE_QAT_SW_SM4_CBC
    if (qat_sm4_cbc_coexist) {
        (void)qat_sw_sm4_cbc_cleanup(ctx); /* Clean coexistence sm4cbc cipher data for qat sw. */
        sm4cbc_hw_sw_ctx = (sm4cbc_coexistence_ctx *)(EVP_CIPHER_CTX_get_cipher_data(ctx));
        qctx = &(sm4cbc_hw_sw_ctx->sm4cbc_qat_hw_ctx);
    } else {
        qctx = qat_sm4_get_cipher_data(ctx);
    }
# else
    qctx = qat_sm4_get_cipher_data(ctx);
# endif
#else
    qctx = (qat_sm4_ctx *)ctx->qat_cipher_ctx;
#endif
    if (qctx == NULL) {
        WARN("qctx parameter is NULL.\n");
        QATerr(QAT_F_QAT_SM4_CBC_CLEANUP, QAT_R_SM4_NULL_POINTER);
        return 0;
    }
#ifndef QAT_OPENSSL_PROVIDER
    if (qctx->sw_ctx_cipher_data != NULL) {
        OPENSSL_free(qctx->sw_ctx_cipher_data);
        qctx->sw_ctx_cipher_data = NULL;
    }
#else
    if (ctx->sw_ctx) {
        OPENSSL_free(ctx->sw_ctx);
        ctx->sw_ctx = NULL;
    }
#endif
    /* ctx may be cleaned before it gets a chance to allocate qop */
    qat_sm4_cbc_free_op(qctx->op ,qctx->qat_svm);

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
        QAT_MEM_FREE_BUFF(qctx->session_ctx, qctx->qat_svm);
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

#ifdef QAT_OPENSSL_PROVIDER
int qat_sm4_cbc_do_cipher(QAT_PROV_CBC_CTX *ctx, unsigned char *out,
                          size_t *outl, size_t outsize,
                          const unsigned char *in, size_t len)
#else
int qat_sm4_cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
#endif
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
#ifdef QAT_OPENSSL_PROVIDER
    QAT_EVP_CIPHER_SM4_CBC sw_sm4_cbc_cipher;
#endif
    unsigned int ivlen = 0;
    int enc;
    int error = 0;
    int outlen = -1;
#ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    int nid = 0;
#endif
    thread_local_variables_t *tlv = NULL;
#if defined(ENABLE_QAT_SW_SM4_CBC) && !defined(QAT_OPENSSL_PROVIDER)
    sm4cbc_coexistence_ctx *sm4cbc_hw_sw_ctx = NULL;
#endif

    if (ctx == NULL) {
        WARN("CTX parameter is NULL.\n");
        QATerr(QAT_F_QAT_SM4_CBC_DO_CIPHER, QAT_R_SM4_NULL_POINTER);
        return -1;
    }
#ifndef QAT_OPENSSL_PROVIDER
# ifdef ENABLE_QAT_SW_SM4_CBC
    if (qat_sm4_cbc_coexist) {
        sm4cbc_hw_sw_ctx = (sm4cbc_coexistence_ctx *)(EVP_CIPHER_CTX_get_cipher_data(ctx));
        qctx = &(sm4cbc_hw_sw_ctx->sm4cbc_qat_hw_ctx);
    } else {
        qctx = qat_sm4_get_cipher_data(ctx);
    }
# else
    qctx = qat_sm4_get_cipher_data(ctx);
# endif
#else
    qctx = ctx->qat_cipher_ctx;
#endif

    if (qctx == NULL) {
        WARN("QAT CTX NULL\n");
        QATerr(QAT_F_QAT_SM4_CBC_DO_CIPHER, QAT_R_SM4_NULL_POINTER);
        return -1;
    }

#if defined(ENABLE_QAT_SW_SM4_CBC) && !defined(QAT_OPENSSL_PROVIDER)
    if (qat_sm4_cbc_coexist) {
        /* 1. Requests will fallback to QAT SW if QAT HW initialize fail.
         *    SM4_CBC_COEXIST_QAT_SW_MAX_PKT_LEN, using QAT_SW, otherwise using
         * 2. CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_SM4_CBC < len <
         *    SM4_CBC_COEXIST_QAT_SW_MAX_PKT_LEN, using QAT_SW, otherwise using
         *    QAT_HW.
         */
        if (fallback_to_qat_sw || ((len >= SM4_CBC_COEXIST_QAT_SW_MIN_PKT_LEN) &&
            (len <= SM4_CBC_COEXIST_QAT_SW_MAX_PKT_LEN))) {
            return qat_sw_sm4_cbc_cipher(ctx, out, in, len);
        }

        /* 1. A retry occurs, 16 requests will switche to QAT SW to be processed. */
        if (qat_sw_sm4_cbc_cipher_req > 0) {
            qat_sw_sm4_cbc_cipher_req--;
            return qat_sw_sm4_cbc_cipher(ctx, out, in, len);
        }
    }
#endif

    if (qctx->fallback == 1) {
        goto fallback;
    }

#ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
# ifndef QAT_OPENSSL_PROVIDER
    nid = EVP_CIPHER_CTX_nid(ctx);
# else
    nid = ctx->nid;
# endif
#endif
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
#ifndef QAT_OPENSSL_PROVIDER
    enc = EVP_CIPHER_CTX_encrypting(ctx);
    ivlen = EVP_CIPHER_CTX_iv_length(ctx);
#else
    enc = ctx->enc;
    ivlen = ctx->ivlen;
#endif

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

#ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    if (len <= qat_pkt_threshold_table_get_threshold(nid)) {
# ifndef QAT_OPENSSL_PROVIDER
        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
        retVal = EVP_CIPHER_meth_get_do_cipher(EVP_sm4_cbc())(ctx, out, in, len);
        if (retVal)
            outlen = len;
#  ifdef ENABLE_QAT_SW_SM4_CBC
        if (qat_sm4_cbc_coexist) {
            EVP_CIPHER_CTX_set_cipher_data(ctx, sm4cbc_hw_sw_ctx);
        } else {
            EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
        }
#  else
        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
#  endif
# else
        sw_sm4_cbc_cipher = get_default_cipher_sm4_cbc();
        if (sw_sm4_cbc_cipher.cupdate == NULL)
            return 0;
        if (in != NULL) {
            retVal = sw_sm4_cbc_cipher.cupdate(ctx->sw_ctx, out, outl, outsize, in, len);
            *outl = len;
        } else {
            retVal = sw_sm4_cbc_cipher.cfinal(ctx->sw_ctx, out, outl, outsize);
            *outl = len;
        }

        if (retVal)
            outlen = 1;
# endif
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
#ifndef QAT_OPENSSL_PROVIDER
    memcpy(opd->pIv, EVP_CIPHER_CTX_iv(ctx), ivlen);
#else
    memcpy(opd->pIv, ctx->iv, ivlen);
#endif
    opd->messageLenToCipherInBytes = len;

    if (!qctx->qat_svm) {
        FLATBUFF_ALLOC_AND_CHAIN(*s_fbuf, *d_fbuf, len);
    } else {
        s_fbuf->pData = (Cpa8U *)in;
        d_fbuf->pData = s_fbuf->pData;
        s_fbuf->dataLenInBytes = len;
        d_fbuf->dataLenInBytes = len;
    }
    if ((s_fbuf->pData) == NULL) {
        WARN("Src buffer is not allocated.\n");
        error = 1;
        goto end;
    }

    if (!qctx->qat_svm)
        memcpy(d_fbuf->pData, in, len);

    DUMP_SYM_PERFORM_OP(qat_instance_handles[qctx->inst_num], opd, s_sgl, d_sgl);

    sts = qat_sym_perform_op(qctx->inst_num, &op_done, opd, s_sgl, d_sgl, NULL);

    /* QAT_HW return retry, 16 requests will switche to QAT SW to be processed. */
#if defined(ENABLE_QAT_SW_SM4_CBC) && !defined(QAT_OPENSSL_PROVIDER)
    if (qat_sm4_cbc_coexist && (sts == CPA_STATUS_RETRY)) {
        DEBUG("Qat retry occurred.\n");
        qaeCryptoMemFreeNonZero(qctx->op->src_fbuf.pData);
        qctx->op->src_fbuf.pData = NULL;
        qctx->op->dst_fbuf.pData = NULL;
        qat_sw_sm4_cbc_cipher_req--;
        return qat_sw_sm4_cbc_cipher(ctx, out, in, len);
    }
#endif

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

    if (qat_sm4_cbc_coexist) {
        ++num_sm4_cbc_hw_cipher_reqs;
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
#ifndef QAT_OPENSSL_PROVIDER
        retVal = 1;
        outlen = len;
#else
        *outl = len;
	outlen = 1;
#endif
    if (!qctx->qat_svm)
       memcpy(out, qctx->op->dst_fbuf.pData, len);
    else
       qctx->op->dst_fbuf.pData = (Cpa8U *)out;
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
    if (!qctx->qat_svm)
        qaeCryptoMemFreeNonZero(qctx->op->src_fbuf.pData);
    qctx->op->src_fbuf.pData = NULL;
    qctx->op->dst_fbuf.pData = NULL;

    if (enc) {
#ifndef QAT_OPENSSL_PROVIDER
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx),
               out + len - ivlen, ivlen);
#else
        memcpy(ctx->iv, out + len - ctx->ivlen, ctx->ivlen);
#endif
        DEBUG("Encryption succeeded.\n");
    } else {
        DEBUG("Decryption succeeded.\n");
    }

#ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
cleanup:
#endif
fallback:
    if (qctx->fallback == 1) {
        DEBUG("- Switched to OpenSSL SW mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to OpenSSL SW - %s\n", __func__);
#ifndef QAT_OPENSSL_PROVIDER
        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
        retVal = EVP_CIPHER_meth_get_do_cipher(EVP_sm4_cbc())(ctx, out, in, len);
        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);

        if (retVal)
            outlen = len;
#else
        sw_sm4_cbc_cipher = get_default_cipher_sm4_cbc();
        if (sw_sm4_cbc_cipher.cupdate == NULL)
            return 0;
        if (in != NULL) {
            retVal = sw_sm4_cbc_cipher.cupdate(ctx->sw_ctx, out, outl, outsize, in, len);
            *outl = len;
        } else {
            retVal = sw_sm4_cbc_cipher.cfinal(ctx->sw_ctx, out, outl, outsize);
            *outl = len;
        }

        if (retVal)
            outlen = 1;
#endif
    }
    return outlen;
}
#endif /* ENABLE_QAT_HW_SM4_CBC */
