/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2019-2023 Intel Corporation.
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
 * @file qat_hkdf.c
 *
 * This file provides an implementation of the HKDF operations for an
 * OpenSSL engine
 *
 *****************************************************************************/
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <pthread.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>

#include "openssl/ossl_typ.h"
#include "openssl/kdf.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "qat_evp.h"
#include "qat_utils.h"
#include "e_qat.h"
#include "qat_hw_callback.h"
#include "qat_hw_polling.h"
#include "qat_events.h"
#include "qat_hw_hkdf.h"

#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_USDM_MEM
# include "qat_hw_usdm_inf.h"
#endif

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_key.h"

/* These limits are based on QuickAssist limits.
 * OpenSSL is more generous but better to restrict and fail
 * early on here if they are exceeded rather than later on
 * down in the driver.
 */
#define QAT_HKDF_INFO_MAXBUF 1024

/* Have a store of the s/w EVP_PKEY_METHOD for software fallback purposes. */
#ifndef QAT_OPENSSL_3
/* Only for OpenSSL 1.1.1. For OpenSSL 3, we use the default provider for SW fallback */
static const EVP_PKEY_METHOD *sw_hkdf_pmeth = NULL;
#endif
static EVP_PKEY_METHOD *_hidden_hkdf_pmeth = NULL;

EVP_PKEY_METHOD *qat_hkdf_pmeth(void)
{
    if (_hidden_hkdf_pmeth) {
        if (!qat_reload_algo)
            return _hidden_hkdf_pmeth;
        EVP_PKEY_meth_free(_hidden_hkdf_pmeth);
    }

    if ((_hidden_hkdf_pmeth =
         EVP_PKEY_meth_new(EVP_PKEY_HKDF, 0)) == NULL) {
        QATerr(QAT_F_QAT_HKDF_PMETH, ERR_R_INTERNAL_ERROR);
        return NULL;
    }
#ifndef QAT_OPENSSL_3
    /* Now save the current (non-offloaded) hkdf pmeth to sw_hkdf_pmeth */
    /* for software fallback purposes */
    if ((sw_hkdf_pmeth = EVP_PKEY_meth_find(EVP_PKEY_HKDF)) == NULL) {
        QATerr(QAT_F_QAT_HKDF_PMETH, ERR_R_INTERNAL_ERROR);
        return NULL;
    }
#endif

#ifdef ENABLE_QAT_HW_HKDF
    if (qat_hw_offload && (qat_hw_algo_enable_mask & ALGO_ENABLE_MASK_HKDF)) {
        EVP_PKEY_meth_set_init(_hidden_hkdf_pmeth, qat_hkdf_init);
        EVP_PKEY_meth_set_cleanup(_hidden_hkdf_pmeth, qat_hkdf_cleanup);
        EVP_PKEY_meth_set_derive(_hidden_hkdf_pmeth, NULL,
                qat_hkdf_derive);
        EVP_PKEY_meth_set_ctrl(_hidden_hkdf_pmeth, qat_hkdf_ctrl, NULL);
        qat_hw_hkdf_offload = 1;
        DEBUG("QAT HW HKDF Registration succeeded\n");
    } else {
        qat_hw_hkdf_offload = 0;
    }
#endif

    if (!qat_hw_hkdf_offload) {
#ifndef QAT_OPENSSL_3
        EVP_PKEY_meth_copy(_hidden_hkdf_pmeth, sw_hkdf_pmeth);
        DEBUG("OpenSSL HW HKDF is disabled, using OpenSSL SW\n");
#else
        /* Although QAEngine supports software fallback to the default provider when
        * using the OpenSSL 3 legacy engine API, if it fails during the registration
        * phase, the pkey method cannot be set correctly because the OpenSSL3 legacy
        * engine framework no longer provides a standard method for HKDF, PRF and SM2.
        * So it will just return NULL.
        * https://github.com/openssl/openssl/issues/19047
        */
        WARN("HKDF methods registration failed with OpenSSL 3.\n");
        EVP_PKEY_meth_free(_hidden_hkdf_pmeth);
        return NULL;
#endif
    }
    return _hidden_hkdf_pmeth;
}

#ifdef ENABLE_QAT_HW_HKDF
/******************************************************************************
* function:
*        qat_hkdf_init(EVP_PKEY_CTX *ctx)
*
* @param ctx   [IN] - PKEY Context structure pointer
*
* @param       [OUT] - Status
*
* description:
*   Qat HKDF init function
******************************************************************************/
int qat_hkdf_init(EVP_PKEY_CTX *ctx)
{
    QAT_HKDF_CTX *qat_hkdf_ctx = NULL;
#ifndef QAT_OPENSSL_3
    int (*sw_init_fn_ptr)(EVP_PKEY_CTX *) = NULL;
    int ret = 0;
#endif
    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL \n");
        QATerr(QAT_F_QAT_HKDF_INIT, ERR_R_INTERNAL_ERROR);
        return 0;
    }
#ifndef QAT_OPENSSL_3
    if (qat_get_qat_offload_disabled() || qat_get_sw_fallback_enabled()) {
        DEBUG("- Switched to software mode or fallback mode enabled.\n");
        EVP_PKEY_meth_get_init((EVP_PKEY_METHOD *)sw_hkdf_pmeth, &sw_init_fn_ptr);
        ret = (*sw_init_fn_ptr)(ctx);
        if (ret != 1) {
            WARN("s/w hkdf_init fn failed.\n");
            QATerr(QAT_F_QAT_HKDF_INIT, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
#endif
    qat_hkdf_ctx = OPENSSL_zalloc(sizeof(*qat_hkdf_ctx));
    if (qat_hkdf_ctx == NULL) {
        WARN("Cannot allocate qat_hkdf_ctx\n");
        QATerr(QAT_F_QAT_HKDF_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (qat_get_qat_offload_disabled() || qat_get_sw_fallback_enabled())
        qat_hkdf_ctx->sw_hkdf_ctx_data = EVP_PKEY_CTX_get_data(ctx);

    qat_hkdf_ctx->hkdf_op_data =
        (CpaCyKeyGenHKDFOpData *) qaeCryptoMemAlloc(sizeof(CpaCyKeyGenHKDFOpData), __FILE__,
                __LINE__);
    if (NULL == qat_hkdf_ctx->hkdf_op_data) {
        WARN("Failed to allocate memory for hkdf_op_data\n");
        QATerr(QAT_F_QAT_HKDF_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memset(qat_hkdf_ctx->hkdf_op_data, 0, sizeof(CpaCyKeyGenHKDFOpData));

    EVP_PKEY_CTX_set_data(ctx, qat_hkdf_ctx);
    return 1;

}


/******************************************************************************
* function:
*         qat_hkdf_cleanup(EVP_PKEY_CTX *ctx)
*
* @param ctx    [IN] - PKEY Context structure pointer
*
* description:
*   Clear the QAT specific data stored in qat_hkdf_ctx
******************************************************************************/
void qat_hkdf_cleanup(EVP_PKEY_CTX *ctx)
{
    QAT_HKDF_CTX *qat_hkdf_ctx = NULL;
#ifndef QAT_OPENSSL_3
    void (*sw_cleanup_fn_ptr)(EVP_PKEY_CTX *) = NULL;
#endif
    if (unlikely(ctx == NULL)) {
        WARN("ctx (type EVP_PKEY_CTX) is NULL \n");
        return;
    }

    qat_hkdf_ctx = (QAT_HKDF_CTX *)EVP_PKEY_CTX_get_data(ctx);
    if (qat_hkdf_ctx == NULL) {
        WARN("qat_hkdf_ctx is NULL\n");
        return;
    }

#ifndef QAT_OPENSSL_3
    if (qat_get_qat_offload_disabled() || qat_get_sw_fallback_enabled()) {
        DEBUG("- Switched to software mode or fallback mode enabled.\n");
        /* Clean up the sw_hkdf_ctx_data created by the init function */
        EVP_PKEY_meth_get_cleanup((EVP_PKEY_METHOD *)sw_hkdf_pmeth, &sw_cleanup_fn_ptr);
        EVP_PKEY_CTX_set_data(ctx, qat_hkdf_ctx->sw_hkdf_ctx_data);
        (*sw_cleanup_fn_ptr)(ctx);
    }
#else
    /* Cleanup the memory used for sw fallback */
    OPENSSL_cleanse(qat_hkdf_ctx->sw_ikm, qat_hkdf_ctx->sw_ikm_size);
    OPENSSL_cleanse(qat_hkdf_ctx->sw_info, qat_hkdf_ctx->sw_info_size);
    OPENSSL_cleanse(qat_hkdf_ctx->sw_salt, qat_hkdf_ctx->sw_salt_size);
#endif

    if (qat_hkdf_ctx->hkdf_op_data) {
        if (qat_hkdf_ctx->hkdf_op_data->seedLen)
            OPENSSL_cleanse(qat_hkdf_ctx->hkdf_op_data->seed,
                    qat_hkdf_ctx->hkdf_op_data->seedLen);

         if (qat_hkdf_ctx->hkdf_op_data->secretLen)
            OPENSSL_cleanse(qat_hkdf_ctx->hkdf_op_data->secret,
                    qat_hkdf_ctx->hkdf_op_data->secretLen);

        if (qat_hkdf_ctx->hkdf_op_data->infoLen)
            OPENSSL_cleanse(qat_hkdf_ctx->hkdf_op_data->info,
                    qat_hkdf_ctx->hkdf_op_data->infoLen);

	if (qat_hkdf_ctx->hkdf_op_data->label[0].labelLen) {
            OPENSSL_cleanse(&qat_hkdf_ctx->hkdf_op_data->label[0],
                    qat_hkdf_ctx->hkdf_op_data->label[0].labelLen);
            qat_hkdf_ctx->hkdf_op_data->numLabels = 0;
	}

        qaeCryptoMemFreeNonZero(qat_hkdf_ctx->hkdf_op_data);
    }
    OPENSSL_free(qat_hkdf_ctx);
    EVP_PKEY_CTX_set_data(ctx, NULL);

}


/******************************************************************************
* function:
*        qat_hkdf_ctrl(EVP_PKEY_CTX *ctx,
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
*   Qat HKDF control function
******************************************************************************/
int qat_hkdf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    if (unlikely(ctx == NULL)) {
        WARN("Invalid input param.\n");
        return 0;
    }

    QAT_HKDF_CTX *qat_hkdf_ctx = (QAT_HKDF_CTX *)EVP_PKEY_CTX_get_data(ctx);
#ifndef QAT_OPENSSL_3
    int (*sw_ctrl_fn_ptr)(EVP_PKEY_CTX *, int, int, void *) = NULL;
    int ret = 0;
#endif

    if (unlikely(qat_hkdf_ctx == NULL)) {
         WARN("qat_hkdf_ctx cannot be NULL\n");
         return 0;
    }
#ifndef QAT_OPENSSL_3
    if (qat_get_qat_offload_disabled() || qat_get_sw_fallback_enabled()) {
        DEBUG("- Switched to software mode or fallback mode enabled.\n");
        EVP_PKEY_meth_get_ctrl((EVP_PKEY_METHOD *)sw_hkdf_pmeth, &sw_ctrl_fn_ptr, NULL);
        EVP_PKEY_CTX_set_data(ctx, qat_hkdf_ctx->sw_hkdf_ctx_data);
        ret = (*sw_ctrl_fn_ptr)(ctx, type, p1, p2);
        EVP_PKEY_CTX_set_data(ctx, qat_hkdf_ctx);
        if (ret != 1) {
            WARN("S/W hkdf_ctrl fn failed\n");
            return 0;
        }
    }
#endif
    switch (type) {
        case EVP_PKEY_CTRL_HKDF_MD:
            if (unlikely(p2 == NULL)) {
                WARN("Invalid input param.\n");
                return 0;
            }
            qat_hkdf_ctx->qat_md = p2;
            return 1;

        case EVP_PKEY_CTRL_HKDF_MODE:
            qat_hkdf_ctx->mode = p1;
            return 1;

        case EVP_PKEY_CTRL_HKDF_SALT:
            if (p1 == 0 || p2 == NULL)
                return 1;

            if (p1 < 0) {
                WARN("Input param p1 length less than zero\n");
                return 0;
            }

            if (qat_hkdf_ctx->hkdf_op_data == NULL) {
                WARN("hkdf_op_data is NULL\n");
                return 0;
            }
#ifdef QAT_OPENSSL_3
            /* Setup the sw fallback parameters */
            OPENSSL_cleanse(qat_hkdf_ctx->sw_salt,
                            QAT_KDF_MAX_SEED_SZ);
            memcpy(qat_hkdf_ctx->sw_salt, p2, p1);
            qat_hkdf_ctx->sw_salt_size = p1;
#endif
            OPENSSL_cleanse(qat_hkdf_ctx->hkdf_op_data->seed,
                            qat_hkdf_ctx->hkdf_op_data->seedLen);
            qat_hkdf_ctx->hkdf_op_data->seedLen = 0;

            memcpy(qat_hkdf_ctx->hkdf_op_data->seed, p2, p1);
            qat_hkdf_ctx->hkdf_op_data->seedLen = p1;
            return 1;

        case EVP_PKEY_CTRL_HKDF_KEY:
            if (p1 < 0) {
                WARN("Input param p1 length less than zero\n");
                return 0;
            }

            if (qat_hkdf_ctx->hkdf_op_data == NULL) {
                WARN("hkdf_op_data is NULL\n");
                return 0;
            }
#ifdef QAT_OPENSSL_3
            /* Setup the sw fallback parameters */
            OPENSSL_cleanse(qat_hkdf_ctx->sw_ikm,
                            QAT_KDF_MAX_KEY_SZ);
            memcpy(qat_hkdf_ctx->sw_ikm, p2, p1);
            qat_hkdf_ctx->sw_ikm_size = p1;
#endif
            OPENSSL_cleanse(qat_hkdf_ctx->hkdf_op_data->secret,
                            qat_hkdf_ctx->hkdf_op_data->secretLen);
            qat_hkdf_ctx->hkdf_op_data->secretLen = 0;

            memcpy(qat_hkdf_ctx->hkdf_op_data->secret, p2, p1);
            qat_hkdf_ctx->hkdf_op_data->secretLen = p1;
            return 1;

        case EVP_PKEY_CTRL_HKDF_INFO:
            if (p1 == 0 || p2 == NULL)
                return 1;

            if (qat_hkdf_ctx->hkdf_op_data == NULL) {
                WARN("hkdf_op_data is NULL\n");
                return 0;
            }

            if (p1 < 0 || p1 > (int) QAT_HKDF_INFO_MAXBUF - qat_hkdf_ctx->hkdf_op_data->infoLen) {
                WARN("info p1 %d is out of range\n", p1);
                return 0;
            }
#ifdef QAT_OPENSSL_3
            /* Setup the sw fallback parameters */
            memcpy(qat_hkdf_ctx->sw_info + qat_hkdf_ctx->sw_info_size, p2, p1);
            qat_hkdf_ctx->sw_info_size += p1;
#endif
            memcpy(qat_hkdf_ctx->hkdf_op_data->info
                   + qat_hkdf_ctx->hkdf_op_data->infoLen, p2, p1);
            qat_hkdf_ctx->hkdf_op_data->infoLen += p1;
            return 1;
#ifdef QAT_OPENSSL_PROVIDER
          case EVP_PKEY_CTRL_HKDF_PREFIX:
            if (p1 == 0 || p2 == NULL)
                return 1;

            if (qat_hkdf_ctx->hkdf_op_data == NULL) {
                WARN("hkdf_op_data is NULL\n");
                return 0;
            }

            qat_hkdf_ctx->prefix = OPENSSL_zalloc(p1);
            if (qat_hkdf_ctx->prefix == NULL) {
                   WARN("Cannot allocate qat_hkdf_ctx\n");
                   QATerr(QAT_F_QAT_HKDF_CTRL, ERR_R_MALLOC_FAILURE);
                   return 0;
            }
            memcpy(qat_hkdf_ctx->prefix, p2, p1);
            qat_hkdf_ctx->prefix_len = p1;
            return 1;

        case EVP_PKEY_CTRL_HKDF_DATA:
            if (p1 == 0 || p2 == NULL)
                return 1;

            if (qat_hkdf_ctx->hkdf_op_data == NULL) {
                WARN("hkdf_op_data is NULL\n");
                return 0;
            }
            qat_hkdf_ctx->data = OPENSSL_zalloc(p1);
            if (qat_hkdf_ctx->data == NULL) {
                WARN("Cannot allocate qat_hkdf_ctx\n");
                QATerr(QAT_F_QAT_HKDF_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            memcpy(qat_hkdf_ctx->data, p2, p1);
            qat_hkdf_ctx->data_len = p1;
            return 1;
        case EVP_PKEY_CTRL_HKDF_LABEL:
            if (p1 == 0 || p2 == NULL)
                return 1;

            if (qat_hkdf_ctx->hkdf_op_data == NULL) {
                WARN("hkdf_op_data is NULL\n");
                return 0;
            }
            qat_hkdf_ctx->hkdf_op_data->numLabels = 1;
            qat_hkdf_ctx->label = OPENSSL_zalloc(p1);
            qat_hkdf_ctx->label_len = p1;
            if (qat_hkdf_ctx->label == NULL) {
                WARN("Cannot allocate qat_hkdf_ctx\n");
                QATerr(QAT_F_QAT_HKDF_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            memcpy(qat_hkdf_ctx->label, p2, p1);

            return 1;
#endif
        default:
            WARN("Invalid type %d\n", type);
            return -2;
    } /* switch */
}


/******************************************************************************
 * function:
 *         void qat_hkdf_cb(void *pCallbackTag,
 *                          CpaStatus status,
 *                          void *pOpdata,
 *                          CpaFlatBuffer *pOut)
 *
 * @param pCallbackTag   [IN]  - Pointer to user data
 * @param status         [IN]  - Status of the operation
 * @param pOpData        [IN]  - Pointer to operation data of the request
 * @param out            [IN]  - Pointer to the output buffer
 *
 * description:
 *   Callback to indicate the completion of HKDF
 ******************************************************************************/
static void qat_hkdf_cb(void *pCallbackTag, CpaStatus status,
                        void *pOpData, CpaFlatBuffer * pOut)
{
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_kdf_requests_in_flight);
    }
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, CPA_TRUE);
}


/******************************************************************************
* function:
*         qat_get_cipher_suite(HKDF *qat_hkdf_ctx
*                              CpaCyKeyHKDFCipherSuite *cipher_suite)
*
* @param qat_hkdf_ctx   [IN]  - HKDF context
* @param cipher_suite   [OUT] - Ptr to cipher suite in CPA format
*
* description:
*   Retrieve the cipher suite from the hkdf context and convert it to
*   the CPA format
******************************************************************************/
static int qat_get_cipher_suite(QAT_HKDF_CTX * qat_hkdf_ctx,
                                CpaCyKeyHKDFCipherSuite* cipher_suite)
{
    const EVP_MD *md = NULL;
    if (qat_hkdf_ctx == NULL || cipher_suite == NULL) {
        WARN("Either qat_hkdf_ctx %p or  cipher_suite %p is NULL\n",
              qat_hkdf_ctx, cipher_suite);
        return 0;
    }

    md = qat_hkdf_ctx->qat_md;
    if (md == NULL) {
        WARN("md is NULL.\n");
        return 0;
    }

    switch (EVP_MD_type(md)) {
        case NID_sha256:
            *cipher_suite = CPA_CY_HKDF_TLS_AES_128_GCM_SHA256;
            break;
        case NID_sha384:
            *cipher_suite = CPA_CY_HKDF_TLS_AES_256_GCM_SHA384;
            break;

#if defined(QAT20_OOT)
        case NID_sm3:
            WARN("HKDF based on SM3 not supported\n");
            return 0;
#endif

        default:
            WARN("Unsupported HKDF hash type\n");
            return 0;
    }

    return 1;
}

/******************************************************************************
* function:
*         qat_set_hkdf_mode(HKDF *qat_hkdf_ctx)
*
* @param qat_hkdf_ctx    [IN]  - HKDF context
*
* description:
*   Set the mode into hkdf_op_data from the hkdf context
******************************************************************************/
static int qat_set_hkdf_mode(QAT_HKDF_CTX * qat_hkdf_ctx)
{
    if (qat_hkdf_ctx == NULL) {
        WARN("Either qat_hkdf_ctx %p is NULL\n", qat_hkdf_ctx);
        return 0;
    }

    switch (qat_hkdf_ctx->mode) {

        case EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY:
            qat_hkdf_ctx->hkdf_op_data->hkdfKeyOp = CPA_CY_HKDF_KEY_EXTRACT;
            break;

        case EVP_PKEY_HKDEF_MODE_EXPAND_ONLY:
#ifdef QAT_OPENSSL_PROVIDER
	    if (!strcmp((const char*)kdf_name, "HKDF"))
	        qat_hkdf_ctx->hkdf_op_data->hkdfKeyOp = CPA_CY_HKDF_KEY_EXPAND;
	    if(!strcmp((const char*)kdf_name, "TLS13-KDF"))
                qat_hkdf_ctx->hkdf_op_data->hkdfKeyOp = CPA_CY_HKDF_KEY_EXPAND_LABEL;
#else
                qat_hkdf_ctx->hkdf_op_data->hkdfKeyOp = CPA_CY_HKDF_KEY_EXPAND;
#endif
            break;

        case EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND:
            qat_hkdf_ctx->hkdf_op_data->hkdfKeyOp = CPA_CY_HKDF_KEY_EXTRACT_EXPAND;
            break;

        default:
            WARN("Unknown HKDF mode \n");
            return 0;
    }

    return 1;
}

#ifdef QAT_OPENSSL_3
/******************************************************************************
* function:
*         default_provider_HKDF_derive(QAT_HKDF_CTX *qat_hkdf_ctx,
*                                      unsigned char *out,
*                                      size_t olen)
*
* @param qat_hkdf_ctx    [IN]  - HKDF context
* @param out             [OUT] - Ptr to the key that will be generated
* @param olen            [IN]  - Length of the key
*
* description:
*   HKDF SW fallback function. Using default provider of OpenSSL 3
******************************************************************************/
int default_provider_HKDF_derive(QAT_HKDF_CTX *qat_hkdf_ctx, unsigned char *out, size_t olen) {
    int rv = 1;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[6], *p = params;
    OSSL_LIB_CTX *library_context = NULL;
    char *mode = NULL;
    const char *mdname;

    library_context = OSSL_LIB_CTX_new();
    if (library_context == NULL) {
        fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
        goto end;
    }

    /* Fetch the key derivation function implementation */
    kdf = EVP_KDF_fetch(library_context, "HKDF", "provider=default");
    if (kdf == NULL) {
        fprintf(stderr, "EVP_KDF_fetch() returned NULL\n");
        goto end;
    }

    /* Create a context for the key derivation operation */
    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        fprintf(stderr, "EVP_KDF_CTX_new() returned NULL\n");
        goto end;
    }

    switch (qat_hkdf_ctx->mode) {
        case EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY:
            mode = "EXTRACT_ONLY";
            break;

        case EVP_PKEY_HKDEF_MODE_EXPAND_ONLY:
            mode = "EXPAND_ONLY";
            break;

        case EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND:
            mode = "EXTRACT_AND_EXPAND";
            break;

        default:
            WARN("Unknown HKDF mode \n");
            return 0;
    }

    mdname = EVP_MD_get0_name(qat_hkdf_ctx->qat_md);

    /* Set the underlying hash function used to derive the key */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)mdname, 0);
    /* Set input keying material */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, qat_hkdf_ctx->sw_ikm,
                                             qat_hkdf_ctx->sw_ikm_size);
    /* Set application specific information */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, qat_hkdf_ctx->sw_info,
                                                qat_hkdf_ctx->sw_info_size);
    /* Set mode */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, mode, 0);
    /* Set salt */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, qat_hkdf_ctx->sw_salt,
                                             qat_hkdf_ctx->sw_salt_size);

    *p = OSSL_PARAM_construct_end();

    /* Derive the key */
    if (EVP_KDF_derive(kctx, out, olen, params) != 1) {
        fprintf(stderr, "EVP_KDF_derive() failed\n");
        goto end;
    }

    rv = 0;
end:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    OSSL_LIB_CTX_free(library_context);
    return rv;
}
#endif
/******************************************************************************
* function:
*         qat_hkdf_derive(QAT_HKDF_CTX *qat_hkdf_ctx,
*                         unsigned char *key,
*                         size_t *olen)
*
* @param qat_hkdf_ctx    [IN]  - HKDF context
* @param key             [OUT] - Ptr to the key that will be generated
* @param olen            [IN]  - Length of the key
*
* description:
*   HKDF derive function for TLS case
******************************************************************************/
int qat_hkdf_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *olen)
{
    int ret = 0, job_ret = 0;
    CpaFlatBuffer *generated_key = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    QAT_HKDF_CTX *qat_hkdf_ctx = NULL;
    CpaCyKeyHKDFCipherSuite cipher_suite;
    int key_length = 0;
    int offset = 0;
    int md_size = 0;
    op_done_t op_done;
    int qatPerformOpRetries = 0;
    int iMsgRetry = getQatMsgRetryCount();
    unsigned long int ulPollInterval = getQatPollInterval();
    int inst_num = QAT_INVALID_INSTANCE;
    thread_local_variables_t *tlv = NULL;
    int fallback = 0;
#ifdef QAT_OPENSSL_PROVIDER
    size_t hkdflabellen;
    unsigned char hkdflabel[2048];
    qat_WPACKET pkt;
    const unsigned char *tls13_data;
    size_t tls13_datalen;
    unsigned char tls13_kdf_hash[EVP_MAX_MD_SIZE];
#endif
#ifndef QAT_OPENSSL_3
    int (*sw_derive_fn_ptr)(EVP_PKEY_CTX *, unsigned char *, size_t *) = NULL;
#endif
    if (unlikely(NULL == ctx || NULL == key || NULL == olen)) {
        WARN("Either ctx %p, key %p or olen %p is NULL\n", ctx, key, olen);
        QATerr(QAT_F_QAT_HKDF_DERIVE, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    DEBUG("QAT HW HKDF Started\n");
    qat_hkdf_ctx = (QAT_HKDF_CTX *)EVP_PKEY_CTX_get_data(ctx);
    if (qat_hkdf_ctx == NULL) {
        WARN("qat_hkdf_ctx is NULL\n");
        QATerr(QAT_F_QAT_HKDF_DERIVE, ERR_R_INTERNAL_ERROR);
        return ret;
    }

    if (qat_get_qat_offload_disabled()) {
        DEBUG("- Switched to software mode\n");
        fallback = 1;
        goto err;
    }

    if (!qat_get_cipher_suite(qat_hkdf_ctx, &cipher_suite)) {
        DEBUG("Failed to get cipher suite, fallback to SW\n");
        fallback = 1;
        goto err;
    }

    if (!qat_set_hkdf_mode(qat_hkdf_ctx)) {
        WARN("Error setting mode into HKDFOpdata\n");
        QATerr(QAT_F_QAT_HKDF_DERIVE, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    generated_key = (CpaFlatBuffer *) OPENSSL_zalloc(sizeof(CpaFlatBuffer));

    if (NULL == generated_key) {
        WARN("Failed to allocate memory for generated_key\n");
        QATerr(QAT_F_QAT_HKDF_DERIVE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    key_length = *olen;
    md_size = EVP_MD_size(qat_hkdf_ctx->qat_md);
#ifdef QAT_OPENSSL_PROVIDER
    /*hkdf label creation and intialization for TLS13-KDF*/
    if((qat_hkdf_ctx->hkdf_op_data->hkdfKeyOp == CPA_CY_HKDF_KEY_EXPAND_LABEL)) {
        if (qat_hkdf_ctx->hkdf_op_data->seedLen != 0) {
            EVP_MD_CTX *mctx = EVP_MD_CTX_new();

            /* The pre-extract derive step uses a hash of no messages */
            if (mctx == NULL
                    || EVP_DigestInit_ex(mctx, qat_hkdf_ctx->qat_md, NULL) <= 0
                    || EVP_DigestFinal_ex(mctx, tls13_kdf_hash, NULL) <= 0) {
                EVP_MD_CTX_free(mctx);
                return 0;
            }
            EVP_MD_CTX_free(mctx);

            memcpy(qat_hkdf_ctx->hkdf_op_data->secret, qat_hkdf_ctx->hkdf_op_data->seed,
                   qat_hkdf_ctx->hkdf_op_data->seedLen);
            qat_hkdf_ctx->hkdf_op_data->secretLen = qat_hkdf_ctx->hkdf_op_data->seedLen;

            OPENSSL_cleanse(qat_hkdf_ctx->hkdf_op_data->seed,
                            qat_hkdf_ctx->hkdf_op_data->seedLen);
            qat_hkdf_ctx->hkdf_op_data->seedLen = 0;

            tls13_data = tls13_kdf_hash;
            tls13_datalen = md_size;

        } else {
            tls13_data = qat_hkdf_ctx->data;
            tls13_datalen = qat_hkdf_ctx->data_len;
        }
        if (!QAT_WPACKET_init_static_len(&pkt, hkdflabel, sizeof(hkdflabel), 0)
            || !QAT_WPACKET_put_bytes_u16(&pkt, key_length)
            || !QAT_WPACKET_start_sub_packet_u8(&pkt)
            || !QAT_WPACKET_memcpy(&pkt, qat_hkdf_ctx->prefix, qat_hkdf_ctx->prefix_len)
            || !QAT_WPACKET_memcpy(&pkt, qat_hkdf_ctx->label, qat_hkdf_ctx->label_len)
            || !QAT_WPACKET_close(&pkt)
            || !QAT_WPACKET_sub_memcpy_u8(&pkt, tls13_data, (tls13_data == NULL) ? 0 : tls13_datalen)
            || !QAT_WPACKET_get_total_written(&pkt, &hkdflabellen)
            || !QAT_WPACKET_finish(&pkt)) {
            QAT_WPACKET_cleanup(&pkt);}

        memcpy(qat_hkdf_ctx->hkdf_op_data->label[0].label, hkdflabel, hkdflabellen);
        qat_hkdf_ctx->hkdf_op_data->label[0].labelLen = hkdflabellen;
        qat_hkdf_ctx->hkdf_op_data->label[0].sublabelFlag = 0x00;
    }
#endif
    /* For Extract and Expand, PRK and OKM is sent back so datalen is
       modified here to accommodate it */
    if (qat_hkdf_ctx->hkdf_op_data->hkdfKeyOp == CPA_CY_HKDF_KEY_EXTRACT_EXPAND) {
        offset = md_size;
        key_length = 2 * offset;
    }

    /* API Expects Key Length equal to md_size */
    if (key_length < md_size)
        key_length = md_size;

    generated_key->pData = (Cpa8U *) qaeCryptoMemAlloc(key_length,
                            __FILE__, __LINE__);
    if (NULL == generated_key->pData) {
        WARN("Failed to allocate memory for generated_key data\n");
        QATerr(QAT_F_QAT_HKDF_DERIVE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    generated_key->dataLenInBytes = key_length;

    /* ---- Perform the operation ---- */
    DUMP_HKDF_OP_DATA(qat_hkdf_ctx->hkdf_op_data);

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        QATerr(QAT_F_QAT_HKDF_DERIVE, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_HKDF_DERIVE, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            goto err;
        }
    }

    do {
        if ((inst_num = get_next_inst_num(INSTANCE_TYPE_CRYPTO_SYM))
             == QAT_INVALID_INSTANCE) {
            WARN("Failed to get an instance\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                fallback = 1;
            } else {
                QATerr(QAT_F_QAT_HKDF_DERIVE, ERR_R_INTERNAL_ERROR);
            }
            if (op_done.job != NULL) {
                qat_clear_async_event_notification(op_done.job);
            }
            qat_cleanup_op_done(&op_done);
            goto err;
        }

        DUMP_KEYGEN_TLS(qat_instance_handles[inst_num], generated_key);
        DEBUG("Calling cpaCyKeyGenTls3 \n");
        status = cpaCyKeyGenTls3(qat_instance_handles[inst_num],
                                 qat_hkdf_cb, &op_done,
                                 qat_hkdf_ctx->hkdf_op_data,
                                 cipher_suite,
                                 generated_key);

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
                if ((qat_wake_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0) ||
                    (qat_pause_job(op_done.job, ASYNC_STATUS_EAGAIN) == 0)) {
                    WARN("qat_wake_job or qat_pause_job failed\n");
                    break;
                }
            }
        }

    } while (status == CPA_STATUS_RETRY);

    if (CPA_STATUS_SUCCESS != status) {
        WARN("Failed to submit request to qat - status = %d\n", status);
        if (qat_get_sw_fallback_enabled() &&
            (status == CPA_STATUS_RESTARTING || status == CPA_STATUS_FAIL)) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            fallback = 1;
        } else if (status == CPA_STATUS_UNSUPPORTED) {
            WARN("Algorithm Unsupported in QAT_HW! Using OpenSSL SW\n");
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_HKDF_DERIVE, ERR_R_INTERNAL_ERROR);
        }
        if (op_done.job != NULL) {
            qat_clear_async_event_notification(op_done.job);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n",
                      &hw_polling_thread_sem);
                QATerr(QAT_F_QAT_HKDF_DERIVE, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                goto err;
            }
        }
    }

    if (qat_get_sw_fallback_enabled()) {
        CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n",
                       inst_num,
                       qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                       __func__);
    }

    if (enable_heuristic_polling) {
        QAT_ATOMIC_INC(num_kdf_requests_in_flight);
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
            if ((job_ret = qat_pause_job(op_done.job, ASYNC_STATUS_OK)) == 0)
                sched_yield();
        } else {
            sched_yield();
        }
    }
    while (!op_done.flag ||
           QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DUMP_KEYGEN_TLS_OUTPUT(generated_key);
    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

    if (op_done.verifyResult != CPA_TRUE) {
        WARN("Verification of result failed\n");
        if (qat_get_sw_fallback_enabled() && op_done.status == CPA_STATUS_FAIL) {
            CRYPTO_QAT_LOG("Verification of result failed for qat inst_num %d device_id %d - fallback to SW - %s\n",
                           inst_num,
                           qat_instance_details[inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            fallback = 1;
        } else {
            QATerr(QAT_F_QAT_HKDF_DERIVE, ERR_R_INTERNAL_ERROR);
        }
        qat_cleanup_op_done(&op_done);
        goto err;
    }

    qat_cleanup_op_done(&op_done);

    DUMPL("Generated key", generated_key->pData, key_length);

    if (unlikely(generated_key->pData == NULL)) {
        WARN("generated_key->pData is NULL\n");
        QATerr(QAT_F_QAT_HKDF_DERIVE, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    memcpy(key, generated_key->pData + offset, *olen);
    ret = 1;

 err:
    /* Clean the memory  */
    if (NULL != qat_hkdf_ctx->hkdf_op_data) {
        if (NULL != generated_key) {
            if (NULL != generated_key->pData) {
                OPENSSL_cleanse(generated_key->pData, key_length);
                qaeCryptoMemFreeNonZero(generated_key->pData);
            }
            OPENSSL_free(generated_key);
          }
    }

    if (fallback) {
        WARN("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
#ifndef QAT_OPENSSL_3
        EVP_PKEY_meth_get_derive((EVP_PKEY_METHOD *)sw_hkdf_pmeth, NULL, &sw_derive_fn_ptr);
        EVP_PKEY_CTX_set_data(ctx, qat_hkdf_ctx->sw_hkdf_ctx_data);
        ret = (*sw_derive_fn_ptr)(ctx, key, olen);
        EVP_PKEY_CTX_set_data(ctx, qat_hkdf_ctx);
#else
        ret = default_provider_HKDF_derive(qat_hkdf_ctx, key, *olen);
#endif
    }
    return ret;
}
#endif /* ENABLE_QAT_HW_HKDF */
