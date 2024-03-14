/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023-2024 Intel Corporation.
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
 * @file qat_hw_ccm.c
 *
 * This file contains the engine implementations for CCM cipher operations
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <string.h>
#include <pthread.h>
#include <signal.h>
#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_USDM_MEM
# include "qat_hw_usdm_inf.h"
#endif
#include "e_qat.h"
#include "qat_utils.h"
#include "qat_hw_callback.h"
#include "qat_hw_polling.h"
#include "qat_events.h"

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_sym.h"
#include "qat_evp.h"
#include "qat_hw_ccm.h"
#include "qat_hw_ciphers.h"
#ifdef QAT_OPENSSL_PROVIDER
# include "qat_prov_aes_ccm.h"
#endif

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/tls1.h>
#include <openssl/ssl.h>

#define GET_SW_AES_CCM_CIPHER(ctx) \
    qat_ccm_cipher_sw_impl(EVP_CIPHER_CTX_type((ctx)) )

#ifdef ENABLE_QAT_HW_CCM
/******************************************************************************
* function:
*         qat_session_data_init(EVP_CIPHER_CTX *ctx,
*                               qat_aes_ccm_ctx *qctx,
*                               const unsigned char* key,
*                               const unsigned char* iv,
*                               int enc)
*
* @param ctx     [IN] - pointer to the evp context
* @param qctx    [IN] - pointer to the qat context
* @param key     [IN] - pointer to the cipher key
* @param iv      [IN] - pointer to the iv this maybe NULL.
* @param enc     [IN] - whether we are doing encryption (1) or decryption (0).
*
* description:
*    This function is to create QAT specific session data.
*    It is called from the function qat_aes_ccm_init().
*
*    It will return 1 if successful and 0 on failure.
******************************************************************************/
# ifdef QAT_OPENSSL_PROVIDER
static int qat_session_data_init(EVP_CIPHER_CTX *ctx,
                                 void *vctx,
                                 const unsigned char *key,
                                 int keylen,
                                 const unsigned char *iv, int ivlen, int enc)
# else
static int qat_session_data_init(EVP_CIPHER_CTX *ctx,
                                 qat_ccm_ctx * qctx,
                                 const unsigned char *key,
                                 const unsigned char *iv, int enc)
# endif
{
# ifdef QAT_OPENSSL_PROVIDER
    QAT_PROV_CCM_CTX *qctx = (QAT_PROV_CCM_CTX *) vctx;
# endif
    DEBUG("QAT HW CCM Started\n");
    if (NULL == qctx || NULL == ctx) {
        WARN("qctx or ctx is NULL\n");
        QATerr(QAT_F_QAT_SESSION_DATA_INIT, QAT_R_QCTX_CTX_NULL);
        return 0;
    }

    if (key != NULL) {
        if (qctx->qat_svm) {
            if (qctx->cipher_key) {
                OPENSSL_free(qctx->cipher_key);
                qctx->cipher_key = NULL;
            }
# ifdef QAT_OPENSSL_PROVIDER
            qctx->cipher_key = OPENSSL_zalloc(keylen);
# else
            qctx->cipher_key = OPENSSL_zalloc(EVP_CIPHER_CTX_key_length(ctx));
# endif
        } else {
            if (qctx->cipher_key) {
                qaeCryptoMemFreeNonZero(qctx->cipher_key);
                qctx->cipher_key = NULL;
            }
# ifdef QAT_OPENSSL_PROVIDER
            qctx->cipher_key = qaeCryptoMemAlloc(keylen, __FILE__, __LINE__);
# else
            qctx->cipher_key =
                qaeCryptoMemAlloc(EVP_CIPHER_CTX_key_length(ctx), __FILE__,
                                  __LINE__);
# endif
        }

        if (qctx->cipher_key == NULL) {
            WARN("Unable to allocate memory for qctx->cipher_key.\n");
            QATerr(QAT_F_QAT_SESSION_DATA_INIT, QAT_R_KEY_MALLOC_FAILURE);
            return 0;
        }
# ifdef QAT_OPENSSL_PROVIDER
        memcpy(qctx->cipher_key, key, keylen);
# else
        memcpy(qctx->cipher_key, key, EVP_CIPHER_CTX_key_length(ctx));
# endif
        qctx->key_set = 1;
    }

    if (iv != NULL && qctx->iv_set) {
        qctx->OpData.ivLenInBytes = QAT_AES_CCM_OP_VALUE - qctx->L;
    }
    if (NULL == qctx->session_data) {
        qctx->session_data = OPENSSL_zalloc(sizeof(CpaCySymSessionSetupData));
        if (NULL == qctx->session_data) {
            WARN("session setup data zalloc failure\n");
            QATerr(QAT_F_QAT_SESSION_DATA_INIT, QAT_R_SSD_MALLOC_FAILURE);
            return 0;
        }
    }
    /* Set priority and operation of this session */
    qctx->session_data->sessionPriority = CPA_CY_PRIORITY_HIGH;
    qctx->session_data->symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING;

    /* --- Cipher configuration --- */

    /* Cipher algorithm and mode */
    qctx->session_data->cipherSetupData.cipherAlgorithm =
        CPA_CY_SYM_CIPHER_AES_CCM;
    /* Cipher key length */
    if (key != NULL && qctx->key_set) {
# ifdef QAT_OPENSSL_PROVIDER
        qctx->session_data->cipherSetupData.cipherKeyLenInBytes = keylen;
# else
        qctx->session_data->cipherSetupData.cipherKeyLenInBytes =
            EVP_CIPHER_CTX_key_length(ctx);
# endif
    }

    if (qctx->key_set) {
        qctx->session_data->cipherSetupData.pCipherKey =
            (Cpa8U *) qctx->cipher_key;
    }

    /* Operation to perform */
    if (enc) {
        qctx->session_data->cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;
        qctx->session_data->algChainOrder =
            CPA_CY_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER;
        /* Tag follows immediately after the region to hash */
    } else {
        qctx->session_data->cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;
        qctx->session_data->algChainOrder =
            CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH;
    }

    /* --- Hash Configuration --- */

    /* Set the hash mode and the length of the digest */
    qctx->session_data->hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_AES_CCM;
    qctx->session_data->hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
    qctx->session_data->hashSetupData.digestResultLenInBytes = qctx->M;

    /* For CCM authKey and authKeyLen are not required.
     * This information is provided by the cipherKey in cipherSetupData */
    qctx->session_data->hashSetupData.authModeSetupData.authKey = NULL;
    qctx->session_data->hashSetupData.authModeSetupData.authKeyLenInBytes = 0;

    /* Set the length of the AAD to the default value */
    qctx->session_data->hashSetupData.authModeSetupData.aadLenInBytes = 0;

    /* Tag follows immediately after the region to hash */
    qctx->session_data->digestIsAppended = CPA_TRUE;

    /* digestVerify is not required to be set. For CCM authenticated
     * encryption this value is understood to be CPA_FALSE during encryption and
     * CPA_TRUE during decryption */

    qctx->init_params_set = 1;

    return 1;
}

/******************************************************************************
* function:
*         qat_aes_ccm_init(EVP_CIPHER_CTX *ctx,
*                          const unsigned char *inkey,
*                          const unsigned char *iv,
*                          int enc)
*
* @param ctx     [IN]  - pointer to existing context
* @param inKey   [IN]  - input cipher key
* @param iv      [IN]  - initialisation vector
* @param enc     [IN]  - 1 encrypt 0 decrypt
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function initialises the cipher and hash algorithm parameters for this
*  EVP context.
*
******************************************************************************/
# ifdef QAT_OPENSSL_PROVIDER
int qat_aes_ccm_init(void *ctx, const unsigned char *inkey,
                     int keylen, const unsigned char *iv, int ivlen, int enc)
{
# else
int qat_aes_ccm_init(EVP_CIPHER_CTX *ctx,
                     const unsigned char *inkey,
                     const unsigned char *iv, int enc)
{
# endif
# ifdef QAT_OPENSSL_PROVIDER
    QAT_PROV_CCM_CTX *qctx = (QAT_PROV_CCM_CTX *) ctx;
# else
    qat_ccm_ctx *qctx = NULL;
# endif

# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    int ret = 1;
#  ifdef QAT_OPENSSL_PROVIDER
    QAT_EVP_CIPHER sw_aes_ccm_cipher;
    int nid = qctx->nid;
#  endif
# endif

    if (NULL == ctx) {
        WARN("ctx is NULL\n");
        QATerr(QAT_F_QAT_AES_CCM_INIT, QAT_R_CTX_NULL);
        return 0;
    }

    DEBUG("CTX = %p, key = %p, iv = %p, enc = %d\n",
          (void *)ctx, (void *)inkey, (void *)iv, enc);

# ifndef QAT_OPENSSL_PROVIDER
    qctx = QAT_CCM_GET_CTX(ctx);
# else
    qctx->enc = enc;
# endif

    /* Initialise a QAT session and set the cipher keys */
    if (NULL == qctx) {
        WARN("qctx is NULL\n");
        QATerr(QAT_F_QAT_AES_CCM_INIT, QAT_R_QCTX_NULL);
        return 0;
    }
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  ifndef QAT_OPENSSL_PROVIDER
    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
    /* Run the software init function */
    ret =
        EVP_CIPHER_meth_get_init(GET_SW_AES_CCM_CIPHER(ctx)) (ctx, inkey, iv,
                                                              enc);
    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
    if (ret != 1)
        goto err;
#  else
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    sw_aes_ccm_cipher = get_default_cipher_aes_ccm(nid);

    if (enc) {
        if (!qctx->sw_ctx)
            qctx->sw_ctx = sw_aes_ccm_cipher.newctx(ctx);
        ret =
            sw_aes_ccm_cipher.einit(qctx->sw_ctx, inkey, keylen, iv, ivlen,
                                    params);
    } else {
        if (!qctx->sw_ctx)
            qctx->sw_ctx = sw_aes_ccm_cipher.newctx(ctx);

        unsigned int pad = 0;
        params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &pad);
        ret =
            sw_aes_ccm_cipher.dinit(qctx->sw_ctx, inkey, keylen, iv, ivlen,
                                    params);
    }
    if (ret != 1)
        goto err;
#  endif
# endif

    if (!inkey && !iv) {
        DEBUG("key and IV not set\n");
        return 1;
    }

    if ((qctx->inst_num = get_instance(QAT_INSTANCE_SYM, QAT_INSTANCE_ANY))
        == QAT_INVALID_INSTANCE) {
        WARN("Failed to get QAT Instance Handle\n");
        return 0;
    }

    qctx->qat_svm =
        !qat_instance_details[qctx->inst_num].qat_instance_info.
        requiresPhysicallyContiguousMemory;

    if (iv) {
        /* Set the value of the IV */
        memcpy(qctx->next_iv, iv, QAT_AES_CCM_OP_VALUE - qctx->L);
        qctx->iv_len = QAT_AES_CCM_OP_VALUE - qctx->L;
        qctx->iv_set = 1;
    }

    qctx->tls_aad_len = -1;
    qctx->tag_len = -1;
    qctx->tag_set = 0;
    qctx->len_set = 0;

    /* Initialize QAT session */
# ifdef QAT_OPENSSL_PROVIDER
    if (0 == qat_session_data_init(ctx, qctx, inkey, keylen, iv, ivlen, enc)) {
# else
    if (0 == qat_session_data_init(ctx, qctx, inkey, iv, enc)) {
# endif
        WARN("qat_session_data_init failed.\n");
        goto err;
    }

    return 1;

 err:
    QAT_MEM_FREE_BUFF(qctx->cipher_key, qctx->qat_svm);
    return 0;
}

/******************************************************************************
* function:
*    qat_aes_ccm_ctrl(EVP_CIPHER_CTX *ctx,
*                     int type, int arg, void *ptr)
*
* @param ctx     [IN]  - pointer to existing context
* @param type    [IN]  - type of request either
*                        EVP_CTRL_AEAD_SET_MAC_KEY or EVP_CTRL_AEAD_TLS1_AAD
* @param arg     [IN]  - size of the pointed to by ptr
* @param ptr     [IN]  - input buffer contain the necessary parameters
*
* @retval x      The return value is dependent on the type of request being made
*                EVP_CTRL_AEAD_SET_MAC_KEY return of 1 is success
*                EVP_CTRL_AEAD_TLS1_AAD return value indicates the amount
*                for padding to be applied to the SSL/TLS record
* @retval -1     function failed
*
* description:
*    This function is a generic control interface provided by the EVP API. For
*  chained requests this interface is used for setting the hmac key value for
*  authentication of the SSL/TLS record.
*  The second type is used to specify the TLS virtual header which is used
*  in the authentication calculation and to identify record payload size.
*
******************************************************************************/
# ifdef QAT_OPENSSL_PROVIDER
int qat_aes_ccm_ctrl(void *ctx, int type, int arg, void *ptr)
# else
int qat_aes_ccm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
# endif
{
# ifdef QAT_OPENSSL_PROVIDER
    QAT_PROV_CCM_CTX *qctx = (QAT_PROV_CCM_CTX *) ctx;
# else
    qat_ccm_ctx *qctx = NULL;
#  ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    int ret_sw = 0;
    int nid = EVP_CIPHER_CTX_nid(ctx);
#  endif
# endif
    unsigned int plen = 0;
    int enc = 0;

    if (NULL == ctx) {
        WARN("ctx is NULL.\n");
        QATerr(QAT_F_QAT_AES_CCM_CTRL, QAT_R_CTX_NULL);
        return 0;
    }
# ifdef QAT_OPENSSL_PROVIDER
    enc = qctx->enc;
# else
    enc = EVP_CIPHER_CTX_encrypting(ctx);
    qctx = QAT_CCM_GET_CTX(ctx);

    if (NULL == qctx) {
        WARN("qctx is NULL\n");
        QATerr(QAT_F_QAT_AES_CCM_CTRL, QAT_R_QCTX_NULL);
        return 0;
    }
# endif

    switch (type) {
    case EVP_CTRL_INIT:
        DEBUG("EVP_CTRL_INIT, ctx = %p, type = %d, "
              "arg = %d, ptr = %p\n", (void *)ctx, type, arg, ptr);
        qctx->key_set = 0;
        qctx->iv_len = QAT_CCM_TLS_TOTAL_IV_LEN;
        qctx->iv_set = 0;
        qctx->tag_set = 0;
        qctx->L = 8;
        qctx->M = 12;
        qctx->tls_aad_len = -1;
        qctx->tag_len = -1;
        qctx->len_set = 0;
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  ifndef QAT_OPENSSL_PROVIDER
        if (qctx->sw_ctx_cipher_data == NULL) {
            unsigned int sw_size = 0;
            sw_size = EVP_CIPHER_impl_ctx_size(GET_SW_AES_CCM_CIPHER(ctx));
            qctx->sw_ctx_cipher_data = OPENSSL_zalloc(sw_size);
            if (qctx->sw_ctx_cipher_data == NULL) {
                WARN("Unable to allocate memory for sw_ctx_cipher_data\n");
                return -1;
            }
        }
        goto sw_ctrl;
#  endif
# endif
        return 1;

    case EVP_CTRL_GET_IVLEN:
        DEBUG("EVP_CTRL_CCM_GET_IVLEN, ctx = %p, type = %d,"
              " arg = %d, ptr = %p\n", (void *)ctx, type, arg, ptr);
        *(int *)ptr = QAT_AES_CCM_OP_VALUE - qctx->L;
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  ifndef QAT_OPENSSL_PROVIDER
        if (qctx->packet_size <= qat_pkt_threshold_table_get_threshold(nid)) {
            goto sw_ctrl;
        }
#  endif
# endif
        return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        DEBUG("EVP_CTRL_AEAD_SET_TAG, ctx = %p, type = %d,"
              " arg = %d, ptr = %p\n", (void *)ctx, type, arg, ptr);

        if (arg < QAT_CCM_TAG_MIN_LEN || arg > QAT_CCM_TAG_MAX_LEN) {
            WARN("TAG length invalid or invalid operation enc\n");
            QATerr(QAT_F_QAT_AES_CCM_CTRL, QAT_R_SET_TAG_INVALID_OP);
            return 0;
        }

        if (NULL == EVP_CIPHER_CTX_buf_noconst(ctx)) {
            WARN("Memory pointer is not valid\n");
            QATerr(QAT_F_QAT_AES_CCM_CTRL, QAT_R_INVALID_PTR);
            return 0;
        }

        /* ctx->buf is a static buffer of size
         * EVP_MAX_BLOCK_LENGTH = 32
         */
        if (ptr) {
            memcpy(EVP_CIPHER_CTX_buf_noconst(ctx), ptr, arg);
            qctx->tag_set = 1;
        }
        qctx->tag_len = arg;
        qctx->M = arg;
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  ifndef QAT_OPENSSL_PROVIDER
        if (qctx->packet_size <= qat_pkt_threshold_table_get_threshold(nid)) {
            goto sw_ctrl;
        }
#  endif
# endif
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        DEBUG("EVP_CTRL_CCM_GET_TAG, ctx = %p, type = %d,"
              " arg = %d, ptr = %p\n", (void *)ctx, type, arg, ptr);
        if (arg <= QAT_CCM_TAG_MIN_LEN || arg > QAT_CCM_TAG_MAX_LEN || !enc) {
            WARN("TAG length invalid or invalid operation (!enc)\n");
            QATerr(QAT_F_QAT_AES_CCM_CTRL, QAT_R_SET_TAG_INVALID_OP);
            return 0;
        }
        if (NULL == EVP_CIPHER_CTX_buf_noconst(ctx) || NULL == ptr) {
            WARN("Memory pointer is not valid\n");
            QATerr(QAT_F_QAT_AES_CCM_CTRL, QAT_R_INVALID_PTR);
            return 0;
        }
        memcpy(ptr, EVP_CIPHER_CTX_buf_noconst(ctx), arg);
        qctx->tag_set = 0;
        qctx->iv_set = 0;
        qctx->len_set = 0;
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  ifndef QAT_OPENSSL_PROVIDER
        if (qctx->packet_size <= qat_pkt_threshold_table_get_threshold(nid)) {
            goto sw_ctrl;
        }
#  endif
# endif
        return 1;

    case EVP_CTRL_CCM_SET_IV_FIXED:
        DEBUG("EVP_CTRL_CCM_SET_IV_FIXED, ctx = %p, type = %d,"
              " arg = %d, ptr = %p\n", (void *)ctx, type, arg, ptr);
        if (NULL == ptr) {
            WARN("Memory pointer is not valid\n");
            QATerr(QAT_F_QAT_AES_CCM_CTRL, QAT_R_INVALID_PTR);
            return 0;
        }

        /* Special case: -1 length restores whole IV */
        if (arg == -1) {
            memcpy(qctx->next_iv, ptr, QAT_CCM_TLS_TOTAL_IV_LEN);
            return 1;
        }
        /* Fixed field must be at least 4 bytes (EVP_CCM_TLS_FIXED_IV_LEN)
         * and invocation field at least 8 (EVP_CCM_TLS_EXPLICIT_IV_LEN)
         */
        if ((arg < EVP_CCM_TLS_FIXED_IV_LEN) ||
            (qctx->iv_len - arg) < EVP_CCM_TLS_EXPLICIT_IV_LEN) {
            WARN("IV length invalid\n");
            return 0;
        }

        if (arg != EVP_CCM_TLS_FIXED_IV_LEN) {
            WARN("IV length not supported\n");
            return 0;
        }
        if (arg) {
            memcpy(qctx->next_iv, ptr, arg);
        }
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  ifndef QAT_OPENSSL_PROVIDER
        if (qctx->packet_size <= qat_pkt_threshold_table_get_threshold(nid)) {
            goto sw_ctrl;
        }
#  endif
# endif
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
# ifdef ENABLE_QAT_SMALL_PKT_OFFLOAD
        arg = QAT_AES_CCM_OP_VALUE - arg;
# endif
        /* fall thru */

    case EVP_CTRL_CCM_SET_L:
# ifdef ENABLE_QAT_SMALL_PKT_OFFLOAD
        if (arg < 2 || arg > 8)
            return 0;

        qctx->L = arg;
# endif
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  ifndef QAT_OPENSSL_PROVIDER
        qctx->L = QAT_AES_CCM_OP_VALUE - arg;
        goto sw_ctrl;
#  endif
# endif
        return 1;

    case EVP_CTRL_AEAD_TLS1_AAD:
        DEBUG("EVP_CTRL_AEAD_TLS1_AAD, ctx = %p, type = %d,"
              " arg = %d, ptr = %p\n", (void *)ctx, type, arg, ptr);
        if (TLS_VIRT_HDR_SIZE != arg) {
            WARN("AAD length is not valid\n");
            QATerr(QAT_F_QAT_AES_CCM_CTRL, QAT_R_AAD_LEN_INVALID);
            return 0;
        }

        /* Allocate the memory only the first time */
        if (qctx->tls_aad_len < 0) {
            int aad_buffer_len = TLS_VIRT_HDR_SIZE;
            DEBUG("Allocating memory for AAD in TLS sync\n");
            /* For QAT the length of the buffer for AAD must be multiple
             * of block size */
            if (aad_buffer_len % AES_BLOCK_SIZE) {
                aad_buffer_len +=
                    AES_BLOCK_SIZE - (aad_buffer_len % AES_BLOCK_SIZE);
                DEBUG("Adjusting AAD buffer length = %d\n", aad_buffer_len);
            }
            qctx->aad =
                qat_mem_alloc(aad_buffer_len, qctx->qat_svm, __FILE__,
                              __LINE__);
            if (NULL == qctx->aad) {
                WARN("Unable to allocate memory for TLS header\n");
                QATerr(QAT_F_QAT_AES_CCM_CTRL, QAT_R_AAD_MALLOC_FAILURE);
                return 0;
            }

            /* Set the flag to mark the TLS case */
            qctx->tls_aad_len = arg;

            /* Set the length of the AAD in the session
             * The session hasn't been initialized yet here and this value
             * should never change in the TLS case */
            qctx->session_data->hashSetupData.authModeSetupData.aadLenInBytes =
                arg;
        }

        if (NULL == qctx->aad || NULL == ptr) {
            WARN("Memory pointer is not valid\n");
            QATerr(QAT_F_QAT_AES_CCM_CTRL, QAT_R_AAD_INVALID_PTR);
            return 0;
        }

        /* Copy the header from p into the buffer */
        memcpy(qctx->aad, ptr, arg);

        /* Extract the length of the payload from the TLS header */
        plen = qctx->aad[arg - QAT_CCM_TLS_PAYLOADLENGTH_MSB_OFFSET]
            << QAT_BYTE_SHIFT |
            qctx->aad[arg - QAT_CCM_TLS_PAYLOADLENGTH_LSB_OFFSET];

        DEBUG("IN plen = %d\n", plen);
        DUMPL("IN qctx->aad", qctx->aad, TLS_VIRT_HDR_SIZE);

        /* The payload contains the explicit IV -> correct the length */
        plen -= EVP_CCM_TLS_EXPLICIT_IV_LEN;

        /* If decrypting correct for tag too */
        if (!enc) {
            plen -= qctx->M;
        }

        /* Fix the length like in the SW version of CCM */
        qctx->aad[arg - QAT_CCM_TLS_PAYLOADLENGTH_MSB_OFFSET]
            = plen >> QAT_BYTE_SHIFT;
        qctx->aad[arg - QAT_CCM_TLS_PAYLOADLENGTH_LSB_OFFSET]
            = plen & 0xff;

        DEBUG("OUT plen = %d\n", plen);
        DUMPL("OUT qctx->aad", qctx->aad, TLS_VIRT_HDR_SIZE);
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  ifndef QAT_OPENSSL_PROVIDER
        if (qctx->packet_size <= qat_pkt_threshold_table_get_threshold(nid)) {
            goto sw_ctrl;
        }
#  endif
# endif
        /* Return the length of the TAG */
        return qctx->M;

    case EVP_CTRL_COPY:
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  ifndef QAT_OPENSSL_PROVIDER
        if (qctx->packet_size <= qat_pkt_threshold_table_get_threshold(nid)) {
            goto sw_ctrl;
        }
#  endif
# endif
        return 1;

    default:
        WARN("Invalid type %d\n", type);
        QATerr(QAT_F_QAT_AES_CCM_CTRL, QAT_R_INVALID_CTRL_TYPE);
        return -1;
    }
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  ifndef QAT_OPENSSL_PROVIDER
 sw_ctrl:
    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
    ret_sw =
        EVP_CIPHER_meth_get_ctrl(GET_SW_AES_CCM_CIPHER(ctx)) (ctx, type, arg,
                                                              ptr);
    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
    if (ret_sw < 0) {
        WARN("SW aes-ccm ctrl function failed.\n");
        return -1;
    }
    return ret_sw;
#  endif
# endif
}

/******************************************************************************
* function:
*    qat_aes_ccm_cleanup(EVP_CIPHER_CTX *ctx)
*
* @param ctx    [IN]  - pointer to existing context
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function will cleanup all allocated resources required to perform the
*  cryptographic transform.
*
******************************************************************************/
# ifdef QAT_OPENSSL_PROVIDER
int qat_aes_ccm_cleanup(void *ctx)
# else
int qat_aes_ccm_cleanup(EVP_CIPHER_CTX *ctx)
# endif
{
# ifdef QAT_OPENSSL_PROVIDER
    QAT_PROV_CCM_CTX *qctx = (QAT_PROV_CCM_CTX *) ctx;
# else
    qat_ccm_ctx *qctx = NULL;
# endif
    CpaStatus sts = 0;
    CpaCySymSessionSetupData *session_data = NULL;
    CpaBoolean sessionInUse = CPA_FALSE;
    int ret_val = 1;

    DEBUG("- Entering\n");

    if (NULL == ctx) {
        WARN("ctx is NULL\n");
        QATerr(QAT_F_QAT_AES_CCM_CLEANUP, QAT_R_CTX_NULL);
        return 0;
    }
# ifndef QAT_OPENSSL_PROVIDER
    qctx = QAT_CCM_GET_CTX(ctx);

    if (NULL == qctx) {
        WARN("qctx is NULL\n");
        QATerr(QAT_F_QAT_AES_CCM_CLEANUP, QAT_R_QCTX_NULL);
        return 0;
    }
# endif

    /* Wait for in-flight requests before removing session */
    if (qctx->qat_ctx != NULL) {
        do {
            cpaCySymSessionInUse(qctx->qat_ctx, &sessionInUse);
        } while (sessionInUse);
    }

    session_data = qctx->session_data;
    if (session_data) {
        /* Remove the session */
        if (qctx->qat_ctx) {
            if ((sts =
                 cpaCySymRemoveSession(qat_instance_handles[qctx->inst_num],
                                       qctx->qat_ctx))
                != CPA_STATUS_SUCCESS) {
                WARN("cpaCySymRemoveSession FAILED, sts = %d.!\n", sts);
                ret_val = 0;
                /* Lets not return yet and instead make a best effort to
                 * cleanup the rest to avoid memory leaks
                 */
            }

            /* Cleanup the memory */
            QAT_MEM_FREE_NONZERO_BUFF(qctx->qat_ctx, qctx->qat_svm);
            QAT_MEM_FREE_NONZERO_BUFF(qctx->srcBufferList.pPrivateMetaData,
                                      qctx->qat_svm);
            QAT_MEM_FREE_NONZERO_BUFF(qctx->dstBufferList.pPrivateMetaData,
                                      qctx->qat_svm);
            QAT_MEM_FREE_BUFF(qctx->cipher_key, qctx->qat_svm);
            QAT_MEM_FREE_NONZERO_BUFF(qctx->aad, qctx->qat_svm);
            QAT_MEM_FREE_NONZERO_BUFF(qctx->OpData.pAdditionalAuthData,
                                      qctx->qat_svm);
            QAT_MEM_FREE_NONZERO_BUFF(qctx->OpData.pIv, qctx->qat_svm);
            qctx->qat_ctx = NULL;
            qctx->srcBufferList.pPrivateMetaData = NULL;
            qctx->dstBufferList.pPrivateMetaData = NULL;
            qctx->OpData.pAdditionalAuthData = NULL;
            qctx->OpData.pIv = NULL;
            qctx->cipher_key = NULL;
            qctx->aad = NULL;
        }
        session_data->cipherSetupData.pCipherKey = NULL;
        OPENSSL_clear_free(session_data, sizeof(CpaCySymSessionSetupData));
    }
    qctx->is_session_init = 0;
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  ifndef QAT_OPENSSL_PROVIDER
    qctx->packet_size = 0;
    if (qctx->sw_ctx_cipher_data) {
        OPENSSL_free(qctx->sw_ctx_cipher_data);
        qctx->sw_ctx_cipher_data = NULL;
    }
#  endif
# endif
# ifdef QAT_OPENSSL_PROVIDER
    if (qctx->sw_ctx) {
        OPENSSL_free(qctx->sw_ctx);
        qctx->sw_ctx = NULL;
    }
# endif

    return ret_val;
}

/******************************************************************************
 *  * function:
 *
 * static void qat_ccm_cb(void *pCallbackTag, CpaStatus status,
 *                        const CpaCySymOp operationType,
 *                        void *pOpData, CpaBufferList *pDstBuffer,
 *                        CpaBoolean verifyResult)
 *
 * @param pCallbackTag  [IN] -  Opaque value provided by user while making
 *                              individual function call. Cast to op_done_pipe_t.
 * @param status        [IN] -  Status of the operation.
 * @param operationType [IN] -  Identifies the operation type requested.
 * @param pOpData       [IN] -  Pointer to structure with input parameters.
 * @param pDstBuffer    [IN] -  Destination buffer to hold the data output.
 * @param verifyResult  [IN] -  Used to verify digest result.
 *
 * description:
 Callback to indicate the completion of crypto operation
 ******************************************************************************/
static void qat_ccm_cb(void *pCallbackTag, CpaStatus status,
                       const CpaCySymOp operationType,
                       void *pOpData, CpaBufferList * pDstBuffer,
                       CpaBoolean verifyResult)
{
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_cipher_pipeline_requests_in_flight);
    }
    DEBUG("status is = %d  | verifyResult is  = %d | tag function called %p \n",
          status, verifyResult, (struct COMPLETION_STRUCT *)pCallbackTag);
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, verifyResult);
}

/******************************************************************************
* function:
*         qat_aes_ccm_session_init(EVP_CIPHER_CTX *ctx)
*
* @param ctx [IN] - pointer to context
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function synchronises the initialisation of the QAT session and
*  pre-allocates the necessary buffers for the session.
******************************************************************************/
# ifdef QAT_OPENSSL_PROVIDER
static int qat_aes_ccm_session_init(void *ctx)
# else
static int qat_aes_ccm_session_init(EVP_CIPHER_CTX *ctx)
# endif
{
# ifdef QAT_OPENSSL_PROVIDER
    QAT_PROV_CCM_CTX *qctx = NULL;
# else
    qat_ccm_ctx *qctx = NULL;
# endif
    CpaCySymSessionSetupData *sessionSetupData = NULL;
    Cpa32U sessionCtxSize = 0;
    CpaCySymSessionCtx pSessionCtx = NULL;
    int numBuffers = 1, enc = 0;

    DEBUG("- Entering\n");

    if (NULL == ctx) {
        WARN("parameter ctx is NULL\n");
        QATerr(QAT_F_QAT_AES_CCM_SESSION_INIT, QAT_R_CTX_NULL);
        return 0;
    }
# ifdef QAT_OPENSSL_PROVIDER
    qctx = (QAT_PROV_CCM_CTX *) ctx;
    enc = QAT_CCM_GET_ENC(qctx);;
# else
    qctx = QAT_CCM_GET_CTX(ctx);
    enc = EVP_CIPHER_CTX_encrypting(ctx);
# endif

    if (NULL == qctx) {
        WARN("qctx is NULL\n");
        QATerr(QAT_F_QAT_AES_CCM_SESSION_INIT, QAT_R_QCTX_NULL);
        return 0;
    }

    /* All parameters have not been set yet or we have already been
     * initialised. */
    if ((1 != qctx->init_params_set) || (1 == qctx->is_session_init)) {
        WARN("Parameters not set or session already initialised\n");
        goto err;
    }

    sessionSetupData = qctx->session_data;
    if (NULL == sessionSetupData) {
        WARN("sessionSetupData is NULL\n");
        QATerr(QAT_F_QAT_AES_CCM_SESSION_INIT, QAT_R_SSD_NULL);
        goto err;
    }

    if ((qctx->inst_num = get_instance(QAT_INSTANCE_SYM, QAT_INSTANCE_ANY))
        == QAT_INVALID_INSTANCE) {
        WARN("Failed to get QAT Instance Handle\n");
        QATerr(QAT_F_QAT_AES_CCM_SESSION_INIT, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Update digestResultLenInBytes with qctx->tag_len if both lengths
       are mismatch for decryption */
    if (!enc) {
        DEBUG("digestResultLenInBytes = %d, tag len = %d\n",
              sessionSetupData->hashSetupData.digestResultLenInBytes,
              (int)qctx->M);
        if (!(qctx->tag_len < 0)
            && sessionSetupData->hashSetupData.digestResultLenInBytes !=
            qctx->M) {
            sessionSetupData->hashSetupData.digestResultLenInBytes = qctx->M;
            DEBUG("Taglen updated\n");
        }
    }

    if (cpaCySymSessionCtxGetSize(qat_instance_handles[qctx->inst_num],
                                  sessionSetupData,
                                  &sessionCtxSize) != CPA_STATUS_SUCCESS) {
        WARN("cpaCySymSessionCtxGetSize failed.\n");
        QATerr(QAT_F_QAT_AES_CCM_SESSION_INIT, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    pSessionCtx =
        (CpaCySymSessionCtx) qat_mem_alloc(sessionCtxSize, qctx->qat_svm,
                                           __FILE__, __LINE__);
    if (NULL == pSessionCtx) {
        WARN("pSessionCtx malloc failed\n");
        QATerr(QAT_F_QAT_AES_CCM_SESSION_INIT, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    DUMP_SESSION_SETUP_DATA(sessionSetupData);
    if (cpaCySymInitSession(qat_instance_handles[qctx->inst_num],
                            qat_ccm_cb,
                            sessionSetupData,
                            pSessionCtx) != CPA_STATUS_SUCCESS) {
        WARN("cpaCySymInitSession failed.\n");
        QATerr(QAT_F_QAT_AES_CCM_SESSION_INIT, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    qctx->qat_ctx = pSessionCtx;

    /* Setup meta data for buffer lists */
    if (cpaCyBufferListGetMetaSize(qat_instance_handles[qctx->inst_num],
                                   numBuffers, &(qctx->meta_size))
        != CPA_STATUS_SUCCESS) {
        WARN("cpaCyBufferListGetBufferSize failed.\n");
        QATerr(QAT_F_QAT_AES_CCM_SESSION_INIT, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    qctx->srcBufferList.numBuffers = numBuffers;
    qctx->srcBufferList.pBuffers = &qctx->srcFlatBuffer;
    qctx->srcBufferList.pUserData = NULL;

    qctx->dstBufferList.numBuffers = numBuffers;
    qctx->dstBufferList.pBuffers = &qctx->dstFlatBuffer;
    qctx->dstBufferList.pUserData = NULL;

    if (qctx->meta_size) {
        qctx->srcBufferList.pPrivateMetaData =
            qat_mem_alloc(qctx->meta_size, qctx->qat_svm, __FILE__, __LINE__);
        if (NULL == qctx->srcBufferList.pPrivateMetaData) {
            WARN("srcBufferList.pPrivateMetaData is NULL.\n");
            QATerr(QAT_F_QAT_AES_CCM_SESSION_INIT, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        qctx->dstBufferList.pPrivateMetaData =
            qat_mem_alloc(qctx->meta_size, qctx->qat_svm, __FILE__, __LINE__);
        if (NULL == qctx->dstBufferList.pPrivateMetaData) {
            WARN("dstBufferList.pPrivateMetaData is NULL.\n");
            QATerr(QAT_F_QAT_AES_CCM_SESSION_INIT, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        qctx->srcBufferList.pPrivateMetaData = NULL;
        qctx->dstBufferList.pPrivateMetaData = NULL;
    }

    /* Create the OpData structure to remove this processing from the data
     * path */
    qctx->OpData.sessionCtx = qctx->qat_ctx;
    qctx->OpData.packetType = CPA_CY_SYM_PACKET_TYPE_FULL;

    /* Set the IV */
    if (NULL == qctx->OpData.pIv) {
        qctx->OpData.pIv =
            qat_mem_alloc(QAT_CCM_IV_MAX_LEN, qctx->qat_svm,
                          __FILE__, __LINE__);
        if (NULL == qctx->OpData.pIv) {
            WARN("qctx->OpData.pIv is NULL.\n");
            QATerr(QAT_F_QAT_AES_CCM_SESSION_INIT, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        memcpy(&qctx->OpData.pIv[QAT_CCM_IV_WRITE_BUFFER], qctx->next_iv,
               qctx->iv_len);
    }
    /* Set the AAD */
    if (NULL == qctx->OpData.pAdditionalAuthData) {
        int aad_buffer_len = qctx->packet_size;
        if (qctx->tls_aad_len < 0) {
            DEBUG("Allocating memory for AAD in TLS sync\n");
            /* For QAT the length of the buffer for AAD must be multiple
             * of block size */
            if (aad_buffer_len % AES_BLOCK_SIZE) {
                aad_buffer_len +=
                    AES_BLOCK_SIZE - (aad_buffer_len % AES_BLOCK_SIZE);
                DEBUG("Adjusting AAD buffer length = %d\n", aad_buffer_len);
            }
        }

        qctx->OpData.pAdditionalAuthData =
            qat_mem_alloc(aad_buffer_len + QAT_CCM_IV_MAX_LEN, qctx->qat_svm,
                          __FILE__, __LINE__);
        if (NULL == qctx->OpData.pAdditionalAuthData) {
            WARN("qctx->OpData.pAdditionalAuthData is NULL.\n");
            QATerr(QAT_F_QAT_AES_CCM_SESSION_INIT, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (qctx->aad) {
            memcpy(&qctx->OpData.pAdditionalAuthData[QAT_CCM_AAD_WRITE_BUFFER],
                   qctx->aad,
                   qctx->session_data->hashSetupData.
                   authModeSetupData.aadLenInBytes);
        }
        memcpy(&qctx->OpData.pAdditionalAuthData[QAT_CCM_IV_WRITE_BUFFER],
               qctx->next_iv, qctx->iv_len);
    }
    DUMPL("qctx->OpData.pAdditionalAuthData",
          &qctx->OpData.pAdditionalAuthData[QAT_CCM_AAD_WRITE_BUFFER],
          qctx->session_data->hashSetupData.authModeSetupData.aadLenInBytes);

    /* All the data in the buffer must be encrypted */
    qctx->OpData.cryptoStartSrcOffsetInBytes = 0;

    /* Following parameters are ignored in CCM */
    qctx->OpData.messageLenToHashInBytes = 0;
    qctx->OpData.hashStartSrcOffsetInBytes = 0;
    qctx->OpData.pDigestResult = NULL;
    qctx->is_session_init = 1;
    return 1;
 err:
    QAT_MEM_FREE_NONZERO_BUFF(qctx->srcBufferList.pPrivateMetaData,
                              qctx->qat_svm);
    QAT_MEM_FREE_NONZERO_BUFF(qctx->dstBufferList.pPrivateMetaData,
                              qctx->qat_svm);
    QAT_MEM_FREE_NONZERO_BUFF(qctx->OpData.pIv, qctx->qat_svm);
    QAT_MEM_FREE_NONZERO_BUFF(pSessionCtx, qctx->qat_svm);
    qctx->srcBufferList.pPrivateMetaData = NULL;
    qctx->dstBufferList.pPrivateMetaData = NULL;
    qctx->OpData.pIv = NULL;
    pSessionCtx = NULL;
    qctx->qat_ctx = NULL;

    return 0;
}

/******************************************************************************
* function:
*    qat_aes_ccm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
*                           const unsigned char *in, size_t len)
*
* @param ctx [IN]  - pointer to existing context
* @param out     [OUT] - output buffer for transform result
* @param in      [IN]  - input buffer
* @param len     [IN]  - length of input buffer
*
* @retval 0      function failed
* @retval 1      function succeeded
*
* description:
*    This function performs the cryptographic transform according to the
*  parameters setup during initialisation.
*
*  This is the function used in the TLS case.
*
******************************************************************************/
# ifdef QAT_OPENSSL_PROVIDER
int qat_aes_ccm_tls_cipher(void *ctx, unsigned char *out,
                           size_t *padlen, size_t outsize,
                           const unsigned char *in, size_t len)
# else
int qat_aes_ccm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t len)
# endif
{
# ifdef QAT_OPENSSL_PROVIDER
    QAT_PROV_CCM_CTX *qctx = (QAT_PROV_CCM_CTX *) ctx;
#  ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    QAT_EVP_CIPHER sw_aes_ccm_cipher;
#  endif
# else
    qat_ccm_ctx *qctx = NULL;
# endif
    CpaStatus sts = 0;
    op_done_t op_done;
    int ret_val = -1;
    int job_ret = 0;
    int enc = 0;
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    int nid = 0;
# endif
    unsigned int message_len = 0;
    unsigned int buffer_len = 0;
    thread_local_variables_t *tlv = NULL;

    CRYPTO_QAT_LOG("CIPHER - %s\n", __func__);

    if (NULL == ctx) {
        WARN("ctx is NULL\n");
        QATerr(QAT_F_QAT_AES_CCM_TLS_CIPHER, QAT_R_CTX_NULL);
        return -1;
    }
# ifndef QAT_OPENSSL_PROVIDER
    qctx = QAT_CCM_GET_CTX(ctx);
# endif
    if (NULL == qctx) {
        WARN("qctx is NULL\n");
        QATerr(QAT_F_QAT_AES_CCM_TLS_CIPHER, QAT_R_QCTX_NULL);
        return -1;
    }

    /* Encrypt/decrypt must be performed in place */
    if (NULL == in ||
        out != in || len < (EVP_CCM_TLS_EXPLICIT_IV_LEN + qctx->M)) {
        WARN("Input parameters are not valid.\n");
        QATerr(QAT_F_QAT_AES_CCM_TLS_CIPHER, QAT_R_INVALID_LEN);
        return -1;
    }
# ifdef QAT_OPENSSL_PROVIDER
    enc = QAT_CCM_GET_ENC(qctx);
# else
    enc = EVP_CIPHER_CTX_encrypting(ctx);
# endif

# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  ifdef QAT_OPENSSL_PROVIDER
    nid = qctx->nid;
#  else
    nid = EVP_CIPHER_CTX_nid(ctx);
#  endif
# endif

    DEBUG("enc = %d - ctx = %p, out = %p, in = %p, len = %zu\n",
          enc, (void *)ctx, (void *)out, (void *)in, len);

# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    qctx->packet_size = len;
    if ((len - (EVP_CCM_TLS_EXPLICIT_IV_LEN + qctx->M)) <=
        qat_pkt_threshold_table_get_threshold(nid)) {
        DEBUG("Using OpenSSL SW for Packetsize %zu\n", len -
              (EVP_CCM_TLS_EXPLICIT_IV_LEN + qctx->M));
#  ifdef QAT_OPENSSL_PROVIDER
        sw_aes_ccm_cipher = get_default_cipher_aes_ccm(nid);
        if (sw_aes_ccm_cipher.cupdate == NULL)
            goto err;

        ret_val =
            sw_aes_ccm_cipher.cupdate(qctx->sw_ctx, out, padlen, outsize, in,
                                      len);

        if (!ret_val)
            goto err;

        return ret_val;
#  else
        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
        ret_val = EVP_CIPHER_meth_get_do_cipher(GET_SW_AES_CCM_CIPHER(ctx))
            (ctx, out, in, len);
        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
        goto err;
#  endif
    }
# endif
    /* The key has been set in the init function: no need to check it here */

    /* Initialize the session if not done before */
    if (0 == qctx->is_session_init) {
# ifdef QAT_OPENSSL_PROVIDER
        if (0 == qat_aes_ccm_session_init(qctx)) {
# else
        if (0 == qat_aes_ccm_session_init(ctx)) {
# endif
            WARN("Unable to initialise Cipher context.\n");
            goto err;
        }
    } else {
        memcpy(&qctx->OpData.pAdditionalAuthData[QAT_CCM_AAD_WRITE_BUFFER],
               qctx->aad, qctx->tls_aad_len);
    }

    /* Encryption: generate explicit IV and write to start of buffer.
     * Decryption: read the explicit IV from start of buffer
     */
    if (enc) {
        memcpy(&qctx->OpData.pIv[QAT_CCM_IV_WRITE_BUFFER], qctx->next_iv,
               qctx->iv_len);
        /* Copy the explicit IV to the output buffer */
        memcpy(out, qctx->next_iv + EVP_CCM_TLS_FIXED_IV_LEN,
               EVP_CCM_TLS_EXPLICIT_IV_LEN);
        qctx->iv_set = 1;
    } else {
        /* Retrieve the explicit IV from the message buffer */
        memcpy(qctx->next_iv + EVP_CCM_TLS_FIXED_IV_LEN, in,
               EVP_CCM_TLS_EXPLICIT_IV_LEN);

        /* Set the IV that will be used in the current operation */
        memcpy(&qctx->OpData.pIv[QAT_CCM_IV_WRITE_BUFFER], qctx->next_iv,
               qctx->iv_len);
        qctx->iv_set = 1;
    }
    DUMPL("Post ctrl IV: ", &qctx->OpData.pIv[QAT_CCM_IV_WRITE_BUFFER],
          qctx->iv_len);
    DUMPL("Post ctrl next IV: ", qctx->next_iv, qctx->iv_len);

    DUMPL("qctx->OpData.pAdditionalAuthData",
          &qctx->OpData.pAdditionalAuthData[QAT_CCM_AAD_WRITE_BUFFER],
          qctx->session_data->hashSetupData.authModeSetupData.aadLenInBytes);

    /* Set the generated IV to OpData */
    if (qctx->iv_set) {
        memcpy(&qctx->OpData.pAdditionalAuthData[QAT_CCM_IV_WRITE_BUFFER],
               &qctx->OpData.pIv[QAT_CCM_IV_WRITE_BUFFER], qctx->iv_len);
        qctx->OpData.ivLenInBytes = QAT_AES_CCM_OP_VALUE - qctx->L;
    }

    /* If key or IV not set, throw error here and return. */
    if (!qctx->key_set || !qctx->iv_set) {
        WARN("Cipher key or IV not set.\n");
        QATerr(QAT_F_QAT_AES_CCM_TLS_CIPHER, QAT_R_KEY_IV_NOT_SET);
        goto err;
    }

    /* Include the explicit part of the IV at the beginning of the output  */
    in += EVP_CCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_CCM_TLS_EXPLICIT_IV_LEN;

    /* This is the length of the message that must be encrypted */
    message_len = len - (EVP_CCM_TLS_EXPLICIT_IV_LEN + qctx->M);

    /* The buffer must have enough memory to save also the TAG */
    buffer_len = message_len + qctx->M;

    /* Build request/response buffers */
    /* Allocate the memory of the FlatBuffer and copy the payload */
    if (!qctx->qat_svm)
        qctx->srcFlatBuffer.pData =
            qaeCryptoMemAlloc(buffer_len, __FILE__, __LINE__);
    else
        qctx->srcFlatBuffer.pData = (Cpa8U *) in;
    if (NULL == qctx->srcFlatBuffer.pData) {
        WARN("src/dst buffer allocation.\n");
        goto err;
    }

    if (!qctx->qat_svm)
        qctx->dstFlatBuffer.pData = qctx->srcFlatBuffer.pData;
    else
        qctx->dstFlatBuffer.pData = (Cpa8U *) out;

    if (!enc) {
        /* Decryption: the tag is appended and must be copied to the buffer */
        if (!qctx->qat_svm)
            memcpy(qctx->srcFlatBuffer.pData, in, message_len + qctx->M);
        qctx->tag_len = qctx->M;
    } else {
        /* Encryption: copy only the payload */
        if (!qctx->qat_svm)
            memcpy(qctx->srcFlatBuffer.pData, in, message_len);
    }

    /* The operation is done in place in the buffers
     * The variables in and out remain separate */
    qctx->srcFlatBuffer.dataLenInBytes = buffer_len;
    qctx->srcBufferList.pUserData = NULL;
    qctx->dstFlatBuffer.dataLenInBytes = buffer_len;
    qctx->dstBufferList.pUserData = NULL;

    qctx->OpData.messageLenToCipherInBytes = message_len;

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        QATerr(QAT_F_QAT_AES_CCM_TLS_CIPHER, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failure to setup async event notifications\n");
            QATerr(QAT_F_QAT_AES_CCM_TLS_CIPHER, ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            goto err;
        }
    }

    CRYPTO_QAT_LOG("CIPHER - %s\n", __func__);
    DUMP_SYM_PERFORM_OP_GCM_CCM(qat_instance_handles[qctx->inst_num],
                                qctx->OpData, qctx->srcBufferList,
                                qctx->dstBufferList);

    sts = qat_sym_perform_op(qctx->inst_num,
                             &op_done,
                             &(qctx->OpData),
                             &(qctx->srcBufferList),
                             &(qctx->dstBufferList),
                             &(qctx->session_data->verifyDigest));
    if (sts != CPA_STATUS_SUCCESS) {
        if (!qctx->qat_svm) {
            qaeCryptoMemFreeNonZero(qctx->srcFlatBuffer.pData);
            qctx->srcFlatBuffer.pData = NULL;
            qctx->dstFlatBuffer.pData = NULL;
        }
        qat_cleanup_op_done(&op_done);
        WARN("cpaCySymPerformOp failed sts=%d.\n", sts);
        if (sts == CPA_STATUS_UNSUPPORTED) {
            QATerr(QAT_F_QAT_AES_CCM_TLS_CIPHER, QAT_R_ALGO_TYPE_UNSUPPORTED);
        } else {
            QATerr(QAT_F_QAT_AES_CCM_TLS_CIPHER, ERR_R_INTERNAL_ERROR);
        }
        goto err;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n", &hw_polling_thread_sem);
                QATerr(QAT_F_QAT_AES_CCM_TLS_CIPHER, ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                goto err;
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

# ifdef QAT_OPENSSL_PROVIDER
    if (enc) {
        *padlen = len;
        ret_val = 1;
        DEBUG("Encryption succeeded\n");
    } else if (CPA_TRUE == op_done.verifyResult) {
        *padlen = message_len;
        ret_val = 1;
        DEBUG("Decryption succeeded\n");
    } else {
        DEBUG("Decryption failed\n");
    }
# else
    if (enc) {
        ret_val = len;
        DEBUG("Encryption succeeded\n");
    } else if (CPA_TRUE == op_done.verifyResult) {
        ret_val = message_len;
        DEBUG("Decryption succeeded\n");
    } else {
        DEBUG("Decryption failed\n");
    }
# endif

    DUMP_SYM_PERFORM_OP_GCM_CCM_OUTPUT(qctx->dstBufferList);
    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

    qat_cleanup_op_done(&op_done);

    if (!qctx->qat_svm) {
        memcpy(out, qctx->dstFlatBuffer.pData, message_len + qctx->M);
        qaeCryptoMemFreeNonZero(qctx->srcFlatBuffer.pData);
        qctx->srcFlatBuffer.pData = NULL;
        qctx->dstFlatBuffer.pData = NULL;
    }
    DUMPL("Digest Result", out, message_len + qctx->M);

 err:
    /* Don't reuse the IV */
    qctx->iv_set = 0;
    DEBUG("Function result = %d\n", ret_val);
    return ret_val;
}

/******************************************************************************
* function:
*    qat_aes_ccm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
*                       size_t *padlen, const unsigned char *in,
*                       size_t len)
*
* @param ctx    [IN]  - pointer to existing context
* @param out        [OUT] - output buffer for transform result
* @param in         [IN]  - input buffer
* @param len        [IN]  - length of input buffer
*
* @retval -1      function failed
* @retval len     function succeeded
*
* description:
*    This function performs the cryptographic transform according to the
*  parameters setup during initialisation.
*
*  This is the implementation of the Update case: the AAD is added by calling
*  UpdateEncrypt() with out == NULL.
*  This is the case used in the speed test.
*
*  The flag EVP_CIPH_FLAG_CUSTOM_CIPHER is required to have the Update function
*  working correctly when out == NULL, that is when setting the AAD.
*  When this flag is enabled, the function must return -1 in case of failure and
*  the length of the output (value >= 0) for success.
*
*  QAT vs SW Engine
*  ================
*
*  In the Update use case, the behavior of the functions is different between
*  the QAT and the SW engine.
*
*  EVP Function     SW Engine                       QAT Engine
*  ----------------------------------------------------------------------------
*  Encrypt Update   Encrypt the payload             Encrypt the payload AND
*                                                   compute the tag
*
*  Encrypt Final    Compute the tag                 Does nothing
*
*  Decrypt Update   Decrypt the payload             Decrpyt the payload and
*                                                   verify the TAG. Return failure
*                                                   if the TAG is not correct
*
*  Decrypt Final    Verify the TAG and              Does nothing
*                   return failure if not correct
*
*  This doesn't impact the TLS case because Update and Final are considered
*  a single operation like in the QAT engine.
*
******************************************************************************/
# ifdef QAT_OPENSSL_PROVIDER
int qat_aes_ccm_cipher(void *ctx, unsigned char *out,
                       size_t *padlen, size_t outsize,
                       const unsigned char *in, size_t len)
# else
int qat_aes_ccm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       const unsigned char *in, size_t len)
# endif
{
# ifdef QAT_OPENSSL_PROVIDER
    QAT_PROV_CCM_CTX *qctx = (QAT_PROV_CCM_CTX *) ctx;
    const int RET_SUCCESS = 1;
#  ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    QAT_EVP_CIPHER sw_aes_ccm_cipher;
#  endif
# else
    qat_ccm_ctx *qctx = NULL;
    const int RET_SUCCESS = 0;
# endif
    CpaStatus sts = 0;
    op_done_t op_done;
    const int RET_FAIL = -1;
    int ret_val = RET_FAIL;
    int job_ret = 0;
    int enc = 0;
    size_t aad_len = 0;
    int aad_buffer_len = 0;
    unsigned buffer_len = 0;
    thread_local_variables_t *tlv = NULL;
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    int nid = 0;
#  ifndef QAT_OPENSSL_PROVIDER
    int retVal = 0;
#  endif
# endif

    CRYPTO_QAT_LOG("CIPHER - %s\n", __func__);

    if (NULL == ctx) {
        WARN("ctx is NULL\n");
        QATerr(QAT_F_QAT_AES_CCM_CIPHER, QAT_R_CTX_NULL);
        return RET_FAIL;
    }
# ifdef QAT_OPENSSL_PROVIDER
    enc = qctx->enc;
# else
    qctx = QAT_CCM_GET_CTX(ctx);
    enc = EVP_CIPHER_CTX_encrypting(ctx);
# endif

# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  ifdef QAT_OPENSSL_PROVIDER
    nid = qctx->nid;
#  else
    nid = EVP_CIPHER_CTX_nid(ctx);
#  endif
# endif

    if (NULL == qctx) {
        WARN("qctx is NULL\n");
        QATerr(QAT_F_QAT_AES_CCM_CIPHER, QAT_R_QCTX_NULL);
        return RET_FAIL;
    }
    DEBUG("enc = %d - ctx = %p, out = %p, in = %p, len = %zu\n",
          enc, (void *)ctx, (void *)out, (void *)in, len);

    /* Distinguish the Update and TLS case */
    if (qctx->tls_aad_len >= 0) {
# ifdef QAT_OPENSSL_PROVIDER
        return qat_aes_ccm_tls_cipher(ctx, out, padlen, outsize, in, len);
# else
        return qat_aes_ccm_tls_cipher(ctx, out, in, len);
# endif
    }

    /* If either key or IV not set, throw error here. */
    if (!qctx->key_set || !qctx->iv_set) {
        WARN("Cipher key or IV not set.\n");
        QATerr(QAT_F_QAT_AES_CCM_CIPHER, QAT_R_KEY_IV_NOT_SET);
        return RET_FAIL;
    }

    if ((in == NULL) && (out == NULL)) {
        if (qctx->OpData.pIv == NULL) {
            qctx->OpData.pIv =
                qat_mem_alloc(QAT_CCM_IV_MAX_LEN, qctx->qat_svm,
                              __FILE__, __LINE__);
            if (NULL == qctx->OpData.pIv) {
                WARN("Unable to allocate memory for qctx->OpData.pIv\n");
                return RET_FAIL;
            }
        }
        memcpy(&qctx->OpData.pIv[QAT_CCM_IV_WRITE_BUFFER], qctx->next_iv,
               qctx->iv_len);
        qctx->len_set = 1;
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  ifdef QAT_OPENSSL_PROVIDER
        sw_aes_ccm_cipher = get_default_cipher_aes_ccm(nid);
        if (sw_aes_ccm_cipher.cupdate == NULL)
            return RET_FAIL;

        if (!sw_aes_ccm_cipher.
            cupdate(qctx->sw_ctx, out, padlen, outsize, in, len))
            return RET_FAIL;
#  else
        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
        EVP_CIPHER_meth_get_do_cipher(GET_SW_AES_CCM_CIPHER(ctx)) (ctx, out, in,
                                                                   len);
        EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
#  endif
# endif
# ifdef QAT_OPENSSL_PROVIDER
        *padlen = len;
# endif
        return len;
    }

    /* This is called when doing Update */
    if (in) {
        if (out == NULL) {
            DEBUG("in != NULL && out == NULL -> Adding AAD\n");

            aad_len = len;

            /* Check if the length of the AAD has changed */
            if (qctx->session_data->hashSetupData.
                authModeSetupData.aadLenInBytes != aad_len) {
                /* Free the memory used for the previous AAD */
                if (qctx->OpData.pAdditionalAuthData) {
                    QAT_MEM_FREE_BUFF(qctx->OpData.pAdditionalAuthData,
                                      qctx->qat_svm);
                    qctx->OpData.pAdditionalAuthData = NULL;
                }
                /* For QAT the length of the buffer for AAD must be multiple of block size */
                aad_buffer_len = aad_len;
                if (aad_buffer_len % AES_BLOCK_SIZE) {
                    aad_buffer_len +=
                        AES_BLOCK_SIZE - (aad_buffer_len % AES_BLOCK_SIZE);
                    DEBUG("Adjusting AAD buffer length = %d\n", aad_buffer_len);
                }
                qctx->OpData.pAdditionalAuthData =
                    qat_mem_alloc(aad_buffer_len + QAT_CCM_IV_MAX_LEN,
                                  qctx->qat_svm, __FILE__, __LINE__);
                if (NULL == qctx->OpData.pAdditionalAuthData) {
                    WARN("Unable to allocate memory for AAD\n");
                    QATerr(QAT_F_QAT_AES_CCM_CIPHER, ERR_R_INTERNAL_ERROR);
                    return RET_FAIL;
                }

                /* Set the length of the AAD */
                qctx->session_data->hashSetupData.
                    authModeSetupData.aadLenInBytes = aad_len;
            }

            memcpy(&qctx->OpData.pAdditionalAuthData[QAT_CCM_AAD_WRITE_BUFFER],
                   in, aad_len);
            DUMPL("qctx->aad",
                  &qctx->OpData.pAdditionalAuthData[QAT_CCM_AAD_WRITE_BUFFER],
                  aad_len);
            /* The pAdditionalAuthData will be initialized firstly in
             * qat_aes_ccm_session_init(), but the AAD can be updated
             * for several times. So it is very important to update the
             * AAD pointer in qat OpData structure in time. */
            memcpy(&qctx->OpData.pAdditionalAuthData[QAT_CCM_IV_WRITE_BUFFER],
                   &qctx->OpData.pIv[QAT_CCM_IV_WRITE_BUFFER],
                   QAT_AES_CCM_OP_VALUE - qctx->L);
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  ifdef QAT_OPENSSL_PROVIDER
            sw_aes_ccm_cipher = get_default_cipher_aes_ccm(nid);
            if (sw_aes_ccm_cipher.cupdate == NULL)
                return RET_FAIL;

            if (!sw_aes_ccm_cipher.
                cupdate(qctx->sw_ctx, out, padlen, outsize, in, len))
                return RET_FAIL;
#  else
            EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
            EVP_CIPHER_meth_get_do_cipher(GET_SW_AES_CCM_CIPHER(ctx)) (ctx, out,
                                                                       in, len);
            EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
#  endif
# endif
# ifdef QAT_OPENSSL_PROVIDER
            *padlen = aad_len;
# endif
            return 1;
        } else {
            /* The key has been set in the init function: no need to check it */
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
            qctx->packet_size = len;
            if (len <= qat_pkt_threshold_table_get_threshold(nid)) {
                DEBUG("Using OpenSSL SW for Packetsize %zu\n", len);
#  ifdef QAT_OPENSSL_PROVIDER
                sw_aes_ccm_cipher = get_default_cipher_aes_ccm(nid);
                if (sw_aes_ccm_cipher.cupdate == NULL)
                    return 0;

                ret_val =
                    sw_aes_ccm_cipher.cupdate(qctx->sw_ctx, out, padlen,
                                              outsize, in, len);
                if (!ret_val)
                    return RET_FAIL;

                *padlen = len;
                return ret_val;
#  else
                EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
                retVal =
                    EVP_CIPHER_meth_get_do_cipher(GET_SW_AES_CCM_CIPHER(ctx))
                    (ctx, out, in, len);
                EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
                if (retVal)
                    return len;

                return retVal;
#  endif
            }
# endif
            if (0 == qctx->is_session_init) {
# ifdef QAT_OPENSSL_PROVIDER
                if (0 == qat_aes_ccm_session_init(qctx)) {
# else
                if (0 == qat_aes_ccm_session_init(ctx)) {
# endif
                    WARN("Unable to initialise Cipher context.\n");
                    return RET_FAIL;
                }
            }
            if (len == 0)
                buffer_len = EVP_CCM_TLS_TAG_LEN;
            else
                buffer_len = len + EVP_CCM_TLS_TAG_LEN;

            /* Build request/response buffers */
            /* Allocate the memory of the FlatBuffer and copy the payload */
            if (!qctx->qat_svm)
                qctx->srcFlatBuffer.pData =
                    qaeCryptoMemAlloc(buffer_len, __FILE__, __LINE__);
            else
                qctx->srcFlatBuffer.pData = (Cpa8U *) in;
            if (NULL == qctx->srcFlatBuffer.pData) {
                WARN("src/dst buffer allocation.\n");
                QATerr(QAT_F_QAT_AES_CCM_CIPHER, ERR_R_INTERNAL_ERROR);
                return RET_FAIL;
            }
            if (!qctx->qat_svm) {
                qctx->dstFlatBuffer.pData = qctx->srcFlatBuffer.pData;
                memcpy(qctx->srcFlatBuffer.pData, in, len);
            } else {
                qctx->dstFlatBuffer.pData = (Cpa8U *) out;
            }

            /* The operation is done in place in the buffers
             * The variables in and out remain separate */
            qctx->srcFlatBuffer.dataLenInBytes = buffer_len;
            qctx->srcBufferList.pUserData = NULL;
            qctx->dstFlatBuffer.dataLenInBytes = buffer_len;
            qctx->dstBufferList.pUserData = NULL;

            qctx->OpData.messageLenToCipherInBytes = len;
# ifdef QAT_OPENSSL_PROVIDER
            qctx->OpData.ivLenInBytes = QAT_AES_CCM_OP_VALUE - qctx->L;
            qctx->OpData.cryptoStartSrcOffsetInBytes = 0;
# endif

            /* Decryption: set the digest (tag) for verification
             * This is different from SW implementation. Here we have a single
             * function to decrypt AND verify
             */
            if (!enc) {
                /* Copy EVP_CCM_TLS_TAG_LEN bytes from tag buffer
                   as the maximum tag length can only be
                   EVP_CCM_TLS_TAG_LEN */
# ifdef QAT_OPENSSL_PROVIDER
                memcpy(qctx->dstFlatBuffer.pData + len, qctx->buf, qctx->M);
# else
                if (NULL == EVP_CIPHER_CTX_buf_noconst(ctx)) {
                    WARN("Tag not set\n");
                    if (!qctx->qat_svm) {
                        qaeCryptoMemFreeNonZero(qctx->srcFlatBuffer.pData);
                        qctx->srcFlatBuffer.pData = NULL;
                        qctx->dstFlatBuffer.pData = NULL;
                    }
                    return RET_FAIL;
                } else {
                    memcpy(qctx->dstFlatBuffer.pData + len,
                           EVP_CIPHER_CTX_buf_noconst(ctx), qctx->M);
                }
# endif
            }

            tlv = qat_check_create_local_variables();
            if (NULL == tlv) {
                WARN("could not create local variables\n");
                QATerr(QAT_F_QAT_AES_CCM_CIPHER, ERR_R_INTERNAL_ERROR);
                return RET_FAIL;
            }

            qat_init_op_done(&op_done);
            if (op_done.job != NULL) {
                if (qat_setup_async_event_notification(op_done.job) == 0) {
                    WARN("Failure to setup async event notifications\n");
                    QATerr(QAT_F_QAT_AES_CCM_CIPHER, ERR_R_INTERNAL_ERROR);
                    qat_cleanup_op_done(&op_done);
                    return RET_FAIL;
                }
            }

            DUMP_SYM_PERFORM_OP_GCM_CCM(qat_instance_handles[qctx->inst_num],
                                        qctx->OpData, qctx->srcBufferList,
                                        qctx->dstBufferList);
            DUMPL("AAD: ", qctx->OpData.pAdditionalAuthData,
                  qctx->session_data->hashSetupData.
                  authModeSetupData.aadLenInBytes);

            sts = qat_sym_perform_op(qctx->inst_num,
                                     &op_done,
                                     &(qctx->OpData),
                                     &(qctx->srcBufferList),
                                     &(qctx->dstBufferList),
                                     &(qctx->session_data->verifyDigest));
            if (sts != CPA_STATUS_SUCCESS) {
                if (!qctx->qat_svm) {
                    qaeCryptoMemFreeNonZero(qctx->srcFlatBuffer.pData);
                    qctx->srcFlatBuffer.pData = NULL;
                    qctx->dstFlatBuffer.pData = NULL;
                }
                qat_cleanup_op_done(&op_done);
                WARN("cpaCySymPerformOp failed sts=%d.\n", sts);
                if (sts == CPA_STATUS_UNSUPPORTED) {
                    QATerr(QAT_F_QAT_AES_CCM_CIPHER,
                           QAT_R_ALGO_TYPE_UNSUPPORTED);
                } else {
                    QATerr(QAT_F_QAT_AES_CCM_CIPHER, ERR_R_INTERNAL_ERROR);
                }
                return RET_FAIL;
            }

            QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            if (qat_use_signals()) {
                if (tlv->localOpsInFlight == 1) {
                    if (sem_post(&hw_polling_thread_sem) != 0) {
                        WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n", &hw_polling_thread_sem);
                        QATerr(QAT_F_QAT_AES_CCM_CIPHER, ERR_R_INTERNAL_ERROR);
                        QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                        return RET_FAIL;
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
                    if ((job_ret = qat_pause_job(op_done.job, 0)) == 0)
                        sched_yield();
                } else {
                    sched_yield();
                }
            } while (!op_done.flag ||
                     QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

            DUMP_SYM_PERFORM_OP_GCM_CCM_OUTPUT(qctx->dstBufferList);

            if (enc) {
                if (CPA_TRUE == op_done.verifyResult) {
                    ret_val = len;
                    DEBUG("Encryption succeeded\n");
                } else {
                    DEBUG("Encryption failed\n");
                }

            } else {
                /* qctx->tag_len < 0 condition is added to workaround
                   OpenSSL Speed tests as tag will not be set */
                if (CPA_TRUE == op_done.verifyResult || qctx->tag_len < 0) {
                    ret_val = len;
                    DEBUG("Decryption succeeded\n");
                } else {
                    DEBUG("Decryption failed\n");
                }
            }

            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            qat_cleanup_op_done(&op_done);

            if (enc) {
                /* After encryption, copy the TAG from the buffer to the ctx */
# ifdef QAT_OPENSSL_PROVIDER
                memcpy(qctx->buf, qctx->dstFlatBuffer.pData + len, qctx->M);
                DUMPL("TAG calculated by QAT", qctx->buf, qctx->M);
                qctx->tag_set = 1;
# endif
                memcpy(EVP_CIPHER_CTX_buf_noconst(ctx),
                       qctx->dstFlatBuffer.pData + len, qctx->M);
                DUMPL("TAG calculated by QAT", EVP_CIPHER_CTX_buf_noconst(ctx),
                      EVP_CCM_TLS_TAG_LEN);
                qctx->tag_len = qctx->M;
            }

            if (!qctx->qat_svm) {
                memcpy(out, qctx->dstFlatBuffer.pData, len);
                qaeCryptoMemFreeNonZero(qctx->srcFlatBuffer.pData);
                qctx->srcFlatBuffer.pData = NULL;
                qctx->dstFlatBuffer.pData = NULL;
            }
# ifdef QAT_OPENSSL_PROVIDER
            *padlen = len;
# endif
            return ret_val;
        }
    } else {
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
#  ifdef QAT_OPENSSL_PROVIDER
        if (len <= qat_pkt_threshold_table_get_threshold(nid)) {
            sw_aes_ccm_cipher = get_default_cipher_aes_ccm(nid);
            if (sw_aes_ccm_cipher.cfinal == NULL)
                return 0;
            ret_val =
                sw_aes_ccm_cipher.cfinal(qctx->sw_ctx, out, padlen, outsize);
            *padlen = len;
        }
#  endif
# endif
        if (!enc) {
# if OPENSSL_VERSION_NUMBER < 0x30200000
            if (qctx->tag_len < 0)
                return RET_FAIL;
# endif
            /* Don't reuse the IV */
            qctx->iv_set = 0;
            DEBUG("Decrypt Final()\n");
            /* The SW implem here compares the TAGs and returns -1 if they are different.
             * Now the TAGs are checked when decrypting the payload so Final always return success
             */
            return RET_SUCCESS;
        }

        DEBUG("Encrypt Final()\n");

        /* The SW implem here copy the TAG to ctx->buf so that it can be
         * retrieved using ctrl() with GET_TAG.
         * Now the TAG is appended and has already been copied to that location
         * hence we do nothing.
         */

        /* Don't reuse the IV */
        qctx->iv_set = 0;
        return RET_SUCCESS;
    }
}
#endif
