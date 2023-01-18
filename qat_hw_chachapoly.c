/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021-2023 Intel Corporation.
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
 * @file qat_hw_chachapoly.c
 *
 * This file provides an implementation of CHACHAPOLY operations for OpenSSL
 * engine
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
#include "openssl/async.h"
#include <openssl/evp.h>
#include "e_qat.h"
#include "qat_hw_callback.h"
#include "qat_hw_polling.h"
#include "qat_events.h"
#include "qat_utils.h"
#include "qat_hw_ciphers.h"
#include "qat_evp.h"
#include "qat_hw_chachapoly.h"

#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_USDM_MEM
# include "qat_hw_usdm_inf.h"
#endif

#ifdef QAT_HW_INTREE
# define ENABLE_QAT_HW_CHACHAPOLY
#endif

# define GET_SW_CHACHA_CTX EVP_chacha20_poly1305()

#ifdef ENABLE_QAT_HW_CHACHAPOLY
# ifdef QAT_OPENSSL_PROVIDER
static int qat_chacha20_poly1305_init_key_iv(qat_chachapoly_ctx *cp_ctx,
                                             const unsigned char *key,
                                             const unsigned char *iv);
static int qat_chacha20_poly1305_mac_keygen(qat_chachapoly_ctx *cp_ctx);
static void qat_chacha20_core(chacha_buf *output,
                              const unsigned int input[16]);
static void qat_chacha20_ctr32(unsigned char *out, const unsigned char *inp,
                               size_t len, const unsigned int key[8],
                               const unsigned int counter[4]);
# else
static int qat_chacha20_poly1305_init(EVP_CIPHER_CTX *ctx,
                                      const unsigned char *user_key,
                                      const unsigned char *iv, int enc);
static int qat_chacha20_poly1305_do_cipher(EVP_CIPHER_CTX * ctx,
                                           unsigned char *out,
                                           const unsigned char *in,
                                           size_t len);
static int qat_chacha20_poly1305_cleanup(EVP_CIPHER_CTX *ctx);
static int qat_chacha20_poly1305_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                      void *ptr);
static int qat_chacha20_poly1305_init_key_iv(qat_chachapoly_ctx *cp_ctx,
                                             const unsigned char *key,
                                             const unsigned char *iv);
static int qat_chacha20_poly1305_mac_keygen(qat_chachapoly_ctx *cp_ctx);
static void qat_chacha20_core(chacha_buf *output,
                              const unsigned int input[16]);
static void qat_chacha20_ctr32(unsigned char *out, const unsigned char *inp,
                               size_t len, const unsigned int key[8],
                               const unsigned int counter[4]);
# endif

/******************************************************************************
 * function:
 *         chachapoly_cipher_meth(int nid, int keylen)
 *
 * @param nid    [IN] - Cipher NID to be created
 * @param keylen [IN] - Key length of cipher
 * @retval            - EVP_CIPHER * to created cipher
 * @retval            - NULL if failure
 *
 * description:
 *   create a new EVP_CIPHER based on requested nid
 ******************************************************************************/
const EVP_CIPHER *chachapoly_cipher_meth(int nid, int keylen)
{
    EVP_CIPHER *c = NULL;
# ifndef QAT_OPENSSL_PROVIDER
    int res = 1;

    if (qat_hw_offload &&
        (qat_hw_algo_enable_mask & ALGO_ENABLE_MASK_CHACHA_POLY)) {
        /* block size is 1 and key size is 32 bytes. */
        if ((c = EVP_CIPHER_meth_new(nid, 1, keylen)) == NULL) {
            WARN("Failed to allocate cipher methods for nid %d\n", nid);
            return NULL;
        }

        /* IV size is 12 bytes for TLS protocol */
        res &= EVP_CIPHER_meth_set_iv_length(c, QAT_CHACHA20_POLY1305_MAX_IVLEN);
        res &= EVP_CIPHER_meth_set_flags(c, EVP_CIPH_FLAG_AEAD_CIPHER |
                                        EVP_CIPH_CUSTOM_IV |
                                        EVP_CIPH_ALWAYS_CALL_INIT |
                                        EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY |
                                        EVP_CIPH_FLAG_CUSTOM_CIPHER |
                                        EVP_CIPH_CUSTOM_IV_LENGTH);
        res &= EVP_CIPHER_meth_set_init(c, qat_chacha20_poly1305_init);
        res &= EVP_CIPHER_meth_set_do_cipher(c, qat_chacha20_poly1305_do_cipher);
        res &= EVP_CIPHER_meth_set_cleanup(c, qat_chacha20_poly1305_cleanup);
        res &= EVP_CIPHER_meth_set_impl_ctx_size(c, 0);
        res &= EVP_CIPHER_meth_set_set_asn1_params(c, NULL);
        res &= EVP_CIPHER_meth_set_get_asn1_params(c, NULL);
        res &= EVP_CIPHER_meth_set_ctrl(c, qat_chacha20_poly1305_ctrl);

        if (res == 0) {
            WARN("Failed to set cipher methods for nid %d\n", nid);
            EVP_CIPHER_meth_free(c);
            c = NULL;
        }

        qat_hw_chacha_poly_offload = 1;
        DEBUG("QAT HW CHACHA POLY registration succeeded\n");
        return c;
    } else {
        qat_hw_chacha_poly_offload = 0;
        DEBUG("QAT HW CHACHA POLY is disabled, using OpenSSL SW\n");
        return EVP_chacha20_poly1305();
    }
# else
    return c;
# endif
}

/******************************************************************************
 * function:
 *         qat_chachapoly_cb(void *callbackTag, CpaStatus status,
 *                           const CpaCySymOp operationType, void *pOpData,
 *                           CpaBufferList * pDstBuffer, CpaBoolean verifyResult)
 *

 * @param pCallbackTag  [IN] -  Opaque value provided by user while making
 *                              individual function call.
 * @param status        [IN] -  Status of the operation.
 * @param operationType [IN] -  Identifies the operation type requested.
 * @param pOpData       [IN] -  Pointer to structure with input parameters.
 * @param pDstBuffer    [IN] -  Destination buffer to hold the data output.
 * @param verifyResult  [IN] -  Used to verify digest result.
 *
 * description:
 *   Callback function used by chachapoly.
 ******************************************************************************/
static void qat_chachapoly_cb(void *callbackTag, CpaStatus status,
                              const CpaCySymOp operationType,
                              void *pOpData, CpaBufferList *pDstBuffer,
                              CpaBoolean verifyResult)
{
    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_cipher_pipeline_requests_in_flight);
    }
    qat_crypto_callbackFn(callbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, CPA_TRUE);
}

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

/******************************************************************************
 * function:
 *         qat_chacha20_core(chacha_buf *output, const unsigned int input[16])
 *
 * @param output    [OUT]  - output buffer to hold key bytes
 * @param input     [IN]   - input keystream
 *
 * description:
 *    chacha_core performs 20 rounds of ChaCha on the input words in
 *    "input" and writes the 64 output bytes to "output".
 ******************************************************************************/
static void qat_chacha20_core(chacha_buf *output, const unsigned int input[16])
{
    unsigned x[16];
    int i;

    memcpy(x, input, sizeof(x));

    for (i = 20; i > 0; i -= 2) {
        QUARTERROUND(0, 4, 8, 12);
        QUARTERROUND(1, 5, 9, 13);
        QUARTERROUND(2, 6, 10, 14);
        QUARTERROUND(3, 7, 11, 15);
        QUARTERROUND(0, 5, 10, 15);
        QUARTERROUND(1, 6, 11, 12);
        QUARTERROUND(2, 7, 8, 13);
        QUARTERROUND(3, 4, 9, 14);
    }

    for (i = 0; i < 16; ++i)
        output->u[i] = x[i] + input[i];
}

/******************************************************************************
 * function:
 *         qat_chacha20_ctr32(unsigned char *out, const unsigned char *inp,
 *                            size_t len, const unsigned int key[8],
 *                            const unsigned int counter[4])
 *
 * @param out    [OUT]    - output buffer to hold key bytes
 * @param inp     [IN]    - input keystream
 * @param len     [IN]    - length of input key buffer
 * @param key     [IN]    - chacha key collected into 8 64-bit elements
 * @param counter [IN]    - nonce and counter values concatenated into 4 32-bit elements
 *
 * description:
 *    ChaCha20_ctr32 encrypts "len" bytes from "inp" with the given key and
 *    nonce and writes the result to "out", which may be equal to "inp".
 ******************************************************************************/
static void qat_chacha20_ctr32(unsigned char *out, const unsigned char *inp,
                               size_t len, const unsigned int key[8],
                               const unsigned int counter[4])
{
    static const char sigma[16] = "expand 32-byte k";
    const char *constants;
    unsigned int input[16];
    chacha_buf buf;
    size_t todo, i;

    constants = sigma;
    input[0] = U8TO32_LITTLE(constants + 0);
    input[1] = U8TO32_LITTLE(constants + 4);
    input[2] = U8TO32_LITTLE(constants + 8);
    input[3] = U8TO32_LITTLE(constants + 12);

    input[4] = key[0];
    input[5] = key[1];
    input[6] = key[2];
    input[7] = key[3];
    input[8] = key[4];
    input[9] = key[5];
    input[10] = key[6];
    input[11] = key[7];

    input[12] = counter[0];
    input[13] = counter[1];
    input[14] = counter[2];
    input[15] = counter[3];

    while (len > 0) {
        todo = sizeof(buf);
        if (len < todo)
            todo = len;

        qat_chacha20_core(&buf, input);

        for (i = 0; i < todo; i++)
            out[i] = inp[i] ^ buf.c[i];
        out += todo;
        inp += todo;
        len -= todo;

        input[12]++;
    }
}

/******************************************************************************
 * function:
 *         qat_chacha20_poly1305_init_key_iv(qat_chachapoly_ctx *ctx,
 *                                           const unsigned char *key,
 *                                           const unsigned char *iv)
 *
 * @param ctx    [IN]  - pointer to existing cipher ctx
 * @param key    [IN]  - 256 bit cipher key
 * @param iv     [IN]  - 96 bit IV
 *
 * @retval 1      function succeeded
 * @retval 0      function failed
 *
 * description:
 *    Initialise cipher key and IV in order to generate Poly1305(mac) key.
 ******************************************************************************/
static int qat_chacha20_poly1305_init_key_iv(qat_chachapoly_ctx *cp_ctx,
                                             const unsigned char *key,
                                             const unsigned char *iv)
{
    int i;

    if (cp_ctx == NULL) {
        WARN("chachapoly cipher data is NULL.\n");
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_INIT_KEY_IV,
                QAT_R_CHACHAPOLY_CTX_NULL);
        return 0;
    }

    if (iv != NULL) {
        unsigned char temp[QAT_CHACHA_CTR_SIZE] = { 0 };

        if (cp_ctx->nonce_len <= QAT_CHACHA_CTR_SIZE)
            memcpy(temp + QAT_CHACHA_CTR_SIZE - cp_ctx->nonce_len, iv,
                   cp_ctx->nonce_len);

        for (i = 0; i < QAT_CHACHA_CTR_SIZE; i+=4)
            cp_ctx->counter[i/4] = CHACHA_U8TOU32(temp+i);

        cp_ctx->iv[0] = cp_ctx->counter[1];
        cp_ctx->iv[1] = cp_ctx->counter[2];
        cp_ctx->iv[2] = cp_ctx->counter[3];
    }
    if (key != NULL) {
        for (i = 0; i < QAT_CHACHA_KEY_SIZE; i+=4)
            cp_ctx->chacha_key[i/4] = CHACHA_U8TOU32(key+i);
    }
    return 1;
}

/******************************************************************************
 * function:
 *         qat_chacha20_poly1305_mac_keygen(qat_chachapoly_ctx *cp_ctx)
 *
 * @param ctx    [IN]  - pointer to existing cipher ctx
 *
 * @retval 1      function succeeded
 * @retval 0      function failed
 *
 * description:
 *    Generate One-Time Poly1305 key for the hash operation
 *    using cipher key and IV.
 ******************************************************************************/
static int qat_chacha20_poly1305_mac_keygen(qat_chachapoly_ctx *cp_ctx)
{
    const unsigned char in_buf[2 * QAT_CHACHA_BLK_SIZE] = { 0 };

    if (cp_ctx == NULL) {
        WARN("chachapoly cipher data is NULL.\n");
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_MAC_KEYGEN,
               QAT_R_CHACHAPOLY_CTX_NULL);
        return 0;
    }

    /* Initialise counter as 0. */
    cp_ctx->counter[0] = 0;
    /* qat_chacha20_ctr32 encrypts QAT_CHACHA_BLK_SIZE bytes from in_buf
     * with the given key and nonce and writes the result
     * to cp_ctx->mac_key */
    qat_chacha20_ctr32(cp_ctx->mac_key, in_buf, QAT_CHACHA_BLK_SIZE,
                       cp_ctx->chacha_key, cp_ctx->counter);
    cp_ctx->mac_key_set = 1;

    return 1;
}

/******************************************************************************
 * function:
 *         qat_chachapoly_session_data_init(qat_chachapoly_ctx *cp_ctx,
 *                                          const unsigned char *inkey,
 *                                          const unsigned char *iv,
 *                                          int enc)
 *
 * @param ctx    [IN]  - pointer to existing cipher ctx
 * @param inKey  [IN]  - cipher key
 * @param iv     [IN]  - initialisation vector
 * @param enc    [IN]  - 1 = encrypt, 0 = decrypt
 *
 * @retval 1      function succeeded
 * @retval 0      function failed
 *
 * description:
 *    This function is to create QAT specific session data.
 *    It is called from the function qat_chacha20_poly1305_init().
 ******************************************************************************/
static int qat_chachapoly_session_data_init(qat_chachapoly_ctx *cp_ctx,
                                            const unsigned char* key,
                                            const unsigned char* iv,
                                            int enc)
{
    if (cp_ctx == NULL) {
        WARN("chachapoly cipher data is NULL.\n");
        QATerr(QAT_F_QAT_CHACHAPOLY_SESSION_DATA_INIT,
               QAT_R_CHACHAPOLY_CTX_NULL);
        return 0;
    }

    if (cp_ctx->session_data == NULL) {
        cp_ctx->session_data = OPENSSL_zalloc(sizeof(CpaCySymSessionSetupData));
        if (cp_ctx->session_data == NULL) {
            WARN("Failed to allocate session setup data\n");
            QATerr(QAT_F_QAT_CHACHAPOLY_SESSION_DATA_INIT,
                    ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }

    if (cp_ctx->mac_key == NULL) {
        cp_ctx->mac_key = qaeCryptoMemAlloc(QAT_CHACHA_BLK_SIZE, __FILE__, __LINE__);
        if (cp_ctx->mac_key == NULL) {
            WARN("Failure in mac_key buffer allocation.\n");
            QATerr(QAT_F_QAT_CHACHAPOLY_SESSION_DATA_INIT,
                    ERR_R_MALLOC_FAILURE);
            return -1;
        }
    }

    if (key != NULL) {
        memcpy(cp_ctx->cipher_key, key, QAT_CHACHA_KEY_SIZE);
        cp_ctx->key_set = 1;
        DUMPL("key", key, QAT_CHACHA_KEY_SIZE);
    }
    if (iv != NULL) {
        memcpy(cp_ctx->nonce, iv, QAT_CHACHA20_POLY1305_MAX_IVLEN);
        cp_ctx->iv_set = 1;
        DUMPL("IV", iv, QAT_CHACHA20_POLY1305_MAX_IVLEN);
    }

    cp_ctx->session_data->sessionPriority = CPA_CY_PRIORITY_HIGH;
    cp_ctx->session_data->symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING;

    cp_ctx->session_data->cipherSetupData.cipherAlgorithm = CPA_CY_SYM_CIPHER_CHACHA;
    cp_ctx->session_data->cipherSetupData.cipherDirection = CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;
    cp_ctx->session_data->cipherSetupData.cipherKeyLenInBytes = QAT_CHACHA_KEY_SIZE;
    /* Cipher key set NULL here as it will be set later. */
    cp_ctx->session_data->cipherSetupData.pCipherKey = NULL;

    cp_ctx->session_data->hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_POLY;
    cp_ctx->session_data->hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
    cp_ctx->session_data->hashSetupData.digestResultLenInBytes = QAT_POLY1305_DIGEST_SIZE;
    cp_ctx->session_data->hashSetupData.authModeSetupData.authKey = NULL;
    cp_ctx->session_data->hashSetupData.authModeSetupData.authKeyLenInBytes = 0;
    cp_ctx->session_data->hashSetupData.authModeSetupData.aadLenInBytes = 0;

    /* ChachaPoly performs the chacha(cipher) operation first and then
     * the Poly MAC operation (hash) during encryption. */
    cp_ctx->session_data->algChainOrder = CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH;
    cp_ctx->session_data->digestIsAppended = CPA_FALSE;
    cp_ctx->session_data->verifyDigest = CPA_FALSE;
    if (!enc) {
        cp_ctx->session_data->cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;
        cp_ctx->session_data->algChainOrder = CPA_CY_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER;
    }

    /* Partial requests not supported for CHACHA-POLY in the driver. */
    cp_ctx->session_data->partialsNotRequired = CPA_TRUE;

    if (cp_ctx->opd == NULL) {
        cp_ctx->opd = OPENSSL_zalloc(sizeof(template_opData));
        if (cp_ctx->opd == NULL) {
            WARN("memory allocation failed for symopData struct.\n");
            QATerr(QAT_F_QAT_CHACHAPOLY_SESSION_DATA_INIT, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        /* Set cipher operation data template */
        memcpy(cp_ctx->opd, &template_opData, sizeof(template_opData));
    }

    /* Set cipher key and IV. */
    if (cp_ctx->key_set && cp_ctx->iv_set) {
        if (qat_chacha20_poly1305_init_key_iv(cp_ctx, cp_ctx->cipher_key, cp_ctx->nonce)) {
            /* Generate Poly1305 mac key */
            if (!qat_chacha20_poly1305_mac_keygen(cp_ctx)) {
                WARN("MAC keygen operation failed.\n");
                QATerr(QAT_F_QAT_CHACHAPOLY_SESSION_DATA_INIT,
                       ERR_R_INTERNAL_ERROR);
                return 0;
            }
            DEBUG("Poly1305 key generated\n");
        }
        cp_ctx->session_data->cipherSetupData.pCipherKey = cp_ctx->cipher_key;

        if (cp_ctx->opd->pIv == NULL) {
            cp_ctx->opd->pIv = qaeCryptoMemAlloc(QAT_CHACHA20_POLY1305_MAX_IVLEN,
                                                  __FILE__, __LINE__);
            if (cp_ctx->opd->pIv == NULL) {
                WARN("Malloc Failure for opd->pIv.\n");
                QATerr(QAT_F_QAT_CHACHAPOLY_SESSION_DATA_INIT, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        }
        memcpy(cp_ctx->opd->pIv, cp_ctx->nonce, QAT_CHACHA20_POLY1305_MAX_IVLEN);
        cp_ctx->opd->ivLenInBytes = QAT_CHACHA20_POLY1305_MAX_IVLEN;
    }
    /* Mark session context init as set. */
    cp_ctx->context_params_set = 1;
    DEBUG("Chachapoly context init set.\n");

    return 1;
}

/******************************************************************************
 * function:
 *         qat_chacha20_poly1305_init(EVP_CIPHER_CTX *ctx,
 *                                    const unsigned char *inkey,
 *                                    const unsigned char *iv,
 *                                    int enc)
 *
 * @param ctx    [IN]  - pointer to existing cipher ctx
 * @param inKey  [IN]  - cipher key
 * @param iv     [IN]  - initialisation vector
 * @param enc    [IN]  - 1 = encrypt, 0 = decrypt
 *
 * @retval 1      function succeeded
 * @retval 0      function failed
 *
 * description:
 *    This function initialises the cipher parameters for this EVP context.
 *    This function can and will be **called multiple times** with some args
 *    being NULL.
 *
 ******************************************************************************/
#ifdef QAT_OPENSSL_PROVIDER
int qat_chacha20_poly1305_init(QAT_PROV_CIPHER_CTX *ctx,
                               const unsigned char *user_key,
                               const unsigned char *iv, int enc)
#else
static int qat_chacha20_poly1305_init(EVP_CIPHER_CTX *ctx,
                                      const unsigned char *user_key,
                                      const unsigned char *iv, int enc)
#endif
{
    int ret = 1;

    if (unlikely(ctx == NULL)) {
        WARN("cipher context is NULL.\n");
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_INIT, QAT_R_CTX_NULL);
        return 0;
    }
#ifdef QAT_OPENSSL_PROVIDER
    qat_chachapoly_ctx *cp_ctx = ctx->qat_cpctx;
#else
    qat_chachapoly_ctx *cp_ctx = qat_chachapoly_data(ctx);
#endif

    if (cp_ctx == NULL) {
        WARN("chachapoly cipher data is NULL.\n");
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_INIT, QAT_R_CHACHAPOLY_CTX_NULL);
        return 0;
    }

#ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
# ifndef QAT_OPENSSL_PROVIDER
    EVP_CIPHER_CTX_set_cipher_data(ctx, cp_ctx->sw_ctx_cipher_data);
    /* Run the software init function */
    ret = EVP_CIPHER_meth_get_init(GET_SW_CHACHA_CTX)(ctx, user_key, iv, enc);
    EVP_CIPHER_CTX_set_cipher_data(ctx, cp_ctx);
    if (ret != 1)
        goto init_err;
# endif
#endif

    /* Return 1 since it's not an error if key and IV not set. */
    if (!user_key && !iv) {
        DEBUG("key and IV not set.\n");
        return 1;
    }

    /* Initialize QAT session */
    ret = qat_chachapoly_session_data_init(cp_ctx, user_key, iv, enc);
    if (ret == 0) {
        WARN("qat_chachapoly_session_data_init failed.\n");
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_INIT, ERR_R_INTERNAL_ERROR);
        goto init_err;
    }

    DEBUG("Init complete. ctx %p, cp_ctx %p, Session data %p\n", ctx, cp_ctx,
           cp_ctx->session_data);
    return ret;

init_err:
    if (cp_ctx->opd->pIv)
        qaeCryptoMemFreeNonZero(cp_ctx->opd->pIv);
    if (cp_ctx->opd)
        OPENSSL_clear_free(cp_ctx->opd, sizeof(template_opData));
    if (cp_ctx->session_data != NULL) {
        OPENSSL_free(cp_ctx->session_data);
        cp_ctx->session_data = NULL;
    }
    return ret;
}

/******************************************************************************
 * function:
 *    qat_chachapoly_setup_op_params(qat_chachapoly_ctx *cp_ctx)
 *
 * @param ctx    [IN]  - pointer to existing ctx
 *
 * @retval 1      function succeeded
 * @retval 0      function failed
 *
 * description:
 *    This function initialises the crypto session and flatbuffer lists to be
 *    passed to the driver.
 *
 ******************************************************************************/
static int qat_chachapoly_setup_op_params(qat_chachapoly_ctx *cp_ctx)
{
    int numBuffers = 1; /* Set numBuffers to 1. (For cipher and hash operations.) */
    Cpa32U bufferMetaSize = 0;
    Cpa32U sctx_size = 0;
    CpaStatus status;

    if (cp_ctx == NULL) {
        WARN("chachapoly context cipher data is NULL.\n");
        QATerr(QAT_F_QAT_CHACHAPOLY_SETUP_OP_PARAMS, QAT_R_CHACHAPOLY_CTX_NULL);
        return 0;
    }

    cp_ctx->inst_num = get_next_inst_num(INSTANCE_TYPE_CRYPTO_SYM);
    if (cp_ctx->inst_num == QAT_INVALID_INSTANCE) {
        WARN("Failed to get a QAT instance.\n");
        QATerr(QAT_F_QAT_CHACHAPOLY_SETUP_OP_PARAMS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    status = cpaCySymSessionCtxGetSize(qat_instance_handles[cp_ctx->inst_num],
                                       cp_ctx->session_data, &sctx_size);
    if (status != CPA_STATUS_SUCCESS) {
        WARN("Failed to get SessionCtx size.\n");
        QATerr(QAT_F_QAT_CHACHAPOLY_SETUP_OP_PARAMS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    DEBUG("Size of session ctx = %d\n", sctx_size);
    cp_ctx->session_ctx = (CpaCySymSessionCtx) qaeCryptoMemAlloc(sctx_size,
                                                __FILE__, __LINE__);
    if (cp_ctx->session_ctx == NULL) {
        WARN("Memory alloc failed for session ctx\n");
        QATerr(QAT_F_QAT_CHACHAPOLY_SETUP_OP_PARAMS, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    DUMP_SESSION_SETUP_DATA(cp_ctx->session_data);
    /* Initialise Session data */
    status = cpaCySymInitSession(qat_instance_handles[cp_ctx->inst_num],
                                 qat_chachapoly_cb,
                                 cp_ctx->session_data, cp_ctx->session_ctx);
    if (status != CPA_STATUS_SUCCESS) {
        WARN("cpaCySymInitSession failed! Status = %d\n", status);
        if (((status == CPA_STATUS_RESTARTING) || (status == CPA_STATUS_FAIL))) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d\n",
                           cp_ctx->inst_num,
                           qat_instance_details[cp_ctx->inst_num].qat_instance_info.physInstId.packageId);
        }
        QATerr(QAT_F_QAT_CHACHAPOLY_SETUP_OP_PARAMS, ERR_R_INTERNAL_ERROR);
        qaeCryptoMemFreeNonZero(cp_ctx->session_ctx);
        return 0;
    }

    /* Get buffer metasize */
    status = cpaCyBufferListGetMetaSize(qat_instance_handles[cp_ctx->inst_num],
                                        numBuffers, &bufferMetaSize);
    if (status != CPA_STATUS_SUCCESS) {
        WARN("cpaCyBufferListGetMetaSize failed for the instance id %d\n",
             cp_ctx->inst_num);
        QATerr(QAT_F_QAT_CHACHAPOLY_SETUP_OP_PARAMS, ERR_R_INTERNAL_ERROR);
        qaeCryptoMemFreeNonZero(cp_ctx->session_ctx);
        return 0;
    }

    DEBUG("Buffer MetaSize : %d\n", bufferMetaSize);
    cp_ctx->pSrcBufferList.numBuffers = numBuffers;
    cp_ctx->pDstBufferList.numBuffers = numBuffers;

    if (bufferMetaSize) {
        cp_ctx->pSrcBufferList.pPrivateMetaData =
            qaeCryptoMemAlloc(bufferMetaSize, __FILE__, __LINE__);
        cp_ctx->pDstBufferList.pPrivateMetaData =
            qaeCryptoMemAlloc(bufferMetaSize, __FILE__, __LINE__);
        if (cp_ctx->pSrcBufferList.pPrivateMetaData == NULL ||
            cp_ctx->pDstBufferList.pPrivateMetaData == NULL) {
            WARN("QMEM alloc failed for PrivateData\n");
            QATerr(QAT_F_QAT_CHACHAPOLY_SETUP_OP_PARAMS, ERR_R_MALLOC_FAILURE);
            qaeCryptoMemFreeNonZero(cp_ctx->session_ctx);
            qaeCryptoMemFreeNonZero(cp_ctx->pSrcBufferList.pPrivateMetaData);
            qaeCryptoMemFreeNonZero(cp_ctx->pDstBufferList.pPrivateMetaData);
            return 0;
        }
    } else {
        cp_ctx->pSrcBufferList.pPrivateMetaData = NULL;
        cp_ctx->pDstBufferList.pPrivateMetaData = NULL;
    }

    cp_ctx->pDstBufferList.pUserData = NULL;
    cp_ctx->pSrcBufferList.pUserData = NULL;
    cp_ctx->pSrcBufferList.pBuffers = &cp_ctx->src_buffer;
    cp_ctx->pDstBufferList.pBuffers = &cp_ctx->dst_buffer;

    /* Mark session init as set.*/
    cp_ctx->session_init = 1;

    return 1;
}

/******************************************************************************
 * function:
 *    qat_chacha20_poly1305_tls_cipher(EVP_CIPHER_CTX *evp_ctx, unsigned char *out,
 *                                     const unsigned char *in, size_t len)
 *
 * @param evp_ctx [IN]  - pointer to existing context
 * @param out     [OUT] - output buffer for transform result
 * @param in      [IN]  - input buffer
 * @param len     [IN]  - length of input buffer
 *
 * @retval  0      failure
 * @retval  1      success
 *
 * description:
 *    This function performs the cryptographic transform according to the
 *  parameters setup during initialisation.
 *
 *  This is the function used in the TLS case.
 *
 ******************************************************************************/
#ifdef QAT_OPENSSL_PROVIDER
static int qat_chacha20_poly1305_tls_cipher(QAT_PROV_CIPHER_CTX * ctx, unsigned char *out,
                                     size_t *outl, const unsigned char *in, size_t len)
#else
static int qat_chacha20_poly1305_tls_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
                                            const unsigned char *in, size_t len)
#endif
{
    int outlen = 0;
    int job_ret = 0;
    int cipher_len = 0;
    int plen;
    int enc;
    CpaStatus status;
    op_done_t op_done;
    thread_local_variables_t *tlv = NULL;
    qat_chachapoly_ctx *cp_ctx = NULL;
#if !defined(QAT_OPENSSL_PROVIDER) && !defined(ENABLE_QAT_SMALL_PKT_OFFLOAD)
    int retVal = 0;
# endif

    if (unlikely(ctx == NULL)) {
        WARN("ctx parameter is NULL.\n");
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_TLS_CIPHER, QAT_R_CTX_NULL);
        return -1;
    }

#ifdef QAT_OPENSSL_PROVIDER
    cp_ctx = ctx->qat_cpctx;
#else
    cp_ctx = qat_chachapoly_data(ctx);
#endif

    if (cp_ctx == NULL) {
        WARN("chachapoly context cipher data is NULL.\n");
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_TLS_CIPHER,
               QAT_R_CHACHAPOLY_CTX_NULL);
        return -1;
    }

    plen = cp_ctx->tls_payload_length;

    if (len != plen + QAT_POLY1305_BLOCK_SIZE) {
        WARN("Invalid tls payload length\n");
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_TLS_CIPHER,
               QAT_R_INVALID_INPUT_LENGTH);
        return -1;
    }

    DEBUG("ctx %p, cp_ctx %p, len %zu plen %d enc: %d\n",
           ctx, cp_ctx, len, plen, enc);

#ifdef QAT_OPENSSL_PROVIDER
    enc = QAT_PROV_GET_ENC(ctx);
#else
    enc = EVP_CIPHER_CTX_encrypting(ctx);
#endif

#ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    cp_ctx->packet_size = len;
# ifdef QAT_OPENSSL_PROVIDER
    if ( (len - QAT_POLY1305_BLOCK_SIZE) <=
          qat_pkt_threshold_table_get_threshold(ctx->nid)) {
        int sw_final_len = 0;
        DEBUG("Using OpenSSL SW for Packetsize %zu\n", len);
        if (!EVP_CipherUpdate(ctx->sw_ctx, out, &outlen, in, len))
            goto cleanup;
        if (!EVP_CipherFinal_ex(ctx->sw_ctx, out + outlen, &sw_final_len))
            goto cleanup;
        outlen = len + sw_final_len;
        goto cleanup;
    }
# else
    if ( (len - QAT_POLY1305_BLOCK_SIZE) <=
        qat_pkt_threshold_table_get_threshold(EVP_CIPHER_CTX_nid(ctx))) {
        DEBUG("Using OpenSSL SW for Packetsize %zu\n", len);
        EVP_CIPHER_CTX_set_cipher_data(ctx, cp_ctx->sw_ctx_cipher_data);
        retVal = EVP_CIPHER_meth_get_do_cipher(GET_SW_CHACHA_CTX)
                 (ctx, out, in, len);
        EVP_CIPHER_CTX_set_cipher_data(ctx, cp_ctx);
        if (retVal)
            outlen = len;
        goto cleanup;
    }
# endif
#endif
    /* Set chachapoly opdata params and initialise session. */
    if (cp_ctx->context_params_set && !cp_ctx->session_init) {
        if (!qat_chachapoly_setup_op_params(cp_ctx)) {
            WARN("chachapoly operational params setup failed.\n");
            QATerr(QAT_F_QAT_CHACHA20_POLY1305_TLS_CIPHER,
                   ERR_R_INTERNAL_ERROR);
            goto tls_cipher_err;
        }
    }

    /* Actual message length is the input length minus the tag length. */
    cipher_len = len - QAT_POLY1305_DIGEST_SIZE;
    DEBUG("InputLen %zu, CipherLen %d\n", len, cipher_len);

    /* Allocate buffer for HASH and CIPHER operation. */
    cp_ctx->src_buffer.pData = qaeCryptoMemAlloc(len, __FILE__, __LINE__);
    if ((cp_ctx->src_buffer.pData) == NULL) {
        WARN("Failure in src buffer allocation.\n");
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_TLS_CIPHER, ERR_R_MALLOC_FAILURE);
        goto tls_cipher_err;
    }

    cp_ctx->dst_buffer.pData = cp_ctx->src_buffer.pData;
    /* Copy only the payload during encryption whereas copy the entire input
     * during decryption. */
    memcpy(cp_ctx->src_buffer.pData, in, cipher_len);

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
        WARN("could not create local variables\n");
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_TLS_CIPHER, ERR_R_INTERNAL_ERROR);
        goto tls_cipher_err;
    }

    qat_init_op_done(&op_done);
    if (op_done.job != NULL) {
        if (qat_setup_async_event_notification(op_done.job) == 0) {
            WARN("Failed to setup async event notification\n");
            QATerr(QAT_F_QAT_CHACHA20_POLY1305_TLS_CIPHER,
                   ERR_R_INTERNAL_ERROR);
            qat_cleanup_op_done(&op_done);
            goto tls_cipher_err;
        }
    }

    cp_ctx->src_buffer.dataLenInBytes = cipher_len;
    cp_ctx->pSrcBufferList.pUserData = NULL;
    cp_ctx->dst_buffer.dataLenInBytes = cipher_len;
    cp_ctx->pDstBufferList.pUserData = NULL;
    cp_ctx->opd->sessionCtx = cp_ctx->session_ctx;
    /* Set messageLenToCipherInBytes to the cipher buffer length. */
    cp_ctx->opd->messageLenToCipherInBytes = cipher_len;
    /* Set the offset where the tag need to be written in the destination buffer. */
    cp_ctx->opd->hashStartSrcOffsetInBytes = cipher_len;
    /* Set AAD */
    cp_ctx->opd->pAdditionalAuthData = cp_ctx->tls_aad;
    cp_ctx->opd->pDigestResult = cp_ctx->mac_key;
    DUMPL("pDigestResult", cp_ctx->opd->pDigestResult, QAT_CHACHA_KEY_SIZE);

    DUMPL("AAD Buffer", cp_ctx->opd->pAdditionalAuthData,
           cp_ctx->session_data->hashSetupData.authModeSetupData.aadLenInBytes);

    OPENSSL_cleanse(cp_ctx->opd->pIv, QAT_CHACHA20_POLY1305_MAX_IVLEN);
    memcpy(cp_ctx->opd->pIv, cp_ctx->derived_iv, QAT_CHACHA20_POLY1305_MAX_IVLEN);

    if (!is_instance_available(cp_ctx->inst_num)) {
        WARN("QAT instance %d not available.\n", cp_ctx->inst_num);
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_TLS_CIPHER, ERR_R_INTERNAL_ERROR);
        if (op_done.job != NULL)
            qat_clear_async_event_notification(op_done.job);
        qat_cleanup_op_done(&op_done);
        goto tls_cipher_err;
    }

    DUMP_CP_PERFORM_OP(qat_instance_handles[cp_ctx->inst_num], cp_ctx->opd,
                       cp_ctx->pSrcBufferList, cp_ctx->pDstBufferList);
    status = qat_sym_perform_op(cp_ctx->inst_num, &op_done, cp_ctx->opd,
                                &(cp_ctx->pSrcBufferList),
                                &(cp_ctx->pDstBufferList),
                                &(cp_ctx->session_data->verifyDigest));

    if (status != CPA_STATUS_SUCCESS) {
        if (((status == CPA_STATUS_RESTARTING) || (status == CPA_STATUS_FAIL))) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - %s\n",
                    cp_ctx->inst_num,
                    qat_instance_details[cp_ctx->inst_num].qat_instance_info.physInstId.packageId);
        }
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_TLS_CIPHER, ERR_R_INTERNAL_ERROR);
        if (op_done.job != NULL)
            qat_clear_async_event_notification(op_done.job);
        qat_cleanup_op_done(&op_done);
        goto tls_cipher_err;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (sem_post(&hw_polling_thread_sem) != 0) {
                WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n",
                      &hw_polling_thread_sem);
                QATerr(QAT_F_QAT_CHACHA20_POLY1305_TLS_CIPHER,
                       ERR_R_INTERNAL_ERROR);
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                goto tls_cipher_err;
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
    } while (!op_done.flag ||
            QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    DUMP_CP_PERFORM_OP_OUTPUT(&(cp_ctx->session_data->verifyDigest),
                              cp_ctx->pDstBufferList);

    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

    if (enc) {
        outlen = len;
        DEBUG("Encryption succeeded.\n");
    } else {
        if (op_done.verifyResult != CPA_TRUE) {
            WARN("Verification of result failed\n");
            QATerr(QAT_F_QAT_CHACHA20_POLY1305_TLS_CIPHER, ERR_R_INTERNAL_ERROR);
            if (op_done.status == CPA_STATUS_FAIL) {
                CRYPTO_QAT_LOG("Verification of result failed for qat inst_num %d device_id %d - %s\n",
                               inst_num,
                               qat_instance_details[cp_ctx->_inst_num].qat_instance_info.physInstId.packageId);
                qat_cleanup_op_done(&op_done);
                goto tls_cipher_err;
            }
        }
        outlen = cipher_len;
        DEBUG("Decryption succeeded.\n");
    }
    qat_cleanup_op_done(&op_done);
    /* Copy destination buffer into out buffer. */
    memcpy(out, cp_ctx->dst_buffer.pData, cipher_len);
    memcpy(out + cipher_len, cp_ctx->opd->pDigestResult, QAT_POLY1305_DIGEST_SIZE);

# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
cleanup:
# endif
tls_cipher_err:
    if (cp_ctx->src_buffer.pData) {
        qaeCryptoMemFreeNonZero(cp_ctx->src_buffer.pData);
        cp_ctx->src_buffer.pData = NULL;
        cp_ctx->dst_buffer.pData = NULL;
    }

# ifdef QAT_OPENSSL_PROVIDER
    *outl = outlen;
# endif
    return outlen;
}
/******************************************************************************
 * function:
 *    qat_chacha20_poly1305_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
 *                                    const unsigned char *in, size_t len)
 *
 * @param ctx    [IN]  - pointer to existing ctx
 * @param out   [OUT]  - output buffer for transform result
 * @param in     [IN]  - input buffer
 * @param len    [IN]  - length of input buffer
 *
 * @retval  0     failure
 * @retval  1     success
 *
 * description:
 *    This function performs the cryptographic transform according to the
 *  parameters setup during initialisation.
 *
 ******************************************************************************/
# ifdef QAT_OPENSSL_PROVIDER
int qat_chacha20_poly1305_do_cipher(QAT_PROV_CIPHER_CTX * ctx, unsigned char *out,
                                    size_t *outl, const unsigned char *in, size_t len)
# else
static int qat_chacha20_poly1305_do_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
                                           const unsigned char *in, size_t len)
# endif
{
    int outlen = 0;
    int job_ret = 0;
    int plen;
    int enc;
    CpaStatus status;
    op_done_t op_done;
    thread_local_variables_t *tlv = NULL;
    qat_chachapoly_ctx *cp_ctx = NULL;
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    int retVal = 0;
# endif

    if (unlikely(ctx == NULL)) {
        WARN("ctx parameter is NULL.\n");
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_DO_CIPHER, QAT_R_CTX_NULL);
        return -1;
    }
# ifdef QAT_OPENSSL_PROVIDER
    cp_ctx = ctx->qat_cpctx;
# else
    cp_ctx = qat_chachapoly_data(ctx);
# endif
    if (cp_ctx == NULL) {
        WARN("chachapoly context cipher data is NULL.\n");
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_DO_CIPHER, QAT_R_CHACHAPOLY_CTX_NULL);
        return -1;
    }

    plen = cp_ctx->tls_payload_length;

    DEBUG("in %p, out %p ctx %p, cp_ctx %p, len %zu, plen %d enc %d\n",
           in, out, ctx, cp_ctx, len, plen, enc);
# ifdef QAT_OPENSSL_PROVIDER
    enc = QAT_PROV_GET_ENC(ctx);
# else
    enc = EVP_CIPHER_CTX_encrypting(ctx);
# endif

    if (plen != NO_TLS_PAYLOAD_LENGTH && out != NULL) {
# ifdef QAT_OPENSSL_PROVIDER
        return qat_chacha20_poly1305_tls_cipher(ctx, out, outl, in, len);
# else
        return qat_chacha20_poly1305_tls_cipher(ctx, out, in, len);
# endif
    }

    /* Partial requests are not supported in the QAT driver
     * for CHACHA-POLY. */
    if (out != NULL && in == NULL && enc) {
        WARN("QAT Engine does not support partial requests.\n");
# if !defined(QAT_OPENSSL_PROVIDER) && !defined(ENABLE_QAT_SMALL_PKT_OFFLOAD)
        EVP_CIPHER_CTX_set_cipher_data(ctx, cp_ctx->sw_ctx_cipher_data);
        EVP_CIPHER_meth_get_do_cipher(GET_SW_CHACHA_CTX)
                 (ctx, out, in, len);
        EVP_CIPHER_CTX_set_cipher_data(ctx, cp_ctx);
# endif
# ifdef QAT_OPENSSL_PROVIDER
        *outl = len;
        return 1;
# else
        return 0;
# endif
    }

    if (in != NULL) {
        if (out == NULL) {

            /* Copy "in" buffer data into tls_aad when "out" buffer is NULL
             * as done in the software implementation. */
            if (cp_ctx->session_data->hashSetupData.authModeSetupData.aadLenInBytes != len) {
                if (cp_ctx->tls_aad == NULL)
                    cp_ctx->tls_aad = qaeCryptoMemAlloc(len, __FILE__, __LINE__);
                if (NULL == cp_ctx->tls_aad) {
                    WARN("Unable to allocate memory for TLS header\n");
                    QATerr(QAT_F_QAT_CHACHA20_POLY1305_DO_CIPHER,
                           ERR_R_MALLOC_FAILURE);
                    return -1;
                }
                cp_ctx->session_data->hashSetupData.authModeSetupData.aadLenInBytes = len;
            }
            memcpy(cp_ctx->tls_aad, in, len);
            DUMPL("AAD", cp_ctx->tls_aad, len);
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
            DEBUG("Using OpenSSL SW for Packetsize %zu\n", len);
#  ifdef QAT_OPENSSL_PROVIDER
            if (!EVP_CipherUpdate(ctx->sw_ctx, out, &outlen, in, len))
                goto cleanup;
            retVal = 1;
#  else
            EVP_CIPHER_CTX_set_cipher_data(ctx, cp_ctx->sw_ctx_cipher_data);
            EVP_CIPHER_meth_get_do_cipher(GET_SW_CHACHA_CTX)(ctx, out, in, len);
            EVP_CIPHER_CTX_set_cipher_data(ctx, cp_ctx);
#  endif
# endif

# ifdef QAT_OPENSSL_PROVIDER
            *outl = len;
# endif
            return 1;
        } else { /* EncryptUpdate/DecryptUpdate case */
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
            cp_ctx->packet_size = len;
#  ifndef QAT_OPENSSL_PROVIDER
            if (len <= qat_pkt_threshold_table_get_threshold(EVP_CIPHER_CTX_nid(ctx))) {
                DEBUG("Using OpenSSL SW for Packetsize %zu\n", len);
                EVP_CIPHER_CTX_set_cipher_data(ctx, cp_ctx->sw_ctx_cipher_data);
                retVal = EVP_CIPHER_meth_get_do_cipher(GET_SW_CHACHA_CTX) (ctx, out, in, len);
                EVP_CIPHER_CTX_set_cipher_data(ctx, cp_ctx);
                if (retVal)
                    outlen = len;
                goto cleanup;
            }
#  endif
# endif

            if (cp_ctx->context_params_set && !cp_ctx->session_init) {
                /* Set chachapoly opdata params and initialise session. */
                if (!qat_chachapoly_setup_op_params(cp_ctx)) {
                    WARN("chachapoly operational params setup failed.\n");
                    QATerr(QAT_F_QAT_CHACHA20_POLY1305_DO_CIPHER,
                           ERR_R_INTERNAL_ERROR);
                    goto do_cipher_err;
                }
            }

            /* Allocate buffer for HASH and Cipher operation. */
            cp_ctx->src_buffer.pData = qaeCryptoMemAlloc(len, __FILE__, __LINE__);
            if ((cp_ctx->src_buffer.pData) == NULL) {
                WARN("Unable to allocate memory for buffer for chacha cipher.\n");
                QATerr(QAT_F_QAT_CHACHA20_POLY1305_DO_CIPHER,
                       ERR_R_MALLOC_FAILURE);
                goto do_cipher_err;
            }

            /* In-Place operation */
            cp_ctx->dst_buffer.pData = cp_ctx->src_buffer.pData;
            /* Copy message into source buffer. */
            memcpy(cp_ctx->src_buffer.pData, in, len);

            tlv = qat_check_create_local_variables();
            if (NULL == tlv) {
                WARN("could not create local variables\n");
                QATerr(QAT_F_QAT_CHACHA20_POLY1305_DO_CIPHER,
                       ERR_R_INTERNAL_ERROR);
                goto do_cipher_err;
            }

            qat_init_op_done(&op_done);
            if (op_done.job != NULL) {
                if (qat_setup_async_event_notification(op_done.job) == 0) {
                    WARN("Failed to setup async event notification\n");
                    QATerr(QAT_F_QAT_CHACHA20_POLY1305_DO_CIPHER,
                           ERR_R_INTERNAL_ERROR);
                    qat_cleanup_op_done(&op_done);
                    goto do_cipher_err;
                }
            }
            cp_ctx->src_buffer.dataLenInBytes = len;
            cp_ctx->pSrcBufferList.pUserData = NULL;
            cp_ctx->dst_buffer.dataLenInBytes = len;
            cp_ctx->pDstBufferList.pUserData = NULL;

            cp_ctx->opd->sessionCtx = cp_ctx->session_ctx;
            /* Set messageLenToCipherInBytes to the cipher buffer length. */
            cp_ctx->opd->messageLenToCipherInBytes = len;
            /* Set the offset from where the tag needs to be written. */
            cp_ctx->opd->hashStartSrcOffsetInBytes = len;
            /* Set AAD. */
            cp_ctx->opd->pAdditionalAuthData = cp_ctx->tls_aad;
            /* Add Mackey into Digest */
            cp_ctx->opd->pDigestResult = cp_ctx->mac_key;
            DUMPL("pDigestResult", cp_ctx->opd->pDigestResult, QAT_CHACHA_KEY_SIZE);
            DUMPL("AAD", cp_ctx->opd->pAdditionalAuthData,
                   cp_ctx->session_data->hashSetupData.authModeSetupData.aadLenInBytes);

            if (!is_instance_available(cp_ctx->inst_num)) {
                WARN("QAT instance %d not available.\n", cp_ctx->inst_num);
                QATerr(QAT_F_QAT_CHACHA20_POLY1305_DO_CIPHER,
                       ERR_R_INTERNAL_ERROR);
                if (op_done.job != NULL) {
                    qat_clear_async_event_notification(op_done.job);
                }
                qat_cleanup_op_done(&op_done);
                goto do_cipher_err;
            }

            DUMP_CP_PERFORM_OP(qat_instance_handles[cp_ctx->inst_num],
                               cp_ctx->opd, cp_ctx->pSrcBufferList,
                               cp_ctx->pDstBufferList);
            status = qat_sym_perform_op(cp_ctx->inst_num, &op_done, cp_ctx->opd,
                    &(cp_ctx->pSrcBufferList),
                    &(cp_ctx->pDstBufferList),
                    &(cp_ctx->session_data->verifyDigest));

            if (status != CPA_STATUS_SUCCESS) {
                if (((status == CPA_STATUS_RESTARTING) || (status == CPA_STATUS_FAIL))) {
                    CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - %s\n",
                                    cp_ctx->inst_num,
                                    qat_instance_details[cp_ctx->inst_num].qat_instance_info.physInstId.packageId);
                }
                QATerr(QAT_F_QAT_CHACHA20_POLY1305_DO_CIPHER,
                       ERR_R_INTERNAL_ERROR);
                if (op_done.job != NULL)
                    qat_clear_async_event_notification(op_done.job);
                qat_cleanup_op_done(&op_done);
                goto do_cipher_err;
            }

            QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
            if (qat_use_signals()) {
                if (tlv->localOpsInFlight == 1) {
                    if (sem_post(&hw_polling_thread_sem) != 0) {
                        WARN("hw sem_post failed!, hw_polling_thread_sem address: %p.\n",
                              &hw_polling_thread_sem);
                        QATerr(QAT_F_QAT_CHACHA20_POLY1305_DO_CIPHER,
                               ERR_R_INTERNAL_ERROR);
                        QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                        goto do_cipher_err;
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
            } while (!op_done.flag ||
                    QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

            DUMP_CP_PERFORM_OP_OUTPUT(&(cp_ctx->session_data->verifyDigest),
                                      cp_ctx->pDstBufferList);

            QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

            if (enc) {
                DEBUG("Encryption succeeded\n");
                /* Set tag after the encryption operation. */
                memcpy(cp_ctx->tag, cp_ctx->opd->pDigestResult,
                       QAT_POLY1305_DIGEST_SIZE);
                DUMPL("Tag",cp_ctx->tag, QAT_POLY1305_DIGEST_SIZE);
                cp_ctx->tag_len = QAT_POLY1305_DIGEST_SIZE;
            } else {
                if (op_done.verifyResult != CPA_TRUE) {
                    WARN("Verification of result failed\n");
                    QATerr(QAT_F_QAT_CHACHA20_POLY1305_DO_CIPHER,
                            ERR_R_INTERNAL_ERROR);
                    if (op_done.status == CPA_STATUS_FAIL) {
                        CRYPTO_QAT_LOG("Verification of result failed for qat inst_num %d device_id %d - %s\n",
                                       inst_num,
                                       qat_instance_details[cp_ctx->_inst_num].qat_instance_info.physInstId.packageId);
                        qat_cleanup_op_done(&op_done);
                        goto do_cipher_err;
                    }
                } else {
                    DEBUG("Decryption succeeded\n");
                }
            }
            outlen = len;
            qat_cleanup_op_done(&op_done);
            /* Copy destination buffer into "out" buffer. */
            memcpy(out, cp_ctx->dst_buffer.pData, len);
        }
    }
    /* DecryptFinal case need not be handled explicitly here.
     * Software Implementation compare received tag and
     * calculated tag here.
     */
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
cleanup:
# endif
do_cipher_err:
    if (cp_ctx->src_buffer.pData) {
        qaeCryptoMemFreeNonZero(cp_ctx->src_buffer.pData);
        cp_ctx->src_buffer.pData = NULL;
        cp_ctx->dst_buffer.pData = NULL;
    }

#ifdef QAT_OPENSSL_PROVIDER
    *outl = outlen;
    if (in == NULL && enc == 0) 
        return 1;
# ifndef ENABLE_QAT_SMALL_PKT_OFFLOAD
    if (outlen == 0)
        return retVal;
# endif
#endif
    return outlen;
}

/******************************************************************************
 * function:
 *    qat_chacha20_poly1305_cleanup(EVP_CIPHER_CTX *ctx)
 *
 * @param ctx    [IN]  - pointer to existing ctx
 *
 * @retval 1      success
 * @retval 0      failure
 *
 * description:
 *    This function will cleanup all allocated resources required to perform the
 *  cryptographic transform.
 *
 ******************************************************************************/
#ifdef QAT_OPENSSL_PROVIDER
int qat_chacha20_poly1305_cleanup(QAT_PROV_CIPHER_CTX *ctx)
#else
static int qat_chacha20_poly1305_cleanup(EVP_CIPHER_CTX *ctx)
#endif
{
    int ret = 1;
    qat_chachapoly_ctx *cp_ctx = NULL;
    CpaStatus status;
    CpaCySymSessionSetupData *ssd = NULL;

    if (unlikely(ctx == NULL)) {
        WARN("ctx parameter is NULL.\n");
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_CLEANUP, QAT_R_CTX_NULL);
        return 0;
    }

#ifdef QAT_OPENSSL_PROVIDER
    cp_ctx = ctx->qat_cpctx;
#else
    cp_ctx = qat_chachapoly_data(ctx);
#endif
    if (cp_ctx == NULL) {
        WARN("chachapoly context cipher data is NULL.\n");
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_CLEANUP, QAT_R_CHACHAPOLY_CTX_NULL);
        return 0;
    }

    ssd = cp_ctx->session_data;
    DEBUG("ctx %p, cp_ctx %p, SSD %p\n", ctx, cp_ctx, cp_ctx->session_data);
    if (ssd) {
        if (cp_ctx->session_init) {
            status = cpaCySymRemoveSession(qat_instance_handles[cp_ctx->inst_num],
                                           cp_ctx->session_ctx);
            if (status != CPA_STATUS_SUCCESS) {
                WARN("cpaCySymRemoveSession FAILED, status = %d\n", status);
                QATerr(QAT_F_QAT_CHACHA20_POLY1305_CLEANUP,
                       ERR_R_INTERNAL_ERROR);
                ret = 0;
            }
            qaeCryptoMemFreeNonZero(cp_ctx->session_ctx);
            cp_ctx->session_ctx = NULL;
        }
        OPENSSL_free(ssd);
        ssd = NULL;
    }
    /* Cleanup the memory */
    if (cp_ctx->tls_aad) {
        qaeCryptoMemFreeNonZero(cp_ctx->tls_aad);
        cp_ctx->tls_aad = NULL;
    }
    if (cp_ctx->pSrcBufferList.pPrivateMetaData) {
        qaeCryptoMemFreeNonZero(cp_ctx->pSrcBufferList.pPrivateMetaData);
        cp_ctx->pSrcBufferList.pPrivateMetaData = NULL;
    }
    if (cp_ctx->pDstBufferList.pPrivateMetaData) {
        qaeCryptoMemFreeNonZero(cp_ctx->pDstBufferList.pPrivateMetaData);
        cp_ctx->pDstBufferList.pPrivateMetaData = NULL;
    }
    if (cp_ctx->opd) {
        if (cp_ctx->opd->pIv) {
            qaeCryptoMemFreeNonZero(cp_ctx->opd->pIv);
            cp_ctx->opd->pIv = NULL;
        }
        OPENSSL_clear_free(cp_ctx->opd, sizeof(template_opData));
        cp_ctx->opd = NULL;
    }
    if (cp_ctx->mac_key) {
        qaeCryptoMemFreeNonZero(cp_ctx->mac_key);
        cp_ctx->mac_key = NULL;
    }
    cp_ctx->context_params_set = 0;
    cp_ctx->session_init = 0;
    cp_ctx->packet_size = 0;
# if !defined(ENABLE_QAT_SMALL_PKT_OFFLOAD) && !defined(QAT_OPENSSL_PROVIDER)
    if (cp_ctx->sw_ctx_cipher_data) {
        OPENSSL_free(cp_ctx->sw_ctx_cipher_data);
        cp_ctx->sw_ctx_cipher_data = NULL;
    }
#endif

    return ret;
}

/******************************************************************************
 * function:
 *    qat_chacha20_poly1305_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
 *
 * @param ctx    [IN]  - pointer to existing ctx
 * @param type   [IN]  - type of request
 * @param arg    [IN]  - size of the pointed to by ptr
 * @param ptr    [IN]  - input buffer contain the necessary parameters
 *
 * @retval x         The return value is dependent on the type of request being made.
 * @retval 0, -1     failure
 *
 * description:
 *    This function is a generic control interface provided by the EVP API.
 *
 ******************************************************************************/
#ifdef QAT_OPENSSL_PROVIDER
int qat_chacha20_poly1305_ctrl(QAT_PROV_CIPHER_CTX *ctx, int type, int arg,
                               void *ptr)
#else
static int qat_chacha20_poly1305_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                      void *ptr)
#endif
{
    int enc;
    EVP_CIPHER_CTX *dst_ctx = NULL;
    void *tmp_ctx = NULL;
# if !defined(ENABLE_QAT_SMALL_PKT_OFFLOAD) && !defined(QAT_OPENSSL_PROVIDER)
    int ret_sw = 0;
# endif

    if (unlikely(ctx == NULL)) {
        WARN("ctx parameter is NULL.\n");
        QATerr(QAT_F_QAT_CHACHA20_POLY1305_CTRL, QAT_R_CTX_NULL);
        return 0;
    }

#ifdef QAT_OPENSSL_PROVIDER
    qat_chachapoly_ctx *cp_ctx = ctx->qat_cpctx;
    enc = QAT_PROV_GET_ENC(ctx);
#else
    qat_chachapoly_ctx *cp_ctx = qat_chachapoly_data(ctx);
    enc = EVP_CIPHER_CTX_encrypting(ctx);
#endif
    DEBUG("Entering ctrl %d\n", type);

    switch (type) {
    case EVP_CTRL_INIT:
        if (cp_ctx == NULL) {
            cp_ctx = OPENSSL_zalloc(sizeof(qat_chachapoly_ctx));
            if (cp_ctx == NULL) {
                WARN("unable to allocate memory for chachapoly ctx.\n");
                QATerr(QAT_F_QAT_CHACHA20_POLY1305_CTRL, ERR_R_MALLOC_FAILURE);
                return -1;
            }
        }
        DEBUG("ctx %p cp_ctx %p\n", ctx, cp_ctx);
        cp_ctx->tag_len = 0;
        cp_ctx->nonce_len = QAT_CHACHA20_POLY1305_MAX_IVLEN;
        cp_ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
        cp_ctx->tls_aad = NULL;
        cp_ctx->tls_aad_len = 0;
        cp_ctx->key_set = 0;
        cp_ctx->iv_set = 0;
        cp_ctx->mac_key_set = 0;
        cp_ctx->mac_key = NULL;

#ifndef QAT_OPENSSL_PROVIDER
        EVP_CIPHER_CTX_set_cipher_data(ctx, cp_ctx);
#endif

# if !defined(ENABLE_QAT_SMALL_PKT_OFFLOAD) && !defined(QAT_OPENSSL_PROVIDER)
        if (cp_ctx->sw_ctx_cipher_data == NULL) {
            cp_ctx->sw_ctx_cipher_data = OPENSSL_zalloc(QAT_CP_SW_CTX_MEM_SIZE);
            if (cp_ctx->sw_ctx_cipher_data == NULL) {
                WARN("Unable to allocate memory for sw_ctx_cipher_data\n");
                QATerr(QAT_F_QAT_CHACHA20_POLY1305_CTRL, ERR_R_MALLOC_FAILURE);
                return -1;
            }
        }
	    goto sw_ctrl;
# endif
        return 1;

    case EVP_CTRL_COPY:
        dst_ctx = (EVP_CIPHER_CTX *)ptr;
        tmp_ctx = OPENSSL_memdup(cp_ctx, sizeof(qat_chachapoly_ctx));
        if (tmp_ctx == NULL) {
            WARN("unable to copy chachapoly cipher context data.\n");
            QATerr(QAT_F_QAT_CHACHA20_POLY1305_CTRL, ERR_R_MALLOC_FAILURE);
            return -1;
        }
        EVP_CIPHER_CTX_set_cipher_data(dst_ctx, tmp_ctx);
# if !defined(ENABLE_QAT_SMALL_PKT_OFFLOAD) && !defined(QAT_OPENSSL_PROVIDER)
        if (cp_ctx->packet_size <= qat_pkt_threshold_table_get_threshold(
            EVP_CIPHER_CTX_nid(ctx))) {
            goto sw_ctrl;
        }
# endif
        return 1;

    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = cp_ctx->nonce_len;
# if !defined(ENABLE_QAT_SMALL_PKT_OFFLOAD) && !defined(QAT_OPENSSL_PROVIDER)
        if (cp_ctx->packet_size <=
            qat_pkt_threshold_table_get_threshold(
            EVP_CIPHER_CTX_nid(ctx))) {
            goto sw_ctrl;
        }
# endif
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
         if (arg <= 0 || arg > QAT_CHACHA20_POLY1305_MAX_IVLEN) {
             WARN("Invalid IV length.\n");
             QATerr(QAT_F_QAT_CHACHA20_POLY1305_CTRL, QAT_R_INVALID_IVLEN);
             return 0;
         }
         cp_ctx->nonce_len = arg;
# if !defined(ENABLE_QAT_SMALL_PKT_OFFLOAD) && !defined(QAT_OPENSSL_PROVIDER)
        if (cp_ctx->packet_size <= qat_pkt_threshold_table_get_threshold(
            EVP_CIPHER_CTX_nid(ctx))) {
            goto sw_ctrl;
         }
# endif
         return 1;

     case EVP_CTRL_AEAD_SET_IV_FIXED:
         if (arg != QAT_CHACHA20_POLY1305_MAX_IVLEN) {
             WARN("Invalid fixed IV length.\n");
             QATerr(QAT_F_QAT_CHACHA20_POLY1305_CTRL, QAT_R_INVALID_IVLEN);
             return 0;
         }
         cp_ctx->iv[0] = CHACHA_U8TOU32((unsigned char *)ptr);
         cp_ctx->iv[1] = CHACHA_U8TOU32((unsigned char *)ptr+4);
         cp_ctx->iv[2] = CHACHA_U8TOU32((unsigned char *)ptr+8);

# if !defined(ENABLE_QAT_SMALL_PKT_OFFLOAD) && !defined(QAT_OPENSSL_PROVIDER)
        if (cp_ctx->packet_size <=
            qat_pkt_threshold_table_get_threshold(
            EVP_CIPHER_CTX_nid(ctx))) {
            goto sw_ctrl;
         }
# endif
         return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        if (arg <= 0 || arg > QAT_POLY1305_BLOCK_SIZE) {
            WARN("Invalid TAG length.\n");
            QATerr(QAT_F_QAT_CHACHA20_POLY1305_CTRL, QAT_R_INVALID_TAG_LEN);
            return 0;
        }
        if (ptr != NULL) {
            memcpy(cp_ctx->tag, ptr, arg);
            cp_ctx->tag_len = arg;
        }

# if !defined(ENABLE_QAT_SMALL_PKT_OFFLOAD) && !defined(QAT_OPENSSL_PROVIDER)
        if (cp_ctx->packet_size <= qat_pkt_threshold_table_get_threshold(
            EVP_CIPHER_CTX_nid(ctx))) {
            goto sw_ctrl;
        }
# endif
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (arg <= 0 || arg > QAT_POLY1305_BLOCK_SIZE || !enc) {
            WARN("Invalid TAG operation.\n");
            QATerr(QAT_F_QAT_CHACHA20_POLY1305_CTRL, QAT_R_INVALID_TAG_LEN);
            return 0;
        }
        memcpy(ptr, cp_ctx->tag, arg);

# if !defined(ENABLE_QAT_SMALL_PKT_OFFLOAD) && !defined(QAT_OPENSSL_PROVIDER)
        if (cp_ctx->packet_size <=
            qat_pkt_threshold_table_get_threshold(
            EVP_CIPHER_CTX_nid(ctx))) {
            goto sw_ctrl;
        }
# endif
        return 1;

    case EVP_CTRL_AEAD_TLS1_AAD:
        if (arg != EVP_AEAD_TLS1_AAD_LEN) {
            WARN("Invalid AAD length.\n");
            QATerr(QAT_F_QAT_CHACHA20_POLY1305_CTRL, QAT_R_AAD_LEN_INVALID);
            return 0;
        }
        unsigned int len;
        unsigned char *aad = ptr;

        if (cp_ctx->tls_aad_len <= 0) {
            cp_ctx->tls_aad = qaeCryptoMemAlloc(arg, __FILE__, __LINE__);
            if (cp_ctx->tls_aad == NULL) {
                WARN("Unable to allocate memory for TLS header\n");
                QATerr(QAT_F_QAT_CHACHA20_POLY1305_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            cp_ctx->tls_aad_len = arg;
        }
        memcpy(cp_ctx->tls_aad, ptr, EVP_AEAD_TLS1_AAD_LEN);

        /* Get the length of the TLS payload */
        len = aad[EVP_AEAD_TLS1_AAD_LEN - 2] << 8 |
                aad[EVP_AEAD_TLS1_AAD_LEN - 1];

        aad = cp_ctx->tls_aad;

        if (!enc) {
            if (len < QAT_POLY1305_BLOCK_SIZE) {
                WARN("Invalid TAG length or no TAG.\n");
                QATerr(QAT_F_QAT_CHACHA20_POLY1305_CTRL,
                       QAT_R_INVALID_ATTACHED_TAG);
                return 0;
            }
            /* Discount attached tag */
            len -= QAT_POLY1305_BLOCK_SIZE;
            /* Adjust the length of the payload */
            aad[EVP_AEAD_TLS1_AAD_LEN - 2] = (unsigned char)(len >> 8);
            aad[EVP_AEAD_TLS1_AAD_LEN - 1] = (unsigned char)len;
        }
        cp_ctx->session_data->hashSetupData.authModeSetupData.aadLenInBytes = EVP_AEAD_TLS1_AAD_LEN;
        cp_ctx->tls_payload_length = len;

        /* merge record sequence number as per RFC7905 */
        cp_ctx->counter[1] = cp_ctx->iv[0];
        cp_ctx->counter[2] = cp_ctx->iv[1] ^ CHACHA_U8TOU32(aad);
        cp_ctx->counter[3] = cp_ctx->iv[2] ^ CHACHA_U8TOU32(aad+4);

        memset(cp_ctx->derived_iv, 0, QAT_CHACHA20_POLY1305_MAX_IVLEN);

        memcpy(cp_ctx->derived_iv, cp_ctx->nonce, 4);
        U32TOU8(cp_ctx->derived_iv + 4, cp_ctx->counter[2]);
        U32TOU8(cp_ctx->derived_iv + 8, cp_ctx->counter[3]);

        cp_ctx->mac_key_set = 0;

# if !defined(ENABLE_QAT_SMALL_PKT_OFFLOAD) && !defined(QAT_OPENSSL_PROVIDER)
        if (len <= qat_pkt_threshold_table_get_threshold(
                   EVP_CIPHER_CTX_nid(ctx))) {
            goto sw_ctrl;
        }
# endif
        return QAT_POLY1305_BLOCK_SIZE;

   default:
        WARN("Unknown type parameter\n");
        return -1;
    }
# if !defined(ENABLE_QAT_SMALL_PKT_OFFLOAD) && !defined(QAT_OPENSSL_PROVIDER)
sw_ctrl:
    EVP_CIPHER_CTX_set_cipher_data(ctx, cp_ctx->sw_ctx_cipher_data);
    ret_sw = EVP_CIPHER_meth_get_ctrl(GET_SW_CHACHA_CTX)(ctx, type, arg, ptr);
    EVP_CIPHER_CTX_set_cipher_data(ctx, cp_ctx);
    if(ret_sw < 0){
       WARN("SW chachapoly ctrl function failed.\n");
       return -1;
    }
    return ret_sw;
# endif
}
#endif
