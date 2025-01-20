/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2024-2025 Intel Corporation.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/async.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/bio.h>

#include "tests.h"
#include "../qat_utils.h"

#ifdef ENABLE_QAT_SW_SM4_GCM
#define SM4_BLOCKSIZE 16

static const unsigned char key[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};

/* 12 bytes initialisation vector */
static const unsigned char iv[] = {
	0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00,
	0x00, 0x00, 0x00, 0xAB, 0xCD};

/******************************************************************************
* function:
*         run_sm4gcm_update (void *args)
*
* @param args [IN] - the test parameters
*
* SW engine differs from the QAT engine in the following ways:
* EVP Function        SW Engine                       QAT Engine
* ---------------------------------------------------------------------------
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
*****************************************************************************/
static int run_sm4gcm_update(void *args)
{
    TEST_PARAMS *temp_args = (TEST_PARAMS *)args;
#ifndef QAT_OPENSSL_PROVIDER
    ENGINE *e = temp_args->e;
#endif
    int size = temp_args->size;
    int print_output = temp_args->print_output;
    int verify = temp_args->verify;
    int ret = 0;

    /* 16 bytes additional authentication data.
     * AAD is not to be encrypted. It is passed along with the plaintext
     * and ciphertext to the recipient. */
    const unsigned char aad[] = {
	0xFE,0xED,0xFA,0xCE,0xDE,0xAD,0xBE,0xEF,0xFE,0xED,
	0xFA,0xCE,0xDE,0xAD,0xBE,0xEF,0xAB,0xAD,0xDA,0xD2};

    unsigned char plaintext[] = {
	    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
	    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
	    0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
	    0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	    0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
	    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};

    unsigned char *ciphertext = OPENSSL_malloc(size + (SM4_BLOCKSIZE * 4));
    unsigned char tag[EVP_GCM_TLS_TAG_LEN] = { 0 };
    unsigned char *dec_cipher = OPENSSL_malloc(size + (SM4_BLOCKSIZE * 4));
    unsigned char *enc_cipher = NULL;

    int ciphertext_len = 0;
    int tmpout_len = 0;
    int enc_cipher_len = 0;
    int dec_cipher_len = 0;

    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER_CTX *dec_ctx = NULL;

#ifndef QAT_OPENSSL_PROVIDER
    if (!temp_args->enable_async) {
        e = NULL;
    }
#endif

    if (ciphertext == NULL || dec_cipher == NULL) {
        INFO("# FAIL: [%s] --- Initial parameters malloc failed ! \n",
             __func__);
        exit(EXIT_FAILURE);
    }

    enc_cipher = ciphertext;

    if (print_output)
        tests_hexdump("SM4-GCM: input message", plaintext, /*size*/sizeof(plaintext));

    /* Create context for encrypt operation */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        INFO("# FAIL: [%s] --- EVP_CIPHER_CTX_new() failed for ctx\n",
             __func__);
        goto err;
    }

    /* Initialize encryption context for sm4-gcm */
#ifdef QAT_OPENSSL_PROVIDER
    ret = EVP_EncryptInit(ctx, EVP_sm4_gcm(), NULL, NULL);
#else
    ret = EVP_EncryptInit_ex(ctx, EVP_sm4_gcm() , e, NULL, NULL);
#endif
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_EncryptInit_ex() failed: ret %d\n",
             __func__, ret);
        goto err;
    }

    /*
     *  Set IV length other than the default 12 bytes but QAT Engine supports
     * only 12 bytes.
     * Optional - The default is 12 bytes according to the TLS spec.
     */
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL);
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_CIPHER_CTX_ctrl() failed: ret %d\n",
             __func__, ret);
        goto err;
    }

    /*
     *  Initialise the sm4-gcm encryption context with 16-byte key and
     * 12-byte IV.
     */
#ifdef QAT_OPENSSL_PROVIDER
    ret = EVP_EncryptInit(ctx, NULL, key, iv);
#else
    ret = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
#endif
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_EncryptInit_ex() failed: ret %d\n",
             __func__, ret);
        goto err;
    }

    /* Pass AAD to the encryption context before encrypting the input plaintext. */
    ret = EVP_EncryptUpdate(ctx, NULL, &tmpout_len, aad, sizeof(aad));
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_EncryptUpdate() failed when adding aad: ret %d\n",
             __func__, ret);
        goto err;
    }

    /* Encrypt the input plaintext. */
    ret = EVP_EncryptUpdate(ctx, ciphertext, &tmpout_len, plaintext, sizeof(plaintext));
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_EncryptUpdate() failed for inputtext: ret %d\n",
             __func__, ret);
        goto err;
    }
    else
        ciphertext_len = tmpout_len;

    /* Finalise the encryption - EVP_EncryptFinal_ex()
     * This operation is not needed for QAT Engine calculates and finalises
     * the ciphertext in EVP_EncryptUpdate() itself.
     * */
    ret = EVP_EncryptFinal_ex(ctx, ciphertext + tmpout_len, &tmpout_len);
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_EncryptFinal_ex() failed for ciphertext: ret %d\n",
             __func__, ret);
        goto err;
    }
    ciphertext_len += tmpout_len;

    if (print_output)
        tests_hexdump("SM4-GCM ciphertext:", ciphertext, ciphertext_len);

    /* Retrieve the 16 byte tag */
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVP_GCM_TLS_TAG_LEN,
                              tag);
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_CIPHER_CTX_ctrl() failed for tag: ret %d\n",
             __func__, ret);
        goto err;
    }

    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    tmpout_len = 0;
    enc_cipher_len = ciphertext_len;

/*----------------------- Decryption ------------------------ */

    /* Create context for decrypt operation */
    dec_ctx = EVP_CIPHER_CTX_new();
    if (dec_ctx == NULL) {
        INFO("# FAIL: [%s] --- EVP_CIPHER_CTX_new() failed for dec_ctx\n",
             __func__);
        goto err;
    }

    /* Initialize decryption context for sm4-gcm */
#ifdef QAT_OPENSSL_PROVIDER
    ret = EVP_DecryptInit(dec_ctx, EVP_sm4_gcm(), NULL, NULL);
#else
    ret = EVP_DecryptInit_ex(dec_ctx, EVP_sm4_gcm(), e, NULL, NULL);
#endif
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_DecryptInit_ex() failed: ret %d\n",
             __func__, ret);
        goto err;
    }

    /* Set IV length other than the default 12 bytes but QAT Engine supports
     * only 12 bytes.
     * Optional - The default is 12 bytes according to the TLS spec. */
    ret = EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL);
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_CIPHER_CTX_ctrl() failed: ret %d\n",
             __func__, ret);
        goto err;
    }

    /*
     *  Initialise the sm4-gcm decryption context with 16-byte key and
     *  12-byte IV.
     */
#ifdef QAT_OPENSSL_PROVIDER
    ret = EVP_DecryptInit(dec_ctx, NULL, key, iv);
#else
    ret = EVP_DecryptInit_ex(dec_ctx, NULL, NULL, key, iv);
#endif
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_DecryptInit_ex() failed: ret %d\n",
             __func__, ret);
        goto err;
    }

    /* QAT engine reads tag before starting the decrypt operation whereas
     * SW engine performs the decrypt op first and then reads the tag. */
    ret = EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_TAG,
                              EVP_GCM_TLS_TAG_LEN, tag);
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_CIPHER_CTX_ctrl() failed while setting the tag: ret %d\n",
             __func__, ret);
        goto err;
    }

    /* AAD is passed to EVP_DecryptUpdate() with output buffer set to NULL */
    ret = EVP_DecryptUpdate(dec_ctx, NULL, &tmpout_len, aad, sizeof(aad));
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_DecryptUpdate() failed when adding aad: ret %d\n",
             __func__, ret);
        goto err;
    }

    /* Decrypt the ciphertext */
    ret = EVP_DecryptUpdate(dec_ctx, dec_cipher, &tmpout_len, enc_cipher,
                            enc_cipher_len);
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_DecryptUpdate() failed when decrypting ciphertext: ret %d\n",
             __func__, ret);
        goto err;
    }
    else
        dec_cipher_len += tmpout_len;

    /* Read the tag after the decrypt operation */
    ret = EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_TAG,
                              EVP_GCM_TLS_TAG_LEN, tag);
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_CIPHER_CTX_ctrl() failed while setting the tag: ret %d\n",
             __func__, ret);
        goto err;
    }

    if (print_output)
        tests_hexdump("SM4-GCM enc tag:", tag, EVP_GCM_TLS_TAG_LEN);

    if (print_output)
        tests_hexdump("SM4-GCM decrypted plaintext:", dec_cipher,
                      dec_cipher_len);

    /* Compare and verify the decrypt and encrypt message. */
    if (verify) {
        if (memcmp(dec_cipher, plaintext, /*size*/sizeof(plaintext))) {
            INFO("# FAIL verify for SM4 GCM update\n");
            ret = 0;

            tests_hexdump("SM4GCM actual  :", dec_cipher, dec_cipher_len);
            tests_hexdump("SM4GCM expected:", plaintext, size);
        } else { 
            INFO("# PASS verify for SM4 GCM update\n");
        }
    }

    EVP_CIPHER_CTX_free(dec_ctx);
    dec_ctx = NULL;

    if (ciphertext)
        OPENSSL_free(ciphertext);
    if (dec_cipher)
        OPENSSL_free(dec_cipher);

    return ret;

err:
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    if (dec_ctx != NULL)
        EVP_CIPHER_CTX_free(dec_ctx);

    return ret;
}

void tests_run_sm4_gcm(TEST_PARAMS *args)
{
    args->additional_args = NULL;
    if (args->enable_async)
        start_async_job(args, run_sm4gcm_update);
    else
        run_sm4gcm_update(args);
}
#endif /* ENABLE_QAT_SW_SM4_GCM */
