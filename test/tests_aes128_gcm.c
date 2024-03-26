/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021-2024 Intel Corporation.
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

#include "tests.h"
#include "../qat_utils.h"

#define AES128_BLOCKSIZE 16

/* 16 bytes key */
static const unsigned char key[] = {
    0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
};

/* 12 bytes initialisation vector */
static const unsigned char iv[] = {
    0x99, 0xaa, 0x3e, 0x68, /* fixed IV - 4 bytes */
    0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84 /* explicit IV - 8 bytes */
};

/******************************************************************************
* function:
*         run_aesgcm128_update (void *args)
*
* @param args [IN] - the test parameters
*
* SW engine differs from the QAT engine in the following ways:
* EVP Function        SW Engine                       QAT Engine
* ----------------------------------------------------------------------------
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
static int run_aesgcm128_update(void *args)
{
    TEST_PARAMS *temp_args = (TEST_PARAMS *)args;
#ifndef QAT_OPENSSL_PROVIDER
    ENGINE *e = temp_args->e;
#endif
    int size = temp_args->size;
    int print_output = temp_args->print_output;
    int verify = temp_args->verify;
    int i;
    int ret = 0;

    /* 16 bytes additional authentication data.
     * AAD is not to be encrypted. It is passed along with the plaintext
     * and ciphertext to the recipient. */
    const unsigned char aad[] = {
        0x61, 0x31, 0xFF, 0x29, 0xCE, 0x13, 0x75, 0xBD,
        0x72, 0xD2, 0x3A, 0x11, 0x55, 0x42, 0xBB, 0xFF
    };

    unsigned char *input = OPENSSL_malloc(size);
    unsigned char *plaintext = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char tag[EVP_GCM_TLS_TAG_LEN] = { 0 };
    unsigned char *dec_cipher = NULL;

    int ciphertext_len = 0;
    int tmpout_len = 0;
    int dec_cipher_len = 0;

    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER_CTX *dec_ctx = NULL;
#ifndef QAT_OPENSSL_PROVIDER
    if (e !=NULL) {
        const EVP_CIPHER *c = ENGINE_get_cipher(e, NID_aes_128_gcm);

        if (!c) {
            INFO("AES-128-GCM cipher disabled in QAT_Engine\n");
            e = NULL;
        }
    }
#endif

    if (input == NULL) {
        INFO("# FAIL: [%s] --- Initial parameters malloc failed ! \n",
             __func__);
        exit(EXIT_FAILURE);
    }

    /* Set input data */
    for (i = 0; i < size; i++)
         input[i] = i % 16;

    if (print_output)
        tests_hexdump("AES-GCM 128: input message", input, size);

    /* Create context for encrypt operation */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        INFO("# FAIL: [%s] --- EVP_CIPHER_CTX_new() failed for ctx\n",
             __func__);
        goto err;
    }

    /* Initialize encryption context for aes-gcm-128 */
#ifdef QAT_OPENSSL_PROVIDER
    ret = EVP_EncryptInit(ctx, EVP_aes_128_gcm(), NULL, NULL);
#else
    ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), e, NULL, NULL);
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
     *  Initialise the aes-gcm-128 encryption context with 16-byte key and
     * 12-byte IV.
     */
#ifdef QAT_OPENSSL_PROVIDER
    ret = EVP_EncryptInit(ctx, NULL, key, iv);
#else
    ret = EVP_EncryptInit_ex(ctx, NULL, e, key, iv);
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
    plaintext = OPENSSL_malloc(size + (AES128_BLOCKSIZE * 4));
    if (plaintext == NULL) {
	INFO("# FAIL: [%s] --- malloc failed for plaintext! \n", __func__);
	goto err;
    }
    ciphertext = plaintext;

    memcpy(plaintext, input, size);

    /* Encrypt the input plaintext. */
    ret = EVP_EncryptUpdate(ctx, ciphertext, &tmpout_len, plaintext, size);
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
        tests_hexdump("AES-GCM 128 ciphertext:", ciphertext, ciphertext_len);

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

/*----------------------- Decryption ------------------------ */

    /* Create context for decrypt operation */
    dec_ctx = EVP_CIPHER_CTX_new();
    if (dec_ctx == NULL) {
        INFO("# FAIL: [%s] --- EVP_CIPHER_CTX_new() failed for dec_ctx\n",
             __func__);
        goto err;
    }

    /* Initialize decryption context for aes-gcm-128 */
#ifdef QAT_OPENSSL_PROVIDER
    ret = EVP_DecryptInit(dec_ctx, EVP_aes_128_gcm(), NULL, NULL);
#else
    ret = EVP_DecryptInit_ex(dec_ctx, EVP_aes_128_gcm(), e, NULL, NULL);
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
     *  Initialise the aes-gcm-128 decryption context with 16-byte key and
     *  12-byte IV.
     */
#ifdef QAT_OPENSSL_PROVIDER
    ret = EVP_DecryptInit(dec_ctx, NULL, key, iv);
#else
    ret = EVP_DecryptInit_ex(dec_ctx, NULL, e, key, iv);
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
    dec_cipher = ciphertext;

    /* Decrypt the ciphertext */
    ret = EVP_DecryptUpdate(dec_ctx, dec_cipher, &tmpout_len, ciphertext,
                            ciphertext_len);
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_DecryptUpdate() failed when decrypting ciphertext: ret %d\n",
             __func__, ret);
        goto err;
    }
    else
        dec_cipher_len = tmpout_len;

    /* Read the tag after the decrypt operation */
    ret = EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_TAG,
                              EVP_GCM_TLS_TAG_LEN, tag);
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_CIPHER_CTX_ctrl() failed while setting the tag: ret %d\n",
             __func__, ret);
        goto err;
    }

    if (print_output)
        tests_hexdump("AES-GCM 128 tag:", tag, EVP_GCM_TLS_TAG_LEN);

    if (print_output)
        tests_hexdump("AES-GCM 128 decrypted plaintext:", dec_cipher,
                      dec_cipher_len);

    /* Compare and verify the decrypt and encrypt message. */
    if (verify) {
        if (memcmp(dec_cipher, plaintext, size)) {
            INFO("# FAIL verify for AES128 GCM update\n");
            ret = 0;

            tests_hexdump("AES128GCM actual  :", dec_cipher, dec_cipher_len);
            tests_hexdump("AES128GCM expected:", plaintext, size);
        }
        else
            INFO("# PASS verify for AES128 GCM update\n");
    }

    EVP_CIPHER_CTX_free(dec_ctx);
    dec_ctx = NULL;

    if (input)
        OPENSSL_free(input);
    if (plaintext)
        OPENSSL_free(plaintext);

    return ret;

err:
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    if (dec_ctx != NULL)
        EVP_CIPHER_CTX_free(dec_ctx);

    return ret;
}

/******************************************************************************
* function:
*         run_aesgcm128_tls (void *args)
*
* @param args [IN] - the test parameters
*
* TLS: The API is used as in the TLS stack of OpenSSL.
*      The operations must be performed inplace and
*      the AAD must be added using the function ctrl.
*
* The ciphertext in the TLS case has the following format:
*
*       +-------------+-----------------------------+-------+
*       | explicit IV |         ciphertext          |  tag  |
*       +-------------+-----------------------------+-------+
*             8                     size                 16
*******************************************************************************/
static int run_aesgcm128_tls(void *args)
{
    TEST_PARAMS *temp_args = (TEST_PARAMS *)args;
    ENGINE *e = temp_args->e;
    int size = temp_args->size;
    int print_output = temp_args->print_output;
    int verify = temp_args->verify;
    int i;
    int ret = 0;

    /* For TLS enc: include the length of the explicit IV */
    unsigned char length_byte1_tls_enc =
        (size + EVP_GCM_TLS_EXPLICIT_IV_LEN) >> 8;
    unsigned char length_byte2_tls_enc =
        (size + EVP_GCM_TLS_EXPLICIT_IV_LEN) |16 >> 8;
    unsigned char tls_enc_virt_hdr[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x16, 0x03, 0x01, length_byte1_tls_enc, length_byte2_tls_enc
    };

    /* For TLS dec: include the length of the explicit IV + TAG */
    unsigned char length_byte1_tls_dec =
        (size + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN) >> 8;
    unsigned char length_byte2_tls_dec =
        (size + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN) |16 >> 8;
    unsigned char tls_dec_virt_hdr[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x16, 0x03, 0x01, length_byte1_tls_dec, length_byte2_tls_dec
    };

    unsigned char *input = OPENSSL_malloc(size);
    unsigned char *plaintext = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char tag[EVP_GCM_TLS_TAG_LEN] = { 0 };
    unsigned char *dec_cipher = NULL;

    int ciphertext_len = 0;
    int tmpout_len = 0;
    int dec_cipher_len = 0;
    int plaintext_len = size;

    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER_CTX *dec_ctx = NULL;
#ifndef QAT_OPENSSL_PROVIDER
    if (e != NULL) {
        const EVP_CIPHER *c = ENGINE_get_cipher(e, NID_aes_128_gcm);

        if (!c) {
            INFO("AES-128-GCM disabled in QAT_Engine\n");
            e = NULL;
        }
    }
#endif

    if (input == NULL) {
        INFO("# FAIL: [%s] --- Initial parameters malloc failed ! \n",
             __func__);
        exit(EXIT_FAILURE);
    }

    /*
     * Set the plaintext input data.
     * This is a copy of the plaintext that will be used to check the
     * decrypted message. Original plaintext is destroyed in TLS case.
     */
    for (i = 0; i < size; i++)
         input[i] = i % 16;

    if (print_output)
        tests_hexdump("AES-GCM 128: input message", input, size);

    /* Create a new context for the TLS encrypt operation */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        INFO("# FAIL: [%s] --- EVP_CIPHER_CTX_new() failed for ctx\n",
             __func__);
        exit(EXIT_FAILURE);
    }

    /*
     * IV used in the initialization of the cipher: in TLS case it is set
     * using ctrl() instead of EncryptInit_ex().
     */
    ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), e, key, NULL);
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_EncryptInit_ex() failed: ret %d\n",
             __func__, ret);
        goto err;
    }

    /*
     * Specify the fixed part of the IV.
     * When arg_len == -1 the explicit part of the IV is copied
     * and not filled with random bytes
     */
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, -1, (void *)iv);
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_CIPHER_CTX_ctrl() failed for setting IV: ret %d\n",
             __func__, ret);
        goto err;
    }

    /* Provide the AAD as in the TLS stack of OpenSSL */
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD,
                              sizeof(tls_enc_virt_hdr),
                              tls_enc_virt_hdr);
    if (ret != EVP_GCM_TLS_TAG_LEN) {
        INFO("# FAIL: [%s] --- EVP_CIPHER_CTX_ctrl() failed for setting aad: ret %d\n",
             __func__, ret);
        goto err;
    }

    /*
     * In TLS case the explicit IV must be prepended to the plaintext
     * and there must be space to save the tag at the end of the buffer.
     */
    plaintext_len += EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;

    plaintext = OPENSSL_malloc(plaintext_len);
    if (plaintext == NULL) {
        INFO("# FAIL: [%s] --- malloc failed for plaintext! \n", __func__);
        goto err;
    }

    memcpy(plaintext, iv + EVP_GCM_TLS_FIXED_IV_LEN,
           EVP_GCM_TLS_EXPLICIT_IV_LEN);
    memcpy(plaintext + EVP_GCM_TLS_EXPLICIT_IV_LEN, input, size);

    /* TLS case works only inplace */
    ciphertext = plaintext;

    /* TLS Decrypt operation */
    ret = EVP_EncryptUpdate(ctx, ciphertext, &tmpout_len, plaintext,
                            plaintext_len);
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_EncryptUpdate() failed for inputtext: ret %d\n",
             __func__, ret);
        goto err;
    }
    else
        ciphertext_len = tmpout_len;

    if (print_output)
        tests_hexdump("AES-GCM 128 ciphertext:", ciphertext, ciphertext_len);

    /* The tag is contained in the last EVP_GCM_TLS_TAG_LEN Bytes of the payload */
    memcpy(tag, ciphertext + EVP_GCM_TLS_EXPLICIT_IV_LEN + size,
           EVP_GCM_TLS_TAG_LEN);

    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    tmpout_len = 0;

/*----------------------- Decryption ------------------------ */

    /* Create context for TLS decrypt */
    dec_ctx = EVP_CIPHER_CTX_new();
    if (dec_ctx == NULL) {
        INFO("# FAIL: [%s] --- EVP_CIPHER_CTX_new() failed for dec_ctx\n",
             __func__);
        exit(EXIT_FAILURE);
    }

    /* Initialise the context for decryption with 16-byte key and 12-byte IV. */
    ret = EVP_DecryptInit_ex(dec_ctx, EVP_aes_128_gcm(), e, key, iv);
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_DecryptInit_ex() failed: ret %d\n",
             __func__, ret);
        goto err;
    }

    /* Specify the fixed part of the IV */
    ret = EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_IV_FIXED,
                              EVP_GCM_TLS_FIXED_IV_LEN, (void *)iv);
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_CIPHER_CTX_ctrl() failed for setting IV: ret %d\n",
             __func__, ret);
        goto err;
    }

    /* Provide the AAD as in the TLS stack of OpenSSL */
    ret = EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_AEAD_TLS1_AAD,
                              sizeof(tls_dec_virt_hdr),
                              tls_dec_virt_hdr);
    if (ret != EVP_GCM_TLS_TAG_LEN) {
        INFO("# FAIL: [%s] --- EVP_CIPHER_CTX_ctrl() failed for setting aad: ret %d\n",
             __func__, ret);
        goto err;
    }

    /* TLS case works only inplace */
    dec_cipher = ciphertext;

    /* TLS Decrypt operation */
    ret = EVP_DecryptUpdate(dec_ctx, dec_cipher, &dec_cipher_len, ciphertext,
                            ciphertext_len);
    if (ret != 1) {
        INFO("# FAIL: [%s] --- EVP_DecryptUpdate() failed when decrypting ciphertext: ret %d\n",
             __func__, ret);
        goto err;
    }

    if (print_output)
        tests_hexdump("AES-GCM 128 tag:", tag, EVP_GCM_TLS_TAG_LEN);

    /* In TLS case the first part of the output can be skipped */
    dec_cipher += EVP_GCM_TLS_EXPLICIT_IV_LEN;

    if (print_output)
        tests_hexdump("AES-GCM 128 decrypted plaintext:", dec_cipher,
                      dec_cipher_len);

    /* Compare and verify the decrypt and encrypt message. */
    if (verify) {
        if (memcmp(dec_cipher, input, size)) {
            INFO("# FAIL verify for TLS AES128 GCM\n");
            ret = 0;

            tests_hexdump("AES128GCM actual  :", dec_cipher, size);
            tests_hexdump("AES128GCM expected:", plaintext, size);
        }
        else
            INFO("# PASS verify for TLS AES128 GCM\n");
    }

    EVP_CIPHER_CTX_free(dec_ctx);
    dec_ctx = NULL;

    if (input != NULL)
        OPENSSL_free(input);
    if (plaintext != NULL)
        OPENSSL_free(plaintext);

    return ret;

err:
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    if (dec_ctx != NULL)
        EVP_CIPHER_CTX_free(dec_ctx);

    return ret;
}

void tests_run_aes128_gcm(TEST_PARAMS *args)
{
    args->additional_args = NULL;
    if (args->enable_async) {
        start_async_job(args, run_aesgcm128_update);
        start_async_job(args, run_aesgcm128_tls);
    }
    else {
        run_aesgcm128_update(args);
	    run_aesgcm128_tls(args);
    }
}
