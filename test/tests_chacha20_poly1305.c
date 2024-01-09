/***************************************************************************
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021-2024 Intel Corporation. All rights reserved.
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
 *
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/async.h>
#include <openssl/objects.h>
#include <openssl/engine.h>

#include "tests.h"
#include "../qat_utils.h"

#define USE_ENGINE      1
#define USE_SW          0

#define POLY1305_DIGEST_SIZE 16

#define FAIL_MSG(fmt, args...)  fprintf(stderr, "# FAIL " fmt, ##args)
#define PASS_MSG(fmt, args...)  fprintf(stderr, "# PASS " fmt, ##args)

/* 256-bit cipher key */
static const unsigned char _key32[] = {
    0xa5, 0x10, 0xca, 0x7c, 0x35, 0xc4, 0x52, 0x84,
    0x82, 0xa8, 0x0c, 0x13, 0x17, 0xaf, 0x19, 0xa7,
    0x80, 0x5f, 0xcf, 0xba, 0x5c, 0xbb, 0x6f, 0x9b,
    0x8e, 0xa4, 0x36, 0xa6, 0x16, 0xbb, 0xcd, 0x7f
};

/* 96-bit IV */
static unsigned char _ivec[] = {
    0x2a, 0xf3, 0x01, 0x27,
    0x05, 0x68, 0x03, 0x7a,
    0x8b, 0xaf, 0x40, 0x9a
};

static int run_chachapoly_update(void *args, int enc, int dec)
{
    TEST_PARAMS *temp_args = (TEST_PARAMS *)args;
    ENGINE *enc_e = enc == USE_ENGINE ? temp_args->e : NULL;
    ENGINE *dec_e = dec == USE_ENGINE ? temp_args->e : NULL;
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
    unsigned char tag[POLY1305_DIGEST_SIZE] = { 0 };
    unsigned char *dec_cipher = NULL;

    int ciphertext_len = 0;
    int tmpout_len = 0;
    int dec_cipher_len = 0;
    int plaintext_len = size;

    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER_CTX *dec_ctx = NULL;

    if (input == NULL) {
        fprintf(stderr,"# FAIL: [%s] --- Initial parameters malloc failed ! \n",
                            __func__);
        exit(EXIT_FAILURE);
    }

    /* Set input data */
    for (i = 0; i < size; i++)
        input[i] = i % 16;

    if (print_output)
        tests_hexdump("CHACHAPOLY: input message", input, size);

    /* Create context for encrypt operation */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_CIPHER_CTX_new() failed for ctx\n",
                             __func__);
        goto err;
    }

    /* Initialize encryption context for aes-gcm-128 */
    ret = EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), enc_e, NULL, NULL);
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_EncryptInit_ex() failed: ret %d\n",
                            __func__, ret);
        goto err;
    }

    /* Set IV length other than the default 12 bytes but QAT Engine supports
     * only 12 bytes.
     * Optional - The default is 12 bytes according to the TLS spec. */
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(_ivec), NULL);
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_CIPHER_CTX_ctrl() failed: ret %d\n",
                            __func__, ret);
        goto err;
    }

    /* Initialise the aes-gcm-128 encryption context with 16-byte key and 12-byte IV. */
    ret = EVP_EncryptInit_ex(ctx, NULL, enc_e, _key32, _ivec);
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_EncryptInit_ex() failed: ret %d\n",
                            __func__, ret);
        goto err;
    }

    /* Pass AAD to the encryption context before encrypting the input plaintext. */
    ret = EVP_EncryptUpdate(ctx, NULL, &tmpout_len, aad, sizeof(aad));
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_EncryptUpdate() failed when adding aad: ret %d\n",
                           __func__, ret);
        goto err;
    }
    plaintext_len += POLY1305_DIGEST_SIZE;
    plaintext = OPENSSL_malloc(plaintext_len);
    if (plaintext == NULL) {
	INFO("# FAIL: [%s] --- malloc failed for plaintext! \n", __func__);
	goto err;
    }
    ciphertext = plaintext;

    memcpy(plaintext, input, size);

    /* Encrypt the input plaintext. */
    ret = EVP_EncryptUpdate(ctx, ciphertext, &tmpout_len, plaintext, size);
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_EncryptUpdate() failed for inputtext: ret %d\n",
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
        fprintf(stderr,"# FAIL: [%s] --- EVP_EncryptFinal_ex() failed for ciphertext: ret %d\n",
                __func__, ret);
        goto err;
    }
    ciphertext_len += tmpout_len;

    if (print_output)
        tests_hexdump("CHACHAPOLY ciphertext:", ciphertext, ciphertext_len);

    /* Retrieve the 16 byte tag */
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, POLY1305_DIGEST_SIZE, tag);
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_CIPHER_CTX_ctrl() failed for tag: ret %d\n",
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
        fprintf(stderr,"# FAIL: [%s] --- EVP_CIPHER_CTX_new() failed for dec_ctx\n",
                            __func__);
        goto err;
    }

    /* Initialize decryption context for aes-gcm-128 */
    ret = EVP_DecryptInit_ex(dec_ctx, EVP_chacha20_poly1305(), dec_e, NULL, NULL);
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_DecryptInit_ex() failed: ret %d\n",
                            __func__, ret);
        goto err;
    }

    /* Set IV length other than the default 12 bytes but QAT Engine supports
     * only 12 bytes.
     * Optional - The default is 12 bytes according to the TLS spec. */
    ret = EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(_ivec), NULL);
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_CIPHER_CTX_ctrl() failed: ret %d\n",
                            __func__, ret);
        goto err;
    }

    /* Initialise the aes-gcm-128 decryption context with 16-byte key and 12-byte IV. */
    ret = EVP_DecryptInit_ex(dec_ctx, NULL, dec_e, _key32, _ivec);
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_DecryptInit_ex() failed: ret %d\n",
                            __func__, ret);
        goto err;
    }

    /* QAT engine reads tag before starting the decrypt operation whereas
     * SW engine performs the decrypt op first and then reads the tag. */
    ret = EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_AEAD_SET_TAG,
                              POLY1305_DIGEST_SIZE, tag);
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_CIPHER_CTX_ctrl() failed while setting the tag: ret %d\n",
                __func__, ret);
        goto err;
    }

    /* AAD is passed to EVP_DecryptUpdate() with output buffer set to NULL */
    ret = EVP_DecryptUpdate(dec_ctx, NULL, &tmpout_len, aad, sizeof(aad));
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_DecryptUpdate() failed when adding aad: ret %d\n",
                            __func__, ret);
        goto err;
    }
    dec_cipher = ciphertext;

    /* Decrypt the ciphertext */
    ret = EVP_DecryptUpdate(dec_ctx, dec_cipher, &tmpout_len, ciphertext,
                            ciphertext_len);
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_DecryptUpdate() failed when decrypting ciphertext: ret %d\n",
                            __func__, ret);
        goto err;
    }
    else
        dec_cipher_len = tmpout_len;

    ret = EVP_DecryptFinal_ex(dec_ctx, dec_cipher + tmpout_len, &tmpout_len);
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_DecryptFinal_ex() failed for ciphertext: ret %d\n",
                __func__, ret);
        goto err;
    }
    dec_cipher_len += tmpout_len;

    if (print_output)
        tests_hexdump("CHACHAPOLY tag:", tag, POLY1305_DIGEST_SIZE);

    if (print_output)
        tests_hexdump("CHACHAPOLY decrypted plaintext:", dec_cipher,
                          dec_cipher_len);

    /* Compare and verify the decrypt and encrypt message. */
    if (verify) {
        if (memcmp(dec_cipher, plaintext, size)) {
            fprintf(stderr,"# FAIL verify for CHACHAPOLY update\n");
            ret = 0;

            tests_hexdump("CHACHAPOLY actual  :", dec_cipher, dec_cipher_len);
            tests_hexdump("CHACHAPOLY expected:", plaintext, size);
        }
        else
            fprintf(stderr,"# PASS verify for CHACHAPOLY update\n");
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

static int run_chachapoly_tls(void *args, int enc, int dec)
{
    TEST_PARAMS *temp_args = (TEST_PARAMS *)args;
    ENGINE *enc_e = enc == USE_ENGINE ? temp_args->e : NULL;
    ENGINE *dec_e = dec == USE_ENGINE ? temp_args->e : NULL;
    int size = temp_args->size;
    int print_output = temp_args->print_output;
    int verify = temp_args->verify;
    int i;
    int ret = 0;
    unsigned char length_byte1_tls_enc = size >> 8;
    unsigned char length_byte2_tls_enc = size |16 >> 8;
    unsigned char tls_enc_virt_hdr[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x16, 0x03, 0x01, length_byte1_tls_enc, length_byte2_tls_enc
    };

    unsigned char length_byte1_tls_dec = (size + POLY1305_DIGEST_SIZE) >> 8;
    unsigned char length_byte2_tls_dec = (size + POLY1305_DIGEST_SIZE) |16 >> 8;
    unsigned char tls_dec_virt_hdr[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x16, 0x03, 0x01, length_byte1_tls_dec, length_byte2_tls_dec
    };

    unsigned char *input = OPENSSL_malloc(size);
    unsigned char *plaintext = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char tag[POLY1305_DIGEST_SIZE] = { 0 };
    unsigned char *dec_cipher = NULL;

    int ciphertext_len = 0;
    int tmpout_len = 0;
    int dec_cipher_len = 0;
    int plaintext_len = size;

    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER_CTX *dec_ctx = NULL;

    if (input == NULL) {
        fprintf(stderr,"# FAIL: [%s] --- Initial parameters malloc failed ! \n",
                           __func__);
        exit(EXIT_FAILURE);
    }

    /* Set the plaintext input data.
     * This is a copy of the plaintext that will be used to check the
     * decrypted message. Original plaintext is destroyed in TLS case. */
    for (i = 0; i < size; i++)
        input[i] = i % 16;

    if (print_output)
        tests_hexdump("CHACHA20-POLY1305: input message", input, size);

    /* Create a new context for the TLS encrypt operation */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_CIPHER_CTX_new() failed for ctx\n",
                            __func__);
        exit(EXIT_FAILURE);
    }

    /* IV used in the initialization of the cipher: in TLS case it is set
     * using ctrl() instead of EncryptInit_ex(). */
    ret = EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), enc_e, _key32, _ivec);
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_EncryptInit_ex() failed: ret %d\n",
                            __func__, ret);
        goto err;
    }

    /* Provide the AAD as in the TLS stack of OpenSSL */
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD,
                              sizeof(tls_enc_virt_hdr),
                              tls_enc_virt_hdr);
    if (ret != POLY1305_DIGEST_SIZE) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_CIPHER_CTX_ctrl() failed for setting aad: ret %d\n", __func__, ret);
        goto err;
    }

    /* In TLS case the explicit IV must be prepended to the plaintext
     * and there must be space to save the tag at the end of the buffer.
     */
    plaintext_len += POLY1305_DIGEST_SIZE;

    plaintext = OPENSSL_malloc(plaintext_len);
    if (plaintext == NULL) {
        fprintf(stderr,"# FAIL: [%s] --- malloc failed for plaintext! \n",
                           __func__);
        goto err;
    }

    memcpy(plaintext, input, size);

    /* TLS case works only inplace */
    ciphertext = plaintext;

    /* TLS Decrypt operation */
    ret = EVP_EncryptUpdate(ctx, ciphertext, &tmpout_len, plaintext,
                            plaintext_len);
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_EncryptUpdate() failed for inputtext: ret %d\n", __func__, ret);
        goto err;
    }
    else
        ciphertext_len = tmpout_len;

    if (print_output)
        tests_hexdump("CHACHA20-POLY1305 ciphertext:", ciphertext, ciphertext_len);

    /* The tag is contained in the last POLY1305_DIGEST_SIZE Bytes of the payload */
    memcpy(tag, ciphertext + size,
           POLY1305_DIGEST_SIZE);

    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    tmpout_len = 0;

/*----------------------- Decryption ------------------------ */

    /* Create context for TLS decrypt */
    dec_ctx = EVP_CIPHER_CTX_new();
    if (dec_ctx == NULL) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_CIPHER_CTX_new() failed for dec_ctx\n", __func__);
        exit(EXIT_FAILURE);
    }

    /* Initialise the context for decryption with 16-byte key and 12-byte IV. */
    ret = EVP_DecryptInit_ex(dec_ctx, EVP_chacha20_poly1305(), dec_e, _key32, _ivec);
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_DecryptInit_ex() failed: ret %d\n",
                            __func__, ret);
        goto err;
    }

    /* Provide the AAD as in the TLS stack of OpenSSL */
    ret = EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_AEAD_TLS1_AAD,
                              sizeof(tls_dec_virt_hdr),
                              tls_dec_virt_hdr);
    if (ret != POLY1305_DIGEST_SIZE) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_CIPHER_CTX_ctrl() failed for setting aad: ret %d\n", __func__, ret);
        goto err;
    }

    /* TLS case works only inplace */
    dec_cipher = ciphertext;

    /* TLS Decrypt operation */
    ret = EVP_DecryptUpdate(dec_ctx, dec_cipher, &dec_cipher_len, ciphertext,
                            ciphertext_len);
    if (ret != 1) {
        fprintf(stderr,"# FAIL: [%s] --- EVP_DecryptUpdate() failed when decrypting ciphertext: ret %d\n", __func__, ret);
        goto err;
    }

    if (print_output)
        tests_hexdump("CHACHA20-POLY1305 tag:", tag, POLY1305_DIGEST_SIZE);

    if (print_output)
        tests_hexdump("CHACHA20-POLY1305 decrypted plaintext:", dec_cipher,
                       dec_cipher_len);

    /* Compare and verify the decrypt and encrypt message. */
    if (verify) {
        if (memcmp(dec_cipher, input, size)) {
            fprintf(stderr,"# FAIL verify for TLS CHACHA20-POLY1305\n");
            ret = 0;

            tests_hexdump("CHACHA20-POLY1305 actual  :", dec_cipher, size);
            tests_hexdump("CHACHA20-POLY1305 expected:", plaintext, size);
        }
        else
            fprintf(stderr,"# PASS verify for TLS CHACHA20-POLY1305\n");
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

static int test_chachapoly_update(void *args)
{
    run_chachapoly_update(args, USE_ENGINE, USE_ENGINE);
    run_chachapoly_update(args, USE_ENGINE, USE_SW);
    run_chachapoly_update(args, USE_SW, USE_ENGINE);
    run_chachapoly_update(args, USE_SW, USE_SW);

    return 1;
}

static int test_chachapoly_tls(void *args)
{
    run_chachapoly_tls(args, USE_ENGINE, USE_ENGINE);
    run_chachapoly_tls(args, USE_ENGINE, USE_SW);
    run_chachapoly_tls(args, USE_SW, USE_ENGINE);
    run_chachapoly_tls(args, USE_SW, USE_SW);

    return 1;
}

void tests_run_chacha20_poly1305(TEST_PARAMS *args)
{
    args->additional_args = NULL;

    if (!args->enable_async) {
        test_chachapoly_update(args);
        test_chachapoly_tls(args);
    } else {
        start_async_job(args, test_chachapoly_update);
        start_async_job(args, test_chachapoly_tls);
    }
}
