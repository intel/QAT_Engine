/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2024 Intel Corporation.
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

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/async.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#ifdef QAT_OPENSSL_3
# include <openssl/core_names.h>
#endif

#include "tests.h"

#define ALGO_ENABLE_MASK_SM4                0x1000

extern char *sw_algo_bitmap;
extern char *hw_algo_bitmap;

#ifdef ENABLE_QAT_HW_SM4_CBC
#include <openssl/bio.h>
#include <openssl/tls1.h>

#include "../qat_utils.h"
#endif

#ifdef ENABLE_QAT_SW_SM4_CBC
/* Crypto_mb includes */
#include "crypto_mb/sm4.h"
#include "crypto_mb/cpu_features.h"
#endif

#ifdef ENABLE_QAT_SW_SM4_CBC
#define SM4_CBC_KEY_SIZE  (16)
#define SM4_CBC_IV_SIZE  (16)
#define MULTIBUFF_SM4_BATCH (16)
#endif

#ifdef ENABLE_QAT_HW_SM4_CBC
#define ENC             1
#define DEC             0
#define USE_ENGINE      1
#define USE_SW          0
#define NON_TLS         0
#define EVP_FAIL       -1

#define TLS_HDR_MODIFY_SEQ  0x01
#define NO_HMAC_KEY         0x02
#define NO_AAD              0x04
#define DEF_CFG             0x00

#define ENCRYPT_BUFF_ERROR      0
#define ENCRYPT_BUFF_IDENTICAL  1
#define ENCRYPT_BUFF_DIFFERENT  2

#define FAIL_MSG(fmt, args...)  WARN( "# FAIL " fmt, ##args)
#define FAIL_MSG_END(fmt, args...)  INFO( "# FAIL " fmt, ##args)
#define PASS_MSG(fmt, args...)  INFO( "# PASS " fmt, ##args)

/* AES key, 256 bits long */
static const unsigned char _key16[] = {
    0xEE, 0xE2, 0x7B, 0x5B, 0x10, 0xFD, 0xD2, 0x58,
    0x49, 0x77, 0xF1, 0x22, 0xD7, 0x1B, 0xA4, 0xCA};

/* Initialization vector */
static const unsigned char _ivec[] = {
    0x7E, 0x9B, 0x4C, 0x1D, 0x82, 0x4A, 0xC5, 0xDF,
    0x99, 0x4C, 0xA1, 0x44, 0xAA, 0x8D, 0x37, 0x27};

typedef struct _sm4_alg_info {
    int testtype;               /* Indicates the sm4 cipher algorithm */
    const EVP_CIPHER *(*pfunc) (void); /* function to get cipher object */
    const unsigned char *key;   /* Key to use for cipher op */
    const char *name;           /* Name to use in console messages */
} sm4_alg_info;

typedef struct _test_info_ {
    int bufsz;
    int count;
    ENGINE *e;
    sm4_alg_info *c;
} test_info;

static const sm4_alg_info alg_i[] = {
    {TEST_SM4_CBC, EVP_sm4_cbc, _key16, "SM4-CBC"},
};

/* get_alg_info:
 *      for a given testtype, returns the related info structure.
 */
static const sm4_alg_info *get_alg_info(int testtype)
{
    const int num = sizeof(alg_i) / sizeof(sm4_alg_info);
    int i;

    for (i = 0; i < num; i++) {
        if (alg_i[i].testtype == testtype)
            return &alg_i[i];
    }

    return NULL;
}

/*
 * set_pkt_threshold:
 *      Set the small packet threshold value for given cipher.
 *      Buffers with size greater than the threshold value are
 *      offloaded to QAT engine for processing.
 */
static inline int set_pkt_threshold(ENGINE *e, const char* cipher, int thr)
{
    char thr_str[128];
    int ret = 0;
    snprintf(thr_str, 128, "%s:%d", cipher, thr);
    ret = ENGINE_ctrl_cmd(e, "SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD",
                          0, (void *)thr_str, NULL, 0);
    if (ret != 1)
        FAIL_MSG("Failed to set threshold %d for cipher %s\n", thr, cipher);

    return ret;
}

/*
 *  setup_ctx:
 *      Setup cipher context ready to be used in a cipher operation.
 *      It also sets up additional information required i.e. tls headers.
 */
static EVP_CIPHER_CTX *setup_ctx(const test_info *t, int enc, int e)
{
    EVP_CIPHER_CTX *ctx = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return NULL;

    if (EVP_CipherInit_ex(ctx, t->c->pfunc(),
                          e == USE_ENGINE ? t->e : NULL,
                          t->c->key,
                          _ivec, enc) != 1)
        goto err;

    return ctx;

 err:
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
}

/*
 * perform_op:
 *      performs the following operations:
 *          1. Allocate buffers for input and output.
 *          2. Populate input buffer with sample data.
 *          3. Perform cipher operation (populates output buffer)
 *          4. Convey result, numbytes operated and allocated buffers
 */
static int perform_op(EVP_CIPHER_CTX *ctx, unsigned char **in,
                      unsigned char **out, unsigned int size,
                      int *nbytes)
{
    int s, i;
    int ret = 0;
    unsigned char *inb = NULL;
    unsigned char *outb = NULL;

    int enc = EVP_CIPHER_CTX_encrypting(ctx);

    if (in == NULL || out == NULL || nbytes == NULL)
        return 0;

    *nbytes = 0;

    /* Allocate and fill src buffer if encrypting */
    if (enc == 1 && *in == NULL) {
        *in = inb = OPENSSL_malloc(size);
        if (inb == NULL)
            return 0;

        /* setup input message values */
        for (i = 0; i < size; i++)
            inb[i] = i % 16;
    } else {
        /* Decrypt the src buffer contents */
        inb = *in;
    }

    if (*out == NULL) {
        *out = outb = inb;
        if (outb == NULL)
            goto err;
    } else {
        outb = *out;
    }

    /* perform the operation */
    s = EVP_CipherUpdate(ctx, outb, nbytes, inb, size);
    if (s != 1) {
        ret = EVP_FAIL;
        goto err;
    }

    return 1;

 err:
    return ret;
}

/*
 * encrypt_buff :
 *      For a given TLS version, allocate and encrypt
 *      buffer. Return pointers to buffers along with
 *      number of bytes encrypted and ivlen used.
 */
static int encrypt_buff(const test_info *t, int impl,
                        unsigned char **buf, unsigned char **encbuf,
                        int *num_encbytes, unsigned int *ivlen)
{
    int ret = 0;
    int size = t->bufsz;
    char msgstr[128];
    EVP_CIPHER_CTX *ctx = NULL;

    ctx = setup_ctx(t, ENC, impl);

    if (ctx == NULL) {
        FAIL_MSG("%s failed to setup enc context\n", msgstr);
        return -1;
    }

    ret = perform_op(ctx, buf, encbuf, size, num_encbytes);

    if (ret == 1 && *num_encbytes != size)
        printf("%s: nbytes %d != outl %d\n", msgstr, *num_encbytes, size);

    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

/*
 * decrypt_buff :
 *      Given a pointer to encrypted buffer encbuf, decrypt using
 *      implementation as specified by impl.
 */
static int decrypt_buff(const test_info *t, int impl, unsigned char **encbuf,
                        unsigned char **decbuf, int len)
{
    int ret = 0;
    int num_decbytes = 0;
#if defined(QAT_WARN) || defined(QAT_DEBUG)
    char msgstr[128];
#endif
    EVP_CIPHER_CTX *ctx = NULL;

    ctx = setup_ctx(t, DEC, impl);

    if (ctx == NULL) {
        FAIL_MSG("%s failed to setup dec context\n", msgstr);
        return -1;
    }

    ret = perform_op(ctx, encbuf, decbuf, len, &num_decbytes);

    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * encrypt_and_compare :
 *      Encrypt a test buffer using engine and openssl sw
 *      implementation. Compare the output and return
 *      ENCRYPT_BUFF_ERROR : Error
 *      ENCRYPT_BUFF_IDENTICAL : ENC buffers are byte identical
 *      ENCRYPT_BUFF_DIFFERENT : ENC buffers not byte identical
 *                               for first ivlen bytes and engine
 *                               enc buffer has explicit IV as plain text.
 */
static int encrypt_and_compare(const test_info *t, int *buflen)
{
    int ret = ENCRYPT_BUFF_ERROR;
    unsigned char *textbuf = NULL;
    unsigned char *eng_buf = NULL;
    unsigned char *sw_buf = NULL;
    int eng_opbytes, sw_opbytes;
    unsigned int ivlen = 0;

    if ( t == NULL || buflen == NULL)
        return ret;

    *buflen = 0;

    if (encrypt_buff(t, USE_ENGINE, &textbuf, &eng_buf,
                     &eng_opbytes, &ivlen) != 1) {
        FAIL_MSG("%s: failed to perform Encryption using Engine!\n",
                 __func__);
        goto err;
    }

    if (encrypt_buff(t, USE_SW, &textbuf, &sw_buf, &sw_opbytes, &ivlen) != 1) {
        FAIL_MSG("%s: failed to perform Encryption using SW!\n",
                 __func__);
        goto err;
    }

    if (eng_opbytes != sw_opbytes) {
        FAIL_MSG("%s: Num Encrypted bytes Engine[%d] != SW[%d]\n",
                 __func__, eng_opbytes, sw_opbytes);
        goto err;
    }

    *buflen = eng_opbytes;

    /*
     * OpenSSL SW implementation encrypts the Explicit IV and PAYLOAD
     * using the IV placed in CTX which may or maynot be explicit IV.
     * whereas QAT engine encrypts the PAYLOAD alone using the
     * Explicit IV. Hence the encrypted bytes differ.
     * This is true for TLS >= 1.1
     */
    if (!memcmp(eng_buf, sw_buf, eng_opbytes)) {
        /* the buffers are byte identical for entire length */
        ret = ENCRYPT_BUFF_IDENTICAL;
    } else {
        /*
         * explicit IV encoded is byte identical but encrypted payload is
         * different. This is an error condition.
         */
        FAIL_MSG("[%s:%s]verify failed  for ENGINE and SW Encrypt",
                 __func__, t->c->name);
        tests_hexdump("SM4-CBC ENGINE  :", eng_buf, eng_opbytes);
        tests_hexdump("SM4-CBC SW:", sw_buf, eng_opbytes);
        ret = ENCRYPT_BUFF_ERROR;
    }

 err:
    OPENSSL_free(textbuf);
    return ret;
}

/*
 * test_crypto_op :
 *      test chained ciphers crypto operation.
 *      depending on the enc_imp/dec_imp, use either a engine or
 *      software implementation to perform encryption/decryption.
 *      if DEC_imp(ENC_imp(text)) = text, then report success else
 *      fail.
 */
static int test_crypto_op(const test_info *t, int enc_imp, int dec_imp)
{
    int ret = 0;
    unsigned int ivlen = 0;
    int num_encbytes;
#if defined(QAT_WARN) || defined(QAT_DEBUG)
    char msgstr[128];
#endif
    unsigned char *textbuf = NULL;
    unsigned char *encbuf = NULL;
    unsigned char *decbuf = NULL;

    /* Get an encrypted buffer along with it's plain text */
    ret = encrypt_buff(t, enc_imp, &textbuf, &encbuf, &num_encbytes, &ivlen);
    if (ret != 1) {
        FAIL_MSG("%s failed to perform Encryption!\n", msgstr);
        goto err;
    }

    /* Decrypt the encrypted buffer above and get decrpyted contents */
    ret = decrypt_buff(t, dec_imp, &encbuf, &decbuf, num_encbytes);
    if (ret != 1) {
        FAIL_MSG("%s failed to perform Decryption!\n", msgstr);
        goto err;
    }

    /* Compare and verify the decrypt and encrypt message. */
    if (memcmp(decbuf, textbuf, t->bufsz)) {
        FAIL_MSG("verify failed for %s", msgstr);
        tests_hexdump("SM4-CBC actual  :", decbuf , t->bufsz);
        tests_hexdump("SM4-CBC expected:", textbuf, t->bufsz);
        goto err;
    }

    ret = 1;

 err:
    OPENSSL_free(textbuf);
    return ret;
}

/*
 * test_multi_op :
 *          Perform the cipher operation multiple times with the same ctx.
 */
static int test_multi_op(const test_info *t)
{
    int ret = 0;
    int size = t->bufsz;
    char msgstr[128];
    int i = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *buf[6] = { NULL };
    unsigned char *ebuf[6] = { NULL };
    int num_encbytes[6] = { 0 };

    ctx = setup_ctx(t, ENC, USE_SW);
    if (ctx == NULL) {
        FAIL_MSG("%s failed to setup enc context\n", msgstr);
        return -1;
    }

    for (i = 0; i < 6; i++) {
        ret = perform_op(ctx, &buf[i], &ebuf[i], size,
                         &num_encbytes[i]);
        if (ret != 1) {
            FAIL_MSG("%s: Failed to encrypt %d time", msgstr, i);
            goto err;
        }

        if (ret == 1 && num_encbytes[i] != size)
            printf("%s[%d time]: nbytes %d != outl %d\n", msgstr, i,
                   num_encbytes[i], size);
    }

 err:
    EVP_CIPHER_CTX_free(ctx);
    for (i = 0; i < 6; i++) {
        OPENSSL_free(buf[i]);
    }
    return ret;
}

static int test_performance_encrypt(const test_info *t)
{
    int ret = 0;
    int size = t->bufsz;
    char msgstr[128];
    int i = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *buf = NULL;
    unsigned char *ebuf = NULL;
    int num_encbytes = 0;

    ctx = setup_ctx(t, ENC, USE_ENGINE);
    if (ctx == NULL) {
        FAIL_MSG("%s failed to setup enc context\n", msgstr);
        return -1;
    }

    for (i = 0; i < t->count; i++) {
        ret = perform_op(ctx, &buf, &ebuf, size,
                         &num_encbytes);
        if (ret != 1) {
            FAIL_MSG("%s: Failed to encrypt %d time", msgstr, i);
            goto err;
        }

        if (ret == 1 && num_encbytes != size)
            printf("%s[%d time]: nbytes %d != outl %d\n", msgstr, i,
                   num_encbytes, size);
    }

err:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_free(buf);
    OPENSSL_free(ebuf);
    return ret;
}

/*
 * test_encrpted_buffer :
 *      Encrypty buffer using ENGINE and Openssl SW
 *      implementation and check if they are byte identical.
 */
static int test_encrypted_buffer(const test_info *t)
{
    int ret = 0;
    int buflen = 0;

    ret = encrypt_and_compare(t, &buflen);

    if (ret == ENCRYPT_BUFF_IDENTICAL) {
        ret = 1;
    } else {
        FAIL_MSG("verify failed ENGINE and SW Encrypt"
                 " does match for %s\n", t->c->name);
    }

    return ret;
}

static int test_small_pkt_offload(const test_info *t)
{
    int ret = 0;
#if defined(QAT_WARN) || defined(QAT_DEBUG)
    int run = 0;
    char msgstr[128];
#endif
    int buflen = 0;
    int status = 0;

    /*
     * Engine was configured at the start of test run to offload all packets
     * to engine
     */
    ret = encrypt_and_compare(t, &buflen);
    /* Check if SW and Engine implementation are different and valid */
    if (ret != ENCRYPT_BUFF_IDENTICAL) {
        FAIL_MSG("%s encrypted buffers not identical status:%d run:%d\n",
                 msgstr, ret, ++run);
        return status;
    }

    /*
     * The threshold value is matched against the buffer length to decide
     * whether to offload the packet to engine or sw. The buffer length is
     * greater than the payload length as it also includes space for iv, hmac
     * and padding.
     * set threshold to the buflen.
     */
    ret = set_pkt_threshold(t->e, t->c->name, buflen);
    if (ret != 1)
        goto end;

    /*
     * As buffers greater than threshold size are offloaded to Qat engine,
     * the engine will use the software implementation for all buffers less than
     * or equal to threshold. As a result, encrypting via engine or through
     * software will create byte identical encrypted buffers.
     */
    ret = encrypt_and_compare(t, &buflen);
    /* check if SW and Engine implementation byte identical */
    if (ret != ENCRYPT_BUFF_IDENTICAL) {
        FAIL_MSG("%s Encrypted buffers not identical status:%d run:%d\n",
                 msgstr, ret, ++run);
        goto end;
    }

    /*
     * If negative values are send for threshold, the engine cntrl sets the
     * threshold back to zero. All buffers are then offloaded to qat.
     */
    ret = set_pkt_threshold(t->e, t->c->name, -312);
    if (ret != 1)
        goto end;
    ret = encrypt_and_compare(t, &buflen);
    if (ret != ENCRYPT_BUFF_IDENTICAL) {
        FAIL_MSG("%s encrypted buffers not identical status:%d run:%d\n",
                 msgstr, ret, ++run);
        goto end;
    }

    /*
     * The upper limit for threshold values is 16384. If a value greater than
     * upper limit is provided, the threshold is set to 16384. No buffers are
     * then offloaded to the engine as the maximum size of TLS payload is 16384.
     */
    ret = set_pkt_threshold(t->e, t->c->name, 17000);
    if (ret != 1)
        goto end;
    ret = encrypt_and_compare(t, &buflen);
    if (ret != ENCRYPT_BUFF_IDENTICAL) {
        FAIL_MSG("%s Encrypted buffers not identical status:%d run:%d\n",
                 msgstr, ret, ++run);
        goto end;
    }

    status = 1;

end:
    /* Set the threshold back to 0 */
    set_pkt_threshold(t->e, t->c->name, 0);
    return status;
}


static int run_sm4_cbc(void *pointer)
{
    int cnt;
    int ret = 1;
    test_info ti;
    char msg[128];
    TEST_PARAMS *args = (TEST_PARAMS *) pointer;
    ti.bufsz = args->size;
    ti.count = *(args->count);

    if ((ti.c = (sm4_alg_info *) get_alg_info(args->type)) == NULL) {
        FAIL_MSG("Unknown Test Type %d ti.c %p\n", args->type, ti.c);
        return 0;
    }

    /*
     * If temp_args->explicit_engine is not set then set the
     * engine to NULL to allow fallback to software if
     * that engine under test does not support this operation.
     * This relies on the engine we are testing being
     * set as the default engine.
     */
    ti.e = args->e;

    if (ti.e) {
        EVP_CIPHER *cipher = (EVP_CIPHER *)ENGINE_get_cipher(ti.e, NID_sm4_cbc);
        /* Set Engine to NULL if this algorithm is disabled in configuration or
           disabled by the co-existence algorithm bitmap. */
        if (cipher == NULL || cipher == EVP_sm4_cbc())
            ti.e = NULL;
    }

    /*
     * For the qat engine, offload all packet sizes to engine
     * by setting the threshold sizes to 0 for the cipher under test.
     */
    if (ti.e != NULL) {
        ret = set_pkt_threshold(ti.e, ti.c->name, 0);
        /* Set engine to NULL as threshold will fail if NID not supported*/
        if (ret != 1) {
            return 0;
        }
    }

    if (args->performance)
        return test_performance_encrypt(&ti);
    
    /* If the inner run fails, abandon test */
    for (cnt = 0; ret && cnt < *(args->count); cnt++) {
        if (
            /*
            * Running the test with SW implementation to check if
            * the test logic is correct.
            */
            (test_crypto_op(&ti, USE_SW, USE_SW) != 1) ||
            ((ti.e != NULL) && (
                /* Perform these tests only if engine is present */
                (test_encrypted_buffer(&ti) != 1) ||
                (test_crypto_op(&ti, USE_ENGINE, USE_SW) != 1) ||
                (test_crypto_op(&ti, USE_SW, USE_ENGINE) != 1) ||
                (test_crypto_op(&ti, USE_ENGINE, USE_ENGINE) != 1) ||
                (test_multi_op(&ti) != 1) ||
                (test_small_pkt_offload(&ti) != 1)
                )
            )
            ) {
            ret = 0;
            break;
        }
    }

    if (args->verify) {
        if (ret == 0)
            FAIL_MSG_END("verify failed %s%s", ti.c->name,
                         cnt > 1 ? msg : "\n");
        else
            PASS_MSG("verify %s%s", ti.c->name, cnt > 1 ? msg : "\n");
    }

    /* Restore value to default */
    if (ti.e != NULL) {
        ret = set_pkt_threshold(ti.e, ti.c->name, 2048);
        if (ret != 1)
            return 0;
    }
    return ret;
}
#endif /* ENABLE_QAT_HW_SM4_CBC */

#ifdef ENABLE_QAT_SW_SM4_CBC
void tests_sm4_cbc_hexdump(const char *title, const unsigned char *s, int l)
{
#ifdef QAT_DEBUG
    int i = 0;

    printf("%s", title);

    for (i = 0; i < l; i++) {
        if ((i % 8) == 0)
            printf("\n        ");

        printf("0x%02X, ", s[i]);
    }

    printf("\n\n");
#endif
}

static int test_sm4_cbc_encrypt(int num_buffers, ENGINE *e, int *len,
                                int8u **engine_in, int8u **engine_out,
                                int8u **openssl_in, int8u **openssl_out,
                                int8u **mb_in, int8u **mb_out,
                                int8u **iv, sm4_key **key)
{
    mbx_sm4_key_schedule rkey;
    EVP_CIPHER_CTX *ctx[MULTIBUFF_SM4_BATCH];
    int outl;
    int ret = 1;
#ifdef QAT_OPENSSL_3
    OSSL_PARAM params[4] = {OSSL_PARAM_END, OSSL_PARAM_END,
                               OSSL_PARAM_END, OSSL_PARAM_END};
    unsigned int pad = 0;
    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &pad);
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "SM4-CBC", "");
    EVP_CIPHER *sw_cipher = EVP_CIPHER_fetch(NULL, "SM4-CBC", "provider=default");
#endif

    /* Use Engine to do the encryption. */
    for (int i = 0; i < num_buffers; i++) {
        ctx[i] = EVP_CIPHER_CTX_new();
#ifdef QAT_OPENSSL_3
        if (e == NULL)
            EVP_CipherInit_ex2(ctx[i], cipher, (int8u*)key[i], iv[i], 1, params);
        else
#endif
            EVP_EncryptInit_ex(ctx[i], EVP_sm4_cbc(), e, (int8u*)key[i], iv[i]);
    }

    for (int i = 0; i < num_buffers; i++) {
        EVP_EncryptUpdate(ctx[i], engine_out[i], &outl, engine_in[i], len[i]);
    }

    for (int i = 0; i < num_buffers; i++) {
        EVP_EncryptFinal(ctx[i], engine_out[i] + len[i], &outl);
        EVP_CIPHER_CTX_free(ctx[i]);
    }

    /* OpenSSL and crypto_mb are used as reference */
    for (int i = 0; i < num_buffers; i++) {
        ctx[i] = EVP_CIPHER_CTX_new();
#ifdef QAT_OPENSSL_3
	params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &pad);
        EVP_CipherInit_ex2(ctx[i], sw_cipher, (int8u*)key[i], iv[i], 1, NULL);
#else
        EVP_EncryptInit(ctx[i], EVP_sm4_cbc(), (int8u*)key[i], iv[i]);
#endif
        EVP_EncryptUpdate(ctx[i], openssl_out[i], &outl, openssl_in[i], len[i]);
        EVP_EncryptFinal(ctx[i], openssl_out[i] + len[i], &outl);
        EVP_CIPHER_CTX_free(ctx[i]);
    }

    /* crypto_mb encryption */
    mbx_sm4_set_key_mb16(&rkey, (const sm4_key**)key);
    mbx_sm4_encrypt_cbc_mb16(mb_out, (const int8u**)mb_in, (const int*)len, &rkey, (const int8u**)iv);

    /* Comparison with OpenSSL and crypto_mb */
    for (int i = 0; i < num_buffers; i++) {
        tests_sm4_cbc_hexdump("mb_enc_txt", mb_out[i], len[i]);
        tests_sm4_cbc_hexdump("openssl_enc_txt", openssl_out[i], len[i]);
        tests_sm4_cbc_hexdump("engine_enc_txt", engine_out[i], len[i]);
        if (memcmp(mb_out[i], openssl_out[i], len[i])) {
            ret = 0;
            printf("encryption: openssl_sw vs crypto_mb, not matched\n");
        }
        if (memcmp(mb_out[i], engine_out[i], len[i])) {
            ret = 0;
            printf("encryption: engine vs crypto_mb, not matched\n");
        }
        if (memcmp(openssl_out[i], engine_out[i], len[i])) {
            ret = 0;
            printf("encryption: engine vs openssl_sw, not matched\n");
        }
    }

    if (ret)
        printf("encryption test successful\n");
#ifdef QAT_OPENSSL_3
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_free(sw_cipher);
#endif
    return ret;
}

static int test_sm4_cbc_decrypt(int num_buffers, ENGINE *e, int *len,
                                int8u **engine_in, int8u **engine_out,
                                int8u **openssl_in, int8u **openssl_out,
                                int8u **mb_in, int8u **mb_out,
                                int8u **iv, sm4_key **key)
{
    mbx_sm4_key_schedule rkey;
    EVP_CIPHER_CTX *ctx[MULTIBUFF_SM4_BATCH];
    int outl;
    int ret = 1;
#ifdef QAT_OPENSSL_3
    OSSL_PARAM params[4] = {OSSL_PARAM_END, OSSL_PARAM_END,
                               OSSL_PARAM_END, OSSL_PARAM_END};
    unsigned int pad = 0;
    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &pad);
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "SM4-CBC", "");
    EVP_CIPHER *sw_cipher = EVP_CIPHER_fetch(NULL, "SM4-CBC", "provider=default");
#endif
    /* Use Engine to do the decryption. */
    for (int i = 0; i < num_buffers; i++) {
        ctx[i] = EVP_CIPHER_CTX_new();
#ifdef QAT_OPENSSL_3
        if (e == NULL)
            EVP_CipherInit_ex2(ctx[i], cipher, (int8u*)key[i], iv[i], 0, params);
	else
#endif
            EVP_DecryptInit_ex(ctx[i], EVP_sm4_cbc(), e, (int8u*)key[i], iv[i]);
    }

    for (int i = 0; i < num_buffers; i++) {
        EVP_DecryptUpdate(ctx[i], engine_out[i], &outl, engine_in[i], len[i]);
    }

    for (int i = 0; i < num_buffers; i++) {
        EVP_DecryptFinal(ctx[i], engine_out[i] + len[i], &outl);
        EVP_CIPHER_CTX_free(ctx[i]);
    }

    /* OpenSSL and crypto_mb are used as reference */
    for (int i = 0; i < num_buffers; i++) {
        ctx[i] = EVP_CIPHER_CTX_new();
#ifdef QAT_OPENSSL_3
        EVP_CipherInit_ex2(ctx[i], sw_cipher, (int8u*)key[i], iv[i], 0, params);
#else
        EVP_DecryptInit(ctx[i], EVP_sm4_cbc(), (int8u*)key[i], iv[i]);
#endif
        EVP_DecryptUpdate(ctx[i], openssl_out[i], &outl, openssl_in[i], len[i]);
        EVP_DecryptFinal(ctx[i], openssl_out[i] + len[i], &outl);
        EVP_CIPHER_CTX_free(ctx[i]);
    }

    /* crypto_mb decryption */
    mbx_sm4_set_key_mb16(&rkey, (const sm4_key**)key);
    mbx_sm4_decrypt_cbc_mb16(mb_out, (const int8u**)mb_in, (const int*)len, &rkey, (const int8u**)iv);

    /* Comparison with OpenSSL and crypto_mb */
    for (int i = 0; i < num_buffers; i++) {
        tests_sm4_cbc_hexdump("mb_dec_txt", mb_out[i], len[i]);
        tests_sm4_cbc_hexdump("openssl_dec_txt", openssl_out[i], len[i]);
        tests_sm4_cbc_hexdump("engine_dec_txt", engine_out[i], len[i]);
        if (memcmp(mb_out[i], openssl_out[i], len[i])) {
            ret = 0;
            printf("decryption: openssl_sw vs crypto_mb, not matched\n");
        }
        if (memcmp(mb_out[i], engine_out[i], len[i])) {
            ret = 0;
            printf("decryption: engine vs crypto_mb, not matched\n");
        }
        if (memcmp(openssl_out[i], engine_out[i], len[i])) {
            ret = 0;
            printf("decryption: engine vs openssl_sw, not matched\n");
        }
    }

    if (ret)
        printf("decryption test successful\n");
#ifdef QAT_OPENSSL_3
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_free(sw_cipher);
#endif
    return ret;
}

static int test_sm4_cbc(ENGINE *e, int count, int size)
{
    int      len[MULTIBUFF_SM4_BATCH];
    int8u*   mb_txt[MULTIBUFF_SM4_BATCH];
    int8u*   mb_enc_txt[MULTIBUFF_SM4_BATCH];
    int8u*   mb_dec_txt[MULTIBUFF_SM4_BATCH];
    int8u*   mb_iv[MULTIBUFF_SM4_BATCH];
    sm4_key* mb_key[MULTIBUFF_SM4_BATCH];

    int8u* engine_enc_txt[MULTIBUFF_SM4_BATCH];
    int8u* engine_dec_txt[MULTIBUFF_SM4_BATCH];
    int8u* openssl_enc_txt[MULTIBUFF_SM4_BATCH];
    int8u* openssl_dec_txt[MULTIBUFF_SM4_BATCH];

    int num_buffers = MULTIBUFF_SM4_BATCH;
    int ret = 1;

    printf("\nStart %d round test, size: %d\n", count, size);

    /* Init random data for testing */
    for (int i = 0; i < num_buffers; i++) {
        len[i] = size;
        mb_key[i] = (sm4_key*)OPENSSL_zalloc(SM4_CBC_KEY_SIZE);
        mb_enc_txt[i] = (int8u*)OPENSSL_zalloc(len[i]);
        mb_dec_txt[i] = (int8u*)OPENSSL_zalloc(len[i]);
        mb_txt[i] = (int8u*)OPENSSL_zalloc(len[i]);
        mb_iv[i] = (int8u*)OPENSSL_zalloc(SM4_CBC_IV_SIZE);

        engine_enc_txt[i] = OPENSSL_zalloc(len[i] + SM4_CBC_KEY_SIZE);
        engine_dec_txt[i] = OPENSSL_zalloc(len[i] + SM4_CBC_KEY_SIZE);
        openssl_enc_txt[i] = OPENSSL_zalloc(len[i] + SM4_CBC_KEY_SIZE);
        openssl_dec_txt[i] = OPENSSL_zalloc(len[i] + SM4_CBC_KEY_SIZE);

        RAND_bytes(*mb_key[i], SM4_CBC_KEY_SIZE);
        RAND_bytes(mb_txt[i], len[i]);
        RAND_bytes(mb_iv[i], SM4_CBC_IV_SIZE);

        tests_sm4_cbc_hexdump("mb_key", *mb_key[i], SM4_CBC_KEY_SIZE);
        tests_sm4_cbc_hexdump("mb_txt", mb_txt[i], len[i]);
        tests_sm4_cbc_hexdump("mb_iv", mb_iv[i], SM4_CBC_IV_SIZE);
    }

    /* out-of-place operation */
    printf("out-of-place operation tests: \n");

    /* Encryption */
    if (!test_sm4_cbc_encrypt(num_buffers, e, len,
                                mb_txt, engine_enc_txt,
                                mb_txt, openssl_enc_txt,
                                mb_txt, mb_enc_txt,
                                mb_iv, mb_key)) {
        ret = 0;
    }

    /* Decryption */
    if (!test_sm4_cbc_decrypt(num_buffers, e, len,
                                engine_enc_txt, engine_dec_txt,
                                openssl_enc_txt, openssl_dec_txt,
                                mb_enc_txt, mb_dec_txt,
                                mb_iv, mb_key)) {
        ret = 0;
    }

if (ret)
    printf("out-of-place tests are successful\n");
else {
    printf("out-of-place tests failed\n");
}

    /* in-place operation */
    printf("\nin-place operation tests: \n");

    /* Encryption */
    for (int i = 0; i < num_buffers; i++) {
        memset(engine_enc_txt[i], 0, len[i] + SM4_CBC_KEY_SIZE);
        memcpy(engine_enc_txt[i], mb_txt[i], len[i]);
        memset(openssl_enc_txt[i], 0, len[i] + SM4_CBC_KEY_SIZE);
        memcpy(openssl_enc_txt[i], mb_txt[i], len[i]);
        memcpy(mb_enc_txt[i], mb_txt[i], len[i]);
    }
    if (!test_sm4_cbc_encrypt(num_buffers, e, len,
                                engine_enc_txt, engine_enc_txt,
                                openssl_enc_txt, openssl_enc_txt,
                                mb_enc_txt, mb_enc_txt,
                                mb_iv, mb_key)) {
        ret = 0;
    }

    /* Decryption */
    for (int i = 0; i < num_buffers; i++) {
        memset(engine_dec_txt[i], 0, len[i] + SM4_CBC_KEY_SIZE);
        memcpy(engine_dec_txt[i], engine_enc_txt[i], len[i]);
        memset(openssl_dec_txt[i], 0, len[i] + SM4_CBC_KEY_SIZE);
        memcpy(openssl_dec_txt[i], openssl_enc_txt[i], len[i]);
        memcpy(mb_dec_txt[i], mb_enc_txt[i], len[i]);
    }
    if (!test_sm4_cbc_decrypt(num_buffers, e, len,
                                engine_dec_txt, engine_dec_txt,
                                openssl_dec_txt, openssl_dec_txt,
                                mb_dec_txt, mb_dec_txt,
                                mb_iv, mb_key)) {
        ret = 0;
    }

    if (ret)
        printf("in-place tests are successful\n");
    else {
        printf("in-place tests failed\n");
    }

    /* Free memory */
    for (int i = 0; i < num_buffers; i++) {
        if (openssl_enc_txt[i])
            OPENSSL_free(openssl_enc_txt[i]);
        if (openssl_dec_txt[i])
            OPENSSL_free(openssl_dec_txt[i]);
        if (engine_enc_txt[i])
            OPENSSL_free(engine_enc_txt[i]);
        if (engine_dec_txt[i])
            OPENSSL_free(engine_dec_txt[i]);
        if (mb_enc_txt[i])
            OPENSSL_free(mb_enc_txt[i]);
        if (mb_dec_txt[i])
            OPENSSL_free(mb_dec_txt[i]);
        if (mb_txt[i])
            OPENSSL_free(mb_txt[i]);
        if (mb_iv[i])
            OPENSSL_free(mb_iv[i]);
        if (mb_key[i])
            OPENSSL_free(mb_key[i]);
    }

    return ret;
}

/* message length list for test */
static const int test_size[] = { 16, 64, 256, 1024, 2048, 4096, 8192, 16384 };

static int run_sm4_cbc_msg(void *args)
{
    TEST_PARAMS *temp_args = (TEST_PARAMS *)args;
    int count = *(temp_args->count);
    int ns = sizeof(test_size)/ sizeof(int);
    int i = 0, cnt = 0;
    int ret = 1;

    /* If temp_args->explicit_engine is not set then set the
       engine to NULL to allow fallback to software if
       that engine under test does not support this operation.
       This relies on the engine we are testing being
       set as the default engine. */
#ifndef QAT_OPENSSL_PROVIDER
    ENGINE *e = temp_args->e;
#else
    ENGINE *e = NULL;
#endif


    /* If the inner run fails, abandon test */
    for (cnt = 0; ret && cnt < count; cnt++) {
        for (i = 0; i < ns; i++) {
            ret = test_sm4_cbc(e, cnt, test_size[i]);
        }
    }

    if (ret)
        printf("\nAll tests passed\n");

    return ret;
}
#endif /* ENABLE_QAT_SW_SM4_CBC */

/******************************************************************************
* function:
*   tests_run_sm4_cbc (TEST_PARAMS *args)
*
* @param args [IN] - the test parameters
*
* Description:
*   This function is designed to test the QAT engine with all message sizes
*   using the SM4_CBC algorithm. The higher level EVP interface function
*   EVP_Encrypt*() and EVP_Decrypt*() are used inside of test application.
*   This is a boundary test, the application should return the expected cipher value.
******************************************************************************/
void tests_run_sm4_cbc(TEST_PARAMS *args)
{
    args->additional_args = NULL;

#if (defined ENABLE_QAT_SW_SM4_CBC) && (defined ENABLE_QAT_HW_SM4_CBC)
    int sw_bitmap = strtol(sw_algo_bitmap, NULL, 16);
    int hw_bitmap = strtol(hw_algo_bitmap, NULL, 16);

    if(((hw_bitmap & ALGO_ENABLE_MASK_SM4) == 0)
        && ((sw_bitmap & ALGO_ENABLE_MASK_SM4) != 0)) {
        if (!args->enable_async)
            run_sm4_cbc_msg(args);
        else
            start_async_job(args, run_sm4_cbc_msg);
    } else {
        if (!args->enable_async)
            run_sm4_cbc(args);
        else
            start_async_job(args, run_sm4_cbc);
    }
#endif

#if (defined ENABLE_QAT_SW_SM4_CBC) && (!defined ENABLE_QAT_HW_SM4_CBC)
        if (!args->enable_async)
            run_sm4_cbc_msg(args);
        else
            start_async_job(args, run_sm4_cbc_msg);
#endif

#if (defined ENABLE_QAT_HW_SM4_CBC) && (!defined ENABLE_QAT_SW_SM4_CBC)
    if (!args->enable_async)
        run_sm4_cbc(args);
    else
        start_async_job(args, run_sm4_cbc);
#endif
}
