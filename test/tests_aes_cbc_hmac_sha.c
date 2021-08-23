/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021 Intel Corporation.
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
#include <openssl/engine.h>
#include <openssl/tls1.h>

#include "tests.h"
#include "../qat_utils.h"

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

/* 32 bytes key */
static const unsigned char _key32[] = {
    0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
};

/* 16 bytes key */
static const unsigned char _key16[] = {
    0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
};

/* 16 bytes initial vector */
static unsigned char _ivec[] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42
};

static unsigned char _hmac_key[] = {
    0xAC, 0xAC, 0xAC, 0xAC, 0xAC, 0xAC, 0xAC, 0xAC,
    0xAC, 0xAC, 0xAC, 0xAC, 0xAC, 0xAC, 0xAC, 0xAC
};

/* TLS Version used to Test Chained Cipher.
 * 0 indicates NON-TLS use case.
 */
typedef struct _tls_v {
    int v;                      /* version */
    const char *v_str;          /* string format */
} tls_v;

static const tls_v test_tls[] = {
    {TLS1_VERSION, "TLS1.0"},
    {TLS1_1_VERSION, "TLS1.1"},
    {TLS1_2_VERSION, "TLS1.2"},
    {NON_TLS, "Non-TLS"}
};

typedef struct _chained_alg_info {
    int testtype;               /* Indicates the Chained cipher algorithm */
    const EVP_CIPHER *(*pfunc) (void); /* function to get cipher object */
    const unsigned char *key;   /* Key to use for cipher op */
    const char *name;           /* Name to use in console messages */
} chained_alg_info;

static const chained_alg_info alg_i[] = {
    {TEST_AES128_CBC_HMAC_SHA1, EVP_aes_128_cbc_hmac_sha1,
     _key16, "AES-128-CBC-HMAC-SHA1"},
    {TEST_AES256_CBC_HMAC_SHA1, EVP_aes_256_cbc_hmac_sha1,
     _key32, "AES-256-CBC-HMAC-SHA1"},
    {TEST_AES128_CBC_HMAC_SHA256, EVP_aes_128_cbc_hmac_sha256,
     _key16, "AES-128-CBC-HMAC-SHA256"},
    {TEST_AES256_CBC_HMAC_SHA256, EVP_aes_256_cbc_hmac_sha256,
     _key32, "AES-256-CBC-HMAC-SHA256"}
};

/* Structure to pass test information to functions */
typedef struct _test_info_ {
    int bufsz;
    int count;
    ENGINE *e;
    chained_alg_info *c;
    tls_v *tls;
} test_info;

/* get_alg_info:
 *      for a given testtype, returns the related info structure.
 */
static const chained_alg_info *get_alg_info(int testtype)
{
    const int num = sizeof(alg_i) / sizeof(chained_alg_info);
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
 * compute_buff_size:
 *          Depending on the version of TLS protocol, compute the
 *          size of buffer needed for the packet.
 *          Also finds the number of bytes used by IV
 */
int compute_buff_size(int size, unsigned int *ivlen,
                      int pad, int tls_v, EVP_CIPHER_CTX *ctx)
{
    *ivlen = 0;
    int len = 0;

    switch (tls_v) {
    case NON_TLS:
        /* Non-TLS case: Align size to block size */
        len = (size + (EVP_CIPHER_CTX_block_size(ctx) - 1))
            & ~(EVP_CIPHER_CTX_block_size(ctx) - 1);
        break;
    case TLS1_1_VERSION:
    case TLS1_2_VERSION:
        /* For TLS Versions >= 1.1, Add room for iv in buffers */
        *ivlen = EVP_CIPHER_CTX_iv_length(ctx);
    case TLS1_VERSION:
        /*
         * increase the size by amount of DIGEST len and padding
         * plus ivlen
         */
        len = size + (pad + *ivlen);
        break;
    default:
        len = 0;
        *ivlen = 0;
    }
    return len;
}

/*
 *  setup_ctx:
 *      Setup cipher context ready to be used in a cipher operation.
 *      It also sets up additonal information required i.e. tls headers.
 */
static EVP_CIPHER_CTX *setup_ctx(const test_info *t, int enc,
                                 int e, int *pad, int cfg)
{
    int padlen = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned int size = t->bufsz;
    unsigned char tls_hdr[] = { 0x00, 0x00, 0x00, 0x00, /* TLS Seq */
        0x00, 0x00, 0x00, 0x00, /* of 8Bytes */
        /* Record Type, Major, Minor, Len-MSB, Len-LSB */
        0x16, 0x03, 0x00, 0x00, 0x00
    };

    if (pad != NULL)
        *pad = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return NULL;


    if (EVP_CipherInit_ex(ctx, t->c->pfunc(),
                          e == USE_ENGINE ? t->e : NULL,
                          t->c->key,
                          t->tls->v >= TLS1_1_VERSION && enc == 0 ?
                          NULL : _ivec, enc) != 1)
        goto err;

    /* call the EVP API to set up the HMAC key */
    if (!(cfg & NO_HMAC_KEY))
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_MAC_KEY,
                            sizeof(_hmac_key), _hmac_key);

    if (!(cfg & NO_AAD) && t->tls->v != 0) {
        /*
         * For tls >= 1.1, iv is prepenned to the payload.
         * Encoded size in header passed to control message
         * includes this length as well.
         */
        if (t->tls->v >= TLS1_1_VERSION)
            size += EVP_CIPHER_CTX_iv_length(ctx);

        /* Set up TLS Header */
        tls_hdr[10] = t->tls->v & 0xff;
        tls_hdr[11] = (size & 0xff00) >> 8;
        tls_hdr[12] = size & 0x00ff;

        /*
         * Change a byte in sequence number for
         * second header so it is different from first.
         */
        if (cfg & TLS_HDR_MODIFY_SEQ)
            tls_hdr[1] = 0xA3;

        /* get the TLS record padding size */
        padlen = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD,
                                     sizeof(tls_hdr), (void *)tls_hdr);
    }

    if (pad != NULL)
        *pad = padlen;

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
                      int *nbytes, int tls)
{
    int s, i;
    int ret = 0;
    unsigned int ivlen = 0;
    unsigned char *inb = NULL;
    unsigned char *outb = NULL;

    int enc = EVP_CIPHER_CTX_encrypting(ctx);

    if (in == NULL || out == NULL || nbytes == NULL)
        return 0;

    *nbytes = 0;
    if (tls >= TLS1_1_VERSION)
        ivlen = EVP_CIPHER_CTX_iv_length(ctx);

    /* Allocate and fill src buffer if encrypting */
    if (enc == 1 && *in == NULL) {
        *in = inb = OPENSSL_malloc(size);
        if (inb == NULL)
            return 0;
        /* In case of TLS < 1.1, this a zero byte copy */
        memcpy(inb, _ivec, ivlen);

        /* setup input message values */
        for (i = ivlen; i < size; i++)
            inb[i] = i % 16;
    } else {
        /* Decrypt the src buffer contents */
        inb = *in;
    }

    if (*out == NULL) {
        *out = outb = OPENSSL_malloc(size);

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
    int pad = 0;
    int size = t->bufsz;
    char msgstr[128];
    EVP_CIPHER_CTX *ctx = NULL;

    /* str to append to message to distinguish test runs */
    snprintf(msgstr, 128, "[%s: %s encrypt %s] ", t->c->name,
             impl == USE_ENGINE ? "ENG" : "SW", t->tls->v_str);

    /* setup ctx for encryption */
    if (t->tls->v == NON_TLS)
        ctx = setup_ctx(t, ENC, impl, &pad, DEF_CFG | NO_HMAC_KEY);
    else
        ctx = setup_ctx(t, ENC, impl, &pad, DEF_CFG);

    if (ctx == NULL) {
        FAIL_MSG("%s failed to setup enc context\n", msgstr);
        return -1;
    }

    /* Compute the size of the buffer needed for this TLS use case */
    size = compute_buff_size(size, ivlen, pad, t->tls->v, ctx);

    ret = perform_op(ctx, buf, encbuf, size, num_encbytes, t->tls->v);

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
    char msgstr[128];
    EVP_CIPHER_CTX *ctx = NULL;

    /* str to append to message to distinguish test runs */
    snprintf(msgstr, 128, "[%s: %s decrypt %s] ", t->c->name,
             impl == USE_ENGINE ? "ENG" : "SW", t->tls->v_str);

    /* initialise ctx for decryption */
    if (t->tls->v == NON_TLS)
        ctx = setup_ctx(t, DEC, impl, NULL, DEF_CFG | NO_HMAC_KEY);
    else
        ctx = setup_ctx(t, DEC, impl, NULL, DEF_CFG);

    if (ctx == NULL) {
        FAIL_MSG("%s failed to setup dec context\n", msgstr);
        return -1;
    }

    ret = perform_op(ctx, encbuf, decbuf, len, &num_decbytes, t->tls->v);

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
        FAIL_MSG("%s:%s failed to perform Encryption using Engine!\n",
                 __func__, t->tls->v_str);
        goto err;
    }

    if (encrypt_buff(t, USE_SW, &textbuf, &sw_buf, &sw_opbytes, &ivlen) != 1) {
        FAIL_MSG("%s:%s failed to perform Encryption using SW!\n",
                 __func__, t->tls->v_str);
        goto err;
    }

    if (eng_opbytes != sw_opbytes) {
        FAIL_MSG("%s: %s Num Encrypted bytes Engine[%d] != SW[%d]\n",
                 __func__, t->tls->v_str, eng_opbytes, sw_opbytes);
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
    } else if (memcmp(eng_buf, sw_buf, ivlen) &&
               !memcmp(eng_buf, _ivec, ivlen)) {
        /*
         * first ivlen bytes are different i.e. Openssl SW enc buffer encrypts the
         * explicit IV whereas QAT engine sends the explicit IV in clear text
         */
        ret = ENCRYPT_BUFF_DIFFERENT;
    } else {
        /*
         * explicit IV encoded is byte identical but encrypted payload is
         * different. This is an error condition.
         */
        FAIL_MSG("[%s:%s:%s]verify failed  for ENGINE and SW Encrypt",
                 __func__, t->tls->v_str, t->c->name);
        tests_hexdump("AES*-CBC-HMAC-SHA* ENGINE  :", eng_buf, eng_opbytes);
        tests_hexdump("AES*-CBC-HMAC-SHA* SW:", sw_buf, eng_opbytes);
        ret = ENCRYPT_BUFF_ERROR;
    }

 err:
    OPENSSL_free(textbuf);
    OPENSSL_free(eng_buf);
    OPENSSL_free(sw_buf);
    return ret;
}

/*
 * test_crypto_op :
 *      test chained ciphers crypto operation.
 *      depending on the enc_imp/dec_imp, use either a engine or
 *      software implemention to perform encryption/decryption.
 *      if DEC_imp(ENC_imp(text)) = text, then report success else
 *      fail.
 */
static int test_crypto_op(const test_info *t, int enc_imp, int dec_imp)
{
    int ret = 0;
    unsigned int ivlen = 0;
    int num_encbytes;
    unsigned char *textbuf = NULL;
    unsigned char *encbuf = NULL;
    unsigned char *decbuf = NULL;
    char msgstr[128];

    /* str to append to message to distinguish test runs */
    snprintf(msgstr, 128, "[%s: %s encrypt %s decrypt for %s] ", t->c->name,
             enc_imp == USE_ENGINE ? "ENG" : "SW",
             dec_imp == USE_ENGINE ? "ENG" : "SW", t->tls->v_str);

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
    if (memcmp(decbuf + ivlen, textbuf + ivlen, t->bufsz)) {
        FAIL_MSG("verify failed for %s", msgstr);
        tests_hexdump("AES*-CBC-HMAC-SHA* actual  :", decbuf + ivlen,
                      t->bufsz);
        tests_hexdump("AES*-CBC-HMAC-SHA* expected:", textbuf + ivlen,
                      t->bufsz);
        goto err;
    }

    ret = 1;

 err:
    OPENSSL_free(textbuf);
    OPENSSL_free(encbuf);
    OPENSSL_free(decbuf);
    return ret;
}

/*
 * test_no_hmac_key :
 *          Do not set HMAC key and test behaviour of cipher operation.
 */
int test_no_hmac_key_set(const test_info *t)
{
    int ret = 0;
    int pad = 0;
    int size = t->bufsz;
    char msgstr[128];
    unsigned int ivlen;
    int num_encbytes;
    unsigned char *buf = NULL;
    unsigned char *encbuf = NULL;
    EVP_CIPHER_CTX *ctx = NULL;

    /* str to append to message to distinguish test runs */
    snprintf(msgstr, 128, "[%s: ENG Test %s with NO HMAC key set] ",
             t->c->name, t->tls->v_str);

    /* setup ctx for encryption */
    ctx = setup_ctx(t, ENC, USE_ENGINE, &pad, DEF_CFG | NO_HMAC_KEY);
    if (ctx == NULL) {
        FAIL_MSG("%s failed to setup enc context\n", msgstr);
        return -1;
    }

    /* Compute the size of the buffer needed for this TLS use case */
    size = compute_buff_size(size, &ivlen, pad, t->tls->v, ctx);

    /* Encrypt operation should be successful */
    ret = perform_op(ctx, &buf, &encbuf, size, &num_encbytes, t->tls->v);

    if (ret != 1) {
        FAIL_MSG("%s failed to perform Encryption!\n", msgstr);
        goto err;
    }

    if (ret == 1 && num_encbytes != size)
        FAIL_MSG("%s: nbytes %d != outl %d\n", msgstr, num_encbytes, size);

 err:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_free(buf);
    OPENSSL_free(encbuf);

    return ret;
}

/*
 * test_multi_op :
 *          Perform the cipher operation multiple times with the same ctx.
 */
int test_multi_op(const test_info *t)
{
    int ret = 0;
    int pad = 0;
    unsigned int ivlen = 0;
    int size = t->bufsz;
    char msgstr[128];
    int i = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *buf[6] = { NULL };
    unsigned char *ebuf[6] = { NULL };
    unsigned char *dbuf[6] = { NULL };
    int num_encbytes[6] = { 0 };

    /* str to append to message to distinguish test runs */
    snprintf(msgstr, 128, "[%s: multi op %s] ", t->c->name, t->tls->v_str);

    ctx = setup_ctx(t, ENC, USE_SW, &pad, DEF_CFG);
    if (ctx == NULL) {
        FAIL_MSG("%s failed to setup enc context\n", msgstr);
        return -1;
    }

    /* Compute the size of the buffer needed for this TLS use case */
    size = compute_buff_size(size, &ivlen, pad, t->tls->v, ctx);

    for (i = 0; i < 6; i++) {
        ret = perform_op(ctx, &buf[i], &ebuf[i], size,
                         &num_encbytes[i], t->tls->v);
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
        OPENSSL_free(ebuf[i]);
        OPENSSL_free(dbuf[i]);
    }
    return ret;
}

int test_performance_encrypt(const test_info *t)
{
    int ret = 0;
    int pad = 0;
    unsigned int ivlen = 0;
    int size = t->bufsz;
    char msgstr[128];
    int i = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *buf = NULL;
    unsigned char *ebuf = NULL;
    int num_encbytes = 0;

    /* str to append to message to distinguish test runs */
    snprintf(msgstr, 128, "[%s: perf enc %s] ", t->c->name, t->tls->v_str);

    ctx = setup_ctx(t, ENC, USE_ENGINE, &pad, DEF_CFG);
    if (ctx == NULL) {
        FAIL_MSG("%s failed to setup enc context\n", msgstr);
        return -1;
    }

    /* Compute the size of the buffer needed for this TLS use case */
    size = compute_buff_size(size, &ivlen, pad, t->tls->v, ctx);

    for (i = 0; i < t->count; i++) {
        ret = perform_op(ctx, &buf, &ebuf, size,
                         &num_encbytes, t->tls->v);
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
int test_encrypted_buffer(const test_info *t)
{
    int ret = 0;
    int buflen = 0;

    ret = encrypt_and_compare(t, &buflen);
    if (ret == ENCRYPT_BUFF_ERROR) {
        FAIL_MSG("Failed to perform encrypt and compare operation for %s:%s\n",
                 t->tls->v_str, t->c->name);
        return ret;
    }

    if (t->tls->v >= TLS1_1_VERSION && ret != ENCRYPT_BUFF_DIFFERENT) {
        /* If the bytes match, flag behaviour change as failure. */
        FAIL_MSG("ENGINE and SW Encrypt does match for %s for %s\n",
                 t->tls->v_str, t->c->name);
    } else if (t->tls->v < TLS1_1_VERSION && ret != ENCRYPT_BUFF_IDENTICAL) {
        /*
         * There is no explicit IV, so the encrypted buffers should
         * byte match.
         */
        FAIL_MSG("verify failed ENGINE and SW Encrypt"
                 " does match for %s for %s\n", t->tls->v_str, t->c->name);
    } else {
        ret = 1;
    }

    return ret;
}

/*
 * test_auth_header :
 *      TLS header is used in calculation of HMAC code.
 *      Any change in header should result in AUTH failure.
 *      This function tests this by using changing headers
 *      between encryption and decryption.
 */
static int test_auth_header(const test_info *t, int impl)
{
    int ret = 0;
    unsigned int ivlen = 0;
    int num_encbytes, num_decbytes;
    unsigned char *textbuf = NULL;
    unsigned char *encbuf = NULL;
    unsigned char *decbuf = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    char msgstr[128];

    snprintf(msgstr, 128, "[%s:%s:%s] ", __func__, t->tls->v_str,
             impl == USE_ENGINE ? "ENG" : "SW");

    /*
     * There is no AUTH info for NON_TLS use case.
     * Pass by default
     */
    if (t->tls->v == NON_TLS)
        return 1;

    /* Get an encrypted buffer along with it's plain text */
    ret = encrypt_buff(t, impl, &textbuf, &encbuf, &num_encbytes, &ivlen);
    if (ret != 1) {
        FAIL_MSG("%s failed to perform Encryption!\n", msgstr);
        goto err;
    }

    /*
     * Setup ctx for decryption and use control message to setup
     * a different TLS header than for encryption */
    ctx = setup_ctx(t, DEC, impl, NULL, TLS_HDR_MODIFY_SEQ);
    if (ctx == NULL) {
        FAIL_MSG("%s failed to setup dec context\n", msgstr);
        goto err;
    }

    /*
     * Perform decryption, followed by authentication which should
     * fail.
     */
    ret = perform_op(ctx, &encbuf, &decbuf, num_encbytes, &num_decbytes,
                     t->tls->v);
    if (ret != EVP_FAIL) {
        FAIL_MSG("%s Decrypt+Auth did not fail\n", msgstr);
        ret = 0;
        goto err;
    }

    ret = 1;

err:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_free(textbuf);
    OPENSSL_free(encbuf);
    OPENSSL_free(decbuf);
    return ret;
}

static int test_auth_pkt(const test_info *t, int impl)
{
    int ret = 0;
    unsigned int ivlen = 0;
    int num_encbytes;
    unsigned char *textbuf = NULL;
    unsigned char *encbuf = NULL;
    unsigned char *decbuf = NULL;
    char msgstr[128];

    /*
     * There is no AUTH info for NON_TLS use case.
     * Pass by default
     */
    if (t->tls->v == NON_TLS)
        return 1;

    /* str to append to message to distinguish test runs */
    snprintf(msgstr, 128, "[%s: %s encrypt SW decrypt for %s] ", __func__,
             impl == USE_ENGINE ? "ENG" : "SW", t->tls->v_str);

    /* Get an encrypted buffer along with it's plain text */
    ret = encrypt_buff(t, USE_SW, &textbuf, &encbuf, &num_encbytes, &ivlen);
    if (ret != 1) {
        FAIL_MSG("%s failed to perform Encryption!\n", msgstr);
        goto err;
    }

    /*
     * Change bytes in the encrypted buffer. The bytes tampered with
     * should be past the IVLEN.
     * Flipping bits in the encrypted buffer to simulate corruption.
     */
    encbuf[ivlen + 10] = ~encbuf[ivlen + 10];

    /* Decrypt the encrypted buffer above and get decrpyted contents */
    ret = decrypt_buff(t, impl, &encbuf, &decbuf, num_encbytes);
    if (ret != EVP_FAIL) {
        FAIL_MSG("%s Dec+Auth did not fail\n", msgstr);
        goto err;
    }

    ret = 1;

err:
    OPENSSL_free(textbuf);
    OPENSSL_free(encbuf);
    OPENSSL_free(decbuf);
    return ret;
}

static int test_pipeline_setup(const test_info *t)
{
#define NUMPIPES 10
    EVP_CIPHER_CTX *ctx = NULL;
    int pad = 0;
    int ret = 0;
    int outl = 0;
    int i, j;
    int size = t->bufsz;
    unsigned int ivlen = 0;
    unsigned long flags = 0;
    unsigned char **ebufs = NULL;
    unsigned char **ibufs = NULL;
    unsigned char **dbufs = NULL;
    size_t *inlens;
    unsigned char tls_hdr[] = { 0x00, 0x00, 0x00, 0x00, /* TLS Seq */
        0x00, 0x00, 0x00, 0x00, /* of 8Bytes */
        /* Record Type, Major, Minor, Len-MSB, Len-LSB */
        0x16, 0x03, 0x00, 0x00, 0x00
    };

    /* Pipeline supported for version >= 1.1 */
    if (t->tls->v < TLS1_1_VERSION)
        return 1;

    /* Setup context with engine without adding tls header */
    ctx = setup_ctx(t, ENC, USE_ENGINE, &pad, DEF_CFG | NO_AAD);
    if (ctx == NULL) {
        FAIL_MSG("%s failed to setup enc context\n", __func__);
        return 0;
    }

    flags = EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(ctx));
    if (!(flags & EVP_CIPH_FLAG_PIPELINE)) {
        FAIL_MSG("%s PIPELINE flag not set\n", __func__);
        return 0;
    }

    ibufs = OPENSSL_zalloc(sizeof(unsigned char *) * NUMPIPES);
    ebufs = OPENSSL_zalloc(sizeof(unsigned char *) * NUMPIPES);
    dbufs = OPENSSL_zalloc(sizeof(unsigned char *) * NUMPIPES);
    inlens = OPENSSL_zalloc(sizeof(size_t) * NUMPIPES);
    if (ibufs == NULL || ebufs == NULL || dbufs == NULL || inlens == NULL) {
        FAIL_MSG("%s Failed to allocate memory for buffer arrays\n",
                 __func__);
        goto err;
    }

    if ((EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS, NUMPIPES,
                             (void *)ebufs) != 1) ||
        (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_PIPELINE_INPUT_BUFS, NUMPIPES,
                             (void *)ibufs) != 1) ||
        (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_PIPELINE_INPUT_LENS, NUMPIPES,
                             (void *)inlens) != 1) || 0) {
        FAIL_MSG(" %s Failed to set  buffer for Pipeline\n", __func__);
        goto err;
    }

    /* Not supplied all the aad data this test should fail */
    if (EVP_CipherUpdate(ctx, ebufs[0], &outl, ibufs[0], 128) != 0) {
        FAIL_MSG("%s Cipher operation completed without all aad!\n",
                 __func__);
        goto err;
    }

    /* Setup aad data */
    ivlen = EVP_CIPHER_CTX_iv_length(ctx);

    for (i = 0; i < NUMPIPES; i++) {
        /*
         * Set the fields for each iteration as the pointer
         * may be modified by the control message if EVP software
         * implementation is used.
         */
        tls_hdr[10] = t->tls->v & 0xff;
        tls_hdr[11] = ((size + ivlen) & 0xff00) >> 8;
        tls_hdr[12] = (size + ivlen) & 0x00ff;
        pad = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD,
                                  sizeof(tls_hdr), (void *)tls_hdr);
        inlens[i] = compute_buff_size(size, &ivlen, pad, t->tls->v, ctx);
        ibufs[i] = OPENSSL_zalloc(inlens[i]);
        ebufs[i] = OPENSSL_zalloc(inlens[i]);
        dbufs[i] = NULL;
        if (ibufs[i] == NULL || ebufs[i] == NULL) {
            FAIL_MSG("%s Failed to allocate memory for buffers\n", __func__);
            goto err;
        }
        /* Setup Input buffers */
        memcpy(ibufs[i], _ivec, ivlen);
        for (j = ivlen; j < size + ivlen; j++)
             ibufs[i][j] = ((i << 4) | (j % 16));
    }

    if (EVP_CipherUpdate(ctx, NULL, &outl, NULL, 128) != 1) {
        FAIL_MSG("%s Encryption failed for Pipeline\n", __func__);
        goto err;
    }

    /* Decrypt each pipe encrypted buffer through software and compare */
    for (i = 0; i < NUMPIPES; i++) {
        ret = decrypt_buff(t, USE_SW, &ebufs[i], &dbufs[i], inlens[i]);
        if (ret != 1) {
            FAIL_MSG("%s SW Decryption failed for pipe %d\n", __func__, i);
            goto err;
        }

        /* Compare and verify the decrypt and encrypt message. */
        if (memcmp(dbufs[i] + ivlen, ibufs[i] + ivlen, size)) {
            FAIL_MSG("verify failed for pipe %d\n", i);
            tests_hexdump("AES*-CBC-HMAC-SHA* actual  :", dbufs[i] + ivlen,
                          size);
            tests_hexdump("AES*-CBC-HMAC-SHA* expected:", ibufs[i] + ivlen,
                          size);
            goto err;
        }
    }
    ret = 1;

err:
    EVP_CIPHER_CTX_free(ctx);
    for (i = 0; i < NUMPIPES; i++) {
        OPENSSL_free(ibufs[i]);
        OPENSSL_free(ebufs[i]);
        OPENSSL_free(dbufs[i]);
    }
    OPENSSL_free(ibufs);
    OPENSSL_free(ebufs);
    OPENSSL_free(dbufs);
    OPENSSL_free(inlens);
    return ret;
}

/*
 * test_small_pkt_offload:
 *      Small pkt offload test relies on the fact the Openssl SW
 *      implementation and Qat engine implementation encrypts TLS1.1
 *      and TLS1.2 packets differently. This is used to detect which
 *      implementation was used after the threshold was set.
 */
static int test_small_pkt_offload(const test_info *t)
{
    int ret = 0;
    char msgstr[128];
# if defined(QAT_WARN) || defined(QAT_DEBUG)
    int run = 0;
#endif
    int buflen = 0;
    int status = 0;

    /* str to append to message to distinguish test runs */
    snprintf(msgstr, 128, "[%s %s:%s] ", __func__, t->c->name, t->tls->v_str);

    /*
     * Test is used only for version TLS1.1 and TLS1.2
     * that use explicit IV.
     */
    if (t->tls->v < TLS1_1_VERSION)
        return 1;

    /*
     * Engine was configured at the start of test run to offload all packets
     * to engine
     */
    ret = encrypt_and_compare(t, &buflen);
    /* Check if SW and Engine implementation are different and valid */
    if (ret != ENCRYPT_BUFF_DIFFERENT) {
        FAIL_MSG("%s encrypted buffers not different status:%d run:%d\n",
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
    /* check if SW and Engine implemantation byte identical */
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
    if (ret != ENCRYPT_BUFF_DIFFERENT) {
        FAIL_MSG("%s encrypted buffers not different status:%d run:%d\n",
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

/*
 * run_aes_cbc_hmac_sha :
 *      For each version of supported TLS protocol,
 *      run various tests.
 */
static int run_aes_cbc_hmac_sha(void *pointer)
{
    int ntls = sizeof(test_tls) / sizeof(tls_v);
    int i, cnt;
    int ret = 1;
    test_info ti;
    char msg[128];
    TEST_PARAMS *args = (TEST_PARAMS *) pointer;
    ti.bufsz = args->size;
    ti.count = *(args->count);

    if ((ti.c = (chained_alg_info *) get_alg_info(args->type)) == NULL) {
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

    /*
     * For the qat engine, offload all packet sizes to engine
     * by setting the threshold sizes to 0 for the cipher under test.
     */
    if (ti.e != NULL) {
        ret = set_pkt_threshold(ti.e, ti.c->name, 0);
        if (ret != 1)
            return 0;
    }

    if (args->performance) {
        if(!strcmp(args->tls_version, "TLSv1"))
            ti.tls = (tls_v *)&test_tls[0];
        else if(!strcmp(args->tls_version, "TLSv1_1"))
            ti.tls = (tls_v *)&test_tls[1];
        else if(!strcmp(args->tls_version, "TLSv1_2"))
            ti.tls = (tls_v *)&test_tls[2];
        else
            ti.tls = (tls_v *)&test_tls[3];

        return test_performance_encrypt(&ti);
    }

    /* If the inner run fails, abandon test */
    for (cnt = 0; ret && cnt < *(args->count); cnt++) {
        for (i = 0; i < ntls; i++) {
            ti.tls = (tls_v *)&test_tls[i];
            if (
                /*
                 * Running the test with SW implementation to check if
                 * the test logic is correct.
                 */
                (test_crypto_op(&ti, USE_SW, USE_SW) != 1) ||
                (test_auth_header(&ti, USE_SW) != 1) ||
                (test_auth_pkt(&ti, USE_SW) != 1) ||
                ((ti.e != NULL) && (
                    /*
                     * Perform these tests only if engine
                     * is present.
                     */
                  (test_encrypted_buffer(&ti) != 1) ||
                  (test_no_hmac_key_set(&ti) != 1) ||
                  (test_crypto_op(&ti, USE_ENGINE, USE_SW) != 1) ||
                  (test_crypto_op(&ti, USE_SW, USE_ENGINE) != 1) ||
                  (test_crypto_op(&ti, USE_ENGINE, USE_ENGINE) != 1) ||
                  (test_auth_header(&ti, USE_ENGINE) != 1) ||
                  (test_auth_pkt(&ti, USE_ENGINE) != 1) ||
                  (test_multi_op(&ti) != 1) ||
                  (test_pipeline_setup(&ti) != 1) ||
                  (test_small_pkt_offload(&ti) != 1)
                 )
                )
               ) {
                ret = 0;
                break;
            }
        }
    }

    if (args->verify) {
        snprintf(msg, 128, " [%d out %d test run passed.]\n", cnt,
                 *args->count);
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

/*
 * tests_run_aes_cbc_hmac_sha:
 *      Start Chained Cipher tests.
 */
void tests_run_aes_cbc_hmac_sha(TEST_PARAMS *args)
{
    args->additional_args = NULL;

    if (!args->enable_async)
        run_aes_cbc_hmac_sha(args);
    else
        start_async_job(args, run_aes_cbc_hmac_sha);
}
