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

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/async.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>

#include "tests.h"
#include "../qat_utils.h"
#ifndef OPENSSL_NO_SM2_SM3
#define SM3_DIGEST_LENGTH 32

typedef struct DIGEST_CASE {
    int len;
    unsigned char expected[SM3_DIGEST_LENGTH];
} digest_case;

static int run_sm3_msg_once(void *args, int inLen, unsigned char expected[])
{
    TEST_PARAMS *temp_args = (TEST_PARAMS *) args;
    int count = *(temp_args->count);
    /* If temp_args->explicit_engine is not set then set the
       engine to NULL to allow fallback to software if
       that engine under test does not support this operation.
       This relies on the engine we are testing being
       set as the default engine. */
    ENGINE *e = temp_args->explicit_engine ? temp_args->e : NULL;
    int print_output = temp_args->print_output;
    int verify = temp_args->verify;

    int i = 0;
    int ret = 1;

    unsigned char md[SM3_DIGEST_LENGTH];
    unsigned char *inData = NULL;

    if (inLen) {
        inData = OPENSSL_malloc(inLen);
        memset(inData, 0xaa, inLen);
    }

    /* Setup the input and output data. */
    memset(md, 0x00, SM3_DIGEST_LENGTH);

    for (i = 0; i < count; i++) {
        ret = EVP_Digest(inData, /* Input data pointer.  */
                         inLen, /* Input data length.  */
                         md,    /* Output hash pointer.  */
                         NULL, EVP_sm3(), /* Hash algorithm indicator. */
                         e);    /* Engine indicator.  */
        if (ret != 1 || verify) {
            /* Compare the digest results with the expected results. */
            if (memcmp(md, expected, SM3_DIGEST_LENGTH)) {
                fprintf(stderr, "# FAIL verify for SM3.\n");
                ret = 0;
                tests_hexdump("SM3 actual  :", md, SM3_DIGEST_LENGTH);
                tests_hexdump("SM3 expected:", expected, SM3_DIGEST_LENGTH);
                break;
            } else {
                fprintf(stderr, "# PASS verify for SM3 dgst %d bytes.\n",
                        inLen);
            }
        }
    }                           /* count for-loop */
    if (print_output)
        tests_hexdump("SM3 digest text:", md, SM3_DIGEST_LENGTH);

    if (inData)
        OPENSSL_free(inData);
    return ret;
}

static int run_sm3_hmac_once(void *args, int inLen, unsigned char expected[])
{
    TEST_PARAMS *temp_args = (TEST_PARAMS *) args;
    int count = *(temp_args->count);
    int print_output = temp_args->print_output;
    int verify = temp_args->verify;

    int i = 0;
    int ret = 1;
    unsigned char *result = NULL;

    unsigned char md[SM3_DIGEST_LENGTH];
    unsigned char *inData = NULL;
    unsigned int md_len = 0;

    static const unsigned char dummy_key[1] = { '\0' };

    if (inLen) {
        inData = OPENSSL_malloc(inLen);
        memset(inData, 0xaa, inLen);
    }

    /* Setup the input and output data. */
    memset(md, 0x00, SM3_DIGEST_LENGTH);

    for (i = 0; i < count; i++) {
        result = HMAC(EVP_sm3(), /* Hash function */
                      dummy_key, /* Key */
                      0,        /* Key length */
                      inData,   /* Input data */
                      inLen,    /* Input data length */
                      md,       /* HMAC result */
                      &md_len   /* HMAC result length */
            );

        if (result == NULL || verify) {
            /* Compare the digest results with the expected results. */
            if (memcmp(md, expected, SM3_DIGEST_LENGTH)) {
                fprintf(stderr, "# FAIL verify for SM3.\n");
                ret = 0;
                tests_hexdump("SM3 actual  :", md, SM3_DIGEST_LENGTH);
                tests_hexdump("SM3 expected:", expected, SM3_DIGEST_LENGTH);
                break;
            } else {
                fprintf(stderr, "# PASS verify for SM3 HMAC %d bytes.\n",
                        inLen);
            }
        }
    }                           /* count for-loop */
    if (print_output)
        tests_hexdump("SM3 digest text:", md, SM3_DIGEST_LENGTH);

    if (inData)
        OPENSSL_free(inData);
    return ret;
}

/******************************************************************************
* function:
*   run_sm3_msg (void *args)
*
* @param args [IN] - the test parameters
*
* Description:
******************************************************************************/
static int run_sm3_msg(void *args)
{
    digest_case cases[] = {
        {0,                     /* length = 0 */
         {
          0x1A, 0xB2, 0x1D, 0x83, 0x55, 0xCF, 0xA1, 0x7F,
          0x8E, 0x61, 0x19, 0x48, 0x31, 0xE8, 0x1A, 0x8F,
          0x22, 0xBE, 0xC8, 0xC7, 0x28, 0xFE, 0xFB, 0x74,
          0x7E, 0xD0, 0x35, 0xEB, 0x50, 0x82, 0xAA, 0x2B,
          }
         },

        {1024,                  /* length = 1024 */
         {
          0x69, 0xA5, 0xCF, 0x23, 0x25, 0x4A, 0x38, 0x54,
          0x03, 0xA6, 0xA8, 0x98, 0x88, 0xCC, 0x3F, 0x9E,
          0xC7, 0x03, 0x11, 0x7E, 0xD9, 0xFC, 0x06, 0xDE,
          0x77, 0x1B, 0x31, 0x86, 0x02, 0x28, 0xA6, 0x69,
          }
         },

        {1 * 1024 * 1024,       /* length = 1M */
         {
          0x47, 0x8D, 0xA3, 0x3C, 0x71, 0xED, 0xC9, 0x50,
          0x6D, 0x75, 0xE9, 0xDF, 0xA1, 0xD3, 0xDB, 0xA2,
          0x8B, 0x12, 0x48, 0x7A, 0x38, 0x37, 0xEC, 0xC5,
          0xA9, 0x58, 0xFE, 0x3B, 0xD2, 0x00, 0x06, 0x8D,
          }
         },

        {-1, {}}                /* end */
    };

    TEST_PARAMS *temp_args = (TEST_PARAMS *) args;
    int verify = temp_args->verify;
    int inLen = temp_args->size;
    int ret = 1;

    DEBUG("\n----- SM3 digest msg ----- \n\n");

    if (verify) {
        int i;
        for (i = 0; /* */ ; i++) {
            if (cases[i].len == -1)
                break;

            ret = run_sm3_msg_once(args, cases[i].len, cases[i].expected);

            if (ret != 1)
                break;
        }
    } else {
        ret = run_sm3_msg_once(args, inLen, NULL);
    }

    return ret;
}

/******************************************************************************
* function:
*   run_sm3_hmac (void *args)
*
* @param args [IN] - the test parameters
*
* Description:
******************************************************************************/
static int run_sm3_hmac(void *args)
{
    digest_case cases[] = {
        {0,                     /* length = 0 */
         {
          0x0D, 0x23, 0xF7, 0x2B, 0xA1, 0x5E, 0x9C, 0x18,
          0x9A, 0x87, 0x9A, 0xEF, 0xC7, 0x09, 0x96, 0xB0,
          0x60, 0x91, 0xDE, 0x6E, 0x64, 0xD3, 0x1B, 0x7A,
          0x84, 0x00, 0x43, 0x56, 0xDD, 0x91, 0x52, 0x61,
          }
         },

        {1024,                  /* length = 1024 */
         {
          0x3C, 0xC4, 0xDA, 0x4C, 0xED, 0x9C, 0xD9, 0x71,
          0xFE, 0x9C, 0x08, 0x4B, 0x43, 0x49, 0x02, 0x61,
          0x4E, 0x21, 0xC7, 0x3F, 0x8D, 0xFF, 0x61, 0x51,
          0x1F, 0x6F, 0x6B, 0x31, 0xC1, 0xE8, 0xBD, 0x55,
          }
         },

        {1 * 1024 * 1024,       /* length = 1M */
         {
          0x95, 0xC9, 0x06, 0xBE, 0x01, 0x21, 0x14, 0xA4,
          0x0D, 0x3F, 0xFA, 0x9B, 0x1E, 0x50, 0x26, 0x6F,
          0xDE, 0x2B, 0x30, 0x26, 0x81, 0x53, 0x98, 0x75,
          0xC8, 0x47, 0x91, 0x1E, 0x74, 0x8A, 0x17, 0xC3,
          }
         },

        {-1, {}}                /* end */
    };

    TEST_PARAMS *temp_args = (TEST_PARAMS *) args;
    int verify = temp_args->verify;
    int inLen = temp_args->size;
    int ret = 1;

    DEBUG("\n----- SM3 HMAC msg ----- \n\n");

    if (verify) {
        int i;
        for (i = 0; /* */ ; i++) {
            if (cases[i].len == -1)
                break;

            ret = run_sm3_hmac_once(args, cases[i].len, cases[i].expected);

            if (ret != 1)
                break;
        }
    } else {
        ret = run_sm3_hmac_once(args, inLen, NULL);
    }

    return ret;
}

/******************************************************************************
* function:
*   tests_run_sm3 (TEST_PARAMS *args)
*
* @param args [IN] - the test parameters
*
* Description:
*   This function is designed to test the QAT engine with variable message sizes
*   using the SM3 algorithm. The higher level EVP interface function EVP_Digest()
*   is used inside of test application.
*   This is a boundary test, the application should return the expected digest hash value.
*   In verify mode a input size of 1024 bytes is used to generate a comparison digest.
******************************************************************************/
void tests_run_sm3(TEST_PARAMS *args)
{
    args->additional_args = NULL;

    if (!args->enable_async) {
        run_sm3_msg(args);
        run_sm3_hmac(args);
    } else {
        start_async_job(args, run_sm3_msg);
        start_async_job(args, run_sm3_hmac);
    }
}
#endif /* OPENSS_NOS_SM2_SM3 */
