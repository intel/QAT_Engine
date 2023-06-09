
/***************************************************************************
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023 Intel Corporation. All rights reserved.
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
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/async.h>
#include <openssl/objects.h>
#include <openssl/engine.h>

#include "tests.h"
#include "../qat_utils.h"

#define SHA2_224_DIGEST_LENGTH 28
#define SHA2_256_DIGEST_LENGTH 32
#define SHA2_384_DIGEST_LENGTH 48
#define SHA2_512_DIGEST_LENGTH 64

unsigned char sha2_224_expected[] = {
    0x27, 0x1E, 0x41, 0xDB, 0x21, 0x89, 0xDC, 0x9D,
    0xB9, 0x4E, 0x7A, 0x56, 0x41, 0xDB, 0xF6, 0x78,
    0x9D, 0xB6, 0x61, 0xDA, 0xDC, 0x24, 0x86, 0xEA,
    0xEF, 0xB5, 0xFF, 0xD6,
};

unsigned char sha2_256_expected[] = {
    0xC6, 0x22, 0x00, 0x54, 0x93, 0xC4, 0xCB, 0x75,
    0xF3, 0xE0, 0x8E, 0xDA, 0x4C, 0xC0, 0xBF, 0xE1,
    0x72, 0xE2, 0xC5, 0xEE, 0xCA, 0x66, 0x1E, 0xC4,
    0x90, 0x8C, 0x54, 0x90, 0xFC, 0x3D, 0x69, 0x94,
};

unsigned char sha2_384_expected[] = {
    0x49, 0x13, 0x44, 0x2B, 0x8D, 0x4C, 0xA7, 0x39,
    0x98, 0x22, 0x98, 0x03, 0xFB, 0x3E, 0xEE, 0x49,
    0x55, 0x5C, 0x16, 0x62, 0x38, 0x44, 0x54, 0x9D,
    0xA5, 0x4E, 0x2C, 0xA3, 0x00, 0x63, 0xE3, 0x70,
    0x00, 0xBB, 0x66, 0x38, 0xED, 0x89, 0x59, 0xFA,
    0xC9, 0x90, 0xD6, 0x35, 0xC9, 0xB8, 0x42, 0x28,
};

unsigned char sha2_512_expected[] = {
    0x87, 0x73, 0xF7, 0xF1, 0x90, 0x99, 0x33, 0xF5,
    0x96, 0x6C, 0xAE, 0xC1, 0x8F, 0x5B, 0xB1, 0x20,
    0x09, 0x22, 0x81, 0xC0, 0xCC, 0x47, 0x33, 0x44,
    0xA0, 0x82, 0x21, 0xAF, 0x3A, 0x0D, 0x5E, 0xE3,
    0xD6, 0x3F, 0xFD, 0xBD, 0xEA, 0x86, 0xB9, 0xE4,
    0x25, 0x58, 0x3F, 0xFA, 0x7B, 0x11, 0x8A, 0xEE,
    0xED, 0x90, 0x65, 0x14, 0x35, 0x46, 0xCA, 0xD0,
    0x08, 0xA9, 0x3D, 0x3E, 0x7F, 0x03, 0x18, 0xB2,
};

/******************************************************************************
* function:
*   run_sha2(void *args)
*
* @param args [IN] - the test parameters
*
* Description: Runs SHA-2 tests for corresponding digest length
******************************************************************************/
static int run_sha2(void *args)
{
    TEST_PARAMS *temp_args = (TEST_PARAMS *) args;
    int count = *(temp_args->count);
    int size = temp_args->size;
    /* If temp_args->explicit_engine is not set then set the
       engine to NULL to allow fallback to software if
       that engine under test does not support this operation.
       This relies on the engine we are testing being
       set as the default engine. */
    ENGINE *e = temp_args->explicit_engine ? temp_args->e : NULL;
    int print_output = temp_args->print_output;
    int verify = temp_args->verify;
    int i = 0;
    int inLen = size;
    int ret = 1;
    unsigned int digest_len = 0;
    unsigned char md[SHA2_512_DIGEST_LENGTH];
    unsigned char *expected = NULL;

    /* Use default input size in verify mode. */
    if (verify)
        inLen = 4096;
    unsigned char *inData = OPENSSL_malloc(inLen);

    if (inData == NULL) {
        fprintf(stderr, "# FAIL: [%s] --- inData malloc failed! \n", __func__);
        exit(EXIT_FAILURE);
    }

    /* Setup the input and output data. */
    memset(inData, 0xaa, inLen);
    memset(md, 0x00, SHA2_512_DIGEST_LENGTH);

    for (i = 0; i < count; i++) {
        switch (temp_args->type) {
        case TEST_SHA2_224:
            DEBUG("\n----- SHA2_224 digest ----- \n\n");

            digest_len = SHA2_224_DIGEST_LENGTH;
            expected = (void *)&sha2_224_expected;
            ret = EVP_Digest(inData, /* Input data pointer.  */
                             inLen, /* Input data length.  */
                             md, /* Output hash pointer.  */
                             NULL, EVP_sha224(), /* Hash algorithm indicator. */
                             e); /* Engine indicator.  */
            break;

        case TEST_SHA2_256:
            DEBUG("\n----- SHA2_256 digest ----- \n\n");

            digest_len = SHA2_256_DIGEST_LENGTH;
            expected = (void *)&sha2_256_expected;
            ret = EVP_Digest(inData, /* Input data pointer.  */
                             inLen, /* Input data length.  */
                             md, /* Output hash pointer.  */
                             NULL, EVP_sha256(), /* Hash algorithm indicator. */
                             e); /* Engine indicator.  */
            break;

        case TEST_SHA2_384:
            DEBUG("\n----- SHA2_384 digest ----- \n\n");

            digest_len = SHA2_384_DIGEST_LENGTH;
            expected = (void *)&sha2_384_expected;
            ret = EVP_Digest(inData, /* Input data pointer.  */
                             inLen, /* Input data length.  */
                             md, /* Output hash pointer.  */
                             NULL, EVP_sha384(), /* Hash algorithm indicator. */
                             e); /* Engine indicator.  */
            break;

        case TEST_SHA2_512:
            DEBUG("\n----- SHA2_512 digest ----- \n\n");

            digest_len = SHA2_512_DIGEST_LENGTH;
            expected = (void *)&sha2_512_expected;
            ret = EVP_Digest(inData, /* Input data pointer.  */
                             inLen, /* Input data length.  */
                             md, /* Output hash pointer.  */
                             NULL, EVP_sha512(), /* Hash algorithm indicator. */
                             e); /* Engine indicator.  */
            break;
        }
        if (ret != 1 || verify) {
            /* Compare the digest results with the expected results. */
            if (memcmp(md, expected, digest_len)) {
                fprintf(stderr, "# FAIL verify for %s.\n",
                        test_name(temp_args->type));
                tests_hexdump("SHA2 actual  :", md, digest_len);
                tests_hexdump("SHA2 expected:", expected, digest_len);
                ret = 0;
                break;
            } else {
                fprintf(stderr, "# PASS verify for %s.\n",
                        test_name(temp_args->type));
            }
        }
    }                           /* count for-loop */

    if (print_output)
        tests_hexdump("SHA2 digest text:", md, digest_len);

    if (inData)
        OPENSSL_free(inData);
    return ret;
}

/******************************************************************************
* function:
*   tests_run_sha2(TEST_PARAMS *args)
*
* @param args [IN] - the test parameters
*
* Description:
*   This function is designed to test the QAT engine with variable message sizes
*   using the SHA2 algorithm. The higher level EVP interface function EVP_Digest()
*   is used inside of test application.
*   This is a boundary test, the application should return the expected digest hash value.
*   In verify mode a input size of 1024 bytes is used to generate a comparison digest.
******************************************************************************/
void tests_run_sha2(TEST_PARAMS *args)
{
    args->additional_args = NULL;

    if (!args->enable_async)
        run_sha2(args);
    else
        start_async_job(args, run_sha2);
}
