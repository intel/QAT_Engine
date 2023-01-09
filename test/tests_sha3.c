
/***************************************************************************
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021-2023 Intel Corporation. All rights reserved.
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

#define SHA3_224_DIGEST_LENGTH 28
#define SHA3_256_DIGEST_LENGTH 32
#define SHA3_384_DIGEST_LENGTH 48
#define SHA3_512_DIGEST_LENGTH 64

unsigned char sha3_224_expected[] = {
   0x7C, 0x96, 0x7A, 0xDB, 0xB3, 0x77, 0x92, 0x68,
   0x94, 0x4A, 0x15, 0xE4, 0x29, 0xD2, 0x5A, 0x62,
   0xAA, 0x19, 0x7F, 0xFD, 0x51, 0x28, 0x38, 0xC2,
   0x23, 0x58, 0x31, 0xED,
};

unsigned char sha3_256_expected[] = {
    0x9C, 0x8F, 0xEE, 0x6B, 0x6A, 0x7C, 0x0B, 0xD3,
    0x7E, 0xD6, 0x83, 0xFC, 0x40, 0x6A, 0x8C, 0x1B,
    0x1C, 0x2D, 0xE6, 0x1C, 0x76, 0xE0, 0xE6, 0xD3,
    0x95, 0xDB, 0x93, 0x5E, 0x86, 0x17, 0x0D, 0xEC,
};

unsigned char sha3_384_expected[] = {
    0x6A, 0x11, 0x7F, 0x2D, 0xF7, 0x1B, 0xE3, 0x49,
    0x9E, 0x05, 0xDC, 0x72, 0x1A, 0x75, 0x82, 0xAE,
    0x5B, 0x10, 0x03, 0xF8, 0xE9, 0x97, 0x68, 0xAF,
    0x6E, 0x0B, 0x36, 0xA6, 0xCA, 0xDF, 0x5B, 0x10,
    0xB1, 0x9F, 0xA8, 0x78, 0xFA, 0x61, 0x4A, 0x20,
    0x17, 0xE0, 0xAA, 0x7F, 0x58, 0xA9, 0xB5, 0x80,
};

unsigned char sha3_512_expected[] = {
    0xE8, 0xAC, 0xFF, 0xFB, 0x33, 0xEF, 0x29, 0x3F,
    0xE6, 0x23, 0xD8, 0xEA, 0x8E, 0x4E, 0x45, 0x72,
    0xA3, 0xD9, 0x15, 0x1D, 0xC9, 0x1E, 0x87, 0x93,
    0x6B, 0xF1, 0xB3, 0x8C, 0x18, 0x60, 0x1A, 0x40,
    0xF7, 0x03, 0x79, 0x3D, 0x48, 0x51, 0x4C, 0xA2,
    0x53, 0x29, 0x47, 0x82, 0x4C, 0x1D, 0x2F, 0xEF,
    0x25, 0x9D, 0xA1, 0x9C, 0xAF, 0x75, 0xE3, 0xC8,
    0x4C, 0x5B, 0x56, 0xBE, 0xF7, 0x1D, 0xD9, 0xE3,
};

/******************************************************************************
* function:
*   run_sha3(void *args)
*
* @param args [IN] - the test parameters
*
* Description: Runs SHA-3 tests for corresponding digest length
******************************************************************************/
static int run_sha3(void *args)
{
    TEST_PARAMS *temp_args = (TEST_PARAMS *)args;
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
    unsigned char md[SHA3_512_DIGEST_LENGTH];
    unsigned char *expected = NULL;

    /* Use default input size in verify mode. */
    if (verify)
        inLen = 4096;
    unsigned char *inData = OPENSSL_malloc(inLen);

    if (inData == NULL)
    {
        fprintf(stderr,"# FAIL: [%s] --- inData malloc failed! \n", __func__);
        exit(EXIT_FAILURE);
    }

    /* Setup the input and output data. */
    memset(inData, 0xaa, inLen);
    memset(md, 0x00, SHA3_512_DIGEST_LENGTH);

    for (i = 0; i < count; i++) {
       switch(temp_args->type) {
       case TEST_SHA3_224:
           DEBUG("\n----- SHA3_224 digest ----- \n\n");

           digest_len = SHA3_224_DIGEST_LENGTH;
           expected = (void*) &sha3_224_expected;
           ret = EVP_Digest(inData, /* Input data pointer.  */
                            inLen,  /* Input data length.  */
                            md,     /* Output hash pointer.  */
                            NULL, EVP_sha3_224(),  /* Hash algorithm indicator. */
                            e);     /* Engine indicator.  */
           break;

       case TEST_SHA3_256:
           DEBUG("\n----- SHA3_256 digest ----- \n\n");

           digest_len = SHA3_256_DIGEST_LENGTH;
           expected = (void*) &sha3_256_expected;
           ret = EVP_Digest(inData, /* Input data pointer.  */
                            inLen,  /* Input data length.  */
                            md,     /* Output hash pointer.  */
                            NULL, EVP_sha3_256(),  /* Hash algorithm indicator. */
                            e);     /* Engine indicator.  */
           break;

       case TEST_SHA3_384:
           DEBUG("\n----- SHA3_384 digest ----- \n\n");

           digest_len = SHA3_384_DIGEST_LENGTH;
           expected = (void*) &sha3_384_expected;
           ret = EVP_Digest(inData, /* Input data pointer.  */
                            inLen,  /* Input data length.  */
                            md,     /* Output hash pointer.  */
                            NULL, EVP_sha3_384(),  /* Hash algorithm indicator. */
                            e);     /* Engine indicator.  */
           break;

       case TEST_SHA3_512:
           DEBUG("\n----- SHA3_512 digest ----- \n\n");

           digest_len = SHA3_512_DIGEST_LENGTH;
           expected = (void*) &sha3_512_expected;
           ret = EVP_Digest(inData, /* Input data pointer.  */
                            inLen,  /* Input data length.  */
                            md,     /* Output hash pointer.  */
                            NULL, EVP_sha3_512(),  /* Hash algorithm indicator. */
                            e);     /* Engine indicator.  */
           break;
       }
       if (ret != 1 || verify) {
           /* Compare the digest results with the expected results. */
           if (memcmp(md, expected, digest_len)) {
               fprintf(stderr,"# FAIL verify for %s.\n", test_name(temp_args->type));
               tests_hexdump("SHA3 actual  :", md, digest_len);
               tests_hexdump("SHA3 expected:", expected, digest_len);
               ret = 0;
               break;
           } else {
               fprintf(stderr,"# PASS verify for %s.\n", test_name(temp_args->type));
           }
       }
    } /* count for-loop */

    if (print_output)
        tests_hexdump("SHA3 digest text:", md, digest_len);

    if (inData)
        OPENSSL_free(inData);
    return ret;
}

/******************************************************************************
* function:
*   tests_run_sha3(TEST_PARAMS *args)
*
* @param args [IN] - the test parameters
*
* Description:
*   This function is designed to test the QAT engine with variable message sizes
*   using the SHA3 algorithm. The higher level EVP interface function EVP_Digest()
*   is used inside of test application.
*   This is a boundary test, the application should return the expected digest hash value.
*   In verify mode a input size of 1024 bytes is used to generate a comparison digest.
******************************************************************************/
void tests_run_sha3(TEST_PARAMS *args)
{
    args->additional_args = NULL;

    if (!args->enable_async)
        run_sha3(args);
    else {
        start_async_job(args, run_sha3);
    }
}
