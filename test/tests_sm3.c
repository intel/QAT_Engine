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

#define SM3_DIGEST_LENGTH 32


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


    /* Use default input size in verify mode. */
    if (verify)
        inLen = 1024;

    unsigned char md[SM3_DIGEST_LENGTH];
    unsigned char *inData = OPENSSL_malloc(inLen);

    unsigned char expected[] = {
        0x69, 0xA5, 0xCF, 0x23, 0x25, 0x4A, 0x38, 0x54,
        0x03, 0xA6, 0xA8, 0x98, 0x88, 0xCC, 0x3F, 0x9E,
        0xC7, 0x03, 0x11, 0x7E, 0xD9, 0xFC, 0x06, 0xDE,
        0x77, 0x1B, 0x31, 0x86, 0x02, 0x28, 0xA6, 0x69,
    };

    unsigned char expected_res[] = {
        0x9F, 0xEF, 0xD6, 0x3A, 0xE0, 0x52, 0x54, 0x08,
        0x5E, 0x48, 0x3E, 0xF0, 0x41, 0xAD, 0x81, 0xC6,
        0x72, 0x1E, 0xEB, 0x7E, 0x34, 0xC8, 0xF2, 0x9B,
        0xBA, 0xF7, 0x59, 0x41, 0xA1, 0x6F, 0x0A, 0x26,
    };

    if (inData == NULL)
    {
        fprintf(stderr,"# FAIL: [%s] --- inData malloc failed! \n", __func__);
        exit(EXIT_FAILURE);
    }

    /* Setup the input and output data. */
    memset(inData, 0xaa, inLen);
    memset(md, 0x00, SM3_DIGEST_LENGTH);

    for (i = 0; i < count; i++)
    {
        DEBUG("\n----- SM3 digest msg ----- \n\n");

        ret = EVP_Digest(inData,    /* Input data pointer.  */
                         inLen, /* Input data length.  */
                         md,    /* Output hash pointer.  */
                         NULL, EVP_sm3(),  /* Hash algorithm indicator. */
                         e);      /* Engine indicator.  */
        if (ret != 1 || verify)
        {
            /* Compare the digest results with the expected results. */
            if ((memcmp(md, expected, SM3_DIGEST_LENGTH)) &&
                (memcmp(md, expected_res, SM3_DIGEST_LENGTH)))
            {
                fprintf(stderr,"# FAIL verify for SM3.\n");
                ret = 0;
                tests_hexdump("SM3 actual  :", md, SM3_DIGEST_LENGTH);
                tests_hexdump("SM3 expected:", expected, SM3_DIGEST_LENGTH);
                break;
            }
            else
                fprintf(stderr,"# PASS verify for SM3.\n");
        }
    } /* count for-loop */
    if (print_output)
        tests_hexdump("SM3 digest text:", md, SM3_DIGEST_LENGTH);

    if (inData)
        OPENSSL_free(inData);
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

    if (!args->enable_async)
        run_sm3_msg(args);
    else {
        start_async_job(args, run_sm3_msg);
    }
}
