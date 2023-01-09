/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2022-2023 Intel Corporation.
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
 * @file test_bssl_utils.c
 *
 * This file provides a QAT Engine test functions.
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifndef __USE_GNU
# define __USE_GNU
#endif

#ifndef QAT_DEBUG
# define TEST_DEBUG
#endif

#include <stdio.h>

#include "qat_utils.h"

/* OpenSSL Includes */
#include <openssl/base.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

void *qat_load_priv_key(const char *key_path)
{
    EVP_PKEY *pkey = NULL;
    BIO *bp;

    if (access(key_path, F_OK)) {
        printf("-- File %s does not exist\n", key_path);
        return NULL;
    }

    bp = BIO_new_file(key_path, "r");
    if (!bp) {
        printf("-- BIO new failed\n");
        return NULL;
    }

    pkey = PEM_read_bio_PrivateKey(bp, NULL, 0, NULL);
    if (!pkey) {
        printf("-- Error in PEM_read_bio_PrivateKey\n");
        return NULL;
    }

    return pkey;
}

void qat_hex_dump2(const unsigned char p[], int l)
{
    int i;

    if (NULL != p && l > 0) {
        for (i = 0; i < l; i++) {
            if (i > 0 && i % 16 == 0)
                puts("");
            else if (i > 0 &&  i % 8 == 0) {
                putc('-', stdout);
                putc(' ', stdout);
            }
            printf("%02x ", p[i]);
        }
    }
    puts("");
}
