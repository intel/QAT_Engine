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
 * @file main.c
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

/* System Includes */
#include <string.h>

/* Local Includes */
#include "qat_bssl.h"
#include "qat_utils.h"
#include "test_bssl_utils.h"
#include "test_bssl_rsa.h"
#include "test_bssl_ecdsa.h"

/* OpenSSL Includes */
#include <openssl/evp.h>

char *key_path = NULL;
char *bin_name = NULL;
int flag = 0;

static void process_test_job(void);
static int parse_private_key(void);
static int parse_user_option(int argc, char *argv[]);
static void print_test_help(void);
static const char *get_bin_name(const char *path);

int main(int argc, char *argv[])
{
    if (!parse_user_option(argc, argv)) {
        process_test_job();
    }

    return 0;
}

void process_test_job(void)
{
    if (parse_private_key() <= 0) {
        T_DEBUG("Test Failed\n");
        PRINT_TIPS();
        return;
    }
    T_DEBUG("Test Success\n");
    PRINT_TIPS();

    if (bin_name) {
        OPENSSL_free(bin_name);
    }
}

int parse_private_key(void)
{
    int ret = -1;
    EVP_PKEY *pkey = NULL;

    if (NULL == (pkey = (EVP_PKEY *)qat_load_priv_key(key_path))) {
        T_ERROR("Failed to load private key\n");
        return ret;
    }

    switch(EVP_PKEY_id(pkey)) {
        case EVP_PKEY_RSA:
            ENGINE_load_qat();
            ret = qat_rsa_test(pkey, flag);
            ENGINE_unload_qat();
            break;
        case EVP_PKEY_EC:
            ENGINE_load_qat();
            ret = qat_ecdsa_test(pkey, flag);
            ENGINE_unload_qat();
            break;
        default:
            T_WARN("Unknown algorithm type, only RSA and ECDSA supported\n");
            break;
    }

    return ret;
}

int parse_user_option(int argc, char *argv[])
{
    int input;

    if(!get_bin_name(argv[0])) {
        T_ERROR("Get executable binary name failed\n");
        return 1;
    }

    while ((input = getopt(argc, argv, "a::d::h::k:")) != -1) {
        switch (input) {
            case 'k':
                {
                    int slen = strlen(optarg);
                    if (!optarg || access(optarg, F_OK) == -1 ) {
                        T_ERROR("key_path not set or exist\n");
                        return 1;
                    }

                    if (NULL == key_path)
                        key_path = (char *)OPENSSL_zalloc(slen + 1);
                    if (NULL == key_path) {
                        T_ERROR("Error: allocated memory failed\n");
                        return 1;
                    }
                    strncpy(key_path, optarg, slen);
                }
                break;
            case 'h':
                print_test_help();
                return 1;
            case 'd':
                flag |= RSA_DECRYPT_TEST;
                break;
            case 'a':
                flag |= RSA_ASYNC_MODE;
                break;
            case '?':
                T_WARN("Unknown option: -%c\n",(char)optopt);
                print_test_help();
                return 1;
        }
    }

    if (!key_path) {
        T_ERROR("private key path not set\n");
        print_test_help();
        return 1;
    }

    return 0;
}

const char *get_bin_name(const char *path)
{
    char *p = strrchr(path, '/');

    if (strstr(p, "lt-")) {
        p = strchr(p,'-');
    }

    if (p) {
        /* Save executable binary name */
        bin_name = OPENSSL_strdup(++p);
    }

    return bin_name;
}

void print_test_help(void)
{
    printf("Usage: ./%s [-h/-d/-a] <-k>\n", bin_name);
    printf("\t-a : \tEnable async mode\n");
    printf("\t-d : \tTest on rsa private decrypt \n");
    printf("\t-h : \tPrint all avaliable options\n");
    printf("\t-k : \tSet private key file path for test purpose e.g. /opt/rsa_key.pmem\n");
    printf("Test command lines for reference:\n");
    printf("\t./%s -k /opt/rsa_private_2k.key\n", bin_name);
    printf("\t./%s -k /opt/rsa_private_2k.key -a\n", bin_name);
    printf("\t./%s -k /opt/rsa_private_2k.key -d\n", bin_name);
    printf("\t./%s -k /opt/rsa_private_4k.key\n", bin_name);
    printf("\t./%s -k /opt/ec-secp384r1-priv-key.pem\n", bin_name);
    printf("\t./%s -k /opt/ec-secp384r1-priv-key.pem -a\n", bin_name);
}
