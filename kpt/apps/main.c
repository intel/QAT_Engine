/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023-2025 Intel Corporation.
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
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include "kpt_key.h"
#include "kpt_dev_pp.h"

void tool_usage(void)
{
    log_print("kpttool generate or parse wpk\n");
    log_print("Usage of kpttool:\n");
    log_print("kpttool -act [gen|par]  -alg [rsa|ecc] -in [<cpk.key>|<wpk.key>] -out <wpk.key>\n");
    log_print("        -act (action): gen (generate wpk (wrap private key)), par (parse wpk (wrap private key))\n");
    log_print("        -alg (algorithm): rsa (-in rsa private key file), ecc (-in ecc private key)\n");
    log_print("        -in:  -act gen input cpk (customer private key) file\n");
    log_print("              -act par input wpk (wrap private key) file\n");
    log_print("        -out: -act gen output wpk (wrap private key) file\n");
    log_print("e.g. kpttool -act gen -alg ecc -in ec_secp256r1_private.key -out ec_secp256r1_wpk.key\n");
    log_print("e.g. kpttool -act par -alg ecc -in ec_secp256r1_wpk.key\n");
    log_print("e.g. kpttool -act gen -alg rsa -in rsa_2k_private.key -out rsa_2k_wpk.key\n");
    log_print("e.g. kpttool -act par -alg rsa -in rsa_2k_wpk.key\n");
}

int main(int argc, char** argv)
{
    unsigned char *input_file = NULL;
    unsigned char *output_file = NULL;
    unsigned char *action = NULL;
    unsigned char *algo = NULL;
    int ret = 0;

    argc--;
    argv++;

    while (argc >= 1) {
        if (strcmp(*argv, "-act") == 0) {
            if (--argc < 1) {
                tool_usage();
                return 0;
            }
            action = *(++argv);
        } else if (strcmp(*argv, "-alg") == 0) {
            if (--argc < 1) {
                tool_usage();
                return 0;
            }
            algo = *(++argv);
        } else if (strcmp(*argv, "-in") == 0) {
            if (--argc < 1) {
                tool_usage();
                return 0;
            }
            input_file = *(++argv);
        } else if (strcmp(*argv, "-out") == 0) {
            if (--argc < 1) {
                tool_usage();
                return 0;
            }
            output_file = *(++argv);
        } else {
            tool_usage();
            return 0;
        }
        argc--;
        argv++;
    }

    if (!action || !algo) {
        tool_usage();
        exit(1);
    }
    log_print("input file %s \n",input_file);
    log_print("output file %s \n",output_file);
    log_print("alg %s \n",algo);
    log_print("action %s \n",action);

    if (strcmp(algo, "ecc") == 0) {
        if (strcmp(action, "gen") == 0) {
            ret = kpt_ecc_wpk_gen(input_file, output_file);
        } else if (strcmp(action, "par") == 0) {
            kpt_ecc_wpk ecc_wpk;
            ret = kpt_ecc_wpk_parse(&ecc_wpk, input_file);
        } else {
            tool_usage();
        }
    } else if (strcmp(algo, "rsa") == 0) {
        if (strcmp(action, "gen") == 0) {
            ret = kpt_rsa_wpk_gen(input_file, output_file);
        } else if (strcmp(action, "par") == 0) {
            kpt_rsa_wpk rsa_wpk;
            ret = kpt_rsa_wpk_parse(&rsa_wpk, input_file);
        } else {
            tool_usage();
        }
    } else {
        tool_usage();
    }

    return ret;
}
