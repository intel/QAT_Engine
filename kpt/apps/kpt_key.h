/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2023 Intel Corporation.
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

#ifndef __KPT_KEY_H__
#define __KPT_KEY_H__

#define MAX_ECC_KEY_SIZE (1024)
#define MAX_ESWK_SIZE (512)
#define MAX_KPT_RSA_KEY_TYPE1_SIZE (2064)
#define MAX_KPT_RSA_KEY_TYPE2_SIZE (3600)
#define MAX_KPT_RSA_KEY_N_SIZE (1024)
#define MAX_KPT_RSA_KEY_E_SIZE (1024)
#define MAX_CPU_SOCKET (32)

typedef enum kpt_gen_s {
    KPT_GEN1 = 1,
    KPT_GEN2
} kpt_gen_t;

typedef struct kpt_ecc_wpk_st {
    long version;
    unsigned char swkSec[MAX_CPU_SOCKET][MAX_ESWK_SIZE];
    unsigned char swkPub[MAX_CPU_SOCKET][MAX_ESWK_SIZE];
    unsigned char wpk[MAX_ECC_KEY_SIZE];
    unsigned char pub_key[MAX_ECC_KEY_SIZE];
    int swkSec_size[MAX_CPU_SOCKET];
    int swkPub_size[MAX_CPU_SOCKET];
    int wpk_size;
    int pub_key_size;
    int curve_nid;             /* optional NID for named curve */
    int wrapping_alg_nid;
} kpt_ecc_wpk;

typedef struct kpt_rsa_wpk_st {
    long version;
    long size;
    unsigned char swkSec[MAX_CPU_SOCKET][MAX_ESWK_SIZE];
    unsigned char swkPub[MAX_CPU_SOCKET][MAX_ESWK_SIZE];
    unsigned char wpk_type1[MAX_KPT_RSA_KEY_TYPE1_SIZE];
    unsigned char wpk_type2[MAX_KPT_RSA_KEY_TYPE2_SIZE];
    unsigned char n[MAX_KPT_RSA_KEY_N_SIZE];
    unsigned char e[MAX_KPT_RSA_KEY_E_SIZE];
    int swkSec_size[MAX_CPU_SOCKET];
    int swkPub_size[MAX_CPU_SOCKET];
    int wpk_type1_size;
    int wpk_type2_size;
    int n_size;
    int e_size;
    int rsa_nid;
    int wrapping_alg_nid;
} kpt_rsa_wpk;

int kpt_ecc_wpk_gen(unsigned char *cpk_file, unsigned char *wpk_file);
int kpt_ecc_wpk_parse(kpt_ecc_wpk *ecc_wpk, unsigned char *wpk_file);
int kpt_rsa_wpk_gen(unsigned char *cpk_file, unsigned char *wpk_file);
int kpt_rsa_wpk_parse(kpt_rsa_wpk *rsa_wpk, unsigned char *wpk_file);

#endif
