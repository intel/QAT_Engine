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

#ifndef __KPT_DEV_PP_H__
#define __KPT_DEV_PP_H__

#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>

#define MAX_SOCKET (32)
#define KPT_PER_PART_KEY_N_LEN (384)
#define KPT_PER_PART_KEY_E_LEN (8)
#define KPT_PER_PART_SIG_LEN (384)

typedef struct {
    unsigned char pub_n[KPT_PER_PART_KEY_N_LEN];
    int len_pub_n;
    unsigned char pub_e[KPT_PER_PART_KEY_E_LEN];
    int len_pub_e;
    unsigned char sig[KPT_PER_PART_SIG_LEN];
    int len_sig;
} kpt_per_part_context;

extern kpt_per_part_context kpt_per_part_context_ptr[MAX_SOCKET];

extern int cpu_socket_num;

extern int kpt_get_per_part_key(void);

enum log_level {
    LOG_ERR = 0,
    LOG_DEBUG,
    LOG_PRINT
};

const char *log_level_str(int level);
int xlog(int level, const char *fmt, ...);

#define log_err(fmt, ...)   xlog(LOG_ERR, fmt, ##__VA_ARGS__)
#define log_debug(fmt, ...)  xlog(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define log_print(fmt, ...)  xlog(LOG_PRINT, fmt, ##__VA_ARGS__)

#endif
