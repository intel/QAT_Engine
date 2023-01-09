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
 * @file test_bssl_utils.h
 *
 * This file provides a QAT Engine test functions.
 *
 *****************************************************************************/

#ifndef TEST_BSSL_UTILS_H
# define TEST_BSSL_UTILS_H

#ifndef QAT_DEBUG
# define PRINT_TIPS() printf("To get more debug information, enable \
QATEngine option: --enable-qat_debug\n");
#else
# define PRINT_TIPS()
#endif

# define T_DEBUG(fmt_str, ...)                                 \
    do {                                                       \
        struct timespec ts = { 0 };                            \
        clock_gettime(CLOCK_MONOTONIC, &ts);                   \
        printf("[DEBUG][%lld.%06ld] PID [%d]"                  \
                " Thread [%lx][%s:%d:%s()] "fmt_str,           \
                (long long)ts.tv_sec,                          \
                ts.tv_nsec / NANO_TO_MICROSECS,                \
                getpid(), (long)pthread_self(),  __FILE__,     \
                __LINE__,__func__,##__VA_ARGS__);              \
        fflush(stdout);                                        \
    } while (0)

# define T_ERROR(fmt_str, ...)                                 \
    do {                                                       \
        struct timespec ts = { 0 };                            \
        clock_gettime(CLOCK_MONOTONIC, &ts);                   \
        printf("[ERROR][%lld.%06ld] PID [%d]"                  \
                " Thread [%lx][%s:%d:%s()] "fmt_str,           \
                (long long)ts.tv_sec,                          \
                ts.tv_nsec / NANO_TO_MICROSECS,                \
                getpid(), (long)pthread_self(),  __FILE__,     \
                __LINE__,__func__,##__VA_ARGS__);              \
        fflush(stdout);                                        \
    } while (0)

# define T_WARN(fmt_str, ...)                                  \
    do {                                                       \
        struct timespec ts = { 0 };                            \
        clock_gettime(CLOCK_MONOTONIC, &ts);                   \
        printf("[WARN][%lld.%06ld] PID [%d]"                   \
                " Thread [%lx][%s:%d:%s()] "fmt_str,           \
                (long long)ts.tv_sec,                          \
                ts.tv_nsec / NANO_TO_MICROSECS,                \
                getpid(), (long)pthread_self(),  __FILE__,     \
                __LINE__,__func__,##__VA_ARGS__);              \
        fflush(stdout);                                        \
    } while (0)

#ifdef QAT_DEBUG
# define T_DUMP_ALGO_INPUT_DATA(data, size, tag)               \
    do {                                                       \
        printf("=========================\n");                 \
        printf("%s Input(Bytes: %ld):\n", #tag, size);         \
        qat_hex_dump2(data, size);                             \
        printf("=========================\n");                 \
        fflush(stdout);                                        \
    } while (0)

# define T_DUMP_ALGO_OUTPUT_DATA(data, size, tag)              \
    do {                                                       \
        printf("=========================\n");                 \
        printf("%s Output(Bytes: %ld):\n", #tag, size);        \
        qat_hex_dump2(data, size);                             \
        printf("=========================\n");                 \
        fflush(stdout);                                        \
    } while (0)

# define T_DUMP_ECDSA_SIGN_INPUT(data, size)                   \
    do {                                                       \
        printf("=========================\n");                 \
        printf("ECDSA Sign Input Message(Bytes: %ld):\n", size);\
        printf("%s\n", data);                                  \
        printf("=========================\n");                 \
        fflush(stdout);                                        \
    } while (0)

# define T_DUMP_ECDSA_SIGN_OUTPUT(data, size)                  \
    do {                                                       \
        printf("=========================\n");                 \
        printf("ECDSA Sign Output(Bytes: %d):\n", size);       \
        qat_hex_dump2(data, size);                             \
        printf("=========================\n");                 \
        fflush(stdout);                                        \
    } while (0)


# define T_DUMP_RSA_SIGN_INPUT(data, size)                     \
    T_DUMP_ALGO_INPUT_DATA(data, size, RSA Sign)

# define T_DUMP_RSA_SIGN_OUTPUT(data, size)                    \
    T_DUMP_ALGO_OUTPUT_DATA(data, size, RSA Sign)

# define T_DUMP_RSA_DECRYPT_INPUT(data, size)                  \
    T_DUMP_ALGO_INPUT_DATA(data, size, RSA Decrypt)

# define T_DUMP_RSA_DECRYPT_OUTPUT(data, size)                 \
    T_DUMP_ALGO_OUTPUT_DATA(data, size, RSA Decrypt)

#else
    # define T_DUMP_ECDSA_SIGN_INPUT(data, size)
    # define T_DUMP_ECDSA_SIGN_OUTPUT(data, size)
    # define T_DUMP_RSA_SIGN_INPUT(data, size)
    # define T_DUMP_RSA_SIGN_OUTPUT(data, size)
    # define T_DUMP_RSA_DECRYPT_INPUT(data, size)
    # define T_DUMP_RSA_DECRYPT_OUTPUT(data, size)
#endif

void *qat_load_priv_key(const char *key_path);

void qat_hex_dump2(const unsigned char p[], int l);

#endif /* TEST_BSSL_UTILS_H */
