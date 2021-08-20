/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021 Intel Corporation.
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

/* macros defined to allow use of the cpu get and set affinity functions */
#define _GNU_SOURCE
#define __USE_GNU

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#ifndef __FreeBSD__
# include <sched.h>
# else
# include <pthread_np.h>
# include <sys/types.h>
# include <sys/sysctl.h>
# include <unistd.h>
# include <errno.h>
#endif
#include <sys/time.h>
#include <unistd.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/async.h>

#include "tests.h"
#include "../qat_utils.h"

#ifndef __FreeBSD__
typedef  cpu_set_t qat_cpuset;
#else
typedef  cpuset_t  qat_cpuset;
#endif

FILE *qatDebugLogFile = NULL;

static pthread_cond_t ready_cond;
static pthread_cond_t start_cond;
static pthread_cond_t stop_cond;
static pthread_mutex_t mutex;
static int cleared_to_start;
static int active_thread_count;
static int ready_thread_count;

/* thread_count - control number of threads created */
static int thread_count = 1;

/* define the initial test values */
static int core_count = 1;
static int enable_engine = 0;

/* test_count - specify the number of operations that each thread does */
static int test_count = 1;
static int test_size = 2048;  /* default key size is 2048 */
static int cpu_affinity = 0;
static int test_alg = 0;
static int enable_perf = 0;
static int enable_async = 0;
#ifdef QAT_OPENSSL_3
static int use_callback_mode = 0;
#endif
static int enable_external_polling = 0;
static int enable_event_driven_polling = 0;
static int enable_negative = 0;
static int print_output = 0;
static int verify = 0;
static int curve = P_CURVE_256;  /* default curve is NIST Prime-Curve P-256 */
static int kdf = 1;
static int zero_copy = 0;
static int cpu_core_info = 0;
static int qatPerformOpRetries;
static char *engine_id;
static ENGINE *engine = NULL;
static char *default_tls_string = "TLSv1_2";
static char *default_digest_string = "SHA256";
static char *tls_version = NULL;
static char *digest_kdf = NULL;
static int prf_op = -1;
#if OPENSSL_VERSION_NUMBER > 0x10101000L
static int hkdf_op = -1;
static int ecx_op = -1;
#endif
static int explicit_engine = 0;
static int async_jobs = 1;
static int sw_fallback = 0;
static int sign_only = 0;
static int verify_only = 0;
static int encrypt_only = 0;
static int decrypt_only = 0;

/* Thread_info structure declaration */
typedef struct {
    pthread_t th;
    int id;
    int count;
    TEST_PARAMS *test_params;
}
THREAD_INFO;

#define MAX_STAT 10

#ifdef __FreeBSD__
# define MAX_CORE 88
#else
# define MAX_CORE 48
#endif

typedef union {
    struct {
        int user;
        int nice;
        int sys;
        int idle;
        int io;
#ifndef __FreeBSD__
        int irq;
        int softirq;
#else
        /* interrupt */
        int intr;
#endif
        int context;
    };
    int d[MAX_STAT];
}
cpu_time_t;

static cpu_time_t cpu_time[MAX_CORE];
static cpu_time_t cpu_time_total;
#ifndef __FreeBSD__
static cpu_time_t cpu_context;
#endif

#define MAX_THREAD 1024

THREAD_INFO tinfo[MAX_THREAD];

#ifdef __FreeBSD__
# define CPU_STATES 5
# define CP_USER    0
# define CP_NICE    1
# define CP_SYS     2
# define CP_INTR    3
# define CP_IDLE    4

# define CP_STAT_SIZE (MAX_CORE * CPU_STATES)
#endif

typedef struct options_data {
    const char *name;
    int test_size;
    int test_alg;
    int curve_name;
    int op;
} option_data;

static const option_data rsa_choices[] = {
    {"rsa1024", 1024, TEST_RSA, 0, 0},
    {"rsa2048", 2048, TEST_RSA, 0, 0},
    {"rsa3072", 3072, TEST_RSA, 0, 0},
    {"rsa4096", 4096, TEST_RSA, 0, 0},
};

static const option_data dsa_choices[] = {
    {"dsa1024", 1024, TEST_DSA, 0, 0},
    {"dsa2048", 2048, TEST_DSA, 0, 0},
    {"dsa4096", 4096, TEST_DSA, 0, 0},
};

static const option_data ecdh_choices[] = {
    {"ecdhp192", 0, TEST_ECDH, P_CURVE_192, 0},
    {"ecdhp224", 0, TEST_ECDH, P_CURVE_224, 0},
    {"ecdhp256", 0, TEST_ECDH, P_CURVE_256, 0},
    {"ecdhp384", 0, TEST_ECDH, P_CURVE_384, 0},
    {"ecdhp521", 0, TEST_ECDH, P_CURVE_521, 0},
    {"ecdhk163", 0, TEST_ECDH, K_CURVE_163, 0},
    {"ecdhk233", 0, TEST_ECDH, K_CURVE_233, 0},
    {"ecdhk283", 0, TEST_ECDH, K_CURVE_283, 0},
    {"ecdhk409", 0, TEST_ECDH, K_CURVE_409, 0},
    {"ecdhk571", 0, TEST_ECDH, K_CURVE_571, 0},
    {"ecdhb163", 0, TEST_ECDH, B_CURVE_163, 0},
    {"ecdhb233", 0, TEST_ECDH, B_CURVE_233, 0},
    {"ecdhb283", 0, TEST_ECDH, B_CURVE_283, 0},
    {"ecdhb409", 0, TEST_ECDH, B_CURVE_409, 0},
    {"ecdhb571", 0, TEST_ECDH, B_CURVE_571, 0},
    {"ecdhx25519", 0, TEST_ECX, 0, 0},
    {"ecdhx448", 0, TEST_ECX, 0, 1},
};

static const option_data ecdsa_choices[] = {
    {"ecdsap192", 0, TEST_ECDSA, P_CURVE_192, 0},
    {"ecdsap224", 0, TEST_ECDSA, P_CURVE_224, 0},
    {"ecdsap256", 0, TEST_ECDSA, P_CURVE_256, 0},
    {"ecdsap384", 0, TEST_ECDSA, P_CURVE_384, 0},
    {"ecdsap521", 0, TEST_ECDSA, P_CURVE_521, 0},
    {"ecdsak163", 0, TEST_ECDSA, K_CURVE_163, 0},
    {"ecdsak233", 0, TEST_ECDSA, K_CURVE_233, 0},
    {"ecdsak283", 0, TEST_ECDSA, K_CURVE_283, 0},
    {"ecdsak409", 0, TEST_ECDSA, K_CURVE_409, 0},
    {"ecdsak571", 0, TEST_ECDSA, K_CURVE_571, 0},
    {"ecdsab163", 0, TEST_ECDSA, B_CURVE_163, 0},
    {"ecdsab233", 0, TEST_ECDSA, B_CURVE_233, 0},
    {"ecdsab283", 0, TEST_ECDSA, B_CURVE_283, 0},
    {"ecdsab409", 0, TEST_ECDSA, B_CURVE_409, 0},
    {"ecdsab571", 0, TEST_ECDSA, B_CURVE_571, 0},
};

static const option_data aes_choices[] = {
    {"aes128_cbc_hmac_sha1", 0, TEST_AES128_CBC_HMAC_SHA1, 0, 0},
    {"aes256_cbc_hmac_sha1", 0, TEST_AES256_CBC_HMAC_SHA1, 0, 0},
    {"aes128_cbc_hmac_sha256", 0, TEST_AES128_CBC_HMAC_SHA256, 0, 0},
    {"aes256_cbc_hmac_sha256", 0, TEST_AES256_CBC_HMAC_SHA256, 0, 0},
    {"aes128gcm", 0, TEST_AES128_GCM, 0, 0},
    {"aes256gcm", 0, TEST_AES256_GCM, 0, 0},
};

static const option_data sha3_choices[] = {
    {"sha3-224", 0, TEST_SHA3_224, 0, 0},
    {"sha3-256", 0, TEST_SHA3_256, 0, 0},
    {"sha3-384", 0, TEST_SHA3_384, 0, 0},
    {"sha3-512", 0, TEST_SHA3_512, 0, 0},
};

/******************************************************************************
* function:
*    cpu_time_add (cpu_time_t *t1, cpu_time_t *t2, int subtract)
*
* @param t1 [IN] - cpu time
* @param t2 [IN] - cpu time
* @param substract [IN] - subtract flag
*
* description:
*   CPU timing calculation functions.
******************************************************************************/
static void cpu_time_add (cpu_time_t *t1, cpu_time_t *t2, int subtract)
{
    int i;

    for (i = 0; i < MAX_STAT; i++) {
        if (subtract)
            t1->d[i] -= t2->d[i];
        else
            t1->d[i] += t2->d[i];
    }
}

#ifndef __FreeBSD__
/******************************************************************************
* function:
*   read_stat (int init)
*
* @param init [IN] - op flag
*
* description:
*  read in CPU status from proc/stat file
******************************************************************************/
static void read_stat (int init)
{
     char line[1024];
     char tag[10];
     FILE *fp;
     int index = 0;
     int i;
     cpu_time_t tmp;

     if ((fp = fopen("/proc/stat", "r")) == NULL) {
         WARN("# FAIL: Can't open proc stat\n");
         exit(1);
     }

     while (!feof(fp)) {
         if (fgets(line, sizeof(line) - 1, fp) == NULL)
             break;

         if (!strncmp(line, "ctxt", 4)) {
             if (sscanf(line, "%*s %d", &tmp.context) < 1)
                 goto parse_fail;

             cpu_time_add(&cpu_context, &tmp, init);
             continue;
         }

         if (strncmp(line, "cpu", 3))
             continue;

         if (sscanf(line, "%s %d %d %d %d %d %d %d",
                 tag,
                 &tmp.user,
                 &tmp.nice,
                 &tmp.sys,
                 &tmp.idle,
                 &tmp.io,
                 &tmp.irq,
                 &tmp.softirq) < 8)
             goto parse_fail;

         if (!strcmp(tag, "cpu"))
             cpu_time_add(&cpu_time_total, &tmp, init);
         else if (!strncmp(tag, "cpu", 3)) {
             index = atoi(&tag[3]);
             if ((index >= 0) && (index < MAX_CORE))
                 cpu_time_add(&cpu_time[index], &tmp, init);
         }
     }

     if (!init && cpu_core_info) {
         printf("      %10s %10s %10s %10s %10s %10s %10s\n",
                 "user", "nice", "sys", "idle", "io", "irq", "sirq");
         for (i = 0; i < MAX_CORE + 1; i++) {
             cpu_time_t *t;

             if (i == MAX_CORE) {
                 printf("total ");
                 t = &cpu_time_total;
             }
             else {
                 printf("cpu%d  ", i);
                 t = &cpu_time[i];
             }

             printf(" %10d %10d %10d %10d %10d %10d %10d\n",
                     t->user,
                     t->nice,
                     t->sys,
                     t->idle,
                     t->io,
                     t->irq,
                     t->softirq);
         }

         printf("Context switches: %d\n", cpu_context.context);
     }

     fclose(fp);
     return;

parse_fail:
     WARN("# FAIL: Failed to parse %s\n", line);
     exit(1);
}
#else

/******************************************************************************
* function:
*   read_stat_systemctl (int init)
*
* @param init [IN] - op flag
*
* description:
*  read in CPU status from systemctl system call using kern.cp_time and
   kern.cp_times

******************************************************************************/
static void read_stat_systemctl (int init)
{
    int index = 0;
    int i;
    int core;
    cpu_time_t tmp;
    long cputotal[CPU_STATES];
    long pcpustat[CP_STAT_SIZE];
    size_t cputotal_size;
    size_t pcpustat_size;

    cputotal_size = sizeof(cputotal);
    pcpustat_size = sizeof(pcpustat);

    if (sysctlbyname("kern.cp_time", &cputotal, &cputotal_size, NULL, 0) < 0) {
        WARN("#FAIL: Error reading kern.cp_time sysctl : %s\n",
                     strerror(errno));
        exit(1);
    }

    tmp.user = (int) cputotal[CP_USER];
    tmp.nice = (int) cputotal[CP_NICE];
    tmp.sys = (int) cputotal[CP_SYS];
    tmp.intr = (int) cputotal[CP_INTR];
    tmp.idle = (int) cputotal[CP_IDLE];

    cpu_time_add(&cpu_time_total, &tmp, init);

    if (sysctlbyname("kern.cp_times", &pcpustat, &pcpustat_size, NULL, 0) < 0) {
        WARN("#FAIL: Error reading kern.cp_times sysctl : %s\n",
                     strerror(errno));
        exit(1);
    }

    core = 0;
    for (index = 0; index < CP_STAT_SIZE; index += CPU_STATES) {
        tmp.user = (int) pcpustat[index + CP_USER];
        tmp.nice = (int) pcpustat[index + CP_NICE];
        tmp.sys = (int) pcpustat[index + CP_SYS];
        tmp.intr = (int) pcpustat[index + CP_INTR];
        tmp.idle = (int) pcpustat[index + CP_IDLE];

        if(core < MAX_CORE + 1)
            cpu_time_add(&cpu_time[core], &tmp, init);

        core = core + 1;
    }

    if (!init && cpu_core_info) {
        printf("      %10s %10s %10s %10s %10s\n", "user", "nice", "sys",
                   "intr", "idle");
        for (i = 0; i < MAX_CORE + 1; i++) {
            cpu_time_t *t;

            if (i == MAX_CORE) {
                printf("total ");
                t = &cpu_time_total;
            }
            else {
                printf("cpu%d  ", i);
                t = &cpu_time[i];
            }

            printf(" %10d %10d %10d %10d %10d\n", t->user, t->nice,
                       t->sys, t->intr, t->idle);
        }

    }

    return;
}
#endif

/******************************************************************************
 * function:
 *   rdtsc (void)

 * description:
 *   Timetamp Counter for measuring clock cycles in performance testing.
 ******************************************************************************/
static __inline__ unsigned long long rdtsc(void)
{
    unsigned long a, d;

    asm volatile ("rdtsc":"=a" (a), "=d"(d));

    return (((unsigned long long)a) | (((unsigned long long)d) << 32));
}


/******************************************************************************
* function:
*           *test_name(int test)
*
* @param test [IN] - test case
*
* description:
*   test_name selection list
******************************************************************************/
char *test_name(int test)
{
    switch (test) {
    case TEST_RSA:
        return "RSA";
    case TEST_DSA:
        return "DSA";
    case TEST_DH:
        return "DH";
    case TEST_AES128_CBC_HMAC_SHA1:
        return "AES128 CBC HMAC SHA1";
    case TEST_AES256_CBC_HMAC_SHA1:
        return "AES256 CBC HMAC SHA1";
    case TEST_AES128_CBC_HMAC_SHA256:
        return "AES128 CBC HMAC SHA256";
    case TEST_AES256_CBC_HMAC_SHA256:
        return "AES256 CBC HMAC SHA256";
    case TEST_ECDH:
        return "ECDH";
    case TEST_ECDSA:
        return "ECDSA";
    case TEST_PRF:
        return "PRF";
#if OPENSSL_VERSION_NUMBER > 0x10101000L
    case TEST_HKDF:
        return "HKDF";
    case TEST_ECX:
        return "ECX";
#endif
    case TEST_AES128_GCM:
        return "AES128 GCM";
    case TEST_AES256_GCM:
        return "AES256 GCM";
    case TEST_SHA3_224:
        return "SHA3-224";
    case TEST_SHA3_256:
        return "SHA3-256";
    case TEST_SHA3_384:
        return "SHA3-384";
    case TEST_SHA3_512:
        return "SHA3-512";
    case 0:
        return "all tests";
    default:
        return "*unknown or not supported on this platform*";
    }
}

/******************************************************************************
* function:
*           *ecdh_curve__name(int type)
*
* @param test [IN] - curve type
*
* description:
*   ecdh curve name selection list
******************************************************************************/
char *ecdh_curve_name(int type)
{
    switch (type) {
    case P_CURVE_192:
        return "NIST Prime-Curve P-192";
    case P_CURVE_224:
        return "NIST Prime-Curve P-224";
    case P_CURVE_256:
        return "NIST Prime-Curve P-256";
    case P_CURVE_384:
        return "NIST Prime-Curve P-384";
    case P_CURVE_521:
        return "NIST Prime-Curve P-521";
    case K_CURVE_163:
        return "NIST Binary-Curve K-163";
    case K_CURVE_233:
        return "NIST Binary-Curve K-233";
    case K_CURVE_283:
        return "NIST Binary-Curve K-283";
    case K_CURVE_409:
        return "NIST Binary-Curve K-409";
    case K_CURVE_571:
        return "NIST Binary-Curve K-571";
    case B_CURVE_163:
        return "NIST Binary-Curve B-163";
    case B_CURVE_233:
        return "NIST Binary-Curve B-233";
    case B_CURVE_283:
        return "NIST Binary-Curve B-283";
    case B_CURVE_409:
        return "NIST Binary-Curve B-409";
    case B_CURVE_571:
        return "NIST Binary-Curve B-571";
    case 0:
        return "all curves";
    default:
        return "*unknown*";
    }
}

/******************************************************************************
* function:
*           usage(char *program)
*
*
* @param program [IN] - input argument
*
* description:
*   test application usage help
******************************************************************************/
static void usage(char *program)
{
    printf("\nUsage:\n");
    printf("\t%s [-c <count>] ", program);
    printf("[-n <count>] [-nc <count>] [-af] [-p] [-v] [-async] ");
#ifdef QAT_OPENSSL_3
    printf("[-callback] ");
#endif
    printf("[-u] [-perf] [-x] [-z] [-epoll] [-poll] [-f] [-engine <string>] ");
    printf("[-ne] [-tls_version <tls>] [-di <digest>] ");
    printf("[-async_jobs <count>] [-prf_op <op>] ");
#if OPENSSL_VERSION_NUMBER > 0x10101000L
    printf("[-hkdf_op <op>]");
#endif
    printf("[-sw_fallback] ");
    printf("[-sign] [-verify] [-encrypt] [-decrypt] [-h] [<test>] \n");
    printf("Where:\n");
    printf("\t-c      specifies the test iteration count\n");
    printf("\t-n      specifies the number of threads to run\n");
    printf("\t-nc     specifies the number of CPU cores\n");
    printf("\t-af     enables core affinity\n");
    printf("\t-p      print the test output\n");
    printf("\t-v      verify the output\n");
    printf("\t-async  enable asynchronous processing\n");
#ifdef QAT_OPENSSL_3
    printf("\t-callback enable callback mode in asynchronous processing\n");
#endif
    printf("\t-u      display cpu usage per core\n");
    printf("\t-perf   run performance measurement\n");
    printf("\t-x      force EVP layer calls to use an explicit engine.\n");
    printf("\t        Note: This will cause any calls that are not implemented\n");
    printf("\t        by the engine under test to fail.\n");
    printf("\t-z      enable zero copy mode\n");
    printf("\t-epoll  enable event driven polling\n");
    printf("\t-poll   enable external polling of the engine (qat engine only)\n");
    printf("\t-f      specifies whether to enable(1) or disable(0) KDF for ECDH \n");
    printf("\t-engine specify the engine to use, eg -engine qatengine (default is software)\n");
    printf("\t-ne     enables negative scenario test cases \n");
    printf("\t-tls_version  specifies tls_version TLSv1,TLSv1_1, TLSv1_2 \n");
    printf("\t-di     specifies digest for prf and hkdf (OpenSSL_1.1.1 & higher), MD5, SHA256, SHA384, SHA512 \n");
    printf("\t-async_jobs   specifies the number of asynchronous jobs per thread\n");
    printf("\t-prf_op specifies the PRF operation required (default is to run them all)\n");
#if OPENSSL_VERSION_NUMBER > 0x10101000L
    printf("\t-hkdf_op specifies the HKDF operation (0-Extract&Expand 1-Extract 2-Expand (default is to run them all))\n");
#endif
    printf("\t-sw_fallback  enables the sw fallback feature (qat engine only)\n");
    printf("\t-sign   sign only\n");
    printf("\t-verify verify only\n");
    printf("\t-encrypt encrypt only\n");
    printf("\t-decrypt decrypt only\n");
    printf("\t-h      print this usage\n");
    printf("\nTests:\n");
    printf("\trsa1024 RSA 1024 test\n");
    printf("\trsa2048 RSA 2048 test\n");
    printf("\trsa3072 RSA 3072 test\n");
    printf("\trsa4096 RSA 4096 test\n");
    printf("\tdsa1024 DSA 1024 test\n");
    printf("\tdsa2048 DSA 2048 test\n");
    printf("\tdsa4096 DSA 4096 test\n");
    printf("\tdh      DH test\n");
    printf("\taes128_cbc_hmac_sha1 AES128 CBC HMAC SHA1 test\n");
    printf("\taes256_cbc_hmac_sha1 AES256 CBC HMAC SHA1 test\n");
    printf("\taes128_cbc_hmac_sha256 AES128 CBC HMAC SHA256 test\n");
    printf("\taes256_cbc_hmac_sha256 AES256 CBC HMAC SHA256 test\n");
    /* ECDH options */
    printf("\tecdhp192 ECDH P192 test\n");
    printf("\tecdhp224 ECDH P224 test\n");
    printf("\tecdhp256 ECDH P256 test\n");
    printf("\tecdhp384 ECDH P384 test\n");
    printf("\tecdhp521 ECDH P521 test\n");
    printf("\tecdhk163 ECDH K163 test\n");
    printf("\tecdhk233 ECDH K233 test\n");
    printf("\tecdhk283 ECDH K283 test\n");
    printf("\tecdhk409 ECDH K409 test\n");
    printf("\tecdhk571 ECDH K571 test\n");
    printf("\tecdhb163 ECDH B163 test\n");
    printf("\tecdhb233 ECDH B233 test\n");
    printf("\tecdhb283 ECDH B283 test\n");
    printf("\tecdhb409 ECDH B409 test\n");
    printf("\tecdhb571 ECDH B571 test\n");
#if OPENSSL_VERSION_NUMBER > 0x10101000L
    /* ECX options */
    printf("\tecdhx25519 ECX25519 test\n");
    printf("\tecdhx448 ECX448 test\n");
#endif
    /* ECDSA options */
    printf("\tecdsap192 ECDSA P192 test\n");
    printf("\tecdsap224 ECDSA P224 test\n");
    printf("\tecdsap256 ECDSA P256 test\n");
    printf("\tecdsap384 ECDSA P384 test\n");
    printf("\tecdsap521 ECDSA P521 test\n");
    printf("\tecdsak163 ECDSA K163 test\n");
    printf("\tecdsak233 ECDSA K233 test\n");
    printf("\tecdsak283 ECDSA K283 test\n");
    printf("\tecdsak409 ECDSA K409 test\n");
    printf("\tecdsak571 ECDSA K571 test\n");
    printf("\tecdsab163 ECDSA B163 test\n");
    printf("\tecdsab233 ECDSA B233 test\n");
    printf("\tecdsab283 ECDSA B283 test\n");
    printf("\tecdsab409 ECDSA B409 test\n");
    printf("\tecdsab571 ECDSA B571 test\n");
    printf("\tprf     PRF test\n");
#if OPENSSL_VERSION_NUMBER > 0x10101000L
    printf("\thkdf    HKDF test\n");
#endif
    printf("\taes128gcm AES128 GCM test\n");
    printf("\taes256gcm AES256 GCM test\n");
#if OPENSSL_VERSION_NUMBER > 0x10101000L
    printf("\tsha3-224    SHA3 224 test\n");
    printf("\tsha3-256    SHA3 256 test\n");
    printf("\tsha3-384    SHA3 384 test\n");
    printf("\tsha3-512    SHA3 512 test\n\n");
#endif

    printf("\nIf test is not specified, one iteration "
           "of each test is executed and verified.\n");

    /* In order to measure the maximum throughput from QAT, the iteration
     * test will repeat actual operation to keep QAT busy without reset
     * input variables such as initial vector. Thus, the iteration count should
     * limited to one for verification propose.
     */
    printf("The test iteration count will set to 1 if the verify flag raised.\n\n");

    exit(EXIT_SUCCESS);
}

/******************************************************************************
* function:
* parse_option(int *index,
*                        int argc,
*                       char *argv[],
*                        int *value)
*
* @param index [IN] - index pointer
* @param argc [IN] - input argument count
* @param argv [IN] - argument buffer
* @param value [IN] - input value pointer
*
* description:
*   user input arguments check
******************************************************************************/
static void parse_option(int *index, int argc, char *argv[], int *value)
{
    if (*index + 1 >= argc) {
        WARN("\n# FAIL: Parameter expected\n");
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    (*index)++;

    *value = atoi(argv[*index]);

}

/******************************************************************************
* function:
* parse_option_string(int *index,
*                        int argc,
*                       char *argv[],
*                       char *str
*
* @param index [IN] - index pointer
* @param argc [IN] - input argument count
* @param argv [IN] - argument buffer
* @param str [IN] - char * pointer to strore the string
*
* description:
*   user input arguments check
******************************************************************************/
static void parse_option_string(int *index, int argc, char *argv[], char **str)
{
    if (*index + 1 >= argc) {
        WARN("\n# FAIL: Parameter expected\n");
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    (*index)++;

    *str = argv[*index];

}

/******************************************************************************
* function:
*           handle_option(int argc,
*                         char *argv[],
*                         int *index)
*
* @param argc [IN] - input argument count
* @param argv [IN] - argument buffer
* @param index [IN] - index pointer
*
* description:
*   input operation handler
******************************************************************************/
static void handle_option(int argc, char *argv[], int *index)
{
    char *option = argv[*index];
    int i, size;

    if (!strcmp(option, "-n"))
        parse_option(index, argc, argv, &thread_count);
    else if (!strcmp(option, "-perf"))
        enable_perf = 1;
    else if (!strcmp(option, "-async"))
        enable_async = 1;
#ifdef QAT_OPENSSL_3
    else if (!strcmp(option, "-callback"))
        use_callback_mode = 1;
#endif
    else if (!strcmp(option, "-epoll"))
        enable_event_driven_polling = 1;
    else if (!strcmp(option, "-poll"))
        enable_external_polling = 1;
    else if (!strcmp(option, "-c"))
        parse_option(index, argc, argv, &test_count);
    else if (!strcmp(option, "-af"))
        cpu_affinity = 1;
    else if (!strcmp(option, "-nc"))
        parse_option(index, argc, argv, &core_count);
    else if (!strcmp(option, "-engine")) {
        parse_option_string(index, argc, argv, &engine_id);
        enable_engine = 1;
        printf("[%s] engine enabled ! \n", engine_id);
    } else if (!strcmp(option, "-p"))
        print_output = 1;
    else if (!strcmp(option, "-v"))
        verify = 1;
    else if (!strcmp(option, "-sign"))
        sign_only = 1;
    else if (!strcmp(option, "-verify"))
        verify_only = 1;
    else if (!strcmp(option, "-encrypt"))
        encrypt_only = 1;
    else if (!strcmp(option, "-decrypt"))
        decrypt_only = 1;
    else if (!strcmp(option, "dh"))
        test_alg = TEST_DH;
    else if (!strcmp(option, "prf"))
        test_alg = TEST_PRF;
    else if (!strcmp(option, "hkdf"))
        test_alg = TEST_HKDF;
    else if (!strncmp(option, "rsa", strlen("rsa"))) {
        size = sizeof(rsa_choices) / sizeof(option_data);
        for (i = 0; i < size; i++)
            if (!strcmp(option, rsa_choices[i].name)) {
                test_size = rsa_choices[i].test_size;
                test_alg = rsa_choices[i].test_alg;
                break;
            }
    } else if (!strncmp(option, "dsa", strlen("dsa"))) {
        size = sizeof(dsa_choices) / sizeof(option_data);
        for (i = 0; i < size; i++)
            if (!strcmp(option, dsa_choices[i].name)) {
                test_size = dsa_choices[i].test_size;
                test_alg = dsa_choices[i].test_alg;
                break;
            }
    } else if (!strncmp(option, "ecdh", strlen("ecdh"))) {
        size = sizeof(ecdh_choices) / sizeof(option_data);
        for (i = 0; i < size; i++)
            if (!strcmp(option, ecdh_choices[i].name)) {
                curve = ecdh_choices[i].curve_name;
                test_alg = ecdh_choices[i].test_alg;
                ecx_op = ecdh_choices[i].op;
                break;
            }
    } else if (!strncmp(option, "ecdsa", strlen("ecdsa"))) {
        size = sizeof(ecdh_choices) / sizeof(option_data);
        for (i = 0; i < size; i++)
            if (!strcmp(option, ecdsa_choices[i].name)) {
                curve = ecdsa_choices[i].curve_name;
                test_alg = ecdsa_choices[i].test_alg;
                break;
            }
    } else if (!strncmp(option, "aes", strlen("aes"))) {
           size = sizeof(aes_choices) / sizeof(option_data);
           for (i = 0; i < size; i++)
                if (!strcmp(option, aes_choices[i].name)) {
                    test_alg = aes_choices[i].test_alg;
                    break;
                }
    } else if (!strncmp(option, "sha3", strlen("sha3"))) {
           size = sizeof(sha3_choices) / sizeof(option_data);
           for (i = 0; i < size; i++)
                if (!strcmp(option, sha3_choices[i].name)) {
                    test_alg = sha3_choices[i].test_alg;
                    test_size = 4096;
                    break;
                }
    } else if (!strcmp(option, "-f"))
        parse_option(index, argc, argv, &kdf);
    else if (!strcmp(option, "-x"))
        explicit_engine = 1;
    else if (!strcmp(option, "-z"))
        zero_copy = 1;
    else if (!strcmp(option, "-u"))
        cpu_core_info = 1;
    else if (!strcmp(option, "-tls_version"))
         parse_option_string(index, argc, argv, &tls_version);
    else if(!strcmp(option, "-ne"))
         enable_negative = 1;
    else if (!strcmp(option, "-di"))
         parse_option_string(index, argc, argv, &digest_kdf);
    else if (!strcmp(option, "-async_jobs")) {
        parse_option(index, argc, argv, &async_jobs);
        if (async_jobs <= 0) {
            WARN("\n# FAIL: Invalid number of async_jobs.\n");
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    else if (!strcmp(option, "-prf_op")) {
        parse_option(index, argc, argv, &prf_op);
        if (prf_op < 0 || prf_op > 4) {
            WARN("\n# FAIL: Invalid prf_op number.\n");
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
#if OPENSSL_VERSION_NUMBER > 0x10101000L
    else if (!strcmp(option, "-hkdf_op")) {
        parse_option(index, argc, argv, &hkdf_op);
        if (hkdf_op < 0 || hkdf_op > 2) {
            WARN("\n# FAIL: Invalid hkdf_op number.\n");
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
#endif
    else if (!strcmp(option, "-sw_fallback"))
        sw_fallback = 1;
    else if (!strcmp(option, "-h"))
        usage(argv[0]);
    else {
        WARN("\n# FAIL: Invalid option '%s'\n", option);
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    if (verify) {
        test_count = 1;
        core_count = 1;
        thread_count = 1;
    }
}

/******************************************************************************
* function:
*           *thread_worker(void *arg)
*
* @param arg [IN] - thread structure info
*
* description:
*   thread worker setups. the threads will launch at the same time after
*   all of them in ready condition.
******************************************************************************/
static void *thread_worker(void *arg)
{

     THREAD_INFO *info = (THREAD_INFO *) arg;

     if (enable_engine && !enable_external_polling){
         ENGINE_ctrl_cmd(engine,"SET_INSTANCE_FOR_THREAD",info->id,NULL,NULL,0);
     }

     /* mutex lock for thread count */
     pthread_mutex_lock(&mutex);
     ready_thread_count++;
     pthread_cond_broadcast(&ready_cond);
     pthread_mutex_unlock(&mutex);

     /* waiting for thread clearance */
     pthread_mutex_lock(&mutex);

     while (!cleared_to_start)
         pthread_cond_wait(&start_cond, &mutex);

     pthread_mutex_unlock(&mutex);

     tests_run(info->test_params, info->id);

    /* update active threads */
    pthread_mutex_lock(&mutex);
    active_thread_count--;
    pthread_cond_broadcast(&stop_cond);
    pthread_mutex_unlock(&mutex);

    return NULL;
}

/******************************************************************************
* function:
*           performance_test(void)
*
* description:
*   performers test application running on user definition .
******************************************************************************/
static void performance_test(void)
{
    int i, j;
    int coreID = 0;
    int sts = 1;
    qat_cpuset cpuset;
    struct timeval start_time;
    struct timeval stop_time;
    int elapsed = 0;
    unsigned long long rdtsc_start = 0;
    unsigned long long rdtsc_end = 0;
    int bytes_to_bits = 8;
    int crypto_ops_per_test = 1;
    float throughput = 0.0;
    char name[20];
    THREAD_INFO *info = NULL;

    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&ready_cond, NULL);
    pthread_cond_init(&start_cond, NULL);
    pthread_cond_init(&stop_cond, NULL);

    for (i = 0; i < thread_count; i++) {
        info = &tinfo[i];

        info->id = i;
        info->count = (test_count / thread_count) / async_jobs;
        info->test_params = OPENSSL_malloc(sizeof(TEST_PARAMS));
        if (info->test_params == NULL) {
            WARN("# FAIL: Unable to allocate info->test_params\n");
            exit(EXIT_FAILURE);
        }
        memset(info->test_params, 0, sizeof(TEST_PARAMS));
        info->test_params->engine_id = engine_id;
        info->test_params->count = &info->count;
        info->test_params->type = test_alg;
        info->test_params->size = test_size;
        info->test_params->e = engine;
        info->test_params->print_output = print_output;
        info->test_params->verify = verify;
        info->test_params->performance = enable_perf;
        info->test_params->enable_external_polling = enable_external_polling;
        info->test_params->enable_event_driven_polling =
            enable_event_driven_polling;
        info->test_params->enable_async = enable_async;
#ifdef QAT_OPENSSL_3
        info->test_params->use_callback_mode = use_callback_mode;
#endif
        info->test_params->enable_negative = enable_negative;
        info->test_params->curve = curve;
        info->test_params->kdf = kdf;
        info->test_params->tls_version = tls_version;
        info->test_params->digest_kdf = digest_kdf;
        info->test_params->explicit_engine = explicit_engine;
        info->test_params->sign_only = sign_only;
        info->test_params->verify_only = verify_only;
        info->test_params->encrypt_only = encrypt_only;
        info->test_params->decrypt_only = decrypt_only;
        info->test_params->async_jobs = async_jobs;
        info->test_params->prf_op = prf_op;
#if OPENSSL_VERSION_NUMBER > 0x10101000L
        info->test_params->hkdf_op = hkdf_op;
        info->test_params->ecx_op = ecx_op;
#endif
        info->test_params->jobs = OPENSSL_malloc(sizeof(ASYNC_JOB*)*async_jobs);
        if (info->test_params->jobs == NULL) {
            WARN("# FAIL: Unable to allocate info->test_params->jobs\n");
            exit(EXIT_FAILURE);
        }
        info->test_params->awcs = OPENSSL_malloc(
            sizeof(ASYNC_WAIT_CTX*)*async_jobs);
        if (info->test_params->awcs == NULL) {
            WARN("# FAIL: Unable to allocate info->test_params->awcs\n");
            exit(EXIT_FAILURE);
        }
        memset(info->test_params->jobs, 0, sizeof(ASYNC_JOB*)*async_jobs);
        memset(info->test_params->awcs, 0, sizeof(ASYNC_WAIT_CTX*)*async_jobs);
        for (j =0; j < async_jobs; j++) {
            info->test_params->awcs[j] = ASYNC_WAIT_CTX_new();
            if (info->test_params->awcs[j] == NULL) {
                WARN("# FAIL: Unable to allocate info->test_params->awcs[%d]\n",
                     j);
                exit(EXIT_FAILURE);
            }
        }
        pthread_create(&tinfo[i].th, NULL, thread_worker, (void *)&tinfo[i]);
        sprintf(name, "worker-%d", i);

        /* cpu affinity setup */
        if (cpu_affinity == 1) {
            CPU_ZERO(&cpuset);

            /* assigning thread to different cores */
            coreID = (i % core_count);
            CPU_SET(coreID, &cpuset);

            sts = pthread_setaffinity_np(info->th, sizeof(qat_cpuset), &cpuset);
            if (sts != 0) {
                WARN("# FAIL: pthread_setaffinity_np error, status = %d \n",
                     sts);
                exit(EXIT_FAILURE);
            }
            sts = pthread_getaffinity_np(info->th, sizeof(qat_cpuset), &cpuset);
            if (sts != 0) {
                WARN("# FAIL: pthread_getaffinity_np error, status = %d \n",
                     sts);
                exit(EXIT_FAILURE);
            }

            if (CPU_ISSET(coreID, &cpuset))
                printf("Thread %d assigned on CPU core %d\n", i, coreID);
        }
    }

    /* set all threads to ready condition */
    pthread_mutex_lock(&mutex);

    while (ready_thread_count < thread_count)
        pthread_cond_wait(&ready_cond, &mutex);

    pthread_mutex_unlock(&mutex);

    printf("Beginning test ....\n");
    /* all threads start at the same time */
#ifdef __FreeBSD__
    read_stat_systemctl(1);
#else
    read_stat(1);
#endif
    gettimeofday(&start_time, NULL);
    rdtsc_start = rdtsc();
    pthread_mutex_lock(&mutex);
    cleared_to_start = 1;

    pthread_cond_broadcast(&start_cond);
    pthread_mutex_unlock(&mutex);

    /* wait for other threads stop */
    pthread_mutex_lock(&mutex);

    while (active_thread_count > 0)
        pthread_cond_wait(&stop_cond, &mutex);

    pthread_mutex_unlock(&mutex);

    for (i = 0; i < thread_count; i++) {
        if (pthread_join(tinfo[i].th, NULL))
            printf("Could not join thread id - %d !\n", i);
    }

    rdtsc_end = rdtsc();
    gettimeofday(&stop_time, NULL);
#ifdef __FreeBSD__
    read_stat_systemctl(0);
#else
    read_stat(0);
#endif
    printf("All threads complete\n\n");

    /* generate report */
    elapsed = (stop_time.tv_sec - start_time.tv_sec) * 1000000 +
        (stop_time.tv_usec - start_time.tv_usec);

    /* Cipher tests contain 2 performOp calls. */
    crypto_ops_per_test = 2;

    /* Cast test_size * test_count to avoid int overflow */
    throughput = ((float)test_size * (float)test_count *
                  (bytes_to_bits * crypto_ops_per_test) / (float)elapsed);

    printf("Elapsed time   = %.3f msec\n", (float)elapsed / 1000);
    printf("Operations     = %d\n", test_count);

    printf("Time per op    = %.3f usec (%d ops/sec)\n",
           (float)elapsed / test_count,
           (int)((float)test_count * 1000000.0 / (float)elapsed));

    printf("Elapsed cycles = %llu\n", rdtsc_end - rdtsc_start);

    printf("Throughput     = %.2f (Mbps)\n", throughput);

    if (enable_engine){
        ENGINE_ctrl_cmd(engine, "GET_NUM_OP_RETRIES", 0,
                        &qatPerformOpRetries,NULL,0);
        printf("Retries        = %d\n", qatPerformOpRetries);
    }

    printf("\nCSV summary:\n");

    printf("Algorithm,"
           "Test_type,"
           "Using_engine,"
           "Core_affinity,"
           "Elapsed_usec,"
           "Cores,"
           "Threads,"
           "Count,"
           "Data_size,"
           "Mbps,"
           "CPU_time,"
           "User_time,"
           "Kernel_time\n");

    int cpu_time = 0;
    int cpu_user = 0;
    int cpu_kernel = 0;
#ifdef __FreeBSD__
    cpu_time = (cpu_time_total.user +
                cpu_time_total.nice +
                cpu_time_total.sys +
                cpu_time_total.intr) * 10000 / core_count;
#else
    cpu_time = (cpu_time_total.user +
                cpu_time_total.nice +
                cpu_time_total.sys +
                cpu_time_total.io +
                cpu_time_total.irq +
                cpu_time_total.softirq) * 10000 / core_count;
#endif
    cpu_user = cpu_time_total.user * 10000 / core_count;
    cpu_kernel = cpu_time_total.sys * 10000 / core_count;
    printf("csv,%s,%d,%s,%s,%d,%d,%d,%d,%d,%.2f,%d,%d,%d\n",
           test_name(test_alg),
           test_alg,
           (enable_engine) ? "Yes" : "No",
           cpu_affinity ? "Yes" : "No",
           elapsed,
           core_count, thread_count, test_count, test_size, throughput,
           cpu_time * 100 / elapsed,
           cpu_user * 100 / elapsed,
           cpu_kernel * 100 / elapsed);

    for (i = 0; i < thread_count; i++) {
        info = &tinfo[i];
        for (j =0; j < async_jobs; j++)
            ASYNC_WAIT_CTX_free(info->test_params->awcs[j]);
        if (info->test_params->awcs)
            OPENSSL_free(info->test_params->awcs);
        if (info->test_params->jobs)
            OPENSSL_free(info->test_params->jobs);
        if (info->test_params)
            OPENSSL_free(info->test_params);
    }
}

/******************************************************************************
* function:
*           functional_test(void)
*
* description:
*    Default testing application, a single thread test running through all the
*    test cases with testing function definition values
******************************************************************************/
static void functional_test(void)
{
    int i;
    int count = 1;
    TEST_PARAMS args;

    args.engine_id = engine_id;
    args.count = &test_count;
    args.type = test_alg;
    args.size = test_size;
    args.e = engine;
    args.print_output = print_output;
    args.verify = verify;
    args.performance = enable_perf;
    args.enable_external_polling = enable_external_polling;
    args.enable_event_driven_polling = enable_event_driven_polling;
    args.enable_async = enable_async;
#ifdef QAT_OPENSSL_3
    args.use_callback_mode = use_callback_mode;
#endif
    args.enable_negative = enable_negative;
    args.curve = curve;
    args.kdf = kdf;
    args.tls_version = tls_version;
    args.digest_kdf = digest_kdf;
    args.explicit_engine = explicit_engine;
    args.sign_only = sign_only;
    args.verify_only = verify_only;
    args.encrypt_only = encrypt_only;
    args.decrypt_only = decrypt_only;
    args.async_jobs = async_jobs;
    args.prf_op = prf_op;
#if OPENSSL_VERSION_NUMBER > 0x10101000L
    args.hkdf_op = hkdf_op;
    args.ecx_op = ecx_op;
#endif
    args.jobs = OPENSSL_malloc(sizeof(ASYNC_JOB*)*async_jobs);
    if (args.jobs == NULL) {
        WARN("# FAIL: Unable to allocate args.jobs\n");
        exit(EXIT_FAILURE);
    }
    args.awcs = OPENSSL_malloc(sizeof(ASYNC_WAIT_CTX*)*async_jobs);
    if (args.awcs == NULL) {
        WARN("# FAIL: Unable to allocate args.awcs\n");
        exit(EXIT_FAILURE);
    }
    memset(args.jobs, 0, sizeof(ASYNC_JOB*)*async_jobs);
    memset(args.awcs, 0, sizeof(ASYNC_WAIT_CTX*)*async_jobs);
    for (i =0; i < async_jobs; i++) {
        args.awcs[i] = ASYNC_WAIT_CTX_new();
        if (args.awcs[i] == NULL) {
            WARN("# FAIL: Unable to allocate args.awcs[%d]\n", i);
            exit(EXIT_FAILURE);
        }
    }

    if (test_alg == 0) {
        args.size   = 1024;
        args.verify = 1;
        args.count  = &count;
        printf("\nResults for functional test cases: force variables:- \nverify = %d, count = %d, size = %d\n",
               args.verify, *(args.count), args.size);
        for (i = 1; i < TEST_TYPE_MAX; i++) {
            if (zero_copy &&
                (i == TEST_DSA||
                 i == TEST_DH ||
                 i == TEST_ECDH ||
                 i == TEST_ECDSA ||
                 i == TEST_PRF
#if OPENSSL_VERSION_NUMBER > 0x10101000L
                 || i == TEST_HKDF
                 || i == TEST_ECX
#endif
                )) {
                printf ("skipping %s in zero copy mode\n",
                        test_name(i));
                continue;
            }
            args.type = i;
            tests_run(&args, 0);
        }
    } else if (test_alg == TEST_TYPE_MAX - 1) {
        args.count = &test_count;
        tests_run(&args, 0);
    } else
        tests_run(&args, 0);

    for (i =0; i < async_jobs; i++)
        ASYNC_WAIT_CTX_free(args.awcs[i]);

    OPENSSL_free(args.awcs);
    OPENSSL_free(args.jobs);
}

/******************************************************************************
* function:
*           main(int argc,
*                char *argv[])
*
* @param argc [IN] - input argument count
* @param argv [IN] - argument buffer
*
* description:
*    main function is used to setups QAT engine setups and define the testing
*    type.
******************************************************************************/
int main(int argc, char *argv[])
{
    int i = 0;
    tls_version = default_tls_string;
    digest_kdf = default_digest_string;

    QAT_DEBUG_LOG_INIT();

    for (i = 1; i < argc; i++) {
        /*
         *  allow rsa, dsa, dh, aes, prf, hkdf, sha-3 & ecx options
         *  without '-' prefix
         */
        if ((argv[i][0] != '-') &&
            (argv[i][0] != 'r') &&
            (argv[i][0] != 'd') &&
            (argv[i][0] != 'a') &&
            (argv[i][0] != 'e') &&
            (argv[i][0] != 'p') &&
            (argv[i][0] != 'h') &&
            (argv[i][0] != 's'))
            break;

        handle_option(argc, argv, &i);
    }

    /* The thread count should not be great than the test count */
    if (thread_count > test_count ) {
        thread_count = test_count;
        printf("\nWARNING - Thread Count cannot exceed the Test Count");
        printf("\nThread Count adjusted to: %d\n\n", thread_count);
    }

    if (i < argc) {
        WARN("# FAIL: This program does not take arguments, please use -h for usage.\n");
        exit(EXIT_FAILURE);
    }

    active_thread_count = thread_count;
    ready_thread_count = 0;

    /* Zero Copy Mode is currently disabled */
    if (zero_copy) {
         printf("Zero copy mode is currently disabled! Running in standard mode\n");
         zero_copy = 0;
    }

    /* Load engine for workers */
    if (enable_engine) {
        ENGINE_load_builtin_engines();
        engine = tests_initialise_engine(engine_id, enable_external_polling,
                                         enable_event_driven_polling,
                                         enable_async, zero_copy, sw_fallback);

        if (!engine) {
            WARN("# FAIL: ENGINE load error, exit! \n");
            exit(EXIT_FAILURE);
        }
    }
    else
        printf("Engine disabled! using software implementation\n");

    printf("\nQAT Engine Test Application\n");
    printf("\n\tCopyright (C) 2021 Intel Corporation\n");
    printf("\nTest Parameters:\n\n");
    printf("\tTest Type:            %s\n",
           enable_perf ? "Performance" : "Functional");
    printf("\tTest Alg:             %d (%s", test_alg, test_name(test_alg));
    if (sign_only) printf(" sign");
    if (verify_only) printf(" verify");
    if (encrypt_only) printf(" encrypt");
    if (decrypt_only) printf(" decrypt");
    printf(")\n");
    printf("\tTest Count:           %d\n", test_count);
    printf("\tThread Count:         %d\n", thread_count);
    printf("\tMessage Size:         %d\n", test_size);
    printf("\tPrint Output:         %s\n", print_output ? "Yes" : "No");
    printf("\tCPU Core Affinity:    %s\n", cpu_affinity ? "Yes" : "No");
    printf("\tNumber of Cores:      %d\n", core_count);
    printf("\tAsynchronous:         %s\n", enable_async ? "Yes" : "No");
#ifdef QAT_OPENSSL_3
    printf("\tUse asynch callback:  %s\n", use_callback_mode ? "Yes" : "No");
#endif
    printf("\tExternal Polling:     %s\n",
           enable_external_polling ? "Yes" : "No");
    printf("\tEvent Driven Polling: %s\n",
           enable_event_driven_polling ? "Yes" : "No");
    printf("\tEngine Enabled:       %s\n", enable_engine ? "Yes" : "No");
    printf("\tForce Explicit Engine:%s\n", explicit_engine ? "Yes" : "No");
    printf("\tNegative Scenario:    %s\n", enable_negative ? "Yes" : "No");
    printf("\tPRF TLS Version:      %s\n", tls_version);
    if (strcmp(tls_version, "TLSv1_2") == 0)
        printf("\tKDF Digest:           %s\n", digest_kdf);
    if (prf_op != -1)
        printf("\tPRF Operation:        %d\n", prf_op);
#if OPENSSL_VERSION_NUMBER > 0x10101000L
    if (hkdf_op != -1)
        printf("\tHKDF Operation:       %d\n", hkdf_op);
    if (ecx_op != -1)
        printf("\tECX Operation:        %s\n", ecx_op ? "X448" : "X25519");
#endif
    printf("\tSW Fallback:          %s\n", sw_fallback ? "Yes" : "No");
    printf("\n");

    if (enable_perf == 0)
        functional_test();
    else
        performance_test();

    if (engine)
        tests_cleanup_engine(engine, engine_id, enable_async,
                             enable_external_polling,
                             enable_event_driven_polling, sw_fallback);

    return 0;
}
