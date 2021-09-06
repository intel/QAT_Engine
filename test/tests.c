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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/async.h>
#include <openssl/engine.h>
#include <openssl/des.h>
#include <openssl/rand.h>

#define _GNU_SOURCE
#define __USE_GNU

#include <pthread.h>

#include "tests.h"
#include "../qat_utils.h"

# include <fcntl.h>
# ifndef __FreeBSD__
#  include <sys/epoll.h>
# endif
# define MAX_EVENTS 32
# define MAX_CRYPTO_INSTANCES 64
# define QAT_ENGINE_ID "qatengine"
# define QAT_ENGINE_ID_LENGTH 9
typedef struct {
    int eng_fd;
    int (*eng_poll_handler_ptr) (ENGINE *eng, int *poll_status);
} ENG_POLL_EVENT;

#ifndef __FreeBSD__
static int efd = 0;
struct epoll_event event[MAX_CRYPTO_INSTANCES];
static int no_of_inst = 0;
#endif

static int qat_keep_polling = 0;
pthread_t *testapp_polling_threads;
pthread_t *testapp_heartbeat_threads;

static int eng_poll_handler(ENGINE *eng, int *poll_status)
{
    /* Poll for 0 means process all packets on the instance */
    if (!ENGINE_ctrl_cmd(eng, "POLL", 0, &poll_status, NULL, 0)) {
        WARN("# FAIL: POLL not supported or failed\n");
        return 0;
    }
    return 1;
}

static int eng_heartbeat_handler(ENGINE *eng, int *poll_status)
{
    if (!ENGINE_ctrl_cmd(eng, "HEARTBEAT_POLL", 0, &poll_status, NULL, 0)) {
        WARN("# FAIL: HEARTBEAT_POLL not supported or failed\n");
        return 0;
    }
    return 1;
}

#ifndef __FreeBSD__
/******************************************************************************
 * function:
 *   qat_epoll_engine(ENGINE* eng, struct epoll_event *events, int *poll_status,
 *                    int timeout)
 *
 * description:
 *   In epoll for completion of async event.
 ******************************************************************************/
int qat_epoll_engine(ENGINE* eng, struct epoll_event *events, int *poll_status,
                     int timeout)
{
    int n = 0, i = 0;
    ENG_POLL_EVENT *eng_poll_event;
    n = epoll_wait(efd, events, MAX_EVENTS, timeout);
    for (i = 0; i < n; ++i) {
        if ((events[i].data.ptr) && (events[i].events & EPOLLIN)) {
            eng_poll_event = (ENG_POLL_EVENT *) events[i].data.ptr;
            if (!(eng_poll_event->eng_poll_handler_ptr(eng, poll_status))) {
                WARN("# FAIL: CTRL command not supported or failed\n");
                return 0;
            }
        }
    }
    return 1;
}

static void *ePoll_loop(void *engine)
{
    int poll_status = 0;
    ENGINE* eng = (ENGINE*)engine;
    int poll_interval = 1000;
    struct epoll_event *events = calloc(MAX_EVENTS, sizeof(struct epoll_event));
    if (events == NULL) {
        WARN("# FAIL: Error allocating events\n");
        return NULL;
    }
    while (qat_keep_polling)
        qat_epoll_engine(eng, events, &poll_status, poll_interval);

    free(events);
    return NULL;
}
#endif
static void *poll_loop(void *engine)
{
    int poll_status = 0;

    struct timespec reqTime = { 0 };
    struct timespec remTime = { 0 };
    unsigned int retry_count = 0; /* to prevent too much time drift */

    while (qat_keep_polling) {
        reqTime.tv_nsec = 10000;
        eng_poll_handler(engine, &poll_status);

        retry_count = 0;
        do {
            retry_count++;
            nanosleep(&reqTime, &remTime);
            reqTime.tv_sec = remTime.tv_sec;
            reqTime.tv_nsec = remTime.tv_nsec;
            if ((errno < 0) && (EINTR != errno)) {
                WARN("# FAIL: nanosleep system call failed: errno %i\n",
                     errno);
                break;
            }
        } while ((retry_count <= 4) && (EINTR == errno));
    }
    return NULL;
}

static void *heartbeat_poll_loop(void *engine)
{
    int poll_status = 0;

    struct timespec reqTime = { 0 };
    struct timespec remTime = { 0 };
    unsigned int retry_count = 0; /* to prevent too much time drift */

    while (qat_keep_polling) {
        reqTime.tv_sec = 1;
        eng_heartbeat_handler(engine, &poll_status);

        retry_count = 0;
        do {
            retry_count++;
            nanosleep(&reqTime, &remTime);
            reqTime.tv_sec = remTime.tv_sec;
            reqTime.tv_nsec = remTime.tv_nsec;
            if ((errno < 0) && (EINTR != errno)) {
                WARN("# FAIL: nanosleep system call failed: errno %i\n",
                     errno);
                break;
            }
        } while ((retry_count <= 4) && (EINTR == errno));
    }
    return NULL;
}


#ifdef QAT_OPENSSL_3
static int test_callback(void *arg)
{
    struct async_args_callback *args = (struct async_args_callback *)arg;

    DEBUG("test_callback start for async_job %d - job_ready = %d\n",
          args->i, args->job_ready);

    args->job_ready = 1;

    DEBUG("test_callback finish for async_job %d - job_ready = %d\n",
          args->i, args->job_ready);
    return 1;
}
#endif


int start_async_job(TEST_PARAMS *args, int (*func)(void *))
{
    int ret = 0;
    int poll_status = 0;
    int jobs_inprogress = 0;
    int i = 0;
    OSSL_ASYNC_FD job_fd = 0;
    OSSL_ASYNC_FD max_fd = 0;
    int select_result = 0;
    size_t numfds;
    fd_set waitfdset;
    struct timeval select_timeout;
    FD_ZERO(&waitfdset);
    select_timeout.tv_sec = 0;
    select_timeout.tv_usec = 0;
#ifdef QAT_OPENSSL_3
    struct async_args_callback **ptr_async_args_callback = NULL;
#endif
#ifndef __FreeBSD__
    struct epoll_event *events = calloc(MAX_EVENTS, sizeof(struct epoll_event));
    if (events == NULL) {
        WARN("# FAIL: Error allocating memory events.\n");
        return ret;
    }
#endif

    DEBUG("start_async_job() - start\n");
#ifdef QAT_OPENSSL_3
    if (args->use_callback_mode == 1) {
        ptr_async_args_callback =
            (struct async_args_callback **)OPENSSL_zalloc(
                sizeof(struct async_args_callback *)* args->async_jobs);
        if (ptr_async_args_callback == NULL) {
            WARN("# FAIL: Error allocating memory for ptr_async_args_callback.\n");
            return ret;
        }

        for (i = 0; i < args->async_jobs; i++) {
            ptr_async_args_callback[i] =
                (struct async_args_callback *)OPENSSL_zalloc(
                    sizeof(struct async_args_callback));
            if (ptr_async_args_callback[i] == NULL) {
                WARN("# FAIL: Error allocating memory for ptr_async_args_callback array elements).\n");
                return ret;
            }
        }
    }
#endif


    for (i = 0; i < args->async_jobs; i++) {
#ifdef QAT_OPENSSL_3
        if (args->use_callback_mode == 1) {
            ptr_async_args_callback[i]->i = i;

            if (ASYNC_WAIT_CTX_set_callback(args->awcs[i],
                                            test_callback,
                                            (void *)ptr_async_args_callback[i])
                != 1) {
                WARN("# FAIL: Error setting callback.\n");
                return ret;
            }
        }
#endif
        switch (ASYNC_start_job(&args->jobs[i], args->awcs[i], &ret, func, args,
                sizeof(TEST_PARAMS))) {
        case ASYNC_ERR:
        case ASYNC_NO_JOBS:
            DEBUG("ASYNC_ERR \n");
            break;
        case ASYNC_PAUSE:
            ++jobs_inprogress;
            DEBUG("ASYNC_PAUSE \n");
            break;
        case ASYNC_FINISH:
            DEBUG("ASYNC_FINISH \n");
            break;
        }
    }

    while (jobs_inprogress > 0) {
#ifdef QAT_OPENSSL_3
        if (args->use_callback_mode != 1) { /* Not callback mode so use fd's */
#endif
            for (i = 0; i < args->async_jobs && jobs_inprogress > 0; i++) {
                if (args->jobs[i] == NULL)
                    continue;

                if (!ASYNC_WAIT_CTX_get_all_fds(args->awcs[i], NULL, &numfds)
                    || numfds > 1) {
                    WARN("# FAIL: Too Many FD's in Use\n");
                    break;
                }
                ASYNC_WAIT_CTX_get_all_fds(args->awcs[i], &job_fd,  &numfds);
                FD_SET(job_fd, &waitfdset);
                if (job_fd > max_fd)
                    max_fd = job_fd;
            }

            if (max_fd >= (OSSL_ASYNC_FD)FD_SETSIZE) {
                WARN("# FAIL: Too many FD's in use in the system already\n");
                break;
            }

            select_result = select(max_fd + 1, &waitfdset, NULL, NULL,
                                   &select_timeout);

            if (select_result == -1 && errno == EINTR)
                continue;

            if (select_result == -1) {
                WARN("# FAIL: Select Failure \n");
                break;
            }

            if (select_result == 0) {
                if (args->e) {
                    if (strncmp(args->engine_id, QAT_ENGINE_ID,
                                QAT_ENGINE_ID_LENGTH) == 0) {
                        if (args->enable_external_polling) {
#ifndef __FreeBSD__
                            if (args->enable_event_driven_polling) {
                                qat_epoll_engine(args->e, events, &poll_status,
                                                 0);
                            }
                            else
                                eng_poll_handler(args->e, &poll_status);
#else
                            eng_poll_handler(args->e, &poll_status);
#endif
                        }
                    }
                }
                continue;
            }
#ifdef QAT_OPENSSL_3
        }
#endif
        for (i = 0; i < args->async_jobs; i++) {
            if (args->jobs[i] == NULL)
                continue;
#ifdef QAT_OPENSSL_3
            if (args->use_callback_mode != 1) { /* Not callback mode so use fd's */
#endif
                if (!ASYNC_WAIT_CTX_get_all_fds(args->awcs[i], NULL, &numfds)
                    || numfds > 1) {
                    WARN("# FAIL: Too Many FD's in Use\n");
                    break;
                }
                ASYNC_WAIT_CTX_get_all_fds(args->awcs[i], &job_fd,  &numfds);

                if (numfds == 1 && !FD_ISSET(job_fd, &waitfdset))
                    continue;
#ifdef QAT_OPENSSL_3
            } else { /* in callback mode */
                if (ptr_async_args_callback[i]->job_ready == 0)
                    continue;
            }
            if (args->use_callback_mode == 1) {
                /* reset the jobs_ready flag */
                DEBUG("Resetting job_ready flag for async_job %d\n", i);
                ptr_async_args_callback[i]->job_ready = 0;
            }
#endif
            switch (ASYNC_start_job(&args->jobs[i], args->awcs[i], &ret, func,
                    args, sizeof(TEST_PARAMS))) {
            case ASYNC_PAUSE:
                break;
            case ASYNC_FINISH:
                --jobs_inprogress;
                args->jobs[i] = NULL;
                break;
            case ASYNC_NO_JOBS:
            case ASYNC_ERR:
                --jobs_inprogress;
                args->jobs[i] = NULL;
                break;
            }
        }
        if (args->e) {
            if (strncmp(args->engine_id, QAT_ENGINE_ID, QAT_ENGINE_ID_LENGTH)
                == 0) {
                if (args->enable_external_polling) {
#ifndef __FreeBSD__
                    if (args->enable_event_driven_polling)
                        qat_epoll_engine(args->e, events, &poll_status, 0);
                    else
                        eng_poll_handler(args->e, &poll_status);
#else
                    eng_poll_handler(args->e, &poll_status);
#endif
                }
            }
        }
    } /* while (jobs_inprogress > 0) */
#ifndef __FreeBSD__
    free(events);
#endif
#ifdef QAT_OPENSSL_3
    if (ptr_async_args_callback != NULL) {
        for (i = 0; i < args->async_jobs; i++) {
            if (ptr_async_args_callback[i] != NULL)
                OPENSSL_free(ptr_async_args_callback[i]);
        }
        OPENSSL_free(ptr_async_args_callback);
    }
#endif
    DEBUG("start_async_job() returning ret = %d\n", ret);
    return ret;
}


/******************************************************************************
* function:
*   tests_initialise_engine(char *engine_id, int enable_external_polling,
*                           int enable_event_driven_polling,
*                           int enable_async, int zero_copy, int sw_fallback)
*
* description:
*   QAT engine initialise functions, load up the QAT engine and set as the
*   default engine in OpenSSL.
******************************************************************************/

ENGINE *tests_initialise_engine(char *engine_id, int enable_external_polling,
                                int enable_event_driven_polling,
                                int enable_async, int zero_copy,
                                int sw_fallback)
{
    /* loading qat engine */
    ENGINE *e = NULL;
#ifndef __FreeBSD__
    int instance_no = 0;
#endif

    DEBUG("Loading Engine ! \n");
    e = ENGINE_by_id(engine_id);

    if (!e) {
        WARN("# FAIL: Engine load failed, using default engine !\n");
        return NULL;
    }

    if (strncmp(engine_id, QAT_ENGINE_ID, QAT_ENGINE_ID_LENGTH) == 0) {
        if (enable_event_driven_polling) {
            if (!ENGINE_ctrl_cmd(e, "ENABLE_EVENT_DRIVEN_POLLING_MODE", 0,
                                 NULL, NULL, 0)) {
                WARN("# FAIL: Unable to enable event driven polling mode on engine\n");
                goto err;
            }
        }
        if (enable_external_polling) {
            if (!ENGINE_ctrl_cmd(e, "ENABLE_EXTERNAL_POLLING", 0, NULL,
                                 NULL, 0)) {
                WARN("# FAIL: Unable to enable polling on engine\n");
                goto err;
            }
        }
        if (sw_fallback) {
            if (!ENGINE_ctrl_cmd(e, "ENABLE_SW_FALLBACK", 0, NULL, NULL, 0)) {
                WARN("# FAIL: Unable to enable sw fallback on engine\n");
                goto err;
            }
        }
    }

    if (!ENGINE_init(e)) {
        WARN("# FAIL: Engine initialise failed ! using default engine\n");
        goto err;
    }

    /*
     * Set QAT engine as the default engine for all except ciphers.
     * The Cipher test cases utilise both engine and SW implementation.
     * Setting Engine as default leaves no way of accessing the SW ones.
     */
    ENGINE_set_default(e, (ENGINE_METHOD_ALL & ~(ENGINE_METHOD_CIPHERS)));


    if (strncmp(engine_id, QAT_ENGINE_ID, QAT_ENGINE_ID_LENGTH) == 0) {
#ifndef __FreeBSD__
        if (enable_external_polling && enable_event_driven_polling) {
            ENG_POLL_EVENT *eng_poll_event;
            int crypto_fd = 0;

            efd = epoll_create1(0);
            if (-1 == efd) {
                WARN("# FAIL: Error creating epoll fd\n");
                goto err;
            }

            if (!ENGINE_ctrl_cmd(e, "GET_NUM_CRYPTO_INSTANCES", 0, &no_of_inst,
                                 NULL, 0)) {
                WARN("# FAIL: Retrieving the total number of instances failed\n");
                goto err;
            }

            if (no_of_inst == 0) {
                WARN("# FAIL: No instances are available\n");
                goto err;
            }

            for (instance_no = 0; instance_no < no_of_inst; instance_no++) {
                if (!ENGINE_ctrl_cmd(e, "GET_EXTERNAL_POLLING_FD",
                                     instance_no, &crypto_fd, NULL, 0)) {
                    WARN("# FAIL: Unable to get polling fd for engine\n");
                    goto err;
                }
                eng_poll_event = malloc(sizeof(ENG_POLL_EVENT));
                if (NULL == eng_poll_event) {
                    WARN("# FAIL: Failed to malloc eng_poll_event in tests_initialise_engine()\n");
                    goto err;
                }
                eng_poll_event->eng_poll_handler_ptr = eng_poll_handler;
                eng_poll_event->eng_fd = crypto_fd;
                event[instance_no].events = EPOLLIN;
                event[instance_no].data.ptr = (void *)eng_poll_event;
                if (-1 == epoll_ctl(efd, EPOLL_CTL_ADD, crypto_fd,
                                    &event[instance_no])) {
                    WARN("# FAIL: Error adding fd to epoll\n");
                    if (eng_poll_event)
                        free(eng_poll_event);
                    goto err;
                }
                eng_poll_event = NULL;
            }
        }
#endif
        if (!enable_async && enable_external_polling) {
            qat_keep_polling = 1;
            testapp_polling_threads =
                (pthread_t *) OPENSSL_malloc(sizeof(pthread_t));
#ifndef __FreeBSD__
            pthread_create(&testapp_polling_threads[0], NULL,
                           enable_event_driven_polling ? ePoll_loop : poll_loop,
                           (void *)e);
#else
            pthread_create(&testapp_polling_threads[0], NULL,
                           poll_loop, (void *)e);
#endif

        }
        if (sw_fallback && enable_external_polling) {
            qat_keep_polling = 1;
            testapp_heartbeat_threads =
                (pthread_t *) OPENSSL_malloc(sizeof(pthread_t));
            pthread_create(&testapp_heartbeat_threads[0], NULL,
                           heartbeat_poll_loop, (void *)e);
        }
    }
    return e;
err:
    ENGINE_free(e);
    return NULL;
}

/******************************************************************************
* function:
*   tests_cleanup_engine (ENGINE *e)
*
* @param e [IN] - OpenSSL engine pointer
*
* description:
*   QAT engine clean up function.
******************************************************************************/
void tests_cleanup_engine(ENGINE * e, char *engine_id, int enable_async,
                          int enable_external_polling,
                          int enable_event_driven_polling,
                          int sw_fallback)
{
#ifndef __FreeBSD__
    int i = 0;
    int crypto_fd = 0;
    ENG_POLL_EVENT *eng_poll_event;
#endif
    if (strncmp(engine_id, QAT_ENGINE_ID, QAT_ENGINE_ID_LENGTH) == 0) {
        if (!enable_async && enable_external_polling) {
            qat_keep_polling = 0;
            pthread_join(testapp_polling_threads[0], NULL);
            if (testapp_polling_threads)
                OPENSSL_free(testapp_polling_threads);
#ifndef __FreeBSD__
            if (enable_event_driven_polling) {
                for (i = 0; i < no_of_inst; i++) {
                    eng_poll_event = (ENG_POLL_EVENT *)event[i].data.ptr;
                    crypto_fd = eng_poll_event->eng_fd;
                    if (-1 == epoll_ctl(efd, EPOLL_CTL_DEL, crypto_fd,
                                        &event[i])) {
                        WARN("# FAIL: Error removing fd from epoll\n");
                    }
                    if (eng_poll_event)
                        free(eng_poll_event);
                }
            }
#endif
        }
        if (sw_fallback && enable_external_polling) {
            qat_keep_polling = 0;
            pthread_join(testapp_heartbeat_threads[0], NULL);
            if (testapp_heartbeat_threads)
                OPENSSL_free(testapp_heartbeat_threads);
        }
    }
    if (e) {
        /* Release the functional reference from ENGINE_init() */
        ENGINE_finish(e);
        /* Release the structural reference from ENGINE_by_id() */
        ENGINE_free(e);
    }
    DEBUG("QAT Engine Freed ! \n");
}

/******************************************************************************
* function:
*   tests_hexdump (const char *title,
*                  const unsigned char *s,
*                  int l)
*
* @param title [IN] - hex dump title
* @param s [IN] - input pointer
* @param l [IN] - length of input
*
* description:
*   hex dump function.
******************************************************************************/
void tests_hexdump(const char *title, const unsigned char *s, int l)
{
    int i = 0;

    printf("%s", title);

    for (i = 0; i < l; i++) {
        if ((i % 8) == 0)
            printf("\n        ");

        printf("0x%02X, ", s[i]);
    }

    printf("\n\n");
}

/******************************************************************************
* function:
*   tests_run (TEST_PARAMS *args, int id)
*
* @param args [IN] - the test parameters
*
* description:
*   select which test to run based on user input
******************************************************************************/

void tests_run(TEST_PARAMS *args, int id)
{
    if (args->performance) {
        printf("\n|-----------------------------------------------------|\n");
        printf("|----------Thread ID %d, running in progress-----------|\n",
               id);
        printf("|-----------------------------------------------------|\n");
    }

    switch (args->type) {
#if defined(QAT_SW) || defined(QAT_HW)
    /*
     * RSA sign, verify, encrypt and decrypt tests, input message length 124
     * bytes
     */
    case TEST_RSA:
        tests_run_rsa(args);
        break;
    case TEST_ECDH:             /* ECDH test application */
        tests_run_ecdh(args);
        break;
    case TEST_ECDSA:            /* ECDSA test application */
        tests_run_ecdsa(args);
        break;
    case TEST_AES128_GCM:
        tests_run_aes128_gcm(args);
        break;
    case TEST_AES256_GCM:
        tests_run_aes256_gcm(args);
        break;
# if OPENSSL_VERSION_NUMBER > 0x10101000L
    case TEST_ECX:              /* X25519 & X448 test application */
        tests_run_ecx(args);
        break;
# endif
#endif

#ifdef QAT_HW
    /* DSA sign & verify tests, input message length 124 bytes */
    case TEST_DSA:
        tests_run_dsa(args);
        break;
    /* DH tests, input message length 124 bytes */
    case TEST_DH:
        tests_run_dh(args);
        break;
    case TEST_AES128_CBC_HMAC_SHA1:
    case TEST_AES256_CBC_HMAC_SHA1:
    case TEST_AES128_CBC_HMAC_SHA256:
    case TEST_AES256_CBC_HMAC_SHA256:
        tests_run_aes_cbc_hmac_sha(args);
        break;
    case TEST_PRF:              /* PRF test application */
        tests_run_prf(args);
        break;
# if OPENSSL_VERSION_NUMBER > 0x10101000L
    case TEST_HKDF:             /* HKDF test application */
        tests_run_hkdf(args);
        break;
    /* SHA3 tests */
    case TEST_SHA3_224:
    case TEST_SHA3_256:
    case TEST_SHA3_384:
    case TEST_SHA3_512:
        tests_run_sha3(args);
        break;
    case TEST_CHACHA20_POLY1305:
        tests_run_chacha20_poly1305(args);
        break;
# endif
#endif
    default:
        WARN("# FAIL: Unknown test type %d\n", args->type);
        exit(EXIT_FAILURE);
    }

    if (args->performance) {
        printf("\n|-----------------------------------------------------|\n");
        printf("|----------Thread ID %3d finished---------------------|\n",
               id);
        printf("|-----------------------------------------------------|\n");
    }
}
