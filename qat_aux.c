/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2020 Intel Corporation.
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
 * @file qat_aux.c
 *
 * In order to use with OpenSSL 1.0.2, some stubs are fabricated to avoid
 * using too much the macro OPENSSL_VERSION_NUMBER.
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define __USE_GNU

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <string.h>
#include <unistd.h>
#include <openssl/crypto.h>

#include "qat_aux.h"

int qatPerformOpRetries = 0;

ASYNC_JOB *ASYNC_get_current_job(void)
{
    return NULL;
}

int ASYNC_pause_job(void)
{
    return 0;
}

ASYNC_WAIT_CTX *ASYNC_get_wait_ctx(ASYNC_JOB *job)
{
    return NULL;
}

int ASYNC_WAIT_CTX_get_fd(ASYNC_WAIT_CTX *ctx, const void *key,
                          OSSL_ASYNC_FD *fd, void **custom_data)
{
    return 0;
}

int ASYNC_WAIT_CTX_set_wait_fd(ASYNC_WAIT_CTX *ctx, const void *key,
                               OSSL_ASYNC_FD fd, void *custom_data,
                               void (*cleanup)(ASYNC_WAIT_CTX *, const void *,
                                               OSSL_ASYNC_FD, void *))
{
    return 0;
}

int ASYNC_WAIT_CTX_get_changed_fds(ASYNC_WAIT_CTX *ctx, OSSL_ASYNC_FD *addfd,
                                   size_t *numaddfds, OSSL_ASYNC_FD *delfd,
                                   size_t *numdelfds)
{
    return 0;
}

int ASYNC_WAIT_CTX_clear_fd(ASYNC_WAIT_CTX *ctx, const void *key)
{
    return 0;
}

void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    void *ret = CRYPTO_malloc(num, file, line);

    if (ret!= NULL)
        memset(ret, 0, num);
    return ret;
}

void qat_create_ciphers(void)
{
    return;
}

int qat_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    return 0;
}

void qat_free_ciphers(void)
{
    return;
}

EC_KEY_METHOD *qat_get_EC_methods(void)
{
    return NULL;
}

void qat_free_EC_methods(void)
{
    return;
}

int ENGINE_set_EC(ENGINE *e, const EC_KEY_METHOD *ec_meth)
{
    return 1;
}

DH_METHOD *qat_get_DH_methods(void)
{
    return NULL;
}

void qat_free_DH_methods(void)
{
    return;
}

DSA_METHOD *qat_get_DSA_methods(void)
{
    return NULL;
}

void qat_free_DSA_methods(void)
{
    return;
}

int qat_PRF_pkey_methods(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                         const int **nids, int nid)
{
    return 0;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
