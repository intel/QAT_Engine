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
 * @file cmn_mem_drv_inf.c
 *
 * This file provides an interface to use a memory driver to provide contig
 * pinned memory.
 *
 *****************************************************************************/

#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include "qat_utils.h"
#include "cmn_mem_drv_inf.h"
#include "qae_mem.h"

#define unlikely(x) __builtin_expect (!!(x), 0)

static pthread_mutex_t mem_mutex = PTHREAD_MUTEX_INITIALIZER;
static int crypto_inited = 0;


static void crypto_init(void)
{
    MEM_WARN("Memory Driver Warnings Enabled.\n");
    MEM_DEBUG("Memory Driver Debug Enabled.\n");

    crypto_inited = 1;
}


void qaeCryptoMemFree(void *ptr)
{
    int rc;

    MEM_DEBUG("Address: %p\n", ptr);

    if (unlikely(NULL == ptr)) {
        MEM_WARN("qaeCryptoMemFree trying to free NULL pointer.\n");
        return;
    }

    MEM_DEBUG("pthread_mutex_lock\n");
    if ((rc = pthread_mutex_lock(&mem_mutex)) != 0) {
        MEM_WARN("pthread_mutex_lock: %s\n", strerror(rc));
        return;
    }

    qaeMemFreeNUMA(&ptr);

    if ((rc = pthread_mutex_unlock(&mem_mutex)) != 0) {
        MEM_WARN("pthread_mutex_unlock: %s\n", strerror(rc));
        return;
    }
    MEM_DEBUG("pthread_mutex_unlock\n");
}

void qaeCryptoMemFreeNonZero(void *ptr)
{
    int rc;

    MEM_DEBUG("Address: %p\n", ptr);

    if (unlikely(NULL == ptr)) {
        MEM_WARN("qaeCryptoMemFreeNonZero trying to free NULL pointer.\n");
        return;
    }

    MEM_DEBUG("pthread_mutex_lock\n");
    if ((rc = pthread_mutex_lock(&mem_mutex)) != 0) {
        MEM_WARN("pthread_mutex_lock: %s\n", strerror(rc));
        return;
    }
#ifndef QAT_DISABLE_NONZERO_MEMFREE
    qaeMemFreeNonZeroNUMA(&ptr);
#else
    qaeMemFreeNUMA(&ptr);
#endif
    if ((rc = pthread_mutex_unlock(&mem_mutex)) != 0) {
        MEM_WARN("pthread_mutex_unlock: %s\n", strerror(rc));
        return;
    }
    MEM_DEBUG("pthread_mutex_unlock\n");
}

void *qaeCryptoMemAlloc(size_t memsize, const char *file, int line)
{
    /* Input params should already have been sanity-checked by calling function. */
    int rc;
    void *pAddress = NULL;

    if (!crypto_inited)
        crypto_init();

    MEM_DEBUG("pthread_mutex_lock\n");
    if ((rc = pthread_mutex_lock(&mem_mutex)) != 0) {
        MEM_WARN("pthread_mutex_lock: %s\n", strerror(rc));
        return NULL;
    }

    pAddress = qaeMemAllocNUMA(memsize, NUMA_ANY_NODE, QAT_BYTE_ALIGNMENT);
    MEM_DEBUG("Address: %p Size: %zd File: %s:%d\n", pAddress,
          memsize, file, line);
    if ((rc = pthread_mutex_unlock(&mem_mutex)) != 0) {
        MEM_WARN("pthread_mutex_unlock: %s\n", strerror(rc));
    }
    MEM_DEBUG("pthread_mutex_unlock\n");
    return pAddress;
}

void *qaeCryptoMemRealloc(void *ptr, size_t memsize, const char *file,
                          int line)
{
    void *nptr;

    /* copyAllocPinnedMemory() will check the input params. */
    nptr = copyAllocPinnedMemory(ptr, memsize, file, line);
    if (nptr) {
        qaeCryptoMemFree(ptr);
    }
    return nptr;
}

void *qaeCryptoMemReallocClean(void *ptr, size_t memsize,
                               size_t original_size, const char *file,
                               int line)
{
    void *nptr;

    /* copyAllocPinnedMemoryClean() checks the input params. */
    nptr =
        copyAllocPinnedMemoryClean(ptr, memsize, original_size, file, line);
    if (nptr) {
        qaeCryptoMemFree(ptr);
    }
    return nptr;
}

void *copyAllocPinnedMemory(void *ptr, size_t size, const char *file,
                            int line)
{
    void *nptr;

    if (unlikely((ptr == NULL) ||
                 (size == 0) ||
                 (file == NULL) ||
                 ((nptr = qaeCryptoMemAlloc(size, file, line)) == NULL))) {
        MEM_WARN("Pinned memory allocation failure\n");
        return NULL;
    }
    memcpy(nptr, ptr, size);
    return nptr;
}

void *copyAllocPinnedMemoryClean(void *ptr, size_t size, size_t original_size,
                                 const char *file, int line)
{
    void *nptr;

    if (unlikely((ptr == NULL) ||
                 (size == 0) ||
                 (original_size == 0) ||
                 (file == NULL))) {
        MEM_WARN("Invalid input params.\n");
        return NULL;
    }
    if (original_size > size) {
        MEM_WARN("original_size : %zd > size : %zd", original_size, size);
        return NULL;
    }
    if ((nptr = qaeCryptoMemAlloc(size, file, line)) == NULL) {
        MEM_WARN("Clean pinned memory allocation failure\n");
        return NULL;
    }

    memcpy(nptr, ptr, original_size);
    return nptr;
}

int copyFreePinnedMemory(void *uptr, void *kptr, int size)
{
    if (uptr == NULL || kptr == NULL || size <= 0) {
        MEM_WARN("Input pointers uptr or kptr are NULL, or size invalid.\n");
        return 0;
    }

    memcpy(uptr, kptr, size);
    qaeCryptoMemFree(kptr);
    return 1;
}

CpaPhysicalAddr qaeCryptoMemV2P(void *v)
{
    if (v == NULL) {
        MEM_WARN("NULL address passed to function\n");
        return (CpaPhysicalAddr)0;
    }
    return qaeVirtToPhysNUMA(v);
}

void qaeCryptoAtFork()
{
    qaeAtFork();
}
