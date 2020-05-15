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
 * @file cmn_mem_drv_inf.h
 *
 * This file provides an interface to a memory driver that supplies contig
 * pinned memory.
 *
 *****************************************************************************/

#ifndef CMN_MEM_DRV_INF_H
# define CMN_MEM_DRV_INF_H

# include <stdio.h>
# include <pthread.h>
# include "cpa.h"

extern FILE* qatDebugLogFile;

#ifdef QAT_MEM_DEBUG
# define MEM_DEBUG(fmt_str, ...)                                    \
    do {                                                           \
        fprintf(qatDebugLogFile,"[MEM_DEBUG][%s:%d:%s()] "fmt_str, \
                __FILE__, __LINE__, __func__, ##__VA_ARGS__);      \
        fflush(qatDebugLogFile);                                   \
    } while(0)
#else
# define MEM_DEBUG(...)
#endif

# define MEM_ERROR(fmt_str, ...)                                   \
    do {                                                           \
        fprintf(qatDebugLogFile,"[MEM_ERROR][%s:%d:%s()] "fmt_str, \
                __FILE__, __LINE__, __func__, ##__VA_ARGS__);      \
        fflush(qatDebugLogFile);                                   \
    } while(0)

#if defined(QAT_MEM_WARN) || defined(QAT_MEM_DEBUG)
# define MEM_WARN(fmt_str, ...)                                    \
    do {                                                           \
        fprintf(qatDebugLogFile,"[MEM_WARN][%s:%d:%s()] "fmt_str,  \
                __FILE__, __LINE__, __func__, ##__VA_ARGS__);      \
        fflush(qatDebugLogFile);                                   \
    } while(0)
#else
# define MEM_WARN(...)
#endif

void qaeCryptoMemFree(void *ptr);
void qaeCryptoMemFreeNonZero(void *ptr);
void *qaeCryptoMemAlloc(size_t memsize, const char *file, int line);
void *qaeCryptoMemRealloc(void *ptr, size_t memsize, const char *file,
                          int line);
void *qaeCryptoMemReallocClean(void *ptr, size_t memsize,
                               size_t original_size, const char *file,
                               int line);
CpaPhysicalAddr qaeCryptoMemV2P(void *v);
void qaeCryptoAtFork();
void *copyAllocPinnedMemory(void *ptr, size_t size, const char *file,
                            int line);
void *copyAllocPinnedMemoryClean(void *ptr, size_t size, size_t original_size,
                                 const char *file, int line);
int copyFreePinnedMemory(void *uptr, void *kptr, int size);

#endif                          /* CMN_MEM_DRV_INF_H */
