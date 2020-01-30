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
 * @file qae_mem_utils.h
 *
 * This file provides linux kernel memory allocation for quick assist API
 *
 *****************************************************************************/

#ifndef __QAE_MEM_UTILS_H
# define __QAE_MEM_UTILS_H

# include "cpa.h"

/*
 * define types which need to vary between 32 and 64 bit
 */
# ifdef __x86_64__
#  define QAE_UINT  Cpa64U
#  define QAE_INT   Cpa64S
# else
#  define QAE_UINT  Cpa32U
#  define QAE_INT  Cpa32S
# endif

# define QAE_BYTE_ALIGNMENT 0x0040/* 64 bytes */

extern FILE* qatDebugLogFile;

#ifdef QAT_MEM_DEBUG
# define MEM_DEBUG(fmt_str, ...)                                   \
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


/*****************************************************************************
 * function:
 *         qaeCryptoMemAlloc(size_t memsize, const char *file, int line);
 *
 * @description
 *      allocates memsize bytes of memory
 *
 * @param[in] memsize, the amount of memory in bytes to be allocated
 *
 * @retval pointer to the allocated memory
 *
 *****************************************************************************/
void *qaeCryptoMemAlloc(size_t memsize, const char *file, int line);

/*****************************************************************************
 * function:
 *         qaeCryptoMemRealloc(void *ptr, size_t memsize, const char *file, int line)
 *
 * @description
 *      re-allocates memsize bytes of memory
 *
 * @param[in] pointer to existing memory
 * @param[in] memsize, the amount of memory in bytes to be allocated
 *
 * @retval pointer to the allocated memory
 *
 *****************************************************************************/
void *qaeCryptoMemRealloc(void *ptr, size_t memsize, const char *file,
                          int line);

/*****************************************************************************
 * function:
 *         qaeCryptoMemReallocClean(void *ptr, size_t memsize, size_t original_size, const char *file, int line)
 *
 * @description
 *      re-allocates memsize bytes of memory
 *
 * @param[in] pointer to existing memory
 * @param[in] memsize, the amount of memory in bytes to be allocated
 * @param[in] original_size, original size
 * @param[in] file, the C source filename of the call site
 * @param[in] line, the line number withing the C source file of the call site
 *
 * @retval pointer to the allocated memory
 *
 *****************************************************************************/
void *qaeCryptoMemReallocClean(void *ptr, size_t memsize,
                               size_t original_size, const char *file,
                               int line);

/*****************************************************************************
 * function:
 *         qaeCryptoMemFree(void *ptr)
 *
 * @description
 *      frees memory allocated by the qaeCryptoMemAlloc function
 *
 *
 * @param[in] pointer to the memory to be freed
 *
 * @retval none
 *
 *****************************************************************************/
void qaeCryptoMemFree(void *ptr);

/*****************************************************************************
 * function:
 *         qaeCryptoMemV2P(void *v)
 *
 * @description
 *      find the physical address of a block of memory referred to by virtual
 *      address v in the current process's address map
 *
 *
 * @param[in] ptr, virtual pointer to the memory
 *
 * @retval the physical address of the memory referred to by ptr
 *
 *****************************************************************************/
CpaPhysicalAddr qaeCryptoMemV2P(void *v);

/******************************************************************************
* function:
*         setMyVirtualToPhysical(CpaVirtualToPhysical fp)
*
* @param CpaVirtualToPhysical [IN] - Function pointer to translation function
*
* description:
*   External API to allow users to specify their own virtual to physical
*   address translation function.
*
******************************************************************************/
void setMyVirtualToPhysical(CpaVirtualToPhysical fp);

void *copyAllocPinnedMemory(void *ptr, size_t size, const char *file,
                            int line);
void *copyAllocPinnedMemoryClean(void *ptr, size_t size, size_t original_size,
                                 const char *file, int line);
int copyFreePinnedMemory(void *uptr, void *kptr, int size);

void qaeCryptoAtFork();

#endif
