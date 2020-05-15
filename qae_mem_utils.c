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
 * @file qae_mem_utils.c
 *
 * This file provides an interface to the QAT Linux kernel memory
 * allocation driver and manages the slabs in user space.
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include "qat_sys_call.h"
#include "qae_mem_utils.h"
#ifdef USE_QAT_CONTIG_MEM
# include "qat_contig_mem.h"
#endif
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>

/*
 * Error from file descriptor operation
 */
#define FD_ERROR           -1
#define unlikely(x) __builtin_expect (!!(x), 0)

/* flag for mutex lock */
static int crypto_inited = 0;

#define PAGE_SHIFT         12
#define PAGE_SIZE          (1UL << PAGE_SHIFT)
#define PAGE_MASK          (~(PAGE_SIZE-1))
#define MAX_PAGES_SHIFT    5
#define MAX_PAGES          (1UL << MAX_PAGES_SHIFT)

#ifdef USE_QAT_CONTIG_MEM
/* qat_contig_mem ioctl open file descriptor */
static int crypto_qat_contig_memfd = FD_ERROR;
#endif

/* Big Slab Allocator Lock */
static pthread_mutex_t crypto_bsal = PTHREAD_MUTEX_INITIALIZER;

/*
 * We allocate memory in slabs consisting of a number of slots to avoid
 * fragmentation and also to reduce cost of allocation There are nine
 * predefined slot sizes: 128 bytes, 256 bytes, 512 bytes, 1024 bytes,
 * 2048 bytes, 4096 bytes, 8192 bytes, 16384 bytes and 32768 bytes.
 * Slabs are 128KB in size.  Each slot has an overhead of a qae_slot
 * structure plus QAE_BYTE_ALIGNMENT bytes. The slab also has an
 * overhead of a qae_slab structure plus QAE_BYTE_ALIGNMENT bytes
 * so the full 128KB is not available for allocation or splitting into
 * slots. For allocations bigger than 32KB but less than MAX_ALLOC
 * we do not split the slab into slots but just allocate the whole slab.
 */
#define SLAB_SIZE          0x20000

/* Slot sizes */
#define NUM_SLOT_SIZE      10
#define SLOT_128_BYTES     0x0080
#define SLOT_256_BYTES     0x0100
#define SLOT_512_BYTES     0x0200
#define SLOT_1_KILOBYTES   0x0400
#define SLOT_2_KILOBYTES   0x0800
#define SLOT_4_KILOBYTES   0x1000
#define SLOT_8_KILOBYTES   0x2000
#define SLOT_16_KILOBYTES  0x4000
#define SLOT_32_KILOBYTES  0x8000
#define SLOT_DEFAULT_INIT  -1
/* slot free signature */
#define SIG_FREE           0xF1F2F3F4

/* slot allocate signature */
#define SIG_ALLOC          0xA1A2A3A4

/* maxmium slot size */
#define MAX_ALLOC (SLAB_SIZE - sizeof(qae_slab) - QAE_BYTE_ALIGNMENT)
#define MAX_EMPTY_SLAB     128

#define IN_EMPTY_LIST      0
#define IN_AVAILABLE_LIST  1
#define IN_FULL_LIST       2

typedef struct _qae_slot {
    struct _qae_slot *next;
    int sig;
    int pool_index;
    /* pointer to the slab which contains this slot */
    struct _qae_slab *slab;
    char *file;
    int line;
} qae_slot;

typedef struct _qae_slab {
    qat_contig_mem_config memCfg;
    /* this field has two meanings:
     *  in normal slab node, it means the size of the slot in current slab
     *  as a head slab node, it means the number of slabs in current list */
    int slot_size;
    int sig;
    struct _qae_slab *next;
    struct _qae_slab *prev;
    struct _qae_slot *next_slot;
    /* used slots in slab */
    int used_slots;
    /* total slots in slab */
    int total_slots;
    /* indicate which slab list is current slab in */
    int list_index;
    /* indicate which process alloc this slab */
    pid_t pid;
} qae_slab;

static int slot_sizes_available[] = {
    SLOT_128_BYTES + QAE_BYTE_ALIGNMENT + sizeof(qae_slot),
    SLOT_256_BYTES + QAE_BYTE_ALIGNMENT + sizeof(qae_slot),
    SLOT_512_BYTES + QAE_BYTE_ALIGNMENT + sizeof(qae_slot),
    SLOT_1_KILOBYTES + QAE_BYTE_ALIGNMENT + sizeof(qae_slot),
    SLOT_2_KILOBYTES + QAE_BYTE_ALIGNMENT + sizeof(qae_slot),
    SLOT_4_KILOBYTES + QAE_BYTE_ALIGNMENT + sizeof(qae_slot),
    SLOT_8_KILOBYTES + QAE_BYTE_ALIGNMENT + sizeof(qae_slot),
    SLOT_16_KILOBYTES + QAE_BYTE_ALIGNMENT + sizeof(qae_slot),
    SLOT_32_KILOBYTES + QAE_BYTE_ALIGNMENT + sizeof(qae_slot)
};

/* head of a cyclic doubly linked list, reused qae_slab data structure */
typedef qae_slab qae_slab_pool;

/* slab list containing full used slabs */
static qae_slab_pool full_slab_list;
/* array of slab lists containing empty slabs by slot size */
static qae_slab_pool empty_slab_list[NUM_SLOT_SIZE];
/* array of slab lists containing partially used slabs by slot size */
static qae_slab_pool available_slab_list[NUM_SLOT_SIZE];

/* init the head node of a linked list */
static void init_pool(qae_slab_pool *list)
{
    memset(list, 0, sizeof(qae_slab_pool));
    list->next = (qae_slab *)list;
    list->prev = (qae_slab *)list;
    list->slot_size = 0;
    list->pid = getpid();
}

/* fetch the head node from a list */
static qae_slab * get_node_from_head(qae_slab_pool *list)
{
    qae_slab *ret = NULL;
    if(list->slot_size <= 0)
        return ret;
    ret = list->next;
    ret->next->prev = (qae_slab *)list;
    list->next = ret->next;
    ret->next = ret->prev = NULL;
    list->slot_size--;
    return ret;
}

/* remove the node from a list */
static unsigned int remove_node_from_list(qae_slab_pool *list, qae_slab *node)
{
    if(!(node && list->slot_size > 0)) {
        return 0;
    }
    node->prev->next = node->next;
    node->next->prev = node->prev;
    list->slot_size--;
    node->next = node->prev = NULL;
    return 1;
}

/* insert a node to the end of a list */
static void insert_node_at_end(qae_slab_pool *list, qae_slab *node)
{
    qae_slab *tail = list->prev;
    tail->next = node;
    node->prev = tail;
    node->next = (qae_slab *)list;
    list->prev = node;
    list->slot_size++;
}

/* insert a node at the head of a list */
static void insert_node_at_head(qae_slab_pool *list, qae_slab *node)
{
    qae_slab *head = list->next;
    head->prev = node;
    node->next = head;
    node->prev = (qae_slab *)list;
    list->next = node;
    list->slot_size++;
}

static void crypto_init(void);

/******************************************************************************
* function:
*         copyAllocPinnedMemory(void *ptr, size_t size, const char *file,
*                               int line)
*
* @param ptr [IN]  - Pointer to data to be copied
* @param size [IN] - Size of data to be copied
* @param[in] file, the C source filename of the call site
* @param[in] line, the line number within the C source file of the call site
*
* description:
*   Internal API to allocate a pinned memory
*   buffer and copy data to it.
*
* @retval NULL      failed to allocate memory
* @retval non-NULL  pointer to allocated memory
******************************************************************************/
void *copyAllocPinnedMemory(void *ptr, size_t size, const char *file,
                            int line)
{
    void *nptr;

    if (unlikely((ptr == NULL) ||
                 (size == 0) ||
                 (file == NULL) ||
                 ((nptr = qaeCryptoMemAlloc(size, file, line)) == NULL))) {
        MEM_WARN("pinned memory allocation failure\n");
        return NULL;
    }
    memcpy(nptr, ptr, size);
    return nptr;
}

/******************************************************************************
* function:
*         copyAllocPinnedMemoryClean(void *ptr, size_t size,
*                                    size_t original_size,
*                                    const char *file, int line)
*
* @param ptr [IN]  - Pointer to data to be copied
* @param size [IN] - Size of data to be copied
* @param original_size [IN] - Original size
* @param[in] file, the C source filename of the call site
* @param[in] line, the line number within the C source file of the call site
*
* description:
*   Internal API to allocate a pinned memory
*   buffer and copy data to it.
*
* @retval NULL      failed to allocate memory
* @retval non-NULL  pointer to allocated memory
******************************************************************************/
void *copyAllocPinnedMemoryClean(void *ptr, size_t size, size_t original_size,
                                 const char *file, int line)
{
    void *nptr;

    if (unlikely(ptr == NULL ||
                 size == 0 ||
                 original_size == 0 ||
                 file == NULL)) {
        MEM_WARN("Invalid input params.\n");
        return NULL;
    }
    if (original_size > size) {
        MEM_WARN("original_size : %zd > size : %zd", original_size, size);
        return NULL;
    }
    if ((nptr = qaeCryptoMemAlloc(size, file, line)) == NULL) {
        MEM_WARN("pinned memory allocation failure\n");
        return NULL;
    }

    memcpy(nptr, ptr, original_size);
    return nptr;
}

/******************************************************************************
* function:
*         copyFreePinnedMemory(void *uptr, void *kptr, int size)
*
* @param uptr [IN] - Pointer to user data
* @param kptr [IN] - Pointer to pinned memory to be copied
* @param size [IN] - Size of data to be copied
*
* description:
*   Internal API to allocate a pinned memory
*   buffer and copy data to it.
*
******************************************************************************/
int copyFreePinnedMemory(void *uptr, void *kptr, int size)
{
    if (unlikely(uptr == NULL || kptr == NULL || size <= 0)) {
        MEM_WARN("Input pointers uptr or kptr are NULL, or size invalid.\n");
        return 0;
    }
    if (size > MAX_ALLOC) {
        MEM_WARN("Size greater than MAX_ALLOC\n");
        return 0;
    }
    memcpy(uptr, kptr, size);
    qaeCryptoMemFree(kptr);
    return 1;
}

/*****************************************************************************
 * function:
 *         crypto_create_slab(int size, int pool_index)
 *
 * @param[in] size, the size of the slots within the slab. Note that this is
 *                  not the size of the slab itself
 * @param[in] pool_index, the index of the slot pool
 * @retval qae_slab*, a pointer to the new slab.
 *
 * @description
 *      create a new slab and add it to the global linked list
 *      retval pointer to the new slab
 *
 *****************************************************************************/
static qae_slab *crypto_create_slab(int size, int pool_index)
{
    int i = 0;
    int nslot = 0;
    qat_contig_mem_config qmcfg = { 0, (uintptr_t) NULL, 0, (uintptr_t) NULL };
    qae_slab *result = NULL;
    qae_slab *slb = NULL;
    qae_slot *slt = NULL;
    QAE_UINT alignment;

    qmcfg.length = SLAB_SIZE;
#ifdef USE_QAT_CONTIG_MEM
    if (qat_ioctl(crypto_qat_contig_memfd, QAT_CONTIG_MEM_MALLOC, &qmcfg) == -1) {
        static char errmsg[LINE_MAX];

        snprintf(errmsg, LINE_MAX, "ioctl QAT_CONTIG_MEM_MALLOC(%d)",
                 qmcfg.length);
        perror(errmsg);
        goto exit;
    }
    if ((slb =
         qat_mmap(NULL, qmcfg.length*QAT_CONTIG_MEM_MMAP_ADJUSTMENT,
                  PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_LOCKED, crypto_qat_contig_memfd,
                  qmcfg.virtualAddress)) == MAP_FAILED) {
        static char errmsg[LINE_MAX];
        snprintf(errmsg, LINE_MAX, "mmap: %d %s", errno, strerror(errno));
        perror(errmsg);
        goto exit;
    }
#endif
    MEM_DEBUG("Splitting slab into slot size %d\n", size);
    slb->slot_size = size;
    slb->next_slot = NULL;
    slb->sig = SIG_ALLOC;
    slb->used_slots = 0;
    slb->pid = getpid();

    for (i = sizeof(qae_slab); SLAB_SIZE - i >= size; i += size) {
        slt = (qae_slot *) ((unsigned char *)slb + i);
        alignment =
            QAE_BYTE_ALIGNMENT -
            (((QAE_UINT) slt + sizeof(qae_slot)) % QAE_BYTE_ALIGNMENT);
        slt = (qae_slot *) (((QAE_UINT) slt) + alignment);
        slt->next = slb->next_slot;
        slt->pool_index = pool_index;
        slt->sig = SIG_FREE;
        slt->file = NULL;
        slt->line = 0;
        slb->next_slot = slt;
        nslot++;
        slt->slab = slb;
    }
    slb->total_slots = nslot;
    /*
     * Make sure the update of the slab list is the last thing to be done.
     * This means it is not necessary to lock against anyone iterating the
     * list from the head
     */

    result = slb;
    MEM_DEBUG("slab %p slotsize is %d last slot is %p, count is %d\n", slb, size, slt,
          nslot);
 exit:
    return result;
}

/*****************************************************************************
 * function:
 *         crypto_get_empty_slab(int size, int pool_index)
 *
 * @param[in] size, the size of the slots within the slab. Note that this is
 *                  not the size of the slab itself
 * @param[in] pool_index, index of slot pools
 * @retval qae_slab*, a pointer to the new slab.
 *
 * @description
 *     request a slab from the empty slab list, if empty slab list has no slab
 *     available, then create a new slab
 *     retval pointer to the new slab
 *
 ******************************************************************************/
static qae_slab *crypto_get_empty_slab(int size, int pool_index)
{
    qae_slab *result = NULL;
    result = get_node_from_head(&empty_slab_list[pool_index]);
    if(result == NULL) {
        result = crypto_create_slab(size,pool_index);
    }
    return result;
}

/*****************************************************************************
 * function:
 *         crypto_alloc_from_slab(int size, const char *file, int line)
 *
 * @param[in] size, the size of the memory block required
 * @param[in] file, the C source filename of the call site
 * @param[in] line, the line number within the C source file of the call site
 *
 * @description
 *      allocate a slot of memory from some slab
 *      retval pointer to the allocated block
 *
 *****************************************************************************/
static void *crypto_alloc_from_slab(int size, const char *file, int line)
{
    qae_slab *slb = NULL;
    qae_slot *slt;
    int slot_size;
    void *result = NULL;
    int rc;
    int i;
    int internal_size = size + QAE_BYTE_ALIGNMENT + sizeof(qae_slot);

    if (!crypto_inited)
        crypto_init();

    slot_size = SLOT_DEFAULT_INIT;

    for (i = 0; i < sizeof(slot_sizes_available) / sizeof(int); i++) {
        if (internal_size <= slot_sizes_available[i]) {
            slot_size = slot_sizes_available[i];
            break;
        }
    }

    if (SLOT_DEFAULT_INIT == slot_size) {
        if (size <= MAX_ALLOC) {
            slot_size = MAX_ALLOC;
        } else {
            MEM_WARN("Allocation of %d bytes is too big, MAX_ALLOC %lu\n",
                      size, (long unsigned int)MAX_ALLOC);
            goto exit;
        }
    }

    if (available_slab_list[i].pid != getpid())
        crypto_init();

    MEM_DEBUG("pthread_mutex_lock\n");
    if ((rc = pthread_mutex_lock(&crypto_bsal)) != 0) {
        MEM_WARN("pthread_mutex_lock: %s\n", strerror(rc));
        return result;
    }

    if(available_slab_list[i].slot_size > 0) {
        slt = available_slab_list[i].next->next_slot;
    } else {
        /* no free slots need to allocate new slab */
        slb = crypto_get_empty_slab(slot_size, i);

        if (NULL == slb) {
            MEM_WARN("error, create_slab failed - memory allocation error\n");
            if ((rc = pthread_mutex_unlock(&crypto_bsal)) != 0) {
                MEM_WARN("pthread_mutex_unlock: %s\n", strerror(rc));
            }
            MEM_DEBUG("pthread_mutex_unlock\n");
            goto exit;
        }
        /*allocate a new slab, add it into the available slab list*/
        slt = slb->next_slot;
        slb->list_index = IN_AVAILABLE_LIST;
        insert_node_at_head(&available_slab_list[i],slb);
    }

    slb = slt->slab;
    if (slt->sig != SIG_FREE) {
        MEM_WARN("error alloc slot that isn't free %p\n", slt);
        goto exit;
    }

    slt->sig = SIG_ALLOC;
    slt->file = strdup(file);
    slt->line = line;

   /* increase the reference couter */
    slb->used_slots++;
    /* get the available slot from the head of available slab list */
    slb->next_slot = slt->next;
    slt->next = NULL;
    /* if current slab has no slot available, remove the slab from
     * available slab list and add it to the full slab list */
    if(slb->used_slots >= slb->total_slots) {
        remove_node_from_list(&available_slab_list[i],slb);
        insert_node_at_end(&full_slab_list,slb);
        slb->list_index = IN_FULL_LIST;
    }

    result = (void *)((unsigned char *)slt + sizeof(qae_slot));

    if ((rc = pthread_mutex_unlock(&crypto_bsal)) != 0) {
        MEM_WARN("pthread_mutex_unlock: %s\n", strerror(rc));
    }
    MEM_DEBUG("pthread_mutex_unlock\n");

 exit:
    return result;
}

/*****************************************************************************
 * function:
 *         crypto_free_slab(qae_slab *slb)
 *
 * @param[in] slb, pointer to the slab to be freed
 *
 * @description
 *      free a slab to kernel
 *
 ******************************************************************************/
static void crypto_free_slab(qae_slab *slb)
{
    qat_contig_mem_config qmcfg;

#ifdef USE_QAT_CONTIG_MEM
    MEM_DEBUG("do munmap  of %p\n", slb);
    qmcfg = *((qat_contig_mem_config *) slb);

    if (qat_munmap(slb, SLAB_SIZE) == -1) {
        perror("munmap");
        exit(EXIT_FAILURE);
    }
    MEM_DEBUG("ioctl free of %p\n", slb);
    if (qat_ioctl(crypto_qat_contig_memfd, QAT_CONTIG_MEM_FREE, &qmcfg) == -1) {
        perror("ioctl QAT_CONTIG_MEM_FREE");
        exit(EXIT_FAILURE);
    }
#endif
}

/*****************************************************************************
 * function:
 *         crypto_free_to_slab(void *ptr)
 *
 * @param[in] ptr, pointer to the memory to be freed
 *
 * @description
 *      free a slot of memory back to its slab
 *
 *****************************************************************************/
static void crypto_free_to_slab(void *ptr)
{
    qae_slot *slt = (qae_slot *)((unsigned char *)ptr - sizeof(qae_slot));
    if (!slt) {
        MEM_WARN("Error freeing memory - unknown address\n");
        return;
    }

    qae_slab *slb = slt->slab;
    int i = slt->pool_index;
    int rc;

    MEM_DEBUG("pthread_mutex_lock\n");
    if ((rc = pthread_mutex_lock(&crypto_bsal)) != 0) {
        MEM_WARN("pthread_mutex_lock: %s\n", strerror(rc));
        return;
    }

    if (slt->sig != SIG_ALLOC) {
        MEM_WARN("error trying to free slot that hasn't been alloc'd %p\n", slt);
        goto exit;
    }

    free(slt->file);
    slt->sig = SIG_FREE;
    slt->file = NULL;
    slt->line = 0;

    /* insert the slot into the slab */
    slt->next = slb->next_slot;
    slb->next_slot = slt;
    /* decrease the reference count */
    slb->used_slots--;
    /* if the used_slots is 0, this slab is empty, it should be
     * processed properly */
    if(slb->used_slots == 0) {
        /* remove this slab from the slab list */
        switch(slb->list_index) {
            case IN_AVAILABLE_LIST:
                remove_node_from_list(&available_slab_list[i],slb);
                break;
            case IN_FULL_LIST:
                remove_node_from_list(&full_slab_list,slb);
                break;
            default:
                break;
        }
        /* free slab or assign it to the head of the empty slab list */
        if(empty_slab_list[i].slot_size >= MAX_EMPTY_SLAB) {
            crypto_free_slab(slb);
            slb = NULL;
        } else {
            insert_node_at_head(&empty_slab_list[i],slb);
            slb->list_index = IN_EMPTY_LIST;
        }
    } else {
    /* if current slab is in full slab list,
     *  remove it from the full_slab_list list and then
     *  append it at the end of the available list */
        switch(slb->list_index) {
            case IN_FULL_LIST:
                remove_node_from_list(&full_slab_list,slb);
                insert_node_at_end(&available_slab_list[i],slb);
                slt->slab->list_index = IN_AVAILABLE_LIST;
                break;
            default:
                break;
        }
    }

 exit:
    if ((rc = pthread_mutex_unlock(&crypto_bsal)) != 0) {
        MEM_WARN("pthread_mutex_unlock: %s\n", strerror(rc));
    }
    MEM_DEBUG("pthread_mutex_unlock\n");
}

/*****************************************************************************
 * function:
 *         crypto_slot_get_size(void *ptr)
 *
 * @param[in] ptr, pointer to the slot memory
 * @retval int, the size of the slot in bytes
 *
 * @description
 *      get the slot memory size in bytes
 *
 *****************************************************************************/
static int crypto_slot_get_size(void *ptr)
{
    if (NULL == ptr) {
        MEM_WARN("error can't find %p\n", ptr);
        return 0;
    }
    qae_slot *slt = (qae_slot *)((unsigned char *)ptr - sizeof(qae_slot));
    if (slt->pool_index == (NUM_SLOT_SIZE - 1)) {
        return MAX_ALLOC;
    } else if (slt->pool_index >= 0 && slt->pool_index <= NUM_SLOT_SIZE - 2) {
        return slot_sizes_available[slt->pool_index] - sizeof(qae_slot) -
            QAE_BYTE_ALIGNMENT;
    } else {
        MEM_WARN("error invalid pool_index %d\n", slt->pool_index);
        return 0;
    }
}

/*****************************************************************************
 * function:
 *         fork_slab_list(qae_slab* list)
 * @param[in] list, pointer to a slab list
 *
 * @description
 *      allocate and remap memory following a fork
 *
 *****************************************************************************/
void fork_slab_list(qae_slab_pool * list)
{
    int rc = 0;
    int count = 0;
    if ((rc = pthread_mutex_lock(&crypto_bsal)) != 0) {
        MEM_WARN("pthread_mutex_lock: %s\n", strerror(rc));
        return;
    }
    MEM_DEBUG("fork_slab_list.\n");
    MEM_DEBUG("pthread_mutex_lock\n");
    qae_slab *old_slb = list->next;
    qae_slab *new_slb = NULL;
    qat_contig_mem_config qmcfg =
        { 0, (uintptr_t) NULL, SLAB_SIZE, (uintptr_t) NULL };

    while (count < list->slot_size) {
#ifdef USE_QAT_CONTIG_MEM
        if (qat_ioctl(crypto_qat_contig_memfd, QAT_CONTIG_MEM_MALLOC, &qmcfg)
            == -1) {
            static char errmsg[LINE_MAX];

            snprintf(errmsg, LINE_MAX, "ioctl QAT_CONTIG_MEM_MALLOC(%d)",
                     qmcfg.length);
            perror(errmsg);
            exit(EXIT_FAILURE);
        }

        if ((new_slb =
             qat_mmap(NULL, qmcfg.length*QAT_CONTIG_MEM_MMAP_ADJUSTMENT,
                      PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_LOCKED, crypto_qat_contig_memfd,
                      qmcfg.virtualAddress)) == MAP_FAILED) {
            static char errmsg[LINE_MAX];
            snprintf(errmsg, LINE_MAX, "mmap: %d %s", errno, strerror(errno));
            perror(errmsg);
            exit(EXIT_FAILURE);
        }
        memcpy((void *)new_slb + sizeof(qat_contig_mem_config),
               (void *)old_slb + sizeof(qat_contig_mem_config),
               SLAB_SIZE - sizeof(qat_contig_mem_config));

#endif
        qae_slab *to_unmap = old_slb;
        old_slb = old_slb->next;
        if (qat_munmap(to_unmap, SLAB_SIZE) == -1) {
            perror("munmap");
            exit(EXIT_FAILURE);
        }
        qae_slab *remap = qat_mremap(new_slb, SLAB_SIZE, SLAB_SIZE,
                                     MREMAP_FIXED | MREMAP_MAYMOVE, to_unmap);
        if ((remap == MAP_FAILED) || (remap != to_unmap)) {
            perror("mremap");
            exit(EXIT_FAILURE);
        }
        count++;
    }

    if ((rc = pthread_mutex_unlock(&crypto_bsal)) != 0) {
        MEM_WARN("pthread_mutex_unlock: %s\n", strerror(rc));
    }
    MEM_DEBUG("pthread_mutex_unlock\n");
}

/*****************************************************************************
 * function:
 *        crypto_free_slab_list(qae_slab_pool *list)
 * @param[in] list, pointer to a slab list
 *
 * @description
 *      Free all slabs in the supplied slab list.
 *
 ******************************************************************************/
static void crypto_free_slab_list(qae_slab_pool *list)
{
    qae_slab *slb, *s_next_slab;
    int rc;
#ifdef USE_QAT_CONTIG_MEM
    qat_contig_mem_config qmcfg;
#endif

    MEM_DEBUG("pthread_mutex_lock\n");
    if ((rc = pthread_mutex_lock(&crypto_bsal)) != 0) {
        MEM_WARN("pthread_mutex_lock: %s\n", strerror(rc));
        return;
    }

    /* cleanup all the empty slab */
    for (slb = list->next; list->slot_size > 0 ; slb = s_next_slab) {
        /* need to save this off before unmapping. This is why we can't have
           slb = slb->next_slab in the for loop above. */
        s_next_slab = slb->next;
#ifdef USE_QAT_CONTIG_MEM
        MEM_DEBUG("do munmap of %p\n", slb);
        qmcfg = *((qat_contig_mem_config *) slb);

        if (qat_munmap(slb, SLAB_SIZE) == -1) {
            perror("munmap");
            exit(EXIT_FAILURE);
        }
        MEM_DEBUG("ioctl free of %p\n", slb);
        if (qat_ioctl(crypto_qat_contig_memfd, QAT_CONTIG_MEM_FREE, &qmcfg)
            == -1) {
            perror("ioctl QAT_CONTIG_MEM_FREE");
            exit(EXIT_FAILURE);
        }
#endif
        list->slot_size--;
    }

    MEM_DEBUG("done\n");

    if ((rc = pthread_mutex_unlock(&crypto_bsal)) != 0) {
        MEM_WARN("pthread_mutex_unlock: %s\n", strerror(rc));
    }
    MEM_DEBUG("pthread_mutex_unlock\n");
}

/*****************************************************************************
 * function:
 *        crypto_free_empty_slab_list(void)
 *
 * @description
 *      Free all slabs in the empty slab list.
 *
 ******************************************************************************/
void crypto_free_empty_slab_list()
{
    int i;
    for(i = 0; i < NUM_SLOT_SIZE; i++) {
        crypto_free_slab_list(&empty_slab_list[i]);
    }

}

/*****************************************************************************
 * function:
 *        slab_list_stat(qae_slab * list)
 * @param[in] list, pointer to a slab list
 * @description
 *      print statistical information about a slab list.
 *
 ******************************************************************************/
void slab_list_stat(qae_slab_pool * list)
{
    qae_slab *slb;
    int index;
    if(0 == list->slot_size) {
        MEM_DEBUG("The list is empty.\n");
        return;
    }
    for (slb = list->next, index = 0; index < list->slot_size;
         slb = slb->next) {
        MEM_DEBUG("Slab index        : %d\n",index);
        index++;
        MEM_DEBUG("Slab virtual addr : %p\n",
                (void *)slb->memCfg.virtualAddress);
        MEM_DEBUG("Slab physical addr: %p\n",
                (void *)slb->memCfg.physicalAddress);
        MEM_DEBUG("Slab slot size    : %d\n",slb->slot_size);
        MEM_DEBUG("Slab used slots   : %d\n",slb->used_slots);
        MEM_DEBUG("Slab total slots  : %d\n",slb->total_slots);
    }
    return;
}

/*****************************************************************************
 * function:
 *         crypto_cleanup_slabs(void)
 *
 * @description
 *      Free all memory managed by the slab allocator. This function is
 *      intended to be registered as an atexit() handler.
 *
 *****************************************************************************/
void crypto_cleanup_slabs(void)
{
    crypto_free_empty_slab_list();
#ifdef QAT_MEM_DEBUG
    int i;
    /* stat of available slab list*/
    for(i = 0;  i < NUM_SLOT_SIZE; i++) {
        MEM_DEBUG("available_slab_list[%d]:\n",i);
        slab_list_stat(&available_slab_list[i]);
    }
    /*stat of full slab list*/
    MEM_DEBUG("full_slab_list:\n");
    slab_list_stat(&full_slab_list);
#endif
}

/******************************************************************************
* function:
*         crypto_init(void)
*
* @description
*   Initialise the user-space part of the QAT memory allocator.
*
******************************************************************************/
static void crypto_init(void)
{
    int i = 0;

    MEM_WARN("Memory Driver Warnings Enabled.\n");
    MEM_DEBUG("Memory Driver Debug Enabled.\n");
    for(i = 0 ; i < NUM_SLOT_SIZE ; i++) {
        init_pool(&available_slab_list[i]);
        init_pool(&empty_slab_list[i]);
    }
    init_pool(&full_slab_list);
#ifdef USE_QAT_CONTIG_MEM
    if ((crypto_qat_contig_memfd = qat_open("/dev/qat_contig_mem", O_RDWR)) == FD_ERROR) {
        perror("open qat_contig_mem");
        exit(EXIT_FAILURE);
    }
#endif
    atexit(crypto_cleanup_slabs);
    crypto_inited = 1;
}

/*****************************************************************************
 * function:
 *         qaeCryptoAtFork()
 *
 * @description
 *      allocate and remap memory following a fork
 *
 *****************************************************************************/
void qaeCryptoAtFork()
{
    MEM_DEBUG("qaeCryptoAtFork.\n");
    int i;
    fork_slab_list(&full_slab_list);
    for(i = 0;i < NUM_SLOT_SIZE; i++) {
        fork_slab_list(&empty_slab_list[i]);
        fork_slab_list(&available_slab_list[i]);
    }
}

/******************************************************************************
* function:
*         qaeCryptoMemV2P(void *v)
*
* @param[in] v, virtual memory address pointer
* @retval CpaPhysicalAddress, the physical memory address pointer, it
*         returns 0 if not found.
*
* description:
*       map virtual memory address to physical memory address
*
******************************************************************************/
CpaPhysicalAddr qaeCryptoMemV2P(void *v)
{
   qat_contig_mem_config *memCfg = NULL;
   void *pVirtPageAddress = NULL;
   ptrdiff_t offset = 0;
   if (unlikely(v == NULL)) {
       MEM_WARN("NULL address passed to function\n");
       return (CpaPhysicalAddr)0;
   }

   /* Get the physical address contained in the slab
      header using the fact the slabs are aligned in
      virtual address space */
   pVirtPageAddress = (void *)(((ptrdiff_t)v) &
                      (~(MAX_PAGES*PAGE_SIZE-1)));

   offset = (ptrdiff_t)v &
            (ptrdiff_t)(MAX_PAGES*PAGE_SIZE-1);

   memCfg = (qat_contig_mem_config *)pVirtPageAddress;
   if(memCfg->signature == QAT_CONTIG_MEM_ALLOC_SIG)
       return (CpaPhysicalAddr)(memCfg->physicalAddress + offset);
   MEM_WARN("Virtual to Physical memory lookup failure\n");
   return (CpaPhysicalAddr)0;
}

/**************************************
 * Memory functions
 *************************************/

/******************************************************************************
* function:
*         qaeCryptoMemAlloc(size_t memsize, const char *file, int line)
*
* @param[in] memsize,  size of usable memory requested
* @param[in] file,     the C source filename of the call site
* @param[in] line,     the line number within the C source file of the call
*                      site
*
* description:
*   Allocate a block of pinned memory.
*
******************************************************************************/
void *qaeCryptoMemAlloc(size_t memsize, const char *file, int line)
{
    /* Input params should already have been sanity-checked by calling function. */
    void *pAddress = crypto_alloc_from_slab(memsize, file, line);
    MEM_DEBUG("Address: %p Size: %lu File: %s:%d\n",
              pAddress, memsize, file, line);
    return pAddress;
}

/******************************************************************************
* function:
*         qaeCryptoMemFree(void *ptr)
*
* @param[in] ptr, address of start of usable memory
*
* description:
*   Free a block of memory previously allocated by this allocator.
*
******************************************************************************/
void qaeCryptoMemFree(void *ptr)
{
    MEM_DEBUG("Address: %p\n", ptr);
    {
        if (NULL != ptr)
            crypto_free_to_slab(ptr);
        else {
            MEM_WARN("qaeCryptoMemFree trying to free NULL pointer.\n");
        }
    }
}

/******************************************************************************
* function:
*         qaeCryptoMemFreeNonZero(void *ptr)
*
* @param[in] ptr, address of start of usable memory
*
* description:
*   It calls qaeCryptoMemFree() as NonZeroNUMA API is invoked only with the
*   upstream driver.
*
******************************************************************************/
void qaeCryptoMemFreeNonZero(void *ptr)
{
    qaeCryptoMemFree(ptr);
}

/******************************************************************************
* function:
*         qaeCryptoMemRealloc(void *ptr, size_t memsize, const char *file,
*                             int line)
*
* @param[in] ptr,     address of start of usable memory for old allocation
* @param[in] memsize, size of new block required
* @param[in] file,    the C source filename of the call site
* @param[in] line,    the line number within the C source file of the call
*                     site
*
* description:
*   Change the size of usable memory in an allocated block. This may allocate
*   a new block and copy the data to it.
*
******************************************************************************/
void *qaeCryptoMemRealloc(void *ptr, size_t memsize, const char *file,
                          int line)
{
    if (unlikely((ptr == NULL) ||
                 (memsize == 0) ||
                 (file == NULL))) {
        MEM_WARN("Input parameter invalid.\n");
        return NULL;
    }

    int copy = crypto_slot_get_size(ptr);
    void *n = crypto_alloc_from_slab(memsize, file, line);
    if (n == NULL) {
        MEM_WARN("Failure in crypto_alloc_from_slab\n");
        return n;
    }
    MEM_DEBUG("Alloc Address: %p Size: %lu File: %s:%d\n", n,
               memsize, file, line);

    if (memsize < copy)
        copy = memsize;
    memcpy(n, ptr, copy);
    MEM_DEBUG("Free Address: %p\n", ptr);
    crypto_free_to_slab(ptr);
    return n;
}

/*******************************************************************************
* function:
*         qaeCryptoMemReallocClean(void *ptr, size_t memsize,
*                                  size_t original_size,
*                                  const char *file, int line)
*
* @param[in] ptr,               address of start of usable memory for old
*                               allocation
* @param[in] memsize,           size of new block required
* @param[in] original_size,     original size
* @param[in] file,              the C source filename of the call site
* @param[in] line,              the line number within the C source file of the
*                               call site
*
* description:
*   Change the size of usable memory in an allocated block. This may allocate
*   a new block and copy the data to it.
*
*******************************************************************************/
void *qaeCryptoMemReallocClean(void *ptr, size_t memsize,
                               size_t original_size, const char *file,
                               int line)
{
    if (unlikely((ptr == NULL) ||
                 (memsize == 0) ||
                 (original_size == 0) ||
                 (file == NULL))) {
        MEM_WARN("Input param. invalid.\n");
        return NULL;
    }
    if (original_size > memsize) {
        MEM_WARN("original_size : %zd > memsize : %zd", original_size, memsize);
        return NULL;
    }

    int copy = crypto_slot_get_size(ptr);
    void *n = crypto_alloc_from_slab(memsize, file, line);
    if (n == NULL) {
        MEM_WARN("Failure in crypto_alloc_from_slab. Size: %lu File: %s:%d\n",
                  memsize, file, line);
        return n;
    }
    MEM_DEBUG("Alloc Address: %p Size: %lu File: %s:%d\n", n,
               memsize, file, line);

    if (memsize < copy)
        copy = memsize;
    memcpy(n, ptr, copy);
    MEM_DEBUG("Free Address: %p\n", ptr);
    crypto_free_to_slab(ptr);
    return n;
}
