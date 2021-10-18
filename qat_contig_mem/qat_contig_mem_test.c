/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2007-2021 Intel Corporation */

#define _XOPEN_SOURCE 600

#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Linux doesn't conform to the POSIX standard here: #include <stropts.h>
 */
#include <sys/ioctl.h>

#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include "qat_contig_mem.h"

#define SEG_LEN 64
#define TEST_STR_LEN 64

/******************************************************************************
* function:
*         main(void)
*
* description:
*   Entry point.
*
******************************************************************************/
int main(void)
{
    int qat_contig_memfd = -1;
    qat_contig_mem_config qmcfg;
    void *addr = MAP_FAILED;
    qat_contig_mem_config *mem_to_free = NULL;
    int ret = EXIT_SUCCESS;
    char test_str[TEST_STR_LEN] = "Hello world!";

    if ((qat_contig_memfd = open("/dev/qat_contig_mem", O_RDWR)) == -1) {
        perror("# FAIL open qat_contig_mem");
        ret = EXIT_FAILURE;
        goto cleanup;
    }
    qmcfg.length = SEG_LEN;
    if (ioctl(qat_contig_memfd, QAT_CONTIG_MEM_MALLOC, &qmcfg) == -1) {
        perror("# FAIL ioctl QAT_CONTIG_MEM_MALLOC");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    if ((addr =
         mmap(NULL, SEG_LEN*QAT_CONTIG_MEM_MMAP_ADJUSTMENT,
              PROT_READ | PROT_WRITE, MAP_PRIVATE, qat_contig_memfd,
              qmcfg.virtualAddress)) == MAP_FAILED) {
        perror("# FAIL mmap");
        ret = EXIT_FAILURE;
        goto cleanup;
    }
    mem_to_free = addr;
    printf("seg mapped to %p, virtualAddress in seg %p, length %d\n", addr,
           (void *)mem_to_free->virtualAddress, mem_to_free->length);
    strncpy(addr + sizeof(qat_contig_mem_config), test_str, TEST_STR_LEN);
    puts(addr + sizeof(qat_contig_mem_config));
 cleanup:
    if (qat_contig_memfd != -1 && mem_to_free != NULL
        && ioctl(qat_contig_memfd, QAT_CONTIG_MEM_FREE, mem_to_free) == -1) {
        perror("# FAIL ioctl QAT_CONTIG_MEM_FREE");
        ret = EXIT_FAILURE;
    }
    if (addr != MAP_FAILED && munmap(addr, SEG_LEN) == -1) {
       perror("# FAIL munmap");
       ret = EXIT_FAILURE;
    }
    if (qat_contig_memfd != -1 && close(qat_contig_memfd) == -1) {
       perror("# FAIL close qat_contig_mem");
       ret = EXIT_FAILURE;
    }
    if (ret == EXIT_SUCCESS)
        printf("# PASS Verify for QAT Contig Mem Test. \n");
    else
        printf("# FAIL Verify for QAT Contig Mem Test. \n");
    exit(ret);
}
