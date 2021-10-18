/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2007-2021 Intel Corporation */

#ifndef __QAT_CONTIG_MEM_H
# define __QAT_CONTIG_MEM_H

# include <asm/ioctl.h>

# ifndef __KERNEL__
#  include <stdint.h>
# endif

typedef struct _qat_contig_mem_config {
    uint32_t signature;
    uintptr_t virtualAddress;
    int length;
    uintptr_t physicalAddress;
} qat_contig_mem_config;

# define QAT_CONTIG_MEM_MAGIC    0x95
# define QAT_CONTIG_MEM_ALLOC_SIG 0xDEADBEEF
# define QAT_CONTIG_MEM_MMAP_ADJUSTMENT 2
# define QAT_CONTIG_MEM_MALLOC  _IOWR(QAT_CONTIG_MEM_MAGIC, 0, qat_contig_mem_config)
# define QAT_CONTIG_MEM_FREE    _IOW(QAT_CONTIG_MEM_MAGIC, 2, qat_contig_mem_config)

#endif
