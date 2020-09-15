/***************************************************************************
 *
 * This file is provided under a GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 *
 *   GPL LICENSE SUMMARY
 *
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 *
 *   Contact Information:
 *   Intel Corporation
 *
 ***************************************************************************/
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
