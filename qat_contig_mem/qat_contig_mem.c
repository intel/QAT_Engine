/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 *
 *   GPL LICENSE SUMMARY
 *
 *   Copyright(c) 2007-2018 Intel Corporation. All rights reserved.
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
 *   BSD LICENSE
 *
 *   Copyright(c) 2007-2018 Intel Corporation.
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
 *
 ***************************************************************************/

/* This example contiguous memory allocator is written as a slab allocator.
   The expectation is that allocations passed to it are for
   multiples of PAGE_SIZE up to 2^5 pages. If you use a non-multiple
   of PAGE_SIZE you need to be careful how you use mmap and how you
   locate the slab header. */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h> 

#include "qat_contig_mem.h"

#define PAGE_ORDER 5
#define MAX_MEM_ALLOC (PAGE_SIZE * (2 << PAGE_ORDER) - sizeof(qat_contig_mem_config))

static int major;
static unsigned long bytesToPageOrder(long int memSize);

module_param(major, int, S_IRUGO);

/**
 *****************************************************************************
 * @description
 *      This structure contains data relating to the device driver that this
 *      file implements
 *
 ****************************************************************************/
typedef struct chr_drv_info_s {
    struct module *owner;
    unsigned major;
    unsigned min_minor;
    unsigned max_minor;
    char *name;
    struct file_operations *file_ops;
    struct cdev drv_cdev;
    struct class *drv_class;
    struct device *drv_class_dev;
} chr_drv_info_t;

#define DEV_MEM_NAME            "qat_contig_mem"
#define DEV_MEM_MAJOR           0
#define DEV_MEM_MAX_MINOR       4
#define DEV_MEM_BASE_MINOR      0
#define FAIL                    1
#define SUCCESS                 0
#define FREE(ptr) kfree(ptr)

/******************************************************************************
* function:
*         qat_contig_mem_read(struct file *filp, char __user *buffer, size_t length,
*                             loff_t *offset)
*
* @param filp   [IN] - unused
* @param buffer [IN] - unused
* @param length [IN] - unused
* @param offset [IN] - unused
*
* description:
*   Callback for read operations on the device node. We don't support them.
*
******************************************************************************/
static ssize_t qat_contig_mem_read(struct file *filp, char __user * buffer,
                                   size_t length, loff_t * offset)
{
    return -EIO;
}

/******************************************************************************
* function:
*         qat_contig_mem_write(struct file *filp, char __user *buffer, size_t length,
*                              loff_t *offset)
*
* @param filp [IN] - unused
* @param buff [IN] - unused
* @param leng [IN] - unused
* @param off  [IN] - unused
*
* description:
*   Callback for write operations on the device node. We don't support them.
*
******************************************************************************/
static ssize_t qat_contig_mem_write(struct file *filp, const char __user * buff,
                                    size_t len, loff_t * off)
{
    return -EIO;
}

/*
 * driver open function
 */
static int qat_contig_mem_open(struct inode *inp, struct file *fp)
{
    return 0;
}

/*
 * driver close/release function
 */
static int qat_contig_mem_release(struct inode *inp, struct file *fp)
{
    return 0;
}

/******************************************************************************
* function:
*         do_ioctl(qat_contig_mem_config *mem, unsigned int cmd, unsigned long arg)
*
* @param mem [IN] - pointer to mem structure
* @param cmd [IN] - ioctl number requested
* @param arg [IN] - any arg needed by ioctl implementaion
*
* description:
*   Callback for ioctl operations on the device node. This is our control path.
*   We support two ioctls, QAT_MEM_MALLOC and QAT_MEM_FREE.
*
******************************************************************************/
static int do_ioctl(qat_contig_mem_config * mem, unsigned int cmd, unsigned long arg)
{

    switch (cmd) {
    case QAT_CONTIG_MEM_MALLOC:
        if (mem->length <= 0) {
            printk
                ("%s: invalid inputs in qat_contig_mem_config structure!\n",
                 __func__);
            return -EINVAL;
        }

        if (mem->length > MAX_MEM_ALLOC) {
            printk
                ("%s: memory requested (%d) greater than max allocation (%ld)\n",
                 __func__, mem->length, MAX_MEM_ALLOC);
            return -EINVAL;
        }
        mem->virtualAddress =
            (uintptr_t) __get_free_pages(GFP_KERNEL,
                                         bytesToPageOrder(mem->length));
        if (mem->virtualAddress == (uintptr_t) 0) {
            printk("%s: __get_free_pages() failed\n", __func__);
            return -EINVAL;
        }

        mem->physicalAddress =
            (uintptr_t) virt_to_phys((void *)(mem->virtualAddress));
        mem->signature = QAT_CONTIG_MEM_ALLOC_SIG;
        memcpy((unsigned char *)mem->virtualAddress, mem, sizeof(*mem));

        if (copy_to_user((void *)arg, mem, sizeof(*mem))) {
            printk("%s: copy_to_user failed\n", __func__);
            return -EFAULT;
        }
        break;

    case QAT_CONTIG_MEM_FREE:
        if ((void *)mem->virtualAddress == NULL) {
            printk
                ("%s: invalid inputs in qat_contig_mem_config structure !\n",
                 __func__);
            return -EINVAL;
        }

        free_pages((unsigned long)mem->virtualAddress,
                   bytesToPageOrder(mem->length));
        break;

    default:
        printk("%s: unknown request\n", __func__);
        return -ENOTTY;
    }

    return 0;

}

/******************************************************************************
* function:
*         qat_contig_mem_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
*
* @param file [IN] - unused
* @param cmd  [IN] - ioctl number requested
* @param arg  [IN] - any arg needed by the ioctl implementation
*
* description:
*   Parameter-check the ioctl call before calling do_ioctl() to do the actual
*   work.
*
* @see do_ioctl()
*
******************************************************************************/
static long
qat_contig_mem_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    qat_contig_mem_config mem;

    if (_IOC_SIZE(cmd) != sizeof(mem)) {
        printk("%s: invalid parameter length\n", __func__);
        return -EINVAL;
    }
    if (copy_from_user(&mem, (unsigned char *)arg, sizeof(mem))) {
        printk("%s: copy_from_user failed\n", __func__);
        return -EFAULT;
    }

    return do_ioctl(&mem, cmd, arg);
}

/******************************************************************************
* function:
*         qat_contig_mem_mmap(struct file *filp, struct vm_area_struct *vma)
*
* @param filp [IN]    - unused
* @param vma  [INOUT] - struct containing details of the requested mmap, and
*                       also the resulting offset
*
* description:
*   Callback for mmap operations on the device node. This is identical to the
*   /dev/kmem device on some Linux distros, but others have removed this for
*   security reasons so we have to re-implement it.
*
******************************************************************************/
static int qat_contig_mem_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int ret = 0;
    unsigned long pfn;
    unsigned long offset = 0;
    unsigned long mmap_size = 0;
    /*
     * Convert the vm_pgoff page frame number to an address, then a physical
     * address, then convert it back to a page frame number. The final result
     * of this is to ensure that pfn is a _physical_ page frame number
     */
    pfn = __pa((u64)vma->vm_pgoff << PAGE_SHIFT) >> PAGE_SHIFT;
    if (!pfn_valid(pfn)) {
        printk("%s: invalid pfn\n", __func__);
        return -EIO;
    }
    vma->vm_pgoff = pfn;
    mmap_size = vma->vm_end - vma->vm_start;
    if (mmap_size > PAGE_SIZE) {
       /* The amount of memory that is passed in to mmap should be
          twice the amount that has been actually allocated. This
          gives us a virtual address space twice the size of the
          allocation. That then allows us to adjust the address
          we are going to map at so that we can align the slabs
          start address to be on a multiple of the slab size.
          Later when doing V2P lookups this allows us to find
          the slab header from any address by just doing simple
          maths (based on the fact we know the slab size we are
          using). For allocations that result in only 1 page of
          virtual address space there is no need to adjust the
          mapping as it will already be aligned on a page
          boundary. */
       offset = vma->vm_end % (mmap_size/2);
       vma->vm_end = vma->vm_end - offset;
       vma->vm_start = vma->vm_start + (mmap_size/2) - offset;
    }
    ret = remap_pfn_range(vma,
                          vma->vm_start,
                          vma->vm_pgoff,
                          vma->vm_end-vma->vm_start,
                          vma->vm_page_prot);
    if (ret != 0) {
        printk("%s: remap_pfn_range failed, returned %d\n", __func__, ret);
    }
    return ret;
}

/*
 * structure describing device function mappings
 */
static struct file_operations mem_ops = {
 owner:THIS_MODULE,
 mmap:qat_contig_mem_mmap,
 read:qat_contig_mem_read,
 write:qat_contig_mem_write,
 unlocked_ioctl:qat_contig_mem_ioctl,
 open:qat_contig_mem_open,
 release:qat_contig_mem_release,
};

/*
 * instantiation of the driver
 */
static chr_drv_info_t mem_drv_info = {
 owner:THIS_MODULE,
 major:DEV_MEM_MAJOR,
 min_minor:DEV_MEM_BASE_MINOR,
 max_minor:DEV_MEM_MAX_MINOR,
 name:DEV_MEM_NAME,
 file_ops:&mem_ops,
};

/*
 * create the device driver class
 */
static int chr_drv_create_class(chr_drv_info_t * drv_info)
{
    if (NULL == drv_info) {
        printk("chr_drv_create_class(): parameter is NULL\n");
        return FAIL;
    }

    drv_info->drv_class = class_create(THIS_MODULE, drv_info->name);
    if (IS_ERR(drv_info->drv_class)) {
        printk("class_create failed\n");
        return FAIL;
    }
    return SUCCESS;
}

/*
 * destroy the device driver class
 */
static void chr_drv_destroy_class(chr_drv_info_t * drv_info)
{
    if (NULL == drv_info) {
        printk("chr_drv_destroy_class(): parameter is NULL\n");
        return;
    }
    class_destroy(drv_info->drv_class);
}

/*
 * destroy the device driver
 */
static void chr_drv_destroy_device(chr_drv_info_t * drv_info)
{
    if (NULL == drv_info) {
        printk("chr_drv_destroy(): parameter is NULL\n");
        return;
    }

    if (NULL != drv_info->drv_class_dev) {
        device_destroy(drv_info->drv_class, MKDEV(drv_info->major,
                                                  drv_info->min_minor));
    }
    cdev_del(&(drv_info->drv_cdev));
    unregister_chrdev_region(MKDEV(drv_info->major, drv_info->min_minor),
                             drv_info->max_minor);
}

/*
 * create the device driver
 */
static int chr_drv_create_device(chr_drv_info_t * drv_info)
{
    int ret = 0;
    dev_t devid = 0;

    if (NULL == drv_info) {
        printk("chr_drv_create_device(): parameter is NULL\n");
        return FAIL;
    }

    ret = alloc_chrdev_region(&devid,
                              drv_info->min_minor,
                              drv_info->max_minor, drv_info->name);

    if (ret < 0) {
        printk("%s:%d unable to allocate chrdev region\n", __func__,
               __LINE__);
        return FAIL;
    }

    drv_info->major = MAJOR(devid);
    cdev_init(&(drv_info->drv_cdev), drv_info->file_ops);
    drv_info->drv_cdev.owner = drv_info->owner;

    ret = cdev_add(&(drv_info->drv_cdev), devid, drv_info->max_minor);
    if (ret < 0) {
        printk("%s:%d cdev add failed\n", __func__, __LINE__);
        chr_drv_destroy_device(drv_info);
        return FAIL;
    }

    drv_info->drv_class_dev = device_create(drv_info->drv_class,
                                            NULL, MKDEV(drv_info->major,
                                                        drv_info->min_minor),
                                            NULL, drv_info->name);

    if (NULL == drv_info->drv_class_dev) {
        printk("%s:%d chr_drv_create_device: device_create failed\n",
               __func__, __LINE__);
        chr_drv_destroy_device(drv_info);
        return FAIL;
    }
    return SUCCESS;
}

/*
 * register the device driver
 */
int register_mem_device_driver(void)
{
    int ret = 0;

    ret = chr_drv_create_class(&mem_drv_info);
    if (SUCCESS != ret) {
        printk("%s:%d failed to create device driver class\n",
               __func__, __LINE__);
        return FAIL;
    }
    ret = chr_drv_create_device(&mem_drv_info);
    if (SUCCESS != ret) {
        printk("%s:%d failed to create mem numa device driver\n",
               __func__, __LINE__);
        chr_drv_destroy_class(&mem_drv_info);
        return FAIL;
    }
    return SUCCESS;
}

/*
 * unregister the device driver
 */

void unregister_mem_device_driver(void)
{
    chr_drv_destroy_device(&mem_drv_info);
    chr_drv_destroy_class(&mem_drv_info);
}

/******************************************************************************
* function:
*         bytesToPageOrder(long int memSize)
*
* @param memSize [IN] - number of bytes requested
*
* description:
*   Return the ln2 of the number of pages needed to store memSize bytes.
*
******************************************************************************/
static unsigned long bytesToPageOrder(long int memSize)
{
    if (memSize <= PAGE_SIZE)
        return 0;
    else if (memSize <= PAGE_SIZE * 1 << 1)
        return 1;
    else if (memSize <= PAGE_SIZE * 1 << 2)
        return 2;
    else if (memSize <= PAGE_SIZE * 1 << 3)
        return 3;
    else if (memSize <= PAGE_SIZE * 1 << 4)
        return 4;
    else if (memSize <= PAGE_SIZE * 1 << 5)
        return 5;
    else
        return -1;
}

/*
 * Initialization function to insmod device driver
 */
int qat_contig_mem_init(void)
{

    printk("Loading QAT CONTIG MEM Module ...\n");
    if (SUCCESS != register_mem_device_driver()) {
        printk("Error loading QAT CONTIG MEM Module\n");
        return FAIL;
    }
    return SUCCESS;
}

/*
 * tear down function to rmmod device driver
 */
void qat_contig_mem_exit(void)
{
    printk("Unloading QAT CONTIG MEM Module ...\n");
    unregister_mem_device_driver();
}

module_init(qat_contig_mem_init);
module_exit(qat_contig_mem_exit);
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("QAT Contig Mem");
