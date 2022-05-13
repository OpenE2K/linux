/*!
 *****************************************************************************
 *
 * @File       img_mem_man.h
 * ---------------------------------------------------------------------------
 *
 * Copyright (c) Imagination Technologies Ltd.
 *
 * The contents of this file are subject to the MIT license as set out below.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 ("GPL")in which case the provisions of
 * GPL are applicable instead of those above.
 *
 * If you wish to allow use of your version of this file only under the terms
 * of GPL, and not to allow others to use your version of this file under the
 * terms of the MIT license, indicate your decision by deleting the provisions
 * above and replace them with the notice and other provisions required by GPL
 * as set out in the file called "GPLHEADER" included in this distribution. If
 * you do not delete the provisions above, a recipient may use your version of
 * this file under the terms of either the MIT license or GPL.
 *
 * This License is also included in this distribution in the file called
 * "MIT_COPYING".
 *
 *****************************************************************************/

#ifndef IMG_MEM_MAN_H
#define IMG_MEM_MAN_H

#include <linux/mm.h>
#include <linux/types.h>
#include <linux/device.h>

#include "uapi/img_mem_man.h"

struct mmu_config {
	uint32_t addr_width;
};

/* MMU page size */
enum {
	IMG_MMU_SOFT_PAGE_SIZE_PAGE_64K = 0x4,
	IMG_MMU_SOFT_PAGE_SIZE_PAGE_16K = 0x2,
	IMG_MMU_SOFT_PAGE_SIZE_PAGE_4K = 0x0,
};

/* MMU PTD entry flags */
enum {
	IMG_MMU_PTD_FLAG_NONE = 0x0,
	IMG_MMU_PTD_FLAG_VALID = 0x1,
	IMG_MMU_PTD_FLAG_WRITE_ONLY = 0x2,
	IMG_MMU_PTD_FLAG_READ_ONLY = 0x4,
	IMG_MMU_PTD_FLAG_CACHE_COHERENCY = 0x8,
	IMG_MMU_PTD_FLAG_MASK = 0xf,
};

enum heap_type {
	IMG_MEM_HEAP_TYPE_UNIFIED = 1,
	IMG_MEM_HEAP_TYPE_CARVEOUT,
	IMG_MEM_HEAP_TYPE_ION,
	IMG_MEM_HEAP_TYPE_DMABUF,
	IMG_MEM_HEAP_TYPE_SECURE,
};

union heap_options {
	struct {
		gfp_t gfp_type; /* pool and flags for buffer allocations */
	} unified;
#ifdef CONFIG_ION
	struct {
		struct ion_client *client; /* must be provided by platform */
	} ion;
#endif
	struct {
		void *kptr; /* pointer to kernel mapping of memory */
		phys_addr_t phys; /* physical address start of memory */
		size_t size; /* size of memory */
	} carveout;
};

struct heap_config {
	enum heap_type type;
	union heap_options options;
	/* (optional) function to convert a physical address as seen from
	   the CPU to the physical address as seen from the vxd device. When
	   not implemented, it is assumed that physical addresses are the
	   same regardless of viewpoint */
	phys_addr_t (*to_dev_addr)(union heap_options *opts, phys_addr_t addr);
};

enum img_mmu_callback_type {
	IMG_MMU_CALLBACK_MAP = 1,
	IMG_MMU_CALLBACK_UNMAP,
};

struct mem_ctx;
struct mmu_ctx;

int img_mem_add_heap(const struct heap_config *heap_cfg, int *heap_id);
void img_mem_del_heap(int heap_id);

/*
*  related to process context (contains SYSMEM heap's functionality in general)
*/

int img_mem_create_proc_ctx(struct mem_ctx **ctx);
void img_mem_destroy_proc_ctx(struct mem_ctx *ctx);

int img_mem_alloc(struct device *device, struct mem_ctx *ctx, int heap_id,
		  size_t size, enum img_mem_attr attributes, int *buf_id);
int img_mem_import(struct device *device, struct mem_ctx *ctx, int heap_id,
		   size_t size, enum img_mem_attr attributes, int buf_fd,
		   int *buf_id);
void img_mem_free(struct mem_ctx *ctx, int buf_id);

int img_mem_map_um(struct mem_ctx *ctx, int buf_id, struct vm_area_struct *vma);
int img_mem_map_km(struct mem_ctx *ctx, int buf_id);
void *img_mem_get_kptr(struct mem_ctx *ctx, int buf_id);

int img_mem_sync_cpu_to_device(struct mem_ctx *ctx, int buf_id);
int img_mem_sync_device_to_cpu(struct mem_ctx *ctx, int buf_id);

size_t img_mem_get_usage(const struct mem_ctx *ctx);

/*
* related to stream MMU context (constains IMGMMU functionality in general)
*/
int img_mmu_ctx_create(struct device *device, const struct mmu_config *config,
		       struct mem_ctx *mem_ctx, int heap_id,
		       void (*callback_fn)(enum img_mmu_callback_type type,
					   int buff_id, void *data),
		       void *callback_data,
		       struct mmu_ctx **mmu_ctx);
void img_mmu_ctx_destroy(struct mmu_ctx *mmu);

int img_mmu_map(struct mmu_ctx *mmu_ctx, struct mem_ctx *mem_ctx, int buff_id,
		uint32_t virt_addr, unsigned int map_flags);
int img_mmu_unmap(struct mmu_ctx *mmu_ctx, struct mem_ctx *mem_ctx, int buf_id);

int img_mmu_get_ptd(const struct mmu_ctx *ctx, unsigned int *ptd_reg);

phys_addr_t img_mmu_get_paddr(const struct mmu_ctx *ctx,
		uint32_t vaddr, uint8_t *flags);

#endif /* IMG_MEM_MAN_H */

/*
 * coding style for emacs
 *
 * Local variables:
 * indent-tabs-mode: t
 * tab-width: 8
 * c-basic-offset: 8
 * End:
 */
