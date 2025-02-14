/*!
 *****************************************************************************
 *
 * @File       img_mem_man_priv.h
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

#ifndef IMG_MEM_MAN_PRIV_H
#define IMG_MEM_MAN_PRIV_H

#include <linux/list.h>
#include <linux/idr.h>
#include <linux/scatterlist.h>
#include <linux/device.h>

#include <img_mem_man.h>

/* Memory context : one per process */
struct mem_ctx {
	struct idr buffers;
	struct list_head mmu_ctxs;
	struct list_head mem_man_entry; /* Entry in <mem_man:mem_ctxs> */
	size_t mem_usage;   /* Used to track memory usage */
};

/* An MMU mapping of a buffer */
struct mmu_ctx_mapping {
	struct mmu_ctx *mmu_ctx;
	struct buffer *buffer;
	struct MMUMapping *map;
	uint32_t virt_addr;
	struct list_head mmu_ctx_entry; /* Entry in <mmu_ctx:mappings> */
	struct list_head buffer_entry; /* Entry in <buffer:mappings> */
};

/* mmu context : one per stream */
struct mmu_ctx {
	struct device *device;
	struct mmu_config config;
	struct mem_ctx *mem_ctx; /* for memory allocations */
	struct heap *heap; /* for memory allocations */
	struct MMUDirectory *mmu_dir;
	struct list_head mappings; /* contains <struct mmu_ctx_mapping> */
	struct list_head mem_ctx_entry; /* Entry in <mem_ctx:mmu_ctxs> */
	void (*callback_fn)(enum img_mmu_callback_type type, int buff_id,
			    void *data);
	void *callback_data;
};

/* buffer : valid in the context of a mem_ctx */
struct buffer {
	int id; /* Generated in <mem_ctx:buffers> */
	size_t request_size;
	size_t actual_size;
	struct device *device;
	struct mem_ctx *mem_ctx;
	struct heap *heap;
	struct list_head mappings; /* contains <struct mmu_ctx_mapping> */
	void *kptr;
	void *priv;
};

struct heap_ops {
	int (*alloc)(struct device *device, struct heap *heap,
		     size_t size, enum img_mem_attr attr,
		     struct buffer *buffer);
	int (*import)(struct device *device, struct heap *heap,
		      size_t size, enum img_mem_attr attr, int buf_fd,
		      struct buffer *buffer);
	void (*free)(struct heap *heap, struct buffer *buffer);
	int (*map_um)(struct heap *heap, struct buffer *buffer,
		      struct vm_area_struct *vma);
	int (*map_km)(struct heap *heap, struct buffer *buffer);
	int (*get_sg_table)(struct heap *heap, struct buffer *buffer,
			    struct sg_table **sg_table);
	int (*get_page_array)(struct heap *heap, struct buffer *buffer,
			      uint64_t **addrs);
	void (*sync_cpu_to_dev)(struct heap *heap, struct buffer *buffer);
	void (*sync_dev_to_cpu)(struct heap *heap, struct buffer *buffer);
	void (*destroy)(struct heap *heap);
};

struct heap {
	int id; /* Generated in <mem_man:heaps> */
	enum heap_type type;
	struct heap_ops *ops;
	union heap_options options;
	phys_addr_t (*to_dev_addr)(union heap_options *opts, phys_addr_t addr);
	void *priv;
};

int img_mem_unified_init(const struct heap_config *config, struct heap *heap);

#ifdef CONFIG_DMA_SHARED_BUFFER
int img_mem_dmabuf_init(const struct heap_config *config, struct heap *heap);
#endif

#ifdef CONFIG_ION
int img_mem_ion_init(const struct heap_config *config, struct heap *heap);
#endif

#ifdef CONFIG_GENERIC_ALLOCATOR
int img_mem_carveout_init(const struct heap_config *config, struct heap *heap);
#endif

int img_mem_secure_init(const struct heap_config *heap_cfg, struct heap *heap);

#endif /* IMG_MEM_MAN_PRIV_H */

/*
 * coding style for emacs
 *
 * Local variables:
 * indent-tabs-mode: t
 * tab-width: 8
 * c-basic-offset: 8
 * End:
 */
