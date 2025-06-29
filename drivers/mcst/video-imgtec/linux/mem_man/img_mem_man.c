/*!
 *****************************************************************************
 *
 * @File       img_mem_man.c
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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>

#include <img_mem_man.h>
#include <mmu.h>
#include <heap.h>

#include "img_mem_man_priv.h"

/* heaps ids (global) */
#define MIN_HEAP 1
#define MAX_HEAP 16

struct mem_man {
	struct idr heaps;
	struct list_head mem_ctxs;
	struct mutex mutex;
};
/* define like this, so it is easier to convert to a function argument later */
static struct mem_man mem_man_data;

/* wrapper struct for IMGMMU_Page */
struct imgmmu_page {
	struct buffer *buffer;
	IMGMMU_Page page;
	uint32_t addr_shift;
};

static int trace_physical_pages;

/*
 * memory heaps
 */

static char *get_heap_name(enum heap_type type)
{
	switch (type) {
	case IMG_MEM_HEAP_TYPE_UNIFIED:
		return "unified";
	case IMG_MEM_HEAP_TYPE_CARVEOUT:
		return "carveout";
	case IMG_MEM_HEAP_TYPE_ION:
		return "ion";
	case IMG_MEM_HEAP_TYPE_DMABUF:
		return "dmabuf";
	case IMG_MEM_HEAP_TYPE_SECURE:
		return "secure";
	default:
		WARN_ON(type);
		return "unknown";
	}
}

int img_mem_add_heap(const struct heap_config *heap_cfg, int *heap_id)
{
	struct mem_man *mem_man = &mem_man_data;
	struct heap *heap;
	int (*init_fn)(const struct heap_config *heap_cfg, struct heap *heap);
	int ret;

	pr_debug("%s:%d\n", __func__, __LINE__);

	switch (heap_cfg->type) {
	case IMG_MEM_HEAP_TYPE_UNIFIED:
		init_fn = img_mem_unified_init;
		break;
#ifdef CONFIG_DMA_SHARED_BUFFER
	case IMG_MEM_HEAP_TYPE_DMABUF:
		init_fn = img_mem_dmabuf_init;
		break;
#endif
#ifdef CONFIG_ION
	case IMG_MEM_HEAP_TYPE_ION:
		init_fn = img_mem_ion_init;
		break;
#endif
#ifdef CONFIG_GENERIC_ALLOCATOR
	case IMG_MEM_HEAP_TYPE_CARVEOUT:
		init_fn = img_mem_carveout_init;
		break;
#endif
	case IMG_MEM_HEAP_TYPE_SECURE:
		init_fn = img_mem_secure_init;
		break;
	default:
		pr_err("%s: heap type %d unknown\n", __func__, heap_cfg->type);
		return -EINVAL;
	}

	heap = kmalloc(sizeof(struct heap), GFP_KERNEL);
	if (!heap)
		return -ENOMEM;

	ret = mutex_lock_interruptible(&mem_man->mutex);
	if (ret)
		goto lock_failed;

	ret = idr_alloc(&mem_man->heaps, heap, MIN_HEAP, MAX_HEAP, GFP_KERNEL);
	if (ret < 0) {
		pr_err("%s: idr_alloc failed\n", __func__);
		goto alloc_id_failed;
	}

	heap->id = ret;
	heap->type = heap_cfg->type;
	heap->options = heap_cfg->options;
	heap->to_dev_addr = heap_cfg->to_dev_addr;
	heap->priv = NULL;

	ret = init_fn(heap_cfg, heap);
	if (ret) {
		pr_err("%s: heap init failed\n", __func__);
		goto heap_init_failed;
	}

	*heap_id = heap->id;
	mutex_unlock(&mem_man->mutex);

	pr_info("%s created heap %d type %d (%s)\n",
		__func__, *heap_id, heap_cfg->type, get_heap_name(heap->type));
	return 0;

heap_init_failed:
	idr_remove(&mem_man->heaps, heap->id);
alloc_id_failed:
	mutex_unlock(&mem_man->mutex);
lock_failed:
	kfree(heap);
	return ret;
}
EXPORT_SYMBOL(img_mem_add_heap);

static void _img_mem_del_heap(struct heap *heap)
{
	struct mem_man *mem_man = &mem_man_data;

	pr_debug("%s heap %d 0x%p\n", __func__, heap->id, heap);

	WARN_ON(!mutex_is_locked(&mem_man->mutex));

	if (heap->ops->destroy)
		heap->ops->destroy(heap);

	idr_remove(&mem_man->heaps, heap->id);
}

void img_mem_del_heap(int heap_id)
{
	struct mem_man *mem_man = &mem_man_data;
	struct heap *heap;

	pr_debug("%s:%d heap %d\n", __func__, __LINE__, heap_id);

	mutex_lock(&mem_man->mutex);

	heap = idr_find(&mem_man->heaps, heap_id);
	if (!heap) {
		pr_warn("%s heap %d not found!\n", __func__, heap_id);
		mutex_unlock(&mem_man->mutex);
		return;
	}

	_img_mem_del_heap(heap);

	mutex_unlock(&mem_man->mutex);

	kfree(heap);
}
EXPORT_SYMBOL(img_mem_del_heap);

/*
 * related to process context (contains SYSMEM heap's functionality in general)
 */
int img_mem_create_proc_ctx(struct mem_ctx **new_ctx)
{
	struct mem_man *mem_man = &mem_man_data;
	struct mem_ctx *ctx;

	pr_debug("%s:%d\n", __func__, __LINE__);

	ctx = kzalloc(sizeof(struct mem_ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	idr_init(&ctx->buffers);
	INIT_LIST_HEAD(&ctx->mmu_ctxs);

	mutex_lock(&mem_man->mutex);
	list_add(&ctx->mem_man_entry, &mem_man->mem_ctxs);
	mutex_unlock(&mem_man->mutex);

	*new_ctx = ctx;
	return 0;
}
EXPORT_SYMBOL(img_mem_create_proc_ctx);

static void _img_mem_free(struct buffer *buffer);
static void _img_mmu_unmap(struct mmu_ctx_mapping *mapping);
static void _img_mmu_ctx_destroy(struct mmu_ctx *ctx);

static void _img_mem_destroy_proc_ctx(struct mem_ctx *ctx)
{
	struct mem_man *mem_man = &mem_man_data;
	struct buffer *buffer;
	int buff_id;

	pr_debug("%s:%d\n", __func__, __LINE__);

	WARN_ON(!mutex_is_locked(&mem_man->mutex));

	/* free derelict mmu contexts */
	while (!list_empty(&ctx->mmu_ctxs)) {
		struct mmu_ctx *mc;

		mc = list_first_entry(&ctx->mmu_ctxs,
				      struct mmu_ctx, mem_ctx_entry);
		pr_warn("%s: found derelict mmu context %p\n", __func__, mc);
		_img_mmu_ctx_destroy(mc);
		kfree(mc);
	}

	/* free derelict buffers */
	buff_id = IMG_MEM_MAN_MIN_BUFFER;
	buffer = idr_get_next(&ctx->buffers, &buff_id);
	while (buffer) {
		pr_warn("%s: found derelict buffer %d\n", __func__, buff_id);
		_img_mem_free(buffer);
		kfree(buffer);
		buff_id = IMG_MEM_MAN_MIN_BUFFER;
		buffer = idr_get_next(&ctx->buffers, &buff_id);
	}

	idr_destroy(&ctx->buffers);
	list_del(&ctx->mem_man_entry);
}

void img_mem_destroy_proc_ctx(struct mem_ctx *ctx)
{
	struct mem_man *mem_man = &mem_man_data;

	pr_debug("%s:%d\n", __func__, __LINE__);

	mutex_lock(&mem_man->mutex);
	_img_mem_destroy_proc_ctx(ctx);
	mutex_unlock(&mem_man->mutex);

	kfree(ctx);
}
EXPORT_SYMBOL(img_mem_destroy_proc_ctx);

static int _img_mem_alloc(struct device *device, struct mem_ctx *ctx,
			  struct heap *heap, size_t size,
			  enum img_mem_attr attr, struct buffer **buffer_new)
{
	struct mem_man *mem_man = &mem_man_data;
	struct buffer *buffer;
	int ret;

	pr_debug("%s heap %p ctx %p size %zu\n", __func__, heap, ctx, size);

	WARN_ON(!mutex_is_locked(&mem_man->mutex));

	if (size == 0) {
		pr_err("%s: buffer size is zero\n", __func__);
		return -EINVAL;
	}

	if (heap->ops == NULL || heap->ops->alloc == NULL) {
		pr_err("%s: no alloc funcion in heap %d!\n",
		       __func__, heap->id);
		return -EINVAL;
	}

	buffer = kzalloc(sizeof(struct buffer), GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	ret = idr_alloc(&ctx->buffers, buffer,
			IMG_MEM_MAN_MIN_BUFFER, IMG_MEM_MAN_MAX_BUFFER,
			GFP_KERNEL);
	if (ret < 0) {
		pr_err("%s: idr_alloc failed\n", __func__);
		goto idr_alloc_failed;
	}

	buffer->id = ret;
	buffer->request_size = size;
	buffer->actual_size = ((size + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
	buffer->device = device;
	buffer->mem_ctx = ctx;
	buffer->heap = heap;
	INIT_LIST_HEAD(&buffer->mappings);
	buffer->kptr = NULL;
	buffer->priv = NULL;
	ctx->mem_usage += buffer->actual_size;

	ret = heap->ops->alloc(device, heap, buffer->actual_size, attr, buffer);
	if (ret) {
		pr_err("%s: heap %d alloc failed\n", __func__, heap->id);
		goto heap_alloc_failed;
	}

	*buffer_new = buffer;

	pr_debug("%s heap %p ctx %p created buffer %d (%p) actual_size %zu\n",
		 __func__, heap, ctx, buffer->id, buffer, buffer->actual_size);
	return 0;

heap_alloc_failed:
	idr_remove(&ctx->buffers, buffer->id);
idr_alloc_failed:
	kfree(buffer);
	return ret;
}

int img_mem_alloc(struct device *device, struct mem_ctx *ctx, int heap_id,
		  size_t size, enum img_mem_attr attr, int *buf_id)
{
	struct mem_man *mem_man = &mem_man_data;
	struct heap *heap;
	struct buffer *buffer;
	int ret;

	pr_debug("%s heap %d ctx %p size %zu\n", __func__, heap_id, ctx, size);

	ret = mutex_lock_interruptible(&mem_man->mutex);
	if (ret)
		return ret;

	heap = idr_find(&mem_man->heaps, heap_id);
	if (!heap) {
		pr_err("%s: heap id %d not found\n", __func__, heap_id);
		mutex_unlock(&mem_man->mutex);
		return -EINVAL;
	}

	ret = _img_mem_alloc(device, ctx, heap, size, attr, &buffer);
	if (ret) {
		mutex_unlock(&mem_man->mutex);
		return ret;
	}

	*buf_id = buffer->id;
	mutex_unlock(&mem_man->mutex);

	pr_debug("%s heap %d ctx %p created buffer %d (%p) size %zu\n",
		 __func__, heap_id, ctx, *buf_id, buffer, size);
	return ret;
}
EXPORT_SYMBOL(img_mem_alloc);

static int _img_mem_import(struct device *device,
			   struct mem_ctx *ctx, struct heap *heap,
			   size_t size, enum img_mem_attr attr, int buf_fd,
			   struct buffer **buffer_new)
{
	struct mem_man *mem_man = &mem_man_data;
	struct buffer *buffer;
	int ret;

	WARN_ON(!mutex_is_locked(&mem_man->mutex));

	if (size == 0) {
		pr_err("%s: buffer size is zero\n", __func__);
		return -EINVAL;
	}

	if (heap->ops == NULL || heap->ops->import == NULL) {
		pr_err("%s: no import funcion in heap %d!\n",
		       __func__, heap->id);
		return -EINVAL;
	}

	buffer = kzalloc(sizeof(struct buffer), GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	ret = idr_alloc(&ctx->buffers, buffer,
			IMG_MEM_MAN_MIN_BUFFER, IMG_MEM_MAN_MAX_BUFFER,
			GFP_KERNEL);
	if (ret < 0) {
		pr_err("%s: idr_alloc failed\n", __func__);
		goto idr_alloc_failed;
	}

	buffer->id = ret;
	buffer->request_size = size;
	buffer->actual_size = ((size + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
	buffer->device = device;
	buffer->mem_ctx = ctx;
	buffer->heap = heap;
	INIT_LIST_HEAD(&buffer->mappings);
	buffer->kptr = NULL;
	buffer->priv = NULL;
	ctx->mem_usage += buffer->actual_size;

	ret = heap->ops->import(device, heap, buffer->actual_size, attr,
				buf_fd, buffer);
	if (ret) {
		pr_err("%s: heap %d import failed\n", __func__, heap->id);
		goto heap_import_failed;
	}

	*buffer_new = buffer;
	return 0;

heap_import_failed:
	idr_remove(&ctx->buffers, buffer->id);
idr_alloc_failed:
	kfree(buffer);
	return ret;
}

int img_mem_import(struct device *device, struct mem_ctx *ctx, int heap_id,
		   size_t size, enum img_mem_attr attr, int buf_fd,
		   int *buf_id)
{
	struct mem_man *mem_man = &mem_man_data;
	struct heap *heap;
	struct buffer *buffer;
	int ret;

	pr_debug("%s heap %d ctx %p fd %d\n", __func__, heap_id, ctx, buf_fd);

	ret = mutex_lock_interruptible(&mem_man->mutex);
	if (ret)
		return ret;

	heap = idr_find(&mem_man->heaps, heap_id);
	if (!heap) {
		pr_err("%s: heap id %d not found\n", __func__, heap_id);
		mutex_unlock(&mem_man->mutex);
		return -EINVAL;
	}

	ret = _img_mem_import(device, ctx, heap, size, attr, buf_fd, &buffer);
	if (ret) {
		mutex_unlock(&mem_man->mutex);
		return ret;
	}

	*buf_id = buffer->id;
	mutex_unlock(&mem_man->mutex);

	pr_info("%s buf_fd %d heap %d (%s) buffer %d size %zu\n", __func__,
		buf_fd, heap_id, get_heap_name(heap->type), *buf_id, size);
	pr_debug("%s heap %d ctx %p created buffer %d (%p) size %zu\n",
		 __func__, heap_id, ctx, *buf_id, buffer, size);
	return ret;
}
EXPORT_SYMBOL(img_mem_import);

static void _img_mem_free(struct buffer *buffer)
{
	struct mem_man *mem_man = &mem_man_data;
	struct heap *heap = buffer->heap;
	struct mem_ctx *ctx = buffer->mem_ctx;

	pr_debug("%s buffer 0x%p\n", __func__, buffer);

	WARN_ON(!mutex_is_locked(&mem_man->mutex));

	if (heap->ops == NULL || heap->ops->free == NULL) {
		pr_err("%s: no free funcion in heap %d!\n", __func__, heap->id);
		return;
	}

	/* TODO: sgt and kptr? */

	while (!list_empty(&buffer->mappings)) {
		struct mmu_ctx_mapping *map;

		map = list_first_entry(&buffer->mappings,
				       struct mmu_ctx_mapping, buffer_entry);
		pr_warn("%s: found mapping for buffer %d (size %zu)\n",
			__func__, map->buffer->id, map->buffer->actual_size);
		_img_mmu_unmap(map);
		kfree(map);
	}

	heap->ops->free(heap, buffer);

	idr_remove(&ctx->buffers, buffer->id);
}

void img_mem_free(struct mem_ctx *ctx, int buff_id)
{
	struct mem_man *mem_man = &mem_man_data;
	struct buffer *buffer;

	pr_debug("%s:%d buffer %d\n", __func__, __LINE__, buff_id);

	mutex_lock(&mem_man->mutex);

	buffer = idr_find(&ctx->buffers, buff_id);
	if (!buffer) {
		pr_err("%s: buffer id %d not found\n", __func__, buff_id);
		mutex_unlock(&mem_man->mutex);
		return;
	}

	_img_mem_free(buffer);

	mutex_unlock(&mem_man->mutex);

	kfree(buffer);
}
EXPORT_SYMBOL(img_mem_free);

int img_mem_map_um(struct mem_ctx *ctx, int buff_id, struct vm_area_struct *vma)
{
	struct mem_man *mem_man = &mem_man_data;
	struct buffer *buffer;
	struct heap *heap;
	int ret;

	pr_debug("%s:%d buffer %d\n", __func__, __LINE__, buff_id);

	mutex_lock(&mem_man->mutex);
	buffer = idr_find(&ctx->buffers, buff_id);
	if (!buffer) {
		pr_err("%s: buffer id %d not found\n", __func__, buff_id);
		mutex_unlock(&mem_man->mutex);
		return -EINVAL;
	}
	pr_debug("%s:%d buffer 0x%p\n", __func__, __LINE__, buffer);

	heap = buffer->heap;
	if (heap->ops == NULL || heap->ops->map_um == NULL) {
		pr_err("%s: no map_um in heap %d!\n", __func__, heap->id);
		mutex_unlock(&mem_man->mutex);
		return -EINVAL;
	}

	ret = heap->ops->map_um(heap, buffer, vma);

	mutex_unlock(&mem_man->mutex);

	return ret;
}
EXPORT_SYMBOL(img_mem_map_um);

static int _img_mem_map_km(struct buffer *buffer)
{
	struct mem_man *mem_man = &mem_man_data;
	struct heap *heap = buffer->heap;

	pr_debug("%s:%d buffer 0x%p\n", __func__, __LINE__, buffer);

	WARN_ON(!mutex_is_locked(&mem_man->mutex));

	if (heap->ops == NULL || heap->ops->map_km == NULL) {
		pr_err("%s: no map_km in heap %d!\n", __func__, heap->id);
		return -EINVAL;
	}

	return heap->ops->map_km(heap, buffer);
}

int img_mem_map_km(struct mem_ctx *ctx, int buff_id)
{
	struct mem_man *mem_man = &mem_man_data;
	struct buffer *buffer;
	int ret;

	pr_debug("%s:%d buffer %d\n", __func__, __LINE__, buff_id);

	mutex_lock(&mem_man->mutex);
	buffer = idr_find(&ctx->buffers, buff_id);
	if (!buffer) {
		pr_err("%s: buffer id %d not found\n", __func__, buff_id);
		mutex_unlock(&mem_man->mutex);
		return -EINVAL;
	}

	ret = _img_mem_map_km(buffer);

	mutex_unlock(&mem_man->mutex);

	return ret;
}
EXPORT_SYMBOL(img_mem_map_km);

void *img_mem_get_kptr(struct mem_ctx *ctx, int buff_id)
{
	struct mem_man *mem_man = &mem_man_data;
	struct buffer *buffer;
	void *kptr;

	mutex_lock(&mem_man->mutex);
	buffer = idr_find(&ctx->buffers, buff_id);
	if (!buffer) {
		pr_err("%s: buffer id %d not found\n", __func__, buff_id);
		mutex_unlock(&mem_man->mutex);
		return NULL;
	}
	kptr = buffer->kptr;
	mutex_unlock(&mem_man->mutex);
	return kptr;
}
EXPORT_SYMBOL(img_mem_get_kptr);

static void _img_mem_sync_cpu_to_device(struct buffer *buffer)
{
	struct mem_man *mem_man = &mem_man_data;
	struct heap *heap = buffer->heap;

	pr_debug("%s:%d buffer %d size %zu kptr %p\n", __func__, __LINE__,
		 buffer->id, buffer->actual_size, buffer->kptr);

	WARN_ON(!mutex_is_locked(&mem_man->mutex));

	if (heap->ops && heap->ops->sync_cpu_to_dev)
		heap->ops->sync_cpu_to_dev(heap, buffer);

#ifdef CONFIG_ARM
	dmb();
#else
	mb();
#endif
}

int img_mem_sync_cpu_to_device(struct mem_ctx *ctx, int buff_id)
{
	struct mem_man *mem_man = &mem_man_data;
	struct buffer *buffer;

	pr_debug("%s:%d buffer %d\n", __func__, __LINE__, buff_id);

	mutex_lock(&mem_man->mutex);
	buffer = idr_find(&ctx->buffers, buff_id);
	if (!buffer) {
		pr_err("%s: buffer id %d not found\n", __func__, buff_id);
		mutex_unlock(&mem_man->mutex);
		return -EINVAL;
	}

	_img_mem_sync_cpu_to_device(buffer);

	mutex_unlock(&mem_man->mutex);
	return 0;
}
EXPORT_SYMBOL(img_mem_sync_cpu_to_device);

static void _img_mem_sync_device_to_cpu(struct buffer *buffer)
{
	struct mem_man *mem_man = &mem_man_data;
	struct heap *heap = buffer->heap;

	pr_debug("%s:%d buffer %d size %zu kptr %p\n", __func__, __LINE__,
		 buffer->id, buffer->actual_size, buffer->kptr);

	WARN_ON(!mutex_is_locked(&mem_man->mutex));

	if (heap->ops && heap->ops->sync_dev_to_cpu)
		heap->ops->sync_dev_to_cpu(heap, buffer);
}

int img_mem_sync_device_to_cpu(struct mem_ctx *ctx, int buff_id)
{
	struct mem_man *mem_man = &mem_man_data;
	struct buffer *buffer;

	pr_debug("%s:%d buffer %d\n", __func__, __LINE__, buff_id);

	mutex_lock(&mem_man->mutex);
	buffer = idr_find(&ctx->buffers, buff_id);
	if (!buffer) {
		pr_err("%s: buffer id %d not found\n", __func__, buff_id);
		mutex_unlock(&mem_man->mutex);
		return -EINVAL;
	}

	_img_mem_sync_device_to_cpu(buffer);

	mutex_unlock(&mem_man->mutex);
	return 0;
}
EXPORT_SYMBOL(img_mem_sync_device_to_cpu);

size_t img_mem_get_usage(const struct mem_ctx *ctx)
{
	struct mem_man *mem_man = &mem_man_data;
	size_t mem_usage;

	mutex_lock(&mem_man->mutex);
	mem_usage = ctx->mem_usage;
	mutex_unlock(&mem_man->mutex);

	return mem_usage;
}
EXPORT_SYMBOL(img_mem_get_usage);

/*
 * related to stream MMU context (constains IMGMMU functionality in general)
 */
static struct MMUPage *imgmmu_page_alloc(void *arg)
{
	struct mem_man *mem_man = &mem_man_data;
	struct mmu_ctx *mmu_ctx = arg;
	struct imgmmu_page *page;
	struct buffer *buffer;
	struct heap *heap;
	int ret;

	pr_debug("%s:%d arg %p\n", __func__, __LINE__, arg);

	WARN_ON(!mutex_is_locked(&mem_man->mutex));

	page = kzalloc(sizeof(struct imgmmu_page), GFP_KERNEL);
	if (!page)
		return NULL;

	ret = _img_mem_alloc(mmu_ctx->device, mmu_ctx->mem_ctx, mmu_ctx->heap,
			     PAGE_SIZE, 0, &buffer);
	if (ret) {
		pr_err("%s: img_mem_alloc failed (%d)\n", __func__, ret);
		goto free_page;
	}

	ret = _img_mem_map_km(buffer);
	if (ret) {
		pr_err("%s: img_mem_map_km failed (%d)\n", __func__, ret);
		goto free_buffer;
	}

	page->addr_shift = mmu_ctx->config.addr_width - 32;
	page->buffer = buffer;
	page->page.uiCpuVirtAddr = (uintptr_t)buffer->kptr;

	heap = buffer->heap;
	if (heap->ops && heap->ops->get_sg_table) {
		struct sg_table *sgt;

		ret = heap->ops->get_sg_table(heap, buffer, &sgt);
		if (ret) {
			pr_err("%s: heap %d buffer %d no sg_table!\n",
			       __func__, heap->id, buffer->id);
			ret = -EINVAL;
			goto free_buffer;
		}
#ifdef CONFIG_MCST
		page->page.uiPhysAddr = sg_dma_address(sgt->sgl);
#else
		page->page.uiPhysAddr = sg_phys(sgt->sgl);
#endif
	} else if (heap->ops && heap->ops->get_page_array) {
		uint64_t *addrs;

		ret = heap->ops->get_page_array(heap, buffer, &addrs);
		if (ret) {
			pr_err("%s: heap %d buffer %d no page array!\n",
			       __func__, heap->id, buffer->id);
			ret = -EINVAL;
			goto free_buffer;
		}
		page->page.uiPhysAddr = *addrs; /* we allocated a single page */
	} else {
		pr_err("%s: heap %d buffer %d no get_sg or get_page_array!\n",
		       __func__, heap->id, buffer->id);
		ret = -EINVAL;
		goto free_buffer;
	}

	pr_debug("%s:%d virt addr %#lx\n", __func__, __LINE__,
		 page->page.uiCpuVirtAddr);
	pr_debug("%s:%d phys addr %#llx\n", __func__, __LINE__,
		 page->page.uiPhysAddr);
	return &page->page;

free_buffer:
	_img_mem_free(buffer);
	kfree(buffer);
free_page:
	kfree(page);
	return NULL;
}

static void imgmmu_page_free(struct MMUPage *arg)
{
	struct mem_man *mem_man = &mem_man_data;
	struct imgmmu_page *page;

	pr_debug("%s:%d\n", __func__, __LINE__);

	page = container_of(arg, struct imgmmu_page, page);

	WARN_ON(!mutex_is_locked(&mem_man->mutex));

	_img_mem_free(page->buffer);
	kfree(page->buffer);
	kfree(page);
}

static void imgmmu_page_write(struct MMUPage *page,
			      unsigned int offset, uint64_t addr,
			      unsigned int flags)
{
	uint32_t *mem = (uint32_t *)page->uiCpuVirtAddr;
	struct imgmmu_page *imgmmu_page;
	struct heap *heap;

	/* Apply mask */
	flags &= IMG_MMU_PTD_FLAG_MASK;

	if (trace_physical_pages && flags)
		pr_info("%s: off %#x addr %#llx flags %#x\n",
			 __func__, offset, addr, flags);

	imgmmu_page = container_of(page, struct imgmmu_page, page);
	heap = imgmmu_page->buffer->heap;

	/* skip translation when flags are zero, assuming address is invalid */
	if (flags && heap->to_dev_addr)
		addr = heap->to_dev_addr(&heap->options, addr);
	addr >>= imgmmu_page->addr_shift;

	mem[offset] = addr | flags;
}

static IMG_UINT32 imgmmu_page_read(struct MMUPage *page,
				   unsigned int offset)
{
	uint32_t *mem = (uint32_t *)page->uiCpuVirtAddr;
	uint32_t entry = mem[offset];
	unsigned flags = entry & IMG_MMU_PTD_FLAG_MASK;
	struct imgmmu_page *imgmmu_page;
	uint64_t addr;

	imgmmu_page = container_of(page, struct imgmmu_page, page);
	addr = (entry & ~IMG_MMU_PTD_FLAG_MASK) <<
			imgmmu_page->addr_shift;

	if (trace_physical_pages && flags)
		pr_info("%s: off %#x addr %#llx flags %#x\n",
			 __func__, offset, addr, flags);

	/* TODOL: We are returning 32bit entry for now,
	 * maybe better to return phys_addr_t ? */
	return entry;
}

static void imgmmu_update_page(struct MMUPage *arg)
{
	struct mem_man *mem_man = &mem_man_data;
	struct imgmmu_page *page;

	if (trace_physical_pages)
		pr_debug("%s\n", __func__);

	page = container_of(arg, struct imgmmu_page, page);

	WARN_ON(!mutex_is_locked(&mem_man->mutex));

	_img_mem_sync_cpu_to_device(page->buffer);
}

int img_mmu_ctx_create(struct device *device, const struct mmu_config *config,
		       struct mem_ctx *mem_ctx, int heap_id,
		       void (*callback_fn)(enum img_mmu_callback_type type,
					   int buff_id, void *data),
		       void *callback_data, struct mmu_ctx **mmu_ctx)
{
	struct mem_man *mem_man = &mem_man_data;

	static IMGMMU_Info imgmmu_functions = {
		.pfnPageAlloc = imgmmu_page_alloc,
		.pfnPageFree = imgmmu_page_free,
		.pfnPageWrite = imgmmu_page_write,
		.pfnPageRead = imgmmu_page_read,
		.pfnPageUpdate = imgmmu_update_page,
	};
	struct mmu_ctx *ctx;
	IMG_RESULT res;

	if (config->addr_width < 32) {
		pr_err("%s: invalid addr_width (%d) must be >= 32 !\n",
		       __func__, config->addr_width);
		return -EINVAL;
	}

	ctx = kzalloc(sizeof(struct mmu_ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->device = device;
	ctx->mem_ctx = mem_ctx;
	memcpy(&ctx->config, config, sizeof(struct mmu_config));

	mutex_lock(&mem_man->mutex);

	ctx->heap = idr_find(&mem_man->heaps, heap_id);
	if (!ctx->heap) {
		pr_err("%s: invalid heap_id (%d)!\n", __func__, heap_id);
		mutex_unlock(&mem_man->mutex);
		kfree(ctx);
		return -EINVAL;
	}

	imgmmu_functions.allocCtx = ctx;
	ctx->mmu_dir = IMGMMU_DirectoryCreate(&imgmmu_functions, &res);
	if (res) {
		pr_err("%s: directory create failed (%d)!\n", __func__, res);
		mutex_unlock(&mem_man->mutex);
		kfree(ctx);
		return -EFAULT;
	}

	list_add(&ctx->mem_ctx_entry, &mem_ctx->mmu_ctxs);
	INIT_LIST_HEAD(&ctx->mappings);

	ctx->callback_fn = callback_fn;
	ctx->callback_data = callback_data;

	*mmu_ctx = ctx;

	mutex_unlock(&mem_man->mutex);

	return 0;
}
EXPORT_SYMBOL(img_mmu_ctx_create);

static void _img_mmu_ctx_destroy(struct mmu_ctx *ctx)
{
	struct mem_man *mem_man = &mem_man_data;
	IMG_RESULT res;

	WARN_ON(!mutex_is_locked(&mem_man->mutex));

	while (!list_empty(&ctx->mappings)) {
		struct mmu_ctx_mapping *map;

		map = list_first_entry(&ctx->mappings,
				       struct mmu_ctx_mapping, mmu_ctx_entry);
		pr_info("%s: found mapped buffer %d (size %zu)\n",
			__func__, map->buffer->id, map->buffer->request_size);
		_img_mmu_unmap(map);
		kfree(map);
	}

	res = IMGMMU_DirectoryDestroy(ctx->mmu_dir);
	if (res)
		pr_err("IMGMMU_DirectoryDestroy failed (%d)!\n", res);

	list_del(&ctx->mem_ctx_entry);
}

void img_mmu_ctx_destroy(struct mmu_ctx *ctx)
{
	struct mem_man *mem_man = &mem_man_data;

	mutex_lock(&mem_man->mutex);
	_img_mmu_ctx_destroy(ctx);
	mutex_unlock(&mem_man->mutex);

	kfree(ctx);
}
EXPORT_SYMBOL(img_mmu_ctx_destroy);

int img_mmu_map(struct mmu_ctx *mmu_ctx, struct mem_ctx *mem_ctx, int buff_id,
		uint32_t virt_addr, unsigned int map_flags)
{
	struct mem_man *mem_man = &mem_man_data;
	struct mmu_ctx_mapping *mapping;
	struct MMUHeapAlloc heap_alloc;
	struct buffer *buffer;
	struct heap *heap;
	IMG_RESULT res;
	int ret;

	pr_debug("%s buffer %d virt_addr %#x\n", __func__, buff_id, virt_addr);

	mapping = kzalloc(sizeof(struct mmu_ctx_mapping), GFP_KERNEL);
	if (!mapping)
		return -ENOMEM;

	mutex_lock(&mem_man->mutex);
	buffer = idr_find(&mem_ctx->buffers, buff_id);
	if (!buffer) {
		pr_err("%s: buffer id %d not found\n", __func__, buff_id);
		ret = -EINVAL;
		goto error;
	}
	pr_debug("%s buffer %d 0x%p size %zu virt_addr %#x\n", __func__,
		 buff_id, buffer, buffer->request_size, virt_addr);

	heap_alloc.uiVirtualAddress = virt_addr;
	heap_alloc.uiAllocSize = buffer->actual_size;

	mapping->mmu_ctx = mmu_ctx;
	mapping->buffer = buffer;
	mapping->virt_addr = virt_addr;

	heap = buffer->heap;
	if (heap->ops && heap->ops->get_sg_table) {
		struct sg_table *sgt;

		ret = heap->ops->get_sg_table(heap, buffer, &sgt);
		if (ret) {
			pr_err("%s: heap %d buffer %d no sg_table!\n",
			       __func__, heap->id, buffer->id);
			goto error;
		}

		mapping->map = IMGMMU_DirectoryMapSG(mmu_ctx->mmu_dir, sgt->sgl,
						     &heap_alloc, map_flags,
						     &res);
	} else if (heap->ops && heap->ops->get_page_array) {
		uint64_t *addrs;

		ret = heap->ops->get_page_array(heap, buffer, &addrs);
		if (ret) {
			pr_err("%s: heap %d buffer %d no page array!\n",
			       __func__, heap->id, buffer->id);
			goto error;
		}

		mapping->map = IMGMMU_DirectoryMapArr(mmu_ctx->mmu_dir, addrs,
						      &heap_alloc, map_flags,
						      &res);
	} else {
		pr_err("%s: heap %d buffer %d no get_sg or get_page_array!\n",
		       __func__, heap->id, buffer->id);
		ret = -EINVAL;
		goto error;
	}
	if (res) {
		pr_err("IMGMMU_DirectoryMap failed (%d)!\n", res);
		ret = -EFAULT;
		goto error;
	}

	list_add(&mapping->mmu_ctx_entry, &mmu_ctx->mappings);
	list_add(&mapping->buffer_entry, &mapping->buffer->mappings);

	if (mmu_ctx->callback_fn)
		mmu_ctx->callback_fn(IMG_MMU_CALLBACK_MAP, buffer->id,
				     mmu_ctx->callback_data);

	mutex_unlock(&mem_man->mutex);
	return 0;

error:
	mutex_unlock(&mem_man->mutex);
	kfree(mapping);
	return ret;
}
EXPORT_SYMBOL(img_mmu_map);

static void _img_mmu_unmap(struct mmu_ctx_mapping *mapping)
{
	struct mem_man *mem_man = &mem_man_data;
	struct mmu_ctx *ctx = mapping->mmu_ctx;
	IMG_RESULT res;

	pr_debug("%s:%d mapping %p buffer %d\n",
		 __func__, __LINE__, mapping, mapping->buffer->id);

	WARN_ON(!mutex_is_locked(&mem_man->mutex));

	res = IMGMMU_DirectoryUnMap(mapping->map);
	if (res)
		pr_warn("IMGMMU_DirectoryUnMap failed (%d)!\n", res);

	list_del(&mapping->mmu_ctx_entry);
	list_del(&mapping->buffer_entry);

	if (ctx->callback_fn)
		ctx->callback_fn(IMG_MMU_CALLBACK_UNMAP, mapping->buffer->id,
				 ctx->callback_data);
}

int img_mmu_unmap(struct mmu_ctx *mmu_ctx, struct mem_ctx *mem_ctx, int buff_id)
{
	struct mem_man *mem_man = &mem_man_data;
	struct mmu_ctx_mapping *mapping;
	struct list_head *lst;

	pr_debug("%s:%d buffer %d\n", __func__, __LINE__, buff_id);

	mutex_lock(&mem_man->mutex);

	mapping = NULL;
	list_for_each(lst, &mmu_ctx->mappings) {
		struct mmu_ctx_mapping *m;

		m = list_entry(lst, struct mmu_ctx_mapping, mmu_ctx_entry);
		if (m->buffer->id == buff_id) {
			mapping = m;
			break;
		}
	}

	if (!mapping) {
		pr_err("%s: buffer id %d not found\n", __func__, buff_id);
		mutex_unlock(&mem_man->mutex);
		return -EINVAL;
	}

	_img_mmu_unmap(mapping);

	mutex_unlock(&mem_man->mutex);
	kfree(mapping);
	return 0;
}
EXPORT_SYMBOL(img_mmu_unmap);

int img_mmu_get_ptd(const struct mmu_ctx *ctx, unsigned int *ptd)
{
	struct mem_man *mem_man = &mem_man_data;
	IMGMMU_Page *page;
	phys_addr_t addr;
	struct imgmmu_page *imgmmu_page;

	mutex_lock(&mem_man->mutex);

	page = IMGMMU_DirectoryGetPage(ctx->mmu_dir);
	if (!page) {
		mutex_unlock(&mem_man->mutex);
		return -EINVAL;
	}

	addr = page->uiPhysAddr;
	if (ctx->heap->to_dev_addr)
		addr = ctx->heap->to_dev_addr(&ctx->heap->options, addr);

	imgmmu_page = container_of(page, struct imgmmu_page, page);

	mutex_unlock(&mem_man->mutex);

	*ptd = (unsigned int)(addr >>= imgmmu_page->addr_shift);

	pr_debug("%s: addr %#llx ptd %#x\n", __func__, page->uiPhysAddr, *ptd);
	return 0;
}
EXPORT_SYMBOL(img_mmu_get_ptd);

phys_addr_t img_mmu_get_paddr(const struct mmu_ctx *ctx,
		uint32_t vaddr, uint8_t *flags)
{
	struct mem_man *mem_man = &mem_man_data;
	uint32_t entry = 0;
	phys_addr_t paddr = 0;

	*flags = 0;
	mutex_lock(&mem_man->mutex);

	entry = IMGMMU_DirectoryGetDirectoryEntry(ctx->mmu_dir, vaddr);
	if (entry != ~0) {
		entry = IMGMMU_DirectoryGetPageTableEntry(ctx->mmu_dir, vaddr);
		if (entry != ~0) {
			*flags = entry & IMG_MMU_PTD_FLAG_MASK;
			paddr = (entry & ~IMG_MMU_PTD_FLAG_MASK) <<
						(ctx->config.addr_width - 32);
		}
	}

	mutex_unlock(&mem_man->mutex);

	return paddr;
}
EXPORT_SYMBOL(img_mmu_get_paddr);

/*
 * Initialisation
 */
static int __init img_mem_init(void)
{
	struct mem_man *mem_man = &mem_man_data;

	pr_debug("%s:%d\n", __func__, __LINE__);

	idr_init(&mem_man->heaps);
	INIT_LIST_HEAD(&mem_man->mem_ctxs);
	mutex_init(&mem_man->mutex);

	return 0;
}

static void __exit img_mem_exit(void)
{
	struct mem_man *mem_man = &mem_man_data;
	struct heap *heap;
	int heap_id;

	pr_debug("%s:%d\n", __func__, __LINE__);

	/* keeps mutex checks (WARN_ON) happy, this will never actually wait */
	mutex_lock(&mem_man->mutex);

	while (!list_empty(&mem_man->mem_ctxs)) {
		struct mem_ctx *mc;

		mc = list_first_entry(&mem_man->mem_ctxs,
				      struct mem_ctx, mem_man_entry);
		pr_warn("%s derelict memory context %p!\n", __func__, mc);
		_img_mem_destroy_proc_ctx(mc);
		kfree(mc);
	}

	heap_id = MIN_HEAP;
	heap = idr_get_next(&mem_man->heaps, &heap_id);
	while (heap) {
		pr_warn("%s derelict heap %d!\n", __func__, heap_id);
		_img_mem_del_heap(heap);
		kfree(heap);
		heap_id = MIN_HEAP;
		heap = idr_get_next(&mem_man->heaps, &heap_id);
	}
	idr_destroy(&mem_man->heaps);

	mutex_unlock(&mem_man->mutex);

	mutex_destroy(&mem_man->mutex);
}

module_init(img_mem_init);
module_exit(img_mem_exit);

MODULE_LICENSE("GPL");

/*
 * coding style for emacs
 *
 * Local variables:
 * indent-tabs-mode: t
 * tab-width: 8
 * c-basic-offset: 8
 * End:
 */
