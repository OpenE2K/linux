/*!
 *****************************************************************************
 *
 * @File       img_mem_unified.c
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
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <linux/vmalloc.h>
#include <linux/dma-mapping.h>
#ifdef CONFIG_MCST
#include <linux/dma-map-ops.h>
#endif
#ifdef CONFIG_X86
#include <asm/cacheflush.h>
#endif
#ifdef CONFIG_E2K
#include <asm/set_memory.h>
#endif

#include <img_mem_man.h>
#include "img_mem_man_priv.h"

static int trace_physical_pages;

#ifdef CONFIG_MCST

static int unified_alloc_wo_iommu(struct device *device, struct heap *heap,
			size_t size, enum img_mem_attr attr,
			struct buffer *buffer)
{
	struct sg_table *sgt;
	struct scatterlist *sgl;
	int pages;
	int ret;

	sgt = kmalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!sgt)
		return -ENOMEM;

	pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;

	ret = sg_alloc_table(sgt, pages, GFP_KERNEL);
	if (ret)
		goto sg_alloc_table_failed;

	sgl = sgt->sgl;
	while (sgl) {
		struct page *page;
		page = alloc_page(heap->options.unified.gfp_type);
		if (!page) {
			ret = -ENOMEM;
			goto alloc_page_failed;
		}
		sg_set_page(sgl, page, PAGE_SIZE, 0);
#if defined CONFIG_X86 || defined CONFIG_E2K
		set_memory_wc((unsigned long)page_address(page), 1);
#endif
		sgl = sg_next(sgl);
	}

	ret = dma_map_sg(device, sgt->sgl, sgt->orig_nents,
			DMA_BIDIRECTIONAL);
	if (ret <= 0) {
		ret = -EIO;
		goto alloc_page_failed;
	}
	sgt->nents = ret;

	buffer->priv = sgt;
	return 0;

alloc_page_failed:
	sgl = sgt->sgl;
	while (sgl) {
		struct page *page = sg_page(sgl);

		if (page) {
#if defined CONFIG_X86 || defined CONFIG_E2K
			set_memory_wb((unsigned long)page_address(page), 1);
#endif
			__free_page(page);
		}
		sgl = sg_next(sgl);
	}
	sg_free_table(sgt);
sg_alloc_table_failed:
	kfree(sgt);
	return ret;
}

static int unified_alloc_w_iommu(struct device *device, struct heap *heap,
			size_t size, enum img_mem_attr attr,
			struct buffer *buffer)
{
	struct sg_table *sgt;
	int ret;
	dma_addr_t	dma_addr;

	sgt = kmalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!sgt)
		return -ENOMEM;

	buffer->kptr = dma_alloc_coherent(device, size,
			&dma_addr, heap->options.unified.gfp_type);
	if (!buffer->kptr) {
		ret = -EFAULT;
		goto alloc_page_failed;
	}

	ret = dma_get_sgtable(device, sgt, buffer->kptr, dma_addr, size);
	if (ret)
		goto get_sgtable_failed;

#if defined CONFIG_X86 || defined CONFIG_E2K
	set_memory_wc((unsigned long) buffer->kptr, PAGE_ALIGN(size) >> PAGE_SHIFT);
#endif

	sg_dma_len(sgt->sgl) = size;
	sg_dma_address(sgt->sgl) = dma_addr;

	buffer->priv = sgt;
	return 0;

get_sgtable_failed:
	dma_free_coherent(device, size, buffer->kptr, dma_addr);
alloc_page_failed:
	kfree(sgt);
	return ret;
}

static int unified_alloc(struct device *device, struct heap *heap,
			size_t size, enum img_mem_attr attr,
			struct buffer *buffer)
{
	
	return device_iommu_mapped(device) ?
		unified_alloc_w_iommu(device, heap, size, attr, buffer) :
		unified_alloc_wo_iommu(device, heap, size, attr, buffer);
		
}
static void unified_free(struct heap *heap, struct buffer *buffer)
{
	struct sg_table *sgt = buffer->priv;
	struct scatterlist *sgl = sgt->sgl;
	if (device_iommu_mapped(buffer->device)) {
#if defined CONFIG_X86 || defined CONFIG_E2K
		set_memory_wb((unsigned long) buffer->kptr,
				PAGE_ALIGN(buffer->actual_size) >> PAGE_SHIFT);
#endif
		dma_free_coherent(buffer->device, buffer->actual_size,
						buffer->kptr, sg_dma_address(sgl));
	} else {
		struct sg_table *sgt = buffer->priv;
		struct scatterlist *sgl;
		if (buffer->kptr)
			vunmap(buffer->kptr);
		dma_unmap_sg(buffer->device, sgt->sgl,
				sgt->orig_nents, DMA_BIDIRECTIONAL);
		sgl = sgt->sgl;
		while (sgl) {
	#if defined CONFIG_X86 || defined CONFIG_E2K
			set_memory_wb((unsigned long)page_address(sg_page(sgl)), 1);
	#endif
			__free_page(sg_page(sgl));
			sgl = sg_next(sgl);
		}
	}
	sg_free_table(sgt);
	kfree(sgt);
}
#else /*CONFIG_MCST*/
static int unified_alloc(struct device *device, struct heap *heap,
			size_t size, enum img_mem_attr attr,
			struct buffer *buffer)
{
	struct sg_table *sgt;
	struct scatterlist *sgl;
	int pages;
	int ret;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	sgt = kmalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!sgt)
		return -ENOMEM;

	pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;

	ret = sg_alloc_table(sgt, pages, GFP_KERNEL);
	if (ret)
		goto sg_alloc_table_failed;

	sgl = sgt->sgl;
	while (sgl) {
		struct page *page;
		dma_addr_t dma_addr;

		page = alloc_page(heap->options.unified.gfp_type);
		if (!page) {
			pr_err("%s alloc_page failed!\n", __func__);
			ret = -ENOMEM;
			goto alloc_page_failed;
		}
		if (trace_physical_pages)
			pr_debug("%s:%d phys %#llx size %lu page_address %p\n",
				__func__, __LINE__,
				(unsigned long long)page_to_phys(page),
				PAGE_SIZE, page_address(page));

		/*
		 * dma_map_page() is probably going to fail if alloc flags are
		 * GFP_HIGHMEM, since it is not mapped to CPU. Hopefully, this
		 * will never happen because memory of this sort cannot be used
		 * for DMA anyway. To check if this is the case, build with
		 * debug, set trace_physical_pages=1 and check if page_address
		 * printed above is NULL
		 */
		dma_addr = dma_map_page(device, page, 0, PAGE_SIZE,
					DMA_BIDIRECTIONAL);
		if (dma_mapping_error(device, dma_addr)) {
			__free_page(page);
			pr_err("%s dma_map_page failed!\n", __func__);
			ret = -EIO;
			goto alloc_page_failed;
		}
		dma_unmap_page(device, dma_addr, PAGE_SIZE, DMA_BIDIRECTIONAL);
		sg_set_page(sgl, page, PAGE_SIZE, 0);
#ifdef CONFIG_X86
		set_memory_wc((unsigned long)page_address(page), 1);
#endif
		sgl = sg_next(sgl);
	}
	buffer->priv = sgt;
	return 0;

alloc_page_failed:
	sgl = sgt->sgl;
	while (sgl) {
		struct page *page = sg_page(sgl);

		if (page) {
#ifdef CONFIG_X86
			set_memory_wb((unsigned long)page_address(page), 1);
#endif
			__free_page(page);
		}
		sgl = sg_next(sgl);
	}
	sg_free_table(sgt);
sg_alloc_table_failed:
	kfree(sgt);
	return ret;
}

static void unified_free(struct heap *heap, struct buffer *buffer)
{
	struct sg_table *sgt = buffer->priv;
	struct scatterlist *sgl;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	if (buffer->kptr) {
		pr_debug("%s vunmap 0x%p\n", __func__, buffer->kptr);
		dma_unmap_sg(buffer->device, sgt->sgl,
				sgt->orig_nents, DMA_FROM_DEVICE);
		vunmap(buffer->kptr);
	}
	sgl = sgt->sgl;
	while (sgl) {
#ifdef CONFIG_X86
		set_memory_wb((unsigned long)page_address(sg_page(sgl)), 1);
#endif
		__free_page(sg_page(sgl));
		sgl = sg_next(sgl);
	}
	sg_free_table(sgt);
	kfree(sgt);
}
#endif /*CONFIG_MCST*/

static int unified_map_um(struct heap *heap, struct buffer *buffer,
			struct vm_area_struct *vma)
{
	struct sg_table *sgt = buffer->priv;
	struct scatterlist *sgl;
	unsigned long addr;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);
	pr_debug("%s:%d vm_start %#lx vm_end %#lx size %ld\n",
		__func__, __LINE__,
		vma->vm_start, vma->vm_end, vma->vm_end - vma->vm_start);

	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	sgl = sgt->sgl;
	addr = vma->vm_start;
	while (sgl && addr < vma->vm_end) {
		dma_addr_t phys = sg_phys(sgl); /* sg_dma_address ? */
		unsigned long pfn = phys >> PAGE_SHIFT;
		unsigned int len = sgl->length;
		int ret;

		if (vma->vm_end < (addr + len)) {
			unsigned long size = vma->vm_end - addr;
			pr_debug("%s:%d buffer %d (0x%p) truncating len=%x to size=%lx\n",
				__func__, __LINE__,
				buffer->id, buffer, len, size);
			WARN(round_up(size, PAGE_SIZE) != size,
				"VMA size %lx not page aligned\n", size);
			len = size;
		}
		if (trace_physical_pages)
			pr_debug("%s:%d phys %#llx vaddr %#lx length %u\n",
				__func__, __LINE__,
				(unsigned long long)phys, addr, len);

		ret = remap_pfn_range(vma, addr, pfn, len, vma->vm_page_prot);
		if (ret)
			return ret; /* TODO: revert on error? */

		addr += len;
		sgl = sg_next(sgl);
	}

	return 0;
}


static int unified_map_km(struct heap *heap, struct buffer *buffer)
{
	struct sg_table *sgt = buffer->priv;
	struct scatterlist *sgl = sgt->sgl;
	unsigned int num_pages = sg_nents(sgl);
	struct page **pages;
	pgprot_t prot;
#ifndef CONFIG_MCST
	int ret;
#endif

	int i;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	if (buffer->kptr) {
#ifndef CONFIG_MCST
		pr_warn("%s called for already mapped buffer %d\n",
			__func__, buffer->id);
#endif
		return 0;
	}

	pages = kmalloc_array(num_pages, sizeof(struct page *), GFP_KERNEL);
	if (!pages) {
		pr_err("%s failed to allocate memory for pages\n", __func__);
		return -ENOMEM;
	}

	prot = PAGE_KERNEL;
	prot = pgprot_writecombine(prot);

	i = 0;
	while (sgl) {
		pages[i++] = sg_page(sgl);
		sgl = sg_next(sgl);
	}

	buffer->kptr = vmap(pages, num_pages, VM_MAP, prot);
	kfree(pages);
	if (!buffer->kptr) {
		pr_err("%s vmap failed!\n", __func__);
		return -EFAULT;
	}
#ifndef CONFIG_MCST
	ret = dma_map_sg(buffer->device, sgt->sgl, sgt->orig_nents,
			DMA_FROM_DEVICE);
	if (ret <= 0) {
		pr_err("%s dma_map_sg failed!\n", __func__);
		vunmap(buffer->kptr);
		return -EFAULT;
	}
	pr_debug("%s:%d buffer %d orig_nents %d nents %d\n", __func__, __LINE__,
		buffer->id, sgt->orig_nents, ret);
	sgt->nents = ret;
#endif
	pr_debug("%s:%d buffer %d vmap to 0x%p\n", __func__, __LINE__,
		buffer->id, buffer->kptr);

	return 0;
}

static int unified_get_sg_table(struct heap *heap, struct buffer *buffer,
				struct sg_table **sg_table)
{
	*sg_table = buffer->priv;
	return 0;
}

static void unified_sync_cpu_to_dev(struct heap *heap, struct buffer *buffer)
{
	struct sg_table *sgt = buffer->priv;

	if (!buffer->kptr)
		return;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	dma_sync_sg_for_device(buffer->device, sgt->sgl, sgt->orig_nents,
				DMA_TO_DEVICE);
}

static void unified_sync_dev_to_cpu(struct heap *heap, struct buffer *buffer)
{
	struct sg_table *sgt = buffer->priv;

	if (!buffer->kptr)
		return;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	dma_sync_sg_for_cpu(buffer->device, sgt->sgl, sgt->orig_nents,
				DMA_TO_DEVICE);
}

static void unified_heap_destroy(struct heap *heap)
{
	pr_debug("%s:%d\n", __func__, __LINE__);
}

static struct heap_ops unified_heap_ops = {
	.alloc = unified_alloc,
	.import = NULL,
	.free = unified_free,
	.map_um = unified_map_um,
	.map_km = unified_map_km,
	.get_sg_table = unified_get_sg_table,
	.get_page_array = NULL,
	.sync_cpu_to_dev = unified_sync_cpu_to_dev,
	.sync_dev_to_cpu = unified_sync_dev_to_cpu,
	.destroy = unified_heap_destroy,
};

int img_mem_unified_init(const struct heap_config *heap_cfg, struct heap *heap)
{
	pr_debug("%s:%d\n", __func__, __LINE__);

	heap->ops = &unified_heap_ops;
	return 0;
}

/*
 * coding style for emacs
 *
 * Local variables:
 * indent-tabs-mode: t
 * tab-width: 8
 * c-basic-offset: 8
 * End:
 */
