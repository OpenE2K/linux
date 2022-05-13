/*!
 *****************************************************************************
 *
 * @File       img_mem_secure.c
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
#ifdef CONFIG_X86
#include <asm/cacheflush.h>
#endif
#ifdef CONFIG_E2K
#include <asm/set_memory.h>
#endif

#include <img_mem_man.h>
#include "img_mem_man_priv.h"

static int trace_physical_pages;

static int secure_alloc(struct device *device, struct heap *heap,
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
#if defined CONFIG_X86 || defined CONFIG_E2K
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

static void secure_free(struct heap *heap, struct buffer *buffer)
{
	struct sg_table *sgt = buffer->priv;
	struct scatterlist *sgl;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		 buffer->id, buffer);

	sgl = sgt->sgl;
	while (sgl) {
#if defined CONFIG_X86 || defined CONFIG_E2K
		set_memory_wb((unsigned long)page_address(sg_page(sgl)), 1);
#endif
		__free_page(sg_page(sgl));
		sgl = sg_next(sgl);
	}
	sg_free_table(sgt);
	kfree(sgt);
}

static int secure_get_sg_table(struct heap *heap, struct buffer *buffer,
				struct sg_table **sg_table)
{
	*sg_table = buffer->priv;
	return 0;
}

static void secure_heap_destroy(struct heap *heap)
{
	pr_debug("%s:%d\n", __func__, __LINE__);
}

static struct heap_ops secure_heap_ops = {
	.alloc = secure_alloc,
	.import = NULL,
	.free = secure_free,
	.map_um = NULL,
	.map_km = NULL,
	.get_sg_table = secure_get_sg_table,
	.get_page_array = NULL,
	.sync_cpu_to_dev = NULL,
	.sync_dev_to_cpu = NULL,
	.destroy = secure_heap_destroy,
};

int img_mem_secure_init(const struct heap_config *heap_cfg, struct heap *heap)
{
	pr_debug("%s:%d\n", __func__, __LINE__);

	heap->ops = &secure_heap_ops;
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
