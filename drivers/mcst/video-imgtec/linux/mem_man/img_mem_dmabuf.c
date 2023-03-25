/*!
 *****************************************************************************
 *
 * @File       img_mem_dmabuf.c
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
#include <linux/device.h>
#include <linux/vmalloc.h>

#include <linux/dma-buf.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/version.h>

#include <img_mem_man.h>
#include "img_mem_man_priv.h"

static int trace_physical_pages;

struct buffer_data {
	struct dma_buf *dma_buf;
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;
};

static int dmabuf_heap_import(struct device *device, struct heap *heap,
				size_t size, enum img_mem_attr attr, int buf_fd,
				struct buffer *buffer)
{
	struct buffer_data *data;
	int ret;

	pr_debug("%s:%d buffer %d (0x%p) buf_fd %d\n", __func__, __LINE__,
		buffer->id, buffer, buf_fd);

	data = kmalloc(sizeof(struct buffer_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->dma_buf = dma_buf_get(buf_fd);
	if (IS_ERR_OR_NULL(data->dma_buf)) {
		pr_err("%s dma_buf_get fd %d\n", __func__, buf_fd);
		ret = -EINVAL;
		goto dma_buf_get_failed;
	}
	pr_debug("%s:%d buffer %d dma_buf %p\n", __func__, __LINE__,
		buffer->id, data->dma_buf);

	data->attach = dma_buf_attach(data->dma_buf, device);
	if (IS_ERR(data->attach)) {
		pr_err("%s dma_buf_attach fd %d\n", __func__, buf_fd);
		ret = -EINVAL;
		goto dma_buf_attach_failed;
	}

	data->sgt = dma_buf_map_attachment(data->attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(data->sgt)) {
		pr_err("%s dma_buf_map_attachment fd %d\n", __func__, buf_fd);
		ret = -EINVAL;
		goto dma_buf_map_failed;
	}

	if (trace_physical_pages) {
		struct scatterlist *sgl = data->sgt->sgl;

		while (sgl) {
			pr_debug("%s:%d phys %#llx length %d\n",
				__func__, __LINE__,
				(unsigned long long)sg_phys(sgl), sgl->length);
			sgl = sg_next(sgl);
		}
	}

	buffer->priv = data;
	return 0;

dma_buf_map_failed:
	dma_buf_detach(data->dma_buf, data->attach);
dma_buf_attach_failed:
	dma_buf_put(data->dma_buf);
dma_buf_get_failed:
	kfree(data);
	return ret;
}

static void dmabuf_heap_free(struct heap *heap, struct buffer *buffer)
{
	struct buffer_data *data = buffer->priv;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	dma_buf_unmap_attachment(data->attach, data->sgt, DMA_BIDIRECTIONAL);
	dma_buf_detach(data->dma_buf, data->attach);
	dma_buf_put(data->dma_buf);
	kfree(data);
}

static int dmabuf_heap_map_um(struct heap *heap, struct buffer *buffer,
				struct vm_area_struct *vma)
{
	struct buffer_data *data = buffer->priv;
	struct scatterlist *sgl;
	unsigned long addr;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);
	pr_debug("%s:%d vm_start %#lx vm_end %#lx size %ld\n",
		__func__, __LINE__,
		vma->vm_start, vma->vm_end, vma->vm_end - vma->vm_start);

	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	sgl = data->sgt->sgl;
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

static int dmabuf_heap_map_km(struct heap *heap, struct buffer *buffer)
{
	struct buffer_data *data = buffer->priv;
	struct dma_buf *dma_buf = data->dma_buf;
	int ret;

	pr_debug("%s:%d buffer %d (0x%p)\n", __func__, __LINE__,
		buffer->id, buffer);

	if (buffer->kptr) {
		pr_warn("%s called for already mapped buffer %d\n",
			__func__, buffer->id);
		return 0;
	}

	ret = dma_buf_begin_cpu_access(dma_buf,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
					0 /* start */,
					buffer->actual_size,
#endif
					DMA_BIDIRECTIONAL);
	if (ret) {
		pr_err("%s begin_cpu_access fd %d\n", __func__, buffer->id);
		return ret;
	}

	/* maybe dma_buf_kmap ? */
	buffer->kptr = dma_buf_vmap(dma_buf);
	if (!buffer->kptr) {
		pr_err("%s dma_buf_kmap failed!\n", __func__);
		return -EFAULT;
	}

	pr_debug("%s:%d buffer %d vmap to 0x%p\n", __func__, __LINE__,
		buffer->id, buffer->kptr);
	return 0;
}

static int dmabuf_get_sg_table(struct heap *heap, struct buffer *buffer,
				struct sg_table **sg_table)
{
	struct buffer_data *data = buffer->priv;

	*sg_table = data->sgt;
	return 0;
}

static void dmabuf_heap_destroy(struct heap *heap)
{
	pr_debug("%s:%d\n", __func__, __LINE__);
}

static struct heap_ops dmabuf_heap_ops = {
	.alloc = NULL,
	.import = dmabuf_heap_import,
	.free = dmabuf_heap_free,
	.map_um = dmabuf_heap_map_um,
	.map_km = dmabuf_heap_map_km,
	.get_sg_table = dmabuf_get_sg_table,
	.get_page_array = NULL,
	.sync_cpu_to_dev = NULL, /* TODO */
	.sync_dev_to_cpu = NULL, /* TODO */
	.destroy = dmabuf_heap_destroy,
};

int img_mem_dmabuf_init(const struct heap_config *heap_cfg, struct heap *heap)
{
	pr_debug("%s:%d\n", __func__, __LINE__);

	heap->ops = &dmabuf_heap_ops;
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
