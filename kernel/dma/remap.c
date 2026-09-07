// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2014 The Linux Foundation
 */
#include <linux/dma-map-ops.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#ifdef CONFIG_E2K
# include <asm/set_memory.h>
#endif

struct page **dma_common_find_pages(void *cpu_addr)
{
	struct vm_struct *area = find_vm_area(cpu_addr);

	if (!area || area->flags != VM_DMA_COHERENT)
		return NULL;
	return area->pages;
}

/*
 * Remaps an array of PAGE_SIZE pages into another vm_area.
 * Cannot be used in non-sleeping contexts
 */
void *dma_common_pages_remap(struct page **pages, size_t size,
			 pgprot_t prot, const void *caller)
{
	void *vaddr;
#ifdef CONFIG_E2K
	if (pgprot_val(prot) == pgprot_val(pgprot_writecombine(prot))) {
		if (set_pages_array_wc(pages, PAGE_ALIGN(size) >> PAGE_SHIFT))
			return NULL;
	}
#endif
	vaddr = vmap(pages, PAGE_ALIGN(size) >> PAGE_SHIFT,
		     VM_DMA_COHERENT, prot);
	if (vaddr)
		find_vm_area(vaddr)->pages = pages;
	return vaddr;
}

/*
 * Remaps an allocated contiguous region into another vm_area.
 * Cannot be used in non-sleeping contexts
 */
void *dma_common_contiguous_remap(struct page *page, size_t size,
			pgprot_t prot, const void *caller)
{
	int count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	struct page **pages;
	void *vaddr;
	int i;

	pages = kvmalloc_array(count, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return NULL;
	for (i = 0; i < count; i++)
		pages[i] = nth_page(page, i);
	vaddr = vmap(pages, count, VM_DMA_COHERENT, prot);
	kvfree(pages);

	return vaddr;
}

/*
 * Unmaps a range previously mapped by dma_common_*_remap
 */
#ifdef CONFIG_E2K
void dma_common_free_remap(void *cpu_addr, size_t size, unsigned long attrs)
#else
void dma_common_free_remap(void *cpu_addr, size_t size)
#endif
{
	struct vm_struct *area = find_vm_area(cpu_addr);

	if (!area || area->flags != VM_DMA_COHERENT) {
		WARN(1, "trying to free invalid coherent area: %p\n", cpu_addr);
		return;
	}
#ifdef CONFIG_E2K
	if (attrs & DMA_ATTR_WRITE_COMBINE) {
		if (WARN_ON(set_pages_array_wb(area->pages,
				PAGE_ALIGN(size) >> PAGE_SHIFT))) {
			return;
		}
	}
#endif
	vunmap(cpu_addr);
}
