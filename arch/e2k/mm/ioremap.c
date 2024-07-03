/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Same as arch/i386/mm/ioremap.c Special thanks to Linus Torvalds.
 *
 * Re-map IO memory to kernel address space so that we can access it.
 * This is needed for high PCI addresses that aren't mapped in the
 * 640k-1MB IO memory area
 *
 */

#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/pgtable.h>

#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/e2k_debug.h>
#include <asm/vga.h>

#undef	DebugIO
#undef	DEBUG_IO_REMAP_MODE
#define	DEBUG_IO_REMAP_MODE	0	/* Remap IO memory */
#define DebugIO(...)		DebugPrint(DEBUG_IO_REMAP_MODE ,##__VA_ARGS__)

int no_writecombine;
EXPORT_SYMBOL(no_writecombine);

int __init no_writecombine_setup(char *str)
{
	no_writecombine = 1;
	return 1;
}
__setup("no_writecombine", no_writecombine_setup);

static int remap_area_pages(unsigned long start,
			unsigned long phys_addr, unsigned long size,
			pte_mem_type_t memory_type)
{
	unsigned long end = start + size;
	pgprot_t prot;

	DebugIO("started for addr 0x%lx, size 0x%lx, phys addr 0x%lx, memory type %d\n",
			start, size, phys_addr, memory_type);
	BUG_ON(start >= end);
	if (unlikely(no_writecombine))
		memory_type = EXT_CONFIG_MT;
	prot = __pgprot(_PAGE_SET_MEM_TYPE(_PAGE_IO_MAP_BASE, memory_type));

	return ioremap_page_range(start, end, phys_addr, prot);
}

/*
 * Generic mapping function (not visible outside):
 *
 * Remap an arbitrary physical address space into the kernel virtual
 * address space. Needed when the kernel wants to access high IO (PCI)
 * addresses directly.
 *
 * NOTE! We need to allow non-page-aligned mappings too: we will obviously
 * have to convert them into an offset in a page-aligned mapping, but the
 * caller shouldn't need to know that small detail.
 */
static void __iomem *__ioremap_caller(resource_size_t phys_addr,
		unsigned long size, pte_mem_type_t memory_type, void *caller)
{
	struct vm_struct * area;
	unsigned long offset, last_addr, vaddr;
	struct page *page;

	DebugIO("started for phys addr 0x%llx, size 0x%lx, memory type %d\n",
		phys_addr, size, memory_type);

	/* Don't allow wraparound or zero size */
	last_addr = phys_addr + size - 1;
	if (!size || last_addr < phys_addr)
		return NULL;

	/* Don't remap the VGA area, it's always mapped */
	if (phys_addr >= VGA_VRAM_PHYS_BASE &&
			last_addr < (VGA_VRAM_PHYS_BASE + VGA_VRAM_SIZE)) {
		DebugIO("VGA VRAM phys. area, it's always mapped\n");
		return (void __iomem *) phys_to_virt((phys_addr_t) phys_addr);
	}

	/*
	 * Don't allow anybody to remap normal RAM that we're using..
	 */
	if (pfn_valid(__phys_to_pfn(phys_addr))) {
		for (page = pfn_to_page(__phys_to_pfn(phys_addr));
				page <= pfn_to_page(__phys_to_pfn(last_addr)); page++) {
			if (!PageReserved(page)) {
				WARN_ONCE(1, "phys. area at %pa - %pa is not reserved and can not be remapped\n",
						&phys_addr, &last_addr);
				return NULL;
			}
		}
	}

	/*
	 * Why would we need ioremap() that early in the boot process?
	 */
	BUG_ON(!slab_is_available());

	/*
	 * Mappings have to be page-aligned
	 */
	offset = phys_addr & ~PAGE_MASK;
	phys_addr &= PAGE_MASK;
	size = PAGE_ALIGN(last_addr+1) - phys_addr;

	/*
	 * Ok, go for it..
	 */
	area = get_vm_area_caller(size, VM_IOREMAP, caller);
	if (!area)
		return NULL;
	area->phys_addr = phys_addr;
	vaddr = (unsigned long) area->addr;
	DebugIO("get_vm_area() returned area from addr 0x%lx\n", vaddr);
	
	if (remap_area_pages(vaddr, phys_addr, size, memory_type)) {
		free_vm_area(area);
		return NULL;
	}

	DebugIO("returns IO area from virt addr 0x%lx\n", vaddr + offset);
	return (void __iomem *) (vaddr + offset);
}

void __iomem *ioremap(resource_size_t address, unsigned long size)
{
	return __ioremap_caller(address, size, EXT_NON_PREFETCH_MT,
			__builtin_return_address(0));
}
EXPORT_SYMBOL(ioremap);

void __iomem *ioremap_wc(resource_size_t address, unsigned long size)
{
	return __ioremap_caller(address, size, EXT_PREFETCH_MT,
			__builtin_return_address(0));
}
EXPORT_SYMBOL(ioremap_wc);

void __iomem *ioremap_np(resource_size_t address, unsigned long size)
{
	return __ioremap_caller(address, size, EXT_CONFIG_MT,
			__builtin_return_address(0));
}
EXPORT_SYMBOL(ioremap_np);

void __iomem *ioremap_prot(resource_size_t address, unsigned long size,
		unsigned long prot_val)
{
	return __ioremap_caller(address, size, get_pte_val_memory_type(prot_val),
			__builtin_return_address(0));
}
EXPORT_SYMBOL(ioremap_prot);

void iounmap(volatile void __iomem *addr)
{
	DebugIO("started for virtual addr 0x%px\n", addr);

	/* Don't unmap the VGA area, it's always mapped */
	if ((void *)addr >= phys_to_virt(VGA_VRAM_PHYS_BASE) &&
	    (void *)addr < phys_to_virt(VGA_VRAM_PHYS_BASE + VGA_VRAM_SIZE)) {
		DebugIO("VGA VRAM phys. area, it's always mapped\n");
		return;
	}

	addr = (volatile void __iomem *)
		(PAGE_MASK & (unsigned long __force) addr);
	vunmap((void __force *) addr);
}
EXPORT_SYMBOL(iounmap);

#ifdef CONFIG_HAVE_ARCH_HUGE_VMAP
int arch_ioremap_pud_supported(void)
{
	return 0;
}

int arch_ioremap_pmd_supported(void)
{
	return 1;
}

int arch_ioremap_p4d_supported(void)
{
	return 0;
}
#endif

void *arch_memremap_wb(phys_addr_t phys_addr, size_t size)
{
	/*
	 * For RAM remapping arch-independent code will try reusing
	 * linear map.  So we get here only when trying to map device
	 * memory as WriteBack which is not allowed on e2k.
	 */
	WARN_ONCE(1, "Writeback remap attempted on non-ram region %llx-%llx\n",
			phys_addr, phys_addr + size);
	return NULL;
}
