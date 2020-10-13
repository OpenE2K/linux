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

#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/e2k_debug.h>

#undef	DebugIO
#undef	DEBUG_IO_REMAP_MODE
#define	DEBUG_IO_REMAP_MODE	0	/* Remap IO memory */
#define DebugIO(...)		DebugPrint(DEBUG_IO_REMAP_MODE ,##__VA_ARGS__)

static e2k_addr_t early_io_vm_area_base = EARLY_IO_VMALLOC_START;
static DEFINE_SPINLOCK(early_io_vmlist_lock);

static inline void *
early_get_io_vm_area(e2k_size_t size)
{
	e2k_addr_t io_area_start = 0;

	spin_lock(&early_io_vmlist_lock);
	if (early_io_vm_area_base + size > EARLY_IO_VMALLOC_END) {
		printk("early_get_io_vm_area() early IO VM area is overflowed "
			"current start 0x%lx + needs size 0x%lx > end 0x%lx\n",
			early_io_vm_area_base, size, EARLY_IO_VMALLOC_END);
	} else {
		io_area_start = early_io_vm_area_base;
		early_io_vm_area_base += size;
	}
	spin_unlock(&early_io_vmlist_lock);
	return (void *)io_area_start;
}

static inline int node_remap_area_pte(int nid, pmd_t * pmd,
			unsigned long address, unsigned long end,
			unsigned long phys_addr, pgprot_t prot)
{
	pte_t *pte;

	DebugIO("started for pmd 0x%p == 0x%lx, addr "
		"0x%lx, end 0x%lx, phys addr 0x%lx, prot 0x%lx\n",
		pmd, pmd_val(*pmd), address, end, phys_addr, pgprot_val(prot));
	if (mem_init_done) {
		pte = node_pte_alloc_kernel(nid, pmd, address);
	} else {
		pte = early_pte_alloc(pmd, address);
	}
	if (!pte)
		return -ENOMEM;
	BUG_ON(address >= end);
	do {
		DebugIO("addr 0x%lx, phys addr 0x%lx, "
			"pte 0x%p == 0x%lx\n",
			address, phys_addr, pte, pte_val(*pte));
		if (!pte_none(*pte)) {
			printk("node_remap_area_pte(): page already exists, "
				"addr 0x%lx pte 0x%p == 0x%lx\n",
				address, pte, pte_val(*pte));
			BUG();
		}
		set_pte_at(current->mm, address, pte,
				mk_pte_phys(phys_addr, prot));
		phys_addr += PAGE_SIZE;
	} while (pte ++, address += PAGE_SIZE, address != end);
	return 0;
}

static inline int node_remap_area_pmd(int nid, pud_t * pud,
			unsigned long address, unsigned long end,
			unsigned long phys_addr, pgprot_t prot)
{
	pmd_t *pmd;
	unsigned long next;

	DebugIO("started for pud 0x%p == 0x%lx, addr "
		"0x%lx, end 0x%lx, phys addr 0x%lx, prot 0x%lx\n",
		pud, pud_val(*pud), address, end, phys_addr, pgprot_val(prot));
	if (mem_init_done) {
		pmd = node_pmd_alloc_kernel(nid, pud, address);
	} else {
		pmd = early_pmd_alloc(pud, address);
	}
	if (!pmd)
		return -ENOMEM;
	phys_addr -= address;
	BUG_ON(address >= end);
	do {
		DebugIO("addr 0x%lx, phys addr 0x%lx, "
			"pmd 0x%p == 0x%lx\n",
			address, phys_addr + address, pmd, pmd_val(*pmd));
		next = pmd_addr_end(address, end);
		if (node_remap_area_pte(nid, pmd, address, next,
					address + phys_addr, prot))
			return -ENOMEM;
	} while (pmd ++, address = next, address != end);
	return 0;
}

static inline int node_remap_area_pud(int nid, pgd_t * dir,
			unsigned long address, unsigned long end,
			unsigned long phys_addr, pgprot_t prot)
{
	pud_t *pud;
	unsigned long next;

	DebugIO("started for pgd 0x%p == 0x%lx, addr "
		"0x%lx, end 0x%lx, phys addr 0x%lx, prot 0x%lx\n",
		dir, pgd_val(*dir), address, end, phys_addr, pgprot_val(prot));
	if (mem_init_done) {
		pud = node_pud_alloc_kernel(nid, dir, address);
	} else {
		pud = early_pud_alloc(dir, address);
	}
	if (!pud)
		return -ENOMEM;
	phys_addr -= address;
	BUG_ON(address >= end);
	do {
		DebugIO("addr 0x%lx, phys addr 0x%lx, "
			"pud 0x%p == 0x%lx\n",
			address, phys_addr + address, pud, pud_val(*pud));
		next = pud_addr_end(address, end);
		if (node_remap_area_pmd(nid, pud, address, next,
					address + phys_addr, prot))
			return -ENOMEM;
	} while (pud ++, address = next, address != end);
	return 0;
}

static int __ref node_remap_page_range(int nid, unsigned long address,
		unsigned long end, unsigned long phys_addr,  pgprot_t prot)
{
	pgd_t *dir;
	unsigned long start = address;
	unsigned long next;

	DebugIO("started for addr 0x%lx, "
		"end 0x%lx, phys addr 0x%lx, prot 0x%lx\n",
		start, end, phys_addr, pgprot_val(prot));
	BUG_ON(start >= end);
	phys_addr -= address;
	dir = node_pgd_offset_kernel(nid, address);
	do {
		DebugIO("addr 0x%lx, phys addr "
			"0x%lx, pgd 0x%p == 0x%lx\n",
			address, phys_addr + address, dir, pgd_val(*dir));
		next = pgd_addr_end(address, end);
		if (node_remap_area_pud(nid, dir, address, next,
					 phys_addr + address, prot))
			return -ENOMEM;
	} while (dir ++, address = next, address != end);
	if (num_online_cpus() > 1)
		flush_tlb_all();
	else
		__flush_tlb_all();
	return 0;
}

static int no_writecombine;
int __init no_writecombine_setup(char *str)
{
	no_writecombine = 1;
	return 1;
}
__setup("no_writecombine", no_writecombine_setup);

static int remap_area_pages(unsigned long address, unsigned long phys_addr,
				 unsigned long size, unsigned long flags)
{
	unsigned long start = address;
	unsigned long end = address + size;
	pgprot_t prot;
	int nid = numa_node_id();
	int error;

	DebugIO("started for addr 0x%lx, "
		"size 0x%lx, phys addr 0x%lx, flags 0x%lx\n",
		start, size, phys_addr, flags);
	BUG_ON(start >= end);
	if (no_writecombine) {
		if ((flags & (_PAGE_CD_DIS | _PAGE_PWT)) == _PAGE_CD_DIS)
			flags |= _PAGE_PWT;
	}
	prot = __pgprot(_PAGE_IO_MAP_CACHE | flags);
	error = node_remap_page_range(nid, start, end, phys_addr, prot);
	if (error)
		return error;
#ifdef	CONFIG_NUMA
	if (all_other_nodes_map_vm_area(nid, start, size)) {
		panic("Could not do remap IO area from phys addr 0x%lx, "
			"size 0x%lx on all numa nodes\n",
			start, size);
	}
#endif	/* CONFIG_NUMA */
	return 0;
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
static void __iomem *__e2k_ioremap(unsigned long phys_addr, unsigned long size,
		    unsigned long flags)
{
	void *addr;
	struct vm_struct * area;
	unsigned long offset, last_addr;

	DebugIO("started for phys addr 0x%lx, size 0x%lx, "
		"flags 0x%lx\n",
		phys_addr, size, flags);
	/* Don't allow wraparound or zero size */
	last_addr = phys_addr + size - 1;
	if (!size || last_addr < phys_addr)
		return NULL;

	/*
	 * Don't remap the low PCI/ISA area, it's always mapped..
	 */
	if (phys_addr >= E2K_X86_LOW_IO_AREA_PHYS_BASE &&
		last_addr < (E2K_X86_LOW_IO_AREA_PHYS_BASE +
					E2K_X86_LOW_IO_AREA_SIZE)) {
		DebugIO("phys. area from PCI/ISA area, it's "
			"always mapped\n");
		return phys_to_virt(phys_addr);
	}

	/*
	 * Don't allow anybody to remap normal RAM that we're using..
	 */
	if (phys_addr_valid(phys_addr)) {
		char *t_addr, *t_end;
		struct page *page;

		DebugIO("phys. area is normal RAM that we're "
			"using\n");
		t_addr = __va(phys_addr);
		t_end = t_addr + (size - 1);

		for(page = virt_to_page(t_addr); page <= virt_to_page(t_end);
								page ++)
			if(!PageReserved(page))
				return NULL;
		DebugIO("phys. area is not reserved and can be "
			"remapped\n");
	}

	/*
	 * Mappings have to be page-aligned
	 */
	offset = phys_addr & ~PAGE_MASK;
	phys_addr &= PAGE_MASK;
	size = PAGE_ALIGN(last_addr) - phys_addr;

	/*
	 * Ok, go for it..
	 */
	if (mem_init_done) {
		DebugIO("will start get_vm_area()\n");
		area = get_vm_area(size, VM_IOREMAP);
		if (!area)
			return NULL;
		addr = area->addr;
		DebugIO("get_vm_area() returned area from addr "
			"0x%p\n", addr);
	} else {
		addr = early_get_io_vm_area(size);
		if (addr == NULL)
			return NULL;
		DebugIO("early_get_vm_area() returned area from "
			"addr 0x%p\n", addr);
	}
	if (remap_area_pages((e2k_addr_t)addr, phys_addr, size, flags)) {
		if (mem_init_done)
			vfree(addr);
		return NULL;
	}
	DebugIO("returns IO area from virt addr 0x%lx\n",
		(e2k_addr_t)addr + offset);
	return (void *) (offset + (char *)addr);
}

void __iomem *ioremap_nocache(unsigned long address, unsigned long size)
{
	return __e2k_ioremap(address, size, _PAGE_CD_DIS | _PAGE_PWT);
}
EXPORT_SYMBOL(ioremap_nocache);

void __iomem *ioremap_cache(unsigned long address, unsigned long size)
{
	return __e2k_ioremap(address, size, 0);
}
EXPORT_SYMBOL(ioremap_cache);

void __iomem *ioremap_wc(unsigned long address, unsigned long size)
{
	return __e2k_ioremap(address, size, _PAGE_CD_DIS);
}
EXPORT_SYMBOL(ioremap_wc);

void iounmap(void *io_base)
{
	e2k_addr_t addr = (e2k_addr_t)io_base;

	DebugIO("started for virtual addr 0x%p\n",
		io_base);
	if (addr >= VMALLOC_START && addr < VMALLOC_END)
		return vfree((void *) (PAGE_MASK & (unsigned long) addr));
	else if (addr >= EARLY_IO_VMALLOC_START &&
				addr < EARLY_IO_VMALLOC_END) {
		printk("iounmap() early vmalloc memory 0x%p can not be "
			"unmapped\n", io_base);
	} else {
		printk("iounmap() IO unmapped area 0x%p is out of the "
			"kernel VM areas\n", io_base);
	}
}
EXPORT_SYMBOL(iounmap);
