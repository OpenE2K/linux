/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/bitops.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/pfn_t.h>

#include <asm/pci.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/trace.h>


/* Check if the whole region is in ram.  Note that the range
 * [start; end) is exclusive on the right side. */
static bool region_is_ram_only(phys_addr_t start, phys_addr_t end)
{
	unsigned long start_pfn = PHYS_PFN(start);
	unsigned long end_pfn = PHYS_PFN(end + PAGE_SIZE - 1);

	if (start_pfn >= end_pfn)
		return false;

	do {
		unsigned long block_start_pfn, block_end_pfn;

		if (memblock_search_pfn_nid(start_pfn, &block_start_pfn,
				&block_end_pfn) < 0) {
			return false;
		}
		start_pfn = block_end_pfn;
	} while (start_pfn < end_pfn);

	return true;
}

static char *memtype_name(enum page_cache_mode memtype)
{
	switch (memtype) {
	case PCM_UC: return "incoherent";
	case PCM_WC: return "coherent uncached";
	case PCM_WB: return "coherent cached";
	case PCM_UNKNOWN: return "uninitialized";
	default:
		WARN_ONCE(1, "Got an impossible value for enum, some type error in kernel?");
		return "'internal error'";
	}
}


static bool memtype_is_coherent(enum page_cache_mode memtype)
{
	return pte_mem_type_is_coherent(memtype2pte_mem_type(memtype));
}

/*
 * On e2k a single physical page must have the same coherency rules across
 * all its mappings (coherency enabled everywhere or disabled everywhere).
 *
 * To enforce that rule we do the same thing as x86: set_memory_{wc/uc/wb}
 * interfaces track the requested mapping type in struct page while also
 * setting it in the linear mapping.  Then later remapping into user space
 * with remap_pfn_range()/vmf_insert_pfn() will use the saved type.  Note
 * that this requires that drivers are using the x86 interface as decribed
 * in Documentation/x86/pat.rst:
 *  1) {set_memory/set_pages/set_pages_array}_{uc/wc}() requests needed memory
 *     type in linear mapping;
 *  2) pgprot_writecombine() or pgprot_noncached() sets that type in pgprot;
 *  3) remap_pfn_range(pgprot)/vmf_insert_pfn(pgprot) does the remapping;
 *  4) {set_memory/set_pages/set_pages_array}_wb() before freeing memory will
 *     revert memory type changes.
 *
 * If driver just wants to remap RAM as coherent cacheable (i.e. without
 * changing type) then it can call remap_pfn_range() directly - but then
 * the driver must not also remap this memory as writecombine/noncached.
 *
 * Also note that the set_memory_* interfaces can be used on PCI memory
 * received from ioremap*() call, in which case they will not remember
 * anything and just change the mapping type in corresponding VMALLOC area.
 *
 * Note that the default value for 'struct page' flags used for saving (both 0)
 * does not correspond to any mapping type.  So we either use type from
 * 'struct page' if it is valid or use the type passed in pgprot (and issue
 * a warning because this means that driver does not use set_memory_*() and
 * is susceptible to aliasing).
 */
#define PAGE_UNCACHED	(1ull << PG_uncached)
#define PAGE_COHERENT	(1ull << PG_arch_1)

static enum page_cache_mode page_flags_to_memtype(unsigned long flags)
{
	switch (flags & (PAGE_COHERENT | PAGE_UNCACHED)) {
	case PAGE_COHERENT | PAGE_UNCACHED:
		return PCM_WC;
	case PAGE_UNCACHED:
		return PCM_UC;
	case PAGE_COHERENT:
		return PCM_WB;
	default:
		return PCM_UNKNOWN;
	}
}

static enum page_cache_mode get_page_memtype(const struct page *page)
{
	return page_flags_to_memtype(page->flags);
}

static void set_page_memtype(struct page *page, enum page_cache_mode mode)
{
	unsigned long set_flags, old, new;

	if (mode == PCM_UC) {
		set_flags = PAGE_UNCACHED;
	} else if (mode == PCM_WC) {
		set_flags = PAGE_COHERENT | PAGE_UNCACHED;
	} else if (mode == PCM_WB) {
		set_flags = PAGE_COHERENT;
	} else { /* mode == PCM_UNKNOWN */
		set_flags = 0;
	}

	do {
		old = page->flags;
		new = (old & ~(PAGE_COHERENT| PAGE_UNCACHED)) | set_flags;
	} while (cmpxchg(&page->flags, old, new) != old);
}

static enum page_cache_mode lookup_memtype(phys_addr_t physaddr)
{
	unsigned long pfn = PHYS_PFN(physaddr);

	/* Check that there is a struct page */
	if (WARN_ON_ONCE(!pfn_valid(pfn)))
		return PCM_UNKNOWN;

	return get_page_memtype(pfn_to_page(pfn));
}

static inline pgprot_t __must_check set_ram_memtype(
		pgprot_t prot, enum page_cache_mode memtype)
{
	pte_mem_type_t mt = memtype2pte_mem_type(memtype);

	return __pgprot(set_pte_val_memory_type(pgprot_val(prot), mt));
}

static void check_memtypes_are_same(unsigned long prot,
		phys_addr_t paddr, unsigned long size)
{
	enum pte_mem_type req_memtype = get_pte_val_memory_type(prot);
	phys_addr_t pa;

	trace_pfn_remap(paddr, paddr + size, true, pte_mem_type_name(req_memtype));

	for (pa = paddr; pa < paddr + size; pa += PAGE_SIZE) {
		enum pte_mem_type page_memtype = memtype2pte_mem_type(lookup_memtype(pa));
		if (req_memtype == page_memtype)
			continue;

		WARN_ONCE(1, "%s [%d]: map phys. address 0x%llx in range [mem 0x%llx-0x%llx], requested %s, got %s\n",
			current->comm, current->pid, pa, paddr, paddr + size - 1,
			pte_mem_type_name(req_memtype),
			pte_mem_type_name(page_memtype));
	}
}


/**
 * check_cacheflush_on_remap - check if CPU caches flush is needed
 *			       when changing memory coherency/cacheability
 * @prev_memtype - previous memory protection (General/External/WC/UC/WB ...)
 * @req_memtype - new memory protection
 * @is_ram - true if this is RAM area
 *
 * 1) When remapping from coherent memory type (General on iset v6 and WB/WC
 * on iset <v6) to incoherent type (External on iset v6 and UC on iset <v6)
 * we must flush previous cache contents so that they won't overwrite RAM
 * contents later.
 *
 * Flush must be done after remapping.
 *
 * 2) When remapping memory from incoherent to coherent type it is possible
 * that hardware prefetcher has loaded some of its older contents into cache
 * so it must be invalidated.  Other possibility is that a speculative load
 * landed into an alias mapping at PAGE_OFFSET - and also loaded older memory
 * contents into cache.
 *
 * We avoid aliases by using this trace_pfn_*() API to track the needed
 * memory type, so we only have to worry about CPUs with hardware prefetcher
 * here. Another important nuance is that there is a prefetch instruction
 * that loads a cache line while also marking it as dirty, and this means
 * that we _must_ either avoid this instruction - or avoid aliases.
 *
 * Cache invalidation is not supported on e2k, but we rely on the fact that
 * hardware speculative prefetches will populate cache with no-dirty lines
 * only, and software speculative accesses won't happen while memory is
 * mapped as incoherent.  Then we can flush cache instead of invalidating
 * it (the result is the same - non-dirty lines are dropped).
 *
 * Flush must be done before remapping.
 */
static bool check_cacheflush_on_remap(enum page_cache_mode prev_memtype,
		enum page_cache_mode req_memtype, bool is_ram)
{
	bool prev_coherent, req_coherent;

	/* Nothing to flush for PCI memory, we do not support writeback
	 * mapping for it (i.e. have no proper ioremap_cache() support). */
	if (!is_ram)
		return false;

	prev_coherent = memtype_is_coherent(prev_memtype);
	req_coherent = memtype_is_coherent(req_memtype);

	if (/* 1st case above */ !req_coherent && prev_coherent ||
			/* 2nd case above */ cpu_has(CPU_FEAT_HW_PREFETCHER_L2) &&
			req_coherent && !prev_coherent) {
		return true;
	}

	return false;
}

/*
 * Save the new memory type into 'struct page' flags
 */
int memtype_reserve(phys_addr_t start, phys_addr_t end,
		    enum page_cache_mode memtype, bool *cache_flush_needed)
{
	unsigned long pfn;

	*cache_flush_needed = false;

	if (start >= end) {
		WARN("%s failed: mem [0x%llx-0x%llx], requested %s",
				__func__, start, end - 1, memtype_name(memtype));
		return -EINVAL;
	}

	if (!region_is_ram_only(start, end))
		return 0;

	trace_pfn_remap(start, end, false, memtype_name(memtype));

	/* Check that driver did not forget to call set_memory_wb() when
	 * freeing memory that had set_memory_{uc/wc}() called on it */
	for (pfn = PHYS_PFN(start); pfn < PHYS_PFN(end); ++pfn) {
		enum page_cache_mode prev_type = get_page_memtype(pfn_to_page(pfn));

		if (prev_type != PCM_UNKNOWN) {
			WARN_ONCE(1, "memtype_reserve failed [mem 0x%llx-0x%llx], requested %s but pfn 0x%lx is mapped as %s already (instead of %s)\n",
				start, end - 1, memtype_name(memtype),
				pfn, memtype_name(prev_type),
				memtype_name(PCM_UNKNOWN));
			return -EBUSY;
		}
	}

	for (pfn = PHYS_PFN(start); pfn < PHYS_PFN(end); ++pfn) {
		set_page_memtype(pfn_to_page(pfn), memtype);
	}

	*cache_flush_needed = check_cacheflush_on_remap(PCM_WB, memtype, true);

	return 0;
}

/*
 * This must be called _before_ remapping memory back to WB type.
 * Returns whether memtype_free() call is needed after the remap.
 */
bool __must_check memtype_free_cacheflush(phys_addr_t start, phys_addr_t end)
{
	enum page_cache_mode prev_type;

	if (!region_is_ram_only(start, end))
		return false;

	prev_type = get_page_memtype(pfn_to_page(PHYS_PFN(start)));

	if (check_cacheflush_on_remap(prev_type, PCM_WB, true))
		write_back_cache_range((unsigned long) __va(start), end - start);

	return true;
}

/*
 * Clear memory type information from 'struct page' flags.
 */
void memtype_free(phys_addr_t start, phys_addr_t end)
{
	unsigned long pfn;
	enum page_cache_mode prev_type;

	if (!region_is_ram_only(start, end))
		return;

	trace_pfn_remap(start, end, false, memtype_name(PCM_UNKNOWN));

	for (pfn = PHYS_PFN(start); pfn < PHYS_PFN(end); ++pfn) {
		struct page *page = pfn_to_page(pfn);
		prev_type = get_page_memtype(page);

		if (prev_type == PCM_WB ||
		    prev_type == PCM_UNKNOWN) {
			WARN_ONCE(1, "memtype_free for [mem 0x%llx-0x%llx], pfn 0x%lx is mapped as %s already\n",
				start, end - 1, pfn,
				memtype_name(PCM_WB));
			continue;
		}

		set_page_memtype(page, PCM_UNKNOWN);
	}
}

/*
 * track_pfn_copy is called when vma that is covering the pfnmap gets
 * copied through copy_page_range().
 */
int track_pfn_copy(struct vm_area_struct *vma)
{
	phys_addr_t paddr;
	unsigned long prot;

	/* Note that for non-ram memory this bit won't be set.
	 * Also the only reason this bit exists now is the debugging
	 * check below.  If after some time it never triggers, then it
	 * should be safe to remove VM_MEMTYPE_TRACKED altogether. */
	if (!(vma->vm_flags & VM_MEMTYPE_TRACKED))
		return 0;

	/* Check that memtype did not change unexpectedly */
	if (follow_phys(vma, vma->vm_start, 0, &prot, &paddr)) {
		WARN_ON_ONCE(1);
		return -EINVAL;
	}
	check_memtypes_are_same(prot, paddr, vma->vm_end - vma->vm_start);

	return 0;
}

static pgprot_t __must_check fixup_pgprot_from_page_memtype(pgprot_t req_prot,
		enum page_cache_mode page_memtype, phys_addr_t paddr)
{
	if (page_memtype == PCM_UNKNOWN) {
		enum pte_mem_type req_memtype = get_pte_val_memory_type(pgprot_val(req_prot));
		WARN_ONCE(req_memtype != GEN_CACHE_MT,
			"%s [%d]: map phys. address 0x%llx, requested %s, but memtype_reserve was not called\n",
			current->comm, current->pid, paddr,
			pte_mem_type_name(req_memtype));

		return set_general_mt(req_prot);
	} else {
		return set_ram_memtype(req_prot, page_memtype);
	}
}

/*
 * track_pfn_remap is called when a _new_ pfn mapping is being established
 * by remap_pfn_range() for physical range indicated by pfn and size.
 */
int track_pfn_remap(struct vm_area_struct *vma, pgprot_t *prot,
		unsigned long pfn, unsigned long addr, unsigned long size)
{
	phys_addr_t paddr = PFN_PHYS(pfn), p;
	enum page_cache_mode page_memtype;

	/* For PCI memory just set external type */
	if (!region_is_ram_only(paddr, paddr + size)) {
		*prot = set_external_mt(*prot);
		return 0;
	}

	/* Track the whole chunk starting from paddr */
	if (!vma || (addr == vma->vm_start && size == (vma->vm_end - vma->vm_start))) {
		*prot = set_general_mt(*prot);

		check_memtypes_are_same(pgprot_val(*prot), paddr, size);

		if (vma)
			vma->vm_flags |= VM_MEMTYPE_TRACKED;
		return 0;
	}

	/* For anything smaller than the vma size set prot based on
	 * the lookup (the same as we do for track_pfn_insert()). */
	page_memtype = lookup_memtype(PFN_PHYS(pfn));

	/* Check memtype for the remaining pages */
	for (p = paddr + PAGE_SIZE; p < paddr + size; p += PAGE_SIZE) {
		if (WARN_ON_ONCE(page_memtype != lookup_memtype(p)))
			return -EINVAL;
	}

	*prot = fixup_pgprot_from_page_memtype(*prot, page_memtype, paddr);
	return 0;
}

/*
 * track_pfn_insert is called when a _new_ single pfn is established
 * by vm_insert_pfn().
 *
 * This does not cover vm_insert_page so if some bad driver decides
 * to use it on I/O memory we could get into trouble.
 */
void track_pfn_insert(struct vm_area_struct *vma, pgprot_t *prot, pfn_t pfn)
{
	phys_addr_t paddr = pfn_t_to_phys(pfn);

	if (region_is_ram_only(paddr, paddr + PAGE_SIZE)) {
		/* Previous calls to memtype_reserve() should have saved
		 * the needed mapping type in 'struct page', so that's
		 * where we take it from. */
		enum page_cache_mode page_memtype = lookup_memtype(paddr);

		*prot = fixup_pgprot_from_page_memtype(*prot, page_memtype, paddr);
	} else {
		*prot = set_external_mt(*prot);
	}
}

/*
 * untrack_pfn is called while unmapping a pfnmap for a region.
 * untrack can be called for a specific region indicated by pfn and size or
 * can be for the entire vma (in which case pfn, size are zero).
 */
void untrack_pfn(struct vm_area_struct *vma, unsigned long pfn, unsigned long size)
{
	phys_addr_t paddr = PFN_PHYS(pfn);
	unsigned long prot;

	/* PCI memory is always of external type, nothing to untrack here */
	if (!region_is_ram_only(paddr, paddr + PAGE_SIZE))
		return;

	/*
	 * Some drivers (like VFIO) may delay mapping after setting VM_PFNMAP.
	 * It should be safe to ignore this warning.
	 */
	if (!pfn && !size && follow_phys(vma, vma->vm_start, 0, &prot, &paddr))
		pr_warn_once("%s(): PID %d: failed to find mapping for address 0x%lx\n",
			__func__, current->pid, vma->vm_start);

	if (vma)
		vma->vm_flags &= ~VM_MEMTYPE_TRACKED;
}

/*
 * untrack_pfn_moved is called while mremapping a pfnmap for a new region.
 */
void untrack_pfn_moved(struct vm_area_struct *vma)
{
	vma->vm_flags &= ~VM_MEMTYPE_TRACKED;
}


int io_remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
		       unsigned long pfn, unsigned long size, pgprot_t prot)
{
	int is_ram = region_intersects(PFN_PHYS(pfn), size,
			IORESOURCE_SYSTEM_RAM, IORES_DESC_NONE);
	WARN_ONCE(is_ram != REGION_DISJOINT, "I/O remap attempted on ram region at 0x%lx - 0x%lx\n",
			addr, addr + size);
	return remap_pfn_range(vma, addr, pfn, size, pgprot_decrypted(prot));
}
EXPORT_SYMBOL(io_remap_pfn_range);


/*
 * /dev/mem mapping:
 *  if opened with O_SYNC, then use WC for RAM and UC for device memory;
 *  otherwise use WB.
 */
pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
		unsigned long size, pgprot_t vma_prot)
{
	int ram_intersect = region_intersects(PFN_PHYS(pfn), size,
			IORESOURCE_SYSTEM_RAM, IORES_DESC_NONE);

	switch (ram_intersect) {
	case REGION_INTERSECTS:
		if (file->f_flags & O_DSYNC)
			return pgprot_writecombine(vma_prot);
		break;
	case REGION_MIXED:
		WARN_ONCE(true, "[mem 0x%llx-0x%llx] is both RAM and device memory\n",
				PFN_PHYS(pfn), PFN_PHYS(pfn) + size - 1);
		fallthrough;
	case REGION_DISJOINT:
		if (file->f_flags & O_DSYNC)
			return pgprot_noncached(vma_prot);
		break;
	}

	return vma_prot;
}
EXPORT_SYMBOL(phys_mem_access_prot);


/*
 * Used to set accessed or dirty bits in the page table entries
 * on other architectures. On e2k, the accessed and dirty bits
 * are tracked by hardware. However, do_wp_page calls this function
 * to also make the pte writeable at the same time the dirty bit is
 * set. In that case we do actually need to write the PTE.
 *
 * This also fixes race in arch-independent ptep_set_access_flags()
 * (see commit 66dbd6e6
 *  "arm64: Implement ptep_set_access_flags() for hardware AF/DBM")
 */
int ptep_set_access_flags(struct vm_area_struct *vma,
			  unsigned long address, pte_t *ptep,
			  pte_t entry, int dirty)
{
	int changed = !pte_same(*ptep, entry);

	if (changed && dirty) {
		set_pte_at(vma->vm_mm, address, ptep, entry);
		flush_tlb_page(vma, address);
	}

	return changed;
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/*
 * Same as ptep_set_access_flags() but for PMD
 */
int pmdp_set_access_flags(struct vm_area_struct *vma,
			  unsigned long address, pmd_t *pmdp,
			  pmd_t entry, int dirty)
{
	int changed = !pmd_same(*pmdp, entry);

	VM_BUG_ON(address & ~HPAGE_PMD_MASK);

	if (changed && dirty) {
		set_pmd_at(vma->vm_mm, address, pmdp, entry);
		flush_pmd_tlb_range(vma, address, address + HPAGE_PMD_SIZE);
	}

	return changed;
}

/*
 * Same as ptep_set_access_flags() but for PUD
 */
int pudp_set_access_flags(struct vm_area_struct *vma,
			  unsigned long address, pud_t *pudp,
			  pud_t entry, int dirty)
{
	int changed = !pud_same(*pudp, entry);

	VM_BUG_ON(address & ~HPAGE_PUD_MASK);

	if (changed && dirty) {
		set_pud_at(vma->vm_mm, address, pudp, entry);
		flush_pud_tlb_range(vma, address, address + HPAGE_PUD_SIZE);
	}

	return changed;
}
#endif

#ifdef CONFIG_HAVE_ARCH_HUGE_VMAP
int pmd_set_huge(pmd_t *pmd, phys_addr_t phys, pgprot_t prot)
{
	BUG_ON(phys & ~PMD_MASK);
	BUG_ON(!pmd_none(*pmd));

	set_pmd(pmd, pmd_mkhuge(mk_pmd_phys(phys, prot)));

	return 1;
}

int pmd_clear_huge(pmd_t *pmd)
{
	if (!kernel_pmd_huge(*pmd))
		return 0;
	pmd_clear(pmd);
	return 1;
}

int pmd_free_pte_page(pmd_t *pmd, unsigned long addr)
{
	pte_t *pte = (pte_t *) pmd_page_vaddr(*pmd);
	pmd_clear(pmd);

	flush_tlb_kernel_range(addr, addr + PMD_SIZE);

	pte_free_kernel(&init_mm, pte);

	return 1;
}

int pud_set_huge(pud_t *pud, phys_addr_t phys, pgprot_t prot)
{
	/* Not supported (see arch_ioremap_pud_supported()) */
	BUG();
}

int pud_clear_huge(pud_t *pud)
{
	if (!kernel_pud_huge(*pud))
		return 0;
	pud_clear(pud);
	return 1;
}

int pud_free_pmd_page(pud_t *pud, unsigned long addr)
{
	/* Not supported (see arch_ioremap_pud_supported()) */
	BUG();
}

int p4d_free_pud_page(p4d_t *p4d, unsigned long addr)
{
	return 0;
}
#endif
