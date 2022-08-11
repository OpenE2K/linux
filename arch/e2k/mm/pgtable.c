#include <linux/bitops.h>
#include <linux/mm.h>
#include <linux/pfn_t.h>

#include <asm/pgalloc.h>
#include <asm/tlbflush.h>

/*
 * track_pfn_remap is called when a _new_ pfn mapping is being established
 * by remap_pfn_range() for physical range indicated by pfn and size.
 */
int track_pfn_remap(struct vm_area_struct *vma, pgprot_t *prot,
		unsigned long pfn, unsigned long addr, unsigned long size)
{
	pgprot_t old_prot = *prot;

	if (pfn_valid(pfn))
		*prot = set_general_mt(old_prot);
	else
		*prot = set_external_mt(old_prot);

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
	pgprot_t old_prot = *prot;

	if (likely(pfn_valid(pfn_t_to_pfn(pfn)))) {
		*prot = set_general_mt(old_prot);
	} else {
		VM_WARN_ON_ONCE(1);
		*prot = set_external_mt(old_prot);
	}
}

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
	pte_t *pte;

	//TODO remove this after upgrading - check is moved to arch-indep. code
	if (!pmd_present(*pmd))
		return 1;

	pte = (pte_t *) pmd_page_vaddr(*pmd);
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
