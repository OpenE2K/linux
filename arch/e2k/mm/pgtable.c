#include <linux/bitops.h>
#include <linux/mm.h>

#include <asm/tlbflush.h>

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
void pmdp_splitting_flush(struct vm_area_struct *vma,
			  unsigned long address, pmd_t *pmdp)
{
	int set;
	VM_BUG_ON(address & ~HPAGE_PMD_MASK);
	set = !test_and_set_bit(_PAGE_SPLITTING_BIT, pmdp);
	if (set) {
		/* tlb flush only to serialize against gup-fast */
		flush_tlb_range(vma, address, address + HPAGE_PMD_SIZE);
	}
}
#endif
