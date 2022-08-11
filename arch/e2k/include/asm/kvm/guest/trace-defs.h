#ifndef _E2K_KVM_GUEST_TRACE_DEFS_H_
#define _E2K_KVM_GUEST_TRACE_DEFS_H_

#include <linux/types.h>

#include <asm/mmu_types.h>
#include <asm/pgtable_def.h>
#include <asm/kvm/hypercall.h>

static inline void
trace_kvm_get_gva_spt_translation(e2k_addr_t address,
	pgdval_t *pgd, pudval_t *pud, pmdval_t *pmd, pteval_t *pte, int *pt_level)
{
	mmu_spt_trans_t spt_trans;
	int ret;

	ret = HYPERVISOR_get_spt_translation(address, &spt_trans);
	if (unlikely(ret != 0)) {
		pr_err("%s() : host could not get guest address 0x%lx "
			"translation at SPTs, error %d\n",
			__func__, address, ret);
		*pgd = -1;
		*pt_level = E2K_PGD_LEVEL_NUM;
		return;
	}
	*pt_level = spt_trans.pt_levels;
	if (*pt_level <= E2K_PGD_LEVEL_NUM) {
		*pgd = spt_trans.pgd;
	}
	if (*pt_level <= E2K_PUD_LEVEL_NUM) {
		*pud = spt_trans.pud;
	}
	if (*pt_level <= E2K_PMD_LEVEL_NUM) {
		*pmd = spt_trans.pmd;
	}
	if (*pt_level <= E2K_PTE_LEVEL_NUM) {
		*pte = spt_trans.pte;
	}
}

#endif /* _E2K_KVM_GUEST_TRACE_DEFS_H_ */
