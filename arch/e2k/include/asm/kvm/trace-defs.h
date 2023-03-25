#ifndef _E2K_KVM_TRACE_DEFS_H_
#define _E2K_KVM_TRACE_DEFS_H_

#include <linux/types.h>

#include <asm/mmu_types.h>
#include <asm/pgtable_def.h>
#include <asm/kvm/mmu.h>

#ifdef	CONFIG_VIRTUALIZATION

static inline void
trace_kvm_get_va_translation(struct kvm_vcpu *vcpu, e2k_addr_t address,
	pgdval_t *pgd, pudval_t *pud, pmdval_t *pmd, pteval_t *pte, int *pt_level)
{
	kvm_get_spt_translation(vcpu, address, pgd, pud, pmd, pte, pt_level);
}

static inline unsigned long
trace_kvm_get_gva_to_hva(struct kvm_vcpu *vcpu, gva_t gva)
{
	return kvm_get_gva_to_hva(vcpu, gva);
}

#endif	/* CONFIG_VIRTUALIZATION */

#endif /* _E2K_KVM_TRACE_DEFS_H_ */
