/*
 * Guest MMU caches flushing on KVM host
 *
 * Copyright 2016 Salavat S. Gilyazov (atic@mcst.ru)
 */
#ifndef _E2K_KVM_TLBFLUSH_H
#define _E2K_KVM_TLBFLUSH_H

#include <linux/mm.h>
#include <linux/kvm_host.h>

#include <asm/kvm/hypercall.h>

/*
 * Guest VM support on host
 * TLB flushing:
 *
 *  - flush_tlb_mm(mm) flushes the specified mm context TLB's
 *  - flush_tlb_page(vma, vmaddr) flushes one page
 *  - flush_tlb_range(mm, start, end) flushes a range of pages
 */

extern void mmu_pv_flush_tlb_range(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			const e2k_addr_t start, const e2k_addr_t end);
extern void mmu_pv_flush_cpu_root_pt_mm(struct kvm_vcpu *vcpu, gmm_struct_t *gmm);
extern void mmu_pv_flush_cpu_root_pt(struct kvm_vcpu *vcpu);

extern long kvm_pv_sync_and_flush_tlb(struct kvm_vcpu *vcpu,
			mmu_spt_flush_t __user *flush_user);
extern long kvm_pv_sync_addr_range(struct kvm_vcpu *vcpu,
			gva_t start_gva, gva_t end_gva);

extern void host_flush_shadow_pt_tlb_range(struct kvm_vcpu *vcpu,
			gva_t start, gva_t end, pgprot_t spte, int level);

extern void host_flush_shadow_pt_level_tlb(struct kvm *kvm, gmm_struct_t *gmm,
			gva_t gva, int level, pgprot_t new_spte, pgprot_t old_spte);

/*
 * Shadow PT TLB flushing (same as flush_tlb_*() but for gmm)
 * Real switching to a new gmm context (PID) will be a little later
 * while return from hypercall to the guest mode (host_guest_enter()),
 * and it is then that the PID will become active, but now it is still passive.
 */

extern void host_local_flush_tlb_range_and_pgtables(gmm_struct_t *gmm,
					unsigned long start, unsigned long end);
extern void host_flush_tlb_mm(gmm_struct_t *gmm);
extern void host_flush_tlb_page(gmm_struct_t *gmm, unsigned long addr);
extern void host_flush_tlb_range(gmm_struct_t *gmm,
				 unsigned long start, unsigned long end);
extern void host_flush_tlb_kernel_range(gmm_struct_t *gmm,
					unsigned long start, unsigned long end);
extern void host_flush_tlb_range_and_pgtables(gmm_struct_t *gmm,
					unsigned long start, unsigned long end);
extern void host_flush_pmd_tlb_range(gmm_struct_t *gmm,
				     unsigned long start, unsigned long end);

#endif /* _E2K_KVM_TLBFLUSH_H */
