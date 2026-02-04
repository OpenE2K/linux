/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/kvm_host.h>
#include <asm/machdep.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/hw_prefetchers.h>

#include "iset-kvm.h"


void save_kvm_context_v7(struct kvm_vcpu_arch *vcpu)
{
	kvm_save_host_context(arch_to_vcpu(vcpu), E2K_ISET_V7);
}

void restore_kvm_context_v7(const struct kvm_vcpu_arch *vcpu)
{
	kvm_restore_host_context(arch_to_vcpu(vcpu), E2K_ISET_V7);
}

e2k_tlb_pref_ctrl_t tlb_prefetcher_save(void)
{
	e2k_tlb_pref_ctrl_t tlb_pref_ctrl;

	if (!cpu_has(CPU_FEAT_HW_PREFETCHER_TLB))
		return (e2k_tlb_pref_ctrl_t) { .word = 0 };

	AW(tlb_pref_ctrl) = NATIVE_GET_MMUREG(dtlb_pref_ctrl);
	if (!tlb_pref_ctrl.disable) {
		unsigned long flags;

		e2k_tlb_pref_ctrl_t tlb_pref_ctrl_nopref = tlb_pref_ctrl;
		tlb_pref_ctrl_nopref.disable = 1;
		raw_all_irq_save(flags);
		NATIVE_SET_MMUREG(dtlb_pref_ctrl, AW(tlb_pref_ctrl_nopref));
		raw_all_irq_restore(flags);
	}

	return tlb_pref_ctrl;
}

void tlb_prefetcher_restore(e2k_tlb_pref_ctrl_t tlb_pref_ctrl)
{
	unsigned long flags;

	if (!cpu_has(CPU_FEAT_HW_PREFETCHER_TLB) || tlb_pref_ctrl.disable)
		return;

	raw_all_irq_save(flags);
	NATIVE_SET_MMUREG(dtlb_pref_ctrl, AW(tlb_pref_ctrl));
	raw_all_irq_restore(flags);
}

e2k_l1_pref_ctrl_t l1_prefetcher_save(void)
{
	e2k_l1_pref_ctrl_t l1_pref_ctrl;

	if (!cpu_has(CPU_FEAT_HW_PREFETCHER_L1))
		return (e2k_l1_pref_ctrl_t) { .word = 0 };

	AW(l1_pref_ctrl) = NATIVE_GET_MMUREG(l1_pref_ctrl);
	if (!l1_pref_ctrl.l1pref_str_dsbl || !l1_pref_ctrl.l1pref_spp_dsbl) {
		unsigned long flags;

		e2k_l1_pref_ctrl_t l1_pref_ctrl_nopref = l1_pref_ctrl;
		l1_pref_ctrl_nopref.l1pref_str_dsbl = 1;
		l1_pref_ctrl_nopref.l1pref_spp_dsbl = 1;
		raw_all_irq_save(flags);
		NATIVE_SET_MMUREG(l1_pref_ctrl, AW(l1_pref_ctrl_nopref));
		raw_all_irq_restore(flags);
	}

	return l1_pref_ctrl;
}

void l1_prefetcher_restore(e2k_l1_pref_ctrl_t l1_pref_ctrl)
{
	unsigned long flags;

	if (!cpu_has(CPU_FEAT_HW_PREFETCHER_L1) ||
			l1_pref_ctrl.l1pref_str_dsbl && l1_pref_ctrl.l1pref_spp_dsbl)
		return;

	raw_all_irq_save(flags);
	NATIVE_SET_MMUREG(l1_pref_ctrl, AW(l1_pref_ctrl));
	raw_all_irq_restore(flags);
}
