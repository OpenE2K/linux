/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/* GLAUNCH and saving/restoring code that surround it
 * are put here in a separate file because they require
 * special compilation flags. */

#include <linux/kvm_host.h>

#include <asm/cpu_regs.h>
#include <asm/e2k_api.h>
#include <asm/kvm/switch.h>
#include <asm/sections.h>

/*
 * This function is written this way (not used e2k_ctpr_t struct)
 * due to lcc troubles whith check_stack (the same as __interrupt)
 * compilation mode
 */
noinline  __interrupt void launch_hv_vcpu(struct kvm_vcpu_arch *vcpu)
{
	struct thread_info *ti = current_thread_info();
	struct kvm_intc_cpu_context *intc_ctxt = &vcpu->intc_ctxt;
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->sw_ctxt;

	e2k_ctpr_t ctpr1 = intc_ctxt->ctpr1;
	e2k_ctpr_t ctpr2 = intc_ctxt->ctpr2;
	e2k_ctpr_t ctpr3 = intc_ctxt->ctpr3;
	u64 lsr = intc_ctxt->lsr, lsr1 = intc_ctxt->lsr1,
	    ilcr = intc_ctxt->ilcr, ilcr1 = intc_ctxt->ilcr1;

	if (cpu_has(CPU_HWBUG_VIRT_PUSD_PSL) &&
			unlikely(vcpu_usd_p(arch_to_vcpu(vcpu), sw_ctxt->usd))) {
		E2K_KVM_BUG_ON(!vcpu_usd_psl(arch_to_vcpu(vcpu), sw_ctxt->usd));
		sw_ctxt->usd.Psl--;
	}

	/*
	 * Here kernel is on guest context including data stack
	 * so nothing complex: calls, prints, etc
	 */

	__guest_enter(ti, vcpu, FULL_CONTEXT_SWITCH | USD_CONTEXT_SWITCH |
		      DEBUG_REGS_SWITCH);

	/* CPU_HWBUG_BRANCH_ACTIVATES_CTPR: avoid rbranch, ibranch and ibranchd
	 * instructions between %ctpr[.hi] restoring and glaunch instruction. */
	RWSH_CTPR_NOIRQ(ctpr2, ctpr2);
	/* These registers must be restored after ctpr2 */
	native_set_aau_aaldis_aaldas(ti->aalda, &sw_ctxt->aau_context);
	NATIVE_RESTORE_AAU_MASK_REGS(sw_ctxt->aau_context.aaldm,
				     sw_ctxt->aau_context.aaldv, sw_ctxt->aasr);
	/* issue GLAUNCH instruction.
	 * This macro does not restore %ctpr2 register because of ordering
	 * with AAU restore. */
	E2K_GLAUNCH(LO(ctpr1), HI(ctpr1), LO(ctpr2), HI(ctpr2),
		    LO(ctpr3), HI(ctpr3), lsr, lsr1, ilcr, ilcr1);

	intc_ctxt->ctpr1 = ctpr1;
	/* Make sure that the first kernel memory access is store.
	 * This is needed to flush SLT before trying to load anything. */
	barrier();
	intc_ctxt->ctpr2 = ctpr2;
	intc_ctxt->ctpr3 = ctpr3;
	intc_ctxt->lsr = lsr;
	intc_ctxt->lsr1 = lsr1;
	intc_ctxt->ilcr = ilcr;
	intc_ctxt->ilcr1 = ilcr1;

	__guest_exit(ti, vcpu, FULL_CONTEXT_SWITCH | USD_CONTEXT_SWITCH |
		     DEBUG_REGS_SWITCH);
}
