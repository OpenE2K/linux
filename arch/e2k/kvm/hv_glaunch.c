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

noinline __interrupt
void launch_hv_vcpu(struct kvm_vcpu_arch *vcpu)
{
	struct thread_info *ti = current_thread_info();
	struct kvm_intc_cpu_context *intc_ctxt = &vcpu->intc_ctxt;
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->sw_ctxt;
	u64 ctpr1 = AW(intc_ctxt->ctpr1), ctpr1_hi = AW(intc_ctxt->ctpr1_hi),
	    ctpr2 = AW(intc_ctxt->ctpr2), ctpr2_hi = AW(intc_ctxt->ctpr2_hi),
	    ctpr3 = AW(intc_ctxt->ctpr3), ctpr3_hi = AW(intc_ctxt->ctpr3_hi),
	    lsr = intc_ctxt->lsr, lsr1 = intc_ctxt->lsr1,
	    ilcr = intc_ctxt->ilcr, ilcr1 = intc_ctxt->ilcr1;

	if (cpu_has(CPU_HWBUG_VIRT_PUSD_PSL)) {
		e2k_pusd_lo_t pusd_lo;

		AW(pusd_lo) = AW(sw_ctxt->usd_lo);
		if (unlikely(pusd_lo.PUSD_lo_p)) {
			E2K_KVM_BUG_ON(!pusd_lo.PUSD_lo_psl);
			pusd_lo.PUSD_lo_psl -= 1;
			AW(sw_ctxt->usd_lo) = AW(pusd_lo);
		}
	}

	/*
	 * Here kernel is on guest context including data stack
	 * so nothing complex: calls, prints, etc
	 */

	__guest_enter(ti, vcpu, FULL_CONTEXT_SWITCH | USD_CONTEXT_SWITCH |
				DEBUG_REGS_SWITCH);

	NATIVE_WRITE_CTPR2_REG_VALUE(ctpr2);
	NATIVE_WRITE_CTPR2_HI_REG_VALUE(ctpr2_hi);
#ifdef CONFIG_USE_AAU
	/* These registers must be restored after ctpr2 */
	native_set_aau_aaldis_aaldas(ti->aalda, &sw_ctxt->aau_context);
	NATIVE_RESTORE_AAU_MASK_REGS(sw_ctxt->aau_context.aaldm,
			sw_ctxt->aau_context.aaldv, sw_ctxt->aasr);
#endif
	/* issue GLAUNCH instruction.
	 * This macro does not restore %ctpr2 register because of ordering
	 * with AAU restore. */
	E2K_GLAUNCH(ctpr1, ctpr1_hi, ctpr2, ctpr2_hi, ctpr3, ctpr3_hi, lsr, lsr1, ilcr, ilcr1);

	AW(intc_ctxt->ctpr1) = ctpr1;
	/* Make sure that the first kernel memory access is store.
	 * This is needed to flush SLT before trying to load anything. */
	barrier();
	AW(intc_ctxt->ctpr2) = ctpr2;
	AW(intc_ctxt->ctpr3) = ctpr3;
	AW(intc_ctxt->ctpr1_hi) = ctpr1_hi;
	AW(intc_ctxt->ctpr2_hi) = ctpr2_hi;
	AW(intc_ctxt->ctpr3_hi) = ctpr3_hi;
	intc_ctxt->lsr = lsr;
	intc_ctxt->lsr1 = lsr1;
	intc_ctxt->ilcr = ilcr;
	intc_ctxt->ilcr1 = ilcr1;

	__guest_exit(ti, vcpu, FULL_CONTEXT_SWITCH | USD_CONTEXT_SWITCH |
				DEBUG_REGS_SWITCH);
}

