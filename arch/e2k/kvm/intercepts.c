/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


/*
 * CPU hardware virtualized support
 * Interceptions handling
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/uaccess.h>
#include <asm/cpu_regs.h>
#include <asm/trap_table.h>
#include <asm/traps.h>
#include <asm/mmu_regs_types.h>
#include <asm/system.h>
#include <asm/kvm/cpu_hv_regs_types.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/mmu_hv_regs_types.h>
#include <asm/kvm/mmu_hv_regs_access.h>
#include <asm/kvm/process.h>
#include <asm/kvm/runstate.h>
#include <asm/kvm/switch.h>
#include <asm/kvm/guest/tlb_regs_types.h>
#include <asm/kvm/mmu_regs_access.h>
#include <asm/kvm/async_pf.h>
#include <asm/kvm/trace_kvm.h>
#include <asm/kvm/trace_kvm_hv.h>
#include <asm/kvm/gregs.h>

#include "cpu_defs.h"
#include "mmu_defs.h"
#include "cpu.h"
#include "mmu.h"
#include "process.h"
#include "io.h"
#include "intercepts.h"

#undef	DEBUG_LWISH_TIRs_MODE
#undef	DebugLWTIRs
#define	DEBUG_LWISH_TIRs_MODE	0	/* intercept on last wish TIRs */
					/* debugging */
#define	DebugLWTIRs(fmt, args...)					\
({									\
	if (DEBUG_LWISH_TIRs_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_INTC_VM_EXIT_MODE
#undef	DebugVMEX
#define	DEBUG_INTC_VM_EXIT_MODE	0	/* VM exit intercept debug mode */
#define	DebugVMEX(fmt, args...)						\
({									\
	if (DEBUG_INTC_VM_EXIT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

int do_hret_last_wish_intc(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	struct trap_pt_regs *trap = regs->trap;
	unsigned long flags;
	bool was_trap_wish = false;

	if (DEBUG_LWISH_TIRs_MODE &&
			trap->nr_TIRs >= 0 && !AW(trap->TIRs[0].TIR_hi)) {
		pr_err("%s(): empty TIR[0] in HRET last wish intercept\n",
			__func__);
		print_all_TIRs(trap->TIRs, trap->nr_TIRs);
	}

	if (vcpu->arch.vm_exit_wish) {
		DebugVMEX("intercept to do VM exit, exit reason %d\n",
			vcpu->arch.exit_reason);
		vcpu->arch.vm_exit_wish = false;
		return 1;
	}

	if (vcpu->arch.trap_wish) {
		DebugVMEX("intercept to inject VM traps\n");
		regs->traps_to_guest |= vcpu->arch.trap_mask_wish;
		kvm_clear_guest_traps_wish(vcpu);
		vcpu->arch.trap_mask_wish = 0;
		was_trap_wish = true;
	}

	if (!vcpu->arch.virq_wish) {
		if (!was_trap_wish) {
			pr_err("%s(): unknown reason for HRET last wish "
				"intercept\n",
				__func__);
		}
		return 0;
	}

	raw_spin_lock_irqsave(&vcpu->kvm->arch.virq_lock, flags);

	if (!kvm_has_virqs_to_guest(vcpu)) {
		/* nothing pending VIRQs to pass to guest */
		raw_spin_unlock_irqrestore(&vcpu->kvm->arch.virq_lock, flags);
		return 0;
	}

	E2K_KVM_BUG_ON(!kvm_test_pending_virqs(vcpu));

	raw_spin_unlock_irqrestore(&vcpu->kvm->arch.virq_lock, flags);

	/* trap is only to inject interrupt to guest */
	if (vcpu->arch.is_hv) {
		if (!(vcpu->arch.intc_ctxt.exceptions & exc_interrupt_mask)) {
			kvm_need_create_vcpu_exception(vcpu,
						       exc_interrupt_mask);
		}
		vcpu->arch.virq_wish = false;
	} else if (vcpu->arch.is_pv) {
		kvm_inject_interrupt(vcpu, regs);
		vcpu->arch.virq_wish = false;
	} else {
		/* guest traps are handled by host at first */
		/* and host only pass guest traps to guest */
		kvm_need_create_vcpu_exception(vcpu, exc_last_wish_mask);
	}
	return 0;
}

