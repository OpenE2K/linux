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


static void launch_hv_vcpu_nostack(struct kvm_vcpu *vcpu);
static void launch_hv_vcpu_exit(struct kvm_vcpu *vcpu);

/*
 * This function is written this way (not used e2k_ctpr_t struct)
 * due to lcc troubles whith check_stack (the same as __interrupt)
 * compilation mode
 */
noinline void launch_hv_vcpu(struct kvm_vcpu_arch *vcpu_arch)
{
	struct kvm_vcpu *vcpu = arch_to_vcpu(vcpu_arch);
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu_arch->sw_ctxt;

	if (cpu_has(CPU_HWBUG_VIRT_PUSD_PSL) && unlikely(vcpu_usd_p(vcpu, sw_ctxt->usd))) {
		if (!WARN_ON_ONCE(!vcpu_usd_psl(vcpu, sw_ctxt->usd)))
			sw_ctxt->usd.Psl--;
	}

	__guest_enter(current_thread_info(), vcpu_arch,
		      FULL_CONTEXT_SWITCH | DONT_SAVE_KGREGS_SWITCH | DEBUG_REGS_SWITCH);

	E2K_JUMP_WITH_ARGUMENTS(launch_hv_vcpu_nostack, 1, vcpu);
}

/*
 * This executes on guest context including data stack so
 * must not use anything complex: calls, prints, etc.
 *
 * To reduce compiler incompatibilities this should execute
 * only the part that actually does not have access to
 * kernel's data stack.
 */
static noinline __interrupt void launch_hv_vcpu_nostack(struct kvm_vcpu *vcpu)
{
	struct kvm_intc_cpu_context *intc_ctxt = &vcpu->arch.intc_ctxt;
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;

	/* Switch data stack after all function calls */
	kvm_guest_enter_stack_regs(sw_ctxt, false);

	/* Cannot use current and cpu_has() after this */
	kvm_switch_gregs(sw_ctxt, true);

	E2K_GLAUNCH(intc_ctxt, sw_ctxt);

	/* Can use current and cpu_has() after this */
	kvm_switch_gregs(sw_ctxt, false);

	/* Switch data stack before all function calls */
	kvm_guest_exit_stack_regs(sw_ctxt, &vcpu->arch.hw_ctxt, false);

	E2K_JUMP_WITH_ARGUMENTS(launch_hv_vcpu_exit, 1, vcpu);
}

static noinline void launch_hv_vcpu_exit(struct kvm_vcpu *vcpu)
{
	__guest_exit(current_thread_info(), &vcpu->arch,
		     FULL_CONTEXT_SWITCH | DONT_SAVE_KGREGS_SWITCH | DEBUG_REGS_SWITCH);
}
