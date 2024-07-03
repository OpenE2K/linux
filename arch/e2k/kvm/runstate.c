/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file manage VCPU run state in/out trap/interrupts
 */

#include <linux/kvm_host.h>
#include <linux/irqflags.h>
#include <linux/uaccess.h>
#include <asm/kvm/runstate.h>


/* guest VCPU run state should be updated in traps and interrupts */

void kvm_set_guest_runstate_in_user_trap(void)
{
	thread_info_t *ti = current_thread_info();
	struct kvm_vcpu *vcpu;
	struct pt_regs *regs = ti->pt_regs;

	if (likely(!test_ti_is_vcpu_thread(ti)))
		return;
	if (!regs || !kvm_test_intc_emul_flag(regs))
		return;
	vcpu = ti->is_vcpu;
	BUG_ON(vcpu == NULL);
	BUG_ON(!psr_and_upsr_irqs_disabled());
	WARN_ON(kvm_get_guest_vcpu_runstate(vcpu) != RUNSTATE_in_intercept);
	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_trap);
}
void kvm_set_guest_runstate_out_user_trap(void)
{
	thread_info_t *ti = current_thread_info();
	struct kvm_vcpu *vcpu;
	struct pt_regs *regs = ti->pt_regs;

	if (likely(!test_ti_is_vcpu_thread(ti)))
		return;
	if (!regs || !kvm_test_intc_emul_flag(regs))
		return;
	vcpu = ti->is_vcpu;
	if (vcpu == NULL)
		return;
	BUG_ON(!psr_and_upsr_irqs_disabled());
	WARN_ON(kvm_get_guest_vcpu_runstate(vcpu) != RUNSTATE_in_trap);
	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_intercept);
}
int kvm_set_guest_runstate_in_kernel_trap(void)
{
	thread_info_t *ti = current_thread_info();
	struct kvm_vcpu *vcpu;
	struct pt_regs *regs = ti->pt_regs;
	int cur_runstate;

	if (likely(!test_ti_is_vcpu_thread(ti)))
		return -1;
	if (!regs || !kvm_test_intc_emul_flag(regs))
		return -1;
	vcpu = ti->is_vcpu;
	if (vcpu == NULL)
		return -1;
	BUG_ON(!psr_and_upsr_irqs_disabled());
	cur_runstate = kvm_get_guest_vcpu_runstate(vcpu);
	if (cur_runstate == RUNSTATE_offline)
		/* VCPU is not yet started */
		return -1;
	WARN_ON(cur_runstate == RUNSTATE_running &&
		!test_ti_thread_flag(ti, TIF_GENERIC_HYPERCALL));
	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_trap);
	return cur_runstate;
}
void kvm_set_guest_runstate_out_kernel_trap(int saved_runstate)
{
	thread_info_t *ti = current_thread_info();
	struct kvm_vcpu *vcpu;
	struct pt_regs *regs = ti->pt_regs;
	int cur_runstate;

	if (likely(!test_ti_is_vcpu_thread(ti)))
		return;
	if (!regs || !kvm_test_intc_emul_flag(regs))
		return;
	vcpu = ti->is_vcpu;
	if (vcpu == NULL)
		return;
	BUG_ON(!psr_and_upsr_irqs_disabled());
	cur_runstate = kvm_get_guest_vcpu_runstate(vcpu);
	if (cur_runstate == RUNSTATE_offline)
		/* VCPU is not yet started */
		return;
	WARN_ON(cur_runstate != RUNSTATE_in_trap);
	kvm_do_update_guest_vcpu_current_runstate(vcpu, saved_runstate);
}
