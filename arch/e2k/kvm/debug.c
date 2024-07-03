/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


/*
 * CPU virtualization
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
#include <asm/kvm/process.h>
#include <asm/kvm/stacks.h>
#include <asm/kvm/gregs.h>
#include "cpu.h"
#include "process.h"
#include "gaccess.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

static inline struct pt_regs *
find_intc_emul_regs(const pt_regs_t *pt_regs)
{
	while (pt_regs) {
		CHECK_PT_REGS_LOOP(pt_regs);
		if (kvm_test_intc_emul_flag((pt_regs_t *)pt_regs))
			break;
		pt_regs = pt_regs->next;
	};
	return (struct pt_regs *) pt_regs;
}

static bool
get_vcpu_stack_regs_in_hypercall(struct kvm_vcpu *vcpu, stack_regs_t *const regs)
{
	guest_hw_stack_t *guest_stacks;

	guest_stacks = &vcpu->arch.guest_stacks;
	if (!guest_stacks->valid) {
		/* nothing active guest process stacks */
		pr_alert("%s(): guest stacks is not valid\n", __func__);
		return false;
	}

	regs->crs = guest_stacks->crs;
	regs->pcsp_hi = guest_stacks->stacks.pcsp_hi;
	regs->pcsp_lo = guest_stacks->stacks.pcsp_lo;
	regs->psp_hi = guest_stacks->stacks.psp_hi;
	regs->psp_lo = guest_stacks->stacks.psp_lo;
	regs->base_psp_stack = (void *)regs->psp_lo.PSP_lo_base;
	regs->orig_base_psp_stack_u = (u64)regs->base_psp_stack;
	regs->orig_base_psp_stack_k = (u64)regs->base_psp_stack;
	regs->size_psp_stack = regs->psp_hi.PSP_hi_ind;

	if (regs->show_trap_regs) {
		int i;

		for (i = 0; i < MAX_USER_TRAPS; i++) {
			regs->trap[i].valid = 0;
		}
	}

	pr_alert("%s(): guest in hypercall and its stacks is valid\n", __func__);
	return true;
}

static bool
get_vcpu_stack_regs_in_intc(struct kvm_vcpu *vcpu, const pt_regs_t *intc_regs,
			    stack_regs_t *const regs)
{

	regs->crs = intc_regs->crs;
	regs->pcsp_lo = intc_regs->stacks.pcsp_lo;
	regs->pcsp_hi = intc_regs->stacks.pcsp_hi;
	regs->psp_lo = intc_regs->stacks.psp_lo;
	regs->psp_hi = intc_regs->stacks.psp_hi;

	regs->base_psp_stack = (void *)regs->psp_lo.PSP_lo_base;
	regs->orig_base_psp_stack_u = (u64)regs->base_psp_stack;
	regs->orig_base_psp_stack_k = (u64)regs->base_psp_stack;
	regs->size_psp_stack = regs->psp_hi.PSP_hi_ind;

	if (regs->show_trap_regs) {
		int i, trap_no = 0;

		if (from_trap(intc_regs)) {
			fill_trap_stack_regs(intc_regs, &regs->trap[trap_no]);
			trap_no++;
		}
		for (i = trap_no; i < MAX_USER_TRAPS; i++) {
			regs->trap[i].valid = 0;
		}
	}
	if (from_syscall(intc_regs)) {
		pr_alert("%s(): guest in intercept on system call\n", __func__);
	} else if (from_trap(intc_regs)) {
		pr_alert("%s(): guest in intercept on trap\n", __func__);
	} else {
		pr_alert("%s(): guest in intercept on unknown reason\n", __func__);
	}
	return true;
}

static void copy_vcpu_stack_regs(struct kvm_vcpu *vcpu, const pt_regs_t *intc_regs,
				stack_regs_t *const regs, struct task_struct *task)
{
	u64	cr_ind;
	int	i;
	u64	psp_ind;
	u64	sz;
	void	*dst;
	void	*src;
	int	ret;

	regs->valid = 0;

	if (vcpu == NULL)
		return;

	if (vcpu->arch.sw_ctxt.in_hypercall) {
		if (!get_vcpu_stack_regs_in_hypercall(vcpu, regs))
			return;
	} else if (intc_regs != NULL) {
		if (!get_vcpu_stack_regs_in_intc(vcpu, intc_regs, regs))
			return;
	} else {
		E2K_KVM_BUG_ON(true);
	}

#ifdef CONFIG_DATA_STACK_WINDOW
	regs->base_k_data_stack = NULL;
	for (i = 0; i < MAX_PT_REGS_SHOWN; i++) {
		regs->pt_regs[i].valid = 0;
	}
#endif

#ifdef CONFIG_GREGS_CONTEXT
	get_all_user_glob_regs(&regs->gregs);
	regs->gregs_valid = 1;
#endif

	/*
	 * Copy a part (or all) of the chain stack.
	 * If it fails then leave regs->valid set to 0.
	 */
	regs->base_chain_stack = (u64 *)regs->base_chain_stack;
	if (!regs->base_chain_stack)
		goto out;

	cr_ind = regs->pcsp_hi.PCSP_hi_ind;
	regs->size_chain_stack = min_t(u64, cr_ind, VIRT_SIZE_CHAIN_STACK);
	sz = regs->size_chain_stack;

	dst = regs->base_chain_stack;
	src = (void *)regs->pcsp_lo.PCSP_lo_base + cr_ind - sz;

	/* Remember original stack address. */
	regs->orig_base_chain_stack_u = (u64)src;
	regs->orig_base_chain_stack_k = (u64)src;

	/* FIXME: only guest system stacks can be correctly copied, */
	/* it need implement guest user stacks case */
	ret = kvm_vcpu_read_guest_system(vcpu, (gva_t)src, dst, sz);
	if (ret != 0) {
		pr_err("%s(): could not copy guest chain stacks from guest "
			"virt address %px, size 0x%llx\n",
			__func__, src, sz);
		goto out;
	}

	/*
	 * Copy a part (or all) of the procedure stack.
	 * Do _not_ set regs->valid to 0 if it fails
	 * (we can still print stack albeit without register windows)
	 */
	psp_ind = regs->psp_hi.PSP_hi_ind;
	regs->base_psp_stack = (u64 *) regs->psp_stack_cache;
	if (!regs->base_psp_stack)
		goto finish_copying_psp_stack;

	regs->size_psp_stack = min_t(u64, psp_ind, SIZE_PSP_STACK);

	sz = regs->size_psp_stack;

	dst = regs->base_psp_stack;

	src = (void *)regs->psp_lo.PSP_lo_base + psp_ind - sz;

	/* FIXME: only guest system stacks can be correctly copied, */
	/* it need implement guest user stacks case */
	ret = kvm_vcpu_read_guest_system(vcpu, (gva_t)src, dst, sz);
	if (ret != 0) {
		pr_err("%s(): could not copy guest procedure stacks from guest "
			"virt address %px, size 0x%llx\n",
			__func__, src, sz);
		regs->base_psp_stack = NULL;
		goto finish_copying_psp_stack;
	}

finish_copying_psp_stack:

	regs->task = task;
	regs->ignore_banner = true;
	regs->valid = 1;
	return;
out:
	regs->valid = 0;
	return;
}

static void vcpu_stack_banner(struct kvm_vcpu *vcpu, gthread_info_t *gti)
{
	gmm_struct_t *gmm = NULL;

	if (gti != NULL)
		gmm = gti->gmm;

	pr_info("VCPU #%d GPID %d guest %s Thread\n",
		vcpu->vcpu_id, vcpu->kvm->arch.vmid.nr,
		(gmm == NULL) ? "Kernel" : "User");

	if (gti != NULL) {
		pr_alert("GUEST PROCESS: PID on host: %d , flags: 0x%lx\n",
			gti->gpid->nid.nr, gti->flags);
	}
}

void kvm_dump_guest_stack(struct task_struct *task,
		stack_regs_t *const stack_regs, bool show_reg_window)
{
	thread_info_t *ti = task_thread_info(task);
	struct kvm_vcpu *vcpu;
	const pt_regs_t *intc_regs;

	vcpu = (ti->vcpu) ? ti->vcpu : ti->is_vcpu;
	if (likely(vcpu == NULL))
		/* guest process already completed */
		return;

	intc_regs = find_intc_emul_regs(ti->pt_regs);
	if (unlikely(!(intc_regs || vcpu->arch.sw_ctxt.in_hypercall)))
		/* guest is not running by this process */
		return;

	copy_vcpu_stack_regs(vcpu, intc_regs, stack_regs, task);
	if (!stack_regs->valid) {
		return;
	}

	if (stack_regs->ignore_banner)
		vcpu_stack_banner(vcpu, ti->gthread_info);
	print_chain_stack(stack_regs, show_reg_window);
}
