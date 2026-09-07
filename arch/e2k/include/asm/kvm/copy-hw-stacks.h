/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM guest kernel processes support
 */

#ifndef _E2K_KVM_COPY_HW_STACKS_H
#define _E2K_KVM_COPY_HW_STACKS_H

#include <linux/kvm_host.h>

#include <asm/cpu_regs.h>
#include <asm/regs_state.h>
#include <asm/kvm/vcpu-descr-regs.h>
#include <asm/kvm/thread_info.h>
#include <asm/kvm/mmu.h>
#include <asm/kvm/page.h>
#include <asm/kvm/switch.h>

#undef	DEBUG_KVM_GUEST_STACKS_MODE
#undef	DebugGUST
#define	DEBUG_KVM_GUEST_STACKS_MODE	0	/* guest user stacks */
						/* copy debug */
#define	DebugGUST(fmt, args...)						\
({									\
	if (DEBUG_KVM_GUEST_STACKS_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#ifdef	CONFIG_KVM_HOST_KERNEL

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static inline void
prepare_pv_vcpu_inject_stacks(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	e2k_stacks_t *stacks, *g_stacks;
	gthread_info_t *gti = pv_vcpu_get_gti(vcpu);

	if (regs->g_stacks_valid) {
		/* already prepared */
		return;
	}

	/* all stacks at empty state, because of guest user recursion */
	/* of trap/system calls can not be */
	g_stacks = &regs->g_stacks;
	g_stacks->usd = gti->g_usd;
	g_stacks->top = gti->g_sbr.base;
	g_stacks->psp = gti->g_psp;
	g_stacks->pcsp = gti->g_pcsp;

	/* pshtp & pcshtp from guest user stack real state upon trap/syscall */
	stacks = &regs->stacks;
	g_stacks->pshtp = stacks->pshtp;
	g_stacks->pcshtp = stacks->pcshtp;

	regs->g_stacks_valid = true;
	regs->g_stacks_active = false;
	regs->need_inject = false;
}

#undef	EMULATE_EMPTY_CHAIN_STACK	/* only to debug */

#ifdef	EMULATE_EMPTY_CHAIN_STACK
static __always_inline void
pv_vcpu_emulate_empty_chain_staks(struct kvm_vcpu *vcpu, pt_regs_t *regs,
				  e2k_stacks_t *stacks, bool guest_user)
{
	e2k_pcshtp_t pcshtp;
	unsigned long flags;
	e2k_pcsp_t g_pcsp, k_pcsp;
	e2k_mem_crs_t __user *g_cframe;
	e2k_mem_crs_t *k_crs;
	int ret;

	pcshtp = stacks->pcshtp;
	if (!(guest_user && pcshtp <= 0x40))
		return;

	g_pcsp = regs->stacks.pcsp;
	g_pcsp = regs->stacks.pcsp;

	raw_all_irq_save(flags);
	NATIVE_FLUSHC;
	k_pcsp = native_read_PCSP_reg();
	BUG_ON(k_pcsp.ind != pcshtp);

	k_crs = (e2k_mem_crs_t *) k_pcsp.base;
	g_cframe = (e2k_mem_crs_t __user *) (g_pcsp_lo).base + g_pcsp.ind - pcshtp;
	ret = user_hw_stack_frames_copy(g_cframe, k_crs, pcshtp, regs,
					k_pcsp.ind, true);
	if (ret) {
		pr_err("%s(): copy to user stack failed\n", __func__);
		BUG_ON(true);
	}
	k_pcsp.ind -= pcshtp;
	pcshtp = 0;
	regs->stacks.pcshtp = pcshtp;
	stacks->pcshtp = pcshtp;
	native_write_PCSP_reg(k_pcsp);
	raw_all_irq_restore(flags);
}
#else /* !EMULATE_EMPTY_CHAIN_STACK */
static __always_inline void
pv_vcpu_emulate_empty_chain_staks(struct kvm_vcpu *vcpu, pt_regs_t *regs,
				  e2k_stacks_t *stacks, bool guest_user)
{
}
#endif /* EMULATE_EMPTY_CHAIN_STACK */

/**
 * pv_vcpu_user_hw_stacks_copy - check size of user hardware stacks that have
 *				 been SPILLed to kernel back to guest space
 * @regs - saved guest user stack registers
 * @cur_window_q - size of current window in procedure stack
 *
 * All guest user's stacks part were already copied to guest kernel stacks,
 * so it need only check that it was full size and nothing to copy here
 */
static __always_inline int
pv_vcpu_user_hw_stacks_copy(struct kvm_vcpu *vcpu, pt_regs_t *regs, e2k_stacks_t *stacks,
			    u64 cur_window_q, bool guest_user)
{
	e2k_psp_t g_psp = stacks->psp;
	e2k_pcsp_t g_pcsp = stacks->pcsp;
	s64 g_pshtp_size, g_pcshtp_size, ps_copy_size, pcs_copy_size;
	int ret;

	DebugUST("guest kernel chain state: base 0x%llx ind 0x%llx size 0x%llx\n",
		 vcpu_pcsp_base(vcpu, g_pcsp), vcpu_pcsp_ind(vcpu, g_pcsp),
		 vcpu_pcsp_size(vcpu, g_pcsp));
	DebugUST("guest kernel proc state: base 0x%llx ind 0x%llx size 0x%llx\n",
		 vcpu_psp_base(vcpu, g_psp), vcpu_psp_ind(vcpu, g_psp),
		 vcpu_psp_size(vcpu, g_psp));
	g_pshtp_size = PSHTP_MEM_INDEX(stacks->pshtp);
	g_pcshtp_size = stacks->pcshtp.ind;
	DebugUST("guest kernel chain stack PCSHTP 0x%llx, proc stack PSHTP 0x%llx cur window 0x%llx\n",
		 g_pcshtp_size, g_pshtp_size, cur_window_q);

	/*
	 * FIXME: the current implementation of the guest user signal handler
	 * injection uses direct copying to guest hardware stacks.
	 * It is bad decision, needs to be corrected
	 */
#if 0
	E2K_KVM_BUG_ON(is_paging(current_thread_info()->vcpu) &&
		   (g_psp_lo.PSP_lo_base < GUEST_TASK_SIZE ||
			g_pcsp_lo.PCSP_lo_base < GUEST_TASK_SIZE));
#endif

	/*
	 * Calculate size of user's part to copy from kernel stacks
	 * into guest kernel stacks
	 */
	pcs_copy_size = get_pcs_copy_size(g_pcshtp_size);
	ps_copy_size = get_ps_copy_size(cur_window_q, g_pshtp_size);
	/* Make sure there is enough space in CF for the FILL */
	BUG_ON((E2K_MAXCR_q - 4) * 16 < E2K_CF_MAX_FILL);
	DebugUST("to copy chain stack 0x%llx, proc stack 0x%llx\n",
		 pcs_copy_size, ps_copy_size);

	if (likely(pcs_copy_size <= 0 && ps_copy_size <= 0))
		return 0;

	if (unlikely(pcs_copy_size > 0)) {
		e2k_pcsp_t k_pcsp = native_read_PCSP_reg();
		void  __priv *dst;
		void *src;

		/* Since SPILL'ed guest user data will be copyed to guest */
		/* kernel stacks then cannot be any overflow of user's */
		/* hardware stack. */
		if (unlikely(vcpu_pcsp_ind(vcpu, g_pcsp) > vcpu_pcsp_size(vcpu, g_pcsp))) {
			pr_err("%s(): guest kernel chain stack overflow\n"
			       "(out of memory?): ind 0x%llx size 0x%llx\n",
			       __func__, vcpu_pcsp_ind(vcpu, g_pcsp),
			       vcpu_pcsp_ind(vcpu, g_pcsp));
			E2K_KVM_BUG_ON(true);
		}
		dst = vcpu_pcsp_ptr(vcpu, g_pcsp);
		if (!guest_user) {
			/* stack index has been incremented on PCSHTP */
			dst -= g_pcshtp_size;
		}
		src = (void *)PCSP_BASE(current_thread_info()->k_pcsp);

		if (trace_host_copy_hw_stack_enabled())
			trace_host_copy_hw_stack(dst, src, pcs_copy_size, true);

		ret = user_pcsp_stack_copy(dst, PCSP_IND(k_pcsp), src, pcs_copy_size, regs);
		if (trace_host_chain_stack_frame_enabled())
			trace_chain_stack_frames((e2k_mem_crs_t __user *) dst,
					(e2k_mem_crs_t *) src, pcs_copy_size,
					trace_host_chain_stack_frame);
		if (ret)
			return ret;
		if (guest_user) {
			g_pcsp = vcpu_incr_pcsp_ind(vcpu, g_pcsp, pcs_copy_size);
			stacks->pcsp = g_pcsp;
			DebugGUST("guest user chain stack frames copied from\n"
				  "host %px to guest kernel from %px size 0x%llx PCSP.ind 0x%llx\n",
				  src, dst, pcs_copy_size, vcpu_pcsp_ind(vcpu, g_pcsp));
		}
	}

	if (unlikely(ps_copy_size > 0)) {
		e2k_psp_t k_psp = native_read_PSP_reg();
		volatile void __user __priv *dst;
		void *src;

		/* Since SPILL'ed guest user data will be copyed to guest */
		/* kernel stacks then cannot be any overflow of user's */
		/* hardware stack. */
		if (unlikely(vcpu_psp_ind(vcpu, g_psp) > vcpu_psp_size(vcpu, g_psp))) {
			pr_err("%s(): guest kernel proc stack overflow (out of memory?): ind 0x%llx size 0x%llx\n",
			       __func__, vcpu_psp_ind(vcpu, g_psp), vcpu_psp_size(vcpu, g_psp));
			E2K_KVM_BUG_ON(true);
		}
		dst = vcpu_psp_ptr(vcpu, g_psp);
		if (!guest_user) {
			/* stack index has been incremented on PSHTP */
			dst -= g_pshtp_size;
		}
		src = (void *)PSP_BASE(current_thread_info()->k_psp);

		if (trace_host_copy_hw_stack_enabled())
			trace_host_copy_hw_stack(dst, src, ps_copy_size, false);

		ret = user_psp_stack_copy(dst, PSP_IND(k_psp), src, ps_copy_size, regs);
		if (trace_host_proc_stack_frame_enabled())
			trace_proc_stack_frames((kernel_mem_ps_t __user *) dst,
					(kernel_mem_ps_t *) src, ps_copy_size,
					trace_host_proc_stack_frame);
		if (ret)
			return ret;
		if (guest_user) {
			g_psp = vcpu_incr_psp_ind(vcpu, g_psp, ps_copy_size);
			stacks->psp = g_psp;
			DebugGUST("guest user proc stack frames copied from\n"
				  "host %px to guest kernel from %px size 0x%llx PSP.ind 0x%llx\n",
				  src, dst, ps_copy_size, vcpu_psp_ind(vcpu, g_psp));
		}
	}

	return 0;
}

/**
 * pv_vcpu_user_hw_stacks_prepare - prepare guest user hardware stacks
				    that have been SPILLed to kernel back
				    to guest user space
 * @regs - saved guest user stack registers
 * @cur_window_q - size of current window in procedure stack
 * @syscall - true if called upon direct system call exit (no signal handlers)
 *
 * This does two things:
 *
 * 1) It is possible that upon kernel entry pcshtp == 0 in some cases:
 *   - user signal handler had pcshtp==0x20 before return to sigreturn()
 *   - user context had pcshtp==0x20 before return to makecontext_trampoline()
 *   - chain stack underflow happened
 * So it is possible in sigreturn() and traps, but not in system calls.
 * If we are using the trick with return to FILL user hardware stacks than
 * we must have frame in chain stack to return to. So in this case kernel's
 * chain stack is moved up by one frame (0x20 bytes).
 * We also fill the new frame with actual user data and update stacks->pcshtp,
 * this is needed to keep the coherent state where saved stacks->pcshtp values
 * shows how much data from user space has been spilled to kernel space.
 *
 * 2) It is not possible to always FILL all of user data that have been
 * SPILLed to kernel stacks. So we manually copy the leftovers that can
 * not be FILLed to user space.
 * This copy does not update stacks->pshtp and stacks->pcshtp. Main reason
 * is signals: if a signal arrives after copying then it must see a coherent
 * state where saved stacks->pshtp and stacks->pcshtp values show how much
 * data from user space has been spilled to kernel space.
 */
static __always_inline void
pv_vcpu_user_hw_stacks_prepare(struct kvm_vcpu *vcpu, pt_regs_t *regs,
		u64 cur_window_q, enum restore_caller from, int syscall)
{
	e2k_stacks_t *stacks;
	e2k_pcshtp_t pcshtp;
	bool guest_user;
	bool paging = is_paging(vcpu);
	int ret;

	if (likely(paging)) {
		guest_user = !!(syscall || !pv_vcpu_trap_on_guest_kernel(regs));
	} else {
		guest_user = false;
	}
	if (guest_user) {
		if (from & FROM_PV_VCPU_MODE) {
			/* all preparation has been made */
			/* by host & guest handler */
			return;
		}

		/* trap on/syscall from guest user, so regs keeps user */
		/* registers state and it need use guest kernel stacks */
		/* in empty state to handle this trap/syscall */
		if (!regs->g_stacks_valid) {
			prepare_pv_vcpu_inject_stacks(vcpu, regs);
		}
		stacks = &regs->g_stacks;
	} else {
		/* trap on guest kernel, so regs already points to guest */
		/* kernel stacks and trap will be handled by host */
		/* same as other user's processes traps */
		stacks = &regs->stacks;
	}

	/* only to debug on simulator : pcshtp == 0 */
	pv_vcpu_emulate_empty_chain_staks(vcpu, regs, stacks, guest_user);

	pcshtp = stacks->pcshtp;
	DebugUST("guest kernel chain stack state: base 0x%llx ind 0x%llx size 0x%llx\n",
		 vcpu_pcsp_base(vcpu, stacks->pcsp), vcpu_pcsp_ind(vcpu, stacks->pcsp),
		 vcpu_pcsp_size(vcpu, stacks->pcsp));
	DebugUST("host kernel chain stack state: base 0x%llx ind 0x%llx size 0x%llx\n",
		 PCSP_BASE(native_read_PCSP_reg()),
		 PCSP_IND(native_read_PCSP_reg()),
		 PCSP_SIZE(native_read_PCSP_reg()));
	DebugUST("guest kernel chain stack size to fill PCSHTP 0x%x\n",
		 AW(pcshtp));
	/*
	 * 1) Make sure there is free space in kernel chain stack to return to
	 */
	if (!syscall && pcshtp.ind == 0 && !guest_user) {
		unsigned long flags;
		e2k_pcsp_t g_pcsp = stacks->pcsp;
		e2k_pcsp_t k_pcsp;
		e2k_mem_crs_t __priv *g_cframe;
		e2k_mem_crs_t *k_crs;
		int ret = -EINVAL;

		raw_all_irq_save(flags);
		NATIVE_FLUSHC;
		k_pcsp = native_read_PCSP_reg();
		BUG_ON(PCSP_IND(k_pcsp));
		k_pcsp = incr_pcsp_ind(k_pcsp, SZ_OF_CR);
		native_write_PCSP_reg(k_pcsp);

		k_crs = (e2k_mem_crs_t *) PCSP_BASE(current_thread_info()->k_pcsp);
		g_cframe = (e2k_mem_crs_t __priv *)vcpu_pcsp_ptr(vcpu, g_pcsp);
		if ((unsigned long)g_cframe > vcpu_pcsp_base(vcpu, g_pcsp)) {
			ret = copy_priv_to_current_hw_stack(k_crs, g_cframe - 1,
					sizeof(*k_crs), regs, true);
		}
		raw_all_irq_restore(flags);

		/* Can happen if application returns until runs out of
		 * chain stack or there is no free memory for stacks.
		 * There is no user stack to return to - die. */
		if (ret) {
			E2K_LMS_HALT_OK;
			pr_err("%s(): SIGKILL. %s\n", __func__,
			       (ret == -EINVAL) ? "tried to return to kernel" :
			       "ran into Out-of-Memory on user stacks");
			force_sig(SIGKILL);
			return;
		}
		DebugUST("copy guest user chain frame from %px to kernel bottom from %px\n",
			g_cframe - 1, k_crs);

		if (vcpu_pcsp_ind(vcpu, g_pcsp) < SZ_OF_CR) {
			pr_err("%s(): guest kernel chain stack underflow\n", __func__);
			E2K_KVM_BUG_ON(true);
		}

		pcshtp.ind = SZ_OF_CR;
		stacks->pcshtp = pcshtp;
		DebugUST("guest kernel chain stack to FILL PCSHTP set to 0x%x\n",
			AW(stacks->pcshtp));
	} else if (!syscall && pcshtp.ind == 0 && guest_user) {
		/* in this case the trampoline frame is added into the guest */
		/* kernel chain stack */

		/* set flag for unconditional injection to do not copy */
		/* from guest user space */
		regs->need_inject = true;
	}

	/*
	 * 2) Copy user data that cannot be FILLed
	 */
	ret = pv_vcpu_user_hw_stacks_copy(vcpu, regs, stacks, cur_window_q, guest_user);
	if (unlikely(ret)) {
		pr_err("%s(): kill guest: user hw stacks copy failed, error %d\n",
		       __func__, ret);
		do_exit(SIGKILL);
	}
}

static __always_inline void
host_user_hw_stacks_prepare(struct e2k_stacks *stacks, pt_regs_t *regs,
			    u64 cur_window_q, enum restore_caller from, int syscall)
{
	struct kvm_vcpu *vcpu;

	if (likely(!kvm_test_intc_emul_flag(regs))) {
		/* trap on/syscall from host user processes */
		return native_user_hw_stacks_prepare(stacks, regs, cur_window_q,
						     from, syscall);
	}

	vcpu = current_thread_info()->vcpu;
	BUG_ON(vcpu == NULL);
	pv_vcpu_user_hw_stacks_prepare(vcpu, regs, cur_window_q, from, syscall);
}
#else
static __always_inline void
host_user_hw_stacks_prepare(struct e2k_stacks *stacks, pt_regs_t *regs,
			    u64 cur_window_q, enum restore_caller from, int syscall)
{
	native_user_hw_stacks_prepare(stacks, regs, cur_window_q, from, syscall);
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

/* Same as for native kernel without virtualization support */
static __always_inline int
user_hw_stacks_copy(struct e2k_stacks *stacks,
		    pt_regs_t *regs, u64 cur_window_q, bool copy_full)
{
	return native_user_hw_stacks_copy(stacks, regs, cur_window_q, copy_full);
}

#endif /* CONFIG_KVM_HOST_KERNEL */

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel */
#include <asm/kvm/guest/copy-hw-stacks.h>
#else /* CONFIG_VIRTUALIZATION && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native host kernel with virtualization support */
/* or it is paravirtualized host and guest kernel */
#endif /* ! CONFIG_KVM_GUEST_KERNEL */

#endif /* ! _E2K_KVM_COPY_HW_STACKS_H */
