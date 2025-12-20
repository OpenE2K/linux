/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Guest paravitualized version of user signal handler
 */

#include <linux/signal.h>
#include <linux/ptrace.h>
#include <linux/tracehook.h>
#include <linux/mm.h>

#include <asm/cpu_regs.h>
#include <asm/e2k_syswork.h>
#include <asm/getsp_adj.h>
#include <asm/glob_regs.h>
#include <asm/gregs.h>
#include <linux/uaccess.h>
#include <asm/process.h>
#include <asm/copy-hw-stacks.h>
#include <asm/trap_table.h>
#include <asm/regs_state.h>
#include <asm/ucontext.h>
#include <linux/unistd.h>
#ifdef CONFIG_PROTECTED_MODE
#include <asm/e2k_ptypes.h>
#include <asm/syscalls.h>
#include <asm/protected_syscalls.h>
#endif /* CONFIG_PROTECTED_MODE */
#include <asm/traps.h>
#include <asm/e2k_debug.h>
#include <asm/switch_to.h>

#undef	DEBUG_HS_MODE
#undef	DebugHS
#define	DEBUG_HS_MODE		0	/* Signal handling */
#define	DebugHS(fmt, args...)						\
({									\
	if (DEBUG_HS_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

notrace noinline __interrupt __section(".entry.text")
static void sighandler_trampoline_continue(void)
{
	e2k_addr_t sbr;
	e2k_usd_lo_t usd_lo;
	e2k_usd_hi_t usd_hi;

	if (TASK_IS_PROTECTED(current))
		DISABLE_US_CLW();

	/*
	 * Switch to kernel stacks.
	 */
	GET_SIG_RESTORE_STACK(current_thread_info(), sbr, usd_lo, usd_hi);
	NV_WRITE_USBR_USD_REG_VALUE(sbr, AW(usd_hi), AW(usd_lo));

	/*
	 * Switch to %upsr for interrupts control
	 */
	DO_SAVE_UPSR_REG(current_thread_info()->upsr);
	SET_KERNEL_IRQ_WITH_DISABLED_NMI();

	/*
	 * Set pointer to VCPU state to enable interface host <-> guest
	 * (it is actual only for guest kernel)
	 */
	ONLY_SET_GUEST_GREGS(thread_info);

	raw_all_irq_enable();

	E2K_JUMP(do_sigreturn);
}

static int kvm_launch_sig_handler(struct pt_regs *regs)
{
	kvm_stacks_info_t regs_info;
	long sys_rval = regs->sys_rval;
	e2k_pcsp_hi_t pcsp_hi;
	int pcshtp;
	int ret;

	regs_info.top = regs->stacks.top;
	regs_info.usd_lo = regs->stacks.usd_lo.USD_lo_half;
	regs_info.usd_hi = regs->stacks.usd_hi.USD_hi_half;

	regs_info.psp_lo = regs->stacks.psp_lo.PSP_lo_half;
	regs_info.psp_hi = regs->stacks.psp_hi.PSP_hi_half;
	regs_info.pshtp = regs->stacks.pshtp.PSHTP_reg;

	pcshtp = PCSHTP_SIGN_EXTEND(regs->stacks.pcshtp);
	pcsp_hi = regs->stacks.pcsp_hi;
	if (likely(pcshtp != 0)) {
		/* See comment in user_hw_stacks_copy_full() */
		BUG_ON(pcshtp != SZ_OF_CR);
		pcsp_hi.PCSP_hi_ind -= pcshtp;
		pcshtp = 0;
	}
	regs_info.pcsp_lo = regs->stacks.pcsp_lo.PCSP_lo_half;
	regs_info.pcsp_hi = pcsp_hi.PCSP_hi_half;
	regs_info.pcshtp = pcshtp;

	regs_info.cr0_lo = regs->crs.cr0_lo.CR0_lo_half;
	regs_info.cr0_hi = regs->crs.cr0_hi.CR0_hi_half;
	regs_info.cr1_lo = regs->crs.cr1_lo.CR1_lo_half;
	regs_info.cr1_hi = regs->crs.cr1_hi.CR1_hi_half;

	/* return IRQs mask control from UPSR to PSR */
	KVM_RETURN_TO_USER_UPSR(current_thread_info()->upsr, false);

retry:
	ret = HYPERVISOR_launch_sig_handler(&regs_info,
		(unsigned long)sighandler_trampoline_continue, sys_rval);
	if (unlikely(ret == -EAGAIN)) {
		pr_err("%s(): could not complete launch sig handler on host, "
			"error %d, retry\n",
			__func__, ret);
		goto retry;
	} else if (unlikely(ret < 0)) {
		pr_err("%s(): could not complete launch sig handler on host, "
			"error %d\n",
			__func__, ret);
	}
	return ret;
}

int kvm_signal_setup(struct pt_regs *regs)
{
	register thread_info_t *ti = current_thread_info();
	e2k_stacks_t *stacks = &regs->stacks;
	u64 pframe[32];
	int ret;

	/*
	 * Copy user's part of kernel hardware stacks into user
	 */
	ret = kvm_user_hw_stacks_copy(regs);
	if (ret)
		return ret;

	/*
	 * Copy 2 additional chain stack frames from guest kernel back to user:
	 *	top user frame that caused trap or system call;
	 *	host trampoline to return to user stacks & context;
	 *
	 * plus Guest kernel signal handler trampoline frame;
	 *
	 * The signal handler chain frame should be topmost, so on CRs,
	 * although a copy in memory may be needed
	 */
	ret = kvm_copy_injected_pcs_frames_to_user(regs, 2);
	if (unlikely(ret != 0)) {
		if (likely(ret == -ERESTARTSYS)) {
			/* there is fatal signal to kill the process */
			;
		} else {
			pr_err("%s(): could not restore user hardware stacks frames\n",
				__func__);
		}
		return ret;
	}

	/* Injected chain frames:
	 *	 - upper user frame from which was called syscall all trapped;
	 *	 - host trampoline to return to user;
	 * should be collapsed too
	 */
	collapse_kernel_hw_stacks(regs, stacks);

	ret = signal_rt_frame_setup(regs);
	if (ret != 0) {
		pr_err("%s(): setup signal rt frame failed, error %d\n",
			__func__, ret);
		return ret;
	}

	/*
	 * After having called setup_signal_stack() we must unroll signal
	 * stack by calling pop_signal_stack() in case an error happens.
	 */
	ret = setup_signal_stack(regs, true);
	if (ret)
		return ret;

	/*
	 * We want user to return to sighandler_trampoline so
	 * create fake kernel frame in user's chain stack
	 */
	ret = prepare_sighandler_trampoline(&regs->stacks);
	if (ret)
		goto free_signal_stack;

	/*
	 * User's signal handler frame should be the last in stacks
	 * Signal frame should be copied only after sighandler trampoline
	 * to maintain chain stack discipline
	 */
	ret = prepare_sighandler_frame(stacks, pframe, &regs->crs);
	if (ret)
		goto free_signal_stack;
	ret = copy_sighandler_frame(&regs->stacks, regs->trap,
				    pframe, &regs->crs);
	if (ret)
		goto free_signal_stack;

	/*
	 * Update psize for ttable_entry8: syscall uses 0x70
	 * but handler uses 0x40.
	 */
	if (from_syscall(regs))
		regs->wd.psize = 0x40;

	/*
	 * For e2k applications g16-g31 registers are local, initialize them
	 */
	if (!TASK_IS_BINCO(current)) {
		memset(&ti->k_gregs, 0, sizeof(ti->k_gregs));
	}

	DebugHS("sig=%d siginfo=0x%px\n"
		"\tIS_PROTECTED = 0x%lx\tsa_flags = 0x%lx\t"
		"->thread.flags=0x%lx\n",
		ti->ksig.sig, &ti->ksig.info,
		TASK_IS_PROTECTED(current), ti->ksig.ka.sa.sa_flags,
		current->thread.flags);
	DebugHS("will start handler() 0x%lx for sig #%d\n",
		ti->ksig.ka.sa.sa_handler, ti->ksig.sig);

	if (unlikely(signal_pending(current))) {
		/* there are other signals to handle, setup them up as well */
		return 0;
	}

	signal_setup_done(0, &ti->ksig, test_ts_flag(TS_SINGLESTEP_USER));
	regs->flags.sig_call_handler = 1;
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (regs->trap)
		regs->trap->rp = 0;
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */

	ret = kvm_launch_sig_handler(regs);

	/* should not be return to here */

free_signal_stack:
	pop_signal_stack();
	return ret;
}

int kvm_longjmp_copy_user_to_kernel_hw_stacks(pt_regs_t *regs, const pt_regs_t *new_regs)
{
	const e2k_stacks_t *new_stacks = &new_regs->stacks;
	int ret;

	ret = native_longjmp_copy_user_to_kernel_hw_stacks(new_regs);
	if (ret)
		goto out;

	/* Update CRs in memory too.  Although return to guest updates
	 * CR registers directly, in case when signal handler is delivered
	 * on top of sys_longjmp that update will happen for signal handler
	 * only, and this frame would be left in a bad state. */
	e2k_mem_crs_t *k_crs = (e2k_mem_crs_t *) AS(current_thread_info()->k_pcsp_lo).base;
	NATIVE_FLUSHC;
	*(k_crs + 1) = new_regs->crs;

	if (regs->copyed.pcs_size != 0) {
		/* the user chain frames at the kernel stack has been updated, */
		/* so it need update size of updated part of user stack frames */
		regs->copyed.pcs_size = PCSHTP_SIGN_EXTEND(new_stacks->pcshtp);
	}

out:
	return ret;
}

int kvm_complete_long_jump(struct pt_regs *regs, bool switch_stack, u64 to_key)
{
	kvm_long_jump_info_t regs_info;
	int ret;

	regs_info.top = regs->stacks.top;
	regs_info.usd_lo = regs->stacks.usd_lo.USD_lo_half;
	regs_info.usd_hi = regs->stacks.usd_hi.USD_hi_half;

	regs_info.psp_lo = regs->stacks.psp_lo.PSP_lo_half;
	regs_info.psp_hi = regs->stacks.psp_hi.PSP_hi_half;
	regs_info.pshtp = regs->stacks.pshtp.PSHTP_reg;
	regs_info.pcsp_lo = regs->stacks.pcsp_lo.PCSP_lo_half;
	regs_info.pcsp_hi = regs->stacks.pcsp_hi.PCSP_hi_half;
	regs_info.pcshtp = regs->stacks.pcshtp;

	regs_info.cr0_lo = regs->crs.cr0_lo.CR0_lo_half;
	regs_info.cr0_hi = regs->crs.cr0_hi.CR0_hi_half;
	regs_info.cr1_lo = regs->crs.cr1_lo.CR1_lo_half;
	regs_info.cr1_hi = regs->crs.cr1_hi.CR1_hi_half;

retry:
	ret = HYPERVISOR_complete_long_jump(&regs_info, switch_stack, to_key);
	if (unlikely(ret == -EAGAIN)) {
		pr_err("%s(): could not complete long jump on host, "
			"error %d, retry\n",
			__func__, ret);
		goto retry;
	} else if (unlikely(ret < 0)) {
		pr_err("%s(): could not complete long jump on host, "
			"error %d\n",
			__func__, ret);
		force_sig(SIGKILL);
	}
	return ret;
}

void kvm_update_kernel_crs(e2k_mem_crs_t *crs, e2k_mem_crs_t *prev_crs,
			e2k_mem_crs_t *p_prev_crs)
{
	HYPERVISOR_update_guest_kernel_crs(crs, prev_crs, p_prev_crs);
}

int kvm_add_ctx_signal_stack(u64 key, bool is_main)
{
	return HYPERVISOR_add_ctx_signal_stack(key, is_main);
}

void kvm_remove_ctx_signal_stack(u64 key)
{
	HYPERVISOR_remove_ctx_signal_stack(key);
}
