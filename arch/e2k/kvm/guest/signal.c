/*
 * Guest paravitualized version of user signal handler
 *
 * Copyright (C) 2020 MCST
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
#include <asm/3p.h>
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

static int kvm_copy_sighandler_frame(struct pt_regs *regs, u64 *pframe)
{
	e2k_stacks_t *stacks = &regs->stacks;
	size_t pframe_size;
	void __user *u_pframe;
	unsigned long ts_flag;
	int ret;

	/* copy the signal handler procedure frame */
	/* to the top of user procedure stack */
	u_pframe = (void __user *)(stacks->psp_lo.PSP_lo_base +
					stacks->psp_hi.PSP_hi_ind);
	pframe_size = (TASK_IS_PROTECTED(current)) ? (32 * 8) : (16 * 8);

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __copy_to_user_with_tags(u_pframe, pframe, pframe_size);
	clear_ts_flag(ts_flag);
	if (ret != 0) {
		pr_err("%s(): could not copy user signal handler procedure "
			"stack frame\n",
			__func__);
		goto failed;
	}
	stacks->psp_hi.PSP_hi_ind += pframe_size;
	DebugHS("copy signal handler frame to %px size 0x%lx, "
		"PSP new ind 0x%x\n",
		u_pframe, pframe_size, stacks->psp_hi.PSP_hi_ind);

	return 0;

failed:
	return ret;
}

static int kvm_launch_sig_handler(struct pt_regs *regs)
{
	kvm_stacks_info_t regs_info;
	long sys_rval = regs->sys_rval;
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

	ret = signal_rt_frame_setup(regs);
	if (ret != 0) {
		pr_err("%s(): setup signal rt frame failed, error %d\n",
			__func__, ret);
		return ret;
	}

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
	if (ret != 0) {
		pr_err("%s(): could not restore user hardware stacks frames\n",
			__func__);
		return ret;
	}

	collapse_kernel_hw_stacks(stacks);

	/*
	 * After having called setup_signal_stack() we must unroll signal
	 * stack by calling pop_signal_stack() in case an error happens.
	 */
	ret = setup_signal_stack(regs, true);
	if (ret)
		return ret;

	/*
	 * User's signal handler frame should be the last in stacks
	 */
	ret = prepare_sighandler_frame(stacks, pframe, &regs->crs);
	if (ret)
		goto free_signal_stack;
	ret = kvm_copy_sighandler_frame(regs, pframe);
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

	signal_setup_done(0, &ti->ksig, test_ts_flag(TS_SINGLESTEP_USER));
	regs->flags.sig_call_handler = 1;
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (regs->trap)
		regs->trap->flags &= ~TRAP_RP_FLAG;
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */

	ret = kvm_launch_sig_handler(regs);

	/* should not be return to here */

free_signal_stack:
	pop_signal_stack();
	return ret;
}

int kvm_complete_long_jump(struct pt_regs *regs)
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
	ret = HYPERVISOR_complete_long_jump(&regs_info);
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
