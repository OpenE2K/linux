/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Definition of traps handling routines.
 */

#ifndef _E2K_KERNEL_TTABLE_H
#define _E2K_KERNEL_TTABLE_H

#include <linux/types.h>
#include <asm/e2k_api.h>
#include <asm/cpu_regs_types.h>
#include <asm/trap_def.h>
#include <asm/glob_regs.h>
#include <asm/mmu_regs_types.h>
#include <asm/process.h>
#include <asm/copy-hw-stacks.h>
#include <asm/kvm/switch.h>

#include "ttable-help.h"

#undef	DEBUG_PV_SYSCALL_MODE
#define	DEBUG_PV_SYSCALL_MODE	0	/* syscall injection debugging */

#if	DEBUG_PV_SYSCALL_MODE
extern bool debug_guest_ust;
#else
#define	debug_guest_ust	false
#endif /* DEBUG_PV_SYSCALL_MODE */

extern u64 finish_user_trap_handler_sw_fill_wsz;
extern u64 finish_syscall_sw_fill_wsz;
extern u64 return_to_injected_syscall_sw_fill_wsz;

static __always_inline void
user_hw_stacks_restore__hw(e2k_stacks_t *stacks, u64 cur_window_q,
			   clear_rf_t clear_fn)
{
	e2k_psp_t u_psp;
	e2k_pcsp_t u_pcsp;
	s64 pcs_copy_size, ps_copy_size, u_pshtp_size, u_pcshtp_size;

	u_psp = stacks->psp;
	u_pcsp = stacks->pcsp;

	u_pcshtp_size = stacks->pcshtp.ind;
	u_pshtp_size = PSHTP_MEM_INDEX(stacks->pshtp);
	ps_copy_size = get_ps_copy_size(cur_window_q, u_pshtp_size);
	pcs_copy_size = get_pcs_copy_size(u_pcshtp_size);

	if (ps_copy_size > 0)
		u_pshtp_size -= ps_copy_size;
	if (pcs_copy_size > 0)
		u_pcshtp_size -= pcs_copy_size;

	u_psp = decr_psp_ind(u_psp, u_pshtp_size);
	u_pcsp = decr_pcsp_ind(u_pcsp, u_pcshtp_size);

	FILL_HARDWARE_STACKS__HW();

	write_hw_stacks(u_psp, u_pcsp);
}

extern void fill_handler_0(void);
extern void fill_handler_1(void);
extern void fill_handler_2(void);
extern void fill_handler_3(void);
extern void fill_handler_4(void);
extern void fill_handler_5(void);
extern void fill_handler_6(void);
extern void fill_handler_7(void);
extern void fill_handler_8(void);
extern void fill_handler_9(void);
extern void fill_handler_10(void);
extern void fill_handler_11(void);
extern void fill_handler_12(void);
extern void fill_handler_13(void);
extern void fill_handler_14(void);
extern void fill_handler_15(void);
extern void fill_handler_16(void);
extern void fill_handler_17(void);
extern void fill_handler_18(void);
extern void fill_handler_19(void);
extern void fill_handler_20(void);
extern void fill_handler_21(void);
extern void fill_handler_22(void);
extern void fill_handler_23(void);
extern void fill_handler_24(void);
extern void fill_handler_25(void);
extern void fill_handler_26(void);
extern void fill_handler_27(void);
extern void fill_handler_28(void);
extern void fill_handler_29(void);
extern void fill_handler_30(void);
extern void fill_handler_31(void);
extern void fill_handler_32(void);
extern void fill_handler_33(void);
extern void fill_handler_34(void);
extern void fill_handler_35(void);
extern void fill_handler_36(void);
extern void fill_handler_37(void);
extern void fill_handler_38(void);
extern void fill_handler_39(void);
extern void fill_handler_40(void);
extern void fill_handler_41(void);
extern void fill_handler_42(void);
extern void fill_handler_43(void);
extern void fill_handler_44(void);
extern void fill_handler_45(void);
extern void fill_handler_46(void);
extern void fill_handler_47(void);
extern void fill_handler_48(void);
extern void fill_handler_49(void);
extern void fill_handler_50(void);
extern void fill_handler_51(void);
extern void fill_handler_52(void);
extern void fill_handler_53(void);
extern void fill_handler_54(void);
extern void fill_handler_55(void);
extern void fill_handler_56(void);
extern void fill_handler_57(void);
extern void fill_handler_58(void);
extern void fill_handler_59(void);
extern void fill_handler_60(void);
extern void fill_handler_61(void);
extern void fill_handler_62(void);
extern void fill_handler_63(void);
extern void fill_handler_64(void);
extern void fill_handler_65(void);
extern void fill_handler_66(void);
extern void fill_handler_67(void);
extern void fill_handler_68(void);
extern void fill_handler_69(void);
extern void fill_handler_70(void);
extern void fill_handler_71(void);
extern void fill_handler_72(void);
extern void fill_handler_73(void);
extern void fill_handler_74(void);
extern void fill_handler_75(void);
extern void fill_handler_76(void);
extern void fill_handler_77(void);
extern void fill_handler_78(void);
extern void fill_handler_79(void);
extern void fill_handler_80(void);
extern void fill_handler_81(void);
extern void fill_handler_82(void);
extern void fill_handler_83(void);
extern void fill_handler_84(void);
extern void fill_handler_85(void);
extern void fill_handler_86(void);
extern void fill_handler_87(void);
extern void fill_handler_88(void);
extern void fill_handler_89(void);
extern void fill_handler_90(void);
extern void fill_handler_91(void);
extern void fill_handler_92(void);
extern void fill_handler_93(void);
extern void fill_handler_94(void);
extern void fill_handler_95(void);
extern void fill_handler_96(void);
extern void fill_handler_97(void);
extern void fill_handler_98(void);
extern void fill_handler_99(void);
extern void fill_handler_100(void);
extern void fill_handler_101(void);
extern void fill_handler_102(void);
extern void fill_handler_103(void);
extern void fill_handler_104(void);
extern void fill_handler_105(void);
extern void fill_handler_106(void);
extern void fill_handler_107(void);
extern void fill_handler_108(void);
extern void fill_handler_109(void);
extern void fill_handler_110(void);
extern void fill_handler_111(void);

typedef void (*fill_handler_t)(void);

extern const fill_handler_t fill_handlers_table[E2K_MAXSR];

extern void __noreturn finish_user_trap_handler_sw_fill(void);
extern void __noreturn finish_syscall_sw_fill(void);

static __always_inline void
user_hw_stacks_restore__sw(e2k_stacks_t *stacks, u64 cur_window_q,
			   clear_rf_t clear_fn, void (*sw_fill_sequel),
			   u64 sw_fill_window_q)
{
	struct task_struct *p = (struct task_struct *) read_CURRENT_reg_value();
	e2k_pshtp_t u_pshtp = stacks->pshtp;
	e2k_pcshtp_t u_pcshtp = stacks->pcshtp;
	e2k_psp_t u_psp = stacks->psp;
	e2k_pcsp_t u_pcsp = stacks->pcsp;
	e2k_pcsp_t k_pcsp;
	e2k_cr0_t new_cr0 = {0};
	e2k_cr1_t new_cr1 = {0};
	s64 pcs_copy_size, ps_copy_size, u_pshtp_size, u_pcshtp_size;
	u64 wbs;

	u_pcshtp_size = u_pcshtp.ind;
	u_pshtp_size = PSHTP_MEM_INDEX(u_pshtp);
	ps_copy_size = get_ps_copy_size(max(cur_window_q, sw_fill_window_q), u_pshtp_size);
	pcs_copy_size = get_pcs_copy_size(u_pcshtp_size);

	if (ps_copy_size > 0)
		u_pshtp_size -= ps_copy_size;
	if (pcs_copy_size > 0)
		u_pcshtp_size -= pcs_copy_size;

	u_psp = decr_psp_ind(u_psp, u_pshtp_size);
	u_pcsp = decr_pcsp_ind(u_pcsp, u_pcshtp_size);

	p->thread.fill.u_psp = u_psp;
	p->thread.fill.u_pcsp = u_pcsp;
	p->thread.fill.cr0 = read_CR0_reg();
	p->thread.fill.cr1 = read_CR1_reg();

#ifndef CONFIG_CPU_HW_CLEAR_RF
	clear_fn();
#endif

	if (u_pcshtp_size == 0)
		goto set_new_regs;

	wbs = (u64) u_pshtp_size >> 5UL;
	set_cr0_ip(new_cr0, fill_handlers_table[wbs]);

	new_cr1 = (e2k_cr1_t) {	0};
	new_cr1.psr = AW(E2K_KERNEL_PSR_DISABLED_ALL);
	new_cr1.cui = KERNEL_CODES_INDEX;
	if (!cpu_has(CPU_FEAT_ISET_V6))
		new_cr1.ic = 1;
	new_cr1.wfx = u_pshtp.fx;
	new_cr1.wbs = wbs;
	new_cr1 = set_cr1_ussz(new_cr1, (cpu_has(CPU_FEAT_V7_CPU_REGS)) ?
						0 : USD_IND(read_USD_reg()));

	/* Other barriers will be inserted later when restoring user's CRs */
	write_cr__no_wait(new_cr0, new_cr1);

	prefetch_nospec(&p->thread.fill.cr0);
	prefetch_nospec(&p->thread.fill.return_to_user);

	if (!cpu_has(CPU_FEAT_FILLC)) {
		/*
		 * To make hardware issue a FILL we have to make stack empty first
		 */
		k_pcsp = read_PCSP_reg();
		if (PCSP_IND(k_pcsp))
			E2K_FLUSHC;
	}

#define DEBUG_FILL_HARDWARE_STACKS_V3 0
#if DEBUG_FILL_HARDWARE_STACKS_V3
	if (__builtin_constant_p(cur_window_q))
		asm volatile ("{setwd wsz=%[psize]}" "{setwd wsz=%0}"
			:: "i" (cur_window_q), [psize] "i" (C_ABI_PSIZE_UNPROT));
#endif
	FILL_HARDWARE_STACKS__SW(sw_fill_sequel);

set_new_regs:
	/* Other barriers will be inserted later when restoring user's CRs */
	write_hw_stacks_cr__no_wait(p->thread.fill.u_psp, p->thread.fill.u_pcsp,
			   p->thread.fill.cr0, p->thread.fill.cr1);
}

static __always_inline void user_hw_stacks_restore__sw_sequel(void)
{
	e2k_cr0_t cr0 = current->thread.fill.cr0;
	e2k_cr1_t cr1 = current->thread.fill.cr1;
	e2k_psp_t u_psp = current->thread.fill.u_psp;
	e2k_pcsp_t u_pcsp = current->thread.fill.u_pcsp;

	BUG_ON(cpu_has(CPU_FEAT_FILLC) && cpu_has(CPU_FEAT_FILLR));

	if (cpu_has(CPU_FEAT_FILLC))
		NATIVE_FILL_CHAIN_STACK__HW();

	/* Other barriers will be inserted later when restoring user's CRs */
	write_hw_stacks_cr__no_wait(u_psp, u_pcsp, cr0, cr1);
}

static __always_inline void
user_hw_stacks_restore(e2k_stacks_t *stacks, u64 cur_window_q,
		       clear_rf_t clear_fn, void (*sw_fill_sequel),
		       u64 sw_fill_window_q)
{
	if (cpu_has(CPU_FEAT_FILLC) && cpu_has(CPU_FEAT_FILLR))
		user_hw_stacks_restore__hw(stacks, cur_window_q, clear_fn);
	else
		user_hw_stacks_restore__sw(stacks, cur_window_q, clear_fn, sw_fill_sequel,
			sw_fill_window_q);
}

static __always_inline void
native_jump_to_ttable_entry(struct pt_regs *regs, enum restore_caller from)
{
	if (from & (FROM_SYSCALL_N_PROT | FROM_PV_VCPU_SYSCALL)) {
		switch (regs->kernel_entry) {
		case 1:
			__E2K_JUMP_RNDPR_7(ttable_entry1, regs->sys_num,
					regs->dargs[0], regs->dargs[1], regs->dargs[2],
					regs->dargs[3], regs->dargs[4], regs->dargs[5],
					!is_paravirt_kernel(), regs->rndpr);
		case 3:
			__E2K_JUMP_RNDPR_7(ttable_entry3, regs->sys_num,
					regs->dargs[0], regs->dargs[1], regs->dargs[2],
					regs->dargs[3], regs->dargs[4], regs->dargs[5],
					!is_paravirt_kernel(), regs->rndpr);
		case 4:
			__E2K_JUMP_RNDPR_7(ttable_entry4, -(s32) regs->sys_num,
					regs->dargs[0], regs->dargs[1], regs->dargs[2],
					regs->dargs[3], regs->dargs[4], regs->dargs[5],
					!is_paravirt_kernel(), regs->rndpr);
		default:
			BUG();
		}
#ifdef CONFIG_PROTECTED_MODE
	} else if (from & FROM_SYSCALL_PROT_8) {
		__E2K_RESTART_TTABLE_ENTRY8_C(ttable_entry8, regs->sys_num,
				regs->dargs[0], regs->dargs[1], regs->dargs[2],
				regs->dargs[3], regs->dargs[4], regs->dargs[5],
				regs->dargs[6], regs->dargs[7], regs->dargs[8],
				regs->dargs[9], regs->dargs[10], regs->dargs[11],
				regs->tags, regs->rndpr);
#endif
	} else {
		BUG();
	}
}

#if	!defined(CONFIG_VIRTUALIZATION) || !defined(CONFIG_KVM_GUEST_KERNEL)
static __always_inline void
jump_to_ttable_entry(struct pt_regs *regs, enum restore_caller from)
{
	native_jump_to_ttable_entry(regs, from);
}
#endif /* !CONFIG_VIRTUALIZATION || !CONFIG_KVM_GUEST_KERNEL) */

extern int copy_context_from_signal_stack(struct pt_regs *regs, struct trap_pt_regs *trap,
		e2k_aau_t *aau_context, struct k_sigaction *ka);

static inline int copy_pt_regs_from_signal_stack(struct pt_regs *regs)
{
	return copy_context_from_signal_stack(regs, NULL, NULL, NULL);
}

static __always_inline bool signal_pending_usermode_loop(struct pt_regs *regs)
{
	if (likely(!signal_pending(current)))
		return false;

	/*
	 * We do not want to deliver signals on top of privileged
	 * frames for several reasons:
	 *  - harder to verify user chain stack correctness (CRIU);
	 *  - privileged frame could that of fast_sys_getcontext
	 *    which reads thread_info.signal_stack;
	 *  - for consistency with future iset w/o cr1_lo.pm field.
	 *
	 * So instead we set last wish on the next user frame and
	 * will deliver signal there (or repeat the delay if its
	 * also privileged).
	 *
	 * But do not delay fatal signals - it makes no sense to
	 * continue with e.g. syscall if we are getting killed anyway.
	 */
	if (unlikely(regs->crs.cr1.pm) && task_sigpending(current) &&
			!__fatal_signal_pending(current)) {
		regs->crs.cr1.lw = 1;
		return test_tsk_thread_flag(current, TIF_NOTIFY_SIGNAL);
	}

	return true;
}

static inline unsigned long exit_to_usermode_has_work(const struct pt_regs *regs,
						      bool return_to_user)
{
	unsigned long flags = current_thread_info()->flags;
	e2k_cr1_t cr1 = regs->crs.cr1;

	if (unlikely(!return_to_user))
		return 0;

	return unlikely((flags & _TIF_SIGPENDING) && !(cr1.pm && cr1.lw) ||
			(flags & _TIF_WORK_MASK_NOSIG));
}

/*
 * Loop before exiting to usermode until all events requiring
 * attention are handled (these events include signals,
 * rescheduling and handling of TIF_NOTIFY_RESUME).
 */

static __always_inline e2k_pshtp_t exit_to_usermode_loop(struct pt_regs *regs,
		enum restore_caller from, bool *return_to_user,
		u64 wsz, bool syscall)
{
	e2k_pshtp_t pshtp = regs->stacks.pshtp;
	struct pt_regs __priv *orig_u_pt_regs = NULL;

	/*
	 * Return control from UPSR register to PSR, if UPSR interrupts
	 * control is used. RETURN operation restores PSR state at system
	 * call point and recovers interrupts control
	 *
	 * This also disables interrupts and serves as a compiler barrier.
	 */
	PSR_IRQ_ALL_CLI();

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (unlikely(host_test_intc_emul_mode(regs))) {
		/* host is at guest VCPU interception emulation mode */
		host_exit_to_usermode_loop(regs, syscall,
					   signal_pending_usermode_loop(regs));
		return pshtp;
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	/*
	 * Check under closed interrupts to avoid races
	 */
	while (unlikely(exit_to_usermode_has_work(regs, *return_to_user))) {
		/* Make sure compiler does not reuse previous checks (this
		 * is better than adding "volatile" to reads in hot path). */
		barrier();

		PSR_IRQ_ALL_STI();

		/* Check for rescheduling first */
		if (need_resched())
			schedule();

		/* This will set SIG_*_FLAG_PT_REGS flags */
		if (signal_pending_usermode_loop(regs)) {
			e2k_aau_t *aau_regs = regs->aau_context;
			do_signal(regs);
			/* arch_ptrace_stop() reads current values of AALDI
			 * and AALDA registers and those values must not be
			 * restored - we want APB to restart from the last
			 * *used* address. So recalculate proper values here. */
			if (!syscall && aau_regs &&
			    unlikely(aau_stopped(regs->aasr))) {
				machine.calculate_aau_aaldis_aaldas(regs,
					current_thread_info()->aalda, aau_regs);
			}
		}

		if (syscall && regs->flags.sig_restart_syscall) {
			/*
			 * Rules for system call restart:
			 * 1) First we call signal handlers for _all_ signals
			 * sent to us (if they have handler registered)
			 * 2) Then we restart system call _exactly_once_ even
			 * if multiple signals were restart-worthy.
			 */
			if (regs->flags.sig_call_handler) {
				/* Call handler _before_ restarting system call
				 * and do not forget to restart it later. */
				typeof(orig_u_pt_regs->flags) flags;
				int ret;

				/* This will point to the first pt_regs
				 * where restart logic should apply */
				if (!orig_u_pt_regs)
					orig_u_pt_regs = signal_pt_regs_first();
				ret = get_priv(AW(flags), &AW(orig_u_pt_regs->flags));
				if (!ret) {
					flags.sig_restart_syscall = 1;
					ret = put_priv(AW(flags), &AW(orig_u_pt_regs->flags));
				}
				if (ret)
					force_sigsegv(SIGSEGV);

				/* Restart will be done after signal handling */
				regs->flags.sig_restart_syscall = 0;
			} else if (!signal_pending(current)) {
				/* There are no signal handlers and no more
				 * signals so we can restart this system call */
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
				BUG_ON(host_test_intc_emul_mode(regs));
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
				*return_to_user = false;
			}
		}

		if (test_thread_flag(TIF_NOTIFY_RESUME)) {
			clear_thread_flag(TIF_NOTIFY_RESUME);
			do_notify_resume(regs);
		}

		/*
		 * Signal handler delivery does magic with stack,
		 * so check again whether manual copy is needed
		 */
		if (regs->flags.sig_call_handler) {
			/* this case has not yet been accounted for */
			BUG_ON(!syscall &&
			       guest_trap_from_user(current_thread_info()) ||
			       syscall &&
			       guest_syscall_from_user(current_thread_info()));
			host_user_hw_stacks_prepare(&regs->stacks, regs,
				wsz, from, !(from & ~(FROM_SYSCALL_N_PROT |
						      FROM_SYSCALL_PROT_8)));
		}

		pshtp = regs->stacks.pshtp;
		PSR_IRQ_ALL_CLI();
	}

	return pshtp;
}

static __noreturn __always_inline void finish_user_trap_handler_done(struct thread_info *ti,
		const struct pt_regs *regs, restore_caller_t from)
{
	e2k_rndpr_t rndpr = regs->rndpr;
	e2k_aau_t *aau_regs = regs->aau_context;

	BUILD_BUG_ON(!__builtin_constant_p(from));

	/*
	 * There must not be any branches after restoring ctpr register
	 * because of hardware bug (old one that was not found and also
	 * CPU_HWBUG_BRANCH_ACTIVATES_CTPR), so this 'if' is done before
	 * restoring %ctpr2 (actually it belongs to set_aau_aaldis_aaldas()).
	 *
	 * RESTORE_COMMON_REGS() must be called before RESTORE_AAU_MASK_REGS()
	 * because of ctpr2 and AAU registers restoring dependencies.
	 */
	if (likely(!aau_stopped(regs->aasr))) {
		RESTORE_COMMON_REGS(regs);
		RESTORE_AAU_MASK_REGS((e2k_aaldm_t) { .word = 0 },
				(e2k_aaldv_t) { .word = 0 }, regs->aasr);
		if (from & FROM_SIGRETURN) {
			CLEAR_DO_SIGRETURN_INTERRUPT(rndpr);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		} else if (from & (FROM_RETURN_PV_VCPU_TRAP)) {
			CLEAR_RETURN_PV_VCPU_TRAP_WINDOW(rndpr);
#endif
		} else {
			CLEAR_USER_TRAP_HANDLER_WINDOW(rndpr);
		}
	} else {
		RESTORE_COMMON_REGS(regs);
		native_set_aau_aaldis_aaldas(ti->aalda, aau_regs);
		RESTORE_AAU_MASK_REGS(aau_regs->aaldm, aau_regs->aaldv, regs->aasr);
		if (from & FROM_SIGRETURN) {
			CLEAR_DO_SIGRETURN_INTERRUPT(rndpr);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		} else if (from & (FROM_RETURN_PV_VCPU_TRAP)) {
			CLEAR_RETURN_PV_VCPU_TRAP_WINDOW(rndpr);
#endif
		} else {
			CLEAR_USER_TRAP_HANDLER_WINDOW(rndpr);
		}
	}

	unreachable();
}

/*
 * We have FILLed user hardware stacks so no
 * function calls are allowed after this point.
 */
static __noreturn __always_inline void
finish_user_trap_handler_switched_hw_stacks(struct pt_regs *regs, struct trap_pt_regs *trap,
					 restore_caller_t from)
{
	e2k_aau_t *aau_regs = regs->aau_context;
	struct thread_info *ti;
	e2k_wd_t wd;

	RESTORE_USER_TRAP_STACK_REGS(regs);
#if DEBUG_TRACE_TRAP_USD_CR1
	E2K_WAIT(_all_e);
	current_thread_info()->d_usd = native_read_USD_reg();
	current_thread_info()->d_cr1  = native_read_CR1_reg();
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		current_thread_info()->d_usfs  = native_read_USFS_reg();
	}
#endif
	if (current->thread.flags & E2K_FLAG_PROTECTED_MODE)
		ENABLE_US_CLW();

	if (unlikely(cpu_has(CPU_HWBUG_SS) && test_ts_flag(TS_SINGLESTEP_USER))) {
		/*
		 * Hardware can lose singlestep flag on interrupt if it
		 * arrives earlier, so we must always manually reset it.
		 */
		e2k_cr1_t cr1 = read_CR1_reg();

		if (!cr1.pm) {
			cr1.ss = 1;
			write_CR1_reg(cr1);
		}
	}

	/*
	 * Dequeue current pt_regs structure
	 */
	current_thread_info()->pt_regs = NULL;

	wd = read_WD_reg();
	wd.psize = regs->wd.psize;
	write_WD_reg(wd);

	/* restore some guest context, if trap was on guest */
	ti = current_thread_info();

	if (cpu_has(CPU_HWBUG_AAU_AALDV))
		__E2K_WAIT(_ma_c);
	if (aau_working(regs->aasr)) {
		set_aau_context(aau_regs, ti->aalda, regs->aasr);

		/*
		 * It's important to restore AAD after
		 * all return operations.
		 */
		if (regs->aasr.iab)
			RESTORE_AADS(aau_regs);
	}

	trap_guest_enter(ti, regs, EXIT_FROM_TRAP_SWITCH, from);

	/*
	 * WARNING: from here should not use current, current_thread_info(),
	 * cpu_has() - only variable 'ti'
	 */

	/*
	 * There must not be any branches after restoring ctpr register
	 * because of HW bug
	 */
	if (from & FROM_SIGRETURN)
		finish_user_trap_handler_done(ti, regs, FROM_SIGRETURN);
	else if (from & FROM_RETURN_PV_VCPU_TRAP)
		finish_user_trap_handler_done(ti, regs, FROM_RETURN_PV_VCPU_TRAP);
	else
		finish_user_trap_handler_done(ti, regs, FROM_USER_TRAP);

	unreachable();
}

/*
 * This calculation is based on user_hw_stacks_restore() calculation of register window size
 */
static __always_inline u64 get_finish_handler_wbs(struct e2k_stacks *stacks, u64 finish_wsz)
{
	u64 wsz = get_wsz();

	if (cpu_has(CPU_FEAT_FILLC) && cpu_has(CPU_FEAT_FILLR))
		return wsz;

	return max(wsz, finish_wsz);
}

static __noreturn __always_inline void
finish_user_trap_handler(struct pt_regs *regs, restore_caller_t from)
{
	e2k_aau_t *aau_regs = regs->aau_context;
	struct trap_pt_regs *trap = regs->trap;
	bool return_to_user = true;
	clear_rf_t clear_fn;
	e2k_pshtp_t pshtp;
	e2k_pcshtp_t pcshtp;
	e2k_ctpr_t ctpr3;
	u64 wsz, finish_wsz, num_q;

	if (unlikely(aau_stopped(regs->aasr)))
		machine.calculate_aau_aaldis_aaldas(regs,
				current_thread_info()->aalda, aau_regs);

	/*
	 * This can page fault so call with open interrupts
	 */
	BUILD_BUG_ON(from & ~(FROM_SIGRETURN | FROM_USER_TRAP | FROM_RETURN_PV_VCPU_TRAP));
	wsz = get_wsz();
	finish_wsz = get_finish_handler_wbs(&regs->stacks, finish_user_trap_handler_sw_fill_wsz);
	host_user_hw_stacks_prepare(&regs->stacks, regs, finish_wsz, from, false);

	pshtp = exit_to_usermode_loop(regs, from, &return_to_user, finish_wsz, false);

	clear_apb();

	debug_inject_semi_spec_loads(true);

	exception_exit(trap->prev_state);

	num_q = get_ps_clear_size(finish_wsz, pshtp);

	clear_fn = get_clear_rf_fn(num_q);

	native_write_UPSR_reg(current_thread_info()->upsr);

	pcshtp = regs->stacks.pcshtp;
	ctpr3 = regs->ctpr3;

	/* Update run state info, if trap occured on guest kernel */
	SET_RUNSTATE_OUT_USER_TRAP();

	read_ticks(start_tick);

	info_restore_mmu_reg(start_tick);

	CHECK_PT_REGS_CHAIN(regs, native_read_USD_reg().base,
			    current->stack + KERNEL_C_STACK_SIZE);

	read_ticks(clock);

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (unlikely(trap->rp)) {
		u64 ip = get_cr0_ip(regs->crs.cr0);

		WARN_ON(ip < current_thread_info()->rp_start ||
			ip >= current_thread_info()->rp_end);
		set_cr0_ip(regs->crs.cr0, current_thread_info()->rp_ret_ip);
	}
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */

	/* If user updated chain stack then the change must be propagated
	 * to %ctpr3 in case we are in a trap that arrived between `return
	 * %ctpr3` and `ct %ctpr3`. */
	if (ctpr_ta_tag(ctpr3) == CTPPL_CT_TAG && ctpr_opc(ctpr3) == RETURN_CT_OPC &&
			pcshtp.ind >= SZ_OF_CR) {
		e2k_pcsp_t k_pcsp = current_thread_info()->k_pcsp;
		unsigned long prev_frame;

		E2K_FLUSHC;
		prev_frame = PCSP_BASE(k_pcsp) + pcshtp.ind - SZ_OF_CR;
		ctpr3.ta_base = get_cr0_ip(((e2k_mem_crs_t *) prev_frame)->cr0);
		regs->ctpr3 = ctpr3;
	}

	/* MMU registers must be written with not active CLW/AAU */
	uaccess_enable();

	/* complete intercept emulation mode */
	trap_guest_enter(current_thread_info(), regs, EXIT_FROM_INTC_SWITCH, from);

	info_restore_stack_reg(clock);

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	trap_times->psp_to_done = native_read_PSP_reg();
	trap_times->pcsp_to_done = native_read_PCSP_reg();
	trap_times->pshtp_to_done = native_read_PSHTP_reg();
	trap_times->ctpr1_to_done = AS_WORD(regs->ctpr1);
	trap_times->ctpr2_to_done = AS_WORD(regs->ctpr2);
	trap_times->ctpr3_to_done = AS_WORD(regs->ctpr3);
	E2K_SAVE_CLOCK_REG(trap_times->end);
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */

	if (!cpu_has(CPU_FEAT_FILLC) || !cpu_has(CPU_FEAT_FILLR))
		current->thread.fill.from = from;

	/*
	 * If either FILLC or FILLR isn't supported, jump to finish_user_trap_handler_sw_fill.
	 * Otherwise, fall through and call finish_user_trap_handler_switched_hw_stacks directly.
	 */
	user_hw_stacks_restore(trap_guest_get_restore_stacks(current_thread_info(), regs),
			       wsz, clear_fn, finish_user_trap_handler_sw_fill,
			       finish_user_trap_handler_sw_fill_wsz);

	finish_user_trap_handler_switched_hw_stacks(regs, trap, from);

	unreachable();
}

/*
 * We have FILLed user hardware stacks so no
 * function calls are allowed after this point.
 */
static __always_inline __noreturn
void finish_syscall_switched_hw_stacks(struct pt_regs *regs, enum restore_caller from,
				    bool return_to_user, bool ts_host_at_vcpu_mode)
{
	e2k_rndpr_t rndpr = regs->rndpr;
	u64 rval = regs->sys_rval;
	int return_desk = regs->return_desk;

	/*
	 * It is possible to use closed GNU ASM since we have more than
	 * 4 instructions before the return to user.
	 */
	exit_handle_syscall(regs->stacks.top, regs->stacks.usd,
			    current_thread_info()->upsr, regs->wd.psize, &regs->crs);

	/*
	 * Dequeue current pt_regs structure
	 */
	current_thread_info()->pt_regs = NULL;

	/* restore some guest context, if trap was on guest */
	guest_syscall_exit_trap(regs, ts_host_at_vcpu_mode);

	if (!(from & (FROM_SYSCALL_N_PROT | FROM_PV_VCPU_SYSCALL | FROM_PV_VCPU_SYSFORK))) {
		ENABLE_US_CLW();
	}
	/* %gN-%gN+3 must be restored last as they hold pointers to current */
	CLEAR_KERNEL_GREGS_IN_SYSCALL(current_thread_info());

	if (likely(return_to_user)) {
		if ((from & FROM_SYSCALL_PROT_8) && unlikely(return_desk)) {
			u64 flag, rval1 = regs->rval1, rval2 = regs->rval2;
			int rv1_tag = regs->rv1_tag, rv2_tag = regs->rv2_tag;

			if ((long) rval < 0) {
				flag = 1;
				rval1 = -rval;
			} else {
				flag = 0;
			}

			if (from & FROM_SIGRETURN)
				CLEAR_DO_SIGRETURN_SYSCALL_PROT(flag, 0,
						rval1, rval2, rv1_tag, rv2_tag, rndpr);
#ifdef CONFIG_PROTECTED_MODE
			else
				CLEAR_TTABLE_ENTRY_8_WINDOW_PROT(flag, 0,
						rval1, rval2, rv1_tag, rv2_tag, rndpr);
#endif
		}

		/* Check for 'wsz' modifiers first */
		if (unlikely(from & (FROM_SIGRETURN | FROM_RET_FROM_FORK))) {
			if (from & FROM_SIGRETURN)
				CLEAR_DO_SIGRETURN_SYSCALL(rval, rndpr);
			else /* (from & FROM_RET_FROM_FORK) */
				CLEAR_RET_FROM_FORK_WINDOW(rval, rndpr);
		} else if (from & FROM_SYSCALL_N_PROT) {
			CLEAR_HANDLE_SYS_CALL_WINDOW(rval, rndpr);
#ifdef CONFIG_PROTECTED_MODE
		} else if (from & FROM_SYSCALL_PROT_8) {
			CLEAR_TTABLE_ENTRY_8_WINDOW(rval, rndpr);
#endif
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		} else if (from & FROM_PV_VCPU_SYSCALL) {
			CLEAR_HANDLE_PV_VCPU_SYS_CALL_WINDOW(rval, rndpr);
		} else if (from & FROM_PV_VCPU_SYSFORK) {
			CLEAR_HANDLE_PV_VCPU_SYS_FORK_WINDOW(rval, rndpr);
#endif
		} else {
			BUG();
		}
	} else {
		jump_to_ttable_entry(regs, from);
	}

	unreachable();
}

static __always_inline __noreturn
void finish_syscall(struct pt_regs *regs, enum restore_caller from, bool return_to_user)
{
	e2k_pshtp_t pshtp;
	u64 wsz, finish_wsz, num_q;
	bool ts_host_at_vcpu_mode, intc_emul_flag;
	clear_rf_t clear_fn;

	/*
	 * This can page fault so call with open interrupts
	 */
	wsz = get_wsz();
	finish_wsz = get_finish_handler_wbs(&regs->stacks, finish_syscall_sw_fill_wsz);
	host_user_hw_stacks_prepare(&regs->stacks, regs, finish_wsz, from,
		!(from & ~(FROM_SYSCALL_N_PROT | FROM_SYSCALL_PROT_8)));

	pshtp = exit_to_usermode_loop(regs, from, &return_to_user, finish_wsz, true);

	intc_emul_flag = kvm_test_intc_emul_flag(regs);
	ts_host_at_vcpu_mode = ts_host_at_vcpu_mode() || intc_emul_flag;

	num_q = get_ps_clear_size(finish_wsz, pshtp);

	debug_inject_semi_spec_loads(true);

	if (!cpu_has(CPU_FEAT_FILLC) || !cpu_has(CPU_FEAT_FILLR)) {
		current->thread.fill.from = from;
		current->thread.fill.return_to_user = return_to_user;
		current->thread.fill.ts_host_at_vcpu_mode = ts_host_at_vcpu_mode;
	}

	/*
	 * All signals delivered, can access *regs now
	 */
	BUG_ON(from & FROM_USER_TRAP);

	CHECK_PT_REGS_CHAIN(regs, USD_PTR(native_read_USD_reg()),
			    current->stack + KERNEL_C_STACK_SIZE);

	clear_fn = get_clear_rf_fn(num_q);

	/* MMU registers must be written with not active CLW/AAU */
	uaccess_enable();

	/* complete intercept emulation mode */
	guest_exit_intc(regs, intc_emul_flag, from);

	/*
	 * If either FILLC or FILLR isn't supported, jump to finish_syscall_sw_fill.
	 * Otherwise, fall through and call finish_syscall_switched_hw_stacks directly.
	 */
	user_hw_stacks_restore(syscall_guest_get_restore_stacks(ts_host_at_vcpu_mode, regs),
			       wsz, clear_fn, &finish_syscall_sw_fill,
			       finish_syscall_sw_fill_wsz);

	finish_syscall_switched_hw_stacks(regs, from, return_to_user, ts_host_at_vcpu_mode);

	unreachable();
}

/* virtualization support */
#include "../kvm/ttable-inline.h"

#endif /* _E2K_KERNEL_TTABLE_H */
