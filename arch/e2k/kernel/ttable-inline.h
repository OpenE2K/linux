/*
 *
 * Copyright (C) 2020 MCST
 *
 * Defenition of traps handling routines.
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

#undef	DEBUG_PV_UST_MODE
#undef	DebugUST
#define	DEBUG_PV_UST_MODE	0	/* trap injection debugging */
#define	DebugUST(fmt, args...)						\
({									\
	if (debug_guest_ust)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PV_SYSCALL_MODE
#define	DEBUG_PV_SYSCALL_MODE	0	/* syscall injection debugging */

#if	DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE
extern bool debug_guest_ust;
#else
#define	debug_guest_ust	false
#endif	/* DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE */

#ifdef CONFIG_CPU_HAS_FILL_INSTRUCTION
static __always_inline void
user_hw_stacks_restore(struct pt_regs *regs, e2k_stacks_t *stacks,
			u64 cur_window_q, u64 clear_num_q)
{
	e2k_psp_lo_t u_psp_lo;
	e2k_psp_hi_t u_psp_hi;
	e2k_pcsp_lo_t u_pcsp_lo;
	e2k_pcsp_hi_t u_pcsp_hi;
	s64 pcs_copy_size, ps_copy_size, u_pshtp_size, u_pcshtp_size;

	u_psp_lo = stacks->psp_lo;
	u_psp_hi = stacks->psp_hi;
	u_pcsp_lo = stacks->pcsp_lo;
	u_pcsp_hi = stacks->pcsp_hi;

	u_pshtp_size = GET_PSHTP_MEM_INDEX(stacks->pshtp);
	u_pcshtp_size = PCSHTP_SIGN_EXTEND(stacks->pcshtp);
	ps_copy_size = get_ps_copy_size(cur_window_q, u_pshtp_size);
	pcs_copy_size = get_pcs_copy_size(u_pcshtp_size);

	if (ps_copy_size > 0)
		u_pshtp_size -= ps_copy_size;
	if (pcs_copy_size > 0)
		u_pcshtp_size -= pcs_copy_size;

	AS(u_psp_hi).ind -= u_pshtp_size;
	AS(u_pcsp_hi).ind -= u_pcshtp_size;

	FILL_HARDWARE_STACKS();

	WRITE_PSP_REG(u_psp_hi, u_psp_lo);
	WRITE_PCSP_REG(u_pcsp_hi, u_pcsp_lo);
}
#else	/* !CONFIG_CPU_HAS_FILL_INSTRUCTION */
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

static __always_inline void
user_hw_stacks_restore(struct pt_regs *regs, e2k_stacks_t *stacks,
				u64 cur_window_q, u64 clear_num_q)
{
	e2k_pshtp_t u_pshtp;
	e2k_pcshtp_t u_pcshtp;
	e2k_psp_lo_t u_psp_lo;
	e2k_psp_hi_t u_psp_hi;
	e2k_pcsp_lo_t u_pcsp_lo;
	e2k_pcsp_hi_t u_pcsp_hi;
	e2k_pcsp_hi_t k_pcsp_hi;
	e2k_cr0_hi_t new_cr0_hi;
	e2k_cr1_lo_t new_cr1_lo;
	e2k_cr1_hi_t new_cr1_hi;
	s64 pcs_copy_size, ps_copy_size, u_pshtp_size, u_pcshtp_size;
	u64 wbs;

#ifndef CONFIG_CPU_HW_CLEAR_RF
	clear_rf_kernel_except_current(clear_num_q);
#endif

	u_pshtp = stacks->pshtp;
	u_pcshtp = stacks->pcshtp;
	u_psp_lo = stacks->psp_lo;
	u_psp_hi = stacks->psp_hi;
	u_pcsp_lo = stacks->pcsp_lo;
	u_pcsp_hi = stacks->pcsp_hi;

	u_pshtp_size = GET_PSHTP_MEM_INDEX(u_pshtp);
	u_pcshtp_size = PCSHTP_SIGN_EXTEND(u_pcshtp);
	ps_copy_size = get_ps_copy_size(cur_window_q, u_pshtp_size);
	pcs_copy_size = get_pcs_copy_size(u_pcshtp_size);

	if (ps_copy_size > 0)
		u_pshtp_size -= ps_copy_size;
	if (pcs_copy_size > 0)
		u_pcshtp_size -= pcs_copy_size;

	AS(u_psp_hi).ind -= u_pshtp_size;
	AS(u_pcsp_hi).ind -= u_pcshtp_size;

	current->thread.fill.u_psp_lo = u_psp_lo;
	current->thread.fill.u_psp_hi = u_psp_hi;
	current->thread.fill.u_pcsp_lo = u_pcsp_lo;
	current->thread.fill.u_pcsp_hi = u_pcsp_hi;
	current->thread.fill.cr0_hi = READ_CR0_HI_REG();
	current->thread.fill.cr1_lo = READ_CR1_LO_REG();
	current->thread.fill.cr1_hi = READ_CR1_HI_REG();

	if (u_pcshtp_size == 0)
		goto set_new_regs;

	wbs = (u64) u_pshtp_size >> 5UL;
	AW(new_cr1_lo) = 0;
	AS(new_cr1_lo).psr = AW(E2K_KERNEL_PSR_DISABLED);
	AS(new_cr1_lo).cui = KERNEL_CODES_INDEX;
	if (machine.native_iset_ver < E2K_ISET_V6)
		AS(new_cr1_lo).ic = 1;
	AS(new_cr1_lo).wfx = AS(u_pshtp).fx;
	AS(new_cr1_lo).wbs = wbs;
	AW(new_cr0_hi) = (u64) fill_handlers_table[wbs];
	AW(new_cr1_hi) = 0;
	AS(new_cr1_hi).ussz = AS(READ_USD_HI_REG()).size >> 4;
	WRITE_CR0_HI_REG(new_cr0_hi);
	WRITE_CR1_LO_REG(new_cr1_lo);
	WRITE_CR1_HI_REG(new_cr1_hi);

	prefetch_nospec(&current->thread.fill.cr0_hi);
	prefetch_nospec(&current->thread.fill.return_to_user);

	/*
	 * To make hardware issue a FILL we have to make stack empty first
	 */
	k_pcsp_hi = READ_PCSP_HI_REG();
	if (AS(k_pcsp_hi).ind)
		E2K_FLUSHC;

# define DEBUG_FILL_HARDWARE_STACKS_V2 0
# if DEBUG_FILL_HARDWARE_STACKS_V2
	if (__builtin_constant_p(cur_window_q))
		asm volatile ("{setwd wsz=4}" "{setwd wsz=%0}"
				:: "i" (cur_window_q));
# endif
	FILL_HARDWARE_STACKS();

set_new_regs:

	WRITE_CR0_HI_REG(current->thread.fill.cr0_hi);
	WRITE_CR1_LO_REG(current->thread.fill.cr1_lo);
	WRITE_CR1_HI_REG(current->thread.fill.cr1_hi);

	WRITE_PSP_REG(current->thread.fill.u_psp_hi,
			current->thread.fill.u_psp_lo);
	WRITE_PCSP_REG(current->thread.fill.u_pcsp_hi,
			current->thread.fill.u_pcsp_lo);
}
#endif	/* CONFIG_CPU_HAS_FILL_INSTRUCTION */

static __always_inline void
native_jump_to_ttable_entry(struct pt_regs *regs, enum restore_caller from)
{
	if (from & (FROM_SYSCALL_N_PROT | FROM_PV_VCPU_SYSCALL)) {
		switch (regs->kernel_entry) {
		case 1:
			__E2K_JUMP_WITH_ARGUMENTS_7(ttable_entry1,
					regs->sys_num,
					regs->args[1], regs->args[2],
					regs->args[3], regs->args[4],
					regs->args[5], regs->args[6],
					!is_paravirt_kernel());
		case 3:
			__E2K_JUMP_WITH_ARGUMENTS_7(ttable_entry3,
					regs->sys_num,
					regs->args[1], regs->args[2],
					regs->args[3], regs->args[4],
					regs->args[5], regs->args[6],
					!is_paravirt_kernel());
		case 4:
			__E2K_JUMP_WITH_ARGUMENTS_7(ttable_entry4,
					-(s32) regs->sys_num,
					regs->args[1], regs->args[2],
					regs->args[3], regs->args[4],
					regs->args[5], regs->args[6],
					!is_paravirt_kernel());
		default:
			BUG();
		}
	} else if (from & FROM_SYSCALL_PROT_8) {
		__E2K_RESTART_TTABLE_ENTRY8_C(ttable_entry8, regs->sys_num,
				regs->args[1], regs->args[2], regs->args[3],
				regs->args[4], regs->args[5], regs->args[6],
				regs->args[7], regs->args[8], regs->args[9],
				regs->args[10], regs->args[11], regs->args[12],
				regs->tags);
	} else if (from & FROM_SYSCALL_PROT_10) {
		__E2K_RESTART_TTABLE_ENTRY10_C(ttable_entry10,
				regs->sys_num, regs->args[1], regs->args[2],
				regs->args[3], regs->args[4], regs->args[5],
				regs->args[6], regs->args[7], regs->tags);
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
#endif	/* !CONFIG_VIRTUALIZATION || !CONFIG_KVM_GUEST_KERNEL) */

extern int copy_context_from_signal_stack(struct local_gregs *l_gregs,
		struct pt_regs *regs, struct trap_pt_regs *trap, u64 *sbbp,
		e2k_aau_t *aau_context, struct k_sigaction *ka);

static inline int signal_pending_usermode_loop(bool syscall)
{
	return (syscall || !test_delayed_signal_handling(current,
				current_thread_info())) &&
			signal_pending(current);
}

static inline unsigned long exit_to_usermode_has_work(struct pt_regs *regs,
						bool return_to_user, bool syscall)
{
	if (unlikely(!return_to_user))
		return 0;

	if (syscall)
		return unlikely(current_thread_info()->flags & _TIF_WORK_MASK);

	return unlikely(!test_delayed_signal_handling(current,
					current_thread_info()) &&
			(current_thread_info()->flags & _TIF_SIGPENDING) ||
			(current_thread_info()->flags & _TIF_WORK_MASK_NOSIG));
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
	struct pt_regs __user *orig_u_pt_regs = NULL;

	/*
	 * Return control from UPSR register to PSR, if UPSR interrupts
	 * control is used. RETURN operation restores PSR state at system
	 * call point and recovers interrupts control
	 *
	 * This also disables interrupts and serves as a compiler barrier.
	 */
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_DISABLED));

	if (unlikely(host_test_intc_emul_mode(regs))) {
		/* host is at guest VCPU interception emulation mode */
		host_exit_to_usermode_loop(regs, syscall,
				signal_pending_usermode_loop(syscall));
		return pshtp;
	}

	/*
	 * Check under closed interrupts to avoid races
	 */
	while (unlikely(exit_to_usermode_has_work(regs, *return_to_user, syscall))) {
		/* Make sure compiler does not reuse previous checks (this
		 * is better than adding "volatile" to reads in hot path). */
		barrier();

		WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_ENABLED));

		/* Check for rescheduling first */
		if (need_resched())
			schedule();

		/* This will set SIG_*_FLAG_PT_REGS flags */
		if (signal_pending_usermode_loop(syscall)) {
#ifdef CONFIG_USE_AAU
			struct e2k_aau_context *aau_regs = regs->aau_context;
#endif
			do_signal(regs);
#ifdef CONFIG_USE_AAU
			/* arch_ptrace_stop() reads current values of AALDI
			 * and AALDA registers and those values must not be
			 * restored - we want APB to restart from the last
			 * *used* address. So recalculate proper values here. */
			if (!syscall && aau_regs &&
			    unlikely(AAU_STOPPED(aau_regs->aasr))) {
				machine.calculate_aau_aaldis_aaldas(regs,
					current_thread_info(), aau_regs);
			}
#endif
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
				unsigned long ts_flag;
				int ret;

				/* This will point to the first pt_regs
				 * where restart logic should apply */
				if (!orig_u_pt_regs)
					orig_u_pt_regs = signal_pt_regs_first();
				ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
				ret = __get_user(AW(flags), &AW(orig_u_pt_regs->flags));
				if (!ret) {
					flags.sig_restart_syscall = 1;
					ret = __put_user(AW(flags),
							 &AW(orig_u_pt_regs->flags));
				}
				clear_ts_flag(ts_flag);
				if (ret)
					force_sigsegv(SIGSEGV);

				/* Restart will be done after signal handling */
				regs->flags.sig_restart_syscall = 0;
			} else if (!signal_pending_usermode_loop(syscall)) {
				/* There are no signal handlers and no more
				 * signals so we can restart this system call */
				BUG_ON(host_test_intc_emul_mode(regs));
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
						      FROM_SYSCALL_PROT_8 |
						      FROM_SYSCALL_PROT_10)));
		}

		pshtp = regs->stacks.pshtp;
		WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_DISABLED));
	}

	return pshtp;
}

static __noreturn __always_inline void
finish_user_trap_handler(struct pt_regs *regs, restore_caller_t from)
{
	thread_info_t *ti;
	struct e2k_aau_context *aau_regs = regs->aau_context;
	struct trap_pt_regs *trap = regs->trap;
#if	defined(CONFIG_VIRTUALIZATION) && !defined(CONFIG_KVM_GUEST_KERNEL)
	bool from_paravirt_guest;
#endif	/* CONFIG_VIRTUALIZATION  && ! CONFIG_KVM_GUEST_KERNEL */
	bool return_to_user = true;
	e2k_pshtp_t pshtp;
	u64 wsz, num_q;

#ifdef CONFIG_USE_AAU
	if (unlikely(AAU_STOPPED(aau_regs->aasr)))
		machine.calculate_aau_aaldis_aaldas(regs,
				current_thread_info(), aau_regs);
#endif

	/*
	 * This can page fault so call with open interrupts
	 */
	BUILD_BUG_ON(from & ~(FROM_SIGRETURN | FROM_USER_TRAP |
				FROM_RETURN_PV_VCPU_TRAP));
	wsz = get_wsz(from);
	host_user_hw_stacks_prepare(&regs->stacks, regs, wsz, from, false);

	pshtp = exit_to_usermode_loop(regs, from, &return_to_user, wsz, false);

	exception_exit(trap->prev_state);

	num_q = get_ps_clear_size(wsz, pshtp);

	NATIVE_DO_RESTORE_UPSR_REG(current_thread_info()->upsr);

	/* calculate if done will be to paravirtualized guest */
	GET_PARAVIRT_GUEST_MODE(from_paravirt_guest, regs);

	/* Update run state info, if trap occured on guest kernel */
	SET_RUNSTATE_OUT_USER_TRAP();

	read_ticks(start_tick);

#if (!defined CONFIG_E2K_MACHINE && defined CONFIG_E2K_MINVER_V2) || defined CONFIG_E2K_ES2_DSP || \
		defined CONFIG_E2K_ES2_RU
	/* Hardware bug 71610 workaround */
	if (cpu_has(CPU_HWBUG_ATOMIC) &&
	    unlikely(AS(regs->ctpr1).ta_base == 0xfffffffffff8ULL)) {
		unsigned long long g23;
		int g23_tag;

		E2K_GET_DGREG_VAL_AND_TAG(23, g23, g23_tag);
		if ((current->thread.flags & E2K_FLAG_32BIT)
				&& !TASK_IS_BINCO(current)
				&& !(current->thread.flags &
				     E2K_FLAG_PROTECTED_MODE)) {
			g23 &= 0xffffffffULL;
			g23_tag &= 0x3;
		}
		if (g23_tag == ETAGNVD && access_ok(g23, 1)) {
			__TRY_USR_PFAULT {
				flush_DCACHE_line(g23);
			} CATCH_USR_PFAULT {
			} END_USR_PFAULT
		}
	}
#endif

	info_restore_mmu_reg(start_tick);

	CHECK_PT_REGS_CHAIN(regs,
		NATIVE_NV_READ_USD_LO_REG().USD_lo_base,
		current->stack + KERNEL_C_STACK_SIZE);

	read_ticks(clock);

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (unlikely(trap->flags & TRAP_RP_FLAG)) {
		u64 cr0_hi = AS_WORD(regs->crs.cr0_hi);

		WARN_ON(cr0_hi < current_thread_info()->rp_start ||
			cr0_hi >= current_thread_info()->rp_end);
		AS_WORD(regs->crs.cr0_hi) = current_thread_info()->rp_ret_ip;
	}
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */

	/* complete intercept emulation mode */
	trap_guest_enter(current_thread_info(), regs, EXIT_FROM_INTC_SWITCH);

	RESTORE_USER_TRAP_STACK_REGS(regs);

	if (current->thread.flags & E2K_FLAG_PROTECTED_MODE)
		ENABLE_US_CLW();

	info_restore_stack_reg(clock);

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	trap_times->psp_hi_to_done = NATIVE_NV_READ_PSP_HI_REG();
	trap_times->pcsp_hi_to_done = NATIVE_NV_READ_PCSP_HI_REG();
	trap_times->pshtp_to_done = NATIVE_NV_READ_PSHTP_REG();
	trap_times->ctpr1_to_done = AS_WORD(regs->ctpr1);
	trap_times->ctpr2_to_done = AS_WORD(regs->ctpr2);
	trap_times->ctpr3_to_done = AS_WORD(regs->ctpr3);
	E2K_SAVE_CLOCK_REG(trap_times->end);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	if (unlikely(cpu_has(CPU_HWBUG_SS) &&
		     test_ts_flag(TS_SINGLESTEP_USER))) {
		/*
		 * Hardware can lose singlestep flag on interrupt if it
		 * arrives earlier, so we must always manually reset it.
		 */
		e2k_cr1_lo_t cr1_lo = READ_CR1_LO_REG();

		if (!AS(cr1_lo).pm) {
			AS(cr1_lo).ss = 1;
			WRITE_CR1_LO_REG(cr1_lo);
		}
	}

	/*
	 * We have FILLed user hardware stacks so no
	 * function calls are allowed after this point.
	 */
#if !defined(CONFIG_CPU_HAS_FILL_INSTRUCTION) && \
		defined(CONFIG_VIRTUALIZATION) && \
			!defined(CONFIG_KVM_GUEST_KERNEL)
	from_paravirt_guest = current->thread.fill.from_paravirt_guest;
#endif
	user_hw_stacks_restore(regs,
		trap_guest_get_restore_stacks(current_thread_info(), regs),
		wsz, num_q);
#ifndef CONFIG_CPU_HAS_FILL_INSTRUCTION
	BUILD_BUG_ON(!__builtin_constant_p(from));
# if defined(CONFIG_VIRTUALIZATION) && !defined(CONFIG_KVM_GUEST_KERNEL)
	from_paravirt_guest = current->thread.fill.from_paravirt_guest;
# endif
	regs = current_thread_info()->pt_regs;
	aau_regs = regs->aau_context;
	trap = regs->trap;
#endif

	/* TODO Drop this leftover from Paravirt-1.0 (user_trap_handler
	 * is the last entry, nothing to queue in entry or dequeue here) */
	/*
	 * Dequeue current pt_regs structure and previous
	 * regs will be now actuale
	 */
	current_thread_info()->pt_regs = regs->next;
	regs->next = NULL;

	/* restore some guest context, if trap was on guest */
	ti = current_thread_info();
	trap_guest_enter(ti, regs, EXIT_FROM_TRAP_SWITCH);
	BUG_ON(ti != READ_CURRENT_REG());
	/* WARNING: from here should not use current, current_thread_info() */
	/* only variable 'ti' */

#ifdef CONFIG_USE_AAU
	clear_apb();
	if (cpu_has(CPU_HWBUG_AAU_AALDV))
		__E2K_WAIT(_ma_c);
	if (aau_working(aau_regs)) {
		set_aau_context(aau_regs);

		/*
		 * It's important to restore AAD after
		 * all return operations.
		 */
		if (AS(aau_regs->aasr).iab)
			RESTORE_AADS(aau_regs);
	}

	/*
	 * There must not be any branches after restoring ctpr register
	 * because of HW bug, so this 'if' is done before restoring %ctpr2
	 * (actually it belongs to set_aau_aaldis_aaldas()).
	 *
	 * RESTORE_COMMON_REGS() must be called before RESTORE_AAU_MASK_REGS()
	 * because of ctpr2 and AAU registers restoring dependencies.
	 */
	if (likely(!AAU_STOPPED(aau_regs->aasr))) {
#endif
		RESTORE_COMMON_REGS(regs);
#ifdef CONFIG_USE_AAU
		RESTORE_AAU_MASK_REGS(aau_regs);
#endif
		/* only if return from paravirtualized host to guest */
		COND_GOTO_DONE_TO_PARAVIRT_GUEST(from_paravirt_guest);
		if (from & FROM_SIGRETURN) {
			CLEAR_DO_SIGRETURN_INTERRUPT();
		} else if (from & (FROM_RETURN_PV_VCPU_TRAP)) {
			CLEAR_RETURN_PV_VCPU_TRAP_WINDOW();
		} else {
			CLEAR_USER_TRAP_HANDLER_WINDOW();
		}
#ifdef CONFIG_USE_AAU
	} else {
		BUILD_BUG_ON(!__builtin_constant_p(from));
		RESTORE_GUEST_AAU_AASR(aau_regs,
			test_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE));
		RESTORE_COMMON_REGS(regs);
		native_set_aau_aaldis_aaldas(ti, aau_regs);
		RESTORE_AAU_MASK_REGS(aau_regs);
		/* only if return from paravirtualized host to guest */
		COND_GOTO_DONE_TO_PARAVIRT_GUEST(from_paravirt_guest);
		if (from & FROM_SIGRETURN) {
			CLEAR_DO_SIGRETURN_INTERRUPT();
		} else if (from & (FROM_RETURN_PV_VCPU_TRAP)) {
			CLEAR_RETURN_PV_VCPU_TRAP_WINDOW();
		} else {
			CLEAR_USER_TRAP_HANDLER_WINDOW();
		}
	}
#endif

	unreachable();
}

static __always_inline __noreturn
void finish_syscall(struct pt_regs *regs, enum restore_caller from,
		    bool return_to_user)
{
	e2k_pshtp_t pshtp;
	u64 wsz, num_q, rval;
	int return_desk;
	bool ts_host_at_vcpu_mode, intc_emul_flag;

	/*
	 * This can page fault so call with open interrupts
	 */
	wsz = get_wsz(from);
	host_user_hw_stacks_prepare(&regs->stacks, regs, wsz, from,
		!(from & ~(FROM_SYSCALL_N_PROT | FROM_SYSCALL_PROT_8 |
				   FROM_SYSCALL_PROT_10)));

	pshtp = exit_to_usermode_loop(regs, from, &return_to_user, wsz, true);

	intc_emul_flag = kvm_test_intc_emul_flag(regs);
	ts_host_at_vcpu_mode = ts_host_at_vcpu_mode() || intc_emul_flag;

#ifndef CONFIG_CPU_HAS_FILL_INSTRUCTION
	current->thread.fill.from = from;
	current->thread.fill.return_to_user = return_to_user;
#endif

	/*
	 * All signals delivered, can access *regs now
	 */
	BUG_ON(from & FROM_USER_TRAP);

	CHECK_PT_REGS_CHAIN(regs, NATIVE_NV_READ_USD_LO_REG().USD_lo_base,
			current->stack + KERNEL_C_STACK_SIZE);

	num_q = get_ps_clear_size(wsz, pshtp);

	/* complete intercept emulation mode */
	guest_exit_intc(regs, intc_emul_flag);

	/*
	 * We have FILLed user hardware stacks so no
	 * function calls are allowed after this point.
	 */
	user_hw_stacks_restore(regs,
		syscall_guest_get_restore_stacks(ts_host_at_vcpu_mode, regs),
		wsz, num_q);
#ifndef CONFIG_CPU_HAS_FILL_INSTRUCTION
	regs = current_thread_info()->pt_regs;
	if (!__builtin_constant_p(from))
		from = current->thread.fill.from;
	return_to_user = current->thread.fill.return_to_user;
#endif

	rval = regs->sys_rval;
	return_desk = regs->return_desk;

	/*
	 * It is possible to use closed GNU ASM since we have more than
	 * 4 instructions before the return to user.
	 */
	exit_handle_syscall(regs->stacks.top, regs->stacks.usd_hi,
			regs->stacks.usd_lo, current_thread_info()->upsr);

	/*
	 * Dequeue current pt_regs structure
	 */
	current_thread_info()->pt_regs = NULL;

	/* restore some guest context, if trap was on guest */
	guest_syscall_exit_trap(regs, ts_host_at_vcpu_mode);

	if (!(from & (FROM_SYSCALL_N_PROT | FROM_PV_VCPU_SYSCALL | FROM_PV_VCPU_SYSFORK)))
		ENABLE_US_CLW();

	if (cpu_has(CPU_HWBUG_VIRT_PSIZE_INTERCEPTION) &&
			(from & FROM_SYSCALL_PROT_8)) {
		e2k_wd_t wd = READ_WD_REG();
		wd.psize = 0x80;
		WRITE_WD_REG(wd);
	}

	/* %gN-%gN+3 must be restored last as they hold pointers to current */
	/* now N=16 (see asm/glob_regs.h) */
	RESTORE_KERNEL_GREGS_IN_SYSCALL(current_thread_info());

	if (likely(return_to_user)) {
		if ((from & (FROM_SYSCALL_PROT_8 | FROM_SYSCALL_PROT_10)) &&
				unlikely(return_desk)) {
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
						rval1, rval2, rv1_tag, rv2_tag);
			else if (from & FROM_SYSCALL_PROT_8)
				CLEAR_TTABLE_ENTRY_8_WINDOW_PROT(flag, 0,
						rval1, rval2, rv1_tag, rv2_tag);
			else
				CLEAR_TTABLE_ENTRY_10_WINDOW_PROT(flag, 0,
						rval1, rval2, rv1_tag, rv2_tag);
		}

		/* Check for 'wsz' modifiers first */
		if (from & FROM_SIGRETURN)
			CLEAR_DO_SIGRETURN_SYSCALL(rval);
		else if (from & FROM_RET_FROM_FORK)
			CLEAR_RET_FROM_FORK_WINDOW(rval);
		else if (from & FROM_MAKECONTEXT)
			CLEAR_MAKECONTEXT_WINDOW(rval);
		else if (from & FROM_SYSCALL_N_PROT)
			CLEAR_HANDLE_SYS_CALL_WINDOW(rval);
		else if (from & FROM_SYSCALL_PROT_8)
			CLEAR_TTABLE_ENTRY_8_WINDOW(rval);
		else if (from & FROM_SYSCALL_PROT_10)
			CLEAR_TTABLE_ENTRY_10_WINDOW(rval);
		else if (from & FROM_PV_VCPU_SYSCALL)
			CLEAR_HANDLE_PV_VCPU_SYS_CALL_WINDOW(rval);
		else if (from & FROM_PV_VCPU_SYSFORK)
			CLEAR_HANDLE_PV_VCPU_SYS_FORK_WINDOW(rval);
		else
			BUG();
	} else {
		jump_to_ttable_entry(regs, from);
	}

	unreachable();
}

/* virtualization support */
#include "../kvm/ttable-inline.h"

#endif	/* _E2K_KERNEL_TTABLE_H */
