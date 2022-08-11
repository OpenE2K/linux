/* linux/arch/e2k/kernel/signal.c, v 1.10 08/21/2001.
 * 
 * Copyright (C) 2001 MCST 
 */

#include <linux/context_tracking.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/ptrace.h>
#include <linux/tracehook.h>
#include <linux/irqflags.h>
#include <linux/mman.h>

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

#undef	DEBUG_SIG_MODE
#undef	DebugSig
#define	DEBUG_SIG_MODE		0	/* Signal handling */
#define DebugSig(...)		DebugPrint(DEBUG_SIG_MODE ,##__VA_ARGS__)

#undef	DEBUG_HS_MODE
#undef	DebugHS
#define	DEBUG_HS_MODE		0	/* Signal handling */
#define	DebugHS(fmt, args...)						\
({									\
	if (DEBUG_HS_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SLJ_MODE
#undef	DebugSLJ
#define	DEBUG_SLJ_MODE		0	/* Signal long jump handling */
#define DebugSLJ(...)		DebugPrint(DEBUG_SLJ_MODE ,##__VA_ARGS__)

#define DEBUG_FTRACE_MODE	0
#if DEBUG_FTRACE_MODE
# define DebugFTRACE(...)	pr_info(__VA_ARGS__)
#else
# define DebugFTRACE(...)
#endif

#define	DEBUG_SRT_MODE		0	/* Signal return handling */
#define DebugSRT(...)		DebugPrint(DEBUG_SRT_MODE, ##__VA_ARGS__)

#define	DEBUG_CTX_MODE		0	/* setcontext/swapcontext */
#if DEBUG_CTX_MODE
#define	DebugCTX(...)		DebugPrint(DEBUG_CTX_MODE, ##__VA_ARGS__)
#else
#define DebugCTX(...)
#endif

#undef DebugSCP
#define DebugSCP(fmt, ...) \
do { \
	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_SIGNALS)) \
		pr_info("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)


void
sig_to_exit(int errno)
{
	struct 	kernel_siginfo 	si;
	struct k_sigaction 	*ka;

	DebugSig("start\n");

	ka = &current->sighand->action[SIGSEGV-1];
	ka->sa.sa_handler = SIG_DFL;

	si.si_signo = SIGSEGV;
	si.si_errno = 0;
	si.si_code = SI_KERNEL;
	force_sig_info(&si);
	
	DebugSig("finish\n");
	return;
}

static inline void copy_jmp_regs(pt_regs_t *to, const pt_regs_t *from)
{
	CHECK_PT_REGS_CHAIN((pt_regs_t *)from, NATIVE_NV_READ_USD_LO_REG().USD_lo_base,
			(u64) current->stack + KERNEL_C_STACK_SIZE);

	to->stacks.top = from->stacks.top;
	to->wd = from->wd;
	to->stacks.usd_lo = from->stacks.usd_lo;
	to->stacks.usd_hi = from->stacks.usd_hi;
	to->stacks.psp_lo = from->stacks.psp_lo;
	to->stacks.psp_hi = from->stacks.psp_hi;
	to->stacks.pcsp_lo = from->stacks.pcsp_lo;
	to->stacks.pcsp_hi = from->stacks.pcsp_hi;
	to->stacks.pshtp = from->stacks.pshtp;
	to->stacks.pcshtp = from->stacks.pcshtp;
	to->crs.cr0_lo = from->crs.cr0_lo;
	to->crs.cr0_hi = from->crs.cr0_hi;
	to->crs.cr1_lo = from->crs.cr1_lo;
	to->crs.cr1_hi = from->crs.cr1_hi;
	to->sys_rval = from->sys_rval;
	to->flags = from->flags;
}

static inline int setup_frame(struct sigcontext __user *sigc,
		struct extra_ucontext __user *extra, const pt_regs_t *user_regs)
{
	struct trap_pt_regs *trap = user_regs->trap;
	register struct k_sigaction *ka = &current_thread_info()->ksig.ka;
	int	rval;
	int	i;
	char	tag;
	int	sc_need_rstrt = 0;

	rval = __put_user(AS_WORD(user_regs->crs.cr0_lo), &sigc->cr0_lo);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->crs.cr0_hi),
				    &sigc->cr0_hi);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->crs.cr1_lo),
				    &sigc->cr1_lo);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->crs.cr1_hi),
				    &sigc->cr1_hi);
	
	rval = (rval) ?: __put_user(user_regs->stacks.top, &sigc->sbr);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->stacks.usd_lo),
				    &sigc->usd_lo);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->stacks.usd_hi),
				    &sigc->usd_hi);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->stacks.psp_lo),
				    &sigc->psp_lo);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->stacks.psp_hi),
				    &sigc->psp_hi);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->stacks.pcsp_lo),
				    &sigc->pcsp_lo);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->stacks.pcsp_hi),
				    &sigc->pcsp_hi);

        /* for binary compiler */
	if (unlikely(TASK_IS_BINCO(current))) {
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
		int mlt_num = trap ? trap->mlt_state.num : 0;
#endif

		rval = (rval) ?: __put_user(
					AS_WORD(current_thread_info()->upsr),
					&sigc->upsr);
		rval = (rval) ?: __put_user(user_regs->rpr_hi, &sigc->rpr_hi);
		rval = (rval) ?: __put_user(user_regs->rpr_lo, &sigc->rpr_lo);

		/* copy MLT */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
		if (!rval && mlt_num) {
			if (copy_to_user((void __user *) sigc->mlt,
					trap->mlt_state.mlt,
					sizeof(e2k_mlt_entry_t) * mlt_num))
				rval |= -EFAULT;
		}
		if (!rval && (mlt_num < NATIVE_MAX_MLT_SIZE)) {
			if (clear_user((void *)&sigc->mlt[mlt_num * 3],
					sizeof(e2k_mlt_entry_t) *
					(NATIVE_MAX_MLT_SIZE - mlt_num)))
				rval |= -EFAULT;
		}
#endif
	}

	if (trap) {
		u64 data;

		for (i = 0; i < min(MAX_TC_SIZE, HW_TC_SIZE); i++) {
			rval = (rval) ?: __put_user(trap->tcellar[i].address,
						    &sigc->trap_cell_addr[i]);
			rval = (rval) ?: __put_user(trap->tcellar[i].data,
						    &sigc->trap_cell_val[i]);
			rval = (rval) ?: __put_user(
						trap->tcellar[i].condition.word,
						&sigc->trap_cell_info[i]);
			load_value_and_tagd(
					&trap->tcellar[i].data, &data, &tag);
			rval = (rval) ?: __put_user(tag,
						    &sigc->trap_cell_tag[i]);
		}

		/* TIR */
		rval = (rval) ?: __put_user(trap->nr_TIRs, &sigc->nr_TIRs);
		for (i = 0; i <= trap->nr_TIRs; i++) {
			rval = (rval) ?: __put_user(
						trap->TIRs[i].TIR_hi.TIR_hi_reg,
						&sigc->tir_hi[i]);
			rval = (rval) ?: __put_user(
						trap->TIRs[i].TIR_lo.TIR_lo_reg,
						&sigc->tir_lo[i]);
		}

		rval = (rval) ?: __put_user(trap->tc_count / 3,
					    &extra->tc_count);
		rval = (rval) ?: __put_user(trap->curr_cnt, &extra->curr_cnt);
	} else {
		rval = (rval) ?: __put_user(0, &sigc->nr_TIRs);
		rval = (rval) ?: __put_user(0ULL, &sigc->tir_hi[0]);
		rval = (rval) ?: __put_user(0ULL, &sigc->tir_lo[0]);
		rval = (rval) ?: __put_user(0, &extra->tc_count);
		rval = (rval) ?: __put_user(-1, &extra->curr_cnt);
	}

	rval = (rval) ?: __put_user(AW(user_regs->ctpr1), &extra->ctpr1);
	rval = (rval) ?: __put_user(AW(user_regs->ctpr2), &extra->ctpr2);
	rval = (rval) ?: __put_user(AW(user_regs->ctpr3), &extra->ctpr3);

	if (from_syscall(user_regs) &&
			((user_regs->sys_rval == -ERESTARTNOINTR) ||
			 (user_regs->sys_rval == -ERESTARTSYS) &&
			 (ka->sa.sa_flags & SA_RESTART)))
		sc_need_rstrt = 1;
	rval = (rval) ?: __put_user(sc_need_rstrt, &extra->sc_need_rstrt);

	/* size of saved extra elements */
	rval = (rval) ?: __put_user(sizeof(struct extra_ucontext) - sizeof(int),
				    &extra->sizeof_extra_uc);

	/* DAM */
	SAVE_DAM(current_thread_info()->dam);
	for (i = 0; i < DAM_ENTRIES_NUM; i++)
		rval = (rval) ?: __put_user(current_thread_info()->dam[i],
					    &sigc->dam[i]);

	return rval;
}

#ifdef CONFIG_PROTECTED_MODE
static inline int setup_prot_frame(struct sigcontext_prot *sigc,
				   const pt_regs_t *user_regs)
{
	int rval;

	rval = __put_user(AS_WORD(user_regs->crs.cr0_lo), &sigc->cr0_lo);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->crs.cr0_hi),
				    &sigc->cr0_hi);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->crs.cr1_lo),
				    &sigc->cr1_lo);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->crs.cr1_hi),
				    &sigc->cr1_hi);

	rval = (rval) ?: __put_user(user_regs->stacks.top, &sigc->sbr);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->stacks.usd_lo),
				    &sigc->usd_lo);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->stacks.usd_hi),
				    &sigc->usd_hi);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->stacks.psp_lo),
				    &sigc->psp_lo);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->stacks.psp_hi),
				    &sigc->psp_hi);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->stacks.pcsp_lo),
				    &sigc->pcsp_lo);
	rval = (rval) ?: __put_user(AS_WORD(user_regs->stacks.pcsp_hi),
				    &sigc->pcsp_hi);

	return rval;
}

/*
 * This function fixes alignment of the given pointer 'ptr' towards upper bound:
 * 'alignment' - alignment value (8 or 16)
 * Returning value: pointer aligned.
 */
static inline char *align_ptr_up(const char *ptr, const int alignment)
{
	char *aligned_ptr;

	if (((unsigned long) ptr) % alignment)
		aligned_ptr = (char *) (((unsigned long) ptr
			+ alignment - 1) & ~(alignment - 1));
	else
		aligned_ptr = (char *)ptr;

	return aligned_ptr;
}

#define PROTECTED_ALIGNMENT_VALUE 16

/*
 * This function updates siginfo structure that kernel formed to pass it
 *             to signal handler procedure operating in the protected mode.
 * It does the following:
 * (a) if _sigval field of the siginfo structure stores pointer (sival_ptr),
 *     and the pointer is available in the sival_ptr_list_head list, it
 *     takes the descriptor linked to that pointer, and puts it into
 *     the siginfo structure following protected alignment value;
 * (b) if _sigval field of the siginfo structure stores integer (sival_int)
 *     value, it shifts the value in memory to fix misalignment between
 *     kernel (8 byte base) and protected user memory space (16 byte).
 */
static inline int copy_siginfo_to_user_prot(rt_sigframe_t __user *frame,
					    kernel_siginfo_t *info)
{
	int ret;
	siginfo_t __user *siginfo_ptr = &frame->info;
	char      __user *sigval_prot_ptr;
	void __user *ptr; /* kernel pointer in the siginfo structure */
	struct sival_ptr_list *curr_el;

	ret = copy_siginfo_to_user(&frame->info, info);
	if (ret)
		return ret;

	ptr = info->si_ptr;
	if (!ptr) {
		DbgSCP("Empty 'siginfo_t *info->si_ptr'\n");
		return ret;
	}

	sigval_prot_ptr = align_ptr_up((char *)(&siginfo_ptr->si_ptr),
				       PROTECTED_ALIGNMENT_VALUE);

	DebugHS("ptr=0x%px; si_ptr=0x%llx; sigval_prot_ptr=0x%px\n",
		ptr, &siginfo_ptr->si_ptr, sigval_prot_ptr);

	/* We look thru sival_ptr_list to find a record with the same ptr:
	 */
	curr_el = get_descriptor_attrs(ptr, 0 /*signum*/);

	DebugHS("curr_el=0x%px\n", curr_el);
	if (!curr_el) {
		/*
		 * This may be integer value in siginfo.sival_int field:
		 * Updating field alignment for PM: simply
		 *      moving dwords #6,7 to position #8,9:
		 */
		if ((int)((long)ptr & PAGE_MASK)) {
			/* this is definitely pointer; issuing alert */
			DbgSCP_ALERT("No record for 0x%px in sival_ptr_list\n",
				     ptr);
		} else { /* there can be trash in high 32 bits;
			  * issuing debug message
			  */
			DbgSCP("Not a pointer in '(siginfo_t *)info->si_ptr': 0x%px\n",
			       ptr);
			DbgSCP("from=0x%px [0x%llx] --> to=0x%px [0x%llx]\n",
				&siginfo_ptr->si_ptr, ptr, sigval_prot_ptr,
				*(u64 __user *)sigval_prot_ptr);
		}
		ret = __put_user((u64 __user)ptr,
				 (u64 __user *)sigval_prot_ptr);
	} else {
		/*
		 * Simply adding tags to user_ptr_lo/_hi and
		 *           set these to sigvalptr + 4/5):
		 * --> we need to restore it for PM:
		 */
		DebugHS("curr_el: _lo=0x%llx _hi=0x%llx _tags=0x%x\n",
			curr_el->user_ptr_lo, curr_el->user_ptr_hi,
			curr_el->user_tags);
		TRY_USR_PFAULT {
			NATIVE_STORE_TAGGED_QWORD(
				(e2k_ptr_t *)sigval_prot_ptr,
				curr_el->user_ptr_lo, curr_el->user_ptr_hi,
				curr_el->user_tags & 0xf,
				curr_el->user_tags >> 4);
		} CATCH_USR_PFAULT {
			return -EFAULT;
		} END_USR_PFAULT
	}
	return ret;
}
#else
# define setup_prot_frame(...) do { } while (0)
# define copy_siginfo_to_user_prot(...) do { } while (0)
#endif	/* CONFIG_PROTECTED_MODE */

static inline int setup_rt_frame(rt_sigframe_t __user *frame,
				 kernel_siginfo_t *info,
				 const struct pt_regs *regs)
{
	sigset_t *set = sigmask_to_save();
	compat_sigset_t *cset = (compat_sigset_t *) set;
	struct k_sigaction *ka = &current_thread_info()->ksig.ka;
	int ret;

	if (!access_ok(frame, sizeof(*frame))) {
		DebugHS("access failed to user stack frame %px\n", frame);
		return -EFAULT;
	}
	DebugHS("info=%px signal=%d ->thread.flags=0x%lx IS_PROTECTED=%ld\n",
		info, current_thread_info()->ksig.sig, current->thread.flags,
		TASK_IS_PROTECTED(current));

	if (TASK_IS_PROTECTED(current)) {
		e2k_ptr_t ss_sp;

		ret = setup_prot_frame(&frame->uc_prot.uc_mcontext, regs);
		ret = (ret) ?: __copy_to_user(&frame->uc_prot.uc_sigmask,
					      set, sizeof(*set));

		AW(ss_sp).lo = MAKE_AP_LO(current->sas_ss_sp,
				current->sas_ss_size, 0, 3);
		AW(ss_sp).hi = MAKE_AP_HI(current->sas_ss_sp,
				current->sas_ss_size, 0, 3);
		ret = (ret) ?: __put_user(AW(ss_sp).lo,
					&AW(frame->uc_prot.uc_stack.ss_sp).lo);
		ret = (ret) ?: __put_user(AW(ss_sp).hi,
					&AW(frame->uc_prot.uc_stack.ss_sp).hi);
		ret = (ret) ?: __put_user(sas_ss_flags(
						AS(regs->stacks.usd_lo).base),
					&frame->uc_prot.uc_stack.ss_flags);
		ret = (ret) ?: __put_user(current->sas_ss_size,
					&frame->uc_prot.uc_stack.ss_size);
	} else if (!(current->thread.flags & E2K_FLAG_32BIT)) {
		ret = setup_frame(&frame->uc.uc_mcontext,
				&frame->uc.uc_extra, regs);
		ret = (ret) ?: __copy_to_user(&frame->uc.uc_sigmask,
					      set, sizeof(*set));
		ret = (ret) ?: __save_altstack(&frame->uc.uc_stack,
					AS(regs->stacks.usd_lo).base);
	} else {
		ret = setup_frame(&frame->uc_32.uc_mcontext,
				&frame->uc_32.uc_extra, regs);
		ret = (ret) ?: __copy_to_user(&frame->uc_32.uc_sigmask,
					      cset, sizeof(*cset));
		ret = (ret) ?: __compat_save_altstack(&frame->uc_32.uc_stack,
					AS(regs->stacks.usd_lo).base);
	}

	/*
	 * Must we set additional flags?
	 */
	if (!(ka->sa.sa_flags & SA_SIGINFO))
		return ret;

	if (TASK_IS_PROTECTED(current)) {
		ret = (ret) ?: copy_siginfo_to_user_prot(frame, info);
		ret = (ret) ?: __put_user(0, &frame->uc_prot.uc_flags);
		ret = (ret) ?: __put_user(0, &AW(frame->uc_prot.uc_link).lo);
		ret = (ret) ?: __put_user(0, &AW(frame->uc_prot.uc_link).hi);
	} else if (!(current->thread.flags & E2K_FLAG_32BIT)) {
		ret = (ret) ?: copy_siginfo_to_user(&frame->info, info);
		ret = (ret) ?: __put_user(0, &frame->uc.uc_flags);
		ret = (ret) ?: __put_user(0, &frame->uc.uc_link);
	} else {
		if (current->thread.flags & E2K_FLAG_64BIT_BINCO)
			ret = (ret) ?: copy_siginfo_to_user(&frame->info, info);
		else
			ret = (ret) ?: copy_siginfo_to_user32(
						&frame->compat_info, info);

		ret = (ret) ?: __put_user(0, &frame->uc_32.uc_flags);
		ret = (ret) ?: __put_user(0, &frame->uc_32.uc_link);
	}

	DebugHS("ret=%d info=0x%lx  info->si_value: [int]=%d [ptr]=0x%llx\n",
		ret, info, info->_sifields._rt._sigval.sival_int,
		info->_sifields._rt._sigval.sival_ptr);

	return ret;
}

static inline void copy_user_ctpr(e2k_ctpr_t *dst, e2k_ctpr_t val)
{
	/* Disallow privileged or reserved values */
	if (AS(val).opc == 2 ||
	    (AS(val).ta_tag != CTPLL_CT_TAG && AS(val).ta_tag != CTPNL_CT_TAG))
		return;

	AW(*dst) = 0;
	AS(*dst).ta_base = AS(val).ta_base & ~7ULL;
	AS(*dst).opc = AS(val).opc;
	AS(*dst).ta_tag = AS(val).ta_tag;
	AS(*dst).ipd = AS(val).ipd;
}

int restore_rt_frame(rt_sigframe_t __user *frame, struct k_sigaction *ka)
{
	unsigned long long __user *cr0_hi_ptr;
	struct extra_ucontext __user *uc_extra_ptr;
	void __user *set_ptr;
	sigset_t set;
	int ret = 0;

	if (!access_ok(frame, sizeof(*frame)))
		return -EFAULT;

	if (TASK_IS_PROTECTED(current)) {
		e2k_ptr_t ptr;
		stack_t stack;
		mm_segment_t seg;
		int ret;

		ret = __get_user(stack.ss_flags,
				 &frame->uc_prot.uc_stack.ss_flags);
		ret = (ret) ?: __get_user(stack.ss_size,
					&frame->uc_prot.uc_stack.ss_size);
		ret = (ret) ?: __get_user(AW(ptr).lo,
					&AW(frame->uc_prot.uc_stack.ss_sp).lo);
		ret = (ret) ?: __get_user(AW(ptr).hi,
					&AW(frame->uc_prot.uc_stack.ss_sp).hi);
		if (ret)
			return -EFAULT;

		stack.ss_sp = (void *) (AS(ptr).ap.base + AS(ptr).ap.curptr);

		seg = get_fs();
		set_fs(KERNEL_DS);
		ret = restore_altstack(&stack);
		set_fs(seg);

		set_ptr = &frame->uc_prot.uc_sigmask;
		cr0_hi_ptr = &frame->uc_prot.uc_mcontext.cr0_hi;
		uc_extra_ptr = &frame->uc_prot.uc_extra;
	} else if (!(current->thread.flags & E2K_FLAG_32BIT)) {
		ret = restore_altstack(&frame->uc.uc_stack);

		set_ptr = &frame->uc.uc_sigmask;
		cr0_hi_ptr = &frame->uc.uc_mcontext.cr0_hi;
		uc_extra_ptr = &frame->uc.uc_extra;
	} else {
		ret = compat_restore_altstack(&frame->uc_32.uc_stack);

		set_ptr = (sigset_t *) &frame->uc_32.uc_sigmask;
		cr0_hi_ptr = &frame->uc_32.uc_mcontext.cr0_hi;
		uc_extra_ptr = &frame->uc_32.uc_extra;
	}

	if (ret || __copy_from_user(&set, set_ptr, sizeof(set)))
		return -EFAULT;

	if (ka->sa.sa_flags & SA_SIGINFO) {
		e2k_ctpr_t ctpr1, ctpr2, ctpr3;
		e2k_cr0_hi_t cr0_hi;
		struct pt_regs *regs = current_pt_regs();

		ret = (ret) ?: __get_user(AW(cr0_hi), cr0_hi_ptr);
		ret = (ret) ?: __get_user(AW(ctpr1), &uc_extra_ptr->ctpr1);
		ret = (ret) ?: __get_user(AW(ctpr2), &uc_extra_ptr->ctpr2);
		ret = (ret) ?: __get_user(AW(ctpr3), &uc_extra_ptr->ctpr3);
		if (ret)
			return -EFAULT;

		if (AS(regs->crs.cr0_hi).ip != AS(cr0_hi).ip &&
				(AS(cr0_hi).ip << 3) < TASK_SIZE) {
			/*
			 * There could be such situation:
			 *   - user's signal handler changes IP
			 *   - kernel ignores the trap cellar in this case and
			 *     start to deliver the next signal
			 *   - user's signal handler doesn't change IP
			 *   - kernel starts to handle trap cellar again
			 * Kernel should never handle trap cellar after user's
			 * signal handler changed IP. So kernel should give up
			 * the trap cellar.
			 */
			if (regs->trap) {
				regs->trap->tc_count = 0;
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
				regs->trap->flags &= ~TRAP_RP_FLAG;
#endif
			}

			AS(regs->crs.cr0_hi).ip = AS(cr0_hi).ip;
		}

		if (TASK_IS_BINCO(current)) {
			copy_user_ctpr(&regs->ctpr1, ctpr1);
			copy_user_ctpr(&regs->ctpr2, ctpr2);
			copy_user_ctpr(&regs->ctpr3, ctpr3);
		}
	}

	set_current_blocked(&set);

	return 0;
}

#define	synchronize_user_stack() {} /* Nothing to do. RF is already flushed. */
#define	save_and_clear_fpu()	 {} /* NEEDSWORK */


#ifdef	CONFIG_VIRTUALIZATION
# define printk printk_fixed_args
# define panic panic_fixed_args
static __always_inline notrace __interrupt
void return_to_the_func(long fn, bool system_fn)
{
	register thread_info_t *ti = current_thread_info();
	register e2k_cr1_lo_t	cr1_lo;
	register e2k_cr0_hi_t 	cr0_hi;
	register e2k_cuir_t	cuir;
	register e2k_psr_t	psr;

	cr1_lo = NATIVE_NV_READ_CR1_LO_REG();
	cr0_hi = NATIVE_NV_READ_CR0_HI_REG();

	AS_WORD(psr) = 0;
	AS_STRUCT(psr).sge = 1;
	AS_STRUCT(psr).ie = 1;			/* sti(); */
	AS_STRUCT(psr).nmie = 1;		/* nm sti(); */
	AS_STRUCT(psr).pm = (system_fn) ? 1 : 0;
	AS_STRUCT(cr1_lo).psr = AS_WORD(psr);
	AS_STRUCT(cr0_hi).ip = fn >> 3;		/* start user IP */

	AS_WORD(cuir) = 0;	// AS_STRUCT(cuir).checkup = 0 too
	AS_STRUCT(cr1_lo).cuir = AS_WORD(cuir);
	//TODO
	panic("should write actual cui of guest function into %%cr1_lo as hardware won't load it automatically for us since iset v6\n");

	if (!native_psr_irqs_disabled())
		panic_fixed_args("go2user: under sti\n");
	NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG(cr1_lo);
	NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG(cr0_hi);

	sti_return();

	if (TASK_IS_PROTECTED(current)) {
		e2k_pusd_lo_t pusd_lo;

		pusd_lo = READ_PUSD_LO_REG();
		AS(pusd_lo).p = 1;
		/*
		 * correct usd as if we are entered by call
		 */
		AS(pusd_lo).psl += 1;
		WRITE_PUSD_LO_REG(pusd_lo);
		ENABLE_US_CLW();
	}

	/* Restore user global registers. This is needed only for binco, */
	/* since for e2k applications g16-g31 registers are actually local. */
	if (TASK_IS_BINCO(current)) {
		NATIVE_RESTORE_KERNEL_GREGS(&current_thread_info()->k_gregs);
	} else {
		CLEAR_KERNEL_GREGS();
	}

	WRITE_CUTD_REG(READ_CUTD_REG());

	/* the follow function should restore user UPSR state */
	complete_go2user(ti, fn);

	/* Prevent kernel information leakage */
#if E2K_MAXSR != 112
# error Must clear all registers here
#endif
	E2K_CLEAR_RF_112();
}
noinline notrace __interrupt __section(".entry.text")
void go2guest(long fn, bool priv_guest)
{
	return_to_the_func(fn, priv_guest);
}
# undef printk
# undef panic
#endif	/* CONFIG_VIRTUALIZATION */

static int copy_context_to_signal_stack(
		struct signal_stack_context __user *context,
		struct local_gregs *l_gregs, struct pt_regs *regs,
		struct ksignal *ksig)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);

	ret = __copy_to_user_with_tags(&context->regs, regs, sizeof(*regs));

	if (regs->trap) {
		ret = ret ?: __copy_to_user_with_tags(&context->trap,
					regs->trap, sizeof(*regs->trap));
		/* This pointer must not be accessed directly since signal
		 * stack could be reallocated (use signal_pt_regs_to_trap()
		 * instead), so put bogus value in it to help catch errors. */
		ret = ret ?: __put_user((void *) 1, &context->regs.trap);

		if (regs->trap->sbbp) {
			ret = ret ?: __copy_to_user(&context->sbbp, regs->trap->sbbp,
					sizeof(regs->trap->sbbp[0]) * SBBP_ENTRIES_NUM);
			ret = ret ?: __put_user(context->sbbp,
						&context->trap.sbbp);
		}
	}

	if (regs->aau_context) {
		ret = ret ?: __copy_to_user(&context->aau_regs,
				regs->aau_context, sizeof(*regs->aau_context));
		/* This pointer must not be accessed directly since signal
		 * stack could be reallocated, so put bogus value in it to
		 * help catch errors. */
		ret = ret ?: __put_user((void *) 1, &context->regs.aau_context);
	}

	ret = ret ?: __copy_to_user(&context->sigact, &ksig->ka,
				    sizeof(ksig->ka));

	if (l_gregs) {
		ret = ret ?: __copy_to_user_with_tags(&context->l_gregs,
				l_gregs, sizeof(*l_gregs));
	}

	clear_ts_flag(ts_flag);

	return ret ? -EFAULT : 0;
}

/*
 * Follow function is sutable for native, host and guest kernels
 */
notrace noinline __interrupt __section(".entry.text")
void sighandler_trampoline_continue(void)
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
	SET_KERNEL_UPSR_WITH_DISABLED_NMI();

	/*
	 * Set pointer to VCPU state to enable interface host <-> guest
	 * (it is actual only for guest kernel)
	 */
	ONLY_SET_GUEST_GREGS(thread_info);

	E2K_JUMP(do_sigreturn);
}

/**
 * push_signal_stack - make sure there is enough space in the signal stack
 *		       to store interrupted user context
 *
 * We use privileged area at the end of user space since we have
 * to save privileged structures such as trap cellar or CTPRs.
 */
static struct signal_stack_context __user *push_signal_stack(void)
{
	struct thread_info *ti = current_thread_info();
	unsigned long context_size, address;
	struct signal_stack_context __user *context;

	/*
	 * Is there enough space already?
	 */
	if (ti->signal_stack.size - ti->signal_stack.used >= sizeof(*context)) {
		context = (struct signal_stack_context __user *)
				(ti->signal_stack.base + ti->signal_stack.used);
		ti->signal_stack.used += sizeof(*context);

		return context;
	}

	context_size = sizeof(struct signal_stack_context);
	context_size = round_up(context_size, PAGE_SIZE);

	/*
	 * Allocate if this is the first signal
	 */
	if (!ti->signal_stack.base) {
		unsigned long ti_flags = TS_MMAP_PRIVILEGED |
					 TS_MMAP_SIGNAL_STACK;

		ti->status |= ti_flags;
		address = vm_mmap_notkillable(NULL, USER_HW_STACKS_BASE,
				context_size, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, 0);
		ti->status &= ~ti_flags;

		if (IS_ERR_VALUE(address))
			return ERR_PTR(address);

		ti->signal_stack.base = address;
		ti->signal_stack.size = context_size;
		ti->signal_stack.used = sizeof(*context);

		return (struct signal_stack_context __user *) address;
	}

	/*
	 * Expand already allocated area
	 */
	address = remap_e2k_stack(ti->signal_stack.base, ti->signal_stack.size,
			ti->signal_stack.size + context_size, false);
	if (IS_ERR_VALUE(address))
		return ERR_PTR(address);

	ti->signal_stack.base = address;
	ti->signal_stack.size += context_size;

	context = (struct signal_stack_context __user *)
			(ti->signal_stack.base + ti->signal_stack.used);
	ti->signal_stack.used += sizeof(*context);

	return context;
}

/**
 * pop_signal_stack - counterpart to push_signal_stack()
 */
static struct signal_stack_context __user *do_get_signal_stack(bool push)
{
	struct thread_info *ti = current_thread_info();
	struct signal_stack_context __user *context;
	unsigned long used = ti->signal_stack.used;

	if (WARN_ON_ONCE(used < sizeof(*context)))
		do_exit(SIGKILL);

	used -= sizeof(*context);
	context = (struct signal_stack_context __user *)
				(ti->signal_stack.base + used);
	if (push) {
		ti->signal_stack.used = used;
	}

	return context;
}
struct signal_stack_context __user *get_signal_stack(void)
{
	return do_get_signal_stack(false);
}
struct signal_stack_context __user *pop_signal_stack(void)
{
	return do_get_signal_stack(true);
}

/**
 * free_signal_stack - remove signal stack area on thread or context exit
 */
void free_signal_stack(struct signal_stack *signal_stack)
{
	int ret;

	if (!signal_stack->base)
		return;

	ret = vm_munmap_notkillable(signal_stack->base, signal_stack->size);
	if (ret) {
		pr_err_ratelimited("%s [%d]: Could not free signal stack, error %d\n",
				current->comm, current->pid, ret);
	}

	signal_stack->base = 0;
	signal_stack->size = 0;
	signal_stack->used = 0;
}

/**
 * setup_signal_stack - save priviliged part of interrupted user context
 * to a special privileged area in user space.
 */
int setup_signal_stack(struct pt_regs *regs, bool is_signal)
{
	struct signal_stack_context __user *context;
	struct local_gregs l_gregs, *gregs;
	int ret;

	/* FIXME; macros TASK_IS_BINCO() should be updated to provide */
	/* guest user process case: is one running under binary compiler */
	if (!TASK_IS_BINCO(current)) {
		save_local_glob_regs(&l_gregs, is_signal);
		gregs = &l_gregs;
	} else {
		gregs = NULL;
	}

	context = push_signal_stack();
	if (IS_ERR(context))
		return PTR_ERR(context);

	ret = copy_context_to_signal_stack(context, gregs, regs,
			&current_thread_info()->ksig);
	if (ret)
		pop_signal_stack();

	return ret;
}

static int prepare_sighandler_trampoline(struct e2k_stacks *stacks)
{
	e2k_mem_crs_t *k_crs, crs;
	unsigned long flags;
	int ret;

	/*
	 * Prepare 'sighandler_trampoline' frame
	 */
	ret = chain_stack_frame_init(&crs, sighandler_trampoline,
			current_thread_info()->u_stack.size,
			E2K_KERNEL_PSR_DISABLED, 0, 0, false);
	if (ret)
		return ret;

	/*
	 * Copy the new frame into chain stack
	 *
	 * See user_hw_stacks_copy_full() for an explanation why this frame
	 * is located at (AS(ti->k_pcsp_lo).base).
	 */
	k_crs = (e2k_mem_crs_t *) AS(current_thread_info()->k_pcsp_lo).base;

	raw_all_irq_save(flags);
	E2K_FLUSHC;
	/* User frame from *k_crs has been copied to userspace
	 * already in user_hw_stacks_copy_full() */
	*k_crs = crs;
	/* OK, now account for the new frame in *k_crs. */
	AS(stacks->pcsp_hi).ind += SZ_OF_CR;
	raw_all_irq_restore(flags);

	return 0;
}

int prepare_sighandler_frame(struct e2k_stacks *stacks,
				u64 pframe[32], e2k_mem_crs_t *crs)
{
	struct thread_info *ti = current_thread_info();
	struct ksignal *ksig = &ti->ksig;
	rt_sigframe_t *rt_sigframe;
	void *uc, *u_si;
	u64 u_si_size, uc_size;
	size_t pframe_size;
	unsigned long reg1_offset;
	e2k_usd_lo_t usd_lo;
	e2k_usd_hi_t usd_hi;
	e2k_sbr_t sbr;
	int ret;

	/*
	 * Calculate ucontext/siginfo address
	 */
	rt_sigframe = (rt_sigframe_t *) ti->u_stack.top;

	if (!(ksig->ka.sa.sa_flags & SA_SIGINFO)) {
		/*
		 * On Linux systems we pass 'struct sigcontext' in 2nd argument
		 */
		if (TASK_IS_PROTECTED(current)) {
			u_si = &rt_sigframe->uc_prot.uc_mcontext;
			u_si_size = sizeof(rt_sigframe->uc_prot.uc_mcontext);
		} else if (!(current->thread.flags & E2K_FLAG_32BIT)) {
			u_si = &rt_sigframe->uc.uc_mcontext;
			u_si_size = sizeof(rt_sigframe->uc.uc_mcontext);
		} else {
			u_si = &rt_sigframe->uc_32.uc_mcontext;
			u_si_size = sizeof(rt_sigframe->uc_32.uc_mcontext);
		}

		uc = NULL;
		uc_size = 0;
	} else if (TASK_IS_PROTECTED(current)) {
		u_si = &rt_sigframe->info;
		u_si_size = sizeof(rt_sigframe->info);
		uc = &rt_sigframe->uc_prot;
		uc_size = sizeof(rt_sigframe->uc_prot);
	} else if (!(current->thread.flags & E2K_FLAG_32BIT)) {
		u_si = &rt_sigframe->info;
		u_si_size = sizeof(rt_sigframe->info);
		uc = &rt_sigframe->uc;
		uc_size = sizeof(rt_sigframe->uc);
	} else {
		if (current->thread.flags & E2K_FLAG_64BIT_BINCO) {
			u_si = &rt_sigframe->info;
			u_si_size = sizeof(rt_sigframe->info);
		} else {
			u_si = &rt_sigframe->compat_info;
			u_si_size = sizeof(rt_sigframe->compat_info);
		}
		uc = &rt_sigframe->uc_32;
		uc_size = sizeof(rt_sigframe->uc_32);
	}

	/*
	 * Update data stack
	 */
	usd_hi = stacks->usd_hi;
	AS(usd_hi).size = ti->u_stack.size;
	AW(sbr) = ti->u_stack.top;

	if (!TASK_IS_PROTECTED(current)) {
		usd_lo = stacks->usd_lo;
		AS(usd_lo).base = ti->u_stack.top;
	} else {
		e2k_pusd_lo_t pusd_lo;

		AW(pusd_lo) = AW(stacks->usd_lo);
		AS(pusd_lo).base = ti->u_stack.top & 0xffffffffULL;
		AS(pusd_lo).p = 1;
		AS(pusd_lo).psl += 1; /* signal handler */

		AW(usd_lo) = AW(pusd_lo);
	}

	stacks->usd_lo = usd_lo;
	stacks->usd_hi = usd_hi;
	stacks->top = round_up(AW(sbr), E2K_ALIGN_STACK_BASE_REG);

	/*
	 * Update procedure stack
	 */
	pframe_size = (TASK_IS_PROTECTED(current)) ? (32 * 8) : (16 * 8);
	memset(pframe, 0, pframe_size);

	if (machine.native_iset_ver < E2K_ISET_V5)
		reg1_offset = 1;
	else
		reg1_offset = 2;
	if (!TASK_IS_PROTECTED(current)) {
		pframe[0] = ksig->sig;
		pframe[0 + reg1_offset] = (u64) u_si;
		pframe[4] = (u64) uc;
	} else {
		__NATIVE_STORE_TAGGED_QWORD(&pframe[0],
			MAKE_AP_LO((u64) rt_sigframe, 64, 0UL, RW_ENABLE),
			MAKE_AP_HI((u64) rt_sigframe, 64, 0UL, RW_ENABLE),
			E2K_AP_LO_ETAG, E2K_AP_HI_ETAG, 8 * reg1_offset);
		pframe[4] = ksig->sig;
		__NATIVE_STORE_TAGGED_QWORD(&pframe[8],
			MAKE_AP_LO((u64) u_si, u_si_size, 0UL, RW_ENABLE),
			MAKE_AP_HI((u64) u_si, u_si_size, 0UL, RW_ENABLE),
			E2K_AP_LO_ETAG, E2K_AP_HI_ETAG, 8 * reg1_offset);
		__NATIVE_STORE_TAGGED_QWORD(&pframe[12],
			MAKE_AP_LO((u64) uc, uc_size, 0UL, RW_ENABLE),
			MAKE_AP_HI((u64) uc, uc_size, 0UL, RW_ENABLE),
			E2K_AP_LO_ETAG, E2K_AP_HI_ETAG, 8 * reg1_offset);
	}

	/*
	 * Update chain stack
	 */
	ret = chain_stack_frame_init(crs, ksig->ka.sa.sa_handler, AS(usd_hi).size,
			E2K_USER_INITIAL_PSR, pframe_size / EXT_4_NR_SZ,
			(pframe_size / EXT_4_NR_SZ) / 2, true);
	if (ret)
		return ret;

	/*
	 * Flush CUT cache after modification of CUT (#117859)
	 */
	WRITE_CUTD_REG(READ_CUTD_REG());

	return 0;
}

static int copy_sighandler_frame(struct e2k_stacks *stacks,
				 u64 *pframe, e2k_mem_crs_t *crs)
{
	size_t pframe_size;
	void __user *u_pframe;
	unsigned long flags, ts_flag;
	e2k_mem_crs_t *k_crs;
	int ret;

	u_pframe = (void __user *) (AS(stacks->psp_lo).base +
				    AS(stacks->psp_hi).ind);
	pframe_size = (TASK_IS_PROTECTED(current)) ? (32 * 8) : (16 * 8);

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __copy_to_user_with_tags(u_pframe, pframe, pframe_size);
	clear_ts_flag(ts_flag);
	if (ret)
		return -EFAULT;

	AS(stacks->psp_hi).ind += pframe_size;

	/*
	 * handle_sys_call() does not restore %cr registers from pt_regs
	 * for performance reasons, so update chain stack in memory too.
	 *
	 * See user_hw_stacks_copy_full() for an explanation why this frame
	 * is located at (AS(ti->k_pcsp_lo).base + SZ_OF_CR).
	 */
	k_crs = (e2k_mem_crs_t *) AS(current_thread_info()->k_pcsp_lo).base;

	raw_all_irq_save(flags);
	E2K_FLUSHC;
	*(k_crs + 1) = *crs;
	/* Same as prepare_sighandler_trampoline(): now account for the new
	 * frame in *k_crs.  Its previous contents have been copied already
	 * by user_hw_stacks_copy_full(crs != NULL). */
	AS(stacks->pcsp_hi).ind += SZ_OF_CR;
	raw_all_irq_restore(flags);

	/* See comment in user_hw_stacks_copy_full() */
	BUG_ON(PCSHTP_SIGN_EXTEND(stacks->pcshtp) != SZ_OF_CR);

	return 0;
}

int signal_rt_frame_setup(pt_regs_t *regs)
{
	struct trap_pt_regs		*trap = regs->trap;
	register thread_info_t		*ti = current_thread_info();
	register struct k_sigaction	*ka = &ti->ksig.ka;
	register kernel_siginfo_t	*info = &ti->ksig.info;
	register rt_sigframe_t __user	*rt_sigframe;
	u64 ss_sp, ss_stk_size, tmp_sp, tmp_sz;

	DebugHS("start addr %lx regs %px fn %lx\n",
		(trap) ? trap->tcellar[trap->curr_cnt].address : 0UL,
		regs, ka->sa.sa_handler);

	BUG_ON(!user_mode(regs));
	BUILD_BUG_ON(E2K_ALIGN_STACK !=
			max(E2K_ALIGN_USTACK_SIZE, E2K_ALIGN_PUSTACK_SIZE));

	/* Perform fixup for the pre-signal frame. */
	rseq_signal_deliver(&ti->ksig, regs);

	ss_sp		= user_stack_pointer(regs);
	ss_stk_size	= AS(regs->stacks.usd_hi).size;

	DebugHS("ss_sp 0x%llx size 0x%llx\n", ss_sp, ss_stk_size);

	/*
	 * This is the X/Open sanctioned signal stack switching
	 * to alt stack.
	 */
	if (ka->sa.sa_flags & SA_ONSTACK) {
		if (sas_ss_flags(ss_sp) == 0) {
			u64 alt_ss_stk_base = round_up(current->sas_ss_sp,
						       E2K_ALIGN_STACK);
			u64 alt_ss_stk_size = round_down(current->sas_ss_size +
					current->sas_ss_sp - alt_ss_stk_base,
					E2K_ALIGN_STACK);

			DebugHS("SA_ONSTACK ss 0x%lx sz 0x%lx, after aligning "
				"ss 0x%llx sz 0x%llx, need 0x%lx "
				"for signal frame\n",
				current->sas_ss_sp, current->sas_ss_size,
				alt_ss_stk_base, alt_ss_stk_size,
				sizeof(rt_sigframe_t));

			ss_stk_size = alt_ss_stk_size;
			ss_sp = alt_ss_stk_base + alt_ss_stk_size;
		}

		/*
		 * Do not try to expand altstack, fail with SIGSEGV instead.
		 */
		if (ss_stk_size < sizeof(rt_sigframe_t))
			return -EFAULT;
	} else if (ss_stk_size < sizeof(rt_sigframe_t)) {
		u64 incr;

		DebugHS("user stack size 0x%llx < 0x%lx needed to pass "
			"signal info and context\n",
				ss_stk_size, sizeof(rt_sigframe_t));

		incr = sizeof(rt_sigframe_t) - ss_stk_size + PAGE_SIZE;
		incr = round_up(incr, E2K_ALIGN_STACK_BASE_REG);
		if (expand_user_data_stack(regs, incr)) {
			pr_info_ratelimited("[%d] %s: user data stack overflow\n",
				current->pid, current->comm);
			return -EFAULT;
		}

		ss_sp = user_stack_pointer(regs);
		ss_stk_size = AS(regs->stacks.usd_hi).size;

		DebugHS("expanded stack: ss_sp 0x%llx size 0x%llx\n",
			ss_sp, ss_stk_size);
	}

	tmp_sp = ss_sp;
	tmp_sz = ss_stk_size;
	ss_sp -= sizeof(rt_sigframe_t);
	ss_sp = round_down(ss_sp, E2K_ALIGN_STACK);
	ss_stk_size -= (tmp_sp - ss_sp);
	BUG_ON(ss_stk_size >= tmp_sz || ss_sp >= tmp_sp);

	rt_sigframe = (rt_sigframe_t *) ss_sp;
	DebugHS("rt_sigframe %px\n", rt_sigframe);

	if (TASK_IS_BINCO(current))
		NATIVE_SAVE_RPR_REGS(regs);

	if (setup_rt_frame(rt_sigframe, info, regs))
		return -EFAULT;

	/*
	 * Update stack limits in thread_info - signal handler should use
	 * its own stack (be it altstack or just a part of main C stack).
	 */
	STORE_USER_REGS_TO_THREAD_INFO(ti, ss_sp - ss_stk_size,
						ss_sp, ss_stk_size);
	DebugHS("sig #%d sig_info %px\n",
		ti->ksig.sig, &rt_sigframe->info);

	return 0;
}

int native_signal_setup(struct pt_regs *regs)
{
	thread_info_t *ti = current_thread_info();
	u64 pframe[32];
	int ret;

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
	 * Copy user's part of kernel hardware stacks into user
	 */
	ret = do_user_hw_stacks_copy_full(&regs->stacks, regs, &regs->crs);
	if (ret)
		goto free_signal_stack;

	/*
	 * We want user to return to sighandler_trampoline so
	 * create fake kernel frame in user's chain stack
	 */
	ret = prepare_sighandler_trampoline(&regs->stacks);
	if (ret)
		goto free_signal_stack;

	/*
	 * User's signal handler frame should be the last in stacks
	 */
	ret = prepare_sighandler_frame(&regs->stacks, pframe, &regs->crs);
	ret = ret ?: copy_sighandler_frame(&regs->stacks, pframe, &regs->crs);
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
	if (!TASK_IS_BINCO(current))
		memset(&ti->k_gregs, 0, sizeof(ti->k_gregs));

	DebugHS("signal handler: sig=%d siginfo=0x%px\n"
		"\tIS_PROTECTED = 0x%lx\tsa_flags = 0x%lx\t->thread.flags=0x%lx\n",
		ti->ksig.sig, &ti->ksig.info,
		TASK_IS_PROTECTED(current), ti->ksig.ka.sa.sa_flags,
		current->thread.flags);
	DebugHS("will start handler() 0x%lx for sig #%d\n",
		ti->ksig.ka.sa.sa_handler, ti->ksig.sig);

	return 0;

free_signal_stack:
	pop_signal_stack();

	return ret;
}

void do_signal(struct pt_regs *regs)
{
	struct ksignal *ksig = &current_thread_info()->ksig;
	bool restart_needed;

	DebugSig("signal pending, %s, sys_num %d\n",
			from_trap(regs) ? "trap" : "syscall", regs->sys_num);

#ifdef CONFIG_KERNEL_TIMES_ACCOUNT
	E2K_SAVE_CLOCK_REG(scall_times->do_signal_start);
	scall_times->signals_num++;
#endif

	if (TASK_IS_BINCO(current))
		clear_delayed_signal_handling(current_thread_info());

	if (get_signal(ksig)) {
		int failed = signal_setup(regs);

		signal_setup_done(failed, ksig,
				  test_ts_flag(TS_SINGLESTEP_USER));
		if (!failed) {
			regs->flags.sig_call_handler = 1;
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
			if (regs->trap)
				regs->trap->flags &= ~TRAP_RP_FLAG;
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */
		}

		return;
	}

#ifdef	CONFIG_DEBUG_INIT
	/*
	 * Only to debug kernel, if some test launch as init process
	 */
	if (current->pid <= 1)
		panic("do_signal: signal on Init so will be recursive traps or signals\n");
#endif	/* CONFIG_DEBUG_INIT */

	restart_needed = false;

	/* Did we come from a system call? */
	if (from_syscall(regs)) {
		/* Restart the system call - no handlers present */
		switch (regs->sys_rval) {
		case -ERESTART_RESTARTBLOCK:
			regs->sys_num = __NR_restart_syscall;
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
			restart_needed = true;
			break;
		}
	}
	CHECK_PT_REGS_CHAIN(regs,
		NATIVE_NV_READ_USD_LO_REG().USD_lo_base,
		(u64)current->stack + KERNEL_C_STACK_SIZE);

	/*
	 * If there's no signal to deliver, we just put the saved sigmask
	 * back.
	 */
	restore_saved_sigmask();

	if (restart_needed)
		regs->flags.sig_restart_syscall = 1;
}


static int get_data_stack_from_signal_regs(unsigned long corrected_frame_addr,
		struct thread_info *ti,
		u64 *dstack_sp, u64 *dstack_free, u64 *dstack_top)
{
	struct pt_regs __user *u_regs;
	int skipped_regs, ret = 0;
	unsigned long sig_pcs_window_base, sig_pcs_window_ind, ts_flag;

	skipped_regs = 0;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	signal_pt_regs_for_each(u_regs) {
		e2k_stacks_t stacks;
		unsigned long delta;

		if (__copy_from_user(&stacks, &u_regs->stacks,
					sizeof(stacks))) {
			SIGDEBUG_PRINT("SIGKILL. could not read signal stack\n");
			force_sig(SIGKILL);
			ret = -EFAULT;
			break;
		}

		sig_pcs_window_base = AS(stacks.pcsp_lo).base;
		sig_pcs_window_ind = AS(stacks.pcsp_hi).ind;
		ret = find_in_old_u_pcs_list(sig_pcs_window_base, &delta);
		if (ret) {
			SIGDEBUG_PRINT("SIGKILL. do_longjmp(): could not find sig_u_pcs\n");
			force_sig(SIGKILL);
			break;
		}
		sig_pcs_window_base += delta;

		if (sig_pcs_window_base + sig_pcs_window_ind >=
				corrected_frame_addr) {
			++skipped_regs;

			calculate_e2k_dstack_parameters(&stacks, dstack_sp,
					dstack_free, dstack_top);
		} else {
			break;
		}
	}
	clear_ts_flag(ts_flag);

	/*
	 * Remove unwinded signal stack
	 */
	if (skipped_regs) {
		ti->signal_stack.used -= skipped_regs *
				sizeof(struct signal_stack_context);
		if (WARN_ON_ONCE((s64) ti->signal_stack.used < 0))
			ti->signal_stack.used = 0;
	}

	return ret;

}


struct unwind_stack_args {
	u64 jmp_frame_address;
	u64 *ppsl_shift;
	u64 *psp_delta;
	u64 *pcsp_delta;
	u64 corrected_size;
	u64 *dstack_sp;
	u64 *dstack_free;
	u64 *dstack_top;
	e2k_mem_crs_t *crs;
};

static int __unwind_stack(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, int flags, void *arg)
{
	struct unwind_stack_args *args = arg;
	stack_frame_t cur_frame;
	u64 usd_next_size;
	int ret;

	/*
	 * Are we done yet?
	 */
	if (unlikely(corrected_frame_addr < args->jmp_frame_address)) {
		SIGDEBUG_PRINT("SIGKILL. longjmp(): bad jump address from setjmp()\n");
		force_sig(SIGKILL);
		return -EINVAL;
	}

	if (corrected_frame_addr == args->jmp_frame_address) {
		memcpy(args->crs, frame, sizeof(*args->crs));

		return 1;
	}

	/*
	 * Calculate data stack delta
	 */
	args->corrected_size += 0x100000000L *
				getsp_adj_get_correction(corrected_frame_addr);
	getsp_adj_set_correction(corrected_frame_addr, 0);

	usd_next_size = ((u32) AS(frame->cr1_hi).ussz << 4UL) +
			args->corrected_size;
	*args->dstack_sp += usd_next_size - *args->dstack_free;
	*args->dstack_free = usd_next_size;

	cur_frame = get_stack_frame_type_IP(frame->cr0_hi, frame->cr1_lo,
					    false);
	if (cur_frame == user_frame_type) {
		*args->ppsl_shift += 1;
	} else {
		/* We are at signal trampoline right now so
		 * subtract SZ_OF_CR from frame address because
		 * pt_regs point to user frames below */
		ret = get_data_stack_from_signal_regs(
				corrected_frame_addr - SZ_OF_CR,
				current_thread_info(), args->dstack_sp,
				args->dstack_free, args->dstack_top);
		if (ret)
			return ret;
	}

	/*
	 * Calculate hardware stacks deltas
	 */
	*args->psp_delta += AS(frame->cr1_lo).wbs * EXT_4_NR_SZ;
	*args->pcsp_delta += SZ_OF_CR;

	return 0;
}

/**
 * unwind_stack - go down to the target frame and find its current parameters
 *		  (they could have changed since the call to setjmp())
 *
 * @jmp_pcsp_lo - saved %pcsp.lo
 * @jmp_pcsp_hi - saved %pcsp.hi
 * @stacks - current user stacks
 * @ppsl_shift - psl delta for %usd register will be returned here
 * @psp_delta - procedure stack pointer delta will be returned here
 * @pcsp_delta - chain stack pointer delta will be returned here
 * @crs - target frame's %cr registers will be returned here
 * @dstack_sp, @dstack_free, @dstack_top - data stack parameters for
 *	the target frame will be returned here
 */
static int unwind_stack(e2k_pcsp_lo_t jmp_pcsp_lo, e2k_pcsp_hi_t jmp_pcsp_hi,
		const struct e2k_stacks *stacks, u64 *ppsl_shift,
		u64 *psp_delta, u64 *pcsp_delta, e2k_mem_crs_t *crs,
		u64 *dstack_sp, u64 *dstack_free, u64 *dstack_top)
{
	unsigned long jmp_frame_address, delta;
	struct unwind_stack_args args;
	long ret;

	/* Calculate the starting parameters of data stack */
	calculate_e2k_dstack_parameters(stacks, dstack_sp,
					dstack_free, dstack_top);

	jmp_frame_address = AS(jmp_pcsp_lo).base + AS(jmp_pcsp_hi).ind;
	ret = find_in_old_u_pcs_list(AS(jmp_pcsp_lo).base, &delta);
	if (ret) {
		SIGDEBUG_PRINT("SIGKILL. do_longjmp(): couldn't find new_u_pcs\n");
		force_sig(SIGKILL);
		return ret;
	}
	jmp_frame_address += delta;

	args.jmp_frame_address = jmp_frame_address;
	args.ppsl_shift = ppsl_shift;
	args.psp_delta = psp_delta;
	args.pcsp_delta = pcsp_delta;
	args.corrected_size = 0;
	args.dstack_sp = dstack_sp;
	args.dstack_free = dstack_free;
	args.dstack_top = dstack_top;
	args.crs = crs;

	*ppsl_shift = 0;
	*psp_delta = 0;
	*pcsp_delta = 0;

	ret = parse_chain_stack(PCS_USER | PCS_OPEN_IRQS, NULL,
			__unwind_stack, &args);
	if (ret == 0) {
		SIGDEBUG_PRINT("SIGKILL. longjmp(): could not find jump frame\n");
		force_sig(SIGKILL);
		ret = -ESRCH;
	}

	return (IS_ERR_VALUE(ret)) ? ret : 0;
}

static int check_longjmp_permissions(u64 old_ip, u64 new_ip)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *old_vma, *new_vma;
	int ret = 0;

	down_read(&mm->mmap_sem);

	old_vma = find_vma(mm, old_ip);
	if (!old_vma || old_ip < old_vma->vm_start) {
		ret = -ESRCH;
		goto out_unlock;
	}

	new_vma = find_vma(mm, new_ip);
	if (!new_vma || new_ip < new_vma->vm_start) {
		ret = -ESRCH;
		goto out_unlock;
	}

	if ((old_vma->vm_flags & (VM_READ|VM_WRITE|VM_EXEC)) ^
	    (new_vma->vm_flags & (VM_READ|VM_WRITE|VM_EXEC))) {
		ret = -EPERM;
		goto out_unlock;
	}

out_unlock:
	up_read(&mm->mmap_sem);

	if (ret) {
		SIGDEBUG_PRINT("SIGKILL. longjmp(): old (0x%llx) and new (0x%llx) IPs have different permissions\n",
				old_ip, new_ip);
		force_sig(SIGKILL);
	}
	return ret;
}

static int longjmp_check_goal_frame(const struct e2k_stacks *stacks,
		const e2k_mem_crs_t *crs)
{
	hw_stack_t *u_hw_stack = &current_thread_info()->u_hw_stack;
	unsigned long new_fp;
	int syscall_psize = TASK_IS_PROTECTED(current) ? 8 : 4;
	int ret = -EINVAL;

	/* Check for possible WD.wsz overflow. When a function returns WD.psize
	 * is added to CR1_LO.wbs and the result is written to WD.wsz. Since no
	 * overflow checking is done in hardware we check it in software. */
	if (AS(crs->cr1_lo).wbs + syscall_psize > E2K_MAXSR) {
		SIGDEBUG_PRINT("SIGKILL. longjmp(): corrupted jmp_buf: cr1_lo.wbs (%d) + syscall psize (%d) > MAXSR\n",
				AS(crs->cr1_lo).wbs, syscall_psize);
		goto out;
	}

	new_fp = AS(stacks->pcsp_lo).base + AS(stacks->pcsp_hi).ind;
	if (new_fp > (unsigned long) GET_PCS_BASE(u_hw_stack)) {
		e2k_mem_crs_t __user *u_cframe = (e2k_mem_crs_t *) new_fp - 1;
		e2k_cr1_lo_t cr1_lo;
		unsigned long ts_flag;
		int res;

		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		res = __get_user(AW(cr1_lo), &AW(u_cframe->cr1_lo));
		clear_ts_flag(ts_flag);

		if (res) {
			SIGDEBUG_PRINT("SIGKILL. longjmp(): __get_user() fault\n");
			ret = -EFAULT;
			goto out;
		}

		if (AS(cr1_lo).wbs + AS(crs->cr1_lo).wpsz > E2K_MAXSR) {
			SIGDEBUG_PRINT("SIGKILL. longjmp(): corrupted jmp_buf: caller's wbs + cr1_lo.psz > MAXSR\n");
			goto out;
		}
	}

	/* Avoid targeting kernel stack frames. This check is done just
	 * in case since such bad jmp_buf should not lead to anything bad. */
	if (get_stack_frame_type(crs->cr0_hi, crs->cr1_lo) != user_frame_type) {
		SIGDEBUG_PRINT("SIGKILL. longjmp(): target frame is not user's\n");
		goto out;
	}

	return 0;

out:
	force_sig(SIGKILL);
	return ret;
}

/**
 * longjmp_restore_user_frame_state - restore the last frame to its saved state
 *
 * @crs: current state of frame that called setjmp()/getcontext(),
 *	 this state must be restored to the way it was at the moment
 *	 of the call
 * @jmp_cr0_hi: saved %cr0.hi
 * @jmp_cr1_lo: saved %cr1.lo
 * @jmp_br: saved %br of frame that called setjmp()/getcontext()
 * @jmp_psize: used %psize when calling setjmp()/getcontext()
 * @psp_delta: user's %psp_hi.ind correction can be saved here
 * @wd: current kernel entry's %wd
 *
 * The hard part here is to restore %wd.wsz and %wd.psize since
 * all parameters of PS frame could have changed in the meantime.
 */
static int longjmp_restore_user_frame_state(e2k_mem_crs_t *crs,
		e2k_cr0_hi_t jmp_cr0_hi, e2k_cr1_lo_t jmp_cr1_lo,
		u32 jmp_br, u32 jmp_psize, u64 *psp_delta, e2k_wd_t wd)
{
	/* Take into account possibly different 'wbs' with which
	 * setjmp()/getcontext() and longjmp()/setcontext() have been called */
	*psp_delta += (AS(crs->cr1_lo).wbs - AS(jmp_cr1_lo).wbs) * EXT_4_NR_SZ;
	/* Dealing with this is too hard, and it seems no real
	 * application changes 'psize' in this particular way. */
	if (jmp_psize != AS(wd).psize) {
		SIGDEBUG_PRINT("SIGKILL. longjmp(): corrupted setjmp_buf: wd.psize != system call psize (4)\n");
		goto out;
	}

	if (jmp_cr1_lo.pm) {
		SIGDEBUG_PRINT("SIGKILL. longjmp(): corrupted setjmp_buf: cr1_lo = 0x%llx\n",
				AW(jmp_cr1_lo));
		goto out;
	}

	/*
	 * Restore target frame parameters
	 */
	crs->cr0_hi.ip = jmp_cr0_hi.ip;
	crs->cr1_lo.wfx = jmp_cr1_lo.wfx;
	crs->cr1_lo.wpsz = jmp_cr1_lo.wpsz;
	crs->cr1_lo.wbs = jmp_cr1_lo.wbs;
	crs->cr1_hi.br = jmp_br;

	return 0;

out:
	force_sig(SIGKILL);
	return -EINVAL;
}

static void longjmp_update_hw_stacks(e2k_stacks_t *stacks,
		u64 psp_delta, u64 pcsp_delta)
{
	unsigned long new_fp;

	/*
	 * Calculate new %psp
	 */
	new_fp = AS(stacks->psp_lo).base + AS(stacks->psp_hi).ind - psp_delta;
	update_psp_regs(new_fp, &stacks->psp_lo, &stacks->psp_hi);

	BUG_ON(GET_PSHTP_MEM_INDEX(stacks->pshtp));
	DebugSLJ("new PSP base 0x%llx size 0x%x ind 0x%x PSHTP 0x%llx\n",
		stacks->psp_lo.PSP_lo_base, stacks->psp_hi.PSP_hi_size,
		stacks->psp_hi.PSP_hi_ind, stacks->pshtp.PSHTP_reg);

	/*
	 * Calculate new %pcsp
	 */
	new_fp = AS(stacks->pcsp_lo).base + AS(stacks->pcsp_hi).ind -
		 pcsp_delta;
	update_pcsp_regs(new_fp, &stacks->pcsp_lo, &stacks->pcsp_hi);

	/* See comment in user_hw_stacks_copy_full() */
	BUG_ON(PCSHTP_SIGN_EXTEND(stacks->pcshtp) != SZ_OF_CR);
	DebugSLJ("new PCSP base 0x%llx size 0x%x ind 0x%x PCSHTP 0x%x\n",
		stacks->pcsp_lo.PCSP_lo_base, stacks->pcsp_hi.PCSP_hi_size,
		stacks->pcsp_hi.PCSP_hi_ind, stacks->pcshtp);
}

static int longjmp_switch_to_new_context(pt_regs_t *regs, pt_regs_t *new_regs,
		u64 dstack_sp, u64 dstack_free, u64 dstack_top)
{
	e2k_stacks_t *new_stacks = &new_regs->stacks;
	e2k_mem_crs_t *k_crs;
	e2k_mem_crs_t __user *u_cframe;
	unsigned long flags;
	int ret;

	if (WARN_ON_ONCE(AS(new_stacks->pcsp_hi).ind < SZ_OF_CR))
		do_exit(SIGKILL);

	/*
	 * Copy 2 last frames into chain stack - the first one for
	 * handle_sys_call() which does not restore pt_regs->crs and
	 * the second one because of the trick with FILL_HARDWARE_STACK().
	 *
	 * See user_hw_stacks_copy_full() for an explanation why these
	 * two frames are located at (AS(ti->k_pcsp_lo).base).
	 */
	k_crs = (e2k_mem_crs_t *) AS(current_thread_info()->k_pcsp_lo).base;
	u_cframe = (void __user *) (AS(new_stacks->pcsp_lo).base +
				    AS(new_stacks->pcsp_hi).ind);
	/* Do all of the updates under closed interrupts so that
	 * we still see consistent stack state from interrupt
	 * handler in case an interrupt arrives here. */
	raw_all_irq_save(flags);
	ret = __copy_user_to_current_hw_stack(k_crs, u_cframe - 1,
					    sizeof(*k_crs), new_regs, true);
	if (ret) {
		SIGDEBUG_PRINT("SIGKILL. lcngjmp(): copy_user_to_current_hw_stack() fault\n");
		goto out;
	}

	new_stacks->pcshtp = SZ_OF_CR;
	NATIVE_FLUSHC;
	*(k_crs + 1) = new_regs->crs;

	current_thread_info()->u_stack.bottom = dstack_sp - dstack_free;
	current_thread_info()->u_stack.top = dstack_top;

	copy_jmp_regs(regs, new_regs);

out:
	raw_all_irq_restore(flags);

	if (ret)
		force_sig(SIGKILL);
	return ret;
}

static void longjmp_update_dstack(struct e2k_stacks *stacks, u64 dstack_sp,
		u64 dstack_free, u64 dstack_top, u64 ppsl_shift,
		e2k_pcsp_hi_t jmp_pcsp_hi)
{
	stacks->top = dstack_top;

	AS(stacks->usd_hi).size = dstack_free;

	if (!TASK_IS_PROTECTED(current)) {
		AS(stacks->usd_lo).base = dstack_sp;
	} else {
		e2k_pusd_lo_t pusd_lo;

		AW(pusd_lo) = AW(stacks->usd_lo);
		AS(pusd_lo).base = dstack_sp & 0xffffffffUL;
		AS(pusd_lo).psl -= ppsl_shift;
		AW(stacks->usd_lo) = AW(pusd_lo);

		DebugSLJ("new psl %d, ppsl_shift %lld, jump point pusd_lo.psl %d\n",
				AS(pusd_lo).psl, ppsl_shift, AS(pusd_lo).psl);

		/*
		 * Delete global pointers to local data stack.
		 * setjmp - libc procedure and field .psl in usd_lo more 1 than
		 * in user procedure
		 */
		if ((AS(pusd_lo).psl - 1) * SZ_OF_CR > AS(jmp_pcsp_hi).ind) {
			pr_info_ratelimited(" BAD in longjmp() jmp_pcsp_hi.ind : 0x%d jmp_psl=%d\n",
					AS(jmp_pcsp_hi).ind, AS(pusd_lo).psl);
		}
		delete_records(AS(pusd_lo).psl);
	}


}

#if _NSIG != 64
# error Fix sigmask restoring in longjmp/setcontext
#endif
long do_longjmp(u64 retval, u64 jmp_sigmask, e2k_cr0_hi_t jmp_cr0_hi,
		e2k_cr1_lo_t jmp_cr1_lo, e2k_pcsp_lo_t jmp_pcsp_lo,
		e2k_pcsp_hi_t jmp_pcsp_hi, u32 jmp_br, u32 jmp_psize,
		e2k_fpcr_t fpcr, e2k_fpsr_t fpsr, e2k_pfpfr_t pfpfr, bool restore_fpu)
{
	thread_info_t *ti = current_thread_info();
	pt_regs_t new_regs, *regs = ti->pt_regs;
	u64 psp_delta, pcsp_delta, dstack_sp, dstack_free, dstack_top,
	    ppsl_shift;
	int ret;

	/*
	 * Copy user's part from kernel stacks back to user.
	 * This also removes any need to FILL before return to user.
	 */
	ret = do_user_hw_stacks_copy_full(&regs->stacks, regs, NULL);
	if (ret)
		return ret;

	DebugSLJ("current PCSP : base 0x%llx, ind 0x%x, size 0x%x PCSHTP 0x%x\n"
		 "        ip 0x%llx cr1_lo 0x%llx : wbs 0x%x wpsz 0x%x wfx %d\n",
		 regs->stacks.pcsp_lo.PCSP_lo_base,
		 regs->stacks.pcsp_hi.PCSP_hi_ind,
		 regs->stacks.pcsp_hi.PCSP_hi_size,
		 regs->stacks.pcshtp,
		 regs->crs.cr0_hi.CR0_hi_IP,
		 regs->crs.cr1_lo.CR1_lo_half,
		 regs->crs.cr1_lo.CR1_lo_wbs,
		 regs->crs.cr1_lo.CR1_lo_wpsz,
		 regs->crs.cr1_lo.CR1_lo_wfx);
	DebugSLJ("current PSP : base 0x%llx, ind 0x%x, size 0x%x PSHTP 0x%llx\n",
		 regs->stacks.psp_lo.PSP_lo_base,
		 regs->stacks.psp_hi.PSP_hi_ind,
		 regs->stacks.psp_hi.PSP_hi_size,
		 regs->stacks.pshtp.PSHTP_reg);

	init_pt_regs_for_syscall(&new_regs);
	copy_jmp_regs(&new_regs, regs);

	DebugSLJ("jump point PCSP : base 0x%llx, ind 0x%x, size 0x%x\n"
		 "jump point sigmask 0x%llx ip 0x%llx cr1_lo 0x%llx : wbs 0x%x wpsz 0x%x wfx %d\n",
		 jmp_pcsp_lo.PCSP_lo_base, jmp_pcsp_hi.PCSP_hi_ind,
		 jmp_pcsp_hi.PCSP_hi_size, jmp_sigmask, AW(jmp_cr0_hi),
		 AW(jmp_cr1_lo), AS_STRUCT(jmp_cr1_lo).wbs,
		 AS(jmp_cr1_lo).wpsz, AS(jmp_cr1_lo).wfx);

	ret = check_longjmp_permissions(AS(regs->crs.cr0_hi).ip << 3,
			AS(jmp_cr0_hi).ip << 3);
	if (ret)
		return ret;

	/* unwind_stack - go down to the target frame and find its current
	 * parameters (they could have changed since the call to setjmp()) */
	ret = unwind_stack(jmp_pcsp_lo, jmp_pcsp_hi, &new_regs.stacks,
			   &ppsl_shift, &psp_delta, &pcsp_delta, &new_regs.crs,
			   &dstack_sp, &dstack_free, &dstack_top);
	if (ret)
		return ret;

	/* Restore the last frame %cr to its saved state */
	ret = longjmp_restore_user_frame_state(&new_regs.crs, jmp_cr0_hi,
			jmp_cr1_lo, jmp_br, jmp_psize, &psp_delta, new_regs.wd);
	if (ret)
		return ret;

	/* Update all 3 stacks' pointers in pt_regs */
	longjmp_update_hw_stacks(&new_regs.stacks, psp_delta, pcsp_delta);
	longjmp_update_dstack(&new_regs.stacks, dstack_sp, dstack_free,
			dstack_top, ppsl_shift, jmp_pcsp_hi);

	/* Check that passed buffer is correct */
	ret = longjmp_check_goal_frame(&new_regs.stacks, &new_regs.crs);
	if (ret)
		return ret;

	ret = longjmp_switch_to_new_context(regs, &new_regs,
			dstack_sp, dstack_free, dstack_top);
	if (ret)
		return ret;

	ret = complete_long_jump(&new_regs);
	if (ret)
		return ret;

	if (jmp_sigmask & sigmask(SIGKILL)) {
		sigset_t k_sigset = { .sig[0] = jmp_sigmask };
		set_current_blocked(&k_sigset);
	}

	if (restore_fpu) {
		WRITE_FPCR_REG(fpcr);
		WRITE_FPSR_REG(fpsr);
		WRITE_PFPFR_REG(pfpfr);
	}

	DebugSLJ("jump point new CR1: wbs 0x%x, wpsz 0x%x, wfx %d\n"
		"jump point IP in mem CR0 0x%llx new IP 0x%llx\n"
		"jump point BR in mem CR1 0x%x new BR 0x%x\n"
		"jump point new USD = %llx:%llx\n",
		AS(jmp_cr1_lo).wbs, AS(jmp_cr1_lo).wpsz, AS(jmp_cr1_lo).wfx,
		AS(new_regs.crs.cr0_hi).ip << 3, AS(jmp_cr0_hi).ip << 3,
		AS(new_regs.crs.cr1_hi).br, jmp_br,
		AW(new_regs.stacks.usd_hi), AW(new_regs.stacks.usd_lo));

	return retval;
}

long sys_e2k_longjmp2(struct jmp_info __user *env, u64 retval)
{
	struct jmp_info	jmp_info;
	u32 jmp_psize;
	struct pt_regs *regs = current_pt_regs();
	e2k_pcsp_lo_t pcsp_lo;
	unsigned long delta;

	DebugSLJ("pid %d start env %px retval %lld\n",
		current->pid, env, retval);

	if (copy_from_user(&jmp_info, env, sizeof(jmp_info)))
		return -EFAULT;

	/* Switch to another context if needed */
	AW(pcsp_lo) = jmp_info.pcsplo;
	if (find_in_old_u_pcs_list(AS(pcsp_lo).base, &delta)) {
		e2k_usd_lo_t usd_lo = (e2k_usd_lo_t) jmp_info.usd_lo;
		long ret = hw_context_lookup_pcsp_and_switch(pcsp_lo, usd_lo);
		if (ret)
			return ret;
	}

	jmp_psize = AS((e2k_wd_t) ((u64) jmp_info.wd_hi32 << 32ULL)).psize;

	return do_longjmp(retval, jmp_info.sigmask,
			(e2k_cr0_hi_t) jmp_info.ip,
			(e2k_cr1_lo_t) jmp_info.cr1lo,
			(e2k_pcsp_lo_t) jmp_info.pcsplo, (e2k_pcsp_hi_t)
			(jmp_info.pcsphi + PCSHTP_SIGN_EXTEND(jmp_info.pcshtp)),
			jmp_info.br, jmp_psize, (e2k_fpcr_t) { .word = 0},
			(e2k_fpsr_t) { .word = 0 }, (e2k_pfpfr_t) { .word = 0},
			false);
}

#ifdef CONFIG_PROTECTED_MODE
long protected_sys_rt_sigaction(int sig,
			const void __user *ptr, void __user *ptr2,
			const size_t sigsetsize)

{
	long rval;
	struct k_sigaction new_ka, old_ka;
	prot_sigaction_old_t __user *act;
	prot_sigaction_old_t __user *oact;
	int tag = -1;

	if (sigsetsize != sizeof(sigset_t)) {
		if (sigsetsize > sizeof(sigset_t)
			&& !(sigsetsize >> 8)) /* reasonable positive value */
			DbgSCP_ALERT("SigSetSize seems extended beyond 64 bits.\n");
		else
			DbgSCP_ALERT("Wrong 'sigsetsize' value (%zd); expected %zd.\n",
					sigsetsize, sizeof(sigset_t));
		return -EINVAL;
	}

	if (ptr) {
		e2k_pl_lo_t pl_lo;

		act = (prot_sigaction_old_t __user *)ptr;

		if (GET_USER_VAL_TAGD(AW(pl_lo), tag, &act->sa_handler)) {
			DebugSCP("Bad act->sa_handler = %px\n",
				&act->sa_handler);
			return -EFAULT;
		}
		new_ka.sa.sa_handler = (__sighandler_t)pl_lo.target;

		if (tag != E2K_PL_ETAG && new_ka.sa.sa_handler != SIG_DFL &&
					  new_ka.sa.sa_handler != SIG_IGN) {
			DebugSCP("Wrong act->sa_handler %d %px %px\n",
				tag, &act->sa_handler,
				new_ka.sa.sa_handler);
			return -EINVAL;
		}

		/* Note that I intentionally ignore sa_restorer below */
		/* because it seems to be useless on E2K. */
		if (copy_from_user(&new_ka.sa.sa_mask, &act->sa_mask,
					sizeof(new_ka.sa.sa_mask)) ||
				get_user(new_ka.sa.sa_flags, &act->sa_flags))
			return -EFAULT;
	}

	rval = do_sigaction(sig, (ptr) ? &new_ka : NULL,
				(ptr2) ? &old_ka : NULL);
	DebugSCP("sys_rt_sigaction rval = %ld\n", rval);

	if (!rval && ptr2) {
		oact = (prot_sigaction_old_t __user *)ptr2;

		if (old_ka.sa.sa_handler != SIG_DFL &&
				old_ka.sa.sa_handler != SIG_IGN) {
			if (IS_CPU_ISET_V6())
				return -ENOSYS;
			rval = PUT_USER_PL_V2(&oact->sa_handler,
					   (u64)old_ka.sa.sa_handler);
		} else {
			rval = put_user((u64)old_ka.sa.sa_handler,
						&oact->sa_handler.PL_lo_value);
		}

		rval = (rval) ?: copy_to_user(
					&oact->sa_mask, &old_ka.sa.sa_mask,
					sizeof(old_ka.sa.sa_mask));
		rval = (rval) ?: put_user(old_ka.sa.sa_flags, &oact->sa_flags);
	}

	return rval;
}

long protected_sys_rt_sigaction_ex(int sig,
		const void __user *ptr, void __user *ptr2,
		const size_t sigsetsize)
{
	long rval;
	struct k_sigaction new_ka, old_ka;
	prot_sigaction_t __user *act;
	prot_sigaction_t __user *oact;
	int tag_lo;
	int tag_hi;

	if (sigsetsize != sizeof(sigset_t)) {
		DbgSCP_ALERT("SigSetSize seems extended beyond 64 bits.\n");
		return -EINVAL;
	}

	if (ptr) {
		e2k_pl_lo_t pl_lo;
		e2k_pl_hi_t pl_hi;

		act = (prot_sigaction_t __user *)ptr;

		if (GET_USER_VAL_TAGD(AW(pl_lo), tag_lo,
				&act->sa_handler.PLLO_item)) {
			DebugSCP("Bad act->sa_handler = %px\n",
				 &act->sa_handler);
			return -EFAULT;
		}
		new_ka.sa.sa_handler = (__sighandler_t)pl_lo.target;

		if (!IS_CPU_ISET_V6()) {
			if (tag_lo != E2K_PL_ETAG &&
				new_ka.sa.sa_handler != SIG_DFL &&
				new_ka.sa.sa_handler != SIG_IGN) {
				DebugSCP("Wrong act->sa_handler tag 0x%x %px %px\n",
					tag_lo, &act->sa_handler.PLLO_item,
					new_ka.sa.sa_handler);
				return -EINVAL;
			}
		} else if (new_ka.sa.sa_handler != SIG_DFL &&
			   new_ka.sa.sa_handler != SIG_IGN) {
			/* it is CPU ISET version >= V6 */
			if (tag_lo != E2K_PLLO_ETAG) {
				DebugSCP("Bad act->sa_handler lo tag 0x%x\n",
					tag_lo);
				return -EINVAL;
			}
			if (GET_USER_VAL_TAGD(pl_hi.PL_hi_value, tag_hi,
					&act->sa_handler.PLHI_item)) {
				DebugSCP("Bad act->sa_handler = %px\n",
					&act->sa_handler.PLHI_item);
				return -EFAULT;
			}
			if (tag_hi != E2K_PLHI_ETAG) {
				DebugSCP("Bad act->sa_handler "
					"hi tag 0x%x\n",
					tag_hi);
				return -EINVAL;
			}
			if (pl_hi.PL_hi_cui == 0) {
				DebugSCP("Zero CUI of act->sa_handler "
					"procedure label\n");
				return -EINVAL;
			}
			new_ka.sa_handler_cui = pl_hi.PL_hi_cui;
		}

		/* Note that I intentionally ignore sa_restorer below
		   because it seems to be useless on E2K.  */

		if (copy_from_user(&new_ka.sa.sa_mask, &act->sa_mask,
					sizeof(new_ka.sa.sa_mask)) ||
				get_user(new_ka.sa.sa_flags, &act->sa_flags))
			return -EFAULT;
	}

	rval = do_sigaction(sig, (ptr) ? &new_ka : NULL,
				(ptr2) ? &old_ka : NULL);
	DebugSCP("rval = %ld\n", rval);
	if (rval)
		return rval;

	if (ptr2) {
		oact = (prot_sigaction_t __user *)ptr2;

		rval = PUT_USER_PL(&oact->sa_handler, (u64)old_ka.sa.sa_handler,
							old_ka.sa_handler_cui);
		rval = (rval) ?: copy_to_user(
					&oact->sa_mask, &old_ka.sa.sa_mask,
					sizeof(old_ka.sa.sa_mask));
		rval = (rval) ?: put_user(old_ka.sa.sa_flags, &oact->sa_flags);

		if (rval)
			DbgSCP_ALERT("failed to return 'oldact'.\n");
	}

	return rval;
}

#endif	/* CONFIG_PROTECTED_MODE */
