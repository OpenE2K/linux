/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/context_tracking.h>
#include <linux/errno.h>
#include <linux/irqflags.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>

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
#include <asm/kvm/ctx_signal_stacks.h>

#undef	DEBUG_SIG_MODE
#undef	DebugSig
#define	DEBUG_SIG_MODE		0	/* Signal handling */
#define DebugSig(...)		DebugPrint(DEBUG_SIG_MODE ,##__VA_ARGS__)

#undef	DEBUG_HS_MODE
#undef	DebugHS
#define	DEBUG_HS_MODE		0	/* Signal handling */
#define DebugHS(...)		DebugPrint(DEBUG_HS_MODE ,##__VA_ARGS__)

#define	DEBUG_SLJ_MODE		0	/* Signal long jump handling */
#define DebugSLJ(...)		DebugPrint(DEBUG_SLJ_MODE ,##__VA_ARGS__)


static void copy_jmp_regs(pt_regs_t *to, const pt_regs_t *from)
{
	CHECK_PT_REGS_CHAIN((pt_regs_t *)from, USD_PTR(native_read_USD_reg()),
			    (u64) current->stack + KERNEL_C_STACK_SIZE);

	to->stacks.top = from->stacks.top;
	to->wd = from->wd;
	to->stacks.usd = from->stacks.usd;
	to->stacks.psp = from->stacks.psp;
	to->stacks.pcsp = from->stacks.pcsp;
	to->stacks.pshtp = from->stacks.pshtp;
	to->stacks.pcshtp = from->stacks.pcshtp;
	to->crs.cr0 = from->crs.cr0;
	to->crs.cr1 = from->crs.cr1;
	to->sys_rval = from->sys_rval;
	to->flags = from->flags;
}

static int setup_frame(struct sigcontext __user *sigc,
		struct extra_ucontext __user *extra, const pt_regs_t *user_regs)
{
	struct trap_pt_regs *trap = user_regs->trap;
	register struct k_sigaction *ka = &current_thread_info()->ksig.ka;
	int	rval;
	int	i;
	char	tag;
	int	sc_need_rstrt = 0;

	rval = __put_user(LO(user_regs->crs.cr0), &sigc->cr0_lo);
	rval = (rval) ?: __put_user(HI(user_regs->crs.cr0), &sigc->cr0_hi);
	rval = (rval) ?: __put_user(LO(user_regs->crs.cr1), &sigc->cr1_lo);
	rval = (rval) ?: __put_user(HI(user_regs->crs.cr1), &sigc->cr1_hi);
	rval = (rval) ?: __put_user(user_regs->stacks.top, &sigc->sbr);
	rval = (rval) ?: __put_user(LO(user_regs->stacks.usd), &sigc->usd_lo);
	rval = (rval) ?: __put_user(HI(user_regs->stacks.usd), &sigc->usd_hi);
	rval = (rval) ?: __put_user(LO(user_regs->stacks.psp), &sigc->psp_lo);
	rval = (rval) ?: __put_user(HI(user_regs->stacks.psp), &sigc->psp_hi);
	rval = (rval) ?: __put_user(LO(user_regs->stacks.pcsp), &sigc->pcsp_lo);
	rval = (rval) ?: __put_user(HI(user_regs->stacks.pcsp), &sigc->pcsp_hi);

	/* for binary compiler */
	if (unlikely(TASK_IS_BINCO(current))) {
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
		int mlt_num = trap ? trap->mlt_state.num : 0;
#endif

		rval = (rval) ?: __put_user(AW(current_thread_info()->upsr), &sigc->upsr);
		rval = (rval) ?: __put_user(HI(user_regs->rpr), &sigc->rpr_hi);
		rval = (rval) ?: __put_user(LO(user_regs->rpr), &sigc->rpr_lo);

		/* copy MLT */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
		if (!rval && mlt_num) {
			if (copy_to_user((void __user *) sigc->mlt,
					 trap->mlt_state.mlt,
					 sizeof(e2k_mlt_entry_t) * mlt_num))
				rval = rval ?: -EFAULT;
		}
		if (!rval && (mlt_num < NATIVE_MLT_SIZE)) {
			if (clear_user((void __user *)&sigc->mlt[mlt_num * 3],
				       sizeof(e2k_mlt_entry_t) *
				       (NATIVE_MLT_SIZE - mlt_num)))
				rval = rval ?: -EFAULT;
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
			rval = (rval) ?: __put_user(trap->tcellar[i].condition.word,
						    &sigc->trap_cell_info[i]);
			load_value_and_tagd(&trap->tcellar[i].data, &data, &tag);
			rval = (rval) ?: __put_user(tag, &sigc->trap_cell_tag[i]);
		}

		/* TIR */
		rval = (rval) ?: __put_user(trap->nr_TIRs, &sigc->nr_TIRs);
		for (i = 0; i <= trap->nr_TIRs; i++) {
			rval = (rval) ?: __put_user(HI(trap->TIRs[i]), &sigc->tir_hi[i]);
			rval = (rval) ?: __put_user(LO(trap->TIRs[i]), &sigc->tir_lo[i]);
		}

		rval = (rval) ?: __put_user(trap->tc_count / 3, &extra->tc_count);
		rval = (rval) ?: __put_user(trap->curr_cnt, &extra->curr_cnt);

		/* CTPR */
		rval = (rval) ?: __put_user(LO(user_regs->ctpr1), &extra->ctpr1);
		rval = (rval) ?: __put_user(LO(user_regs->ctpr2), &extra->ctpr2);
		rval = (rval) ?: __put_user(LO(user_regs->ctpr3), &extra->ctpr3);
		if (cpu_has(CPU_FEAT_ISET_V6)) {
			rval = (rval) ?: __put_user(HI(user_regs->ctpr1), &extra->ctpr1_hi);
			rval = (rval) ?: __put_user(HI(user_regs->ctpr2), &extra->ctpr2_hi);
			rval = (rval) ?: __put_user(HI(user_regs->ctpr3), &extra->ctpr3_hi);
		} else {
			rval = (rval) ?: __put_user(0, &extra->ctpr1_hi);
			rval = (rval) ?: __put_user(0, &extra->ctpr2_hi);
			rval = (rval) ?: __put_user(0, &extra->ctpr3_hi);
		}
	} else {
		rval = (rval) ?: __put_user(0, &sigc->nr_TIRs);
		rval = (rval) ?: __put_user(0ULL, &sigc->tir_hi[0]);
		rval = (rval) ?: __put_user(0ULL, &sigc->tir_lo[0]);
		rval = (rval) ?: __put_user(0, &extra->tc_count);
		rval = (rval) ?: __put_user(-1, &extra->curr_cnt);
		rval = (rval) ?: __put_user(0, &extra->ctpr1);
		rval = (rval) ?: __put_user(0, &extra->ctpr2);
		rval = (rval) ?: __put_user(0, &extra->ctpr3);
		rval = (rval) ?: __put_user(0, &extra->ctpr1_hi);
		rval = (rval) ?: __put_user(0, &extra->ctpr2_hi);
		rval = (rval) ?: __put_user(0, &extra->ctpr3_hi);
	}

	if (from_syscall(user_regs) &&
	    ((user_regs->sys_rval == -ERESTARTNOINTR) ||
	     (user_regs->sys_rval == -ERESTARTSYS) &&
	     (ka->sa.sa_flags & SA_RESTART)))
		sc_need_rstrt = 1;
	rval = (rval) ?: __put_user(sc_need_rstrt, &extra->sc_need_rstrt);

	rval = (rval) ?: __put_user(PCSP_PTR(user_regs->stacks.pcsp) +
					SZ_OF_CR - (unsigned long) CURRENT_PCS_BASE(),
				    &extra->chain_stack_offset);
	rval = (rval) ?: __put_user(PSP_PTR(user_regs->stacks.psp) -
					(unsigned long) CURRENT_PS_BASE(),
				    &extra->proc_stack_offset);

	/* size of saved extra elements */
	rval = (rval) ?: __put_user(sizeof(struct extra_ucontext) - sizeof(int),
					 &extra->sizeof_extra_uc);

	/* DAM */
	BUILD_BUG_ON(sizeof(sigc->dam) != sizeof(current->thread.dam));
	if (!current->ptrace)
		memset(current->thread.dam, 0, sizeof(current->thread.dam));
	rval = (rval) ?: __copy_to_user(sigc->dam, current->thread.dam,
					sizeof(current->thread.dam));

	return rval;
}

#ifdef CONFIG_PROTECTED_MODE
static int setup_prot_frame(struct sigcontext_prot __user *sigc, const pt_regs_t *user_regs)
{
	int rval;

	rval = __put_user(LO(user_regs->crs.cr0), &sigc->cr0_lo);
	rval = (rval) ?: __put_user(HI(user_regs->crs.cr0), &sigc->cr0_hi);
	rval = (rval) ?: __put_user(LO(user_regs->crs.cr1), &sigc->cr1_lo);
	rval = (rval) ?: __put_user(HI(user_regs->crs.cr1), &sigc->cr1_hi);

	rval = (rval) ?: __put_user(user_regs->stacks.top, &sigc->sbr);
	rval = (rval) ?: __put_user(LO(user_regs->stacks.usd), &sigc->usd_lo);
	rval = (rval) ?: __put_user(HI(user_regs->stacks.usd), &sigc->usd_hi);
	rval = (rval) ?: __put_user(LO(user_regs->stacks.psp), &sigc->psp_lo);
	rval = (rval) ?: __put_user(HI(user_regs->stacks.psp), &sigc->psp_hi);
	rval = (rval) ?: __put_user(LO(user_regs->stacks.pcsp), &sigc->pcsp_lo);
	rval = (rval) ?: __put_user(LO(user_regs->stacks.pcsp), &sigc->pcsp_hi);

	return rval;
}

#endif /* CONFIG_PROTECTED_MODE */

static int setup_rt_frame(rt_sigframe_t __user *frame,
				 kernel_siginfo_t *info,
				 const struct pt_regs *regs)
{
	sigset_t *set = sigmask_to_save();
#ifdef CONFIG_COMPAT
	compat_sigset_t *cset = (compat_sigset_t *) set;
#endif
	struct k_sigaction *ka = &current_thread_info()->ksig.ka;
	int ret = 0;

	if (!access_ok(frame, sizeof(*frame))) {
		DebugHS("access failed to user stack frame %px\n", frame);
		return -EFAULT;
	}
	DebugHS("info=%px signal=%d ->thread.flags=0x%lx IS_PROTECTED=%ld\n",
		info, current_thread_info()->ksig.sig, current->thread.flags,
		TASK_IS_PROTECTED(current));

	if (__put_user(get_return_ip(regs), &frame->orig_return_ip))
		return -EFAULT;

#ifdef CONFIG_PROTECTED_MODE
	if (TASK_IS_PROTECTED(current)) {
		e2k_ap_t ss_sp = new_ap(current->sas_ss_sp, current->sas_ss_size, 0, RW_ENABLE);

		ret = setup_prot_frame(&frame->uc_prot.uc_mcontext, regs);
		ret = (ret) ?: __copy_to_user(&frame->uc_prot.uc_sigmask,
					      set, sizeof(*set));

		ret = (ret) ?: __put_user(ss_sp.lo, &frame->uc_prot.uc_stack.ss_sp.lo);
		ret = (ret) ?: __put_user(ss_sp.hi, &frame->uc_prot.uc_stack.ss_sp.hi);
		ret = (ret) ?: __put_user(sas_ss_flags(USD_PTR(regs->stacks.usd)),
					  &frame->uc_prot.uc_stack.ss_flags);
		ret = (ret) ?: __put_user(current->sas_ss_size,
					  &frame->uc_prot.uc_stack.ss_size);
	} else
#endif
	if (!(current->thread.flags & E2K_FLAG_32BIT)) {
		ret = setup_frame(&frame->uc.uc_mcontext,
				  &frame->uc.uc_extra, regs);
		ret = (ret) ?: __copy_to_user(&frame->uc.uc_sigmask,
					      set, sizeof(*set));
		ret = (ret) ?: __save_altstack(&frame->uc.uc_stack,
					       USD_PTR(regs->stacks.usd));
	}
#ifdef CONFIG_COMPAT
	else {
		ret = setup_frame(&frame->uc_32.uc_mcontext,
				  &frame->uc_32.uc_extra, regs);
		ret = (ret) ?: __copy_to_user(&frame->uc_32.uc_sigmask,
					      cset, sizeof(*cset));
		ret = (ret) ?: __compat_save_altstack(&frame->uc_32.uc_stack,
						      USD_PTR(regs->stacks.usd));
	}
#endif /* CONFIG_COMPAT */
	/*
	 * Must we set additional flags?
	 */
	if (!(ka->sa.sa_flags & SA_SIGINFO))
		return ret;

#ifdef CONFIG_PROTECTED_MODE
	if (TASK_IS_PROTECTED(current)) {
		ret = (ret) ?: copy_siginfo_to_prot_user(&frame->prot_siginfo, info);
		ret = (ret) ?: __put_user(0, &frame->uc_prot.uc_flags);
		ret = (ret) ?: __put_user(0, &frame->uc_prot.uc_link.lo);
		ret = (ret) ?: __put_user(0, &frame->uc_prot.uc_link.hi);
	} else
#endif
	if (!(current->thread.flags & E2K_FLAG_32BIT)) {
		ret = (ret) ?: copy_siginfo_to_user(&frame->info, info);
		ret = (ret) ?: __put_user(0, &frame->uc.uc_flags);
		ret = (ret) ?: __put_user(NULL, &frame->uc.uc_link);
	} else {
		if (current->thread.flags & E2K_FLAG_64BIT_BINCO)
			ret = (ret) ?: copy_siginfo_to_user(&frame->info, info);
#ifdef CONFIG_COMPAT
		else
			ret = (ret) ?: copy_siginfo_to_user32(&frame->compat_info, info);
#endif
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
	u64 ta_tag = ctpr_ta_tag(val);
	u64 opc = ctpr_opc(val);
	u64 ipd = ctpr_ipd(val);

	/* Disallow privileged or reserved values */
	if (opc == 2 || (ta_tag != CTPLL_CT_TAG && ta_tag != CTPNL_CT_TAG))
		return;

	dst->ta_base = val.ta_base & ~7ULL;
	*dst = ctpr_with_ta_tag(*dst, ta_tag);
	*dst = ctpr_with_opc(*dst, opc);
	*dst = ctpr_with_ipd(*dst, ipd);
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

#ifdef CONFIG_PROTECTED_MODE
	if (TASK_IS_PROTECTED(current)) {
		e2k_ptr_t ptr;
		stack_t stack;
		stack_t __user *pustack;
		int ret;

		ret = __get_user(stack.ss_flags,
				 &frame->uc_prot.uc_stack.ss_flags);
		ret = (ret) ?: __get_user(stack.ss_size,
					  &frame->uc_prot.uc_stack.ss_size);
		ret = (ret) ?: __get_user(ptr.lo,
					  &frame->uc_prot.uc_stack.ss_sp.lo);
		ret = (ret) ?: __get_user(ptr.hi,
					  &frame->uc_prot.uc_stack.ss_sp.hi);
		if (ret)
			return -EFAULT;

		stack.ss_sp = (void __user *) AP_PTR(ptr);

		pustack = __get_user_space(sizeof(stack_t));
		ret = copy_to_user(pustack, &stack, sizeof(stack_t));
		ret = restore_altstack(pustack);

		set_ptr = &frame->uc_prot.uc_sigmask;
		cr0_hi_ptr = &frame->uc_prot.uc_mcontext.cr0_hi;
		uc_extra_ptr = &frame->uc_prot.uc_extra;
	} else
#endif
#ifdef CONFIG_COMPAT
	if (current->thread.flags & E2K_FLAG_32BIT) {
		ret = compat_restore_altstack(&frame->uc_32.uc_stack);

		set_ptr = (sigset_t __user *) &frame->uc_32.uc_sigmask;
		cr0_hi_ptr = &frame->uc_32.uc_mcontext.cr0_hi;
		uc_extra_ptr = &frame->uc_32.uc_extra;
	} else
#endif /* CONFIG_COMPAT */
	{
		ret = restore_altstack(&frame->uc.uc_stack);
		set_ptr = &frame->uc.uc_sigmask;
		cr0_hi_ptr = &frame->uc.uc_mcontext.cr0_hi;
		uc_extra_ptr = &frame->uc.uc_extra;
	}

	if (ret || __copy_from_user(&set, set_ptr, sizeof(set)))
		return -EFAULT;

	if (ka->sa.sa_flags & SA_SIGINFO) {
		e2k_ctpr_t ctpr1, ctpr2, ctpr3;
		e2k_cr0_t cr0;
		u64 orig_return_ip;
		struct pt_regs *regs = current_pt_regs();

		ret = (ret) ?: __get_user(orig_return_ip, &frame->orig_return_ip);
		ret = (ret) ?: __get_user(HI(cr0), cr0_hi_ptr);
		ret = (ret) ?: __get_user(LO(ctpr1), &uc_extra_ptr->ctpr1);
		ret = (ret) ?: __get_user(LO(ctpr2), &uc_extra_ptr->ctpr2);
		ret = (ret) ?: __get_user(LO(ctpr3), &uc_extra_ptr->ctpr3);
		if (cpu_has(CPU_FEAT_ISET_V6)) {
			ret = (ret) ?: __get_user(HI(ctpr1), &uc_extra_ptr->ctpr1_hi);
			ret = (ret) ?: __get_user(HI(ctpr2), &uc_extra_ptr->ctpr2_hi);
			ret = (ret) ?: __get_user(HI(ctpr3), &uc_extra_ptr->ctpr3_hi);
		} else {
			HI(ctpr1) = 0;
			HI(ctpr2) = 0;
			HI(ctpr3) = 0;
		}
		if (ret)
			return -EFAULT;

		/*
		 * There could be such situation:
		 *   - user's signal handler changes IP
		 *   - kernel ignores the trap cellar in this case and
		 *     start to deliver the next signal
		 *   - user's signal handler doesn't change IP
		 *   - kernel starts to handle trap cellar again
		 * Kernel should never handle trap cellar after user's signal
		 * handler changed IP. So kernel should give up the trap cellar.
		 */
		if (orig_return_ip != get_cr0_ip(cr0) && get_cr0_ip(cr0) < TASK_SIZE) {
			if (regs->trap) {
				regs->trap->tc_count = 0;
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
				regs->trap->rp = 0;
#endif
			}
		}

		/* User could have changed chain stack in memory, but
		 * values from uc_mcontext should take priority so we
		 * update cr0_hi unconditionally here. */
		copy_cr0_ip(regs->crs.cr0, cr0);

		if (TASK_IS_BINCO(current)) {
			copy_user_ctpr(&regs->ctpr1, ctpr1);
			copy_user_ctpr(&regs->ctpr2, ctpr2);
			copy_user_ctpr(&regs->ctpr3, ctpr3);
		}
	}

	set_current_blocked(&set);

	return 0;
}

static int copy_context_to_signal_stack(struct signal_stack_context __priv *context,
					struct local_gregs *l_gregs,
					const struct pt_regs *regs, const struct ksignal *ksig)
{
	const struct trap_pt_regs *trap = regs->trap;

	if (copy_to_priv_tagged(&context->regs, regs, sizeof(*regs)))
		return -EFAULT;

	if (trap) {
		trap_cellar_t tcellar[HW_TC_SIZE];
		int count;

		if (copy_to_priv_tagged(&context->trap,
				regs->trap, sizeof(*regs->trap)))
			return -EFAULT;

		/* Skip all completed entries.
		 * This allows to simplify checks in CRIU. */
		BUILD_BUG_ON(ARRAY_SIZE(tcellar) != ARRAY_SIZE(trap->tcellar));
		memset(&tcellar, 0, sizeof(tcellar));
		count = 0;
		for (int i = trap->curr_cnt; 3 * i < trap->tc_count; i++) {
			/* IMPORTANT: must correspond to check in do_trap_cellar() */
			if (tc_record_asynchronous(&trap->tcellar[i]))
				continue;
			tagged_memcpy_8(&tcellar[i], &trap->tcellar[i], sizeof(tcellar[i]));
			count++;
		}
		if (copy_to_priv_tagged(&context->trap.tcellar,
					      tcellar, sizeof(tcellar)) ||
		    put_priv(3 * count, &context->trap.tc_count) ||
		    put_priv(0, &context->trap.curr_cnt) ||
		    /* This pointer must not be accessed directly since signal
		     * stack could be reallocated (use signal_pt_regs_to_trap()
		     * instead), so put bogus value in it to help catch errors. */
		    put_priv((void *) 1, &context->regs.trap)) {
			return -EFAULT;
		}
	}
	if (regs->aau_context) {
		if (copy_to_priv(&context->aau_regs,
				      regs->aau_context, sizeof(*regs->aau_context)) ||
		    /* This pointer must not be accessed directly since signal
		     * stack could be reallocated, so put bogus value in it to
		     * help catch errors. */
		    put_priv((void *) 1, &context->regs.aau_context)) {
			return -EFAULT;
		}
	}

	if (copy_to_priv(&context->sigact, &ksig->ka, sizeof(ksig->ka)))
		return -EFAULT;

	if (l_gregs && copy_to_priv_tagged(&context->l_gregs, l_gregs, sizeof(*l_gregs)))
		return -EFAULT;

	return 0;
}


/**
 * allocate_signal_stack - allocate space for the signal stack
 *			   to store interrupted user context
 * @size: size of signal stack can be for a few context frames and
 *	  should be the page size aligned
 *
 * We use privileged area at the end of user space since we have
 * to save privileged structures such as trap cellar or CTPRs.
 */
void __priv *allocate_signal_stack(unsigned long size)
{
	unsigned long address, ts_flags;

	BUG_ON(size != round_up(size, PAGE_SIZE));

	ts_flags = set_ts_flag(TS_MMAP_PRIVILEGED | TS_MMAP_SIGNAL_STACK | TS_KERNEL_SYSCALL);
	address = vm_mmap_notkillable(NULL, USER_HW_STACKS_BASE,
				      size, PROT_READ | PROT_WRITE,
				      MAP_PRIVATE | MAP_ANONYMOUS, 0);
	clear_ts_flag(ts_flags);

	if (IS_ERR_VALUE(address)) {
		pr_err("%s(): could not allocate stack size 0x%lx vm_mmap returned %ld\n",
		       __func__, size, address);
	}
	return (void __priv *) address;
}

/**
 * push_signal_stack - make sure there is enough space in the signal stack
 *		       to store interrupted user context
 *
 * We use privileged area at the end of user space since we have
 * to save privileged structures such as trap cellar or CTPRs.
 */
static struct signal_stack_context __priv *push_signal_stack(void)
{
	struct thread_info *ti = current_thread_info();
	unsigned long context_size;
	void __priv *address;
	struct signal_stack_context __priv *context;

	/*
	 * Is there enough space already?
	 */
	if (ti->signal_stack.size - ti->signal_stack.used >= sizeof(*context)) {
		context = (struct signal_stack_context __priv *)
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
		address = allocate_signal_stack(context_size);
		if (IS_ERR(address))
			return address;

		ti->signal_stack.base = address;
		ti->signal_stack.size = context_size;
		ti->signal_stack.used = sizeof(*context);

		return address;
	}

	/*
	 * Expand already allocated area
	 */
	address = remap_e2k_stack(ti->signal_stack.base, ti->signal_stack.size,
				  ti->signal_stack.size + context_size, false);
	if (IS_ERR(address)) {
		pr_err("%s(): stack base 0x%lx size 0x%lx used 0x%lx context size 0x%lx vm_mmap returned %ld\n",
		       __func__, ti->signal_stack.base, ti->signal_stack.size,
		       ti->signal_stack.used, context_size, PTR_ERR(address));
		return address;
	}

	ti->signal_stack.base = address;
	ti->signal_stack.size += context_size;

	context = (struct signal_stack_context __priv *)
			(ti->signal_stack.base + ti->signal_stack.used);
	ti->signal_stack.used += sizeof(*context);

	return context;
}

/**
 * pop_signal_stack - counterpart to push_signal_stack()
 */
static struct signal_stack_context __priv *
do_get_signal_stack(struct signal_stack *signal_stack, bool push)
{
	struct signal_stack_context __priv *context;
	unsigned long used = signal_stack->used;

	if (used == 0) {
		/* signal stacks is empty */
		return NULL;
	}
	if (WARN_ON_ONCE(used < sizeof(*context)))
		do_exit(SIGKILL);

	used -= sizeof(*context);
	context = (struct signal_stack_context __priv *)
				(signal_stack->base + used);
	if (push) {
		signal_stack->used = used;
	}

	return context;
}

static struct signal_stack_context __priv *
do_get_prev_signal_stack(struct signal_stack *signal_stack,
			 struct signal_stack_context __priv *context)
{
	struct signal_stack_context __priv *prev_context;
	unsigned long used = signal_stack->used;

	if (used == 0) {
		/* signal stacks is empty */
		return NULL;
	}
	if (WARN_ON_ONCE(used < sizeof(*context)))
		do_exit(SIGKILL);
	if (WARN_ON_ONCE((unsigned long)context < (unsigned long)signal_stack->base ||
			 (unsigned long)context + sizeof(*context) >
				(unsigned long)signal_stack->base + used))
		do_exit(SIGKILL);

	used = (unsigned long)context - (unsigned long)signal_stack->base;
	if (used == 0) {
		/* signal stacks is empty */
		return NULL;
	}
	if (WARN_ON_ONCE(used < sizeof(*context)))
		do_exit(SIGKILL);

	used -= sizeof(*context);

	prev_context = (struct signal_stack_context __priv *)
				(signal_stack->base + used);

	return prev_context;
}

struct signal_stack_context __priv *
get_the_signal_stack(struct signal_stack *signal_stack)
{
	return do_get_signal_stack(signal_stack, false);
}

struct signal_stack_context __priv *get_signal_stack(void)
{
	return get_the_signal_stack(&current_thread_info()->signal_stack);
}

struct signal_stack_context __priv *
get_prev_signal_stack(struct signal_stack_context __priv *context)
{
	return do_get_prev_signal_stack(&current_thread_info()->signal_stack,
					context);
}

struct signal_stack_context __priv *
pop_the_signal_stack(struct signal_stack *signal_stack)
{
	return do_get_signal_stack(signal_stack, true);
}

struct signal_stack_context __priv *pop_signal_stack(void)
{
	return pop_the_signal_stack(&current_thread_info()->signal_stack);
}

/**
 * free_signal_stack - remove signal stack area on thread or context exit
 */
void free_signal_stack(struct signal_stack *signal_stack)
{
	unsigned long ts_flag;
	int ret;

	if (!signal_stack->base)
		return;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = vm_munmap_notkillable((unsigned long) signal_stack->base,
			signal_stack->size);
	clear_ts_flag(ts_flag);
	if (ret) {
		pr_err_ratelimited("%s [%d]: Could not free signal stack, error %d\n",
				   current->comm, current->pid, ret);
	}

	signal_stack->base = NULL;
	signal_stack->size = 0;
	signal_stack->used = 0;
}

/**
 * setup_signal_stack - save priviliged part of interrupted user context
 * to a special privileged area in user space.
 */
int setup_signal_stack(struct pt_regs *regs, bool is_signal)
{
	struct signal_stack_context __priv *context;
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

/*
 * Reserve space for guest's context on signal stack.
 * guest's context will be restored in these space
 * in return_from_makecontext_trampoline
 */
int reserve_signal_stack(void)
{
	struct signal_stack_context __priv *context = push_signal_stack();

	if (IS_ERR(context))
		return PTR_ERR(context);

	return 0;
}


int prepare_sighandler_trampoline(struct e2k_stacks *stacks)
{
	e2k_mem_crs_t *k_crs, crs;
	unsigned long trampoline;
	unsigned long flags;
	int ret;

	if (TASK_IS_PROTECTED(current)) {
		trampoline = sighandler_trampoline_128;
	} else if (current->thread.flags & E2K_FLAG_32BIT) {
		trampoline = sighandler_trampoline_32;
	} else {
		trampoline = sighandler_trampoline_64;
	}

	/*
	 * Prepare 'sighandler_trampoline' frame
	 */
	ret = chain_stack_frame_init(&crs, trampoline, current_thread_info()->u_stack.size,
				     0, E2K_USER_INITIAL_PSR, 0, 1, true);
	if (ret)
		return ret;

	/*
	 * Copy the new frame into chain stack
	 *
	 * See user_hw_stacks_copy_full() for an explanation why this frame
	 * is located at (ti->k_pcsp.base).
	 */
	k_crs = (e2k_mem_crs_t *) PCSP_BASE(current_thread_info()->k_pcsp);

	raw_all_irq_save(flags);
	E2K_FLUSHC;
	*k_crs = crs;
	/*
	 * On the host user frame from *k_crs has been copied to userspace
	 * already in user_hw_stacks_copy_full().
	 * On the guest return from guest kernel to user only possible via host.
	 * So the frame needs to be additionally duplicated to userspace stack.
	 */
	dup_chain_stack_frame_to_user(&crs, stacks);
	/* OK, now account for the new frame in *k_crs. */
	stacks->pcsp = incr_pcsp_ind(stacks->pcsp, SZ_OF_CR);
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
	unsigned long reg1_offset, top;
	e2k_usd_t usd;
	int ret;

	/*
	 * Calculate ucontext/siginfo address
	 */
	rt_sigframe = (rt_sigframe_t *) ti->u_stack.top;

	if (!(ksig->ka.sa.sa_flags & SA_SIGINFO)) {
		/*
		 * On Linux systems we pass 'struct sigcontext' in 2nd argument
		 */
#ifdef CONFIG_PROTECTED_MODE
		if (TASK_IS_PROTECTED(current)) {
			u_si = &rt_sigframe->uc_prot.uc_mcontext;
			u_si_size = sizeof(rt_sigframe->uc_prot.uc_mcontext);
		} else
#endif
		if (!(current->thread.flags & E2K_FLAG_32BIT)) {
			u_si = &rt_sigframe->uc.uc_mcontext;
			u_si_size = sizeof(rt_sigframe->uc.uc_mcontext);
		} else {
			u_si = &rt_sigframe->uc_32.uc_mcontext;
			u_si_size = sizeof(rt_sigframe->uc_32.uc_mcontext);
		}

		uc = NULL;
		uc_size = 0;
#ifdef CONFIG_PROTECTED_MODE
	} else if (TASK_IS_PROTECTED(current)) {
		u_si = &rt_sigframe->info;
		u_si_size = sizeof(rt_sigframe->info);
		uc = &rt_sigframe->uc_prot;
		uc_size = sizeof(rt_sigframe->uc_prot);
#endif
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
	 *
	 * "top" calculation here should correspond to "ss_sp"
	 * calculation in signal_rt_frame_setup() since we locate
	 * rt_sigframe_t in do_sigreturn() by checking "top".
	 * BUT !!! calculated here 'top' cannot be used as SBR register,
	 * because of this register is PAGE_SIZE aligned.
	 */
	top = round_down(ti->u_stack.top, E2K_ALIGN_USTACK_BOUNDS);

	if (!TASK_IS_PROTECTED(current) || cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		usd = new_usd(top - ti->u_stack.size, ti->u_stack.size, ti->u_stack.size);
	} else {
		usd = new_pusd(top - ti->u_stack.size, ti->u_stack.size,
			       ti->u_stack.size, USD_PSL(stacks->usd) + 1);
	}

	stacks->usd = usd;
	stacks->top = top;

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
		e2k_ap_t ap;
		ap = new_ap((u64) rt_sigframe, 64, 0, RW_ENABLE);
		__NATIVE_STORE_TAGGED_QWORD(&pframe[0],	ap.lo, ap.hi,
			E2K_AP_LO_ETAG, E2K_AP_HI_ETAG, 8 * reg1_offset);
		pframe[4] = ksig->sig;
		ap = new_ap((u64)u_si, u_si_size, 0, RW_ENABLE);
		__NATIVE_STORE_TAGGED_QWORD(&pframe[8], ap.lo, ap.hi,
			E2K_AP_LO_ETAG, E2K_AP_HI_ETAG, 8 * reg1_offset);
		ap = new_ap((u64)uc, uc_size, 0, RW_ENABLE);
		__NATIVE_STORE_TAGGED_QWORD(&pframe[12], ap.lo, ap.hi,
			E2K_AP_LO_ETAG, E2K_AP_HI_ETAG, 8 * reg1_offset);
	}

	/*
	 * Update chain stack
	 */
	void __user *handler = (!TASK_IS_PROTECTED(current))
			? (void __user *) ksig->ka.sa.sa_handler
			: (void __user *) ((e2k_pl_t) {
				.lo = (unsigned long)ksig->ka.sa.sa_handler
			}).target;
	ret = chain_stack_frame_init(crs, (unsigned long) handler, USD_IND(usd), 0,
				     E2K_USER_INITIAL_PSR, pframe_size / EXT_4_NR_SZ,
				     (pframe_size / EXT_4_NR_SZ) / 2, true);
	if (ret)
		return ret;

	/*
	 * Flush CUT cache after modification of CUT (#117859)
	 */
	write_CUTD_reg(read_CUTD_reg());

	return 0;
}

int copy_sighandler_frame(struct e2k_stacks *stacks, struct trap_pt_regs *trap,
				 u64 *pframe, e2k_mem_crs_t *crs)
{
	size_t pframe_size;
	unsigned long flags;
	void __priv *u_pframe;
	e2k_mem_crs_t *k_crs;
	int ret;

	/*
	 * Update procedure stack
	 */

	/* Make sure there is enough space in the stack before copying */
	pframe_size = (TASK_IS_PROTECTED(current)) ? (32 * 8) : (16 * 8);
	if (unlikely(PSP_IND(stacks->psp) + pframe_size > PSP_SIZE(stacks->psp))) {
		stacks->psp = incr_psp_ind(stacks->psp, pframe_size);
		ret = handle_proc_stack_bounds(stacks, trap);
		stacks->psp = decr_psp_ind(stacks->psp, -pframe_size);
		if (ret)
			return ret;
	}

	u_pframe = (void __priv *) PSP_PTR(stacks->psp);
	if (copy_to_priv_tagged(u_pframe, pframe, pframe_size))
		return -EFAULT;

	stacks->psp = incr_psp_ind(stacks->psp, pframe_size);

	/*
	 * handle_sys_call() does not restore %cr registers from pt_regs
	 * for performance reasons, so update chain stack in memory too.
	 *
	 * See user_hw_stacks_copy_full() for an explanation why this frame
	 * is located at (ti->k_pcsp.base + SZ_OF_CR).
	 */
	k_crs = (e2k_mem_crs_t *) PCSP_BASE(current_thread_info()->k_pcsp);

	raw_all_irq_save(flags);
	E2K_FLUSHC;
	*(k_crs + 1) = *crs;
	/* Same as prepare_sighandler_trampoline(): now account for the new
	 * frame in *k_crs.  Its previous contents have been copied already
	 * by user_hw_stacks_copy_full(crs != NULL). */
	dup_chain_stack_frame_to_user(crs, stacks);
	stacks->pcsp = incr_pcsp_ind(stacks->pcsp, SZ_OF_CR);
	raw_all_irq_restore(flags);

	/* See comment in user_hw_stacks_copy_full() */
	check_last_user_frame_loss(stacks);

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

	/* Perform fixup for the pre-signal frame. */
	rseq_signal_deliver(&ti->ksig, regs);

	ss_sp		= user_stack_pointer(regs);
	ss_stk_size	= USD_IND(regs->stacks.usd);

	DebugHS("ss_sp 0x%llx size 0x%llx\n", ss_sp, ss_stk_size);

	/*
	 * This is the X/Open sanctioned signal stack switching
	 * to alt stack.
	 */
	if (ka->sa.sa_flags & SA_ONSTACK) {
		if (sas_ss_flags(ss_sp) == 0) {
			u64 alt_ss_stk_base = round_up(current->sas_ss_sp,
						       E2K_ALIGN_USTACK_BOUNDS);
			u64 alt_ss_stk_size = round_down(current->sas_ss_size +
							 current->sas_ss_sp - alt_ss_stk_base,
							 E2K_ALIGN_USTACK_BOUNDS);

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
		ss_stk_size = USD_IND(regs->stacks.usd);

		DebugHS("expanded stack: ss_sp 0x%llx size 0x%llx\n",
			ss_sp, ss_stk_size);
	}

	tmp_sp = ss_sp;
	tmp_sz = ss_stk_size;
	ss_sp -= sizeof(rt_sigframe_t);
	ss_sp = round_down(ss_sp, E2K_ALIGN_USTACK_BOUNDS);
	ss_stk_size -= (tmp_sp - ss_sp);
	BUG_ON(ss_stk_size >= tmp_sz || ss_sp >= tmp_sp);

	rt_sigframe = (rt_sigframe_t __user *) ss_sp;
	DebugHS("rt_sigframe %px\n", rt_sigframe);

	if (TASK_IS_BINCO(current))
		regs->rpr = native_read_RPR_reg();

	if (setup_rt_frame(rt_sigframe, info, regs))
		return -EFAULT;

	/*
	 * Update stack limits in thread_info - signal handler should use
	 * its own stack (be it altstack or just a part of main C stack).
	 */
	update_u_stack_limits(ss_sp - ss_stk_size, ss_sp);
	DebugHS("sig #%d sig_info %px\n", ti->ksig.sig, &rt_sigframe->info);

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
	ret = ret ?: copy_sighandler_frame(&regs->stacks, regs->trap,
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

	if (get_signal(ksig)) {
		int failed = signal_setup(regs);

		signal_setup_done(failed, ksig,
				  test_ts_flag(TS_SINGLESTEP_USER));
		if (!failed) {
			regs->flags.sig_call_handler = 1;
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
			if (regs->trap)
				regs->trap->rp = 0;
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */
		}

		return;
	}

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
			    (u64) current->stack + KERNEL_C_STACK_SIZE);

	/*
	 * If there's no signal to deliver, we just put the saved sigmask
	 * back.
	 */
	restore_saved_sigmask();

	if (restart_needed)
		regs->flags.sig_restart_syscall = 1;
}


static int get_data_stack_from_signal_regs(unsigned long corrected_frame_addr,
					   struct thread_info *ti, u64 *dstack_sp,
					   u64 *dstack_free, u64 *dstack_top)
{
	struct pt_regs __priv *u_regs;
	int skipped_regs, ret = 0;
	unsigned long sig_pcs_window_base, sig_pcs_window_ind;

	skipped_regs = 0;

	signal_pt_regs_for_each(u_regs) {
		e2k_stacks_t stacks;
		unsigned long delta;

		if (copy_from_priv(&stacks, &u_regs->stacks, sizeof(stacks))) {
			SIGDEBUG_PRINT("SIGKILL. could not read signal stack\n");
			force_sig(SIGKILL);
			ret = -EFAULT;
			break;
		}

		sig_pcs_window_base = PCSP_BASE(stacks.pcsp);
		sig_pcs_window_ind = PCSP_IND(stacks.pcsp);
		ret = find_in_old_u_pcs_list(sig_pcs_window_base, &delta);
		if (ret) {
			SIGDEBUG_PRINT("SIGKILL. do_longjmp(): could not find sig_u_pcs\n");
			force_sig(SIGKILL);
			break;
		}
		sig_pcs_window_base += delta;

		if (sig_pcs_window_base + sig_pcs_window_ind >= corrected_frame_addr) {
			++skipped_regs;

			calculate_e2k_dstack_parameters(&stacks, dstack_sp,
							dstack_free, dstack_top);
		} else {
			break;
		}
	}

	/*
	 * Remove unwinded signal stack
	 */
	if (skipped_regs) {
		ti->signal_stack.used -= skipped_regs * sizeof(struct signal_stack_context);
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
		unsigned long corrected_frame_addr, chain_write_fn_t write_frame, void *arg)
{
	struct unwind_stack_args *args = arg;
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
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		/* `ussz` field has full size since iset v7
		 * so no need to check getsp_adjcorrection */
		size_t frame_size = get_cr1_ussz(frame->cr1);
		*args->dstack_sp += frame_size;
		*args->dstack_free += frame_size;
	} else {
		args->corrected_size += 0x100000000L *
					getsp_adj_get_correction(corrected_frame_addr);
		getsp_adj_set_correction(0, corrected_frame_addr);

		u64 usd_next_size = get_cr1_ussz(frame->cr1) + args->corrected_size;
		*args->dstack_sp += usd_next_size - *args->dstack_free;
		*args->dstack_free = usd_next_size;
	}

	if (likely(!might_be_sighandler_trampoline(frame))) {
		*args->ppsl_shift += 1;
	} else {
		/* We are at signal trampoline right now so
		 * subtract SZ_OF_CR from frame address because
		 * pt_regs point to user frames below */
		ret = get_data_stack_from_signal_regs(corrected_frame_addr - SZ_OF_CR,
						current_thread_info(), args->dstack_sp,
						args->dstack_free, args->dstack_top);
		if (ret)
			return ret;
	}

	/*
	 * Calculate hardware stacks deltas
	 */
	*args->psp_delta += frame->cr1.wbs * EXT_4_NR_SZ;
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
static int unwind_stack(e2k_pcsp_t jmp_pcsp,
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

	jmp_frame_address = PCSP_PTR(jmp_pcsp);
	ret = find_in_old_u_pcs_list(PCSP_BASE(jmp_pcsp), &delta);
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

	ret = parse_chain_stack(true, NULL, __unwind_stack, &args);
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

	mmap_read_lock(mm);

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
	if ((old_vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC)) ^
	    (new_vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC))) {
		ret = -EPERM;
		goto out_unlock;
	}

out_unlock:
	mmap_read_unlock(mm);

	if (ret) {
		SIGDEBUG_PRINT("SIGKILL. longjmp(): old (0x%llx) and new (0x%llx) IPs have different permissions\n",
			       old_ip, new_ip);
		force_sig(SIGKILL);
	}
	return ret;
}

static int longjmp_check_wsz_overflow(const struct e2k_stacks *stacks,
				      const e2k_mem_crs_t *crs, e2k_wd_t wd)
{
	hw_stack_t *u_hw_stack = &current_thread_info()->u_hw_stack;
	unsigned long new_fp;
	int ret;

	/* Hardware will generate exception in case of overflow
	 * so there is no need for a software check. */
	if (cpu_has(CPU_FEAT_ISET_V7))
		return 0;

	if (crs->cr1.wbs + wd.psize_q > E2K_MAXSR) {
		SIGDEBUG_PRINT("SIGKILL. longjmp(): corrupted jmp_buf: cr1_lo.wbs (%d) + syscall psize (%d) > MAXSR\n",
			       crs->cr1.wbs, wd.psize_q);
		ret = -EINVAL;
		goto signal;
	}

	new_fp = PCSP_PTR(stacks->pcsp);
	if (new_fp > (unsigned long) GET_PCS_BASE(u_hw_stack)) {
		e2k_mem_crs_t __priv *u_cframe = (e2k_mem_crs_t __priv *) new_fp - 1;
		e2k_cr1_t cr1;

		if (get_priv(LO(cr1), &LO(u_cframe->cr1)) ||
		    get_priv(HI(cr1), &HI(u_cframe->cr1))) {
			SIGDEBUG_PRINT("SIGKILL. longjmp(): get_priv() fault\n");
			ret = -EFAULT;
			goto signal;
		}

		if (cr1.wbs + crs->cr1.wpsz > E2K_MAXSR) {
			SIGDEBUG_PRINT("SIGKILL. longjmp(): corrupted jmp_buf: caller's wbs + cr1_lo.psz > MAXSR\n");
			ret = -EINVAL;
			goto signal;
		}
	}

	return 0;

signal:
	force_sig(SIGKILL);
	return ret;
}

static int longjmp_check_goal_frame(const struct e2k_stacks *stacks,
				    const e2k_mem_crs_t *crs, e2k_wd_t wd)
{
	int ret;

	/* Check for possible WD.wsz overflow. When a function returns WD.psize
	 * is added to CR1_LO.wbs and the result is written to WD.wsz. */
	ret = longjmp_check_wsz_overflow(stacks, crs, wd);
	if (ret)
		return ret;

	/* Avoid targeting kernel stack frames. This check is done just
	 * in case since there should not be any kernel frames in user's stack. */
	if (get_stack_frame_type(crs->cr0, crs->cr1) != user_frame_type) {
		SIGDEBUG_PRINT("SIGKILL. longjmp(): target frame is not user's\n");
		force_sig(SIGKILL);
		return -EINVAL;
	}

	return 0;
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
static int longjmp_restore_user_frame_state(e2k_mem_crs_t *crs, e2k_cr0_t jmp_cr0,
					    e2k_cr1_t jmp_cr1, u32 jmp_br,
					    u32 jmp_psize, u64 *psp_delta, e2k_wd_t wd)
{
	/* Take into account possibly different 'wbs' with which
	 * setjmp()/getcontext() and longjmp()/setcontext() have been called */

	*psp_delta += EXT_4_NR_SZ * (crs->cr1.wbs - jmp_cr1.wbs);

	/* Dealing with this is too hard, and it seems no real
	 * application changes 'psize' in this particular way. */

	if (jmp_psize != wd.psize) {
		SIGDEBUG_PRINT("SIGKILL. longjmp(): corrupted setjmp_buf:  wd.psize != system call psize (%d)\n",
			       wd.psize);
		goto out;
	}

	if (jmp_cr1.pm) {
		SIGDEBUG_PRINT("SIGKILL. longjmp(): corrupted setjmp_buf: cr1_lo = 0x%llx\n",
			       LO(jmp_cr1));
		goto out;
	}

	/*
	 * Restore target frame parameters
	 */
	copy_cr0_ip(crs->cr0, jmp_cr0);
	crs->cr1.wfx = jmp_cr1.wfx;
	crs->cr1.wpsz = jmp_cr1.wpsz;
	crs->cr1.wbs = jmp_cr1.wbs;
	crs->cr1.br = jmp_br;

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
	new_fp = PSP_PTR(stacks->psp) - psp_delta;
	update_psp_regs(new_fp, &stacks->psp);

	BUG_ON(PSHTP_MEM_INDEX(stacks->pshtp));
	DebugSLJ("new PSP base 0x%llx size 0x%llx ind 0x%llx PSHTP 0x%llx\n",
		 PSP_BASE(stacks->psp), PSP_SIZE(stacks->psp),
		 PSP_IND(stacks->psp), AW(stacks->pshtp));

	/*
	 * Calculate new %pcsp
	 */
	new_fp = PCSP_PTR(stacks->pcsp) - pcsp_delta;
	update_pcsp_regs(new_fp, &stacks->pcsp);

	/* See comment in user_hw_stacks_copy_full() */
	BUG_ON(stacks->pcshtp.ind != SZ_OF_CR);
	DebugSLJ("new PCSP base 0x%llx size 0x%llx ind 0x%llx PCSHTP 0x%x\n",
		 PCSP_BASE(stacks->pcsp), PCSP_SIZE(stacks->pcsp),
		 PCSP_IND(stacks->pcsp), AW(stacks->pcshtp));
}

/*
 * Even after user_hw_stacks_copy_full() kernel's chain stack will
 * have one additional user frame saved at pcsp.base address, which
 * we have to update manually (besides updating pt_regs->crs).
 *
 * See user_hw_stacks_copy_full() for an explanation why this frame
 * is located at (AS(ti->k_pcsp_lo).base).
 */
int native_longjmp_copy_user_to_kernel_hw_stacks(const pt_regs_t *regs)
{
	e2k_mem_crs_t *k_crs = (e2k_mem_crs_t *) PCSP_BASE(current_thread_info()->k_pcsp);
	e2k_mem_crs_t __priv *u_cframe = (e2k_mem_crs_t __priv *) PCSP_PTR(regs->stacks.pcsp);
	return copy_priv_to_current_hw_stack(k_crs, u_cframe - 1,
					     sizeof(*k_crs), regs, true);
}

static int longjmp_switch_to_new_context(pt_regs_t *regs, pt_regs_t *new_regs,
					 u64 dstack_sp, u64 dstack_free, u64 dstack_top)
{
	e2k_stacks_t *new_stacks = &new_regs->stacks;
	unsigned long flags;
	int ret;

	if (WARN_ON_ONCE(PCSP_IND(new_stacks->pcsp) < SZ_OF_CR))
		do_exit(SIGKILL);

	/*
	 * Do all of the updates under closed interrupts so that
	 * we still see consistent stack state from interrupt
	 * handler in case an interrupt arrives here.
	 */
	raw_all_irq_save(flags);

	ret = longjmp_copy_user_to_kernel_hw_stacks(regs, new_regs);
	if (ret) {
		SIGDEBUG_PRINT("SIGKILL. longjmp(): copy user stacks to kernel current_hw_stack() fault\n");
		goto out;
	}

	update_u_stack_limits(dstack_sp - dstack_free, dstack_top);

	copy_jmp_regs(regs, new_regs);

out:
	raw_all_irq_restore(flags);

	if (ret)
		force_sig(SIGKILL);
	return ret;
}

static void longjmp_update_dstack(struct e2k_stacks *stacks, u64 dstack_sp,
				  u64 dstack_free, u64 dstack_top,
				  u64 ppsl_shift, e2k_pcsp_t jmp_pcsp)
{
	stacks->top = dstack_top;

	if (!TASK_IS_PROTECTED(current) || cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		stacks->usd = new_usd(dstack_sp - dstack_free,
				      dstack_top - dstack_sp + dstack_free,
				      dstack_free);
	} else {
		stacks->usd = new_pusd(dstack_sp - dstack_free,
				       dstack_top - dstack_sp + dstack_free,
				       dstack_free,
				       USD_PSL(stacks->usd) - ppsl_shift);

	}

}

#if _NSIG != 64
# error Fix sigmask restoring in longjmp/setcontext
#endif
long do_longjmp(u64 retval, u64 jmp_sigmask, e2k_cr0_t jmp_cr0,
		e2k_cr1_t jmp_cr1, e2k_pcsp_t jmp_pcsp, u32 jmp_br, u32 jmp_psize)
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

	DebugSLJ("current PCSP : base 0x%llx, ind 0x%llx, size 0x%llx PCSHTP 0x%x\n"
		 "        ip 0x%llx cr1_lo 0x%llx : wbs 0x%x wpsz 0x%x wfx %d\n",
		 PCSP_BASE(regs->stacks.pcsp),
		 PCSP_IND(regs->stacks.pcsp),
		 PCSP_SIZE(regs->stacks.pcsp),
		 AW(regs->stacks.pcshtp),
		 get_cr0_ip(regs->crs.cr0),
		 LO(regs->crs.cr1),
		 regs->crs.cr1.wbs,
		 regs->crs.cr1.wpsz,
		 regs->crs.cr1.wfx);
	DebugSLJ("current PSP : base 0x%llx, ind 0x%llx, size 0x%llx PSHTP 0x%llx\n",
		 PSP_BASE(regs->stacks.psp),
		 PSP_IND(regs->stacks.psp),
		 PSP_SIZE(regs->stacks.psp),
		 AW(regs->stacks.pshtp));

	init_pt_regs_for_syscall(&new_regs);
	copy_jmp_regs(&new_regs, regs);

	DebugSLJ("jump point PCSP : base 0x%llx, ind 0x%llx, size 0x%llx\n"
		 "jump point sigmask 0x%llx ip 0x%llx cr1_lo 0x%llx : wbs 0x%x wpsz 0x%x wfx %d\n",
		 PCSP_BASE(jmp_pcsp), PCSP_IND(jmp_pcsp), PCSP_SIZE(jmp_pcsp),
		 jmp_sigmask, get_cr0_ip(jmp_cr0), LO(jmp_cr1),
		 jmp_cr1.wbs, jmp_cr1.wpsz, jmp_cr1.wfx);

	ret = check_longjmp_permissions(get_cr0_ip(regs->crs.cr0),
					get_cr0_ip(jmp_cr0));
	if (ret)
		return ret;

	/* unwind_stack - go down to the target frame and find its current
	 * parameters (they could have changed since the call to setjmp()) */
	ret = unwind_stack(jmp_pcsp, &new_regs.stacks,
			   &ppsl_shift, &psp_delta, &pcsp_delta, &new_regs.crs,
			   &dstack_sp, &dstack_free, &dstack_top);
	if (ret)
		return ret;

	/* Restore the last frame %cr to its saved state */
	ret = longjmp_restore_user_frame_state(&new_regs.crs, jmp_cr0,
					       jmp_cr1, jmp_br, jmp_psize,
					       &psp_delta, new_regs.wd);
	if (ret)
		return ret;

	/* Update all 3 stacks' pointers in pt_regs */
	longjmp_update_hw_stacks(&new_regs.stacks, psp_delta, pcsp_delta);
	longjmp_update_dstack(&new_regs.stacks, dstack_sp, dstack_free,
			      dstack_top, ppsl_shift, jmp_pcsp);

	/* Check that passed buffer is correct */
	ret = longjmp_check_goal_frame(&new_regs.stacks, &new_regs.crs, new_regs.wd);
	if (ret)
		return ret;

	ret = longjmp_switch_to_new_context(regs, &new_regs,
					    dstack_sp, dstack_free, dstack_top);
	if (ret)
		return ret;

	ret = complete_long_jump(&new_regs, false, 0);
	if (ret)
		return ret;

	if (jmp_sigmask & sigmask(SIGKILL)) {
		sigset_t k_sigset = { .sig[0] = jmp_sigmask };
		set_current_blocked(&k_sigset);
	}

	DebugSLJ("jump point new CR1: wbs 0x%x, wpsz 0x%x, wfx %d\n"
		 "jump point IP in mem CR0 0x%llx new IP 0x%llx\n"
		 "jump point BR in mem CR1 0x%x new BR 0x%x\n"
		 "jump point new USD = %llx:%llx\n",
		 jmp_cr1.wbs, jmp_cr1.wpsz, jmp_cr1.wfx,
		 get_cr0_ip(new_regs.crs.cr0), get_cr0_ip(jmp_cr0),
		 new_regs.crs.cr1.br, jmp_br,
		 HI(new_regs.stacks.usd), LO(new_regs.stacks.usd));

	return retval;
}

SYSCALL_DEFINE2(e2k_longjmp2, struct jmp_info __user *, env, u64, retval)
{
	struct jmp_info jmp_info;
	u32 jmp_psize;
	struct pt_regs *regs = current_pt_regs();
	e2k_pcsp_t pcsp;
	e2k_cr0_t cr0;
	e2k_cr1_t cr1;
	unsigned long delta;

	DebugSLJ("pid %d start env %px retval %lld\n",
		 current->pid, env, retval);

	if (copy_from_user(&jmp_info, env, sizeof(jmp_info)))
		return -EFAULT;

	LO(pcsp) = jmp_info.pcsplo;
	HI(pcsp) = jmp_info.pcsphi;
	/* Switch to another coroutine if needed */
	unsigned long pcsp_base = PCSP_BASE(pcsp);
	if (find_in_old_u_pcs_list(pcsp_base, &delta)) {
		/* Will also call longjmp inside another context if needed */
		return coroutine_switch_and_longjmp(pcsp_base, &jmp_info, retval);
	}

	pcsp = incr_pcsp_ind(pcsp, jmp_info.pcshtp.ind);
	jmp_psize = ((e2k_wd_t) { .word = (u64) jmp_info.wd_hi32 << 32ULL }).psize;
	HI(cr0) = jmp_info.ip;
	LO(cr1) = jmp_info.cr1lo;
	return do_longjmp(retval, jmp_info.sigmask, cr0, cr1,
			  pcsp, jmp_info.br, jmp_psize);
}

