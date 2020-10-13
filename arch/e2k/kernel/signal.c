
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
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
# include <linux/ftrace.h>
#endif

#include <asm/cpu_regs.h>
#include <asm/e2k_syswork.h>
#include <asm/uaccess.h>
#include <asm/process.h>
#include <asm/regs_state.h>
#include <asm/sge.h>
#include <asm/ucontext.h>
#include <linux/unistd.h>
#include <asm/lms.h>
#ifdef CONFIG_PROTECTED_MODE
#include <asm/3p.h>
#include <asm/e2k_ptypes.h>
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
#define DebugHS(...)		DebugPrint(DEBUG_HS_MODE ,##__VA_ARGS__)

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
#define DebugSRT(...)		DebugPrint(DEBUG_SRT_MODE ,##__VA_ARGS__)

#define	DEBUG_CTX_MODE		0	/* setcontext/swapcontext */
#if DEBUG_CTX_MODE
#define	DebugCTX(...)		DebugPrint(DEBUG_CTX_MODE ,##__VA_ARGS__)
#else
#define DebugCTX(...)
#endif

typedef struct rt_sigframe {
	siginfo_t		info;
	union {
		struct ucontext		uc;
#ifdef CONFIG_PROTECTED_MODE
		struct ucontext_prot	__pad;
#endif
	};
	sigset_t	saved_set;
} rt_sigframe_t;

extern int constrict_hardware_stacks(pt_regs_t *curr_regs, pt_regs_t *user_env);
extern int go_hd_stk_down(e2k_psp_hi_t psp_hi,
		e2k_pcsp_lo_t pcsp_lo, e2k_pcsp_hi_t pcsp_hi,
		int down,
		e2k_addr_t *psp_ind, e2k_addr_t *pcsp_ind,
		e2k_size_t *wd_psize, int *sw_num_p,
		e2k_mem_crs_t *crs, int user_stacks);

static int do_sigreturn(pt_regs_t *regs, unsigned long signo,
			rt_sigframe_t *user_sigframe);


void
sig_to_exit(int errno)
{
	struct 	siginfo 	si;
	struct k_sigaction 	*ka;

	DebugSig("start\n");

	ka = &current->sighand->action[SIGSEGV-1];
	ka->sa.sa_handler = SIG_DFL;

	si.si_signo = SIGSEGV;
	si.si_errno = 0;
	si.si_code = SI_KERNEL;
	force_sig_info(SIGSEGV, &si, current);
	
	DebugSig("finish\n");
	return;
}


static inline void adjust_intr_counter(struct pt_regs *regs)
{
	int nr = 0;

	do {
		if (from_trap(regs))
			++nr;

		regs = regs->next;
	} while (regs);

	current->thread.intr_counter = nr;
}

static inline void
copy_jmp_regs(pt_regs_t *from, pt_regs_t *to)
{
	to->stacks.sbr = from->stacks.sbr;
        to->wd = from->wd;
        to->stacks.usd_lo = from->stacks.usd_lo;
        to->stacks.usd_hi = from->stacks.usd_hi;
        to->stacks.psp_lo = from->stacks.psp_lo;
        to->stacks.psp_hi = from->stacks.psp_hi;
        to->stacks.pcsp_lo = from->stacks.pcsp_lo;
        to->stacks.pcsp_hi = from->stacks.pcsp_hi;
	to->stacks.u_stk_base_old = from->stacks.u_stk_base_old;
	to->stacks.u_stk_top_old = from->stacks.u_stk_top_old;
	to->stacks.u_stk_sz_old = from->stacks.u_stk_sz_old;
	to->stacks.alt_stack_old = from->stacks.alt_stack_old;
	to->stacks.valid = from->stacks.valid;
        to->crs.cr0_lo = from->crs.cr0_lo;
        to->crs.cr0_hi = from->crs.cr0_hi;
        to->crs.cr1_lo = from->crs.cr1_lo;
        to->crs.cr1_hi = from->crs.cr1_hi;
        to->sys_rval = from->sys_rval;
}

static inline int
check_jump_info(struct jmp_info *jmp_info)
{
	/*
	 * We should check that we can do changing of user hard snacks
	 */

	if ((current->thread.flags & E2K_FLAG_32BIT) &&
	     jmp_info->ip > TASK32_SIZE)
		return -EFAULT;

	if (jmp_info->ip > TASK_SIZE)
		return -EFAULT;

	return 0;
}

static inline int
copy_jmpinfo_from_user(struct jmp_info *from, struct jmp_info *to) 
{
	int rval;

	if (!access_ok(VERIFY_READ, from, sizeof(struct jmp_info)))
		return -EFAULT;

	rval = __get_user(to->sigmask, &from->sigmask);
	rval |= __get_user(to->ip, &from->ip);
	rval |= __get_user(to->cr1lo, &from->cr1lo);
	rval |= __get_user(to->pcsplo, &from->pcsplo);
	rval |= __get_user(to->pcsphi,  &from->pcsphi);
	rval |= __get_user(to->pcshtp, &from->pcshtp);
	rval |= __get_user(to->br, &from->br);
	rval |= __get_user(to->reserv1, &from->reserv1);
	rval |= __get_user(to->reserv2, &from->reserv2);

	if (rval)
		return -EFAULT;

        return check_jump_info(to);
}

void _NSIG_WORDS_is_unsupported_size(void)
{
	sig_to_exit(-EINVAL);
}

static inline int setup_frame(struct sigcontext *sigc, siginfo_t *info, 
			struct extra_ucontext *extra, pt_regs_t *user_regs)
{
	struct trap_pt_regs *trap = user_regs->trap;
	int rval = 0;
        int i;
        char tag;

	rval |= __put_user(AS_WORD(user_regs->crs.cr0_lo), &sigc->cr0_lo);
	rval |= __put_user(AS_WORD(user_regs->crs.cr0_hi), &sigc->cr0_hi);
	rval |= __put_user(AS_WORD(user_regs->crs.cr1_lo), &sigc->cr1_lo);
	rval |= __put_user(AS_WORD(user_regs->crs.cr1_hi), &sigc->cr1_hi);
	
	rval |= __put_user(user_regs->stacks.sbr, &sigc->sbr);
	rval |= __put_user(AS_WORD(user_regs->stacks.usd_lo), &sigc->usd_lo);
	rval |= __put_user(AS_WORD(user_regs->stacks.usd_hi), &sigc->usd_hi);
	rval |= __put_user(AS_WORD(user_regs->stacks.psp_lo), &sigc->psp_lo);
	rval |= __put_user(AS_WORD(user_regs->stacks.psp_hi), &sigc->psp_hi);
	rval |= __put_user(AS_WORD(user_regs->stacks.pcsp_lo), &sigc->pcsp_lo);
	rval |= __put_user(AS_WORD(user_regs->stacks.pcsp_hi), &sigc->pcsp_hi);

        /* for binary compiler */
	if (unlikely(TASK_IS_BINCO(current))) {
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
		int mlt_num = user_regs->mlt_state.num;
#endif

		rval |= __put_user(AS_WORD(current_thread_info()->upsr),
				&sigc->upsr);
		rval |= __put_user(user_regs->rpr_hi, &sigc->rpr_hi);
		rval |= __put_user(user_regs->rpr_lo, &sigc->rpr_lo);

		/* copy MLT */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
		if (mlt_num) {
			if (copy_to_user((void *)sigc->mlt,
					 user_regs->mlt_state.mlt,
					 sizeof(e2k_mlt_entry_t) * mlt_num))
				rval |= -EFAULT;
		}
		if (mlt_num < E2K_MAX_MLT_SIZE) {
			if (clear_user((void *)&sigc->mlt[mlt_num * 3],
				       sizeof(e2k_mlt_entry_t) *
						(E2K_MAX_MLT_SIZE - mlt_num)))
				rval |= -EFAULT;
		}
#endif
	}
	if (trap) {
		for (i = 0; i < MAX_TC_SIZE; i++) {
			rval |= __put_user(trap->tcellar[i].address,
						&sigc->trap_cell_addr[i]);
			rval |= __put_user(trap->tcellar[i].data,
						&sigc->trap_cell_val[i]);
			rval |= __put_user(trap->tcellar[i].condition.word,
						&sigc->trap_cell_info[i]);
			tag = E2K_LOAD_TAGD(&trap->tcellar[i].data);
			rval |= __put_user(tag, &sigc->trap_cell_tag[i]);
		}
		/* TIR */
		rval |= __put_user(trap->nr_TIRs, &sigc->nr_TIRs);
		for (i = 0; i <= trap->nr_TIRs; i++) {
			rval |= __put_user(trap->TIRs[i].TIR_hi.TIR_hi_reg,
							&sigc->tir_hi[i]);
			rval |= __put_user(trap->TIRs[i].TIR_lo.TIR_lo_reg,
							&sigc->tir_lo[i]);
		}
		rval |= __put_user(trap->tc_count / 3, &extra->tc_count);
		rval |= __put_user(trap->curr_cnt, &extra->curr_cnt);
	} else {
		rval |= __put_user(0, &sigc->nr_TIRs);
		rval |= __put_user(0ULL, &sigc->tir_hi[0]);
		rval |= __put_user(0ULL, &sigc->tir_lo[0]);
		rval |= __put_user(0, &extra->tc_count);
		rval |= __put_user(-1, &extra->curr_cnt);
	}
	rval |= __put_user(AW(user_regs->ctpr1), &extra->ctpr1);
	rval |= __put_user(AW(user_regs->ctpr2), &extra->ctpr2);
	rval |= __put_user(AW(user_regs->ctpr3), &extra->ctpr3);
	/* size of saved extra elements */
	rval |= __put_user(sizeof(struct extra_ucontext) - sizeof(int),
			   &extra->sizeof_extra_uc);
        /*   DAM  */
	SAVE_DAM(current_thread_info()->dam);
	for (i = 0; i < DAM_ENTRIES_NUM; i++)
		rval |= __put_user(current_thread_info()->dam[i],
				   &sigc->dam[i]);

	return rval;
}

static inline int setup_ucontext32(struct ucontext_32 *uc, siginfo_t *info, 
	    sigset32_t *oldset, e2k_usd_lo_t ss_usd_lo, pt_regs_t *user_regs)
{
	int rval = 0;

	rval |= __put_user(0, &uc->uc_flags);
	rval |= __put_user(0, &uc->uc_link);
	rval |= __put_user((int)current->sas_ss_sp, &uc->uc_stack.ss_sp);
	rval |= __put_user(sas_ss_flags(AS_STRUCT(ss_usd_lo).base),
			&uc->uc_stack.ss_flags);
	rval |= __put_user((int)current->sas_ss_size, &uc->uc_stack.ss_size);

	rval |= setup_frame(&uc->uc_mcontext, info, &uc->uc_extra, user_regs);

	rval |= __copy_to_user(&uc->uc_sigmask, oldset, sizeof(*oldset));

	return rval;
}

static inline int setup_ucontext(struct ucontext *uc, siginfo_t *info, 
		sigset_t *oldset, e2k_usd_lo_t ss_usd_lo, pt_regs_t *user_regs)
{
	int rval = 0;

	rval |= __put_user(0, &uc->uc_flags);
	rval |= __put_user(0, &uc->uc_link);
	rval |= __put_user((void *)current->sas_ss_sp, &uc->uc_stack.ss_sp);
	rval |= __put_user(sas_ss_flags(AS_STRUCT(ss_usd_lo).base),
			&uc->uc_stack.ss_flags);
	rval |= __put_user(current->sas_ss_size, &uc->uc_stack.ss_size);
	
	rval |= setup_frame(&uc->uc_mcontext, info, &uc->uc_extra, user_regs);

	rval |= __copy_to_user(&uc->uc_sigmask, oldset, sizeof(*oldset));

	return rval;
}

#ifdef CONFIG_PROTECTED_MODE
static inline int setup_prot_frame(struct sigcontext_prot *sigc,
				   siginfo_t *info, pt_regs_t *user_regs)
{
	int rval;

	rval = __put_user(AS_WORD(user_regs->crs.cr0_lo), &sigc->cr0_lo);
	rval |= __put_user(AS_WORD(user_regs->crs.cr0_hi), &sigc->cr0_hi);
	rval |= __put_user(AS_WORD(user_regs->crs.cr1_lo), &sigc->cr1_lo);
	rval |= __put_user(AS_WORD(user_regs->crs.cr1_hi), &sigc->cr1_hi);

	rval |= __put_user(user_regs->stacks.sbr, &sigc->sbr);
	rval |= __put_user(AS_WORD(user_regs->stacks.usd_lo), &sigc->usd_lo);
	rval |= __put_user(AS_WORD(user_regs->stacks.usd_hi), &sigc->usd_hi);
	rval |= __put_user(AS_WORD(user_regs->stacks.psp_lo), &sigc->psp_lo);
	rval |= __put_user(AS_WORD(user_regs->stacks.psp_hi), &sigc->psp_hi);
	rval |= __put_user(AS_WORD(user_regs->stacks.pcsp_lo), &sigc->pcsp_lo);
	rval |= __put_user(AS_WORD(user_regs->stacks.pcsp_hi), &sigc->pcsp_hi);

	return rval;
}

static inline int setup_ucontext_prot(struct ucontext_prot *uc, siginfo_t *info,
		sigset_t *oldset, e2k_usd_lo_t ss_usd_lo, pt_regs_t *user_regs)
{
	struct thread_info *ti = current_thread_info();
	int rval = 0;

	rval |= __put_user(0, &uc->uc_flags);
	rval |= __put_user(0, &AW(uc->uc_link).lo);
	rval |= __put_user(0, &AW(uc->uc_link).hi);

	AW(ti->ss_sp).lo = MAKE_SAP_LO(current->sas_ss_sp,
			current->sas_ss_size, 0, 3);
	AW(ti->ss_sp).hi = MAKE_SAP_HI(current->sas_ss_sp,
			current->sas_ss_size, 0, 3);
	rval |= copy_to_user_with_tags(&uc->uc_stack.ss_sp,
			&ti->ss_sp, sizeof(ti->ss_sp));
	rval |= __put_user(sas_ss_flags(AS_STRUCT(ss_usd_lo).base),
			&uc->uc_stack.ss_flags);
	rval |= __put_user(current->sas_ss_size, &uc->uc_stack.ss_size);

	rval |= setup_prot_frame(&uc->uc_mcontext, info, user_regs);

	rval |= __copy_to_user(&uc->uc_sigmask, oldset, sizeof(*oldset));

	return rval;
}
#endif	/* CONFIG_PROTECTED_MODE */

#define printk printk_fixed_args
static inline int setup_rt_frame(struct ucontext *uc, siginfo_t *u_si, siginfo_t *info,
		sigset_t *oldset, e2k_usd_lo_t ss_usd_lo, pt_regs_t *user_regs)
{
	int rval = 0;

	if (current->thread.flags & E2K_FLAG_32BIT) {
#ifdef CONFIG_PROTECTED_MODE
		if (!(current->thread.flags & E2K_FLAG_PROTECTED_MODE)) {
#endif	/* CONFIG_PROTECTED_MODE */
			if (current->thread.flags & E2K_FLAG_64BIT_BINCO)
				rval = copy_siginfo_to_user(u_si, info);
			else
				rval = copy_siginfo_to_user32(
					(compat_siginfo_t *) u_si, info);
			if (rval) {
				DebugHS("bad copy_siginfo_to_user32 from 0x%p to 0x%p rval %d\n",
					info, u_si, rval);
				return rval;
			}
			rval = setup_ucontext32((struct ucontext_32 *)uc, info,
					(sigset32_t *)oldset, ss_usd_lo,
					user_regs);
#ifdef CONFIG_PROTECTED_MODE
		} else {
			rval = copy_siginfo_to_user(u_si, info);
			if (rval) {
				DebugHS("bad copy_siginfo_"
					"to_user from 0x%p to 0x%p rval %d\n",
					info, u_si, rval);
				return rval;
			}
			rval = setup_ucontext_prot((struct ucontext_prot *) uc,
					info, oldset, ss_usd_lo, user_regs);
 		}
#endif	/* CONFIG_PROTECTED_MODE */
	} else {
		rval = copy_siginfo_to_user(u_si, info);
		if (rval) {
			DebugHS("bad copy_siginfo_to_user() "
				"from 0x%p to 0x%p rval %d\n",
				info, u_si, rval);
			return rval;
		}
		rval = setup_ucontext(uc, info, oldset, ss_usd_lo, user_regs);
	}

	return rval;
}
#undef printk

static int sigset_restore(rt_sigframe_t *user_sigframe, pt_regs_t *regs)
{
	struct k_sigaction *ka = &regs->ka;
	sigset_t *set_ptr;
	sigset_t set;

	if (ka->sa.sa_flags & SA_SIGINFO) {
		if (!(current->thread.flags & E2K_FLAG_32BIT)) {
			set_ptr = &user_sigframe->uc.uc_sigmask;
#ifdef CONFIG_PROTECTED_MODE
		} else if (current->thread.flags & E2K_FLAG_PROTECTED_MODE) {
			struct ucontext_prot *uc;

			uc = (struct ucontext_prot *) &user_sigframe->uc;
			set_ptr = &uc->uc_sigmask;
#endif
		} else {
			struct ucontext_32 *uc;

			uc = (struct ucontext_32 *) &user_sigframe->uc;
			set_ptr = (sigset_t *) &uc->uc_sigmask;
		}
	} else {
		set_ptr = &user_sigframe->saved_set;
	}

	if (copy_from_user(&set, set_ptr, sizeof(set))) {
		force_sig(SIGSEGV, current);
		return -EFAULT;
	}

	/*
	 * All bellow as sys_rt_sigreturn for i386
	 */
	sigdelsetmask(&set, ~_BLOCKABLE);
	spin_lock_irq(&current->sighand->siglock);
	current->blocked = set;
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
	DebugSig("signal pending is %d\n",
		signal_pending(current));

	return 0;
}


#define	synchronize_user_stack() {} /* Nothing to do. RF is already flushed. */
#define	save_and_clear_fpu()	 {} /* NEEDSWORK */


#define printk printk_fixed_args
#define panic panic_fixed_args
noinline notrace __protect __interrupt
void go2user(long fn)
{
	register e2k_cr1_lo_t	cr1_lo;
	register e2k_cr0_hi_t 	cr0_hi;
	register e2k_cuir_t	cuir;
	register e2k_psr_t	psr;

//	DebugSig("start fn is 0x%lx\n", fn);
	AS_WORD(cr1_lo) = E2K_GET_DSREG_NV(cr1.lo);
	AS_WORD(cr0_hi) = E2K_GET_DSREG_NV(cr0.hi);

	AS_WORD(psr) = 0;
	AS_STRUCT(psr).sge = 1;
	AS_STRUCT(psr).ie = 1;			/* sti(); */
	AS_STRUCT(psr).nmie = 1;		/* nm sti(); */
	AS_STRUCT(psr).pm = 0;			/* user mode */
	AS_STRUCT(cr1_lo).psr = AS_WORD(psr);
	AS_STRUCT(cr0_hi).ip = fn >> 3;		/* start user IP */

	AS_WORD(cuir) = 0;	// AS_STRUCT(cuir).checkup = 0 too
#if 0
		if ((current->thread.flags & E2K_FLAG_32BIT)) {
			AS_STRUCT(cuir).index = USER_CODES_32_INDEX;
		} else {
			AS_STRUCT(cuir).index = USER_CODES_START_INDEX;
		}
#endif
	AS_STRUCT(cr1_lo).cuir = AS_WORD(cuir);

	if (!psr_irqs_disabled())
		panic_fixed_args("go2user: under sti\n");
	E2K_SET_DSREG_NV_NOIRQ(cr1.lo, AS_WORD(cr1_lo));
	E2K_SET_DSREG_NV_NOIRQ(cr0.hi, AS_WORD(cr0_hi));
//	DebugHS("cr1.lo 0x%lx cr0.hi 0x%lx\n",
//		AS_WORD(cr1_lo), AS_WORD(cr0_hi));

//	DebugHS("usd.hi %lx usd.lo %lx\n",
//		READ_USD_HI_REG_VALUE(), READ_USD_LO_REG_VALUE());
//	DebugHS("finish\n");

#ifdef CONFIG_CLI_CHECK_TIME
	sti_return();
#endif

#ifdef CONFIG_PROTECTED_MODE
	if ((current->thread.flags & E2K_FLAG_PROTECTED_MODE)) {
		e2k_usd_lo_t usd_lo;
		usd_lo = READ_USD_LO_REG();
		usd_lo.USD_lo_p = 1;
                usd_lo.USD_lo_base = (usd_lo.USD_lo_base & 0xFFFFFFFF) | 
			(current_thread_info()->pusd_pil + 0x100000000);
		// correct usd as if we are entered by call
		// hope we don't overflow psl field
		WRITE_USD_LO_REG(usd_lo);
		ENABLE_US_CLW();
	}
#endif
	/*
	 * Set UPSR register in the initial state for user process
	 */
	WRITE_UPSR_REG(current_thread_info()->upsr);

	/* Restore user global registers. This is needed only for binco,
	 * since for e2k applications g16-g31 registers are actually local. */
	E2K_RESTORE_GREG_IN_TRAP(current_thread_info()->gbase,
				 current_thread_info()->gext, 16, 17, 18, 19);

	/* Prevent kernel information leakage */
#if E2K_MAXSR != 112
# error Must clear all registers here
#endif
#ifndef CONFIG_E2S_CPU_RF_BUG
	E2K_CLEAR_RF_112();
#endif
}
#undef printk
#undef panic

__protect
extern void prot_as_sa_handler(long r0, long r1, int sig, long fn,
		long r4, long r5, long r6, long r7,
		e2k_sbr_t sbr, e2k_usd_lo_t usd_lo, e2k_usd_hi_t usd_hi);
#ifdef CONFIG_PROTECTED_MODE
__protect
extern void as_sa_handler_not_protect(int sig, siginfo_t *sip,
		struct ucontext *env, long fn,
		e2k_sbr_t sbr, e2k_usd_lo_t usd_lo, e2k_usd_hi_t usd_hi);
#endif

/*
 * as_sa_handler() invokes a hook to enter the signal handler
 * after return from go2user().
 *
 * The hook will work in user mode (pm = 0) but its cr0.lo will
 * have pm set to 1 (see go2user() above).
 *
 * We are to remember that we work on user resources here.
 */
notrace noinline void __protect
as_sa_handler(int sig, siginfo_t *sip, struct ucontext *env, long fn,
		e2k_sbr_t sbr, e2k_usd_lo_t usd_lo, e2k_usd_hi_t usd_hi)
{
#ifdef CONFIG_PROTECTED_MODE
	struct thread_info *ti;
	u64	m[8];
	u64 a = (u64)m;
#endif

#ifdef CONFIG_PROTECTED_MODE
	if (!(current->thread.flags & E2K_FLAG_PROTECTED_MODE)) {
		as_sa_handler_not_protect(sig, sip, env, fn,
				sbr, usd_lo, usd_hi);
	} else {
		a = (a + 15) & ~0x000000000000000FUL;
		prot_as_sa_handler(
			MAKE_AP_LO((unsigned long)a, 8*8, 0UL, RW_ENABLE),
			MAKE_AP_HI((unsigned long)a, 8*8, 0UL, RW_ENABLE),
			sig, fn,
			MAKE_AP_LO((unsigned long)sip, sizeof (siginfo_t),
				0UL, RW_ENABLE),
			MAKE_AP_HI((unsigned long)sip, sizeof (siginfo_t),
				0UL, RW_ENABLE),
			MAKE_AP_LO((unsigned long)env, sizeof ( *env),
				0UL, RW_ENABLE),
			MAKE_AP_HI((unsigned long)env, sizeof ( *env),
				0UL, RW_ENABLE),
			sbr, usd_lo, usd_hi);
	}
#else
	as_sa_handler_not_protect(sig, sip, env, fn,
			sbr, usd_lo, usd_hi);
#endif /* CONFIG_PROTECTED_MODE */

#ifdef CONFIG_PROTECTED_MODE
	ti = (struct thread_info *) E2K_GET_DSREG_NV(osr0);
	if (ti->task->thread.flags & E2K_FLAG_PROTECTED_MODE)
		DISABLE_US_CLW();
#endif
}

#ifdef	CONFIG_KERNEL_CODE_CONTEXT
extern notrace noinline __interrupt void __protect
start_handler_sequel(int sig, siginfo_t *sip, struct ucontext *env, long fn,
		e2k_sbr_t sbr, e2k_usd_lo_t usd_lo, e2k_usd_hi_t usd_hi,
		e2k_cutd_t u_cutd);

notrace __interrupt
static void hwbug_zero_cui_workaround(int sig, siginfo_t *u_si,
		struct ucontext *uc, long fn, u64 ss_sbr,
		u64 ss_usd_lo, u64 ss_usd_hi)
{
	e2k_cutd_t	k_cutd;
	u64		u_cutd;
	u64		k_usd_lo;
	void (*start_handler_sequel_func)(
			int sig, siginfo_t *sip, struct ucontext *env, long fn,
			u64 sbr, u64 usd_lo, u64 usd_hi, u64 u_cutd);

	u_cutd = E2K_GET_DSREG_NV(cutd);
	k_usd_lo = E2K_GET_DSREG_NV(usd.lo);
	start_handler_sequel_func = (typeof(start_handler_sequel_func))
		AS_WORD(MAKE_PRIV_PL((e2k_addr_t)&start_handler_sequel));
	E2K_PUTTAGD(start_handler_sequel_func, ETAGPLD);
	/*
	 * Cannot do
	 *
	 *     AS(k_usd_lo).p = 1;
	 *
	 * because of LCC problems with __check_stack
	 */
	k_usd_lo |= 1UL << 58;
	/* Since USD.p == 1, the next call will increase USD.psl.
	 * But USD is essentially non-protected so we do not want that. */
	k_usd_lo -= 0x100000000;
	WRITE_USD_LO_REG_VALUE(k_usd_lo);
	/* User CUT can be unavailable right now (swapped out),
	 * so set kernel CUT before switching to non-zero CUI
	 * (i.e. before accessing CUT). */
	AW(k_cutd) = 0;
	AS(k_cutd).base = (unsigned long) kernel_CUT;
	WRITE_CUTD_REG(k_cutd);
	start_handler_sequel_func(sig, u_si, uc, fn,
			ss_sbr, ss_usd_lo, ss_usd_hi, u_cutd);
}
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */

#define printk printk_fixed_args
#define panic panic_fixed_args
static __interrupt notrace int
handle_signal(unsigned long sig, sigset_t *oldset, struct pt_regs *regs)
{
	struct trap_pt_regs		*trap = regs->trap;
	register thread_info_t		*thread_info = current_thread_info();
	register struct k_sigaction	*ka = &regs->ka;
	register siginfo_t		*info = &regs->info;
	register pt_regs_t		*tmp;
	register rt_sigframe_t		*rt_sigframe;
	pt_regs_t			*env = NULL;
	struct ucontext			*uc = NULL;
	siginfo_t			*u_si = NULL;
	u64				ss_sbr, ss_sp, ss_stk_base, ss_stk_size;
	u64				sigframe_size, fn;
	e2k_usd_lo_t			ss_usd_lo;
	e2k_usd_hi_t			ss_usd_hi;
	int				rval = 0, err = 0, nr_signals;

	fn = (u64)(ka->sa.sa_handler);
	
	DebugHS("start addr %lx regs %p fn %lx\n",
		(trap) ? trap->tcellar[trap->curr_cnt].address : 0UL, regs, fn);

	if (ka->sa.sa_flags & SA_ONESHOT) {
		DebugHS("ka->sa.sa_handler = SIG_DFL\n");
		ka->sa.sa_handler = SIG_DFL;
	}

	/*
	 * We use stack frame, to have possibility to pass
	 * siginfo_t for handler. Maybe it isn't needed
	 * but maybe will be needed additional info.
	 * pt_regs are needed all time.
	 * ss_usd is signal stack usd.
	 * ss_usd can point to the current user stack or to sigaltstack
	 */

	BUG_ON(!user_mode(regs));

	nr_signals = 0;
	for (tmp = regs->next; tmp != NULL; tmp = tmp->next)
		++nr_signals;

	if (unlikely(nr_signals >= MAX_HANDLED_SIGS)) {
		pr_info_ratelimited("[%d] %s: maximum signal recursion reached\n",
				current->pid, current->comm);
		do_exit(SIGKILL);
	}

	ss_sbr		= regs->stacks.sbr;
	ss_usd_lo	= regs->stacks.usd_lo;
	ss_usd_hi	= regs->stacks.usd_hi;
	ss_sp 		= AS_STRUCT(ss_usd_lo).base;

	SAVE_USER_REGS_FROM_THREAD_INFO(thread_info, regs);
	if (ss_usd_lo.USD_lo_p) {
                current_thread_info()->pusd_pil = ss_sp & 0xFFF00000000;
		DebugHS("%s: saved pil = 0x%lx\n", __FUNCTION__, ss_sp & 0xFFF00000000);
		ss_sp = (ss_sp & 0xFFFFFFFF) + (ss_sbr & 0xFFF00000000);
	}
	ss_stk_size 	= AS_STRUCT(ss_usd_hi).size;
	ss_stk_base 	= ss_sp - ss_stk_size;
	
	DebugHS("ss_sp 0x%lx size 0x%lx ss_stk_base 0x%lx\n",
			ss_sp, ss_stk_size, ss_stk_base);
	DebugHS("usd.hi %lx usd.lo %lx\n",
		READ_USD_HI_REG_VALUE(), READ_USD_LO_REG_VALUE());
	sigframe_size = round_up(sizeof(rt_sigframe_t) + _PSIG_SIZE_,
				 E2K_ALIGN_USTACK);
	/* 
	 * This is the X/Open sanctioned signal stack switching
	 * to alt stack.
	 */
	if (ka->sa.sa_flags & SA_ONSTACK) {
		bool use_alt_stack = false;

		if (!on_sig_stack(ss_sp)) {
			u64 alt_ss_stk_base = round_up(current->sas_ss_sp,
						       E2K_ALIGN_USTACK);
			u64 alt_ss_stk_size = round_down(current->sas_ss_size +
					current->sas_ss_sp - alt_ss_stk_base,
					E2K_ALIGN_USTACK);

			DebugHS("SA_ONSTACK ss 0x%lx sz 0x%lx, after aligning ss 0x%lx sz 0x%lx\n",
				current->sas_ss_sp, current->sas_ss_size,
				alt_ss_stk_base, alt_ss_stk_size);
			if (alt_ss_stk_size >= sigframe_size) {
				ss_stk_base = alt_ss_stk_base;
				ss_stk_size = alt_ss_stk_size;
				ss_sp = ss_stk_base + ss_stk_size;
				use_alt_stack = true;
			} else
				DebugHS("alternative stack size 0x%lx < 0x%lx needed to pass signal info and context. Using standart stack.\n",
					ss_stk_size, sigframe_size);
		}

		if (use_alt_stack) {
			AS_STRUCT(ss_usd_lo).base = ss_stk_base;
			STORE_USER_REGS_TO_THREAD_INFO(thread_info,
				      ss_stk_base,
				      ss_stk_base + ss_stk_size,
				      ss_stk_size
				      );
		}
	}

	while (ss_stk_size < sigframe_size) {
		DebugHS("user stack size 0x%lx < 0x%lx needed to pass signal info and context\n",
			ss_stk_size, sigframe_size);
		if (expand_user_data_stack(regs, current, false)) {
			pr_info_ratelimited("[%d] %s: user data stack overflow\n",
				current->pid, current->comm);
			do_exit(SIGKILL);
		}
		ss_sbr		= regs->stacks.sbr;
		ss_usd_lo	= regs->stacks.usd_lo;
		ss_usd_hi	= regs->stacks.usd_hi;
		ss_sp 		= AS_STRUCT(ss_usd_lo).base;
                if (ss_usd_lo.USD_lo_p) {
                       ss_sp = (ss_sp &0xFFFFFFFF) + (ss_sbr & 0xFFF00000000);
                }

		ss_stk_size 	= AS_STRUCT(ss_usd_hi).size;
		ss_stk_base 	= ss_sp - ss_stk_size;
	
		DebugHS("expanded stack: ss_sp 0x%lx size 0x%lx ss_stk_base 0x%lx\n",
			ss_sp, ss_stk_size, ss_stk_base);
	}

	rt_sigframe = (rt_sigframe_t *) (ss_sp - sizeof(rt_sigframe_t));
	
	ss_sp -= sigframe_size;

	DebugHS("rt_sigframe %p\n", rt_sigframe);
	
	if (!access_ok(VERIFY_WRITE, rt_sigframe, sizeof(rt_sigframe_t))) {
		DebugHS("access failed to user stack frame base 0x%lx size 0x%lx sp 0x%lx\n",
			ss_stk_base, ss_stk_size, ss_sp);
		goto give_sigsegv;
	}
	u_si = &(rt_sigframe->info);
	uc = &(rt_sigframe->uc);

	if (__copy_to_user(&rt_sigframe->saved_set, oldset, sizeof(sigset_t)))
		goto give_sigsegv;

	if (TASK_IS_BINCO(current))
		SAVE_RPR_REGS(regs);

	if (ka->sa.sa_flags & SA_SIGINFO) {
		err = setup_rt_frame(uc, u_si, info, oldset,
						ss_usd_lo, regs);
		if (err)
			goto give_sigsegv;
	} else
	{
		err = setup_frame((struct sigcontext *)u_si, info,
						&uc->uc_extra, regs);
		if (err)
			goto give_sigsegv;
	}

	/* To do new usd */
#ifdef CONFIG_PROTECTED_MODE
        if (current->thread.flags & E2K_FLAG_PROTECTED_MODE) {
		/* let's work with unprotected usd  */
	        /* change it in last moment */
		ss_usd_lo.USD_lo_p = 0;
	}
#endif
	AS_STRUCT(ss_usd_lo).base = ss_sp;
	ss_stk_size = (ss_sp - ss_stk_base);
	AS_STRUCT(ss_usd_hi).size = ss_stk_size;
	DebugHS("ss_stk_size %lx\n", ss_stk_size);

	DebugHS("ss_usd_lo.base %lx ss_usd_hi.size %lx\n",
		AS_STRUCT(ss_usd_lo).base, AS_STRUCT(ss_usd_hi).size);
	DebugHS("ss_usd_lo %lx ss_usd_hi %lx\n",
		(u64)AS_WORD(ss_usd_lo), (u64)AS_WORD(ss_usd_hi));

	/*
	 * Go to user hard stack and user c-stack but we will continue
	 * to work in kernel mode using window regs only befor
	 * we ret to user handler.
	 */

	DebugHS("handle_signal() will start handler() 0x%lx for sig #%ld sig_info %p env %p\n",
		fn, sig, u_si, env);

	/*
	 * Do this after the point of no return and after we have
	 * used "oldset" (which may point to current->blocked).
	 */
	spin_lock_irq(&current->sighand->siglock);
	sigorsets(&current->blocked, &current->blocked, &ka->sa.sa_mask);
	if (!(ka->sa.sa_flags & SA_NODEFER)) {
		DebugHS("! SA_NODEFER\n");
		sigaddset(&current->blocked, sig);
	}
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	/* Critical section here is short and tracing it is error-prone
	 * since we switch stacks */
	raw_all_irq_disable();

	/*
	 * Notify kernel that we are ready to call signal handler.
	 * Do this under closed interrupts to avoid races with interrupt
	 * handlers adding work for us to do (interrupts will be reenabled
	 * only after switching to user).
	 */
	while (test_thread_flag(TIF_NOTIFY_RESUME)) {
		raw_all_irq_enable();
		clear_thread_flag(TIF_NOTIFY_RESUME);
		/* We do not have pt_regs that correspond to
		 * the handler context so just pass NULL. */
		do_notify_resume(NULL);
		raw_all_irq_disable();
	}

	/*
	 * User function will be executed under PSR interrupts control
	 * and kernel should return interrupts mask control to PSR register
	 * (if it needs), before as_sa_handler() call to save this PSR into
	 * CR rigester from which register will be recovered while user
	 * function return. Otherwise it can be saved with control under UPSR.
	 * But UPSR is global register and it state can be modified by user
	 * and kernel will inherit user's UPSR, where interrupts is enable
	 * when they should be disabled in this point (see above).
	 */

	RETURN_IRQ_TO_PSR();

	if (from_trap(regs))
		exception_exit(regs->trap->prev_state);
	else
		user_enter();

	/*
	 * Set current state of kernel stacks as entry points to switch
	 * to kernel stack to enable recursive traps on user handler
	 */
	AW(thread_info->k_usd_hi) = READ_USD_HI_REG_VALUE();
	AW(thread_info->k_usd_lo) = READ_USD_LO_REG_VALUE();
	CHECK_TI_K_USD_SIZE(thread_info);

#ifdef	CONFIG_KERNEL_CODE_CONTEXT
	hwbug_zero_cui_workaround(sig, u_si, uc, fn,
			ss_sbr, AW(ss_usd_lo), AW(ss_usd_hi));
#else
	as_sa_handler(sig, u_si, uc, fn, ss_sbr, ss_usd_lo, ss_usd_hi);
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */

	/*
	 * Save new values of g16-g19 and set current pointers.
	 * This must be done at the same level as restoring %sbr,
	 * otherwise user_trap_handler() will save kernel values
	 * of global registers into thread_info.
	 */
	thread_info = (struct thread_info *) E2K_GET_DSREG_NV(osr0);
	E2K_SAVE_GREG(thread_info->gbase, thread_info->gext,
		      thread_info->tag, 16, 17);
	E2K_SAVE_GREG(&thread_info->gbase[2], &thread_info->gext[2],
		      &thread_info->tag[2], 18, 19);
	E2K_SET_DGREG_NV(16, thread_info);
	E2K_SET_DGREG_NV(17, thread_info->task);
	E2K_SET_DGREG_NV(19, (u64) thread_info->cpu);
	set_my_cpu_offset(per_cpu_offset(raw_smp_processor_id()));

	/*
	 * User process can do fork() in the signal handler and
	 * we can return here from the son on other kernel stacks
	 * Restore all address info related to kernel stacks and
	 * task & thread_info structures
	 */
	regs = thread_info->pt_regs;
	BUG_ON(!user_mode(regs));
	CHECK_CT_INTERRUPTED(regs);

	/*
	 * We will return from user here and will be under cli and
	 * under PSR control. Restore kernel UPSR register state and
	 * switch to UPSR interrupts control (if needs)
	 */
	DO_SAVE_UPSR_REG(current_thread_info()->upsr);

	SET_KERNEL_UPSR_WITH_DISABLED_NMI(0);

	/*
	 * We continue to work on user hard stack.
	 * But we should return on kernel resources
	 */
#ifdef CONFIG_CLI_CHECK_TIME
	check_cli();
#endif

	/*
	 * Return to kernel stacks
	 * If hardware stacks are common for user and kernel, we do not
	 * return to user stacks and continue on the same stacks
	 */
	WRITE_SBR_REG_VALUE(thread_info->k_stk_base + thread_info->k_stk_sz);
	WRITE_USD_REG_VALUE(AW(thread_info->k_usd_hi),
					AW(thread_info->k_usd_lo));

	CHECK_TI_K_USD_SIZE(thread_info);

	if (rval) {
		E2K_SET_USER_STACK(1);
		panic("handle_signal(): could not find user pt_regs structure after return from signal handler\n");
	}

	if (from_trap(regs))
		regs->trap->prev_state = exception_enter();
	else
		user_exit();

	/* Critical section here is short and tracing it is error-prone
	 * since we switch stacks */
	raw_all_irq_enable();

	/*
	 * rt_sigreturn() is sys_call and we get trap and call ttable_entry().
	 * We will return to user according to regs (arg of rt_sigreturn).
	 */
	if (DEBUG_HS_MODE && signal_pending(current)) {
		E2K_SET_USER_STACK(1);
		DebugHS("we get sig again\n");
	}
	if (DEBUG_HS_MODE) {
		e2k_psp_hi_t	psp_hi;
		e2k_pcsp_hi_t	pcsp_hi;
		e2k_pshtp_t	pshtp;
		e2k_pcshtp_t	pcshtp;

		E2K_SET_USER_STACK(1);
		raw_all_irq_disable();
		psp_hi = READ_PSP_HI_REG();
		pshtp = READ_PSHTP_REG();
		pcsp_hi = READ_PCSP_HI_REG();
		pcshtp = READ_PCSHTP_REG();
		raw_all_irq_enable();
		DebugHS("after user handler PS: ind 0x%lx, pshtp.ind 0x%lx, size 0x%lx, k_sz 0x%lx\n",
			psp_hi.PSP_hi_ind, GET_PSHTP_INDEX(pshtp),
			psp_hi.PSP_hi_size, KERNEL_P_STACK_SIZE);
		DebugHS("after user handler PCS: ind 0x%lx, pcshtp.ind 0x%lx, size 0x%lx, k_sz 0x%lx\n",
			pcsp_hi.PCSP_hi_ind, PCSHTP_SIGN_EXTEND(pcshtp),
			pcsp_hi.PCSP_hi_size, KERNEL_PC_STACK_SIZE);
		DebugHS("will start rt_sigreturn() with regs 0x%p\n",
			regs);
	}

	RESTORE_USER_REGS_TO_THREAD_INFO(thread_info, regs);
	do_sigreturn(regs, sig, rt_sigframe);

	return 0;
	
give_sigsegv:
	force_sigsegv(sig, current);

	DebugHS("force_sig_info return\n");

	return -EFAULT;
}
#undef printk
#undef panic

/*
 * Note that 'init' is a special process: it doesn't get signals it doesn't
 * want to handle. Thus you cannot kill init even with a SIGKILL even by
 * mistake.
 */
#define printk printk_fixed_args
#define panic panic_fixed_args
int __interrupt do_signal(struct pt_regs *regs)
{
	siginfo_t		*info = &regs->info;
	struct k_sigaction      *ka = &regs->ka;
	int			signr;
	long			errno = regs->sys_rval;
	sigset_t		*oldset;

	BUG_ON(sge_checking_enabled());

	if (TASK_IS_BINCO(current))
		clear_delayed_signal_handling(current_thread_info());

	if (current_thread_info()->status & TS_RESTORE_SIGMASK)
		oldset = &current->saved_sigmask;
	else
		oldset = &current->blocked;

	DebugHS("start pid %d\n", current->pid);

	signr = get_signal_to_deliver(info, ka, regs, NULL);
	DebugHS("signr %d regs->sys_num == %ld\n",
			signr, regs->sys_num);
	if (signr > 0) {
		DebugHS("signr == %d ka is 0x%p\n", signr, ka);

		regs->restart_needed = 0;

		/* Are we from a system call? */
#if defined(CONFIG_SECONDARY_SPACE_SUPPORT)
		if (regs->sys_num >= 0 &&
				!current_thread_info()->sc_restart_ignore) {
#else
		if (regs->sys_num >= 0) {
#endif
			DebugHS("sys_num = %ld signr = %d errno %ld\n",
				regs->sys_num, signr, errno);
			/*
			 * If so, check system call restarting.
			 * It is done as for i386 (almost) but for i386
			 * for case -ERESTARTNOINTR:regs->eip -= 2;
			 * to do restart when we return from syscall.
			 * We here set restart_needed = 1 and do_signal
			 * returns -1.
			 */			
			switch (errno) {
			case -ERESTART_RESTARTBLOCK:
			case -ERESTARTNOHAND:
				regs->sys_rval = -EINTR;
				break;
			case -ERESTARTSYS:
				if (!((*ka).sa.sa_flags & SA_RESTART)) {
					regs->sys_rval = -EINTR;
					break;
				}
			/* fallthrough */
			case -ERESTARTNOINTR:
				regs->restart_needed = 1;
			}
			DebugHS("sys_rval = %ld restart = %ld\n",
					regs->sys_rval, regs->restart_needed);
		}

		/* Whee!  Actually deliver the signal.  */

		/*
		 * Before calling signal handler we save global registers and
		 * restore them after it returns. This is to support compiler
		 * optimization which uses %g16-%g31 global registers as local
		 * instead of using usual registers.
		 */
#ifdef CONFIG_GREGS_CONTEXT
		if (!TASK_IS_BINCO(current)) {
			E2K_MOVE_TAGGED_QWORD(&current_thread_info()->gbase[0],
					      &regs->gregs.gbase[0]);
			E2K_MOVE_TAGGED_QWORD(&current_thread_info()->gbase[2],
					      &regs->gregs.gbase[2]);
			regs->gregs.gext[0] = current_thread_info()->gext[0];
			regs->gregs.gext[1] = current_thread_info()->gext[1];
			regs->gregs.gext[2] = current_thread_info()->gext[2];
			regs->gregs.gext[3] = current_thread_info()->gext[3];
			SAVE_GLOBAL_REGISTERS_SIGNAL(&regs->gregs);
		}
#endif

		if (handle_signal(signr, oldset, regs) == 0) {
			/*
			 * A signal was successfully delivered; the saved
			 * sigmask have been stored in the signal frame
			 * and restored by do_sigreturn(), so we can simply
			 * clear the TS_RESTORE_SIGMASK flag.
			 */
			current_thread_info()->status &= ~TS_RESTORE_SIGMASK;
		}

		/*
		 * User process can do fork() in the signal handler and
		 * we can return here from the son on other kernel stacks.
		 * Restore all address info related to kernel stacks and
		 * task & thread_info structures.
		 */
		regs = current_thread_info()->pt_regs;

#ifdef CONFIG_GREGS_CONTEXT
		if (!TASK_IS_BINCO(current)) {
			LOAD_GLOBAL_REGISTERS_SIGNAL(&regs->gregs);
			E2K_MOVE_TAGGED_QWORD(&regs->gregs.gbase[0],
					      &current_thread_info()->gbase[0]);
			E2K_MOVE_TAGGED_QWORD(&regs->gregs.gbase[2],
					      &current_thread_info()->gbase[2]);
			current_thread_info()->gext[0] = regs->gregs.gext[0];
			current_thread_info()->gext[1] = regs->gregs.gext[1];
			current_thread_info()->gext[2] = regs->gregs.gext[2];
			current_thread_info()->gext[3] = regs->gregs.gext[3];
		}
#endif

		if (regs->restart_needed)
			return -1;
		return 1;
	}

#ifdef	CONFIG_DEBUG_INIT
	/*
	 * Only to debug kernel, if some test launch as init process
	 */
	if (current->pid <= 1)
		panic("do_signal: signal on Init so will be recursive traps or signals\n");
#endif	/* CONFIG_DEBUG_INIT */

	/* Did we come from a system call? */
#if defined(CONFIG_SECONDARY_SPACE_SUPPORT)
	if (regs->sys_num >= 0 &&
			!current_thread_info()->sc_restart_ignore) {
#else
	if (regs->sys_num >= 0) {
#endif
		/* Restart the system call - no handlers present */
		if (errno == -ERESTARTNOHAND ||
		    errno == -ERESTARTSYS ||
		    errno == -ERESTARTNOINTR) {
			DebugSig("ret -1 no handlers pid %d and replay syscall\n",
		    		current->pid);
		    	return -1;
		}
		if (errno == -ERESTART_RESTARTBLOCK){
			DebugSig("ret -1 no handlers pid %d and force the restart syscall\n",
		    		current->pid);
		    	return -ERESTART_RESTARTBLOCK;
		}
	}

	/*
	 * If there's no signal to deliver, we just put the saved sigmask back.
	 */
	if (current_thread_info()->status & TS_RESTORE_SIGMASK) {
		current_thread_info()->status &= ~TS_RESTORE_SIGMASK;
		sigprocmask(SIG_SETMASK, &current->saved_sigmask, NULL);
	}

	DebugSig("exited with 0\n");

	return 0;
}
#undef printk
#undef panic

static int
do_sigreturn(pt_regs_t *regs, unsigned long signo, rt_sigframe_t *user_sigframe)
{
	struct k_sigaction *ka = &regs->ka;
	struct trap_pt_regs *trap = regs->trap;
	int ret;

	if ((ret = sigset_restore(user_sigframe, regs)))
		return ret;

	if (ka->sa.sa_flags & SA_SIGINFO) {
		unsigned long long *u_cr0_hi;
		e2k_cr0_hi_t cr0_hi;

		/*
		 * User signal handler can change its return IP.
		 * Update kernel pt_regs struct with a new value.
		 */
		if (current->thread.flags & E2K_FLAG_32BIT) {
#ifdef CONFIG_PROTECTED_MODE
			if (!(current->thread.flags & E2K_FLAG_PROTECTED_MODE))
#endif
				u_cr0_hi = &(((struct ucontext_32 *)
				     (&user_sigframe->uc))->uc_mcontext.cr0_hi);
#ifdef CONFIG_PROTECTED_MODE
			else
				u_cr0_hi = &(((struct ucontext_prot *)
				     (&user_sigframe->uc))->uc_mcontext.cr0_hi);
#endif
		} else {
			u_cr0_hi = &(user_sigframe->uc.uc_mcontext.cr0_hi);
		}

		__get_user(AW(cr0_hi), u_cr0_hi);

		DebugSRT("update user process return IP u_cr0_hi =%p from 0x%lx to 0x%lx\n",
			u_cr0_hi, AS(regs->crs.cr0_hi).ip << 3,
			AS(cr0_hi).ip << 3);

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
			if (trap) {
				trap->tc_count = 0;
				DebugSRT("curr_cnt:%d tc_cnt:%d\n",
					trap->curr_cnt, trap->tc_count / 3);
			}

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
			regs->rp_ret = 0;
#endif

			AS(regs->crs.cr0_hi).ip = AS(cr0_hi).ip;
		}
	}

	if (trap && (3 * trap->curr_cnt) < trap->tc_count &&
			trap->tc_count > 0) {
		DebugSRT("continue intrpt addr %lx cnt %d tc_count %d\n",
			trap->tcellar[trap->curr_cnt].address,
			trap->curr_cnt, trap->tc_count);
		trap->from_sigreturn = 1;
		do_trap_cellar(regs, 0);
	}

	DebugSRT("return 0\n");
	return 0;
}


#ifdef CONFIG_FUNCTION_GRAPH_TRACER
/**
 * jump_graph_ftrace - mark skipped entries as finished in longjmp().
 * @limit - trim all frames after this.
 */
static notrace void jump_graph_ftrace(unsigned long limit)
{
	e2k_mem_crs_t *frame;
	unsigned long fp;
	unsigned long flags;
	unsigned long original_return_point;
	int index;

	if (current->curr_ret_stack < 0 || !current->ret_stack)
		return;

	/* We are removing psl_down windows from the top of the
	 * stack. Corresponding entries from current->ret_stack
	 * must be deleted (otherwise they will confuse ftrace
	 * itself, copy_thread() and do_execve()). */
# if DEBUG_FTRACE_MODE
	pr_info("%d: fixing ftrace stack\n", current->pid);
	for (index = 0; index <= current->curr_ret_stack; index++)
		pr_info("%d:\tentry at 0x%lx has %pS return value\n",
				current->pid, current->ret_stack[index].fp,
				current->ret_stack[index].ret);
# endif

	/*
	 * Remove all entries whose windows will be trimmed.
	 * We are currently here:
	 *
	 * ttable_entry -> ... -> jump_graph_ftrace
	 *
	 * Previous functions in chain stack could be replaced with
	 * return_to_handler_XX(). But consider the following situation:
	 *
	 * <user functions 1>
	 * <kernel functions 1>
	 * <user functions 2>
	 * <kernel functions 2>   <=== WE ARE HERE
	 *
	 * If we jump to <user functions 1> then we have to skip ftrace's
	 * ret_stack entries from <kernel functions 1>, but we must keep
	 * ttable_entry() which is in <kernel functions 2>. This is kinda
	 * awkward, and we have to mark all of those functions as finished
	 * right now.
	 */

	index = current->curr_ret_stack;
	fp = current->ret_stack[index].fp;

	/* Remove all trimmed entries from current->ret_stack,
	 * restoring pointers along the way. */
	while (index >= 0 && fp > limit) {
		DebugFTRACE("%d:\tremoving entry at 0x%lx (%pS)\n",
				current->pid, current->ret_stack[index].fp,
				current->ret_stack[index].ret);

		raw_all_irq_save(flags);
		original_return_point = ftrace_return_to_handler(fp);

		E2K_FLUSHC;
		E2K_FLUSH_WAIT;

		frame = (e2k_mem_crs_t *) fp;
		AW(frame->cr0_hi) = original_return_point;
		raw_all_irq_restore(flags);

		--index;
		if (index < 0)
			break;
		fp = current->ret_stack[index].fp;
	}
}
#endif /* CONFIG_FUNCTION_GRAPH_TRACER */

static void check_longjmp_permissions(u64 old_ip, u64 new_ip)
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
		SIGDEBUG_PRINT("SIGKILL. longjmp(): old and new IPs have different permissions\n");
		force_sig(SIGKILL, current);
	}
}



#if _NSIG != 64
# error Fix sigmask restoring in longjmp/setcontext
#endif
noinline
long do_longjmp(u64 retval, u64 jmp_sigmask, e2k_cr0_hi_t jmp_cr0_hi,
		e2k_cr1_lo_t jmp_cr1_lo, e2k_pcsp_lo_t jmp_pcsp_lo,
		e2k_pcsp_hi_t jmp_pcsp_hi, u32 jmp_br,
		u32 fpcr, u32 fpsr, u32 pfpfr, bool restore_fpu)
{
	thread_info_t		*thread_info = current_thread_info();
	long			rval = 0;
	pt_regs_t		*cur_regs;
	pt_regs_t		*regs;
	struct pt_regs		new_regs;
	e2k_psp_hi_t		psp_hi;
	e2k_pcsp_lo_t		pcsp_lo;
	e2k_pcsp_hi_t		pcsp_hi;
	s64			fp_ind;
	s64			cr_ind;
	e2k_addr_t		pcs_base_candidate;
	e2k_addr_t		ps_base_candidate;
	e2k_addr_t		pcs_window_base;
	e2k_addr_t		new_pcs_window_base;
	e2k_size_t		pcs_window_size;
	e2k_size_t		new_pcs_window_size;
	e2k_size_t		pcs_window_ind;
	e2k_size_t		new_pcs_window_ind;
	e2k_addr_t		new_sbr;
	e2k_addr_t		ps_base;
	e2k_addr_t		ps_window_offset;
	e2k_addr_t		pcs_ind;
	e2k_addr_t		pcs_base;
	e2k_addr_t		pcs_window_offset;
	e2k_addr_t		ps_ind;
	int			psl_down;
	int			ppsl_shift = 0;
	e2k_size_t		wd_psize;
	int			sw_num;
	int			sw;
	u64			ussz;
	e2k_mem_crs_t		*crs;
	struct hw_stack_area	*new_u_pcs;
	int			new_u_pcs_found = 0;

	cur_regs = thread_info->pt_regs;

	copy_jmp_regs(cur_regs, &new_regs);

	DebugSLJ("current regs 0x%p\n", cur_regs);

	DebugSLJ("system call from IP in CR0 0x%lx\n",
		AS_STRUCT(cur_regs->crs.cr0_hi).ip << 3);

	DebugSLJ("jump point sigmask 0x%lx ip 0x%lx cr1_lo 0x%lx : wbs 0x%x wpsz 0x%x wfx %d\n",
			jmp_sigmask, AW(jmp_cr0_hi), AW(jmp_cr1_lo),
			AS_STRUCT(jmp_cr1_lo).wbs,
			AS_STRUCT(jmp_cr1_lo).wpsz,
			AS_STRUCT(jmp_cr1_lo).wfx);
	DebugSLJ("jump point PCSP : base 0x%llx, ind 0x%x, size 0x%x\n",
			jmp_pcsp_lo.PCSP_lo_base, jmp_pcsp_hi.PCSP_hi_ind,
			jmp_pcsp_hi.PCSP_hi_size);

	check_longjmp_permissions(AS(cur_regs->crs.cr0_hi).ip << 3,
				  AS(jmp_cr0_hi).ip << 3);

	psp_hi = cur_regs->stacks.psp_hi;
	ps_base = (e2k_addr_t) GET_PS_BASE(thread_info);
	ps_window_offset = cur_regs->stacks.psp_lo.PSP_lo_base - ps_base;
	ps_ind = ps_window_offset + psp_hi.PSP_hi_ind;

	pcsp_lo = cur_regs->stacks.pcsp_lo;
	pcsp_hi = cur_regs->stacks.pcsp_hi;
	pcs_base = (e2k_addr_t) GET_PCS_BASE(thread_info);
	pcs_window_base = pcsp_lo.PCSP_lo_base;
	pcs_window_size = pcsp_hi.PCSP_hi_size;
	pcs_window_ind = pcsp_hi.PCSP_hi_ind;
	pcs_window_offset = pcs_window_base - pcs_base;
	pcs_ind = pcs_window_offset + pcs_window_ind;

	pcsp_lo.PCSP_lo_base = pcs_base;
	pcsp_hi.PCSP_hi_ind = pcs_ind;
	psp_hi.PSP_hi_ind = ps_ind;

	new_pcs_window_base = jmp_pcsp_lo.PCSP_lo_base;
	new_pcs_window_size = jmp_pcsp_hi.PCSP_hi_size;
	new_pcs_window_ind = jmp_pcsp_hi.PCSP_hi_ind;

	/*
	 * In the case of pseudo discontinuous user hardware stacks one should
	 * find an area of user hardware stack to make a longjmp to and correct
	 * new_pcs_window_base.
	 */
	if (UHWS_PSEUDO_MODE) {
		new_u_pcs = thread_info->cur_pcs;
		if (new_pcs_window_base < (e2k_addr_t)new_u_pcs->base ||
				new_pcs_window_base >=
					(e2k_addr_t)new_u_pcs->base +
					new_u_pcs->size) {
			list_for_each_entry(new_u_pcs,
					    &thread_info->old_u_pcs_list,
					    list_entry) {
				if (new_pcs_window_base >=
						(e2k_addr_t)new_u_pcs->base &&
							new_pcs_window_base <
						(e2k_addr_t)new_u_pcs->base +
							new_u_pcs->size) {
					new_u_pcs_found = 1;
					break;
				}
			}
			if (!new_u_pcs_found) {
				SIGDEBUG_PRINT("SIGKILL. do_longjmp(): couldn't find new_u_pcs\n");
				force_sig(SIGKILL, current);
				return 0;
			}
			new_pcs_window_base +=
				(e2k_addr_t)thread_info->cur_pcs->base -
				(e2k_addr_t)new_u_pcs->base;
		}
	}

	psl_down = ((pcs_window_base + pcs_window_ind) -
			(new_pcs_window_base + new_pcs_window_ind)) / SZ_OF_CR;

	if (current->thread.flags & E2K_FLAG_PROTECTED_MODE) {
		unsigned long flags;

		raw_all_irq_save(flags);
	        E2K_FLUSHC;	/* Chain stack only flushing is enough here.*/
		E2K_FLUSH_WAIT;
		crs = (e2k_mem_crs_t *) (pcs_window_base + pcs_window_ind);
		while (crs > (e2k_mem_crs_t *) (new_pcs_window_base +
				new_pcs_window_ind)) {
			if ((e2k_addr_t) crs < pcs_window_base) {
				raw_all_irq_restore(flags);
				SIGDEBUG_PRINT("SIGKILL. do_longjmp(): invalid parameters pcs_window_base:0x%lx pcs_window_ind:0x%lx new_pcs_window_base:0x%lx new_pcs_window_ind:0x%lx\n",
						pcs_window_base, pcs_window_ind,
						new_pcs_window_base,
						new_pcs_window_ind);
				force_sig(SIGKILL, current);
				return 0;
        		}        
	        	if ((AS_STRUCT(crs->cr0_hi).ip << 3) < TASK_SIZE) {
		        	 ppsl_shift++;
		        }
        		crs--;  
	        }
		raw_all_irq_restore(flags);
        }         

	DebugSLJ("current USD = 0x%lx : 0x%lx; psl_down = %d, ppsl_shift = %d\n ",
		AS_WORD(cur_regs->stacks.usd_hi),
		AS_WORD(cur_regs->stacks.usd_lo), psl_down, ppsl_shift);

	DebugSLJ("current psp=  0x%lx : 0x%lx to be constricted\n",
		AS_WORD(cur_regs->stacks.psp_hi),
		AS_WORD(cur_regs->stacks.psp_lo));

	if (ps_window_offset) {
		DebugSLJ("procedure stack absolute base addr 0x%lx, offset 0x%lx absolute ind 0x%lx\n",
			ps_base, ps_window_offset, ps_ind);
	}

	DebugSLJ("current chain stack base 0x%lx ind 0x%lx size 0x%lx will be constricted for %d level(s)\n",
		pcs_window_base, pcs_window_ind, pcs_window_size, psl_down);

	if (pcs_window_offset) {
		DebugSLJ("procedure chain stack absolute base addr 0x%lx, offset 0x%lx absolute ind 0x%lx\n",
			pcs_base, pcs_window_offset, pcs_ind);
	}

	go_hd_stk_down(psp_hi, pcsp_lo, pcsp_hi,
		psl_down, (e2k_addr_t *) &fp_ind, (e2k_addr_t *) &cr_ind,
		&wd_psize, &sw_num, &new_regs.crs, 1 /* user stacks */);

	DebugSLJ("jump point procedure stack ind 0x%lx, chain stack ind 0x%lx, WD_psize 0x%lx SW_num %d\n",
		fp_ind, cr_ind, wd_psize, sw_num);

	if (psl_down != 0) {
		e2k_size_t cur_wbs;	/* in quad registers */
		e2k_size_t jmp_wbs;
		e2k_size_t wd_size;
		e2k_size_t delta;
		e2k_size_t jmp_psize;

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
		jump_graph_ftrace(new_pcs_window_ind -
				(pcs_window_base - new_pcs_window_base));
#endif

		/*
		 * Need to correct procedure stack frame size of
		 * function to jump, as it was while setting jumping
		 * point. Now we can be here after trap (wd_psize == 0)
		 * or jumping function call some other function
		 * with other parametrs number. If parametrs number was
		 * changed it needs correct fp_ind for procedure stack
		 */
		cur_wbs = AS_STRUCT(new_regs.crs.cr1_lo).wbs;
		jmp_wbs = AS_STRUCT(jmp_cr1_lo).wbs;
		wd_size = cur_wbs + wd_psize;
		DebugSLJ("current CR1.wbs 0x%lx, jump point CR1.wbs 0x%lx WD.size should be 0x%lx\n",
			cur_wbs, jmp_wbs, wd_size);
		if (wd_size <= jmp_wbs) {
			SIGDEBUG_PRINT("SIGKILL. sys_e2k_longjmp2(): calculated jump point WD_size 0x%lx (CR1.wbs 0x%lx + WD.psize 0x%lx) <= 0x%lx received from jump info wbs\n",
					wd_size, cur_wbs, wd_psize, jmp_wbs);
			force_sig(SIGKILL, current);
			return 0;
		}
		delta = cur_wbs - jmp_wbs;
		if (delta != 0) {
			fp_ind -= (delta * EXT_4_NR_SZ);
			DebugSLJ("corrected jump point procedure stack ind 0x%lx\n",
				fp_ind);
		}
		jmp_psize = (wd_size - jmp_wbs) * E2K_NR_SIZE;
		delta = AS_STRUCT(new_regs.wd).psize - jmp_psize;
		DebugSLJ("current WD_psize 0x%x, jump point WD.psize 0x%lx\n",
			AS_STRUCT(new_regs.wd).psize, jmp_psize);
		if (delta != 0) {
			s64 new_wd_psize = AS_STRUCT(new_regs.wd).psize -
						delta;
			if (new_wd_psize <= 0) {
				SIGDEBUG_PRINT("SIGKILL. sys_e2k_longjmp2(): calculated jump point WD.psize 0x%lx <= 0 (was WD.psize 0x%x, should be 0x%lx)\n",
						new_wd_psize,
						AS_STRUCT(new_regs.wd).psize,
						jmp_psize);
				force_sig(SIGKILL, current);
				return 0;
			}
			AS_STRUCT(new_regs.wd).psize = new_wd_psize;
			DebugSLJ("corrected jump point WD_psize 0x%x\n",
				AS_STRUCT(new_regs.wd).psize);
		}
	}
	if (fp_ind < 0) {
		SIGDEBUG_PRINT("SIGKILL. sys_e2k_longjmp2(): jump point procedure stack index (-0x%llx) is out of user PS\n",
				-fp_ind);
		force_sig(SIGKILL, current);
		return 0;
	} else if (fp_ind < ps_window_offset) {
		/* Went below */
		DebugSLJ("jump point procedure stack ind (fp) is below of current active frame\n");
		ps_base_candidate = ps_base + fp_ind;

		new_regs.stacks.psp_lo.PSP_lo_base =
					ps_base_candidate & PAGE_MASK;
		new_regs.stacks.psp_hi.PSP_hi_ind  =
					ps_base_candidate & (~PAGE_MASK);
		DebugSLJ("jump point procedure stack new active frame base 0x%llx, ind 0x%x, size 0x%x\n",
			new_regs.stacks.psp_lo.PSP_lo_base,
			new_regs.stacks.psp_hi.PSP_hi_ind,
			new_regs.stacks.psp_hi.PSP_hi_size);
	} else if (fp_ind <= ps_window_offset +
				cur_regs->stacks.psp_hi.PSP_hi_ind) {

		/* Same frame */
		new_regs.stacks.psp_hi.PSP_hi_ind = fp_ind - ps_window_offset;
		DebugSLJ("jump point procedure stack is in the current active frame: base 0x%llx, ind 0x%x, size 0x%x\n",
			new_regs.stacks.psp_lo.PSP_lo_base,
			new_regs.stacks.psp_hi.PSP_hi_ind,
			new_regs.stacks.psp_hi.PSP_hi_size);
	} else {
		SIGDEBUG_PRINT("SIGKILL. sys_e2k_longjmp2(): jump point procedure stack index (0x%llx) can not be above of current active PS (0x%llx)\n",
				fp_ind, ps_window_offset +
					cur_regs->stacks.psp_hi.PSP_hi_ind);
		force_sig(SIGKILL, current);
		return 0;
	}

	if (cr_ind < 0) {
		SIGDEBUG_PRINT("SIGKILL. sys_e2k_longjmp2(): jump point procedure chain stack index (-0x%llx) is out of user PCS\n",
				-cr_ind);
		force_sig(SIGKILL, current);
		return 0;
	} else if (cr_ind < pcs_window_offset) {

		/* Went below */
		DebugSLJ("jump point procedure stack ind (fp) is below of current active frame\n");
		pcs_base_candidate = pcs_base + cr_ind;
		new_regs.stacks.pcsp_lo.PCSP_lo_base =
					pcs_base_candidate & PAGE_MASK;
		new_regs.stacks.pcsp_hi.PCSP_hi_ind  =
					pcs_base_candidate & (~PAGE_MASK);
		DebugSLJ("jump point procedure chain stack new active frame base 0x%llx, ind 0x%x, size 0x%x\n",
			new_regs.stacks.pcsp_lo.PCSP_lo_base,
			new_regs.stacks.pcsp_hi.PCSP_hi_ind,
			new_regs.stacks.pcsp_hi.PCSP_hi_size);
	} else if (cr_ind <= pcs_window_offset + pcs_window_ind) {

		/* Same frame */
		new_regs.stacks.pcsp_hi.PCSP_hi_ind = cr_ind -
				pcs_window_offset;
		DebugSLJ("jump point procedure chain stack is in the current active frame: base 0x%llx, ind 0x%x, size 0x%x\n",
			new_regs.stacks.pcsp_lo.PCSP_lo_base,
			new_regs.stacks.pcsp_hi.PCSP_hi_ind,
			new_regs.stacks.pcsp_hi.PCSP_hi_size);
	} else {
		SIGDEBUG_PRINT("SIGKILL. sys_e2k_longjmp2(): jump point procedure chain stack index (0x%llx) can not be above of current active PCS (0x%llx)\n",
				cr_ind, pcs_window_offset + pcs_window_ind);
		force_sig(SIGKILL, current);
		return 0;
	}
/*
	jmp_regs.sys_rval = (int)retval;
	if (retval == 0) jmp_regs.sys_rval = 1;
*/

	ussz = AS_STRUCT(new_regs.crs.cr1_hi).ussz << 4;
	DebugSLJ("jump point data stack size 0x%lx\n",
		ussz);

	new_regs.crs.cr1_lo = jmp_cr1_lo;
	DebugSLJ("jump point in mem CR1: wbs 0x%x, wpsz 0x%x, wfx %d\n",
		AS_STRUCT(new_regs.crs.cr1_lo).wbs,
		AS_STRUCT(new_regs.crs.cr1_lo).wpsz,
		AS_STRUCT(new_regs.crs.cr1_lo).wfx);
	DebugSLJ("jump point IP in mem CR0 0x%lx new IP 0x%lx\n",
		AS(new_regs.crs.cr0_hi).ip << 3, AS(jmp_cr0_hi).ip << 3);

	DebugSLJ("jump point BR in mem CR1 0x%x new BR 0x%x\n",
		AS_STRUCT(new_regs.crs.cr1_hi).br , jmp_br);

	AS_STRUCT(new_regs.crs.cr0_hi).ip = AS(jmp_cr0_hi).ip;
	AS_STRUCT(new_regs.crs.cr1_hi).br = jmp_br;
	
	/* we can be from user sig handler */

        /*
	 * constrict_hardware_stacks() is needed,
	 * because hard stacks (which we return for)
	 * can be less then now.
	 */
	rval = constrict_hardware_stacks(cur_regs, &new_regs);
	if (rval != 0) {
		SIGDEBUG_PRINT("SIGKILL. sys_e2k_longjmp2(): could not constrict hardware stacks\n");
		force_sig(SIGKILL, current);
		return 0;
	}

	/*
	 * Find first pt_regs structure near long jump point
	 * so delete all pt_regs to throw away
	 */
	local_irq_disable();
	
	regs = cur_regs;
	DebugSLJ("pt_regs list head is 0x%p\n",
		regs);
	for (sw = 0; sw < sw_num; sw ++) {
		CHECK_PT_REGS_LOOP(regs);
		regs = regs->next;
		if (regs == NULL) {
			panic("do_longjmp(): could not find pt_regs struture #%d in the list of thread regs\n",
				sw);
		}
	}
	if (!user_mode(regs)) {
		panic("do_longjmp(): find pt_regs struture #%d is not user regs structure\n",
			sw_num);
	}
	DebugSLJ("pt_regs to jump is 0x%p\n",
		regs);
	new_regs.next = regs->next;
	CHECK_PT_REGS_LOOP(new_regs.next);

	/*
	 * usd stack restoration if signal SA_ONSTACK flag set
	 */
#ifdef CONFIG_PROTECTED_MODE
	if (current->thread.flags & E2K_FLAG_PROTECTED_MODE) {
		/*
		 * For protected mode in define SAVE_USER_USD_REGS
		 * (regs)->stacks.usd_lo.USD_lo_half = pusd_lo.PUSD_lo_half
		 * It needs only  address in PUSD_lo_base (last 32 bits)
		 */
		new_sbr = (AS_STRUCT(regs->stacks.usd_lo).base & 0xffffffff) -
			AS_STRUCT(regs->stacks.usd_hi).size;
	} else {
#endif /* CONFIG_PROTECTED_MODE */
		new_sbr = AS_STRUCT(regs->stacks.usd_lo).base -
			AS_STRUCT(regs->stacks.usd_hi).size;
#ifdef CONFIG_PROTECTED_MODE
	}
#endif /* CONFIG_PROTECTED_MODE */

	AS_STRUCT(new_regs.stacks.usd_lo).base = new_sbr + ussz;
	AS_STRUCT(new_regs.stacks.usd_hi).size = ussz;

#ifdef CONFIG_PROTECTED_MODE
	/* delete global pointers to the local stack */
	if (current->thread.flags & E2K_FLAG_PROTECTED_MODE) {
		int jmp_psl;
		e2k_pusd_lo_t *pusd_lo, *new_pusd_lo;

		pusd_lo = (e2k_pusd_lo_t *) &cur_regs->stacks.usd_lo;
		new_pusd_lo = (e2k_pusd_lo_t *) &new_regs.stacks.usd_lo;

		jmp_psl = (AS(*pusd_lo).psl) - ppsl_shift;

		ASP(new_pusd_lo).psl = jmp_psl;

		DebugSLJ("new USD = %lx:%lx NEW psl is %d ppsl_shift=%d psl_down=%d\n",
			AS_WORD(new_regs.stacks.usd_hi),
			AS_WORD(new_regs.stacks.usd_lo),
			ASP(pusd_lo).psl, ppsl_shift , psl_down);
        
		if (jmp_psl * SZ_OF_CR > new_pcs_window_ind) {
			pr_info(" BAD in longjmp() new_pcs_window_ind:0x %ld jmp_psl=%d(%ld)\n",
					new_pcs_window_ind, jmp_psl,
					jmp_psl * SZ_OF_CR);

			ASP(new_pusd_lo).psl = jmp_psl;
                }    
		delete_records(jmp_psl);

		DebugSLJ("jump point pusd_lo.psl %d\n", ASP(pusd_lo).psl);
	}
#endif
	DebugSLJ("jump point psl_down %d\n", psl_down);
	
	DebugSLJ("new USD = %lx:%lx\n",
			AS_WORD(new_regs.stacks.usd_hi),
			AS_WORD(new_regs.stacks.usd_lo));

	copy_jmp_regs(&new_regs, regs);
	adjust_intr_counter(regs);
	thread_info->pt_regs = regs;
	thread_info->u_stk_base = new_sbr;
	if (jmp_sigmask & sigmask(SIGKILL)) {
		jmp_sigmask &= _BLOCKABLE;
		(&current->blocked)->sig[0] = jmp_sigmask;
		recalc_sigpending();
	}
	local_irq_enable();

	if (restore_fpu) {
		E2K_SET_SREG_NV(fpcr, fpcr);
		E2K_SET_SREG_NV(fpsr, fpsr);
		E2K_SET_SREG_NV(pfpfr, pfpfr);
	}

	return retval;
}

long sys_e2k_longjmp2(struct jmp_info *env, u64 retval)
{
	struct jmp_info	jmp_info;
	int rval;

	DebugSLJ("pid %d start env %p retval %ld\n",
		current->pid, env, retval);

	rval = copy_jmpinfo_from_user(env, &jmp_info);
	if (rval) {
		SIGDEBUG_PRINT("SIGKILL. sys_e2k_longjmp2(): could not copy jump info from user env 0x%p\n",
				env);
		force_sig(SIGKILL, current);
		return rval;
	}

	return do_longjmp(retval, jmp_info.sigmask,
			(e2k_cr0_hi_t) jmp_info.ip,
			(e2k_cr1_lo_t) jmp_info.cr1lo,
			(e2k_pcsp_lo_t) jmp_info.pcsplo, (e2k_pcsp_hi_t)
			(jmp_info.pcsphi + PCSHTP_SIGN_EXTEND(jmp_info.pcshtp)),
			jmp_info.br, 0, 0, 0, 0);
}

long sys_setcontext(const struct ucontext __user *ucp, int sigsetsize)
{
	int rval;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	u64 sigmask, prev_key, next_key;
	u32 fpcr, fpsr, pfpfr;

	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (!access_ok(ACCESS_WRITE, ucp, sizeof(struct ucontext)))
		return -EFAULT;

	rval = __get_user(next_key, &ucp->uc_mcontext.sbr);
	if (rval)
		return -EFAULT;

	prev_key = context_ti_key(current_thread_info());

	DebugCTX("ucp=%lx current key=0x%lx next key=0x%lx\n",
			ucp, prev_key, next_key);
	if (!context_keys_equal(prev_key, next_key))
		return do_swapcontext(NULL, ucp, false, CTX_64_BIT);

	rval = __copy_from_user(&sigmask, &ucp->uc_sigmask,
			sizeof(ucp->uc_sigmask));
	rval |= __get_user(AW(cr0_hi), &ucp->uc_mcontext.cr0_hi);
	rval |= __get_user(AW(cr1_lo), &ucp->uc_mcontext.cr1_lo);
	rval |= __get_user(AW(cr1_hi), &ucp->uc_mcontext.cr1_hi);
	rval |= __get_user(AW(pcsp_lo), &ucp->uc_mcontext.pcsp_lo);
	rval |= __get_user(AW(pcsp_hi), &ucp->uc_mcontext.pcsp_hi);
	rval |= __get_user(fpcr, &ucp->uc_extra.fpcr);
	rval |= __get_user(fpsr, &ucp->uc_extra.fpsr);
	rval |= __get_user(pfpfr, &ucp->uc_extra.pfpfr);
	if (rval)
		return -EFAULT;

	/* A hack to make do_longjmp() restore blocked signals mask */
	sigmask |= sigmask(SIGKILL);

	DebugCTX("calling longjmp\n");
	do_longjmp(0, sigmask, cr0_hi, cr1_lo, pcsp_lo, pcsp_hi,
			AS(cr1_hi).br, fpcr, fpsr, pfpfr, 1);

	return 0;
}

#ifdef CONFIG_COMPAT
long compat_sys_setcontext(const struct ucontext_32 __user *ucp,
		int sigsetsize)
{
	int rval;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	u64 sigmask, prev_key, next_key;
	u32 fpcr, fpsr, pfpfr;

	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (!access_ok(ACCESS_WRITE, ucp, sizeof(struct ucontext)))
		return -EFAULT;

	rval = __get_user(next_key, &ucp->uc_mcontext.sbr);
	if (rval)
		return -EFAULT;

	prev_key = context_ti_key(current_thread_info());

	DebugCTX("ucp=%lx current key=0x%lx next key=0x%lx\n",
			ucp, prev_key, next_key);
	if (!context_keys_equal(prev_key, next_key))
		return do_swapcontext(NULL, ucp, false, CTX_32_BIT);

	rval = __copy_from_user(&sigmask, &ucp->uc_sigmask,
			sizeof(ucp->uc_sigmask));
	rval |= __get_user(AW(cr0_hi), &ucp->uc_mcontext.cr0_hi);
	rval |= __get_user(AW(cr1_lo), &ucp->uc_mcontext.cr1_lo);
	rval |= __get_user(AW(cr1_hi), &ucp->uc_mcontext.cr1_hi);
	rval |= __get_user(AW(pcsp_lo), &ucp->uc_mcontext.pcsp_lo);
	rval |= __get_user(AW(pcsp_hi), &ucp->uc_mcontext.pcsp_hi);
	rval |= __get_user(fpcr, &ucp->uc_extra.fpcr);
	rval |= __get_user(fpsr, &ucp->uc_extra.fpsr);
	rval |= __get_user(pfpfr, &ucp->uc_extra.pfpfr);
	if (rval)
		return -EFAULT;

	/* A hack to make do_longjmp() restore blocked signals mask */
	sigmask |= sigmask(SIGKILL);

	DebugCTX("calling longjmp\n");
	do_longjmp(0, sigmask, cr0_hi, cr1_lo, pcsp_lo, pcsp_hi,
			AS(cr1_hi).br, fpcr, fpsr, pfpfr, 1);

	return 0;
}
#endif

#ifdef CONFIG_PROTECTED_MODE
long protected_sys_setcontext(const struct ucontext_prot __user *ucp,
		int sigsetsize)
{
	int rval;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	u64 sigmask, prev_key, next_key;
	u32 fpcr, fpsr, pfpfr;

	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (!access_ok(ACCESS_WRITE, ucp, sizeof(struct ucontext)))
		return -EFAULT;

	rval = __get_user(next_key, &ucp->uc_mcontext.sbr);
	if (rval)
		return -EFAULT;

	prev_key = context_ti_key(current_thread_info());

	DebugCTX("ucp=%lx current key=0x%lx next key=0x%lx\n",
			ucp, prev_key, next_key);
	if (!context_keys_equal(prev_key, next_key))
		return do_swapcontext(NULL, ucp, false, CTX_128_BIT);

	rval = __copy_from_user(&sigmask, &ucp->uc_sigmask,
			sizeof(ucp->uc_sigmask));
	rval |= __get_user(AW(cr0_hi), &ucp->uc_mcontext.cr0_hi);
	rval |= __get_user(AW(cr1_lo), &ucp->uc_mcontext.cr1_lo);
	rval |= __get_user(AW(cr1_hi), &ucp->uc_mcontext.cr1_hi);
	rval |= __get_user(AW(pcsp_lo), &ucp->uc_mcontext.pcsp_lo);
	rval |= __get_user(AW(pcsp_hi), &ucp->uc_mcontext.pcsp_hi);
	rval |= __get_user(fpcr, &ucp->uc_extra.fpcr);
	rval |= __get_user(fpsr, &ucp->uc_extra.fpsr);
	rval |= __get_user(pfpfr, &ucp->uc_extra.pfpfr);
	if (rval)
		return -EFAULT;

	/* A hack to make do_longjmp() restore blocked signals mask */
	sigmask |= sigmask(SIGKILL);

	DebugCTX("calling longjmp\n");
	do_longjmp(0, sigmask, cr0_hi, cr1_lo, pcsp_lo, pcsp_hi,
			AS(cr1_hi).br, fpcr, fpsr, pfpfr, 1);

	return 0;
}
#endif

