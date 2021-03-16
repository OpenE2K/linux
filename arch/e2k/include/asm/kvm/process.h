/*
 * KVM guest kernel processes support
 * Copyright 2011 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_KVM_PROCESS_H
#define _E2K_KVM_PROCESS_H

#include <linux/kvm_host.h>

#include <asm/cpu_regs.h>
#include <asm/regs_state.h>
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

extern void kvm_clear_host_thread_info(thread_info_t *ti);
extern gthread_info_t *create_guest_start_thread_info(struct kvm_vcpu *vcpu);
extern int kvm_resume_vm_thread(void);

extern int kvm_correct_guest_trap_return_ip(unsigned long return_ip);

extern long return_pv_vcpu_syscall_fork(void);

/*
 * Is the CPU at guest Hardware Virtualized mode
 * CORE_MODE.gmi is true only at guest HV mode
 */
static inline bool is_CPU_at_guest_hv_vm_mode(void)
{
	e2k_core_mode_t CORE_MODE;

	CORE_MODE.CORE_MODE_reg = native_read_CORE_MODE_reg_value();
	if (CORE_MODE.CORE_MODE_gmi) {
		return true;
	}
	return false;
}
#ifdef	CONFIG_KVM_HOST_MODE
/* it is native host kernel with virtualization support */
/* or it is paravirtualized host and guest kernel */
static inline bool host_is_at_HV_GM_mode(void)
{
	if (unlikely(!IS_HV_GM() && is_CPU_at_guest_hv_vm_mode()))
		return true;
	return false;
}
#endif	/* CONFIG_KVM_HOST_MODE */

static __always_inline bool
is_guest_user_hardware_stack(e2k_addr_t stack_base, e2k_size_t stack_size)
{
	if (stack_base < GUEST_TASK_SIZE) {
		return true;
	}
	return false;
}

/* host kernel support virtualization and should update VCPU thread context */
/* see arch/e2k/include/asm/process.h for more details why and how */
static __always_inline void
kvm_host_update_vcpu_thread_context(struct task_struct **task,
	struct thread_info **ti, struct pt_regs **regs,
	struct gthread_info **gti, struct kvm_vcpu **vcpu)
{
	if (!test_thread_flag(TIF_VIRTUALIZED_GUEST))
		/* ot is not VCPU thread */
		return;
	if ((ti != NULL) && (*ti == current_thread_info()))
		/* thread is not changed, so need not updates */
		return;
	if (ti != NULL)
		*ti = current_thread_info();
	if (task != NULL)
		*task = current;
	if (regs != NULL)
		*regs = current_thread_info()->pt_regs;
	if (gti != NULL)
		*gti = current_thread_info()->gthread_info;
	if (vcpu != NULL)
		*vcpu = current_thread_info()->vcpu;
}
#define	KVM_HOST_UPDATE_VCPU_THREAD_CONTEXT(__task, __ti, __regs,	\
						__gti, __vcpu)		\
		kvm_host_update_vcpu_thread_context(__task, __ti, __regs, \
							__gti, __vcpu)
#define KVM_HOST_CHECK_VCPU_THREAD_CONTEXT(__ti)	\
do { \
	GTI_BUG_ON((__ti) != current_thread_info()); \
} while (false)

/*
 * In some case local data stack cannot be expanded,
 * here should be all cases for kvm guest.
 * Guest kernel is user process of host and kernel threads are maintained by
 * host, including all traps on guest kernel threads
 */
#define kvm_usd_cannot_be_expanded(regs)				\
({									\
	bool is;							\
									\
	if (!test_thread_flag(TIF_VIRTUALIZED_GUEST) ||			\
						paravirt_enabled())	\
		/* Stack is not guest data stack */			\
		/* or it is guest and it cannot run own guest */	\
		is = false;						\
	else if (user_stack_cannot_be_expanded() ||			\
		(regs->stacks.usd_lo.USD_lo_base >= GUEST_TASK_SIZE &&	\
		    regs->stacks.usd_lo.USD_lo_base < HOST_TASK_SIZE))  \
		/* it is stack of guest kernel thread, kernel stacks */	\
		/* should not be expanded */				\
		is = true;						\
	else {								\
		/* it is not guest process or it is guest user */	\
		/* cannot be here */					\
		BUG_ON(true);						\
		is = false;						\
	}								\
	is;								\
})

static inline void
kvm_clear_virt_thread_struct(thread_info_t *thread_info)
{
	thread_info->gpid_nr = -1;	/* cannot inherit, only set by */
					/* guest/host kernel */
#ifdef	CONFIG_KVM_HOST_MODE
	/* clear KVM support fields and flags */
	if (test_ti_thread_flag(thread_info, TIF_VIRTUALIZED_HOST) ||
		test_ti_thread_flag(thread_info, TIF_VIRTUALIZED_GUEST))
		/* It is clone() on host to create guest */
		/* VCPU or VIRQ VCPU threads */
		kvm_clear_host_thread_info(thread_info);
	if (thread_info->gthread_info) {
		/* It is guest thread: clear from old process */
		thread_info->gthread_info = NULL;
		/* kvm_pv_clear_guest_thread_info(thread_info->gthread_info); */
	}
	/* VCPU host/guest thread flags and VCPU structure cannot inherit */
	/* only to pass */
	clear_ti_thread_flag(thread_info, TIF_VIRTUALIZED_HOST);
	thread_info->vcpu = NULL;
#endif	/* CONFIG_KVM_HOST_MODE */
}

#if	!defined(CONFIG_PARAVIRT_GUEST) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* host kernel with virtualization support */

#define	UPDATE_VCPU_THREAD_CONTEXT(__task, __ti, __regs, __gti, __vcpu)	\
		KVM_HOST_UPDATE_VCPU_THREAD_CONTEXT(__task, __ti, __regs, \
						__gti, __vcpu)
#define	CHECK_VCPU_THREAD_CONTEXT(__ti)	\
		KVM_HOST_CHECK_VCPU_THREAD_CONTEXT(__ti)

#endif	/* ! CONFIG_PARAVIRT_GUEST  && ! CONFIG_KVM_GUEST_KERNEL */

#define	KVM_GOTO_RETURN_TO_PARAVIRT_GUEST(ret_value)	\
		E2K_GOTO_ARG1(return_to_paravirt_guest, ret_value)
#define	KVM_COND_GOTO_RETURN_TO_PARAVIRT_GUEST(cond, ret_value)	\
		DEF_COND_GOTO_ARG1(return_to_paravirt_guest, cond, ret_value)
#define	KVM_GOTO_DONE_TO_PARAVIRT_GUEST()	\
		E2K_GOTO(done_to_paravirt_guest)
#define	KVM_COND_GOTO_DONE_TO_PARAVIRT_GUEST(cond)	\
		DEF_COND_GOTO(done_to_paravirt_guest, cond)

/*
 * The function completes on host done to guest process after trap handling
 */
#define	KVM_GET_PARAVIRT_GUEST_MODE(pv_guest, regs)			\
({									\
	bool		pv_mode;					\
									\
	pv_mode = test_thread_flag(TIF_PARAVIRT_GUEST);			\
	/* trap can occur on light hypercall and handled as trap on user */ \
	/* but return will be on host kernel into light hypercall */	\
	/* In this case do not switch to guest shadow image */		\
	pv_mode &= from_host_user_mode((regs)->crs.cr1_lo);		\
									\
	(pv_guest) = pv_mode;						\
})

/*
 * Set global registers used by host to support virtualization
 * Now only one (pair) register is used as pointer to VCPU state structure
 */
#ifndef	CONFIG_USE_GD_TO_VCPU_ACCESS
#define	SET_HOST_GREG(greg_no, value)	NATIVE_SET_DGREG(greg_no, value)
#define	GET_HOST_GREG(greg_no)		NATIVE_GET_UNTEGGED_DGREG(greg_no)
#else	/* CONFIG_USE_GD_TO_VCPU_ACCESS */
 #error	"Global pointer to VCPU state can not be loadded to GD register"
#endif	/* ! CONFIG_USE_GD_TO_VCPU_ACCESS */

extern noinline notrace __interrupt
void go2guest(long fn, bool priv_guest);

#ifdef	CONFIG_KVM_HOST_MODE
/* it is native host kernel with virtualization support */
/* or it is paravirtualized host and guest kernel */

#define	GET_GUEST_VCPU_STATE_POINTER(__vcpu)				\
({									\
	e2k_addr_t vs = (e2k_addr_t)((__vcpu)->arch.vcpu_state);	\
									\
	vs = kvm_vcpu_hva_to_gpa(__vcpu, vs);				\
	if (is_paging(__vcpu))						\
		vs = (e2k_addr_t)__guest_va(vs);			\
	vs;								\
})

#define	INIT_HOST_VCPU_STATE_GREG_COPY(__ti, __vcpu)			\
({									\
	e2k_addr_t vs = GET_GUEST_VCPU_STATE_POINTER(__vcpu);		\
									\
	HOST_ONLY_COPY_TO_VCPU_STATE_GREG(&(__ti)->k_gregs, vs);	\
})

#define	INIT_HOST_GREGS_COPY(__ti, __vcpu)				\
({									\
	/* Zeroing global registers used by kernel */			\
	CLEAR_KERNEL_GREGS_COPY(__ti);					\
	/* Set pointer to VCPU state to enable interface with guest */	\
	INIT_HOST_VCPU_STATE_GREG_COPY(__ti, vcpu);			\
})

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
	g_stacks->usd_lo = gti->g_usd_lo;
	g_stacks->usd_hi = gti->g_usd_hi;
	g_stacks->top = gti->g_sbr.SBR_base;
	g_stacks->psp_lo = gti->g_psp_lo;
	g_stacks->psp_hi = gti->g_psp_hi;
	g_stacks->pcsp_lo = gti->g_pcsp_lo;
	g_stacks->pcsp_hi = gti->g_pcsp_hi;

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
	e2k_pcsp_lo_t g_pcsp_lo, k_pcsp_lo;
	e2k_pcsp_hi_t g_pcsp_hi, k_pcsp_hi;
	e2k_mem_crs_t __user *g_cframe;
	e2k_mem_crs_t *k_crs;
	int ret;

	pcshtp = stacks->pcshtp;
	if (!(guest_user && pcshtp <= 0x40))
		return;

	g_pcsp_lo = regs->stacks.pcsp_lo;
	g_pcsp_hi = regs->stacks.pcsp_hi;

	raw_all_irq_save(flags);
	NATIVE_FLUSHC;
	k_pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();
	k_pcsp_lo = NATIVE_NV_READ_PCSP_LO_REG();
	BUG_ON(AS(k_pcsp_hi).ind != pcshtp);

	k_crs = (e2k_mem_crs_t *) AS(k_pcsp_lo).base;
	g_cframe = (e2k_mem_crs_t __user *) (AS(g_pcsp_lo).base +
				AS(g_pcsp_hi).ind - pcshtp);
	ret = user_hw_stack_frames_copy(g_cframe, k_crs, pcshtp, regs,
					k_pcsp_hi.PCSP_hi_ind, true);
	if (ret) {
		pr_err("%s(): copy to user stack failed\n", __func__);
		BUG_ON(true);
	}
	k_pcsp_hi.PCSP_hi_ind -= pcshtp;
	pcshtp = 0;
	regs->stacks.pcshtp = pcshtp;
	stacks->pcshtp = pcshtp;
	NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG(k_pcsp_hi);
	raw_all_irq_restore(flags);
}
#else	/* !EMULATE_EMPTY_CHAIN_STACK */
static __always_inline void
pv_vcpu_emulate_empty_chain_staks(struct kvm_vcpu *vcpu, pt_regs_t *regs,
				  e2k_stacks_t *stacks, bool guest_user)
{
}
#endif	/* EMULATE_EMPTY_CHAIN_STACK */

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
pv_vcpu_user_hw_stacks_copy(pt_regs_t *regs, e2k_stacks_t *stacks,
				u64 cur_window_q, bool guest_user)
{
	e2k_psp_lo_t  g_psp_lo = stacks->psp_lo,
		      k_psp_lo = current_thread_info()->k_psp_lo;
	e2k_psp_hi_t  g_psp_hi = stacks->psp_hi;
	e2k_pcsp_lo_t g_pcsp_lo = stacks->pcsp_lo,
		      k_pcsp_lo = current_thread_info()->k_pcsp_lo;
	e2k_pcsp_hi_t g_pcsp_hi = stacks->pcsp_hi;
	s64 g_pshtp_size, g_pcshtp_size, ps_copy_size, pcs_copy_size;
	int ret;

	DebugUST("guest kernel chain state: base 0x%llx ind 0x%x size 0x%x\n",
		g_pcsp_lo.PCSP_lo_base, g_pcsp_hi.PCSP_hi_ind,
		g_pcsp_hi.PCSP_hi_size);
	DebugUST("guest kernel proc state: base 0x%llx ind 0x%x size 0x%x\n",
		g_psp_lo.PSP_lo_base, g_psp_hi.PSP_hi_ind,
		g_psp_hi.PSP_hi_size);
	g_pshtp_size = GET_PSHTP_MEM_INDEX(stacks->pshtp);
	g_pcshtp_size = PCSHTP_SIGN_EXTEND(stacks->pcshtp);
	DebugUST("guest kernel chain stack PCSHTP 0x%llx, "
		"proc stack PSHTP 0x%llx cur window 0x%llx\n",
		g_pcshtp_size, g_pshtp_size, cur_window_q);

	/*
	 * FIXME: the current implementation of the guest user signal handler
	 * injection uses direct copying to guest hardware stacks.
	 * It is bad decision, needs to be corrected
	KVM_BUG_ON(is_paging(current_thread_info()->vcpu) &&
			(g_psp_lo.PSP_lo_base < GUEST_TASK_SIZE ||
				g_pcsp_lo.PCSP_lo_base < GUEST_TASK_SIZE));
	 */

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
		e2k_pcsp_hi_t k_pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();
		void __user *dst;
		void *src;

		/* Since SPILL'ed guest user data will be copyed to guest */
		/* kernel stacks then cannot be any overflow of user's */
		/* hardware stack. */
		if (unlikely(AS(g_pcsp_hi).ind > AS(g_pcsp_hi).size)) {
			pr_err("%s(): guest kernel chain stack overflow "
				"(out of memory?): ind 0x%x size 0x%x\n",
				__func__, g_pcsp_hi.PCSP_hi_ind,
				g_pcsp_hi.PCSP_hi_size);
			KVM_BUG_ON(true);
		}
		dst = (void __user *)(g_pcsp_lo.PCSP_lo_base +
						g_pcsp_hi.PCSP_hi_ind);
		if (!guest_user) {
			/* stack index has been incremented on PCSHTP */
			dst -= g_pcshtp_size;
		}
		src = (void *)k_pcsp_lo.PCSP_lo_base;

		ret = user_hw_stack_frames_copy(dst, src, pcs_copy_size, regs,
						k_pcsp_hi.PCSP_hi_ind, true);
		if (ret)
			return ret;
		if (guest_user) {
			g_pcsp_hi.PCSP_hi_ind += pcs_copy_size;
			stacks->pcsp_hi = g_pcsp_hi;
			DebugGUST("guest user chain stack frames copied from "
				"host %px to guest kernel from %px size 0x%llx "
				"PCSP.ind 0x%x\n",
				src, dst, pcs_copy_size, g_pcsp_hi.PCSP_hi_ind);
		}
	}

	if (unlikely(ps_copy_size > 0)) {
		e2k_psp_hi_t k_psp_hi = NATIVE_NV_READ_PSP_HI_REG();
		void __user *dst;
		void *src;

		/* Since SPILL'ed guest user data will be copyed to guest */
		/* kernel stacks then cannot be any overflow of user's */
		/* hardware stack. */
		if (unlikely(AS(g_psp_hi).ind > AS(g_psp_hi).size)) {
			pr_err("%s(): guest kernel proc stack overflow "
				"(out of memory?): ind 0x%x size 0x%x\n",
				__func__, g_psp_hi.PSP_hi_ind,
				g_psp_hi.PSP_hi_size);
			KVM_BUG_ON(true);
		}
		dst = (void __user *)(g_psp_lo.PSP_lo_base +
						g_psp_hi.PSP_hi_ind);
		if (!guest_user) {
			/* stack index has been incremented on PSHTP */
			dst -= g_pshtp_size;
		}
		src = (void *)k_psp_lo.PSP_lo_base;

		ret = user_hw_stack_frames_copy(dst, src, ps_copy_size, regs,
						k_psp_hi.PSP_hi_ind, false);
		if (ret)
			return ret;
		if (guest_user) {
			g_psp_hi.PSP_hi_ind += ps_copy_size;
			stacks->psp_hi = g_psp_hi;
			DebugGUST("guest user proc stack frames copied from "
				"host %px to guest kernel from %px size 0x%llx "
				"PSP.ind 0x%x\n",
				src, dst, ps_copy_size, g_psp_hi.PSP_hi_ind);
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
	DebugUST("guest kernel chain stack state: base 0x%llx ind 0x%x "
		"size 0x%x\n",
		stacks->pcsp_lo.PCSP_lo_base,
		stacks->pcsp_hi.PCSP_hi_ind,
		stacks->pcsp_hi.PCSP_hi_size);
	DebugUST("host kernel chain stack state: base 0x%llx ind 0x%x "
		"size 0x%x\n",
		NATIVE_NV_READ_PCSP_LO_REG().PCSP_lo_base,
		NATIVE_NV_READ_PCSP_HI_REG().PCSP_hi_ind,
		NATIVE_NV_READ_PCSP_HI_REG().PCSP_hi_size);
	DebugUST("guest kernel chain stack size to fill PCSHTP 0x%x\n",
		pcshtp);
	/*
	 * 1) Make sure there is free space in kernel chain stack to return to
	 */
	if (!syscall && pcshtp == 0 && !guest_user) {
		unsigned long flags;
		e2k_pcsp_lo_t g_pcsp_lo = stacks->pcsp_lo,
			      k_pcsp_lo = current_thread_info()->k_pcsp_lo;
		e2k_pcsp_hi_t g_pcsp_hi = stacks->pcsp_hi, k_pcsp_hi;
		e2k_mem_crs_t __user *g_cframe;
		e2k_mem_crs_t *k_crs;
		int ret = -EINVAL;

		raw_all_irq_save(flags);
		NATIVE_FLUSHC;
		k_pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();
		BUG_ON(AS(k_pcsp_hi).ind);
		AS(k_pcsp_hi).ind += SZ_OF_CR;
		NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG(k_pcsp_hi);

		k_crs = (e2k_mem_crs_t *) AS(k_pcsp_lo).base;
		g_cframe = (e2k_mem_crs_t __user *) (AS(g_pcsp_lo).base +
						     AS(g_pcsp_hi).ind);
		if ((u64) g_cframe > (u64) AS(g_pcsp_lo).base) {
			ret = __copy_user_to_current_hw_stack(k_crs,
				g_cframe - 1, sizeof(*k_crs), regs, true);
		}
		raw_all_irq_restore(flags);

		/* Can happen if application returns until runs out of
		 * chain stack or there is no free memory for stacks.
		 * There is no user stack to return to - die. */
		if (ret) {
			E2K_LMS_HALT_OK;
			pr_err("%s(): SIGKILL. %s\n",
				__func__,
				(ret == -EINVAL) ?
					"tried to return to kernel"
					:
				       "ran into Out-of-Memory on user stacks");
			force_sig(SIGKILL);
			return;
		}
		DebugUST("copy guest user chain frame from %px to kernel "
			"bottom from %px\n",
			g_cframe - 1, k_crs);

		if (AS(g_pcsp_hi).ind < SZ_OF_CR) {
			pr_err("%s(): guest kernel chain stack underflow\n",
				__func__);
			KVM_BUG_ON(true);
		}

		pcshtp = SZ_OF_CR;
		stacks->pcshtp = pcshtp;
		DebugUST("guest kernel chain stack to FILL PCSHTP "
			"set to 0x%x\n",
			stacks->pcshtp);
	} else if (!syscall && pcshtp == 0 && guest_user) {
		e2k_pcsp_hi_t k_pcsp_hi;
		unsigned long flags;

		/* set flag for unconditional injection to do not copy */
		/* from guest user space */
		regs->need_inject = true;

		/* reserve one bottom frames for trampoline */
		/* the guest handler replaces guest user trapped frame */
		raw_all_irq_save(flags);
		NATIVE_FLUSHC;
		k_pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();
		BUG_ON(k_pcsp_hi.PCSP_hi_ind);
		k_pcsp_hi.PCSP_hi_ind += 1 * SZ_OF_CR;
		NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG(k_pcsp_hi);
		raw_all_irq_restore(flags);
	}

	/*
	 * 2) Copy user data that cannot be FILLed
	 */
	ret = pv_vcpu_user_hw_stacks_copy(regs, stacks, cur_window_q,
					  guest_user);
	if (unlikely(ret))
		do_exit(SIGKILL);
}

static __always_inline void
host_user_hw_stacks_prepare(struct e2k_stacks *stacks, pt_regs_t *regs,
		u64 cur_window_q, enum restore_caller from, int syscall)
{
	struct kvm_vcpu *vcpu;

	if (likely(!kvm_test_intc_emul_flag(regs))) {
		/* trap on/syscall from host user processes */
		return native_user_hw_stacks_prepare(stacks, regs,
					cur_window_q, from, syscall);
	}

	vcpu = current_thread_info()->vcpu;
	KVM_BUG_ON(vcpu == NULL);
	pv_vcpu_user_hw_stacks_prepare(vcpu, regs, cur_window_q, from, syscall);
}

#define	SAVE_HOST_KERNEL_GREGS_COPY_TO(__k_gregs, __g_gregs)		\
({									\
	kernel_gregs_t *kg = (__k_gregs);				\
	kernel_gregs_t *gg = (__g_gregs);				\
	unsigned long task__;						\
	unsigned long cpu_id__;						\
	unsigned long cpu_off__;					\
									\
	ONLY_COPY_FROM_KERNEL_GREGS(kg, task__, cpu_id__, cpu_off__);	\
	ONLY_COPY_TO_KERNEL_GREGS(gg, task__, cpu_id__, cpu_off__);	\
})

#define	SAVE_HOST_KERNEL_GREGS_COPY(__ti, __gti)			\
({									\
	kernel_gregs_t *k_gregs = &(__ti)->k_gregs_light;		\
	kernel_gregs_t *g_gregs = &(__gti)->g_gregs;			\
									\
	SAVE_HOST_KERNEL_GREGS_COPY_TO(k_gregs, g_gregs);		\
})

#define	RESTORE_HOST_KERNEL_GREGS_COPY_FROM(__k_gregs, __g_gregs)	\
({									\
	kernel_gregs_t *kg = (__k_gregs);				\
	kernel_gregs_t *gg = (__g_gregs);				\
	unsigned long task__;						\
	unsigned long cpu_id__;						\
	unsigned long cpu_off__;					\
									\
	ONLY_COPY_FROM_KERNEL_GREGS(gg, task__, cpu_id__, cpu_off__);	\
	ONLY_COPY_TO_KERNEL_GREGS(kg, task__, cpu_id__, cpu_off__);	\
})

#define	RESTORE_HOST_KERNEL_GREGS_COPY(__ti, __gti, __vcpu)		\
({									\
	kernel_gregs_t *k_gregs = &(__ti)->k_gregs;			\
	kernel_gregs_t *g_gregs = &(__gti)->g_gregs;			\
									\
	RESTORE_HOST_KERNEL_GREGS_COPY_FROM(k_gregs, g_gregs);		\
	INIT_HOST_VCPU_STATE_GREG_COPY(__ti, __vcpu);			\
})

#define printk		printk_fixed_args
#define __trace_bprintk	__trace_bprintk_fixed_args
#define panic		panic_fixed_args

/*
 * The function completes on host switch to new user process (sys_execve())
 * of guest kernel.
 */
static __always_inline __interrupt void
kvm_complete_switch_to_user_func(void)
{
	thread_info_t	*ti;
	gthread_info_t	*gti;
	bool		from_virt_guest;
	bool		from_pv_guest;

	/* current thread info/task pointer global registers were cleared */
	/* while all global registers were set to emty state */
	ti = NATIVE_READ_CURRENT_REG();
	gti = ti->gthread_info;
	from_virt_guest = test_ti_thread_flag(ti, TIF_VIRTUALIZED_GUEST);
	from_pv_guest = test_ti_thread_flag(ti, TIF_PARAVIRT_GUEST);

	/* the function should switch interrupt control from UPSR to */
	/* PSR and set initial state of user UPSR */
	if (!from_virt_guest) {
		NATIVE_SET_USER_INITIAL_UPSR(E2K_USER_INITIAL_UPSR);
	} else {
		KVM_SET_GUEST_USER_INITIAL_UPSR(ti);
	}

	if (unlikely(from_virt_guest)) {
		/* structure gregs into guest thread info structure will */
		/* contain user global registers from now */
		gti->gregs_active = 1;
		gti->gregs_valid = 0;
		gti->gregs_for_currents_valid = 0;
		KVM_COND_GOTO_RETURN_TO_PARAVIRT_GUEST(from_pv_guest, 0);
	}
}

/*
 * The function completes return to guest user signal handler
 */
static __always_inline __interrupt void
kvm_complete_go2user(thread_info_t *ti, long fn)
{
	bool is_pv_guest;	/* entry point fn is paravirtualized guest */
				/* kernel function */

	if (!test_ti_thread_flag(ti, TIF_VIRTUALIZED_GUEST)) {
		/* it is not guest process return to */
		/* but the function should restore user UPSR state */
		NATIVE_WRITE_UPSR_REG(ti->upsr);
		return;
	}
	if ((e2k_addr_t)fn < GUEST_TASK_SIZE &&
			(ti->vcpu == NULL || is_paging(ti->vcpu))) {
		/* it is guest user process return to */
		/* clear host global registers used for virtualization
		CLEAR_HOST_GREGS();
		 */
		/* the function should restore guest user UPSR state */
		KVM_RESTORE_GUEST_USER_UPSR(ti);
	} else {
		/* it is guest kernel process return to
		ONLY_SET_HOST_GREGS(ti->vcpu, ti->vcpu->arch.vcpu_state);
		 */
		/* the function should restore guest kernel UPSR state */
		KVM_RESTORE_GUEST_KERNEL_UPSR(ti);
	}

	is_pv_guest = ((e2k_addr_t)fn >= HOST_TASK_SIZE);

	KVM_COND_GOTO_RETURN_TO_PARAVIRT_GUEST(is_pv_guest, 0);
}

#undef	printk
#undef	__trace_bprintk
#undef	panic
#else	/* ! CONFIG_KVM_HOST_MODE */
/* it is native kernel without any virtualization or */
/* pure guest kernel */

#define	INIT_HOST_VCPU_STATE_GREG_COPY(__ti, __vcpu)
#define	INIT_HOST_GREGS_COPY(__ti, __vcpu)

#endif	/* CONFIG_KVM_HOST_MODE */

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel */
#include <asm/kvm/guest/process.h>
#else	/* CONFIG_VIRTUALIZATION && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native host kernel with virtualization support */
/* or it is paravirtualized host and guest kernel */
#define	usd_cannot_be_expanded(regs)	kvm_usd_cannot_be_expanded(regs)
#define	clear_vm_thread_flags()						\
({									\
	/*								\
	 * If it is new process with new virtual space forked by QEMU	\
	 * after VM creation and created process execve() other code,	\
	 * then it cannot inherit VM features				\
	 */								\
	clear_thread_flag(TIF_VM_CREATED);				\
})

#define	GET_PARAVIRT_GUEST_MODE(pv_guest, regs)	\
		KVM_GET_PARAVIRT_GUEST_MODE(pv_guest, regs)

static inline void
clear_virt_thread_struct(thread_info_t *thread_info)
{
	kvm_clear_virt_thread_struct(thread_info);
}

static __always_inline __interrupt void
complete_switch_to_user_func(void)
{
	kvm_complete_switch_to_user_func();
}
static __always_inline __interrupt void
complete_go2user(thread_info_t *ti, long fn)
{
	kvm_complete_go2user(ti, fn);
}
static inline void free_virt_task_struct(struct task_struct *task)
{
	/* nothing to free */
}
#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

#endif /* ! _E2K_KVM_PROCESS_H */
