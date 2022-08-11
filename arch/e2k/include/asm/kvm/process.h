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
kvm_clear_virt_thread_struct(thread_info_t *ti)
{
	if (likely(ti->vcpu == NULL)) {
		/* it is not creation of host process */
		/* to support virtualization */
		return;
	}

	/*
	 * Host VCPU thread can be only created by user process (for example
	 * by qemu) and only user process can clone the thread to handle
	 * some VCPU running exit reasons.
	 * But the new thread cannot be one more host VCPU thread,
	 * so clean up all about VCPU
	 */

	/* VCPU thread should be only at host mode (handle exit reason), */
	/* not at running VCPU mode */
	KVM_BUG_ON(test_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE));

	ti->gthread_info = NULL;
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

static __always_inline void
host_exit_to_usermode_loop(struct pt_regs *regs, bool syscall, bool has_signal)
{
	KVM_BUG_ON(!host_test_intc_emul_mode(regs));

	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_ENABLED));

	/* Check for rescheduling first */
	if (need_resched()) {
		schedule();
	}

	if (has_signal) {
		/*
		 * This is guest VCPU interception emulation, but
		 * there is (are) pending signal for host VCPU mode,
		 * so it need switch to host VCPU mode to handle
		 * signal and probably to kill VM
		 */
		WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_DISABLED));
		pv_vcpu_switch_to_host_from_intc(current_thread_info());
	} else if (likely(guest_trap_pending(current_thread_info()))) {
		/*
		 * This is guest VCPU interception emulation and
		 * there is (are) the guest trap(s) to handle
		 */
		insert_pv_vcpu_traps(current_thread_info(), regs);
	} else {
		/*
		 * This is just a return from VCPU interception
		 * emulation mode to the continue execution
		 * of the guest paravirtualized VCPU.
		 * In such case:
		 *	- the currents point to the host qemu-VCPU
		 *	  process structures;
		 *	- the regs points to the host guest-VCPU
		 *	  process structure.
		 * So nothing works based on these non-interconnected
		 * structures cannot be running
		 */
	}

	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_DISABLED));
}

#ifdef	CONFIG_SMP
#define	SAVE_GUEST_KERNEL_GREGS_COPY_TO(__k_gregs, __g_gregs,		\
					only_kernel)			\
({									\
	kernel_gregs_t *kg = (__k_gregs);				\
	kernel_gregs_t *gg = (__g_gregs);				\
	unsigned long task__;						\
	unsigned long cpu_id__;						\
	unsigned long cpu_off__;					\
									\
	if (likely(!(only_kernel))) {					\
		unsigned long vs__;					\
									\
		HOST_ONLY_SAVE_VCPU_STATE_GREG(vs__);			\
		HOST_ONLY_COPY_TO_VCPU_STATE_GREG(gg, vs__);		\
	}								\
	ONLY_COPY_FROM_KERNEL_GREGS(kg, task__, cpu_id__, cpu_off__);	\
	ONLY_COPY_TO_KERNEL_GREGS(gg, task__, cpu_id__, cpu_off__);	\
})
#else	/* ! CONFIG_SMP */
#define	SAVE_GUEST_KERNEL_GREGS_COPY_TO(__k_gregs, __g_gregs,		\
					only_kernel)			\
({									\
	kernel_gregs_t *kg = (__k_gregs);				\
	kernel_gregs_t *gg = (__g_gregs);				\
	unsigned long task__;						\
									\
	if (likely(!(only_kernel))) {					\
		unsigned long vs__;					\
									\
		HOST_ONLY_SAVE_VCPU_STATE_GREG(vs__);			\
		HOST_ONLY_COPY_TO_VCPU_STATE_GREG(gg, vs__);		\
	}								\
	ONLY_COPY_FROM_KERNEL_CURRENT_GREGS(kg, task__);		\
	ONLY_COPY_TO_KERNEL_CURRENT_GREGS(gg, task__);			\
})
#endif	/* CONFIG_SMP */

#define	SAVE_GUEST_KERNEL_GREGS_COPY(__ti, __gti)			\
({									\
	kernel_gregs_t *k_gregs = &(__ti)->k_gregs_light;		\
	kernel_gregs_t *g_gregs = &(__gti)->gk_gregs;			\
									\
	SAVE_GUEST_KERNEL_GREGS_COPY_TO(k_gregs, g_gregs, false);	\
})

#ifdef	CONFIG_SMP
#define	RESTORE_GUEST_KERNEL_GREGS_COPY_FROM(__k_gregs, __g_gregs,	\
						only_kernel)		\
({									\
	kernel_gregs_t *kg = (__k_gregs);				\
	kernel_gregs_t *gg = (__g_gregs);				\
	unsigned long task__;						\
	unsigned long cpu_id__;						\
	unsigned long cpu_off__;					\
									\
	if (likely(!(only_kernel))) {					\
		unsigned long vs__;					\
									\
		HOST_ONLY_COPY_FROM_VCPU_STATE_GREG(k_gregs, vs__);	\
		HOST_ONLY_RESTORE_VCPU_STATE_GREG(vs__);		\
	}								\
	ONLY_COPY_FROM_KERNEL_GREGS(gg, task__, cpu_id__, cpu_off__);	\
	ONLY_COPY_TO_KERNEL_GREGS(kg, task__, cpu_id__, cpu_off__);	\
})
#else	/* ! CONFIG_SMP */
#define	RESTORE_GUEST_KERNEL_GREGS_COPY_FROM(__k_gregs, __g_gregs,	\
						only_kernel)		\
({									\
	kernel_gregs_t *kg = (__k_gregs);				\
	kernel_gregs_t *gg = (__g_gregs);				\
	unsigned long task__;						\
									\
	if (likely(!(only_kernel))) {					\
		unsigned long vs__;					\
									\
		HOST_ONLY_COPY_FROM_VCPU_STATE_GREG(k_gregs, vs__);	\
		HOST_ONLY_RESTORE_VCPU_STATE_GREG(vs__);		\
	}								\
	ONLY_COPY_FROM_KERNEL_CURRENT_GREGS(gg, task__);		\
	ONLY_COPY_TO_KERNEL_CURRENT_GREGS(kg, task__);			\
})
#endif	/* CONFIG_SMP */

#define	RESTORE_GUEST_KERNEL_GREGS_COPY(__ti, __gti, __vcpu)		\
({									\
	kernel_gregs_t *k_gregs = &(__ti)->k_gregs;			\
	kernel_gregs_t *g_gregs = &(__gti)->gu_gregs;			\
									\
	RESTORE_GUEST_KERNEL_GREGS_COPY_FROM(k_gregs, g_gregs, true);	\
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
