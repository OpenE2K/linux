/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_KVM_PTRACE_H
#define _E2K_KVM_PTRACE_H

#include <linux/types.h>
#include <linux/threads.h>

#include <asm/page.h>
#include <asm/bug.h>
#include <asm/e2k_api.h>
#include <asm/pv_info.h>
#include <asm/cpu_regs.h>
#include <asm/glob_regs.h>
#include <asm/mmu_regs_types.h>
#include <asm/aau_regs_access.h>
#include <asm/mlt.h>
#include <asm/ptrace-abi.h>

typedef enum inject_caller {
	FROM_HOST_INJECT = 1 << 0,
	FROM_PV_VCPU_TRAP_INJECT = 1 << 1,
	FROM_PV_VCPU_SYSCALL_INJECT = 1 << 2,
	FROM_PV_VCPU_SIGNAL_INJECT = 1 << 3,
	FROM_PV_VCPU_SIGNAL_RETURN = 1 << 4,
	FROM_PV_VCPU_SYS_SIGRETURN_INJECT = (1 << 5) | FROM_PV_VCPU_SYSCALL_INJECT,
} inject_caller_t;

#ifdef	CONFIG_VIRTUALIZATION

#ifdef	CONFIG_KVM_HOST_KERNEL
/* it is native host kernel with virtualization support */
#define BOOT_TASK_SIZE	(BOOT_HOST_TASK_SIZE)
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is virtualized guest kernel */
#include <asm/kvm/guest/pv_info.h>
/* #define TASK_SIZE		(GUEST_TASK_SIZE) */
/* #define BOOT_TASK_SIZE	(BOOT_GUEST_TASK_SIZE) */
#endif /* CONFIG_KVM_HOST_KERNEL */
#endif /* CONFIG_VIRTUALIZATION */

/*
 * We could check CR.pm and TIR.ip here, but that is not needed
 * because whenever CR.pm = 1 or TIR.ip < TASK_SIZE, SBR points
 * to user space. So checking SBR alone is enough.
 *
 * Testing SBR is necessary because of HW bug #59886 - the 'ct' command
 * (return to user) may be interrupted with closed interrupts.
 * The result - kernel's ip, psr.pm=1, but SBR points to user space.
 * This case should be detected as user mode.
 *
 * Checking via SBR is also useful for detecting fast system calls as
 * user mode.
 */
#define is_user_mode(regs, __USER_SPACE_TOP__)	\
		((regs)->stacks.top < (__USER_SPACE_TOP__))
#define is_kernel_mode(regs, __KERNEL_SPACE_BOTTOM__)	\
		((regs)->stacks.top >= (__KERNEL_SPACE_BOTTOM__))

#define	from_kernel_mode(cr1)	((cr1).pm)
#define	from_user_mode(cr1)	(!(cr1).pm)

#define	is_from_user_IP(cr0, __USER_SPACE_TOP__)			\
	(get_cr0_ip(cr0) < (__USER_SPACE_TOP__))
#define	is_from_kernel_IP(cr0, __KERNEL_SPACE_BOTTOM__)			\
	(get_cr0_ip(cr0) >= (__KERNEL_SPACE_BOTTOM__))

#define	from_user_IP(cr0)	is_from_user_IP(cr0, TASK_SIZE)
#define	from_kernel_IP(cr0)	is_from_kernel_IP(cr0, TASK_SIZE)

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#define is_trap_from_user(regs, __USER_SPACE_TOP__)			\
({									\
	((regs)->TIR.ip < (__USER_SPACE_TOP__))				\
})
#define	is_trap_from_kernel(regs, __KERNEL_SPACE_BOTTOM__)		\
({									\
	((regs)->TIR.ip >= (__KERNEL_SPACE_BOTTOM__))			\
})
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#if	!defined(CONFIG_VIRTUALIZATION) || defined(CONFIG_KVM_HOST_KERNEL)
/* it is native kernel without any virtualization */
/* or host kernel with virtualization support */

static inline void atomic_load_osgd_to_gd(void)
{
	native_atomic_load_osgd_to_gd();
}

#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is virtualized guest kernel */

# include <asm/kvm/guest/ptrace.h>
#else
# error "Undefined type of virtualization"
#endif /* !CONFIG_VIRTUALIZATION || CONFIG_KVM_HOST_KERNEL */

#ifdef	CONFIG_VIRTUALIZATION
/* it is host kernel with virtualization support */
/* or virtualized guest kernel */

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#define	guest_task_mode(task)	\
		(is_task_at_vcpu_intc_emul_mode(task) || \
			is_task_at_vcpu_guest_mode(task))
#define	native_user_mode(regs)		is_user_mode(regs, NATIVE_TASK_SIZE)
#define	guest_user_mode(regs)		is_user_mode(regs, GUEST_TASK_SIZE)
#define	native_kernel_mode(regs)	is_kernel_mode(regs, NATIVE_TASK_SIZE)
#define	guest_kernel_mode(regs)		\
		(is_kernel_mode(regs, GUEST_TASK_SIZE) && \
			!native_kernel_mode(regs))

#define	from_host_user_IP(cr0)	\
		is_from_user_IP(cr0, NATIVE_TASK_SIZE)
#define	from_host_kernel_IP(cr0)		\
		is_from_kernel_IP(cr0, NATIVE_TASK_SIZE)
#define	from_guest_user_IP(cr0)	\
		is_from_user_IP(cr0, GUEST_TASK_SIZE)
#define	from_guest_kernel_IP(cr0)		\
		(is_from_kernel_IP(cr0, GUEST_TASK_SIZE) && \
			!from_host_kernel_IP(cr0))

#define	from_host_user_mode(cr1)	from_user_mode(cr1)
#define	from_host_kernel_mode(cr1)	from_kernel_mode(cr1)
/* guest user is user of guest kernel, so USER MODE (pm = 0) */
#define	from_guest_user_mode(cr1)	from_user_mode(cr1)

#define	is_call_from_user(cr0, cr1, __HOST__)				\
		((__HOST__) ?						\
			is_call_from_host_user(cr0, cr1) :		\
				is_call_from_guest_user(cr0, cr1))
#define	is_call_from_kernel(cr0, cr1, __HOST__)				\
		((__HOST__) ?						\
			is_call_from_host_kernel(cr0, cr1) :		\
				is_call_from_guest_kernel(cr0, cr1))
#else
#define	guest_task_mode(task)	false
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#ifndef	CONFIG_KVM_GUEST_KERNEL
/* it is host kernel with virtualization support */

#define user_mode(regs)   is_user_mode(regs, TASK_SIZE)
#define kernel_mode(regs) is_kernel_mode(regs, TASK_SIZE)

#ifdef CONFIG_KVM_PARAVIRTUALIZATION

#ifdef	CONFIG_KVM_HW_VIRTUALIZATION
/* guest kernel can be: */
/*	user of host kernel, so USER MODE (pm = 0) */
/*	hardware virtualized guest kernel, so KERNEL MODE (pm = 1) */
#define	from_guest_kernel_mode(cr1)	\
		(from_kernel_mode(cr1) || from_user_mode(cr1))
#define	from_guest_kernel(cr0, cr1)	\
		(from_guest_kernel_mode(cr1) && from_guest_kernel_IP(cr0))
#else /* ! CONFIG_KVM_HW_VIRTUALIZATION */
/* guest kernel is user of host kernel, so USER MODE (pm = 0) */
#define	from_guest_kernel_mode(cr1)	\
		from_user_mode(cr1)
#define	from_guest_kernel(cr0, cr1)	\
		(from_guest_kernel_mode(cr1) && from_guest_kernel_IP(cr0))
#endif /* CONFIG_KVM_HW_VIRTUALIZATION */

#define	is_call_from_host_user(cr0, cr1)				\
		(from_host_user_IP(cr0) && from_host_user_mode(cr1))
#define	is_call_from_host_user_IP(cr0, cr1, ignore_IP)			\
		((!(ignore_IP)) ? is_call_from_host_user(cr0, cr1) :	\
			from_host_user_mode(cr1))
#define	is_call_from_guest_user(cr0, cr1)				\
		(from_guest_user_IP(cr0) && from_guest_user_mode(cr1))
#define	is_call_from_guest_user_IP(cr0, cr1, ignore_IP)			\
		((!(ignore_IP)) ? is_call_from_guest_user(cr0, cr1) :	\
			from_guest_user_mode(cr1))
#define	is_call_from_host_kernel(cr0, cr1)				\
		(from_host_kernel_IP(cr0) && from_host_kernel_mode(cr1))
#define	is_call_from_host_kernel_IP(cr0, cr1, ignore_IP)		\
		(!(ignore_IP) ? is_call_from_host_kernel(cr0, cr1) :	\
			from_host_kernel_mode(cr1))
#define	is_call_from_guest_kernel(cr0, cr1)				\
		from_guest_kernel(cr0, cr1)
#define	is_call_from_guest_kernel_IP(cr0, cr1, ignore_IP)		\
		((!(ignore_IP)) ? is_call_from_guest_kernel(cr0, cr1) :	\
			from_guest_kernel_mode(cr1))
#define	call_from_guest_kernel(regs)					\
		is_call_from_guest_kernel((regs)->crs.cr0, (regs)->crs.cr1)

#define	ON_HOST_KERNEL()	(native_read_PSR_reg().pm)

#define	call_from_user_mode(cr0, cr1)					\
		is_call_from_user(cr0, cr1, ON_HOST_KERNEL())
#define	call_from_kernel_mode(cr0, cr1)					\
		is_call_from_kernel(cr0, cr1, ON_HOST_KERNEL())

#define	__trap_from_host_kernel(regs)	native_kernel_mode(regs)
#define __trap_from_guest_user(regs)	guest_user_mode(regs)
#define	guest_trap_user_mode(regs)					\
		(from_guest_kernel((regs)->crs.cr0,			\
					(regs)->crs.cr1) &&		\
			__trap_from_guest_user(regs))

#define	trap_from_host_kernel_mode(regs)				\
		from_host_kernel_mode((regs)->crs.cr1)
#define	trap_from_host_kernel(regs)					\
		(trap_from_host_kernel_mode(regs) &&			\
			__trap_from_host_kernel(regs))

/* macroses to detect guest traps on host, guest has not own guest, so */
/* macroses should always return 'false' for guest */
/* trap occurred on guest process (guest user or guest kernel or on host */
/* while running guest process (guest VCPU thread) */
#define	trap_on_guest(regs)						\
		(!paravirt_enabled() && kvm_test_intc_emul_flag(regs))
#define	trap_on_pv_hv_guest(vcpu, regs)					\
		((vcpu) != NULL && \
			!((vcpu)->arch.is_hv) && trap_on_guest(regs))
/* guest trap occurred on guest user or kernel or on host but due to guest */
/* for example guest kernel address in hypercalls */
#define	due_to_guest_trap_on_pv_hv_host(vcpu, regs)			\
		(trap_on_pv_hv_guest(vcpu, regs) &&			\
			(user_mode(regs) ||				\
			LIGHT_HYPERCALL_MODE(regs) ||			\
			GENERIC_HYPERCALL_MODE()))

#define	addr_from_guest_user(addr)	((addr) < GUEST_TASK_SIZE)

#define guest_user_addr_mode_page_fault(regs, instr_page, addr)		\
		((instr_page) ? guest_user_mode(regs) :			\
					guest_user_mode(regs) ||	\
			(addr_from_guest_user(addr) &&			\
				(!trap_from_host_kernel(regs) ||	\
					LIGHT_HYPERCALL_MODE(regs) ||	\
					GENERIC_HYPERCALL_MODE())))

static inline e2k_addr_t
check_is_user_address(struct task_struct *task, e2k_addr_t address)
{
	if (likely(address < TASK_SIZE))
		return 0;
	if (!paravirt_enabled()) {
		pr_err("Address 0x%016lx is host kernel address\n", address);
		return -1;
	} else if (address < NATIVE_TASK_SIZE) {
		pr_err("Address 0x%016lx is guest kernel address\n", address);
		return -1;
	} else {
		pr_err("Address 0x%016lx is host kernel address\n", address);
		return -1;
	}
}

#define	IS_GUEST_USER_ADDRESS_TO_PVA(task, address)	\
		(test_ti_is_vcpu_thread(task_thread_info(tsk)) && \
			IS_GUEST_USER_ADDRESS(address))
#define	IS_GUEST_ADDRESS_TO_HOST(address)		\
		(IS_ENABLED(CONFIG_KVM_GUEST_KERNEL) && IS_HOST_KERNEL_ADDRESS(address))
#else
#define	call_from_user_mode(cr0, cr1) \
	((is_from_user_IP(cr0, NATIVE_TASK_SIZE) && from_user_mode(cr1)))
#define	call_from_kernel_mode(cr0, cr1)	((cr1).pm)

static inline e2k_addr_t
check_is_user_address(struct task_struct *task, e2k_addr_t address)
{
	return native_check_is_user_address(task, address);
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#ifdef	CONFIG_KVM_GUEST_HW_PV
/* FIXME Instead of ifdef, this should check for is_pv */
#define	print_host_user_address_ptes(mm, address)			\
		native_print_host_user_address_ptes(mm, address)
#else
/* guest page table is pseudo PT and only host PT is used */
/* to translate any guest addresses */
#define	print_host_user_address_ptes(mm, address)	\
({ \
	/* function is actual only for guest kernel */ \
	if (paravirt_enabled()) \
		HYPERVISOR_print_guest_user_address_ptes((mm)->gmmid_nr, \
			address); \
})
#endif	/* CONFIG_KVM_GUEST_HW_PV */
#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

#else	/* ! CONFIG_VIRTUALIZATION */
/* it is native kernel without any virtualization */

#define	guest_task_mode(task)	false	/* only native tasks */

#define user_mode(regs)		is_user_mode(regs, TASK_SIZE)
#define kernel_mode(regs)	is_kernel_mode(regs, TASK_SIZE)

#define	is_call_from_host_user(cr0, cr1)				\
		(from_user_IP(cr0) && from_user_mode(cr1))
#define	is_call_from_host_user_IP(cr0, cr1, ignore_IP)			\
		((!(ignore_IP) ? is_call_from_host_user(cr0, cr1) :	\
			from_user_mode(cr1)))
#define	is_call_from_guest_user(cr0, cr1)			false
#define	is_call_from_guest_user_IP(cr0, cr1, ignoreIP)		false
#define	is_call_from_host_kernel(cr0, cr1)				\
		(from_kernel_IP(cr0) && from_kernel_mode(cr1))
#define	is_call_from_host_kernel_IP(cr0, cr1, ignore_IP)		\
		(!(ignore_IP) ? is_call_from_host_kernel(cr0, cr1) :	\
				from_kernel_mode(cr1))
#define	is_call_from_guest_kernel(cr0, cr1)			false
#define	is_call_from_guest_kernel_IP(cr0, cr1, ignore_IP)	false
#define	call_from_guest_kernel(regs)				false

#define	is_call_from_user(cr0, cr1, __HOST__)				\
		is_call_from_host_user(cr0, cr1)
#define	is_call_from_kernel(cr0, cr1, __HOST__)				\
		is_call_from_host_kernel(cr0, cr1)

/* macroses to detect guest traps on host */
/* Virtualization is off, so nothing guests exist, */
/* so macroses should always return 'false' */
#define	trap_on_guest(regs)	false

#define	ON_HOST_KERNEL()	true
#define	call_from_user_mode(cr0, cr1)					\
		is_call_from_user(cr0, cr1, ON_HOST_KERNEL())
#define	call_from_kernel_mode(cr0, cr1)					\
		is_call_from_kernel(cr0, cr1, ON_HOST_KERNEL())

static inline e2k_addr_t
check_is_user_address(struct task_struct *task, e2k_addr_t address)
{
	return native_check_is_user_address(task, address);
}

#define	IS_GUEST_USER_ADDRESS_TO_PVA(task, address)	\
		NATIVE_IS_GUEST_USER_ADDRESS_TO_PVA(task, address)
#define	IS_GUEST_ADDRESS_TO_HOST(address)		\
		NATIVE_IS_GUEST_ADDRESS_TO_HOST(address)
#define	print_host_user_address_ptes(mm, address)	\
		native_print_host_user_address_ptes(mm, address)

#endif	/* CONFIG_VIRTUALIZATION */

#ifdef CONFIG_KVM_PARAVIRTUALIZATION

#ifndef	CONFIG_VIRTUALIZATION
/* it is native kernel without virtualization support */
#define	LIGHT_HYPERCALL_MODE(regs)		0 /* hypercalls not supported */
#define	TI_GENERIC_HYPERCALL_MODE(thread_info)	0 /* hypercalls not supported */
#define	GENERIC_HYPERCALL_MODE()		0 /* hypercalls not supported */
#define	IN_LIGHT_HYPERCALL()			0 /* hypercalls not supported */
#define	IN_GENERIC_HYPERCALL()			0 /* hypercalls not supported */
#define	IN_HYPERCALL()				0 /* hypercalls not supported */
#elif	defined(CONFIG_KVM_HOST_KERNEL)
/* It is native host kernel with virtualization support on */

#define	LIGHT_HYPERCALL_MODE(pt_regs)					\
({									\
	pt_regs_t *__regs = (pt_regs);					\
	bool is_ligh_hypercall;						\
									\
	is_ligh_hypercall = __regs->flags.light_hypercall;		\
	is_ligh_hypercall;						\
})
#define	TI_LIGHT_HYPERCALL_MODE(thread_info)				\
({									\
	thread_info_t *__ti = (thread_info);				\
	test_ti_thread_flag(__ti, TIF_LIGHT_HYPERCALL);			\
})
#define	IN_LIGHT_HYPERCALL()	TI_LIGHT_HYPERCALL_MODE(current_thread_info())
#define	TI_GENERIC_HYPERCALL_MODE(thread_info)				\
({									\
	thread_info_t *__ti = (thread_info);				\
	test_ti_thread_flag(__ti, TIF_GENERIC_HYPERCALL);		\
})
#define	GENERIC_HYPERCALL_MODE()					\
		TI_GENERIC_HYPERCALL_MODE(current_thread_info())
#define	IN_GENERIC_HYPERCALL()	GENERIC_HYPERCALL_MODE()
#define	IN_HYPERCALL()							\
	(IN_LIGHT_HYPERCALL() || IN_GENERIC_HYPERCALL())
#endif	/* !CONFIG_VIRTUALIZATION */

#ifdef	CONFIG_KVM_HOST_KERNEL
/* It is native host kernel with virtualization support on */

/*
 * Additional context for virtualized guest to save/restore at
 * 'signal_stack_context' structure to handle traps/syscalls by guest
 */

typedef struct pv_vcpu_ctxt {
	inject_caller_t inject_from;	/* reason of injection */
	int trap_no;			/* number of recursive trap */
	int skip_frames;		/* number signal stack frame to remove */
	int skip_traps;			/* number of traps frames to remove */
	int skip_syscalls;		/* number of syscall frames to remove */
	u64 sys_rval;			/* return value of guest system call */
	e2k_psr_t guest_psr;		/* guest PSR state before trap */
	bool irq_under_upsr;		/* is IRQ control under UOSR? */
	bool from_sigreturn;		/* return value of guest system call */
					/* has been already set by sigreturn() */
					/* and should be taken from here */
					/* and not put here */
	unsigned long sigreturn_entry;	/* guest signal return start IP */
} pv_vcpu_ctxt_t;

#else /* !CONFIG_KVM_HOST_KERNEL */
/* it is native kernel without any virtualization */
/* or virtualized guest kernel */

typedef struct pv_vcpu_ctxt {
	/* empty structure */
} pv_vcpu_ctxt_t;

#endif /* CONFIG_KVM_HOST_KERNEL */


#ifdef	CONFIG_VIRTUALIZATION

static inline struct pt_regs *find_guest_user_regs(struct pt_regs *regs)
{
	struct pt_regs *guser_regs = regs;
	do {
		if (guest_user_mode(guser_regs))
			break;
		if (guser_regs->next != NULL && guser_regs->next <= guser_regs) {
			/* pt_regs allocated only at the stack, stack grows */
			/* down, so next structure can be only above current */
			pr_err("%s(): invalid list of pt_regs structures:\n"
			       "next regs %px below current %px\n",
			       __func__, guser_regs->next, guser_regs);
			WARN_ON(true);
			guser_regs = NULL;
			break;
		}
		guser_regs = guser_regs->next;
	} while (guser_regs);

	return guser_regs;
}
#else /* ! CONFIG_VIRTUALIZATION */
static inline struct pt_regs *find_guest_user_regs(struct pt_regs *regs)
{
	return NULL;
}
#endif /* CONFIG_VIRTUALIZATION */

#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#if defined(CONFIG_SMP)
extern unsigned long profile_pc(struct pt_regs *regs);
#else
#define profile_pc(regs) instruction_pointer(regs)
#endif
extern void show_regs(struct pt_regs *);
extern int syscall_trace_entry(struct pt_regs *regs);
extern void syscall_trace_leave(struct pt_regs *regs);

#endif /* _E2K_KVM_PTRACE_H */
