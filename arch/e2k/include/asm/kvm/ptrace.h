#ifndef _E2K_KVM_PTRACE_H
#define _E2K_KVM_PTRACE_H

#ifdef __KERNEL__

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/threads.h>
#endif /* __ASSEMBLY__ */

#include <asm/page.h>

#ifndef __ASSEMBLY__
#include <asm/bug.h>
#include <asm/e2k_api.h>
#include <asm/pv_info.h>
#include <asm/cpu_regs.h>
#include <asm/glob_regs.h>
#include <asm/mmu_regs_types.h>
#ifdef CONFIG_USE_AAU
#include <asm/aau_regs.h>
#endif /* CONFIG_USE_AAU */
#include <asm/mlt.h>
#include <asm/ptrace-abi.h>

#endif /* __ASSEMBLY__ */

#endif /* __KERNEL__ */

typedef enum inject_caller {
	FROM_HOST_INJECT = 1 << 0,
	FROM_PV_VCPU_TRAP_INJECT = 1 << 1,
	FROM_PV_VCPU_SYSCALL_INJECT = 1 << 2
} inject_caller_t;

#ifdef	CONFIG_VIRTUALIZATION

#if !defined(CONFIG_PARAVIRT_GUEST) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native host kernel with virtualization support */
#define BOOT_TASK_SIZE	(BOOT_HOST_TASK_SIZE)
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel */
#include <asm/kvm/guest/pv_info.h>
/* #define TASK_SIZE		(GUEST_TASK_SIZE) */
/* #define BOOT_TASK_SIZE	(BOOT_GUEST_TASK_SIZE) */
#else	/* CONFIG_PARAVIRT_GUEST */
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/pv_info.h>
/* #define TASK_SIZE		(PARAVIRT_TASK_SIZE) */
/* #define BOOT_TASK_SIZE	(BOOT_PARAVIRT_TASK_SIZE) */
#endif	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
#endif	/* CONFIG_VIRTUALIZATION */

#ifdef __KERNEL__

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

#define	from_kernel_mode(cr1_lo)	((cr1_lo).CR1_lo_pm)
#define	from_user_mode(cr1_lo)		(!((cr1_lo).CR1_lo_pm))

#define	is_from_user_IP(cr0_hi, __USER_SPACE_TOP__)			\
({									\
	unsigned long IP;						\
	bool ret;							\
	IP = (cr0_hi).CR0_hi_IP;					\
	ret = (IP < (__USER_SPACE_TOP__));				\
	ret;								\
})
#define	is_from_kernel_IP(cr0_hi, __KERNEL_SPACE_BOTTOM__)		\
({									\
	unsigned long IP;						\
	bool ret;							\
	IP = (cr0_hi).CR0_hi_IP;					\
	ret = (IP >= (__KERNEL_SPACE_BOTTOM__));			\
	ret;								\
})

#define	from_user_IP(cr0_hi)	is_from_user_IP(cr0_hi, TASK_SIZE)
#define	from_kernel_IP(cr0_hi)	is_from_kernel_IP(cr0_hi, TASK_SIZE)

#define is_trap_from_user(regs, __USER_SPACE_TOP__)			\
({									\
	e2k_tir_lo_t tir_lo;						\
	tir_lo.TIR_lo_reg = (regs)->TIR_lo;				\
	tir_lo.TIR_lo_ip < (__USER_SPACE_TOP__);			\
})
#define	is_trap_from_kernel(regs, __KERNEL_SPACE_BOTTOM__)		\
({									\
	e2k_tir_lo_t tir_lo;						\
	tir_lo.TIR_lo_reg = (regs)->TIR_lo;				\
	tir_lo.TIR_lo_ip >= (__KERNEL_SPACE_BOTTOM__);			\
})

#if	!defined(CONFIG_KVM_GUEST_KERNEL) && !defined(CONFIG_PARAVIRT_GUEST)
/* it is native kernel without any virtualization */
/* or host kernel with virtualization support */

static inline void atomic_load_osgd_to_gd(void)
{
	native_atomic_load_osgd_to_gd();
}

#define	SAVE_DAM(__dam)	NATIVE_SAVE_DAM(__dam)
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */

#include <asm/paravirt/mmu.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops) */

#include <asm/kvm/guest/ptrace.h>
#else
 #error	"Undefined type of virtualization"
#endif	/* ! CONFIG_KVM_GUEST_KERNEL && ! CONFIG_PARAVIRT_GUEST */

#if	defined(CONFIG_VIRTUALIZATION)
/* it is host kernel with virtualization support */
/* or paravirtualized host and guest kernel */
/* or pure guest kernel (not paravirtualized based on pv_ops) */
#define	guest_task_mode(task)	\
		test_ti_thread_flag(task_thread_info(task), \
						TIF_VIRTUALIZED_GUEST)
#define	native_user_mode(regs)		is_user_mode(regs, NATIVE_TASK_SIZE)
#define	guest_user_mode(regs)		is_user_mode(regs, GUEST_TASK_SIZE)
#define	native_kernel_mode(regs)	is_kernel_mode(regs, NATIVE_TASK_SIZE)
#define	guest_kernel_mode(regs)		\
		(is_kernel_mode(regs, GUEST_TASK_SIZE) && \
			!native_kernel_mode(regs))

#define	from_host_user_IP(cr0_hi)	\
		is_from_user_IP(cr0_hi, NATIVE_TASK_SIZE)
#define	from_host_kernel_IP(cr0_hi)		\
		is_from_kernel_IP(cr0_hi, NATIVE_TASK_SIZE)
#define	from_guest_user_IP(cr0_hi)	\
		is_from_user_IP(cr0_hi, GUEST_TASK_SIZE)
#define	from_guest_kernel_IP(cr0_hi)		\
		(is_from_kernel_IP(cr0_hi, GUEST_TASK_SIZE) && \
			!from_host_kernel_IP(cr0_hi))

#define	from_host_user_mode(cr1_lo)	from_user_mode(cr1_lo)
#define	from_host_kernel_mode(cr1_lo)	from_kernel_mode(cr1_lo)
/* guest user is user of guest kernel, so USER MODE (pm = 0) */
#define	from_guest_user_mode(cr1_lo)	from_user_mode(cr1_lo)

#define	is_call_from_user(cr0_hi, cr1_lo, __HOST__)			\
		((__HOST__) ?						\
			is_call_from_host_user(cr0_hi, cr1_lo) :	\
				is_call_from_guest_user(cr0_hi, cr1_lo))
#define	is_call_from_kernel(cr0_hi, cr1_lo, __HOST__)			\
		((__HOST__) ?						\
			is_call_from_host_kernel(cr0_hi, cr1_lo) :	\
				is_call_from_guest_kernel(cr0_hi, cr1_lo))

#ifndef	CONFIG_KVM_GUEST_KERNEL
/* it is host kernel with virtualization support */
/* or paravirtualized host and guest kernel */

#define user_mode(regs)		\
		((regs) ? is_user_mode(regs, TASK_SIZE) : false)
#define kernel_mode(regs)	\
		((regs) ? is_kernel_mode(regs, TASK_SIZE) : true)

#ifdef	CONFIG_KVM_HW_VIRTUALIZATION
/* guest kernel can be: */
/*	user of host kernel, so USER MODE (pm = 0) */
/*	hardware virtualized guest kernel, so KERNEL MODE (pm = 1) */
#define	from_guest_kernel_mode(cr1_lo)	\
		(from_kernel_mode(cr1_lo) || from_user_mode(cr1_lo))
#define	from_guest_kernel(cr0_hi, cr1_lo)	\
		(from_guest_kernel_mode(cr1_lo) && \
				from_guest_kernel_IP(cr0_hi))
#else	/* ! CONFIG_KVM_HW_VIRTUALIZATION */
/* guest kernel is user of host kernel, so USER MODE (pm = 0) */
#define	from_guest_kernel_mode(cr1_lo)	\
		from_user_mode(cr1_lo)
#define	from_guest_kernel(cr0_hi, cr1_lo)	\
		(from_guest_kernel_mode(cr1_lo) && \
				from_guest_kernel_IP(cr0_hi))
#endif	/* CONFIG_KVM_HW_VIRTUALIZATION */

#define	is_trap_from_host_kernel(regs)	\
		is_trap_from_kernel(regs, NATIVE_TASK_SIZE)

#define	is_call_from_host_user(cr0_hi, cr1_lo)				\
		(from_host_user_IP(cr0_hi) && from_host_user_mode(cr1_lo))
#define	is_call_from_host_user_IP(cr0_hi, cr1_lo, ignore_IP)		\
		((!(ignore_IP)) ? is_call_from_host_user(cr0_hi, cr1_lo) : \
			from_host_user_mode(cr1_lo))
#define	is_call_from_guest_user(cr0_hi, cr1_lo)				\
		(from_guest_user_IP(cr0_hi) && from_guest_user_mode(cr1_lo))
#define	is_call_from_guest_user_IP(cr0_hi, cr1_lo, ignore_IP)		\
		((!(ignore_IP)) ? is_call_from_guest_user(cr0_hi, cr1_lo) : \
			from_guest_user_mode(cr1_lo))
#define	is_call_from_host_kernel(cr0_hi, cr1_lo)			\
		(from_host_kernel_IP(cr0_hi) && from_host_kernel_mode(cr1_lo))
#define	is_call_from_host_kernel_IP(cr0_hi, cr1_lo, ignore_IP)		\
		((!(ignore_IP)) ? is_call_from_host_kernel(cr0_hi, cr1_lo) : \
			from_host_kernel_mode(cr1_lo))
#define	is_call_from_guest_kernel(cr0_hi, cr1_lo)			\
		from_guest_kernel(cr0_hi, cr1_lo)
#define	is_call_from_guest_kernel_IP(cr0_hi, cr1_lo, ignore_IP)		\
		((!(ignore_IP)) ? is_call_from_guest_kernel(cr0_hi, cr1_lo) : \
			from_guest_kernel_mode(cr1_lo))
#define	call_from_guest_kernel(regs)					\
		is_call_from_guest_kernel((regs)->crs.cr0_hi, (regs)->crs.cr1_lo)

#define	is_trap_on_user(regs, __HOST__)					\
		((__HOST__) ?						\
			trap_from_host_user(regs) :	\
				trap_from_guest_user(regs))
#define	is_trap_on_kernel(regs, __HOST__)			\
		((__HOST__) ?						\
			trap_from_host_kernel(regs) :	\
				(trap_from_guest_kernel(regs) || \
					is_trap_from_host_kernel(regs)))

#define	ON_HOST_KERNEL()	(NATIVE_NV_READ_PSR_REG_VALUE() & PSR_PM)

#define __trap_from_user(regs)		\
		is_trap_on_user(regs, ON_HOST_KERNEL())
#define	__trap_from_kernel(regs)	\
		is_trap_on_kernel(regs, ON_HOST_KERNEL())
#define	trap_on_user(regs)	__trap_from_user(regs)
#define	trap_on_kernel(regs)	__trap_from_kernel(regs)

#define	call_from_user_mode(cr0_hi, cr1_lo)				\
		is_call_from_user(cr0_hi, cr1_lo, ON_HOST_KERNEL())
#define	call_from_kernel_mode(cr0_hi, cr1_lo)				\
		is_call_from_kernel(cr0_hi, cr1_lo, ON_HOST_KERNEL())
#define	call_from_user(regs)						\
		call_from_user_mode((regs)->crs.cr0_hi, (regs)->crs.cr1_lo)
#define	call_from_kernel(regs)						\
		call_from_kernel_mode((regs)->crs.cr0_hi, (regs)->crs.cr1_lo)

#define __trap_from_host_user(regs)	native_user_mode(regs)
#define	__trap_from_host_kernel(regs)	native_kernel_mode(regs)
#define __trap_from_guest_user(regs)	guest_user_mode(regs)
#define	__trap_from_guest_kernel(regs)	guest_kernel_mode(regs)

#define	__call_from_kernel(regs)	call_from_kernel(regs)
#define	__call_from_user(regs)		call_from_user(regs)

#define	trap_on_guest_kernel_mode(regs)					\
		from_guest_kernel_mode((regs)->crs.cr1_lo)
#define	trap_on_guest_kernel_IP(regs)					\
		(from_guest_kernel_IP((regs)->crs.cr0_hi) &&		\
			!from_host_kernel_IP((regs)->crs.cr0_hi))
#define	host_trap_guest_user_mode(regs)					\
		(from_guest_user_mode((regs)->crs.cr1_lo) &&		\
			__trap_from_guest_user(regs))
#define	host_trap_guest_kernel_mode(regs)				\
		(from_guest_kernel((regs)->crs.cr0_hi,			\
					(regs)->crs.cr1_lo) &&		\
			__trap_from_guest_kernel(regs))
#define	guest_trap_user_mode(regs)					\
		(from_guest_kernel((regs)->crs.cr0_hi,			\
					(regs)->crs.cr1_lo) &&		\
			__trap_from_guest_user(regs))
#define	guest_trap_kernel_mode(regs)					\
		(from_guest_kernel((regs)->crs.cr0_hi,			\
					(regs)->crs.cr1_lo) &&		\
			__trap_from_guest_kernel(regs))

#define	trap_from_host_kernel_mode(regs)				\
		from_host_kernel_mode((regs)->crs.cr1_lo)
#define	trap_from_host_kernel_IP(regs)					\
		from_host_kernel_IP((regs)->crs.cr0_hi)
#define	trap_from_host_kernel(regs)					\
		(trap_from_host_kernel_mode(regs) &&			\
			__trap_from_host_kernel(regs))
#define	trap_from_host_user(regs)					\
		(from_host_user_mode((regs)->crs.cr1_lo) &&		\
			__trap_from_host_user(regs))
/* macros to detect guest kernel traps on guest and on host */
/* trap only on guest kernel */
#define	trap_from_guest_kernel(regs)					\
		(from_guest_kernel_mode((regs)->crs.cr1_lo) &&		\
			__trap_from_guest_kernel(regs))
/* macros to detect guest traps on host, guest has not own guest, so */
/* macros should always return 'false' for guest */
/* trap occurred on guest user only */
#define trap_from_guest_user(regs)					\
({									\
	bool is;							\
									\
	if (paravirt_enabled() ||					\
		!test_thread_flag(TIF_VIRTUALIZED_GUEST))		\
		/* It is guest and it cannot run own guest */		\
		/* or trap is not on guest process */			\
		is = false;						\
	else if (host_trap_guest_user_mode(regs))			\
		is = true;						\
	else								\
		is = false;						\
	is;								\
})
/* macroses to detect guest traps on host, guest has not own guest, so */
/* macroses should always return 'false' for guest */
/* trap occurred on guest process (guest user or guest kernel or on host */
/* while running guest process (guest VCPU thread) */
#define	trap_on_guest(regs)						\
		(!paravirt_enabled() &&					\
			test_thread_flag(TIF_VIRTUALIZED_GUEST))
#define	trap_on_pv_hv_guest(vcpu, regs)					\
		((vcpu) != NULL && \
			!((vcpu)->arch.is_hv) && trap_on_guest(regs))
/* guest trap occurred on guest user or kernel */
#define	guest_trap_on_host(regs)					\
		(trap_on_guest(regs) && user_mode(regs))
#define	guest_trap_on_pv_hv_host(vcpu, regs)				\
		(trap_on_pv_hv_guest(vcpu, regs) && user_mode(regs))
/* trap occurred on guest kernel or user, but in host mode */
/* and the trap can be due to guest or not */
#define	host_trap_on_guest(regs)					\
		(guest_trap_on_host(regs) &&				\
			trap_from_host_kernel_mode(regs) &&		\
				trap_from_host_kernel_IP(regs))
/* guest trap occurred on guest user or kernel or on host but due to guest */
/* for example guest kernel address in hypercalls */
#define	due_to_guest_trap_on_host(regs)					\
		(trap_on_guest(regs) &&					\
			(user_mode(regs) ||				\
			LIGHT_HYPERCALL_MODE(regs) ||			\
			GENERIC_HYPERCALL_MODE()))
#define	due_to_guest_trap_on_pv_hv_host(vcpu, regs)			\
		(trap_on_pv_hv_guest(vcpu, regs) &&			\
			(user_mode(regs) ||				\
			LIGHT_HYPERCALL_MODE(regs) ||			\
			GENERIC_HYPERCALL_MODE()))
/* page fault is from intercept */
#define	due_to_intc_page_fault(vcpu, regs)				\
		((vcpu) != NULL &&					\
			(vcpu)->arch.is_hv &&				\
				(regs)->trap->is_intc)
/* trap occurred on guest user only */
#define	guest_user_trap_on_host(regs)					\
		(trap_on_guest(regs) && guest_trap_user_mode(regs))
/* trap occurred on guest kernel only */
#define	guest_kernel_trap_on_host(regs)					\
		(trap_on_guest(regs) && guest_trap_kernel_mode(regs))

/* macros to detect guest traps on guest and on host */
/* trap on guest user, kernel or on host kernel due to guest */
#define	__guest_trap(regs)						\
		(paravirt_enabled() ||					\
			test_thread_flag(TIF_VIRTUALIZED_GUEST))

#define	addr_from_guest_user(addr)	((addr) < GUEST_TASK_SIZE)
#define	addr_from_guest_kernel(addr)	\
		((addr) >= GUEST_TASK_SIZE && (addr) < HOST_TASK_SIZE)

#define guest_user_addr_mode_page_fault(regs, instr_page, addr)		\
		((instr_page) ? guest_user_mode(regs) :			\
					guest_user_mode(regs) ||	\
			(addr_from_guest_user(addr) &&			\
				(!trap_from_host_kernel(regs) ||	\
					LIGHT_HYPERCALL_MODE(regs) ||	\
					GENERIC_HYPERCALL_MODE())))
/* macros to detect guest user address on host, */
/* guest has not own guest, so macros should always return 'false' for guest */
/* faulted address is from guest user space */
#define	guest_mode_page_fault(regs, instr_page, addr)			\
		(trap_on_guest(regs) &&					\
			guest_user_addr_mode_page_fault(regs,		\
						instr_page, addr))
/* macros to detect instruction page fault on guest kernel access */
/* such traps should be handled by host because of guest kernel */
/* is user of host */
#define	guest_kernel_instr_page_fault(regs)				\
		(trap_on_guest(regs) &&					\
			guest_trap_kernel_mode(regs) &&			\
				trap_on_guest_kernel_IP(regs))
/* macros to detect instruction page fault on guest user access */
/* such traps should be handled by guest kernel */
#define	guest_user_instr_page_fault(regs)				\
		(trap_on_guest(regs) &&	guest_user_mode(regs))

static inline e2k_addr_t
check_is_user_address(struct task_struct *task, e2k_addr_t address)
{
	if (likely(address < TASK_SIZE))
		return 0;
	if (!paravirt_enabled()) {
		pr_err("Address 0x%016lx is host kernel address\n",
			address);
		return -1;
	} else if (address < NATIVE_TASK_SIZE) {
		pr_err("Address 0x%016lx is guest kernel address\n",
			address);
		return -1;
	} else {
		pr_err("Address 0x%016lx is host kernel address\n",
			address);
		return -1;
	}
}
#define	IS_GUEST_USER_ADDRESS_TO_PVA(task, address)	\
		(test_ti_thread_flag(task_thread_info(tsk), \
						TIF_VIRTUALIZED_GUEST) && \
			IS_GUEST_USER_ADDRESS(address))
#define	IS_GUEST_ADDRESS_TO_HOST(address)		\
		(paravirt_enabled() && !IS_HV_GM() && \
				IS_HOST_KERNEL_ADDRESS(address))

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
#else	/* CONFIG_KVM_GUEST_KERNEL */
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/ptrace.h>
#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

#else	/* ! CONFIG_VIRTUALIZATION */
/* it is native kernel without any virtualization */

#define	guest_task_mode(task)	false	/* only native tasks */

#define user_mode(regs)		is_user_mode(regs, TASK_SIZE)
#define kernel_mode(regs)	is_kernel_mode(regs, TASK_SIZE)

#define	is_call_from_host_user(cr0_hi, cr1_lo)	\
		(from_user_IP(cr0_hi) && from_user_mode(cr1_lo))
#define	is_call_from_host_user_IP(cr0_hi, cr1_lo, ignore_IP)	\
		((!(ignore_IP)) ? is_call_from_host_user(cr0_hi, cr1_lo) : \
			from_user_mode(cr1_lo))
#define	is_call_from_guest_user(cr0_hi, cr1_lo)			false
#define	is_call_from_guest_user_IP(cr0_hi, cr1_lo, ignoreIP)	false
#define	is_call_from_host_kernel(cr0_hi, cr1_lo)			\
		(from_kernel_IP(cr0_hi) && from_kernel_mode(cr1_lo))
#define	is_call_from_host_kernel_IP(cr0_hi, cr1_lo, ignore_IP)	\
		((!(ignore_IP)) ? is_call_from_host_kernel(cr0_hi, cr1_lo) : \
			from_kernel_mode(cr1_lo))
#define	is_call_from_guest_kernel(cr0_hi, cr1_lo)		false
#define	is_call_from_guest_kernel_IP(cr0_hi, cr1_lo, ignore_IP)	false
#define	call_from_guest_kernel(regs)				false

#define	is_call_from_user(cr0_hi, cr1_lo, __HOST__)			\
		is_call_from_host_user(cr0_hi, cr1_lo)
#define	is_call_from_kernel(cr0_hi, cr1_lo, __HOST__)			\
		is_call_from_host_kernel(cr0_hi, cr1_lo)

#define __trap_from_user(regs)		is_trap_from_user(regs, TASK_SIZE)
#define	__trap_from_kernel(regs)	is_trap_from_kernel(regs, TASK_SIZE)
#define	trap_on_user(regs)		user_mode(regs)
#define	trap_on_kernel(regs)		kernel_mode(regs)

/* macroses to detect guest traps on host */
/* Virtualization is off, so nothing guests exist, */
/* so macroses should always return 'false' */
#define	trap_on_guest(regs)	false
/* trap occurred on guest user or kernel */
#define	guest_trap_on_host(regs)					\
		false		/* guest is not supported */
/* trap occurred on guest kernel or user, but in host mode */
/* and the trap can be due to guest or not */
#define	host_trap_on_guest(regs)					\
		false		/* guest is not supported */
/* trap occurred on guest user or kernel or on host but due to guest */
#define	due_to_guest_trap_on_host(regs)					\
		false		/* guest is not supported */
/* page fault is from intercept */
#define	due_to_intc_page_fault(vcpu, regs)				\
		false		/* guest is not supported */
/* trap occurred on guest user only */
#define	guest_user_trap_on_host(regs)					\
		false		/* guest is not supported */
/* trap occurred on guest kernel only */
#define	guest_kernel_trap_on_host(regs)					\
		false		/* guest is not supported */

/* macros to detect guest traps on guest and on host */
/* trap on guest user, kernel or on host kernel due to guest */
#define	__guest_trap(regs)						\
		false		/* guest is not supported */
/* macros to detect guest kernel traps on guest and on host */
/* trap only on guest kernel */
#define	trap_from_guest_kernel(regs)					\
		false		/* guest is not supported */

#define	__call_from_kernel(regs)	from_kernel_mode((regs)->crs.cr1_lo)
#define	__call_from_user(regs)		from_user_mode((regs)->crs.cr1_lo)

#define	ON_HOST_KERNEL()	true
#define	call_from_user_mode(cr0_hi, cr1_lo)				\
		is_call_from_user(cr0_hi, cr1_lo, ON_HOST_KERNEL())
#define	call_from_kernel_mode(cr0_hi, cr1_lo)				\
		is_call_from_kernel(cr0_hi, cr1_lo, ON_HOST_KERNEL())
#define	call_from_user(regs)						\
		call_from_user_mode((regs)->crs.cr0_hi, (regs)->crs.cr1_lo)
#define	call_from_kernel(regs)						\
		call_from_kernel_mode((regs)->crs.cr0_hi, (regs)->crs.cr1_lo)

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

#define	guest_mode_page_fault(regs, instr_page, addr)	false

#endif	/* CONFIG_VIRTUALIZATION */

#ifndef	CONFIG_VIRTUALIZATION
/* it is native kernel without virtualization support */
#define	LIGHT_HYPERCALL_MODE(regs)		0 /* hypercalls not supported */
#define	TI_GENERIC_HYPERCALL_MODE(thread_info)	0 /* hypercalls not supported */
#define	GENERIC_HYPERCALL_MODE()		0 /* hypercalls not supported */
#define	IN_LIGHT_HYPERCALL()			0 /* hypercalls not supported */
#define	IN_GENERIC_HYPERCALL()			0 /* hypercalls not supported */
#define	IN_HYPERCALL()				0 /* hypercalls not supported */
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized) */
#include <asm/kvm/guest/ptrace.h>
#elif	defined(CONFIG_VIRTUALIZATION) || defined(CONFIG_PARAVIRT_GUEST)
/* It is native host kernel with virtualization support on */
/* or it is paravirtualized host and guest kernel */

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
#else	/* ! CONFIG_VIRTUALIZATION && ! CONFIG_PARAVIRT_GUEST */
 #error "Unknown virtualization type"
#endif	/* ! CONFIG_VIRTUALIZATION */

#ifdef	CONFIG_KVM_HOST_MODE
/* It is native host kernel with virtualization support on */

/*
 * Additional context for paravirtualized guest to save/restore at
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
	bool in_sig_handler;		/* signal handler in progress */
	unsigned long sigreturn_entry;	/* guest signal return start IP */
} pv_vcpu_ctxt_t;

#else	/* !CONFIG_KVM_HOST_MODE */
/* it is native kernel without any virtualization */
/* or pure guest kernel (not paravirtualized) */

typedef struct pv_vcpu_ctxt {
	/* empty structure */
} pv_vcpu_ctxt_t;

#endif	/* CONFIG_KVM_HOST_MODE */

#ifdef	CONFIG_VIRTUALIZATION

static inline struct pt_regs *find_guest_user_regs(struct pt_regs *regs)
{
	struct pt_regs *guser_regs = regs;
	do {
		if (guest_user_mode(guser_regs))
			break;
		if (guser_regs->next != NULL &&
				guser_regs->next <= guser_regs) {
			/* pt_regs allocated only at the stack, stack grows */
			/* down, so next structure can be only above current */
			pr_err("%s(): invalid list of pt_regs structures: "
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
#else	/* ! CONFIG_VIRTUALIZATION */
static inline struct pt_regs *find_guest_user_regs(struct pt_regs *regs)
{
	return NULL;
}
#endif	/* CONFIG_VIRTUALIZATION */


#if defined(CONFIG_SMP)
extern unsigned long profile_pc(struct pt_regs *regs);
#else
#define profile_pc(regs) instruction_pointer(regs)
#endif
extern void show_regs(struct pt_regs *);
extern int syscall_trace_entry(struct pt_regs *regs);
extern void syscall_trace_leave(struct pt_regs *regs);

#endif /* __KERNEL__ */
#endif /* _E2K_KVM_PTRACE_H */

