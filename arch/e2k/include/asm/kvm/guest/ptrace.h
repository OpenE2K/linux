#ifndef __E2K_KVM_GUEST_PTRACE_H
#define __E2K_KVM_GUEST_PTRACE_H

/* Does not include this header directly, include <asm/trap_table.h> */

#include <asm/e2k.h>
#include <asm/sigcontext.h>
#include <asm/kvm/hypercall.h>

struct task_struct;

static inline void
kvm_save_DAM(unsigned long long dam[DAM_ENTRIES_NUM])
{
	int ret;

	ret = HYPERVISOR_get_DAM(dam, DAM_ENTRIES_NUM);
	if (ret != 0) {
		pr_err("%s(): could not receive DAM state, error %d\n",
			__func__, ret);
	}
}

static inline void kvm_atomic_load_osgd_to_gd(void)
{
	/* FIXME: it is not now understand what to do */
}

static inline e2k_addr_t
kvm_check_is_user_address(struct task_struct *task, e2k_addr_t address)
{
	if (likely(address < GUEST_TASK_SIZE))
		return 0;
	if (address < NATIVE_TASK_SIZE) {
		pr_err("Address 0x%016lx is guest kernel address\n",
			address);
		return -1;
	}
	pr_err("Address 0x%016lx is host kernel address\n",
		address);
	return -1;
}
#define	KVM_IS_GUEST_USER_ADDRESS_TO_PVA(task, address)	\
		false	/* pure guest kernel has not own guests */
#define	KVM_IS_GUEST_ADDRESS_TO_HOST(address)		\
		IS_HOST_KERNEL_ADDRESS(address)

/* guest page table is pseudo PT and only host PT is used */
/* to translate any guest addresses */
#define	kvm_print_host_user_address_ptes(mm, address)	\
({ \
	HYPERVISOR_print_guest_user_address_ptes((mm)->gmmid_nr, address); \
})

#ifdef	CONFIG_KVM_GUEST_KERNEL

#define user_mode(regs)		is_user_mode(regs, GUEST_TASK_SIZE)
#define kernel_mode(regs)	is_kernel_mode(regs, GUEST_TASK_SIZE)

/* guest kernel can be: */
/*	user of host kernel, so USER MODE (pm = 0) */
/*	hardware virtualized guest kernel, so KERNEL MODE (pm = 1) */
#define	from_guest_kernel_mode(cr1_lo)	\
		((IS_HV_GM()) ? from_kernel_mode(cr1_lo) : \
					from_user_mode(cr1_lo))
#define	from_guest_kernel(cr0_hi, cr1_lo)	\
		(from_guest_kernel_mode(cr1_lo) && \
				from_guest_kernel_IP(cr0_hi))

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

/* macroses to detect guest traps on host */
/* Gust has not own nested VM, so nothing guests exist */
/* and macroses should always return 'false' */
#define	trap_on_guest(regs)						\
		false		/* own guest is not supported */
#define	trap_on_pv_hv_guest(vcpu, regs)					\
		false		/* own guest is not supported */
/* trap occurred on guest user or kernel */
#define	guest_trap_on_host(regs)					\
		false		/* own guest is not supported */
#define	guest_trap_on_pv_hv_host(vcpu, regs)				\
		false		/* own guest is not supported */
/* trap occurred on guest kernel or user, but in host mode */
/* and the trap can be due to guest or not */
#define	host_trap_on_guest(regs)					\
		false		/* own guest is not supported */
/* trap occurred on guest user or kernel or on host but due to guest */
#define	due_to_guest_trap_on_host(regs)					\
		false		/* own guest is not supported */
#define	due_to_guest_trap_on_pv_hv_host(vcpu, regs)			\
		false		/* own guest is not supported */

#define	ON_HOST_KERNEL()	false	/* it is guest, not host */
#define	call_from_user_mode(cr0_hi, cr1_lo)				\
		is_call_from_user(cr0_hi, cr1_lo, ON_HOST_KERNEL())
#define	call_from_kernel_mode(cr0_hi, cr1_lo)				\
		is_call_from_kernel(cr0_hi, cr1_lo, ON_HOST_KERNEL())
#define	call_from_user(regs)						\
		call_from_user_mode((regs)->crs.cr0_hi, (regs)->crs.cr1_lo)
#define	call_from_kernel(regs)						\
		call_from_kernel_mode((regs)->crs.cr0_hi, (regs)->crs.cr1_lo)

#define	SAVE_DAM(dam)	kvm_save_DAM(dam)

static inline void atomic_load_osgd_to_gd(void)
{
	kvm_atomic_load_osgd_to_gd();
}

/* it is pure KVM guest kernel (not paravirtualized based on pv_ops) */
#define	LIGHT_HYPERCALL_MODE(regs)		0 /* hypercalls not supported */
#define	TI_GENERIC_HYPERCALL_MODE(thread_info)	0 /* hypercalls not supported */
#define	GENERIC_HYPERCALL_MODE()		0 /* hypercalls not supported */
#define	IN_LIGHT_HYPERCALL()			0 /* hypercalls not supported */
#define	IN_GENERIC_HYPERCALL()			0 /* hypercalls not supported */
#define	IN_HYPERCALL()				0 /* hypercalls not supported */

static inline e2k_addr_t
check_is_user_address(struct task_struct *task, e2k_addr_t address)
{
	return kvm_check_is_user_address(task, address);
}
#define	IS_GUEST_USER_ADDRESS_TO_PVA(task, address)	\
		KVM_IS_GUEST_USER_ADDRESS_TO_PVA(task, address)
#define	IS_GUEST_ADDRESS_TO_HOST(address)		\
		KVM_IS_GUEST_ADDRESS_TO_HOST(address)
#define	print_host_user_address_ptes(mm, address)	\
		kvm_print_host_user_address_ptes(mm, address)
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* __E2K_KVM_GUEST_PTRACE_H */
