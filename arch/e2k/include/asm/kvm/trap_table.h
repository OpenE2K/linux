#ifndef __KVM_E2K_TRAP_TABLE_H
#define __KVM_E2K_TRAP_TABLE_H

/* Does not include this header directly, include <asm/trap_table.h> */

#ifndef	__ASSEMBLY__

#include <linux/kvm.h>
#include <linux/kvm_host.h>

#include <asm/ptrace.h>
#include <asm/thread_info.h>
#include <asm/traps.h>
#include <asm/kvm/cpu_regs_access.h>
#include <asm/kvm/mmu.h>

#undef	DEBUG_KVM_GUEST_TRAPS_MODE
#undef	DebugKVMGT
#define	DEBUG_KVM_GUEST_TRAPS_MODE	0	/* KVM guest trap debugging */
#define	DebugKVMGT(fmt, args...)					\
({									\
	if (DEBUG_KVM_GUEST_TRAPS_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_VERBOSE_GUEST_TRAPS_MODE
#undef	DebugKVMVGT
#define	DEBUG_KVM_VERBOSE_GUEST_TRAPS_MODE	0	/* KVM verbose guest */
							/* trap debugging */
#define	DebugKVMVGT(fmt, args...)					\
({									\
	if (DEBUG_KVM_VERBOSE_GUEST_TRAPS_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */
# define TT_BUG_ON(cond) BUG_ON(cond)
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native guest kernel */
# define TT_BUG_ON(cond) BUG_ON(cond)
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel or host kernel with virtualization support */
# define TT_BUG_ON(cond) do { } while (0)
#endif	/* CONFIG_PARAVIRT_GUEST */

/* structure of result of trap passing to guest functions */
#define	KVM_PASSED_TRAPS_MASK		((1ULL << (exc_max_num + 1)) - 1)
#define	KVM_GUEST_KERNEL_ADDR_PF_BIT	(exc_max_num + 1)
#define	KVM_SHADOW_PT_PROT_PF_BIT	(exc_max_num + 2)
#define	KVM_PASS_RESULT_PF_BIT		KVM_SHADOW_PT_PROT_PF_BIT
#define	KVM_PASS_RESULT_PF_MASK		\
		((1ULL << (KVM_PASS_RESULT_PF_BIT + 1)) - 1)

/* events to complete VCPU trap handling */
#define	KVM_PV_MMU_RESTORE_CONTEXT_PF_BIT	(exc_max_num + 5)
#define	KVM_SHADOW_NONP_PF_BIT			(exc_max_num + 6)

#define	KVM_GUEST_KERNEL_ADDR_PF_MASK	\
		(1ULL << KVM_GUEST_KERNEL_ADDR_PF_BIT)
#define	KVM_SHADOW_PT_PROT_PF_MASK	\
		(1ULL << KVM_SHADOW_PT_PROT_PF_BIT)
#define	KVM_SHADOW_NONP_PF_MASK		\
		(1ULL << KVM_SHADOW_NONP_PF_BIT)
#define	KVM_PV_MMU_RESTORE_CONTEXT_PF_MASK	\
		(1ULL << KVM_PV_MMU_RESTORE_CONTEXT_PF_BIT)

#define	KVM_NOT_GUEST_TRAP_RESULT	0ULL
#define	KVM_TRAP_IS_PASSED(trap_no)	(1ULL << (trap_no))
#define	KVM_GUEST_KERNEL_ADDR_PF	KVM_GUEST_KERNEL_ADDR_PF_MASK
#define	KVM_SHADOW_PT_PROT_PF		KVM_SHADOW_PT_PROT_PF_MASK
#define	KVM_SHADOW_NONP_PF		KVM_SHADOW_NONP_PF_MASK
#define	KVM_NEED_COMPLETE_PF_MASK	\
		(KVM_PV_MMU_RESTORE_CONTEXT_PF_MASK)

#define	KVM_IS_ERROR_RESULT_PF(hret)	((long)(hret) < 0)
#define	KVM_GET_PASS_RESULT_PF(hret)	((hret) & KVM_PASS_RESULT_PF_MASK)
#define	KVM_IS_NOT_GUEST_TRAP(hret)	\
		(KVM_GET_PASS_RESULT_PF(hret) == KVM_NOT_GUEST_TRAP_RESULT)
#define	KVM_GET_PASSED_TRAPS(hret)	\
		(KVM_GET_PASS_RESULT_PF(hret) & KVM_PASSED_TRAPS_MASK)
#define	KVM_IS_TRAP_PASSED(hret)	(KVM_GET_PASSED_TRAPS(hret) != 0)
#define	KVM_IS_GUEST_KERNEL_ADDR_PF(hret)	\
		(KVM_GET_PASS_RESULT_PF(hret) == KVM_GUEST_KERNEL_ADDR_PF)
#define	KVM_IS_SHADOW_PT_PROT_PF(hret)	\
		(KVM_GET_PASS_RESULT_PF(hret) == KVM_SHADOW_PT_PROT_PF)
#define	KVM_IS_SHADOW_NONP_PF(hret)	\
		((hret) & KVM_SHADOW_NONP_PF_MASK)
#define	KVM_GET_NEED_COMPLETE_PF(hret)	\
		((hret) & KVM_NEED_COMPLETE_PF_MASK)
#define	KVM_IS_NEED_RESTORE_CONTEXT_PF(hret)	\
		((KVM_GET_NEED_COMPLETE_PF(hret) & \
			KVM_PV_MMU_RESTORE_CONTEXT_PF_MASK) != 0)
#define	KVM_CLEAR_NEED_RESTORE_CONTEXT_PF(hret)	\
		(KVM_GET_NEED_COMPLETE_PF(hret) & \
			~KVM_PV_MMU_RESTORE_CONTEXT_PF_MASK)

static inline unsigned int
kvm_host_is_kernel_data_stack_bounds(bool on_kernel, e2k_usd_lo_t usd_lo)
{
	return native_is_kernel_data_stack_bounds(true, usd_lo);
}

#ifdef	CONFIG_VIRTUALIZATION
/* It is native host guest kernel with virtualization support */
/* or paravirtualized host and guest kernel */
/* or pure guest kernel */
static inline unsigned int
is_kernel_data_stack_bounds(bool on_kernel, e2k_usd_lo_t usd_lo)
{
	return kvm_host_is_kernel_data_stack_bounds(on_kernel, usd_lo);
}
#endif	/* CONFIG_VIRTUALIZATION */

/*
 * Hypervisor supports light hypercalls
 * Lighte hypercalls does not:
 *  - switch to kernel stacks
 *  - use data stack
 *  - call any function wich can use stack
 * So SBR does not switch to kernel stack, but we use
 * SBR value to calculate user/kernel mode of trap/system call
 * Light hypercals can be trapped (page fault on guest address, for example)
 * In this case SBR value shows user trap mode, but trap occurs on hypervisor
 * and we need know about it to do not save/restore global registers which
 * used by kernel to optimaze access to current/current_thread_info()
 */

#define	CR1_LO_PSR_PM_SHIFT	57	/* privileged mode */

#ifndef	CONFIG_VIRTUALIZATION
/* it is native kernel without any virtualization */

#define	handle_guest_traps(regs)	/* none any guests */
static __always_inline void
init_guest_traps_handling(struct pt_regs *regs, bool user_mode_trap)
{
}
static __always_inline void
init_guest_syscalls_handling(struct pt_regs *regs)
{
}

static inline bool
is_guest_proc_stack_bounds(struct pt_regs *regs)
{
	return false;	/* none any guest */
}
static inline bool
is_guest_chain_stack_bounds(struct pt_regs *regs)
{
	return false;	/* none any guest */
}
static inline bool
is_guest_TIRs_frozen(struct pt_regs *regs)
{
	return false;	/* none any guest */
}

static inline bool
handle_guest_last_wish(struct pt_regs *regs)
{
	return false;	/* none any guest and any wishes from */
}

/*
 * Following functions run on host, check if traps occurred on guest user
 * or kernel, so probably should be passed to guest kernel to handle.
 * None any guests when virtualization is off
 */
static inline unsigned long
pass_aau_trap_to_guest(struct pt_regs *regs,
			unsigned long TIR_hi, unsigned long TIR_lo)
{
	return 0;
}
static inline unsigned long
pass_the_trap_to_guest(struct pt_regs *regs, int trap_no,
			unsigned long TIR_hi, unsigned long TIR_lo)
{
	return 0;
}
static inline unsigned long
pass_stack_bounds_trap_to_guest(struct pt_regs *regs,
				bool proc_bounds, bool chain_bounds)
{
	return 0;
}
static inline unsigned long
pass_coredump_trap_to_guest(struct pt_regs *regs)
{
	return 0;
}
static inline unsigned long
pass_interrupt_to_guest(struct pt_regs *regs, int trap_no,
			unsigned long TIR_hi, unsigned long TIR_lo)
{
	return 0;
}
static inline unsigned long
pass_nm_interrupt_to_guest(struct pt_regs *regs, int trap_no,
			unsigned long TIR_hi, unsigned long TIR_lo)
{
	return 0;
}
static inline unsigned long
pass_virqs_to_guest(struct pt_regs *regs,
			unsigned long TIR_hi, unsigned long TIR_lo)
{
	return 0;
}
static inline unsigned long
pass_clw_fault_to_guest(struct pt_regs *regs, trap_cellar_t *tcellar)
{
	return 0;
}
static inline unsigned long
pass_page_fault_to_guest(struct pt_regs *regs, trap_cellar_t *tcellar)
{
	return 0;
}
static inline void
complete_page_fault_to_guest(unsigned long what_complete)
{
}
#else	/* CONFIG_VIRTUALIZATION */

/*
 * Special section of kernel image to be common for host and guest kernel and
 * to support paravirtualized host and guest running.
 * Functions at this section have fixed addressees and offsets into both images
 * Any function call from this section will run host image copy of this
 * function because of only host image section mapped to both image - host and
 * guest.
 */
#define __to_paravirt_guest	\
		__attribute__((__section__(".to_paravirt_guest")))
#define __to_guest	\
		__attribute__((__section__(".to_guest")))

extern char	__ptext_host_start[], __ptext_host_end[];

/*
 * KVM guest kernel trap handling support
 */

/* results of trap handling */
typedef enum trap_hndl {
	GUEST_TRAP_IMPOSSIBLE,		/* guest kernel does not support */
					/* so guest trap cannot be occured */
	GUEST_TRAP_NOT_HANDLED,		/* trap on guest, but guest kernel */
					/* cannot handle the trap */
	GUEST_TRAP_HANDLED,		/* guest trap was successfully */
					/* handled */
	GUEST_TRAP_FAILED,		/* guest trap handling failed */
} trap_hndl_t;

extern trap_hndl_t kvm_do_handle_guest_traps(struct pt_regs *regs);

extern bool kvm_is_guest_TIRs_frozen(struct pt_regs *regs);
extern bool kvm_is_guest_proc_stack_bounds(struct pt_regs *regs);
extern bool kvm_is_guest_chain_stack_bounds(struct pt_regs *regs);
extern unsigned long kvm_host_aau_page_fault(struct kvm_vcpu *vcpu,
				pt_regs_t *regs,
				unsigned long TIR_hi, unsigned long TIR_lo);
extern unsigned long kvm_pass_the_trap_to_guest(struct kvm_vcpu *vcpu,
				pt_regs_t *regs,
				unsigned long TIR_hi, unsigned long TIR_lo,
				int trap_no);
extern unsigned long kvm_pass_stack_bounds_trap_to_guest(struct pt_regs *regs,
				bool proc_bounds, bool chain_bounds);
extern unsigned long kvm_pass_virqs_to_guest(struct pt_regs *regs,
				unsigned long TIR_hi, unsigned long TIR_lo);
extern unsigned long kvm_pass_coredump_trap_to_guest(struct kvm_vcpu *vcpu,
							struct pt_regs *regs);
extern unsigned long kvm_pass_clw_fault_to_guest(struct pt_regs *regs,
				trap_cellar_t *tcellar);
extern unsigned long kvm_pass_page_fault_to_guest(struct pt_regs *regs,
				trap_cellar_t *tcellar);
extern void kvm_complete_page_fault_to_guest(unsigned long what_complete);

extern int do_hret_last_wish_intc(struct kvm_vcpu *vcpu, struct pt_regs *regs);

extern void trap_handler_trampoline(void);
extern void syscall_handler_trampoline(void);
extern void trap_handler_trampoline_continue(void);
extern void syscall_handler_trampoline_continue(u64 sys_rval);
extern void syscall_fork_trampoline(void);
extern void syscall_fork_trampoline_continue(u64 sys_rval);
extern notrace long return_pv_vcpu_trap(void);
extern notrace long return_pv_vcpu_syscall(void);

static __always_inline void
kvm_init_guest_traps_handling(struct pt_regs *regs, bool user_mode_trap)
{
	regs->traps_to_guest = 0;	/* only for host */
	regs->is_guest_user = false;	/* only for host */
	regs->g_stacks_valid = false;	/* only for host */
	if (user_mode_trap && test_thread_flag(TIF_LIGHT_HYPERCALL) &&
			(NATIVE_NV_READ_CR1_LO_REG().CR1_lo_pm)) {
		regs->flags.light_hypercall = 1;
	}
}

static __always_inline void
kvm_init_guest_syscalls_handling(struct pt_regs *regs)
{
	regs->traps_to_guest = 0;	/* only for host */
	regs->is_guest_user = true;	/* only for host */
	regs->g_stacks_valid = false;	/* only for host */
}

static inline void
kvm_exit_handle_syscall(e2k_addr_t sbr, e2k_usd_hi_t usd_hi,
			e2k_usd_lo_t usd_lo, e2k_upsr_t upsr)
{
	KVM_WRITE_UPSR_REG_VALUE(upsr.UPSR_reg);
	KVM_WRITE_USD_REG(usd_hi, usd_lo);
	KVM_WRITE_SBR_REG_VALUE(sbr);
}

/*
 * The function should return boolen value 'true' if the trap is wish
 * of host to inject VIRQs interrupt and return 'false' if the wish is not
 * from host to deal with guest
 */
static inline bool
kvm_handle_guest_last_wish(struct pt_regs *regs)
{
	struct kvm_vcpu *vcpu = current_thread_info()->vcpu;

	if (vcpu == NULL) {
		/* it is not guest VCPU thread, or completed */
		return false;
	}
	if (vcpu->arch.trap_wish) {
		/* some trap was injected, goto trap handling */
		regs->traps_to_guest |= vcpu->arch.trap_mask_wish;
		vcpu->arch.trap_mask_wish = 0;
		return true;
	}
	if (vcpu->arch.virq_wish) {
		/* trap is only to interrupt guest kernel on guest mode */
		/* to provide injection of pending VIRQs on guest */
		if (!vcpu->arch.virq_injected) {
			vcpu->arch.virq_injected = true;
			vcpu->arch.virq_wish = false;
			return true;
		}	/* else already injected */
	}
	return false;
}

/*
 * Guest kernel (same as host) does not use AAU, so if trap occurred on
 * guest kernel it is error. Do not pass the trap to guest, host will handle
 * thr trap and kill the guest.
 * Guest user can use AAU and if trap occurred on guest user, then this trap
 * need pass to handle one by guest kernel
 */
static inline bool
kvm_should_pass_aau_kernel_trap_to_guest(struct pt_regs *regs)
{
	return false;
}
static inline bool
kvm_should_pass_aau_user_trap_to_guest(struct pt_regs *regs)
{
	return true;
}

/*
 * Some traps need not pass to guest, they can be handled by host only.
 */

#define	kvm_needless_guest_exc_mask	(0UL |				\
					exc_interrupt_mask |		\
					exc_nm_interrupt_mask |		\
					exc_mem_error_mask |		\
					exc_data_page_mask |		\
					0UL)
#define	kvm_guest_exc_mask		(exc_all_mask & \
						~kvm_needless_guest_exc_mask)

static inline bool
kvm_should_pass_the_trap_to_guest(struct pt_regs *regs, int trap_no)
{
	unsigned long trap_mask = (1UL << trap_no);

	if (trap_no == exc_last_wish_num) {
		struct kvm_vcpu *vcpu = current_thread_info()->vcpu;

		if (vcpu->arch.is_hv) {
			if (vcpu->arch.virq_wish || vcpu->arch.vm_exit_wish) {
				/* it is last wish to support guest on host */
				/* do not pass to guest */
				return false;
			}
		} else if (vcpu->arch.is_pv) {
			if (vcpu->arch.virq_wish) {
				/* it is paravirtualized guest, pass */
				/* interrupt to guest, if it is enabled */
				;
			} else if (vcpu->arch.trap_wish) {
				/* it is wish to inject some trap to guest */
				;
			} else {
				/* there is not any wish for guest */
				return false;
			}
		} else {
			KVM_BUG_ON(true);
		}
	}
	if (trap_mask & kvm_guest_exc_mask)
		return true;
	return false;
}
/*
 * Some traps will be passed to guest, but by host handler of the trap.
 */

#define	kvm_defer_guest_exc_mask	(0UL |				\
					exc_data_page_mask |		\
					exc_mem_lock_mask |		\
					exc_ainstr_page_miss_mask |	\
					exc_ainstr_page_prot_mask |	\
					0UL)
#define	kvm_pv_defer_guest_exc_mask	(0UL)

static inline bool
kvm_defered_pass_the_trap_to_guest(struct pt_regs *regs, int trap_no)
{
	unsigned long trap_mask = (1UL << trap_no);

	if (trap_mask & kvm_pv_defer_guest_exc_mask)
		return true;
	return false;
}

/*
 * The function controls traps handling by guest kernel.
 * Traps were passed to guest kernel (set TIRs and trap cellar) before
 * calling the function.
 * Result of function is bool 'traps were handled by guest'
 * If the trap is trap of guest user and was handled by guest kernel
 * (probably with fault), then the function return bool 'true' and handling
 * of this trap can be completed.
 * If the trap is not trap of guest user or cannot be handled by guest kernel,
 * then the function return bool 'false' and handling of this trap should
 * be continued by host.
 * WARNING: The function can be called only on host kernel (guest cannot
 * run own guests.
 */
static inline bool kvm_handle_guest_traps(struct pt_regs *regs)
{
	struct kvm_vcpu *vcpu;
	int ret;

	vcpu = current_thread_info()->vcpu;
	if (!due_to_guest_trap_on_pv_hv_host(vcpu, regs)) {
		DebugKVMVGT("trap occurred outside of guest user and "
			"kernel\n");
		return false;
	}
	if (regs->traps_to_guest == 0) {
		DebugKVMVGT("it is recursive trap on host and can be handled "
			"only by host\n");
		return false;
	}
	if (vcpu == NULL) {
		DebugKVMVGT("it is not VCPU thread or VCPU is not yet "
			"created\n");
		return false;
	}
	ret = kvm_do_handle_guest_traps(regs);
	regs->traps_to_guest = 0;

	if (ret == GUEST_TRAP_HANDLED) {
		DebugKVMGT("the guest trap handled\n");
		return true;
	} else if (ret == GUEST_TRAP_FAILED) {
		DebugKVMGT("the guest trap handled, but with fault\n");
		return true;
	} else if (ret == GUEST_TRAP_NOT_HANDLED) {
		DebugKVMGT("guest cannot handle the guest trap\n");
		return false;
	} else if (ret == GUEST_TRAP_IMPOSSIBLE) {
		DebugKVMGT("it is not guest user trap\n");
		return false;
	} else {
		BUG_ON(true);
	}
	return false;
}

static inline bool
is_guest_proc_stack_bounds(struct pt_regs *regs)
{
	if (!kvm_test_intc_emul_flag(regs))
		return false;

	return kvm_is_guest_proc_stack_bounds(regs);
}
static inline bool
is_guest_chain_stack_bounds(struct pt_regs *regs)
{
	if (!kvm_test_intc_emul_flag(regs))
		return false;

	return kvm_is_guest_chain_stack_bounds(regs);
}

#ifndef	CONFIG_KVM_GUEST_KERNEL
/* It is native host kernel with virtualization support on */
/* or it is paravirtualized host and guest kernel */
/* guest cannot support hypervisor mode and create own virtual machines, */
/* so in paravirtualized mode the following functions are called only */
/* on host mode and should not be used on guest mode */

#define	handle_guest_traps(regs)	kvm_handle_guest_traps(regs)

static __always_inline void
init_guest_traps_handling(struct pt_regs *regs, bool user_mode_trap)
{
	kvm_init_guest_traps_handling(regs, user_mode_trap);
}
static __always_inline void
init_guest_syscalls_handling(struct pt_regs *regs)
{
	kvm_init_guest_syscalls_handling(regs);
}

static inline bool
is_guest_TIRs_frozen(struct pt_regs *regs)
{
	if (!kvm_test_intc_emul_flag(regs))
		return false;

	return kvm_is_guest_TIRs_frozen(regs);
}

static inline bool
handle_guest_last_wish(struct pt_regs *regs)
{
	if (!kvm_test_intc_emul_flag(regs))
		return 0;

	return kvm_handle_guest_last_wish(regs);
}
static inline void
kvm_host_instr_page_fault(struct pt_regs *regs, tc_fault_type_t ftype,
				const int async_instr)
{
	struct kvm_vcpu *vcpu = current_thread_info()->vcpu;

	if (!kvm_test_intc_emul_flag(regs)) {
		native_instr_page_fault(regs, ftype, async_instr);
		return;
	}

	kvm_pv_mmu_instr_page_fault(vcpu, regs, ftype, async_instr);
}

static inline int
kvm_host_do_aau_page_fault(struct pt_regs *const regs, e2k_addr_t address,
		const tc_cond_t condition, const tc_mask_t mask,
		const unsigned int aa_no)
{
	if (likely(!kvm_test_intc_emul_flag(regs))) {
		return native_do_aau_page_fault(regs, address, condition, mask,
						aa_no);
	}

	return kvm_pv_mmu_aau_page_fault(current_thread_info()->vcpu, regs,
					 address, condition, aa_no);
}

/*
 * Following functions run on host, check if traps occurred on guest user
 * or kernel, so probably sould be passed to guest kernel to handle.
 * In some cases traps should be passed to guest, but need be preliminary
 * handled by host (for example hardware stack bounds).
 * Functions return flag or mask of traps which passed to guest and
 * should not be handled by host
 */
static inline unsigned long
pass_aau_trap_to_guest(struct pt_regs *regs,
			unsigned long TIR_hi, unsigned long TIR_lo)
{
	struct kvm_vcpu *vcpu;

	if (!kvm_test_intc_emul_flag(regs))
		return 0;

	vcpu = current_thread_info()->vcpu;

	return kvm_host_aau_page_fault(vcpu, regs, TIR_hi, TIR_lo);
}
static inline unsigned long
pass_stack_bounds_trap_to_guest(struct pt_regs *regs,
				bool proc_bounds, bool chain_bounds)
{
	if (!kvm_test_intc_emul_flag(regs))
		return 0;

	return kvm_pass_stack_bounds_trap_to_guest(regs,
					proc_bounds, chain_bounds);
}
static inline bool
pass_instr_page_fault_trap_to_guest(struct pt_regs *regs, int trap_no)
{
	if (!kvm_test_intc_emul_flag(regs))
		return false;

	return true;

}
static inline unsigned long
pass_the_trap_to_guest(struct pt_regs *regs,
				unsigned long TIR_hi, unsigned long TIR_lo,
				int trap_no)
{
	struct kvm_vcpu *vcpu;

	if (!kvm_test_intc_emul_flag(regs))
		return 0;

	vcpu = current_thread_info()->vcpu;

/*
	if (trap_no == exc_proc_stack_bounds_num)
		return pass_stack_bounds_trap_to_guest(regs, true, false);
	if (trap_no == exc_chain_stack_bounds_num)
		return pass_stack_bounds_trap_to_guest(regs, false, true);
 */

	if (!kvm_should_pass_the_trap_to_guest(regs, trap_no)) {
		DebugKVMVGT("trap #%d needs not handled by guest\n",
			trap_no);
		return 0;
	}
	if (trap_no == exc_instr_page_miss_num) {
		tc_fault_type_t ftype;

		AW(ftype) = 0;
		AS(ftype).page_miss = 1;
		kvm_pv_mmu_instr_page_fault(vcpu, regs, ftype, 0);
		return 1;
	}
	if (trap_no == exc_instr_page_prot_num) {
		tc_fault_type_t ftype;

		AW(ftype) = 0;
		AS(ftype).illegal_page = 1;
		kvm_pv_mmu_instr_page_fault(vcpu, regs, ftype, 0);
		return 1;
	}
	if (trap_no == exc_ainstr_page_miss_num) {
		tc_fault_type_t ftype;

		AW(ftype) = 0;
		AS(ftype).page_miss = 1;
		kvm_pv_mmu_instr_page_fault(vcpu, regs, ftype, 1);
		return 1;
	}
	if (trap_no == exc_ainstr_page_prot_num) {
		tc_fault_type_t ftype;

		AW(ftype) = 0;
		AS(ftype).illegal_page = 1;
		kvm_pv_mmu_instr_page_fault(vcpu, regs, ftype, 1);
		return 1;
	}
	if (trap_no == exc_last_wish_num) {
		int r;

		r = do_hret_last_wish_intc(vcpu, regs);
		if (r == 0) {
			return 1;
		} else {
			return 0;
		}
	}
	if (kvm_vcpu_in_hypercall(vcpu)) {
		/* the trap on host, so handles it by host */
		return 0;
	}
	if (kvm_defered_pass_the_trap_to_guest(regs, trap_no)) {
		DebugKVMVGT("trap #%d will be passed later by host "
			"handler of the trap\n", trap_no);
		return 0;
	}
	return kvm_pass_the_trap_to_guest(vcpu, regs, TIR_hi, TIR_lo, trap_no);
}
static inline unsigned long
pass_coredump_trap_to_guest(struct pt_regs *regs)
{
	struct kvm_vcpu *vcpu;

	if (!kvm_test_intc_emul_flag(regs))
		return 0;

	vcpu = current_thread_info()->vcpu;


	return kvm_pass_coredump_trap_to_guest(vcpu, regs);
}

/*
 * Now interrupts are handled by guest only in bottom half style
 * Host pass interrupts to special virtual IRQ process (activate VIRQ VCPU)
 * This process activates specified for this VIRQ guest kernel thread
 * to handle interrupt.
 * So do not pass real interrupts to guest kernel
 */
static inline unsigned long
pass_interrupt_to_guest(struct pt_regs *regs, int trap_no,
			unsigned long TIR_hi, unsigned long TIR_lo)
{
	return 0;
}
static inline unsigned long
pass_nm_interrupt_to_guest(struct pt_regs *regs, int trap_no,
			unsigned long TIR_hi, unsigned long TIR_lo)
{
	return 0;
}
static inline unsigned long
pass_virqs_to_guest(struct pt_regs *regs,
			unsigned long TIR_hi, unsigned long TIR_lo)
{
	if (!kvm_test_intc_emul_flag(regs))
		return 0;

	if (test_thread_flag(TIF_PSEUDOTHREAD)) {
		/* it is VIRQ VCPU thread, it cannot handle interrupts */
		return 0;
	}
	if (!test_thread_flag(TIF_VIRQS_ACTIVE)) {
		/* VIRQ VCPU thread is not yet active */
		return 0;
	}
	return kvm_pass_virqs_to_guest(regs, TIR_hi, TIR_lo);
}
static inline unsigned long
pass_clw_fault_to_guest(struct pt_regs *regs, trap_cellar_t *tcellar)
{
	if (!kvm_test_intc_emul_flag(regs))
		return 0;

	return kvm_pass_clw_fault_to_guest(regs, tcellar);
}
static inline unsigned long
pass_page_fault_to_guest(struct pt_regs *regs, trap_cellar_t *tcellar)
{
	if (!kvm_test_intc_emul_flag(regs))
		return 0;

	return kvm_pass_page_fault_to_guest(regs, tcellar);
}
static inline void
complete_page_fault_to_guest(unsigned long what_complete)
{
	kvm_complete_page_fault_to_guest(what_complete);
}
#endif	/* ! CONFIG_KVM_GUEST_KERNEL */
#endif	/* ! CONFIG_VIRTUALIZATION */

static inline bool
native_is_proc_stack_bounds(struct thread_info *ti, struct pt_regs *regs)
{
	return (user_mode(regs) &&
			regs->stacks.psp_hi.PSP_hi_ind >=
				regs->stacks.psp_hi.PSP_hi_size) ||
			regs->stacks.psp_hi.PSP_hi_ind <= 0;
}
static inline bool
native_is_chain_stack_bounds(struct thread_info *ti, struct pt_regs *regs)
{
	return (user_mode(regs) &&
			regs->stacks.pcsp_hi.PCSP_hi_ind >=
				regs->stacks.pcsp_hi.PCSP_hi_size) ||
			regs->stacks.pcsp_hi.PSP_hi_ind <= 0;
}

#if	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native guest kernel */
#include <asm/kvm/guest/trap_table.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host/guest kernel */
#include <asm/paravirt/trap_table.h>
#else	/* ! CONFIG_KVM_GUEST_KERNEL && ! CONFIG_PARAVIRT_GUEST */
/* it is native kernel with or without virtualization support */
static inline bool
is_proc_stack_bounds(struct thread_info *ti, struct pt_regs *regs)
{
	return native_is_proc_stack_bounds(ti, regs);
}
static inline bool
is_chain_stack_bounds(struct thread_info *ti, struct pt_regs *regs)
{
	return native_is_chain_stack_bounds(ti, regs);
}

#ifdef	CONFIG_VIRTUALIZATION
/* it is host kernel with virtualization support */
static inline void
instr_page_fault(struct pt_regs *regs, tc_fault_type_t ftype,
			const int async_instr)
{
	kvm_host_instr_page_fault(regs, ftype, async_instr);
}

static inline int
do_aau_page_fault(struct pt_regs *const regs, e2k_addr_t address,
		const tc_cond_t condition, const tc_mask_t mask,
		const unsigned int aa_no)
{
	return kvm_host_do_aau_page_fault(regs, address, condition, mask,
					  aa_no);
}
#endif	/* CONFIG_VIRTUALIZATION */

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#else	/* __ASSEMBLY__ */
#include <asm/kvm/trap_table.S.h>
#endif	/* ! __ASSEMBLY__ */

#endif	/* __KVM_E2K_TRAP_TABLE_H */
