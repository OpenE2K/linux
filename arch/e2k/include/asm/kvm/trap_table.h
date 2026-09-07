/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

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
	if (DEBUG_KVM_GUEST_TRAPS_MODE)					\
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

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
# define TT_BUG_ON(cond) BUG_ON(cond)
#else /* !CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel whithout any virtualization */
/* or host kernel with virtualization support */
# define TT_BUG_ON(cond) do { } while (0)
#endif /* CONFIG_KVM_GUEST_KERNEL */

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
kvm_host_is_kernel_data_stack_bounds(bool on_kernel, e2k_usd_t usd)
{
	return native_is_kernel_data_stack_bounds(true, usd);
}

#ifdef	CONFIG_VIRTUALIZATION
/* It is native host guest kernel with virtualization support */
/* or virtualized guest kernel */
static inline unsigned int
is_kernel_data_stack_bounds(bool on_kernel, e2k_usd_t usd)
{
	return kvm_host_is_kernel_data_stack_bounds(on_kernel, usd);
}
#endif /* CONFIG_VIRTUALIZATION */

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

static __always_inline void
init_guest_traps_handling(struct pt_regs *regs, bool user_mode_trap)
{
}

static __always_inline void init_guest_syscalls_handling(struct pt_regs *regs)
{
}

static inline bool is_guest_TIRs_frozen(struct pt_regs *regs)
{
	return false;	/* none any guest */
}

static inline bool is_injected_guest_coredump(struct pt_regs *regs)
{
	return false;	/* none any guest */
}

static inline bool handle_guest_last_wish(struct pt_regs *regs)
{
	return false;	/* none any guest and any wishes from */
}

/*
 * Following functions run on host, check if traps occurred on guest user
 * or kernel, so probably should be passed to guest kernel to handle.
 * None any guests when virtualization is off
 */
static inline unsigned long
pass_aau_trap_to_guest(struct pt_regs *regs, e2k_tir_t TIR)
{
	return 0;
}

static inline unsigned long
pass_the_trap_to_guest(struct pt_regs *regs, e2k_tir_t TIR, int trap_no)
{
	return 0;
}

static inline unsigned long
pass_stack_bounds_trap_to_guest(struct pt_regs *regs,
				bool proc_bounds, bool chain_bounds)
{
	return 0;
}

static inline unsigned long pass_coredump_trap_to_guest(struct pt_regs *regs)
{
	return 0;
}

static inline unsigned long
pass_interrupt_to_guest(struct pt_regs *regs, e2k_tir_t TIR, int trap_no)
{
	return 0;
}

static inline unsigned long
pass_nm_interrupt_to_guest(struct pt_regs *regs, e2k_tir_t TIR, int trap_no)
{
	return 0;
}

static inline unsigned long
pass_virqs_to_guest(struct pt_regs *regs, e2k_tir_t TIR)
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

static inline void complete_page_fault_to_guest(unsigned long what_complete)
{
}
#else /* CONFIG_VIRTUALIZATION */

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
					     pt_regs_t *regs, e2k_tir_t TIR);
extern unsigned long kvm_pass_the_trap_to_guest(struct kvm_vcpu *vcpu,
						pt_regs_t *regs, e2k_tir_t TIR, int trap_no);
extern unsigned long kvm_pass_stack_bounds_trap_to_guest(struct pt_regs *regs,
							 bool proc_bounds, bool chain_bounds);
extern unsigned long kvm_pass_virqs_to_guest(struct pt_regs *regs, e2k_tir_t TIR);
extern unsigned long kvm_pass_coredump_trap_to_guest(struct kvm_vcpu *vcpu,
						     struct pt_regs *regs);
extern void kvm_pass_coredump_to_all_vm(struct pt_regs *regs);
extern unsigned long kvm_pass_clw_fault_to_guest(struct pt_regs *regs,
						 trap_cellar_t *tcellar);
extern unsigned long kvm_pass_page_fault_to_guest(struct pt_regs *regs,
						  trap_cellar_t *tcellar);
extern void kvm_complete_page_fault_to_guest(unsigned long what_complete);

extern int intc_hret_last_wish(struct kvm_vcpu *vcpu, struct pt_regs *regs);

extern unsigned long (*ttable_entry18) (unsigned long, unsigned long,
					unsigned long, unsigned long,
					unsigned long, unsigned long,
					unsigned long, unsigned long);
extern unsigned long kvm_disabled_priv_hcall(unsigned long nr,
					     unsigned long arg1,
					     unsigned long arg2,
					     unsigned long arg3,
					     unsigned long arg4,
					     unsigned long arg5,
					     unsigned long arg6,
					     unsigned long arg7);

extern void trap_handler_trampoline(void);
extern void syscall_handler_trampoline(void);
extern void sys_sigreturn_handler_trampoline(void);
extern void return_pv_vcpu_from_mkctxt(void);
extern void trap_handler_trampoline_continue(void);
extern void syscall_handler_trampoline_continue(u64 sys_rval);
extern void return_pv_vcpu_from_mkctxt_continue(void);
extern void syscall_fork_trampoline(void);
extern void syscall_fork_trampoline_continue(u64 sys_rval);
extern notrace long return_pv_vcpu_trap(void);
extern notrace long return_pv_vcpu_syscall(void);
extern notrace void pv_vcpu_mkctxt_complete(void);

static __always_inline void
kvm_init_guest_traps_handling(struct pt_regs *regs, bool user_mode_trap)
{
	regs->traps_to_guest = 0;	/* only for host */
	regs->is_guest_user = false;	/* only for host */
	regs->g_stacks_valid = false;	/* only for host */
	regs->in_fast_syscall = false;	/* only for host */
	if (user_mode_trap && test_thread_flag(TIF_LIGHT_HYPERCALL) &&
	    native_read_CR1_reg().pm) {
		regs->flags.light_hypercall = 1;
	}
}

static __always_inline void
kvm_init_guest_syscalls_handling(struct pt_regs *regs)
{
	regs->traps_to_guest = 0;	/* only for host */
	regs->is_guest_user = true;	/* only for host */
	regs->g_stacks_valid = false;	/* only for host */
	regs->in_fast_syscall = false;	/* only for host */
}

static inline void kvm_exit_handle_syscall(e2k_sbr_t sbr, e2k_usd_t usd,
					   e2k_upsr_t upsr, e2k_mem_crs_t crs)
{
	KVM_WRITE_UPSR_REG_VALUE(AW(upsr));
	KVM_WRITE_SBR_REG_VALUE(AW(sbr));
	KVM_WRITE_USD_REG(usd);
	KVM_WRITE_CR0_REG(crs.cr0);
	KVM_WRITE_CR1_REG(crs.cr1);
}

/*
 * The function should return boolen value 'true' if the trap is wish
 * of host to inject VIRQs interrupt and return 'false' if the wish is not
 * from host to deal with guest
 */
static inline bool kvm_handle_guest_last_wish(struct pt_regs *regs)
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

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
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
				/* it is virtualized guest, pass */
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
			E2K_KVM_BUG_ON(true);
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
		DebugKVMVGT("trap occurred outside of guest user and kernel\n");
		return false;
	}
	if (regs->traps_to_guest == 0) {
		DebugKVMVGT("it is recursive trap on host and can be handled only by host\n");
		return false;
	}
	if (vcpu == NULL) {
		DebugKVMVGT("it is not VCPU thread or VCPU is not yet created\n");
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
#else
static inline int
kvm_host_do_aau_page_fault(struct pt_regs *const regs, e2k_addr_t address,
			   const tc_cond_t condition, const tc_mask_t mask,
			   const unsigned int aa_no)
{
	return native_do_aau_page_fault(regs, address, condition, mask, aa_no);
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#ifndef	CONFIG_KVM_GUEST_KERNEL
/* It is native host kernel with virtualization support on */
/* guest cannot support hypervisor mode and create own virtual machines, */

static __always_inline void
init_guest_traps_handling(struct pt_regs *regs, bool user_mode_trap)
{
	kvm_init_guest_traps_handling(regs, user_mode_trap);
}

static __always_inline void init_guest_syscalls_handling(struct pt_regs *regs)
{
	kvm_init_guest_syscalls_handling(regs);
}

static inline bool is_guest_TIRs_frozen(struct pt_regs *regs)
{
	if (!kvm_test_intc_emul_flag(regs))
		return false;

	return kvm_is_guest_TIRs_frozen(regs);
}

static inline bool is_injected_guest_coredump(struct pt_regs *regs)
{
	return regs->traps_to_guest == core_dump_mask;
}

static inline bool handle_guest_last_wish(struct pt_regs *regs)
{
	if (!kvm_test_intc_emul_flag(regs))
		return 0;

	return kvm_handle_guest_last_wish(regs);
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static bool kvm_check_sys_call_disable(pt_regs_t *regs, e2k_tir_t TIR)
{
	e2k_tir_t tir;
	e2k_ctpr_t ctpr1;
	unsigned long trap_ip, ctpr_ip, entry_ip;

	tir = TIR;
	trap_ip = tir.ip;
	ctpr1 = regs->ctpr1;
	ctpr_ip = ctpr1.ta_base;
	entry_ip = (unsigned long)&ttable_entry18;

	if (likely(trap_ip != entry_ip && ctpr_ip != entry_ip)) {
		/* real invalid instruction address: pass to guest  */
		return false;
	}

	/* privileged action system call entry disabled by OSEM */
	/* update ctpr IP to call disabled case of privileged actions */
	ctpr1.ta_base = (unsigned long)kvm_disabled_priv_hcall;
	ctpr1 = ctpr_with_ta_tag(ctpr1, CTPSL_CT_TAG);
	regs->ctpr1 = ctpr1;
	/* return flag to ignore the trap by host */
	return true;
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
pass_aau_trap_to_guest(struct pt_regs *regs, e2k_tir_t TIR)
{
	struct kvm_vcpu *vcpu;

	if (!kvm_test_intc_emul_flag(regs))
		return 0;

	vcpu = current_thread_info()->vcpu;

	return kvm_host_aau_page_fault(vcpu, regs, TIR);
}

static inline unsigned long
pass_stack_bounds_trap_to_guest(struct pt_regs *regs,
				bool proc_bounds, bool chain_bounds)
{
	if (!kvm_test_intc_emul_flag(regs))
		return 0;

	return kvm_pass_stack_bounds_trap_to_guest(regs, proc_bounds, chain_bounds);
}

static inline bool
pass_instr_page_fault_trap_to_guest(struct pt_regs *regs, int trap_no)
{
	if (!kvm_test_intc_emul_flag(regs))
		return false;

	return true;

}

static inline long
pass_the_trap_to_guest(struct pt_regs *regs, e2k_tir_t TIR, int trap_no)
{
	struct kvm_vcpu *vcpu;
	int ret;

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
		DebugKVMVGT("trap #%d needs not handled by guest\n", trap_no);
		return 0;
	}
	if (trap_no == exc_instr_page_miss_num) {
		tc_fault_type_t ftype;

		AW(ftype) = 0;
		ftype.page_miss = 1;
		ret = kvm_pv_mmu_instr_page_fault(vcpu, regs, ftype, 0);
		if (unlikely(ret < 0)) {
			/* page fault handling was failed */
			goto failed;
		}
		return 1;
	}
	if (trap_no == exc_instr_page_prot_num) {
		tc_fault_type_t ftype;

		AW(ftype) = 0;
		ftype.illegal_page = 1;
		ret = kvm_pv_mmu_instr_page_fault(vcpu, regs, ftype, 0);
		if (unlikely(ret < 0)) {
			/* page fault handling was failed */
			goto failed;
		}
		return 1;
	}
	if (trap_no == exc_ainstr_page_miss_num) {
		tc_fault_type_t ftype;

		ftype.page_miss = 1;
		ret = kvm_pv_mmu_instr_page_fault(vcpu, regs, ftype, 1);
		if (unlikely(ret < 0)) {
			/* page fault handling was failed */
			goto failed;
		}
		return 1;
	}
	if (trap_no == exc_ainstr_page_prot_num) {
		tc_fault_type_t ftype;

		ftype.illegal_page = 1;
		ret = kvm_pv_mmu_instr_page_fault(vcpu, regs, ftype, 1);
		if (unlikely(ret < 0)) {
			/* page fault handling was failed */
			goto failed;
		}
		return 1;
	}
	if (trap_no == exc_last_wish_num) {
		int r;

		r = intc_hret_last_wish(vcpu, regs);
		if (r == 0) {
			return 1;
		} else {
			return 0;
		}
	}
	if (trap_no == exc_instr_debug_num || trap_no == exc_data_debug_num) {
		/* debug trap on host, handle by host */
		return 0;
	}
	if (trap_no == exc_illegal_instr_addr_num) {
		/* probably system call disabled by OSEM */
		if (kvm_check_sys_call_disable(regs, TIR))
			return 1;
	}
	if (kvm_vcpu_in_hypercall(vcpu)) {
		/* the trap on host, so handles it by host */
		return 0;
	}
	if (kvm_defered_pass_the_trap_to_guest(regs, trap_no)) {
		DebugKVMVGT("trap #%d will be passed later by host handler of the trap\n",
			    trap_no);
		return 0;
	}
	return kvm_pass_the_trap_to_guest(vcpu, regs, TIR, trap_no);

failed:
	if (unlikely(ret < 0)) {
		pr_err("%s(): kill guest: fault handling failed, error %d\n",
		       __func__, ret);
		do_group_exit(ret);
	}
	return ret;
}
#else
static inline unsigned long
pass_aau_trap_to_guest(struct pt_regs *regs, e2k_tir_t TIR)
{
	return 0;
}

static inline unsigned long
pass_the_trap_to_guest(struct pt_regs *regs, e2k_tir_t TIR, int trap_no)
{
	return 0;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static inline unsigned long pass_coredump_trap_to_guest(struct pt_regs *regs)
{
	struct kvm_vcpu *vcpu;

	if (!kvm_test_intc_emul_flag(regs)) {
		kvm_pass_coredump_to_all_vm(regs);
		return 0;
	}

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
pass_interrupt_to_guest(struct pt_regs *regs, e2k_tir_t TIR, int trap_no)
{
	return 0;
}

static inline unsigned long
pass_nm_interrupt_to_guest(struct pt_regs *regs, e2k_tir_t TIR, int trap_no)
{
	return 0;
}

static inline unsigned long
pass_virqs_to_guest(struct pt_regs *regs, e2k_tir_t TIR)
{
	if (!kvm_test_intc_emul_flag(regs))
		return 0;

	if (!test_thread_flag(TIF_VIRQS_ACTIVE)) {
		/* VIRQ VCPU thread is not yet active */
		return 0;
	}
	return kvm_pass_virqs_to_guest(regs, TIR);
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
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

static inline void complete_page_fault_to_guest(unsigned long what_complete)
{
	kvm_complete_page_fault_to_guest(what_complete);
}
#else
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

static inline void complete_page_fault_to_guest(unsigned long what_complete) { }
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#endif /* ! CONFIG_KVM_GUEST_KERNEL */
#endif /* ! CONFIG_VIRTUALIZATION */

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel */
#include <asm/kvm/guest/trap_table.h>
#else /* !CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel with or without virtualization support */

#ifdef	CONFIG_VIRTUALIZATION
/* it is host kernel with virtualization support */

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static inline int
instr_page_fault(struct pt_regs *regs, tc_fault_type_t ftype, const int async_instr)
{
	struct kvm_vcpu *vcpu = current_thread_info()->vcpu;
	int ret;

	if (!kvm_test_intc_emul_flag(regs)) {
		native_instr_page_fault(regs, ftype, async_instr);
		return 0;
	}

	ret = kvm_pv_mmu_instr_page_fault(vcpu, regs, ftype, async_instr);
	if (unlikely(ret < 0)) {
		pr_err("%s(): kill guest: fault handling failed, error %d\n",
		       __func__, ret);
		do_group_exit(ret);
	}
	return ret;
}
#else
# define instr_page_fault native_do_instr_page_fault
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static inline int
do_aau_page_fault(struct pt_regs *const regs, e2k_addr_t address,
		  const tc_cond_t condition, const tc_mask_t mask,
		  const unsigned int aa_no)
{
	int ret;

	ret = kvm_host_do_aau_page_fault(regs, address, condition, mask, aa_no);
	if (unlikely(ret < 0)) {
		pr_err("%s(): kill guest: fault handling failed, error %d\n",
		       __func__, ret);
		do_group_exit(ret);
	}
	return ret;
}
#endif /* CONFIG_VIRTUALIZATION */

#endif /* CONFIG_KVM_GUEST_KERNEL */

#else /* __ASSEMBLY__ */
#include <asm/kvm/trap_table.S.h>
#endif /* ! __ASSEMBLY__ */

#endif /* __KVM_E2K_TRAP_TABLE_H */
