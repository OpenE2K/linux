/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

#include <linux/kvm_host.h>
#include <asm/cpu_regs.h>
#include <asm/trap_table.h>
#include <asm/kvm/switch.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/trace_kvm.h>

#include "../intercepts.h"
#include "../process.h"
#include "../irq.h"
#include "../mmutrace-e2k.h"
#include <asm/kvm/paravirt_sw/runstate.h>
#include "cpu_defs.h"
#include "mmu_defs.h"
#include "trace-virq.h"
#include "trace-gmm.h"

#undef	DEBUG_HOST_ACTIVATION_MODE
#undef	DebugHACT
#define	DEBUG_HOST_ACTIVATION_MODE	0	/* KVM host kernel data */
						/* stack activations */
						/* debugging */
#define	DebugHACT(fmt, args...)						\
({									\
	if (DEBUG_HOST_ACTIVATION_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_ACTIVATION_MODE
#undef	DebugKVMACT
#define	DEBUG_KVM_ACTIVATION_MODE	0	/* KVM guest kernel data stack activations */
#define	DebugKVMACT(fmt, args...)					\
({									\
	if (DEBUG_KVM_ACTIVATION_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

extern void kvm_reset_cpu_state(struct kvm_vcpu *vcpu);
extern void kvm_set_pv_vcpu_kernel_image(struct kvm_vcpu *vcpu);
extern void write_hw_ctxt_to_pv_vcpu_registers(struct kvm_vcpu *vcpu,
					const struct kvm_hw_cpu_context *hw_ctxt,
					const struct kvm_sw_cpu_context *sw_ctxt);
extern noinline __interrupt void startup_pv_vcpu(struct kvm_vcpu *vcpu,
				     guest_hw_stack_t *stack_regs,
				     unsigned flags);
extern noinline __interrupt unsigned long launch_pv_vcpu(struct kvm_vcpu *vcpu,
					     unsigned switch_flags);
extern void kvm_reset_cpu_state_idr(struct kvm_vcpu *vcpu);

/* guest kernel trap table base address: ttable0 */
extern char __kvm_pv_vcpu_ttable_entry0[];

/*
 * Only the state of the hardware virtualization bits is interesting
 */
static inline e2k_core_mode_t read_guest_CORE_MODE_reg(struct kvm_vcpu *vcpu)
{
	e2k_core_mode_t core_mode;

	AW(core_mode) = 0;

	if (vcpu->arch.is_hv) {
		/* register state is real actual */
		return read_SH_CORE_MODE_reg();
	} else if (vcpu->arch.is_pv) {
		/* register state is not actual */
		return core_mode;
	}
	return core_mode;
}

static inline void
write_guest_CORE_MODE_reg(struct kvm_vcpu *vcpu, e2k_core_mode_t new_reg)
{
	if (vcpu->arch.is_hv) {
		/* register state is real actual */
		write_SH_CORE_MODE_reg(new_reg);
	} else if (vcpu->arch.is_pv) {
		/* register state is not actual, ignore */
		;
	}
}

static inline e2k_addr_t kvm_get_pv_vcpu_ttable_base(struct kvm_vcpu *vcpu)
{
	if (likely(vcpu->arch.is_hv || vcpu->arch.is_pv)) {
		return (e2k_addr_t) vcpu->arch.trap_entry;
	} else {
		E2K_KVM_BUG_ON(true);
		return -1UL;
	}
}

static inline void
set_pv_vcpu_u_stack_context(struct kvm_vcpu *vcpu, guest_hw_stack_t *stack_regs)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	e2k_stacks_t *stacks = &stack_regs->stacks;

	sw_ctxt->sbr.base = stacks->top;
	sw_ctxt->usd = stacks->usd;
	sw_ctxt->cutd = stack_regs->cutd;
}

static inline unsigned int guest_trap_init(struct kvm *kvm)
{
	/* Enable system calls for user's processes. */
	unsigned int linux_osem = osem_calculate(false, false);

#ifdef CONFIG_KVM_HOST_KERNEL
	linux_osem |= HYPERCALLS_TRAPS_MASK;
#ifdef	CONFIG_PRIV_HYPERCALLS
	if (test_kvm_mode_flag(kvm, KVMF_PRIV_HCALL_ENABLE))
		linux_osem |= PRIV_HYPERCALLS_TRAPS_MASK;
#endif /* CONFIG_PRIV_HYPERCALLS */
#endif /* CONFIG_KVM_HOST_KERNEL */

	return linux_osem;
}

/*
 * The function emulates change of guest PSR state on trap & system call.
 * In these cases interrupts mask are disabled into PSR
 * WARNING: 'sge' flag is disabled only on trap, but for guest kernel is need
 * disable flag too to mask hardware stacks bounds traps while guest kernel
 * saving user context and enabling the trap.
 * Function return source state of PSR to enable recovery after 'done'
 */
static inline e2k_psr_t
kvm_emulate_guest_vcpu_psr_trap(struct kvm_vcpu *vcpu, bool *irqs_under_upsr)
{
	e2k_psr_t psr;
	e2k_psr_t new_psr = (e2k_psr_t) { 0 };

	psr = kvm_get_guest_vcpu_PSR(vcpu);
	*irqs_under_upsr = kvm_get_guest_vcpu_under_upsr(vcpu);
	new_psr.pm = 1;
	kvm_set_guest_vcpu_PSR(vcpu, new_psr);
	trace_kvm_set_guest_vcpu_PSR(vcpu, psr, new_psr, *irqs_under_upsr,
				     native_read_IP_reg_value(),
				     get_cr0_ip(native_read_CR0_reg()));
	return psr;
}

/*
 * The function emulates change of guest PSR state on done from trap or
 * return after system call.
 * In these cases PSR state is recovered from CR1.lo by hardware.
 * For guest VCPU registers state (copy into memory) only host can recover
 * source state, which be saved by function above or from CR1.lo
 */
static inline void
kvm_emulate_guest_vcpu_psr_done(struct kvm_vcpu *vcpu, e2k_psr_t source_psr,
				bool source_under_upsr)
{
	e2k_psr_t psr;

	psr = kvm_get_guest_vcpu_PSR(vcpu);
	kvm_set_guest_vcpu_PSR(vcpu, source_psr);
	kvm_set_guest_vcpu_under_upsr(vcpu, source_under_upsr);
	trace_kvm_set_guest_vcpu_PSR(vcpu, psr, source_psr, source_under_upsr,
				     native_read_IP_reg_value(),
				     get_cr0_ip(native_read_CR0_reg()));
}

static inline void
kvm_emulate_guest_vcpu_psr_return(struct kvm_vcpu *vcpu, e2k_mem_crs_t *crs)
{
	e2k_psr_t guest_psr;
	e2k_psr_t host_psr;

	guest_psr = kvm_get_guest_vcpu_PSR(vcpu);
	host_psr.all = crs->cr1.psr;
	E2K_KVM_BUG_ON(!psr_all_irqs_enabled_flags(host_psr.all) ||
		       all_loc_irqs_under_upsr_flags(host_psr.all));
	kvm_set_guest_vcpu_PSR(vcpu, host_psr);
	kvm_set_guest_vcpu_under_upsr(vcpu, false);
	trace_kvm_set_guest_vcpu_PSR(vcpu, guest_psr, host_psr, false,
				     native_read_IP_reg_value(),
				     get_cr0_ip(native_read_CR0_reg()));
}

extern int kvm_update_hw_stacks_frames(struct kvm_vcpu *vcpu,
				       e2k_mem_crs_t *u_pcs_frame,
				       int pcs_frame_ind,
				       kernel_mem_ps_t *u_ps_frame,
				       int ps_frame_ind, int ps_frame_size);
extern int kvm_patch_guest_data_and_chain_stacks(struct kvm_vcpu *vcpu,
						 kvm_data_stack_info_t *u_ds_patch,
						 kvm_pcs_patch_info_t pcs_patch[],
						 int pcs_frames);

#ifdef	CONFIG_KVM_HOST_KERNEL
/* It is paravirtualized host and guest kernel */
/* or native host kernel with virtualization support */
/* FIXME: kvm host and hypervisor features is not supported on guest mode */
/* and all files from arch/e2k/kvm should not be compiled for guest kernel */
/* only arch/e2k/kvm/guest/ implements guest kernel support */
/* So this ifdef should be deleted after excluding arch/e2k/kvm compilation */

extern unsigned long kvm_get_guest_local_glob_regs(struct kvm_vcpu *vcpu,
						   unsigned long *u_l_gregs[2],
						   bool is_signal);
extern unsigned long kvm_set_guest_local_glob_regs(struct kvm_vcpu *vcpu,
						   unsigned long *u_l_gregs[2],
						   bool is_signal);
extern int kvm_copy_guest_all_glob_regs(struct kvm_vcpu *vcpu,
					e2k_global_regs_t *h_gregs,
					unsigned long *g_gregs);
extern int kvm_get_all_guest_glob_regs(struct kvm_vcpu *vcpu,
				       unsigned long *g_gregs[2]);
#endif /* CONFIG_KVM_HOST_KERNEL */

static __always_inline bool pv_vcpu_trap_from_guest_kernel(pt_regs_t *regs)
{
	return regs && from_trap(regs) && call_from_guest_kernel(regs);
}

static __always_inline bool pv_vcpu_syscall_from_guest_kernel(pt_regs_t *regs)
{
	return regs && from_syscall(regs) && call_from_guest_kernel(regs);
}

static __always_inline bool
pv_vcpu_syscall_in_user_mode(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	return !pv_vcpu_syscall_from_guest_kernel(regs);
}

static __always_inline bool
pv_vcpu_trap_in_fast_syscall(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	return regs && regs->in_fast_syscall;
}

static __always_inline void
pv_vcpu_check_trap_in_fast_syscall(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	if (unlikely(vcpu->arch.sw_ctxt.in_fast_syscall)) {
		/*
		 * Trap or system call instead of unsuccessful fast system call
		 * occurs when guest fast system call is handling.
		 * Save the flag of that in the regs and clear at the sw_ctxt
		 * to enable recursive traps.
		 * The flag should be restored while trap handling completion
		 */
		regs->in_fast_syscall = true;
		vcpu->arch.sw_ctxt.in_fast_syscall = false;
	}
}

static __always_inline void
host_return_from_fast_syscall(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	/* it need restore flag of fast system call at sw_ctxt */
	/* and clear at regs */
	E2K_KVM_BUG_ON(!regs->in_fast_syscall);
	E2K_KVM_BUG_ON(vcpu->arch.sw_ctxt.in_fast_syscall);
	vcpu->arch.sw_ctxt.in_fast_syscall = true;
	regs->in_fast_syscall = false;
}

static __always_inline void
host_return_to_fast_syscall(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	/* it need keep flag of fast system call at regs */
	/* and flag should remain as cleared at regs */
	E2K_KVM_BUG_ON(!regs->in_fast_syscall);
	E2K_KVM_BUG_ON(vcpu->arch.sw_ctxt.in_fast_syscall);
}

static __always_inline bool
pv_vcpu_trap_in_user_mode(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	gthread_info_t *gti = pv_vcpu_get_gti(vcpu);

	if (likely(regs->is_guest_user)) {
		return true;
	} else {
		return !(test_gti_thread_flag(gti, GTIF_KERNEL_THREAD) ||
			 pv_vcpu_trap_on_guest_kernel(regs));
	}
}

static inline int get_pv_vcpu_traps_num(struct kvm_vcpu *vcpu)
{
	kvm_host_context_t *host_ctxt = &vcpu->arch.host_ctxt;

	return atomic_read(&host_ctxt->signal.traps_num);
}

static inline int get_pv_vcpu_pre_trap_gener(struct kvm_vcpu *vcpu)
{
	return get_pv_vcpu_traps_num(vcpu) - 1;
}

static inline int get_pv_vcpu_post_trap_gener(struct kvm_vcpu *vcpu)
{
	return get_pv_vcpu_traps_num(vcpu);
}

static inline bool is_actual_pv_vcpu_l_gregs(struct kvm_vcpu *vcpu)
{
	gthread_info_t *gti = pv_vcpu_get_gti(vcpu);
	vcpu_l_gregs_t *l_gregs = &gti->l_gregs;

	if (likely(l_gregs->valid)) {
		return true;
	}
	return false;
}

static inline vcpu_l_gregs_t *get_actual_pv_vcpu_l_gregs(struct kvm_vcpu *vcpu)
{
	gthread_info_t *gti = pv_vcpu_get_gti(vcpu);
	vcpu_l_gregs_t *l_gregs = &gti->l_gregs;

	if (!is_actual_pv_vcpu_l_gregs(vcpu)) {
		/* there is not actual gregs */
		return NULL;
	}
	return l_gregs;
}

static inline vcpu_l_gregs_t *init_pv_vcpu_l_gregs(gthread_info_t *gti)
{
	vcpu_l_gregs_t *l_gregs = &gti->l_gregs;

	/* invalidate current generation */
	l_gregs->updated = 0;
	l_gregs->valid = false;
	return l_gregs;
}

static inline void put_pv_vcpu_l_gregs(struct kvm_vcpu *vcpu)
{
	gthread_info_t *gti = pv_vcpu_get_gti(vcpu);
	vcpu_l_gregs_t *l_gregs = &gti->l_gregs;

	E2K_KVM_BUG_ON(!is_actual_pv_vcpu_l_gregs(vcpu));

	/* invalidate current generation */
	E2K_KVM_BUG_ON(l_gregs->updated != 0);
	l_gregs->valid = false;
}

static __always_inline int
kvm_switch_guest_kernel_return_ip(unsigned long new_function_ip)
{
	e2k_mem_crs_t *top_crs;
	e2k_pcsp_t pcsp;

	E2K_FLUSHC;
	pcsp = native_read_PCSP_reg();
	top_crs = (e2k_mem_crs_t *)U_PCSP_PTR(pcsp);
	if (unlikely(PCSP_IND(pcsp) < SZ_OF_CR)) {
		/* empty chain stack of guest kernel */
		return -EINVAL;
	}
	--top_crs;	/* previous frame */
	set_cr0_ip(top_crs->cr0, new_function_ip);
	return 0;
}

static __always_inline void
do_emulate_pv_vcpu_intc(thread_info_t *ti, pt_regs_t *regs,
			trap_pt_regs_t *trap)
{
	struct kvm_vcpu *vcpu = ti->vcpu;
	unsigned long mmu_pid;

	__guest_exit(ti, &vcpu->arch, DONT_AAU_CONTEXT_SWITCH | DONT_MMU_CONTEXT_SWITCH);

	kvm_set_intc_emul_flag(regs);

	kvm_init_pv_vcpu_intc_handling(vcpu, regs);

	vcpu->mode = OUTSIDE_GUEST_MODE;
	smp_wmb();		/* See the comment in kvm_vcpu_exiting_guest_mode() */

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_intercept);

	mmu_pid = current->mm->context.cpumsk[smp_processor_id()];
	trace_kvm_switch_to_host_mmu_pid(vcpu, current->mm, mmu_pid, trap_sw_to_host);
}

static notrace __always_inline void
return_from_pv_vcpu_inject(struct kvm_vcpu *vcpu)
{
	E2K_KVM_BUG_ON(!test_and_clear_ts_flag(TS_HOST_AT_VCPU_MODE));

	/* return to hypervisor context */
	__guest_exit(current_thread_info(), &vcpu->arch,
		     DONT_MMU_CONTEXT_SWITCH);

	vcpu->mode = OUTSIDE_GUEST_MODE;
	smp_wmb();		/* See the comment in kvm_vcpu_exiting_guest_mode() */
}

static __always_inline void host_return_to_guest_kernel(struct thread_info *ti)
{
	/* return to guest kernel to handle trap/system call/sigreturn */
	/* or trap was on guest kernel and return to guest kernel */
	clear_ti_status_flag(ti, TS_HOST_TO_GUEST_USER);
	/* MMU context (pid) can be keeped */
	clear_ti_status_flag(ti, TS_HOST_SWITCH_MMU_PID);
}

static __always_inline void
host_return_to_guest_user(struct thread_info *ti, bool new_context)
{
	/* return to guest user after injected trap/system call/exec new user */
	/* handling completion by guest kernel */
	set_ti_status_flag(ti, TS_HOST_TO_GUEST_USER);

	if (!new_context) {
		/* MMU context (pid) will be the same */
		/* and old contexts can be keeped */
		clear_ti_status_flag(ti, TS_HOST_SWITCH_MMU_PID);
	} else {
		/* MMU context should be switched to flush TLB */
		/* entries of guest kernel to disable access to kernel space */
		set_ti_status_flag(ti, TS_HOST_SWITCH_MMU_PID);
	}
}

static __always_inline void
do_return_from_pv_vcpu_intc(struct thread_info *ti, pt_regs_t *regs, restore_caller_t from)
{
	struct kvm_vcpu *vcpu = ti->vcpu;

	/*
	 * Ensure we set mode to IN_GUEST_MODE after we disable
	 * interrupts and before the final VCPU requests check.
	 * See the comment in kvm_vcpu_exiting_guest_mode() and
	 * Documentation/virt/kvm/vcpu-requests.rst
	 */
	smp_store_mb(vcpu->mode, IN_GUEST_MODE);

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_running);

	if (unlikely(pv_vcpu_trap_in_fast_syscall(vcpu, regs))) {
		/* it is host trap on fast system call handler of guest kernel */
		/* or return from system call caused by guest kernel */
		/* instead of unsuccessful fast system call */

		/* in any case return should be to guest kernel, which */
		/* should issue light hypercall to complete fast system call */
		host_return_to_guest_kernel(ti);
		if (from & FROM_PV_VCPU_MODE) {
			/* return to guest kernel after completion of */
			/* injected trap or system call instead of */
			/* unsuccessful fast system call */
			host_return_from_fast_syscall(vcpu, regs);
		} else if (host_return_to_injected_guest_syscall(ti, regs) ||
			   host_return_to_injected_guest_trap(ti, regs)) {
			/* return to injected trap/system call to handle its */
			/* by guest kernel handler */
			host_return_to_fast_syscall(vcpu, regs);
		} else {
			/* return to guest kernel after trap handling */
			/* completion by host itself */
			host_return_from_fast_syscall(vcpu, regs);
		}
	} else if (pv_vcpu_trap_in_user_mode(vcpu, regs)) {
		/* trap/system call was on guest user and return */
		/* to guest user to continue execution */
		if (from & FROM_PV_VCPU_MODE) {
			/* return to guest user after injected trap/system call */
			/* handling completion by guest kernel */
			/* or exec new user */
			host_return_to_guest_user(ti, true);
		} else if (host_return_to_injected_guest_syscall(ti, regs) ||
			   host_return_to_injected_guest_trap(ti, regs)) {
			/* return to injected trap/system call to handle its */
			/* by guest kernel handler */
			/* MMU context should be keeped */
			host_return_to_guest_kernel(ti);
		} else {
			/* return to guest user after trap handling completion */
			/* by host */
			/* MMU context can be keeped to do not flush TLB */
			host_return_to_guest_user(ti, false);
		}
	} else {
		host_return_to_guest_kernel(ti);
	}

	trace_host_get_gmm_root_hpa(pv_vcpu_get_gmm(vcpu), native_read_IP_reg_value());
	__guest_enter(ti, &vcpu->arch, DONT_AAU_CONTEXT_SWITCH);

	/* from now the host process is at paravirtualized guest (VCPU) mode */
	set_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE);
}

static __always_inline void
pv_mmu_switch_to_fast_sys_call(struct kvm_vcpu *vcpu, thread_info_t *ti)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;

	host_return_to_guest_kernel(ti);
	sw_ctxt->in_fast_syscall = true;

	mmu_reg_t gk_pptb = kvm_get_space_type_spt_gk_root(vcpu);
	NATIVE_SET_MMUREG_ISET(6, u_pptb, gk_pptb);
}

static __always_inline void
pv_mmu_switch_from_fast_sys_call(struct kvm_vcpu *vcpu, thread_info_t *ti)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;

	E2K_KVM_BUG_ON(!sw_ctxt->in_fast_syscall);
	host_return_to_guest_user(ti, true);
	sw_ctxt->in_fast_syscall = false;

	mmu_reg_t u_pptb = kvm_get_space_type_spt_u_root(vcpu);
	NATIVE_SET_MMUREG_ISET(6, u_pptb, u_pptb);
}

static __always_inline void
trap_handler_trampoline_finish(struct kvm_vcpu *vcpu,
		pv_vcpu_ctxt_t *vcpu_ctxt, kvm_host_context_t *host_ctxt)
{
	E2K_KVM_BUG_ON(vcpu_ctxt->inject_from != FROM_PV_VCPU_TRAP_INJECT);

	E2K_KVM_BUG_ON(atomic_read(&host_ctxt->signal.traps_num) <= 0);
	E2K_KVM_BUG_ON(atomic_read(&host_ctxt->signal.traps_num) !=
			       atomic_read(&host_ctxt->signal.in_work));
	E2K_KVM_BUG_ON(vcpu_ctxt->trap_no !=
		   atomic_read(&host_ctxt->signal.traps_num));

	/* emulate restore of guest VCPU PSR state after done */
	kvm_emulate_guest_vcpu_psr_done(vcpu, vcpu_ctxt->guest_psr, vcpu_ctxt->irq_under_upsr);

	/* decrement number of handled recursive traps */
	atomic_dec(&host_ctxt->signal.traps_num);
	atomic_dec(&host_ctxt->signal.in_work);
}

static notrace __always_inline void
syscall_handler_trampoline_start(struct kvm_vcpu *vcpu, u64 sys_rval)
{
	struct signal_stack_context __user *context;
	pv_vcpu_ctxt_t __user *vcpu_ctxt;
	kvm_host_context_t *host_ctxt = &vcpu->arch.host_ctxt;
	bool from_sigreturn;
	unsigned long ts_flag;
	int ret;

	context = get_signal_stack();
	vcpu_ctxt = &context->vcpu_ctxt;

	E2K_KVM_BUG_ON(atomic_read(&host_ctxt->signal.syscall_num) <= 0);
	E2K_KVM_BUG_ON(atomic_read(&host_ctxt->signal.syscall_num) !=
		   atomic_read(&host_ctxt->signal.in_syscall));

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __get_user(from_sigreturn, &vcpu_ctxt->from_sigreturn);
	if (ret) {
		clear_ts_flag(ts_flag);
		user_exit();
		do_exit(SIGKILL);
	}
	if (unlikely(from_sigreturn)) {
		/* system call return value has been passed by sys_sigreturn() */
		ret |= __get_user(sys_rval, &vcpu_ctxt->sys_rval);
	}
	ret |= __put_user(sys_rval, &vcpu_ctxt->sys_rval);
	clear_ts_flag(ts_flag);
	if (ret) {
		user_exit();
		do_exit(SIGKILL);
	}

	atomic_dec(&host_ctxt->signal.syscall_num);
	atomic_dec(&host_ctxt->signal.in_syscall);
}


static notrace __always_inline void
set_syscall_handler_ret_value(pt_regs_t *regs, pv_vcpu_ctxt_t *vcpu_ctxt)
{
	struct signal_stack_context __priv *prev_context;
	pv_vcpu_ctxt_t __priv *prev_vcpu_ctxt;
	long sys_rval;
	bool is_sigreturn;

	is_sigreturn = (regs->sys_num == __NR_sigreturn);
	sys_rval = vcpu_ctxt->sys_rval;

	if (likely(!is_sigreturn)) {
		regs->sys_rval = vcpu_ctxt->sys_rval;
		return;
	}

	/*
	 * This system call is sys_sigreturn() and it return value
	 * should be passed to context frame of previous system call,
	 * which has been signalled during handling
	 */
	prev_context = get_signal_stack();
	E2K_KVM_BUG_ON(prev_context == NULL);

	prev_vcpu_ctxt = &prev_context->vcpu_ctxt;

	if (unlikely(put_priv(sys_rval, &prev_vcpu_ctxt->sys_rval) ||
		     put_priv(true, &prev_vcpu_ctxt->from_sigreturn))) {
		user_exit();
		do_exit(SIGKILL);
	}

	regs->sys_rval = 0;
}

static __always_inline void
remove_skipped_signal_stack_frames(struct kvm_vcpu *vcpu, thread_info_t *ti,
				   pv_vcpu_ctxt_t *vcpu_ctxt,
				   kvm_host_context_t *host_ctxt)
{
	if (unlikely(vcpu_ctxt->skip_frames == 0))
		return;

	ti->signal_stack.used -= vcpu_ctxt->skip_frames *
	    sizeof(struct signal_stack_context);
	if (WARN_ON_ONCE((s64) ti->signal_stack.used < 0))
		ti->signal_stack.used = 0;

	E2K_KVM_BUG_ON(atomic_read(&host_ctxt->signal.traps_num) !=
		       atomic_read(&host_ctxt->signal.in_work));
	if (vcpu_ctxt->skip_traps) {
		atomic_sub(vcpu_ctxt->skip_traps, &host_ctxt->signal.traps_num);
		atomic_sub(vcpu_ctxt->skip_traps, &host_ctxt->signal.in_work);
		E2K_KVM_BUG_ON(atomic_read(&host_ctxt->signal.traps_num) < 0);
	}

	E2K_KVM_BUG_ON(atomic_read(&host_ctxt->signal.syscall_num) !=
		       atomic_read(&host_ctxt->signal.in_syscall));
	if (vcpu_ctxt->skip_syscalls) {
		atomic_sub(vcpu_ctxt->skip_syscalls,
			   &host_ctxt->signal.syscall_num);
		atomic_sub(vcpu_ctxt->skip_syscalls,
			   &host_ctxt->signal.in_syscall);
		E2K_KVM_BUG_ON(atomic_read(&host_ctxt->signal.syscall_num) < 0);
	}
}

static __always_inline void
syscall_handler_trampoline_finish(struct kvm_vcpu *vcpu, pt_regs_t *regs,
		pv_vcpu_ctxt_t *vcpu_ctxt, kvm_host_context_t *host_ctxt)
{
	E2K_KVM_BUG_ON(vcpu_ctxt->inject_from != FROM_PV_VCPU_SYSCALL_INJECT);
	E2K_KVM_BUG_ON(atomic_read(&host_ctxt->signal.syscall_num) !=
		   atomic_read(&host_ctxt->signal.in_syscall));
	if (vcpu_ctxt->skip_frames > 0) {
		/* there are a few signal frames to remove (after long jump) */
		remove_skipped_signal_stack_frames(vcpu, current_thread_info(),
						   vcpu_ctxt, host_ctxt);
	}

	/* emulate restore of guest VCPU PSR state after return from syscall */
	kvm_emulate_guest_vcpu_psr_done(vcpu, vcpu_ctxt->guest_psr,
					vcpu_ctxt->irq_under_upsr);
}

static __always_inline notrace void
syscall_fork_handler_trampoline_start(struct kvm_vcpu *vcpu)
{
	kvm_host_context_t *host_ctxt = &vcpu->arch.host_ctxt;

	E2K_KVM_BUG_ON(atomic_read(&host_ctxt->signal.syscall_num) <= 0);
	E2K_KVM_BUG_ON(atomic_read(&host_ctxt->signal.syscall_num) !=
		   atomic_read(&host_ctxt->signal.in_syscall));

	atomic_dec(&host_ctxt->signal.syscall_num);
	atomic_dec(&host_ctxt->signal.in_syscall);
}

extern unsigned long kvm_get_guest_glob_regs(struct kvm_vcpu *vcpu,
					     unsigned long *g_gregs[2],
					     unsigned long not_get_gregs_mask,
					     bool keep_bgr, unsigned int *bgr);
extern unsigned long kvm_set_guest_glob_regs(struct kvm_vcpu *vcpu,
					     unsigned long *g_gregs[2],
					     unsigned long not_set_gregs_mask,
					     bool dirty_bgr, unsigned int *bgr);

static inline void
save_pv_vcpu_sys_call_stack_regs(struct kvm_vcpu *vcpu, const pt_regs_t *regs)
{
	e2k_pcsp_t pcsp;
	e2k_pcshtp_t pcshtp;
	e2k_psp_t psp;
	e2k_pshtp_t pshtp;

	kvm_set_guest_vcpu_USD(vcpu, regs->stacks.usd);
	kvm_set_guest_vcpu_SBR(vcpu, (e2k_sbr_t) {
			       .base = regs->stacks.top});

	kvm_set_guest_vcpu_CR0(vcpu, regs->crs.cr0);
	kvm_set_guest_vcpu_CR1(vcpu, regs->crs.cr1);
	kvm_set_guest_vcpu_WD(vcpu, regs->wd);

	/* regs.PSP.ind has been increased by PSHTP value, so decrement here */
	psp = regs->stacks.psp;
	pshtp = regs->stacks.pshtp;
	E2K_KVM_BUG_ON(vcpu_psp_ind(vcpu, psp) < PSHTP_MEM_INDEX(pshtp));
	psp = vcpu_decr_psp_ind(vcpu, psp, PSHTP_MEM_INDEX(pshtp));
	kvm_set_guest_vcpu_PSP(vcpu, psp);
	kvm_set_guest_vcpu_PSHTP(vcpu, pshtp);

	/* regs.PCSP.ind has been increased by PCSHTP value, ro decrement */
	pcsp = regs->stacks.pcsp;
	pcshtp = regs->stacks.pcshtp;
	E2K_KVM_BUG_ON(vcpu_pcsp_ind(vcpu, pcsp) < pcshtp.ind);
	pcsp = vcpu_decr_pcsp_ind(vcpu, pcsp, pcshtp.ind);
	kvm_set_guest_vcpu_PCSP(vcpu, pcsp);
	kvm_set_guest_vcpu_PCSHTP(vcpu, pcshtp);

	/* set UPSR as before trap */
	kvm_set_guest_vcpu_UPSR(vcpu, current_thread_info()->upsr);
}

static inline void save_guest_sys_call_stack_regs(struct kvm_vcpu *vcpu,
						  e2k_usd_t usd, e2k_addr_t sbr)
{
	NATIVE_FLUSHCPU;
	NATIVE_FLUSHCPU;

	kvm_set_guest_vcpu_WD(vcpu, native_read_WD_reg());
	kvm_set_guest_vcpu_USD(vcpu, usd);
	kvm_set_guest_vcpu_SBR(vcpu, (e2k_sbr_t) {.base = sbr});

	kvm_set_guest_vcpu_PSHTP(vcpu, native_read_PSHTP_reg());
	kvm_set_guest_vcpu_CR0(vcpu, native_read_CR0_reg());
	kvm_set_guest_vcpu_CR1(vcpu, native_read_CR1_reg());

	E2K_WAIT_ALL;
	kvm_set_guest_vcpu_PSP(vcpu, native_read_PSP_reg());
	kvm_set_guest_vcpu_PCSP(vcpu, native_read_PCSP_reg());
}

static inline void
save_guest_sys_call_user_regs(struct kvm_vcpu *vcpu, gthread_info_t *gti)
{
	GTI_BUG_ON(!gti->u_upsr_valid);
	kvm_set_guest_vcpu_UPSR(vcpu, gti->u_upsr);
}

static inline void restore_guest_sys_call_stack_regs(thread_info_t *ti,
						     struct kvm_vcpu *vcpu,
						     e2k_usd_t usd,
						     e2k_addr_t sbr_base)
{
	unsigned long regs_status = kvm_get_guest_vcpu_regs_status(vcpu);
	bool hw_frame_updated = false;
	gthread_info_t *gti;
	gpt_regs_t *gregs;
	gpt_regs_t *prev_gregs;
	struct task_struct *task;
	e2k_pcsp_t new_pcsp;
	e2k_pcsp_t cur_pcsp;
	e2k_pcshtp_t cur_pcshtp;
	e2k_size_t new_ind;
	e2k_size_t cur_ind;
	e2k_sbr_t sbr;

	sbr.base = sbr_base;

	if (!KVM_TEST_UPDATED_CPU_REGS_FLAGS(regs_status)) {
		native_write_USBR_USD_regs(sbr, usd);
		return;
	}

	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, WD_UPDATED_CPU_REGS)) {
		e2k_wd_t wd = native_read_WD_reg();
		wd.psize = kvm_get_guest_vcpu_WD(vcpu).psize;
		native_write_WD_reg(wd);
	}
	/* FIXME: only to debug info print follow external if-statement */
	if (!(DEBUG_HOST_ACTIVATION_MODE || DEBUG_GREGS_MODE || DEBUG_GTI)) {
		if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, USD_UPDATED_CPU_REGS)) {
			native_write_USBR_USD_regs(kvm_get_guest_vcpu_SBR(vcpu),
						   kvm_get_guest_vcpu_USD(vcpu));
		} else {
			native_write_USBR_USD_regs(sbr, usd);
		}
	}
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, HS_REGS_UPDATED_CPU_REGS)) {
		cur_pcsp = native_read_PCSP_reg();
		cur_pcsp = set_pcsp_ind(cur_pcsp, 0);
		cur_pcshtp = native_read_PCSHTP_reg();
		native_strip_PCSHTP_window();
		native_strip_PSHTP_window();
		new_pcsp = kvm_get_guest_vcpu_PCSP(vcpu);
		native_write_hw_stacks(kvm_get_guest_vcpu_PSP(vcpu), new_pcsp);
		if (PCSP_BASE(cur_pcsp) != vcpu_pcsp_base(vcpu, new_pcsp) ||
		    (PCSP_IND(cur_pcsp) + cur_pcshtp.ind) != vcpu_pcsp_ind(vcpu, new_pcsp)) {
			hw_frame_updated = true;
		}
	}
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, CRS_UPDATED_CPU_REGS)) {
		native_write_cr(kvm_get_guest_vcpu_CR0(vcpu),
				kvm_get_guest_vcpu_CR1(vcpu));
	}
	kvm_reset_guest_updated_vcpu_regs_flags(vcpu, regs_status);
	if (!hw_frame_updated)
		/* FIXME: only to debug info print, change to return */
		goto debug_exit;
	/* FIXME: only to debug, should be deleted */
	E2K_SET_USER_STACK(DEBUG_HOST_ACTIVATION_MODE || DEBUG_GTI);

	/*
	 * Hardware stack frame has been updated, it can be long jump,
	 * so host needs restore own thread and stacks state, including
	 * guest kernel stacks state
	 */
	task = thread_info_task(ti);
	gti = ti->gthread_info;
	GTI_BUG_ON(gti == NULL);
	new_ind = vcpu_pcsp_ind(vcpu, new_pcsp);
	DebugHACT("new chain stack base 0x%llx index 0x%llx size 0x%llx\n",
		  vcpu_pcsp_base(vcpu, new_pcsp), vcpu_pcsp_ind(vcpu, new_pcsp),
		  vcpu_pcsp_size(vcpu, new_pcsp));
	DebugHACT("data stack state: guest #%d usd size 0x%llx, host #%d usd size 0x%llx\n",
		  gti->g_stk_frame_no, vcpu_usd_ind(vcpu, gti->stack_regs.stacks.usd),
		  gti->k_stk_frame_no, vcpu_usd_ind(vcpu, ti->k_usd));
	GTI_BUG_ON(vcpu_pcsp_base(vcpu, new_pcsp) < (u64) GET_PCS_BASE(&gti->hw_stacks) ||
		   vcpu_pcsp_ptr(vcpu, new_pcsp) >= (u64) GET_PCS_BASE(&gti->hw_stacks) +
						gti->hw_stacks.pcs.size);
	gregs = get_gpt_regs(ti);
	if (gregs == NULL) {
		/* none host activations, so nothing update */
		/* it can be direct long jump from user without any trap and */
		/* signal handler: */
		/*      user user -> syscall -> long jump + */
		/*       ^                                | */
		/*       |                                | */
		/*       +--------------------------------+ */
		GTI_BUG_ON(ti->pt_regs != NULL);
		DebugHACT("none any guest pt_regs structure, so noting update\n");
		/* FIXME: only to debug info print, change to return */
		goto debug_exit;
	}
	prev_gregs = NULL;
	do {
		DebugHACT("current activation type %d guest #%d usd size 0x%lx, host #%d usd size 0x%lx, chain stack index 0x%lx\n",
		     gregs->type, gregs->g_stk_frame_no, gregs->g_usd_size,
		     gregs->k_stk_frame_no, gregs->k_usd_size, gregs->pcsp_ind);
		DebugHACT("current thread state: pt_regs %px\n",
			  gregs->pt_regs);
		cur_ind = gregs->pcsp_ind;
		if (cur_ind < new_ind) {
			/* current activation is the nearest to jump point */
			/* and is below of this point */
			DebugHACT("the activation is the nearest and below to jump point, use prev to update\n");
			break;
		}
		prev_gregs = gregs;
		delete_gpt_regs(ti);
		gregs = get_gpt_regs(ti);
	} while (gregs);
	if (prev_gregs) {
		struct pt_regs *regs;

		/* restore state of host thread at the find point */
		DO_RESTORE_KVM_KERNEL_STACKS_STATE(ti, gti, prev_gregs);
		regs = ti->pt_regs;
		if (regs == NULL) {
			/* none host activations, so nothing update */
			/* it can be direct long jump from user into */
			/* system call from signal handler: */
			/*      user user -> syscall ->                       */
			/*                      signal handler -> long jump + */
			/*       ^                                          | */
			/*       |                                          | */
			/*       +------------------------------------------+ */
			;
		} else {
			ti->pt_regs = regs->next;
		}
	} else {
		DebugHACT("none activation the nearest and above to jump point, so do not update state\n");
	}
	DebugHACT("new data stack state: guest #%d usd size 0x%llx, host #%d usd size 0x%llx\n",
		  gti->g_stk_frame_no, vcpu_usd_ind(vcpu, gti->stack_regs.stacks.usd),
		  gti->k_stk_frame_no, USD_IND(ti->k_usd));
debug_exit:
	if ((DEBUG_HOST_ACTIVATION_MODE || DEBUG_GREGS_MODE || DEBUG_GTI)) {
		if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, USD_UPDATED_CPU_REGS)) {
			native_write_USBR_USD_regs(kvm_get_guest_vcpu_SBR(vcpu),
						   kvm_get_guest_vcpu_USD(vcpu));
		} else {
			native_write_USBR_USD_regs(sbr, usd);
		}
	}
}

static __always_inline void
kvm_pv_clear_hcall_host_stacks(struct kvm_vcpu *vcpu)
{
	vcpu->arch.hypv_backup.users = 0;
	vcpu->arch.guest_stacks.valid = false;
}

/* interrupts/traps should be disabled by caller */
static __always_inline int
kvm_pv_switch_to_hcall_host_stacks(struct kvm_vcpu *vcpu)
{
	bu_hw_stack_t *hypv_backup;
	guest_hw_stack_t *guest_stacks;
	e2k_psp_t psp;
	e2k_pcsp_t pcsp;
	int users;

	users = (++vcpu->arch.hypv_backup.users);
	if (users > 1) {
		/* already on hypercall (hypervisor) stacks */
		E2K_KVM_BUG_ON(!vcpu->arch.guest_stacks.valid);
		/* FIXME: it need check PSP/PCSP point to that stacks */
		return users;
	}
	E2K_KVM_BUG_ON(vcpu->arch.guest_stacks.valid);

	NATIVE_FLUSHCPU;

	/* These will wait for the flush so we give
	 * the flush some time to finish. */

	hypv_backup = &vcpu->arch.hypv_backup;
	guest_stacks = &vcpu->arch.guest_stacks;
	psp = hypv_backup->psp;
	pcsp = hypv_backup->pcsp;

	E2K_WAIT_MA;		/* wait for spill completion */

	guest_stacks->stacks.psp = native_read_PSP_reg();
	guest_stacks->stacks.pcsp = native_read_PCSP_reg();

	/* the follow info only to correctly dump guest stack */
	guest_stacks->crs.cr0 = native_read_CR0_reg();
	guest_stacks->crs.cr1 = native_read_CR1_reg();

	/* guest pointers are actual */
	guest_stacks->valid = true;

	E2K_WAIT_ST;		/* wait for all hardware stacks registers saving */

	native_write_hw_stacks(psp, pcsp);

	return users;
}

/* interrupts/traps should be disabled by caller */
static __always_inline int
kvm_pv_restore_hcall_guest_stacks(struct kvm_vcpu *vcpu)
{
	guest_hw_stack_t *guest_stacks;
	int users;

	E2K_KVM_BUG_ON(!vcpu->arch.guest_stacks.valid);
	users = (--vcpu->arch.hypv_backup.users);
	if (users != 0) {
		/* there are some other users of hypervisor stacks */
		/* so it need remain on that stacks */
		/* FIXME: it need check PSP/PCSP point to that stacks */
		return users;
	}

	/* host hardware stacks should be empty before return from HCALL */
	BUG_ON(native_read_PCSHTP_reg().ind != 0);
	BUG_ON(native_read_PSHTP_reg().ind != 0);

	guest_stacks = &vcpu->arch.guest_stacks;
	native_write_hw_stacks(guest_stacks->stacks.psp, guest_stacks->stacks.pcsp);

	/* pointers are not more actual */
	guest_stacks->valid = false;

	E2K_WAIT_ALL_OP;	/* wait for registers restore completion */

	return users;
}

/* interrupts/traps should be disabled by caller */
static __always_inline int
kvm_pv_put_hcall_guest_stacks(struct kvm_vcpu *vcpu, bool should_be_empty)
{
	int users;

	KVM_WARN_ON(!vcpu->arch.guest_stacks.valid);
	users = (--vcpu->arch.hypv_backup.users);
	if (users != 0) {
		/* there are some other users of hypervisor stacks */
		/* so it need remain on that stacks */
		/* FIXME: it need check PSP/PCSP point to that stacks */
		return users;
	}

	if (should_be_empty) {
		/* host hardware stacks should be empty before free stacks */
		BUG_ON(native_read_PSHTP_reg().ind != 0);
		BUG_ON(native_read_PCSHTP_reg().ind != 0);
	}

	/* pointers are not more actual */
	vcpu->arch.guest_stacks.valid = false;

	return users;
}

static __always_inline bool
kvm_pv_is_vcpu_on_hcall_host_stacks(struct kvm_vcpu *vcpu)
{
	/* hypercall is running on host stacks */
	return vcpu->arch.guest_stacks.valid &&
	    (vcpu->arch.hypv_backup.users != 0);
}

/* interrupts/traps should be disabled by caller */
static __always_inline int kvm_pv_switch_to_host_stacks(struct kvm_vcpu *vcpu)
{
	/* hypercall stacks are now used for hypervisor handlers */
	return kvm_pv_switch_to_hcall_host_stacks(vcpu);
}

/* interrupts/traps should be disabled by caller */
static __always_inline int kvm_pv_switch_to_guest_stacks(struct kvm_vcpu *vcpu)
{
	/* hypercall stacks are now used for hypervisor handlers */
	return kvm_pv_restore_hcall_guest_stacks(vcpu);
}

static __always_inline bool kvm_pv_is_vcpu_on_host_stacks(struct kvm_vcpu *vcpu)
{
	/* hypercall stacks are now used for hypervisor handlers */
	return kvm_pv_is_vcpu_on_hcall_host_stacks(vcpu);
}

static __always_inline bool kvm_inject_vcpu_exit(struct kvm_vcpu *vcpu)
{
	WARN_ON(vcpu->arch.vm_exit_wish);
	vcpu->arch.vm_exit_wish = true;
	return true;
}

static __always_inline bool kvm_is_need_inject_vcpu_exit(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.vm_exit_wish;
}

static __always_inline void
kvm_inject_guest_traps_wish(struct kvm_vcpu *vcpu, int trap_no)
{
	unsigned long trap_mask = 0;

	trap_mask |= (1UL << trap_no);
	vcpu->arch.trap_mask_wish |= trap_mask;
	vcpu->arch.trap_wish = true;
}

static __always_inline void kvm_clear_guest_traps_wish(struct kvm_vcpu *vcpu)
{
	vcpu->arch.trap_wish = false;
}

static __always_inline void
kvm_inject_guest_coredump_wish(struct kvm_vcpu *vcpu)
{
	kvm_inject_guest_traps_wish(vcpu, core_dump_num);
}

static __always_inline void kvm_clear_guest_coredump_wish(struct kvm_vcpu *vcpu)
{
	kvm_clear_guest_traps_wish(vcpu);
}

static __always_inline bool
kvm_is_need_inject_guest_traps(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.trap_wish;
}

static __always_inline bool
kvm_is_need_inject_coredump(struct kvm_vcpu *vcpu,
			    unsigned long upsr, unsigned long psr)
{
	if (likely(!kvm_test_request_to_coredump(vcpu)))
		return false;

	if (unlikely(kvm_is_need_inject_guest_traps(vcpu))) {
		/* there is/are some other traps injected to guest, */
		/* coredump trap assumes no other traps */
		return false;
	}
	if (kvm_guest_vcpu_irqs_disabled(vcpu, upsr, psr)) {
		/* guest IRQs disabled, coredump cannot be passed right now */
		return false;
	}
	kvm_inject_guest_coredump_wish(vcpu);
	return true;
}

static inline void init_pv_vcpu_intc_ctxt(struct kvm_vcpu *vcpu)
{
	vcpu->arch.from_pv_intc = false;

	vcpu->arch.on_idle = false;
	vcpu->arch.on_spinlock = false;
	vcpu->arch.on_csd_lock = false;

	vcpu->arch.virq_wish = false;
	vcpu->arch.vm_exit_wish = false;
	kvm_clear_guest_traps_wish(vcpu);
	vcpu->arch.trap_mask_wish = 0;
}

static __always_inline bool
kvm_try_inject_event_wish(struct kvm_vcpu *vcpu, struct thread_info *ti,
			  unsigned long upsr, unsigned long psr)
{
	bool need_inject = false;

	/* probably need inject VM exit to handle exit reason by QEMU */
	need_inject |= kvm_is_need_inject_vcpu_exit(vcpu);

	if (atomic_read(&vcpu->arch.host_ctxt.signal.traps_num) -
	    atomic_read(&vcpu->arch.host_ctxt.signal.in_work) > 1) {
		/* there is (are) already traps to handle by guest */
		/* FIXME: interrupts probavly can be added to guest TIRs, */
		/* if guest did not yet read its */
		goto out;
	}
	/* probably need inject some traps */
	need_inject |= kvm_is_need_inject_guest_traps(vcpu);
	/* probably need inject virtual interrupts */
	need_inject |= kvm_try_inject_direct_guest_virqs(vcpu, ti, upsr, psr);
	if (!need_inject) {
		/* probably need inject coredump trap to show VCPU state */
		need_inject |= kvm_is_need_inject_coredump(vcpu, upsr, psr);
	}

out:
	return need_inject;
}

/* See at arch/include/asm/switch.h  the 'switch_flags' argument values */
static __always_inline __interrupt unsigned long
switch_to_host_pv_vcpu_mode(thread_info_t *ti, struct kvm_vcpu *vcpu,
			    bool from_hypercall, unsigned switch_flags,
			    long ret_value)
{
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	e2k_cr0_t cr0;
	e2k_cr1_t cr1;
	e2k_psp_t psp;
	e2k_pcsp_t pcsp;
	e2k_usd_t usd;
	e2k_sbr_t sbr;
	long now_ret;

	if (from_hypercall) {
		struct mm_struct *mm;
		unsigned long mmu_pid;

		E2K_KVM_BUG_ON(!test_and_clear_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE));
		__guest_exit(ti, &vcpu->arch, switch_flags);
		/* kvm_generic_hcalls() has switch page tables already */
		uaccess_disable();
		/* return to hypervisor MMU context to emulate hw intercept */
		mm = thread_info_task(ti)->mm;
		mmu_pid = mm->context.cpumsk[smp_processor_id()];
		trace_kvm_switch_to_host_mmu_pid(vcpu, mm, mmu_pid,
						 to_qemu_sw_to_host);
	} else {
		/* switch from interception emulation mode to host vcpu mode */
		E2K_KVM_BUG_ON(test_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE));
		__guest_exit(ti, &vcpu->arch, switch_flags);
	}

	/* restore host VCPU data stack pointer registers */
	if (!from_hypercall) {
		usd = native_read_USD_reg();
		sbr = native_read_SBR_reg();
	}
	native_write_USBR_USD_regs(sw_ctxt->host_sbr, sw_ctxt->host_usd);
	if (!from_hypercall) {
		sw_ctxt->host_sbr = sbr;
		sw_ctxt->host_usd = usd;
	}

	if (from_hypercall) {
		vcpu->mode = OUTSIDE_GUEST_MODE;

		smp_wmb();	/* See the comment in kvm_vcpu_exiting_guest_mode() */
	} else {
		E2K_KVM_BUG_ON(vcpu->mode == IN_GUEST_MODE);
	}

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_intercept);

	/*
	 * Save the return value of hypercall to vcpu-guest,
	 * this value should be return by vcpu-host to vcpu-guest
	 * at launch VCPU
	 */
	now_ret = sw_ctxt->ret_value;
	sw_ctxt->ret_value = ret_value;

	cr0 = sw_ctxt->crs.cr0;
	cr1 = sw_ctxt->crs.cr1;
	psp = hw_ctxt->sh_psp;
	pcsp = hw_ctxt->sh_pcsp;

	NATIVE_FLUSHCPU;	/* spill all host hardware stacks */

	sw_ctxt->crs.cr0 = native_read_CR0_reg();
	sw_ctxt->crs.cr1 = native_read_CR1_reg();

	E2K_WAIT_MA;		/* wait for spill completion */

	hw_ctxt->sh_psp = native_read_PSP_reg();
	hw_ctxt->sh_pcsp = native_read_PCSP_reg();

	/*
	 * There might be a FILL operation still going right now.
	 * Wait for it's completion before going further - otherwise
	 * the next FILL on the new PSP/PCSP registers will race
	 * with the previous one.
	 *
	 * The first and the second FILL operations will use different
	 * addresses because we will change PSP/PCSP registers, and
	 * thus loads/stores from these two FILLs can race with each
	 * other leading to bad register file (containing values from
	 * both stacks)..
	 */
	E2K_WAIT(_ma_c);

	native_write_hw_stacks_cr(psp, pcsp, cr0, cr1);

	return now_ret;
}

/* See at arch/include/asm/switch.h  the 'switch_flags' argument values */
static __always_inline __interrupt unsigned long
return_to_intc_pv_vcpu_mode(thread_info_t *ti, struct kvm_vcpu *vcpu,
			    unsigned switch_flags)
{
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	e2k_cr0_t cr0;
	e2k_cr1_t cr1;
	e2k_psp_t psp;
	e2k_pcsp_t pcsp;
	e2k_usd_t usd;
	e2k_sbr_t sbr;

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_trap);

	/* return to interception emulation mode from host vcpu mode */
	E2K_KVM_BUG_ON(test_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE));
	__guest_enter(ti, &vcpu->arch, switch_flags);

	/* restore host VCPU data stack pointer registers */
	usd = native_read_USD_reg();
	sbr = native_read_SBR_reg();
	native_write_USBR_USD_regs(sw_ctxt->host_sbr, sw_ctxt->host_usd);
	sw_ctxt->host_sbr = sbr;
	sw_ctxt->host_usd = usd;

	cr0 = sw_ctxt->crs.cr0;
	cr1 = sw_ctxt->crs.cr1;
	psp = hw_ctxt->sh_psp;
	pcsp = hw_ctxt->sh_pcsp;

	NATIVE_FLUSHCPU;	/* spill all host hardware stacks */

	sw_ctxt->crs.cr0 = native_read_CR0_reg();
	sw_ctxt->crs.cr1 = native_read_CR1_reg();

	E2K_WAIT_MA;		/* wait for spill completion */

	hw_ctxt->sh_psp = native_read_PSP_reg();
	hw_ctxt->sh_pcsp = native_read_PCSP_reg();

	/*
	 * There might be a FILL operation still going right now.
	 * Wait for it's completion before going further - otherwise
	 * the next FILL on the new PSP/PCSP registers will race
	 * with the previous one.
	 *
	 * The first and the second FILL operations will use different
	 * addresses because we will change PSP/PCSP registers, and
	 * thus loads/stores from these two FILLs can race with each
	 * other leading to bad register file (containing values from
	 * both stacks)..
	 */
	E2K_WAIT(_ma_c);

	native_write_hw_stacks_cr(psp, pcsp, cr0, cr1);

	return 0;
}

static __always_inline __interrupt unsigned long
pv_vcpu_return_to_host(thread_info_t *ti, struct kvm_vcpu *vcpu,
		       long ret_value)
{
	return switch_to_host_pv_vcpu_mode(ti, vcpu, true /* from hypercall */ ,
					   FULL_CONTEXT_SWITCH |
					   USD_CONTEXT_SWITCH, ret_value);
}

/*
 * WARNING: do not use global registers optimization:
 *	current
 *	current_thread_info()
 *	smp_processor_id()
 *	cpu_offset... to access to per-cpu items
 */
static __always_inline __interrupt unsigned long
kvm_hcall_return_from(struct thread_info *ti,
		      e2k_upsr_t user_upsr, unsigned long psr,
		      bool restore_data_stack, e2k_size_t g_usd_size,
		      unsigned long ret)
{
	/*
	 * Now we should restore kernel saved stack state and
	 * return to guest kernel data stack, if it need
	 */
	if (ti->gthread_info != NULL &&
	    !test_gti_thread_flag(ti->gthread_info, GTIF_KERNEL_THREAD)) {
		RESTORE_KVM_GUEST_KERNEL_STACKS_STATE(ti);
		delete_gpt_regs(ti);
		DebugKVMACT("restored guest data stack activation #%d: base 0x%llx, size 0x%llx, top 0x%llx\n",
			    ti->gthread_info->g_stk_frame_no,
			    vcpu_usd_ptr(ti->vcpu, ti->gthread_info->stack_regs.stacks.usd),
			    vcpu_usd_ind(ti->vcpu, ti->gthread_info->stack_regs.stacks.usd),
			    (u64) ti->gthread_info->stack_regs.stacks.top);
		if (DEBUG_GPT_REGS_MODE)
			print_all_gpt_regs(ti);
	}
	if (restore_data_stack) {
		RETURN_TO_GUEST_KERNEL_DATA_STACK(ti, g_usd_size);
	}

	/* if there are pending VIRQs, then provide with direct interrupt */
	/* to cause guest interrupting and handling VIRQs */
	kvm_try_inject_event_wish(ti->vcpu, ti, AW(user_upsr), psr);

	/*
	 * Return control from UPSR register to PSR, if UPSR
	 * interrupts control is used.
	 * RETURN operation restores PSR state at hypercall point and
	 * recovers interrupts control
	 * Restoring of user UPSR should be after global registers restoring
	 * to preserve FP disable exception on movfi instructions
	 * while global registers manipulations
	 */
	NATIVE_RETURN_TO_USER_UPSR(AW(user_upsr));

	return ret;
}

#undef	DEBUG_CHECK_VCPU_STATE_GREG

#ifdef	DEBUG_CHECK_VCPU_STATE_GREG
static inline void kvm_check_vcpu_ids_as_light(struct kvm_vcpu *vcpu)
{
	gva_t greg_vs_gva;
	kvm_vcpu_state_t *greg_vs;

	greg_vs_gva = (gva_t)HOST_GET_SAVED_VCPU_STATE_GREG_AS_LIGHT(current_thread_info());
	greg_vs = (kvm_vcpu_state_t *) kvm_vcpu_gva_to_hva(vcpu, greg_vs_gva, false, NULL);
	if (!kvm_is_error_hva((unsigned long)greg_vs)) {
		int greg_vs_id, ret;

		ret = __get_user(greg_vs_id, &greg_vs->cpu.regs.CPU_VCPU_ID);
		E2K_KVM_BUG_ON(!ret && greg_vs_id != vcpu->vcpu_id);
	}
}

static inline void kvm_check_vcpu_state_greg(void)
{
	struct kvm_vcpu *vcpu = current_thread_info()->vcpu;
	unsigned long vs;
	kvm_vcpu_state_t *greg_vs, *vcpu_vs;

	BUG_ON(vcpu == NULL);
	if (!vcpu->arch.is_hv) {
		vs = HOST_GET_SAVED_VCPU_STATE_GREG(current_thread_info());
		greg_vs = (kvm_vcpu_state_t *) vs;
		vcpu_vs = (kvm_vcpu_state_t *) GET_GUEST_VCPU_STATE_POINTER(vcpu);
		if (greg_vs != vcpu_vs) {
			pr_err("%s(): vcpu state pointer on greg %px != vcpu #%d state pointer %px\n",
				__func__, greg_vs, vcpu->vcpu_id, vcpu_vs);
			HOST_ONLY_COPY_TO_VCPU_STATE_GREG(&current_thread_info
							  ()->k_gregs,
							  (u64) vcpu_vs);
			greg_vs = vcpu_vs;
		}
		E2K_KVM_BUG_ON(greg_vs != vcpu_vs);
	}
}

static inline bool
kvm_is_guest_migrated_to_other_vcpu(thread_info_t *ti, struct kvm_vcpu *vcpu)
{
	unsigned long vs;
	kvm_vcpu_state_t *greg_vs, *vcpu_vs;

	vs = HOST_GET_SAVED_VCPU_STATE_GREG(ti);
	greg_vs = (kvm_vcpu_state_t *) vs;
	vcpu_vs = (kvm_vcpu_state_t *) GET_GUEST_VCPU_STATE_POINTER(vcpu);
	return greg_vs != vcpu_vs;
}
#else /* !DEBUG_CHECK_VCPU_STATE_GREG */
static inline void kvm_check_vcpu_ids_as_light(struct kvm_vcpu *vcpu)
{
}

static inline void kvm_check_vcpu_state_greg(void)
{
}

static inline bool
kvm_is_guest_migrated_to_other_vcpu(thread_info_t *ti, struct kvm_vcpu *vcpu)
{
	return false;
}
#endif /* DEBUG_CHECK_VCPU_STATE_GREG */

/*
 * Guest trap handling support
 */
static inline void
save_guest_trap_aau_regs(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	trap_pt_regs_t *trap;
	e2k_aau_t *aau;
	e2k_aasr_t aasr;
	bool aau_fault = false;
	int i;

	trap = pt_regs_to_trap_regs(regs);
	regs->trap = trap;
	aau = regs->aau_context;
	aasr = regs->aasr;
	kvm_set_guest_vcpu_aasr(vcpu, aasr);
	kvm_set_guest_vcpu_aaldm(vcpu, (aau) ? aau->aaldm : (e2k_aaldm_t) {.word = 0});
	kvm_set_guest_vcpu_aaldv(vcpu, (aau) ? aau->aaldv : (e2k_aaldv_t) {.word = 0});
	if (aasr.iab)
		kvm_copy_to_guest_vcpu_aads(vcpu, aau->aads);
	for (i = 0; i <= trap->nr_TIRs; i++) {
		if (trap->TIRs[i].aa) {
			aau_fault = true;
			break;
		}
	}

	if (unlikely(aau_fault)) {
		kvm_set_guest_vcpu_aafstr_value(vcpu, aau->aafstr);
	}

	if (aasr.iab) {
		/* get descriptors & auxiliary registers */
		kvm_copy_to_guest_vcpu_aainds(vcpu, aau->aainds);
		kvm_set_guest_vcpu_aaind_tags_value(vcpu, aau->aaind_tags);
		kvm_copy_to_guest_vcpu_aaincrs(vcpu, aau->aaincrs);
		kvm_set_guest_vcpu_aaincr_tags_value(vcpu, aau->aaincr_tags);
	}

	if (aasr.stb) {
		/* get synchronous part of APB */
		kvm_copy_to_guest_vcpu_aastis(vcpu, aau->aastis);
		kvm_set_guest_vcpu_aasti_tags_value(vcpu, aau->aasti_tags);
	}
}

static inline void
save_guest_trap_cpu_regs(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	/* stacks registers */
	kvm_set_guest_vcpu_WD(vcpu, regs->wd);
	kvm_set_guest_vcpu_USD(vcpu, regs->stacks.usd);
	kvm_set_guest_vcpu_SBR(vcpu, TOS(e2k_sbr_t, regs->stacks.top));
	DebugKVMVGT("regs USD: base 0x%llx size 0x%llx top 0x%llx\n",
		    vcpu_usd_ptr(vcpu, regs->stacks.usd),
		    vcpu_usd_ind(vcpu, regs->stacks.usd),
		    (u64) regs->stacks.top);

	kvm_set_guest_vcpu_CR0(vcpu, regs->crs.cr0);
	kvm_set_guest_vcpu_CR1(vcpu, regs->crs.cr1);

	kvm_set_guest_vcpu_PSHTP(vcpu, regs->stacks.pshtp);
	kvm_set_guest_vcpu_PSP(vcpu, regs->stacks.psp);
	DebugKVMVGT("regs  PSP:  base 0x%llx size 0x%llx ind 0x%llx\n",
		    vcpu_psp_base(vcpu, regs->stacks.psp),
		    vcpu_psp_size(vcpu, regs->stacks.psp),
		    vcpu_psp_ind(vcpu, regs->stacks.psp));
	kvm_set_guest_vcpu_PCSHTP(vcpu, regs->stacks.pcshtp);
	kvm_set_guest_vcpu_PCSP(vcpu, regs->stacks.pcsp);
	DebugKVMVGT("regs  PCSP:  base 0x%llx size 0x%llx ind 0x%llx\n",
		    vcpu_pcsp_base(vcpu, regs->stacks.pcsp),
		    vcpu_pcsp_size(vcpu, regs->stacks.pcsp),
		    vcpu_pcsp_ind(vcpu, regs->stacks.pcsp));

	/* Control transfer registers */
	kvm_set_guest_vcpu_CTPR1(vcpu, regs->ctpr1);
	kvm_set_guest_vcpu_CTPR2(vcpu, regs->ctpr2);
	kvm_set_guest_vcpu_CTPR3(vcpu, regs->ctpr3);
	/* Cycles control registers */
	kvm_set_guest_vcpu_LSR(vcpu, regs->lsr);
	kvm_set_guest_vcpu_LSR1(vcpu, regs->lsr1);
	kvm_set_guest_vcpu_ILCR(vcpu, regs->ilcr);
	kvm_set_guest_vcpu_ILCR1(vcpu, regs->ilcr1);
	/* set UPSR as before trap */
	kvm_set_guest_vcpu_UPSR(vcpu, current_thread_info()->upsr);
}

static inline void
save_guest_trap_regs(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	save_guest_trap_aau_regs(vcpu, regs);
	save_guest_trap_cpu_regs(vcpu, regs);
}

static inline bool check_is_guest_TIRs_frozen(pt_regs_t *regs, bool to_update)
{
	struct kvm_vcpu *vcpu = current_thread_info()->vcpu;
	bool TIRs_empty = kvm_check_is_guest_TIRs_empty(vcpu);

	if (TIRs_empty)
		return false;
	if (regs->traps_to_guest == 0) {
		/* probably it is recursive traps on host and can be */
		/* handled only by host */
		if (count_trap_regs(regs) <= 1) {
			/* it is not recursive trap */
			return true;
		}
		/* it is recursive trap and previous guest traps is not yet */
		/* saved, so it can be only host traps; check enable, */
		/* update diasble */
		return to_update;
	}
	/* TIRs are not empty and there ara unhandled guest traps, */
	/* so it can be new guest trap */
	return false;
}

static inline void
kvm_set_pv_vcpu_trap_context(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	E2K_KVM_BUG_ON(check_is_guest_TIRs_frozen(regs, false));

	if (kvm_get_guest_vcpu_TIRs_num(vcpu) < 0) {
		E2K_KVM_BUG_ON(kvm_check_is_vcpu_guest_stacks_empty
			       (vcpu, regs));
	}

	if (DEBUG_KVM_VERBOSE_GUEST_TRAPS_MODE)
		print_pt_regs(regs);

	E2K_KVM_BUG_ON(test_ts_flag(TS_HOST_AT_VCPU_MODE));

	E2K_KVM_BUG_ON(kvm_get_guest_vcpu_runstate(vcpu) != RUNSTATE_in_trap &&
		   kvm_get_guest_vcpu_runstate(vcpu) != RUNSTATE_in_intercept);

	save_guest_trap_regs(vcpu, regs);
}

static inline void
kvm_set_pv_vcpu_SBBP_TIRs(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	int TIRs_num, TIR_no;
	e2k_tir_t TIR;
	unsigned long mask = 0;

	TIRs_num = kvm_get_vcpu_intc_TIRs_num(vcpu);
	kvm_reset_guest_vcpu_TIRs_num(vcpu);

	for (TIR_no = 0; TIR_no <= TIRs_num; TIR_no++) {
		TIR = kvm_get_vcpu_intc_TIR(vcpu, TIR_no);
		mask |= kvm_update_guest_vcpu_TIR(vcpu, TIR_no, TIR);
	}
	regs->traps_to_guest |= mask;
	kvm_clear_vcpu_intc_TIRs_num(vcpu);

	kvm_copy_guest_vcpu_SBBP(vcpu, regs->trap->sbbp);
}

static inline void kvm_inject_pv_vcpu_tc_entry(struct kvm_vcpu *vcpu,
					       trap_cellar_t *tc_from)
{
	void *tc_kaddr = vcpu->arch.mmu.tc_kaddr;
	kernel_trap_cellar_t *tc;
	kernel_trap_cellar_ext_t *tc_ext;
	tc_opcode_t opcode;
	int cnt, fmt;

	cnt = vcpu->arch.mmu.tc_num;
	tc = tc_kaddr;
	tc_ext = tc_kaddr + TC_EXT_OFFSET;
	tc += cnt;
	tc_ext += cnt;

	tc->address = tc_from->address;
	tc->condition = tc_from->condition;
	AW(opcode) = tc_from->condition.opcode;
	fmt = opcode.fmt;
	if (fmt == LDST_QP_FMT) {
		tc_ext->mask = tc_from->mask;
	}
	if (tc_from->condition.store) {
		NATIVE_MOVE_TAGGED_DWORD(&tc_from->data, &tc->data);
		if (fmt == LDST_QP_FMT) {
			NATIVE_MOVE_TAGGED_DWORD(&tc_from->data_ext, &tc_ext->data);
		}
	}
	cnt++;
	vcpu->arch.mmu.tc_num = cnt;

	/* MMU TRAP_COUNT cannot be set, so write flag of end of records */
	tc++;
	AW(tc->condition) = -1;
}

static inline bool
check_injected_stores_to_addr(struct kvm_vcpu *vcpu, gva_t addr, int size)
{
	void *tc_kaddr = vcpu->arch.mmu.tc_kaddr;
	kernel_trap_cellar_t *tc;
	tc_cond_t tc_cond;
	e2k_addr_t tc_addr, tc_end;
	bool tc_store;
	int tc_size;
	gva_t start, end;
	int cnt, num;

	start = addr & PAGE_MASK;
	end = (addr + (size - 1)) & PAGE_MASK;
	tc = tc_kaddr;
	num = vcpu->arch.mmu.tc_num;
	for (cnt = 0; cnt < num; cnt++) {
		tc_cond = tc->condition;
		tc_store = tc_cond_is_store(tc_cond);
		if (!tc_store)
			continue;

		tc_size = tc_cond_to_size(tc_cond);
		tc_addr = tc->address;
		tc_end = (tc_addr + (tc_size - 1)) & PAGE_MASK;
		tc_addr &= PAGE_MASK;
		if (tc_addr == start || tc_addr == end ||
		    tc_end == start || tc_end == end)
			return true;
	}
	return false;
}

static inline void kvm_set_pv_vcpu_trap_cellar(struct kvm_vcpu *vcpu)
{
	kvm_write_pv_vcpu_mmu_TRAP_COUNT_reg(vcpu, vcpu->arch.mmu.tc_num * 3);
}

static inline void
kvm_init_pv_vcpu_trap_handling(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	/* clear guest trap TIRs & trap cellar */
	kvm_reset_guest_vcpu_TIRs_num(vcpu);
	if (regs) {
		regs->traps_to_guest = 0;
	}
	kvm_clear_vcpu_trap_cellar(vcpu);
}

extern void kvm_dump_shadow_u_pptb(struct kvm_vcpu *vcpu, const char *title);