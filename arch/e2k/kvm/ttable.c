/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Guest user traps and system calls support on host
 */

#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/tty.h>
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <asm/process.h>
#include <asm/traps.h>
#include <asm/e2k_debug.h>
#include <asm/mmu_context.h>
#include <asm/kvm/switch.h>
#include <asm/kvm/runstate.h>

#include "process.h"
#include "cpu.h"
#include "gaccess.h"
#include "mman.h"
#include "string.h"
#include "irq.h"
#include "time.h"
#include "lapic.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PV_UST_MODE
#undef	DebugUST
#define	DEBUG_PV_UST_MODE	0	/* trap injection debugging */
#define	DebugUST(fmt, args...)						\
({									\
	if (debug_guest_ust)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PV_SYSCALL_MODE
#define	DEBUG_PV_SYSCALL_MODE	0	/* syscall injection debugging */

#if	DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE
extern bool debug_guest_ust;
#else
#define	debug_guest_ust	false
#endif	/* DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE */

#undef	DEBUG_KVM_GUEST_TRAPS_MODE
#undef	DebugKVMGT
#define	DEBUG_KVM_GUEST_TRAPS_MODE	0	/* KVM guest trap debugging */
#define	DebugKVMGT(fmt, args...)					\
({									\
	if (DEBUG_KVM_GUEST_TRAPS_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_AAU_TRAPS_MODE
#undef	DebugAAUGT
#define	DEBUG_KVM_AAU_TRAPS_MODE	0	/* KVM guest trap debugging */
#define	DebugAAUGT(fmt, args...)					\
({									\
	if (DEBUG_KVM_AAU_TRAPS_MODE)					\
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

#undef	DEBUG_KVM_SGE_MODE
#undef	DebugKVMSGE
#define	DEBUG_KVM_SGE_MODE	0	/* KVM guest 'sge' flag debugging */
#define	DebugKVMSGE(fmt, args...)					\
({									\
	if (DEBUG_KVM_SGE_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_HW_STACK_BOUNDS_MODE
#undef	DebugHWSB
#define	DEBUG_KVM_HW_STACK_BOUNDS_MODE	0	/* guest hardware stacks */
						/* bounds trap debugging */
#define	DebugHWSB(fmt, args...)						\
({									\
	if (DEBUG_KVM_HW_STACK_BOUNDS_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PARAVIRT_FAULT
#undef	DebugPVF
#define	DEBUG_PARAVIRT_FAULT	0	/* KVM paravirt fault */
#define	DebugPVF(fmt, args...)						\
({									\
	if (DEBUG_PARAVIRT_FAULT)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#define	DEBUG_ACT		0
#define	DEBUG_ACTIVATION_MODE	0

#undef	DEBUG_KVM_ACTIVATION_MODE
#undef	DebugKVMACT
#define	DEBUG_KVM_ACTIVATION_MODE	0	/* KVM guest kernel data */
						/* stack activations */
						/* debugging */
#define	DebugKVMACT(fmt, args...)					\
({									\
	if (DEBUG_KVM_ACTIVATION_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SWITCH_VCPU_MODE
#undef	DebugSWVCPU
#define	DEBUG_KVM_SWITCH_VCPU_MODE	false	/* guest thread switch to */
						/* other VCPU */
#define	DebugSWVCPU(fmt, args...)					\
({									\
	if (DEBUG_KVM_SWITCH_VCPU_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_VIRQs_MODE
#undef	DebugVIRQs
#define	DEBUG_KVM_VIRQs_MODE	0	/* VIRQs debugging */
#define	DebugVIRQs(fmt, args...)					\
({									\
	if (DEBUG_KVM_VIRQs_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_COREDUMP_MODE
#undef	DebugCDUMP
#define	DEBUG_KVM_COREDUMP_MODE	1	/* coredump VCPUs state debugging */
#define	DebugCDUMP(fmt, args...)					\
({									\
	if (DEBUG_KVM_COREDUMP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

/* FIXME: the follow define only to debug, delete after completion and */
/* turn on __interrupt atribute */
#undef	DEBUG_GTI
#define	DEBUG_GTI	1

#undef	DEBUG_GPT_REGS_MODE
#define	DEBUG_GPT_REGS_MODE	DEBUG_ACT	/* KVM host and guest kernel */
					/* stack activations print */

#define	CHECK_GUEST_VCPU_UPDATES

#include "trace-virq.h"

bool kvm_is_guest_TIRs_frozen(pt_regs_t *regs)
{
	if (check_is_guest_TIRs_frozen(regs, false)) {
		/* guest TIRs should be unfrozen, but new traps can be */
		/* recieved by host and only for host */
		/* (for example interrupts) */
		pr_err("%s(): guest TIRs is now frozen\n", __func__);
		dump_stack();
		pr_err("%s(): Trap in trap and may be recursion, "
			"so kill the VCPU and VM\n",
			__func__);
		do_exit(-EDEADLK);
	}
	return false;
}

/*
 * Following functions run on host, check if traps occurred on guest user
 * or kernel, so probably should be passed to guest kernel to handle.
 * In some cases traps should be passed to guest, but need be preliminary
 * handled by host (for example hardware stack bounds).
 * Functions return flag or mask of traps which passed to guest and
 * should not be handled by host
 */
#ifdef CONFIG_USE_AAU
unsigned long kvm_host_aau_page_fault(struct kvm_vcpu *vcpu, pt_regs_t *regs,
			unsigned long TIR_hi, unsigned long TIR_lo)
{
	unsigned int aa_mask;

	aa_mask = GET_AA_TIRS(TIR_hi);
	E2K_KVM_BUG_ON(aa_mask == 0);

	machine.do_aau_fault(aa_mask, regs);

	return SET_AA_TIRS(0UL, GET_AA_TIRS(TIR_hi));
}
#endif
unsigned long kvm_pass_the_trap_to_guest(struct kvm_vcpu *vcpu, pt_regs_t *regs,
			unsigned long TIR_hi, unsigned long TIR_lo, int trap_no)
{
	e2k_tir_lo_t tir_lo;
	e2k_tir_hi_t tir_hi;
	int tir_no;
	unsigned long trap_mask;

	DebugKVMVGT("trap #%d TIRs hi 0x%016lx lo 0x%016lx\n",
		trap_no, TIR_hi, TIR_lo);

	BUG_ON(trap_no > exc_max_num);
	trap_mask = (1UL << trap_no);
	BUG_ON(trap_mask == 0);

	if (trap_no == exc_illegal_opcode_num) {
		/* Trap on guest kernel, so it probably can be because of */
		/* break point on debugger */
		if (is_gdb_breakpoint_trap(regs)) {
			/* It is debugger trap, so pass to host */
			return 0;
		}
	}

	tir_lo.TIR_lo_reg = TIR_lo;
	tir_hi.TIR_hi_reg = TIR_hi;
	tir_hi.TIR_hi_aa = 0;	/* clear AAU traps mask */
	tir_hi.TIR_hi_exc = trap_mask;
	tir_no = tir_hi.TIR_hi_j;
	if (tir_lo.TIR_lo_ip == 0) {
		tir_lo.TIR_lo_ip = regs->crs.cr0_hi.CR0_hi_IP;
	}
	kvm_update_vcpu_intc_TIR(vcpu, tir_no, tir_hi, tir_lo);
	regs->traps_to_guest |= trap_mask;
	DebugKVMVGT("trap is set to guest TIRs #%d\n", tir_no);
	return trap_mask;
}
static inline unsigned long
pass_virqs_to_guest_TIRs(struct pt_regs *regs,
		unsigned long TIR_hi, unsigned long TIR_lo)
{
	struct kvm_vcpu *vcpu;
	e2k_tir_hi_t tir_hi;
	e2k_tir_hi_t g_TIR_hi;
	e2k_tir_lo_t g_TIR_lo;
	int TIR_no;

	BUG_ON(check_is_guest_TIRs_frozen(regs, true));
	vcpu = current_thread_info()->vcpu;

	if (TIR_hi == 0) {
		TIR_no = 0;
	} else {
		tir_hi.TIR_hi_reg = TIR_hi;
		TIR_no = tir_hi.TIR_hi_j;
	}
	g_TIR_lo.TIR_lo_reg = TIR_lo;
	g_TIR_hi.TIR_hi_reg = GET_CLEAR_TIR_HI(TIR_no);
	g_TIR_hi.TIR_hi_exc = exc_interrupt_mask;
	kvm_update_guest_vcpu_TIR(vcpu, TIR_no, g_TIR_hi, g_TIR_lo);
	regs->traps_to_guest |= exc_interrupt_mask;
	DebugKVMVGT("interrupt is set to guest TIRs #%d hi 0x%016llx "
		"lo 0x%016llx\n",
		TIR_no, g_TIR_hi.TIR_hi_reg, g_TIR_lo.TIR_lo_reg);
	return exc_interrupt_mask;
}

static bool lapic_state_printed = false;

unsigned long kvm_pass_virqs_to_guest(struct pt_regs *regs,
			unsigned long TIR_hi, unsigned long TIR_lo)
{
	struct kvm_vcpu *vcpu;
	unsigned long ret;

	vcpu = current_thread_info()->vcpu;
	BUG_ON(vcpu == NULL);

	if (DEBUG_KVM_VIRQs_MODE && !lapic_state_printed) {
		lapic_state_printed = true;
		kvm_print_local_APIC(vcpu);
	} else if (!DEBUG_KVM_VIRQs_MODE && lapic_state_printed) {
		lapic_state_printed = false;
	}
	BUG_ON(!irqs_disabled());

	if (guest_trap_user_mode(regs) && !kvm_get_guest_vcpu_sge(vcpu)) {
		pr_debug("%s(): sge disabled on guest user\n", __func__);
	}

	raw_spin_lock(&vcpu->kvm->arch.virq_lock);

	if (unlikely(trap_from_host_kernel_mode(regs))) {
		/* trap on host mode, for example at the beginning of */
		/* hypercall on spill hardware stacks */
		goto out_unlock;
	}
	if (!kvm_has_virqs_to_guest(vcpu)) {
		/* nothing pending VIRQs to pass to guest */
		trace_kvm_pass_virqs_to_guest(vcpu, no_pending_pass_virq);
		goto out_unlock;
	}
	if (atomic_read(&vcpu->arch.host_ctxt.signal.traps_num) -
			atomic_read(&vcpu->arch.host_ctxt.signal.in_work) > 1) {
		/* VCPU is now at trap handling, probably VIRQs will */
		/* handled too, if not, pending VIRQs will be passed later */
		trace_kvm_pass_virqs_to_guest(vcpu, vcpu_in_trap_pass_virq);
		goto some_later;
	}
	if (kvm_guest_vcpu_irqs_disabled(vcpu,
			kvm_get_guest_vcpu_UPSR_value(vcpu),
			kvm_get_guest_vcpu_PSR_value(vcpu))) {
		/* guest IRQs is now disabled, so it cannot pass interrupts */
		/* right now, so pending VIRQs flag is not cleared to pass */
		/* them to other appropriate case */
		DebugVIRQs("IRQs is disabled on guest kernel thread, "
			"could not pass\n");
		trace_kvm_pass_virqs_to_guest(vcpu, irqs_disabled_pass_virq);
		trace_kvm_irq_disabled_on_guest(vcpu, regs->crs.cr0_hi.CR0_hi_IP,
			kvm_get_guest_vcpu_UPSR_value(vcpu),
			kvm_get_guest_vcpu_PSR_value(vcpu));
		goto some_later;
	}

	BUG_ON(!kvm_test_pending_virqs(vcpu));

	if (kvm_test_virqs_injected(vcpu)) {
		E2K_KVM_BUG_ON(vcpu->arch.virq_wish);
		trace_kvm_pass_virqs_to_guest(vcpu, already_injected_pass_virq);
		goto already_injected;
	}

	raw_spin_unlock(&vcpu->kvm->arch.virq_lock);

	DebugVIRQs("pass interrupt to guest\n");
	kvm_inject_interrupt(vcpu, regs);

	/* set flag to disable re-injection of the same pending VIRQs */
	/* through the last with or direct injection of interrupt */
	kvm_set_virqs_injected(vcpu);
	if (vcpu->arch.virq_wish) {
		/* it is request from host to inject last wish */
		/* on return from hypercall to cause preliminary */
		/* trap on guest and then inject interrupt for guest. */
		/* Convert last wish to interrupt and clear last wish flag */
		vcpu->arch.virq_wish = false;
	}
	trace_kvm_pass_virqs_to_guest(vcpu, injected_pass_virq);

	ret = exc_interrupt_mask;

	return ret;

some_later:
	if (vcpu->arch.virq_wish) {
		/* interrupt cannot be passed right now, so clear wish flag */
		vcpu->arch.virq_wish = false;
	}
already_injected:
out_unlock:
	raw_spin_unlock(&vcpu->kvm->arch.virq_lock);
	return 0;
}

static bool kvm_coredump_in_progress = false;
static atomic_t kvm_coredump_in_progress_num = ATOMIC_INIT(0);

static void kvm_complete_request_to_coredump(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int in_coredump = 0;
	int i;

	mutex_lock(&kvm->lock);
	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (kvm_test_request_to_coredump(vcpu)) {
			in_coredump++;
		}
	}
	mutex_unlock(&kvm->lock);
	if (in_coredump <= 0) {
		if (atomic_dec_return(&kvm_coredump_in_progress_num) <= 0) {
			kvm_coredump_in_progress = false;
		}
	}
}

unsigned long kvm_pass_coredump_trap_to_guest(struct kvm_vcpu *vcpu,
							struct pt_regs *regs)
{
	e2k_tir_hi_t tir_hi;
	e2k_tir_lo_t tir_lo;
	int tir_no;

	if (regs->traps_to_guest != 0 && !is_injected_guest_coredump(regs) ||
			!kvm_check_is_guest_TIRs_empty(vcpu) ||
				kvm_guest_vcpu_irqs_disabled(vcpu,
					kvm_get_guest_vcpu_UPSR_value(vcpu),
					kvm_get_guest_vcpu_PSR_value(vcpu))) {
		if (regs->traps_to_guest != 0 &&
					!is_injected_guest_coredump(regs)) {
			pr_err("%s(): there is other trap(s) passed to "
				"guest 0x%016lx\n",
				__func__, regs->traps_to_guest);
		}
		if (!kvm_check_is_guest_TIRs_empty(vcpu)) {
			pr_err("%s(): guest TIRs is not empty, handling in progress "
				"TIR[0].hi : 0x%016llx\n",
				__func__,
				kvm_get_guest_vcpu_TIR_hi(vcpu, 0).TIR_hi_reg);
		}
		if (kvm_guest_vcpu_irqs_disabled(vcpu,
					kvm_get_guest_vcpu_UPSR_value(vcpu),
					kvm_get_guest_vcpu_PSR_value(vcpu))) {
			pr_err("%s(): guest IRQs disabled, coredump cannot "
				"be passed right now, PSR 0x%x UPSR 0x%x\n",
				__func__,
				kvm_get_guest_vcpu_PSR_value(vcpu),
				kvm_get_guest_vcpu_UPSR_value(vcpu));
		}
		if (unlikely(kvm_test_request_to_coredump(vcpu))) {
			pr_err("%s(): coredump request has been already suspended\n",
				__func__);
		} else {
			kvm_set_request_to_coredump(vcpu);
		}
		/* coredump trap cannot be passed, but was suspended */
		/* to inject some later */
		return 0;
	}
	/* empty TIRs is signal to do coredump */
	tir_lo.TIR_lo_reg = GET_CLEAR_TIR_LO(0);
	tir_hi.TIR_hi_reg = GET_CLEAR_TIR_HI(0);
	tir_no = 0;
	kvm_update_vcpu_intc_TIR(vcpu, tir_no, tir_hi, tir_lo);
	regs->traps_to_guest |= core_dump_mask;
	kvm_clear_request_to_coredump(vcpu);
	DebugKVMVGT("trap is set to guest TIRs #0 hi 0x%016llx lo 0x%016llx\n",
		tir_hi.TIR_hi_reg, tir_lo.TIR_lo_reg);
	kvm_complete_request_to_coredump(vcpu->kvm);
	return core_dump_mask;
}

void kvm_pass_coredump_to_all_vm(struct pt_regs *regs)
{
	struct kvm *kvm;

	mutex_lock(&kvm_lock);
	if (likely(list_empty(&vm_list))) {
		DebugCDUMP("nothing VM detected\n");
		goto out;
	}
	if (kvm_coredump_in_progress) {
		DebugCDUMP("CPU #%d coredump is already in progress\n",
			smp_processor_id());
		goto out;
	}
	kvm_coredump_in_progress = true;
	list_for_each_entry(kvm, &vm_list, vm_list) {
		DebugCDUMP("CPU #%d started for VM #%d\n",
			smp_processor_id(), kvm->arch.vmid.nr);
		kvm_make_all_cpus_request(kvm, KVM_REQ_TO_COREDUMP);
		atomic_inc(&kvm_coredump_in_progress_num);
	}

out:
	mutex_unlock(&kvm_lock);
}

/*
 * CLW requests should be handled by host, but address to clear can be
 * from guest user data stack range, so preliminary this page fault should
 * be passed to guest kernel to handle page miss.
 * CLW requests are executed before other faulted requests, so this page miss
 * fault should be passed and handled by guest.
 * Function returns non zero value if CLW request is from guest, guest kernel
 * successfully it completed and host can terminate CLW and continue handle
 * other trap cellar requests
 */
unsigned long kvm_pass_clw_fault_to_guest(struct pt_regs *regs,
			trap_cellar_t *tcellar)
{
	trap_pt_regs_t	*trap = regs->trap;
	e2k_addr_t address;
	tc_cond_t cond;
	tc_cond_t g_cond;
	struct kvm_vcpu *vcpu;
	e2k_tir_hi_t g_TIR_hi;
	e2k_tir_lo_t g_TIR_lo;
	int TIR_no;
	int tc_no;
	bool handled;

	address = tcellar->address;
	cond = tcellar->condition;
	BUG_ON(!guest_user_addr_mode_page_fault(regs,
						false /* instr page */,
						address));
	DebugKVMVGT("trap occurred on guest user: address 0x%lx "
		"condition 0x%016llx\n",
		address, AW(cond));

	BUG_ON(check_is_guest_TIRs_frozen(regs, true));
	TIR_no = trap->TIR_no;
	g_TIR_lo.TIR_lo_reg = trap->TIR_lo;
	g_TIR_hi.TIR_hi_reg = trap->TIR_hi;
	WARN_ON(TIR_no != g_TIR_hi.TIR_hi_j);
	g_TIR_hi.TIR_hi_aa = 0;
	g_TIR_hi.TIR_hi_exc = exc_data_page_mask;
	WARN_ON((1UL << trap->nr_trap) != exc_data_page_mask);

	/* set guest VCPU TIR registers state to simulate data page trap */
	vcpu = current_thread_info()->vcpu;
	BUG_ON(vcpu == NULL);
	kvm_update_guest_vcpu_TIR(vcpu, TIR_no, g_TIR_hi, g_TIR_lo);
	regs->traps_to_guest |= exc_data_page_mask;
	DebugKVMVGT("trap is set to guest TIRs #%d hi 0x%016llx lo 0x%016llx\n",
		TIR_no, g_TIR_hi.TIR_hi_reg, g_TIR_lo.TIR_lo_reg);

	/* add new trap cellar entry for guest VCPU */
	/* to simulate CLW page fault */
	AW(g_cond) = 0;
	AS(g_cond).fault_type = AS(cond).fault_type;
	WARN_ON(AS(cond).fault_type == 0);
	AS(g_cond).chan = AS(cond).chan;
	AS(g_cond).opcode = AS(cond).opcode;
	WARN_ON(!AS(cond).store);
	AS(g_cond).store = 1;
	AS(g_cond).empt = 1;	/* special case: 'store empty' to ignore */
				/* recovery of store operation after */
				/* page fault handling */
	AS(g_cond).scal = 1;
	AS(g_cond).dst_rcv = AS(cond).dst_rcv;
	AS(g_cond).rcv = AS(cond).rcv;
	tc_no = kvm_add_guest_vcpu_tc_entry(vcpu, address, g_cond, NULL);
	DebugKVMVGT("new entry #%d added to guest trap cellar: address 0x%lx "
		"condition 0x%016llx\n",
		tc_no, address, AW(g_cond));

	/* now it needs handle the page fault passed to guest kernel */
	handled = kvm_handle_guest_traps(regs);
	if (!handled)
		return 0;	/* host should handle the trap */
	return exc_data_page_mask;
}

/*
 * Page faults on guest user addresses should be handled by guest kernel, so
 * it need pass these faulted requests to guest.
 * Function returns non zero value if the request is from guest and it
 * successfully passed to guest (set VCPU TIRs and trap cellar)
 */
unsigned long kvm_pass_page_fault_to_guest(struct pt_regs *regs,
			trap_cellar_t *tcellar)
{
	trap_pt_regs_t	*trap = regs->trap;
	struct kvm_vcpu *vcpu;
	int ret;
	unsigned long pfres;

	vcpu = current_thread_info()->vcpu;
	BUG_ON(vcpu == NULL);

	E2K_KVM_BUG_ON(!kvm_test_intc_emul_flag(regs));

	regs->dont_inject = kvm_vcpu_test_and_clear_dont_inject(vcpu);

	pfres = 0;
	if (!is_paging(vcpu))
		pfres |= KVM_SHADOW_NONP_PF_MASK;

	ret = kvm_pv_mmu_page_fault(vcpu, regs, tcellar, false);
	if (ret == 0) {
		/* page fault successfully handled and need recover */
		/* load/store operation */
		pfres |= KVM_GUEST_KERNEL_ADDR_PF_MASK;
		return pfres;
	}
	if (ret == 1) {
		/* guest try write to protected PT, page fault handled */
		/* and recovered by hypervisor */
		pfres |= KVM_SHADOW_PT_PROT_PF_MASK;
		return pfres;
	}
	if (ret == 2) {
		/* page fault is injected to guest, and wiil be */
		/* handled by guest */
		return KVM_TRAP_IS_PASSED(trap->nr_trap);
	}
	if (ret == 3) {
		/* page fault does not be injected to guest, and wiil be */
		/* handled by host */
		return KVM_NOT_GUEST_TRAP_RESULT;
	}
	if (ret < 0) {
		/* page fault handling failed */
		return ret;
	}

	/* could not handle, so host should to do it */
	return KVM_NOT_GUEST_TRAP_RESULT;
}

void kvm_complete_page_fault_to_guest(unsigned long what_complete)
{
	struct kvm_vcpu *vcpu;

	if (what_complete == 0)
		return;

	vcpu = current_thread_info()->vcpu;
	BUG_ON(vcpu == NULL);

	E2K_KVM_BUG_ON(what_complete != 0);
}

/*
 * Guest hardware stacks bounds can occure, but 'sge' mask can be disabled,
 * so host handler incremented stack size on reserve limit of guest and
 * update hardware stack pointers on host.
 * But stack bounds trap should be handled by guest, increment user
 * hardware stacks size and update own stack pointers state.
 * Not zero value of hardware stack reserved part is signal to pass trap
 * on stacks bouns to handle by guest kernel.
 */
bool kvm_is_guest_proc_stack_bounds(struct pt_regs *regs)
{
	if (likely(!test_guest_proc_bounds_waiting(current_thread_info())))
		return false;
	WARN_ONCE(1, "implement me");
	return true;
}
bool kvm_is_guest_chain_stack_bounds(struct pt_regs *regs)
{
	if (likely(!test_guest_chain_bounds_waiting(current_thread_info())))
		return false;
	WARN_ONCE(1, "implement me");
	return true;
}

static inline unsigned long
pass_hw_stack_bounds_to_guest_TIRs(struct pt_regs *regs,
					unsigned long trap_mask)
{
	struct kvm_vcpu *vcpu;
	e2k_tir_hi_t g_TIR_hi;
	e2k_tir_lo_t g_TIR_lo;

	vcpu = current_thread_info()->vcpu;

	/* trap on host kernel and IRQs at this moment were disabled */
	/* so trap cannot be passed immediatly to guest, because of */
	/* any call of guest kernel can be trapped and host receives */
	/* recursive trap and may be dedlock. */
	/* For example hardware stack bounds trap on native change */
	/* stacks from scheduler (see 2) below) */
	BUG_ON(native_kernel_mode(regs));

	if (!kvm_get_guest_vcpu_sge(vcpu) ||
			kvm_guest_vcpu_irqs_disabled(vcpu,
				kvm_get_guest_vcpu_UPSR_value(vcpu),
				kvm_get_guest_vcpu_PSR_value(vcpu))) {
		/*
		 * 1) 'sge' trap masked on guest, so cannot pass the trap;
		 * 2) interrupts disabled,  so cannot too pass the trap.
		 *    In this case, if the trap will be passed, then guest
		 *    trap handler (parse_TIR_registers()) can enable
		 *    interrupts and may be dedlock. For example while scheduler
		 *    switch to other process interrupts disabled and spinlock
		 *    rq->lock taken, so if trap is passed and is handling, then
		 *    IRQs enable and new interrupt on timer can call some
		 *    function (for example scheduler_tick()) which need take
		 *    the same spinlock rq->lock
		 */
		DebugKVMSGE("%s (%d/%d) hardware stack bounds trap is masked "
			"on guest, cannot pass the trap to guest\n",
			current->comm, current->pid,
			current_thread_info()->gthread_info->gpid->nid.nr);
		/* trap on guest and should be handled by guest, */
		/* but now trap handling is masked, */
		/* still trap will repeat again some later */
		if (test_and_set_guest_hw_stack_bounds_waiting(
				current_thread_info(), trap_mask)) {
			DebugKVMSGE("trap on hardware stack bounds is already "
				"waiting for pass trap to guest\n");
		}
		return masked_hw_stack_bounds_mask | trap_mask;
	}
	BUG_ON(check_is_guest_TIRs_frozen(regs, true));
	/* set guest VCPU TIR registers state to simulate stack bounds trap */
	g_TIR_lo.TIR_lo_reg = GET_CLEAR_TIR_LO(0);
	g_TIR_hi.TIR_hi_reg = GET_CLEAR_TIR_HI(0);
	g_TIR_hi.TIR_hi_exc = trap_mask;
	kvm_update_guest_vcpu_TIR(vcpu, 0, g_TIR_hi, g_TIR_lo);
	regs->traps_to_guest |= trap_mask;
	if (test_and_clear_guest_hw_stack_bounds_waiting(
				current_thread_info(), trap_mask)) {
		DebugKVMSGE("trap on hardware stack bounds was waiting and "
			"trap now is passed to guest\n");
	}
	DebugHWSB("hardware stack bounds trap is set to guest TIRs #0\n");
	return trap_mask;
}

/*
 * Guest process hardware stacks overflow or underflow occurred.
 * This trap should handle guest kernel, but before transfer to guest,
 * host should expand hardware stack on guest kernel reserved part to enable
 * safe handling by guest. Otherwise can be recursive hardware stacks
 * bounds traps.
 * PSR.sge flag should be enabled to detect recursive bounds while guest
 * handler running in user mode
 * If the guest kernel trap handler cannot be started, then this function
 * send signal to complete guest and return non-zero value to disable continue
 * of the trap handling by host.
 * WARNING: Interrupts should be disabled by caller
 */
static inline unsigned long
kvm_handle_guest_proc_stack_bounds(struct pt_regs *regs)
{
	hw_stack_t *hw_stacks;
	struct kvm_vcpu *vcpu;
	bool underflow = false;
	e2k_size_t ps_size;
	e2k_size_t ps_ind;
	e2k_psp_hi_t gpsp_hi;
	e2k_size_t gps_size;
	int ret;

	hw_stacks = &current_thread_info()->u_hw_stack;
	vcpu = current_thread_info()->vcpu;
	BUG_ON(vcpu == NULL);
	ps_size = regs->stacks.psp_hi.PSP_hi_size;
	ps_ind = regs->stacks.psp_hi.PSP_hi_ind;
	DebugHWSB("procedure stack bounds: index 0x%lx size 0x%lx\n",
		ps_ind, ps_size);
	if (ps_ind < (ps_size >> 1)) {
		underflow = true;
		DebugHWSB("procedure stack underflow, stack need not "
			"be expanded on guest kernel part\n");
		goto guest_handler;
	}

	WARN_ONCE(1, "implememt me");

	gpsp_hi = kvm_get_guest_vcpu_PSP_hi(vcpu);
	gps_size = gpsp_hi.PSP_hi_size;
	kvm_set_guest_vcpu_PSP_hi(vcpu, gpsp_hi);
	DebugHWSB("procedure stack will be incremented on guest kernel "
		"reserved part: size 0x%lx, new size 0x%x\n",
		gps_size, gpsp_hi.PSP_hi_size);

	ret = -ENOSYS; //TODO update_guest_kernel_hw_ps_state(vcpu);
	if (ret) {
		pr_err("%s(): could not expand guest procedure stack "
			"on kernel reserved part, error %d\n",
			__func__, ret);
		goto out_failed;
	}
	/* correct PSP rigister state in pt_regs structure */
	regs->stacks.psp_hi.PSP_hi_size = gpsp_hi.PSP_hi_size;

guest_handler:
	return pass_hw_stack_bounds_to_guest_TIRs(regs,
				exc_proc_stack_bounds_mask);
out_failed:
	force_sig(SIGSEGV);
	return exc_proc_stack_bounds_mask;
}

static inline unsigned long
kvm_handle_guest_chain_stack_bounds(struct pt_regs *regs)
{
	hw_stack_t *hw_stacks;
	struct kvm_vcpu *vcpu;
	bool underflow = false;
	e2k_size_t pcs_size;
	e2k_size_t pcs_ind;
	e2k_pcsp_hi_t gpcsp_hi;
	e2k_size_t gpcs_size;
	int ret;

	hw_stacks = &current_thread_info()->u_hw_stack;
	vcpu = current_thread_info()->vcpu;
	pcs_size = regs->stacks.pcsp_hi.PCSP_hi_size;
	pcs_ind = regs->stacks.pcsp_hi.PCSP_hi_ind;
	DebugHWSB("chain stack bounds: index 0x%lx size 0x%lx\n",
		pcs_ind, pcs_size);
	if (pcs_ind < (pcs_size >> 1)) {
		underflow = true;
		DebugHWSB("chain stack underflow, stack need not "
			"be expanded on guest kernel part\n");
		goto guest_handler;
	}
	
	WARN_ONCE(1, "implememt me");

	gpcsp_hi = kvm_get_guest_vcpu_PCSP_hi(vcpu);
	gpcs_size = gpcsp_hi.PCSP_hi_size;
	kvm_set_guest_vcpu_PCSP_hi(vcpu, gpcsp_hi);
	DebugHWSB("chain stack will be incremented on guest kernel "
		"reserved part: size 0x%lx, new size 0x%x\n",
		gpcs_size, gpcsp_hi.PCSP_hi_size);

	ret = -ENOSYS; //TODO update_guest_kernel_hw_pcs_state(vcpu);
	if (ret) {
		pr_err("%s(): could not expand guest chain stack "
			"on kernel reserved part, error %d\n",
			__func__, ret);
		goto out_failed;
	}
	/* correct PCSP rigister state in pt_regs structure */
	regs->stacks.pcsp_hi.PCSP_hi_size = gpcsp_hi.PCSP_hi_size;

guest_handler:
	return pass_hw_stack_bounds_to_guest_TIRs(regs,
				exc_chain_stack_bounds_mask);

out_failed:
	force_sig(SIGSEGV);
	return exc_chain_stack_bounds_mask;
}

unsigned long kvm_pass_stack_bounds_trap_to_guest(struct pt_regs *regs,
					bool proc_bounds, bool chain_bounds)
{
	unsigned long passed = 0;
	unsigned long flags;

	/* hw stack bounds traps can have not trap IP and proper TIRs */
	if (LIGHT_HYPERCALL_MODE(regs)) {
		DebugHWSB("hw stacks bounds occurred in light hypercall: "
			"%s %s\n",
			(proc_bounds) ? "proc" : "",
			(chain_bounds) ? "chain" : "");
	} else if (guest_kernel_mode(regs)) {
		DebugHWSB("hw stacks bounds occurred on guest kernel: "
			"%s %s\n",
			(proc_bounds) ? "proc" : "",
			(chain_bounds) ? "chain" : "");
	} else if (guest_user_mode(regs)) {
		DebugHWSB("hw stacks bounds occurred on guest user: %s %s\n",
			(proc_bounds) ? "proc" : "",
			(chain_bounds) ? "chain" : "");
	} else {
		pr_err("hw stacks bounds occurred on host running guest "
			"process: %s %s\n",
			(proc_bounds) ? "proc" : "",
			(chain_bounds) ? "chain" : "");
		BUG_ON(true);
	}

	local_irq_save(flags);
	if (proc_bounds)
		passed |= kvm_handle_guest_proc_stack_bounds(regs);
	if (chain_bounds)
		passed |= kvm_handle_guest_chain_stack_bounds(regs);
	local_irq_restore(flags);

	return passed;
}

int kvm_apply_updated_psp_bounds(struct kvm_vcpu *vcpu,
		unsigned long base, unsigned long size,
		unsigned long start, unsigned long end, unsigned long delta)
{
	int ret;

	ret = apply_psp_delta_to_signal_stack(base, size, start, end, delta);
	if (ret != 0) {
		pr_err("%s(): could not apply updated procedure stack "
			"boundaries, error %d\n",
			__func__, ret);
	}
	return ret;
}

int kvm_apply_updated_pcsp_bounds(struct kvm_vcpu *vcpu,
		unsigned long base, unsigned long size,
		unsigned long start, unsigned long end, unsigned long delta)
{
	int ret;

	ret = apply_pcsp_delta_to_signal_stack(base, size, start, end, delta);
	if (ret != 0) {
		pr_err("%s(): could not apply updated chain stack "
			"boundaries, error %d\n",
			__func__, ret);
	}
	return ret;
}

int kvm_apply_updated_usd_bounds(struct kvm_vcpu *vcpu,
		unsigned long top, unsigned long delta, bool incr)
{
	int ret;
	unsigned long chain_stack_border = 0;

	ret = apply_usd_delta_to_signal_stack(top, delta, incr, &chain_stack_border);
	if (ret != 0) {
		pr_err("%s(): could not apply updated user data stack "
			"boundaries, error %d\n",
			__func__, ret);
	}
	return ret;
}

#ifdef	CHECK_GUEST_VCPU_UPDATES
static inline void
check_guest_stack_regs_updates(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	{
		e2k_addr_t sbr = kvm_get_guest_vcpu_SBR_value(vcpu);
		e2k_usd_lo_t usd_lo = kvm_get_guest_vcpu_USD_lo(vcpu);
		e2k_usd_hi_t usd_hi = kvm_get_guest_vcpu_USD_hi(vcpu);

		if (usd_lo.USD_lo_half != regs->stacks.usd_lo.USD_lo_half ||
			usd_hi.USD_hi_half != regs->stacks.usd_hi.USD_hi_half ||
			sbr != regs->stacks.top) {
			DebugKVMGT("FAULT: source  USD: base 0x%llx size 0x%x "
				"top 0x%lx\n",
				regs->stacks.usd_lo.USD_lo_base,
				regs->stacks.usd_hi.USD_hi_size,
				regs->stacks.top);
			DebugKVMGT("NOT updated    USD: base 0x%llx size 0x%x "
				"top 0x%lx\n",
				usd_lo.USD_lo_base,
				usd_hi.USD_hi_size,
				sbr);
		}
	}
	{
		e2k_psp_lo_t psp_lo = kvm_get_guest_vcpu_PSP_lo(vcpu);
		e2k_psp_hi_t psp_hi = kvm_get_guest_vcpu_PSP_hi(vcpu);
		e2k_pcsp_lo_t pcsp_lo = kvm_get_guest_vcpu_PCSP_lo(vcpu);
		e2k_pcsp_hi_t pcsp_hi = kvm_get_guest_vcpu_PCSP_hi(vcpu);

		if (psp_lo.PSP_lo_half != regs->stacks.psp_lo.PSP_lo_half ||
			psp_hi.PSP_hi_size != regs->stacks.psp_hi.PSP_hi_size) {
			/* PSP_hi_ind/PCSP_hi_ind can be modified and should */
			/* be restored as saved at regs state */
			DebugKVMGT("FAULT: source  PSP:  base 0x%llx size 0x%x "
				"ind 0x%x\n",
				regs->stacks.psp_lo.PSP_lo_base,
				regs->stacks.psp_hi.PSP_hi_size,
				regs->stacks.psp_hi.PSP_hi_ind);
			DebugKVMGT("NOT updated    PSP:  base 0x%llx size 0x%x "
				"ind 0x%x\n",
				psp_lo.PSP_lo_base,
				psp_hi.PSP_hi_size,
				psp_hi.PSP_hi_ind);
		}
		if (pcsp_lo.PCSP_lo_half != regs->stacks.pcsp_lo.PCSP_lo_half ||
			pcsp_hi.PCSP_hi_size !=
				regs->stacks.pcsp_hi.PCSP_hi_size) {
			DebugKVMGT("FAULT: source  PCSP: base 0x%llx size 0x%x "
				"ind 0x%x\n",
				regs->stacks.pcsp_lo.PCSP_lo_base,
				regs->stacks.pcsp_hi.PCSP_hi_size,
				regs->stacks.pcsp_hi.PCSP_hi_ind);
			DebugKVMGT("NOT updated    PCSP: base 0x%llx size 0x%x "
				"ind 0x%x\n",
				pcsp_lo.PCSP_lo_base,
				pcsp_hi.PCSP_hi_size,
				pcsp_hi.PCSP_hi_ind);
		}
	}
	{
		unsigned long cr0_lo = kvm_get_guest_vcpu_CR0_lo_value(vcpu);
		unsigned long cr0_hi = kvm_get_guest_vcpu_CR0_hi_value(vcpu);
		e2k_cr1_lo_t cr1_lo = kvm_get_guest_vcpu_CR1_lo(vcpu);
		e2k_cr1_hi_t cr1_hi = kvm_get_guest_vcpu_CR1_hi(vcpu);

		if (cr0_lo != regs->crs.cr0_lo.CR0_lo_half ||
			cr0_hi != regs->crs.cr0_hi.CR0_hi_half ||
			cr1_lo.CR1_lo_half != regs->crs.cr1_lo.CR1_lo_half ||
			cr1_hi.CR1_hi_half != regs->crs.cr1_hi.CR1_hi_half) {
			DebugKVMGT("FAULT: source  CR0.lo 0x%016llx CR0.hi "
				"0x%016llx CR1.lo.wbs 0x%x CR1.hi.ussz 0x%x\n",
				regs->crs.cr0_lo.CR0_lo_half,
				regs->crs.cr0_hi.CR0_hi_half,
				regs->crs.cr1_lo.CR1_lo_wbs,
				regs->crs.cr1_hi.CR1_hi_ussz);
			DebugKVMGT("NOT updated    CR0.lo 0x%016lx CR0.hi "
				"0x%016lx CR1.lo.wbs 0x%x CR1.hi.ussz 0x%x\n",
				cr0_lo,
				cr0_hi,
				cr1_lo.CR1_lo_wbs,
				cr1_hi.CR1_hi_ussz);
		}
	}
}
#else	/* ! CHECK_GUEST_VCPU_UPDATES */
static inline void
check_guest_stack_regs_updates(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
}
#endif	/* CHECK_GUEST_VCPU_UPDATES */

static inline void
restore_guest_trap_stack_regs(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	unsigned long regs_status = kvm_get_guest_vcpu_regs_status(vcpu);

	if (!KVM_TEST_UPDATED_CPU_REGS_FLAGS(regs_status)) {
		DebugKVMVGT("competed: nothing updated");
		goto check_updates;
	}

	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, WD_UPDATED_CPU_REGS)) {
		e2k_wd_t wd = kvm_get_guest_vcpu_WD(vcpu);

#ifdef	CHECK_GUEST_VCPU_UPDATES
		if (wd.WD_psize != regs->wd.WD_psize) {
			DebugKVMGT("source  WD: size 0x%x\n",
				regs->wd.WD_psize);
#endif	/* CHECK_GUEST_VCPU_UPDATES */

			regs->wd.WD_psize = wd.WD_psize;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated WD: size 0x%x\n",
				regs->wd.WD_psize);
		}
#endif	/* CHECK_GUEST_VCPU_UPDATES */
	}
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, USD_UPDATED_CPU_REGS)) {
		unsigned long sbr = kvm_get_guest_vcpu_SBR_value(vcpu);
		unsigned long usd_lo = kvm_get_guest_vcpu_USD_lo_value(vcpu);
		unsigned long usd_hi = kvm_get_guest_vcpu_USD_hi_value(vcpu);

#ifdef	CHECK_GUEST_VCPU_UPDATES
		if (usd_lo != regs->stacks.usd_lo.USD_lo_half ||
				usd_hi != regs->stacks.usd_hi.USD_hi_half ||
				sbr != regs->stacks.top) {
			DebugKVMGT("source  USD: base 0x%llx size 0x%x "
				"top 0x%lx\n",
				regs->stacks.usd_lo.USD_lo_base,
				regs->stacks.usd_hi.USD_hi_size,
				regs->stacks.top);
#endif	/* CHECK_GUEST_VCPU_UPDATES */

			regs->stacks.usd_lo.USD_lo_half = usd_lo;
			regs->stacks.usd_hi.USD_hi_half = usd_hi;
			regs->stacks.top = sbr;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated USD: base 0x%llx size 0x%x "
				"top 0x%lx\n",
				regs->stacks.usd_lo.USD_lo_base,
				regs->stacks.usd_hi.USD_hi_size,
				regs->stacks.top);
		}
#endif	/* CHECK_GUEST_VCPU_UPDATES */
	}
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status,
						HS_REGS_UPDATED_CPU_REGS)) {
		unsigned long psp_lo = kvm_get_guest_vcpu_PSP_lo_value(vcpu);
		unsigned long psp_hi = kvm_get_guest_vcpu_PSP_hi_value(vcpu);
		unsigned long pcsp_lo = kvm_get_guest_vcpu_PCSP_lo_value(vcpu);
		unsigned long pcsp_hi = kvm_get_guest_vcpu_PCSP_hi_value(vcpu);

#ifdef	CHECK_GUEST_VCPU_UPDATES
		if (psp_lo != regs->stacks.psp_lo.PSP_lo_half ||
				psp_hi != regs->stacks.psp_hi.PSP_hi_half) {
			DebugKVMGT("source  PSP:  base 0x%llx size 0x%x "
				"ind 0x%x\n",
				regs->stacks.psp_lo.PSP_lo_base,
				regs->stacks.psp_hi.PSP_hi_size,
				regs->stacks.psp_hi.PSP_hi_ind);
#endif	/* CHECK_GUEST_VCPU_UPDATES */

			regs->stacks.psp_lo.PSP_lo_half = psp_lo;
			regs->stacks.psp_hi.PSP_hi_half = psp_hi;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated PSP:  base 0x%llx size 0x%x "
				"ind 0x%x\n",
				regs->stacks.psp_lo.PSP_lo_base,
				regs->stacks.psp_hi.PSP_hi_size,
				regs->stacks.psp_hi.PSP_hi_ind);
		}
#endif	/* CHECK_GUEST_VCPU_UPDATES */

#ifdef	CHECK_GUEST_VCPU_UPDATES
		if (pcsp_lo != regs->stacks.pcsp_lo.PCSP_lo_half ||
				pcsp_hi != regs->stacks.pcsp_hi.PCSP_hi_half) {
			DebugKVMGT("source  PCSP: base 0x%llx size 0x%x "
				"ind 0x%x\n",
				regs->stacks.pcsp_lo.PCSP_lo_base,
				regs->stacks.pcsp_hi.PCSP_hi_size,
				regs->stacks.pcsp_hi.PCSP_hi_ind);
#endif	/* CHECK_GUEST_VCPU_UPDATES */

			regs->stacks.pcsp_lo.PCSP_lo_half = pcsp_lo;
			regs->stacks.pcsp_hi.PCSP_hi_half = pcsp_hi;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated PCSP: base 0x%llx size 0x%x "
				"ind 0x%x\n",
				regs->stacks.pcsp_lo.PCSP_lo_base,
				regs->stacks.pcsp_hi.PCSP_hi_size,
				regs->stacks.pcsp_hi.PCSP_hi_ind);
		}
#endif	/* CHECK_GUEST_VCPU_UPDATES */
	}
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, CRS_UPDATED_CPU_REGS)) {
		unsigned long cr0_lo = kvm_get_guest_vcpu_CR0_lo_value(vcpu);
		unsigned long cr0_hi = kvm_get_guest_vcpu_CR0_hi_value(vcpu);
		unsigned long cr1_lo = kvm_get_guest_vcpu_CR1_lo_value(vcpu);
		unsigned long cr1_hi = kvm_get_guest_vcpu_CR1_hi_value(vcpu);

#ifdef	CHECK_GUEST_VCPU_UPDATES
		if (cr0_lo != regs->crs.cr0_lo.CR0_lo_half ||
				cr0_hi != regs->crs.cr0_hi.CR0_hi_half ||
				cr1_lo != regs->crs.cr1_lo.CR1_lo_half ||
				cr1_hi != regs->crs.cr1_hi.CR1_hi_half) {
			DebugKVMGT("source  CR0.lo 0x%016llx CR0.hi 0x%016llx "
				"CR1.lo.wbs 0x%x CR1.hi.ussz 0x%x\n",
				regs->crs.cr0_lo.CR0_lo_half,
				regs->crs.cr0_hi.CR0_hi_half,
				regs->crs.cr1_lo.CR1_lo_wbs,
				regs->crs.cr1_hi.CR1_hi_ussz);
#endif	/* CHECK_GUEST_VCPU_UPDATES */

			regs->crs.cr0_lo.CR0_lo_half = cr0_lo;
			regs->crs.cr0_hi.CR0_hi_half = cr0_hi;
			regs->crs.cr1_lo.CR1_lo_half = cr1_lo;
			regs->crs.cr1_hi.CR1_hi_half = cr1_hi;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated CR0.lo 0x%016llx CR0.hi 0x%016llx "
				"CR1.lo.wbs 0x%x CR1.hi.ussz 0x%x\n",
				regs->crs.cr0_lo.CR0_lo_half,
				regs->crs.cr0_hi.CR0_hi_half,
				regs->crs.cr1_lo.CR1_lo_wbs,
				regs->crs.cr1_hi.CR1_hi_ussz);
		}
#endif	/* CHECK_GUEST_VCPU_UPDATES */
	}
	kvm_reset_guest_updated_vcpu_regs_flags(vcpu, regs_status);

check_updates:
	check_guest_stack_regs_updates(vcpu, regs);
}

void restore_guest_trap_regs(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	restore_guest_trap_stack_regs(vcpu, regs);
}

int kvm_correct_guest_trap_return_ip(unsigned long return_ip)
{
	struct signal_stack_context __user *context;
	struct pt_regs __user *u_regs;
	e2k_cr0_hi_t cr0_hi;
	unsigned long ts_flag;
	int ret;

	if ((long)return_ip < 0) {
		/* return IP was inverted to tell the host that the return */
		/* should be on the host privileged action handler */
		E2K_KVM_BUG_ON(current->thread.usr_pfault_jump == 0);
		return_ip = current->thread.usr_pfault_jump;
	}
	context = get_signal_stack();
	u_regs = &context->regs;
	cr0_hi.CR0_hi_half = 0;
	cr0_hi.CR0_hi_IP = return_ip;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);

	ret = __put_user(cr0_hi.CR0_hi_half, &u_regs->crs.cr0_hi.CR0_hi_half);

	clear_ts_flag(ts_flag);

	if (ret != 0) {
		pr_err("%s(): put to user corrected IP failed, error %d\n",
			__func__, ret);
	}
	return ret;
}


unsigned long kvm_disabled_priv_hcall(unsigned long nr,
			unsigned long arg1, unsigned long arg2,
			unsigned long arg3, unsigned long arg4,
			unsigned long arg5, unsigned long arg6,
			unsigned long arg7)
{
	return -ENOSYS;
}


/* FIXME: kvm trap entry should be passed by guest kernel through common */
/* locked area kvm_state_t or as arg of guest kernel entry_point to start it
static char *kvm_guest_ttable_base = NULL;
 * should be deleted
 */

trap_hndl_t kvm_do_handle_guest_traps(struct pt_regs *regs)
{
	pr_err("%s() should not be called and need delete\n", __func__);
	return (trap_hndl_t)-ENOSYS;
}

/*
 * Any system calls from guest user start this function.
 * User data stack was not switched to kernel (host or guest) stack, so
 * the host function (including all called functions) should not use data stack.
 * Function switch user data stack just to guest kernel stack and possible
 * debugging mode will use guest stack (it is not right in theory, but it need
 * only to debug)
 */
/* FIXME: only to debug (including gregs save/restore), __interrupt */
/* should be uncommented */
long /*__interrupt*/
goto_guest_kernel_ttable_C(long sys_num_and_entry,
		u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5, u64 arg6)
{
	pr_err("%s() should not be called and need delete\n", __func__);
	return -ENOSYS;
}

int kvm_copy_hw_stacks_frames(struct kvm_vcpu *vcpu,
		void __user *dst, void __user *src, long size, bool is_chain)
{
	int ret;

	E2K_KVM_BUG_ON(((unsigned long)dst & PAGE_MASK) !=
			((unsigned long)(dst + (size - 1)) & PAGE_MASK));
	E2K_KVM_BUG_ON(((unsigned long)src & PAGE_MASK) !=
			((unsigned long)(src + (size - 1)) & PAGE_MASK));

	ret = kvm_copy_from_to_user_with_tags(vcpu, dst, src, size);
	if (ret != size) {
		pr_err("%s(): copy from %px to %px failed, error %d\n",
			__func__, src, dst, ret);
		return (ret < 0) ? ret : -EFAULT;
	}

	return 0;
}

/*
 * Prepare chain stack frame for guest fast syscall ttable entry handler
 * - change return ip to guest ttable entry
 * - Change psr to user (unprivilidged)
 */
__section(".entry.text")
static inline void prepare_guest_fast_ttable_entry_crs(struct kvm_vcpu *vcpu,
							u64 trap_num)
{
	u64 gst_fast_sys_call_trap = ((u64) vcpu->arch.trap_entry) +
				trap_num * E2K_SYSCALL_TRAP_ENTRY_SIZE;

	/* Get current parameters of top chain stack frame */
	e2k_cr0_lo_t cr0_lo = READ_CR0_LO_REG();
	e2k_cr0_hi_t cr0_hi = READ_CR0_HI_REG();
	e2k_cr1_lo_t cr1_lo = READ_CR1_LO_REG();
	e2k_cr1_hi_t cr1_hi = READ_CR1_HI_REG();

	/*
	 * Correct ip and psr value in top chain stack frame
	 * to return to guest ttable entry in unprivlidged mode
	 */
	AS(cr0_lo).pf = -1ULL;
	AS(cr0_hi).ip = gst_fast_sys_call_trap >> 3;
	AS(cr1_lo).psr = AW(E2K_USER_INITIAL_PSR);
	AS(cr1_lo).cui = KERNEL_CODES_INDEX;

	/* Write back new chain stack frame parameters to cr */
	WRITE_CR0_LO_REG(cr0_lo);
	WRITE_CR0_HI_REG(cr0_hi);
	WRITE_CR1_LO_REG(cr1_lo);
	WRITE_CR1_HI_REG(cr1_hi);

	return;
}

/*
 * Special host-side handler for fast guest syscalls
 *
 * __interupt since this is executed in fast syscall
 * so any exceptions are passed to guest, but guest
 * can't handle getsp that originated in hypervisor code.
 */
__interrupt __section(".entry.text")
void notrace handle_guest_fast_sys_call(void)
{
	struct thread_info *ti = NATIVE_READ_CURRENT_REG();
	struct kvm_vcpu *vcpu = ti->vcpu;

	pv_mmu_switch_to_fast_sys_call(vcpu, ti);
	HOST_VCPU_STATE_REG_SWITCH_TO_GUEST(vcpu);
	prepare_guest_fast_ttable_entry_crs(vcpu,
			GUEST_FAST_SYSCALL_TRAP_NUM);
 
	/* Pass control to guest fast syscall ttable entry */
	return;
}

/* Special host-side handler for compat fast guest syscalls */
__section(".entry.text")
void notrace handle_compat_guest_fast_sys_call(void)
{
	struct thread_info *ti = NATIVE_READ_CURRENT_REG();
	struct kvm_vcpu *vcpu = ti->vcpu;

	pv_mmu_switch_to_fast_sys_call(vcpu, ti);
	HOST_VCPU_STATE_REG_SWITCH_TO_GUEST(vcpu);
	prepare_guest_fast_ttable_entry_crs(vcpu,
			GUEST_COMPAT_FAST_SYSCALL_TRAP_NUM);

	/* Pass control to guest compat fast syscall ttable entry */
}
