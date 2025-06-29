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

#undef	DEBUG_PV_SYSCALL_MODE
#define	DEBUG_PV_SYSCALL_MODE	0	/* syscall injection debugging */

#if	DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE
extern bool debug_guest_ust;
#else
#define	debug_guest_ust	false
#endif /* DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE */

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

#define	DEBUG_ACT		0

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
		pr_err("%s(): Trap in trap and may be recursion, so kill the VCPU and VM\n",
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
unsigned long kvm_host_aau_page_fault(struct kvm_vcpu *vcpu, pt_regs_t *regs,
				      e2k_tir_t TIR)
{
	unsigned int aa_mask;

	aa_mask = TIR.aa;
	E2K_KVM_BUG_ON(aa_mask == 0);

	machine.do_aau_fault(aa_mask, regs);

	return 1;
}

unsigned long kvm_pass_the_trap_to_guest(struct kvm_vcpu *vcpu,
					 pt_regs_t *regs, e2k_tir_t TIR,
					 int trap_no)
{
	e2k_tir_t tir;
	int tir_no;
	unsigned long trap_mask;

	DebugKVMVGT("trap #%d TIRs hi 0x%016llx lo 0x%016llx\n",
		    trap_no, HI(TIR), LO(TIR));

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

	tir = TIR;
	tir.aa = 0;		/* clear AAU traps mask */
	tir.exc = trap_mask;
	tir_no = tir.j;
	if (tir.ip == 0) {
		tir.ip = get_cr0_ip(regs->crs.cr0);
	}
	kvm_update_vcpu_intc_TIR(vcpu, tir_no, tir);
	regs->traps_to_guest |= trap_mask;
	DebugKVMVGT("trap is set to guest TIRs #%d\n", tir_no);
	return trap_mask;
}

static inline unsigned long
pass_virqs_to_guest_TIRs(struct pt_regs *regs, e2k_tir_t TIR)
{
	struct kvm_vcpu *vcpu;
	e2k_tir_t tir;
	e2k_tir_t g_TIR;
	int TIR_no;

	BUG_ON(check_is_guest_TIRs_frozen(regs, true));
	vcpu = current_thread_info()->vcpu;

	if (TIR.exc_al_aa_j == 0) {
		TIR_no = 0;
	} else {
		tir.exc_al_aa_j = TIR.exc_al_aa_j;
		TIR_no = tir.j;
	}
	g_TIR.ip = TIR.ip;
	g_TIR.exc_al_aa_j = GET_CLEAR_TIR_HI(TIR_no);
	g_TIR.exc_interrupt = 1;
	kvm_update_guest_vcpu_TIR(vcpu, TIR_no, g_TIR);
	regs->traps_to_guest |= exc_interrupt_mask;
	DebugKVMVGT("interrupt is set to guest TIRs #%d hi 0x%016llx lo 0x%016llx\n",
		TIR_no, HI(g_TIR), LO(g_TIR));

	return g_TIR.exc;
}

static bool lapic_state_printed = false;

unsigned long kvm_pass_virqs_to_guest(struct pt_regs *regs, e2k_tir_t TIR)
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
					 AW(kvm_get_guest_vcpu_UPSR(vcpu)),
					 AW(kvm_get_guest_vcpu_PSR(vcpu)))) {
		/* guest IRQs is now disabled, so it cannot pass interrupts */
		/* right now, so pending VIRQs flag is not cleared to pass */
		/* them to other appropriate case */
		DebugVIRQs("IRQs is disabled on guest kernel thread, could not pass\n");
		trace_kvm_pass_virqs_to_guest(vcpu, irqs_disabled_pass_virq);
		trace_kvm_irq_disabled_on_guest(vcpu, get_cr0_ip(regs->crs.cr0),
					AW(kvm_get_guest_vcpu_UPSR(vcpu)),
					AW(kvm_get_guest_vcpu_PSR(vcpu)));
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
	unsigned long i;

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
	e2k_tir_t tir;
	int tir_no;

	if (regs->traps_to_guest != 0 && !is_injected_guest_coredump(regs) ||
	    !kvm_check_is_guest_TIRs_empty(vcpu) ||
	    kvm_guest_vcpu_irqs_disabled(vcpu,
					 AW(kvm_get_guest_vcpu_UPSR(vcpu)),
					 AW(kvm_get_guest_vcpu_PSR(vcpu)))) {
		if (regs->traps_to_guest != 0 && !is_injected_guest_coredump(regs)) {
			pr_err("%s(): there is other trap(s) passed to guest 0x%016lx\n",
			       __func__, regs->traps_to_guest);
		}
		if (!kvm_check_is_guest_TIRs_empty(vcpu)) {
			pr_err("%s(): guest TIRs is not empty, handling in progress TIR[0].hi : 0x%016llx\n",
				__func__, HI(kvm_get_guest_vcpu_TIR(vcpu, 0)));
		}
		if (kvm_guest_vcpu_irqs_disabled(vcpu,
					AW(kvm_get_guest_vcpu_UPSR(vcpu)),
					AW(kvm_get_guest_vcpu_PSR(vcpu)))) {
			pr_err("%s(): guest IRQs disabled, coredump cannot be passed right now, PSR 0x%x UPSR 0x%x\n",
			       __func__, AW(kvm_get_guest_vcpu_PSR(vcpu)),
			       AW(kvm_get_guest_vcpu_UPSR(vcpu)));
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
	tir.ip = 0;
	tir.exc_al_aa_j = GET_CLEAR_TIR_HI(0);
	tir_no = 0;
	kvm_update_vcpu_intc_TIR(vcpu, tir_no, tir);
	regs->traps_to_guest |= core_dump_mask;
	kvm_clear_request_to_coredump(vcpu);
	DebugKVMVGT("trap is set to guest TIRs #0 hi 0x%016llx lo 0x%016llx\n",
		    HI(tir), LO(tir));
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
		kvm_make_all_cpus_request(kvm, KVM_REQ_TO_COREDUMP |
							KVM_REQUEST_NO_WAKEUP);
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
	trap_pt_regs_t *trap = regs->trap;
	e2k_addr_t address;
	tc_cond_t cond;
	tc_cond_t g_cond;
	struct kvm_vcpu *vcpu;
	e2k_tir_t g_TIR;
	int TIR_no;
	int tc_no;
	bool handled;

	address = tcellar->address;
	cond = tcellar->condition;
	BUG_ON(!guest_user_addr_mode_page_fault(regs, false /* instr page */ ,
						address));
	DebugKVMVGT("trap occurred on guest user: address 0x%lx condition 0x%016llx\n",
		address, AW(cond));

	BUG_ON(check_is_guest_TIRs_frozen(regs, true));
	TIR_no = trap->TIR_no;
	g_TIR = trap->TIR;
	WARN_ON(TIR_no != g_TIR.j);
	g_TIR.aa = 0;
	g_TIR.exc = 0;
	g_TIR.exc_data_page = 1;
	WARN_ON((1UL << trap->nr_trap) != g_TIR.exc);

	/* set guest VCPU TIR registers state to simulate data page trap */
	vcpu = current_thread_info()->vcpu;
	BUG_ON(vcpu == NULL);
	kvm_update_guest_vcpu_TIR(vcpu, TIR_no, g_TIR);
	regs->traps_to_guest |= g_TIR.exc;
	DebugKVMVGT("trap is set to guest TIRs #%d hi 0x%016llx lo 0x%016llx\n",
		    TIR_no, HI(g_TIR), LO(g_TIR));

	/* add new trap cellar entry for guest VCPU */
	/* to simulate CLW page fault */
	AW(g_cond) = 0;
	g_cond.fault_type = cond.fault_type;
	WARN_ON(cond.fault_type == 0);
	g_cond.chan = cond.chan;
	g_cond.opcode = cond.opcode;
	WARN_ON(!cond.store);
	g_cond.store = 1;
	g_cond.empt = 1;	/* special case: 'store empty' to ignore */
	/* recovery of store operation after */
	/* page fault handling */
	g_cond.scal = 1;
	g_cond.dst_rcv = cond.dst_rcv;
	g_cond.rcv = cond.rcv;
	tc_no = kvm_add_guest_vcpu_tc_entry(vcpu, address, g_cond, NULL);
	DebugKVMVGT("new entry #%d added to guest trap cellar: address 0x%lx condition 0x%016llx\n",
		tc_no, address, AW(g_cond));

	/* now it needs handle the page fault passed to guest kernel */
	handled = kvm_handle_guest_traps(regs);
	if (!handled)
		return 0;	/* host should handle the trap */
	return g_TIR.exc;
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
	trap_pt_regs_t *trap = regs->trap;
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
	e2k_tir_t g_TIR;

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
					 AW(kvm_get_guest_vcpu_UPSR(vcpu)),
					 AW(kvm_get_guest_vcpu_PSR(vcpu)))) {
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
		DebugKVMSGE("%s (%d/%d) hardware stack bounds trap is masked on guest, cannot pass the trap to guest\n",
			    current->comm, current->pid,
			    current_thread_info()->gthread_info->gpid->nid.nr);
		/* trap on guest and should be handled by guest, */
		/* but now trap handling is masked, */
		/* still trap will repeat again some later */
		if (test_and_set_guest_hw_stack_bounds_waiting
		    (current_thread_info(), trap_mask)) {
			DebugKVMSGE("trap on hardware stack bounds is already waiting for pass trap to guest\n");
		}
		return masked_hw_stack_bounds_mask | trap_mask;
	}
	BUG_ON(check_is_guest_TIRs_frozen(regs, true));
	/* set guest VCPU TIR registers state to simulate stack bounds trap */
	g_TIR.ip = 0;
	g_TIR.exc_al_aa_j = GET_CLEAR_TIR_HI(0);
	g_TIR.exc = trap_mask;
	kvm_update_guest_vcpu_TIR(vcpu, 0, g_TIR);
	regs->traps_to_guest |= trap_mask;
	if (test_and_clear_guest_hw_stack_bounds_waiting
	    (current_thread_info(), trap_mask)) {
		DebugKVMSGE("trap on hardware stack bounds was waiting and trap now is passed to guest\n");
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
	e2k_psp_t gpsp;
	u64 gps_size;
	int ret;

	hw_stacks = &current_thread_info()->u_hw_stack;
	vcpu = current_thread_info()->vcpu;
	BUG_ON(vcpu == NULL);
	ps_size = vcpu_psp_size(vcpu, regs->stacks.psp);
	ps_ind = vcpu_psp_ind(vcpu, regs->stacks.psp);
	DebugHWSB("procedure stack bounds: index 0x%lx size 0x%lx\n",
		  ps_ind, ps_size);
	if (ps_ind < (ps_size >> 1)) {
		underflow = true;
		DebugHWSB("procedure stack underflow, stack need not be expanded on guest kernel part\n");
		goto guest_handler;
	}

	WARN_ONCE(1, "implememt me");

	gpsp = kvm_get_guest_vcpu_PSP(vcpu);
	gps_size = vcpu_psp_size(vcpu, gpsp);
	kvm_set_guest_vcpu_PSP(vcpu, gpsp);
	DebugHWSB("procedure stack will be incremented on guest kernel reserved part: size 0x%llx, new size 0x%llx\n",
		  gps_size, vcpu_psp_size(vcpu, gpsp));

	ret = -ENOSYS;	/*TODO update_guest_kernel_hw_ps_state(vcpu); */
	if (ret) {
		pr_err("%s(): could not expand guest procedure stack on kernel reserved part, error %d\n",
			__func__, ret);
		goto out_failed;
	}
	/* correct PSP rigister state in pt_regs structure */
	regs->stacks.psp = vcpu_new_psp(vcpu, vcpu_psp_base(vcpu, regs->stacks.psp),
					vcpu_psp_size(vcpu, gpsp),
					vcpu_psp_ind(vcpu, regs->stacks.psp));

guest_handler:
	return pass_hw_stack_bounds_to_guest_TIRs(regs, exc_proc_stack_bounds_mask);
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
	u64 pcs_size;
	u64 pcs_ind;
	e2k_pcsp_t gpcsp;
	u64 gpcs_size;
	int ret;

	hw_stacks = &current_thread_info()->u_hw_stack;
	vcpu = current_thread_info()->vcpu;
	pcs_size = vcpu_pcsp_size(vcpu, regs->stacks.pcsp);
	pcs_ind = vcpu_pcsp_ind(vcpu, regs->stacks.pcsp);
	DebugHWSB("chain stack bounds: index 0x%llx size 0x%llx\n",
		  pcs_ind, pcs_size);
	if (pcs_ind < (pcs_size >> 1)) {
		underflow = true;
		DebugHWSB("chain stack underflow, stack need not be expanded on guest kernel part\n");
		goto guest_handler;
	}

	WARN_ONCE(1, "implememt me");

	gpcsp = kvm_get_guest_vcpu_PCSP(vcpu);
	gpcs_size = vcpu_pcsp_size(vcpu, gpcsp);
	kvm_set_guest_vcpu_PCSP(vcpu, gpcsp);
	DebugHWSB("chain stack will be incremented on guest kernel reserved part: size 0x%llx, new size 0x%llx\n",
		  gpcs_size, vcpu_pcsp_size(vcpu, gpcsp));

	ret = -ENOSYS;	/*TODO update_guest_kernel_hw_pcs_state(vcpu); */
	if (ret) {
		pr_err("%s(): could not expand guest chain stack on kernel reserved part, error %d\n",
			__func__, ret);
		goto out_failed;
	}
	/* correct PCSP rigister state in pt_regs structure */
	regs->stacks.pcsp = vcpu_new_pcsp(vcpu, vcpu_pcsp_base(vcpu, regs->stacks.pcsp),
					  vcpu_pcsp_size(vcpu, gpcsp),
					  vcpu_pcsp_ind(vcpu, regs->stacks.pcsp));

guest_handler:
	return pass_hw_stack_bounds_to_guest_TIRs(regs, exc_chain_stack_bounds_mask);

out_failed:
	force_sig(SIGSEGV);
	return exc_chain_stack_bounds_mask;
}

unsigned long kvm_pass_stack_bounds_trap_to_guest(struct pt_regs *regs,
						  bool proc_bounds,
						  bool chain_bounds)
{
	unsigned long passed = 0;
	unsigned long flags;

	/* hw stack bounds traps can have not trap IP and proper TIRs */
	if (LIGHT_HYPERCALL_MODE(regs)) {
		DebugHWSB("hw stacks bounds occurred in light hypercall: %s %s\n",
			  (proc_bounds) ? "proc" : "",
			  (chain_bounds) ? "chain" : "");
	} else if (guest_kernel_mode(regs)) {
		DebugHWSB("hw stacks bounds occurred on guest kernel: %s %s\n",
			  (proc_bounds) ? "proc" : "",
			  (chain_bounds) ? "chain" : "");
	} else if (guest_user_mode(regs)) {
		DebugHWSB("hw stacks bounds occurred on guest user: %s %s\n",
			  (proc_bounds) ? "proc" : "",
			  (chain_bounds) ? "chain" : "");
	} else {
		pr_err("hw stacks bounds occurred on host running guest process: %s %s\n",
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
				 unsigned long start, unsigned long end,
				 unsigned long delta)
{
	int ret;

	ret = apply_psp_delta_to_signal_stack(base, size, start, end, delta);
	if (ret != 0) {
		pr_err("%s(): could not apply updated procedure stack boundaries, error %d\n",
			__func__, ret);
	}
	return ret;
}

int kvm_apply_updated_pcsp_bounds(struct kvm_vcpu *vcpu,
				  unsigned long base, unsigned long size,
				  unsigned long start, unsigned long end,
				  unsigned long delta)
{
	int ret;

	ret = apply_pcsp_delta_to_signal_stack(base, size, start, end, delta);
	if (ret != 0) {
		pr_err("%s(): could not apply updated chain stack boundaries, error %d\n",
			__func__, ret);
	}
	return ret;
}

int kvm_apply_updated_usd_bounds(struct kvm_vcpu *vcpu,
				 unsigned long top, unsigned long delta,
				 bool incr)
{
	int ret;
	unsigned long chain_stack_border = 0;

	ret =
	    apply_usd_delta_to_signal_stack(top, delta, incr,
					    &chain_stack_border);
	if (ret != 0) {
		pr_err("%s(): could not apply updated user data stack boundaries, error %d\n",
			__func__, ret);
	}
	return ret;
}

#ifdef	CHECK_GUEST_VCPU_UPDATES
static inline void
check_guest_stack_regs_updates(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	{
		u64 sbr = kvm_get_guest_vcpu_SBR_value(vcpu);
		e2k_usd_t usd = kvm_get_guest_vcpu_USD(vcpu);

		if (LO(usd) != LO(regs->stacks.usd) ||
		    HI(usd) != HI(regs->stacks.usd) ||
		    sbr != regs->stacks.top) {
			DebugKVMGT("FAULT: source  USD: base 0x%llx ind 0x%llx size 0x%llx\n",
				vcpu_usd_base(vcpu, regs->stacks.usd),
				vcpu_usd_ind(vcpu, regs->stacks.usd),
				(u64)regs->stacks.top - vcpu_usd_base(vcpu, regs->stacks.usd));
			DebugKVMGT("NOT updated    USD: base 0x%llx ind 0x%llx size 0x%llx\n",
				vcpu_usd_base(vcpu, usd), vcpu_usd_ind(vcpu, usd),
				sbr - vcpu_usd_base(vcpu, usd));
		}
	}
	{
		e2k_psp_t psp = kvm_get_guest_vcpu_PSP(vcpu);
		e2k_pcsp_t pcsp = kvm_get_guest_vcpu_PCSP(vcpu);

		if (vcpu_psp_base(vcpu, psp) != vcpu_psp_base(vcpu, regs->stacks.psp) ||
		    vcpu_psp_size(vcpu, psp) != vcpu_psp_size(vcpu, regs->stacks.psp)) {
			/* PSP_hi_ind/PCSP_hi_ind can be modified and should */
			/* be restored as saved at regs state */
			DebugKVMGT("FAULT: source  PSP:  base 0x%llx size 0x%llx ind 0x%llx\n",
				vcpu_psp_base(vcpu, regs->stacks.psp),
				vcpu_psp_size(vcpu, regs->stacks.psp),
				vcpu_psp_ind(vcpu, regs->stacks.psp));
			DebugKVMGT("NOT updated    PSP:  base 0x%llx size 0x%llx ind 0x%llx\n",
				vcpu_psp_base(vcpu, psp), vcpu_psp_size(vcpu, psp),
				vcpu_psp_ind(vcpu, psp));
		}
		if (vcpu_pcsp_base(vcpu, pcsp) != vcpu_pcsp_base(vcpu, regs->stacks.pcsp) ||
		    vcpu_pcsp_size(vcpu, pcsp) != vcpu_pcsp_size(vcpu, regs->stacks.pcsp)) {
			DebugKVMGT("FAULT: source  PCSP: base 0x%llx size 0x%llx ind 0x%llx\n",
				vcpu_pcsp_base(vcpu, regs->stacks.pcsp),
				vcpu_pcsp_size(vcpu, regs->stacks.pcsp),
				vcpu_pcsp_ind(vcpu, regs->stacks.pcsp));
			DebugKVMGT("NOT updated    PCSP: base 0x%llx size 0x%llx ind 0x%llx\n",
				vcpu_pcsp_base(vcpu, pcsp), vcpu_pcsp_size(vcpu, pcsp),
				vcpu_pcsp_ind(vcpu, pcsp));
		}
	}
	{
		e2k_cr0_t cr0 = kvm_get_guest_vcpu_CR0(vcpu);
		e2k_cr1_t cr1 = kvm_get_guest_vcpu_CR1(vcpu);

		if (LO(cr0) != LO(regs->crs.cr0) ||
		    HI(cr0) != HI(regs->crs.cr0) ||
		    LO(cr1) != LO(regs->crs.cr1) ||
		    HI(cr1) != HI(regs->crs.cr1)) {
			DebugKVMGT("FAULT: source  CR0.lo 0x%016llx CR0.hi 0x%016llx CR1.lo. 0x%llx CR1.hi. 0x%llx\n",
				   LO(regs->crs.cr0), HI(regs->crs.cr0),
				   LO(regs->crs.cr1), HI(regs->crs.cr1));
			DebugKVMGT("NOT updated    CR0.lo 0x%016llx CR0.hi 0x%016llx CR1.lo 0x%llx CR1.hi 0x%llx\n",
				   LO(cr0), HI(cr0), LO(cr1), HI(cr1));
		}
	}
}
#else /* ! CHECK_GUEST_VCPU_UPDATES */
static inline void
check_guest_stack_regs_updates(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
}
#endif /* CHECK_GUEST_VCPU_UPDATES */

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
		if (wd.psize != regs->wd.psize) {
			DebugKVMGT("source  WD: size 0x%x\n", regs->wd.psize);
#endif /* CHECK_GUEST_VCPU_UPDATES */

			regs->wd.psize = wd.psize;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated WD: size 0x%x\n", regs->wd.psize);
		}
#endif /* CHECK_GUEST_VCPU_UPDATES */
	}
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, USD_UPDATED_CPU_REGS)) {
		unsigned long sbr = kvm_get_guest_vcpu_SBR_value(vcpu);
		e2k_usd_t usd = kvm_get_guest_vcpu_USD(vcpu);

#ifdef	CHECK_GUEST_VCPU_UPDATES
		if (LO(usd) != LO(regs->stacks.usd) ||
		    HI(usd) != HI(regs->stacks.usd) ||
		    sbr != regs->stacks.top) {
			DebugKVMGT("source  USD: base 0x%llx ind 0x%llx size 0x%llx\n",
				   vcpu_usd_base(vcpu, regs->stacks.usd),
				   vcpu_usd_ind(vcpu, regs->stacks.usd),
				   (u64) regs->stacks.top - vcpu_usd_base(vcpu, regs->stacks.usd));
#endif /* CHECK_GUEST_VCPU_UPDATES */

			regs->stacks.usd = usd;
			regs->stacks.top = sbr;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated USD: base 0x%llx ind 0x%llx size 0x%llx\n",
				   vcpu_usd_base(vcpu, regs->stacks.usd),
				   vcpu_usd_ind(vcpu, regs->stacks.usd),
				   (u64)regs->stacks.top - vcpu_usd_base(vcpu, regs->stacks.usd));
		}
#endif /* CHECK_GUEST_VCPU_UPDATES */
	}
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status,
					   HS_REGS_UPDATED_CPU_REGS)) {
		e2k_psp_t psp = kvm_get_guest_vcpu_PSP(vcpu);
		e2k_pcsp_t pcsp = kvm_get_guest_vcpu_PCSP(vcpu);

#ifdef	CHECK_GUEST_VCPU_UPDATES
		if (LO(psp) != LO(regs->stacks.psp) ||
		    HI(psp) != HI(regs->stacks.psp)) {
			DebugKVMGT("source  PSP:  base 0x%llx size 0x%llx ind 0x%llx\n",
				   vcpu_psp_base(vcpu, regs->stacks.psp),
				   vcpu_psp_size(vcpu, regs->stacks.psp),
				   vcpu_psp_ind(vcpu, regs->stacks.psp));
#endif /* CHECK_GUEST_VCPU_UPDATES */

			regs->stacks.psp = psp;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated PSP:  base 0x%llx size 0x%llx ind 0x%llx\n",
				   vcpu_psp_base(vcpu, regs->stacks.psp),
				   vcpu_psp_size(vcpu, regs->stacks.psp),
				   vcpu_psp_ind(vcpu, regs->stacks.psp));
		}
#endif /* CHECK_GUEST_VCPU_UPDATES */

#ifdef	CHECK_GUEST_VCPU_UPDATES
		if (LO(pcsp) != LO(regs->stacks.pcsp) ||
		    HI(pcsp) != HI(regs->stacks.pcsp)) {
			DebugKVMGT("source  PCSP: base 0x%llx size 0x%llx ind 0x%llx\n",
				   vcpu_pcsp_base(vcpu, regs->stacks.pcsp),
				   vcpu_pcsp_size(vcpu, regs->stacks.pcsp),
				   vcpu_pcsp_ind(vcpu, regs->stacks.pcsp));
#endif /* CHECK_GUEST_VCPU_UPDATES */

			regs->stacks.pcsp = pcsp;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated PCSP: base 0x%llx size 0x%llx ind 0x%llx\n",
				   vcpu_pcsp_base(vcpu, regs->stacks.pcsp),
				   vcpu_pcsp_size(vcpu, regs->stacks.pcsp),
				   vcpu_pcsp_ind(vcpu, regs->stacks.pcsp));
		}
#endif /* CHECK_GUEST_VCPU_UPDATES */
	}
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, CRS_UPDATED_CPU_REGS)) {
		e2k_cr0_t cr0 = kvm_get_guest_vcpu_CR0(vcpu);
		e2k_cr1_t cr1 = kvm_get_guest_vcpu_CR1(vcpu);

#ifdef	CHECK_GUEST_VCPU_UPDATES
		if (LO(cr0) != LO(regs->crs.cr0) ||
		    HI(cr0) != HI(regs->crs.cr0) ||
		    LO(cr1) != LO(regs->crs.cr1) ||
		    HI(cr1) != HI(regs->crs.cr1)) {
			DebugKVMGT("source  CR0.lo 0x%016llx CR0.hi 0x%016llx CR1.lo 0x%016llx CR1.hi 0x%016llx\n",
				   LO(regs->crs.cr0), HI(regs->crs.cr0),
				   LO(regs->crs.cr1), HI(regs->crs.cr1));
#endif /* CHECK_GUEST_VCPU_UPDATES */

			regs->crs.cr0 = cr0;
			regs->crs.cr1 = cr1;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated CR0.lo 0x%016llx CR0.hi 0x%016llx CR1.lo 0x%016llx CR1.hi 0x%016llx\n",
				   LO(regs->crs.cr0), HI(regs->crs.cr0),
				   LO(regs->crs.cr1), HI(regs->crs.cr1));
		}
#endif /* CHECK_GUEST_VCPU_UPDATES */
	}
	kvm_reset_guest_updated_vcpu_regs_flags(vcpu, regs_status);

check_updates:
	check_guest_stack_regs_updates(vcpu, regs);
}

int kvm_correct_guest_trap_return_ip(unsigned long return_ip, struct kvm *kvm)
{
	struct signal_stack_context __user *context;
	struct pt_regs __user *u_regs;
	e2k_cr0_t cr0 = (e2k_cr0_t) { 0 };
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
	set_cr0_ip(cr0, return_ip);

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);

	ret = __put_user(HI(cr0), &HI(u_regs->crs.cr0));

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
	return (trap_hndl_t) -ENOSYS;
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
__visible long /*__interrupt*/ goto_guest_kernel_ttable_C(long sys_num_and_entry,
						u64 arg1, u64 arg2, u64 arg3,
						u64 arg4, u64 arg5, u64 arg6)
{
	pr_err("%s() should not be called and need delete\n", __func__);
	return -ENOSYS;
}

int kvm_copy_hw_stacks_frames(struct kvm_vcpu *vcpu, void *dst, void *src,
			      long size, bool is_chain)
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
	e2k_cr0_t cr0 = read_CR0_reg();
	e2k_cr1_t cr1 = read_CR1_reg();

	/*
	 * Correct ip and psr value in top chain stack frame
	 * to return to guest ttable entry in unprivlidged mode
	 */
	set_cr0_ip(cr0, gst_fast_sys_call_trap);
	cr1.psr = E2K_USER_INITIAL_PSR.all;
	cr1.cui = KERNEL_CODES_INDEX;

	/* Write back new chain stack frame parameters to cr */
	write_CR0_ip(cr0);
	write_CR1_reg(cr1);

	return;
}

/*
 * Special host-side handler for fast guest syscalls
 *
 * __interupt since this is executed in fast syscall
 * so any exceptions are passed to guest, but guest
 * can't handle getsp that originated in hypervisor code.
 */
__section(".entry.text")
__interrupt  void notrace handle_guest_fast_sys_call(void)
{
	struct thread_info *ti = native_read_CURRENT_reg_value();
	struct kvm_vcpu *vcpu = ti->vcpu;

	pv_mmu_switch_to_fast_sys_call(vcpu, ti);
	HOST_VCPU_STATE_REG_SWITCH_TO_GUEST(vcpu);
	prepare_guest_fast_ttable_entry_crs(vcpu, GUEST_FAST_SYSCALL_TRAP_NUM);

	/* Pass control to guest fast syscall ttable entry */
	return;
}

/* Special host-side handler for compat fast guest syscalls */
__section(".entry.text")
void notrace handle_compat_guest_fast_sys_call(void)
{
	struct thread_info *ti = native_read_CURRENT_reg_value();
	struct kvm_vcpu *vcpu = ti->vcpu;

	pv_mmu_switch_to_fast_sys_call(vcpu, ti);
	HOST_VCPU_STATE_REG_SWITCH_TO_GUEST(vcpu);
	prepare_guest_fast_ttable_entry_crs(vcpu,
					    GUEST_COMPAT_FAST_SYSCALL_TRAP_NUM);

	/* Pass control to guest compat fast syscall ttable entry */
}
