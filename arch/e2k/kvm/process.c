/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file handles the arch-dependent parts of kvm process handling
 */

#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/tty.h>
#include <linux/freezer.h>
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/mman.h>

#include <asm/thread_info.h>
#include <asm/process.h>
#include <asm/traps.h>
#include <asm/syscalls.h>
#include <asm/mmu_context.h>
#include <asm/kvm/switch.h>
#include <asm/kvm/async_pf.h>

#include "process.h"
#include "cpu.h"
#include "mmu.h"
#include "io.h"
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include <asm/kvm/paravirt_sw/runstate.h>
#include "paravirt_sw/gaccess.h"
#include "paravirt_sw/mman.h"
#include "paravirt_sw/time.h"
# endif /* CONFIG_KVM_PARAVIRTUALIZATION */
#include "pic.h"
#include "../kernel/cpu/iset-kvm.h"

#include "mmutrace-e2k.h"
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include "paravirt_sw/trace-virq.h"
# endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_KERNEL_MODE
#undef	DebugKVMKS
#define	DEBUG_KVM_KERNEL_MODE	0	/* KVM process copy debugging */
#define	DebugKVMKS(fmt, args...)					\
({									\
	if (DEBUG_KVM_KERNEL_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_STARTUP_MODE
#undef	DebugKVMSTUP
#define	DEBUG_KVM_STARTUP_MODE	0	/* VCPU startup debugging */
#define	DebugKVMSTUP(fmt, args...)					\
({									\
	if (DEBUG_KVM_STARTUP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_VCPU_BOOTING_MODE
#undef	DebugBOOT
#define	DEBUG_VCPU_BOOTING_MODE	0	/* VCPU booting debugging */
#define	DebugBOOT(fmt, args...)						\
({									\
	if (DEBUG_VCPU_BOOTING_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_EXEC_MODE
#undef	DebugKVMEX
#define	DEBUG_KVM_EXEC_MODE	0	/* KVM execve() debugging */
#define	DebugKVMEX(fmt, args...)					\
({									\
	if (DEBUG_KVM_EXEC_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_CLONE_USER_MODE
#undef	DebugKVMCLN
#define	DEBUG_KVM_CLONE_USER_MODE	0	/* KVM thread clone debug */
#define	DebugKVMCLN(fmt, args...)					\
({									\
	if (DEBUG_KVM_CLONE_USER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_COPY_USER_MODE
#undef	DebugKVMCPY
#define	DEBUG_KVM_COPY_USER_MODE	0	/* KVM thread clone debugging */
#define	DebugKVMCPY(fmt, args...)					\
({									\
	if (DEBUG_KVM_COPY_USER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SIGNAL_STACK_MODE
#undef	DebugSIGST
#define	DEBUG_SIGNAL_STACK_MODE	0	/* signal stack debug */
#define	DebugSIGST(fmt, args...)					\
({									\
	if (DEBUG_SIGNAL_STACK_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_THREAD_INFO_MODE
#undef	DebugKVMTI
#define	DEBUG_KVM_THREAD_INFO_MODE	0	/* KVM thread info debug */
#define	DebugKVMTI(fmt, args...)					\
({									\
	if (DEBUG_KVM_THREAD_INFO_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_FREE_TASK_STRUCT_MODE
#undef	DebugFRTASK
#define	DEBUG_FREE_TASK_STRUCT_MODE	0	/* free thread info debug */
#define	DebugFRTASK(fmt, args...)					\
({									\
	if (DEBUG_FREE_TASK_STRUCT_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

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

#undef	DEBUG_KVM_SHUTDOWN_MODE
#undef	DebugKVMSH
#define	DEBUG_KVM_SHUTDOWN_MODE	0	/* KVM shutdown debugging */
#define	DebugKVMSH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SHUTDOWN_MODE || kvm_debug)			\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_IDLE_MODE
#undef	DebugKVMIDLE
#define	DEBUG_KVM_IDLE_MODE	0	/* KVM guest idle debugging */
#define	DebugKVMIDLE(fmt, args...)					\
({									\
	if (DEBUG_KVM_IDLE_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SHOW_GUEST_STACKS_MODE
#undef	DebugGST
#define	DEBUG_SHOW_GUEST_STACKS_MODE	true	/* show all guest stacks */
#define	DebugGST(fmt, args...)						\
({									\
	if (DEBUG_SHOW_GUEST_STACKS_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_TO_VIRT_MODE
#undef	DebugTOVM
#define	DEBUG_KVM_TO_VIRT_MODE	0	/* switch guest to virtual mode */
#define	DebugTOVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_TO_VIRT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_USER_STACK_MODE
#undef	DebugGUS
#define	DEBUG_KVM_USER_STACK_MODE	0	/* guest user stacks */
#define	DebugGUS(fmt, args...)						\
({									\
	if (DEBUG_KVM_USER_STACK_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_GUEST_MM_MODE
#undef	DebugGMM
#define	DEBUG_KVM_GUEST_MM_MODE	0	/* guest MM support */
#define	DebugGMM(fmt, args...)						\
({									\
	if (DEBUG_KVM_GUEST_MM_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_IMAGE_SIGNATURE_MODE
#undef	DebugIMSIG
#define	DEBUG_IMAGE_SIGNATURE_MODE	1	/* guest image signature */
#define	DebugIMSIG(fmt, args...)					\
({									\
	if (DEBUG_IMAGE_SIGNATURE_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_FREE_SIGNAL_STACK_MODE
#undef	DebugFreeSS
#define	DEBUG_FREE_SIGNAL_STACK_MODE	0	/* release of signal stack */
#define	DebugFreeSS(fmt, args...)					\
({									\
	if (DEBUG_FREE_SIGNAL_STACK_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SIG_HANDLER_MODE
#undef	DebugSIGH
#define	DEBUG_KVM_SIG_HANDLER_MODE	0	/* signal handler debug */
#define	DebugSIGH(fmt, args...)						\
({									\
	if (DEBUG_KVM_SIG_HANDLER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_LONG_JUMP_MODE
#undef	DebugLJMP
#define	DEBUG_KVM_LONG_JUMP_MODE	0	/* long jump debug */
#define	DebugLJMP(fmt, args...)						\
({									\
	if (DEBUG_KVM_LONG_JUMP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#define	SET_VCPU_BREAKPOINT	false

#ifdef	CONFIG_DATA_BREAKPOINT
atomic_t hw_data_breakpoint_num = ATOMIC_INIT(-1);
#endif /* CONFIG_DATA_BREAKPOINT */

static void kvm_reset_vcpu_thread(struct kvm_vcpu *vcpu)
{
	INIT_LIST_HEAD(&current_thread_info()->tasks_to_spin);
	current_thread_info()->gti_to_spin = NULL;
}

int kvm_init_vcpu_thread(struct kvm_vcpu *vcpu)
{
	char name[80];

	sprintf(name, "kvm/%d-vcpu/%d", vcpu->kvm->arch.vm_id, vcpu->vcpu_id);
	set_task_comm(current, name);
	vcpu->arch.host_task = current;
	task_thread_info(current)->is_vcpu = vcpu;

	kvm_reset_vcpu_thread(vcpu);

	DebugKVM("VCPU %d will be run as thread %px %s (%d) pgd %px\n",
		 vcpu->vcpu_id, current, current->comm, current->pid,
		 current->mm->pgd);
	return 0;
}

/*
 * FIXME: QEMU should pass physical addresses for entry IP and
 * for any addresses info into arguments list to pass to guest.
 * The function convert virtual physical adresses to physical
 * to enable VCPU startup at nonpaging mode
 */
void prepare_vcpu_startup_args(struct kvm_vcpu *vcpu)
{
	unsigned long entry_IP;
	u64 *args;
	int args_num, arg;
	unsigned long long arg_value;

	DebugKVMSTUP("started on VCPU #%d\n", vcpu->vcpu_id);

	if (is_paging(vcpu)) {
		DebugKVMSTUP("there is paging mode, nothing convertions need\n");
		return;
	}
	args_num = vcpu->arch.args_num;
	entry_IP = (unsigned long)vcpu->arch.entry_point;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (entry_IP >= GUEST_PAGE_OFFSET) {
		entry_IP = __guest_pa(entry_IP);
		vcpu->arch.entry_point = (void *)entry_IP;
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	DebugKVMSTUP("VCPU startup entry point at %px\n", (void *)entry_IP);

	args = vcpu->arch.args;

	/* prepare VCPU startup function arguments */
#pragma loop count (2)
	for (arg = 0; arg < args_num; arg++) {
		arg_value = args[arg];
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		if (arg_value >= GUEST_PAGE_OFFSET) {
			arg_value = __guest_pa(arg_value);
			args[arg] = arg_value;
		}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
		DebugKVMSTUP("   arg[%d] is 0x%016llx\n", arg, arg_value);
	}
}

/* Suspend vcpu thread until it will be woken up by pv_kick */
void kvm_pv_wait(struct kvm *kvm, struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/*
	 * If vcpu has pending VIRQs, do not put its thread
	 * into sleep. Exit from kvm_pv_wait to inject
	 * interrupt while hypercall returns.
	 */
	if (kvm_test_pending_virqs(vcpu))
		return;

	/* Update arch-dependent state of vcpu */
	kvm_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_blocked);
	/* For PV guest */
	vcpu->arch.on_idle = true;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	/* Suspend vcpu thread until it will be woken up by pv_kick */
	kvm_vcpu_block(vcpu);

	vcpu->arch.unhalted = false;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/* Restore arch-dependent state of vcpu */
	vcpu->arch.on_idle = false;
	kvm_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_hcall);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
}

/* Wake up sleeping vcpu thread */
int kvm_pv_kick(struct kvm *kvm, int cpu)
{
	struct kvm_vcpu *vcpu_to;

	/* Get vcpu by given cpu id */
	vcpu_to = kvm_get_vcpu_on_id(kvm, cpu);
	if (IS_ERR(vcpu_to))
		return PTR_ERR(vcpu_to);

	vcpu_to->arch.unhalted = true;

	/* Send wake up to target vcpu thread */
	kvm_vcpu_wake_up(vcpu_to);

	/* Yield our cpu to woken vcpu_to thread if possible */
	return kvm_vcpu_yield_to(vcpu_to);
}

void hv_vcpu_default_idle(void)
{
	if (machine.C1_enter)
		machine.C1_enter();
}

void hv_vcpu_wait_for_booting(int vcpu_id, physid_mask_t *vcpu_mask)
{
	mem_wait_vcpu_startup(vcpu_id, vcpu_mask);
}

void hv_vcpu_wait_for_wake_up(int vcpu_id, physid_mask_t *vcpu_mask)
{
	mem_wait_vcpu_wake_up(vcpu_id, vcpu_mask);
}

int hv_vcpu_activate(int vcpu_id)
{
	int ret;

	ret = HYPERVISOR_pv_kick(vcpu_id);
	if (likely(ret == 1)) {
		DebugBOOT("on vcpu #%d indeed boosted the target vcpu #%d\n",
			smp_processor_id(), vcpu_id);
	} else if (ret == 0) {
		DebugBOOT("on vcpu #%d : hypercall to kick vcpu #%d failed " \
			"to boost the target\n",
			smp_processor_id(), vcpu_id);
	} else if (ret == -ESRCH) {
		pr_err("%s() on vcpu #%d : hypercall to kick vcpu #%d failed " \
			"to boost the target, no such vcpu-process on host\n",
			__func__, smp_processor_id(), vcpu_id);
	} else if (ret < 0) {
		pr_err("%s() on vcpu #%d : hypercall to kick vcpu #%d failed, " \
			"unexpected error %d\n",
			__func__, smp_processor_id(), vcpu_id, ret);
	}
	return ret;
}

#ifdef CONFIG_KVM_ASYNC_PF

/*
 * Enable async page fault handling on current vcpu
 */
int kvm_pv_host_enable_async_pf(struct kvm_vcpu *vcpu,
				u64 apf_reason_gpa, u64 apf_id_gpa,
				u32 apf_ready_vector, u32 irq_controller)
{
	int ret, srcu_idx;

	srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);
	ret = kvm_gfn_to_hva_cache_init(vcpu->kvm, &vcpu->arch.apf.reason_gpa,
				apf_reason_gpa, sizeof(u32));
	ret = ret ?: kvm_gfn_to_hva_cache_init(vcpu->kvm, &vcpu->arch.apf.id_gpa,
				apf_id_gpa, sizeof(u32));
	srcu_read_unlock(&vcpu->kvm->srcu, srcu_idx);
	if (ret)
		return ret;

	vcpu->arch.apf.cnt = 1;
	vcpu->arch.apf.host_apf_reason = KVM_APF_NO;
	vcpu->arch.apf.in_pm = false;
	vcpu->arch.apf.apf_ready_vector = apf_ready_vector;
	vcpu->arch.apf.irq_controller = irq_controller;
	vcpu->arch.apf.enabled = true;

	return 0;
}

#endif /* CONFIG_KVM_ASYNC_PF */

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static int wait_for_discard(struct wait_bit_key *key, int mode)
{
	schedule();
	if (signal_pending_state(mode, current))
		return -ERESTARTSYS;
	return 0;
}

static inline void do_wait_for_print_vcpu_stack(struct kvm_vcpu *vcpu)
{
	DebugGST("started for VCPU #%d\n", vcpu->vcpu_id);
	if (kvm_start_vcpu_show_state(vcpu)) {
		/* show of VCPU state is already in progress */
		DebugGST("show of VCPU state is already in progress on VCPU #%d\n",
			vcpu->vcpu_id);
		return;
	}
	local_irq_enable();
	DebugGST("will send SYSRQ for VCPU #%d\n", vcpu->vcpu_id);
	kvm_pic_sysrq_deliver(vcpu);
	DebugGST("goto wait on bit of completion on for VCPU #%d\n",
		 vcpu->vcpu_id);

	do {
		int r;

		r = wait_on_bit_timeout((void *)&vcpu->requests,
					KVM_REG_SHOW_STATE, TASK_KILLABLE, 1);
		if (r == 0)
			break;
		r = wait_for_discard(NULL, TASK_KILLABLE);
		if (r == 0) {
			kvm_vcpu_yield_to(vcpu);
		} else {
			break;
		}
	} while (true);

	DO_DUMP_VCPU_STACK(vcpu) = false;
	DebugGST("waiting is completed for VCPU #%d\n", vcpu->vcpu_id);
}

static int wait_for_print_vcpu_stack(void *data)
{
	struct kvm_vcpu *vcpu = data;

	DebugGST("started for VCPU #%d\n", vcpu->vcpu_id);
	do_wait_for_print_vcpu_stack(vcpu);
	return 0;
}

static inline void do_wait_for_print_all_guest_stacks(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vcpu *other_vcpu;
	unsigned long r;

	mutex_lock(&kvm->lock);
	vcpu = kvm_get_vcpu(kvm, 0);
	if (vcpu == NULL) {
		mutex_unlock(&kvm->lock);
		DebugGST("nothing VCPUs detected\n");
		return;
	}
	DO_DUMP_VCPU_STATE(vcpu) = true;
	do_wait_for_print_vcpu_stack(vcpu);
	DO_DUMP_VCPU_STATE(vcpu) = false;
	kvm_for_each_vcpu(r, other_vcpu, kvm) {
		/* show state of the guest process on the VCPU */
		if (other_vcpu == NULL)
			continue;
		if (other_vcpu == vcpu)
			continue;
		DO_DUMP_VCPU_STACK(other_vcpu) = true;
		do_wait_for_print_vcpu_stack(other_vcpu);
	}
	if (!test_and_clear_kvm_mode_flag(kvm, KVMF_IN_SHOW_STATE)) {
		mutex_unlock(&kvm->lock);
		DebugGST("show of KVM state was not started\n");
		return;
	}
	mutex_unlock(&kvm->lock);
}

/* Send SYSRQ to vcpu 0 and exit */
static inline void do_nowait_print_all_guest_stacks(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;

	mutex_lock(&kvm->lock);
	vcpu = kvm_get_vcpu(kvm, 0);
	if (vcpu == NULL) {
		mutex_unlock(&kvm->lock);
		DebugGST("nothing VCPUs detected\n");
		return;
	}
	kvm_pic_sysrq_deliver(vcpu);
	if (!test_and_clear_kvm_mode_flag(kvm, KVMF_IN_SHOW_STATE)) {
		mutex_unlock(&kvm->lock);
		DebugGST("show of KVM state was not started\n");
		return;
	}
	mutex_unlock(&kvm->lock);
}

void wait_for_print_all_guest_stacks(struct work_struct *work)
{
	struct kvm *kvm;

	mutex_lock(&kvm_lock);
	if (list_empty(&vm_list)) {
		mutex_unlock(&kvm_lock);
		DebugGST("nothing VM detected\n");
		return;
	}
	list_for_each_entry(kvm, &vm_list, vm_list) {
		DebugGST("started for VM #%d\n", kvm->arch.vm_id);
		if (test_and_set_kvm_mode_flag(kvm, KVMF_IN_SHOW_STATE)) {
			DebugGST("show of VM #%d state is already in progress\n",
				kvm->arch.vm_id);
			continue;
		}
		if (kvm->arch.is_hv)
			do_nowait_print_all_guest_stacks(kvm);
		else
			do_wait_for_print_all_guest_stacks(kvm);
	}
	mutex_unlock(&kvm_lock);
}

static inline void deferred_print_vcpu_stack(struct kvm_vcpu *vcpu)
{
	struct task_struct *task;

	DebugGST("started for VCPU #%d\n", vcpu->vcpu_id);

	/* create thread to show state of guest current process on the VCPU */
	/* Function wait_for_print_all_guest_stacks() wait for print */
	/* so cannot be called directly from idle thread for example */
	if (!is_idle_task(current)) {
		task = kthread_create_on_node(wait_for_print_vcpu_stack, vcpu,
					      numa_node_id(),
					      "show-vcpu/%d", vcpu->vcpu_id);
		if (IS_ERR(task)) {
			pr_err("%s(): could not create thread to dump VCPU #%d current stack\n",
				__func__, vcpu->vcpu_id);
			return;
		}
		wake_up_process(task);
	} else {
		int pid;

		pid = kernel_thread(wait_for_print_vcpu_stack, vcpu,
				    CLONE_FS | CLONE_FILES);
		if (pid < 0) {
			pr_err("%s(): Could not create thread to dump VCPU #%d stack(s)\n",
				__func__, vcpu->vcpu_id);
			return;
		}
		rcu_read_lock();
		task = find_task_by_pid_ns(pid, &init_pid_ns);
		rcu_read_unlock();
		snprintf(task->comm, sizeof(task->comm),
			 "show-vcpu/%d", vcpu->vcpu_id);
	}
	DebugGST("created thread %s (%d) to wait for completion on VCPU #%d\n",
		task->comm, task->pid, vcpu->vcpu_id);
}

/* This could be called from IRQ context, so defer work instead of creating
 * kthread */
static inline void deferred_print_all_guest_stacks(void)
{
	DebugGST("started for all VMs\n");
	schedule_work(&kvm_dump_stacks);
	DebugGST("done\n");
}
#else
static void vcpu_inject_empty_tirs(struct kvm_vcpu *vcpu)
{
	vcpu->arch.intc_ctxt.coredump = true;
	kvm_vcpu_wake_up(vcpu);
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

void kvm_print_all_vm_stacks(void)
{
	if (!kvm_debug)
		return;

	mutex_lock(&kvm_lock);
	if (list_empty(&vm_list)) {
		mutex_unlock(&kvm_lock);
		DebugGST("nothing VM detected\n");
		return;
	}
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	deferred_print_all_guest_stacks();
#else
	struct kvm_vcpu *vcpu = current_thread_info()->vcpu;
	if (vcpu) {
		/* If called from guest then dump current VM only */
		vcpu_inject_empty_tirs(vcpu);
	} else {
		struct kvm *kvm;
		list_for_each_entry(kvm, &vm_list, vm_list) {
			struct kvm_vcpu *vcpu = kvm_get_vcpu(kvm, 0);
			if (!vcpu) {
				vcpu_inject_empty_tirs(vcpu);
			}
		}
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	mutex_unlock(&kvm_lock);
}
