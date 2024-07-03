/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file implements the arch-dependent parts of kvm guest
 * csd_lock/csd_unlock functions to serialize access to per-cpu csd resources
 */

#include <linux/types.h>
#include <linux/smp.h>
#include <linux/sched/debug.h>
#include <linux/sched/task.h>
#include <linux/err.h>
#include <linux/processor.h>

#include <asm/pic.h>
#include <asm/cpu.h>
#include <asm/smp-boot.h>
#include <asm/kvm/hypercall.h>
#include <asm/kvm/guest/irq.h>
#include <asm/kvm/guest/host_printk.h>

#include "cpu.h"
#include "pic.h"

/* macros from kernel/smp.c */
#define CSD_TYPE(_csd)	((_csd)->node.u_flags & CSD_FLAG_TYPE_MASK)

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SWITCH_KERNEL_STACKS_MODE
#undef	DebugSWSTK
#define DEBUG_SWITCH_KERNEL_STACKS_MODE	0 /* switch to new kernel stacks */
#define	DebugSWSTK(fmt, args...)					\
({									\
	if (DEBUG_SWITCH_KERNEL_STACKS_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#define CREATE_TRACE_POINTS
#include "trace-csd-lock.h"

void kvm_ap_switch_to_init_stack(e2k_addr_t stack_base, int cpuid, int cpu)
{
	kvm_task_info_t	task_info;
	unsigned long args[2];
	e2k_addr_t us_base;
	e2k_addr_t ps_base;
	e2k_addr_t pcs_base;
	int ret;

	us_base = stack_base + KERNEL_C_STACK_OFFSET;
	ps_base = stack_base + KERNEL_P_STACK_OFFSET;
	pcs_base = stack_base + KERNEL_PC_STACK_OFFSET;

	task_info.sp_offset = KERNEL_C_STACK_SIZE;
	task_info.us_base = us_base;
	task_info.us_size = KERNEL_C_STACK_SIZE;
	task_info.flags = 0;
	DebugSWSTK("local data stack from 0x%lx size 0x%lx SP offset 0x%lx\n",
		task_info.us_base, task_info.us_size, task_info.sp_offset);

	BUG_ON(task_info.sp_offset > task_info.us_size);

	task_info.ps_base = ps_base;
	task_info.ps_ind = 0;
	task_info.ps_size = KERNEL_P_STACK_SIZE;
	DebugSWSTK("procedure stack from 0x%lx size 0x%lx, index 0x%lx\n",
		task_info.ps_base, task_info.ps_size, task_info.ps_ind);

	task_info.pcs_base = pcs_base;
	task_info.pcs_ind = 0;
	task_info.pcs_size = KERNEL_PC_STACK_SIZE;
	DebugSWSTK("procedure chain stack from 0x%lx size 0x%lx, index 0x%lx\n",
		task_info.pcs_base, task_info.pcs_size, task_info.pcs_ind);

	args[0] = cpuid;
	args[1] = cpu;

	ret = HYPERVISOR_switch_guest_kernel_stacks(&task_info,
				(char *) &e2k_start_secondary_switched_stacks,
				args, 2);
	if (ret < 0) {
		panic("%s(): could not switch to init kernel stacks, "
			"error %d\n",
			__func__, ret);
	}
}

void kvm_setup_secondary_task(int cpu)
{
	struct task_struct *idle = idle_tasks[cpu];
	struct thread_info *ti_idle;
	int ret;

	native_setup_secondary_task(cpu);

	/* setup the idle task on host (get GPID_ID #) */
	ret = HYPERVISOR_setup_idle_task(cpu);
	if (ret < 0) {
		panic("%s(): could not setup CPU #%d idle task on host, "
			"error %d\n",
			__func__, cpu, ret);
	}
	ti_idle = task_thread_info(idle);
	ti_idle->gpid_nr = ret;
	ti_idle->gmmid_nr = 0;	/* init mm should have GMMID == 0 */
}

void kvm_stop_this_cpu_ipi(void *dummy)
{
	raw_all_irq_disable();

	set_cpu_online(smp_processor_id(), false);

	spin_begin();

	/* IRQs should be enabled to handle pending VIRQs */
	raw_all_irq_enable();

	do {
		spin_cpu_relax();
	} while (true);

	spin_end();
}

/*
 * The function implements asynchronous wait for csd lock unlocking.
 * In this case csd_lock_wait() has not explicit call and waiting will be
 * started only while next csd lock using. So previous lock can be unlocked
 * and queued as unlocked csd lock on host. The host function should dequeue
 * and free this csd lock.
 */
static inline void kvm_csd_lock_try_wait(call_single_data_t *data)
{
	int ret;

	trace_kvm_csd_lock_try_wait(data, CSD_LOCK_TRY_WAIT_CTL,
				NATIVE_NV_READ_CR0_HI_REG().CR0_hi_IP);
	ret = HYPERVISOR_guest_csd_lock_try_wait(data);
	if (ret == -EBUSY) {
		/* other VCPUs cannot handle IPI, try show all stacks */
		trace_kvm_csd_ctl_failed(data, CSD_LOCK_TRY_WAIT_CTL, ret);
		if (kvm_get_vcpu_state()->do_dump_state) {
			kvm_get_vcpu_state()->do_dump_state = false;
			show_state();
		} else if (kvm_get_vcpu_state()->do_dump_stack) {
			kvm_get_vcpu_state()->do_dump_stack = false;
			dump_stack();
		}
		panic("could not handle IPI by all VCPUs\n");
	}
}

/*
 * csd lock can be already unlocked, flag CSD_FLAG_LOCK cleared and
 * the lock queued as unlocked on host. In this case it need dequeue the lock,
 * so should be call try waiting
 */
void kvm_csd_lock_wait(call_single_data_t *data)
{
	int ret;

	do {
		trace_kvm_csd_lock_wait(data, CSD_LOCK_WAIT_CTL,
				NATIVE_NV_READ_CR0_HI_REG().CR0_hi_IP);
		ret = HYPERVISOR_guest_csd_lock_wait(data);
		if (likely(ret == 0)) {
			break;
		} else if (ret == -EAGAIN) {
			/* lock was interrupted to handle pending virqs */
			/* and support interprocessors IPI towards each other */
			trace_kvm_csd_ctl_failed(data, CSD_LOCK_WAIT_CTL, ret);
			continue;
		} else if (ret == -EBUSY) {
			/* other VCPUs cannot handle IPI */
			trace_kvm_csd_ctl_failed(data, CSD_LOCK_WAIT_CTL, ret);
			panic("%s(): could not handle IPI by all VCPUs\n",
				__func__);
			break;
		}
	} while (true);
	smp_cond_load_acquire(&data->flags, !(VAL & CSD_FLAG_LOCK));
}

void kvm_csd_lock(call_single_data_t *data)
{
	int ret;

	if (likely(!(smp_load_acquire(&data->flags) & CSD_FLAG_LOCK))) {
		/* lock should be already released and in the host queue */
		/* and need be unqueued or lock is free */
		kvm_csd_lock_try_wait(data);
	} else {
		/* lock has been taken and need wait for release */
		kvm_csd_lock_wait(data);
	}

	/*
	 * prevent CPU from reordering the above assignment
	 * to ->flags with any subsequent assignments to other
	 * fields of the specified call_single_data_t structure:
	 */
	smp_mb();
	data->node.u_flags |= CSD_FLAG_LOCK | CSD_TYPE_SYNC;

	/* register lock wait guest on host */
	trace_kvm_csd_lock(data, CSD_LOCK_CTL,
		NATIVE_NV_READ_CR0_HI_REG().CR0_hi_IP);

	ret = HYPERVISOR_guest_csd_lock(data);
	if (ret != 0) {
		/* other VCPUs cannot handle IPI */
		trace_kvm_csd_ctl_failed(data, CSD_LOCK_CTL, ret);
		panic("%s(): could not handle IPI by all VCPUs\n",
			__func__);
	}
	trace_kvm_csd_ctl_succeeded(data, CSD_LOCK_CTL);
}

void kvm_arch_csd_lock_async(call_single_data_t *data)
{
	data->flags = (CSD_FLAG_LOCK | CSD_TYPE_ASYNC);

	/*
	 * prevent CPU from reordering the above assignment
	 * to ->flags with any subsequent assignments to other
	 * fields of the specified call_single_data_t structure:
	 */
	smp_mb();

	/* asynchronous lock need not register on host */
	/* HYPERVISOR_guest_csd_lock(data); */
	trace_kvm_csd_lock(data, CSD_LOCK_CTL,
			NATIVE_NV_READ_CR0_HI_REG().CR0_hi_IP);
}

void kvm_csd_unlock(call_single_data_t *data)
{
	unsigned int flags = data->flags;
	unsigned int csd_type;

	csd_type = CSD_TYPE(data);

	WARN_ON(!(flags & CSD_FLAG_LOCK));

	/* wake up sychronous lock waiting guest on host */
	if (likely(csd_type != CSD_TYPE_ASYNC)) {
		int ret;

		trace_kvm_csd_unlock(data, CSD_UNLOCK_CTL,
				NATIVE_NV_READ_CR0_HI_REG().CR0_hi_IP);
		ret = HYPERVISOR_guest_csd_unlock(data);
		if (ret != 0) {
			/* other VCPUs cannot handle IPI */
			trace_kvm_csd_ctl_failed(data, CSD_UNLOCK_CTL, ret);
			panic("%s(): could not handle IPI by all VCPUs\n",
				__func__);
		}
	}

	/* ensure we're all done before releasing data */
	smp_mb();

	data->node.u_flags &= ~(CSD_FLAG_LOCK | CSD_FLAG_TYPE_MASK);
	trace_kvm_csd_ctl_succeeded(data, CSD_UNLOCK_CTL);
}

void kvm_setup_pic_virq(unsigned int cpuid)
{
	kvm_setup_local_pic_virq(cpuid);
}
void kvm_startup_pic_virq(unsigned int cpuid)
{
	kvm_startup_local_pic_virq(cpuid);
}

void kvm_setup_local_apic_virq(unsigned int cpuid)
{
}
void kvm_startup_local_apic_virq(unsigned int cpuid)
{
	kvm_setup_secondary_lapic_virq(cpuid);
	setup_secondary_APIC_clock();
	store_cpu_info(cpuid);

	/* complete creation of idle task fot this virtual CPU */
	init_idle(current, cpuid);
}

#ifdef CONFIG_EPIC
void kvm_setup_epic_virq(unsigned int cpuid)
{
}

void kvm_startup_epic_virq(unsigned int cpuid)
{
	setup_secondary_epic_clock();
	store_cpu_info(cpuid);

	/* complete creation of idle task fot this virtual CPU */
	init_idle(current, cpuid);
}
#endif

