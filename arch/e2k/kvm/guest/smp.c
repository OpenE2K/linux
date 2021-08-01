/*
 * This file implements the arch-dependent parts of kvm guest
 * csd_lock/csd_unlock functions to serialize access to per-cpu csd resources
 *
 * Copyright 2016 Salavat S. Guiliazov (atic@mcst.ru)
 */

#include <linux/types.h>
#include <linux/smp.h>
#include <linux/sched/debug.h>
#include <linux/sched/task.h>
#include <linux/err.h>

#include <asm/pic.h>
#include <asm/cpu.h>
#include <asm/smp-boot.h>
#include <asm/kvm/hypercall.h>
#include <asm/kvm/guest/irq.h>

#include "cpu.h"
#include "pic.h"

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

	ret = HYPERVISOR_guest_csd_lock_try_wait(data);
	if (ret == -EBUSY) {
		/* other VCPUs cannot handle IPI, try show all stacks */
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

	if (!(data->flags & CSD_FLAG_LOCK))
		return kvm_csd_lock_try_wait(data);
	while (data->flags & CSD_FLAG_LOCK) {
		ret = HYPERVISOR_guest_csd_lock_wait(data);
		if (ret == -EBUSY) {
			/* other VCPUs cannot handle IPI, try show all stacks */
			show_state();
			panic("could not handle IPI by all VCPUs\n");
		}
	}
}

void kvm_csd_lock(call_single_data_t *data)
{
	kvm_csd_lock_try_wait(data);

	/*
	 * prevent CPU from reordering the above assignment
	 * to ->flags with any subsequent assignments to other
	 * fields of the specified call_single_data_t structure:
	 */
	smp_mb();
	data->flags |= CSD_FLAG_LOCK;

	/* register lock wait guest on host */
	HYPERVISOR_guest_csd_lock(data);
}

void kvm_arch_csd_lock_async(call_single_data_t *data)
{
	data->flags = (CSD_FLAG_LOCK | CSD_FLAG_LOCK_ASYNC);

	/*
	 * prevent CPU from reordering the above assignment
	 * to ->flags with any subsequent assignments to other
	 * fields of the specified call_single_data_t structure:
	 */
	smp_mb();

	/* asynchronous lock need not register on host */
	/* HYPERVISOR_guest_csd_lock(data); */
}

void kvm_csd_unlock(call_single_data_t *data)
{
	unsigned int flags = data->flags;

	WARN_ON(!(flags & CSD_FLAG_LOCK));

	/* wake up sychronous lock waiting guest on host */
	if (!(flags & CSD_FLAG_LOCK_ASYNC))
		HYPERVISOR_guest_csd_unlock(data);

	/* ensure we're all done before releasing data */
	smp_mb();

	data->flags &= ~(CSD_FLAG_LOCK | CSD_FLAG_LOCK_ASYNC);
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

static __init int kvm_setup_boot_pic_virq(void)
{
	return kvm_setup_boot_local_pic_virq();
}
early_initcall(kvm_setup_boot_pic_virq);
#endif
