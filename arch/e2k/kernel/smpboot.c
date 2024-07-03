/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * E2K SMP booting functions
 *
 * Much of the core SMP work is based on previous work by Thomas Radke, to
 * whom a great many thanks are extended.
 */

#include <linux/delay.h>
#include <linux/smpboot.h>
#include <linux/sched/mm.h>

#include <asm/pic.h>
#include <asm/cpu.h>
#include <asm/console.h>
#include <asm/boot_profiling.h>
#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <asm/sic_regs_access.h>
#include <asm/smp-boot.h>
#include <asm/qspinlock.h>
#include <asm/regs_state.h>
#include <asm-l/hw_irq.h>


#define DEBUG_SMP_BOOT_MODE	0	/* SMP Booting process */
#define DebugSMPB(...)		DebugPrint(DEBUG_SMP_BOOT_MODE ,##__VA_ARGS__)


/*
 * A small decription of what functions in this file do.
 *
 *
 * SMP boot process:
 *
 * 1) Bootstrap processor (BSP) calls start_kernel() and initializes
 * the most basic things while all other cpus spin in e2k_start_secondary()
 * on callin_go cpumask waiting for the signal from BSP.
 *
 * 2) BSP calls cpu_up() for every other cpu in the system. cpu_up()
 * calls architecture-dependent __cpu_up() which does the following:
 *
 * 	2.1) Creates idle task structure on that cpu.
 *
 * 	2.2) Sets the corresponding bit in the callin_go cpumask.
 *
 * 	3.3) Waits until the cpu sets the corresponding bit in the
 * 	cpu_online_mask cpumask.
 *
 * 3) After 2.2 secondary cpus set up idle task struct (created by
 * BSP in 2.1), initialize LAPIC and some other things like clearing
 * themselves from callin_go which is needed for hotplug.
 *
 * 4) BSP goes on with the initialization, other CPUs call cpu_idle().
 */

static int bsp_cpu;
cpumask_t callin_go;

static int old_num_online_cpus;


void native_wait_for_cpu_booting(void)
{
	/* all waitings on real CPU */
}
void native_wait_for_cpu_wake_up(void)
{
	/* all waitings on real CPU */
}
int native_activate_cpu(int cpu_id)
{
	/* all waitings on real CPUs, so nothing to activate */
	return 0;
}
int native_activate_all_cpus(void)
{
	/* all waitings on real CPUs, so nothing to activate */
	return 0;
}


/* Used solely to pass pointer from cpu_up() running on BSP
 * to e2k_start_secondary() running on AP */
struct task_struct *idle_tasks[NR_CPUS];

/*
 * Setup idle task structure for secondary CPU
 */
void native_setup_secondary_task(int cpu)
{
	struct task_struct *idle = idle_tasks[cpu];

	set_current_thread_info(task_thread_info(idle), idle);

	/*
	 * Init thread structure
	 */
	thread_init();

	/*
	 * All kernel threads share the same mm context.
	 */
	mmgrab(&init_mm);
	current->active_mm = &init_mm;
	BUG_ON(current->mm);
}

void wait_for_startup(int cpuid, int hotplug)
{
	do {
		wait_for_cpu_booting();
		if (!cpu_has(CPU_HWBUG_C3) && hotplug && machine.clk_off)
			machine.clk_off();
	} while (!cpumask_test_cpu(cpuid, &callin_go));
}

void __init_recv e2k_setup_secondary_apic(void)
{
#ifdef CONFIG_L_LOCAL_APIC
	/*
	 * Set up the local APIC of the AP CPU
	 */
	setup_local_APIC();
	end_local_APIC_setup();
#endif
}

void e2k_start_secondary_switched_stacks(int cpuid, int cpu)
{
#ifdef CONFIG_L_LOCAL_APIC
	int phys_id;
#endif /* CONFIG_L_LOCAL_APIC */

	/*
	 * This works even if the APIC is not enabled
	 */
#ifdef CONFIG_L_LOCAL_APIC
	phys_id = read_pic_id();
	if (phys_id != cpuid) {
		INIT_BUG("boot bug, CPU #%d is not the same as ID #%d\n",
			cpuid, phys_id);
	}
#endif /* CONFIG_L_LOCAL_APIC */

	set_smp_processor_id(cpu);

	/* By now percpu areas should have been initialized by BSP */
	set_my_cpu_offset(__per_cpu_offset[cpu]);

	/* cpumask_of_node() and cpu_to_node() initialization */
	set_numa_node(early_cpu_to_node(cpu));
	numa_add_cpu(cpu);

	trap_init();

	this_cpu_write(u_root_ptb, __pa(mm_node_pgd(&init_mm, numa_node_id())));

	/*
	 * The BSP has finished the init stage and is spinning on
	 * cpu_online_mask until we finish. We are free to set up this
	 * CPU, first the init_task structure for this CPU.
	 */
#ifdef CONFIG_L_LOCAL_APIC
	if (!physid_isset(phys_id, phys_cpu_present_map)) {
		INIT_WARNING("boot bug, CPU #%d ID #%d is not present in physical CPU bitmap 0x%lx\n",
			cpuid, phys_id,
			physids_coerce(&phys_cpu_present_map));
		physid_set(phys_id, phys_cpu_present_map);
	}
#endif

	setup_secondary_task(cpu);

	set_secondary_space_MMU_state();

	/*
	 * By this point BSP has already cleared and write-protected
	 * ZERO_PAGE, so flush it from TLB
	 */
	flush_TLB_page((unsigned long) empty_zero_page,
						E2K_KERNEL_CONTEXT);

	/*
	 * init_idle_preempt_count() in e2k set preemt count in register of current cpu,
	 * so we need to stay preempt_disable() here and not perform it in
	 * init_idle_preempt_count(). See 3c51d82d0b7862d7d246016c74b4390fb1fa1f11 for
	 * understanding as it should be.
	 */
	WARN_ON(preempt_count());
	preempt_disable();

	DebugSMPB("e2k_start_secondary, before e2k_setup_secondary_pic().\n");
	e2k_setup_secondary_pic();

	DebugSMPB("Stack at about %px\n", &cpuid);

	/*
	 * Paravirt guest should not enable PIC timer (guest handler is not yet started)
	 */
	if (!(paravirt_enabled() && !IS_HV_GM())) {
		setup_secondary_pic_clock();
		store_cpu_info(cpu);
	}

	__setup_vector_irq(cpu);

	smp_wmb();
	notify_cpu_starting(cpu);

	/* Allow BSP to continue */
	DebugSMPB("CPU #%d set bit in cpu_online_mask\n", cpuid);
	set_cpu_online(cpu, true);

	/* secondary CPU Local PIC VIRQs handler can be now started up */
	startup_local_pic_virq(cpu);

	/* wake up BSP CPU waiting for this CPU start up */
	wmb();
	activate_cpu(bsp_cpu);

	cpumask_clear_cpu(cpuid, &callin_go);

	local_irq_enable();

	BOOT_TRACEPOINT("e2k_start_secondary finished, going to cpu_idle()");

	/*
	 * Processor should go to idle task
	 */
	DebugSMPB("CPU #%d call cpu_idle()\n", cpuid);
	wmb();
	cpu_startup_entry(CPUHP_AP_ONLINE_IDLE);

	BUG();
}

/*
 * Activate a secondary processor.
 */
void e2k_start_secondary(int cpuid)
{
	struct task_struct *idle;
	unsigned long stack_base;
	int cpu;

	wait_for_startup(cpuid, 0);

	DebugSMPB("secondary CPU #%d started up()\n", cpuid);

	/*
	 * Paired with smp_wmb() in e2k_smp_boot_cpu()
	 */
	smp_rmb();

	/*
	 * Now switch to properly allocated stack (with proper size and node)
	 */
	cpu = cpuid_to_cpu(cpuid);
	idle = idle_tasks[cpu];
	stack_base = (unsigned long) idle->stack;
	BUG_ON(!stack_base);
	ap_switch_to_init_stack(stack_base, cpuid, cpu);
}

#ifdef CONFIG_HOTPLUG_CPU
/* Reset stacks and call start_secondary */
void start_secondary_resume(int cpuid, int cpu)
{
	unsigned long stack_base = (unsigned long) idle_tasks[cpu]->stack;

	/* Drop any mappings that could have been invalidated
	 * while this CPU was offline */
	local_flush_tlb_all();

	BUG_ON(!stack_base);
	NATIVE_SWITCH_TO_KERNEL_STACK(
		stack_base + KERNEL_P_STACK_OFFSET, KERNEL_P_STACK_SIZE,
		stack_base + KERNEL_PC_STACK_OFFSET, KERNEL_PC_STACK_SIZE,
		stack_base + KERNEL_C_STACK_OFFSET, KERNEL_C_STACK_SIZE - KERNEL_PT_REGS_SIZE);

	E2K_JUMP_WITH_ARGUMENTS(e2k_start_secondary_switched_stacks, 2,
			cpuid, cpu);
}
#endif

/*
 * Various sanity checks.
 */
static int __init smp_sanity_check(unsigned max_cpus)
{
	preempt_disable();

	/*
	 * If we couldn't find an SMP configuration at boot time,
	 * get out of here now!
	 */
	if (!smp_found_config) {
		preempt_enable();
		pr_err("SMP motherboard not detected.\n");
		return -1;
	}

	/*
	 * Should not be necessary because the MP table should list the boot
	 * CPU too, but we do it for the sake of robustness anyway.
	 */
	if (!apic->check_phys_apicid_present(boot_cpu_physical_apicid)) {
		pr_err("weird, boot CPU (#%d) not listed by the BIOS.\n",
			boot_cpu_physical_apicid);
		physid_set(hard_smp_processor_id(), phys_cpu_present_map);
	}
	preempt_enable();

	/*
	 * If SMP should be disabled, then really disable it!
	 */
	if (!max_cpus) {
		pr_info("SMP mode deactivated.\n");
		return -1;
	}

	return 0;
}

/*
 * Called by smp_init prepare the secondaries
 */
void __init smp_prepare_cpus(unsigned int max_cpus)
{
	int cpu;
	int timeout;

	pr_info("BSP %s ID: %d\n", cpu_has_epic() ? "EPIC" : "APIC",
		boot_cpu_physical_apicid);

	/*
	 * Wait 5 sec. total for all other CPUs will be ready to do
	 * own sequences of initialization
	 */
	for (timeout = 0; timeout < 50000; timeout++) {
		if (num_present_cpus() >= phys_cpu_present_num)
			/* all CPU are in the 'e2k_start_secondary()'
			 * function */
			break;
		udelay(100);
	}
	if (num_present_cpus() < phys_cpu_present_num) {
		pr_err("Only %d CPU(s) from %d has booted\n",
			num_present_cpus(), phys_cpu_present_num);
		for (cpu = 0; cpu < NR_CPUS; cpu++) {
			if (!cpu_present(cpu))
				pr_err("CPU #%d has not booted!\n", cpu);
		}
	}

	smp_sanity_check(max_cpus);

	preempt_disable();
	if (read_pic_id() != boot_cpu_physical_apicid) {
		pr_err("local PIC id #%d of bootstrap CPU is not #%d\n",
				read_pic_id(),
				boot_cpu_physical_apicid);
		BUG();
	}
	preempt_enable();

	DebugSMPB("CPU present number is %d, physical map: 0x%lx\n",
		phys_cpu_present_num, physids_coerce(&phys_cpu_present_map));
}

static int e2k_smp_boot_cpu(unsigned int cpu, int hotplug)
{
	int cpuid = cpu_to_cpuid(cpu);

	if (!cpu_present(cpu)) {
		DebugSMPB("AP CPU #%d does not present\n", cpu);
		return -ENOSYS;
	}

	/* bootstrap CPU can only setup Local PIC VIRQs handler */
	if (!hotplug)
		setup_local_pic_virq(cpu);

	WARN_ON(raw_irqs_disabled());

	/*
	 * Paired with smp_rmb() in e2k_start_secondary()
	 */
	smp_wmb();

	cpumask_set_cpu(cpuid, &callin_go);

	/* Barrier between write to callin_go and sending
	 * a wakeup (be it machine.clk_on or a hypercall) */
	wmb();
	activate_cpu(cpuid);

	if (hotplug && machine.clk_on)
		machine.clk_on(cpu);

	DebugSMPB("wait for CPU %d to come online\n", cpu);
	while (!cpu_online(cpu) || cpumask_test_cpu(cpuid, &callin_go))
		wait_for_cpu_wake_up();

	DebugSMPB("finished for CPU #%d\n", cpu);
	return 0;
}

void __init smp_prepare_boot_cpu(void)
{
	int cpu = smp_processor_id();

	/* Set per_cpu area pointer */
	set_my_cpu_offset(__per_cpu_offset[smp_processor_id()]);

	/* cpumask_of_node() and cpu_to_node() initialization */
	set_numa_node(early_cpu_to_node(cpu));
	numa_add_cpu(cpu);

#ifdef CONFIG_PARAVIRT_SPINLOCKS
	/*
	 * Allocate "PV qspinlock" global hash table used by paravirt spinlocks
	 */
	if (IS_HV_GM())
		__pv_init_lock_hash();
#endif /* CONFIG_PARAVIRT_SPINLOCKS */
}

int __cpu_up(unsigned int cpu, struct task_struct *tidle)
{
	int hotplug = (system_state >= SYSTEM_RUNNING);
	int ret;

	idle_tasks[cpu] = tidle;

	/* Initialize the softirq stacks */
	ret = irq_init_percpu_irqstack(cpu);
	if (ret)
		return ret;

	return e2k_smp_boot_cpu(cpu, hotplug);
}

/* number of CPUs arrived to sync while boot-time init completion */
cpu_sync_count_t ____cacheline_aligned_in_smp init_num_arrived = {.pad = 0};

void __init smp_cpus_done(unsigned int max_cpus)
{
	if (!smp_found_config)
		return;

	if (num_online_cpus() < min(num_present_cpus(), max_cpus)) {
		pr_err("Only %d CPU(s) from %d has completed initialization\n",
				num_online_cpus(), min(num_present_cpus(),
						max_cpus ? max_cpus : 1));
	}

	pr_info("Total of %d processors activated\n", num_online_cpus());

	setup_ioapic_dest();
	setup_processor_pic();

	old_num_online_cpus = num_online_cpus();

	DebugSMPB("finished\n");
}
