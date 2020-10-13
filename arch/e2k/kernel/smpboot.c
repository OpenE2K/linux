/*
 * E2K SMP booting functions
 *
 * Much of the core SMP work is based on previous work by Thomas Radke, to
 * whom a great many thanks are extended.
 */

#include <linux/init.h>
#include <linux/hrtimer.h>
#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/irq.h>
#include <linux/bootmem.h>
#include <linux/smp.h>
#include <linux/notifier.h>
#include <linux/percpu.h>
#include <linux/tick.h>
#include <linux/delay.h>
#include <linux/mc146818rtc.h>

#include <asm/cpu.h>
#include <asm/processor.h>
#include <asm/process.h>
//#include <asm/mtrr.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>
#ifdef	CONFIG_RECOVERY
#include <asm/boot_recovery.h>
#endif	/* CONFIG_RECOVERY */
#include <asm/tlbflush.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>

#include <asm/lms.h>
#include <asm/e3m.h>
#include <asm/e3s_lms.h>
#include <asm/e3s.h>
#include <asm/timer.h>
#include <asm/console.h>
#include <asm/clk_gate.h>

#undef	DEBUG_SMP_BOOT_MODE
#undef	DebugSMPB
#undef	IDebugSMPB
#define	DEBUG_SMP_BOOT_MODE	0	/* SMP Booting process */
#define DebugSMPB(...)		DebugPrint(DEBUG_SMP_BOOT_MODE ,##__VA_ARGS__)
#define	IDebugSMPB		if (DEBUG_SMP_BOOT_MODE) do_boot_printk

#undef DEBUG_HTPL_MODE
#undef DebugHTPL
#define DEBUG_HTPL_MODE		0	/* Debug hotplug */
#define DebugHTPL		if (DEBUG_HTPL_MODE) do_boot_printk

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
 * themselves from callin_go which is needed for recovery and hotplug.
 *
 * 4) BSP goes on with the initialization, other CPUs call cpu_idle().
 *
 *
 * SMP recovery process:
 *
 * 1) Bootstrap processor (BSP) calls recover_kernel() and initializes
 * the most basic things while all other cpus spin in e2k_start_secondary()
 * on callin_go cpumask waiting for the signal from BSP.
 *
 * 2) BSP calls cpu_recover() for every other cpu in the system which
 * does the following:
 *
 * 	2.1) Sets the corresponding bit in the callin_go cpumask.
 *
 * 	2.2) Waits until the cpu sets the corresponding bit in the
 * 	cpu_online_mask cpumask.
 *
 * 3) After 2.2 secondary CPUs initialize LAPIC and some other things
 * like clearing themselves from callin_go which is needed for recovery
 * and hotplug.
 *
 * 4) BSP and all other CPUs return to the interrupted tasks
 * (setting on the way some more resume work for the recovery
 * daemon to do).
 */

extern ktime_t tick_period;

static cpumask_t callin_go;
static cpumask_t cpu_disabled_map;

#ifdef	CONFIG_NUMA
nodemask_t __nodedata	node_has_dup_kernel_map;
atomic_t __nodedata	node_has_dup_kernel_num = ATOMIC_INIT(0);
int __nodedata		all_nodes_dup_kernel_nid[MAX_NUMNODES];
#ifndef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
pgd_t 	__nodedata	*all_nodes_pg_dir[MAX_NUMNODES];
#else	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
pg_dir_t __nodedata	*all_nodes_pg_dir[MAX_NUMNODES];
#endif	/* ! ONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
#endif	/* CONFIG_NUMA */

/*
 * State for each CPU
 */
DEFINE_PER_CPU(int, cpu_state);

/*
 * Per CPU bogomips and other parameters
 */
extern cpuinfo_e2k_t cpu_data[NR_CPUS];

static int old_num_online_cpus;

struct task_struct *init_tasks[NR_CPUS] = {0};


static u8 cpu_to_logical_apicid[NR_CPUS] = { [0 ... NR_CPUS-1] = BAD_APICID };

static void map_cpu_to_logical_apicid(void)
{
	int cpu = smp_processor_id();
	int apicid = logical_smp_processor_id();

	cpu_to_logical_apicid[cpu] = apicid;
}

static inline
int get_logical_apicid_for_cpu(int cpu)
{
	return cpu_to_logical_apicid[cpu];
}

#ifdef	CONFIG_NUMA
/*
 * Which logical CPUs are on which nodes
 */
cpumask_t node_to_cpumask_map[MAX_NUMNODES];
EXPORT_SYMBOL(node_to_cpumask_map);

/*
 * Allocate node_to_cpumask_map based on node_online_map
 * Requires cpu_online_mask to be valid.
 */
void __init_recv setup_node_to_cpumask_map(void)
{
	int node;

	for (node = 0; node < MAX_NUMNODES; node ++) {
		cpumask_clear(&node_to_cpumask_map[node]);
	}
	for_each_online_node(node) {
		node_to_cpumask_map[node] = node_to_cpumask(node);
	}
}
#endif	/* CONFIG_NUMA */

/*
 * Create idle task structure for secondary CPU
 */
static void create_secondary_task(int cpuid)
{
	struct task_struct *idle;

	DebugSMPB("started for CPU %d\n", cpuid);

	set_ts_flag(TS_IDLE_CLONE);
	ts_set_clone_node(current_thread_info(), cpu_to_node(cpuid));
	idle = fork_idle(cpuid);
	ts_clear_clone_node(current_thread_info());
	clear_ts_flag(TS_IDLE_CLONE);
	if (IS_ERR(idle)) {
		INIT_BUG_POINT("create_secondary_task()");
		INIT_BUG("CPU#%d could not allocate idle task structure for "
			"secondary CPU\n",
			cpuid);
	}

	init_tasks[cpuid] = idle;

	DebugSMPB("finished\n");
}

/*
 * Setup idle task structure for secondary CPU
 */
static void __init_recv
setup_secondary_task(int cpuid)
{
	struct task_struct *idle;

	IDebugSMPB("setup_secondary_task() started for cpu %d\n", cpuid);

	idle = init_tasks[cpuid];
	set_current_thread_info(task_thread_info(idle), idle);

	/*
	 * Init thread structure
	 * We need to move all from thread struct to thread_info struct
	 */
	thread_init();

	/*
	 * All kernel threads share the same mm context.
	 */
	atomic_inc(&init_mm.mm_count);
	current->active_mm = &init_mm;

	IDebugSMPB("setup_secondary_task() finished\n");
}

#ifdef CONFIG_HOTPLUG_CPU
static int do_clk_on(int cpuid) {

	int nid;

	if (!IS_MACHINE_ES2 &&
	    !IS_MACHINE_E2S)
		return 0;

	if (IS_MACHINE_ES2) {
		e2k_pwr_mgr_struct_t pwr_mgr;

		nid = cpu_to_node(cpuid);
		pwr_mgr.E2K_PWR_MGR0_reg = early_sic_read_node_nbsr_reg(nid,
								SIC_pwr_mgr);

		if (cpuid & 0x1)
			pwr_mgr.E2K_PWR_MGR0_core1_clk = 1;
		else
			pwr_mgr.E2K_PWR_MGR0_core0_clk = 1;

		early_sic_write_node_nbsr_reg(nid, SIC_pwr_mgr,
						pwr_mgr.E2K_PWR_MGR0_reg);
	} else if (IS_MACHINE_E2S) {
		do_e2s_clk_on(cpuid);
	} else if (IS_MACHINE_E8C) {
		do_e8c_clk_on(cpuid);
	}

	return 0;
}

#define ES2_IB_TERM_DELAY 4096 /* in loops */
#define ES2_CLK_TERM_DELAY 8192  /* in loops */
#define ES2_HTPL_SNOOP_WAIT_512                0
#define ES2_HTPL_SNOOP_WAIT_1024       1
#define ES2_HTPL_SNOOP_WAIT_1536       2
#define ES2_HTPL_SNOOP_WAIT_2048       3

#define E2S_IB_TERM_DELAY ES2_IB_TERM_DELAY
#define E2S_CLK_TERM_DELAY ES2_CLK_TERM_DELAY
#define E8C_IB_TERM_DELAY ES2_IB_TERM_DELAY
#define E8C_CLK_TERM_DELAY ES2_CLK_TERM_DELAY

/* In real case (Cubic) - point of non-return. */
static void do_clk_off(int cpuid) {

	int nid;
	int i;
	unsigned int value;

	if (!IS_MACHINE_ES2 &&
	    !IS_MACHINE_E2S)
		return;

	if (IS_MACHINE_ES2) {
		e2k_pwr_mgr_struct_t pwr_mgr;

		nid = cpu_to_node(cpuid);
		pwr_mgr.E2K_PWR_MGR0_reg =
			early_sic_read_node_nbsr_reg(nid, SIC_pwr_mgr);

		if (cpuid & 0x1)
			pwr_mgr.E2K_PWR_MGR0_core1_clk = 0;
		else
			pwr_mgr.E2K_PWR_MGR0_core0_clk = 0;

		pwr_mgr.E2K_PWR_MGR0_snoop_wait = ES2_HTPL_SNOOP_WAIT_2048;

		value = pwr_mgr.E2K_PWR_MGR0_reg;
		write_back_CACHE_all();
		flush_TLB_all();

		for (i = 0;; i++) {
			if (i == ES2_IB_TERM_DELAY)
				early_sic_write_node_nbsr_reg(nid, SIC_pwr_mgr,
									value);
			if (i == ES2_CLK_TERM_DELAY)
				break;
		}
	} else if (IS_MACHINE_E2S) {
		do_e2s_clk_off(cpuid);
	} else if (IS_MACHINE_E8C) {
		do_e8c_clk_off(cpuid);
	}

	return;
}
#else
/* Stubs:  */
static int do_clk_on(int cpuid) {
	return 0;
}
static void do_clk_off(int cpuid) {
	return;
}
#endif /* CONFIG_HOTPLUG_CPU */

/*
 * Activate or recover a secondary processor.
 */
static int __init_recv e2k_do_start_secondary(int cpuid, int recovery,
								int hotplug)
{
	int phys_id = -1;

	E2K_SET_DGREG_NV(19, (u64) cpuid);

	if (!recovery)
		trap_init();
#ifdef	CONFIG_RECOVERY
	else
		trap_recovery();
#endif	/* CONFIG_RECOVERY */

	IDebugSMPB("e2k_do_start_secondary() started\n");

	/*
	 * This works even if the APIC is not enabled
	 */
#ifdef CONFIG_L_LOCAL_APIC
	phys_id = read_apic_id();
	if (phys_id != cpuid) {
		INIT_BUG_POINT("e2k_do_start_secondary()");
		INIT_BUG("boot bug, CPU #%d is not the same as APIC ID #%d\n",
			cpuid, phys_id);
	}
#endif /* CONFIG_L_LOCAL_APIC */

	IDebugSMPB("CPU#%d (phys ID: %d) waiting for CALLOUT\n",
		cpuid, phys_id);

	/*
	 * Cannot use normal BOOT_TRACEPOINT() here since it calls
	 * raw_smp_processor_id() which does not work yet
	 */
	EARLY_BOOT_TRACEPOINT("smp_callin: waiting for signal from bsp");

	/*
	 * Waiting for startup this CPU from BSP
	 */
	while (1) {
		if (cpu_isset(cpuid, cpu_disabled_map)) {
			/*
			 * This CPU should not be enabled.
			 * CPU is doing infinite loop.
			 */
			IDebugSMPB("e2k_do_start_secondary() CPU#%d "
				"(APIC ID: %d) is disabled by bootstrap CPU\n",
				cpuid, phys_id);
			do {
				cpu_relax();
			} while (1);
		}

		if (hotplug) {
			DebugHTPL("started to hotplug: CLK on CPU #%d\n",
				cpuid);

			do_clk_off(cpuid);
			/* Magic due do_clk_on() in __cpu_up() */
			if (IS_MACHINE_ES2 || IS_MACHINE_E2S) {
				DebugHTPL("CLK on CPU #%d\n", cpuid);
			}
			e2k_clk_resume();
		}

		/*
		 * Has the BSP finished it's STARTUP sequence
		 * and started STARTUP sequence on this CPU?
		 */
		if (cpu_isset(cpuid, callin_go))
			break;
	}

	/* By now percpu areas should have been initialized by BSP */
	set_my_cpu_offset(__per_cpu_offset[cpuid]);

	if (!hotplug) {
		EARLY_BOOT_TRACEPOINT("smp_callin: after sync");
		/*
		 * By this point BSP has already cleared and write-protected
		 * ZERO_PAGE, so flush it from TLB
		 */
		flush_TLB_page((unsigned long) empty_zero_page,
							E2K_KERNEL_CONTEXT);
	}

	/*
	 * The BSP has finished the init stage and is spinning on
	 * cpu_online_mask until we finish. We are free to set up this
	 * CPU, first the init_task structure for this CPU.
	 * CPU logical ID and physical ID should be the same in the
	 * case of recovery process
	 */

#ifdef CONFIG_L_LOCAL_APIC
	if (!physid_isset(phys_id, phys_cpu_present_map)) {
		INIT_WARNING_POINT("e2k_do_start_secondary()");
		INIT_WARNING("boot bug, CPU#%d APIC ID #%d is not present in "
			"physical CPU bitmap 0x%lx\n",
			cpuid, phys_id, physids_coerce(&phys_cpu_present_map));
		physid_set(phys_id, phys_cpu_present_map);
	}
#endif

	if (!recovery) {
		if (!hotplug) {
			IDebugSMPB("e2k_do_start_secondary() will "
				"setup_secondary_task()\n");
			setup_secondary_task(cpuid);
			map_cpu_to_logical_apicid();
		}
	} else if (logical_smp_processor_id() !=
					get_logical_apicid_for_cpu(cpuid)) {
		INIT_BUG_POINT("e2k_do_start_secondary()");
		INIT_BUG("APIC ID: %d for CPU#%d is not the same as before "
			"recovery APIC ID: %d\n",
			logical_smp_processor_id(), cpuid,
			get_logical_apicid_for_cpu(cpuid));
	}

	if (!recovery && !hotplug) {
		IDebugSMPB("e2k_do_start_secondary() will set secondary space support on CPU #%d\n",
			cpuid);
		set_secondary_space_MMU_state(&init_mm, NULL);
		pr_info("Secondary virtual space translations is enabled on CPU #%d\n",
			cpuid);
	}

	/*
	 * This is to make sure that idle task is running with preemption
	 * disabled which is a more robust way of doing it. For BSP this
	 * is done in init/main.c.
	 */
	if (!recovery && !hotplug)
		preempt_disable();

#ifdef CONFIG_L_LOCAL_APIC
	/*
	 * Set up the local APIC of the CPU
	 */
	DebugSMPB("e2k_do_start_secondary, before setup_local_APIC().\n");
	if(!hotplug) {
		if (apic->smp_callin_clear_local_apic)
			apic->smp_callin_clear_local_apic();
		setup_local_APIC();
		end_local_APIC_setup();
	}
#endif /* CONFIG_L_LOCAL_APIC */

	DebugSMPB("Stack at about %p\n", &cpuid);

	if (!recovery) {
		notify_cpu_starting(cpuid);
		if (!hotplug) {
			/*
			 * Setup LAPIC timer before calling store_cpu_info()
			 * which will measure cpu frequency with it.
			 *
			 * We suppose, that all cpus has equal loops_per_jiffy,
			 * so we don't make calibrate_delay() now (as it's too
			 * long) and we make it later, when we allow BSP to
			 * continue.
			 */
			setup_secondary_APIC_clock();
			store_cpu_info(cpuid);

			__setup_vector_irq(cpuid);
		} else {
			hrtimers_reinit(cpuid);
		}
	} else {
		struct clock_event_device *clock_event;
		ktime_t now = ktime_get();

		clock_event = per_cpu(tick_cpu_device,
				smp_processor_id()).evtdev;

		BUG_ON(!clock_event || !clock_event->event_handler
				|| !clock_event->set_mode);

		printk("Setting clock_event %ps to mode %d\n",
				clock_event, clock_event->mode);
		clock_event->set_mode(clock_event->mode, clock_event);

		clockevents_program_event(
			clock_event, ktime_add(now, tick_period), false);
	}

	DebugSMPB("CPU #%d set bit in cpu_online_mask\n", cpuid);
	/* Allow BSP to continue */
	set_cpu_online(cpuid, true);

	per_cpu(cpu_state, cpuid) = CPU_ONLINE;

	if (!recovery && !hotplug) {
		/*
		 * Call calibrate_delay() now so it won't delay BSP
		 */
		calibrate_delay();
		cpu_data[cpuid].loops_per_jiffy =
				per_cpu(cpu_loops_per_jiffy, cpuid);
	}

	/*
	 * Interrupts should be enabled only after switching to
	 * interruppted task in the case of recovery
	 */
#ifdef CONFIG_RECOVERY
	if (recovery)
		WARN_ON(!raw_irqs_disabled());
	else
#endif
		if (!hotplug)
			local_irq_enable();

	/*
	 * Clear current cpu from the callin_go mask so that on recovery
	 * or before hot(un)plugging secondary CPUs will still be cleared
	 */
	cpu_clear(cpuid, callin_go);

	BOOT_TRACEPOINT((!recovery) ?
		"e2k_do_start_secondary finished, going to cpu_idle()" :
		"e2k_do_start_secondary finished, returning to the task");

	/*
	 * Processor should go to idle task in the case of start and
	 * should return to switch to the interrupted task in the case
	 * of recovery
	 */
	if (!recovery && !hotplug) {
		DebugSMPB("CPU #%d call cpu_idle()\n",
			cpuid);
		cpu_startup_entry(CPUHP_ONLINE);
	}

	return 0;
}

/*
 * Activate a secondary processor.
 */
int __init e2k_start_secondary(int cpuid)
{
	return (e2k_do_start_secondary(cpuid, 0, 0));
}

#ifdef	CONFIG_RECOVERY
/*
 * Recover a secondary processor.
 */
int e2k_recover_secondary(int cpuid)
{
	return (e2k_do_start_secondary(cpuid, 1, 0));
}
#endif	/* CONFIG_RECOVERY */

/*
 * Up cpu for hotplug.
 */
int e2k_up_secondary(int cpuid)
{
	return (e2k_do_start_secondary(cpuid, 0, 1));
}

/*
 * Various sanity checks.
 */
static int __init_recv smp_sanity_check(unsigned max_cpus, int recovery)
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
 * Cycle through the processors to complete boot or recovery on each CPU.
 * This function is called on bootstrap processor only.
 * The number of BSP is boot_cpu_physical_apicid
 */

static void __init_recv
e2k_smp_prepare_cpus(unsigned int max_cpus, int recovery)
{
	int cpu;
	int timeout;
	/*
	 * Initialize the logical to physical CPU number mapping
	 * and the per-CPU profiling counter/multiplier
	 */

	/*
	 * Setup boot CPU information
	 */
	if (!recovery) {
		pr_info("CPU%d: APIC ID %d\n",
			boot_cpu_physical_apicid, boot_cpu_physical_apicid);
	} else if (boot_cpu_physical_apicid != read_apic_id()) {
		pr_err("Bootstrap CPU APIC ID is %d then it "
			"should be %d as before recovery\n",
			boot_cpu_physical_apicid, read_apic_id());
	}
	if (!recovery) {
		map_cpu_to_logical_apicid();
	} else if (get_logical_apicid_for_cpu(boot_cpu_physical_apicid) !=
						logical_smp_processor_id()) {
		pr_err("Logical APIC ID: %d : for Bootstrap CPU#%d "
			"is not the same as before recovery "
			"Logical APIC ID: %d\n",
			logical_smp_processor_id(), boot_cpu_physical_apicid,
			get_logical_apicid_for_cpu(boot_cpu_physical_apicid));
	}

	/*
	 * Wait 5 sec. total for all other CPUs will be ready to do
	 * own sequences of initialization or recovery
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
		for (cpu = 0; cpu < NR_CPUS; cpu ++) {
			if (!cpu_present(cpu))
				pr_err("CPU #%d has not booted!\n", cpu);
		}
	}

	smp_sanity_check(max_cpus, recovery);

	preempt_disable();
	if (read_apic_id() != boot_cpu_physical_apicid) {
		pr_err("local APIC id #%d of bootstrap CPU is not #%d\n",
				apic->get_apic_id(arch_apic_read(APIC_ID)),
				boot_cpu_physical_apicid);
		BUG();
	}
	preempt_enable();

	DebugSMPB("CPU present number is %d, physical map: 0x%lx\n",
		phys_cpu_present_num, physids_coerce(&phys_cpu_present_map));
}

static int e2k_smp_boot_cpu(unsigned int cpu, int recovery, int hotplug)
{
	if (!cpu_present(cpu)) {
		DebugSMPB("AP CPU #%d does not present\n", cpu);
		return -ENOSYS;
	}
	if (!recovery && !hotplug) {
		DebugSMPB("starts create_secondary_task()\n");
		create_secondary_task(cpu);
	}
	WARN_ON(!recovery && raw_irqs_disabled());

	per_cpu(cpu_state, cpu) = CPU_UP_PREPARE;
	cpu_set(cpu, callin_go);

	if (hotplug) {
		/* Call clk_on(cpu) - real on es2. */
		if (do_clk_on(cpu)) {
			DebugHTPL("CPU #%d failed to wake\n", cpu);
			return (-ENODEV);
		}
	}

	DebugSMPB("wait for CPU %d to come online\n", cpu);
	while (!cpu_online(cpu))
		cpu_relax();

	DebugSMPB("finished for CPU #%d\n", cpu);
	return 0;
}

static void __init_recv
e2k_smp_cpus_done(unsigned int max_cpus, int recovery)
{
	unsigned long bogosum = 0;
	int cpu;

	if (num_online_cpus() < min(num_present_cpus(), max_cpus)) {
		pr_err("Only %d CPU(s) from %d has completed initialization\n",
				num_online_cpus(), min(num_present_cpus(),
						max_cpus ? max_cpus : 1));
	}

	if (recovery && old_num_online_cpus != num_online_cpus())
		panic("Number of recovered CPU(s) %d is not the same "
				"as before recovery (%d)!\n",
				num_online_cpus(), old_num_online_cpus);

#ifdef	CONFIG_RECOVERY
	max_cpus_to_recover = max_cpus;
#endif	/* CONFIG_RECOVERY */

	/*
	 * Allow the user to impress friends.
	 */

	for (cpu = 0; cpu < NR_CPUS ; cpu ++) {
		if (cpu_online(cpu))
			bogosum += cpu_data[cpu].loops_per_jiffy;
	}
	pr_info("Total of %d processors activated (%lu.%02lu "
			"BogoMIPS).\n", num_online_cpus(),
			bogosum/(500000/HZ), (bogosum/(5000/HZ))%100);

#ifdef	CONFIG_NUMA
	setup_node_to_cpumask_map();
#endif	/* CONFIG_NUMA */

	setup_ioapic_dest();

	if (!recovery)
		old_num_online_cpus = num_online_cpus();

	DebugSMPB("finished\n");
}

/*
 * Called by smp_init prepare the secondaries
 */
void __init smp_prepare_cpus(unsigned int max_cpus)
{
	e2k_smp_prepare_cpus(max_cpus, 0);
}

#ifdef CONFIG_RECOVERY
void smp_prepare_cpus_to_recover(unsigned int max_cpus)
{
	e2k_smp_prepare_cpus(max_cpus, 1);
}
#endif	/* CONFIG_RECOVERY */

static void __init_recv e2k_smp_prepare_boot_cpu(int recovery)
{
	if (recovery) {
		/*
		 * We want to re-use cpu_online mask to synchronize SMP
		 * booting process so re-initialize it here.
		 *
		 * Later we will compare old_num_online_cpus (number of
		 * CPUs booted when creating the recovery point) with
		 * num_online_cpus() (number of CPUs booted when recovering)
		 * and panic if they are not equal.
		 */
		init_cpu_online(cpumask_of(smp_processor_id()));
	} else {
		per_cpu(cpu_state, smp_processor_id()) = CPU_ONLINE;
	}
}

void __init
smp_prepare_boot_cpu(void)
{
	e2k_smp_prepare_boot_cpu(0);
}

#ifdef	CONFIG_RECOVERY
void
smp_prepare_boot_cpu_to_recover(void)
{
	e2k_smp_prepare_boot_cpu(1);
}
#endif	/* CONFIG_RECOVERY */

int __cpu_up(unsigned int cpu, struct task_struct *tidle)
{
	int ret;
	int hotplug = (system_state != SYSTEM_BOOTING);

	return (e2k_smp_boot_cpu(cpu, 0, hotplug));
}

#ifdef	CONFIG_RECOVERY
int
cpu_recover(unsigned int cpu)
{
	return e2k_smp_boot_cpu(cpu, 1, 0);
}
#endif	/* CONFIG_RECOVERY */

void __init smp_cpus_done(unsigned int max_cpus)
{
	if (smp_found_config)
		e2k_smp_cpus_done(max_cpus, 0);
}

#ifdef	CONFIG_RECOVERY
void smp_cpus_recovery_done(unsigned int max_cpus)
{
	if (smp_found_config)
		e2k_smp_cpus_done(max_cpus, 1);
}
#endif	/* CONFIG_RECOVERY */

#ifdef CONFIG_HOTPLUG_CPU

extern void fixup_irqs(void);

int __cpu_disable (void)
{
	/*
	 * From i386 by -zwane:
	 * We won't take down the boot processor on i386 due to some
	 * interrupts only being able to be serviced by the BSP.
	 * Especially so if we're not using an IOAPIC -zwane
	 */
	if (IS_BOOT_STRAP_CPU())
		return -EBUSY;

	/* It's now safe to remove this processor from the online map */
	lock_vector_lock();
	set_cpu_online(raw_smp_processor_id(), false);
	unlock_vector_lock();
	fixup_irqs();

	return 0;
}

void __cpu_die (unsigned int cpu)
{
	unsigned int i;

	for (i = 0; i < 100; i++) {
		/* They ack this in play_dead by setting CPU_DEAD */
		if (per_cpu(cpu_state, cpu) == CPU_DEAD) {
			printk ("CPU %d is now offline\n", cpu);
			return;
		}
		msleep(100);
	}
	printk(KERN_ERR "CPU %u didn't die...\n", cpu);
}
#endif /* CONFIG_HOTPLUG_CPU */

