/*  $Id: boot_recovery.c,v 1.16 2009/06/29 10:37:05 atic Exp $
 *
 * Architecture-specific recovery.
 *
 * Copyright 2001-2003 Salavat S. Guiliazov (atic@mcst.ru)
 */

#include <asm/p2v/boot_cacheflush.h>
#include <asm/p2v/boot_v2p.h>
#include <asm/p2v/boot_init.h>
#include <asm/p2v/boot_phys.h>
#include <asm/boot_profiling.h>
#include <asm/boot_recovery.h>
#include <asm/mmu_regs.h>
#include <asm/p2v/boot_map.h>
#include <asm/mmu_context.h>
#include <asm/regs_state.h>
#include <asm/pic.h>

#undef	boot_printk
#undef	DebugR
#define	DEBUG_RECOVERY_MODE	0	/* system recovery */
#define	boot_printk		if (DEBUG_RECOVERY_MODE) do_boot_printk
#define DebugR(...)		DebugPrint(DEBUG_RECOVERY_MODE ,##__VA_ARGS__)


#ifdef	CONFIG_SMP
static	atomic_t boot_info_recovery_finished = ATOMIC_INIT(0);
#endif	/* CONFIG_SMP */


static void
init_recovery_mem_term(int cpuid)
{
	/*
	 * Flush the temporarly mapped areas to virtual space.
	 */

	DebugR("init_recovery_mem_term() will start init_clear_temporary_ptes() on CPU %d\n",
		cpuid);
	init_clear_temporary_ptes(ALL_TLB_ACCESS_MASK, cpuid);

	set_secondary_space_MMU_state();
}

static noinline void
init_switch_to_interrupted_process(void)
{
	struct task_struct *task;

	DebugR("init_switch_to_interrupted_process() started on CPU #%d\n",
		raw_smp_processor_id());

	task = task_to_recover;
	set_current_thread_info(task_thread_info(task), task);
	if (current->mm != NULL) {
		reload_thread(current->mm);
	}

	/*
	 * Restore state registers of current process to enable
	 * switching to the interrupted task as end of recovery of the system
	 */

	NATIVE_FLUSHCPU;
	NATIVE_RESTORE_TASK_REGS_TO_SWITCH(task, task_thread_info(task));

	/*
	 * Return to interrupted point
	 */
	return;
}

static void
init_recover_system(int cpuid)
{
	bool bsp = boot_early_pic_is_bsp();

	DebugR("init_recover_system() entered.\n");

	/*
	 * Start kernel recovery on bootstrap processor.
	 * Other processors will do some internal recovery and wait
	 * for commands from bootstrap processor.
	 */
#ifdef	CONFIG_SMP
	if (bsp) {
#endif	/* CONFIG_SMP */
		DebugR("init_recover_system() will start recover_kernel() "
			"on CPU #%d\n", cpuid);
		recover_kernel();
#ifdef CONFIG_BOOT_TRACE
		BOOT_TRACEPOINT("Recovery trace finished");
		stop_boot_trace();
#endif
#ifdef	CONFIG_SMP
	} else {
		DebugR("STR is supported only for one CPU now.\n");
		BUG();
	}
#endif	/* CONFIG_SMP */

	/*
	 * Kernel and system recovery process complited
	 * Switch to interrupted processes on each CPU
	 */
	init_switch_to_interrupted_process();

	/*
	 * Never should be here
	 */
	BUG();
}

/*
 * Sequel of process of initialization. This function is run into virtual
 * space and controls farther system boot
 */
static void
boot_recovery_sequel(bool bsp, int cpuid, int cpus_to_sync)
{
	int cpu;

	va_support_on = 1;

	/*
	 * SYNCHRONIZATION POINT #2
	 * At this point all processors should complete switching to
	 * virtual memory
	 * After synchronization all processors can terminate
	 * boot-time recovery of virtual memory support
	 */
	init_sync_all_processors(cpus_to_sync);

#ifdef CONFIG_SMP
	if (bsp)
#endif
		EARLY_BOOT_TRACEPOINT("kernel boot-time init finished");

	cpu = cpuid_to_cpu(cpuid);
	DebugR("CPU #%d has ID #%d\n", cpu, cpuid);

	/* __my_cpu_offset is now stored in g18, so we should to restore it */
	set_my_cpu_offset(__per_cpu_offset[cpu]);


	/*
	 * Set pointer of current task structure to kernel restart task for
	 * this CPU
	 */
	set_current_thread_info(&task_to_restart[cpu].t.thread_info,
				&task_to_restart[cpu].t);
	DebugR("'current' task pointer is set to initial kernel task structure virtual address 0x%px size 0x%lx\n",
		current_thread_info(), sizeof(union thread_union));

	/* This also clears preempt_count and PREEMPT_NEED_RESCHED */
	E2K_SET_DGREG_NV(SMP_CPU_ID_GREG, 0);
#ifdef	CONFIG_SMP
	current->cpu = cpu;
	set_smp_processor_id(cpu);
	init_reset_smp_processors_num();
#endif	/* CONFIG_SMP */

	/*
	 * Flush instruction and data cashes to delete all physical
	 * instruction and data pages
	 */
	flush_ICACHE_all();

	/*
	 * Terminate boot-time recovery of virtual memory support
	 */
	DebugR("boot_recovery_sequel() will start init_recovery_mem_term() on CPU %d\n",
		cpuid);
	init_recovery_mem_term(cpuid);

	/*
	 * Start kernel recovery process
	 */
	init_recover_system(cpuid);
}

static void
boot_recovery_mem_init(int cpuid, bootblock_struct_t *bootblock,
	void (*boot_recovery_sequel_func)(bool bsp, int cpuid, int cpus))
{
	bool bsp = boot_early_pic_is_bsp();

	boot_printk("boot_recovery_mem_init() started()\n");

	/*
	 * SYNCHRONIZATION POINT #0
	 * At this point all processors should complete memory initialization
	 * After synchronization page table is completely constructed for
	 * switching on virtual addresses.
	 */
	boot_sync_all_processors();
#ifdef	CONFIG_SMP
	boot_atomic_set(&boot_info_recovery_finished, 0);
#endif	/* CONFIG_SMP */

	/*
	 * Reset recovery flags into bootblock structure to avoid
	 * recursive recovery while check point to recovery is not ready
	 * Write back all new flags state from cache to memory, else if
	 * CPU restarts then caches will not be flushed and we can have
	 * old state of bootblock info and flags
	 */
#ifdef	CONFIG_SMP
	if (bsp) {
#endif	/* CONFIG_SMP */
		bootblock->kernel_flags &=
			~(RECOVERY_BB_FLAG | NO_READ_IMAGE_BB_FLAG);
		bootblock->boot_flags &=
			~(RECOVERY_BB_FLAG | NO_READ_IMAGE_BB_FLAG);
		write_back_CACHE_L12();
		__E2K_WAIT_ALL;
		if (boot_machine.L3_enable)
			boot_native_flush_L3(boot_machine.native_iset_ver,
					BOOT_THE_NODE_NBSR_PHYS_BASE(0));
#ifdef	CONFIG_SMP
	}
#endif	/* CONFIG_SMP */

	/*
	 * Map some necessary physical areas to the equal virtual addresses to
	 * switch kernel execution into the physical space to execution
	 * into the virtual space.
	 */

	boot_printk("boot_recovery_mem_init() will start "
		"boot_map_needful_to_equal_virt_area()\n");
	boot_map_needful_to_equal_virt_area(
				NATIVE_NV_READ_USD_LO_REG().USD_lo_base);

	/*
	 * SYNCHRONIZATION POINT #1
	 * At this point all processors maped necessary physical areas
	 * to the equal virtual addresses and bootstrap processor maped
	 * general (shared) physical areas.
	 * After synchronization all processors are ready to switching
	 */
	boot_sync_all_processors();

	/*
	 * Switch kernel execution into the physical space to execution
	 * into the virtual space. All following initializations will be
	 * control by 'boot_init_sequel_func()' function.
	 * Should not be return here from this function.
	 */

	boot_printk("boot_recovery_mem_init() will start "
		"boot_native_switch_to_virt()\n");
	boot_native_switch_to_virt(bsp, cpuid, boot_recovery_sequel_func);
}

static void
boot_recovery_setup(bootblock_struct_t *bootblock)
{
	e2k_rwap_lo_struct_t	reg_lo;
	e2k_rwap_hi_struct_t	reg_hi;
	e2k_addr_t		addr;
	e2k_size_t		size;
	boot_info_t		*recovery_info = &bootblock->info;
	bool bsp = boot_early_pic_is_bsp();

	/*
	 * Set 'text' segment CPU registers OSCUD & CUD
	 * to kernel image unit into the physical space
	 */

#ifndef CONFIG_NUMA
	reg_lo.CUD_lo_base = boot_text_phys_base;
#else	/* CONFIG_NUMA */
	reg_lo.CUD_lo_base = boot_node_text_phys_base(BOOT_BS_NODE_ID);
#endif	/* !CONFIG_NUMA */
	reg_lo.CUD_lo_c = E2K_CUD_CHECKED_FLAG;
	reg_lo._CUD_lo_rw = E2K_CUD_RW_PROTECTIONS;

	reg_hi.CUD_hi_size = boot_text_size;
	reg_hi._CUD_hi_curptr = 0;

	NATIVE_WRITE_CUD_REG(reg_hi, reg_lo);
	NATIVE_WRITE_OSCUD_REG(reg_hi, reg_lo);

	/*
	 * Set 'data/bss' segment CPU registers OSGD & GD
	 * to kernel image unit into the physical space
	 */

	addr = boot_data_phys_base;
	reg_lo.GD_lo_base = addr;
	reg_lo._GD_lo_rw = E2K_GD_RW_PROTECTIONS;

	size = boot_data_size;
	reg_hi.GD_hi_size = size;
	reg_hi._GD_hi_curptr = 0;

	NATIVE_WRITE_GD_REG(reg_hi, reg_lo);
	NATIVE_WRITE_OSGD_REG(reg_hi, reg_lo);

	boot_printk("Kernel TEXT segment pointers OSCUD & CUD are set to "
		"base physical address 0x%lx size 0x%lx\n",
		boot_text_phys_base, boot_text_size);
	boot_printk("Kernel DATA/BSS segment pointers OSGD & GD are set to "
		"base physical address 0x%lx size 0x%lx\n",
		addr, size);

#ifdef	CONFIG_SMP
	boot_printk("Kernel boot-time initialization in progress on CPU %d\n",
		boot_smp_processor_id());
#endif	/* CONFIG_SMP */

	/*
	 * Set Trap Cellar pointer and MMU register to kernel image area
	 * and reset Trap Counter register
	 */

	boot_set_MMU_TRAP_POINT(boot_kernel_trap_cellar);
	boot_reset_MMU_TRAP_COUNT();

	boot_printk("Kernel trap cellar set to physical address 0x%lx "
		"MMU_TRAP_CELLAR_MAX_SIZE 0x%x kernel_trap_cellar 0x%lx\n",
		boot_kernel_trap_cellar, MMU_TRAP_CELLAR_MAX_SIZE,
		BOOT_KERNEL_TRAP_CELLAR);

	/*
	 * Recover phys. address of boot information block in
	 * from appropriate data structure.
	 */

#ifdef	CONFIG_SMP
	if (bsp) {
#endif	/* CONFIG_SMP */
		boot_bootinfo_phys_base =
			(e2k_addr_t)boot_pa_to_high_pa(bootblock,
							recovery_info);
		if (boot_bootinfo_phys_base !=
				(e2k_addr_t)boot_bootblock_phys) {
			BOOT_BUG("Invalid address of bootblock 0x%lx != "
				"source bootblock address 0x%lx\n",
				boot_bootinfo_phys_base,
				(e2k_addr_t)boot_bootblock_phys);
		}
		boot_printk("Recovery information physical address: 0x%lx\n",
			boot_bootblock_phys);

		if (recovery_info->signature == ROMLOADER_SIGNATURE) {
			boot_printk("Recovery information passed by ROMLOADER\n");
		} else if (recovery_info->signature == X86BOOT_SIGNATURE) {
			boot_printk("Recovery information passed by BIOS (x86)\n");
		} else {
			BOOT_BUG("Boot information passed by unknown loader\n");
		}
#ifdef	CONFIG_SMP
		boot_recover_smp_cpu_config(recovery_info);
		boot_set_event(&boot_info_recovery_finished);
	} else {
		boot_wait_for_event(&boot_info_recovery_finished);
		if (boot_smp_processor_id() >= NR_CPUS) {
			BOOT_BUG("CPU #%d : this processor number >= than max supported CPU number %d\n",
				boot_smp_processor_id(),
				NR_CPUS);
		}
	}
#endif	/* CONFIG_SMP */
}

void
boot_recovery(bootblock_struct_t *bootblock)
{
	int	cpuid = 0;

#ifdef	CONFIG_SMP
	cpuid = boot_smp_get_processor_id();
	boot_smp_set_processor_id(cpuid);
#endif	/* CONFIG_SMP */

	boot_printk("boot_recovery() started\n");

#ifdef CONFIG_BOOT_TRACE
	reinitialize_boot_trace_data();
#endif

	/*
	 * Initialize virtual memory support for farther system recovery and
	 * switch sequel recovery process to the function
	 * 'boot_recovery_sequel()' which will be executed into
	 * the virtual space.
	 */

	boot_recovery_setup(bootblock);
	boot_recovery_mem_init(cpuid, bootblock, boot_recovery_sequel);

	/*
	 * Never should be here
	 */
	BUG();
}
