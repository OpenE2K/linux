/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Architecture-specific recovery.
 */

#include <asm/p2v/boot_v2p.h>
#include <asm/p2v/boot_cacheflush.h>
#include <asm/p2v/boot_init.h>
#include <asm/p2v/boot_phys.h>
#include <asm/p2v/boot_map.h>
#include <asm/p2v/boot_mmu_context.h>
#include <asm/boot_profiling.h>
#include <asm/boot_recovery.h>
#include <asm/mmu_regs.h>
#include <asm/mmu_context.h>
#include <asm/regs_state.h>
#include <asm/pic.h>

#include <linux/cpu.h>

#undef	boot_printk
#undef	DebugR
#define	DEBUG_RECOVERY_MODE	0	/* system recovery */
#define	DEBUG_BOOT_INFO_MODE	0	/* Boot info */
#define	boot_printk		if (DEBUG_RECOVERY_MODE) do_boot_printk
#define DebugR(...)		DebugPrint(DEBUG_RECOVERY_MODE ,##__VA_ARGS__)


#ifdef	CONFIG_SMP
static	atomic_t boot_info_recovery_finished = ATOMIC_INIT(0);
#endif	/* CONFIG_SMP */


static noinline void
init_switch_to_interrupted_process(void)
{
	struct task_struct *task;

	DebugR("init_switch_to_interrupted_process() started on CPU #%d\n",
		raw_smp_processor_id());

	task = task_to_recover;
	set_current_thread_info(task_thread_info(task), task);
	if (current->mm != NULL)
		reload_thread(current->mm);

	/*
	 * Restore state registers of current process to enable
	 * switching to the interrupted task as end of recovery of the system
	 */
	NATIVE_FLUSHCPU;
	NATIVE_RESTORE_TASK_REGS_TO_SWITCH(task);

	/*
	 * Return to interrupted point
	 */
	return;
}

static void
init_recover_system(bool bsp, int cpuid)
{
	DebugR("init_recover_system() started\n");

	if (BOOT_IS_BSP(bsp)) {
		recover_kernel();
		init_preempt_count_resched(PREEMPT_ENABLED, false);
		init_switch_to_interrupted_process();
	} else {
		init_preempt_count_resched(PREEMPT_ENABLED, false);
		e2k_start_secondary(cpuid);
	}

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

	boot_set_kernel_MMU_state_after();

	init_unmap_virt_to_equal_phys(bsp, cpus_to_sync);

	va_support_on = 1;

	/*
	 * SYNCHRONIZATION POINT
	 * At this point all processors should complete switching to
	 * virtual memory
	 * After synchronization all processors can terminate
	 * boot-time recovery of virtual memory support
	 */
	init_sync_all_processors(cpus_to_sync);

	if (BOOT_IS_BSP(bsp))
		EARLY_BOOT_TRACEPOINT("kernel boot-time init finished");

	cpu = cpuid_to_cpu(cpuid);
	DebugR("CPU #%d has ID #%d\n", cpu, cpuid);

	/* __my_cpu_offset is now stored in g18, so we should to restore it */
	set_my_cpu_offset(__per_cpu_offset[cpu]);

	trap_init();

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
#endif	/* CONFIG_SMP */

	/*
	 * Reset processors number for recovery
	 */
	init_reset_smp_processors_num();

	/*
	 * Flush instruction and data cashes to delete all physical
	 * instruction and data pages
	 */
	flush_ICACHE_all();

	/*
	 * Terminate boot-time recovery of virtual memory support
	 */
	set_secondary_space_MMU_state();

	/*
	 * Start kernel recovery process
	 */
	init_recover_system(bsp, cpuid);
}

static void
boot_recovery_mem_init(bool bsp, int cpuid, bootblock_struct_t *bootblock,
	void (*boot_recovery_sequel_func)(bool bsp, int cpuid, int cpus))
{
	boot_printk("boot_recovery_mem_init() started()\n");

	/*
	 * SYNCHRONIZATION POINT
	 * After synchronization all processors finished working with
	 * boot_info_recovery_finished and it could be cleared
	 */
	boot_sync_all_processors();

#ifdef	CONFIG_SMP
	if (bsp)
		boot_atomic_set(&boot_info_recovery_finished, 0);
#endif	/* CONFIG_SMP */

	/*
	 * Reset recovery flags into bootblock structure to avoid
	 * recursive recovery while check point to recovery is not ready
	 * Write back all new flags state from cache to memory, else if
	 * CPU restarts then caches will not be flushed and we can have
	 * old state of bootblock info and flags
	 */
	if (BOOT_IS_BSP(bsp)) {
		bootblock->kernel_flags &=
			~(RECOVERY_BB_FLAG | NO_READ_IMAGE_BB_FLAG);
		bootblock->boot_flags &=
			~(RECOVERY_BB_FLAG | NO_READ_IMAGE_BB_FLAG);
		write_back_CACHE_L12();
		__E2K_WAIT_ALL;
		if (boot_machine.L3_enable)
			boot_native_flush_L3(boot_machine.native_iset_ver,
					BOOT_THE_NODE_NBSR_PHYS_BASE(0));
	}

	/* define MMU type and initial setup of MMU modes */
	boot_init_mmu_support();

	/*
	 * Map some necessary physical areas to the equal virtual addresses to
	 * switch kernel execution into the physical space to execution
	 * into the virtual space.
	 */
	boot_printk("boot_recovery_mem_init() will start boot_map_needful_to_equal_virt_area()\n");
	boot_map_needful_to_equal_virt_area(
				NATIVE_NV_READ_USD_LO_REG().USD_lo_base);

	/*
	 * SYNCHRONIZATION POINT
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
	boot_printk("boot_recovery_mem_init() will start boot_kernel_switch_to_virt()\n");
	boot_kernel_switch_to_virt(bsp, cpuid, boot_recovery_sequel_func);
}

static void
boot_recovery_setup(bool bsp, bootblock_struct_t *bootblock)
{
	register boot_info_t		*recovery_info = &bootblock->info;
	register e2k_rwap_lo_struct_t	reg_lo = {{ 0 }};
	register e2k_rwap_hi_struct_t	reg_hi = {{ 0 }};
	register e2k_addr_t		addr;
	register e2k_size_t		size;

	/*
	 * Set 'data/bss' segment CPU registers OSGD & GD
	 * to kernel image unit
	 *
	 * TODO This conflicts with later usage of GD as a pointer
	 * into current.  So this better be removed, but then
	 * GD must not be relied on to pass _sdata address in p2v/.
	 */

	addr = (e2k_addr_t)_sdata_bss;
	BOOT_BUG_ON(addr & E2K_ALIGN_OS_GLOBALS_MASK,
		"Kernel 'data' segment start address 0x%lx is not aligned to mask 0x%lx\n",
		addr, E2K_ALIGN_OS_GLOBALS_MASK);
	addr = (e2k_addr_t)boot_vp_to_pp(&_sdata_bss);
	reg_lo.GD_lo_base = addr;
	reg_lo._GD_lo_rw = E2K_GD_RW_PROTECTIONS;

	/* Assume that BSS is placed immediately after data */
	size = (unsigned long) (_edata_bss - _sdata_bss);
	size = ALIGN_TO_MASK(size, E2K_ALIGN_OS_GLOBALS_MASK);
	reg_hi.GD_hi_size = size;
	reg_hi._GD_hi_curptr = 0;

	BOOT_WRITE_GD_REG(reg_hi, reg_lo);
	BOOT_WRITE_OSGD_REG(reg_hi, reg_lo);

	boot_printk("Kernel DATA/BSS segment pointers OSGD & GD are set to base physical address 0x%lx size 0x%lx\n",
		addr, size);

#ifdef	CONFIG_SMP
	boot_printk("Kernel boot-time recovery in progress on CPU %d PIC id %d\n",
		boot_smp_processor_id(),
		boot_early_pic_read_id());
#endif	/* CONFIG_SMP */

	/*
	 * Set 'text' segment CPU registers OSCUD & CUD
	 * to kernel image unit
	 */

	addr = (e2k_addr_t)_start;
	BOOT_BUG_ON(addr & E2K_ALIGN_OSCU_MASK,
		"Kernel 'text' segment start address 0x%lx is not aligned to mask 0x%lx\n",
		addr, E2K_ALIGN_OSCU_MASK);
	addr = (e2k_addr_t)boot_vp_to_pp(&_start);
	reg_lo.CUD_lo_base = addr;
	reg_lo.CUD_lo_c = E2K_CUD_CHECKED_FLAG;
	reg_lo._CUD_lo_rw = E2K_CUD_RW_PROTECTIONS;

	size = (e2k_addr_t)_etext - (e2k_addr_t)_start;
	size = ALIGN_TO_MASK(size, E2K_ALIGN_OSCU_MASK);
	reg_hi.CUD_hi_size = size;
	reg_hi._CUD_hi_curptr = 0;

	BOOT_WRITE_CUD_REG(reg_hi, reg_lo);
	BOOT_WRITE_OSCUD_REG(reg_hi, reg_lo);

	boot_printk("Kernel TEXT segment pointers OSCUD & CUD are set to base physical address 0x%lx size 0x%lx\n",
		addr, size);

	/*
	 * Recover phys address of boot information block in from appropriate
	 * data structure.
	 */

	if (BOOT_IS_BSP(bsp)) {
		boot_bootinfo_phys_base =
			(e2k_addr_t)boot_pa_to_high_pa(bootblock, recovery_info);

		if (boot_bootinfo_phys_base !=
				(e2k_addr_t)boot_bootblock_phys)
			BOOT_BUG("Invalid address of bootblock 0x%lx != source bootblock address 0x%lx\n",
				boot_bootinfo_phys_base,
				(e2k_addr_t)boot_bootblock_phys);

		boot_printk("Recovery information physical address: 0x%lx\n",
			boot_bootblock_phys);

		boot_loader_type_banner(recovery_info);

		if (DEBUG_BOOT_INFO_MODE) {
			int i;
			for (i = 0; i < sizeof(bootblock_struct_t) / 8; i++) {
				do_boot_printk("recovery_info[%d] = 0x%lx\n",
					i, ((u64 *)recovery_info)[i]);
			}
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
#endif	/* CONFIG_SMP */
	}
}

void
boot_recovery(bool bsp, bootblock_struct_t *bootblock)
{
	register int	cpuid = 0;

	cpuid = boot_smp_get_processor_id();
	boot_smp_set_processor_id(cpuid);
	boot_printk("boot_recovery() started on CPU #%d\n", cpuid);

#ifdef CONFIG_BOOT_TRACE
	if (BOOT_IS_BSP(bsp))
		reinitialize_boot_trace_data();
#endif

	/*
	 * Initialize virtual memory support for farther system recovery and
	 * switch sequel recovery process to the function 'boot_recovery_sequel()'
	 * which will be executed into the virtual space. Should not be return here.
	 */

	boot_recovery_setup(bsp, bootblock);
	boot_recovery_mem_init(bsp, cpuid, bootblock, boot_recovery_sequel);

	/*
	 * Never should be here
	 */
	BUG();
}
