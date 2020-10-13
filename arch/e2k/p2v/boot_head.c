/* $Id: boot_head.c,v 1.41 2009/02/24 15:15:42 atic Exp $
 *
 * Control of boot-time initialization.
 *
 * Copyright (C) 2001 Salavat Guiliazov <atic@mcst.ru>
 */
#include <linux/init.h>
#include <linux/sched.h>
#include <stdarg.h>

#include <asm/types.h>
#include <asm/boot_head.h>
#include <asm/boot_init.h>
#include <asm/errors_hndl.h>
#include <asm/console.h>
#include <asm/current.h>
#include <asm/thread_info.h>
#include <asm/atomic.h>

#include <asm/e2k_debug.h>
#include <asm/console.h>
#include <asm/bootinfo.h>
#include <asm/regs_state.h>
#ifdef	CONFIG_RECOVERY
#include <asm/boot_recovery.h>
#include <asm/cnt_point.h>
#endif	/* CONFIG_RECOVERY */
#include <asm/mmu_regs_access.h>

#undef	DEBUG_BOOT_MODE
#undef	boot_printk
#undef	DebugB
#undef	DEBUG_BOOT_INFO_MODE
#define	DEBUG_BOOT_MODE		0	/* Boot process */
#define	DEBUG_BOOT_INFO_MODE	0	/* Boot info */
#define	boot_printk		if (DEBUG_BOOT_MODE) do_boot_printk
#define	DebugB			if (DEBUG_BOOT_MODE) printk
#undef	DebugSMP
#undef	DEBUG_BOOT_SMP_MODE
#define	DEBUG_BOOT_SMP_MODE	0
#define	DebugSMP		if (DEBUG_BOOT_SMP_MODE) do_boot_printk

extern void start_kernel(void);
static void __init	boot_setup(bootblock_struct_t *bootblock);

static void __init	init_switch_to_kernel_stack(int cpuid);

static void __init	boot_init_sequel(void);

/*
 * Current CPU logical number and total number of active CPUs
 */
atomic_t 	boot_cpucount = ATOMIC_INIT(0);
static raw_spinlock_t __initdata boot_cpu_hotplug_lock =
				__RAW_SPIN_LOCK_UNLOCKED(boot_cpu_hotplug_lock);

#ifndef	CONFIG_SMP
unsigned char	boot_init_started = 0;	/* boot-time initialization */
					/* has been started */
unsigned char	_va_support_on = 0;	/* virtual addressing support */
					/* has turned on */
#else
unsigned char	boot_init_started[NR_CPUS] = { [0 ... (NR_CPUS-1)] = 0 };
					/* boot-time initialization */
					/* has been started on CPU */
unsigned char	_va_support_on[NR_CPUS] = { [0 ... (NR_CPUS-1)] = 0 };
					/* virtual addressing support */
					/* has turned on on CPU */
#endif	/* CONFIG_SMP */

bootblock_struct_t *bootblock_phys;	/* bootblock structure */
					/* physical pointer */
bootblock_struct_t *bootblock_virt;	/* bootblock structure */
					/* virtual pointer */

/*
 * Control process of boot-time initialization.
 * Loader or bootloader program should call this function to start boot
 * process of the system. The function provide for virtual memory support
 * and switching to execution into the virtual space. The following part
 * of initialization should be made by 'boot_init_sequel()' function, which
 * will be run with virtula environment support.
 */

void __init
boot_init(bootblock_struct_t *bootblock)
{
	register int	cpuid;

	cpuid = boot_smp_get_processor_id();
	boot_smp_set_processor_id(cpuid);

#ifndef CONFIG_SMP
	if (!IS_BOOT_STRAP_CPU()) {
		boot_atomic_dec(&boot_cpucount);
		while (1) /* Idle if not boot CPU */
			cpu_relax();
	} else {
#endif /* !CONFIG_SMP */
		boot_set_cpu_possible(cpuid);
		boot_set_cpu_present(cpuid);
#ifndef CONFIG_SMP
	}
#endif /* !CONFIG_SMP */
	/*
	 * Preserve recursive call of boot, if some trap occured
	 * while trap table is not installed
	 */

	if (boot_boot_init_started) {
		if (boot_va_support_on) {
			INIT_BUG_POINT("boot_init");
			INIT_BUG("Recursive call of boot_init(), perhaps, due "
				"to trap\n");
		} else {
			BOOT_BUG_POINT("boot_init");
			BOOT_BUG("Recursive call of boot_init(), perhaps, due "
				"to trap\n");
		}
	} else {
		boot_boot_init_started = 1;
	}

	/*
	 * Initialize virtual memory support for farther system boot and
	 * switch sequel initialization to the function 'boot_init_sequel()'
	 * into the real virtual space. Should not be return here.
	 */

	boot_printk("Kernel boot-time initialization started\n");
	boot_setup(bootblock);
	boot_mem_init(boot_init_sequel);
}

/*
 * Setup the needed things to start boot-time initialization.
 */

#ifdef	CONFIG_SMP
static	atomic_t __initdata boot_info_setup_finished = ATOMIC_INIT(0);
#endif	/* CONFIG_SMP */

static void __init
boot_setup(bootblock_struct_t *bootblock)
{
	register boot_info_t		*boot_info = &bootblock->info;
	register e2k_rwap_lo_struct_t	reg_lo = {{ 0 }};
	register e2k_rwap_hi_struct_t	reg_hi = {{ 0 }};
	register e2k_addr_t		addr;
	register e2k_size_t		size;
#ifdef CONFIG_NUMA
	unsigned int cpuid;
#endif

	/*
	 * Set 'data/bss' segment CPU registers OSGD & GD
	 * to kernel image unit
	 */
		
	addr = (e2k_addr_t)_sdata;
	if (addr & E2K_ALIGN_OS_GLOBALS_MASK) {
		BOOT_BUG_POINT("boot_setup()");
		BOOT_BUG("Kernel 'data' segment start address 0x%lx is not "
			"aligned to alignment mask 0x%lx\n",
			addr, E2K_ALIGN_OS_GLOBALS_MASK);
	}
	addr = (e2k_addr_t)boot_vp_to_pp(_sdata);
	reg_lo.GD_lo_base = addr;
	reg_lo._GD_lo_rw = E2K_GD_RW_PROTECTIONS;

	size = (e2k_addr_t)_end - (e2k_addr_t)_sdata;
	size = ALIGN_MASK(size, E2K_ALIGN_OS_GLOBALS_MASK);
	reg_hi.GD_hi_size = size;
	reg_hi._GD_hi_curptr = 0;

	WRITE_GD_REG(reg_hi, reg_lo);
	WRITE_OSGD_REG(reg_hi, reg_lo);

	boot_printk("Kernel DATA/BSS segment pointers OSGD & GD are set to "
		"base physical address 0x%lx size 0x%lx\n",
		addr, size);

#ifdef	CONFIG_SMP
	boot_printk("Kernel boot-time initialization in progress on CPU %d "
		"APIC id %d\n",
		boot_smp_processor_id(), GET_APIC_ID(arch_apic_read(APIC_ID)));
#endif	/* CONFIG_SMP */

#ifdef CONFIG_NUMA
	/*
	 * Do initialization of CPUs possible and present masks again because
	 * these masks could be cleared while BSS cleaning
	 */
	cpuid = boot_smp_processor_id();
	boot_set_cpu_possible(cpuid);
	boot_set_cpu_present(cpuid);

	/*
	 * Do this initialization after BSS is cleared but before
	 * .node.data is duplicated.
	 */
	boot___cpu_to_node[cpuid] = boot_numa_node_id();
#endif

	/*
	 * Set 'text' segment CPU registers OSCUD & CUD
	 * to kernel image unit
	 */

	addr = (e2k_addr_t)_start;
	if (addr & E2K_ALIGN_OSCU_MASK) {
		BOOT_BUG_POINT("boot_setup()");
		BOOT_BUG("Kernel 'text' segment start address 0x%lx is not "
			"aligned to alignment mask 0x%lx\n",
			addr, E2K_ALIGN_OSCU_MASK);
	}
	addr = (e2k_addr_t)boot_vp_to_pp(_start);
	reg_lo.CUD_lo_base = addr;
	reg_lo.CUD_lo_c = E2K_CUD_CHECKED_FLAG;
	reg_lo._CUD_lo_rw = E2K_CUD_RW_PROTECTIONS;

	size = (e2k_addr_t)_etext - (e2k_addr_t)_start;
	size = ALIGN_MASK(size, E2K_ALIGN_OSCU_MASK);
	reg_hi.CUD_hi_size = size;
	reg_hi._CUD_hi_curptr = 0;

	WRITE_CUD_REG(reg_hi, reg_lo);
	WRITE_OSCUD_REG(reg_hi, reg_lo);

	boot_printk("Kernel TEXT segment pointers OSCUD & CUD are set to "
		"base physical address 0x%lx size 0x%lx\n",
		addr, size);
	if (addr != bootblock->info.kernel_base) {
		BOOT_BUG_POINT("boot_setup()");
		BOOT_BUG("Kernel start address 0x%lx is not the same as "
			"base address to load kernel in bootblock structure "
			"0x%lx\n",
			addr, bootblock->info.kernel_base);
	}
	if (size > bootblock->info.kernel_size) {
		BOOT_BUG_POINT("boot_setup()");
		BOOT_BUG("Kernel size 0x%lx is not the same as size to load "
			"kernel in bootblock structure 0x%lx\n",
			size, bootblock->info.kernel_size);
	}

	/*
	 * Set Trap Cellar pointer and MMU register to kernel image area
	 * and reset Trap Counter register
	 * In NUMA mode now we set pointer to base trap cellar on
	 * bootstrap nnode
	 */

	set_MMU_TRAP_POINT(boot_trap_cellar);
	reset_MMU_TRAP_COUNT();

	boot_printk("Kernel trap cellar set to physical address 0x%lx "
		"MMU_TRAP_CELLAR_MAX_SIZE 0x%x kernel_trap_cellar 0x%lx\n",
		boot_kernel_trap_cellar, MMU_TRAP_CELLAR_MAX_SIZE,
		KERNEL_TRAP_CELLAR);

	/*
	 * Remember phys. address of boot information block in
	 * an appropriate data structure.
	 */

#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */
		boot_bootinfo_phys_base = (e2k_addr_t) bootblock;
		/*
		 * error for 18 compiler
			boot_bootblock_phys = bootblock;
		*/
		boot_bootblock_phys_write = bootblock;
		boot_printk("Boot information physical address: 0x%lx\n",
			boot_info);

		if (boot_info->signature == ROMLOADER_SIGNATURE) {
			boot_printk("Boot information passed by ROMLOADER\n");
		} else if (boot_info->signature == X86BOOT_SIGNATURE) {
			boot_printk("Boot information passed by BIOS (x86)\n");
		} else {
			BOOT_BUG_POINT("boot_setup()");
			BOOT_BUG("Boot information passed by unknown loader\n");
		}
		if (DEBUG_BOOT_INFO_MODE) {
			int i;
			for (i = 0; i < sizeof(bootblock_struct_t) / 8; i ++) {
				do_boot_printk("boot_info[%d] = 0x%lx\n",
					i, ((u64 *)boot_info)[i]);
			}
		}
#ifdef	CONFIG_RECOVERY
		boot_recovery_cnt_points(bootblock);
#endif	/* CONFIG_RECOVERY */
#ifdef	CONFIG_SMP
		boot_setup_smp_cpu_config();
		boot_set_event(&boot_info_setup_finished);
	} else {
		boot_wait_for_event(&boot_info_setup_finished);
		if (boot_smp_processor_id() >= NR_CPUS) {
			BOOT_BUG_POINT("boot_setup()");
			BOOT_BUG("CPU #%d : this processor number >= than "
				"max supported CPU number %d\n",
				boot_smp_processor_id(),
				NR_CPUS);
		}
	}
#endif	/* CONFIG_SMP */
}

/*
 * Sequel of process of initialization. This function is run into virtual
 * space and controls farther system boot
 */

static void __init
boot_init_sequel(void)
{
#ifdef	CONFIG_SMP
	register volatile int	cpuid;
#else
#define	cpuid			0
#endif	/* CONFIG_SMP */

	va_support_on = 1;

#ifdef	CONFIG_SMP
	cpuid = init_smp_processor_id();
#endif	/* CONFIG_SMP */

	/*
	 * Sometimes boot forgets to pass CPUs through MP table, so one should
	 * setup some variables manually.
	 */
#if defined(CONFIG_SMP) || defined(CONFIG_L_X86_64)
	early_per_cpu(x86_cpu_to_apicid, cpuid) = cpuid;
	early_per_cpu(x86_bios_cpu_apicid, cpuid) = cpuid;
#endif

	EARLY_BOOT_TRACEPOINT("SYNCHRONIZATION POINT #3");
#ifdef	CONFIG_SMP
	/*
	 * SYNCHRONIZATION POINT #3
	 * At this point all processors should complete switching to
	 * virtual memory
	 * After synchronization all processors can terminate
	 * boot-time initialization of virtual memory support
	 */
	(void) boot_sync_all_processors(BOOT_NO_ERROR_FLAG);
#endif	/* CONFIG_SMP */

#ifdef CONFIG_SMP
	if (IS_BOOT_STRAP_CPU())
#endif	
		EARLY_BOOT_TRACEPOINT("kernel boot-time init finished");

	/*
	 * Initialize dump_printk() - simple printk() which
	 * outputs straight to the serial port.
	 */
#if defined(CONFIG_SERIAL_PRINTK)
	setup_serial_dump_console(&bootblock_virt->info);
#endif

	/*
	 * Set pointer of current task structure to kernel initial task
	 */

#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */
		set_current_thread_info(&init_thread_info, &init_task);
		DebugB("'current' thread pointer is set to initial kernel "
			"thread structure virtual address 0x%p size 0x%lx\n",
			&init_thread_info, THREAD_SIZE);
		set_task_thread_info(&init_task, &init_thread_info);
#ifdef	CONFIG_SMP
		init_tasks[cpuid] = &init_task;
		current_thread_info()->cpu = cpuid;
		E2K_SET_DGREG_NV(19, (u64) cpuid);
		E2K_WAIT_ALL;
		SAVE_USER_ONLY_REGS(current);	/* to save initial state of */
						/* debugging registers to enable */
						/* hardware breakpoints */
		init_reset_smp_processors_num();
	}
#endif	/* CONFIG_SMP */

	/*
	 * Show disabled caches
	 */

#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */
		if (disable_caches != _MMU_CD_EN) {
			if (disable_caches == _MMU_CD_D1_DIS)
				pr_info("Disable L1 cache\n");
			else if (disable_caches == _MMU_CD_D_DIS)
				pr_info("Disable L1 and L2 caches\n");
			else if (disable_caches == _MMU_CD_DIS)
				pr_info("Disable L1, L2 and L3 caches\n");
		}
		if (disable_secondary_caches)
			pr_info("Disable secondary INTEL caches\n");
		if (disable_IP == _MMU_IPD_DIS)
			pr_info("Disable IB prefetch\n");
		DebugB("MMU CR 0x%llx\n", READ_MMU_CR());
#ifdef	CONFIG_SMP
	}
#endif	/* CONFIG_SMP */

	/*
	 * Flush instruction and data cashes to delete all physical
	 * instruction and data pages
	 */

	flush_ICACHE_all();

	/*
	 * Terminate boot-time initialization of virtual memory support
	 */

	init_mem_term(cpuid);

	/*
	 * Switch from boot-time stacks to kernel initial stacks and
	 * start kernel initialization process.
	 */

	init_switch_to_kernel_stack(cpuid);

#ifndef	CONFIG_SMP
#undef	cpuid
#endif	/* CONFIG_SMP */
}

#ifdef CONFIG_SMP
static void __init
init_start_secondary_cpu(int cpuid)
{
	DebugSMP("init_start_secondary_cpu() cpuid %d, machine id 0x%x virt "
		"id 0x%x\n",
		cpuid, machine_id, virt_machine_id);
	if (!IS_VIRT_CPU_ENABLED(cpuid)) {
		raw_spin_lock(&boot_cpu_hotplug_lock);
		DebugSMP("CPU present number is %d, physical map: 0x%lx\n",
			phys_cpu_present_num,
			physids_coerce(&phys_cpu_present_map));
		set_cpu_present(cpuid, 0);
		physid_clear(cpuid, phys_cpu_present_map);
		phys_cpu_present_num --;
		DebugSMP("new CPU present number is %d, physical map: 0x%lx\n",
			phys_cpu_present_num,
			physids_coerce(&phys_cpu_present_map));
		raw_spin_unlock(&boot_cpu_hotplug_lock);
#ifdef CONFIG_HOTPLUG_CPU
		e2k_up_secondary(cpuid);
#endif /* CONFIG_HOTPLUG_CPU */
	} else {
		e2k_start_secondary(cpuid);
	}
}
#endif

/*
 * Switch from boot-time stacks to kernel initial stacks and start kernel
 * initialization process.
 * This stack will be cpu_idle() stack later
 */

static void __init
init_switch_to_kernel_stack(int cpuid)
{
	SWITCH_TO_KERNEL_STACK(
		kernel_init_ps_virt_base(cpuid), kernel_init_ps_size(cpuid),
		kernel_init_pcs_virt_base(cpuid), kernel_init_pcs_size(cpuid),
		kernel_init_stack_virt_base(cpuid),
		kernel_init_stack_size(cpuid));

	/*
	 * Start kernel initialization on bootstrap processor.
	 * Other processors will do some internal initialization and wait
	 * for commands from bootstrap processor. 
	 */
#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */
	#if defined (CONFIG_RECOVERY) && (CONFIG_CNT_POINTS_NUM < 2)
		if (dump_analyze_opt)
			init_dump_analyze_mode();
	#endif	/* CONFIG_RECOVERY && (CNT_POINTS_NUM < 2) */
		start_kernel();
#ifdef	CONFIG_SMP
	} else {
		init_start_secondary_cpu(cpuid);
	}
#endif	/* CONFIG_SMP */

	/*
	 * Never should be here
	 */
	BUG();
}

