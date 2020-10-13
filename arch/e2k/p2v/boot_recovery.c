/*  $Id: boot_recovery.c,v 1.16 2009/06/29 10:37:05 atic Exp $
 *
 * Architecture-specific recovery.
 *
 * Copyright 2001-2003 Salavat S. Guiliazov (atic@mcst.ru)
 */

#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/sched.h>
#include <linux/console.h>
#include <linux/ioport.h>

#include <asm/system.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/head.h>
#include <asm/boot_head.h>
#include <asm/boot_init.h>
#include <asm/boot_map.h>
#include <asm/cnt_point.h>
#include <asm/cpu_regs_access.h>
#include <asm/mmu_regs.h>
#include <asm/machdep.h>
#include <asm/process.h>
#include <asm/bootinfo.h>
#include <asm/regs_state.h>
#include <asm/mmu_context.h>
#include <linux/pci.h>
#include <asm/console.h>
#include <asm/boot_param.h>

#if defined(CONFIG_RECOVERY) && (CONFIG_CNT_POINTS_NUM == 1)
#include <asm/boot_phys.h>
#endif  /* (CONFIG_RECOVERY) && (CONFIG_CNT_POINTS_NUM == 1) */

#undef	boot_printk
#define	DEBUG_RECOVERY_MODE	0	/* system recovery */
#define	DebugR			if (DEBUG_RECOVERY_MODE) printk
#define	boot_printk		if (DEBUG_RECOVERY_MODE) do_boot_printk

static void	init_recover_system(int cpuid);
static void	init_switch_to_interrupted_process(void);
static void	boot_recovery_setup(bootblock_struct_t *bootblock);
static void	boot_recovery_mem_init(void (*boot_recovery_sequel_func)(void));
static void	init_recovery_mem_term(int cpuid);
static void	boot_recovery_sequel(void);
extern void	recover_kernel(void);
extern void	e2k_ide_scan_pcibus(void);
extern void	pcibios_reinit(void);

#ifdef	CONFIG_SMP
extern void	e2k_recover_secondary(int cpuid);
#endif	/* CONFIG_SMP */

#ifdef	CONFIG_SMP
static	DEFINE_RAW_SPINLOCK(boot_areas_lock);
#endif	/* CONFIG_SMP */

extern raw_spinlock_t pci_lock;

void
boot_recovery(bootblock_struct_t *bootblock)
{
#ifdef	CONFIG_SMP
	int	cpuid = 0;
#endif	/* CONFIG_SMP */

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
	boot_recovery_mem_init(boot_recovery_sequel);

	/*
	 * Never should be here
	 */
	BUG();
}

#ifdef	CONFIG_SMP
static	atomic_t boot_info_recovery_finished = ATOMIC_INIT(0);
#endif	/* CONFIG_SMP */

static void
boot_recovery_setup(bootblock_struct_t *bootblock)
{
	e2k_rwap_lo_struct_t	reg_lo;
	e2k_rwap_hi_struct_t	reg_hi;
	e2k_addr_t		addr;
	e2k_size_t		size;
	boot_info_t		*recovery_info = &bootblock->info;

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

	WRITE_CUD_REG(reg_hi, reg_lo);
	WRITE_OSCUD_REG(reg_hi, reg_lo);

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

	WRITE_GD_REG(reg_hi, reg_lo);
	WRITE_OSGD_REG(reg_hi, reg_lo);

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

	set_MMU_TRAP_POINT(boot_kernel_trap_cellar);
	reset_MMU_TRAP_COUNT();

	boot_printk("Kernel trap cellar set to physical address 0x%lx "
		"MMU_TRAP_CELLAR_MAX_SIZE 0x%x kernel_trap_cellar 0x%lx\n",
		boot_kernel_trap_cellar, MMU_TRAP_CELLAR_MAX_SIZE,
		KERNEL_TRAP_CELLAR);

	/*
	 * Recover phys. address of boot information block in
	 * from appropriate data structure.
	 */

#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */
		boot_bootinfo_phys_base = (e2k_addr_t) bootblock;
		if (boot_bootinfo_phys_base != (e2k_addr_t)boot_bootblock_phys) {
			BOOT_BUG_POINT("boot_recovery_setup()");
			BOOT_BUG("Invalid address of bootblock 0x%lx != "
				"source bootblock address 0x%lx\n",
				boot_bootinfo_phys_base,
				(e2k_addr_t)boot_bootblock_phys);
		}
		boot_printk("Recovery information physical address: 0x%lx\n",
			recovery_info);

		if (recovery_info->signature == ROMLOADER_SIGNATURE) {
			boot_printk("Recovery information passed by "
				"ROMLOADER\n");
		} else if (recovery_info->signature == X86BOOT_SIGNATURE) {
			boot_printk("Recovery information passed by "
				"BIOS (x86)\n");
		} else {
			BOOT_BUG_POINT("boot_recovery_setup()");
			BOOT_BUG("Boot information passed by unknown loader\n");
		}
		boot_recovery_cnt_points(bootblock);
#ifdef	CONFIG_SMP
		boot_recover_smp_cpu_config();
		boot_set_event(&boot_info_recovery_finished);
	} else {
		boot_wait_for_event(&boot_info_recovery_finished);
		if (boot_smp_processor_id() >= NR_CPUS) {
			BOOT_BUG_POINT("boot_recovery_setup()");
			BOOT_BUG("CPU #%d : this processor number >= than "
				"max supported CPU number %d\n",
				boot_smp_processor_id(),
				NR_CPUS);
		}
	}
#endif	/* CONFIG_SMP */
}

void
boot_recovery_cnt_points(bootblock_struct_t *bootblock)
{
	if (boot_cnt_points_num != bootblock->cnt_points_num) {
		BOOT_WARNING_POINT("boot_recovery_cnt_points()");
		BOOT_WARNING("Invalid number of control point %d "
			"into bootblock structure != %d (config "
			"value)\n",
			bootblock->cnt_points_num, boot_cnt_points_num);
	}
	boot_cur_cnt_point = bootblock->cur_cnt_point;
#if CONFIG_CNT_POINTS_NUM
	if (boot_cur_cnt_point >= 
			boot_get_cnt_points_num(boot_cnt_points_num)) {
		BOOT_BUG_POINT("boot_recovery_cnt_points()");
		BOOT_BUG("Invalid current # of control point %d >= "
			"%d (total number of points)\n",
			boot_cur_cnt_point, 
			boot_get_cnt_points_num(boot_cnt_points_num));
	}
#endif	/* CONFIG_CNT_POINTS_NUM */
	boot_printk("Current # of control point is %d, from total "
		"number of points %d\n",
		boot_cur_cnt_point,
		boot_get_cnt_points_num(boot_cnt_points_num));
	boot_mem_cnt_points = bootblock->mem_cnt_points;
#if CONFIG_CNT_POINTS_NUM
	if (boot_mem_cnt_points > 
			boot_get_cnt_points_num(boot_cnt_points_num)) {
		BOOT_BUG_POINT("boot_recovery_cnt_points()");
		BOOT_BUG("Invalid started number of control points %d > "
			"%d (total number of points)\n",
			boot_mem_cnt_points, 
			boot_get_cnt_points_num(boot_cnt_points_num));
	}
#endif	/* CONFIG_CNT_POINTS_NUM */
	boot_disk_cnt_points = bootblock->disk_cnt_points;
	if (boot_disk_cnt_points >
			boot_get_cnt_points_num(boot_cnt_points_num)) {
		BOOT_BUG_POINT("boot_recovery_cnt_points()");
		BOOT_BUG("Invalid saved number # of control points %d > "
			"%d (total number of points)\n",
			boot_disk_cnt_points, 
			boot_get_cnt_points_num(boot_cnt_points_num));
	}
	boot_cnt_points_created = bootblock->cnt_points_created;
	if (boot_cnt_points_created) {
		if (boot_mem_cnt_points + boot_disk_cnt_points <
			boot_get_cnt_points_num(boot_cnt_points_num)) {
			BOOT_BUG_POINT("boot_recovery_cnt_points()");
			BOOT_BUG("All control points created, but "
				"total number of control points in "
				"memory %d + on disk %d < %d (total "
				"number of points)\n",
				boot_mem_cnt_points, boot_disk_cnt_points,
				boot_get_cnt_points_num(boot_cnt_points_num));
		}
		boot_printk("All control points created: now in the "
			"memory is %d, saved on the disk is %d\n",
			boot_mem_cnt_points, boot_disk_cnt_points);
	} else {
		boot_printk("Control points is creating: now in the "
			"memory is %d, saved on the disk is %d\n",
			boot_mem_cnt_points, boot_disk_cnt_points);
	}
}

#if (CONFIG_CNT_POINTS_NUM < 2)
void
init_dump_analyze_mode(void)
{
	if (read_bootblock_flags(bootblock_phys) & DUMP_ANALYZE_BB_FLAG) {
		/* Dump anal mode */
		u64 flags = RECOVERY_BB_FLAG | CNT_POINT_BB_FLAG | 
			DUMP_ANALYZE_BB_FLAG;
		dump_analyze_mode = 1;
		reset_bootblock_flags(bootblock_phys, flags);
	} else if (cur_cnt_point == 0) {
		/* Switch on dump anal mode support */
		u64 flags = RECOVERY_BB_FLAG | CNT_POINT_BB_FLAG | 
			DUMP_ANALYZE_BB_FLAG;
		e2k_addr_t kernel_base = get_cntp_kernel_base(1);
#ifdef  CONFIG_NUMA
		e2k_addr_t kernel_phys_base =
			init_node_kernel_phys_base(BOOT_BS_NODE_ID);
#endif  /* CONFIG_NUMA */
		write_bootblock_flags(bootblock_phys, flags);
		write_bootblock_kernel_base(bootblock_phys, kernel_base);
		write_bootblock_cntp_kernel_base(bootblock_phys, 0,
			kernel_phys_base);
		write_bootblock_cur_cnt_point(bootblock_phys, 1);
		write_bootblock_mem_cnt_points(bootblock_phys, 1);
		write_bootblock_disk_cnt_points(bootblock_phys, 1);
		dump_prepare(-1, 0); /* additional info for dump-analyzer utility */
	}
}
#endif	/* CONFIG_CNT_POINTS_NUM < 2 */

static void
boot_recovery_mem_init(void (*boot_recovery_sequel_func)(void))
{
	bootblock_struct_t *bootblock;

	boot_printk("boot_recovery_mem_init() started()\n");
	EARLY_BOOT_TRACEPOINT("Recovery SYNCHRONIZATION POINT #0");
#ifdef	CONFIG_SMP
	/*
	 * SYNCHRONIZATION POINT #0
	 * At this point all processors should complete memory initialization
	 * After synchronization page table is completely constructed for
	 * switching on virtual addresses.
	 */
	(void) boot_sync_all_processors(BOOT_NO_ERROR_FLAG);
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
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */
		bootblock = (bootblock_struct_t *)boot_bootinfo_phys_base;
		bootblock->kernel_flags &= 
			~(RECOVERY_BB_FLAG | NO_READ_IMAGE_BB_FLAG);
		bootblock->boot_flags &= 
			~(RECOVERY_BB_FLAG | NO_READ_IMAGE_BB_FLAG);
		write_back_CACHE_all();
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
	boot_map_needful_to_equal_virt_area(READ_USD_LO_REG().USD_lo_base);

	EARLY_BOOT_TRACEPOINT("Recovery SYNCHRONIZATION POINT #1");
#ifdef	CONFIG_SMP
	/*
	 * SYNCHRONIZATION POINT #1
	 * At this point all processors maped necessary physical areas
	 * to the equal virtual addresses and bootstrap processor maped
	 * general (shared) physical areas. 
	 * After synchronization all processors are ready to switching
	 */
	(void) boot_sync_all_processors(BOOT_NO_ERROR_FLAG);
#endif	/* CONFIG_SMP */

	/* 
	 * Switch kernel execution into the physical space to execution
	 * into the virtual space. All following initializations will be
	 * control by 'boot_init_sequel_func()' function.
	 * Should not be return here from this function.
	 */

	boot_printk("boot_recovery_mem_init() will start "
		"boot_switch_to_virt()\n");
	boot_switch_to_virt(boot_recovery_sequel_func);
}

/*
 * Sequel of process of initialization. This function is run into virtual
 * space and controls farther system boot
 */

static void
boot_recovery_sequel(void)
{
	struct task_struct *task;
	int	cpuid = 0;

	va_support_on = 1;

	EARLY_BOOT_TRACEPOINT("Recovery SYNCHRONIZATION POINT #2");
#ifdef	CONFIG_SMP
	/*
	 * SYNCHRONIZATION POINT #2
	 * At this point all processors should complete switching to
	 * virtual memory
	 * After synchronization all processors can terminate
	 * boot-time recovery of virtual memory support
	 */
	(void) boot_sync_all_processors(BOOT_NO_ERROR_FLAG);
#endif	/* CONFIG_SMP */

#ifdef CONFIG_SMP
	if (IS_BOOT_STRAP_CPU())
#endif	
		EARLY_BOOT_TRACEPOINT("kernel boot-time init finished");	

#ifdef	CONFIG_SMP
	cpuid = init_smp_processor_id();
#endif	/* CONFIG_SMP */
	
	/*
	 * Set pointer of current task structure to kernel restart task for
	 * this CPU
	 */
	task = boot_restart_task(cpuid);
	set_current_thread_info(task_thread_info(task), task);
	DebugR("'current' task pointer is set to initial kernel "
		"task structure virtual address 0x%p size 0x%lx\n",
		current_thread_info(), sizeof (union thread_union));

#ifdef	CONFIG_SMP
	current_thread_info()->cpu = cpuid;
	E2K_SET_DGREG_NV(19, (u64) cpuid);
	init_reset_smp_processors_num();
#endif	/* CONFIG_SMP */

	/* __my_cpu_offset is now stored in g18, so we should to restore it */
	set_my_cpu_offset(__per_cpu_offset[cpuid]);

	/*
	 * If machine is e3s, we should free pci_lock and pci_config_lock,
	 * because it was taken while reset during control point creating
	 */

	if (HAS_MACHINE_E2K_IOHUB) {
		pci_lock = __RAW_SPIN_LOCK_UNLOCKED(pci_lock);
		pci_config_lock = __RAW_SPIN_LOCK_UNLOCKED(pci_config_lock);
	}
	
	/*
	 * Flush instruction and data cashes to delete all physical
	 * instruction and data pages
	 */

	flush_ICACHE_all();

	/*
	 * Terminate boot-time recovery of virtual memory support
	 */

	DebugR("boot_recovery_sequel() will start init_recovery_mem_term() "
		"on CPU %d\n", cpuid);
	init_recovery_mem_term(cpuid);

	/*
	 * Start kernel recovery process
	 */
	init_recover_system(cpuid);
}

#if (CONFIG_CNT_POINTS_NUM == 1)
static void free_recovery_mem(void)
{
	node_phys_mem_t	*full_node_mem = full_phys_mem;
	int node = 0;

	if (dump_analyze_opt)
		return;

	for (; node < L_MAX_MEM_NUMNODES; node++) {
		int bank = 0;
		e2k_phys_bank_t	*phys_bank;
		e2k_addr_t cntp_base, cntp_end;
		e2k_size_t cntp_size;

		for (; bank < L_MAX_NODE_PHYS_BANKS; bank++) {
			int cntp_num = cntp_small_kern_mem_div;

			phys_bank = &full_node_mem->banks[bank];
			if (phys_bank->pages_num == 0)
				break;

			cntp_base = get_cntp_memory_base(
				phys_bank, 
				cntp_num - 1, 
				cntp_num);

			cntp_size = get_cntp_memory_len(
				phys_bank, 
				cntp_num - 1, 
				cntp_num);
			if (cntp_size == 0)
				continue;

			cntp_end = cntp_base + cntp_size;

			DebugR("Freeing CNTP reserved area: node %d, bank %d, "
				"from 0x%lx size 0x%lx\n",
				node, bank, __va(cntp_base), cntp_size);

			for (; cntp_base < cntp_end; cntp_base += PAGE_SIZE) {
				struct page *page;

				page = virt_to_page(__va(cntp_base));
				free_reserved_page(page);
			}

			phys_bank++;
		}

		full_node_mem++;
	}
}
#endif	/* (CONFIG_CNT_POINTS_NUM == 1) */

static void
init_recovery_mem_term(int cpuid)
{

	/* 
	 * Flush the temporarly mapped areas to virtual space.
	 */

	DebugR("init_recovery_mem_term() will start  "
		"init_clear_temporary_ptes() on CPU %d\n", cpuid);
	init_clear_temporary_ptes(ALL_TLB_ACCESS_MASK, cpuid);

	set_secondary_space_MMU_state(&init_mm, NULL);
}

static void
init_recover_system(int cpuid)
{
	DebugR("init_recover_system() entered.\n");

	/*
	 * Start kernel recovery on bootstrap processor.
	 * Other processors will do some internal recovery and wait
	 * for commands from bootstrap processor. 
	 */
#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
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
		DebugR("init_recover_system() will start "
			"e2k_recover_secondary() on CPU #%d\n", cpuid);
		e2k_recover_secondary(cpuid);
	}
#endif	/* CONFIG_SMP */
       
	/*
	 * Free memory, used by the 'small' kernel to create control point.
	 */
#if (CONFIG_CNT_POINTS_NUM == 1)
#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */
		DebugR("init_recover_system() will start "
			"free_recovery_mem()\n");
		free_recovery_mem();
#ifdef	CONFIG_SMP
	}
#endif/* CONFIG_SMP */
#endif	/* (CONFIG_CNT_POINTS_NUM == 1) */

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

static void
init_switch_to_interrupted_process(void)
{
	struct task_struct *task;
	int cpuid = raw_smp_processor_id();

	DebugR("init_switch_to_interrupted_process() started on CPU #%d\n",
		cpuid);

	task = interrupted_task(cpuid);
	set_current_thread_info(task_thread_info(task), task);
	if (current->mm != NULL) {
		reload_thread(current->mm);
	}

	/*
	 * Restore state registers of current process to enable
	 * switching to the interrupted task as end of recovery of the system
	 */

	raw_local_irq_disable();
	E2K_FLUSHCPU;
	RESTORE_TASK_REGS_TO_SWITCH(interrupted_task(cpuid), 1);

	/*
	 * Return to interrupted point
	 */
	return;
}

static int
boot_get_area_unintersection(e2k_addr_t area_base, e2k_size_t area_end,
				bank_info_t *area_bank)
{
	node_phys_mem_t *phys_mem = boot_nodes_phys_mem;
	e2k_phys_bank_t	*cur_bank;
	e2k_addr_t	bank_end;
	int		cur_nodes_num = 0;
	int		node;
	int		bank;

	area_bank->address = area_base;
	area_bank->size = area_end - area_base;
	boot_printk("boot_get_area_unintersection() started for area from 0x%lx "
		"to 0x%lx\n",
		area_base, area_end);
	for (node = 0; node < L_MAX_MEM_NUMNODES; node ++) {
		if (cur_nodes_num >= phys_mem_nodes_num)
			break;		/* no more nodes with memory */
		cur_bank = phys_mem[node].banks;
		if (cur_bank->pages_num == 0)
			continue;	/* node has not memory */
		cur_nodes_num ++;
		for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank ++) {
			if (cur_bank->pages_num == 0)
				break;	/* no more banks on node */
			bank_end = cur_bank->base_addr +
					cur_bank->pages_num * PAGE_SIZE;
			area_end = area_bank->address + area_bank->size;
			if (area_bank->address >= cur_bank->base_addr &&
				area_bank->address < bank_end) {
				if (area_bank->address +
					area_bank->size <= bank_end) {
					boot_printk(
						"boot_get_area_unintersection()"
						" area is full included to "
						"bank from 0x%lx to 0x%lx\n",
						cur_bank->base_addr, bank_end);
					return 0;
				}
				area_bank->size -= (bank_end -
							area_bank->address);
				area_bank->address = bank_end;
				boot_printk("boot_get_area_unintersection() "
					"area is restricted from start to "
					"0x%lx\n", bank_end);
			}
			if (area_end > cur_bank->base_addr &&
							area_end <= bank_end) {
				area_bank->size -= (area_end -
							cur_bank->base_addr);
				area_end = area_bank->address;
				boot_printk("boot_get_area_unintersection() "
					"area is restricted from end to "
					"0x%lx\n", area_end);
			}
			if (area_bank->address < cur_bank->base_addr &&
							area_end > bank_end) {
				area_bank->size -= (cur_bank->base_addr -
							area_bank->address);
				area_end = area_bank->address;
				boot_printk("boot_get_area_unintersection() "
					"area is restricted from end to 0x%lx "
					"and has rest\n", area_end);
				boot_add_mapped_area(bank_end,
							area_end - bank_end);
			}
			boot_printk("boot_get_area_unintersection() area is "
				"full out of current bank from 0x%lx to "
				"0x%lx\n", cur_bank->base_addr, bank_end);
			cur_bank ++;
		}
		if (cur_nodes_num >= phys_mem_nodes_num)
			break;		/* no more nodes with memory */
	}
	return 1;
}

static void
boot_order_areas(e2k_addr_t area_base, e2k_addr_t area_end,
	bank_info_t *areas, int *areas_num, int max_areas_num,
	int start_area_num)
{
	bank_info_t *cur_area;
	bank_info_t *next_area;
	e2k_addr_t cur_area_base;
	e2k_addr_t cur_area_end;
	int total_areas;
	int area;
	int next;

	boot_printk("boot_order_areas() started for area from 0x%lx "
		"to 0x%lx, start area #%d from #%d areas\n",
		area_base, area_end, start_area_num, *areas_num);
	if (area_end <= area_base) {
		BOOT_BUG_POINT("boot_order_areas()");
		BOOT_BUG("Empty area size started from 0x%lx to 0x%lx\n",
			area_base, area_end);
	}
	for (area = start_area_num; area < *areas_num; area ++) {
		cur_area = &areas[area];
		cur_area_base = cur_area->address;
		cur_area_end = cur_area_base + cur_area->size;
		boot_printk("boot_order_areas() current area #%d "
			"from 0x%lx to 0x%lx\n",
			area, cur_area_base, cur_area_end);
		if (area_end < cur_area_base) {
			areas[area].address = area_base;
			areas[area].size = area_end - area_base;
			boot_printk("boot_order_areas() area is set as "
				"area #%d\n",
				area);
			boot_order_areas(cur_area_base, cur_area_end,
				areas, areas_num, max_areas_num, area + 1);
			return;
		}
		if (area_base > cur_area_end) {
			boot_printk("boot_order_areas() area > current "
				"area #%d\n",
				area);
			continue;
		}
		if (area_base >= cur_area_base && area_end <= cur_area_end) {
			boot_printk("boot_order_areas() area is full "
				"included to current area #%d\n",
				area);
			return;
		}
		if (area_base < cur_area_base) {
			areas[area].address = area_base;
			areas[area].size += (cur_area_base - area_base);
			boot_printk("boot_order_areas() current area #%d "
				"is incremented from old start 0x%lx to new "
				"0x%lx\n",
				area, cur_area_base, area_base);
			cur_area_base = area_base;
		}
		if (area_end <= cur_area_end) {
			return;
		}
		areas[area].size += (area_end - cur_area_end);
		boot_printk("boot_order_areas() current area #%d "
			"is incremented from old end 0x%lx to new 0x%lx\n",
			area, cur_area_end, area_end);
		cur_area_end = area_end;
		if (area  + 1 >= *areas_num) {
			boot_printk("boot_order_areas() current area #%d "
				"is last\n", area);
			return;
		}
		if (cur_area_end < areas[area + 1].address) {
			boot_printk("boot_order_areas() next area from "
				"0x%lx does not intersect current\n",
				areas[area + 1].address);
			return;
		}
		total_areas = *areas_num;
		*areas_num = area + 1;
		boot_printk("boot_order_areas() total number of areas "
			"is reset to %d\n",
			area + 1);
		for (next = area + 1; next < total_areas; next ++) {
			next_area = &areas[next];
			boot_order_areas(next_area->address,
				next_area->address + next_area->size,
				areas, areas_num, max_areas_num, area);
		}
		return;
	}
	if (*areas_num >= max_areas_num) {
		BOOT_BUG_POINT("boot_order_areas()");
		BOOT_BUG("Too many areas\n");
		return;
	}
	areas[*areas_num].address = area_base;
	areas[*areas_num].size = area_end - area_base;
	boot_printk("boot_order_areas() area is added as new last "
		"area #%d\n",
		*areas_num);
	*areas_num = *areas_num + 1;
	boot_printk("boot_order_areas() total number of areas "
		"is set to %d\n", *areas_num);
	return;
}

void
boot_add_mapped_area(e2k_addr_t area_base, e2k_size_t area_size)
{
	bank_info_t area_bank;
	e2k_addr_t area_start = PAGE_ALIGN_UP(area_base);
	e2k_addr_t area_end = PAGE_ALIGN_DOWN(area_base + area_size);

	if (!boot_get_area_unintersection(area_start, area_end, &area_bank)) {
		boot_printk("boot_add_mapped_area() area from 0x%lx to 0x%lx "
			"is full included into the memory\n",
			area_bank.address,
			area_bank.address + area_bank.size);
		return;
	}
#ifdef	CONFIG_SMP
	boot_spin_lock(&boot_areas_lock);
#endif	/* CONFIG_SMP */
	boot_order_areas(area_bank.address,
			area_bank.address + area_bank.size,
			boot_just_mapped_areas,  &boot_mapped_areas_num,
			E2K_MAX_MAPPED_AREAS, 0);
#ifdef	CONFIG_SMP
	boot_spin_unlock(&boot_areas_lock);
#endif	/* CONFIG_SMP */
}

void
boot_add_nosave_area(e2k_addr_t area_base, e2k_size_t area_size)
{
	e2k_addr_t area_start = PAGE_ALIGN_UP(area_base);
	e2k_addr_t area_end = PAGE_ALIGN_DOWN(area_base + area_size);

#ifdef	CONFIG_SMP
	boot_spin_lock(&boot_areas_lock);
#endif	/* CONFIG_SMP */
	boot_order_areas(area_start, area_end,
			boot_nosave_areas,  &boot_nosave_areas_num,
			E2K_MAX_NOSAVE_AREAS, 0);
#ifdef	CONFIG_SMP
	boot_spin_unlock(&boot_areas_lock);
#endif	/* CONFIG_SMP */
}

void
add_nosave_area(e2k_addr_t area_base, e2k_size_t area_size)
{
	e2k_addr_t area_start = PAGE_ALIGN_UP(area_base);
	e2k_addr_t area_end = PAGE_ALIGN_DOWN(area_base + area_size);

#ifdef	CONFIG_SMP
	raw_spin_lock(&boot_areas_lock);
#endif	/* CONFIG_SMP */
	boot_order_areas(area_start, area_end,
			nosave_areas,  &nosave_areas_num,
			E2K_MAX_NOSAVE_AREAS, 0);
#ifdef	CONFIG_SMP
	raw_spin_unlock(&boot_areas_lock);
#endif	/* CONFIG_SMP */
}
