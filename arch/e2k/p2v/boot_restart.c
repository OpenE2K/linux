/*  $Id: boot_restart.c,v 1.19 2009/06/29 10:40:15 atic Exp $
 *
 * Architecture-specific recovery.
 *
 * Copyright 2001-2003 Salavat S. Guiliazov (atic@mcst.ru)
 */

#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/sched.h>
#include <linux/init_task.h>
#include <linux/console.h>
#include <linux/ioport.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/device.h>
#include <linux/pm.h>
#include <linux/suspend.h>
#include <linux/syscalls.h>

#include <asm/system.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/head.h>
#include <asm/boot_head.h>
#include <asm/boot_init.h>
#include <asm/boot_map.h>
#include <asm/cnt_point.h>
#include <asm/boot_smp.h>
#include <asm/cpu_regs_access.h>
#include <asm/mmu_regs.h>
#include <asm/bootinfo.h>
#include <asm/e2k_syswork.h>
#include <asm/smp.h>
#include <asm/machdep.h>
#include <asm/process.h>
#include <asm/bootinfo.h>
#include <asm/regs_state.h>
#include <asm/mmu_context.h>
#ifdef	CONFIG_STATE_SAVE
#include <asm/state_save.h>
#endif	/* CONFIG_STATE_SAVE */

#include <asm/e2k_debug.h>

#undef	boot_printk
#define	DEBUG_RECOVERY_MODE	0	/* system recovery */
#define	DebugR			if (DEBUG_RECOVERY_MODE) printk
#define	BDEBUG_RECOVERY_MODE	0	/* system recovery */
#define	boot_printk		if (BDEBUG_RECOVERY_MODE) do_boot_printk

#define DEBUG
#undef	dev_dbg
#ifdef DEBUG
#define dev_dbg(dev, format, arg...)		\
	dev_printk(KERN_ERR , dev , format , ## arg)
#else
#define dev_dbg(dev, format, arg...) do { (void)(dev); } while (0)
#endif

DEFINE_SEMAPHORE(restart_sem);

static void	reset_kernel(void);
static int	recover_system(int async_mode);

#ifdef CONFIG_SMP
static void	halt_other_cpus(void * einfop);
#endif	/* CONFIG_SMP */

#ifdef CONFIG_SMP
struct task_struct		*tasks_to_recover[NR_CPUS] = {NULL, };
struct task_struct		*tasks_to_restart[NR_CPUS] = {NULL, };
#else
struct task_struct		*task_to_recover = NULL;
struct task_struct		*task_to_restart = NULL;
#endif	/* CONFIG_SMP */

/**
 * device_suspend - call ->suspend() on each device to suspend device.
 */

static inline int
device_restart_prepare(void)
{
	int error;

	error = dpm_suspend_start(PMSG_SUSPEND);
	if (error) {
		printk("Some devices failed to suspend, error %d\n", error);
	}
	return error;
}

/**
 * device_resume - call ->resume() on each device to recover.
 */
static inline void
do_device_recovery(void)
{
	dpm_resume_end(PMSG_RESUME);
	pm_restore_console();
}

void
device_recovery(void)
{
	do_device_recovery();
}

/*
 * Creation of control point consists of two part:
 * 1. Freezing current state of all processes and devices
 *    (creation control point in the memory).
 *    Reset of machine to start creation of next control point or
 *    restart from the control point, created in the memory.
 *    We call this part restart system.
 * 2. Restart from control point in the memory returns control to
 *    second part of this function to contine execution from
 *    this control point. We call this part recovery system.
 * We separate second part to the new function recovery_system() and
 * restart_system() only calls them.
 * But both functions is common mechanism of control point,
 * so mutex restart_sem down in the first function and up in the
 * second.
 */
int
restart_system(rest_type_t restart_type, int async_mode)
{
	int error = 0;
	struct extd_info einfo = {NULL, restart_type};
	DebugR("restart_system(type %d) entered on cpu #%d\n",
		restart_type, raw_smp_processor_id());

#ifdef	CONFIG_STATE_SAVE
	init_state_save();
#endif	/* CONFIG_STATE_SAVE */

	raw_local_irq_enable();

#if CONFIG_CNT_POINTS_NUM
	/*
	 * Save on the disk previous created control points, if any
	 */
	if (restart_type != CORE_DUMP_REST_TYPE) {
		DebugR("restart_system() starts cntr points saving on disk\n");
		error = save_control_points();
		if (error) {
			DebugR("restart_system() control points saving on disk "
				"failed with error %d\n", error);
			goto Error_End;
		}
	}
#endif /* CONFIG_CNT_POINTS_NUM != 0 */

	/*
	 * Prepare processes and devices to restart system
	 */

	pm_prepare_console();
	sys_sync();

	DebugR("restart_system() is continuing on cpu #%d\n",
		raw_smp_processor_id());

	if (restart_type != CORE_DUMP_REST_TYPE) {
		DebugR("restart_system() starts devices suspending\n");
		error = device_restart_prepare();
		if (error) {
			DebugR("restart_system() devices suspending failed "
				"with error %d\n", error);
			goto Error_Return;
		}
		DebugR("restart_system() device_restart_prepare() OK\n");
	}

#ifdef	CONFIG_SMP
	DebugR("restart_system() starts halting of other CPUs\n");
	halt_other_cpus((void *)&einfo);
	DebugR("restart_system() other CPUs are halted\n");
#endif	/* CONFIG_SMP */

	switch_to_restart_process((void *)&einfo);

	/*
	 * After restart machine and recovery CPU and processes state
	 * control returns here to continue recovery process:
	 * resuming of devices and saving or restoring control points
	 */

	error = recover_system(async_mode);
	return error;

Error_Return:
	pm_restore_console();
#if CONFIG_CNT_POINTS_NUM
Error_End:
#endif /* CONFIG_CNT_POINTS_NUM != 0 */
	up(&restart_sem);
	DebugR("restart_system() returns to interrupted point\n");
	return error;
}

/*
 * Recovery process is divided into to parts: online and background
 * Online part do the most necessary and background process do the rest
 * actions to start runnig of user processes as erly as enable.
 * Function should return:
 * N - number of created control points in the memory, if it started
 *	control points creation mode. It can be only on first start
 *	from first created point, which was caused by restart_system()
 * 0 - if function started when all points created and it is emergent
 *	restart of the system
 */
static int
recover_system(int async_mode)
{
	int rval = 0;

	if (!cnt_points_created) {
		DebugR("Restart of the system from control point "
			"#%d to continue running\n", cur_cnt_point);
		rval = mem_cnt_points + 1;
	} else {
		DebugR("Emergent restart of the system from control point "
			"#%d\n", cur_cnt_point);
		rval = 0;
	}
	if (async_mode) {
		background_recover_system();
	} else {
		DebugR("Wake up the system restart daemon on cpu #%d "
			"to recover from control point\n",
			raw_smp_processor_id());
		restart_goal = RECOVER_REST_GOAL;
		wake_up_restartd();
	}
	DebugR("recover_system() returns to continue system running\n");
	return rval;
}

void
background_recover_system(void)
{
#if (CONFIG_CNT_POINTS_NUM > 1)
	int error;
#endif /* CONFIG_CNT_POINTS_NUM > 1 */

	DebugR("background_recover_system() starts devices recovery\n");
	do_device_recovery();

#if (CONFIG_CNT_POINTS_NUM > 1)
	/*
	 * Save on the disk previous created control points
	 */
	DebugR("background_recover_system() starts control points "
		"saving on disk\n");
	error = save_control_points();
	if (error) {
		DebugR("background_recover_system() control points "
			"saving on disk failed with error %d\n", error);
	}
	if (!cnt_points_created) {
		if (disk_cnt_points >= cnt_points_num) {
			cnt_points_created = 1;
			set_bootblock_cntp_created(bootblock_phys);
			DebugR("background_recover_system() all %d control "
				"points are created\n", disk_cnt_points);
		}
	}

	/*
	 * Restore from the disk previous created control points
	 * in the memory, if any
	 */
	DebugR("background_recover_system() starts control points "
		"restoring from the disk\n");
	error = restore_control_points();
	if (error) {
		DebugR("background_recover_system() control points "
			"restoring from disk failed with error %d\n", error);
	}
#elif (CONFIG_CNT_POINTS_NUM == 1)
	cnt_points_created = 1;
	set_bootblock_cntp_created(bootblock_phys);
	DebugR("background_recover_system() control point for quick restart "
		"is created\n");
#endif	/* CONFIG_CNT_POINTS_NUM > 1 */

	up(&restart_sem);	/* should be down() in restart_system() */
	DebugR("background_recover_system() completed\n");
}

void
switch_to_restart_process(void * einfop)
{
	int			cpuid = raw_smp_processor_id();
#ifdef	CONFIG_SMP
	struct task_struct	*task_to_restart = NULL;
	thread_info_t		*thread_info = NULL;
#endif
	void			*info = NULL;
	rest_type_t		restart_type = INVALID_REST_TYPE;
	struct extd_info	*einfo = (struct extd_info *)einfop;

#ifdef	CONFIG_SMP
	init_set_smp_processors_num(phys_cpu_present_num);
#endif	/* CONFIG_SMP */
	if (einfo) {
		info = einfo->info;
		restart_type = einfo->restart_type;
	}
	raw_local_irq_enable();

	/*
	 * Save state registers of current process to enable
	 * switching to this task as end of recovery of the system
	 */

	if ((e2k_addr_t)current >= TASK_SIZE) {
		interrupted_task(cpuid) = current;
		SAVE_TASK_REGS_TO_SWITCH(current, 1);
		AW(current->thread.sw_regs.cr0_lo) = E2K_GET_DSREG_NV(cr0.lo);
		AW(current->thread.sw_regs.cr0_hi) = E2K_GET_DSREG_NV(cr0.hi);
	} else {
		cpuid = boot_smp_processor_id();
	}

	DebugR("switch_to_restart_process() started on CPU #%d\n", cpuid);
	if ((BootStrap(arch_apic_read(APIC_BSP)) != 0) == cpuid) {
		printk("switch_to_restart_process() bad CPU #%d "
			 "bootstrap flag %d\n",
			 cpuid, BootStrap(arch_apic_read(APIC_BSP)) != 0);
		print_stack(current);
	}

	/*
	 * Switch to kernel boot-time stack to continue restart process
	 * and call function to do real restart of the system
	 */

	raw_local_irq_disable();

	/*
	 * Switch current task and thread info to special structures
	 * to restart
	 */

#ifdef	CONFIG_SMP
	task_to_restart = restart_task(cpuid);
	if (task_to_restart == NULL) {
		panic("Could not create task structure to "
			"restart CPU #%d\n", cpuid);
	}
	thread_info = task_thread_info(task_to_restart);
	set_current_thread_info(thread_info, task_to_restart);
	E2K_SET_DGREG_NV(19, (u64) cpuid);
	thread_info->cpu = cpuid;
	thread_info->pt_regs = NULL;

	SWITCH_TO_KERNEL_STACK(
		kernel_boot_ps_virt_base(cpuid),
		kernel_boot_ps_size(cpuid),
		kernel_boot_pcs_virt_base(cpuid),
		kernel_boot_pcs_size(cpuid),
		kernel_boot_stack_virt_base(cpuid),
		kernel_boot_stack_size(cpuid));
	if (thread_info != NULL) {
		thread_info->k_stk_base = kernel_boot_stack_virt_base(cpuid);
		thread_info->k_stk_sz = kernel_boot_stack_size(cpuid);
		thread_info->k_usd_hi = READ_USD_HI_REG();
		thread_info->k_usd_lo = READ_USD_LO_REG();
	}
#endif	/* CONFIG_SMP */

#ifdef	CONFIG_STATE_SAVE
	/* Save memory */
	e2k_save_state();
#endif	/* CONFIG_STATE_SAVE */

	set_kernel_MMU_state();

	do_restart_system(restart_type);

	/*
	 * Never should be here
	 */

	BUG();
}

#ifdef	CONFIG_SMP
static	atomic_t reset_kernel_ready = ATOMIC_INIT(0);
#endif	/* CONFIG_SMP */

void
do_restart_system(rest_type_t restart_type)
{
	int		cpuid;

	if ((e2k_addr_t)current >= TASK_SIZE) {
		cpuid = raw_smp_processor_id();
	} else {
		cpuid = boot_smp_processor_id();
	}

	DebugR("do_restart_system() started on CPU #%d\n", cpuid);

#ifdef	CONFIG_SMP

	/*
	 * SYNCHRONIZATION POINT #1
	 * At this point all processors should be switched to
	 * restart task and boot-time stacks
	 */
	atomic_set(&reset_kernel_ready, 0);
	DebugR("do_restart_system() will start boot_sync_all_processors() "
		"for SYNC POINT #1 on CPU #%d\n", cpuid);
	(void) boot_sync_all_processors(BOOT_NO_ERROR_FLAG);
#endif	/* CONFIG_SMP */

#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */

		/*
		 * Init the boot-time support of physical areas mapping
		 * to virtual space
		 */

		if (restart_type != CORE_DUMP_REST_TYPE) {
			DebugR("do_restart_system() will start reset_kernel() "
				"on CPU #%d\n", cpuid);
			reset_kernel();
		}
#ifdef	CONFIG_SMP
		/*
		 * Bootstrap processor completed initialization of support
		 * of physical areas mapping to virtual space
		 */
		boot_set_event(&reset_kernel_ready);
	} else {
		/*
		 * Other processors are waiting for completion of
		 * initialization to start mapping
		 */
		boot_wait_for_event(&reset_kernel_ready);
	}
#endif	/* CONFIG_SMP */	

	/*
	 * Reset machine and start harware boot sequence
	 */

#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
		boot_reset_smp_processors_num();
#endif	/* CONFIG_SMP */
		e2k_reset_machine();
#ifdef	CONFIG_SMP
	}
#endif	/* CONFIG_SMP */

	/*
	 * Wait for reset
	 */

	while(1);
}

#ifdef	CONFIG_SMP

static void
halt_other_cpus(void * einfop)
{
	DebugR("halt_other_cpus() entered.\n");
	DebugR("halt_other_cpus() will start smp_call_function() to start "
		"switch_to_restart_process()\n");
	smp_call_function(switch_to_restart_process, einfop, 0);
	DebugR("halt_other_cpus() smp_call_function() finished\n");
	DebugR("halt_other_cpus() returns.\n");
}

#endif	/* CONFIG_SMP */

static void
reset_kernel(void)
{
	int		new_cnt_point;
	e2k_addr_t	new_cntp_kernel_base;
#ifdef	CONFIG_NUMA
	e2k_addr_t	kernel_phys_base =
				init_node_kernel_phys_base(BOOT_BS_NODE_ID);
#endif	/* CONFIG_NUMA */
	pg_data_t	*pgdat;
	int		cntp_num;

	DebugR("reset_kernel() entered init_bootinfo_phys_base:0x%lx.\n",
		init_bootinfo_phys_base);
	DebugR("reset_kernel() bootblock physical address is 0x%p kernel "
		"image base 0x%lx\n",
		bootblock_phys, kernel_phys_base);
	for_each_online_pgdat(pgdat) {
		DebugR("reset_kernel() pgdat 0x%p\n", pgdat);
	}
	mem_cnt_points ++;
	write_bootblock_mem_cnt_points(bootblock_phys, mem_cnt_points);
	write_bootblock_cntp_kernel_base(bootblock_phys, cur_cnt_point,
							kernel_phys_base);
	write_bootblock_cntp_node_data(bootblock_phys, cur_cnt_point,
					kernel_va_to_pa(first_online_pgdat()));
	write_bootblock_cntp_nosave_areas(bootblock_phys, cur_cnt_point,
						kernel_va_to_pa(nosave_areas));
	write_bootblock_cntp_nosaves_num(bootblock_phys, cur_cnt_point,
						nosave_areas_num);
	set_bootblock_cntp_mem_valid(bootblock_phys, cur_cnt_point);
	if (is_bootblock_cntp_disk_valid(bootblock_phys, cur_cnt_point)) {
		reset_bootblock_cntp_disk_valid(bootblock_phys, cur_cnt_point);
		disk_cnt_points --;
		write_bootblock_disk_cnt_points(bootblock_phys,
							disk_cnt_points);
	}
#if CONFIG_CNT_POINTS_NUM
	new_cnt_point = cur_cnt_point + 1;
	cntp_num = get_cnt_points_num(cnt_points_num);
#else	/* CONFIG_CNT_POINTS_NUM == 0 */
	new_cnt_point = cur_cnt_point;
	cntp_num = 1;
#endif	/* CONFIG_CNT_POINTS_NUM != 0 */

#if CONFIG_CNT_POINTS_NUM < 2
	if (dump_analyze_opt)
		reset_bootblock_flags(bootblock_phys, DUMP_ANALYZE_BB_FLAG);
#endif	/* CONFIG_CNT_POINTS_NUM < 2 */

	if (mem_cnt_points < cntp_num) {
		if (new_cnt_point >= get_cnt_points_num(cnt_points_num)) {
			panic("reset_kernel() new control point #%d > "
				"%d (max points number)\n",
				new_cnt_point, 
				get_cnt_points_num(cnt_points_num));
		}
		set_bootblock_flags(bootblock_phys,
				RECOVERY_BB_FLAG | CNT_POINT_BB_FLAG);
		write_bootblock_cur_cnt_point(bootblock_phys, new_cnt_point);
		new_cntp_kernel_base = get_cntp_kernel_base(new_cnt_point);
		write_bootblock_kernel_base(bootblock_phys,
							new_cntp_kernel_base);
	} else {
		/* last control point */
#if CONFIG_CNT_POINTS_NUM
		if (cur_cnt_point >= get_cnt_points_num(cnt_points_num)) {
			panic("reset_kernel() current control point #%d >= "
				"%d (max points number)\n",
				cur_cnt_point, 
				get_cnt_points_num(cnt_points_num));
		}
#endif	/* CONFIG_CNT_POINTS_NUM != 0 */
		reset_bootblock_flags(bootblock_phys, CNT_POINT_BB_FLAG);
		set_next_control_point();
	}

	DebugR("reset_kernel() set bootblock recovery flag 0x%p to 0x%lx\n",
		&bootblock_phys->boot_flags, 
		read_bootblock_flags(bootblock_phys));

	DebugR("reset_kernel() finished.\n");
}

int
emergency_restart_system(void)
{
	DebugR("emergency_restart_system() started on cpu #%d\n",
		raw_smp_processor_id());

	/*
	 * This function can be called only to simulate emeregency
	 * restart of the system.
	 */
	if (down_trylock(&restart_sem))
		return -EBUSY;
	e2k_reset_machine();
	return 0;
}

