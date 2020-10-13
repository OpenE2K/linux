/* $Id: boot_init.c,v 1.56 2009/06/29 15:10:41 atic Exp $
 *
 * Boot-time initialization of Virtual memory support.
 * Switch from boot execution on physical memory to continuation of boot
 * on virtual memory
 *
 * Copyright (C) 2001 Salavat Guiliazov <atic@mcst.ru>
 */

#include <linux/types.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/bootmem.h>

#include <asm/types.h>
#include <asm/e2k_api.h>
#include <asm/cpu_regs_access.h>
#include <asm/head.h>
#include <asm/lms.h>
#include <asm/io.h>
#include <asm/boot_head.h>
#include <asm/page.h>
#include <asm/boot_init.h>
#include <asm/boot_phys.h>
#include <asm/boot_map.h>
#include <asm/process.h>
#include <asm/mpspec.h>
#include <asm/mmu_context.h>
#ifdef	CONFIG_RECOVERY
#include <asm/cnt_point.h>
#endif	/* CONFIG_RECOVERY */
#include <asm/timer.h>
#include <asm/bootinfo.h>
#include <asm/console.h>
#include <asm/e2k_debug.h>
#include <asm/boot_param.h>

#undef	DEBUG_BOOT_MODE
#undef	boot_printk
#define	DEBUG_BOOT_MODE		0	/* Boot process */
#define	boot_printk		if (DEBUG_BOOT_MODE) do_boot_printk

#undef	DEBUG_NUMA_MODE
#undef	DebugNUMA
#define	DEBUG_NUMA_MODE		0	/* Boot NUMA */
#define	DebugNUMA		if (DEBUG_NUMA_MODE) do_boot_printk

/*
 * Array of 'BOOT_MAX_MEM_NUMNODES' of 'BOOT_MAX_MEM_NUMNODES' structures
 * is statically allocated into the kernel image.
 * The array of structures is used to hold the
 * physical memory configuration of the machine. This is filled in
 * 'boot_probe_memory()' and is later used by 'boot_mem_init()' to setup
 * boot-time memory map and by 'mem_init()' to set up 'mem_map[]'.
 */
			
node_phys_mem_t		nodes_phys_mem[L_MAX_MEM_NUMNODES];
EXPORT_SYMBOL(nodes_phys_mem);

#ifdef	CONFIG_RECOVERY
/*
 * Structure 'full_phys_banks' holds all available physical memory on the
 * system. Structure 'e2k_phys_banks' holds physical memory available to use
 * only by current control point instance.
 */
node_phys_mem_t		full_phys_mem[L_MAX_MEM_NUMNODES];
#endif	/* CONFIG_RECOVERY */

/*
 * FIXME: Nodes number is limited by bits in unsigned long size - 64
 */
int			phys_nodes_num;
unsigned long		phys_nodes_map;
int			phys_mem_nodes_num;
unsigned long		phys_mem_nodes_map;

#ifdef	CONFIG_NUMA
e2k_addr_t node_kernel_phys_base[MAX_NUMNODES] = {
				[ 0 ... (MAX_NUMNODES-1) ] = -1
			};
static raw_spinlock_t __initdata boot_node_kernel_dup_lock[MAX_NUMNODES] = {
				[ 0 ... (MAX_NUMNODES-1) ] =
					__RAW_SPIN_LOCK_UNLOCKED(
						boot_node_kernel_dup_lock)
			};
static int __initdata node_kernel_duplicated[MAX_NUMNODES] = { 0 };
static int __initdata node_set_kernel_duplicated[MAX_NUMNODES] = { 0 };
static int __initdata node_kernel_base_is_set[MAX_NUMNODES] = { 0 };
#define	boot_node_kernel_duplicated					\
		boot_get_vo_value(node_kernel_duplicated[boot_numa_node_id()])
#define	boot_node_set_kernel_duplicated					\
		boot_get_vo_value(node_set_kernel_duplicated[		\
						boot_numa_node_id()])
#define	boot_node_kernel_base_is_set					\
		boot_get_vo_value(node_kernel_base_is_set[		\
						boot_numa_node_id()])
static raw_spinlock_t __initdata boot_node_map_lock[MAX_NUMNODES] = {
				[ 0 ... (MAX_NUMNODES-1) ] =
					__RAW_SPIN_LOCK_UNLOCKED(
						boot_node_map_lock)
			};
static int __initdata node_image_mapped[MAX_NUMNODES] = { 0 };
static int __initdata node_mem_mapped[MAX_NUMNODES] = { 0 };
static int __initdata node_io_mapped[MAX_NUMNODES] = { 0 };
static int __initdata node_info_mapped[MAX_NUMNODES] = { 0 };
static int __initdata node_ports_mapped[MAX_NUMNODES] = { 0 };
#define	boot_node_image_mapped					\
		boot_get_vo_value(node_image_mapped[boot_numa_node_id()])
#define	boot_node_mem_mapped					\
		boot_get_vo_value(node_mem_mapped[boot_numa_node_id()])
#define	boot_node_io_mapped					\
		boot_get_vo_value(node_io_mapped[boot_numa_node_id()])
#define	boot_node_info_mapped					\
		boot_get_vo_value(node_info_mapped[boot_numa_node_id()])
#define	boot_node_ports_mapped					\
		boot_get_vo_value(node_ports_mapped[boot_numa_node_id()])
#else	/* ! CONFIG_NUMA */
e2k_addr_t kernel_phys_base;
#define	boot_node_map_lock	RAW_SPIN_LOCK_UNLOCKED;
#define	boot_node_image_mapped	0
#define	boot_node_mem_mapped	0
#define	boot_node_io_mapped	0
#define	boot_node_info_mapped	0
#define	boot_node_ports_mapped	0
#endif	/* CONFIG_NUMA */

#ifdef	CONFIG_RECOVERY
bank_info_t		just_mapped_areas[E2K_MAX_MAPPED_AREAS];
int			mapped_areas_num = 0;
bank_info_t		nosave_areas[E2K_MAX_NOSAVE_AREAS];
int			nosave_areas_num = 0;
#endif	/* CONFIG_RECOVERY */

#ifdef	CONFIG_RECOVERY
int	cnt_points_num = CONFIG_CNT_POINTS_NUM;
#if (CONFIG_CNT_POINTS_NUM < 2)
int	dump_analyze_mode = 0;
int	cntp_small_kern_mem_div = CONFIG_SMALL_KERN_MEM_DIV;
#endif	/* CONFIG_CNT_POINTS_NUM < 2 */
#ifdef	CONFIG_CNT_POINTS_RECREATE
int	recreate_cnt_points = 1;
#else	/* ! CONFIG_CNT_POINTS_RECREATE */
int	recreate_cnt_points = 0;
#endif	/* CONFIG_CNT_POINTS_RECREATE */
int	cur_cnt_point = 0;
int	mem_cnt_points = 0;
int	disk_cnt_points = 0;
int	cnt_points_created = 0;
#endif	/* CONFIG_RECOVERY */

#if defined (CONFIG_RECOVERY) && (CONFIG_CNT_POINTS_NUM < 2)
#define	DUMP_ANALYZE_CMD_LEN	64

/*
 * Dump analyze mode setup
 */

int	dump_analyze_opt = 0;
char	dump_analyze_cmd[DUMP_ANALYZE_CMD_LEN];

int boot_dump_analyze_cmd_set(char *cmd)
{
	int len = strlen(cmd);

	if (len >= DUMP_ANALYZE_CMD_LEN) {
		boot_printk("Too long dump analyze cmd name. "
			"Dump analyzing option ignored.");
		return -EINVAL;
	}

	strcpy(boot_dump_analyze_cmd, cmd);
	boot_dump_analyze_opt = 1;

	boot_printk("Dump analyzing option enabled. "
		"Dump analyze cmd name '%s'",
		boot_dump_analyze_cmd);

	return 0;
}

boot_param("dump_analyze_cmd", boot_dump_analyze_cmd_set);

#endif	/* CONFIG_RECOVERY && (CONFIG_CNT_POINTS_NUM < 2) */

/*
 * Memory limit setup
 */

static e2k_size_t mem_limit = -1UL;
#define boot_mem_limit	boot_get_vo_value(mem_limit)

static int __init boot_mem_set(char *cmd)
{
	boot_mem_limit = boot_simple_strtoul(cmd, &cmd, 0);
	
	if (*cmd == 'K' || *cmd == 'k')
		boot_mem_limit <<= 10;
	else if (*cmd == 'M' || *cmd == 'm')
		boot_mem_limit <<= 20;

	boot_mem_limit &= ~(PAGE_SIZE-1);
	
	boot_printk("Physical memory limit set to 0x%lx\n", boot_mem_limit);
	
	return 0;
}

boot_param("mem", boot_mem_set);

static e2k_size_t node_mem_limit = -1UL;
#define boot_node_mem_limit	boot_get_vo_value(node_mem_limit)

static int __init boot_node_mem_set(char *cmd)
{
	boot_node_mem_limit = boot_simple_strtoul(cmd, &cmd, 0);
	
	if (*cmd == 'K' || *cmd == 'k')
		boot_node_mem_limit <<= 10;
	else if (*cmd == 'M' || *cmd == 'm')
		boot_node_mem_limit <<= 20;

	boot_node_mem_limit &= ~(PAGE_SIZE-1);
	
	boot_printk("Node physical memory limit set to 0x%lx\n",
		boot_node_mem_limit);
	
	return 0;
}

boot_param("nodemem", boot_node_mem_set);

/*
 * Disabling caches setup
 */

unsigned long disable_caches = _MMU_CD_EN;
#define boot_disable_caches	boot_get_vo_value(disable_caches)

static int __init boot_disable_L1_setup(char *cmd)
{
	if (boot_disable_caches < _MMU_CD_D1_DIS)
		boot_disable_caches = _MMU_CD_D1_DIS;
	return 0;
}
boot_param("disL1", boot_disable_L1_setup);

static int __init boot_disable_L2_setup(char *cmd)
{
	if (!BOOT_IS_MACHINE_E3M && boot_disable_caches < _MMU_CD_D_DIS)
		boot_disable_caches = _MMU_CD_D_DIS;
	return 0;
}
boot_param("disL2", boot_disable_L2_setup);

static int __init boot_disable_L3_setup(char *cmd)
{
	if (!BOOT_IS_MACHINE_E3M && boot_disable_caches < _MMU_CD_DIS)
		boot_disable_caches = _MMU_CD_DIS;
	return 0;
}
boot_param("disL3", boot_disable_L3_setup);

unsigned long disable_secondary_caches = 0;
#define boot_disable_secondary_caches	\
		boot_get_vo_value(disable_secondary_caches)

static int __init boot_disable_LI_setup(char *cmd)
{
	boot_disable_secondary_caches = _MMU_CR_CR0_CD;
	return 0;
}
boot_param("disLI", boot_disable_LI_setup);

unsigned long disable_IP = _MMU_IPD_2_LINE;
#define boot_disable_IP	boot_get_vo_value(disable_IP)

static int __init boot_disable_IP_setup(char *cmd)
{
	boot_disable_IP = _MMU_IPD_DIS;
	return 0;
}
boot_param("disIP", boot_disable_IP_setup);

static int enable_l2_cint = 0;
#define boot_enable_l2_cint	boot_get_vo_value(enable_l2_cint)

static int __init boot_enable_L2_CINT_setup(char *str)
{
	boot_enable_l2_cint = 1;
	return 0;
}
boot_param("L2CINT", boot_enable_L2_CINT_setup);

static inline void boot_set_l2_crc_state(void)
{
	unsigned long l2_cntr;
	int l2_bank;

	if (!boot_enable_l2_cint)
		return;
	for (l2_bank = 0; l2_bank < E2K_L2_BANK_NUM; l2_bank++) {
		l2_cntr = READ_L2_CNTR(l2_bank);
		l2_cntr |= E2K_L2_CNTR_EN_CINT;
		WRITE_L2_CNTR(l2_cntr, l2_bank);
		E2K_WAIT_ALL;
		l2_cntr = READ_L2_CNTR(l2_bank);
	}
}

/*
 * The next structure contains list of descriptors of the memory areas
 * used by boot-time initialization.
 * All the used memory areas enumerate in this structure. If a some new
 * area will be used, then it should be added to the list of already known ones.
 */

bootmem_areas_t		kernel_bootmem;
long			phys_memory_mgb_size;

static	void __init	boot_reserve_all_bootmem(void);
static	void __init	boot_reserve_bootinfo_areas(void);
static	void __init	boot_alloc_init_stacks(void);
static	void __init	boot_alloc_all_bootmem(void);
static	void __init	boot_map_all_bootmem(void);
static	void __init	boot_map_all_bootinfo_areas(void);
static	void __init_recv boot_switch_to_virt_end(void);

#ifdef	CONFIG_KERNEL_CODE_CONTEXT
static void __init boot_fill_kernel_CUT(void);
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */

#ifdef	CONFIG_NUMA
static void __init boot_node_duplicate_kernel(void);
static void __init boot_node_set_duplicated_mode(void);
static void __init boot_node_set_kernel_base(void);
#endif	/* CONFIG_NUMA */

/*
 * Control process of boot-time initialization of Virtual memory support.
 * The main goal of the initialization is switching to further boot execution
 * on virtual memory.
 */

#ifdef	CONFIG_SMP
static	atomic_t boot_physmem_maps_ready = ATOMIC_INIT(0);
#ifndef	CONFIG_NUMA
static	atomic_t boot_mapping_ready = ATOMIC_INIT(0);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */

void __init
boot_mem_init(void (*boot_init_sequel_func)(void))
{
	e2k_size_t	mapped_pages_num;

#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */

		/*
		 * Probe the system memory and fill the structures
		 * 'nodes_phys_mem' of physical memory configuration.
	 	 */

		boot_probe_memory();
		boot_kernel_phys_base = (e2k_addr_t)boot_vp_to_pp(KERNEL_BASE);
#if defined(CONFIG_RECOVERY) && CONFIG_CNT_POINTS_NUM
		if (boot_mem_cnt_points >= 
			boot_get_cnt_points_num(boot_cnt_points_num)) {
			boot_info_t *boot_info = &boot_bootblock_phys->info;
			int cur_cntp = boot_cur_cnt_point;
			e2k_addr_t kernel_base;
			kernel_base = boot_info->cntp_info[cur_cntp].kernel_base;
			if (kernel_base != boot_kernel_phys_base) {
				BOOT_BUG_POINT("boot_mem_init");
				BOOT_BUG("Kernel start address 0x%lx is not the "
					"same as should be to recover in "
					"bootblock structue 0x%lx",
					kernel_base, boot_kernel_phys_base);
			}
		}
#endif	/* defined(CONFIG_RECOVERY) && CONFIG_CNT_POINTS_NUM */

		/*
		 * Create the physical memory pages bitmaps to support
		 * simple boot-time memory allocator.
		 */

		mapped_pages_num = boot_create_physmem_maps();
		boot_printk("The mapped physical memory size is 0x%lx "
			"pages * 0x%x = 0x%lx bytes\n",
			mapped_pages_num, PAGE_SIZE,
			mapped_pages_num * PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
		boot_scan_full_physmem();
#endif	/* CONFIG_RECOVERY */
#ifdef	CONFIG_SMP
		/*
		 * Bootstrap processor completed creation of simple
		 * boot-time memory allocator and all CPUs can start
		 * to reserve used physical memory
		 */
		boot_set_event(&boot_physmem_maps_ready);
	} else {

		/*
		 * Other processors are waiting for completion of creation
		 * to start reservation of used memory by each CPU
		 */
		boot_wait_for_event(&boot_physmem_maps_ready);
	}
#endif	/* CONFIG_SMP */

	/*
	 * Reserve the memory used now by boot-time initialization.
	 */

	boot_reserve_all_bootmem();

	EARLY_BOOT_TRACEPOINT("Init SYNCHRONIZATION POINT #0");
#ifdef	CONFIG_SMP
	/*
	 * SYNCHRONIZATION POINT #0
	 * At this point all processors should complete reservation of
	 * used memory and all busy physical memory is known
	 * After synchronization any processor can allocate needed
	 * physical memory
	 */
	(void) boot_sync_all_processors(BOOT_NO_ERROR_FLAG);
#endif	/* CONFIG_SMP */

	/*
	 * Allocate the needed physical memory used by boot-time initialization
	 */

	boot_alloc_init_stacks();

#ifdef	CONFIG_NUMA
	boot_node_duplicate_kernel();

	EARLY_BOOT_TRACEPOINT("Init SYNCHRONIZATION POINT #0.1");
	/*
	 * SYNCHRONIZATION POINT for NUMA #0.1
	 * At this point all nodes should complete creation of
	 * own copy of kernel image and page tables
	 */
	(void) boot_timed_sync_all_processors(BOOT_NO_ERROR_FLAG,
			BOOT_WAITING_FOR_SYNC_ITER *
			((boot_text_size + boot_dup_data_size) /
							(1024 * 1024)) *
			boot_phys_mem_nodes_num);

	/*
	 * After synchronization all nodes should switch to duplicated
	 * kernel mode and can use own copy of kernel image and page tables
	 */
	boot_node_set_duplicated_mode();

	EARLY_BOOT_TRACEPOINT("Init SYNCHRONIZATION POINT #0.2");
	/*
	 * SYNCHRONIZATION POINT for NUMA #0.2
	 * At this point all nodes should complete switch to duplicated
	 * kernel image and page tables
	 */
	(void) boot_timed_sync_all_processors(BOOT_NO_ERROR_FLAG,
			BOOT_WAITING_FOR_SYNC_ITER * boot_phys_mem_nodes_num);

	/*
	 * After synchronization all nodes run on duplicated image
	 * but if node has not own copy and use some other node copy then
	 * it need change kernel image base from -1 to base address of used
	 * node's image. Base address -1 was used to early detection nodes
	 * without duplicated image
	 */
	boot_node_set_kernel_base();

	/*
	 * Now for NUMA mode we can set Trap Cellar pointer and MMU
	 * register to own copy of kernel image area on each node
	 * and reset Trap Counter register
	 */

#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
	set_MMU_TRAP_POINT(boot_kernel_trap_cellar);

	boot_printk("Kernel trap cellar set to physical "
		"address 0x%lx MMU_TRAP_CELLAR_MAX_SIZE 0x%x "
		"kernel_trap_cellar 0x%lx\n",
		boot_kernel_trap_cellar, MMU_TRAP_CELLAR_MAX_SIZE,
		BOOT_KERNEL_TRAP_CELLAR);
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
#endif	/* CONFIG_NUMA */

#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */
		boot_alloc_all_bootmem();
#ifdef	CONFIG_SMP
	}
#endif	/* CONFIG_SMP */

#ifndef	CONFIG_NUMA
#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */

		/*
		 * Init the boot-time support of physical areas mapping
		 * to virtual space
		 */

		boot_init_mapping();

#ifdef	CONFIG_SMP
		/*
		 * Bootstrap processor completed initialization of support
		 * of physical areas mapping to virtual space
		 */
		boot_set_event(&boot_mapping_ready);
	} else {

		/*
		 * Other processors are waiting for completion of
		 * initialization to start mapping
		 */
		boot_wait_for_event(&boot_mapping_ready);
	}
#endif	/* CONFIG_SMP */
#else	/* CONFIG_NUMA */
	/*
	 * Init the boot-time support of physical areas mapping
	 * to virtual space on each node.
	 * A node has own page table and own mapping of some kernel objects
	 */
	boot_node_init_mapping();

	EARLY_BOOT_TRACEPOINT("Init SYNCHRONIZATION POINT #0.3");
	/*
	 * SYNCHRONIZATION POINT #0.3
	 * Waiting for all nodes init mapping before pgd sets on
	 * cpus of same node
	 */
	(void) boot_sync_all_processors(BOOT_NO_ERROR_FLAG);
#endif	/* ! CONFIG_NUMA */

	/*
	 * Map the kernel memory areas used at boot-time
	 * into the virtual space.
	 */

	boot_map_all_bootmem();
	
#ifdef	CONFIG_KERNEL_CODE_CONTEXT
	/*
	 * Fill kernel compilation units table.
	 */

#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */
		 boot_fill_kernel_CUT();
#ifdef	CONFIG_SMP
	}
#endif	/* CONFIG_SMP */
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */

	EARLY_BOOT_TRACEPOINT("Init SYNCHRONIZATION POINT #1");
#ifdef	CONFIG_SMP
	/*
	 * SYNCHRONIZATION POINT #1
	 * At this point all processors should complete map all
	 * used memory for each CPU and general (shared) memory
	 * After synchronization page table is completely constructed for
	 * switching on virtual addresses.
	 */
	(void) boot_timed_sync_all_processors(BOOT_NO_ERROR_FLAG,
			BOOT_WAITING_FOR_SYNC_ITER * boot_phys_memory_mgb_size);
#endif	/* CONFIG_SMP */

	/*
	 * Map some necessary physical areas to the equal virtual addresses to 
	 * switch kernel execution into the physical space to execution
	 * into the virtual space.
	 */

	boot_map_needful_to_equal_virt_area(READ_USD_LO_REG().USD_lo_base);

	EARLY_BOOT_TRACEPOINT("Init SYNCHRONIZATION POINT #2");
#ifdef	CONFIG_SMP
	/*
	 * SYNCHRONIZATION POINT #2
	 * At this point all processors maped necessary physical areas
	 * to the equal virtual addresses and bootstrap processor maped
	 * general (shared) physical areas. 
	 * After synchronization all procxessors are ready to switching
	 */
	(void) boot_sync_all_processors(BOOT_NO_ERROR_FLAG);
#endif	/* CONFIG_SMP */


	/* 
	 * Switch kernel execution into the physical space to execution
	 * into the virtual space. All following initializations will be
	 * control by 'boot_init_sequel_func()' function.
	 * Should not be return here from this function.
	 */

	boot_switch_to_virt(boot_init_sequel_func);
}

/*
 * Control process of termination of boot-time initialization of Virtual memory
 * support. The function terminates this process and is executed on virtual
 * memory.
 */

void __init
init_mem_term(int cpuid)
{

	/* 
	 * Flush the temporarly mapped areas to virtual space.
	 */

	init_clear_temporary_ptes(ALL_TLB_ACCESS_MASK, cpuid);
}

/*
 * In this case all physical memory is devided to the number of
 * control points. Each instance of system running has own separate
 * memory space
 */

#ifdef	CONFIG_RECOVERY
static int __init
boot_create_cntp_memory(node_phys_mem_t *full_phys_banks,
	node_phys_mem_t *cntp_phys_banks, int bank_num)
{
	node_phys_mem_t	*full_node_mem;
	node_phys_mem_t	*cur_node_mem;
	e2k_phys_bank_t	*phys_bank = NULL;
	e2k_phys_bank_t	*cntp_bank = NULL;
	e2k_addr_t	cntp_base;
	e2k_size_t	pages_num;
	int		cntp_num = boot_cnt_points_num;
	int		cur_cntp = boot_cur_cnt_point;
	int		node;
	int		bank;
	int		cur_bunk;
	int		num_banks = 0;
	e2k_size_t	node_phys_memory_size;
	e2k_size_t	phys_memory_size = 0;
	e2k_addr_t	node_start;
	e2k_addr_t	node_end;

#if (CONFIG_CNT_POINTS_NUM < 2)
	if (boot_cnt_points_num == 1 || boot_dump_analyze_opt)
		cntp_num = boot_cntp_small_kern_mem_div;
#endif	/* CONFIG_CNT_POINTS_NUM < 2 */

	boot_printk("boot_create_cntp_memory() started for current control "
		"point #%d\n", cur_cntp);
	if (cur_cntp > boot_get_cnt_points_num(cntp_num)) {
		BOOT_BUG_POINT("boot_create_cntp_memory");
		BOOT_BUG("Invalid current # of control point %d, should be "
			" <= %d (total number of points)",
			cur_cntp, boot_get_cnt_points_num(cntp_num));
	}

	full_node_mem = full_phys_banks;
	cur_node_mem = cntp_phys_banks;
	for (node = 0; node < L_MAX_MEM_NUMNODES; node ++) {
		cur_bunk = 0;
		node_phys_memory_size = 0;
		node_start = -1UL;
		node_end = 0;
		for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank ++) {
			e2k_addr_t bank_end;

			phys_bank = &full_node_mem->banks[bank];
			if (phys_bank->pages_num == 0) {
				break;	/* no more memory on node */
			}

		#if (CONFIG_CNT_POINTS_NUM < 2)
			if (boot_cnt_points_num == 1 ||
				boot_dump_analyze_opt) {
				if (cur_cntp == 1)
					pages_num = get_cntp_memory_len(
							phys_bank,
							cntp_num - 1,
							cntp_num);
				else
					pages_num = phys_bank->pages_num * 
							PAGE_SIZE;
			} else
		#endif	/* CONFIG_CNT_POINTS_NUM < 2 */
				pages_num = get_cntp_memory_len(
						phys_bank, cur_cntp, cntp_num);
			pages_num =  pages_num / PAGE_SIZE;
			if (pages_num == 0) {
				boot_printk("boot_create_cntp_memory(): "
					"node #%d: empty bank from base 0x%lx "
					"size 0x%lx for control point #%d\n",
					node, phys_bank->base_addr,
					phys_bank->pages_num, cur_cntp);
				continue;
			}

		#if (CONFIG_CNT_POINTS_NUM < 2)
			if (boot_cnt_points_num == 1 ||
				boot_dump_analyze_opt) {
				if (cur_cntp == 1)
					cntp_base = get_cntp_memory_base(
							phys_bank,
							cntp_num - 1,
							cntp_num);
				else
					cntp_base = phys_bank->base_addr;
			} else
		#endif	/* CONFIG_CNT_POINTS_NUM < 2 */
				cntp_base = get_cntp_memory_base(
						phys_bank, cur_cntp, cntp_num);
			if ((cntp_base & ~PAGE_MASK) != 0) {
				BOOT_BUG_POINT("boot_create_cntp_memory");
				BOOT_BUG("Control point #%d node #%d memory "
					"bank base address 0x%lx is not page "
					"aligned for control point #%d",
					cur_cntp, node, cntp_base);
				cntp_base &= PAGE_MASK;
			}

			cntp_bank = &cur_node_mem->banks[cur_bunk];
			cntp_bank->base_addr = cntp_base;
			cntp_bank->pages_num = pages_num;
			node_phys_memory_size += pages_num * PAGE_SIZE;
			boot_printk("Control point #%d node #%d memory bank "
				"#%d: address 0x%lx size is 0x%lx pages "
				"(0x%lx bytes)\n",
				cur_cntp, node, cur_bunk, cntp_base,
				pages_num, pages_num * PAGE_SIZE);

			if (cntp_base < node_start)
				node_start = cntp_base;
			bank_end = cntp_base + pages_num * PAGE_SIZE;
			if (bank_end > node_end)
				node_end = bank_end;

			cur_bunk ++;
		}
		cur_node_mem->start_pfn = node_start >> PAGE_SHIFT;
		cur_node_mem->pfns_num = (node_end - node_start) >> PAGE_SHIFT;

		boot_printk("Control point #%d node #%d memory total size "
			"is %d Mgb\n",
			cur_cntp, node, node_phys_memory_size / (1024 * 1024));
		num_banks += cur_bunk;
		phys_memory_size += node_phys_memory_size;
		full_node_mem ++;
		cur_node_mem ++;
	}
	boot_printk("Control point #%d memory total size is %d Mgb\n",
		cur_cntp, phys_memory_size / (1024 * 1024));
	return num_banks;
}
#endif	/* CONFIG_RECOVERY */

/*
 * bootblock.bios.banks_ex is extended area for all nodes. Firstly, we fill
 * node_phys_mem.banks from bootblock.nodes_mem.banks, which presents for each
 * node. If there are more than L_MAX_NODE_PHYS_BANKS_FUSTY phys banks for a
 * node, we continue to fill node_phys_mem.banks from bootblock.bios.banks_ex,
 * which is one for all nodes. Last element in bootblock.bios.banks_ex for a
 * node, which uses it, should be with size = 0. If a node has only
 * L_MAX_NODE_PHYS_BANKS_FUSTY phys banks, there should be element with size = 0
 * in bootblock.bios.banks_ex for this node.
 *
 *	    node_phys_mem.banks		  bootblock.nodes_mem.banks
 *         __________________________________________
 *  ______|_____________________________   __________|____________
 * |__________________|_________________| |_______________________|
 *                             |
 * L_MAX_NODE_PHYS_BANKS_FUSTY |           bootblock.bios.banks_ex
 * <------------------>        |_____________________
 *                                         __________|____________
 *				          |_______________________|
 * L_MAX_NODE_PHYS_BANKS
 * <----------------------------------->
 */
static void __init
boot_biosx86_probe_node_memory(boot_info_t *bootblock, int node,
	e2k_phys_bank_t *phys_bank, bank_info_t *bank_info,
	e2k_size_t phys_memory_size, bank_info_t **bank_info_ex_p,
	e2k_size_t *bank_memory_size_p, e2k_addr_t *node_start_p,
	e2k_addr_t *node_end_p, int *bank_num_p)
{
	bank_info_t	*bank_info_ex = *bank_info_ex_p;
	e2k_size_t	bank_memory_size = *bank_memory_size_p;
	e2k_addr_t	node_start = *node_start_p;
	e2k_addr_t	node_end = *node_end_p;
	int		bank_num = *bank_num_p;
	int		bank;

	for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank++) {
		e2k_size_t bank_size;
		e2k_addr_t bank_start;
		e2k_addr_t bank_end;

		if (bank >= L_MAX_NODE_PHYS_BANKS_FUSTY) {
			int banks_ex_id = bank_info - bootblock->bios.banks_ex;

			if (bank == L_MAX_NODE_PHYS_BANKS_FUSTY) {
				bank_info = bank_info_ex;
				banks_ex_id =
					bank_info - bootblock->bios.banks_ex;
				boot_printk("Node #%d has phys banks in "
					"extended area, extended area id "
					"0x%x\n",
					node, banks_ex_id);
			}
			if (banks_ex_id >= L_MAX_PHYS_BANKS_EX) {
				bank_info_ex = bank_info;
				BOOT_WARNING_POINT(
					"boot_biosx86_probe_node_memory");
				BOOT_WARNING("Node #%d has phys banks in "
					"extended area, but extended area is "
					"full, ignored",
					node);
				goto out;
			}
		}

		if ((phys_memory_size + bank_memory_size) >= boot_mem_limit ||
				bank_memory_size >= boot_node_mem_limit)
			break;

		bank_start = bank_info->address;
		bank_size = bank_info->size;

		if (bank_size == 0) {
			boot_printk("Node #%d bank #%d: size 0x0\n",
				node, bank);
			if (bank >= L_MAX_NODE_PHYS_BANKS_FUSTY) {
				bank_info_ex = bank_info + 1;
				boot_printk("Phys banks extended area id was set to 0x%lx\n",
					bank_info_ex -
					bootblock->bios.banks_ex);
			}
			goto out; /* no more banks on node */
		}

		if ((bank_size & (PAGE_SIZE - 1)) != 0) {
			BOOT_BUG_POINT("boot_biosx86_probe_node_memory");
			BOOT_BUG("Node #%d: phys bank #%d size 0x%lx is not "
				"page aligned",
				node, bank, bank_size);
			bank_size &= ~(PAGE_SIZE - 1);
		}

		if ((bank_start & (PAGE_SIZE - 1)) != 0) {
			BOOT_BUG_POINT("boot_biosx86_probe_node_memory");
			BOOT_BUG("Node #%d: phys bank base address 0x%lx is "
				"not page aligned",
				node, bank, bank_start);
			bank_size += (bank_start & (PAGE_SIZE - 1));
			bank_start &= ~(PAGE_SIZE - 1);
		}

		if ((phys_memory_size + bank_memory_size + bank_size) >=
				boot_mem_limit) {
			bank_size -= phys_memory_size + bank_memory_size +
				     bank_size - boot_mem_limit;
			boot_printk("Node #%d: phys bank #%d size is reduced "
				"to 0x%lx bytes\n",
				node, bank, bank_size);
		}

		if ((bank_memory_size + bank_size) >= boot_node_mem_limit) {
			bank_size -= bank_memory_size + bank_size -
				     boot_node_mem_limit;
			boot_printk("Node #%d: phys bank #%d size is reduced "
				"to 0x%lx bytes\n",
				node, bank, bank_size);
		}

		phys_bank->base_addr = bank_start;
		phys_bank->pages_num = bank_size >> PAGE_SHIFT;
		if (bank_start < node_start)
			node_start = bank_start;
		bank_end = bank_start + bank_size;
		if (bank_end > node_end)
			node_end = bank_end;
		bank_num++;
		bank_memory_size += bank_size;
		boot_printk("Node #%d: phys bank #%d address 0x%lx, size 0x%lx "
				"pages (0x%lx bytes)\n",
				node, bank, phys_bank->base_addr,
				phys_bank->pages_num,
				phys_bank->pages_num * PAGE_SIZE);
		bank_info++;
		phys_bank++;
	}

	if (bank == L_MAX_NODE_PHYS_BANKS) {
		bank_info_ex = bank_info;
		BOOT_WARNING_POINT("boot_biosx86_probe_node_memory");
		BOOT_WARNING("Node #%d last phys bank for node in extended "
			"area is not null, ignored",
			node);
		boot_printk("Phys banks extended area id was set to 0x%lx\n",
			bank_info_ex - bootblock->bios.banks_ex);
		goto out;
	}

	if (bank < L_MAX_NODE_PHYS_BANKS_FUSTY) {
		for (; bank < L_MAX_NODE_PHYS_BANKS_FUSTY; bank++) {
			if (!bank_info++->size)
				goto out;
		}
	} else {
		bank_info_ex = bank_info;
	}

	while (bank_info_ex++->size) {
		if (++bank >= L_MAX_NODE_PHYS_BANKS) {
			BOOT_WARNING_POINT("boot_biosx86_probe_node_memory");
			BOOT_WARNING("Node #%d last phys bank for node in "
				"extended area is not null, ignored",
				node);
			break;
		}
		if (bank_info_ex - bootblock->bios.banks_ex >=
				L_MAX_PHYS_BANKS_EX) {
			BOOT_WARNING_POINT("boot_biosx86_probe_node_memory");
			BOOT_WARNING("Node #%d last phys bank in "
				"extended area is not null, ignored",
				node);
			break;
		}
	}
	boot_printk("Phys banks extended area id was set to 0x%lx\n",
			bank_info_ex - bootblock->bios.banks_ex);

out:
	*bank_info_ex_p = bank_info_ex;
	*bank_memory_size_p = bank_memory_size;
	*node_start_p = node_start;
	*node_end_p = node_end;
	*bank_num_p = bank_num;
}

/*
 * Probe physical memory configuration of the machine and fill the array of
 * structures of physical memory banks 'e2k_phys_bank'.
 * It is better to merge contiguous memory banks for allocation goals.
 * Base address of a bank should be page aligned.
 */
static int __init
boot_biosx86_probe_memory(node_phys_mem_t *nodes_phys_mem,
	boot_info_t *bootblock)
{
	node_banks_t	*boot_nodes = bootblock->nodes_mem;
	node_phys_mem_t	*node_mem = nodes_phys_mem;
	bank_info_t	*bank_info_ex = bootblock->bios.banks_ex;
	unsigned long	nodes_map = 0;
	int		nodes_num = 0;
	unsigned long	node_mask = 0x1UL;
	int		boot_bank_num;
	int		bank_num = 0;
	int		node;
	e2k_size_t	phys_memory_size = 0;

#ifndef	CONFIG_SMP
	boot_phys_nodes_num = 1;
	boot_phys_nodes_map = 0x1;
#endif	/* CONFIG_SMP */

	for (node = 0; node < L_MAX_MEM_NUMNODES; node++) {
		e2k_phys_bank_t	*phys_bank = node_mem->banks;
		bank_info_t	*bank_info = boot_nodes->banks;
		e2k_addr_t	node_start = -1UL;
		e2k_addr_t	node_end = 0;
		e2k_size_t	bank_memory_size = 0;

		if (phys_memory_size >= boot_mem_limit)
			break;
		if (!(boot_phys_nodes_map & node_mask) &&
						BOOT_HAS_MACHINE_L_SIC) {
			if (bank_info->size != 0) {
				BOOT_WARNING_POINT("boot_biosx86_probe_memory");
				BOOT_WARNING("Node #%d is not online but has "
					"not empty memory bank address 0x%lx, "
					"size 0x%lx, ignored",
					node, bank_info->address,
					bank_info->size);
			}
			goto next_node;
		}
		if (bank_info->size == 0)
			goto next_node;	/* node has not memory */
		if ((!BOOT_HAS_MACHINE_E2K_FULL_SIC) && node != 0) {
			BOOT_WARNING_POINT("boot_biosx86_probe_memory");
			BOOT_WARNING("Machine can have only one node #0, "
				"but memory node #%d has not empty phys "
				"bank address 0x%lx, size 0x%lx, ignored",
				node, bank_info->address, bank_info->size);
			goto next_node;
		}

		nodes_num++;
		nodes_map |= node_mask;

		boot_biosx86_probe_node_memory(bootblock, node, phys_bank,
			bank_info, phys_memory_size, &bank_info_ex,
			&bank_memory_size, &node_start, &node_end, &bank_num);

		node_mem->start_pfn = node_start >> PAGE_SHIFT;
		node_mem->pfns_num = (node_end - node_start) >> PAGE_SHIFT;
		phys_memory_size += bank_memory_size;
		boot_printk("Node #%d: start pfn 0x%lx, size 0x%lx pfns\n",
			node, node_mem->start_pfn, node_mem->pfns_num);

next_node:
		boot_printk("Node #%d: phys memory total size is %d Mgb\n",
			node, bank_memory_size / (1024 * 1024));
		boot_nodes++;
		node_mem++;
		node_mask <<= 1;
	}

	boot_bank_num = bootblock->num_of_banks;

	if (boot_mem_limit != -1UL && boot_node_mem_limit != -1UL && 
			boot_bank_num != 0 && boot_bank_num != bank_num) {
		BOOT_WARNING_POINT("boot_biosx86_probe_memory");
		BOOT_WARNING("Number of banks of physical memory passed "
			"by boot loader %d is not the same as banks at "
			"boot_info structure %d",
			boot_bank_num, bank_num);
	}
	if (nodes_num == 0) {
		BOOT_BUG_POINT("boot_biosx86_probe_memory");
		BOOT_BUG("Empty online nodes map passed by boot loader at "
			"boot_info structure");
	}
	if (boot_phys_nodes_map && ((boot_phys_nodes_map & nodes_map)
			!= nodes_map)) {
		BOOT_BUG_POINT("boot_biosx86_probe_memory");
		BOOT_BUG("Calculated map of nodes with memory 0x%lx "
			"contains node(s) out of total nodes map 0x%lx",
			nodes_map, boot_phys_nodes_map);
	}
	if (boot_phys_nodes_map & ~((1 << L_MAX_MEM_NUMNODES) - 1)) {
		BOOT_WARNING_POINT("boot_biosx86_probe_memory");
		BOOT_WARNING("Probably some nodes 0x%lx out of memory max "
			"nodes range 0x%lx contain memory, but cannot be "
			"accounted",
			boot_phys_nodes_map, (1 << L_MAX_MEM_NUMNODES) - 1);
	}

	boot_phys_mem_nodes_num = nodes_num;
	boot_phys_mem_nodes_map = nodes_map;
	boot_phys_memory_mgb_size = phys_memory_size / (1024 * 1024);
	boot_printk("Phys memory total size is %d Mgb\n",
			boot_phys_memory_mgb_size);
	return bank_num;
}

static inline int __init
boot_romloader_probe_memory(node_phys_mem_t *nodes_phys_mem,
	boot_info_t *bootblock)
{
	return boot_biosx86_probe_memory(nodes_phys_mem, bootblock);
}

void __init
boot_probe_memory(void)
{
	node_phys_mem_t	*all_phys_banks = NULL;
#ifdef	CONFIG_RECOVERY
	node_phys_mem_t	*cur_phys_banks = NULL;
#endif	/* CONFIG_RECOVERY */
	int		bank_num = 0;
	boot_info_t	*bootblock;

#ifndef	CONFIG_RECOVERY
	all_phys_banks = boot_vp_to_pp(nodes_phys_mem);
#else	/* CONFIG_RECOVERY */
	all_phys_banks = boot_vp_to_pp(full_phys_mem);
	cur_phys_banks = boot_vp_to_pp(nodes_phys_mem);
	memset(cur_phys_banks, 0x00, sizeof(*cur_phys_banks));
#endif	/* !CONFIG_RECOVERY */
	memset(all_phys_banks, 0x00, sizeof(*all_phys_banks));

	bootblock = &boot_bootblock_phys->info;
	if (bootblock->signature == ROMLOADER_SIGNATURE) {
		bank_num = boot_romloader_probe_memory(all_phys_banks,
								bootblock);
	} else if (bootblock->signature == X86BOOT_SIGNATURE) {
		bank_num = boot_biosx86_probe_memory(all_phys_banks, bootblock);
	} else {
		BOOT_BUG_POINT("boot_probe_memory");
		BOOT_BUG("Unknown type of Boot information structure");
	}

#ifdef	CONFIG_RECOVERY
	bank_num = boot_create_cntp_memory(all_phys_banks, cur_phys_banks,
						bank_num);
#endif	/* CONFIG_RECOVERY */
}

/*
 * Reserve the memory used by boot-time initialization.
 * All the used memory areas enumerate below. If a some new area will be used,
 * then it should be added to the list of already known ones.
 */

static	void __init
boot_reserve_all_bootmem(void)
{
	e2k_addr_t	area_base;
	e2k_size_t	area_size;
	e2k_addr_t	area_offset;
	oscud_struct_t	OSCUD = {{{0}}, {{0}}};
	osgd_struct_t	OSGD  = {{{0}}, {{0}}};
	psp_struct_t	PSP = {{{0}}, {{0}}};
	pcsp_struct_t	PCSP  = {{{0}}, {{0}}};
	usbr_struct_t	USBR = {{0}};
	usd_struct_t	USD  = {{{0}}, {{0}}};
	boot_info_t	*boot_info;
	int		bank;
	int		ret;

#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */
		/*
		 * Reserve 0 phys page area for software fix of hardware bug:
		 * "page miss" for semi-speculative load for invalid address instead of
		 * diagnostic value because of "illegal page".
		 */
		area_base = 0;
		area_size = PAGE_SIZE;
		ret = _boot_reserve_physmem(area_base, area_size,
				PAGE_SIZE, 0);
		if (ret != 0) {
			BOOT_BUG_POINT("boot_reserve_all_bootmem");
			BOOT_BUG("Could not reserve 0-page area: "
					"base addr 0x%lx size 0x%lx "
					"page size 0x%x",
					area_base, area_size, PAGE_SIZE);
		}
		memset(NULL, 0, PAGE_SIZE);
		boot_printk("The 0-page reserved area: "
			"base addr 0x%lx size 0x%lx page size 0x%x\n",
			area_base, area_size, PAGE_SIZE);

		/*
		 * Reserve kernel image 'text/data/bss' segments.
		 * 'OSCUD' & 'OSGD' register-pointers describe these areas.
		 * 'text' and 'data/bss' segments do not intersect.
		 */
		read_OSCUD_reg(&OSCUD);
		area_base = OSCUD.OSCUD_base;
		area_size = OSCUD.OSCUD_size;
		ret = _boot_reserve_physmem(area_base, area_size,
				BOOT_E2K_KERNEL_PAGE_SIZE, 0);
		if (ret != 0) {
			BOOT_BUG_POINT("boot_reserve_all_bootmem");
			BOOT_BUG("Could not reserve kernel 'text' segment: "
				"base addr 0x%lx size 0x%lx page size 0x%x",
				area_base, area_size, BOOT_E2K_KERNEL_PAGE_SIZE);
		}
		boot_text_phys_base = area_base;
		boot_text_size = area_size;

#ifdef	CONFIG_KERNEL_CODE_CONTEXT
		area_base = (e2k_addr_t)boot_vp_to_pp(_ptext_start);
		area_base = _PAGE_ALIGN_DOWN(area_base,
						E2K_KERNEL_PROT_PAGE_SIZE);
		area_size = (e2k_addr_t)_ptext_end - (e2k_addr_t)_ptext_start;
		area_size = _PAGE_ALIGN_DOWN(area_size,
						E2K_KERNEL_PROT_PAGE_SIZE);
		boot_prot_text_phys_base = area_base;
		boot_prot_text_size = area_size;
		ret = _boot_reserve_physmem(area_base, area_size,
					    E2K_KERNEL_PROT_PAGE_SIZE, 0);
		if (ret) {
			BOOT_BUG_POINT("boot_reserve_all_bootmem");
			BOOT_BUG("Could not reserve kernel 'prot.text' segment: base addr 0x%lx size 0x%lx page size 0x%x",
				area_base, area_size,
				E2K_KERNEL_PROT_PAGE_SIZE);
		}
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */

		boot_printk("The kernel 'text' segment: base 0x%lx size 0x%lx page size 0x%x\n",
			boot_text_phys_base, boot_text_size,
			BOOT_E2K_KERNEL_PAGE_SIZE);
#ifdef	CONFIG_KERNEL_CODE_CONTEXT
		boot_printk("The kernel 'protected text' segment: base 0x%lx size 0x%lx page size 0x%x\n",
			area_base, area_size, E2K_KERNEL_PROT_PAGE_SIZE);
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */

		area_base = (unsigned long) boot_vp_to_pp(__init_begin);
		area_size = (unsigned long) (__init_end - __init_begin);
		ret = _boot_reserve_physmem(area_base, area_size, PAGE_SIZE, 0);
		if (ret) {
			BOOT_BUG_POINT("boot_reserve_all_bootmem");
			BOOT_BUG("Could not reserve kernel 'init' segment: base addr 0x%lx size 0x%lx page size 0x%x",
				area_base, area_size, PAGE_SIZE);
		}
		boot_printk("The kernel 'init' segment: base 0x%lx size 0x%lx page size 0x%x\n",
			area_base, area_size, PAGE_SIZE);

		read_OSGD_reg(&OSGD);
		area_base = OSGD.OSGD_base;
		area_size = OSGD.OSGD_size;
		ret = _boot_reserve_physmem(area_base, area_size,
				BOOT_E2K_KERNEL_PAGE_SIZE, 0);
		if (ret != 0) {
			BOOT_BUG_POINT("boot_reserve_all_bootmem");
			BOOT_BUG("Could not reserve kernel 'data/bss' "
				"segments: base addr 0x%lx size 0x%lx page "
				"size 0x%x",
				area_base, area_size, BOOT_E2K_KERNEL_PAGE_SIZE);
		}
		boot_data_phys_base = area_base;
		boot_data_size = area_size;
		boot_printk("The kernel 'data/bss' segment: "
			"base addr 0x%lx size 0x%lx page size 0x%x\n",
			area_base, area_size, BOOT_E2K_KERNEL_PAGE_SIZE);
#ifdef	CONFIG_SMP
	}
#endif	/* CONFIG_SMP */

	/*
	 * Reserve memory of boot-time hardware procedures stack (PS).
	 * 'PSP' register-pointer describes this area.
	 */

	PSP = RAW_READ_PSP_REG();
	area_base = PSP.PSP_base;
	area_size = PSP.PSP_size;
	ret = _boot_reserve_physmem(area_base,
			area_size + E2K_KERNEL_PS_PAGE_SIZE,
			E2K_KERNEL_PS_PAGE_SIZE,
			1);	/* ignore if stack area is busy */
	if (ret != 0) {
		BOOT_BUG_POINT("boot_reserve_all_bootmem");
		BOOT_BUG("Could not reserve kernel boot-time procedure stack: "
			"base addr 0x%lx size 0x%lx page size 0x%x",
			area_base, area_size + E2K_KERNEL_PS_PAGE_SIZE,
			E2K_KERNEL_PS_PAGE_SIZE);
	}
	boot_boot_ps_phys_base = area_base;
	boot_boot_ps_size = area_size;
	boot_printk("The kernel boot-time procedures stack: "
		"base addr 0x%lx size 0x%lx page size 0x%x\n",
		area_base, area_size + E2K_KERNEL_PS_PAGE_SIZE,
		E2K_KERNEL_PS_PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
	boot_add_nosave_area(area_base, area_size + E2K_KERNEL_PS_PAGE_SIZE);
#endif	/* CONFIG_RECOVERY */

	/*
	 * Reserve memory of boot-time hardware procedure chain stack (PCS).
	 * 'PCSP' register-pointer describes this area.
	 */

	PCSP = RAW_READ_PCSP_REG();
	area_base = PCSP.PCSP_base;
	area_size = PCSP.PCSP_size;
	ret = _boot_reserve_physmem(area_base,
			area_size + E2K_KERNEL_PCS_PAGE_SIZE,
			E2K_KERNEL_PCS_PAGE_SIZE,
			1);	/* ignore if stack area is busy */
	if (ret != 0) {
		BOOT_BUG_POINT("boot_reserve_all_bootmem");
		BOOT_BUG("Could not reserve kernel boot-time procedure chain "
			"stack: base addr 0x%lx size 0x%lx page size 0x%x",
			area_base, area_size + E2K_KERNEL_PCS_PAGE_SIZE,
			E2K_KERNEL_PCS_PAGE_SIZE);
	}
	boot_boot_pcs_phys_base = area_base;
	boot_boot_pcs_size = area_size;
	boot_printk("The kernel boot-time procedure chain stack: "
		"base addr 0x%lx size 0x%lx page size 0x%x\n",
		area_base, area_size + E2K_KERNEL_PCS_PAGE_SIZE,
		E2K_KERNEL_PCS_PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
	boot_add_nosave_area(area_base, area_size + E2K_KERNEL_PCS_PAGE_SIZE);
#endif	/* CONFIG_RECOVERY */

	/*
	 * Reserve memory of boot-time kernel stack (user stack) (US).
	 * 'SBR + USD' registers describe this area.
	 */

	USBR = read_USBR_reg();
	area_base = USBR.USBR_base;
	read_USD_reg(&USD);
	boot_printk("The kernel boot-time data stack: "
		"USBR_base 0x%lx USD_base 0x%lx USD_size 0x%lx\n",
		USBR.USBR_base, USD.USD_base, USD.USD_size);
	area_size = area_base - USD.USD_base;
	area_offset = USD.USD_size;
	area_size += area_offset;
	area_base -= area_size;
	ret = _boot_reserve_physmem(area_base, area_size,
			E2K_KERNEL_US_PAGE_SIZE,
			1);	/* ignore if stack area is busy */
	if (ret != 0) {
		BOOT_BUG_POINT("boot_reserve_all_bootmem");
		BOOT_BUG("Could not reserve kernel boot-time data stack: "
			"base addr 0x%lx size 0x%lx USD offset 0x%lx page "
			"size 0x%x",
			area_base, area_size, area_offset,
			E2K_KERNEL_US_PAGE_SIZE);
	}
	boot_boot_stack_phys_base = area_base;
	boot_boot_stack_phys_offset = area_offset;
	boot_boot_stack_size = area_size;
	boot_printk("The kernel boot-time data stack: "
		"base addr 0x%lx size 0x%lx USD offset 0x%lx page size 0x%x\n",
		area_base, area_size, area_offset, E2K_KERNEL_US_PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
	boot_add_nosave_area(area_base, area_size);
#endif	/* CONFIG_RECOVERY */

	/*
	 * Reserve memory of PC reserved area (640K - 1M).
	 */

#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */
		area_base = 640 * 1024;			/* ROM, VGA ... */
		area_size = 1 * 1024 * 1024 - area_base;
		ret = _boot_reserve_physmem(area_base, area_size,
				E2K_X86_HW_PAGE_SIZE,
				0);	/* do not ignore if PC area is busy */
		if (ret != 0) {
			BOOT_BUG_POINT("boot_reserve_all_bootmem");
			BOOT_BUG("Could not reserve PC area: "
				"base addr 0x%lx size 0x%lx page size 0x%x",
				area_base, area_size, E2K_X86_HW_PAGE_SIZE);
		}
		boot_x86_hw_phys_base = area_base;
		boot_x86_hw_size      = area_size;
		boot_printk("The PC reserved area: "
			"base addr 0x%lx size 0x%lx page size 0x%x\n",
			area_base, area_size, E2K_X86_HW_PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
		boot_add_nosave_area(area_base, area_size);
#endif	/* CONFIG_RECOVERY */
#ifdef	CONFIG_SMP
	}
#endif	/* CONFIG_SMP */

	/*
	 * Reserve boot information records.
	 */

#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */
		area_base = boot_bootinfo_phys_base;	/* cmdline ... */
		area_size = 0;
		{
			boot_info_t *bblock;

			bblock = &boot_bootblock_phys->info;
			if ( bblock->signature == ROMLOADER_SIGNATURE ){
				area_size = sizeof(bootblock_struct_t);
			} else if (bblock->signature == X86BOOT_SIGNATURE) {
				area_size = sizeof(bootblock_struct_t);
			} else {
				BOOT_BUG_POINT("boot_reserve_all_bootmem");
				BOOT_BUG("Unknown type of Boot information "
					"structure");
			}
		}
		ret = _boot_reserve_physmem(area_base, area_size,
			E2K_BOOTINFO_PAGE_SIZE,
			0);	/* do not ignore if BOOTINFO area is busy */
		if (ret != 0) {
			BOOT_BUG_POINT("boot_reserve_all_bootmem");
			BOOT_BUG("Could not reserve BOOTINFO area: "
				"base addr 0x%lx size 0x%lx page size 0x%x",
				area_base, area_size, E2K_BOOTINFO_PAGE_SIZE);
		}

		boot_bootinfo_phys_base = area_base;
		boot_bootinfo_size      = area_size;

		boot_printk("The BOOTINFO reserved area: "
			"base addr 0x%lx size 0x%lx page size 0x%x\n",
			area_base, area_size, E2K_BOOTINFO_PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
#if (CONFIG_CNT_POINTS_NUM != 1)
		/*
		 * In the case of control point 1 we should save bootblock to
		 * restore it during quick restart. As bootblock is placed in
		 * one place for both control points, using for creating
		 * the control point for quick restart, we save the bootblock
		 * of the second control point. But boot initializes needfull
		 * fields of bootblock, so we can do that.
		 */
		boot_add_nosave_area(area_base, area_size);
#endif	/* CONFIG_CNT_POINTS_NUM != 1 */
#endif	/* CONFIG_RECOVERY */

		/*
		 * Reserve the needed areas from boot information records.
		 */

		boot_reserve_bootinfo_areas();
#ifdef	CONFIG_SMP
	}
#endif	/* CONFIG_SMP */

	/*
	 * Reserve memory used by BIOS (e3m loader)
	 */

#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */
#ifndef	CONFIG_RECOVERY
		if (!BOOT_IS_MACHINE_E3M)
#endif	/* CONFIG_RECOVERY */
		{
			boot_info = &boot_bootblock_phys->info;
			for (bank = 0; bank < boot_info->num_of_busy; bank ++) {
				bank_info_t *busy_area;
				busy_area = &boot_info->busy[bank];
				area_base = busy_area->address;
				area_size = busy_area->size;
				ret = _boot_reserve_physmem(area_base,
					area_size,
					PAGE_SIZE,
					1);	/* ignore if area is busy */
				if (ret != 0) {
					BOOT_BUG_POINT(
						"boot_reserve_all_bootmem");
					BOOT_BUG("Could not reserve BIOS data "
						"area #%d : base addr 0x%lx "
						"size 0x%lx page size 0x%x",
						bank, area_base, area_size,
						PAGE_SIZE);
				}
				boot_printk("The BIOS data reserved area #%d : "
					"base addr 0x%lx size 0x%lx page size "
					"0x%x\n",
					bank, area_base, area_size, PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
				boot_add_nosave_area(area_base, area_size);
#endif	/* CONFIG_RECOVERY */
			}
		}

#ifdef	CONFIG_SMP
	}
#endif	/* CONFIG_SMP */

#ifdef CONFIG_DEBUG_PAGEALLOC

	/*
	 * Resereve some memory from the begining of physical memory
	 * This memory was mapped to small pages (from physical
	 * memory start to start of X86 low IO memory area)
	 * Freed memory will be used to split first large pages
	 */

#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */
		if (boot_start_of_phys_memory + DEBUG_PAGEALLOC_AREA_SIZE < 
			E2K_X86_LOW_IO_AREA_PHYS_BASE) {

			/*
			 * We start to reserve memory with PAGE_SIZE offset
			 * because first page from boot_start_of_phys_memory
			 * has already reserved in boot_reserve_all_bootmem()
			 */
			area_base = boot_start_of_phys_memory + PAGE_SIZE;
			area_size = DEBUG_PAGEALLOC_AREA_SIZE - PAGE_SIZE;
			ret = _boot_reserve_physmem(area_base, area_size,
					PAGE_SIZE,
					0);	/* do not ignore if area */
						/* is busy */
			if (ret != 0) {
				BOOT_BUG_POINT("boot_reserve_all_bootmem");
				BOOT_BUG("Could not reserve DEBUG PAGEALLOC "
					"area: base addr 0x%lx size 0x%lx "
					"page size 0x%x",
					area_base, area_size, PAGE_SIZE);
			}
			boot_printk("The DEBUG PAGEALLOC reserved area: "
				"base addr 0x%lx size 0x%lx page size 0x%x\n",
				area_base, area_size, PAGE_SIZE);
		}
#ifdef	CONFIG_SMP
	}
#endif	/* CONFIG_SMP */
#endif	/* CONFIG_DEBUG_PAGEALLOC */

	/*
	 * Reserve memory for the second control point, which is needed for
	 * creating of memory dump of the system for quick restart.
	 */

#if defined (CONFIG_RECOVERY) && (CONFIG_CNT_POINTS_NUM < 2)
#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */
		if ((boot_cnt_points_num == 1 || boot_dump_analyze_opt) &&
			boot_cur_cnt_point == 0) {
			e2k_phys_bank_t	*phys_bank;
			node_phys_mem_t	*full_node_mem;
			e2k_addr_t mem_base;
			e2k_size_t mem_size;
			int cntp_num = boot_cntp_small_kern_mem_div;
			int bank;
			int node;

			full_node_mem = boot_full_phys_mem;
			for (node = 0; node < L_MAX_MEM_NUMNODES; node++) {
				for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS;
					bank++) {
					
					phys_bank = &full_node_mem->banks[bank];
					if (phys_bank->pages_num == 0)
						break;
					mem_base = get_cntp_memory_base(
						phys_bank,
						cntp_num - 1,
						cntp_num);
					mem_size = get_cntp_memory_len(
						phys_bank, 
						cntp_num - 1, 
						cntp_num);
					if (mem_size == 0)
						continue;
					phys_bank++;

					area_base = mem_base;
					area_size = mem_size;
					ret = _boot_reserve_physmem(
							area_base, area_size,
							PAGE_SIZE,
							0);
					if (ret != 0) {
						BOOT_BUG_POINT(
							"boot_reserve_all_bootmem");
						BOOT_BUG("Could not reserve "
							"cntp area on node "
							"#%d bank #%d: base "
							"addr 0x%lx size "
							"0x%lx page size 0x%x",
							node, bank, area_base, 
							area_size, PAGE_SIZE);
					}
					boot_printk("The CNTP reserved area "
						"on node #%d bank #%d: base "
						"addr 0x%lx size 0x%lx page "
						"size 0x%x\n",
						node, bank, area_base,
						area_size, PAGE_SIZE);
					boot_add_nosave_area(
						area_base, area_size);
				}
				full_node_mem++;
			}
		}
#ifdef	CONFIG_SMP
	}
#endif	/* CONFIG_SMP */
#endif	/* CONFIG_RECOVERY && (CONFIG_CNT_POINTS_NUM < 2) */
}

#ifdef	CONFIG_L_IO_APIC
/*
 * Reserve the needed memory from MP - tables
 */

static	void __init
boot_reserve_mp_table(boot_info_t *bblock)
{
	e2k_addr_t	area_base;
	e2k_size_t	area_size;
	int		ret;
	struct intel_mp_floating *mpf;

	if (bblock->mp_table_base == (e2k_addr_t)0UL)
		return;

	/*
	 * MP floating specification table
	 */

	area_base = bblock->mp_table_base;
	area_size = E2K_MPT_PAGE_SIZE;
	ret = _boot_reserve_physmem(area_base, area_size,
			E2K_MPT_PAGE_SIZE,
			1);	/* ignore if MP-table area is busy */
	if (ret != 0) {
		BOOT_BUG_POINT("boot_reserve_mp_table");
		BOOT_BUG("Could not reserve MP floating table area: "
			"base addr 0x%lx size 0x%lx page size 0x%x",
			area_base, area_size, E2K_MPT_PAGE_SIZE);
	}
	boot_mpf_phys_base = area_base;
	boot_mpf_size = area_size;
	boot_printk("The MP floating table: "
		"base addr 0x%lx size 0x%lx page size 0x%x\n",
		area_base, area_size, E2K_MPT_PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
	boot_add_nosave_area(area_base, area_size);
#endif	/* CONFIG_RECOVERY */

	mpf = (struct intel_mp_floating *)bblock->mp_table_base;
	if (DEBUG_BOOT_MODE) {
		int i;
		for (i = 0; i < sizeof (struct intel_mp_floating) / 8; i ++) {
			do_boot_printk("mpf[%d] = 0x%lx\n", i, ((u64 *)mpf)[i]);
		}
	}

	/*
	 * MP configuration table
	 */

	if (mpf->mpf_physptr != (e2k_addr_t)0UL) {
		area_base = mpf->mpf_physptr;
		area_size = E2K_MPT_PAGE_SIZE;
		ret = _boot_reserve_physmem(area_base, area_size,
				E2K_MPT_PAGE_SIZE,
				1);	/* ignore if MP-table area is busy */
		if (ret != 0) {
			BOOT_BUG_POINT("boot_reserve_mp_table");
			BOOT_BUG("Could not reserve MP configuration table "
				"area: base addr 0x%lx size 0x%lx "
				"page size 0x%x",
				area_base, area_size, E2K_MPT_PAGE_SIZE);
		}
		boot_mpc_phys_base = area_base;
		boot_mpc_size = area_size;
		boot_printk("The MP configuration table: "
			"base addr 0x%lx size 0x%lx page size 0x%x\n",
			area_base, area_size, E2K_MPT_PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
		boot_add_nosave_area(area_base, area_size);
#endif	/* CONFIG_RECOVERY */
	}
}
#endif	/* CONFIG_L_IO_APIC */

/*
 * Reserve the needed memory from boot-info used by boot-time initialization.
 * All the used memory areas from boot info enumerate below.
 * If a some new area will be used, then it should be added to the list
 * of already known ones.
 */

static	void __init
boot_reserve_bootinfo_areas(void)
{
#ifdef CONFIG_BLK_DEV_INITRD
	e2k_addr_t	area_base;
	e2k_size_t	area_size;
	int		ret;
#endif	/* CONFIG_BLK_DEV_INITRD */
	boot_info_t	*bblock;

	bblock = &boot_bootblock_phys->info;

#ifdef CONFIG_BLK_DEV_INITRD

	/*
	 * Reserve memory of initial ramdisk (initrd).
	 */

	area_base = bblock->ramdisk_base;	/* INITRD_BASE and */
	area_size = bblock->ramdisk_size;	/* INITRD_SIZE */
						/* comes from Loader */
	if (area_size) {
		ret = _boot_reserve_physmem(area_base, area_size,
				E2K_INITRD_PAGE_SIZE,
				0);	/* do not ignore if initrd area */
					/* is busy */
		if (ret != 0) {
			BOOT_BUG_POINT("boot_reserve_bootinfo_areas");
			BOOT_BUG("Could not reserve initial ramdisk area: "
				"base addr 0x%lx size 0x%lx page size 0x%x",
				area_base, area_size, E2K_INITRD_PAGE_SIZE);
		}
		boot_initrd_phys_base = area_base;
		boot_initrd_size = area_size;
		boot_printk("The initial ramdisk area: "
			"base addr 0x%lx size 0x%lx page size 0x%x\n",
			area_base, area_size, E2K_INITRD_PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
	boot_add_nosave_area(area_base, area_size);
#endif	/* CONFIG_RECOVERY */
	} else {
		boot_printk("Initial ramdisk size is zero\n");
	}
#endif	/* CONFIG_BLK_DEV_INITRD */

	/*
	 * Reserv MP configuration table
	 */

#ifdef	CONFIG_L_IO_APIC
	if (bblock->mp_table_base != (e2k_addr_t)0UL)
		boot_reserve_mp_table(bblock);
#endif	/* CONFIG_L_IO_APIC */
}

/*
 * Allocate the physical memory used by boot-time initialization
 */

static	void __init
boot_alloc_init_stacks(void)
{
	e2k_addr_t	area_base;
	e2k_size_t	area_size;

	/*
	 * Allocate memory for kernel initial stacks (hardware & software)
	 * The stacks will be later stacks of cpu_idle() process
	 */

	area_size = KERNEL_P_STACK_SIZE;
	area_base = (e2k_addr_t) boot_alloc_phys_mem(area_size, PAGE_SIZE);
	if (area_base == -1) {
		BOOT_BUG_POINT("boot_alloc_init_stacks");
		BOOT_BUG("Could not allocate memory for kernel initial procedure stack");
	}
	boot_init_ps_phys_base = area_base;
	boot_init_ps_size = area_size;
	boot_printk("Allocated the kernel initial procedures stack: base addr 0x%lx size 0x%lx + page size 0x%x\n",
		area_base, area_size, E2K_KERNEL_PS_PAGE_SIZE);

	area_size = KERNEL_PC_STACK_SIZE;
	area_base = (e2k_addr_t) boot_alloc_phys_mem(area_size, PAGE_SIZE);
	if (area_base == -1) {
		BOOT_BUG_POINT("boot_alloc_init_stacks");
		BOOT_BUG("Could not allocate memory for kernel initial procedure chain stack");
	}
	boot_init_pcs_phys_base = area_base;
	boot_init_pcs_size = area_size;
	boot_printk("Allocated the kernel initial procedure chain stack: base addr 0x%lx size 0x%lx + page size 0x%x\n",
		area_base, area_size, E2K_KERNEL_PCS_PAGE_SIZE);

	area_size = KERNEL_C_STACK_SIZE;
	area_base = (e2k_addr_t) boot_alloc_phys_mem(area_size,	PAGE_SIZE);
	if (area_base == -1) {
		BOOT_BUG_POINT("boot_alloc_init_stacks");
		BOOT_BUG("Could not allocate memory for kernel initial data stack");
	}
	boot_init_stack_phys_base = area_base;
	boot_init_stack_size = area_size;
	boot_init_stack_phys_offset = 0;
	boot_printk("Allocated the kernel initial data stack: base addr 0x%lx size 0x%lx, page size 0x%x\n",
		area_base, area_size, E2K_KERNEL_US_PAGE_SIZE);
}

#ifdef	CONFIG_NUMA
static void __init
boot_node_set_dup_kernel(void *dup_start)
{
	e2k_addr_t data_offset;

	if (dup_start == (void *)-1) {
		BOOT_BUG_POINT("boot_node_set_dup_kernel");
		BOOT_BUG("Invalid or was not allocated duplicated kernel "
			"base\n");
	}
	boot_kernel_phys_base = (e2k_addr_t)dup_start;
	DebugNUMA("boot_node_set_dup_kernel() set kernel base to 0x%lx\n",
		(e2k_addr_t)dup_start);

	boot_text_phys_base = (e2k_addr_t)dup_start;
#ifdef	CONFIG_KERNEL_CODE_CONTEXT
	boot_prot_text_phys_base = (e2k_addr_t)dup_start +
		(boot_node_prot_text_phys_base(BOOT_BS_NODE_ID) -
		boot_node_text_phys_base(BOOT_BS_NODE_ID));
	boot_prot_text_size = boot_node_prot_text_size(BOOT_BS_NODE_ID);
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */
	boot_data_phys_base = boot_node_data_phys_base(BOOT_BS_NODE_ID);
	boot_data_size = boot_node_data_size(BOOT_BS_NODE_ID);
	data_offset = (e2k_addr_t)__node_data_start - KERNEL_BASE;
	boot_dup_data_phys_base = (e2k_addr_t)dup_start + data_offset;
}

static void __init
boot_node_duplicate_kernel(void)
{
	e2k_addr_t	area_base;
	e2k_addr_t	area_end;
	e2k_size_t	area_size;
	e2k_size_t	data_offset;
	void		*dup_start;
	int		node_id = boot_numa_node_id();

	if (BOOT_TEST_AND_SET_NODE_LOCK(boot_node_kernel_dup_lock,
					boot_node_kernel_duplicated)) {
		DebugNUMA("boot_node_duplicate_kernel() kernel was "
			"duplicated already on node\n");
		return;
	}
	area_base = boot_node_kernel_phys_base(BOOT_BS_NODE_ID);
	area_end = (e2k_addr_t)boot_vp_to_pp(__node_data_end);
	area_end = _PAGE_ALIGN_DOWN(area_end, PAGE_SIZE);
	if (area_end <= area_base) {
		BOOT_BUG_POINT("boot_node_duplicate_kernel");
		BOOT_BUG("Kernel node duplicate area end 0x%lx <= start 0x%lx",
			area_end, area_base);
	}
	area_size = area_end - area_base;
	data_offset = (e2k_addr_t)boot_vp_to_pp(__node_data_start) -
			area_base;
	if (data_offset > area_size) {
		BOOT_BUG_POINT("boot_node_duplicate_kernel");
		BOOT_BUG("Kernel node duplicate data offset 0x%lx > all "
			"area size 0x%lx",
			data_offset, area_size);
	}
	boot_dup_data_size = area_size - data_offset;
	if (!BOOT_IS_BS_NODE) {
		dup_start = boot_the_node_try_alloc_pages(node_id,
					area_size, BOOT_E2K_KERNEL_PAGE_SIZE);
		boot_kernel_phys_base = (e2k_addr_t)dup_start;
		boot_text_size = boot_node_text_size(BOOT_BS_NODE_ID);
		if (dup_start == (void *)-1) {
			BOOT_WARNING_POINT("boot_node_duplicate_kernel");
			BOOT_WARNING("Could not allocate memory on the node "
				"#%d to duplicate kernel text, size 0x%lx",
				node_id, area_size);
			dup_start = (void *)area_base;
		} else {
			memcpy(dup_start, (char *)area_base, area_size);
			boot_atomic_inc(&boot_node_has_dup_kernel_num);
			DebugNUMA("boot_node_duplicate_kernel() allocated "
				"area and duplicate to 0x%lx, size 0x%lx\n",
				(e2k_addr_t)dup_start, area_size);
			boot_node_set_dup_kernel(dup_start);
		}
	} else {
		dup_start = (void *)area_base;
		DebugNUMA("boot_node_duplicate_kernel() node "
			"is BS NODE area 0x%lx, size 0x%lx\n",
			(e2k_addr_t)dup_start, area_size);
		boot_dup_data_phys_base = (e2k_addr_t)dup_start + data_offset;
	}
	BOOT_NODE_UNLOCK(boot_node_kernel_dup_lock,
				boot_node_kernel_duplicated);
}

static void __init
boot_node_set_duplicated_mode(void)
{
	int	has_not_dup = 0;
	int	node_id = boot_numa_node_id();
	int	dup_nid;
	int	nid;
	int	dup_nodes_num = 0;

	if (BOOT_TEST_AND_SET_NODE_LOCK(boot_node_kernel_dup_lock,
					boot_node_set_kernel_duplicated)) {
		DebugNUMA("boot_node_set_duplicated_mode() kernel was "
			"set duplicated mode already on node\n");
		return;
	}
	if (!BOOT_EARLY_THE_NODE_HAS_DUP_KERNEL(node_id)) {
		has_not_dup = 1;
		dup_nid = boot_early_get_next_node_has_dup_kernel(node_id);
		if (dup_nid >= MAX_NUMNODES || dup_nid < 0) {
			BOOT_BUG_POINT("boot_node_set_duplicated_mode");
			BOOT_BUG("Could not find node with duplicated kernel "
				"to share it\n");
		}
		DebugNUMA("boot_node_set_duplicated_mode() node has not "
			"own copy of kernel image and will use NODE #%d "
			"image and page table\n",
			dup_nid);
	} else {
		dup_nid = node_id;
		DebugNUMA("boot_node_set_duplicated_mode() node has own "
			"copy of kernel image from 0x%lx\n",
			boot_kernel_phys_base);
	}
	if (BOOT_IS_BS_NODE) {
		dup_nodes_num = boot_atomic_read(
					&boot_node_has_dup_kernel_num);
	}
	
	boot_for_each_node_has_online_mem(nid) {
		if (!BOOT_EARLY_THE_NODE_HAS_DUP_KERNEL(nid))
			continue;
		boot_the_node_dup_kernel_nid(nid)[node_id] = dup_nid;
		DebugNUMA("boot_node_set_duplicated_mode() set "
			"duplicated node id 0x%p to #%d on node #%d\n",
			&(boot_the_node_dup_kernel_nid(nid)[node_id]),
			boot_the_node_dup_kernel_nid(nid)[node_id], nid);
		if (!has_not_dup) {
			boot_the_node_set_has_dup_kernel(nid, node_id);
		}
		if (BOOT_IS_BS_NODE) {
			boot_atomic_set(&boot_the_node_has_dup_kernel_num(nid),
							dup_nodes_num);
			DebugNUMA("boot_node_set_duplicated_mode() set "
				"duplicated nodes number 0x%p to %d on "
				"node #%d\n",
				&(boot_the_node_has_dup_kernel_num(nid)),
				boot_the_node_has_dup_kernel_num(nid), nid);
		}
		boot_the_node_pg_dir(nid)[node_id] =
			__va(boot_the_node_root_pt(dup_nid));
		DebugNUMA("boot_node_set_duplicated_mode() set "
			"pg_dir pointer 0x%p to 0x%lx on node #%d\n",
			&(boot_the_node_pg_dir(nid)[node_id]),
			boot_the_node_pg_dir(nid)[node_id], nid);
	}
	BOOT_NODE_UNLOCK(boot_node_kernel_dup_lock,
				boot_node_set_kernel_duplicated);
}

static void __init
boot_node_set_kernel_base(void)
{
	int dup_nid;

	if (BOOT_EARLY_NODE_HAS_DUP_KERNEL()) {
		DebugNUMA("boot_node_set_kernel_base() node has own copy and "
			"set already kernel base of copy\n");
		return;
	}
	if (BOOT_TEST_AND_SET_NODE_LOCK(boot_node_kernel_dup_lock,
					boot_node_kernel_base_is_set)) {
		DebugNUMA("boot_node_set_kernel_base() kernel base was "
			"set already on node\n");
		return;
	}
	dup_nid = boot_my_node_dup_kernel_nid;
	if (dup_nid >= MAX_NUMNODES || dup_nid < 0) {
		BOOT_BUG_POINT("boot_node_set_kernel_base");
		BOOT_BUG("Invalid duplicated kernel node id %d\n", dup_nid);
	}
	boot_node_set_dup_kernel((void *)boot_node_kernel_phys_base(dup_nid));
	BOOT_NODE_UNLOCK(boot_node_kernel_dup_lock,
				boot_node_kernel_base_is_set);
}
#endif	/* CONFIG_NUMA */

#ifndef CONFIG_DISCONTIGMEM
static	void __init
boot_alloc_all_bootmem(void)
{
	e2k_addr_t	area_base;
	e2k_size_t	area_size;

	/*
	 * Allocate memory to support bootmap of simple boot-time physical
	 * memory area allocator and free memory collector.
	 * ('linux/mm/bootmem.c')
	 */

	area_size = bootmem_bootmap_pages(boot_end_of_phys_memory -
						boot_start_of_phys_memory);
	area_base = (e2k_addr_t)boot_alloc_phys_mem(area_size, PAGE_SIZE);
	if (area_base == (e2k_addr_t)-1) {
		BOOT_BUG_POINT("boot_alloc_all_bootmem");
		BOOT_BUG("Could not allocate memory for bitmap of "
			"'linux/mm/bootmem.c'");
	}
	boot_bootmap_phys_base = area_base;
	boot_bootmap_size = area_size;
	boot_printk("Allocated the memory for bitmap of 'linux/mm/bootmem.c': "
		"base addr 0x%lx size 0x%lx, page size 0x%x\n",
		area_base, area_size, PAGE_SIZE);
}
#else	/* CONFIG_DISCONTIGMEM */
static	void __init
boot_alloc_all_bootmem(void)
{
	e2k_addr_t		area_base;
	e2k_size_t		bootmap_pages;
	e2k_size_t		area_size;
	node_phys_mem_t		*all_nodes_mem = NULL;
	node_phys_mem_t		*node_mem = NULL;
	int			nodes_num;
	int			cur_nodes_num = 0;
	int			node;

	/*
	 * Allocate memory to support bootmap of simple boot-time physical
	 * memory area allocator and free memory collector on the node.
	 * ('linux/mm/bootmem.c')
	 */

	all_nodes_mem = boot_vp_to_pp(boot_phys_mem);
	nodes_num = boot_phys_mem_nodes_num;
	for (node = 0; node < L_MAX_MEM_NUMNODES; node ++) {
		if (cur_nodes_num >= nodes_num)
			break;	/* no more nodes with memory */
		node_mem = &all_nodes_mem[node];
		if (node_mem->pfns_num == 0)
			continue;	/* node has not memory */
		cur_nodes_num ++;
		bootmap_pages = bootmem_bootmap_pages(node_mem->pfns_num);
		area_size = bootmap_pages * PAGE_SIZE;
#ifndef	CONFIG_NUMA
		area_base = (e2k_addr_t)boot_alloc_phys_mem(area_size,
								PAGE_SIZE);
#else	/* CONFIG_NUMA */
		area_base = (e2k_addr_t)boot_node_alloc_physmem(node,
							area_size, PAGE_SIZE);
#endif	/* ! CONFIG_NUMA */
		if (area_base == (e2k_addr_t)-1) {
			BOOT_BUG_POINT("boot_alloc_all_bootmem");
			BOOT_BUG("Could not allocate memory for bitmap "
				"of 'linux/mm/bootmem.c' on node #%d "
				"size 0x%lx", node, area_size);
		}
		boot_node_bootmap_phys_base(node) = area_base;
		boot_node_bootmap_size(node) = area_size;
		boot_printk("Allocated the memory for bitmap of "
			"'linux/mm/bootmem.c' on node #%d : "
			"base addr 0x%lx size 0x%lx, page size 0x%x\n",
			node, area_base, area_size, PAGE_SIZE);
		if (cur_nodes_num >= nodes_num)
			break;	/* no more nodes with memory */
	}
}
#endif	/* ! CONFIG_DISCONTIGMEM */

__init int boot_is_pfn_valid(e2k_size_t pfn)
{
	node_phys_mem_t	*nodes_mem = NULL;
	int		nodes_num;
	int		cur_nodes_num = 0;
	int		node;
	int		bank;

	nodes_mem = boot_vp_to_pp(boot_phys_mem);
	nodes_num = boot_phys_mem_nodes_num;
	for (node = 0; node < L_MAX_MEM_NUMNODES; node ++) {
		boot_phys_bank_t *phys_bank;

		if (cur_nodes_num >= nodes_num)
			break;	/* no more nodes with memory */
		if (nodes_mem[node].pfns_num == 0)
			continue;	/* node has not memory */
		phys_bank = nodes_mem[node].banks;
		cur_nodes_num ++;
		for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank ++) {
			e2k_addr_t	bank_pfn;
			if (phys_bank->pages_num == 0)
				break;	/* no more banks on node */
			bank_pfn = phys_bank->base_addr >> PAGE_SHIFT;
			if (pfn >= bank_pfn &&
				pfn < bank_pfn + phys_bank->pages_num)
				return 1;
			phys_bank ++;
		}
		if (cur_nodes_num >= nodes_num)
			break;	/* no more nodes with memory */
	}
	return 0;
}

/*
 * Map into the virtual space all physical areas used by kernel while
 * boot-time initialization and needed later.
 * All the mapped areas enumerate below. If a some new area will be used,
 * then it should be added to the list of already known ones.
 */

static	void __init
boot_map_all_bootmem(void)
{
	unsigned long	base, size;
	e2k_addr_t	area_phys_base, area_virt_base;
	e2k_addr_t	bs_text_phys_base;
	e2k_addr_t	text_phys_base, text_virt_base;
	e2k_size_t	text_size, area_size;
#ifdef	CONFIG_KERNEL_CODE_CONTEXT
	e2k_addr_t	prot_text_phys_base, prot_text_virt_base;
	e2k_size_t	prot_text_size;
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */
#ifdef	CONFIG_NUMA
	e2k_addr_t	dup_data_phys_base, dup_data_virt_base;
	e2k_size_t	dup_data_size;
	e2k_addr_t	rem_text_phys_base = 0, rem_text_virt_base = 0;
	e2k_size_t	rem_text_size;
	e2k_addr_t	rem_text_end;
	pgprot_t	rem_text_prot;
#endif	/* CONFIG_NUMA */
#if defined(CONFIG_KERNEL_CODE_CONTEXT) || defined(CONFIG_NUMA)
	e2k_size_t	map_size;
#endif	/* CONFIG_KERNEL_CODE_CONTEXT || CONFIG_NUMA */
	e2k_addr_t	data_phys_base, data_virt_base;
	e2k_size_t	data_size;
	int		ret;

	/*
	 * Map the kernel image 'text/data/bss' segments.
	 * 'text' and 'data/bss' segments can intersect or one can include
	 * other.
	 */

#ifdef	CONFIG_SMP
	if (!BOOT_TEST_AND_SET_NODE_LOCK(boot_node_map_lock,
						boot_node_image_mapped)) {
#endif	/* CONFIG_SMP */
#ifdef CONFIG_NUMA
		if (!BOOT_THERE_IS_DUP_KERNEL && !BOOT_IS_BS_NODE) {
			DebugNUMA("boot_map_all_bootmem() node "
				"has not own page table and will use "
				"BS image mapping\n");
			goto no_mapping;
		} else {
			DebugNUMA("boot_map_all_bootmem() will map kernel "
				"image\n");
		}
#endif /* CONFIG_NUMA */
		text_phys_base = boot_text_phys_base;
		text_size = boot_text_size;
		DebugNUMA("boot_map_all_bootmem() text phys base 0x%lx, size "
			"0x%lx\n",
			text_phys_base, text_size);
#ifdef	CONFIG_KERNEL_CODE_CONTEXT
		prot_text_phys_base = boot_prot_text_phys_base;
		prot_text_size = boot_prot_text_size;
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */

		data_phys_base = boot_data_phys_base;
		data_size = boot_data_size;
		DebugNUMA("boot_map_all_bootmem() data phys base 0x%lx, size "
			"0x%lx\n",
			data_phys_base, data_size);

#ifdef	CONFIG_NUMA
		dup_data_phys_base = boot_dup_data_phys_base;
		dup_data_size = boot_dup_data_size;
		if (BOOT_IS_BS_NODE) {
			bs_text_phys_base = text_phys_base;
			DebugNUMA("boot_map_all_bootmem() node "
				"is BS node, so does not duplicate kernel, "
				"BS image from 0x%lx\n",
				text_phys_base);
		} else if (!boot_node_has_dup_kernel()) {
			DebugNUMA("boot_map_all_bootmem() node "
				"has not duplicated kernel image and will use "
				"image of node #%d from 0x%lx\n",
				text_phys_base, boot_my_node_dup_kernel_nid);
			goto no_mapping;
		} else {
			bs_text_phys_base =
				boot_node_text_phys_base(BOOT_BS_NODE_ID);
			DebugNUMA("boot_map_all_bootmem() node "
				"has duplicated kernel image from 0x%lx\n",
				text_phys_base);
		}
		DebugNUMA("boot_map_all_bootmem() dup data phys base 0x%lx, "
			"size 0x%lx\n",
			dup_data_phys_base, dup_data_size);
#else
		bs_text_phys_base = text_phys_base;
#endif	/* CONFIG_NUMA */

		area_virt_base = KERNEL_BASE;

		if (BOOT_IS_BS_NODE && text_phys_base > data_phys_base) {
			BOOT_BUG_POINT("boot_map_all_bootmem");
			BOOT_BUG("The kernel 'text' segment base addr "
				"0x%lx > 0x%lx 'data' segment base",
				text_phys_base, data_phys_base);
		}

		text_virt_base = area_virt_base;
#if defined(CONFIG_KERNEL_CODE_CONTEXT) || defined(CONFIG_NUMA)
#ifdef	CONFIG_KERNEL_CODE_CONTEXT
		prot_text_virt_base = _PAGE_ALIGN_UP(text_virt_base +
				 	(prot_text_phys_base - text_phys_base),
					E2K_KERNEL_PROT_PAGE_SIZE);
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */
		data_virt_base = _PAGE_ALIGN_UP(text_virt_base +
				 	(data_phys_base - bs_text_phys_base),
					E2K_SMALL_PAGE_SIZE);
		data_phys_base = _PAGE_ALIGN_UP(data_phys_base,
						E2K_SMALL_PAGE_SIZE);
		DebugNUMA("boot_map_all_bootmem() UP data phys base 0x%lx, "
			"size 0x%lx\n",
			data_phys_base, data_size);
#ifdef	CONFIG_NUMA
		dup_data_phys_base = _PAGE_ALIGN_UP(dup_data_phys_base,
						E2K_SMALL_PAGE_SIZE);
		DebugNUMA("boot_map_all_bootmem() UP dup data phys base "
			"0x%lx, size 0x%lx\n",
			dup_data_phys_base, dup_data_size);
#endif	/* CONFIG_NUMA */
#else	/* ! CONFIG_KERNEL_CODE_CONTEXT && ! CONFIG_NUMA */
		data_virt_base = _PAGE_ALIGN_UP(text_virt_base +
				 	(data_phys_base - bs_text_phys_base),
					BOOT_E2K_KERNEL_PAGE_SIZE);
		data_phys_base = _PAGE_ALIGN_UP(data_phys_base,
						BOOT_E2K_KERNEL_PAGE_SIZE);
#endif	/* CONFIG_KERNEL_CODE_CONTEXT || CONFIG_NUMA */
		data_size += (boot_data_phys_base - data_phys_base);
		DebugNUMA("boot_map_all_bootmem() updated data size: phys "
			"base 0x%lx, size 0x%lx\n",
			data_phys_base, data_size);
#ifdef	CONFIG_NUMA
		if (BOOT_IS_BS_NODE && dup_data_phys_base != data_phys_base) {
			BOOT_BUG_POINT("boot_map_all_bootmem");
			BOOT_BUG("The kernel 'data' segment base "
				"addr 0x%lx is not the same as node "
				"duplicated data base 0x%lx",
				data_phys_base, dup_data_phys_base);
		}
#endif	/* CONFIG_NUMA */
#ifdef	CONFIG_NUMA
		dup_data_size = _PAGE_ALIGN_DOWN(dup_data_size,
						E2K_SMALL_PAGE_SIZE);
		dup_data_size += (boot_dup_data_phys_base - dup_data_phys_base);
		dup_data_virt_base = data_virt_base;
		DebugNUMA("boot_map_all_bootmem() down dup data size: phys "
			"base 0x%lx, size 0x%lx\n",
			dup_data_phys_base, dup_data_size);
		data_phys_base += dup_data_size;
		data_virt_base += dup_data_size;
		data_size -= dup_data_size;
		DebugNUMA("boot_map_all_bootmem() update data phys "
			"base 0x%lx, size 0x%lx\n",
			data_phys_base, data_size);
#ifdef	CONFIG_KERNEL_CODE_CONTEXT
		rem_text_end = prot_text_phys_base + prot_text_size;
		rem_text_end = _PAGE_ALIGN_DOWN(rem_text_end,
						E2K_KERNEL_PROT_PAGE_SIZE);
		rem_text_phys_base = _PAGE_ALIGN_UP(prot_text_phys_base +
								prot_text_size,
						E2K_KERNEL_PROT_PAGE_SIZE);
#else	/* ! CONFIG_KERNEL_CODE_CONTEXT */
		rem_text_end = text_phys_base + text_size;
		rem_text_end = _PAGE_ALIGN_DOWN(rem_text_end,
						BOOT_E2K_KERNEL_PAGE_SIZE);
		rem_text_phys_base = _PAGE_ALIGN_UP(text_phys_base + text_size,
						BOOT_E2K_KERNEL_PAGE_SIZE);
		DebugNUMA("boot_map_all_bootmem() rem text phys "
			"base 0x%lx, end 0x%lx\n",
			rem_text_phys_base, rem_text_end);
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */
		if (rem_text_end > dup_data_phys_base) {
			/*
			 * Intersection of kernel text last page and
			 * duplicated data
			 */
			rem_text_size = dup_data_phys_base - rem_text_phys_base;
			DebugNUMA("boot_map_all_bootmem() rem text size "
				"0x%lx\n",
				rem_text_size);
#ifdef	CONFIG_KERNEL_CODE_CONTEXT
			prot_text_size -= rem_text_size;
			rem_text_virt_base = prot_text_virt_base +
				rem_text_phys_base - prot_text_phys_base;
			rem_text_prot = PAGE_KERNEL_PROT_TEXT;
#else	/* ! CONFIG_KERNEL_CODE_CONTEXT */
			text_size -= rem_text_size;
			rem_text_virt_base = text_virt_base +
				rem_text_phys_base - text_phys_base;
			rem_text_prot = PAGE_KERNEL_TEXT;
			DebugNUMA("boot_map_all_bootmem() update text size: "
				"phys base 0x%lx, size 0x%lx\n",
				text_phys_base, text_size);
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */
		} else {
			rem_text_size = 0;
			DebugNUMA("boot_map_all_bootmem() empty rem text size "
				"0x%lx\n",
				rem_text_size);
		}
#endif	/* CONFIG_NUMA */

		ret = boot_map_phys_area(text_phys_base, text_size,
			text_virt_base,
			PAGE_KERNEL_TEXT, BOOT_E2K_KERNEL_PAGE_SIZE,
			0);	/* do not ignore if text mapping virtual */
				/* area is busy */
		if (ret <= 0) {
			BOOT_BUG_POINT("boot_map_all_bootmem");
			BOOT_BUG("Could not map kernel 'text' segment: "
				"base addr 0x%lx size 0x%lx page size 0x%x to "
				"virtual addr 0x%lx",
				text_phys_base, text_size, BOOT_E2K_KERNEL_PAGE_SIZE,
				text_virt_base);
		}
		boot_text_virt_base = text_virt_base;
		boot_printk("The kernel 'text' segment: "
			"base addr 0x%lx size 0x%lx is mapped to %d virtual "
			"page(s) base addr 0x%lx page size 0x%x\n",
			text_phys_base, text_size, ret, text_virt_base,
			BOOT_E2K_KERNEL_PAGE_SIZE);

#ifdef	CONFIG_KERNEL_CODE_CONTEXT
		ret = boot_map_phys_area(prot_text_phys_base, prot_text_size,
			prot_text_virt_base,
			PAGE_KERNEL_PROT_TEXT, E2K_KERNEL_PROT_PAGE_SIZE,
			0);	/* do not ignore if text mapping virtual */
				/* area is busy */
		if (ret <= 0) {
			BOOT_BUG_POINT("boot_map_all_bootmem");
			BOOT_BUG("Could not map kernel 'prot text' segment: "
				"base addr 0x%lx size 0x%lx page size 0x%x to "
				"virtual addr 0x%lx",
				prot_text_phys_base, prot_text_size,
				E2K_KERNEL_PROT_PAGE_SIZE,
				prot_text_virt_base);
		}
		boot_prot_text_virt_base = prot_text_virt_base +
				(boot_prot_text_phys_base -
						prot_text_phys_base);
		boot_printk("The kernel 'protected text' segment: "
			"base addr 0x%lx size 0x%lx is mapped to %d virtual "
			"page(s) base addr 0x%lx page size 0x%x\n",
			prot_text_phys_base, prot_text_size, ret,
			prot_text_virt_base, E2K_KERNEL_PROT_PAGE_SIZE);
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */

		base = (unsigned long) boot_vp_to_pp(__init_text_begin);
		size = __init_text_end - __init_text_begin;
		ret = boot_map_phys_area(base, size,
					 (unsigned long) __init_text_begin,
					 PAGE_KERNEL_TEXT, PAGE_SIZE, 0);
		if (ret <= 0) {
			BOOT_BUG_POINT("boot_map_all_bootmem");
			BOOT_BUG("Could not map kernel '.init.text' segment: base addr 0x%lx size 0x%lx page size 0x%x to virtual addr 0x%lx",
				base, size, PAGE_SIZE, __init_text_begin);
		}

		base = (unsigned long) boot_vp_to_pp(__init_data_begin);
		size = __init_data_end - __init_data_begin;
		ret = boot_map_phys_area(base, size,
					 (unsigned long) __init_data_begin,
					 PAGE_KERNEL_DATA, PAGE_SIZE, 0);
		if (ret <= 0) {
			BOOT_BUG_POINT("boot_map_all_bootmem");
			BOOT_BUG("Could not map kernel '.init.data' segment: base addr 0x%lx size 0x%lx page size 0x%x to virtual addr 0x%lx",
				base, size, PAGE_SIZE, __init_data_begin);
		}

#ifdef	CONFIG_NUMA
		if (rem_text_size != 0) {
			ret = boot_map_phys_area(rem_text_phys_base,
				rem_text_size,
				rem_text_virt_base,
				rem_text_prot, E2K_SMALL_PAGE_SIZE,
				0);	/* do not ignore if data mapping */
					/* virtual area is busy */

			if (ret <= 0) {
				BOOT_BUG_POINT("boot_map_all_bootmem");
				BOOT_BUG("Could not map kernel ending of "
					"'text' segment: base addr 0x%lx size "
					"0x%lx page size 0x%x to virtual addr "
					"0x%lx",
					rem_text_phys_base, rem_text_size,
					E2K_SMALL_PAGE_SIZE,
					rem_text_virt_base);
			}
			boot_printk("The kernel ending of 'text' segment: "
				"base addr 0x%lx size 0x%lx is mapped to %d "
				"virtual page(s) base addr 0x%lx page size "
				"0x%x\n",
				rem_text_phys_base, rem_text_size, ret,
				rem_text_virt_base, E2K_SMALL_PAGE_SIZE);
		}
		if (dup_data_size != 0) {
			ret = boot_map_phys_area(dup_data_phys_base,
				dup_data_size,
				dup_data_virt_base,
				PAGE_KERNEL_DATA, E2K_SMALL_PAGE_SIZE,
				0);	/* do not ignore if data mapping */
					/* virtual area is busy */

			if (ret <= 0) {
				BOOT_BUG_POINT("boot_map_all_bootmem");
				BOOT_BUG("Could not map kernel ' duplicated "
					"data/bss' area: base addr 0x%lx size "
					"0x%lx page size 0x%x to virtual addr "
					"0x%lx",
					dup_data_phys_base, dup_data_size,
					E2K_SMALL_PAGE_SIZE,
					dup_data_virt_base);
			}
			boot_dup_data_virt_base = dup_data_virt_base +
				(boot_dup_data_phys_base - dup_data_phys_base);
			boot_printk("The kernel 'duplicated data/bss' area: "
				"base addr 0x%lx size 0x%lx is mapped to %d "
				"virtual page(s) base addr 0x%lx page size "
				"0x%x\n",
				dup_data_phys_base, dup_data_size, ret,
				dup_data_virt_base,
				E2K_SMALL_PAGE_SIZE);
		}
#endif	/* CONFIG_NUMA */

#if defined(CONFIG_KERNEL_CODE_CONTEXT) || defined(CONFIG_NUMA)
		map_size = data_phys_base & (BOOT_E2K_KERNEL_PAGE_SIZE - 1);
		if (map_size != 0) {
			map_size = _PAGE_ALIGN_DOWN(data_phys_base,
						BOOT_E2K_KERNEL_PAGE_SIZE) -
						map_size;
			if (map_size > data_size)
				map_size = data_size;
			ret = boot_map_phys_area(data_phys_base, map_size,
				data_virt_base,
				PAGE_KERNEL_DATA, E2K_SMALL_PAGE_SIZE,
				0);	/* do not ignore if data mapping */
					/* virtual area is busy */

			if (ret <= 0) {
				BOOT_BUG_POINT("boot_map_all_bootmem");
				BOOT_BUG("Could not map kernel 'data/bss' "
					"segment: base addr 0x%lx size 0x%lx "
					"page size 0x%x to virtual addr 0x%lx",
					data_phys_base, map_size,
					E2K_SMALL_PAGE_SIZE,
					data_virt_base);
			}
			boot_printk("The kernel 'data/bss' segment: "
				"base addr 0x%lx size 0x%lx is mapped to %d "
				"virtual small page(s) base addr 0x%lx page "
				"size 0x%x\n",
				data_phys_base, map_size, ret, data_virt_base,
				E2K_SMALL_PAGE_SIZE);
			data_size -= map_size;
			data_phys_base += map_size;
			data_virt_base += map_size;
		}
#endif	/* CONFIG_KERNEL_CODE_CONTEXT || CONFIG_NUMA */
		boot_data_virt_base = data_virt_base +
			(boot_data_phys_base - data_phys_base);
		if (data_size != 0) {
			ret = boot_map_phys_area(data_phys_base, data_size,
				data_virt_base,
				PAGE_KERNEL_DATA, BOOT_E2K_KERNEL_PAGE_SIZE,
#if !defined(CONFIG_KERNEL_CODE_CONTEXT) && !defined(CONFIG_NUMA)
				1);	/* ignore if data mapping virtual */
					/* area is busy */
#else	/* CONFIG_KERNEL_CODE_CONTEXT || CONFIG_NUMA */
				0);	/* do not ignore if data mapping */
					/* virtual area is busy */
#endif	/* ! CONFIG_KERNEL_CODE_CONTEXT && ! CONFIG_NUMA */

			if (ret <= 0) {
				BOOT_BUG_POINT("boot_map_all_bootmem");
				BOOT_BUG("Could not map kernel 'data/bss' "
					"segment: base addr 0x%lx size 0x%lx "
					"page size 0x%x to virtual addr 0x%lx",
					data_phys_base, data_size,
					BOOT_E2K_KERNEL_PAGE_SIZE,
					data_virt_base);
			}
			boot_printk("The kernel 'data/bss' segment: "
				"base addr 0x%lx size 0x%lx is mapped to %d "
				"virtual page(s) base addr 0x%lx page size "
				"0x%x\n",
				data_phys_base, data_size, ret, data_virt_base,
				BOOT_E2K_KERNEL_PAGE_SIZE);
		}
		if (BOOT_IS_BS_NODE) {
			area_virt_base = KERNEL_BASE;
			area_size = KERNEL_END - KERNEL_BASE;
			boot_kernel_image_size = area_size;
			boot_printk("The kernel full image: "
				"is mapped from base addr 0x%lx size 0x%lx\n",
				area_virt_base, area_size);
		}
#ifdef	CONFIG_NUMA
no_mapping:
#endif	/* CONFIG_NUMA */
#ifdef	CONFIG_SMP
		BOOT_NODE_UNLOCK(boot_node_map_lock, boot_node_image_mapped);
	}
#endif	/* CONFIG_SMP */

	/*
	 * Map the kernel boot-time hardware procedures stack (PS).
	 */
	boot_boot_ps_virt_base = (e2k_addr_t) phys_to_virt(
						boot_boot_ps_phys_base);
	boot_printk("The kernel boot-time procedure stack: %d pages from 0x%lx\n",
		    boot_boot_ps_size / PAGE_SIZE, boot_boot_ps_virt_base);

	/*
	 * Map the kernel boot-time hardware procedure chain stack (PCS).
	 */
	boot_boot_pcs_virt_base = (e2k_addr_t) phys_to_virt(
						boot_boot_pcs_phys_base);
	boot_printk("The kernel boot-time chain stack: %d pages from 0x%lx\n",
		    boot_boot_pcs_size / PAGE_SIZE, boot_boot_pcs_virt_base);

	/*
	 * Map the kernel boot-time data stack (user stack) (US).
	 */
	boot_boot_stack_virt_base = (e2k_addr_t) phys_to_virt(
						boot_boot_stack_phys_base);
	boot_boot_stack_virt_offset = boot_boot_stack_phys_offset &
				      ~E2K_ALIGN_USTACK_MASK;
	boot_printk("The kernel boot-time data stack: %d pages from 0x%lx\n",
		    boot_boot_stack_size / PAGE_SIZE,
		    boot_boot_stack_virt_base);

	/*
	 * Map the kernel initial hardware procedures stack (PS).
	 */
	boot_init_ps_virt_base = (e2k_addr_t) phys_to_virt(
						boot_init_ps_phys_base);
	boot_printk("The kernel initial procedure stack: %d pages from 0x%lx\n",
		    boot_init_ps_size / PAGE_SIZE, boot_init_ps_virt_base);

	/*
	 * Map the kernel initial hardware procedure chain stack (PCS).
	 */
	boot_init_pcs_virt_base = (e2k_addr_t) phys_to_virt(
						boot_init_pcs_phys_base);
	boot_printk("The kernel initial chain stack: %d pages from 0x%lx\n",
		    boot_init_pcs_size / PAGE_SIZE, boot_init_pcs_virt_base);

	/*
	 * Map the kernel initial data stack (user stack) (US).
	 */
	boot_init_stack_virt_base = (e2k_addr_t) phys_to_virt(
						boot_init_stack_phys_base);
	boot_init_stack_virt_offset = boot_init_stack_phys_offset &
				      ~E2K_ALIGN_USTACK_MASK;
	boot_printk("The kernel initial data stack: %d pages from 0x%lx\n",
		    boot_init_stack_size / PAGE_SIZE,
		    boot_init_stack_virt_base);

	/*
	 * Map the available physical memory into virtual space to direct
	 * access to physical memory using kernel pa <-> va translations
	 * All physical memory pages are mapped to virtual space starting
	 * from 'PAGE_OFFSET'
	 */

#ifdef	CONFIG_SMP
	if (!BOOT_TEST_AND_SET_NODE_LOCK(boot_node_map_lock,
						boot_node_mem_mapped)) {
#endif	/* CONFIG_SMP */
#ifdef	CONFIG_NUMA
		if (!boot_node_has_dup_kernel()) {
			DebugNUMA("boot_map_all_bootmem() node "
				"has not own page table and will use "
				"node #%d physical memory mapping\n",
				boot_my_node_dup_kernel_nid);
			goto no_mem_mapping;
		} else {
			DebugNUMA("boot_map_all_bootmem() will map all "
				"physical memory\n");
		}
#endif	/* CONFIG_NUMA */
		boot_printk("The physical memory start address 0x%lx, "
			"end 0x%lx\n",
			boot_start_of_phys_memory,
			boot_end_of_phys_memory);
		area_phys_base = -1;	/* from physical memory begining */
		area_virt_base = (e2k_addr_t)__va(boot_start_of_phys_memory);
		if (boot_start_of_phys_memory < E2K_X86_LOW_IO_AREA_PHYS_BASE) {
			area_phys_base = boot_start_of_phys_memory;
			area_size = E2K_X86_LOW_IO_AREA_PHYS_BASE - boot_start_of_phys_memory;
			ret = boot_map_phys_area(area_phys_base, area_size,
				area_virt_base,
				PAGE_MAPPED_PHYS_MEM, E2K_SMALL_PAGE_SIZE,
				0);	/* do not ignore if data mapping virtual */
					/* area is busy */
			if (ret <= 0) {
				BOOT_BUG_POINT("boot_map_all_bootmem");
				BOOT_BUG("Could not map physical memory area: "
					"base addr 0x%lx size 0x%lx page size 0x%x to "
					"virtual addr 0x%lx",
					area_phys_base, area_size, E2K_SMALL_PAGE_SIZE,
					area_virt_base);
			}
			boot_printk("The physical memory area: "
				"base addr 0x%lx size 0x%lx is mapped to %d virtual "
				"page(s) base addr 0x%lx page size 0x%x\n",
				area_phys_base, area_size, ret, area_virt_base,
				E2K_SMALL_PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
			boot_add_mapped_area(area_phys_base, area_size);
#endif	/* CONFIG_RECOVERY */
			area_virt_base += (area_size + E2K_X86_LOW_IO_AREA_SIZE);
			area_phys_base = E2K_X86_LOW_IO_AREA_PHYS_BASE +
							E2K_X86_LOW_IO_AREA_SIZE;
			if (_PAGE_ALIGN_DOWN(area_phys_base,
					BOOT_E2K_MAPPED_PHYS_MEM_PAGE_SIZE) >
				area_phys_base) {
				area_size = _PAGE_ALIGN_DOWN(area_phys_base,
					BOOT_E2K_MAPPED_PHYS_MEM_PAGE_SIZE)
							- area_phys_base;
				ret = boot_map_phys_area(area_phys_base, area_size,
					area_virt_base,
					PAGE_MAPPED_PHYS_MEM, E2K_SMALL_PAGE_SIZE,
					0);	/* do not ignore if data mapping virtual */
						/* area is busy */
				if (ret <= 0) {
					BOOT_BUG_POINT("boot_map_all_bootmem");
					BOOT_BUG("Could not map physical memory area: "
						"base addr 0x%lx size 0x%lx page size 0x%x to "
						"virtual addr 0x%lx",
						area_phys_base, area_size, E2K_SMALL_PAGE_SIZE,
						area_virt_base);
				}
				boot_printk("The physical memory area: "
					"base addr 0x%lx size 0x%lx is mapped to %d virtual "
					"page(s) base addr 0x%lx page size 0x%x\n",
					area_phys_base, area_size, ret, area_virt_base,
					E2K_SMALL_PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
				boot_add_mapped_area(area_phys_base, area_size);
#endif	/* CONFIG_RECOVERY */
				area_virt_base += area_size;
				area_phys_base += area_size;
			}

		}
		area_size = E2K_MAPPED_PHYS_MEM_SIZE;
		ret = boot_map_physmem(area_phys_base, area_size,
			area_virt_base,
			PAGE_MAPPED_PHYS_MEM, BOOT_E2K_MAPPED_PHYS_MEM_PAGE_SIZE);
		if (ret <= 0) {
			BOOT_BUG_POINT("boot_map_all_bootmem");
			BOOT_BUG("Could not map physical memory area: "
				"base addr 0x%lx size 0x%lx page size 0x%x to "
				"virtual addr 0x%lx",
				area_phys_base, area_size,
				BOOT_E2K_MAPPED_PHYS_MEM_PAGE_SIZE,
				area_virt_base);
		}
		boot_printk("The physical memory area: "
			"base addr 0x%lx size 0x%lx is mapped to %d virtual "
			"page(s) base addr 0x%lx page size 0x%x\n",
			area_phys_base, area_size, ret, area_virt_base,
			BOOT_E2K_MAPPED_PHYS_MEM_PAGE_SIZE);
#ifdef	CONFIG_NUMA
no_mem_mapping:
#endif	/* CONFIG_NUMA */
#ifdef	CONFIG_SMP
		BOOT_NODE_UNLOCK(boot_node_map_lock, boot_node_mem_mapped);
	}
#endif	/* CONFIG_SMP */

	/*
	 * Map the low x86 I/O ports and memory.
	 */

#ifdef	CONFIG_SMP
	if (!BOOT_TEST_AND_SET_NODE_LOCK(boot_node_map_lock,
						boot_node_io_mapped)) {
#endif	/* CONFIG_SMP */
#ifdef	CONFIG_NUMA
		if (!boot_node_has_dup_kernel()) {
			goto no_io_mapping;
		}
#endif	/* CONFIG_NUMA */
		area_phys_base = E2K_X86_LOW_IO_AREA_PHYS_BASE;
		area_size = E2K_X86_LOW_IO_AREA_SIZE;
		area_virt_base = (e2k_addr_t)__va(E2K_X86_LOW_IO_AREA_PHYS_BASE);
		ret = boot_map_phys_area(area_phys_base, area_size,
			area_virt_base,
			PAGE_X86_IO_PORTS, E2K_SMALL_PAGE_SIZE,
			0);	/* do not ignore if data mapping virtual */
				/* area is busy */
		if (ret <= 0) {
			BOOT_BUG_POINT("boot_map_all_bootmem");
			BOOT_BUG("Could not map low x86 I/O ports area: "
				"base addr 0x%lx size 0x%lx page size 0x%x to "
				"virtual addr 0x%lx",
				area_phys_base, area_size, E2K_SMALL_PAGE_SIZE,
				area_virt_base);
		}
		boot_printk("The low x86 I/O ports area: "
			"base addr 0x%lx size 0x%lx is mapped to %d virtual "
			"page(s) base addr 0x%lx page size 0x%x\n",
			area_phys_base, area_size, ret, area_virt_base,
			E2K_SMALL_PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
		boot_add_mapped_area(area_phys_base, area_size);
#endif	/* CONFIG_RECOVERY */
#ifdef	CONFIG_NUMA
no_io_mapping:
#endif	/* CONFIG_NUMA */
#ifdef	CONFIG_SMP
		BOOT_NODE_UNLOCK(boot_node_map_lock, boot_node_io_mapped);
	}
#endif	/* CONFIG_SMP */

	/*
	 * Map all needed physical areas from boot-info.
	 */

#ifdef	CONFIG_SMP
	if (!BOOT_TEST_AND_SET_NODE_LOCK(boot_node_map_lock,
						boot_node_info_mapped)) {
#endif	/* CONFIG_SMP */
#ifdef	CONFIG_NUMA
		if (boot_node_has_dup_kernel())
#endif	/* CONFIG_NUMA */
			boot_map_all_bootinfo_areas();
#ifdef	CONFIG_SMP
		BOOT_NODE_UNLOCK(boot_node_map_lock, boot_node_info_mapped);
	}
#endif	/* CONFIG_SMP */

	/*
	 * Map the x86 I/O ports area to allow IO operations on system console.
	 */

#ifdef	CONFIG_SMP
	if (!BOOT_TEST_AND_SET_NODE_LOCK(boot_node_map_lock,
						boot_node_ports_mapped)) {
#endif	/* CONFIG_SMP */
#ifdef	CONFIG_NUMA
		if (!boot_node_has_dup_kernel())
			goto no_ports_mapping;
#endif	/* CONFIG_NUMA */
		area_phys_base = boot_machine.x86_io_area_base;
		if (BOOT_HAS_MACHINE_E2K_FULL_SIC)
			area_size = E2K_FULL_SIC_IO_AREA_SIZE;
		else if (BOOT_HAS_MACHINE_E2K_LEGACY_SIC)
			area_size = E2K_LEGACY_SIC_IO_AREA_SIZE;
		else
			area_size = E3M_IO_AREA_SIZE;
		area_virt_base = E2K_X86_IO_AREA_BASE;
		ret = boot_map_phys_area(area_phys_base, area_size,
			area_virt_base,
			PAGE_X86_IO_PORTS, BOOT_E2K_X86_IO_PAGE_SIZE,
			0);	/* do not ignore if data mapping virtual */
				/* area is busy */
		if (ret <= 0) {
			BOOT_BUG_POINT("boot_map_all_bootmem");
			BOOT_BUG("Could not map x86 I/O ports area: "
				"base addr 0x%lx size 0x%lx page size 0x%x to "
				"virtual addr 0x%lx",
				area_phys_base, area_size,
				BOOT_E2K_X86_IO_PAGE_SIZE, area_virt_base);
		}
		boot_printk("The x86 I/O ports area: "
			"base addr 0x%lx size 0x%lx is mapped to %d virtual "
			"page(s) base addr 0x%lx page size 0x%x\n",
			area_phys_base, area_size, ret, area_virt_base,
			BOOT_E2K_X86_IO_PAGE_SIZE);
#ifdef	CONFIG_NUMA
no_ports_mapping:
#endif	/* CONFIG_NUMA */
#ifdef	CONFIG_SMP
		BOOT_NODE_UNLOCK(boot_node_map_lock, boot_node_ports_mapped);
	}
#endif	/* CONFIG_SMP */
}


#ifdef	CONFIG_L_IO_APIC
/*
 * Map the needed memory from MP - tables
 */

static	void __init
boot_map_mp_table(void)
{
	e2k_addr_t	area_phys_base;
	e2k_addr_t	area_virt_base;
	e2k_size_t	area_size;
	e2k_size_t	area_offset;
	int		ret;
	struct intel_mp_floating *mpf;

	if (boot_bootblock_phys->info.mp_table_base == (e2k_addr_t)0UL)
		return;

	/*
	 * MP floating specification table
	 */

	area_phys_base = _PAGE_ALIGN_UP(boot_mpf_phys_base, E2K_MPT_PAGE_SIZE);
	area_offset = boot_mpf_phys_base - area_phys_base;
	area_size = boot_mpf_size + area_offset;
	if (!boot_is_pfn_valid(area_phys_base >> PAGE_SHIFT)) {
		area_virt_base = (e2k_addr_t)__va(area_phys_base);
		ret = boot_map_phys_area(area_phys_base, area_size,
			area_virt_base,
			PAGE_MPT, E2K_MPT_PAGE_SIZE,
			0);	/* do not ignore if data mapping virtual */
				/* area is busy */
		if (ret <= 0) {
			BOOT_BUG_POINT("boot_map_all_bootinfo_areas");
			BOOT_BUG("Could not map MP floating table page(s): "
				"base addr 0x%lx size 0x%lx page size 0x%x to "
				"virtual addr 0x%lx",
				area_phys_base, area_size,
				E2K_MPT_PAGE_SIZE,
				area_virt_base);
		}
		boot_printk("The MP floating table page(s): "
			"base addr 0x%lx size 0x%lx is mapped to %d virtual "
			"page(s) base addr 0x%lx page size 0x%x\n",
			area_phys_base, area_size, ret, area_virt_base,
			E2K_MPT_PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
		boot_add_mapped_area(area_phys_base, area_size);
#endif	/* CONFIG_RECOVERY */
	}

	/*
	 * MP configuration table
	 */

	mpf = (struct intel_mp_floating *)boot_mpf_phys_base;
	if (mpf->mpf_physptr == (e2k_addr_t)0UL)
		return;

	area_phys_base = _PAGE_ALIGN_UP(boot_mpc_phys_base, E2K_MPT_PAGE_SIZE);
	area_offset = boot_mpc_phys_base - area_phys_base;
	area_size = boot_mpc_size + area_offset;
	if (!boot_is_pfn_valid(area_phys_base >> PAGE_SHIFT)) {
		area_virt_base = (e2k_addr_t)__va(area_phys_base);
		ret = boot_map_phys_area(area_phys_base, area_size,
			area_virt_base,
			PAGE_MPT, E2K_MPT_PAGE_SIZE,
			1);	/* ignore if data mapping virtual */
				/* area is busy */
		if (ret <= 0) {
			BOOT_BUG_POINT("boot_map_all_bootinfo_areas");
			BOOT_BUG("Could not map MP configuration table page(s): "
				"base addr 0x%lx size 0x%lx page size 0x%x to "
				"virtual addr 0x%lx",
				area_phys_base, area_size,
				E2K_MPT_PAGE_SIZE,
				area_virt_base);
		}
		boot_printk("The MP configuration table page(s): "
			"base addr 0x%lx size 0x%lx is mapped to %d virtual "
			"page(s) base addr 0x%lx page size 0x%x\n",
			area_phys_base, area_size, ret, area_virt_base,
			E2K_MPT_PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
		boot_add_mapped_area(area_phys_base, area_size);
#endif	/* CONFIG_RECOVERY */
	}
}
#endif	/* CONFIG_L_IO_APIC */

/*
 * Map into the virtual space all needed physical areas from boot-info.
 * All the mapped areas enumerate below. If a some new area will be used,
 * then it should be added to the list of already known ones.
 */

static	void __init
boot_map_all_bootinfo_areas(void)
{
	e2k_addr_t	area_phys_base;
	e2k_size_t	area_size;
	e2k_size_t	area_offset;
	e2k_addr_t	area_virt_base;
	e2k_addr_t	symtab_phys_base;
	e2k_addr_t	symtab_virt_base;
	e2k_size_t	symtab_size;
	e2k_addr_t	strtab_phys_base;
	e2k_addr_t	strtab_virt_base;
	e2k_size_t	strtab_size;
	int		ret = 0;


	/*
	 * Map the bootinfo structure.
	 */
	area_phys_base = _PAGE_ALIGN_UP(boot_bootinfo_phys_base,
						E2K_BOOTINFO_PAGE_SIZE);
	area_offset = boot_bootinfo_phys_base - area_phys_base;
	area_size = boot_bootinfo_size + area_offset;

	if (!boot_is_pfn_valid(area_phys_base >> PAGE_SHIFT)) {
		area_virt_base = (e2k_addr_t)__va(area_phys_base);
		ret = boot_map_phys_area(area_phys_base, area_size,
			area_virt_base,
			PAGE_BOOTINFO, E2K_BOOTINFO_PAGE_SIZE,
			0);	/* do not ignore if data mapping virtual */
				/* area is busy */
		if (ret <= 0) {
			BOOT_BUG_POINT("boot_map_all_bootinfo_areas");
			BOOT_BUG("Could not map BOOTINFO structue: "
				"base addr 0x%lx size 0x%lx page size 0x%x to "
				"virtual addr 0x%lx",
				area_phys_base, area_size,
				E2K_BOOTINFO_PAGE_SIZE,
				area_virt_base);
		}
		boot_printk("The BOOTINFO structure pages: "
			"base addr 0x%lx size 0x%lx is mapped to %d virtual "
			"page(s) base addr 0x%lx page size 0x%x\n",
			area_phys_base, area_size, ret, area_virt_base,
			E2K_BOOTINFO_PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
		boot_add_mapped_area(area_phys_base, area_size);
#endif	/* CONFIG_RECOVERY */
	}
	boot_bootblock_virt_write =
			(bootblock_struct_t *)__va(boot_bootinfo_phys_base);

#ifdef CONFIG_BLK_DEV_INITRD
	/*
	 * Map the memory of initial ramdisk (initrd).
	 */

	area_phys_base = boot_initrd_phys_base;		/* INITRD_BASE and */
	area_size = boot_initrd_size;			/* INITRD_SIZE */
							/* comes from Loader */
	if (area_size && !boot_is_pfn_valid(area_phys_base >> PAGE_SHIFT)) {
		area_virt_base = (e2k_addr_t)__va(area_phys_base);
		ret = boot_map_phys_area(area_phys_base, area_size,
			area_virt_base,
			PAGE_INITRD, E2K_INITRD_PAGE_SIZE,
			0);	/* do not ignore if data mapping virtual */
				/* area is busy */
		if (ret <= 0) {
			BOOT_BUG_POINT("boot_map_all_bootinfo_areas");
			BOOT_BUG("Could not map initial ramdisk area: "
				"base addr 0x%lx size 0x%lx page size 0x%x to "
				"virtual addr 0x%lx",
				area_phys_base, area_size,
				E2K_INITRD_PAGE_SIZE,
				area_virt_base);
		}
		boot_printk("The initial ramdisk area: "
			"base addr 0x%lx size 0x%lx is mapped to %d virtual "
			"page(s) base addr 0x%lx page size 0x%x\n",
			area_phys_base, area_size, ret, area_virt_base,
			E2K_INITRD_PAGE_SIZE);
#ifdef	CONFIG_RECOVERY
		boot_add_mapped_area(area_phys_base, area_size);
#endif	/* CONFIG_RECOVERY */
	}
#endif	/* CONFIG_BLK_DEV_INITRD */

	boot_map_mp_table();

	/*
	 * Map the kernel SYMTAB (symbols table).
	 */

	symtab_phys_base = boot_symtab_phys_base;
	symtab_size = boot_symtab_size;

	strtab_phys_base = boot_strtab_phys_base;
	strtab_size = boot_strtab_size;
	if (symtab_size != 0 || strtab_size != 0)
		area_virt_base = E2K_KERNEL_NAMETAB_AREA_BASE;
	else
		area_virt_base = (e2k_addr_t)NULL;

	if (symtab_size == 0)
		symtab_virt_base = (e2k_addr_t)NULL;
	else {
		symtab_phys_base = _PAGE_ALIGN_UP(symtab_phys_base,
					E2K_NAMETAB_PAGE_SIZE);
		symtab_size += (boot_symtab_phys_base - symtab_phys_base);
	}
	if (strtab_size == 0)
		strtab_virt_base = (e2k_addr_t)NULL;
	else {
		strtab_phys_base = _PAGE_ALIGN_UP(strtab_phys_base,
					E2K_NAMETAB_PAGE_SIZE);
		strtab_size += (boot_strtab_phys_base - strtab_phys_base);
	}
	if (symtab_size != 0 && strtab_size != 0) {
		if (symtab_phys_base <= strtab_phys_base) {
			symtab_virt_base = area_virt_base;
			strtab_virt_base = symtab_virt_base +
				 	(strtab_phys_base - symtab_phys_base);
		} else {
			strtab_virt_base = area_virt_base;
			symtab_virt_base = strtab_virt_base +
				 	(symtab_phys_base - strtab_phys_base);
		}
	} else if (symtab_size == 0) {
		symtab_virt_base = (e2k_addr_t)NULL;
		strtab_virt_base = area_virt_base;
	} else {
		strtab_virt_base = (e2k_addr_t)NULL;
		symtab_virt_base = area_virt_base;
	}

	if (symtab_size != 0) {
		ret = boot_map_phys_area(symtab_phys_base, symtab_size,
			symtab_virt_base, PAGE_KERNEL_NAMETAB,
			E2K_NAMETAB_PAGE_SIZE,
			0);	/* do not ignore if symbols table mapping */
				/* virtual area is busy */
		if (ret <= 0) {
			BOOT_BUG_POINT("boot_map_all_bootinfo_areas");
			BOOT_BUG("Could not map kernel symbols table: "
				"base addr 0x%lx size 0x%lx page size 0x%x to "
				"virtual addr 0x%lx",
				symtab_phys_base, symtab_size,
				E2K_NAMETAB_PAGE_SIZE,
				symtab_virt_base);
		}
	}
	boot_symtab_virt_base = symtab_virt_base;
	if (symtab_size != 0) {
		boot_printk("The kernel symbols table: "
			"base addr 0x%lx size 0x%lx is mapped to %d virtual "
			"page(s) base addr 0x%lx page size 0x%x\n",
			symtab_phys_base, symtab_size, ret, symtab_virt_base,
			E2K_NAMETAB_PAGE_SIZE);
	} else {
		boot_printk("The kernel symbols table is empty\n");
	}

	if (strtab_size != 0) {
		ret = boot_map_phys_area(strtab_phys_base, strtab_size,
			strtab_virt_base, PAGE_KERNEL_NAMETAB,
			E2K_NAMETAB_PAGE_SIZE,
			1);	/* ignore if strings table mapping virtual */
				/* area is busy */

		if (ret <= 0) {
			BOOT_BUG_POINT("boot_map_all_bootinfo_areas");
			BOOT_BUG("Could not map kernel strings table: "
				"base addr 0x%lx size 0x%lx page size 0x%x to "
				"virtual addr 0x%lx",
				strtab_phys_base, strtab_size,
				E2K_NAMETAB_PAGE_SIZE,
				strtab_virt_base);
		}
	}
	boot_strtab_virt_base = strtab_virt_base;
	if (strtab_size != 0) {
		boot_printk("The kernel strings table: "
			"base addr 0x%lx size 0x%lx is mapped to %d virtual "
			"page(s) base addr 0x%lx page size 0x%x\n",
			strtab_phys_base, strtab_size, ret, strtab_virt_base,
			E2K_NAMETAB_PAGE_SIZE);
	} else {
		boot_printk("The kernel strings table is empty\n");
	}

	boot_kernel_symtab = (void *)(symtab_virt_base +
		(boot_symtab_phys_base & (E2K_NAMETAB_PAGE_SIZE - 1)));
	boot_kernel_symtab_size = boot_symtab_size;
	boot_printk("The kernel symbols table: addr 0x%lx size 0x%lx\n",
		boot_kernel_symtab, boot_kernel_symtab_size);
	boot_kernel_strtab = (void *)(strtab_virt_base +
		(boot_strtab_phys_base & (E2K_NAMETAB_PAGE_SIZE - 1)));
	boot_kernel_strtab_size = boot_strtab_size;
	boot_printk("The kernel strings table: addr 0x%lx size 0x%lx\n",
		boot_kernel_strtab, boot_kernel_strtab_size);

}


#ifdef	CONFIG_KERNEL_CODE_CONTEXT
/*
 * Fill kernel compilation units table.
 */
static void __init
boot_fill_kernel_CUT(void)
{
	e2k_cute_t *CUT = boot_kernel_CUT;
	e2k_cute_t *kernel_CUTE = &(CUT[KERNEL_CODES_INDEX]);
	bootmem_areas_t *bootmem = boot_kernel_bootmem;

	boot_printk("boot_fill_kernel_CUT() will fill kernel CUT entry #%d, "
		"at addr 0x%lx\n",
		KERNEL_CODES_INDEX, kernel_CUTE);

#ifndef	CONFIG_NUMA
	CUTE_CUD_BASE(kernel_CUTE) = bootmem->prot_text.virt;
#else	/* CONFIG_NUMA */
	CUTE_CUD_BASE(kernel_CUTE) =
		bootmem->prot_text.nodes[BOOT_BS_NODE_ID].virt;
#endif	/* ! CONFIG_NUMA */
	CUTE_CUD_SIZE(kernel_CUTE) = boot_prot_text_size;
	CUTE_CUD_C   (kernel_CUTE) = CUD_CFLAG_SET;
	if (CUTE_CUD_BASE(kernel_CUTE) & E2K_ALIGN_OSCU_MASK) {
		BOOT_BUG_POINT("boot_fill_kernel_CUT()");
		BOOT_BUG("Kernel 'text' segment start address 0x%lx is not "
			"aligned to CU alignment mask 0x%lx\n",
			CUTE_CUD_BASE(kernel_CUTE), E2K_ALIGN_OSCU_MASK);
	}
	if (CUTE_CUD_SIZE(kernel_CUTE) & E2K_ALIGN_OSCU_MASK) {
		BOOT_BUG_POINT("boot_fill_kernel_CUT()");
		BOOT_BUG("Kernel 'text' segment size 0x%lx is not "
			"aligned to CU alignment mask 0x%lx\n",
			CUTE_CUD_SIZE(kernel_CUTE), E2K_ALIGN_OSCU_MASK);
	}
	boot_printk("boot_fill_kernel_CUT() set kernel CUT entry "
		"CUD to: base 0x%lx, size 0x%lx\n",
		CUTE_CUD_BASE(kernel_CUTE), CUTE_CUD_SIZE(kernel_CUTE));

#ifndef	CONFIG_NUMA
	CUTE_GD_BASE(kernel_CUTE) = bootmem->data.virt;
#else	/* CONFIG_NUMA */
	CUTE_GD_BASE(kernel_CUTE) =
		bootmem->data.nodes[BOOT_BS_NODE_ID].virt;
#endif	/* ! CONFIG_NUMA */
	CUTE_GD_SIZE(kernel_CUTE) = boot_data_size;
	if (CUTE_GD_BASE(kernel_CUTE) & E2K_ALIGN_OS_GLOBALS_MASK) {
		BOOT_BUG_POINT("boot_fill_kernel_CUT()");
		BOOT_BUG("Kernel 'data' segment start address 0x%lx is not "
			"aligned to Global alignment mask 0x%lx\n",
			CUTE_GD_BASE(kernel_CUTE), E2K_ALIGN_OS_GLOBALS_MASK);
	}
	if (CUTE_GD_SIZE(kernel_CUTE) & E2K_ALIGN_OS_GLOBALS_MASK) {
		BOOT_BUG_POINT("boot_fill_kernel_CUT()");
		BOOT_BUG("Kernel 'data' segment size 0x%lx is not "
			"aligned to Global alignment mask 0x%lx\n",
			CUTE_GD_SIZE(kernel_CUTE), E2K_ALIGN_OS_GLOBALS_MASK);
	}
	boot_printk("boot_fill_kernel_CUT() set kernel CUT entry "
		"GD to: base 0x%lx, size 0x%lx\n",
		CUTE_GD_BASE(kernel_CUTE), CUTE_GD_SIZE(kernel_CUTE));

	CUTE_TSD_BASE(kernel_CUTE) = 0;
	CUTE_TSD_SIZE(kernel_CUTE) = 0;
	boot_printk("boot_fill_kernel_CUT() set kernel CUT entry "
		"TSD to empty state\n");
}
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */

/*
 * Map some necessary physical areas to the equal virtual addresses to 
 * switch kernel execution into the physical space to execution into the
 * virtual space.
 * Sometime after turn on TLB and translation virtual addresses to physical
 * becomes inevitable, some kernel text and data should be accessed on old
 * physical addresses, which will be treated now as virtual addresses.
 */

void __init_recv
boot_map_needful_to_equal_virt_area(e2k_addr_t stack_top_addr)
{
	e2k_addr_t	area_base;
	e2k_size_t	area_size;
	int		ret;

	/*
	 * Map the function 'boot_switch_to_virt()' of kernel image
	 * 'text' segments. This function will make switching to virtual
	 * space. The first part of the function is executed into the
	 * physical space without any translation virtual addresses.
	 * But second part of one is executed into the equal virtual spce.
	 */

	area_base = (e2k_addr_t)boot_vp_to_pp(boot_switch_to_virt);
	area_size = (e2k_size_t)boot_switch_to_virt_end -
			(e2k_size_t)boot_switch_to_virt;

	ret = boot_map_to_equal_virt_area(area_base, area_size,
		PAGE_KERNEL_SWITCHING_TEXT, TLB_KERNEL_SWITCHING_TEXT,
		BOOT_E2K_KERNEL_PAGE_SIZE, ITLB_ACCESS_MASK, 0);
	if (ret <= 0) {
		BOOT_BUG_POINT("boot_map_needful_to_equal_virt_area");
		BOOT_BUG("Could not map to equal virtual space the "
			"kernel function 'boot_switch_to_virt()': "
			"base addr 0x%lx size 0x%lx page size 0x%x",
			area_base, area_size, BOOT_E2K_KERNEL_PAGE_SIZE);
	}
	boot_printk("The kernel function 'boot_switch_to_virt()' : "
		"base addr 0x%lx size 0x%lx is mapped to %d equal "
		"virtual page(s) page size 0x%lx\n",
		area_base, area_size, ret,
		(e2k_size_t)BOOT_E2K_KERNEL_PAGE_SIZE);

	/*
	 * Map the structure 'kernel_bootmem', which contains all boot-time
	 * memory info.
	 */

	area_base = (e2k_addr_t)boot_kernel_bootmem;
	area_size = sizeof (kernel_bootmem);

	ret = boot_map_to_equal_virt_area(area_base, area_size,
		PAGE_KERNEL_SWITCHING_DATA, TLB_KERNEL_SWITCHING_DATA,
		BOOT_E2K_KERNEL_PAGE_SIZE, ITLB_ACCESS_MASK, 0);
	if (ret <= 0) {
		BOOT_BUG_POINT("boot_map_needful_to_equal_virt_area");
		BOOT_BUG("Could not map to equal virtual space the structure "
			"'kernel_bootmem': "
			"base addr 0x%lx size 0x%lx page size 0x%x",
			area_base, area_size, BOOT_E2K_KERNEL_PAGE_SIZE);
	}
	boot_printk("The kernel structure 'kernel_bootmem' : "
		"base addr 0x%lx size 0x%lx was mapped to %d equal virtual "
		"page(s) page size 0x%lx\n",
		area_base, area_size, ret, (e2k_size_t)BOOT_E2K_KERNEL_PAGE_SIZE);

	/*
	 * Map the top of the kernel data stack to have access to some
	 * functions locals.
	 */

	area_base = stack_top_addr - E2K_KERNEL_US_PAGE_SWITCHING_SIZE +
			sizeof (long);
	area_size = E2K_KERNEL_US_PAGE_SWITCHING_SIZE;

	ret = boot_map_to_equal_virt_area(area_base, area_size,
		PAGE_KERNEL_SWITCHING_US_STACK, TLB_KERNEL_SWITCHING_US_STACK,
		E2K_KERNEL_US_PAGE_SIZE, ITLB_ACCESS_MASK, 0);
	if (ret <= 0) {
		BOOT_BUG_POINT("boot_map_needful_to_equal_virt_area");
		BOOT_BUG("Could not map to equal virtual space the top of the "
			"kernel stack: "
			"base addr 0x%lx size 0x%lx page size 0x%x",
			area_base, area_size, E2K_KERNEL_US_PAGE_SIZE);
	}
	boot_printk("The kernel top of the stack : "
		"base addr 0x%lx size 0x%lx was mapped to %d equal virtual "
		"page(s) page size 0x%lx\n",
		area_base, area_size, ret, (e2k_size_t)E2K_KERNEL_US_PAGE_SIZE);
}

/* 
 * Switch kernel execution into the physical space to execution into the
 * virtual space. This function should be coded very careful.
 * Each the function operator should be weighted, what conseguences it will
 * have.
 */

void __init_recv
boot_switch_to_virt(void (*boot_init_sequel_func)(void))
{
	bootmem_areas_t *bootmem = boot_kernel_bootmem;
	e2k_rwap_lo_struct_t	reg_lo;
	e2k_rwap_hi_struct_t	reg_hi;
	e2k_rwap_lo_struct_t	stack_reg_lo;
	e2k_rwap_hi_struct_t	stack_reg_hi;
	usbr_struct_t		usbr = {{ 0 }};
#ifdef	CONFIG_KERNEL_CODE_CONTEXT
	e2k_cutd_t		cutd = {{ 0 }};
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */
#ifdef	CONFIG_SMP
	int cpuid = boot_smp_processor_id();
#endif	/* CONFIG_SMP */
	unsigned long mmu_cr = _MMU_CR_KERNEL;

	/*
	 * Set all needed MMU registers before to turn on virtual addressing
	 * translation mode
	 */
	boot_set_kernel_MMU_state();

	/*
	 * Set Procedure Stack and Procedure Chain stack registers
	 * to begining virtual stacks addresses and collapse in that way
	 * previuos useless stack frames
	 */
	E2K_FLUSHCPU;
	E2K_WAIT_ALL;
	reg_lo.PSP_lo_half = 0;
#ifndef	CONFIG_SMP
	reg_lo.PSP_lo_base = bootmem->boot_ps.virt;
#else
	reg_lo.PSP_lo_base = bootmem->boot_ps[cpuid].virt;
#endif	/* CONFIG_SMP */
	reg_lo._PSP_lo_rw = E2K_PSP_RW_PROTECTIONS;
	reg_hi.PSP_hi_half = 0;
#ifndef	CONFIG_SMP
	reg_hi.PSP_hi_size = bootmem->boot_ps.size;
#else
	reg_hi.PSP_hi_size = bootmem->boot_ps[cpuid].size;
#endif	/* CONFIG_SMP */
	reg_hi.PSP_hi_ind = 0;
	RAW_WRITE_PSP_REG(reg_hi, reg_lo);

	reg_lo.PCSP_lo_half = 0;
#ifndef	CONFIG_SMP
	reg_lo.PCSP_lo_base = bootmem->boot_pcs.virt;
#else
	reg_lo.PCSP_lo_base = bootmem->boot_pcs[cpuid].virt;
#endif	/* CONFIG_SMP */
	reg_lo._PCSP_lo_rw = E2K_PCSR_RW_PROTECTIONS;
	reg_hi.PCSP_hi_half = 0;
#ifndef	CONFIG_SMP
	reg_hi.PCSP_hi_size = bootmem->boot_pcs.size;
#else
	reg_hi.PCSP_hi_size = bootmem->boot_pcs[cpuid].size;
#endif	/* CONFIG_SMP */
	reg_hi.PCSP_hi_ind = 0;
	RAW_WRITE_PCSP_REG(reg_hi, reg_lo);

	/*
	 * Enable control of PS & PCS stack guard
	 */
	e2k_set_sge();

	/*
	 * Turn on virtual addressing translation mode and disable caches
	 * (write to the MMU control register enables TLB & TLU)
	 */

	if (boot_disable_caches != _MMU_CD_EN) {
		mmu_cr &= ~_MMU_CR_CD_MASK;
		mmu_cr |= (boot_disable_caches & _MMU_CR_CD_MASK);
	}
	if (boot_disable_secondary_caches) {
		mmu_cr &= ~_MMU_CR_CR0_CD;
		mmu_cr |= (boot_disable_secondary_caches & _MMU_CR_CR0_CD);
	}
	if (boot_disable_IP == _MMU_IPD_DIS) {
		mmu_cr &= ~_MMU_CR_IPD_MASK;
		mmu_cr |= (boot_disable_IP & _MMU_CR_IPD_MASK);
	}

	boot_set_l2_crc_state();	/* set L2 CRC control state */
	E2K_WAIT_ALL;
	WRITE_MMU_CR(__mmu_reg(mmu_cr));
	E2K_WAIT_ALL;

	/*
	 * Set Kernel 'text/data/bss' segment registers to consistent
	 * virtual addresses
	 */

#ifndef	CONFIG_NUMA
	reg_lo.CUD_lo_base = bootmem->text.virt;
#else	/* CONFIG_NUMA */
	reg_lo.CUD_lo_base = bootmem->text.nodes[BOOT_BS_NODE_ID].virt;
#endif	/* ! CONFIG_NUMA */
	reg_lo._CUD_lo_rw = E2K_CUD_RW_PROTECTIONS;
	reg_lo.CUD_lo_c = CUD_CFLAG_SET;
	WRITE_CUD_LO_REG(reg_lo);
	WRITE_OSCUD_LO_REG(reg_lo);
#ifndef	CONFIG_NUMA
	reg_lo.GD_lo_base = bootmem->data.virt;
#else	/* CONFIG_NUMA */
	reg_lo.GD_lo_base = bootmem->data.nodes[BOOT_BS_NODE_ID].virt;
#endif	/* ! CONFIG_NUMA */
	reg_lo._GD_lo_rw = E2K_GD_RW_PROTECTIONS;
	WRITE_GD_LO_REG(reg_lo);
	WRITE_OSGD_LO_REG(reg_lo);
#ifdef	CONFIG_KERNEL_CODE_CONTEXT

	/*
	 * Set CPU registers to point to kernel CUT & index
	 */

	cutd.CUTD_base = (e2k_addr_t)kernel_CUT;
	WRITE_CUTD_REG(cutd);
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */

	/*
	 * Switch User Stack registers to virtual kernel stack addresses
	 * The assumption is - stack allocation does not use GETSAP operation
	 * but uses SP and FP pointers and allocates stack from end.
	 * Set stack pointer to the very begining of initial stack to collapse
	 * useless previuos stack frames
	 */

#ifndef	CONFIG_SMP
	usbr.USBR_base = bootmem->boot_stack.virt + bootmem->boot_stack.size;
#else
	usbr.USBR_base = bootmem->boot_stack[cpuid].virt +
				bootmem->boot_stack[cpuid].size;
#endif	/* CONFIG_SMP */
	WRITE_USBR_REG(usbr);

	stack_reg_lo.USD_lo_half = 0;
	stack_reg_hi.USD_hi_half = 0;

#ifndef	CONFIG_SMP
	stack_reg_lo.USD_lo_base = bootmem->boot_stack.virt +
					bootmem->boot_stack.virt_offset;
	stack_reg_hi.USD_hi_size = bootmem->boot_stack.virt_offset;
#else
	stack_reg_lo.USD_lo_base = bootmem->boot_stack[cpuid].virt +
					bootmem->boot_stack[cpuid].virt_offset;
	stack_reg_hi.USD_hi_size = bootmem->boot_stack[cpuid].virt_offset;
#endif	/* CONFIG_SMP */
	stack_reg_lo.USD_lo_p = 0;

	WRITE_USD_REG(stack_reg_hi, stack_reg_lo);

	E2K_WAIT_ALL;

	/*
	 * The following call completes switching into the virtual execution.
	 * Now full virtual addressing support is enable. Should not be
	 * return here from this function.
	 */

	boot_init_sequel_func();
}

/* 
 * The funcrtion is fictitious, only to determine the size of previous function.
 * The function should follow previous function 'boot_switch_to_virt()'
 */

static	void __init_recv
boot_switch_to_virt_end(void)
{
}
