/*
 *  $Id: cnt_point.c,v 1.7 2009/05/29 13:13:35 leoan Exp $
 *
 * Architecture-specific recovery
 *
 * Copyright 2001-2007 Salavat S. Guiliazov (atic@mcst.ru)
 *
 */

#include <linux/blkdev.h>
#include <linux/kthread.h>
#include <linux/swap.h>
#include <linux/ide.h>

#include <asm/cnt_point.h>
#include <asm/tlbflush.h>
#include <asm/tag_mem.h>
#include <asm/pgalloc.h>
#include <asm/e2k_debug.h>
#include <asm/e2k_syswork.h>

extern struct task_struct *dup_task_struct(struct task_struct *orig);

void run_init_process(char *init_filename);

#undef	DEBUG_CNT_POINTS_MODE
#undef	DebugCP
#define	DEBUG_CNT_POINTS_MODE	0	/* control points */
#define DebugCP(...)		DebugPrint(DEBUG_CNT_POINTS_MODE ,##__VA_ARGS__)

#undef	DEBUG_DUMP_MODE
#undef	DebugDUMP
#define	DEBUG_DUMP_MODE		0	/* core dump of memory */
#define DebugDUMP(...)		DebugPrint(DEBUG_DUMP_MODE ,##__VA_ARGS__)

#undef	DEBUG_RECOVERY_MODE
#undef	DebugR
#define	DEBUG_RECOVERY_MODE	0	/* system recovery */
#define DebugR(...)		DebugPrint(DEBUG_RECOVERY_MODE ,##__VA_ARGS__)

#undef	DEBUG_STAT_INFO_MODE
#undef	DebugSI
#define	DEBUG_STAT_INFO_MODE	0	/* system recovery */
#define DebugSI(...)		DebugPrint(DEBUG_STAT_INFO_MODE ,##__VA_ARGS__)

#undef	DEBUG_MEMORY_MAP_MODE
#undef	DebugRMM
#define	DEBUG_MEMORY_MAP_MODE	0	/* CNTP memory mapping/unmapping */
#define DebugRMM(...)		DebugPrint(DEBUG_MEMORY_MAP_MODE ,##__VA_ARGS__)

#undef	DEBUG_MAP_REGION_MODE
#undef	DebugMR
#define	DEBUG_MAP_REGION_MODE	0	/* CNTP region memory mapping */
#define DebugMR(...)		DebugPrint(DEBUG_MAP_REGION_MODE ,##__VA_ARGS__)

#undef	DEBUG_MEM_INTRSC_MODE
#undef	DebugMI
#define	DEBUG_MEM_INTRSC_MODE	0	/* mapping memory intersections */
#define DebugMI(...)		DebugPrint(DEBUG_MEM_INTRSC_MODE ,##__VA_ARGS__)

#undef	DEBUG_ZONE_MEMORY_MODE
#undef	DebugZM
#define	DEBUG_ZONE_MEMORY_MODE	0	/* zone memory saving */
#define DebugZM(...)		DebugPrint(DEBUG_ZONE_MEMORY_MODE ,##__VA_ARGS__)

#undef	DEBUG_ZONE_MODE
#undef	DebugZ
#define	DEBUG_ZONE_MODE		0	/* zone memory manipulations */
#define DebugZ(...)		DebugPrint(DEBUG_ZONE_MODE ,##__VA_ARGS__)

#undef	DEBUG_ZONE_AREAS_MODE
#undef	DebugZA
#define	DEBUG_ZONE_AREAS_MODE	0	/* zone areas saving */
#define DebugZA(...)		DebugPrint(DEBUG_ZONE_AREAS_MODE ,##__VA_ARGS__)

#undef	DEBUG_ZONE_TAGS_MODE
#undef	DebugZT
#define	DEBUG_ZONE_TAGS_MODE	0	/* zone areas saving */
#define DebugZT(...)		DebugPrint(DEBUG_ZONE_TAGS_MODE ,##__VA_ARGS__)

#undef	DEBUG_BIO_MODE
#undef	DebugBIO
#define	DEBUG_BIO_MODE		0	/* all BIO manipulations */
#define DebugBIO(...)		DebugPrint(DEBUG_BIO_MODE ,##__VA_ARGS__)

#undef	DEBUG_ZONE_BIO_MODE
#undef	DebugZBIO
#define	DEBUG_ZONE_BIO_MODE	0	/* zone BIO manipulations */
#define DebugZBIO(...)		DebugPrint(DEBUG_ZONE_BIO_MODE ,##__VA_ARGS__)

#undef	DEBUG_READ_BIO_MODE
#undef	DebugRBIO
#define	DEBUG_READ_BIO_MODE	0	/* read BIO manipulations */
#define DebugRBIO(...)		DebugPrint(DEBUG_READ_BIO_MODE ,##__VA_ARGS__)

#undef	DEBUG_TAGS_BIO_MODE
#undef	DebugTBIO
#define	DEBUG_TAGS_BIO_MODE	0	/* read tags BIO manipulations */
#define DebugTBIO(...)		DebugPrint(DEBUG_TAGS_BIO_MODE ,##__VA_ARGS__)

#undef	DEBUG_CNTP_TB_MODE
#undef	DebugTB
#define	DEBUG_CNTP_TB_MODE	0	/* CNTP table buffer */
#define DebugTB(...)		DebugPrint(DEBUG_CNTP_TB_MODE ,##__VA_ARGS__)

#undef	DEBUG_READ_AREA_MODE
#undef	DebugRA
#define	DEBUG_READ_AREA_MODE	0	/* read area */
#define DebugRA(...)		DebugPrint(DEBUG_READ_AREA_MODE ,##__VA_ARGS__)

#undef	DEBUG_READ_TAGS_MODE
#undef	DebugRT
#define	DEBUG_READ_TAGS_MODE	0	/* read tags pages */
#define DebugRT(...)		DebugPrint(DEBUG_READ_AREA_MODE ,##__VA_ARGS__)

#undef	DEBUG_RESTORE_AREA_MODE
#undef	DebugRMA
#define	DEBUG_RESTORE_AREA_MODE	0	/* restore area */
#define DebugRMA(...)		DebugPrint(DEBUG_RESTORE_AREA_MODE ,##__VA_ARGS__)

#undef	DEBUG_RESTORE_AREA_MODE
#undef	DebugRM
#define	DEBUG_RESTORE_AREA_MODE	0	/* restore area */
#define DebugRM(...)		DebugPrint(DEBUG_RESTORE_AREA_MODE ,##__VA_ARGS__)

#undef	DEBUG_TAG_RECOVERY_MODE
#undef	DebugTR
#define	DEBUG_TAG_RECOVERY_MODE	0	/* tag saving */
#define DebugTR(...)		DebugPrint(DEBUG_TAG_RECOVERY_MODE ,##__VA_ARGS__)

#undef	DEBUG_ALLOC_PAGE_MODE
#undef	DebugAP
#define	DEBUG_ALLOC_PAGE_MODE	0	/* page allocation freeing */
#define DebugAP(...)		DebugPrint(DEBUG_ALLOC_PAGE_MODE ,##__VA_ARGS__)

#undef	DEBUG_COUNT_PAGE_MODE
#undef	DebugCPG
#define	DEBUG_COUNT_PAGE_MODE	0	/* area allocation freeing */
#define DebugCPG(...)		DebugPrint(DEBUG_COUNT_PAGE_MODE ,##__VA_ARGS__)

#ifdef	CONFIG_CNT_POINTS_DEV
static char *dump_specialfile = CONFIG_CNT_POINTS_DEV;
#elif	defined(CONFIG_DUMP_DEV)
static char *dump_specialfile = CONFIG_DUMP_DEV;
#else
static char *dump_specialfile = NULL;
#endif	/* CONFIG_CNT_POINTS_DEV */

static int __init
dump_dev_setup(char *str)
{
	dump_specialfile = str;
	return 1;
}
__setup("dumpdev=", dump_dev_setup);

static int __init
cntp_dev_setup(char *str)
{
	dump_specialfile = str;
	return 1;
}
__setup("cntpdev=", cntp_dev_setup);

inline int __init
do_cntp_recreate_setup(int valid)
{
	recreate_cnt_points = valid;
	return 1;
}
static int __init
rectreate_cntp_setup(char *str)
{
	return do_cntp_recreate_setup(1);
}
static int __init
cntp_re_create_setup(char *str)
{
	return do_cntp_recreate_setup(1);
}
static int __init
cntp_recreate_setup(char *str)
{
	return do_cntp_recreate_setup(1);
}
static int __init
cntp_recreate_clear(char *str)
{
	return do_cntp_recreate_setup(0);
}
__setup("recntp", rectreate_cntp_setup);
__setup("cntpre", cntp_re_create_setup);
__setup("cntprec", cntp_recreate_setup);
__setup("cntpnore", cntp_recreate_clear);

static struct file *dump_file = NULL;
static struct block_device *dump_bdev = NULL;
static dump_header_t *dump_header = NULL;
static unsigned dump_old_block_size;
static long dump_filesize;
static long dump_max_pages;

#if CONFIG_CNT_POINTS_NUM
static struct bio *dump_bio = NULL;
static cntp_desk_t *dump_cntp_desc = NULL;
static u64 dump_cntp_cur_block;

static struct page *cntp_prev_tags_page;
static u8 *cntp_prev_tags_areas;
static int prev_tags_area_size;
static int prev_tags_area_offset;
static struct page *cntp_cur_tags_page;
static u8 *cntp_cur_tags_areas;
static int cur_tags_area_size;
static int cur_tags_area_offset;
static struct bio *dump_tags_areas_bio = NULL;
static u64 cntp_cur_tags_block;
static u64 cntp_end_tags_block;

static cntp_area_t *cntp_table_buffer;
static int cntp_table_areas_num;
static int cntp_table_cur_entry;
static int cntp_table_total_entries;
static u64 cntp_table_file_pos;

static int read_cur_entry;
static e2k_pfn_t read_cur_area_start;
static e2k_pfn_t read_cur_area_end;
static int read_cur_tags_page_index;
static int read_tags_pages_num;
static int restore_cur_entry;
static e2k_pfn_t restore_cur_area_start;
static e2k_pfn_t restore_cur_area_end;
static int restore_cur_tags_page_index;

static e2k_size_t cntp_total_pfns_to_save;
static e2k_size_t cntp_total_bytes_to_save;
static e2k_size_t cntp_total_saved_bytes;
static e2k_size_t cntp_total_tags_pfns_to_save;
static e2k_size_t cntp_total_tags_to_save;
static e2k_size_t cntp_total_saved_tags;
static e2k_size_t cntp_real_tags_pfns;
static e2k_size_t cntp_prev_numeric_tags_pfns;
static e2k_size_t cntp_cur_numeric_tags_pfns;

static int no_ready_pfns_times;
static int not_read_pfn_times;
static int not_read_first_pfn_times;
static int not_read_area_pfn_times;
static int not_read_tags_pfn_times;
static int restore_pfns_times;
static int read_pfns_times;
static int pfns_enough_times;
static int read_tags_pfns_times;
static int tags_pfns_enough_times;
static int first_restored_area = 1;

static e2k_size_t cntp_cur_pfns_to_read;
static e2k_size_t cntp_cur_pfns_to_restore;	/* current number of pfns */
						/* are already read */
static e2k_size_t cntp_cur_pfns_restored;

static e2k_size_t cntp_tags_pfns_to_read;
static e2k_size_t cntp_tags_pfns_to_restore;	/* current number of pfns */
						/* are already read */
static e2k_size_t cntp_tags_pfns_restored;

static int total_alloc_pages = 0;
static int total_free_pages = 0;

static LIST_HEAD(dump_bio_list_head);
static DEFINE_RAW_SPINLOCK(dump_bio_lock);
static struct kmem_cache *dump_bio_cachep = NULL;

static LIST_HEAD(read_page_list_head);
static DEFINE_RAW_SPINLOCK(read_page_lock);
static LIST_HEAD(read_tags_page_list_head);
static DEFINE_RAW_SPINLOCK(read_tags_page_lock);
#endif /* CONFIG_CNT_POINTS_NUM != 0 */

#define	MGB_SIZE_TO_PAGES(mgb)	((((u64)(mgb)) * 1024 * 1024) / PAGE_SIZE)
#ifdef	CONFIG_CNTP_AREA_MAX_SIZE
static u64 cntp_area_max_size = MGB_SIZE_TO_PAGES(CONFIG_CNTP_AREA_MAX_SIZE);
#else
static u64 cntp_area_max_size = 0;
#endif	/* CONFIG_CNTP_AREA_MAX_SIZE */

extern struct 	semaphore restart_sem;
extern long 	time_to_restart_kernel;

extern unsigned int 		nr_swapfiles;
extern struct swap_info_struct	*swap_info[MAX_SWAPFILES];

static int __init
cntp_time(char *str)
{
	int cnt_t;
	get_option(&str, &cnt_t);
	time_to_restart_kernel = cnt_t * HZ;
	return 1;
}
__setup("cntptime=", cntp_time);

static int __init
cntp_area_max_size_setup(char *str)
{
	int max_size;
	get_option(&str, &max_size);
	cntp_area_max_size = MGB_SIZE_TO_PAGES(max_size);
	return 1;
}
__setup("cntpmax=", cntp_area_max_size_setup);

#ifdef	CONFIG_CORE_AREA_MAX_SIZE
static u64 core_area_max_size = MGB_SIZE_TO_PAGES(CONFIG_CORE_AREA_MAX_SIZE);
#elif	defined(CONFIG_EMERGENCY_DUMP)
static u64 core_area_max_size = MGB_SIZE_TO_PAGES(DEFAULT_CORE_AREA_MAX_SIZE);
#else
static u64 core_area_max_size = 0;
#endif	/* CONFIG_CORE_AREA_MAX_SIZE */

static int __init
core_area_max_size_setup(char *str)
{
	int max_size;
	get_option(&str, &max_size);
	core_area_max_size = MGB_SIZE_TO_PAGES(max_size);
	return 1;
}
__setup("dumpmax=", core_area_max_size_setup);

rest_goal_t	restart_goal;

int	open_dump_device(void);
void	close_dump_device(void);
int	writeback_dump_header(void);

static int	do_create_control_point(int async_mode);
static void	reset_cur_control_point(void);

#if CONFIG_CNT_POINTS_NUM || defined(CONFIG_EMERGENCY_DUMP)
static int	create_cntp_dump_header(void);
#endif /* CONFIG_CNT_POINTS_NUM || defined(CONFIG_EMERGENCY_DUMP) */

static int	map_memory_region(cntp_flag_t flags, e2k_addr_t mem_base,
				e2k_addr_t mem_end, int *just_mapped_point);

#if CONFIG_CNT_POINTS_NUM
static int	add_cntp_table_entry(e2k_pfn_t start_pfn, e2k_pfn_t end_pfn);
static void	release_read_tags_areas(int error);

static inline void
free_cntp_table_buffer(cntp_area_t *table)
{
	free_pages((e2k_addr_t)table, CNTP_AREAS_TABLE_ORDER);
	total_free_pages += (1 << CNTP_AREAS_TABLE_ORDER);
}

static bank_info_t *cntp_nosave_areas = NULL;
static int cntp_nosave_areas_num = 0;
static pg_data_t *cntp_node_data = NULL;
#endif	/* CONFIG_CNT_POINTS_NUM */

e2k_addr_t cntp_kernel_base;
EXPORT_SYMBOL(cntp_kernel_base);

struct vm_area_struct *cntp_find_vma(struct task_struct *ts, unsigned long addr)
{
	struct mm_struct        *mm  = NULL;
	struct vm_area_struct   *vma = NULL;

	if (ts->mm == NULL)
		return NULL;
	mm = cntp_va(ts->mm, 0);
	for (vma = cntp_va(mm->mmap, 0); vma != NULL;
			vma = cntp_va(vma->vm_next, 0)) {
		if ((vma->vm_start <= addr) && vma->vm_end > addr)
			return vma;
	}
	return NULL;
}

asmlinkage long sys_cnt_point(void)
{
        long rval = 0;
	printk("sys_cnt_point(): will call create_control_point()\n");
	rval = create_control_point(0);
	printk("sys_cnt_point(): create_control_point() returns %ld\n", rval);
	return rval;
}

/*
 * Create control point based on current state of the system
 * Function returns:
 *  N  - number of created control points (1 - for first CNTP,
 *       2 for second ...)
 *  0  - in the case of restart from created control point
 * < 0 - if control point cannot be created and -errno returns
 *       as result
 */

int
create_control_point(int async_mode)
{
	printk("Creation of control point #%d (from %d) started on cpu #%d\n",
		cur_cnt_point, cnt_points_num, raw_smp_processor_id());
	if (async_mode) {
		restart_goal = CREATE_REST_GOAL;
		wake_up_restartd();
		return 0;
	}
	return do_create_control_point(0);
}

static int
do_create_control_point(int async_mode)
{
	rest_type_t restart_type;
	int error;

	/*
	 * This function can be called only to create new control point or
	 * recreate existing one and restart system.
	 */
	if (down_trylock(&restart_sem)) /* should up() in recovery_system() */
		return -EBUSY;

	if (cnt_points_num == 0) {
		/*
		 * All memory is single control point.
		 * We consider current state of memory as control point,
		 * remember all runing tasks on each CPU;
		 * switch to special task to restart system and boot-time
		 * stacks; suspend all devices; reset machine
		 * System will be recovered from restart point and continue
		 * all tasks from interrupted place
		 */
		DebugR("started in debug mode "
			"to check safety of restart and fast recovery "
			"from restart point\n");
		error = restart_system(RECOVERY_REST_TYPE, async_mode);
		if (error) {
			DebugR("restart_system() "
				"failed, error %d\n", error);
			return error;
		}
		return 0;	/* system recovered from restart point */
	} else if (cnt_points_num == 1) {
		/*
		 * This case is equal suspending mode or saving memory
		 * state to compare with state on simulator.
		 * We should save current state of memory and all tasks
		 * on the disk and power off machine.
		 * System will be resumed from saved point.
		 */

		if (cur_cnt_point == 1)
			return -EBUSY;
		if (cnt_points_created)
			return -EBUSY;
		
		DebugR("started saving current "
			"memory state for quick restart support\n");
		error = restart_system(CREATE_CNTP_REST_TYPE, async_mode);
		if (error < 0) {
			DebugR("restart_system() "
				"failed, error %d\n", error);
		} else if (error > 0) {
			DebugR("Saving current memory state for quick "
				"restart support has been finished on cpu "
				"#%d\n", raw_smp_processor_id());
		} else {
			DebugR("Quick restart has been finished on cpu #%d\n",
				raw_smp_processor_id());
		}
		return error;
	}

	/*
	 * All memory is divided into N parts (N == cnt_points_num)
	 * We run N instance of system, each instance should use
	 * only own part of memory to boot and run kernel and users.
	 * To create all instance it needs start the system N times.
	 * The first call of this function create control point of
	 * the first instance just only in own part of the memory:
	 *	remember all runing tasks on each CPU;
	 *	switch to special tasks to restart system and boot-time
	 *	stacks; suspend all devices; reset machine
	 * System started as second instance on second part of memory.
	 * The second call of this function should store the first
	 * control point from memory to disk and create control point
	 * of the second instance just only in second part of memory.
	 * ...
	 * Last N-th instance started on own N-th part of memory,
	 * store previous control point from memory to disk, create
	 * last control point in the memory and restart system from
	 * first control point in the memory.
	 * First control point should start resume devices and store
	 * last control point from memory to disk as background
	 * process and returns to this function to continue
	 * process-caller of control points creation.
	 * Futher restarts of the machine will be unexpected and
	 * caused by hardware or software failures and it needs
	 * recover system from current safe control point in the memory
	 * First unexpected restart will recover system from second
	 * control point in the memory and should restore first
	 * control point in the memory from disk as background process
	 */

	if (cur_cnt_point >= cnt_points_num) {
		panic("do_create_control_point() current CNTP to create %d >= "
			"total CNTPS %d\n",
			cur_cnt_point, cnt_points_num);
	}
	if (!cnt_points_created) {
		if (cur_cnt_point != mem_cnt_points) {
			panic("do_create_control_point() current CNTP to "
				"create %d != number of created CNTPs in "
				"memory %d\n",
				cur_cnt_point, mem_cnt_points);
		}
		DebugR("started to create "
			"CNTP #%d\n",
			cur_cnt_point);
		restart_type = CREATE_CNTP_REST_TYPE;
	} else {
		DebugR("started to recreate "
			"CNTP #%d\n",
			cur_cnt_point);
		restart_type = RECREATE_CNTP_REST_TYPE;
	}

	error = restart_system(restart_type, async_mode);
	if (error < 0) {
		DebugR("restart_system() "
			"failed, error %d\n", error);
		return error;
	}

	/*
	 * Here we can be only after restart and continue from
	 * created control point or after emergent restart of system
	 * because of harware/software problems/failures
	 */
	if (error > 0) {
		printk("Restart from created control point #%d to continue "
			"normal execution on cpu #%d\n",
			cur_cnt_point, raw_smp_processor_id());
	} else {
		printk("Emergent restart from control point #%d to recover "
			"system running on cpu #%d\n",
			cur_cnt_point, raw_smp_processor_id());
	}
	return error;
}

/*
 * Function should return:
 * N - number of created control points in the memory, if it started in
 *	control points creation mode. It can be only on first start
 *	from first created point, which was caused by restart_system()
 * 0 - if function started when all points created and it is emergent
 *	restart of the system
 * < 0 if any error
 */
void
switch_control_points(void)
{
	set_next_control_point();
	reset_cur_control_point();
}

void
set_next_control_point(void)
{
	int next_cnt_point;
#if CONFIG_CNT_POINTS_NUM
	int cntp;
#endif	/* CONFIG_CNT_POINTS_NUM != 0 */
	e2k_addr_t next_cntp_kernel_base;

	if (mem_cnt_points == 0)
		goto No_Valid_Point;
#if CONFIG_CNT_POINTS_NUM
	for (cntp = 1; cntp < get_cnt_points_num(cnt_points_num); cntp ++) {
		next_cnt_point = cur_cnt_point + cntp;
		if (next_cnt_point >= get_cnt_points_num(cnt_points_num))
			next_cnt_point -= get_cnt_points_num(cnt_points_num);
#else	/* CONFIG_CNT_POINTS_NUM == 0 */
	next_cnt_point = cur_cnt_point;
#endif	/* CONFIG_CNT_POINTS_NUM != 0 */
		if (!is_bootblock_cntp_mem_valid(bootblock_phys,
							next_cnt_point)) {
			DebugR("The control point #%d in the memory is not "
				"yet ready\n", next_cnt_point);
#if CONFIG_CNT_POINTS_NUM
			continue;
#else	/* CONFIG_CNT_POINTS_NUM == 0 */
			goto No_Valid_Point;
		}
#endif	/* CONFIG_CNT_POINTS_NUM != 0 */
#if CONFIG_CNT_POINTS_NUM
		} else {
#endif	/* CONFIG_CNT_POINTS_NUM != 0 */
			DebugR("The next control point in the memory will "
				"be #%d\n", next_cnt_point);
			write_bootblock_cur_cnt_point(bootblock_phys,
							next_cnt_point);
			next_cntp_kernel_base = read_bootblock_cntp_kernel_base(
							bootblock_phys,
							next_cnt_point);
			write_bootblock_kernel_base(bootblock_phys,
							next_cntp_kernel_base);
			set_bootblock_flags(bootblock_phys,
				RECOVERY_BB_FLAG | NO_READ_IMAGE_BB_FLAG);
			return;
#if CONFIG_CNT_POINTS_NUM
		}
	}
#endif	/* CONFIG_CNT_POINTS_NUM != 0 */
No_Valid_Point:
	DebugR("No any ready control point in the memory\n");
	reset_bootblock_flags(bootblock_phys,
		RECOVERY_BB_FLAG | NO_READ_IMAGE_BB_FLAG);
}

static void
reset_cur_control_point(void)
{
	mem_cnt_points --;
	write_bootblock_mem_cnt_points(bootblock_phys, mem_cnt_points);
	reset_bootblock_cntp_mem_valid(bootblock_phys, cur_cnt_point);
	DebugR("Reset control point #%d in the memory is not now valid, "
		"valid CNTPs now is %d\n",
		cur_cnt_point, mem_cnt_points);
	if (mem_cnt_points == 0) {
		reset_bootblock_flags(bootblock_phys,
				RECOVERY_BB_FLAG | NO_READ_IMAGE_BB_FLAG);
		DebugR("No any valid control point in the memory: "
			"reset recovery mode\n");
	}
}

static int
map_memory_pte_region(pmd_t *pmd, e2k_addr_t addr, e2k_addr_t end,
				pgprot_t prot)
{
	pte_t *ptep;
	pte_t pte;

	spin_unlock(&init_mm.page_table_lock);
	ptep = pte_alloc_kernel(pmd, addr);
	spin_lock(&init_mm.page_table_lock);
	if (!ptep){
		printk("map_memory_pte_region() ENOMEM for pte\n");
		return -ENOMEM;
	}
	do {
		WARN_ON(!pte_none(*ptep));

		pte = mk_pte_phys(__pa(addr), prot);
		set_pte_at(&init_mm, addr, ptep, pte);
		DebugPT("set pte 0x%p == 0x%lx for "
			"address 0x%lx\n",
			ptep, pte_val(*ptep), addr);
	} while (ptep ++, addr += PAGE_SIZE, addr != end);
	return 0;
}

static inline int
map_memory_pmd_region(pud_t *pud, e2k_addr_t addr, e2k_addr_t end,
				pgprot_t prot, e2k_size_t page_size)
{
	pmd_t *pmd;
	unsigned long next;

	spin_unlock(&init_mm.page_table_lock);
	pmd = pmd_alloc_kernel(&init_mm, pud, addr);
	spin_lock(&init_mm.page_table_lock);
	if (!pmd){
		printk("map_memory_pmd_region() ENOMEM for pte\n");
		return -ENOMEM;
	}
	if (page_size == E2K_SMALL_PAGE_SIZE) {
	} else if (page_size == E2K_LARGE_PAGE_SIZE) {
		do {
			pte_t *ptep;
			pte_t pte;

			ptep = (pte_t *)pmd;
			DebugPT("pmd 0x%p == "
				"0x%lx for large address 0x%lx\n",
				pmd, pmd_val(*pmd), addr);
			if (!pte_none(*ptep)) {
				DebugPT(KERN_ERR "map_memory_pmd_region(): "
					"pmd.0 0x%p = 0x%lx already exists\n",
					ptep, pte_val(*ptep));
			}

			pte = mk_pte_phys(__pa(addr), prot);
			set_pte_at(&init_mm, addr, ptep, pte);
			DebugPT("set pmd.0 0x%p == "
				"0x%lx for large address 0x%lx\n",
				ptep, pte_val(*ptep), addr);
			if (E2K_LARGE_PAGE_SIZE == E2K_4M_PAGE_SIZE) {
				ptep ++;
				if (!pte_none(*ptep)) {
					DebugPT(KERN_ERR 
						"map_memory_pmd_region(): "
						"pmd.1 0x%p = 0x%lx already "
						"exists\n",
						ptep, pte_val(*ptep));
				}
				set_pte_at(&init_mm, addr, ptep, pte);
				DebugPT("set pmd.1 "
					"0x%p == 0x%lx for large address "
					"0x%lx\n",
					ptep, pte_val(*ptep), addr);
			}
		} while (pmd += PMDS_PER_LARGE_PAGE,
					addr += page_size, addr != end);
		return 0;
	} else {
		panic("map_memory_pmd_region() invalid page size 0x%lx\n",
				page_size);
	}
	do {
		next = pmd_addr_end(addr, end);
		DebugPT("will start "
			"map_memory_pte_region() for pmd 0x%p == 0x%lx "
			"address 0x%lx next 0x%lx\n",
			pmd, pmd_val(*pmd), addr, next);
		if (map_memory_pte_region(pmd, addr, next, prot)){
			printk("map_memory_pmd_region() ENOMEM for map_memory_pte_region\n");
			return -ENOMEM;
		}
	} while (pmd ++, addr = next, addr != end);

	return 0;
}

static inline int
map_memory_pud_region(pgd_t *pgd, e2k_addr_t addr, e2k_addr_t end,
			pgprot_t prot, e2k_size_t page_size)
{
	pud_t *pud;
	e2k_addr_t next;

	spin_unlock(&init_mm.page_table_lock);
	pud = pud_alloc_kernel(&init_mm, pgd, addr);
	spin_lock(&init_mm.page_table_lock);
	if (!pud){
		printk("map_memory_pud_region() ENOMEM for pud\n");
		return -ENOMEM;
	}
	do {
		next = pud_addr_end(addr, end);
		DebugPT("will start "
			"map_memory_pmd_region() for pmd 0x%p == 0x%lx "
			"address 0x%lx next 0x%lx\n",
			pud, pud_val(*pud), addr, next);
		if (map_memory_pmd_region(pud, addr, next, prot, page_size)){
			printk("map_memory_pud_region() ENOMEM for pud rigion\n");
			return -ENOMEM;
		}
	} while (pud ++, addr = next, addr != end);

	return 0;
}

static int
map_memory_pgd_region(e2k_addr_t mem_base, e2k_addr_t mem_end,
			pgprot_t prot_flags, e2k_size_t page_size)
{
	pgprot_t prot;
	pgd_t *pgd;
	e2k_addr_t next;
	e2k_addr_t addr = mem_base;
	e2k_addr_t end = mem_end;
#ifdef CONFIG_NUMA
	e2k_size_t size = mem_end - mem_base;
	int nid = numa_node_id();
#endif /* CONFIG_NUMA */
	int err;

	if (page_size == E2K_SMALL_PAGE_SIZE) {
		prot = pgprot_small_size_set(prot_flags);
	} else if (page_size == E2K_LARGE_PAGE_SIZE) {
		prot = pgprot_large_size_set(prot_flags);
	} else {
		panic("map_memory_pgd_region() invalid page size 0x%lx\n",
				page_size);
	}
	DebugPT("started: address 0x%lx end 0x%lx "
		"prot 0x%lx\n",
		addr, end, pgprot_val(prot));

	BUG_ON(addr >= end);
	pgd = pgd_offset_kernel(addr);
	spin_lock(&init_mm.page_table_lock);
	do {
		next = pgd_addr_end(addr, end);
		DebugPT("will start "
			"map_memory_pud_region() for pgd 0x%p == 0x%lx "
			"address 0x%lx next end 0x%lx\n",
			pgd, pgd_val(*pgd), addr, next);
		err = map_memory_pud_region(pgd, addr, next, prot, page_size);
		if (err)
 			break;
	} while (pgd ++, addr = next, addr != end);
	spin_unlock(&init_mm.page_table_lock);

#ifdef  CONFIG_NUMA
	if (err = all_other_nodes_map_vm_area(nid, mem_base, size)) {
		DebugPT("Could not map area from addr 0x%lx, size 0x%lx "
			"on all numa nodes\n",
			mem_base, size);
	}
#endif  /* CONFIG_NUMA */

	DebugPT("returns with error %d\n", err);

	return err;
}

static void
unmap_memory_pte_region(pmd_t *pmd, e2k_addr_t addr, e2k_addr_t end)
{
	pte_t *pte;

	pte = pte_offset_kernel(pmd, addr);
	do {
		pte_t ptent = ptep_get_and_clear(&init_mm, addr, pte);
		DebugPT("clear pte 0x%p == 0x%lx for "
			"address 0x%lx\n",
			pte, pte_val(ptent), addr);
	} while (pte++, addr += PAGE_SIZE, addr != end);
}

static inline void
unmap_memory_pmd_region(pud_t *pud, e2k_addr_t addr, e2k_addr_t end,
	e2k_size_t page_size)
{
	pmd_t *pmd;
	e2k_addr_t next;

	pmd = pmd_offset_kernel(pud, addr);
	if (page_size == E2K_SMALL_PAGE_SIZE) {
	} else if (page_size == E2K_LARGE_PAGE_SIZE) {
		do {
			pte_t *ptep;
			pte_t pte;

			ptep = (pte_t *)pmd;
			pte = ptep_get_and_clear(&init_mm, addr, ptep);
			DebugPT("clear pmd.0 0x%p == "
				"0x%lx for address 0x%lx\n",
				ptep, pte_val(pte), addr);

			if (E2K_LARGE_PAGE_SIZE == E2K_4M_PAGE_SIZE) {
				ptep ++;
				pte = ptep_get_and_clear(&init_mm, addr, ptep);
				DebugPT("clear "
					"pmd.1 0x%p == 0x%lx for address "
					"0x%lx\n",
					ptep, pte_val(pte), addr);
			}
		} while (pmd += PMDS_PER_LARGE_PAGE,
					addr += page_size, addr != end);
		return;
	}
	do {
		next = pmd_addr_end(addr, end);
		DebugPT("clear pmd 0x%p == 0x%lx for "
			"address 0x%lx\n",
			pmd, pmd_val(*pmd), addr);
		if (pmd_none_or_clear_bad_kernel(pmd))
			continue;
		unmap_memory_pte_region(pmd, addr, next);
	} while (pmd++, addr = next, addr != end);
}

static inline void
unmap_memory_pud_region(pgd_t *pgd, e2k_addr_t addr, e2k_addr_t end,
	e2k_size_t page_size)
{
	pud_t *pud;
	e2k_addr_t next;

	pud = pud_offset_kernel(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		DebugPT("clear pud 0x%p == 0x%lx for "
			"address 0x%lx\n",
			pud, pud_val(*pud), addr);
		if (pud_none_or_clear_bad_kernel(pud))
			continue;
		unmap_memory_pmd_region(pud, addr, next, page_size);
	} while (pud++, addr = next, addr != end);
}

static void
unmap_memory_pgd_region(e2k_addr_t mem_base, e2k_addr_t mem_end,
	e2k_size_t page_size)
{
	pgd_t *pgd;
	e2k_addr_t next;
	e2k_addr_t addr = mem_base;
	e2k_addr_t end = mem_end;

	BUG_ON(addr >= end);
	pgd = pgd_offset_kernel(addr);
	do {
		next = pgd_addr_end(addr, end);
		DebugPT("clear pgd 0x%p == 0x%lx for "
			"address 0x%lx\n",
			pgd, pgd_val(*pgd), addr);
		if (pgd_none_or_clear_bad_kernel(pgd))
			continue;
		unmap_memory_pud_region(pgd, addr, next, page_size);
	} while (pgd++, addr = next, addr != end);
	flush_tlb_kernel_range(mem_base, mem_end);
}

static inline void
clean_area(e2k_addr_t start, e2k_size_t end)
{
	e2k_addr_t addr;
	printk("clean_area() from 0x%lx to 0x%lx\n", start, end);
	for (addr = start; addr < end; addr += sizeof (long long)) {
		*((long long *)addr) = (long long)addr;
	}
}

#ifdef	DEBUG_RESTORE
static void
clean_memory_area(void *startp, void *endp)
{
	e2k_addr_t bootblock_start = (e2k_addr_t)__va(bootblock_phys);
	e2k_addr_t bootblock_end = bootblock_start +
					sizeof (bootblock_struct_t);
	e2k_addr_t start = (e2k_addr_t)startp;
	e2k_addr_t end = (e2k_addr_t)endp;

	if (bootblock_start >= start && bootblock_start < end) {
		if (start < bootblock_start)
			clean_area(start, bootblock_start);
		if (bootblock_end < end)
			clean_area(bootblock_end, end);
	} else {
		clean_area(start, end);
	}
}
#endif	/* DEBUG_RESTORE */

static inline int
get_memory_unintersection(cntp_flag_t flags, e2k_addr_t mem_base,
	e2k_size_t mem_end, int *search_point, bank_info_t *mem_bank)
{
	bank_info_t *cur_area;
	e2k_addr_t area_base;
	e2k_addr_t area_end;
	int area;
	int ret;

	mem_bank->address = mem_base;
	mem_bank->size = mem_end - mem_base;
	DebugMI("started for memory from 0x%lx "
		"to 0x%lx (mapped_areas_num:%d)\n",
		mem_base, mem_end, mapped_areas_num);
	if (*search_point >= mapped_areas_num) {
		DebugMI("no more just mapped "
			"areas\n");
		return 1;
	}
	for (area = *search_point; area < mapped_areas_num; area ++) {
		cur_area = &just_mapped_areas[area];
		area_base = cur_area->address;
		area_end = area_base + cur_area->size;
		DebugMI("current area #%d from "
			"0x%lx to 0x%lx\n", area, area_base, area_end);
		if (mem_end <= area_base) {
			DebugMI("memory bank < "
				"current area\n");
			return 1;
		}
		if (mem_base < area_base) {
			mem_bank->size = area_base - mem_base;
			DebugMI("memory bank is "
				"decreased from end 0x%lx to 0x%lx\n",
				mem_end, area_base);
			if (mem_end <= area_end) {
				DebugMI("decreased "
					"part full included to current area\n");
				return 1;
			}
			mem_base = area_end;
			DebugMI("new memory bank "
				"is created from 0x%lx to 0x%lx\n",
				mem_base, mem_end);
			*search_point = *search_point + 1;
			DebugMI("search point is "
				"incremented, now is %d\n",
				*search_point);
			ret = map_memory_region(flags, mem_base,
							mem_end, search_point);
			if (ret != 0) {
				DebugMI("recursive "
					"map_memory_region(0 failed with error "
					" %d\n", ret);
				return ret;
			}
			return 1;
		}
		if (mem_base < area_end) {
			if (mem_end <= area_end) {
				DebugMI("memory "
					"bank is full included to current "
					"area\n");
				return 0;
			}
			mem_bank->address = area_end;
			mem_bank->size = mem_end - area_end;
			DebugMI("memory bank is "
				"decreased from start 0x%lx to 0x%lx\n",
				mem_base, area_end);
			mem_base = area_end;
		}
		*search_point = *search_point + 1;
		DebugMI("search point is "
			"incremented, now is %d\n",
			*search_point);
	}
	DebugMI("returns memory from 0x%lx "
		"to 0x%lx, search point is %d\n",
		mem_bank->address, mem_bank->address + mem_bank->size,
		*search_point);
	return 1;
}

static int
map_memory_region(cntp_flag_t flags, e2k_addr_t mem_base, e2k_addr_t mem_end,
	int *just_mapped_point)
{
	bank_info_t mem_bank;
	e2k_addr_t area_base;
	e2k_addr_t area_end;
	pgprot_t prot_flags = PAGE_CNTP_MAPPED_MEM;
	int ret;

	DebugMR("started for memory region from 0x%lx "
		"to 0x%lx, just mapped point is %d\n",
		mem_base, mem_end, *just_mapped_point);
	if (!(flags & UNMAP_CNTP_FLAG) && flags & RESTORE_CNTP_FLAG) {
		prot_flags = __pgprot(pgprot_val(prot_flags) | _PAGE_W);
		DebugMR("changed memory page protection "
			"flags to enable writing 0x%lx\n",
			pgprot_val(prot_flags));
	}
	ret = get_memory_unintersection(flags, mem_base, mem_end,
					just_mapped_point, &mem_bank);
	if (ret < 0) {
		DebugMR(""
			"with error is %d\n", ret);
		return ret;
	} else if (ret == 0) {
		DebugMR("region from 0x%lx to 0x%lx "
			"is full included into just mapped areas\n",
			mem_base, mem_end);
		return 0;
	}
	mem_base = mem_bank.address;
	mem_end = mem_base + mem_bank.size;
	DebugMR("will map memory region from 0x%lx "
		"to 0x%lx, page flags 0x%lx\n",
		mem_base, mem_end, pgprot_val(prot_flags));
	if (mem_base & ~PAGE_MASK) {
		panic("map_memory_region() memory base address 0x%lx is not "
			"page aligned\n", mem_base);
	}
	if (mem_end & ~PAGE_MASK) {
		panic("map_memory_region() memory end address 0x%lx is not "
			"page aligned\n", mem_end);
	}
	area_base = _PAGE_ALIGN_DOWN(mem_base,
					E2K_CNTP_MAPPED_MEM_PAGE_SIZE);
	area_end =_PAGE_ALIGN_UP(mem_end,
					E2K_CNTP_MAPPED_MEM_PAGE_SIZE);
	if (area_base < area_end) {
		DebugMR("will map memory region from "
			"0x%lx to 0x%lx, page size 0x%lx\n",
			area_base, area_end, E2K_CNTP_MAPPED_MEM_PAGE_SIZE);
		if (flags & UNMAP_CNTP_FLAG) {
			unmap_memory_pgd_region((e2k_addr_t)__va(area_base),
				(e2k_addr_t)__va(area_end),
				E2K_CNTP_MAPPED_MEM_PAGE_SIZE);
		} else {
			ret = map_memory_pgd_region((e2k_addr_t)__va(area_base),
				(e2k_addr_t)__va(area_end),
				prot_flags,
				E2K_CNTP_MAPPED_MEM_PAGE_SIZE);
			if (ret != 0) {
				DebugMR(""
					"map_memory_pgd_region() "
					"failed with error %d\n", ret);
				return ret;
			}
#ifdef	DEBUG_RESTORE
			if (flags & RESTORE_CNTP_FLAG) {
				clean_memory_area(__va(area_base),
							__va(area_end));
			}
#endif	/* DEBUG_RESTORE */
		}
	} else {
		area_base = mem_end;
		area_end = mem_end;
	}
	if (mem_base < area_base) {
		DebugMR("will map memory reg from "
			"0x%lx to 0x%lx, page size 0x%lx\n",
			mem_base, area_base, E2K_SMALL_PAGE_SIZE);
		if (flags & UNMAP_CNTP_FLAG) {
			unmap_memory_pgd_region((e2k_addr_t)__va(mem_base),
				(e2k_addr_t)__va(area_base),
				E2K_SMALL_PAGE_SIZE);
		} else {
			ret = map_memory_pgd_region((e2k_addr_t)__va(mem_base),
				(e2k_addr_t)__va(area_base),
				prot_flags, E2K_SMALL_PAGE_SIZE);
			if (ret != 0) {
				DebugMR(""
					"map_memory_pgd_region() "
					"failed with error %d\n", ret);
				return ret;
			}
#ifdef	DEBUG_RESTORE
			if (flags & RESTORE_CNTP_FLAG) {
				clean_memory_area(__va(mem_base),
							__va(area_base));
			}
#endif	/* DEBUG_RESTORE */
		}
	}
	if (mem_end > area_end) {
		DebugMR("will map memory region from "
			"0x%lx to 0x%lx, page size 0x%lx\n",
			area_end, mem_end, E2K_SMALL_PAGE_SIZE);
		if (flags & UNMAP_CNTP_FLAG) {
			unmap_memory_pgd_region((e2k_addr_t)__va(area_end),
				(e2k_addr_t)__va(mem_end),
				E2K_SMALL_PAGE_SIZE);
		} else {
			ret = map_memory_pgd_region((e2k_addr_t)__va(area_end),
				(e2k_addr_t)__va(mem_end),
				prot_flags, E2K_SMALL_PAGE_SIZE);
			if (ret != 0) {
				DebugMR(""
					"map_memory_pgd_region() "
					"failed with error %d\n", ret);
				return ret;
			}
#ifdef	DEBUG_RESTORE
			if (flags & RESTORE_CNTP_FLAG) {
				clean_memory_area(__va(area_end),
							__va(mem_end));
			}
#endif	/* DEBUG_RESTORE */
		}
	}
	return 0;
}

static int
map_control_point_memory(cntp_flag_t flags, int cntp_num)
{
	e2k_phys_bank_t	*phys_bank = NULL;
	e2k_addr_t mem_base;
	e2k_size_t mem_size;
	int just_mapped_point = 0;
	int bank;
	int node;
	int cur_node;
	int nodes_num;
	int ret;
	int mapped = 0;

	DebugRMM("started for control point #%d\n",
		cntp_num);

	nodes_num = phys_mem_nodes_num;
	for (node = 0, cur_node = 0; node < L_MAX_MEM_NUMNODES &&
			cur_node < nodes_num ; node ++) {

		phys_bank = full_phys_mem[node].banks;
		if (phys_bank->pages_num == 0)
			continue;       /* node has not memory */
		cur_node++;
		for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank++) {
			if (phys_bank -> pages_num == 0)
				break;  /* no more banks on node */

		#if (CONFIG_CNT_POINTS_NUM < 2)
			if (cnt_points_num == 1 || dump_analyze_opt) {
				mem_size = get_cntp_memory_len(
						phys_bank,
						cntp_small_kern_mem_div - 1,
						cntp_small_kern_mem_div);
				mem_size = phys_bank->pages_num * PAGE_SIZE - 
					mem_size;
				DebugRMM(""
					"mem_size:0x%lx div:%d\n",
					mem_size, cntp_small_kern_mem_div);

			} else
		#endif	/* CONFIG_CNT_POINTS_NUM < 2 */
				mem_size = get_cntp_memory_len(
						phys_bank,
						cntp_num,
						cnt_points_num);
			if (mem_size == 0) {
				DebugRMM("empty "
					"bank from base 0x%lx size 0x%lx for "
					"cntp #%d\n",
					phys_bank->base_addr,
					phys_bank->pages_num, cntp_num);
				continue;
			}

		#if (CONFIG_CNT_POINTS_NUM < 2)
			if (cnt_points_num == 1 || dump_analyze_opt)
				mem_base = phys_bank->base_addr;
			else
		#endif	/* CONFIG_CNT_POINTS_NUM < 2 */
				mem_base = get_cntp_memory_base(
						phys_bank,
						cntp_num,
						cnt_points_num);

			DebugRMM("control point "
				"memory node #%d bank #%d: start address "
				"0x%lx, end address 0x%lx\n",
				node, bank, mem_base, mem_base + mem_size);
			ret = map_memory_region(flags, mem_base,
						mem_base + mem_size,
						&just_mapped_point);
			if (ret != 0) {
				DebugRMM(""
					"map_memory_region() failed with "
					"error %d\n", ret);
				return ret;
			}

			mapped++;
			phys_bank++;
		}
	}
	DebugRMM("mapped %d bank(s) of memory of "
		"control point #%d\n", mapped, cntp_num);
	return 0;
}

#if CONFIG_CNT_POINTS_NUM
static void
unmap_control_point_memory(int cntp_num)
{
	DebugRMM("started for control point #%d\n",
		cntp_num);
	map_control_point_memory(UNMAP_CNTP_FLAG, cntp_num);
}

static pfn_area_t *hole_areas_root = NULL;
static pfn_area_t *hole_areas_list = NULL;
static pfn_area_t *hole_areas_cur = NULL;
static int hole_areas_cur_pos = 0;
static int zone_pfn_hash_shift;

static int
create_hole_areas_root(void)
{
	if (PFN_AREAS_HASH_ORDER) {
		hole_areas_root = (pfn_area_t *)__get_free_pages(
							PFN_AREAS_HASH_GFP,
							PFN_AREAS_HASH_ORDER);
		if (hole_areas_root == NULL) {
			printk("create_hole_areas_root() could not allocate "
				"memory for hash table root\n");
			return -ENOMEM;
		}
		memset(hole_areas_root, 0, PFN_AREAS_HASH_SIZE);
	} else {
		hole_areas_root = (pfn_area_t *)get_zeroed_page(
							PFN_AREAS_HASH_GFP);
		if (hole_areas_root == NULL) {
			printk("create_hole_areas_root() could not allocate "
				"zeroed memory for hash table root\n");
			return -ENOMEM;
		}
	}
	DebugZA("allocated memory for hash table "
		"root at 0x%p\n", hole_areas_root);
	return 0;
}

static int
create_hole_areas_list(void)
{
	pfn_area_t *hole_areas;

	hole_areas = (pfn_area_t *)__get_free_pages(PFN_AREAS_LIST_GFP,
							PFN_AREAS_LIST_ORDER);
	if (hole_areas == NULL) {
		printk("create_hole_areas_list() could not allocate memory "
			"for new page of list. oder=%d\n", PFN_AREAS_LIST_ORDER);
		return -ENOMEM;
	}
	/*
	 * item # 0 of all hole areas list page is link to the next
	 * list page, so zero it
	 */
	hole_areas[0].start = 0;
	hole_areas[0].size = 0;
	hole_areas[0].next = NULL;
	if (hole_areas_list == NULL) {
		hole_areas_list = hole_areas;
		DebugZA("allocated memory for the "
			"first page of the list 0x%p\n", hole_areas);
	} else {
		hole_areas_cur[0].next = hole_areas;
		DebugZA("allocated memory for the "
			"new page of the list 0x%p\n", hole_areas);
	}
	hole_areas_cur = hole_areas;
	hole_areas_cur_pos = 1;	/* pos #0 is link to the next page */
	return 0;
}

static int
init_cntp_memory_state(int cntp_to_save)
{
	cntp_nosave_areas = __va(read_bootblock_cntp_nosave_areas(
					bootblock_phys, cntp_to_save));
	cntp_nosave_areas_num = read_bootblock_cntp_nosaves_num(
					bootblock_phys, cntp_to_save);
	DebugR("no save memory areas list starts "
		"at 0x%p, size %d\n",
		cntp_nosave_areas, cntp_nosave_areas_num);
	cntp_node_data = __va(read_bootblock_cntp_node_data(bootblock_phys,
								cntp_to_save));
	DebugR("memory node data list starts at "
		"0x%p\n", cntp_node_data);
	cntp_kernel_base = read_bootblock_cntp_kernel_base(bootblock_phys,
								cntp_to_save);
	DebugR("kernel image base address is 0x%lx\n",
		cntp_kernel_base);

	return create_hole_areas_root();
}

static void
delete_hole_areas_root(void)
{
	if (hole_areas_root != NULL) {
		free_pages((unsigned long)hole_areas_root,
						PFN_AREAS_HASH_ORDER);
		DebugZA("freeed memory from "
			"root 0x%p\n", hole_areas_root);
		hole_areas_root = NULL;
	}
}

static void
delete_hole_areas_list(void)
{
	pfn_area_t *hole_areas = hole_areas_list;

	while (hole_areas != NULL) {
		hole_areas = hole_areas[0].next;
		free_pages((unsigned long)hole_areas_list,
						PFN_AREAS_LIST_ORDER);
		DebugZA("freeed memory from "
			"list page 0x%p\n", hole_areas_list);
		hole_areas_list = hole_areas;
	}
	hole_areas_cur = NULL;
	hole_areas_cur_pos = 0;
}

static void
delete_zone_hole_areas(void)
{
	delete_hole_areas_list();
	delete_hole_areas_root();
}

static inline int
get_pfn_order(e2k_pfn_t pfn)
{
	int order;
	e2k_pfn_t size;

	size = pfn;
	order = -1;
	while (size) {
		size >>= 1;
		order++;
	};
	if (order == -1)
		return order;
	if ((1 << order) < pfn)
		order ++;
	return order;
}

static void
init_zone_hole_areas_hash(struct zone *zone)
{
	e2k_pfn_t pfn_num = zone->spanned_pages;
	e2k_pfn_t pfn_size = (pfn_num + PFN_AREAS_HASH_ENTRIES - 1) /
						PFN_AREAS_HASH_ENTRIES;
	zone_pfn_hash_shift = get_pfn_order(pfn_size);

	DebugZA("set hash shift to %d for "
		"0x%x pages, hash entries 0x%lx\n",
		zone_pfn_hash_shift, pfn_num, PFN_AREAS_HASH_ENTRIES);
}

static void
reset_hole_areas_root(void)
{
	memset(hole_areas_root, 0, PFN_AREAS_HASH_SIZE);
	DebugZA("zeroed memory for hash table "
		"root at 0x%p\n", hole_areas_root);
}

static void
reset_hole_areas_list(void)
{
	hole_areas_cur = hole_areas_list;
	hole_areas_cur_pos = 1;
	DebugZA("set current position to the "
		"first page of list at 0x%p\n", hole_areas_cur);
}

static void
reset_zone_hole_areas(void)
{
	reset_hole_areas_list();
	reset_hole_areas_root();
}

static pfn_area_t *
get_cur_hole_area(void)
{
	pfn_area_t *hole_area;
	int ret;

	if (hole_areas_list == NULL) {
		DebugZA("hole area list is not created "
			"yet\n");
		ret = create_hole_areas_list();
		if (ret) {
			DebugZA("could not create hole "
				"areas list\n");
			return NULL;
		}
	}
	if (hole_areas_cur_pos >= PFN_AREAS_LIST_ENTRIES) {
		DebugZA("hole area list is exhausted\n");
		ret = create_hole_areas_list();
		if (ret) {
			DebugZA("could not create new "
				"hole areas list\n");
			return NULL;
		}
	}
	hole_area = &hole_areas_cur[hole_areas_cur_pos];
	DebugZA("returns hole area #%d at 0x%p\n",
		hole_areas_cur_pos, hole_area);
	hole_areas_cur_pos ++;
	return hole_area;
}

static int
put_hole_area(e2k_pfn_t start_pfn, e2k_pfn_t size_pfn)
{
	pfn_area_t *hole_area;
	pfn_area_t *prev_area = NULL;
	pfn_area_t *new_area;
	e2k_pfn_t hash_index;
	e2k_pfn_t area_start = 0;
	e2k_pfn_t area_size = 0;

	hash_index = start_pfn >> zone_pfn_hash_shift;
	hole_area = &hole_areas_root[hash_index];
	DebugZM("started for pfn 0x%x, size 0x%x, hash index "
		"0x%x\n", start_pfn, size_pfn, hash_index);
	while (hole_area != NULL) {
		area_start = hole_area->start;
		area_size = hole_area->size;
		DebugZM("current area start pfn 0x%x "
			"size 0x%x\n", area_start, area_size);
		if (area_size == 0) {
			hole_area->start = start_pfn;
			hole_area->size = size_pfn;
			DebugZM("new area put as hash root "
				"item\n");
			return 0;
		}
		if (area_start == start_pfn + size_pfn) {
			hole_area->start = start_pfn;
			hole_area->size += size_pfn;
			DebugZM("new area merged from begin "
				"new start 0x%x, size 0x%x\n",
				hole_area->start, hole_area->size);
			return 0;
		}
		if (area_start + area_size == start_pfn) {
			hole_area->size += size_pfn;
			DebugZM("new area merged from end "
				"new size 0x%x\n", hole_area->size);
			return 0;
		}
		if (start_pfn < area_start) {
			if (start_pfn + size_pfn > area_start) {
				panic("put_hole_area() intersections of hole "
					"areas: current start pfn 0x%x, size "
					"0x%x, new start 0x%x, size 0x%x\n",
					area_start, area_size,
					start_pfn, size_pfn);
			}
			break;
		}
		if (start_pfn < area_start + area_size) {
			panic("put_hole_area() intersections of hole "
				"areas: current start pfn 0x%x, size "
				"0x%x, new start 0x%x, size 0x%x\n",
				area_start, area_size,
				start_pfn, size_pfn);
		}
		prev_area = hole_area;
		hole_area = hole_area->next;
	}
	new_area = get_cur_hole_area();
	if (new_area == NULL) {
		printk("put_hole_area() could not take hole area to put new. ENOMEM\n");
		return -ENOMEM;
	}
	if (prev_area != NULL) {
		new_area->start = start_pfn;
		new_area->size = size_pfn;
		new_area->next = hole_area;
		prev_area->next = new_area;
		DebugZM("new area inserted before current\n");
	} else {
		new_area->start = area_start;
		new_area->size = area_size;
		new_area->next = hole_area->next;
		hole_area->start = start_pfn;
		hole_area->size = size_pfn;
		hole_area->next = new_area;
		DebugZM("new area exchanged with current\n");
	}
	return 0;
}

static pfn_area_t *
link_zone_hole_areas(void)
{
	pfn_area_t *start_area;
	pfn_area_t *end_area;
	pfn_area_t *cur_area;
	int entry;
	int list_len;
	long areas;
	e2k_pfn_t total_pfns = 0;

	for (entry = 0; entry < PFN_AREAS_HASH_ENTRIES; entry ++) {
		start_area = &hole_areas_root[entry];
		DebugZM("root area #%d "
			"pfn 0x%x size 0x%x\n",
			entry, start_area->start, start_area->size);
		if (start_area->size != 0) {
			DebugZA("root area #%d is "
				"start area of the list\n", entry);
			break;
		}
	}
	if (entry >= PFN_AREAS_HASH_ENTRIES) {
		DebugZA("hole areas list is empty\n");
		return NULL;
	}
	end_area = start_area;
	cur_area = start_area->next;
	areas = 1;
	total_pfns = start_area->size;
	do {
		list_len = 0;
		while (cur_area != NULL) {
			DebugZM("current list area #%d "
				"pfn 0x%x size 0x%x\n",
				list_len, cur_area->start, cur_area->size);
			if (end_area->start + end_area->size ==
				cur_area->start) {
				end_area->size += cur_area->size;
				DebugZM("area merged "
					"from end, new size 0x%x\n",
					end_area->size);
				total_pfns += cur_area->size;
			} else if (end_area->start + end_area->size <
							cur_area->start	) {
				end_area->next = cur_area;
				end_area = cur_area;
				areas ++;
				DebugZM("area > end "
					"and set as new end #%ld\n",
					areas);
				total_pfns += cur_area->size;
			} else {
				panic("link_zone_hole_areas() area from 0x%x "
					"size 0x%x is not ordered, current "
					"end from 0x%x size 0x%x\n",
					cur_area->start, cur_area->size,
					end_area->start, end_area->size);
			}
			list_len ++;
			cur_area = cur_area->next;
		}
		entry ++;
		while (entry < PFN_AREAS_HASH_ENTRIES) {
			cur_area = &hole_areas_root[entry];
			DebugZM("current root area #%d "
				"pfn 0x%x size 0x%x\n",
				entry, cur_area->start, cur_area->size);
			if (cur_area->size != 0) {
				DebugZM("hash line #%d is valid\n", entry);
				break;
			} else if (cur_area->next != NULL) {
				panic("link_zone_hole_areas() empty hash line "
					"contains not empty link to "
					"list 0x%p\n", cur_area->next);
			} else {
				DebugZM("hash line #%d is empty\n", entry);
			}
			entry ++;
		}
	} while (entry < PFN_AREAS_HASH_ENTRIES);
	end_area->next = NULL;
	DebugZA("detected %ld contiguous areas of "
		"hole memory, total pfns 0x%x\n", areas, total_pfns);
	return start_area;
}

static int
get_zone_free_areas(struct zone *zone)
{
	e2k_pfn_t size_pfn;
	e2k_pfn_t start_pfn;
	struct page *page;
	struct list_head *lists;
	struct list_head *list;
	struct list_head *list_head;
	long areas = 0;
	e2k_pfn_t total_pfns = 0;
	int order;
	int list_num;
	int cpu;
	int error = 0;

	for (order = MAX_ORDER - 1; order >= 0; --order) {
		size_pfn = 1 << order;
		lists = (struct list_head *)&((struct free_area *)
				cntp_va(zone->free_area, 0))[order].free_list;
		DebugZA("starts to get free areas "
			"for order %d, pfn size %d, free pfn %ld\n",
			order, size_pfn, zone->free_area[order].nr_free);

		for (list_num = 0; list_num < MIGRATE_TYPES; list_num++) {
			list_head = &lists[list_num];
			DebugZM("will put free areas for "
				"list head 0x%p\n",
				list_head);

			for (list = cntp_va(list_head->next, 0);
					list != list_head;
					list = cntp_va(list->next, 0)) {

				page = list_entry(list, struct page, lru);
				start_pfn = zone_page_to_pfn(zone, page);
				DebugZM("will put free "
					"area page 0x%p from pfn 0x%x\n",
					page, start_pfn);

				error = put_hole_area(start_pfn, size_pfn);
				if (error) {
					DebugZM("could "
						"not put free area from pfn "
						"0x%x size 0x%x, error %d\n",
						start_pfn, size_pfn, error);
					return error;
				}
				areas ++;
				total_pfns += size_pfn;
			}
		}
	}
	for_each_online_cpu (cpu) {
		struct per_cpu_pageset *pset =
				cntp_va(per_cpu_ptr(zone->pageset, cpu), 0);
		lists = cntp_va(pset->pcp.lists, 0);
		size_pfn = 1 << 0;
		DebugZA("starts to get free areas "
			"per cpu #%d, pset 0x%p, pfn size %d\n",
			cpu, pset, size_pfn);

		for (list_num = 0; list_num < MIGRATE_PCPTYPES; list_num++) {
			list_head = &lists[list_num];

			DebugZM("will put free areas for "
				"list head 0x%p\n",
				list_head);

			for (list = cntp_va(list_head->next, 0);
					list != list_head;
					list = cntp_va(list->next, 0)) {

				page = list_entry(list, struct page, lru);
				start_pfn = zone_page_to_pfn(zone, page);
				DebugZM("will put free "
					"area for page 0x%p, pfn 0x%x\n",
					page, start_pfn);
				
				error = put_hole_area(start_pfn, size_pfn);
				if (error) {
					DebugZM("could "
						"not put free area for pfn "
						"0x%x size 0x%x, error %d\n",
						start_pfn, size_pfn, error);
					return error;
				}
				areas ++;
				total_pfns += size_pfn;
			}
		}
	}
	DebugZA("detected %ld contiguous areas of "
		"free memory, total pfns 0x%x\n", areas, total_pfns);
	return 0;
}

static int
get_zone_nosave_areas(struct zone *zone)
{
	e2k_pfn_t zone_start_pfn;
	e2k_pfn_t zone_end_pfn;
	e2k_pfn_t start_pfn;
	e2k_pfn_t end_pfn;
	bank_info_t *cur_area;
	e2k_pfn_t total_pfns = 0;
	int areas = 0;
	int area;
	int error = 0;

	zone_start_pfn = zone->zone_start_pfn;
	zone_end_pfn = zone_start_pfn + zone->spanned_pages;
	DebugZA("started for zone start pfn 0x%x, "
		"end pfn 0x%x, nosave list size %d\n",
		zone_start_pfn, zone_end_pfn, cntp_nosave_areas_num);

	for (area = 0; area < cntp_nosave_areas_num; area ++) {
		cur_area = &cntp_nosave_areas[area];
		start_pfn = cur_area->address >> PAGE_SHIFT;
		end_pfn = start_pfn + (cur_area->size >> PAGE_SHIFT);
		DebugZM("current nosave area #%d start "
			"pfn 0x%x, end pfn 0x%x\n",
			area, start_pfn, end_pfn);
		if (start_pfn >= zone_end_pfn) {
			DebugZM("area > zone end, "
				"break creation\n");
			break;
		} else if (end_pfn <= zone_start_pfn) {
			DebugZM("area < zone start, "
				"goto next area\n");
			continue;
		}
		if (start_pfn < zone_start_pfn) {
			start_pfn = zone_start_pfn;
			DebugZM("area start restricted "
				"by zone start 0x%x\n", start_pfn);
		}
		if (end_pfn > zone_end_pfn) {
			end_pfn = zone_end_pfn;
			DebugZM("area end restricted "
				"by zone end 0x%x\n", end_pfn);
		}
		start_pfn -= zone_start_pfn;
		end_pfn -= zone_start_pfn;
		DebugZM("will put nosave area from "
			"pfn 0x%x to 0x%x\n",
			start_pfn, end_pfn);
		error = put_hole_area(start_pfn, end_pfn - start_pfn);
		if (error) {
			DebugZM("could not put "
				"nosave area from pfn 0x%x size 0x%x, "
				"error %d\n",
				start_pfn, end_pfn - start_pfn, error);
			return error;
		}
		areas ++;
		total_pfns += (end_pfn - start_pfn);
	}
	DebugZA("detected %d contiguous areas of "
		"nosave memory, total pfns 0x%x\n", areas, total_pfns);
	return 0;
}

static inline int
init_cntp_file_state(int restore_flag, int cntp_num)
{
	dump_cntp_desc = &dump_header->cntp.cntps[cntp_num];

	if (restore_flag) {
		if (!dump_cntp_desc->valid || dump_cntp_desc->size == 0) {
			panic("init_cntp_file_state() control point #%d to "
				"restore is not valid or empty\n", cntp_num);
		}
	} else if (dump_cntp_desc->valid) {
		/* reset old control point, if any */
		dump_cntp_desc->valid = 0;
		dump_cntp_desc->size = 0;
		dump_header->cntp.count --;
		set_page_dirty(virt_to_page(dump_header)); /* force it to be */
							   /* written out */
		DebugR("reset old control point #%d\n",
			cntp_num);
	}

	dump_cntp_cur_block = dump_cntp_desc->start;
	cntp_cur_tags_block = dump_cntp_desc->tags_start;
	DebugR("set dump file position to %ld the "
		"start of control point #%d, max area size 0x%lx\n",
		dump_cntp_cur_block, cntp_num, dump_cntp_desc->max_size);
	if (restore_flag) {
		cntp_end_tags_block = cntp_cur_tags_block +
						dump_cntp_desc->tags_size;
		DebugR("set tags dump file position "
			"to start 0x%lx, end tags position 0x%lx\n",
			cntp_cur_tags_block, cntp_end_tags_block);
	} else {
		DebugR("set tags dump file position "
			"to 0x%lx, max area size 0x%lx\n",
			cntp_cur_tags_block,
			dump_cntp_desc->tags_max_size);
	}
	if (!restore_flag) {
		cntp_total_pfns_to_save = 0;
		cntp_total_bytes_to_save = 0;
		cntp_total_tags_pfns_to_save = 0;
		cntp_total_tags_to_save = 0;
		cntp_total_saved_tags = 0;
		cntp_prev_numeric_tags_pfns = 0;
	} else {
		cntp_cur_pfns_to_read = 0;
		cntp_cur_pfns_to_restore = 0;
		cntp_cur_pfns_restored = 0;
		cntp_tags_pfns_to_read = 0;
		cntp_tags_pfns_to_restore = 0;
		cntp_tags_pfns_restored = 0;
		no_ready_pfns_times = 0;
		not_read_pfn_times = 0;
		not_read_first_pfn_times = 0;
		first_restored_area = 1;
		not_read_area_pfn_times = 0;
		not_read_tags_pfn_times = 0;
		restore_pfns_times = 0;
		read_pfns_times = 0;
		pfns_enough_times = 0;
		read_tags_pfns_times = 0;
		tags_pfns_enough_times = 0;
	}
	cntp_real_tags_pfns = 0;
	cntp_cur_numeric_tags_pfns = 0;

	return 0;
}

static void
set_cntp_file_state(int cntp_to_save)
{
	dump_cntp_desc->size = dump_cntp_cur_block - dump_cntp_desc->start;
	dump_cntp_desc->tags_size = cntp_cur_tags_block -
					dump_cntp_desc->tags_start;
	dump_cntp_desc->areas_num = cntp_table_total_entries;
	dump_cntp_desc->valid = 1;
	dump_header->cntp.count ++;
	DebugR("validated control point #%d, "
		"total size 0x%lx blocks, tags size 0x%lx, "
		"valid points num %d\n",
		cntp_to_save, dump_cntp_desc->size, dump_cntp_desc->tags_size,
		dump_header->cntp.count);
}

static inline u64
get_cur_cntp_file_pos(void)
{
	return dump_cntp_cur_block;
}

static inline u64
get_dump_file_pos(u64 *pos, e2k_size_t incr_size, u64 start, u64 max_size)
{
	u64 increment = PAGE_ALIGN(incr_size) >> PAGE_SHIFT;
	u64 cur_pos = *pos;
	u64 new_pos = cur_pos + increment;

	if (new_pos - start > max_size) {
		printk("get_dump_file_pos() control point file overflow "
			"current offset 0x%lx + increment 0x%lx > max file "
			"size 0x%lx\n",
			cur_pos - start, increment, max_size);
		return 0;
	}
	*pos = new_pos;
	return cur_pos;
}

static inline u64
get_cntp_file_pos(e2k_size_t incr_size)
{
	return get_dump_file_pos(&dump_cntp_cur_block, incr_size,
					dump_cntp_desc->start,
					dump_cntp_desc->max_size);
}

static inline u64
get_cntp_tags_file_pos(e2k_size_t incr_size)
{
	return get_dump_file_pos(&cntp_cur_tags_block, incr_size,
					dump_cntp_desc->tags_start,
					dump_cntp_desc->tags_max_size);
}

typedef struct mem_area {
	e2k_addr_t start;
	e2k_addr_t end;
	const char *name;
} mem_area_t;

static mem_area_t dump_save_area = { 0, 0, "saved" };
static mem_area_t dump_read_area = { 0, 0, "read" };
static mem_area_t dump_restore_area = { 0, 0, "restored" };

static void
count_mem_area_page(mem_area_t *mem_area, struct page *page, int reset_addr)
{
	e2k_addr_t area_addr;

	area_addr = page->private;
	if (area_addr == 0) {
		DebugAP("page 0x%p is not "
			"%s area page\n", page, mem_area->name);
		return;
	}
	if (reset_addr)
		page->private = 0;
	if (mem_area->end == area_addr) {
		mem_area->end += PAGE_SIZE;
		DebugAP("page 0x%p address 0x%lx "
			"continues %s area\n", page, area_addr, mem_area->name);
		return;
	}
	if (mem_area->end > mem_area->start) {
		DebugCPG("%s area from 0x%lx to "
			"0x%lx is completed\n",
			mem_area->name, mem_area->start, mem_area->end);
	}

	mem_area->start = area_addr;
	mem_area->end = area_addr + PAGE_SIZE;
	DebugAP("page 0x%p is start address "
		"0x%lx of new %s area\n", page, area_addr, mem_area->name);

}

static void
count_zone_area_page(struct page *page)
{
	count_mem_area_page(&dump_save_area, page, 1);
}

static void
count_read_area_page(struct page *page)
{
	count_mem_area_page(&dump_read_area, page, 0);
}

static void
count_restore_area_page(struct page *page)
{
	count_mem_area_page(&dump_restore_area, page, 1);
}

static void
unmap_zone_area_bio(struct bio *bio)
{
	struct page *page;
	struct bio_vec *bvec;
	int i;

	for (i = 0; i < bio->bi_vcnt; i ++) {
		bvec = &bio->bi_io_vec[i];
		page = bvec->bv_page;
		if (page != NULL) {
			count_zone_area_page(page);
			__free_page(page);
			bvec->bv_page = NULL;
			bvec->bv_len = 0;
			DebugAP("free page 0x%p "
				"#%d\n", page, i);
			total_free_pages ++;
		}
	}
	bio->bi_vcnt = 0;
	DebugBIO("unmapped %d pages\n", i);
}

static inline void
put_the_mapped_bio(struct bio *bio)
{
	if (bio == NULL) {
		panic("put_the_mapped_bio() bio is NULL\n");
	}
	unmap_zone_area_bio(bio);
	bio_put(bio);
}

static inline void
put_cur_mapped_bio(struct bio *bio)
{
	if (dump_bio == NULL) {
		panic("put_cur_mapped_bio() currennt bio is NULL\n");
	} else if (bio != dump_bio) {
		panic("put_cur_mapped_bio() passed bio 0x%p is not currennt "
			"0x%p\n", bio, dump_bio);
	}
	put_the_mapped_bio(bio);
	dump_bio = NULL;
}

static int
cntp_bio_endio(struct bio *bio, unsigned int bytes_done, int err)
{
	dump_bio_t *bio_list;
	unsigned long flags;

	if (bio->bi_size) {
		printk("cntp_bio_endio() bio 0x%p was not done, bytes "
			"done 0x%x, rest 0x%x, err %d\n",
			bio, bytes_done, bio->bi_size, err);
		return 1;
	}
	DebugBIO("completed bio 0x%p, bytes done 0x%x, "
		"index 0x%x from 0x%x pages, err %d\n",
		bio, bytes_done, bio->bi_idx, bio->bi_vcnt, err);
	if (!test_bit(BIO_UPTODATE, &bio->bi_flags)) {
		int i;
		DebugBIO("bio is not uptodate "
			"set error to all rest pages\n");
		for (i = bio->bi_idx; i < bio->bi_vcnt; i ++) {
			SetPageError(bio->bi_io_vec[i].bv_page);
			DebugBIO("set error to page "
				"#%d 0x%p\n", i, bio->bi_io_vec[i].bv_page);
		}
	}
	bio_list = bio->bi_private;
	if (bio_list == NULL) {
		panic("cntp_bio_endio() empty pointer of cntp dump list "
			"of bio structure\n");
	}
	raw_spin_lock_irqsave(&dump_bio_lock, flags);
	list_del(&bio_list->list);
	raw_spin_unlock_irqrestore(&dump_bio_lock, flags);
	kmem_cache_free(dump_bio_cachep, bio_list);
	return 0;
}

static void
map_zone_bio_endio(struct bio *bio, int err)
{
	unsigned int bytes_done = bio->bi_idx * PAGE_SIZE;

	if (bio->bi_size) {
		printk("map_zone_bio_endio() bio 0x%p was not done, bytes "
			"done 0x%x, rest 0x%x, err %d\n",
			bio, bytes_done, bio->bi_size, err);
		return;
	}
	if (cntp_bio_endio(bio, bytes_done, err) == 1)
		return;
	put_the_mapped_bio(bio);
	cntp_total_saved_bytes += bytes_done;
}

static void
get_bio_read_pages(struct bio *bio)
{
	struct page *page;
	struct bio_vec *bvec;
	int i;

	for (i = 0; i < bio->bi_vcnt; i ++) {
		bvec = &bio->bi_io_vec[i];
		page = bvec->bv_page;
		if (page != NULL) {
			count_read_area_page(page);

			if (PageError(page)) {
				ClearPageUptodate(page);
				DebugBIO("IO failed : "
					"clear page 0x%p uptodate flag\n",
					page);
			} else {
				SetPageUptodate(page);
			}

			raw_spin_lock_irq(&read_page_lock);
			list_add_tail(&page->lru, &read_page_list_head);
			raw_spin_unlock_irq(&read_page_lock);

			bvec->bv_page = NULL;
			bvec->bv_len = 0;
		}
	}
	bio->bi_vcnt = 0;
	bio_put(bio);
	DebugBIO("add to read done list %d pages\n", i);
}

static void
read_area_bio_endio(struct bio *bio, int err)
{
	unsigned int bytes_done = bio->bi_idx * PAGE_SIZE;

	if (bio->bi_size) {
		DebugBIO("bio 0x%p was not done, bytes "
			"done 0x%x, rest 0x%x, err %d\n",
			bio, bytes_done, bio->bi_size, err);
		return;
	}
	if (cntp_bio_endio(bio, bytes_done, err) == 1)
		return;
	get_bio_read_pages(bio);
	cntp_cur_pfns_to_restore += (bytes_done >> PAGE_SHIFT);
}

static void
get_bio_read_tags_pages(struct bio *bio)
{
	struct page *page;
	struct bio_vec *bvec;
	int i;

	for (i = 0; i < bio->bi_vcnt; i ++) {
		bvec = &bio->bi_io_vec[i];
		page = bvec->bv_page;
		if (page != NULL) {
			if (PageError(page)) {
				ClearPageUptodate(page);
				DebugBIO("IO failed "
					": clear page 0x%p uptodate flag\n",
					page);
			} else {
				SetPageUptodate(page);
			}

			raw_spin_lock_irq(&read_tags_page_lock);
			list_add_tail(&page->lru, &read_tags_page_list_head);
			raw_spin_unlock_irq(&read_tags_page_lock);

			bvec->bv_page = NULL;
			bvec->bv_len = 0;
		}
	}
	bio->bi_vcnt = 0;
	bio_put(bio);
	DebugBIO("add to read done list %d pages\n",
		i);
}

static void
read_tags_bio_endio(struct bio *bio, int err)
{
	unsigned int bytes_done = bio->bi_idx * PAGE_SIZE;

	if (bio->bi_size) {
		DebugBIO("bio 0x%p was not done, bytes "
			"done 0x%x, rest 0x%x, err %d\n",
			bio, bytes_done, bio->bi_size, err);
		return;
	}
	if (cntp_bio_endio(bio, bytes_done, err) == 1)
		return;
	get_bio_read_tags_pages(bio);
	cntp_tags_pfns_to_restore += (bytes_done >> PAGE_SHIFT);
}

static void
wait_for_all_bio_end(void)
{
	while (!list_empty(&dump_bio_list_head)) {
		DebugBIO("does not completed all IOs\n");
		yield();
	}
}

static struct bio *
get_new_bio_to_map(int nr_pages, bio_end_io_t *bio_endio)
{
	struct bio *bio;

	if (nr_pages > dump_max_pages)
		nr_pages = dump_max_pages;
	bio = bio_alloc(GFP_KERNEL, nr_pages);
	if (bio == NULL) {
		DebugBIO("could not allocate "
			"bio structure\n");
		return NULL;
	}
	bio->bi_bdev = dump_bdev;
	bio->bi_end_io = bio_endio;
	DebugBIO("allocated new bio structure "
		"vectors %d, max vectors %d, sector 0x%lx\n",
		bio->bi_vcnt, bio->bi_max_vecs, bio->bi_sector);
	return bio;
}

static inline struct bio *
get_the_bio_to_map(struct bio **bio_p, int nr_pages, bio_end_io_t *bio_endio)
{
	if (*bio_p == NULL) {
		*bio_p = get_new_bio_to_map(dump_max_pages, bio_endio);
		if (*bio_p == NULL) {
			printk("get_the_bio_to_map() could not allocate "
				"bio structure\n");
			return NULL;
		}
		DebugBIO("allocated new bio structure "
			"0x%p\n", *bio_p);
	} else {
		DebugBIO("returns old bio structure "
			"0x%p, vectors %d, max vectors %d\n",
			*bio_p, (*bio_p)->bi_vcnt, (*bio_p)->bi_max_vecs);
	}
	return *bio_p;
}

static inline struct bio *
get_cur_bio_to_map(int nr_pages)
{
	return get_the_bio_to_map(&dump_bio, nr_pages, map_zone_bio_endio);
}

static inline struct bio *
get_the_bio_to_read(struct bio **bio_p, int nr_pages, bio_end_io_t *bio_endio)
{
	if (*bio_p != NULL) {
		DebugBIO("returns old bio structure "
			"0x%p, vectors %d, max vectors %d\n",
			*bio_p, (*bio_p)->bi_vcnt, (*bio_p)->bi_max_vecs);
		return *bio_p;
	}
	if (nr_pages > dump_max_pages) {
		DebugBIO("limits number of pages 0x%x "
			"by max for bio value 0x%lx\n",
			nr_pages, dump_max_pages);
		nr_pages = dump_max_pages;
	}
	*bio_p = get_new_bio_to_map(nr_pages, bio_endio);
	if (*bio_p == NULL) {
		DebugBIO("could not allocate new "
			"bio structure\n");
		return NULL;
	}
	DebugBIO("allocated new bio structure "
		"0x%p\n", *bio_p);
	return *bio_p;
}

static inline struct bio *
get_cur_bio_to_read_area(int nr_pages)
{
	return get_the_bio_to_read(&dump_bio, nr_pages, read_area_bio_endio);
}

static inline struct bio *
get_cur_bio_to_read_tags(int nr_pages)
{
	return get_the_bio_to_read(&dump_tags_areas_bio, nr_pages,
						read_tags_bio_endio);
}

static int
submit_the_mapped_bio(struct bio *bio, int rw)
{
	dump_bio_t *bio_list;

	DebugBIO("started for %d vectors, size 0x%x, "
		"sector 0x%lx\n",
		bio->bi_vcnt, bio->bi_size, bio->bi_sector);
	bio_list = kmem_cache_alloc(dump_bio_cachep, GFP_KERNEL);
	if (bio_list == NULL) {
		printk("submit_the_mapped_bio() ENOMEM in "
			" slab memory for queue bio structure\n");
		return -ENOMEM;
	}
	bio_list->bio = bio;
	INIT_LIST_HEAD(&bio_list->list);
	bio->bi_private = bio_list;

	raw_spin_lock_irq(&dump_bio_lock);
	list_add_tail(&bio_list->list, &dump_bio_list_head);
	raw_spin_unlock_irq(&dump_bio_lock);

	if ((rw & RW_MASK) == WRITE) {
		bio_set_pages_dirty(bio);
	}

	submit_bio(rw, bio);

	return 0;
}

static int
submit_cur_mapped_bio(struct bio *bio, int rw)
{
	u64 start_block;
	e2k_size_t bio_size;
	int error;

	if (dump_bio == NULL) {
		panic("submit_cur_mapped_bio() currennt bio is NULL\n");
	} else if (bio != NULL && bio != dump_bio) {
		panic("submit_cur_mapped_bio() passed bio 0x%p is not "
			"the currennt 0x%p\n", bio, dump_bio);
	} else if (bio == NULL) {
		bio = dump_bio;
	}
	DebugBIO("started for %d vectors, size 0x%x\n",
		bio->bi_vcnt, bio->bi_size);
	start_block = get_cntp_file_pos(bio->bi_size);
	if (start_block == 0) {
		printk("submit_cur_mapped_bio() control point file overflow\n");
		return -ENOSPC;
	}
	bio->bi_sector = CNTP_BLOCK_TO_SECTOR(start_block);
	bio_size = bio->bi_size;

	error = submit_the_mapped_bio(bio, rw);
	if (error) {
		DebugBIO("could not submit current "
			"bio, error %d\n", error);
		return error;
	}
	if ((rw & RW_MASK) == WRITE) {
		cntp_total_bytes_to_save += bio_size;
	} else {
		cntp_cur_pfns_to_read += (bio_size >> PAGE_SHIFT);
	}

	dump_bio = NULL;
	return 0;
}

static int
save_all_mapped_areas(void)
{
	int error;

	if (dump_bio == NULL) {
		DebugZ("mapped areas are empty\n");
		return 0;
	}
	error = submit_cur_mapped_bio(dump_bio, WRITE);
	if (error) {
		printk("save_all_mapped_areas() could not save on disk "
			"already mapped ateas, error %d\n",
			error);
		put_cur_mapped_bio(dump_bio);
	}
	return error;
}

static void
release_all_mapped_areas(void)
{
	if (dump_bio != NULL)
		put_cur_mapped_bio(dump_bio);
}

static inline int
alloc_tags_areas_page(void)
{
	cntp_cur_tags_page = alloc_pages(GFP_KERNEL | GFP_DMA,
							CNTP_TAGS_AREAS_ORDER);
	if (cntp_cur_tags_page == NULL) {
		printk("alloc_tags_areas_page() could not allocate "
			"memory for new page to save tags\n");
		return -ENOMEM;
	}
	cntp_cur_tags_areas = page_address(cntp_cur_tags_page);
	cur_tags_area_size = 0;
	cur_tags_area_offset = 0;
	total_alloc_pages += (1 << CNTP_TAGS_AREAS_ORDER);
	DebugAP("allocated new memory page #%d at 0x%p "
		"to save tags\n", total_alloc_pages, cntp_cur_tags_page);
	return 0;
}

static void
release_tags_areas(void)
{
	if (cntp_prev_tags_page != NULL) {
		__free_pages(cntp_prev_tags_page, CNTP_TAGS_AREAS_ORDER);
		total_free_pages += (1 << CNTP_TAGS_AREAS_ORDER);
		cntp_prev_tags_page = NULL;
		cntp_prev_tags_areas = NULL;
	}
	if (cntp_cur_tags_page != NULL) {
		__free_pages(cntp_cur_tags_page, CNTP_TAGS_AREAS_ORDER);
		total_free_pages += (1 << CNTP_TAGS_AREAS_ORDER);
		cntp_cur_tags_page = NULL;
		cntp_cur_tags_areas = NULL;
	}
}

static inline void
put_tags_areas_bio(struct bio *bio)
{
	if (dump_tags_areas_bio == NULL) {
		panic("put_tags_areas_bio() currennt bio is NULL\n");
	} else if (bio != dump_tags_areas_bio) {
		panic("put_tags_areas_bio() passed bio 0x%p is not currennt "
			"0x%p\n", bio, dump_bio);
	}
	put_the_mapped_bio(bio);
	dump_tags_areas_bio = NULL;
}

static void
release_tags_areas_and_bio(void)
{
	if (dump_tags_areas_bio != NULL)
		put_tags_areas_bio(dump_tags_areas_bio);
	release_tags_areas();
}

static void
release_read_tags_areas_and_bio(int error)
{
	if (dump_tags_areas_bio != NULL)
		put_tags_areas_bio(dump_tags_areas_bio);
	release_read_tags_areas(error);
}

static void
tags_areas_bio_endio(struct bio *bio, int err)
{
	unsigned int bytes_done = bio->bi_idx * PAGE_SIZE;

	if (bio->bi_size) {
		DebugTBIO("bio 0x%p was not done, bytes "
			"done 0x%x, rest 0x%x, err %d\n",
			bio, bytes_done, bio->bi_size, err);
		return;
	}
	if (cntp_bio_endio(bio, bytes_done, err) == 1)
		return;
	put_the_mapped_bio(bio);
	cntp_total_saved_tags += bytes_done;
}

static inline struct bio *
get_tags_areas_bio(int nr_pages)
{
	return get_the_bio_to_map(&dump_tags_areas_bio, nr_pages,
						tags_areas_bio_endio);
}

static int
submit_tags_areas_bio(struct bio *bio, int rw)
{
	u64 start_block;
	e2k_addr_t bio_size;
	int error;

	if (dump_tags_areas_bio == NULL) {
		panic("submit_tags_areas_bio() currennt bio is NULL\n");
	} else if (bio != NULL && bio != dump_tags_areas_bio) {
		panic("submit_tags_areas_bio() passed bio 0x%p is not "
			"the currennt 0x%p\n", bio, dump_tags_areas_bio);
	} else if (bio == NULL) {
		bio = dump_tags_areas_bio;
	}
	DebugTBIO("started for %d vectors, size 0x%x\n",
		bio->bi_vcnt, bio->bi_size);
	start_block = get_cntp_tags_file_pos(bio->bi_size);
	if (start_block == 0) {
		printk("submit_tags_areas_bio() control point file tags area overflow\n");
		return -ENOSPC;
	}
	bio->bi_sector = CNTP_BLOCK_TO_SECTOR(start_block);
	bio_size = bio->bi_size;

	error = submit_the_mapped_bio(bio, rw);
	if (error) {
		DebugTBIO("could not submit current "
			"bio, error %d\n", error);
		return error;
	}
	if ((rw & RW_MASK) == WRITE) {
		cntp_total_tags_to_save += bio_size;
	} else {
		cntp_tags_pfns_to_read += (bio_size >> PAGE_SHIFT);
	}

	dump_tags_areas_bio = NULL;
	return 0;
}

static int
map_tags_areas_to_bio(struct bio *bio, struct page *tags_page, int nr_pages)
{
	int i;

	DebugTBIO("started to map area from page 0x%p, "
		"0x%x pages\n", tags_page, nr_pages);
	for (i = 0; i < nr_pages; i ++) {
		int len;
		DebugTBIO("will add page 0x%p "
			"to bio structure\n", tags_page);
		len = bio_add_page(bio, tags_page, PAGE_SIZE, 0);
		if (len < PAGE_SIZE) {
			if (len > 0) {
				printk("map_tags_areas_to_bio() could not "
					"add full page to bio, only %d bytes "
					"was added\n", len);
				return -ENOMEM;
			}
			DebugTBIO("could not map "
				"tags areas page 0x%p\n", tags_page);
			break;
		}
		tags_page ++;
	}
	DebugTBIO("mapped %d tags pages\n", i);
	return i;
}

static int
save_tags_areas(struct page *tags_page, int len)
{
	struct bio *bio;
	int error;
	int nr_pages = PAGE_ALIGN(len) >> PAGE_SHIFT;
	int cur_pages;

	DebugZT("started to save tags areas page 0x%p, "
		"size 0x%x\n", tags_page, len);
	while (nr_pages) {
		DebugZT("will map to bio 0x%x pages from "
			"0x%p page\n", nr_pages, tags_page);
		bio = get_tags_areas_bio(nr_pages);
		if (bio == NULL) {
			printk("save_tags_areas() could not allocate "
				"bio structure\n");
			return -ENOMEM;
		}
		cur_pages = map_tags_areas_to_bio(bio, tags_page, nr_pages);
		if (cur_pages < 0) {
			printk("save_tags_areas() could not map tags area "
				"to bio structure, error %d\n", cur_pages);
			error = -ENOMEM;
			goto Error_end;
		} else {
			DebugZT("mapped tags area from page "
				"0x%p size 0x%x pages\n",
				tags_page, cur_pages);
		}
		nr_pages -= cur_pages;
		tags_page += cur_pages;
		cntp_total_tags_pfns_to_save += cur_pages;
		if (nr_pages >= 0) {
			error = submit_tags_areas_bio(bio, WRITE);
			if (error) {
				printk("save_tags_areas() could not "
					"start IO on mapped bio, error %d\n",
					error);
				goto Error_end;
			}
		}
	}
	return 0;
Error_end:
	put_tags_areas_bio(bio);
	return error;
}

static int
save_prev_tags_areas(void)
{
	int error;

	DebugZT("started to save previous tags areas "
		"from 0x%p, size 0x%x\n",
		cntp_prev_tags_areas, prev_tags_area_size);
	error = save_tags_areas(cntp_prev_tags_page, prev_tags_area_size);
	if (error) {
		DebugZT("could not save previous tags "
			"areas page, error %d\n", error);
	} else {
		cntp_prev_tags_page = NULL;
		cntp_prev_tags_areas = NULL;
	}
	return error;
}

static int
save_cur_tags_areas(void)
{
	int error;

	DebugZT("started to save current tags areas "
		"from 0x%p, size 0x%x\n",
		cntp_cur_tags_areas, cur_tags_area_size);
	error = save_tags_areas(cntp_cur_tags_page, cur_tags_area_size);
	if (error) {
		DebugZT("could not save current tags "
			"areas page, error %d\n", error);
	} else {
		cntp_cur_tags_page = NULL;
		cntp_cur_tags_areas = NULL;
	}
	return error;
}

static int
create_cur_tags_page(void)
{
	int error;

	if (cur_tags_area_size < CNTP_TAGS_AREAS_SIZE) {
		cntp_prev_tags_page = cntp_cur_tags_page;
		cntp_prev_tags_areas = cntp_cur_tags_areas;
		prev_tags_area_size = cur_tags_area_size;
		prev_tags_area_offset = cur_tags_area_offset;
		DebugZT("remember current page "
				"for tags areas as previous\n");
	} else {
		error = save_cur_tags_areas();
		if (error) {
			printk("create_cur_tags_page() could not save "
				"previous tags areas page, error %d\n",
				error);
			return error;
		}
		DebugZT("saved current tags areas "
			"page\n");
	}
	error = alloc_tags_areas_page();
	if (error) {
		printk("create_cur_tags_page() could not allocate "
			"memory for new page to save tags\n");
		return error;
	}
	return 0;
}

static u8 *
get_cur_tags_area(void)
{
	u8 *tags_area;
	int error;

	if (cur_tags_area_offset >= CNTP_TAGS_AREAS_SIZE) {
		DebugTR("current page for tags areas "
			"is full, allocate new\n");
		error = create_cur_tags_page();
		if (error) {
			printk("get_cur_tags_area() could not allocate page "
				"for tags areas\n");
			return NULL;
		}
	}
	tags_area = &cntp_cur_tags_areas[cur_tags_area_offset];
	DebugTR("tags area from 0x%p offset 0x%x\n",
		tags_area, cur_tags_area_offset);
	return tags_area;
}

static int
put_cur_tags_area(int all_tags_is_numeric)
{
	int error;

	if (!all_tags_is_numeric) {
		DebugTR("area with offset 0x%x contains "
			"real tags of saved page\n", cur_tags_area_offset);
		cur_tags_area_offset += CNTP_1_PAGE_TAGS_AREA_SIZE;
		cur_tags_area_size = cur_tags_area_offset;
		cntp_real_tags_pfns ++;
		if (cntp_prev_tags_page != NULL) {
			error = save_prev_tags_areas();
			if (error) {
				DebugTR("could not save "
					"previous tags areas page, error %d\n",
					error);
				goto Error_end;
			}
			DebugTR("saved previous tags areas "
				"page\n");
		}
		return 0;
	} else if (cntp_prev_tags_page != NULL) {
		DebugTR("area with offset 0x%x contains "
			"only numeric tags, put bad tag to previous page at "
			"offset 0x%x\n",
			cur_tags_area_offset, prev_tags_area_size);
		cntp_prev_tags_areas[prev_tags_area_size] = ETAGBADQ;
		prev_tags_area_size ++;
		cntp_prev_numeric_tags_pfns ++;
		if (prev_tags_area_size >= CNTP_TAGS_AREAS_SIZE) {
			error = save_prev_tags_areas();
			if (error) {
				DebugTR("could not save "
					"previous tags areas page, error %d\n",
					error);
				goto Error_end;
			}
			DebugTR("saved previous tags areas "
				"page as full\n");
		}
		return 0;
	}

	DebugTR("area with offset 0x%x contains "
		"only numeric tags, put bad tag to current page at "
		"offset 0x%x\n",
		cur_tags_area_offset, cur_tags_area_size);
	cntp_cur_tags_areas[cur_tags_area_size] = ETAGBADQ;
	cur_tags_area_size ++;
	cntp_cur_numeric_tags_pfns ++;
	if (cur_tags_area_offset < cur_tags_area_size) {
		cur_tags_area_offset += CNTP_1_PAGE_TAGS_AREA_SIZE;
	}
	return 0;
Error_end:
	release_tags_areas();
	return error;
}

static int
save_all_tags_areas(void)
{
	int error;

	if (cntp_prev_tags_page != NULL) {
		error = save_prev_tags_areas();
		if (error) {
			DebugTR("could not save "
				"previous tags areas page, error %d\n",
				error);
			return error;
		}
	}
	if (cntp_cur_tags_page != NULL && cur_tags_area_size > 0) {
		error = save_cur_tags_areas();
		if (error) {
			DebugTR("could not save "
				"current tags areas page, error %d\n",
				error);
			return error;
		}
	}
	if (dump_tags_areas_bio == NULL) {
		DebugTR("mapped tags areas is empty\n");
		return 0;
	}
	error = submit_tags_areas_bio(dump_tags_areas_bio, WRITE);
	if (error) {
		printk("save_all_tags_areas() could not save on disk "
			"already mapped ateas, error %d\n",
			error);
		put_tags_areas_bio(dump_tags_areas_bio);
	}
	return error;
}

static int
init_tags_areas_state(void)
{
	int error;

	cntp_prev_tags_page = NULL;
	cntp_prev_tags_areas = NULL;
	error = alloc_tags_areas_page();
	if (error) {
		DebugTR("could not allocate memory "
			"to save tags, error %d\n", error);
	}
	return error;
}

static int
init_tags_pages_to_read(void)
{
	read_tags_pages_num = dump_cntp_desc->tags_size;
	read_cur_tags_page_index = 0;
	restore_cur_tags_page_index = 0;
	return 0;
}

static int
copy_page_and_tags(struct page *page, e2k_addr_t addr_from)
{
	u8 *tags_area;
	int all_tags_is_numeric;
	int error;

	tags_area = get_cur_tags_area();
	if (tags_area == NULL) {
		printk("copy_page_and_tags() could not allocate area to "
			"save tags of page\n");
		return -ENOMEM;
	}
	all_tags_is_numeric = do_save_mem_area_tags(addr_from,
					(e2k_addr_t)tags_area,
					PAGE_SIZE, 1,
					(e2k_addr_t)page_address(page));
	DebugTR("tags of the page 0x%lx "
		"was saved into 0x%p, all tags is numeric = %d\n",
		addr_from, tags_area, all_tags_is_numeric);
	error = put_cur_tags_area(all_tags_is_numeric);
	if (error) {
		printk("copy_page_and_tags() could not save current tags "
			"area, error %d\n", error);
	} else {
		page->private = addr_from;
	}
	return error;
}

static int
map_zone_area_to_bio(struct bio *bio, e2k_addr_t start_addr, int nr_pages)
{
	struct page *page = NULL;
	e2k_addr_t cur_addr = start_addr;
	int error = 0;
	int i;

	DebugZBIO("started to map area from addr 0x%lx, "
		"0x%x pages\n", start_addr, nr_pages);
	for (i = 0; i < nr_pages; i ++) {
		int len;
		page = alloc_page(GFP_KERNEL | GFP_DMA);
		if (page == NULL) {
			printk("map_zone_area_to_bio() could not "
				"allocate page\n");
			error = -ENOMEM;
			goto Error_end;
		}
		total_alloc_pages ++;
		DebugAP("allocated page #%d "
			"at 0x%p\n", total_alloc_pages, page);
		len = bio_add_page(bio, page, PAGE_SIZE, 0);
		if (len < PAGE_SIZE) {
			if (len > 0) {
				DebugZBIO("could not "
					"add full page to bio, only %d bytes "
					"was added\n", len);
				goto Tags_error_end;
			}
			DebugZBIO("could not map "
				"zone phys page from 0x%lx\n", cur_addr);
			__free_page(page);
			total_free_pages ++;
			break;
		}
		error = copy_page_and_tags(page, cur_addr);
		if (error) {
			printk("map_zone_area_to_bio() could not copy data "
				"with tags, error %d\n", error);
			goto Tags_error_end;
		}
		DebugZBIO("copied zone phys page 0x%lx "
			"to page 0x%p\n", cur_addr, page);
		cur_addr += PAGE_SIZE;
	}
	DebugZBIO("mapped %d pages\n", i);
	return i;
Error_end:
	if (page) {
		__free_page(page);
		total_free_pages ++;
	}
Tags_error_end:
	return error;
}

static int
save_zone_area_on_disk(struct zone *zone, int cntp_to_save,
			e2k_pfn_t start_pfn, e2k_pfn_t end_pfn)
{
	e2k_pfn_t zone_start_pfn;
	e2k_addr_t start_addr;
	e2k_addr_t end_addr;
	int nr_pages;
	e2k_addr_t cur_addr;
	int cur_pages;
	struct bio *bio;
	int error;

	zone_start_pfn = zone->zone_start_pfn;
	start_addr = (zone_start_pfn + start_pfn);
	start_addr <<= PAGE_SHIFT;
	end_addr = (zone_start_pfn + end_pfn);
	end_addr <<= PAGE_SHIFT;
	DebugZ("started to save area from addr 0x%lx "
		"to 0x%lx\n", start_addr, end_addr);
	start_addr = (e2k_addr_t)__va(start_addr);
	end_addr = (e2k_addr_t)__va(end_addr);

	nr_pages = (end_pfn - start_pfn);
	cur_addr = start_addr;
	while (nr_pages) {
		DebugZA("will map 0x%x pages from "
			"start addr 0x%lx\n", nr_pages, cur_addr);
		bio = get_cur_bio_to_map(nr_pages);
		if (bio == NULL) {
			printk("save_zone_area_on_disk() could not allocate "
				"bio structure\n");
			return -ENOMEM;
		}
		cur_pages = map_zone_area_to_bio(bio, cur_addr, nr_pages);
		if (cur_pages < 0) {
			printk("save_zone_area_on_disk() could not map %d "
				"for bio structure, error %d\n", nr_pages, cur_pages);
			error = -ENOMEM;
			goto Error_end;
		} else {
			DebugZA("mapped area from "
				"0x%lx size 0x%x pages\n",
				cur_addr, cur_pages);
		}
		nr_pages -= cur_pages;
		cur_addr += (cur_pages * PAGE_SIZE);
		if (nr_pages >= 0) {
			error = submit_cur_mapped_bio(bio, WRITE);
			if (error) {
				printk("save_zone_area_on_disk() could not "
					"start IO on mapped bio, error %d\n",
					error);
				goto Error_end;
			}
		}
	}
	return 0;
Error_end:
	put_cur_mapped_bio(bio);
	return error;
}

static int
save_zone_on_disk(struct zone *zone, int cntp_to_save, pfn_area_t *hole_areas)
{
	e2k_pfn_t zone_start_pfn;
	e2k_pfn_t zone_end_pfn;
	e2k_pfn_t start_pfn;
	e2k_pfn_t end_pfn;
	e2k_pfn_t cur_pfn;
	pfn_area_t *cur_hole;
	int areas = 0;
	int error;

	zone_start_pfn = zone->zone_start_pfn;
	zone_end_pfn = zone->spanned_pages;
	DebugZ("started for zone from pfn 0x%x "
		"to 0x%x\n", zone_start_pfn, zone_start_pfn + zone_end_pfn);
	cur_pfn = 0;
	cur_hole = hole_areas;
	while (cur_pfn < zone_end_pfn) {
		DebugZA("current pfn 0x%x, hole 0x%p\n",
			cur_pfn, cur_hole);
		if (cur_hole == NULL) {
			start_pfn = cur_pfn;
			end_pfn = zone_end_pfn;
			cur_pfn = zone_end_pfn;
			DebugZA("none more holes\n");
		} else if (cur_pfn < cur_hole->start) {
			start_pfn = cur_pfn;
			end_pfn = cur_hole->start;
			cur_pfn = end_pfn + cur_hole->size;
			DebugZA("hole from 0x%x "
				"to 0x%x > current area from 0x%x\n",
				end_pfn, cur_pfn, start_pfn);
			cur_hole = cur_hole->next;
			DebugZA("switch to next "
				"hole 0x%p\n", cur_hole);
		} else {
			cur_pfn = cur_hole->start + cur_hole->size;
			DebugZA("hole from 0x%x "
				"to 0x%x <= current area, jump hole\n",
				cur_hole->start, cur_pfn);
			cur_hole = cur_hole->next;
			DebugZA("switch to next "
				"hole 0x%p\n", cur_hole);
			continue;
		}
		DebugZA("will save zone area from 0x%x "
			"to 0x%x\n", start_pfn, end_pfn);
		cntp_total_pfns_to_save += (end_pfn - start_pfn);
		error = add_cntp_table_entry(start_pfn + zone_start_pfn,
						end_pfn + zone_start_pfn);
		if (error) {
			printk("save_zone_on_disk() could not add new area "
				"from 0x%x to 0x%x in the control point areas "
				"table, error %d\n",
				start_pfn + zone_start_pfn,
				end_pfn + zone_start_pfn, error);
			return error;
		}
		error = save_zone_area_on_disk(zone, cntp_to_save,
				start_pfn, end_pfn);
		if (error) {
			printk("save_zone_on_disk() could not save zone "
				"area from 0x%x to 0x%x, error %d\n",
				start_pfn, end_pfn, error);
			return error;
		}
		areas ++;
	}
	DebugZ("saved zone memory areas num %d, "
		"total pfns 0x%lx\n", areas, cntp_total_pfns_to_save);
	return 0;
}

static int
save_cntp_zone_memory(struct zone *zone, int cntp_to_save)
{
	pfn_area_t *hole_areas;
	int error;

	DebugZ("started for zone %s cnt point #%d\n",
		zone->name, cntp_to_save);
	error = get_zone_nosave_areas(zone);
	if (error) {
		printk("save_cntp_zone_memory() : could not create no save "
			"areas list, error %d\n", error);
		return error;
	}
	error = get_zone_free_areas(zone);
	if (error) {
		printk("save_cntp_zone_memory() : could not create free areas "
			"list, error %d\n", error);
		return error;
	}
	hole_areas = link_zone_hole_areas();
	if (hole_areas == NULL) {
		DebugZ("none hole areas in the zone\n");
		return 0;
	}
	error = save_zone_on_disk(zone, cntp_to_save, hole_areas);
	if (error) {
		printk("save_cntp_zone_memory() : could not save zone memory "
			"on disk, error %d\n", error);
	}
	return error;
}

static void
free_cntp_table_bio_buffer(struct bio *bio)
{
	struct page *page = bio->bi_io_vec[0].bv_page;

	free_cntp_table_buffer(page_address(page));
	DebugBIO("freed control point areas "
		"table 0x%p, sector 0x%lx\n",
		page_address(page), bio->bi_sector);
}

static void
cntp_table_bio_endio(struct bio *bio, int err)
{
	unsigned int bytes_done = bio->bi_idx * PAGE_SIZE;

	if (bio->bi_size) {
		printk("cntp_table_bio_endio() bio 0x%p was not done, bytes "
			"done 0x%x, rest 0x%x, err %d\n",
			bio, bytes_done, bio->bi_size, err);
		return;
	}
	if (cntp_bio_endio(bio, bytes_done, err) == 1)
		return;
	free_cntp_table_bio_buffer(bio);
	bio_put(bio);
}

static void
cntp_table_bio_read_endio(struct bio *bio, int err)
{
	unsigned int bytes_done = bio->bi_idx * PAGE_SIZE;
	struct page *page;

	if (bio->bi_size) {
		printk("cntp_table_bio_read_endio() bio 0x%p was not done, "
			"bytes done 0x%x, rest 0x%x, err %d\n",
			bio, bytes_done, bio->bi_size, err);
		return;
	}
	if (cntp_bio_endio(bio, bytes_done, err) == 1)
		return;
	page = bio->bi_io_vec[0].bv_page;
	if (PageError(page)) {
		ClearPageUptodate(page);
		DebugBIO("IO failed : clear  "
			"page 0x%p uptodate flag\n", page);
	} else {
		SetPageUptodate(page);
	}
	unlock_page(page);
	bio_put(bio);
}

static struct bio *
get_cntp_table_bio(cntp_area_t *table, u64 file_pos, e2k_size_t len,
			bio_end_io_t end_io)
{
	int nr_pages = PAGE_ALIGN(len) >> PAGE_SHIFT;
	struct bio *bio;
	e2k_addr_t table_page;
	int i;

	bio = bio_alloc(GFP_KERNEL, nr_pages);
	if (bio == NULL) {
		DebugBIO("could not allocate "
			"bio structure\n");
		return NULL;
	}
	bio->bi_bdev = dump_bdev;
	bio->bi_sector = CNTP_BLOCK_TO_SECTOR(file_pos);
	bio->bi_end_io = end_io;
	table_page = (e2k_addr_t)table;
	for (i = 0; i < nr_pages; i ++) {
		struct page *page;
		int size;
		page = virt_to_page(table_page);
		size = bio_add_page(bio, page, PAGE_SIZE, 0);
		if (size < PAGE_SIZE) {
			DebugBIO("could not "
				"add full page to bio, only %d bytes "
				"was added\n", size);
			goto Error_end;
		}
		table_page += PAGE_SIZE;
	}
	DebugBIO("allocated new bio structure "
		"for areas table, sector 0x%lx\n",
		bio->bi_sector);
	return bio;
Error_end:
	bio_put(bio);
	return NULL;
}

static inline int
submit_cntp_table_bio(struct bio *bio, int rw)
{
	int error;

	error = submit_the_mapped_bio(bio, rw);
	if (error) {
		printk("submit_cntp_table_bio() could not submit areas "
			"table bio, error %d\n", error);
	}
	return error;
}

static int
write_cntp_table_buffer(cntp_area_t *table, u64 file_pos, e2k_size_t len)
{
	struct bio *bio;
	int error;

	bio = get_cntp_table_bio(table, file_pos, len, cntp_table_bio_endio);
	if (bio == NULL) {
		printk("write_cntp_table_buffer() could not allocate "
			"bio structure\n");
		return -ENOMEM;
	}
	error = submit_cntp_table_bio(bio, WRITE);
	if (error) {
		printk("write_cntp_table_buffer() could not "
			"start IO on mapped bio, error %d\n",
			error);
		bio_put(bio);
	}
	return error;
}

static int
read_cntp_table_buffer(cntp_area_t *table, u64 file_pos, e2k_size_t len)
{
	struct bio *bio;
	int error;
	struct page *page;

	page = virt_to_page(table);
	lock_page(page);
	ClearPageUptodate(page);

	bio = get_cntp_table_bio(table, file_pos, len,
					cntp_table_bio_read_endio);
	if (bio == NULL) {
		unlock_page(page);
		printk("read_cntp_table_buffer() could not allocate "
			"bio structure\n");
		return -ENOMEM;
	}
	error = submit_cntp_table_bio(bio, READ_SYNC);
	if (error) {
		unlock_page(page);
		printk("read_cntp_table_buffer() could not "
			"start IO on mapped bio, error %d\n",
			error);
		bio_put(bio);
		return error;
	}

	DebugBIO("will wait on locked table buffer\n");
	wait_on_page_locked(page);

	if (!PageUptodate(page) || PageError(page)) {
		printk("read_cntp_table_buffer() IO failed\n");
		error = -EIO;
	} else {
		DebugBIO("table buffer reading "
			"completed\n");
	}
	return error;
}


static inline cntp_area_t *
alloc_cntp_table_buffer(void)
{
	cntp_area_t *table;

	table = (cntp_area_t *) __get_free_pages(GFP_KERNEL | GFP_DMA,
						CNTP_AREAS_TABLE_ORDER);
	if (table == NULL) {
		DebugTB("could not allocate "
			"memory for control point areas table buffer\n");
	}
	total_alloc_pages ++;
	DebugAP("allocated page #%d at 0x%p\n",
		total_alloc_pages, table);
	return table;
}

static int
save_cntp_table_buffer(void)
{
	int error;

	error = write_cntp_table_buffer(cntp_table_buffer, cntp_table_file_pos,
			cntp_table_cur_entry * sizeof (cntp_area_t));
	if (error) {
		printk("save_cntp_table_buffer() could not write to file "
			"control point areas table, error %d\n", error);
		return error;
	}
	cntp_table_total_entries += cntp_table_cur_entry;
	cntp_table_buffer = NULL;
	DebugTB("saved in the dump file control "
		"point areas table, total table entries %d\n",
		cntp_table_total_entries);
	return 0;
}

static inline void
reset_cntp_table_buffer(void)
{
	cntp_table_cur_entry = 0;
	cntp_table_file_pos = get_cntp_file_pos(CNTP_AREAS_TABLE_SIZE);
	if (cntp_table_file_pos == 0) {
		printk("reset_cntp_table_buffer() got cntp_table_file_pos == 0\n");
	}
	DebugTB("reset to empty state "
		"dump file block %ld\n", cntp_table_file_pos);
}

static inline int
create_cntp_table_buffer(int restore_flag)
{
	int error;

	if (cntp_table_buffer != NULL) {
		if (restore_flag) {
			panic("create_cntp_table_buffer() table buffer is "
				"not already empty\n");
		}
		error = save_all_mapped_areas();
		if (error) {
			printk("create_cntp_table_buffer() could not save "
				"on disk already mapped areas, error %d\n",
				error);
			return error;
		}
		error = save_cntp_table_buffer();
		if (error) {
			printk("create_cntp_table_buffer() could not save "
				"current control point areas table buffer, "
				"error %d\n", error);
			return error;
		}
	}
	cntp_table_buffer = alloc_cntp_table_buffer();
	if (cntp_table_buffer == NULL) {
		printk("create_cntp_table_buffer() could not allocate "
			"memory for control point areas table buffer\n");
		return -ENOMEM;
	}
	DebugTB("allocated new empty "
		"table buffer at 0x%p\n",
		cntp_table_buffer);
	reset_cntp_table_buffer();
	return 0;
}

static inline int
init_cntp_table_state(int restore_flag)
{
	int error;

	cntp_table_buffer = NULL;
	if (restore_flag) {
		cntp_table_total_entries = dump_cntp_desc->areas_num;
		DebugTB("total areas to restore "
			"0x%x\n", cntp_table_total_entries);
	} else {
		cntp_table_total_entries = 0;
	}
	error = create_cntp_table_buffer(restore_flag);
	if (error) {
		printk("init_cntp_table_state() could not create control "
			"point areas table root buffer, error %d\n", error);
	}
	return error;
}

static void
close_cntp_table_state(void)
{
	if (cntp_table_buffer != NULL)
		free_cntp_table_buffer(cntp_table_buffer);
	cntp_table_buffer = NULL;
}

static int
add_cntp_table_entry(e2k_pfn_t start_pfn, e2k_pfn_t end_pfn)
{
	cntp_area_t *cur_table_entry;
	int error;

	if (cntp_table_cur_entry >= CNTP_AREAS_TABLE_ENTRIES) {
		DebugTB("control point areas table "
			"is full, save current mapped areas and create "
			"new buffer\n");
		error = create_cntp_table_buffer(0);
		if (error) {
			printk("add_cntp_table_entry() could not create "
				"new control point areas table, error %d\n",
				error);
			return error;
		}
	}
	cur_table_entry = &cntp_table_buffer[cntp_table_cur_entry];
	cur_table_entry->start = start_pfn;
	cur_table_entry->size = end_pfn - start_pfn;
	DebugR("added new area #%d, start from pfn "
		"0x%x to 0x%x\n",
		cntp_table_cur_entry, start_pfn, end_pfn);
	cntp_table_cur_entry ++;
	return 0;
}

static void
wait_for_saving_completion(void)
{
	wait_for_all_bio_end();
}

static int
complete_cntp_memory_saving(void)
{
	int error;
	error = save_all_mapped_areas();
	if (error) {
		printk("complete_cntp_memory_saving() could not save "
			"on disk remaining mapped areas, error %d\n",
			error);
		return error;
	}
	error = save_all_tags_areas();
	if (error) {
		printk("complete_cntp_memory_saving() could not save "
			"on disk remaining tags areas, error %d\n",
			error);
		return error;
	}
	error = save_cntp_table_buffer();
	if (error) {
		printk("complete_cntp_memory_saving() could not save "
			"last control point areas table buffer, "
			"error %d\n", error);
		return error;
	}
	wait_for_saving_completion();
	return 0;
}

static void
cntp_dump_stat_info(int error)
{
	if (dump_save_area.end > dump_save_area.start) {
		DebugCP("memory area from 0x%lx "
			"to 0x%lx was saved\n",
			dump_save_area.start, dump_save_area.end);
		dump_save_area.start = 0;
		dump_save_area.end = 0;
	}
	DebugSI("total stored on disk pages "
		"0x%lx from to save 0x%lx, mapped to IO 0x%lx, error %d\n",
		cntp_total_saved_bytes >> PAGE_SHIFT,
		cntp_total_pfns_to_save,
		cntp_total_bytes_to_save >> PAGE_SHIFT,
		error);
	DebugSI("total stored on disk tags "
		"0x%lx from to save 0x%lx pfns, mapped to IO 0x%lx\n",
		cntp_total_saved_tags, cntp_total_tags_pfns_to_save,
		cntp_total_tags_to_save);
	DebugSI("total pages 0x%lx : real tags "
		"0x%lx, numeric tags: prev 0x%lx cur 0x%lx\n",
		cntp_real_tags_pfns + cntp_prev_numeric_tags_pfns +
						cntp_cur_numeric_tags_pfns,
		cntp_real_tags_pfns, cntp_prev_numeric_tags_pfns,
		cntp_cur_numeric_tags_pfns);
	DebugSI("control point areas table "
		"contains %d saved entries + %d to save\n",
		cntp_table_total_entries, cntp_table_cur_entry);
	DebugSI("total number pages allocated "
		"0x%x free 0x%x\n",
		total_alloc_pages, total_free_pages);

}

static int
save_cntp_memory(int cntp_to_save)
{
	struct zone *zone;
	int error = 0;
	int zones = 0;

	DebugR("started for control point #%d\n",
		cntp_to_save);

	error = init_cntp_file_state(0, cntp_to_save);
	if (error) {
		printk("save_cntp_memory() : could not set dump file "
			"info to save control point, error %d\n", error);
		goto Error_end;
	}
	error = init_cntp_memory_state(cntp_to_save);
	if (error) {
		printk("save_cntp_memory() : could not create zone memory "
			"areas list, error %d\n", error);
		goto Error_end;
	}
	error = init_tags_areas_state();
	if (error) {
		printk("save_cntp_memory() : could not create initial state "
			"to save tags, error %d\n", error);
		goto Error_end;
	}
	error = init_cntp_table_state(0);
	if (error) {
		printk("save_cntp_memory() : could not create root buffer "
			"of memory areas table, error %d\n", error);
		goto Error_end;
	}
	for_each_cntp_zone (zone) {
		if (is_highmem(zone)) {
			panic("save_cntp_memory() detected high memory zone "
				"from 0x%lx size 0x%lx on node %d\n",
				zone->zone_start_pfn << PAGE_SHIFT,
				zone->spanned_pages << PAGE_SHIFT,
				zone->zone_pgdat->node_id);
		}
		DebugR("will save memory zone from 0x%lx "
			"size 0x%lx on node %d\n",
			zone->zone_start_pfn << PAGE_SHIFT,
			zone->spanned_pages << PAGE_SHIFT,
			zone->zone_pgdat->node_id);
		if (zone->spanned_pages == 0) {
			DebugR("zone is empty\n");
			continue;
		}
		if (zones != 0) {
			reset_zone_hole_areas();
		}
		init_zone_hole_areas_hash(zone);
		error = save_cntp_zone_memory(zone, cntp_to_save);
		if (error) {
			printk("save_cntp_memory() : save_cntp_zone_memory() "
				"failed, error %d\n", error);
			goto Error_end;
		}
		zones ++;
	}
	error = complete_cntp_memory_saving();
	if (error) {
		printk("save_cntp_memory() : could not save remaining "
			"areas or table, error %d\n", error);
		goto Error_end;
	}
	set_cntp_file_state(cntp_to_save);
	writeback_dump_header();
	set_bootblock_cntp_disk_valid(bootblock_phys, cntp_to_save);
	disk_cnt_points ++;
	write_bootblock_disk_cnt_points(bootblock_phys, disk_cnt_points);

Error_end:
	if (error) {
		wait_for_saving_completion();
	}
	release_tags_areas_and_bio();
	close_cntp_table_state();
	release_all_mapped_areas();
	delete_zone_hole_areas();
	cntp_dump_stat_info(error);
	return error;
}

static int
save_control_point(int cntp_to_save)
{
	int ret = 0;

	DebugR("started for control point #%d\n",
		cntp_to_save);
	ret = map_control_point_memory(SAVE_CNTP_FLAG, cntp_to_save);
	if (ret != 0) {
		DebugR(""
			"failed with error %d\n", ret);
		goto Error;
	}
	ret = save_cntp_memory(cntp_to_save);
	if (ret != 0) {
		DebugR(""
			"failed with error %d\n", ret);
		goto Error;
	}
Error:
	unmap_control_point_memory(cntp_to_save);
	return ret;
}

int
save_control_points(void)
{
	int cntp;
	int cntp_to_save;
	int ret;

	DebugR("started, memory CNTPs %d, on disk "
		"%d\n", mem_cnt_points, disk_cnt_points);
	if (cnt_points_created && mem_cnt_points <= disk_cnt_points &&
		disk_cnt_points >= cnt_points_num && !recreate_cnt_points) {
		DebugR("nothing to save\n");
		return 0;
	}
	ret = open_dump_device();
	if (ret) {
		DebugR("open of control points "
			"device failed with error %d\n", ret);
		return ret;
	}
	if (!cnt_points_created && mem_cnt_points == 0) {
		ret = create_cntp_dump_header();
		if (ret) {
			DebugR("creation of control "
				"points header failed with error %d\n", ret);
			goto out;
		}
		ret = writeback_dump_header();
		if (ret) {
			DebugR("writing of control "
				"points header failed with error %d\n", ret);
			goto out;
		}
	}
	cntp_to_save = cur_cnt_point;
	for (cntp = 0; cntp < get_cnt_points_num(cnt_points_num) - 1; cntp ++) {
		cntp_to_save ++;
		if (cntp_to_save >= get_cnt_points_num(cnt_points_num))
			cntp_to_save = 0;
		if (!is_bootblock_cntp_mem_valid(bootblock_phys, cntp_to_save)) {
			DebugR("control point #%d in "
				"the memory is not ready for the time being\n",
				cntp_to_save);
			continue;
		}
		if (is_bootblock_cntp_disk_valid(bootblock_phys, cntp_to_save)) {
			DebugR("control point #%d on "
				"the disk is just ready\n",
				cntp_to_save);
			continue;
		}
		ret = save_control_point(cntp_to_save);
		if (ret != 0) {
			DebugR("failed to save "
				"control point #%d\n",
				cntp_to_save);
			goto out;
		}
	}
	if (mem_cnt_points > disk_cnt_points) {
		panic("save_control_points() could not save all control "
			"points: in the memory %d on the disk only %d\n",
			mem_cnt_points, disk_cnt_points);
	}
out:
	close_dump_device();
	return ret;
}

static inline e2k_addr_t
get_cur_read_area_addr(void)
{
	return (e2k_addr_t)read_cur_area_start << PAGE_SHIFT;
}

static inline int
set_next_read_area(void)
{
	read_cur_entry ++;
	if (read_cur_entry >= cntp_table_areas_num) {
		DebugR("all 0x%x areas were read\n",
			cntp_table_areas_num);
		return 1;
	}
	read_cur_area_start = cntp_table_buffer[read_cur_entry].start;
	read_cur_area_end = read_cur_area_start +
				cntp_table_buffer[read_cur_entry].size;
	DebugR("current area to read set to new entry "
		"#%d, from pfn 0x%x to 0x%x\n",
		read_cur_entry, read_cur_area_start, read_cur_area_end);
	return 0;
}

static inline int
put_cur_read_area_addr(void)
{
	int eop = 0;

	read_cur_area_start ++;
	if (read_cur_area_start >= read_cur_area_end) {
		eop = set_next_read_area();
	}
	return eop;
}

static int
map_read_area_to_bio(struct bio *bio, int nr_pages, int *eop)
{
	struct page *page;
	e2k_addr_t cur_addr;
	int error = 0;
	int i;

	DebugBIO("started to map read area for "
		"0x%x pages\n", nr_pages);
	for (i = 0; i < nr_pages; i ++) {
		int len;
		page = NULL;
		cur_addr = get_cur_read_area_addr();
		page = alloc_page(GFP_KERNEL | GFP_DMA);
		if (page == NULL) {
			printk("map_read_area_to_bio() could not "
				"allocate page\n");
			error = -ENOMEM;
			goto Error_end;
		}
		total_alloc_pages ++;
		DebugAP("allocated page #%d "
			"at 0x%p\n", total_alloc_pages, page);
		page->private = cur_addr;
		len = bio_add_page(bio, page, PAGE_SIZE, 0);
		if (len < PAGE_SIZE) {
			if (len > 0) {
				DebugBIO("could not "
					"add full page to bio, only %d bytes "
					"was added\n", len);
				goto Error_end;
			}
			DebugBIO("could not map "
				"page for area addr 0x%lx\n", cur_addr);
			__free_page(page);
			total_free_pages ++;
			break;
		}
		*eop = put_cur_read_area_addr();
		DebugRBIO("mapped to BIO page for "
			"read area addr 0x%lx\n", cur_addr);
		if (*eop) {
			DebugR("end of pages to read "
				"was reached\n");
			break;
		}
	}
	DebugBIO("mapped %d pages\n", i);
	return i;
Error_end:
	if (page) {
		__free_page(page);
		total_free_pages ++;
	}
	return error;
}

static int
get_cur_pfns_to_read(void)
{
	int pfns_in_io;		/* pfns in IO in the progress */
	int pfns_in_memory;	/* ready and waiting for restore */
	int pfns_in_waiting;	/* total pfns number in IO and ready */
				/* and waiting to restore */
	int pfns_to_read = 0;

	DebugRA("pfns to read 0x%lx, to restore "
		"0x%lx, restored 0x%lx\n",
		cntp_cur_pfns_to_read, cntp_cur_pfns_to_restore,
		cntp_cur_pfns_restored);
	pfns_in_io = cntp_cur_pfns_to_read - cntp_cur_pfns_to_restore;
	pfns_in_memory = cntp_cur_pfns_to_restore - cntp_cur_pfns_restored;
	pfns_in_waiting = pfns_in_io + pfns_in_memory;
	DebugRA("pfns in IO in the progress 0x%x, "
		"ready and waiting for restore 0x%x, "
		"total pfns number in IO and ready 0x%x\n",
		pfns_in_io, pfns_in_memory, pfns_in_waiting);
	if (pfns_in_waiting < MIN_PFNS_STOCK_TO_RESTORE) {
		pfns_to_read = MAX_PFNS_STOCK_TO_RESTORE - pfns_in_waiting;
		DebugRA("total pfns number in IO and "
			"ready to restore 0x%x < min value 0x%x "
			"read new 0x%x pages\n",
			pfns_in_waiting, MIN_PFNS_STOCK_TO_RESTORE,
			pfns_to_read);
	} else {
		pfns_to_read = 0;
		DebugRA("total pfns number in IO and "
			"ready to restore 0x%x is now enough\n",
			pfns_in_waiting);
	}
	return pfns_to_read;
}

static int
read_cur_cntp_area(void)
{
	struct bio *bio;
	int nr_pages;
	int read_size = 0;
	int cur_pages;
	int eop = 0;
	int error = 0;

	read_pfns_times ++;
	nr_pages = get_cur_pfns_to_read();
	if (nr_pages < 0) {
		DebugRA("could take current number of "
			"pages to read, error %d\n", nr_pages);
		return nr_pages;
	} else if (nr_pages == 0) {
		DebugRA("should not read any new pages "
			"so pages to restore are enough\n");
		pfns_enough_times ++;
		return nr_pages;
	}
	DebugRA("should read 0x%x new pages\n",
		nr_pages);
	while (nr_pages) {
		DebugRA("will read next 0x%x pages\n",
			nr_pages);
		bio = get_cur_bio_to_read_area(nr_pages);
		if (bio == NULL) {
			printk("read_cur_cntp_area() could not allocate "
				"bio structure\n");
			return -ENOMEM;
		}
		cur_pages = map_read_area_to_bio(bio, nr_pages, &eop);
		if (cur_pages < 0) {
			printk("read_cur_cntp_area() could not map read area "
				"to bio structure, error %d\n", cur_pages);
			error = -ENOMEM;
			goto Error_end;
		} else {
			DebugRA("mapped to BIO read area "
				"for 0x%x pages\n", cur_pages);
		}
		nr_pages -= cur_pages;
		read_size += cur_pages;
		error = submit_cur_mapped_bio(bio, READ);
		if (error) {
			printk("read_cur_cntp_area() could not start IO "
				"on mapped bio, error %d\n", error);
			goto Error_end;
		}
		if (eop) {
			DebugRA("reached end of pages "
				"to read\n");
			break;
		}
	}
	return read_size;
Error_end:
	put_cur_mapped_bio(bio);
	return error;
}

static inline int
get_cur_read_tags_index(void)
{
	return read_cur_tags_page_index;
}

static inline int
put_cur_read_tags_index(void)
{
	int eop = 0;

	read_cur_tags_page_index ++;
	if (read_cur_tags_page_index >= read_tags_pages_num) {
		eop = 1;
	}
	return eop;
}

static int
map_read_tags_to_bio(struct bio *bio, int nr_pages, int *eop)
{
	struct page *page;
	int cur_index;
	int error = 0;
	int i;

	DebugTBIO("started to map read tags for "
		"0x%x pages\n", nr_pages);
	for (i = 0; i < nr_pages; i ++) {
		int len;
		page = NULL;
		cur_index = get_cur_read_tags_index();
		page = alloc_page(GFP_KERNEL | GFP_DMA);
		if (page == NULL) {
			printk("map_read_tags_to_bio() could not "
				"allocate page\n");
			error = -ENOMEM;
			goto Error_end;
		}
		total_alloc_pages ++;
		DebugAP("allocated page #%d "
			"at 0x%p\n", total_alloc_pages, page);
		page->private = cur_index;
		len = bio_add_page(bio, page, PAGE_SIZE, 0);
		if (len < PAGE_SIZE) {
			if (len > 0) {
				DebugTBIO("could not "
					"add full page to bio, only %d bytes "
					"was added\n", len);
				goto Error_end;
			}
			DebugTBIO("could not map tags "
				"page for index #0x%x\n", cur_index);
			__free_page(page);
			total_free_pages ++;
			break;
		}
		*eop = put_cur_read_tags_index();
		DebugTBIO("mapped to BIO tags page to "
			"read #0x%x\n", cur_index);
		if (*eop) {
			DebugTBIO("end of tags pages to "
				"read was reached\n");
			i ++;
			break;
		}
	}
	DebugTBIO("mapped %d tags pages\n", i);
	return i;
Error_end:
	if (page) {
		__free_page(page);
		total_free_pages ++;
	}
	return error;
}

static int
get_tags_pfns_to_read(void)
{
	int pfns_in_io;		/* pfns in IO in the progress */
	int pfns_in_memory;	/* ready and waiting for restore */
	int pfns_in_waiting;	/* total pfns number in IO and ready */
				/* and waiting to restore */
	int pfns_to_read = 0;

	DebugRT("tags pfns to read 0x%lx, to restore "
		"0x%lx, restored 0x%lx\n",
		cntp_tags_pfns_to_read, cntp_tags_pfns_to_restore,
		cntp_tags_pfns_restored);
	pfns_in_io = cntp_tags_pfns_to_read - cntp_tags_pfns_to_restore;
	pfns_in_memory = cntp_tags_pfns_to_restore - cntp_tags_pfns_restored;
	pfns_in_waiting = pfns_in_io + pfns_in_memory;
	DebugRT("pfns in IO in the progress 0x%x, "
		"ready and waiting for restore 0x%x, "
		"total pfns number in IO and ready 0x%x\n",
		pfns_in_io, pfns_in_memory, pfns_in_waiting);
	if (pfns_in_waiting < MIN_TAGS_PFNS_STOCK_TO_RESTORE) {
		pfns_to_read = MAX_TAGS_PFNS_STOCK_TO_RESTORE - pfns_in_waiting;
		DebugRT("total pfns number in IO and "
			"ready to restore 0x%x < min value 0x%x, "
			"read new 0x%x pages\n",
			pfns_in_waiting, MIN_TAGS_PFNS_STOCK_TO_RESTORE,
			pfns_to_read);
	} else {
		pfns_to_read = 0;
		DebugRT("total pfns number in IO and "
			"ready to restore 0x%x is now enough\n",
			pfns_in_waiting);
	}
	return pfns_to_read;
}

static int
read_cntp_tags_pages(void)
{
	struct bio *bio;
	int nr_pages;
	int read_size = 0;
	int cur_pages;
	int eop = 0;
	int error = 0;

	read_tags_pfns_times ++;
	nr_pages = get_tags_pfns_to_read();
	if (nr_pages < 0) {
		DebugRT("could not get current number "
			"of pages to read, error %d\n", nr_pages);
		return nr_pages;
	} else if (nr_pages == 0) {
		DebugRT("should not read any new "
			"pages so tags pages are enough\n");
		tags_pfns_enough_times ++;
		return nr_pages;
	}
	DebugRT("should read 0x%x new pages\n",
		nr_pages);
	while (nr_pages) {
		DebugRT("will read next 0x%x pages\n",
			nr_pages);
		bio = get_cur_bio_to_read_tags(nr_pages);
		if (bio == NULL) {
			printk("read_cntp_tags_pages() could not allocate "
				"bio structure\n");
			return -ENOMEM;
		}
		cur_pages = map_read_tags_to_bio(bio, nr_pages, &eop);
		if (cur_pages < 0) {
			printk("read_cntp_tags_pages() could not map tags "
				"pages to bio structure, error %d\n",
				cur_pages);
			error = -ENOMEM;
			goto Error_end;
		} else {
			DebugRT("mapped to BIO "
				"0x%x tags pages\n", cur_pages);
		}
		nr_pages -= cur_pages;
		read_size += cur_pages;
		error = submit_tags_areas_bio(bio, READ);
		if (error) {
			printk("read_cntp_tags_pages() could not start IO "
				"on mapped bio, error %d\n", error);
			goto Error_end;
		}
		if (eop) {
			DebugRT("reached end of tags "
				"pages to read\n");
			break;
		}
	}
	return read_size;
Error_end:
	put_tags_areas_bio(bio);
	return error;
}

static inline e2k_addr_t
get_cur_addr_to_restore(void)
{
	return (e2k_addr_t)restore_cur_area_start << PAGE_SHIFT;
}

static inline int
set_next_restore_area(void)
{
	restore_cur_entry ++;
	if (restore_cur_entry >= cntp_table_areas_num) {
		DebugR("all 0x%x areas were restored\n",
			cntp_table_areas_num);
		return 1;
	}
	restore_cur_area_start = cntp_table_buffer[restore_cur_entry].start;
	restore_cur_area_end = restore_cur_area_start +
				cntp_table_buffer[restore_cur_entry].size;
	DebugR("current area to restore set to new "
		"entry #%d, from pfn 0x%x to 0x%x\n",
		restore_cur_entry, restore_cur_area_start,
		restore_cur_area_end);
	return 0;
}

static inline int
put_cur_addr_to_restore(void)
{
	int eop = 0;

	restore_cur_area_start ++;
	if (restore_cur_area_start >= restore_cur_area_end) {
		eop = set_next_restore_area();
	}
	return eop;
}

static inline struct page *
get_page_to_restore(e2k_addr_t addr)
{
	struct page *cur_page = NULL;
	int i = 0;

	raw_spin_lock_irq(&read_page_lock);
	list_for_each_entry(cur_page, &read_page_list_head, lru) {
		i ++;
		if ((e2k_addr_t)cur_page->private == addr) {
			raw_spin_unlock_irq(&read_page_lock);
			DebugRMA("page found "
				"for addr 0x%lx, times %d\n",
				addr, i);
			return cur_page;
		}
	}
	raw_spin_unlock_irq(&read_page_lock);
	return NULL;
}

static inline void
put_page_to_restore(struct page *page)
{
	count_restore_area_page(page);
	raw_spin_lock_irq(&read_page_lock);
	list_del(&page->lru);
	raw_spin_unlock_irq(&read_page_lock);
	__free_page(page);
	total_free_pages ++;
}

static inline void
release_pages_to_restore(int error)
{
	struct page *cur_page = NULL;
	int i = 0;

	while (!list_empty(&read_page_list_head)) {
		cur_page = list_entry(read_page_list_head.next,
							struct page, lru);
		put_page_to_restore(cur_page);
		i ++;
	}
	DebugRMA("released %d read pages to "
		"restore\n", i);
	if (error == 0 && i > 0) {
		panic("release_pages_to_restore() not all pages to restore "
			"are exhausted\n");
	}
}

static void
release_pages_and_bio_to_restore(int error)
{
	release_all_mapped_areas();
	release_pages_to_restore(error);
}

static inline struct page *
get_tags_page_to_restore(int index)
{
	struct page *cur_page = NULL;
	int i = 0;

	raw_spin_lock_irq(&read_tags_page_lock);
	list_for_each_entry(cur_page, &read_tags_page_list_head, lru) {
		i ++;
		if ((e2k_addr_t)cur_page->private == index) {
			raw_spin_unlock_irq(&read_tags_page_lock);
			DebugTR("page found "
				"for index 0x%x, times %d\n",
				index, i);
			return cur_page;
		}
	}
	raw_spin_unlock_irq(&read_tags_page_lock);
	return NULL;
}

static inline void
put_tags_page_to_restore(struct page *page)
{
	page->private = 0;
	raw_spin_lock_irq(&read_tags_page_lock);
	list_del(&page->lru);
	raw_spin_unlock_irq(&read_tags_page_lock);
	__free_page(page);
	total_free_pages ++;
}

static inline int
is_restore_tags_page_exhausted(void)
{
	return restore_cur_tags_page_index >= read_tags_pages_num;
}

static inline int
get_cur_restore_tags_index(void)
{
	if (is_restore_tags_page_exhausted()) {
		panic("get_cur_restore_tags_index() all tags page are "
			"exhausted\n");
	}
	return restore_cur_tags_page_index;
}

static inline int
put_cur_restore_tags_index(void)
{
	int eop = 0;

	restore_cur_tags_page_index ++;
	if (is_restore_tags_page_exhausted()) {
		eop = 1;
	}
	return eop;
}

static inline u8 *
get_cur_tags_areas_page(void)
{
	struct page *cur_page = NULL;
	int index;

	if (cntp_cur_tags_areas == NULL) {
		index = get_cur_restore_tags_index();
		cur_page = get_tags_page_to_restore(index);
		if (cur_page == NULL) {
			DebugTR("could not get page "
				"for tags areas: page is not yet ready\n");
		} else {
			DebugTR("get new page "
				"for tags areas, index %d\n", index);
			cntp_cur_tags_areas = page_address(cur_page);
			cur_tags_area_offset = 0;
		}
	}
	return cntp_cur_tags_areas;
}

static inline int
do_put_cur_tags_areas_page(void)
{
	int eop = 0;

	put_tags_page_to_restore(virt_to_page(cntp_cur_tags_areas));
	cntp_cur_tags_areas = NULL;
	eop = put_cur_restore_tags_index();
	DebugTR("current tags areas "
		"page is exhausted\n");
	if (eop) {
		DebugTR("all tags areas "
			"are exhausted\n");
	}
	cntp_tags_pfns_restored ++;
	return eop;
}

static inline void
put_cur_tags_areas_page(void)
{
	if (cur_tags_area_offset >= CNTP_TAGS_AREAS_SIZE) {
		(void) do_put_cur_tags_areas_page();
	}
}

static inline void
release_read_tags_pages(int error)
{
	struct page *cur_page = NULL;
	int i = 0;

	while (!list_empty(&read_tags_page_list_head)) {
		cur_page = list_entry(read_tags_page_list_head.next,
							struct page, lru);
		put_tags_page_to_restore(cur_page);
		i ++;
	}
	DebugTR("released %d read tags pages\n", i);
	if (error == 0 && i > 0) {
		panic("release_read_tags_pages() not all tags pages "
			"are exhausted\n");
	}
}

static void
release_read_tags_areas(int error)
{
	int eop = 0;

	if (cntp_cur_tags_areas != NULL) {
		eop = do_put_cur_tags_areas_page();
		DebugTR("current tags areas "
			"page is closed\n");
		if (error == 0 && !eop) {
			panic("release_read_tags_areas() not all tags pages "
				"are exhausted\n");
		}
	} else if (error == 0) {
		if (!is_restore_tags_page_exhausted()) {
			panic("release_read_tags_areas() not all tags pages "
				"are exhausted\n");
		}
	}
	release_read_tags_pages(error);
}

static u8 *
get_cur_restore_tags_area(int *all_tags_is_numeric)
{
	u8 *tags_area;

	if (get_cur_tags_areas_page() == NULL) {
		DebugTR("could not get current "
			"page of tags areas\n");
		return NULL;
	}
	tags_area = &cntp_cur_tags_areas[cur_tags_area_offset];
	if (tags_area[0] == ETAGBADQ) {
		*all_tags_is_numeric = 1;
		DebugTR("tags area is all numeric "
			"for offset 0x%x\n", cur_tags_area_offset);
	} else {
		*all_tags_is_numeric = 0;
		DebugTR("real tags area from 0x%p "
			"offset 0x%x\n", tags_area, cur_tags_area_offset);
	}
	return tags_area;
}

static inline void
put_cur_restore_tags_area(int all_tags_is_numeric)
{
	if (!all_tags_is_numeric) {
		DebugTR("area with offset 0x%x "
			"contains real tags of saved page\n",
			cur_tags_area_offset);
		cur_tags_area_offset += CNTP_1_PAGE_TAGS_AREA_SIZE;
		cntp_real_tags_pfns ++;
	} else {
		DebugTR("area with offset 0x%x "
			"contains only numeric tags\n",
			cur_tags_area_offset);
		cur_tags_area_offset ++;
		cntp_cur_numeric_tags_pfns ++;
		if (cur_tags_area_offset < CNTP_TAGS_AREAS_SIZE) {
			if (cntp_cur_tags_areas[cur_tags_area_offset] !=
								ETAGBADQ) {
				cur_tags_area_offset = ALIGN_MASK_DOWN(
					cur_tags_area_offset,
					(CNTP_1_PAGE_TAGS_AREA_SIZE - 1));
				DebugTR("next area "
					"is not numeric, set offset to 0x%x\n",
					cur_tags_area_offset);
			}
		}
	}
	put_cur_tags_areas_page();
}

static int
restore_page_and_tags(struct page *page, e2k_addr_t addr_to)
{
	u8 *tags_area;
	int all_tags_is_numeric = 0;

	tags_area = get_cur_restore_tags_area(&all_tags_is_numeric);
	if (tags_area == NULL) {
		DebugTR("tags page is not yet read, "
			"should wait for it\n");
		return 0;
	}
	if (all_tags_is_numeric) {
		DebugTR("tags of the page "
			"is numeric, copy to 0x%lx\n", addr_to);
		memcpy((void *)addr_to, page_address(page), PAGE_SIZE);
	} else {
		DebugTR("tags of the page restored "
			"from 0x%p and copy to 0x%lx\n",
			tags_area, addr_to);
		do_restore_mem_area_tags((e2k_addr_t)page_address(page),
			(e2k_addr_t)tags_area, PAGE_SIZE, 1, addr_to);
	}
	put_cur_restore_tags_area(all_tags_is_numeric);
	return 1;
}

static int
restore_cur_memory_page(int *eop)
{
	struct page *page;
	e2k_addr_t cur_addr;
	int error;

	cur_addr = get_cur_addr_to_restore();
	DebugRMA("started to restore addr 0x%lx\n",
		cur_addr);
	page = get_page_to_restore(cur_addr);
	if (page == NULL) {
		DebugRMA("page for addr 0x%lx "
			"is not yet read\n", cur_addr);
		not_read_area_pfn_times ++;
		return 0;
	}
	error = restore_page_and_tags(page, (e2k_addr_t)__va(cur_addr));
	if (error < 0) {
		DebugRMA("could not restore page "
			"for addr 0x%lx, error %d\n", cur_addr, error);
		put_page_to_restore(page);
		return error;
	} else if (error == 0) {
		DebugRMA("tags for addr 0x%lx "
			"is not yet read\n", cur_addr);
		not_read_tags_pfn_times ++;
		return 0;
	}
	put_page_to_restore(page);
	*eop = put_cur_addr_to_restore();
	cntp_cur_pfns_restored ++;
	return 1;
}

static int
get_cur_pfns_to_restore(void)
{
	int pfns_to_restore;

	DebugRMA("pfns to read 0x%lx, to restore "
		"0x%lx, restored 0x%lx\n",
		cntp_cur_pfns_to_read, cntp_cur_pfns_to_restore,
		cntp_cur_pfns_restored);
	if (read_cur_entry < cntp_table_areas_num) {
		pfns_to_restore = MAX_PFNS_NUM_TO_RESTORE;
	} else {
		pfns_to_restore = cntp_cur_pfns_to_read -
					cntp_cur_pfns_restored;
	}
	return pfns_to_restore;
}

static int
restore_cur_memory_area(void)
{
	int nr_pages;
	int restored_size = 0;
	int size;
	int i;
	int eop = 0;
	int error = 0;

	restore_pfns_times ++;
	nr_pages = get_cur_pfns_to_restore();
	if (nr_pages < 0) {
		DebugRMA("could not get current "
			"number of pages to restore, error %d\n", nr_pages);
		return nr_pages;
	} else if (nr_pages == 0) {
		DebugRMA("should not restore any "
			"page, so nothing pages are ready\n");
		no_ready_pfns_times ++;
		return nr_pages;
	}
	DebugRMA("should restore 0x%x pages\n",
		nr_pages);
	for (i = 0; i < nr_pages; i ++) {
		size = restore_cur_memory_page(&eop);
		if (size < 0) {
			error = size;
			DebugRMA("could not restore "
				"current page, error %d\n", error);
			return error;
		} else if (size == 0) {
			DebugRMA("current page is "
				"not ready to restore\n");
			not_read_pfn_times ++;
			return 0;
		} else {
			DebugRMA("restored "
				"current page\n");
		}
		restored_size += size;
		if (eop) {
			DebugRMA("all pages are "
				"restored\n");
			break;
		}
	}
	if (first_restored_area) {
		first_restored_area = 0;
		not_read_first_pfn_times = not_read_pfn_times;
	}
	return restored_size;
}

static int
restore_cntp_table_memory(int areas_num)
{
	int read_size;
	int read_tags_size;
	int restore_size;
	int error = 0;

	cntp_table_areas_num = areas_num;
	read_cur_entry = 0;
	read_cur_area_start = cntp_table_buffer[read_cur_entry].start;
	read_cur_area_end = read_cur_area_start +
				cntp_table_buffer[read_cur_entry].size;
	DebugR("currenr area to read and restore "
		"#%d, from pfn 0x%x to 0x%x\n",
		read_cur_entry, read_cur_area_start, read_cur_area_end);
	restore_cur_entry = read_cur_entry;
	restore_cur_area_start = read_cur_area_start;
	restore_cur_area_end = read_cur_area_end;
	while (restore_cur_entry < areas_num) {
		if (read_cur_tags_page_index < read_tags_pages_num) {
			read_tags_size = read_cntp_tags_pages();
			if (read_tags_size < 0) {
				error = read_tags_size;
				DebugR("could "
					"not read current tags areas page "
					"to restore, error %d\n",
					error);
				break;
			}
		} else {
			read_tags_size = 0;
		}
		if (read_cur_entry < cntp_table_areas_num) {
			read_size = read_cur_cntp_area();
			if (read_size < 0) {
				error = read_size;
				DebugR("could "
					"not read current area to restore, "
					"error %d\n", error);
				break;
			}
		} else {
			read_size = 0;
		}
		restore_size = restore_cur_memory_area();
		if (restore_size < 0) {
			error = restore_size;
			DebugRMA("could not "
				"restore current memory area, error %d\n",
				error);
			break;
		} else if (restore_size == 0) {
			DebugRMA("nothing to "
				"restore, waiting for ready pages\n");
			yield();
		} else if (read_size != 0) {
			DebugRMA("some pages "
				"should be read, starting IO\n");
			yield();
		}
	}
	return error;
}

static void
wait_for_restoring_completion(void)
{
	wait_for_all_bio_end();
}

static void
cntp_dump_restore_stat_info(int error)
{
	if (dump_read_area.end > dump_read_area.start) {
		DebugCP("area from 0x%lx "
			"to 0x%lx was read\n",
			dump_read_area.start, dump_read_area.end);
		dump_read_area.start = 0;
		dump_read_area.end = 0;
	}
	if (dump_restore_area.end > dump_restore_area.start) {
		DebugCP("area from 0x%lx "
			"to 0x%lx was restored\n",
			dump_restore_area.start, dump_restore_area.end);
		dump_restore_area.start = 0;
		dump_restore_area.end = 0;
	}
	DebugSI("total restored pages "
		"0x%lx from to restore 0x%lx, mapped to read from disk 0x%lx, "
		"error %d\n",
		cntp_cur_pfns_restored,
		cntp_cur_pfns_to_restore,
		cntp_cur_pfns_to_read,
		error);
	DebugSI("total restored tags pages "
		"0x%lx from to restore 0x%lx, mapped to read from disk 0x%lx\n",
		cntp_tags_pfns_restored, cntp_tags_pfns_to_restore,
		cntp_tags_pfns_to_read);
	DebugSI("total restored tags pages "
		"0x%lx : real tags 0x%lx, numeric tags 0x%lx\n",
		cntp_real_tags_pfns + cntp_cur_numeric_tags_pfns,
		cntp_real_tags_pfns, cntp_cur_numeric_tags_pfns);
	DebugSI("control point areas table "
		"contains %d saved entries, restored %d entries\n",
		cntp_table_total_entries, cntp_table_cur_entry);
	DebugSI("total number pages allocated "
		"0x%x free 0x%x\n",
		total_alloc_pages, total_free_pages);
	DebugSI("total times to restore %d "
		"no any ready pfns %d, pfn was not yet read %d "
		"(before first restore %d) : not read "
		"page %d, not read tags %d\n",
		restore_pfns_times, no_ready_pfns_times, not_read_pfn_times,
		not_read_first_pfn_times,
		not_read_area_pfn_times, not_read_tags_pfn_times);
	DebugSI("total times to read %d, "
		"pfns was yet enough %d\n",
		read_pfns_times, pfns_enough_times);
	DebugSI("total times to read tags %d, "
		"pfns was yet enough %d\n",
		read_tags_pfns_times, tags_pfns_enough_times);
}

static int
restore_cntp_memory(int cntp_to_restore)
{
	int entries_num;
	int buffers_num;
	int buffer_entries;
	int buffer;
	int error = 0;

	DebugR("started for control point #%d\n",
		cntp_to_restore);

	error = init_cntp_file_state(1, cntp_to_restore);
	if (error) {
		printk("restore_cntp_memory() : could not set dump file "
			"info to restore control point, error %d\n", error);
		return error;
	}
	error = init_tags_pages_to_read();
	if (error) {
		printk("restore_cntp_memory() : could not create initial state "
			"to restore tags, error %d\n", error);
		return error;
	}
	error = init_cntp_table_state(1);
	if (error) {
		printk("restore_cntp_memory() : could not create root buffer "
			"of memory areas table, error %d\n", error);
		return error;
	}
	entries_num = cntp_table_total_entries;
	buffers_num = (entries_num + (CNTP_AREAS_TABLE_ENTRIES - 1)) /
						CNTP_AREAS_TABLE_ENTRIES;
	for (buffer = 0; buffer < buffers_num; buffer ++) {
		buffer_entries = entries_num;
		if (buffer_entries > CNTP_AREAS_TABLE_ENTRIES)
			buffer_entries = CNTP_AREAS_TABLE_ENTRIES;
		DebugR("will restore memory from "
			"areas table buffer #%d, entries %d\n",
			buffer, buffer_entries);
		if (buffer != 0) {
			reset_cntp_table_buffer();
		}
		error = read_cntp_table_buffer(cntp_table_buffer,
				cntp_table_file_pos,
				buffer_entries * sizeof (cntp_area_t));
		if (error) {
			DebugR("could not read "
				"control point table buffer, error %d\n",
				error);
			break;
		}
		error = restore_cntp_table_memory(buffer_entries);
		if (error) {
			DebugR("could not restore "
				"memory state, error %d\n",
				error);
			break;
		}
		entries_num -= buffer_entries;
		cntp_table_cur_entry += buffer_entries;
	}
	if (error) {
		DebugR("could not restore "
			"remaining areas or table, error %d\n", error);
		wait_for_restoring_completion();
	} else {
		set_bootblock_cntp_mem_valid(bootblock_phys, cntp_to_restore);
		mem_cnt_points ++;
		write_bootblock_mem_cnt_points(bootblock_phys, mem_cnt_points);
	}

	release_read_tags_areas_and_bio(error);
	release_pages_and_bio_to_restore(error);
	close_cntp_table_state();
	cntp_dump_restore_stat_info(error);
	return error;
}

static int
restore_control_point(int cntp_to_restore)
{
	int ret = 0;

	DebugR("started for control point #%d\n",
		cntp_to_restore);
	ret = map_control_point_memory(RESTORE_CNTP_FLAG, cntp_to_restore);
	if (ret != 0) {
		DebugR("map_control_point_memory() "
			"failed with error %d\n", ret);
		goto Error;
	}
	ret = restore_cntp_memory(cntp_to_restore);
	if (ret != 0) {
		DebugR("restore_cntp_memory() "
			"failed with error %d\n", ret);
		goto Error;
	}
Error:
	unmap_control_point_memory(cntp_to_restore);
	return ret;
}

int
restore_control_points(void)
{
	int cntp;
	int cntp_to_restore;
	int ret;

	DebugR("started, memory CNTPs %d, on disk "
		"%d\n", mem_cnt_points, disk_cnt_points);
	if (mem_cnt_points + 1 >= disk_cnt_points) {
		DebugR("nothing to restore\n");
		return 0;
	}
	ret = open_dump_device();
	if (ret) {
		DebugR("open of control points "
			"device failed with error %d\n", ret);
		return ret;
	}
	cntp_to_restore = cur_cnt_point;
	for (cntp = 0; cntp < cnt_points_num - 1; cntp ++) {
		cntp_to_restore ++;
		if (cntp_to_restore >= cnt_points_num)
			cntp_to_restore = 0;
		if (is_bootblock_cntp_mem_valid(bootblock_phys,
						cntp_to_restore)) {
			DebugR("control point #%d "
				"in the memory is already valid\n",
				cntp_to_restore);
			continue;
		}
		if (!is_bootblock_cntp_disk_valid(bootblock_phys,
							cntp_to_restore)) {
			DebugR("control point #%d "
				"on the disk is not yet ready\n",
				cntp_to_restore);
			continue;
		}
		ret = restore_control_point(cntp_to_restore);
		if (ret != 0) {
			DebugR("failed to restore "
				"control point #%d\n",
				cntp_to_restore);
			goto out;
		}
		set_next_control_point();
	}
	if (mem_cnt_points < disk_cnt_points - 1) {
		panic("restore_control_points() could not restore all control "
			"points: on the disk %d, in the memory only %d \n",
			disk_cnt_points, mem_cnt_points);
	}
out:
	close_dump_device();
	return ret;
}

static void
init_cntp_desc(cntp_desk_t *cntp_desc, u64 start, u64 size)
{
	u64 tags_size = size / (DATA_PAGES_PER_TAGS_PAGE(PAGE_SIZE) * 2);
	cntp_desc->start = start;
	cntp_desc->max_size = size - tags_size;
	cntp_desc->size = 0;
	cntp_desc->tags_start = start + cntp_desc->max_size;
	cntp_desc->tags_max_size = tags_size;
	cntp_desc->tags_size = 0;
	cntp_desc->areas_num = 0;
	cntp_desc->valid = 0;
}

#endif /* CONFIG_CNT_POINTS_NUM != 0 */

#if (CONFIG_CNT_POINTS_NUM < 2)
void
start_dump_analyze(void)
{
	struct task_struct *task;
	int error;

	if (dump_analyze_opt && dump_analyze_mode) {
	        cntp_kernel_base =
			read_bootblock_cntp_kernel_base(bootblock_phys, 0);
		
		if (IS_MACHINE_E3M) {
			pr_alert("Starting dump analyzer '%s'...\n",
				dump_analyze_cmd);
			run_init_process(dump_analyze_cmd);
			pr_alert("Starting dump analyzer failed. Printing cntp stacks.\n");
		}

		error = map_control_point_memory(SAVE_CNTP_FLAG, 0);
		if (error != 0)
			panic("start_dump_analyze(): map_control_point_memory() failed with error %d\n",
				error);

		task = cntp_va(&init_task, 0);
		do {
			/*
			 * TODO: it is too old version of print_chain_stack(),
			 * should be updated.
			 */
			cntp_print_chain_stack(task);

			task = list_entry(cntp_va(task->tasks.next, 0),
					struct task_struct, tasks);
		} while (task != cntp_va(&init_task, 0));

		panic("start_dump_analyze(): failed to start dump analyzer '%s' or machine is not E3M\n",
			dump_analyze_cmd);
	}
}
#endif	/* CONFIG_CNT_POINTS_NUM < 2 */

#if CONFIG_CNT_POINTS_NUM == 1
void
save_dump_for_quick_restart(void)
{

	if (((dump_analyze_opt && !dump_analyze_mode) || !dump_analyze_opt) && 
		cur_cnt_point == 1) {
		int error;
		printk("Control point for quick restart is being created, it "
			"can take much time ...\n");
		if (error = restart_system(CREATE_CNTP_REST_TYPE, 0)) {
			/*
			 * TODO: Switch on using the whole memory and continue
			 * to work without possibility of quick restart
			 */
			panic("save_dump_for_quick_restart(): could not "
				"create control point for quick restart, "
				"because restart_system failed, error %d\n",
				error);
		}
	}
}
#endif /* CONFIG_CNT_POINTS_NUM == 1 */

#if CONFIG_CNT_POINTS_NUM || defined(CONFIG_EMERGENCY_DUMP)
static int
create_dump_header(void)
{
	dump_desc_t *info = &dump_header->info;

	DebugCP("started for dump file header "
		"on %s\n", dump_specialfile);
	DebugCP("Expected cntp file size 0x%ld Mb\n",
		((dump_filesize - core_area_max_size) /
					cnt_points_num - 1) << PAGE_SHIFT);
	info->cntp_valid = 0;
	info->core_valid = 0;
	info->file_size = dump_filesize;
	if (dump_filesize < 1 + core_area_max_size +
					cntp_area_max_size * cnt_points_num) {
		printk(KERN_WARNING "Dump file size on %s shorter than "
			"need : %ld Mb < %ld (=1 + %ld(core pg) + %ld"
			"(cntp_ar pg) * %d(cntN))\n",
			dump_specialfile,
			(dump_filesize << PAGE_SHIFT) / (1024 * 1024),
			((1 + core_area_max_size +
				cntp_area_max_size *
					cnt_points_num) << PAGE_SHIFT) /
								(1024 * 1024),
			(core_area_max_size << PAGE_SHIFT) / (1024 * 1024),
			(cntp_area_max_size << PAGE_SHIFT) / (1024 * 1024),
			cnt_points_num);
		return -EINVAL;
	}
	info->core_offset = CORE_DUMP_AREA_OFFSET;
	info->core_size = core_area_max_size;
	info->cntp_offset = info->core_offset + info->core_size;
	info->cntp_size = dump_filesize - info->cntp_offset;
	info->signature = DUMP_HEADER_SIGNATURE;
	dump_header->magic = DUMP_HEADER_MAGIC;

	printk(KERN_INFO "Created dump file %ldK on %s, pages 0x%lx\n",
		dump_filesize << (PAGE_SHIFT - 10), dump_specialfile,
		dump_filesize);
	return 0;
}

static int
create_cntp_dump_header(void)
{
	dump_desc_t *info = &dump_header->info;
#if CONFIG_CNT_POINTS_NUM
	cntp_dump_t *cntp = &dump_header->cntp;
	u64 start;
	int i;
#endif /* CONFIG_CNT_POINTS_NUM */
	int error;

	DebugCP("started for dump file header "
		"on %s\n", dump_specialfile);
	if (info->signature != DUMP_HEADER_SIGNATURE ||
		dump_header->magic != DUMP_HEADER_MAGIC) {
		if (info->signature != DUMP_HEADER_SIGNATURE &&
			dump_header->magic != DUMP_HEADER_MAGIC) {
			DebugCP("dump file header "
				"was not yet created\n");
		} else {
			printk(KERN_WARNING "Dump header block "
				"is corrupted on %s\n", dump_specialfile);
		}
		error = create_dump_header();
		if (error) {
			DebugCP("could not create "
				"dump file header, error %d\n", error);
			return error;
		}
	} else if (info->cntp_valid || info->core_valid) {
		DebugCP("detected old control "
			"points or dump file header: create new\n");
	} else {
		DebugCP("did not detect any "
			"control points or dump file header: create first\n");
	}
#ifdef	CONFIG_EMERGENCY_DUMP
	info->core_valid = 1;
	printk(KERN_INFO "Created core dump area on %s offset 0x%lx "
		"size 0x%lx pages\n",
		dump_specialfile, info->core_offset, info->core_size);
#endif	/* CONFIG_EMERGENCY_DUMP */
#if CONFIG_CNT_POINTS_NUM
	if (cntp_area_max_size == 0) {
		printk(KERN_WARNING "Control points area size on %s "
			"is 0\n", dump_specialfile);
		printk(KERN_WARNING "Please pass control point area "
			"max size by cntpmax=XXX (Mgb) option "
			"in command line string\n");
		return -EINVAL;
	}
	if (info->cntp_size < cntp_area_max_size * cnt_points_num) {
		printk(KERN_WARNING "Control points area on %s "
			"shorter than need : 0x%lx < 0x%lx * %d\n",
			dump_specialfile,
			info->cntp_size,
			cntp_area_max_size, cnt_points_num);
		return -EINVAL;
	}
	cntp->offset = info->cntp_offset;
	cntp->max_cntps = cnt_points_num;
	cntp->count = 0;
	start = cntp->offset;
	for (i = 0; i < cnt_points_num; i ++) {
		init_cntp_desc(&cntp->cntps[i], start, cntp_area_max_size);
		DebugCP("control point #%d "
			"area offset 0x%lx size 0x%lx pages, tags area "
			"offset 0x%lx size 0x%lx\n",
			i, cntp->cntps[i].start, cntp->cntps[i].max_size,
			cntp->cntps[i].tags_start,
			cntp->cntps[i].tags_max_size);
		start += cntp_area_max_size;
	}
	cntp->size = start - cntp->offset;
	info->cntp_valid = 1;
	printk(KERN_INFO "Created control points area on %s offset 0x%lx "
		"size 0x%lx pages\n",
		dump_specialfile, cntp->offset, cntp->size);
#endif /* CONFIG_CNT_POINTS_NUM != 0 */
	return 0;
}
#endif /* CONFIG_CNT_POINTS_NUM != 0 || CONFIG_EMERGENCY_DUMP */

int
writeback_dump_header(void)
{
	struct page *page = virt_to_page(dump_header);
	int error;

	DebugCP("started for dump file header "
		"on %s\n", dump_specialfile);

	lock_page(page);

	set_page_dirty(page); /* force it to be written out */
	error = write_one_page(page, 1);
	DebugCP("write_one_page() returned "
		"error %d\n", error);

	return error;
}

int
open_dump_device(void)
{
	struct block_device *bdev = NULL;
	struct address_space *mapping;
	int error;
	struct page *page = NULL;
	struct inode *inode = NULL;
	int did_down = 0;
	int i;

	if (dump_specialfile == NULL ||
			dump_specialfile[0] == '\0') {
		printk("Special file does not define to dump, save and restore "
			"control points\n");
		printk("Please use cntpdev= or dumpdev = option in command "
			"line string\n");
		return -EINVAL;
	}
	DebugCP("started for special file %s\n",
		dump_specialfile);
	if (dump_file != NULL) {
		DebugCP("device is open already\n");
		return 0;
	}
	DebugCP("dump_specialfile of special file is %s\n", dump_specialfile);
	dump_file = filp_open(dump_specialfile, O_RDWR | O_LARGEFILE, 0);
	error = PTR_ERR(dump_file);
	if (IS_ERR(dump_file)) {
		dump_file = NULL;
		DebugCP("could not open file, "
			"error %d\n", error);
		goto bad_dump;
	}

	DebugCP("open special file\n");
	mapping = dump_file->f_mapping;
	inode = mapping->host;

	for (i = 0; i < nr_swapfiles; i++) {
		struct swap_info_struct *q = swap_info[i];

		if (!q->swap_file)
			continue;
		if (mapping == q->swap_file->f_mapping) {
			printk("Dump special file %s is busy as "
				"swap device\n", dump_specialfile);
			error = -EBUSY;
			goto bad_dump;
		}
	}

	error = -EINVAL;
	if (S_ISBLK(inode->i_mode)) {
		bdev = I_BDEV(inode);
		DebugCP("special file is blk device\n");
		error = blkdev_get(
				bdev,
				FMODE_READ | FMODE_WRITE,
				open_dump_device);
		if (error < 0) {
			bdev = NULL;
			error = -EINVAL;
			DebugCP("could not claim "
				"blk device, error %d\n", error);
			goto bad_dump;
		}
		dump_old_block_size = block_size(bdev);
		error = set_blocksize(bdev, PAGE_SIZE);
		if (error < 0) {
			DebugCP("could not set block "
				"size of blk device, error %d\n", error);
			goto bad_dump;
		}
		dump_bdev = bdev;
	} else if (S_ISREG(inode->i_mode)) {
		dump_bdev = inode->i_sb->s_bdev;
		DebugCP("special file is regular file\n");
		mutex_lock(&inode->i_mutex);
		did_down = 1;
		if (IS_SWAPFILE(inode)) {
			error = -EBUSY;
			DebugCP("special file is "
				"swap regular file\n");
			goto bad_dump;
		}
	} else {
		DebugCP("special file is not blk device "
			"or regular file\n");
		goto bad_dump;
	}

	dump_filesize = i_size_read(inode) >> PAGE_SHIFT;
	dump_max_pages = bio_get_nr_vecs(dump_bdev);
	DebugCP("dump file 0x%lx pages, max vector size "
		"0x%lx pages\n", dump_filesize, dump_max_pages);

	/*
	 * Read the dump file header.
	 */
	if (!mapping->a_ops->readpage) {
		error = -EINVAL;
		DebugCP("special file has not "
			"readpage operation\n");
		goto bad_dump;
	}
	page = read_cache_page(mapping, 0,
			(filler_t *)mapping->a_ops->readpage, dump_file);
	if (IS_ERR(page)) {
		error = PTR_ERR(page);
		DebugCP("read from special file failed, "
			"error %d\n", error);
		goto bad_dump;
	}
	wait_on_page_locked(page);
	if (!PageUptodate(page)) {
		DebugCP("header page is not uptodate "
			"after read\n");
		goto bad_dump;
	}
	kmap(page);
	dump_header = page_address(page);

	error = 0;
	DebugCP("open dump file %ldK on %s\n",
		dump_filesize << (PAGE_SHIFT - 10), dump_specialfile);
	goto out;
bad_dump:
	if (bdev) {
		set_blocksize(bdev, dump_old_block_size);
		blkdev_put(bdev, FMODE_READ | FMODE_WRITE);
		dump_bdev = NULL;
	}
	if (dump_file) {
		filp_close(dump_file, NULL);
		dump_file = NULL;
	}
	if (page && !IS_ERR(page)) {
		kunmap(page);
		page_cache_release(page);
	}
	dump_header = NULL;
out:
	if (did_down) {
		if (!error)
			inode->i_flags |= S_SWAPFILE;
		mutex_unlock(&inode->i_mutex);
	}
	if (error) {
		printk(KERN_INFO "Could not open control points disk file "
			"on %s : error %d\n", dump_specialfile, error);
	}
	return error;
}

void
close_dump_device(void)
{
	struct inode *inode = NULL;

	DebugCP("started\n");
	if (dump_file == NULL) {
		DebugCP("file does not open\n");
		return;
	}
	inode = dump_file->f_mapping->host;
	if (S_ISBLK(inode->i_mode)) {
		set_blocksize(dump_bdev, dump_old_block_size);
		blkdev_put(dump_bdev, FMODE_READ | FMODE_WRITE);
	} else {
		mutex_lock(&inode->i_mutex);
		inode->i_flags &= ~S_SWAPFILE;
		mutex_unlock(&inode->i_mutex);
	}
	if (dump_header != NULL) {
		struct page *page = virt_to_page(dump_header);
		kunmap(page);
		page_cache_release(page);
	}
	dump_header = NULL;

	dump_bdev = NULL;
	filp_close(dump_file, NULL);
	dump_file = NULL;
	DebugCP("completed\n");
}

#ifdef	CONFIG_EMERGENCY_DUMP
static inline int
get_disk_num(struct gendisk *disk)
{
	unsigned int major;
	unsigned int minor;
	int ide_num;
	int disk_num;

	major = disk->major;
	minor = disk->first_minor;
	switch (major) {
		case IDE0_MAJOR: ide_num = 0; break;
		case IDE1_MAJOR: ide_num = 1; break;
		case IDE2_MAJOR: ide_num = 2; break;
		case IDE3_MAJOR: ide_num = 3; break;
		case IDE4_MAJOR: ide_num = 4; break;
		case IDE5_MAJOR: ide_num = 5; break;
		case IDE6_MAJOR: ide_num = 6; break;
		case IDE7_MAJOR: ide_num = 7; break;
		case IDE8_MAJOR: ide_num = 8; break;
		case IDE9_MAJOR: ide_num = 9; break;
		default:
			printk("get_disk_num() invalid IDE disk major %d\n",
				major);
			return -1;
	}
	disk_num = ide_num * MAX_DRIVES + (minor >> PARTN_BITS);
	return disk_num;
}

int
create_dump_point(void)
{
	struct gendisk *disk;
	int disk_num;
	unsigned long start_sector;
	int ret;

	DebugDUMP("started\n");
	ret = open_dump_device();
	if (ret) {
		DebugDUMP("open of coontrol points "
			"device failed with error %d\n", ret);
		return ret;
	}
	disk = dump_bdev->bd_disk;
	if (disk == NULL) {
		printk("Device or file to dump is not disk\n");
		return -ENODEV;
	}
	ret = create_cntp_dump_header();
	if (ret) {
		DebugDUMP("creation of dump file header "
			"failed with error %d\n", ret);
		goto out;
	}
	disk_num = get_disk_num(disk);
	start_sector = dump_bdev->bd_part->start_sect;
	start_sector += CORE_BLOCK_TO_SECTOR(dump_header->info.core_offset);
	dump_prepare(disk_num, start_sector);
	DebugDUMP("dump file is placed on disk #%d "
		"from sector %ld\n", disk_num, start_sector);
	ret = writeback_dump_header();
	if (ret) {
		DebugDUMP("writing of dump file "
			"header failed with error %d\n", ret);
		goto out;
	}
out:
	close_dump_device();
	return ret;
}
#else	/* ! CONFIG_EMERGENCY_DUMP */
int
create_dump_point(void)
{
	return 0;
}
#endif	/* CONFIG_EMERGENCY_DUMP */

static DECLARE_WAIT_QUEUE_HEAD(restartd_wait);
static int wait_flag = 0;

void
wake_up_restartd(void)
{
	DebugR("started on pid %d\n",
		current->pid);
	wait_flag = 1;
	wake_up(&restartd_wait);
	DebugR("returns\n");
}

static int
restartd(void *unused)
{
	int error;

	printk(KERN_INFO "RESTART daemon started\n");

	for ( ; ; ) {
		DebugR("will prepare to wait\n");
		wait_event_interruptible(restartd_wait, wait_flag != 0);
		wait_flag = 0;
		DebugR("activated after schedule()\n");
		switch (restart_goal) {
		case CREATE_REST_GOAL :
			error = do_create_control_point(1);
			if (error < 0) {
				DebugR("could not restart system, "
					"error %d\n", error);
			}
			break;
		case RECOVER_REST_GOAL :
			background_recover_system();
			break;
		default :
			panic("RESTART daemon invalid goal %d to do\n",
				restart_goal);
		}
		DebugR("finished restarting process\n");
	}
	return 0;
}

static int __init
restart_init(void)
{
	struct task_struct *task_to_restart = NULL, *restart_task;
	int cpu;

#if CONFIG_CNT_POINTS_NUM
	dump_bio_cachep = kmem_cache_create("dump_bio",
				sizeof(dump_bio_t), 0,
				SLAB_HWCACHE_ALIGN, NULL);
	if (!dump_bio_cachep)
		panic("Cannot create dump bio list structures SLAB cache");
#endif	/* CONFIG_CNT_POINTS_NUM != 0 */
	for_each_online_cpu(cpu) {
		task_to_restart = restart_task(cpu);
		if (task_to_restart == NULL) {
			task_to_restart = dup_task_struct(idle_task(cpu));
			if (task_to_restart == NULL) {
				panic("Could not create task structure to "
					"restart CPU #%d\n", cpu);
			}
			strlcpy(task_to_restart->comm, "restartidle",
					sizeof(task_to_restart->comm));
			restart_task(cpu) = task_to_restart;
		}
	}

	restart_task = kthread_run(&restartd, NULL, "cntp_restartd");
	if (IS_ERR(restart_task))
		pr_err("Failed to start RESTART daemon\n");

	return 0;
}

__initcall(restart_init);

