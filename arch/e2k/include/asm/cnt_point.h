/* $Id: cnt_point.h,v 1.3 2009/06/29 11:51:48 atic Exp $
 *
 * Recovery the system from control point.
 */

#ifndef _E2K_CNT_POINT_H
#define _E2K_CNT_POINT_H

#include <asm/types.h>
#include <asm/boot_recovery.h>
#include <asm/boot_flags.h>

/*
 * Core dump header on the disk
 * Total size of header should be one page of memory = one block on disk
 * Note that the first kilobyte is reserved for boot loader or
 * disk label stuff...
 * The following first bytes should contain signature and the last bytes
 * of header - magic value to indicate dump header itegrety
 * Other structures are aligned to have constant offset in the header
 * by adding zip areas in the structure end.
 */
#define	TOTAL_DUMP_HEADER_SIZE		PAGE_SIZE
#define	BOOTBITS_DUMP_HEADER_SIZE	0x400	/* offset 0x000 */
#define	DUMP_INFO_HEADER_SIZE		0x100	/* offset 0x400 */
#define	CORE_DUMP_HEADER_SIZE		0x500	/* offset 0x500 */
						/* offset 0xa00 - gap */
						/* offset 0xff8 - magic */

/*
 * Dump device and common dump state info
 * Dump file space layout:
 *	block	0			dump file header
 *	block	1			core dump area start
 *	---------------------------------
 *	| header |    core dump area	|
 *	---------------------------------
 *	0 block
 *		 1 block
 */

#define	CORE_DUMP_AREA_OFFSET		1
#define	DEFAULT_CORE_AREA_MAX_SIZE	(16 * 1024L) /* 16 Gb */

typedef struct dump_desc {
	u64	signature;		/* signature to indicate dump */
					/* header structure start */
					/* should be first bytes of useful */
					/* part of the header */
	u8	cntp_valid;		/* control points header of file */
					/* is created and valid */
	u8	core_valid;		/* system core dump header of file */
					/* is created and valid */
	u64	file_size;		/* total size of dump file */
					/* in pages */
					/* (page size = block size) */
	u64	cntp_offset;		/* offset (in blocks = page) */
					/* of control points area in */
					/* the dump file */
	u64	cntp_size;		/* size of control points area */
					/* in blocks */
	u64	core_offset;		/* offset (in blocks = page) */
					/* of core dump area in */
					/* the dump file */
	u64	core_size;		/* size of core dump area */
					/* in blocks */
} dump_desc_t;

/*
 * System core dump state info
 */
typedef struct core_dump {
} core_dump_t;

/*
 * Dump header on the disk structure
 */
typedef struct dump_header {
					/* Space for disklabel etc. */
	u8	bootbits[BOOTBITS_DUMP_HEADER_SIZE];

	dump_desc_t	info;		/* Device & dump state common info */
	u8	zip1[DUMP_INFO_HEADER_SIZE - sizeof (dump_desc_t)];

	core_dump_t	core;		/* System core dump header stuff */
	u8	zip3[CORE_DUMP_HEADER_SIZE - sizeof (core_dump_t)];

					/* zip area to make size of */
					/* header - constant  == PAGE_SIZE */
	u8	gap[	TOTAL_DUMP_HEADER_SIZE -
			BOOTBITS_DUMP_HEADER_SIZE -
			DUMP_INFO_HEADER_SIZE -
			CORE_DUMP_HEADER_SIZE -
			8];		/* u64 : magic */

	u64	magic;			/* magic value to indicate control */
					/* point header structure */
					/* should be last bytes of the */
					/* header */
} dump_header_t;

#define	DUMP_HEADER_SIGNATURE		0xe2c0c0e226143210
#define	DUMP_HEADER_MAGIC		0xe2c0c0e22614cdef

#define	DUMP_BLOCK_TO_SECTOR(block)	((block) * (PAGE_SIZE >> 9))
#define	CORE_BLOCK_TO_SECTOR(block)	DUMP_BLOCK_TO_SECTOR(block)

/*
 * Forwards of some functions to recover system state
 */

extern struct vm_area_struct	*cntp_find_vma(struct task_struct *ts,
							unsigned long addr);
extern void	dump_prepare(u16 dump_dev, u64 dump_sector);
extern void	start_emergency_dump(void);
extern int	create_dump_point(void);

extern void	init_dump_analyze_mode(void);
extern void	start_dump_analyze(void);

extern e2k_addr_t 	cntp_kernel_address_to_phys(e2k_addr_t address);
extern e2k_addr_t	cntp_user_address_to_phys(struct task_struct *tsk,
				e2k_addr_t address);

extern int	map_memory_region(e2k_addr_t mem_base, e2k_addr_t mem_end,
				  int *just_mapped_point);

extern int run_init_process(const char *init_filename);

#if defined(CONFIG_EMERGENCY_DUMP)
extern unsigned int	nr_swapfiles;
extern struct swap_info_struct	*swap_info[MAX_SWAPFILES];
#endif

extern	e2k_addr_t	cntp_kernel_base;

extern	int	cur_cnt_point;
extern	int	cntp_small_kern_mem_div;
extern	int	dump_analyze_mode;
extern	int	dump_analyze_opt;
extern	char	dump_analyze_cmd[];

#define	boot_cur_cnt_point			\
	boot_get_vo_value(cur_cnt_point)
#define boot_cntp_small_kern_mem_div		\
	boot_get_vo_value(cntp_small_kern_mem_div)
#define boot_dump_analyze_mode			\
	boot_get_vo_value(dump_analyze_mode)
#define boot_dump_analyze_opt			\
	boot_get_vo_value(dump_analyze_opt)
#define boot_dump_analyze_cmd			\
	boot_vp_to_pp((char *)dump_analyze_cmd)

extern inline e2k_size_t
get_dump_analyze_bank_size(e2k_phys_bank_t *phys_bank, int cntp_num)
{
	e2k_addr_t base, new_base;
	e2k_size_t size, new_size;

	BUG_ON(cntp_num == 0 || cntp_num == 1);

	size = phys_bank->pages_num * PAGE_SIZE;
	base = phys_bank->base_addr;
	new_base = LARGE_PAGE_ALIGN_DOWN(base);
	new_size = size - (new_base - base);

	return LARGE_PAGE_ALIGN_UP(new_size / cntp_num);
}

extern inline e2k_size_t
get_dump_analyze_memory_len(e2k_phys_bank_t *phys_bank, int cntp, int cntp_num)
{
	e2k_size_t size = get_dump_analyze_bank_size(phys_bank, cntp_num);
	e2k_size_t len = size;
	e2k_addr_t base;
	e2k_addr_t new_base;

	BUG_ON(cntp_num == 0 || cntp_num == 1);
	BUG_ON(cntp != cntp_num - 1);


	base = phys_bank->base_addr;
	new_base = LARGE_PAGE_ALIGN_DOWN(base);
	len += phys_bank->pages_num * PAGE_SIZE -
			((new_base - base) + size * cntp_num);

	return len;
}

extern inline e2k_addr_t
get_dump_analyze_memory_offset(e2k_phys_bank_t *phys_bank, int cntp,
	int cntp_num)
{
	e2k_size_t size;
	e2k_addr_t offset = 0;
	e2k_addr_t base;
	e2k_addr_t new_base;

	BUG_ON(cntp_num == 0 || cntp_num == 1);
	BUG_ON(cntp != cntp_num - 1);

	size = get_dump_analyze_bank_size(phys_bank, cntp_num);
	base = phys_bank->base_addr;
	new_base = LARGE_PAGE_ALIGN_DOWN(base);
	offset = (new_base - base) + size * cntp;
	return offset;
}

extern inline e2k_addr_t
get_dump_analyze_memory_base(e2k_phys_bank_t *phys_bank, int cntp, int cntp_num)
{
	e2k_addr_t offset = get_dump_analyze_memory_offset(
					phys_bank, cntp, cntp_num);
	e2k_addr_t base = phys_bank->base_addr;

	base += offset;
	return base;
}

extern inline e2k_addr_t
boot_get_dump_analyze_kernel_base(void)
{
	e2k_phys_bank_t	*phys_bank;
	e2k_addr_t	base;
	e2k_addr_t	new_base;
	e2k_size_t	cntp_size;
	int node;
	int bank;

	for (node = 0; node < L_MAX_MEM_NUMNODES; node ++) {
		phys_bank = full_phys_mem[node].banks;
		if (phys_bank->pages_num == 0)
			continue;	/* node has not memory */

		for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank ++) {
			if (phys_bank->pages_num == 0)
				break;

			cntp_size = get_dump_analyze_memory_len(
					phys_bank,
					boot_cntp_small_kern_mem_div - 1,
					boot_cntp_small_kern_mem_div);
			if (cntp_size < boot_kernel_image_size)
				goto next_bank;

			base = get_dump_analyze_memory_base(
					phys_bank,
					boot_cntp_small_kern_mem_div - 1,
					boot_cntp_small_kern_mem_div);

			new_base = _PAGE_ALIGN_DOWN(base, E2K_KERNEL_PAGE_SIZE);
			if (new_base - base + boot_kernel_image_size <=
					cntp_size)
				return new_base;
next_bank:
			phys_bank ++;
		}
	}

	/*
	 * TODO: avoid this
	 */
	BUG();

	return -1;
}

/*
 * bootblock manipulations (read/write/set/reset) in virtual kernel mode
 * on physical level:
 *	write through and uncachable access on physical address
 *	bootblock virtual address can be only read
 */

static inline u64
read_bootblock_cur_cnt_point(bootblock_struct_t *bootblock)
{
	return READ_BOOTBLOCK_FIELD(bootblock, cur_cnt_point);
}

extern inline void
write_bootblock_cur_cnt_point(bootblock_struct_t *bootblock, u64 new_cnt_point)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, cur_cnt_point, new_cnt_point);
}

extern inline void
write_bootblock_mem_cnt_points(bootblock_struct_t *bootblock, u64 new_mem_points)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, mem_cnt_points, new_mem_points);
}

extern inline void
write_bootblock_disk_cnt_points(bootblock_struct_t *bootblock,
				u64 new_disk_points)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, disk_cnt_points, new_disk_points);
}

extern inline void
write_bootblock_kernel_base(bootblock_struct_t *bootblock,
				u64 new_kernel_base)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, info.kernel_base, new_kernel_base);
}

extern inline u64
read_bootblock_cntp_kernel_base(bootblock_struct_t *bootblock, int cntp)
{
	return READ_BOOTBLOCK_FIELD(bootblock,
					info.cntp_info[cntp].kernel_base);
}

extern inline void
write_bootblock_cntp_kernel_base(bootblock_struct_t *bootblock, int cntp,
				u64 kernel_base)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, info.cntp_info[cntp].kernel_base,
								kernel_base);
}

extern inline void
set_bootblock_cntp_created(bootblock_struct_t *bootblock)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, cnt_points_created, 1);
}

/*
 * Convert virtual address of kernel item in a control point context
 * to the consistent physical address.
 */
#define cntp_va_to_pa(virt_addr, cntp_kernel_phys_base, ts)	  	  \
({									  \
	e2k_addr_t phys = 0;					       	  \
	e2k_addr_t virt = (e2k_addr_t)virt_addr;			  \
									  \
	if (virt > 0 && virt < PAGE_OFFSET)				  \
		phys = cntp_user_address_to_phys(ts, virt);		  \
	else if (virt >= PAGE_OFFSET && virt < PAGE_OFFSET + MAX_PM_SIZE) \
		phys = __pa(virt);				          \
	else if (virt >= KERNEL_BASE && virt <= KERNEL_END)		  \
		phys = virt - KERNEL_BASE + cntp_kernel_phys_base;	  \
	else if (virt != 0)						  \
		phys = cntp_kernel_address_to_phys(virt);    		  \
									  \
	phys;								  \
})

#define	cntp_va(virt_addr, ts)						  \
({								  	  \
	void *virt = (void*)0;			  			  \
	if ((e2k_addr_t)virt_addr != 0)	{			  	  \
		virt = (void *) cntp_va_to_pa(virt_addr, cntp_kernel_base, ts);\
		if (((unsigned long) virt) != -1)			  \
			virt = __va(virt);				  \
	}								  \
	virt;								  \
})
#endif /* _E2K_CNT_POINT_H */
