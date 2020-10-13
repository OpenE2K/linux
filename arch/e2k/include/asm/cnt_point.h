/* $Id: cnt_point.h,v 1.3 2009/06/29 11:51:48 atic Exp $
 *
 * Recovery the system from control point.
 */
#ifndef _E2K_CNT_POINT_H
#define _E2K_CNT_POINT_H

#include <asm/types.h>
#include <asm/boot_recovery.h>

/*
 * Control points & core dump header on the disk
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
						/* offset 0x400 - signature */
#define	CNTP_DUMP_HEADER_SIZE		0x500	/* offset 0x500 */
#define	CORE_DUMP_HEADER_SIZE		0x500	/* offset 0xa00 */
						/* offset 0xf00 - gap */
						/* offset 0xff8 - magic */

/*
 * Dump device and common dump state info
 * Dump file space layout:
 *	block	0			dump file header
 *	block	1			core dump area start
 *	block	MAX_CORE_DUMP_SIZE + 1	control points area start
 *	-----------------------------------------------------------------
 *	| header |    core dump area	|	control points area	|
 *	-----------------------------------------------------------------
 *	0 block
 *		 1 block
 *					MAX_CORE_DUMP_SIZE + 1
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
 * Control points state info
 */
typedef struct cntp_desc {	/* one control point descriptor */
	u64	start;		/* control point start offset in */
				/* dump file */
	u64	max_size;	/* max size of control point space */
	u64	size;		/* real size of control point in blocks */
	u64	tags_start;	/* control point start offset in */
				/* dump file to save tags */
	u64	tags_max_size;	/* max size of control point space to save */
				/* tags */
	u64	tags_size;	/* real size of saved tags in blocks */
	int	areas_num;	/* number of contiguous memory areas */
				/* saved in control point */
				/* (number of entries in cntp areas table */
	u8	valid;		/* control point is valid on file */
} cntp_desk_t;

typedef struct cntp_dump {
	u64	offset;		/* control points area offset */
				/* (same as in dump_desc_t structure */
	u64	size;		/* size of control points area */
				/* (same as in dump_desc_t structure */
	u8	max_cntps;	/* max number of control points */
	u8	count;		/* current number of valid control */
				/* points in the file */
	cntp_desk_t		/* descriptors of all control points */
		cntps[L_MAX_CNT_POINTS];
} cntp_dump_t;

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

	cntp_dump_t	cntp;		/* Control points header stuff */
	u8	zip2[CNTP_DUMP_HEADER_SIZE - sizeof (cntp_dump_t)];

	core_dump_t	core;		/* System core dump header stuff */
	u8	zip3[CORE_DUMP_HEADER_SIZE - sizeof (core_dump_t)];

					/* zip area to make size of */
					/* header - constant  == PAGE_SIZE */
	u8	gap[	TOTAL_DUMP_HEADER_SIZE -
			BOOTBITS_DUMP_HEADER_SIZE -
			DUMP_INFO_HEADER_SIZE -
			CNTP_DUMP_HEADER_SIZE -
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
#define	CNTP_BLOCK_TO_SECTOR(block)	DUMP_BLOCK_TO_SECTOR(block)
#define	CORE_BLOCK_TO_SECTOR(block)	DUMP_BLOCK_TO_SECTOR(block)

/*
 * Control point memory dump consists of number of memory areas.
 * Sequences of areas are discontiguous in the memory,
 * but are contiguous on the disk.
 * So control point memory dump regards
 *
 * on a memory as:
 *
 *				_________________________________
 *				|		hole		|
 *  areas[0].start  -->	    -->	|-------------------------------|-
 *			    |	|	    memory area 0	| | <--
 *			    |	|-------------------------------|-    |
 *			    |	|		hole		|     |
 *			    |	|-------------------------------|     |
 *			    |	|				|     |
 *			    |	|				|     |
 *			    |	|				|     |
 *			    |	|-------------------------------|     |
 *			    |	|		hole		|     |
 *  areas[n].start -->	  --+-> |-------------------------------|-    |
 *			  | |	|	    memory area n	| | <-+---
 *			  | |	|-------------------------------|-    |	 |
 *			  | |	|		hole		|     |  |
 *			  | |	|_______________________________|     |  |
 * on a disk as:	  | |					      |  |
 *			  | |					      |  |
 * cntps[i].start ->	  | |	_________________________________     |  |
 * areas[0]		  | ----|	start		size	|------  |
 *			  |    	|-------------------------------|	 |
 *			  | 	|				|	 |
 *			  | 	|				|	 |
 *			  | 	|				|	 |
 *			  | 	|-------------------------------|	 |
 * areas[n]		  ------|	start		size	|---------
 *				|-------------------------------|
 *				|				|
 *				|_______________________________|
 *				|	memory area 0 dump	|
 *				|-------------------------------|
 *				|				|
 *				|				|
 *				|				|
 *				|-------------------------------|
 *				|	memory area n dump	|
 *				|-------------------------------|
 *				|				|
 *				|_______________________________|
 */
typedef	u32		e2k_pfn_t;	/* physical page number */

typedef struct cntp_area {
	e2k_pfn_t	start;		/* start physical page of the */
					/* memory area */
	e2k_pfn_t	size;		/* number of physical pages in the */
					/* memory area */
} cntp_area_t;

#define	CNTP_AREAS_TABLE_ORDER		0	/* 1 PAGE */
#define	CNTP_AREAS_TABLE_SIZE		\
				((1 << CNTP_AREAS_TABLE_ORDER) * PAGE_SIZE)
#define	CNTP_AREAS_TABLE_ENTRIES	\
				(CNTP_AREAS_TABLE_SIZE / sizeof (cntp_area_t))

#define	CNTP_TAGS_AREAS_ORDER		0	/* 1 PAGE */
#define	CNTP_TAGS_AREAS_SIZE		\
				((1 << CNTP_TAGS_AREAS_ORDER) * PAGE_SIZE)
#define	CNTP_1_PAGE_TAGS_AREA_SIZE	ONE_PAGE_TAGS_AREA_SIZE

#define	MIN_PFNS_STOCK_TO_RESTORE	(128 * 6)	/* pages number == max */
						/* BIO vectors number */
#define	MAX_PFNS_STOCK_TO_RESTORE	(MIN_PFNS_STOCK_TO_RESTORE + 64)

#define MIN_TAGS_PFNS_STOCK_TO_RESTORE	(MIN_PFNS_STOCK_TO_RESTORE / 16)
#define	MAX_TAGS_PFNS_STOCK_TO_RESTORE	(MIN_TAGS_PFNS_STOCK_TO_RESTORE * 4)

#define	MAX_PFNS_NUM_TO_RESTORE		32

typedef struct dump_bio {
	struct  bio *bio;		/* bio structure pointer */
	struct list_head list;		/* list head to queue bio structure */
} dump_bio_t;

typedef enum cntp_flag {
	CREATE_HEADER_CNTP_FLAG = (1 << 0),	/* create new header on */
						/* disk */
	SAVE_CNTP_FLAG		= (1 << 1),	/* save control point in */
						/* memory on disk */
	RESTORE_CNTP_FLAG	= (1 << 2),	/* restore control point in */
						/* memory from disk */
	RESAVE_CNTP_FLAG	= (1 << 3),	/* resave control point in */
						/* memory on disk */
	UNMAP_CNTP_FLAG		= (1 << 4),	/* unmap control point */
						/* in memory */
} cntp_flag_t;

/*
 * Forwards of some functions to recover system state
 */

extern struct vm_area_struct	*cntp_find_vma(struct task_struct *ts,
							unsigned long addr);

extern void	background_recover_system(void);

extern int	create_control_point(int async_mode);
extern void	switch_control_points(void);
extern int	save_control_points(void);
extern int	restore_control_points(void);
extern void	set_next_control_point(void);

extern void	wake_up_restartd(void);

extern void	dump_prepare(u16 dump_dev, u64 dump_sector);
extern int	dump_start(void);
extern void	start_emergency_dump(void);
extern int	create_dump_point(void);

extern void 	save_dump_for_quick_restart(void);

extern void	init_dump_analyze_mode(void);
extern void	start_dump_analyze(void);

extern e2k_addr_t 	cntp_kernel_address_to_phys(e2k_addr_t address);
extern e2k_addr_t	cntp_user_address_to_phys(struct task_struct *tsk,
				e2k_addr_t address);

extern	e2k_addr_t	cntp_kernel_base;
extern	int		cnt_points_num;
extern	int		recreate_cnt_points;
extern	int		cur_cnt_point;
extern	int		mem_cnt_points;
extern	int		disk_cnt_points;
extern	int		cnt_points_created;
extern	int		cntp_small_kern_mem_div;
extern	int		dump_analyze_mode;
extern	int		dump_analyze_opt;
extern	char		dump_analyze_cmd[];

#define	boot_cnt_points_num			\
	boot_get_vo_value(cnt_points_num)
#define	boot_cur_cnt_point			\
	boot_get_vo_value(cur_cnt_point)
#define	boot_mem_cnt_points			\
	boot_get_vo_value(mem_cnt_points)
#define	boot_disk_cnt_points			\
	boot_get_vo_value(disk_cnt_points)
#define	boot_cnt_points_created			\
	boot_get_vo_value(cnt_points_created)
#define boot_cntp_small_kern_mem_div		\
	boot_get_vo_value(cntp_small_kern_mem_div)
#define boot_dump_analyze_mode			\
	boot_get_vo_value(dump_analyze_mode)
#define boot_dump_analyze_opt			\
	boot_get_vo_value(dump_analyze_opt)
#define boot_dump_analyze_cmd			\
	boot_vp_to_pp(dump_analyze_cmd)

/*
 * This function returns the real count of control points. When the system is
 * creating control point 1 for quick restart, it uses 2 control points in 
 * fact.
 */
extern inline int get_cnt_points_num(int cnt_points_num)
{
#if (CONFIG_CNT_POINTS_NUM < 2)
	if (!dump_analyze_opt)
		return (cnt_points_num != 1 ) ? cnt_points_num : 2;
	else
		return 2;
#endif	/* CONFIG_CNT_POINTS_NUM < 2 */
	return cnt_points_num;
}

extern inline int boot_get_cnt_points_num(int cnt_points_num)
{
#if (CONFIG_CNT_POINTS_NUM < 2)
	if (!boot_dump_analyze_opt)
		return (cnt_points_num != 1 ) ? cnt_points_num : 2;
	else
		return 2;
#endif	/* CONFIG_CNT_POINTS_NUM < 2 */
	return cnt_points_num;
}

extern inline e2k_size_t
get_cntp_bank_size(e2k_phys_bank_t *phys_bank, int cntp_num)
{
	e2k_addr_t size = phys_bank->pages_num * PAGE_SIZE;

	if (cntp_num == 0 || cntp_num == 1) {
		return size;
	} else {
		e2k_addr_t base = phys_bank->base_addr;
		e2k_addr_t new_base = LARGE_PAGE_ALIGN_DOWN(base);
		e2k_size_t new_size = size - (new_base - base);
		e2k_size_t len = LARGE_PAGE_ALIGN_UP(new_size / cntp_num);
		return len;
	}
}

extern inline e2k_size_t
get_cntp_memory_len(e2k_phys_bank_t *phys_bank, int cntp, int cntp_num)
{
	e2k_size_t size = get_cntp_bank_size(phys_bank, cntp_num);
	e2k_size_t len = size;
	e2k_addr_t base;
	e2k_addr_t new_base;

	if (cntp_num == 0 || cntp_num == 1) {
		return len;
	}
	if (cntp != 0 && cntp != cntp_num - 1)
		return len;
	if (len == 0) {
		if (cntp == 0)
			len = phys_bank->pages_num * PAGE_SIZE;
		return len;
	}
	base = phys_bank->base_addr;
	new_base = LARGE_PAGE_ALIGN_DOWN(base);
	if (cntp == 0) {
		/*
		 * Add not aligned part at the bank begining
		 */
		len += (new_base - base);
	}
	if (cntp == cntp_num - 1) {
		/*
		 * Add not aligned part at the bank end
		 */
		len += phys_bank->pages_num * PAGE_SIZE -
			((new_base - base) + size * cntp_num);
	}
	return len;
}

extern inline e2k_addr_t
get_cntp_memory_offset(e2k_phys_bank_t *phys_bank, int cntp, int cntp_num)
{
	e2k_size_t size;
	e2k_addr_t offset = 0;
	e2k_addr_t base;
	e2k_addr_t new_base;

	if (cntp_num == 0 || cntp_num == 1)
		return offset;
	if (cntp == 0)
		return offset;
	size = get_cntp_bank_size(phys_bank, cntp_num);
	base = phys_bank->base_addr;
	new_base = LARGE_PAGE_ALIGN_DOWN(base);
	offset = (new_base - base) + size * cntp;
	return offset;
}

extern inline e2k_addr_t
get_cntp_memory_base(e2k_phys_bank_t *phys_bank, int cntp, int cntp_num)
{
	e2k_addr_t offset = get_cntp_memory_offset(phys_bank, cntp, cntp_num);
	e2k_addr_t base = phys_bank->base_addr;

	base += offset;
	return base;
}

extern inline e2k_addr_t
get_cntp_alligned_memory(int cntp, e2k_size_t size, e2k_addr_t mem_align)
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
			if (phys_bank->pages_num == 0) {
				base = -1;
				break;
			}

		#if (CONFIG_CNT_POINTS_NUM < 2)
			if (cnt_points_num == 1 || dump_analyze_opt) {
				if (cntp == 1)
					cntp_size = get_cntp_memory_len(
						phys_bank,
						cntp_small_kern_mem_div - 1,
						cntp_small_kern_mem_div);
			else
				cntp_size = phys_bank->pages_num * PAGE_SIZE;
			} else
		#endif	/* CONFIG_CNT_POINTS_NUM < 2 */
				cntp_size = get_cntp_memory_len(
					phys_bank, cntp, cnt_points_num);
			if (cntp_size < size)
				goto next_bank;

		#if (CONFIG_CNT_POINTS_NUM < 2)
			if (cnt_points_num == 1 || dump_analyze_opt) {
				if (cntp == 1)
					base = get_cntp_memory_base(
						phys_bank,
						cntp_small_kern_mem_div - 1,
						cntp_small_kern_mem_div);

				else
					base = phys_bank->base_addr;

			} else
		#endif	/* CONFIG_CNT_POINTS_NUM < 2 */
				base = get_cntp_memory_base(
					phys_bank, cntp, cnt_points_num);

			new_base = _PAGE_ALIGN_DOWN(base, mem_align);
			if (new_base - base + size <= cntp_size)
				return new_base;
next_bank:
			phys_bank ++;
		}
	}
	return -1;
}

extern inline e2k_addr_t
get_cntp_kernel_base(int cntp)
{
	return get_cntp_alligned_memory(cntp, kernel_image_size,
						E2K_KERNEL_PAGE_SIZE);
}

/*
 * Hash table of free areas in a zone
 */
typedef	struct pfn_area {
	e2k_pfn_t	start;		/* start of physical page area */
	e2k_pfn_t	size;		/* number of pages in the area */
	struct pfn_area	*next;		/* next area pointer */
} pfn_area_t;

#define	PFN_AREAS_HASH_ORDER		0
#define	PFN_AREAS_HASH_SIZE		(PAGE_SIZE << PFN_AREAS_HASH_ORDER)
#define	PFN_AREAS_HASH_GFP		GFP_KERNEL
#define	PFN_AREAS_LIST_ORDER		0
#define	PFN_AREAS_LIST_SIZE		(PAGE_SIZE << PFN_AREAS_LIST_ORDER)
#define	PFN_AREAS_LIST_GFP		GFP_KERNEL
#define PFN_AREAS_HASH_ENTRIES		\
		(PFN_AREAS_HASH_SIZE / sizeof (pfn_area_t))
#define PFN_AREAS_LIST_ENTRIES		\
		(PFN_AREAS_LIST_SIZE / sizeof (pfn_area_t))

/*
 * bootblock manipulations (read/write/set/reset) in virtual kernel mode
 * on physical level:
 *	write through and uncachable access on physical address
 *	bootblock virtual address can be only read
 */

#define	READ_BOOTBLOCK_FIELD(bootblock_p, blk_field)			\
({									\
	u64 field_value;						\
	switch (sizeof ((bootblock_p)->blk_field)) {			\
	case 1 : field_value =						\
			E2K_READ_MAS_B(&((bootblock_p)->blk_field),	\
					MAS_IOADDR);			\
		 break;							\
	case 2 : field_value =						\
			E2K_READ_MAS_H(&((bootblock_p)->blk_field),	\
					MAS_IOADDR);			\
		 break;							\
	case 4 : field_value =						\
			E2K_READ_MAS_W(&((bootblock_p)->blk_field),	\
					MAS_IOADDR);			\
		 break;							\
	case 8 : field_value =						\
			E2K_READ_MAS_D(&((bootblock_p)->blk_field),	\
					MAS_IOADDR);			\
		 break;							\
	default : BUG();						\
	}								\
	(field_value);							\
})

#define	WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field, field_value)	\
({									\
	switch (sizeof((bootblock_p)->blk_field)) {			\
	case 1 : E2K_WRITE_MAS_B(&((bootblock_p)->blk_field),		\
				(field_value), MAS_IOADDR);		\
		 break;							\
	case 2 : E2K_WRITE_MAS_H(&((bootblock_p)->blk_field),		\
				(field_value), MAS_IOADDR);		\
		 break;							\
	case 4 : E2K_WRITE_MAS_W(&((bootblock_p)->blk_field),		\
				(field_value), MAS_IOADDR);		\
		 break;							\
	case 8 : E2K_WRITE_MAS_D(&((bootblock_p)->blk_field),		\
				(field_value), MAS_IOADDR);		\
		 break;							\
	default : BUG();						\
	}								\
})

extern inline u64
read_bootblock_flags(bootblock_struct_t *bootblock)
{
	return READ_BOOTBLOCK_FIELD(bootblock, kernel_flags);
}

extern inline void
write_bootblock_flags(bootblock_struct_t *bootblock, u64 new_flags)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, boot_flags, new_flags);
	WRITE_BOOTBLOCK_FIELD(bootblock, kernel_flags, new_flags);
}

extern inline void
set_bootblock_flags(bootblock_struct_t *bootblock, u64 new_flags)
{
	u64 cur_flags = read_bootblock_flags(bootblock);
	write_bootblock_flags(bootblock, cur_flags | new_flags);
}

extern inline void
reset_bootblock_flags(bootblock_struct_t *bootblock, u64 new_flags)
{
	u64 cur_flags = read_bootblock_flags(bootblock);
	write_bootblock_flags(bootblock, cur_flags & ~new_flags);
}

extern inline u64
read_bootblock_cur_cnt_point(bootblock_struct_t *bootblock)
{
	return READ_BOOTBLOCK_FIELD(bootblock, cur_cnt_point);
}

extern inline void
write_bootblock_cur_cnt_point(bootblock_struct_t *bootblock, u64 new_cnt_point)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, cur_cnt_point, new_cnt_point);
}

extern inline u64
read_bootblock_mem_cnt_points(bootblock_struct_t *bootblock)
{
	return READ_BOOTBLOCK_FIELD(bootblock, mem_cnt_points);
}

extern inline void
write_bootblock_mem_cnt_points(bootblock_struct_t *bootblock, u64 new_mem_points)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, mem_cnt_points, new_mem_points);
}

extern inline u64
read_bootblock_disk_cnt_points(bootblock_struct_t *bootblock)
{
	return READ_BOOTBLOCK_FIELD(bootblock, disk_cnt_points);
}

extern inline void
write_bootblock_disk_cnt_points(bootblock_struct_t *bootblock,
				u64 new_disk_points)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, disk_cnt_points, new_disk_points);
}

extern inline u64
read_bootblock_kernel_base(bootblock_struct_t *bootblock)
{
	return READ_BOOTBLOCK_FIELD(bootblock, info.kernel_base);
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

extern inline u64
read_bootblock_cntp_node_data(bootblock_struct_t *bootblock, int cntp)
{
	return READ_BOOTBLOCK_FIELD(bootblock,
					info.cntp_info[cntp].node_data);
}

extern inline void
write_bootblock_cntp_node_data(bootblock_struct_t *bootblock, int cntp,
				u64 node_data)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, info.cntp_info[cntp].node_data,
								node_data);
}

extern inline void
write_bootblock_cntp_nosave_areas(bootblock_struct_t *bootblock, int cntp,
				u64 nosave_areas)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, info.cntp_info[cntp].nosave_areas,
								nosave_areas);
}

extern inline u64
read_bootblock_cntp_nosave_areas(bootblock_struct_t *bootblock, int cntp)
{
	return READ_BOOTBLOCK_FIELD(bootblock,
					info.cntp_info[cntp].nosave_areas);
}

extern inline void
write_bootblock_cntp_nosaves_num(bootblock_struct_t *bootblock, int cntp,
				u16 nosave_areas_num)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, info.cntp_info[cntp].nosaves_num,
							nosave_areas_num);
}

extern inline u16
read_bootblock_cntp_nosaves_num(bootblock_struct_t *bootblock, int cntp)
{
	return READ_BOOTBLOCK_FIELD(bootblock,
					info.cntp_info[cntp].nosaves_num);
}

extern inline void
set_bootblock_cntp_created(bootblock_struct_t *bootblock)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, cnt_points_created, 1);
}

extern inline void
reset_bootblock_cntp_created(bootblock_struct_t *bootblock)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, cnt_points_created, 0);
}

extern inline void
set_bootblock_cntp_mem_valid(bootblock_struct_t *bootblock, int cntp)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, info.cntp_info[cntp].mem_valid, 1);
}

extern inline void
reset_bootblock_cntp_mem_valid(bootblock_struct_t *bootblock, int cntp)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, info.cntp_info[cntp].mem_valid, 0);
}

extern inline int
is_bootblock_cntp_mem_valid(bootblock_struct_t *bootblock, int cntp)
{
	return READ_BOOTBLOCK_FIELD(bootblock, info.cntp_info[cntp].mem_valid);
}

extern inline void
set_bootblock_cntp_disk_valid(bootblock_struct_t *bootblock, int cntp)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, info.cntp_info[cntp].disk_valid, 1);
}

extern inline void
reset_bootblock_cntp_disk_valid(bootblock_struct_t *bootblock, int cntp)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, info.cntp_info[cntp].disk_valid, 0);
}

extern inline int
is_bootblock_cntp_disk_valid(bootblock_struct_t *bootblock, int cntp)
{
	return READ_BOOTBLOCK_FIELD(bootblock, info.cntp_info[cntp].disk_valid);
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
