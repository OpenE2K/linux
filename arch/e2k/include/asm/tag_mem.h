/* $Id: tag_mem.h,v 1.6 2008/09/18 14:57:23 atic Exp $
 *
 * Heading of tag's memory management.
 *
 * Copyright (C) 2003 Salavat Guiliazov <atic@mcst.ru>
 */

#ifndef	_E2K_TAG_MEM_H
#define	_E2K_TAG_MEM_H

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/spinlock.h>

#include <asm/types.h>
#include <asm/e2k_api.h>
#include <asm/head.h>
#include <asm/process.h>
#include <asm/swap_info.h>

#undef	DEBUG_TAG_MODE
#undef	DebugTM
#define	DEBUG_TAG_MODE		0	/* Tag memory */
#define DebugTM(...)		DebugPrint(DEBUG_TAG_MODE ,##__VA_ARGS__)

#ifndef __ASSEMBLY__


/*
 * Definition to convert data virtual address to appropriate virtual addresses
 * of tags and on the contrary:
 *
 * to each quad-word of data (16 bytes) corresponds 1 byte of tag
 *
 * 0x0000 00f0 0000 0000 - 0x0000 00ff ffff ffff	USER_TAG_MEM_BASE -
 *							USER_TAG_MEM_SIZE
 *
 * Data page	0x0000 0000 0000 0000 <-> Tag page	0x0000 00f0 0000 0000
 *		0x0000 0000 0000 1000 <-> 		0x0000 00f0 0000 0100
 *		.....................			.....................
 *		0x0000 0000 0001 0000 <-> 		0x0000 00f0 0000 1000
 *		.....................			.....................
 *		0x0000 00e0 0000 0000 <-> 		0x0000 00fe 0000 0000
 *		.....................			.....................
 *		0x0000 00ef ffff f000 <-> 		0x0000 00fe ffff ff00
 */

#define	DATA_PAGES_PER_TAGS_PAGE(block_size)	16
#define	ONE_PAGE_TAGS_AREA_SIZE	(PAGE_SIZE / DATA_PAGES_PER_TAGS_PAGE(0))
#define	virt_to_tag(data_addr)	(USER_TAG_MEM_BASE + ((data_addr) >> 4))
#define	tag_to_virt(tag_addr)	(((tag_addr) - USER_TAG_MEM_BASE) << 4)

/*
 * Is the specified address from tags virtual space
 */
#define	is_tags_area_addr(addr)	((addr) >= USER_TAG_MEM_BASE && \
				(addr) < (USER_TAG_MEM_BASE+USER_TAG_MEM_SIZE))

/*
 * vma->vm_flags for tags area
 */

#define	TAG_VM_FLAGS		(VM_READ | VM_WRITE)

/*
 * Structure of tags into the memory
 * One byte contains tag of one quad-word data, which consists of
 * two double-word (low and high) and/or
 * four single-word (0, 1, 2 and 3)
 */

typedef struct mem_tag_s {
	u8	w0	: 2;	/* [1:0] tag of single word # 0 */
	u8	w1	: 2;	/* [3:2] tag of single word # 1 */
	u8	w2	: 2;	/* [5:4] tag of single word # 2 */
	u8	w3	: 2;	/* [7:6] tag of single word # 3 */
} mem_tag_s_t;

typedef struct mem_tag_d {
	u8	lo	: 4;	/* [3:0] tag of low double word */
	u8	hi	: 4;	/* [7:4] tag of high double word */
} mem_tag_d_t;

typedef struct mem_tag_q {
	u8	qw	: 8;	/* [7:0] tag of quad-word */
} mem_tag_q_t;

typedef union mem_tag {
	mem_tag_s_t	sing;	/* as fields of single word tags */
	mem_tag_d_t	doub;	/* as fields of double word tags */
	mem_tag_q_t	quad;	/* as fields of double word tags */
	u8		tags;	/* as entire value */
} mem_tag_t;
#define	dw_lo_mem_tag	doub.lo
#define	dw_hi_mem_tag	doub.hi
#define	qw_mem_tag	quad.qw

extern void __init swap_info_cache_init(void);

extern int add_swap_info_to_page(struct mm_struct* mm, struct page* page, e2k_addr_t addr);

extern int add_swap_info_to_page_next(struct mm_struct* mm, struct page* page, e2k_addr_t addr);

extern swap_page_info_t* get_swap_info_from_page(struct page* page);

extern void free_swap_info_struct(swap_page_info_t* info);

#ifdef CONFIG_SOFTWARE_SWAP_TAGS
extern inline void
remove_swap_info_from_page(struct page* page) {
	swap_page_info_t *info;
        do {
		info = get_swap_info_from_page(page);
		free_swap_info_struct(info);
	} while (PageWithSwapInfo(page));
}
#endif /* CONFIG_SOFTWARE_SWAP_TAGS */

/*
 * Forwards of tags memory management functions
 */

extern int load_page_tags(struct mm_struct* mm, e2k_addr_t page_addr);

extern struct vm_area_struct *create_tags_vma(struct mm_struct *mm,
			e2k_addr_t data_addr);
extern e2k_addr_t get_tags_address(struct mm_struct *mm, e2k_addr_t data_addr,
			int write);
extern struct page *get_tags_page(struct mm_struct *mm, e2k_addr_t data_addr,
			int write_access);

extern int do_tag_munmap(struct mm_struct *mm, e2k_addr_t data_addr,
			e2k_size_t data_len);

/*
 * Save tags of data memory area started from address 'data_addr'
 * The starting address of data area and area size should be quad-word * 8
 * aligned:
 *	1 quad-word (16 bytes) occupies 1 byte of tags
 *	8 tags packed into 1 double-word
 * Argument 'len' specifies saved area size in bytes, so it should be
 * quad-word * 8 multiple
 */
extern inline int
do_save_mem_area_tags(e2k_addr_t data_addr, e2k_addr_t tags_addr, e2k_size_t len,
	int copy_data, e2k_addr_t copy_addr)
{
	int tags_in_dw = sizeof (u64) / sizeof (mem_tag_t);
	int dw_data_in_dw_tags = tags_in_dw * (sizeof (u64) * 2);
	u64 *data_area = (u64 *)(_PAGE_ALIGN_DOWN(data_addr,
							dw_data_in_dw_tags));
	u64 *tags_area = (u64 *)(_PAGE_ALIGN_DOWN(tags_addr, tags_in_dw));
	u64 *copy_area = (u64 *)(_PAGE_ALIGN_DOWN(copy_addr,
							dw_data_in_dw_tags));
	register u64 q0_dw_lo;
	register u64 q0_dw_hi;
	register u64 q1_dw_lo;
	register u64 q1_dw_hi;
	register mem_tag_t q0_tag = {tags : 0};
	register mem_tag_t q1_tag = {tags : 0};
	int all_tags_is_numeric = 1;
	u64 tags_dw = 0;
	int tag_num, dw_num;
	int tag_shift;
	int i = 0;

	DebugTM("started for data addr 0x%lx tag addr 0x%lx and size 0x%lx bytes\n",
		data_addr, tags_addr, len);
	len -= (((e2k_addr_t)data_area) - data_addr);
	len = _PAGE_ALIGN_UP(len, tags_in_dw);

	for (tag_num = 0; tag_num < len / dw_data_in_dw_tags; tag_num ++) {
		tags_dw = 0;
		tag_shift = 0;
		for (dw_num = 0; dw_num < dw_data_in_dw_tags / sizeof (u64);
								dw_num += 4) {
			E2K_LOAD_TAGGED_QWORD_AND_TAGS(&data_area[0], q0_dw_lo,
				q0_dw_hi, q0_tag.dw_lo_mem_tag,
				q0_tag.dw_hi_mem_tag);
			E2K_LOAD_TAGGED_QWORD_AND_TAGS(&data_area[2], q1_dw_lo,
				q1_dw_hi, q1_tag.dw_lo_mem_tag,
				q1_tag.dw_hi_mem_tag);
			data_area += 4;
			tags_dw |= (((u64)(q0_tag.qw_mem_tag)) << tag_shift);
			tag_shift += (sizeof (mem_tag_t) * 8);
			tags_dw |= (((u64)(q1_tag.qw_mem_tag)) << tag_shift);
			tag_shift += (sizeof (mem_tag_t) * 8);
			if (DEBUG_TAG_MODE && i < 16) {
				DebugTM("   data[0x%03x] = 0x%016lx\n",
					(u32) (tag_num * dw_data_in_dw_tags +
					sizeof (*data_area) * (dw_num + 0)),
					q0_dw_lo);
				DebugTM("   data[0x%03x] = 0x%016lx\n",
					(u32) (tag_num * dw_data_in_dw_tags +
					sizeof (*data_area) * (dw_num + 1)),
					q0_dw_hi);
				DebugTM("   data[0x%03x] = 0x%016lx\n",
					(u32) (tag_num * dw_data_in_dw_tags +
					sizeof (*data_area) * (dw_num + 2)),
					q1_dw_lo);
				DebugTM("   data[0x%03x] = 0x%016lx\n",
					(u32) (tag_num * dw_data_in_dw_tags +
					sizeof (*data_area) * (dw_num + 3)),
					q1_dw_hi);
			}
			if (copy_data) {
				E2K_STORE_VALUE_WITH_TAG(&copy_area[0],
							q0_dw_lo, ETAGNVD);
				E2K_STORE_VALUE_WITH_TAG(&copy_area[1],
							q0_dw_hi, ETAGNVD);
				E2K_STORE_VALUE_WITH_TAG(&copy_area[2],
					q1_dw_lo, ETAGNVD);
				E2K_STORE_VALUE_WITH_TAG(&copy_area[3],
					q1_dw_hi, ETAGNVD);

				copy_area += 4;
			}
		}
		tags_area[0] = tags_dw;
		if (tags_dw != ETAGNVQ)
			all_tags_is_numeric = 0;
		if (DEBUG_TAG_MODE && i < 16) {
			DebugTM("   tags[0x%03x] = 0x%016lx\n",
				(u32)(sizeof (*tags_area) * tag_num), tags_dw);
			i += dw_num;
		}
		tags_area ++;
	}
	DebugTM("finished with data addr 0x%px tag addr 0x%px\n",
		data_area, tags_area);
	return all_tags_is_numeric;
}

extern inline int
save_mem_area_tags(e2k_addr_t data_addr, e2k_addr_t tags_addr,
	e2k_size_t len)
{
	return do_save_mem_area_tags(data_addr, tags_addr, len, 0, 0);
}

extern inline int
save_mem_page_tags(e2k_addr_t data_addr, e2k_addr_t tags_addr)
{
	return save_mem_area_tags(data_addr, tags_addr, PAGE_SIZE);
}

extern inline int
save_mem_data_page_tags(struct mm_struct *mm, e2k_addr_t data_addr)
{
	e2k_addr_t tags_addr;

	tags_addr = get_tags_address(mm, data_addr, 1);
	if (tags_addr == (e2k_addr_t)0)
		return -1;
	save_mem_page_tags(data_addr, tags_addr);
	return 0;
}

/*
 * Restore tags of data memory area started from address 'data_addr'
 * The starting address of data area and area size should be quad-word * 8
 * aligned:
 *	1 quad-word (16 bytes) occupies 1 byte of tags
 *	8 tags packed into 1 double-word
 * Argument 'len' specifies restored area size in bytes, so it should be
 * quad-word * 8 multiple
 */
extern inline void
do_restore_mem_area_tags(e2k_addr_t data_addr, e2k_addr_t tags_addr,
	e2k_size_t len, int copy_data, e2k_addr_t copy_addr)
{
	int tags_in_dw = sizeof (u64) / sizeof (mem_tag_t);
	int dw_data_in_dw_tags = tags_in_dw * (sizeof (u64) * 2);
	u64 *data_area = (u64 *)(_PAGE_ALIGN_DOWN(data_addr,
							dw_data_in_dw_tags));
	u64 *tags_area = (u64 *)(_PAGE_ALIGN_DOWN(tags_addr, tags_in_dw));
	u64 *copy_area = (u64 *)(_PAGE_ALIGN_DOWN(copy_addr,
							dw_data_in_dw_tags));
	register u64 q_dw_lo;
	register u64 q_dw_hi;
	register mem_tag_t q_tag = {tags : 0};
	register u64 tags_dw = 0;
	int tag_num, dw_num;
	int i = 0;

	DebugTM("started for data addr 0x%lx tag "
		"addr 0x%lx and size 0x%lx bytes\n",
		data_addr, tags_addr, len);
	len -= (((e2k_addr_t)data_area) - data_addr);
	len = _PAGE_ALIGN_UP(len, tags_in_dw);

	for (tag_num = 0; tag_num < len / dw_data_in_dw_tags; tag_num ++) {
		tags_dw = tags_area[0];
		if (DEBUG_TAG_MODE && i < 16) {
			DebugTM("   tags[0x%03x] = 0x%016lx\n",
				(u32)(sizeof (*tags_area) * tag_num), tags_dw);
		}
		for (dw_num = 0; dw_num < dw_data_in_dw_tags / sizeof (u64);
								dw_num += 2) {
			E2K_LOAD_TAGGED_QWORD(&data_area[0], q_dw_lo, q_dw_hi);
			q_tag.qw_mem_tag = tags_dw;
			tags_dw >>= (sizeof (mem_tag_t) * 8);
			if (!copy_data) {
                        /* After E2K_PUTTAGD must STRONGLY follow STORE_TAG asm
                         * to avoid compiler's problems */
			E2K_STORE_TAGGED_QWORD(&data_area[0],
                                     q_dw_lo, q_dw_hi, 
                                     q_tag.dw_lo_mem_tag, q_tag.dw_hi_mem_tag);
                            
			} else {
                                E2K_STORE_TAGGED_QWORD(&copy_area[0],
                                     q_dw_lo, q_dw_hi, 
                                     q_tag.dw_lo_mem_tag, q_tag.dw_hi_mem_tag);
				copy_area += 2;
			}
			data_area += 2;
			if (DEBUG_TAG_MODE && i < 16) {
				DebugTM("   data[0x%03x] = 0x%016lx\n",
					(u32) (tag_num * dw_data_in_dw_tags +
					sizeof (*data_area) * (dw_num + 0)),
					q_dw_lo);
				DebugTM("   data[0x%03x] = 0x%016lx\n",
					(u32) (tag_num * dw_data_in_dw_tags +
					sizeof (*data_area) * (dw_num + 1)),
					q_dw_hi);
				i += 2;
			}
		}
		tags_area ++;
	}
	DebugTM("finished with data addr 0x%px tag "
		"addr 0x%px\n", data_area, tags_area);
}
extern inline void
restore_mem_area_tags(e2k_addr_t data_addr, e2k_addr_t tags_addr,
	e2k_size_t len)
{
	do_restore_mem_area_tags(data_addr, tags_addr, len, 0, 0);
}

extern inline void
restore_mem_page_tags(e2k_addr_t data_addr, e2k_addr_t tags_addr)
{
	restore_mem_area_tags(data_addr, tags_addr, PAGE_SIZE);
}

extern inline int
restore_mem_data_page_tags(struct mm_struct *mm, e2k_addr_t data_addr)
{
	e2k_addr_t tags_addr;

	data_addr &= PAGE_MASK;
	tags_addr = get_tags_address(mm, data_addr, 0);
	if (tags_addr == (e2k_addr_t)0)
		return -1;
	restore_mem_page_tags(data_addr, tags_addr);
	return 0;
}

extern int save_swapped_page_tags(struct mm_struct *mm,
		struct page *swapped_page, e2k_addr_t data_addr);

extern int restore_swapped_page_tags(struct mm_struct *mm,
		struct page *swapped_page, e2k_addr_t data_addr);

extern inline int
save_swapped_page_tags2(swap_page_info_t* info, struct page* page) {
	return save_swapped_page_tags(info->mm, page, info->addr);
}

#ifdef CONFIG_SOFTWARE_SWAP_TAGS
extern inline int
save_swapped_page_tags_from_page(struct page* page) {
	int ret = 0;
	swap_page_info_t* info;
	do {
		info = get_swap_info_from_page(page);
		if (!is_tags_area_addr(info->addr))
			ret = save_swapped_page_tags2(info, page);
//		free_swap_info_struct(info);
	} while (PageWithSwapInfo(page));
	return ret;
}
#endif /* CONFIG_SOFTWARE_SWAP_TAGS */

#endif /* !(__ASSEMBLY__) */

#endif /* !(_E2K_TAG_MEM_H) */
