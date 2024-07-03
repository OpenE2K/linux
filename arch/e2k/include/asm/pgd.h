/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * The functions and defines necessary to manage root level of page tables - pgd
 */

#ifndef _E2K_PGD_H
#define _E2K_PGD_H

#include <linux/printk.h>

#include <asm/debug_print.h>
#include <asm/mmu_types.h>
#include <asm/pgtable_types.h>

#undef	DEBUG_PA_MODE
#undef	DebugPA
#define	DEBUG_PA_MODE		0	/* page table allocation */
#define DebugPA(...)		DebugPrint(DEBUG_PA_MODE ,##__VA_ARGS__)

static inline void
clear_pgd_range(pgd_t *dst_pgd, int start_index, int end_index)
{
	int index;

	BUG_ON(start_index > PTRS_PER_PGD || end_index > PTRS_PER_PGD ||
			start_index >= end_index);
	BUG_ON(MMU_IS_SEPARATE_PT() && end_index > USER_PTRS_PER_PGD);
	for (index = start_index; index < end_index; index++) {
		DebugPA("clear_pgd_range() clear pgd #%d 0x%px = 0x%lx\n",
			index,
			&dst_pgd[index], pgd_val(dst_pgd[index]));
		dst_pgd[index] = __pgd(0);
	}
}

static inline void
copy_pgd_range(pgd_t *dst_pgd, pgd_t *src_pgd, int start_index, int end_index)
{
	int index;

	BUG_ON(start_index > PTRS_PER_PGD || end_index > PTRS_PER_PGD ||
			start_index >= end_index);
	BUG_ON(MMU_IS_SEPARATE_PT() && end_index > USER_PTRS_PER_PGD);
	for (index = start_index; index < end_index; index++) {
		dst_pgd[index] = src_pgd[index];
		DebugPA("copy_pgd_range() copy pgd #%d 0x%px = 0x%lx to "
			"pgd 0x%px\n",
			index,
			&src_pgd[index], pgd_val(src_pgd[index]),
			&dst_pgd[index]);
	}
}

static inline void
copy_kernel_pgd_range(pgd_t *dst_pgd, pgd_t *src_pgd)
{
	copy_pgd_range(dst_pgd, src_pgd, USER_PTRS_PER_PGD, PTRS_PER_PGD);
}

static inline void
set_pgd_range(pgd_t *dst_pgd, pgd_t pgd_to_set, int start_index, int end_index)
{
	int index;

	BUG_ON(start_index > PTRS_PER_PGD);
	BUG_ON(end_index > PTRS_PER_PGD);
	BUG_ON(start_index >= end_index);
	BUG_ON(MMU_IS_SEPARATE_PT() && end_index > USER_PTRS_PER_PGD);
	for (index = start_index; index < end_index; index++) {
		dst_pgd[index] = pgd_to_set;
		DebugPA("set_pgd_range() set pgd #%d 0x%px to 0x%lx\n",
			index,
			&dst_pgd[index], pgd_val(pgd_to_set));
	}
}

static inline void
set_kernel_pgd_range(pgd_t *dst_pgd, pgd_t pgd_to_set)
{
	set_pgd_range(dst_pgd, pgd_to_set, USER_PTRS_PER_PGD, PTRS_PER_PGD);
}

#endif /* _E2K_PGD_H */
