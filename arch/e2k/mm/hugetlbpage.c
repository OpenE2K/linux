/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * E2K Huge TLB page support.
 */

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/sysctl.h>

#include <asm/mman.h>
#include <asm/pgalloc.h>

/*
 * pmd_huge() returns 1 if @pmd is hugetlb related entry, that is normal
 * hugetlb entry or non-present (migration or hwpoisoned) hugetlb entry.
 * Otherwise, returns 0.
 *
 * Do NOT use this for anything but checking for _possible_ _HugeTLB_ entry.
 */
int pmd_huge(pmd_t pmd)
{
	return !pmd_none(pmd) && _PAGE_GET(pmd_val(pmd),
					   UNI_PAGE_PRESENT | UNI_PAGE_HUGE) !=
						_PAGE_INIT_PRESENT;
}

int pud_huge(pud_t pud)
{
	return user_pud_huge(pud);
}

bool __init arch_hugetlb_valid_size(unsigned long size)
{
	if (size == PMD_SIZE) {
		return true;
	} else if (size == PUD_SIZE && cpu_has(CPU_FEAT_ISET_V5)) {
		return true;
	} else {
		return false;
	}
}

#ifdef CONFIG_CONTIG_ALLOC
__init
static int gigantic_pages_init(void)
{
	/* With compaction or CMA we can allocate gigantic pages at runtime */
	if (cpu_has(CPU_FEAT_ISET_V5) && !size_to_hstate(1UL << PUD_SHIFT))
		hugetlb_add_hstate(PUD_SHIFT - PAGE_SHIFT);

	return 0;
}
arch_initcall(gigantic_pages_init);
#endif

#ifdef HAVE_ARCH_HUGETLB_UNMAPPED_AREA
unsigned long
hugetlb_get_unmapped_area(struct file *file, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct hstate *h = hstate_file(file);
	struct vm_unmapped_area_info info;
	unsigned long begin, end;
	unsigned long is_protected = TASK_IS_PROTECTED(current);
	unsigned long is_32bit = (current->thread.flags & E2K_FLAG_32BIT) &&
				 !is_protected;

	if (len & ~huge_page_mask(h))
		return -EINVAL;

	if (len > TASK_SIZE)
		return -ENOMEM;

	if (flags & MAP_FIXED) {
		if (!test_ts_flag(TS_KERNEL_SYSCALL) &&
				(addr >= USER_ADDR_MAX ||
				 addr + len >= USER_ADDR_MAX))
			return -ENOMEM;
		if (prepare_hugepage_range(file, addr, len))
			return -EINVAL;
		return addr;
	}

	begin = (addr) ?: mm->mmap_base;
	if (!test_ts_flag(TS_KERNEL_SYSCALL)) {
		if (is_32bit || is_protected && (flags & MAP_FIRST32))
			end = TASK32_SIZE;
		else
			end = TASK_SIZE;
		end = min(end, USER_ADDR_MAX);
	} else {
		end = TASK_SIZE;
	}

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (TASK_IS_BINCO(current) && ADDR_IN_SS(addr)) {
		end = min(end, SS_ADDR_END);
		/* Lower mremap() address for binary compiler
		 * must be >= ss_rmp_bottom */
		if (current_thread_info()->ss_rmp_bottom > addr)
			begin = current_thread_info()->ss_rmp_bottom;
	}
#endif

	info.flags = 0;
	info.length = len;
	info.low_limit = begin;
	info.high_limit = end;
	info.align_mask = PAGE_MASK & ~huge_page_mask(h);
	info.align_offset = 0;

	return vm_unmapped_area(&info);
}
#endif	/* HAVE_ARCH_HUGETLB_UNMAPPED_AREA */

