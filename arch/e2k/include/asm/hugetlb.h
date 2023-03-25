#pragma once

#include <linux/mm_types.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

static inline void arch_clear_hugepage_flags(struct page *page)
{
}

static inline int is_hugepage_only_range(struct mm_struct *mm,
		unsigned long addr, unsigned long len)
{
	return 0;
}

#include <asm-generic/hugetlb.h>
