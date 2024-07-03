/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E2K_MM_HOOKS_H
#define _ASM_E2K_MM_HOOKS_H

#include <asm/kvm/mm_hooks.h>

extern int arch_dup_mmap(struct mm_struct *oldmm, struct mm_struct *mm);
extern void arch_exit_mmap(struct mm_struct *mm);

static inline void arch_unmap(struct mm_struct *mm,
			unsigned long start, unsigned long end)
{
}

static inline void arch_bprm_mm_init(struct mm_struct *mm,
				     struct vm_area_struct *vma)
{
}

static inline int arch_bprm_mm_init_locked(struct mm_struct *mm,
				     struct vm_area_struct *vma)
{
	return get_mm_notifier_locked(mm);
}

extern bool arch_vma_access_permitted(struct vm_area_struct *vma,
		bool write, bool execute, bool foreign);

#endif	/* _ASM_E2K_MM_HOOKS_H */
