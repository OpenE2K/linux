/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Define no-op hooks to be included in asm/mmu_context.h
 * for arch e2k.
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

static inline bool arch_vma_access_permitted(struct vm_area_struct *vma,
		bool write, bool execute, bool foreign)
{
	if (vma->vm_flags & VM_PRIVILEGED) {
		/* We have only hardware and signal
		 * stacks in VM_PRIVILEGED area */
		if (execute)
			return false;

		if (!test_ts_flag(TS_KERNEL_SYSCALL))
			return false;
	}

	return true;
}
#endif	/* _ASM_E2K_MM_HOOKS_H */
