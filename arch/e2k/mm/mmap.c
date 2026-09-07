/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/elf-randomize.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/random.h>
#include <linux/sched/mm.h>

#ifdef	CONFIG_DRM
#include <drm/drmP.h>
#endif	/* CONFIG_DRM */

#include <linux/security.h>

#include <asm/process.h>


/*
 * You really shouldn't be using read() or write() on /dev/mem.
 * This might go away in the future.
 *
 * Can we access it for direct reading/writing? Must be RAM:
 */
int valid_phys_addr_range(phys_addr_t addr, size_t count)
{
	return addr + count - 1 <= __pa(high_memory - 1);
}

/* Can we access it through mmap? Must be a valid physical address: */
int valid_mmap_phys_addr_range(unsigned long pfn, size_t count)
{
	phys_addr_t addr = (phys_addr_t) pfn << PAGE_SHIFT;

	return !((addr + count - 1) >> MAX_POSSIBLE_PHYSMEM_BITS);
}


/* Get an address range which is currently unmapped.
 * For mmap() without MAP_FIXED and shmat() with addr=0.
 *
 * Ugly calling convention alert:
 * Return value with the low bits set means error value,
 * ie
 *	if (ret & ~PAGE_MASK)
 *		error = ret;
 *
 * This function "knows" that -ENOMEM has the bits set.
 */
unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		       unsigned long len, unsigned long pgoff,
		       unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_unmapped_area_info info;
	unsigned long begin, end;
	unsigned long is_protected = TASK_IS_PROTECTED(current);
	unsigned long is_32bit = (current->thread.flags & E2K_FLAG_32BIT) &&
				 !is_protected;

	if (is_protected && !cpu_has(CPU_FEAT_V7_CPU_REGS) && (len >> 31)) {
		return -ENOMEM;
	}
	if (flags & MAP_FIXED) {
		if (!test_ts_flag(TS_KERNEL_SYSCALL)) {
			if (!__range_ok(addr, len, USER_ADDR_MAX))
				return -ENOMEM;

			if (!TASK_IS_BINCO(current) && is_32bit &&
					!__range_ok(addr, len, TASK32_SIZE))
				return -ENOMEM;
		}

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
	info.align_mask = 0;
	info.align_offset = 0;
	if (is_protected && cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		unsigned long align_mask = ap_align_mask(len);
		info.length = ((len + align_mask) & ~align_mask);
		info.align_mask = align_mask;
	}

	return vm_unmapped_area(&info);
}

unsigned long arch_mmap_rnd(void)
{
	unsigned long rnd;

#ifdef CONFIG_COMPAT
	if (current->thread.flags & (E2K_FLAG_32BIT | E2K_FLAG_PROTECTED_MODE))
		rnd = get_random_long() & ((1UL << mmap_rnd_compat_bits) - 1);
	else
#endif
		rnd = get_random_long() & ((1UL << mmap_rnd_bits) - 1);
	return rnd << PAGE_SHIFT;
}

/*
 * This function, called very early during the creation of a new
 * process VM image, sets up which VM layout function to use:
 */
void arch_pick_mmap_layout(struct mm_struct *mm, struct rlimit *rlim_stack)
{
	unsigned long random_factor = 0UL;

	if (current->flags & PF_RANDOMIZE)
		random_factor = arch_mmap_rnd();

	mm->mmap_base = TASK_UNMAPPED_BASE + random_factor;
	mm->get_unmapped_area = arch_get_unmapped_area;
}

/*
 * A version of vm_munmap() for VM_PRIVILEGED areas that is
 * not interrupted by signals (to avoid messy error handling).
 */
int vm_munmap_notkillable(unsigned long start, size_t len)
{
	struct mm_struct *mm = current->mm;
	int ret;

	mmap_write_lock(mm);
	ret = do_munmap(mm, start, len, NULL);
	mmap_write_unlock(mm);

	return ret;
}

/*
 * A version of vm_mmap() for VM_PRIVILEGED areas that is
 * not interrupted by signals (to avoid messy error handling).
 */
unsigned long vm_mmap_notkillable(struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot,
	unsigned long flag, unsigned long offset)
{
	unsigned long ret, populate;
	struct mm_struct *mm = current->mm;

	if (unlikely(offset + PAGE_ALIGN(len) < offset))
		return -EINVAL;
	if (unlikely(offset_in_page(offset)))
		return -EINVAL;

	ret = security_mmap_file(file, prot, flag);
	if (!ret) {
		mmap_write_lock(mm);
		ret = do_mmap(file, addr, len, prot, flag, offset >> PAGE_SHIFT,
			      &populate, NULL);
		mmap_write_unlock(mm);
		if (populate)
			mm_populate(ret, populate);
	}
	return ret;
}
