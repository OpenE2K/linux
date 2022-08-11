#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/random.h>
#include <linux/sched/mm.h>

#ifdef	CONFIG_DRM
#include <drm/drmP.h>
#endif	/* CONFIG_DRM */

#include <linux/security.h>

#include <asm/process.h>


#define	DEBUG_MMP_MODE		0	/* Memory mapping in protected mode */
#define DebugMMP(...)		DebugPrint(DEBUG_MMP_MODE ,##__VA_ARGS__)


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
	unsigned long begin, end, ret, hole_size;
	unsigned long is_protected = TASK_IS_PROTECTED(current);
	unsigned long is_32bit = (current->thread.flags & E2K_FLAG_32BIT) &&
				 !is_protected;

	if (flags & MAP_FIXED) {
		if (!test_ts_flag(TS_KERNEL_SYSCALL)) {
			if (addr >= USER_HW_STACKS_BASE ||
			    addr + len >= USER_HW_STACKS_BASE)
				return -ENOMEM;

			if (!TASK_IS_BINCO(current) && is_32bit &&
					(addr >= TASK32_SIZE ||
					 addr + len >= TASK32_SIZE))
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
		end = min(end, USER_HW_STACKS_BASE);
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

	hole_size = 0;
#ifdef	CONFIG_DRM
	if (cpu_has(CPU_HWBUG_PIO_READS)) {
		if (filp && filp->f_op && (filp->f_op->open == &drm_open))
			hole_size = 15 * PAGE_SIZE;
	}
#endif	/* CONFIG_DRM */

	info.flags = 0;
	info.length = len + 2 * hole_size;
	info.low_limit = begin;
	info.high_limit = end;
	info.align_mask = 0;
	info.align_offset = 0;

	ret = vm_unmapped_area(&info);
	if (!(ret & ~PAGE_MASK))
		ret += hole_size;

	return ret;
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
 * This function is based on vm_munmap() function.
 */
int vm_munmap_notkillable(unsigned long start, size_t len)
{
	struct mm_struct *mm = current->mm;
	unsigned long ts_flag;
	int ret;

	down_write(&mm->mmap_sem);
	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = do_munmap(mm, start, len, NULL);
	clear_ts_flag(ts_flag);
	up_write(&mm->mmap_sem);

	return ret;
}

/*
 * This function is based on vm_mmap() function.
 */
unsigned long vm_mmap_notkillable(struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot,
	unsigned long flag, unsigned long offset)
{
	unsigned long ret, populate, ts_flag;
	struct mm_struct *mm = current->mm;

	if (unlikely(offset + PAGE_ALIGN(len) < offset))
		return -EINVAL;
	if (unlikely(offset_in_page(offset)))
		return -EINVAL;

	ret = security_mmap_file(file, prot, flag);
	if (!ret) {
		down_write(&mm->mmap_sem);
		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		ret = do_mmap_pgoff(file, addr, len, prot, flag,
				    offset >> PAGE_SHIFT, &populate, NULL);
		clear_ts_flag(ts_flag);
		up_write(&mm->mmap_sem);
		if (populate)
			mm_populate(ret, populate);
	}
	return ret;
}
