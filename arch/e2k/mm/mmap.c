#include <linux/mm.h>
#include <linux/mman.h>

#include <asm/process.h>

#define	DEBUG_MMP_MODE		0	/* Memory mapping in protected mode */
#define DebugMMP(...)		DebugPrint(DEBUG_MMP_MODE ,##__VA_ARGS__)


#ifdef CONFIG_PROTECTED_MODE
unsigned long
get_protected_unmapped_area(struct file *filp, unsigned long addr,
			    unsigned  long len, unsigned long pgsz)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct * vmm;
	unsigned long start_addr;
	
	DebugMMP("started for addr 0x%lx len 0x%lx\n",
		addr, len);
	if (mm->context.mmap_position < TASK32_SIZE) {
		/* first 2**32 is reserved for fixed map */
		mm->context.mmap_position = TASK32_SIZE;
	}
	if (addr < TASKP_SIZE) {
		if (len > (TASKP_SIZE - mm->context.mmap_position)) {
			DebugMMP("get_protected_unmapped_area(). ENOMEM len(0x%lx) > (TASK32_SIZE - TASK_UNMAPPED_BASE)(0x%lx)\n",
				len, TASK32_SIZE - TASK_UNMAPPED_BASE);
			return -ENOMEM;
		}
		addr = mm->context.mmap_position;
	} else if (len > (TASK_SIZE - TASKP_SIZE)) {
		DebugMMP("get_protected_unmapped_area(). ENOMEM. addr = 0x%lx; len(0x%lx) > (TASK_SIZE - TASK32_SIZE)(0x%lx)\n",
			addr, len, TASK_SIZE - TASK32_SIZE);
		return -ENOMEM;
	}
	start_addr = addr = ALIGN(addr, pgsz);
	DebugMMP("startaddr = 0x%lx; mmap_position = 0x%lx\n",
			start_addr, mm->context.mmap_position);
full_search:
	for (vmm = find_vma(mm, addr); ; vmm = vmm->vm_next) {
		/* It's a usual case */
		if (start_addr < TASKP_SIZE) {
			addr = ALIGN(addr, pgsz);
			if (TASKP_SIZE - len < addr) {
				DebugMMP("get_protected_unmapped_area(). ENOMEM. TASKP_SIZE - len(0x%lx) < addr(0x%lx)\n",
				TASKP_SIZE - len, addr);
				return -ENOMEM;
			}
			mm->context.mmap_position = addr + len;
			DebugMMP("addr found = 0x%lx\n",
				addr);
			return addr;
		}
		/* special case for hw stacks */
		if ((TASK_SIZE - len) < addr) {
			if (start_addr != TASKP_SIZE) {
				/*
				 * may be some holes missed before start addr
				 */
				start_addr = TASKP_SIZE;
				addr = TASKP_SIZE;
				goto full_search;
			} else {
				DebugMMP("get_protected_unmapped_area(). ENOMEM.");
				return -ENOMEM;
			}
		}
		if (!vmm || addr + len <= vmm->vm_start) {
			DebugMMP("protected addr found = 0x%016lx\n", addr);
			return addr;
		}
		addr = vmm->vm_end;
	}
}
#endif

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
	struct vm_unmapped_area_info info;
	unsigned long begin, end, address;

	if (flags & MAP_FIXED) {
		if (!test_ts_flag(TS_KERNEL_SYSCALL) &&
				(addr >= USER_HW_STACKS_BASE ||
				 addr + len >= USER_HW_STACKS_BASE))
			return -ENOMEM;

		return addr;
	}

	begin = (addr) ?: TASK_UNMAPPED_BASE;
	end = test_ts_flag(TS_KERNEL_SYSCALL) ? TASK_SIZE : USER_HW_STACKS_BASE;

#ifdef CONFIG_PROTECTED_MODE
	if (current->thread.flags & E2K_FLAG_PROTECTED_MODE) {
		if (flags & MAP_FIRST32) {
			end = TASK32_SIZE;
		} else {
			return get_protected_unmapped_area(filp, addr,
					   (unsigned long long)len, PAGE_SIZE);
		}
	}
#endif

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
	info.length = len + 2 * PAGE_SIZE;
	info.low_limit = begin;
	info.high_limit = end;
	info.align_mask = 0;
	info.align_offset = 0;

	address = vm_unmapped_area(&info);

	if (IS_ERR_VALUE(address)) {
		info.length = len;

		address = vm_unmapped_area(&info);
	} else {
		/*
		 * We want to insert a hole between WC and cacheable
		 * mappings to reduce performance loss when prefetches
		 * from a cacheable area land into non-cacheable one.
		 */
		address += PAGE_SIZE;
	}

	return address;
}

/*
 * This function, called very early during the creation of a new
 * process VM image, sets up which VM layout function to use:
 */
void arch_pick_mmap_layout(struct mm_struct *mm)
{
	mm->mmap_base = TASK_UNMAPPED_BASE;
	mm->get_unmapped_area = arch_get_unmapped_area;
}
