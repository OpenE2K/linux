/*
 * Lockless get_user_pages_fast for e2k
 */
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/highmem.h>
#include <linux/delay.h>

#include <asm/pgtable.h>
#include <asm/mmu_regs_access.h>

/**
 * get_user_pages_fast() - pin user pages in memory
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @write:	whether pages will be written to
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_pages long.
 *
 * Attempt to pin user pages in memory without taking mm->mmap_sem.
 * If not successful, it will fall back to taking the lock and
 * calling get_user_pages().
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno.
 */
int get_user_pages_fast(unsigned long start, int nr_pages, int write,
			struct page **pages)
{
	struct mm_struct *mm = current->mm;
	unsigned long addr, len, end;
	int nr = 0;
	int ret = -EFAULT;

	start &= PAGE_MASK;
	len = (unsigned long) nr_pages << PAGE_SHIFT;

	if (!access_ok(write ? VERIFY_WRITE : VERIFY_READ,
		(void __user *) start, len))
		return ret;

	end = start + len;
	addr = start;

	local_irq_disable();
	do {
		probe_entry_t	entry = get_MMU_DTLB_ENTRY(addr);
		unsigned long	entry_val = probe_entry_val(entry);
		unsigned long	phys_addr;
		struct page	*page;

		if ((entry_val & ~DTLB_EP_RES) ||
				!(entry_val & DTLB_ENTRY_VVA) ||
				write && !(entry_val & _PAGE_W))
			goto slow;

		phys_addr = entry_val & DTLB_ENTRY_PHA;
		page = pfn_to_page(phys_addr >> PAGE_SHIFT);
		pages[nr] = page;
		get_page(page);
		nr++;
		addr += PAGE_SIZE;
	} while (addr != end);
	local_irq_enable();

	VM_BUG_ON(nr != (end - start) >> PAGE_SHIFT);

	return nr;

slow:
	local_irq_enable();

	/* Try to get the remaining pages with get_user_pages */
	start += nr << PAGE_SHIFT;
	pages += nr;

	down_read(&mm->mmap_sem);
	ret = get_user_pages(current, mm, start,
		(end - start) >> PAGE_SHIFT, write, 0, pages, NULL);
	up_read(&mm->mmap_sem);

	/* Have to be a bit careful with return values */
	if (nr > 0) {
		if (ret < 0)
			ret = nr;
		else
			ret += nr;
	}

	return ret;
}
