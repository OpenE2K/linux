/*  $Id: tag_mem.c,v 1.10 2009/12/10 17:34:00 kravtsunov_e Exp $
 *  arch/e2k/mm/tag_mem.c
 *
 * Tag's memory management
 *
 * Copyright 2003 Salavat S. Guiliazov (atic@mcst.ru)
 */
 
#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>

#include <asm/types.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tag_mem.h>
#include <asm/swap_info.h>

#undef	DEBUG_TAG_MODE
#undef	DebugTM
#define	DEBUG_TAG_MODE		0	/* Tag memory */
#define DebugTM(...)		DebugPrint(DEBUG_TAG_MODE ,##__VA_ARGS__)


/* Cache for swap_info_t structs */
kmem_cache_t* swap_info_cache = NULL;

atomic_t launder_count = ATOMIC_INIT(0);

/*
 * Create a new vma struct for the tags area map from the specified
 * begining address of tags area to the end adress of this area.
 */

static struct vm_area_struct *
create_new_tag_mmap(struct mm_struct *mm, e2k_addr_t tag_start,
	e2k_addr_t tag_end)
{
	struct vm_area_struct *tag_vma;
	struct vm_area_struct *vma_start;
	struct vm_area_struct *vma_end;

	/*
	 * Check an intersection with the previous and next tags areas maps
	 * It possible if the end of the previous data VM area and the
	 * begining of the new area are into the same page of tags and/or
	 * the begining of the next data VM area and the end of the new area
	 * are into one tags page.
	 */

	DebugTM("will start find_vma() for tags area "
		"start page 0x%lx\n", tag_start);
	vma_start = find_vma(mm, tag_start);
	if (vma_start && vma_start->vm_start <= tag_start) {
		DebugTM("found VMA 0x%p intersected with "
			"tags area start page\n", vma_start);
		tag_start = vma_start->vm_end;
		DebugTM("set new tag page start addr to "
			"end of intersected area 0x%lx\n", tag_start);
		if (tag_start >= tag_end) {
			DebugTM("returns : tag page was "
				"included to old tage page VMA\n");
			return vma_start;
		}
	}
	DebugTM("will start find_vma() for tags area "
		"end page 0x%lx\n", tag_end);
	vma_end = find_vma(mm, tag_end);
	if (vma_end && vma_end->vm_start < tag_end) {
		DebugTM("found VMA 0x%p intersected with "
			"tags area end page\n", vma_end);
		tag_end = vma_end->vm_start;
		DebugTM("set new tag page end addr to "
			"start of intersected area 0x%lx\n", tag_end);
		if (tag_start >= tag_end) {
			DebugTM("returns : tag page was "
				"included to old tage page VMA\n");
			return vma_end;
		}
	}

	/*
	 * Create a new vma struct for the tags area mapping
	 */

	DebugTM("will start kmem_cache_alloc()\n");
	tag_vma = kmem_cache_zalloc(vm_area_cachep, SLAB_ATOMIC);
	DebugTM("kmem_cache_alloc() returned vma 0x%p\n",
		tag_vma);
	if (!tag_vma)
		return NULL;	/* no memory */

	tag_vma->vm_mm = mm;
	tag_vma->vm_start = tag_start;
	tag_vma->vm_end = tag_end;
	tag_vma->vm_flags = TAG_VM_FLAGS;
	tag_vma->vm_page_prot = PAGE_TAG_MEMORY;
	tag_vma->vm_ops = NULL;
	tag_vma->vm_pgoff = 0;
	tag_vma->vm_file = NULL;
	tag_vma->vm_private_data = NULL;
	DebugTM("vma->vm_start 0x%lx vm_end 0x%lx\n",
		tag_vma->vm_start, tag_vma->vm_end);

	DebugTM("will start insert_vm_struct()\n");
	__insert_vm_struct(mm, tag_vma);

	/*
	 * Virtual memory for tags maps should not be taken
	 * into account* as it is imposed by kernel???
	 */

//	mm->total_vm += ((tag_end - tag_start) >> PAGE_SHIFT);
//	DebugTM("create_new_tag_mmap() mm->total_vm 0x%lx\n", mm->total_vm);

#ifdef	CONFIG_MAKE_ALL_PAGES_VALID
	if (tag_vma->vm_flags & VM_PAGESVALID) {
		int ret;
		DebugTM("starts make_vma_pages_valid() "
			"for VMA 0x%p\n", tag_vma);
		ret = make_vma_pages_valid(tag_vma, tag_start, tag_end);
		if (ret != 0) {
			DebugTM("make_vma_pages_valid() "
				"finished with error %d\n",
				ret);
			kmem_cache_free(vm_area_cachep, tag_vma);
			return NULL;
		}
		DebugTM("make_vma_pages_valid() finished "
			"OK\n");
	}
#endif	/* CONFIG_MAKE_ALL_PAGES_VALID */

	if (tag_vma->vm_flags & VM_LOCKED) {
		/*
		 * Locked memory for tags maps should not be taken
		 * into account as it is imposed by kernel???
		 */
//		mm->locked_vm += ((tag_end - tag_start) >> PAGE_SHIFT);

		DebugTM("will do __get_user_pages()\n");
		__get_user_pages(current, current->mm, tag_start,
			      (tag_end - tag_start) / PAGE_SIZE,
			      FOLL_TOUCH | FOLL_MLOCK | FOLL_WRITE | FOLL_FORCE,
			      NULL, NULL, NULL);
	}
	DebugTM("finished for tag area from start addr "
		"0x%lx to end addr 0x%lx\n", tag_start, tag_end);
	return tag_vma;
}

/*
 * Map tags memory area approoriate to specified virtual address of data.
 * Function maps all VM area containing specified virtual address.
 * One page of tags memory can contain tags from a few VM areas of data.
 * In maximal case up to 16 pages from different VM areas (if VMA consists
 * of one page).
 * Here it is supposed that tags memories are not unmapped while unmapping
 * the appropriate VM area of data.
 */

static struct vm_area_struct *
do_tag_mmap(struct mm_struct *mm, e2k_addr_t data_addr)
{
	e2k_addr_t tag_start;
	e2k_addr_t tag_end;
	e2k_addr_t prev_end = 0;
	e2k_addr_t next_start = TASK_SIZE;
	struct vm_area_struct *data_vma;
	struct vm_area_struct *prev_vma;
	struct vm_area_struct *tag_vma;
	unsigned long grow;
	int ret;

	DebugTM("started for addr 0x%lx\n", data_addr);

	/*
	 * Find VM area which contains address specified by arg. 'data_addr'
	 * Tags of full VM area should be mapped to appropriate virtual
	 * user space.
	 */

	DebugTM("will start find_vma() for data addr 0x%lx\n",
		data_addr);
	data_vma = find_vma_prev(mm, data_addr, &prev_vma);
	if (data_vma == NULL || data_vma->vm_start > data_addr) {
		printk("do_tag_mmap(): find_vma() could not find VMA for "
			"data addr 0x%lx\n", data_addr);
		BUG();
		return NULL;
	}
	DebugTM("find_vma() returned VMA from 0x%lx to 0x%lx\n",
		data_vma->vm_start, data_vma->vm_end);
	if (prev_vma != NULL)
		prev_end = prev_vma->vm_end;
	if (data_vma->vm_next != NULL)
		next_start = data_vma->vm_next->vm_start;
	DebugTM("previous VMA end is 0x%lx, next VMA start is "
		"0x%lx\n", prev_end, next_start);

	/*
	 * Transform the starting and final addresses of VM area of the data
	 * to appropriate addresses of tags VM area.
	 * One page of tags memory consists of 16 pages of data
	 * VM area should be page aligned, so the starting address of tags
	 * VM area is aligned to the begining of the page and the final address
	 * is aligned to the end of page
	 */

	tag_start = PAGE_ALIGN_UP(virt_to_tag(data_vma->vm_start));
	tag_end = PAGE_ALIGN_DOWN(virt_to_tag(data_vma->vm_end));
	DebugTM("tag page start addr 0x%lx, end addr 0x%lx\n",
		tag_start, tag_end);
	if (tag_start >= tag_end) {
		printk("do_tag_mmap(): tag pages start addr 0x%lx >= end "
			"addr 0x%lx\n",
			tag_start, tag_end);
		BUG();
		return NULL;
	}

	/*
	 * If the tags of the data VM area were not mapped yet to virtual
	 * space then we should create new VM area of tags and clear old
	 * maps. Old maps will be cleared from end of the previous VMA to
	 * start of the next VMA to release the possible hanged old maps.
	 */

	if (!(data_vma->vm_flags & VM_TAGMAPPED)) {
		DebugTM("tags of the data VMA were not mapped "
			"yet : call do_tag_munmap() to unmap tag memory of "
			"the data from 0x%lx to 0x%lx\n",
			prev_end, next_start);
		ret = do_tag_munmap(mm, prev_end, next_start - prev_end);
		if (ret != 0) {
			DebugTM("do_tag_munmap() returned "
				"error %d\n", ret);
			return NULL;
		}
		DebugTM("do_tag_munmap() cleared old maps\n");
		DebugTM("is starting create_new_tag_mmap() "
			"for tags area from 0x%lx to 0x%lx\n",
			tag_start, tag_end);
		tag_vma = create_new_tag_mmap(mm, tag_start, tag_end);
		if (tag_vma != NULL)
			data_vma->vm_flags |= VM_TAGMAPPED;
		return tag_vma;
	}

	/*
	 * Further a case when the tags of the data VM area were already
	 * mapped to virtual space. It means that data VM area was expanded
	 * from left (low addresses : do_brk()) and/or from right (high
	 * addresses : stack expansion), so it needs find existing VMA
	 * of tags area and expand it from left/right
	 */

	DebugTM("tags of the data VMA were already mapped\n");

	/*
	 * Clear the possible hanged old tags maps from end of the previous VMA
	 * to the start of the current VMA and from end of the current VMA to
	 * the start of the next VMA
	 */

	if (data_vma->vm_start > prev_end) {
		DebugTM("will start do_tag_munmap() to unmap "
			"tag memory of the data from previous end 0x%lx to "
			"start of our area 0x%lx\n",
			prev_end, data_vma->vm_start);
		ret = do_tag_munmap(mm, prev_end, data_vma->vm_start -
								prev_end);
		if (ret != 0) {
			DebugTM("do_tag_munmap() returned "
				"error %d\n", ret);
			return NULL;
		}
		DebugTM("do_tag_munmap() cleared old left (low "
			"addresses) maps\n");
	}

	if (next_start > data_vma->vm_end) {
		DebugTM("will start do_tag_munmap() to unmap "
			"tags memory of the data from our area end 0x%lx to "
			"start of the next area 0x%lx\n",
			data_vma->vm_end, next_start);
		ret = do_tag_munmap(mm, data_vma->vm_end,
						next_start - data_vma->vm_end);
		if (ret != 0) {
			DebugTM("do_tag_munmap() returned "
				"error %d\n", ret);
			return NULL;
		}
		DebugTM("do_tag_munmap() cleared old right "
			"(high addresses) maps\n");
	}

	/*
	 * Find VMA of the tags area appropriate to the initial data area
	 * which it was expanded later.
	 * First search the new starting address of tags area, probably the
	 * data area was expanded from the start ('expand_stack()').
	 */

	DebugTM("will start find_vma() for tags area "
		"start addr 0x%lx\n", tag_start);
	tag_vma = find_vma(mm, tag_start);
	if (tag_vma == NULL) {
		printk("do_tag_mmap(): find_vma() could not find VMA of "
			"the mapped earlier tags area with starting addr "
			"0x%lx\n", tag_start);
		BUG();
		return NULL;
	}
	if (tag_vma->vm_start > tag_start) {
		DebugTM("found VMA from 0x%lx to 0x%lx "
			"not intersected with the tags area start addr\n",
			tag_vma->vm_start, tag_vma->vm_end);
		/*
		 * Similar the data area was expanded at the left
		 * (removed the starting address ('expand_stack()'))
		 * Expand VMA of tags area at the left
		 */
		grow = tag_vma->vm_start - tag_start;
		DebugTM("similar the data area was expanded "
			"at the left from 0x%lx to 0x%lx\n",
			tag_vma->vm_start, tag_start);
		tag_vma->vm_start = tag_start;
		tag_vma->vm_pgoff -= grow;
		DebugTM("tags area VMA expanded from "
			"left ; start addr moved to 0x%lx\n",
			tag_vma->vm_start);
	} else {
		DebugTM("found VMA from 0x%lx to 0x%lx "
			"intersected with the tags area start addr\n",
			tag_vma->vm_start, tag_vma->vm_end);
	}
	
	/*
	 * If the next VMA intersects with new tags area then
	 * it will be considered as main VMA, which should be
	 * expanded
	 */
	if (tag_vma->vm_next == NULL) {
		DebugTM("next VMA does not exist\n");
		prev_vma = NULL;
	} else if (tag_vma->vm_next->vm_start < tag_end) {
		/*
		 * The next VMA is considered as main VMA, which
		 * should be expanded
		 */
		DebugTM("next VMA from 0x%lx to 0x%lx "
			"will be considered as main VMA to expand\n",
			tag_vma->vm_next->vm_start,
			tag_vma->vm_next->vm_end);
		prev_vma = tag_vma;
		tag_vma = tag_vma->vm_next;
	} else {
		DebugTM("next VMA exists but has not "
			"intersection with our tags area\n");
		prev_vma = NULL;
	}
	if (prev_vma != NULL) {
		grow = tag_vma->vm_start - prev_vma->vm_end;
		if (grow > 0) {
			/*
			 * There is a hole between previous VMA. where
			 * tags area starts and main VMA where tags area
			 * continues.
			 * Expand main VMA from left (low addresses)
			 */
			DebugTM("there is a hole between "
				"previous VMA and main VMA\n");
			tag_vma->vm_start = prev_vma->vm_end;
			tag_vma->vm_pgoff -= grow;
			DebugTM("main VMA expanded from "
				"left ; start addr moved to 0x%lx\n",
				tag_vma->vm_start);
		}
	}

	/*
	 * Try to expand VMA of tags area from right (move the end),
	 * if it needs
	 */
	if (tag_vma->vm_end < tag_end) {
		DebugTM("VMA of tags area should be "
			"expanded from right : move end from 0x%lx "
			"to 0x%lx\n",
			tag_vma->vm_end, tag_end);
		if (tag_vma->vm_next && tag_vma->vm_next->vm_start < tag_end) {
			printk("do_tag_mmap(): ERROR there are at least"
				" 3 VMAs which intersects with tags "
				"area (3-th VMA from 0x%lx to 0x%lx\n",
				tag_vma->vm_next->vm_start,
				tag_vma->vm_next->vm_end);
			BUG();
			return NULL;
		}
		tag_vma->vm_end = tag_end;
		DebugTM("main VMA expanded from "
			"right ; ennd addr moved to 0x%lx\n",
			tag_vma->vm_end);
	}

	return tag_vma;
}

/*
 * We special-case the C-O-W ZERO_PAGE, because it's such
 * a common occurrence (no need to read the page to know
 * that it's zero - better for the cache and memory subsystem).
 */
static inline void
copy_cow_page(struct page * from, struct page * to, unsigned long address)
{
	if (is_zero_page(from)) {
		clear_user_highpage(to, address);
		return;
	}
	copy_user_highpage(to, from, address);
}

/*
 * Establish a new mapping:
 *  - flush the old one
 *  - update the page tables
 *  - inform the TLB about the new one
 */
static inline void
establish_tags_pte(struct vm_area_struct *vma, unsigned long address,
	pte_t *page_table, pte_t entry)
{
	DebugTM("set pte 0x%p to 0x%lx for addr 0x%lx\n",
		page_table, pte_val(entry), address);
	set_pte_at(vma->vm_mm, address, page_table, entry);
	flush_tlb_page(vma, address);
	update_mmu_cache(vma, address, entry);
}

static inline void
break_tags_cow(struct vm_area_struct *vma, struct page *old_page,
	struct page *new_page, unsigned long address, pte_t *page_table)
{
	DebugTM("will copy page pte 0x%p == 0x%lx for addr "
		"0x%lx\n",
		page_table, pte_val(*page_table), address);
	copy_cow_page(old_page, new_page, address);
	flush_page_to_ram(new_page);
	flush_cache_page(vma, address);
	establish_tags_pte(vma, address, page_table,
		pte_mkwrite(pte_mkdirty(mk_pte(new_page, vma->vm_page_prot))));
}

/*
 * This routine handles present pages, when users try to write
 * to a shared page. It is done by copying the page to a new address
 * and decrementing the shared-page counter for the old page.
 *
 * Goto-purists beware: the only reason for goto's here is that it results
 * in better assembly code.. The "default" path will see no jumps at all.
 *
 * Note that this routine assumes that the protection checks have been
 * done by the caller (the low-level page fault routine in most cases).
 * Thus we can safely just mark it writable once we've done any necessary
 * COW.
 *
 * We also mark the page dirty at this point even though the page will
 * change only once the write actually happens. This avoids a few races,
 * and potentially makes it more efficient.
 *
 * We enter with the page table read-lock held, and need to exit without
 * it.
 */
static int
do_wp_tags_page(struct mm_struct *mm, struct vm_area_struct *vma,
	unsigned long address, pte_t *page_table, pte_t pte)
{
	struct page *old_page, *new_page;

	DebugTM("will do writable page pte 0x%p == 0x%lx for "
		"addr 0x%lx\n",
		page_table, pte_val(pte), address);
	old_page = pte_page(pte);
	if (!VALID_PAGE(old_page))
		goto bad_wp_page;
	
	/*
	 * We can avoid the copy if:
	 * - we're the only user (count == 1)
	 * - the only other user is the swap cache,
	 *   and the only swap cache user is itself,
	 *   in which case we can just continue to
	 *   use the same swap cache (it will be
	 *   marked dirty).
	 */
	switch (page_count(old_page)) {
	case 2:
		/*
		 * Lock the page so that no one can look it up from
		 * the swap cache, grab a reference and start using it.
		 * Can not do lock_page, holding page_table_lock.
		 */
		if (!PageSwapCache(old_page) || TryLockPage(old_page))
			break;
		if (is_page_shared(old_page)) {
			UnlockPage(old_page);
			break;
		}
		UnlockPage(old_page);
		/* FallThrough */
	case 1:
		flush_cache_page(vma, address);
		establish_tags_pte(vma, address, page_table,
			pte_mkyoung(pte_mkdirty(pte_mkwrite(pte))));
		return 1;	/* Minor fault */
	}

	/*
	 * Ok, we need to copy. Oh, well..
	 */
	new_page = page_cache_alloc();
	if (!new_page)
		return -1;

	/*
	 * Re-check the pte - we dropped the lock
	 */
	if (pte_same(*page_table, pte)) {
		if (PageReserved(old_page))
			++mm->rss;
		break_tags_cow(vma, old_page, new_page, address, page_table);

		/* Free the old page.. */
		new_page = old_page;
	}
	page_cache_release(new_page);
	return 1;	/* Minor fault */

bad_wp_page:
	printk("do_wp_page: bogus page at address %08lx (page 0x%lx)\n",
		address, (unsigned long)old_page);
	return -1;
}

static int do_swap_tags_page(struct mm_struct * mm,
	struct vm_area_struct * vma, unsigned long address,
	pte_t * page_table, swp_entry_t entry, int write_access)
{
	struct page *page = lookup_swap_cache(entry);
	pte_t pte;

	if (!page) {
		lock_kernel();
		swapin_readahead(entry);
		page = read_swap_cache(entry);
		unlock_kernel();
		if (!page)
			return -1;

		flush_page_to_ram(page);
		flush_icache_page(vma, page);
	}
	
	mm->rss++;

	pte = mk_pte(page, vma->vm_page_prot);

	/*
	 * Freeze the "shared"ness of the page, ie page_count + swap_count.
	 * Must lock page before transferring our swap count to already
	 * obtained page count.
	 */
	lock_page(page);

	if (PageWithSwapInfo(page)) remove_swap_info_from_page(page);
	
	swap_free(entry);
	if (write_access && !is_page_shared(page))
		pte = pte_mkwrite(pte_mkdirty(pte));
	
	UnlockPage(page);
	set_pte_at(mm, address, page_table, pte);
	/* No need to invalidate - it was non-present before */
	update_mmu_cache(vma, address, pte);
	return 1;	/* Minor fault */
}

/*
 * do_no_page() tries to create a new page mapping. It aggressively
 * tries to share with existing pages, but makes a separate copy if
 * the "write_access" parameter is true in order to avoid the next
 * page fault.
 *
 * As this is called only for pages that do not currently exist, we
 * do not need to flush old virtual caches or the TLB.
 *
 * This is called with the MM semaphore held.
 */
static int
do_no_anonymous_tags_page(struct mm_struct * mm, struct vm_area_struct * vma,
	unsigned long address, int write_access, pte_t *page_table)
{
	struct page *page = NULL;
	pte_t entry;

	DebugTM("started for pte 0x%p == 0x%lx "
		"addr 0x%lx\n",
		page_table, pte_val(*page_table), address);
	entry = pte_wrprotect(mk_pte(ZERO_PAGE(address), vma->vm_page_prot));
	if (write_access) {
		page = alloc_page(GFP_ATOMIC);
		if (!page) 
			return -1;
		clear_user_highpage(page, address);
		entry = pte_mkwrite(pte_mkdirty(mk_pte(page,
							vma->vm_page_prot)));
		mm->rss++;
		flush_page_to_ram(page);
	}
	DebugTM("set pte 0x%p to 0x%lx\n",
		page_table, pte_val(entry));
	set_pte_at(mm, address, page_table, entry);
	/* No need to invalidate - it was non-present before */
	update_mmu_cache(vma, address, entry);
	return 1;	/* Minor fault */
}

/*
 * The function is same as 'handle_pte_fault()', but handles tags pages only
 * Note the "page_table_lock" should be locked by caller (by kswapd).
 *
 * The adding of pages is protected by the MM semaphore, which does not hold,
 * so we need to worry about a page being suddenly been added into
 * our VM.
 */
static inline int
handle_tags_pte_fault(struct mm_struct *mm,
	struct vm_area_struct * vma, e2k_addr_t address, int write_access,
	pte_t * pte)
{
	pte_t entry;

	DebugTM("started for address 0x%lx pte 0x%p == "
		"0x%lx\n", address, pte, pte_val(*pte));
	entry = *pte;
	if (!pte_present(entry)) {
		DebugTM("pte 0x%p == 0x%lx not "
			"present\n", pte, pte_val(*pte));
		if (pte_none(entry)) {
			DebugTM("will start "
				"do_no_anonymous_tags_page()\n");
			return do_no_anonymous_tags_page(mm, vma, address,
					write_access, pte);
		}
		DebugTM("tags page is swapped out, address is 0x%lx\n",
			address);
		return do_swap_tags_page(mm, vma, address, pte, pte_to_swp_entry(entry), write_access);
	}

	if (write_access) {
		if (!pte_write(entry)) {
			DebugTM("will start "
				"do_wp_tags_page()\n");
			return do_wp_tags_page(mm, vma, address, pte, entry);
		}

		DebugTM("will do pte_mkdirty()\n");
		entry = pte_mkdirty(entry);
	}
	DebugTM("will do pte_mkyoung()\n");
	entry = pte_mkyoung(entry);
	DebugTM("will start establish_pte()\n");
	establish_tags_pte(vma, address, pte, entry);
	DebugTM("returns 1\n");
	return 1;
}

/*
 * The function is the same as 'handle_mm_fault()', but makes present
 * tags pages only.
 * By the time we get here, we already hold the 'page_table_lock'
 */
static struct page *
make_tags_page_present(struct mm_struct *mm, struct vm_area_struct *vma,
	e2k_addr_t tags_addr, int write_access)
{
	pgd_t	*pgd;
	pud_t	*pud;
	pmd_t	*pmd;
	pte_t	*pte;
	int	ret;

	DebugTM("started addr 0x%lx\n", tags_addr);
	pgd = pgd_offset(mm, tags_addr);
	pud = pud_alloc(pgd, tags_addr);
	DebugTM("pud_alloc() returned PUD 0x%p\n",
		pud);
	if (pud == NULL) {
		DebugTM("pud_alloc() could not "
			"allocate PUD\n");
		return NULL;
	}
	pmd = pmd_alloc(pud, tags_addr);
	DebugTM("pmd_alloc() returned PMD 0x%p\n",
		pmd);
	if (pmd == NULL) {
		DebugTM("pmd_alloc() could not "
			"allocate PMD\n");
		return NULL;
	}
	pte = pte_alloc_map(pmd, tags_addr);
	DebugTM("pte_alloc_map() returned PTE 0x%p\n",
		pte);
	if (pte == NULL) {
		DebugTM("pte_alloc_map() could not "
			"allocate PTE\n");
		return NULL;
	}
/*
	if (pte_present(*pte)) {
		DebugTM("pte 0x%p == 0x%lx : "
			"tags page for addr 0x%lx is present already\n",
			pte, pte_val(*pte), tags_addr);
		return (pte_page(*pte));
	}
*/

	DebugTM("will start handle_tags_pte_fault() "
		"pte 0x%p for tags address 0x%lx\n", pte, tags_addr);
	ret = handle_tags_pte_fault(mm, vma, tags_addr, write_access, pte);
	if (ret <= 0) {
		DebugTM("handle_tags_pte_fault() "
			"returned error %d : could not make present page "
			"for tags addr 0x%lx\n", ret, tags_addr);
		return NULL;
	}
	DebugTM("returns with OK pte 0x%p == 0x%lx : "
			"tags page for addr 0x%lx is present now\n",
			pte, pte_val(*pte), tags_addr);
	return pte_page(*pte);
}

struct vm_area_struct *
create_tags_vma(struct mm_struct *mm, e2k_addr_t data_addr)
{
	e2k_addr_t tag_addr;
	struct vm_area_struct *vma;

	DebugTM("started for data addr 0x%lx\n", data_addr);

	tag_addr = virt_to_tag(data_addr);
	DebugTM("will start do_tag_mmap() for "
		"tag addr 0x%lx\n", tag_addr);
	vma = do_tag_mmap(mm, data_addr);
	if (vma == NULL) {
		DebugTM("do_tag_mmap() returned NULL for "
			"tag addr 0x%lx : out of memory\n", tag_addr);
		return NULL;
	}
	DebugTM("do_tag_mmap() returned VMA "
		"0x%p for tag addr 0x%lx\n", vma, tag_addr);
	DebugTM("will start find_vma() for tag addr "
		"0x%lx\n", tag_addr);
	vma = find_vma(mm, tag_addr);
	if (vma == NULL || vma->vm_start > tag_addr) {
		printk("create_tags_vma() : could not map tags "
			"area for data address 0x%lx\n",
			data_addr);
		BUG();
		return NULL;
	} else {
		DebugTM("find_vma() returned VMA "
			"0x%p\n", vma);
	}
	return vma;
}

static struct vm_area_struct *
get_tags_addr_vma(struct mm_struct *mm, e2k_addr_t data_addr)
{
	e2k_addr_t tags_addr;
	struct vm_area_struct *vma;

	DebugTM("started for data addr 0x%lx\n", data_addr);

	tags_addr = virt_to_tag(data_addr);
	DebugTM("will start find_vma() for tags addr "
		"0x%lx\n", tags_addr);
	vma = find_vma(mm, tags_addr);
	if (vma == NULL || vma->vm_start > tags_addr) {
		DebugTM("will start create_tags_vma() for "
			"tags addr 0x%lx\n", tags_addr);
		vma = create_tags_vma(mm, data_addr);
		if (vma == NULL) {
			DebugTM("create_tags_vma() "
				"returned NULL for tags addr 0x%lx : "
				"out of memory\n", tags_addr);
			return NULL;
		}
		DebugTM("create_tags_vma() returned VMA "
			"0x%p for tags addr 0x%lx\n", vma, tags_addr);
	} else {
		DebugTM("find_vma() returned VMA "
			"0x%p\n", vma);
	}
	DebugTM("returns VMA for data addr 0x%lx\n",
		data_addr);
	return vma;
}

/*
 * Get tags virtual memory address appropriate to specified virtual addresss
 * of data.
 * Second argument 'data_addr' should be quad-word aligned (16 bytes).
 * Pass start address of virtual page of data to get start address of tags area
 */

struct page *
get_tags_page(struct mm_struct *mm, e2k_addr_t data_addr, int write_access)
{
	e2k_addr_t tags_addr;
	struct vm_area_struct *vma;
	struct page *tags_page;

	DebugTM("started for data addr 0x%lx\n", data_addr);

	tags_addr = virt_to_tag(data_addr);
	DebugTM("will start get_tags_addr_vma() for tags addr "
		"0x%lx\n", tags_addr);
	vma = get_tags_addr_vma(mm, data_addr);
	if (vma == NULL) {
		DebugTM("get_tags_addr_vma() "
			"returned NULL for tags addr 0x%lx : "
			"out of memory\n", tags_addr);
		return NULL;
	} else {
		DebugTM("get_tags_addr_vma() returned VMA "
			"0x%p\n", vma);
	}
	DebugTM("will start make_tags_page_present() for "
		"tags addr 0x%lx\n", tags_addr);
	tags_page = make_tags_page_present(mm, vma, tags_addr, write_access);
	if (tags_page != NULL) {
		DebugTM("make_tags_page_present() returned "
			"page 0x%p : tag addr 0x%lx is now present\n",
			tags_page, tags_addr);
		DebugTM("returns with OK for tags addr 0x%lx\n",
			tags_addr);
		return tags_page;
	}
	DebugTM("make_tags_page_present() returned NULL : "
		"could not allocate tags page or it is swapped out\n");
	return NULL;
}

/*
 * Get tags virtual memory address appropriate to specified virtual addresss
 * of data.
 * Second argument 'data_addr' should be quad-word aligned (16 bytes).
 * Pass start address of virtual page of data to get start address of tags area
 */

e2k_addr_t
get_tags_address(struct mm_struct *mm, e2k_addr_t data_addr, int write)
{
	e2k_addr_t tags_addr;
	struct vm_area_struct *vma;
	int ret;

	DebugTM("started for data addr 0x%lx\n", data_addr);

	tags_addr = virt_to_tag(data_addr);
	DebugTM("will start get_tags_addr_vma() for tags "
		"addr 0x%lx\n", tags_addr);
	vma = get_tags_addr_vma(mm, data_addr);
	if (vma == NULL) {
		DebugTM("get_tags_addr_vma() "
			"returned NULL for tags addr 0x%lx : "
			"out of memory\n", tags_addr);
		return (e2k_addr_t) 0;
	} else {
		DebugTM("get_tags_addr_vma() returned VMA "
			"0x%p\n", vma);
	}
	DebugTM("will start handle_mm_fault() for "
		"tags addr 0x%lx\n", tags_addr);
	ret = handle_mm_fault(mm, vma, tags_addr, write);
	if (ret > 0) {
		DebugTM("handle_mm_fault() returned %d "
			": tags addr 0x%lx is now present\n",
			ret, tags_addr);
		DebugTM("returns tags addr 0x%lx\n",
			tags_addr);
		return tags_addr;
	}
	DebugTM("handle_mm_fault() returned %d : out of "
		"memory\n", ret);
	return (e2k_addr_t) 0;
}

/*
 * Unmap tags memory area appropriate to specified user virtual addresses
 */
int
do_tag_munmap(struct mm_struct *mm, e2k_addr_t data_addr, e2k_size_t data_len)
{
	e2k_addr_t data_end;
	e2k_addr_t tag_start;
	e2k_addr_t tag_end;
	e2k_addr_t prev_end = 0;
	e2k_addr_t next_start = TASK_SIZE;
	struct vm_area_struct *data_vma;
	struct vm_area_struct *prev_vma = NULL;

	DebugTM("started for addr 0x%lx size 0x%lx\n",
		data_addr, data_len);

	if ((data_addr & ~PAGE_MASK) || data_addr > TASK_SIZE ||
		data_len > TASK_SIZE - data_addr) {
		printk("do_tag_munmap() : bad data address 0x%lx or size "
			"0x%lx\n", data_addr, data_len);
		BUG();
		return -EINVAL;
	}

	if ((data_len = PAGE_ALIGN(data_len)) == 0) {
		printk("do_tag_munmap() : empty unmaped data area\n");
		BUG();
		return -EINVAL;
	}
	data_end = data_addr + data_len;
	DebugTM("will start find_vma_prev() for data start "
		"addr 0x%lx\n", data_addr);
	data_vma = find_vma_prev(mm, data_addr, &prev_vma);
	if (data_vma == NULL) {
		DebugTM("find_vma_prev() could not find VMA "
			"and returned NULL for data addr 0x%lx\n", data_addr);
		if (prev_vma != NULL)
			prev_end = prev_vma->vm_end;
	} else if (data_vma->vm_start >= data_end) {
		DebugTM("find_vma_prev() found VMA "
			"but VMA has not any intersection with data area from "
			"start addr 0x%lx to end addr 0x%lx\n",
			data_addr, data_end);
		if (prev_vma != NULL)
			prev_end = prev_vma->vm_end;
		next_start = data_vma->vm_start;
	} else {
		DebugTM("find_vma_prev() found VMA "
			"intersected with data area from start addr 0x%lx "
			"to end addr 0x%lx\n",
			data_addr, data_end);
		if (data_vma->vm_start >= data_addr) {
			DebugTM("VMA start addr 0x%lx >= "
				"data area start addr 0x%lx : take previous "
				"VMA end\n",
				data_vma->vm_start, data_addr);
			if (prev_vma != NULL)
				prev_end = prev_vma->vm_end;
		} else {	/* data_addr > data_vma->vm_start */
			DebugTM("VMA start addr 0x%lx < "
				"data area start addr 0x%lx : could not be "
				"hole from left\n",
				data_vma->vm_start, data_addr);
			prev_end = data_addr;
		}
		if (data_vma->vm_end > data_end) {
			DebugTM("VMA end addr 0x%lx > "
				"data area end addr 0x%lx : could not be "
				"hole from right\n",
				data_vma->vm_end, data_end);
			next_start = data_end;
		} else if (data_vma->vm_end == data_end) {
			DebugTM("VMA end addr 0x%lx == "
				"data area end addr 0x%lx : take next "
				"VMA start\n",
				data_vma->vm_start, data_end);
			if (data_vma->vm_next != NULL)
				next_start = data_vma->vm_next->vm_start;
		} else {
			DebugTM("will start find_vma() "
				"for data end addr 0x%lx\n", data_end);
			data_vma = find_vma(mm, data_end);
			if (data_vma == NULL) {
				DebugTM("find_vma() "
					"could not find VMA and returned NULL "
					"for data end addr 0x%lx\n", data_end);
			} else if (data_vma->vm_start > data_end) {
				DebugTM("VMA start addr 0x%lx "
					">= data area end addr 0x%lx : take "
					"this VMA start addr\n",
					data_vma->vm_start, data_end);
				next_start = data_vma->vm_start;
			} else {	/* data_vma->vm_start <= data_end */
				DebugTM("VMA start addr 0x%lx "
					"<= data area end addr 0x%lx : could "
					"not be hole from right\n",
					data_vma->vm_start, data_end);
				next_start = data_end;
			}
		}
	}
	DebugTM("unmapped start addr 0x%lx, previous end addr "
		"0x%lx, unmapped end addr 0x%lx, next start addr 0x%lx\n",
		data_addr, prev_end, data_end, next_start);
	if (PAGE_ALIGN_DOWN(virt_to_tag(prev_end)) <=
		PAGE_ALIGN_UP(virt_to_tag(data_addr))) {
		tag_start = PAGE_ALIGN_UP(virt_to_tag(data_addr));
	} else {
		tag_start = PAGE_ALIGN_DOWN(virt_to_tag(data_addr));
	}
	if (PAGE_ALIGN_DOWN(virt_to_tag(data_end)) <=
		PAGE_ALIGN_UP(virt_to_tag(next_start))) {
		tag_end = PAGE_ALIGN_DOWN(virt_to_tag(data_end));
	} else {
		tag_end = PAGE_ALIGN_UP(virt_to_tag(data_end));
	}
	DebugTM("unmapped tag memory start addr 0x%lx end "
		"0x%lx\n", tag_start, tag_end);
	if (tag_start >= tag_end)
		return 0;
	DebugTM("will start do_munmap() to unmap tag memory "
		"from start addr 0x%lx to end addr 0x%lx\n",
		tag_start, tag_end);
	return do_munmap(mm, tag_start, tag_end - tag_start);
}

int
save_swapped_page_tags(struct mm_struct * mm, struct page *swapped_page,
	e2k_addr_t data_addr)
{
	e2k_addr_t tags_addr = virt_to_tag(data_addr);
	struct page *tags_page;
	struct vm_area_struct *tags_vma;
	e2k_addr_t k_data_addr = (e2k_addr_t)page_address(swapped_page);
	e2k_addr_t k_tags_addr;

	DebugTM("started for data addr 0x%lx\n",
		data_addr);
	
	down(&mm->swap_info_sem);

	tags_page = get_tags_page(mm, data_addr, 1);
	if (tags_page == NULL) {
		DebugTM("get_tags_page() could not "
			"get tags page : out of memory\n");
		up(&mm->swap_info_sem);
		return -1;
	}
	DebugTM("get_tags_page() returned page "
		"structure 0x%p\n", tags_page);
	tags_vma = find_vma(mm, tags_addr);
	if (tags_vma == NULL || tags_vma->vm_start > tags_addr) {
		printk("save_swapped_page_tags() : could not find VMA for "
			"existing tags addr 0x%lx\n",
			tags_addr);
		BUG();
		return -1;
	}
	k_tags_addr = (e2k_addr_t)page_address(tags_page) +
						(tags_addr & ~PAGE_MASK);
	DebugTM("wiil start save_mem_page_tags() "
		"to save tags from addr 0x%lx to addr 0x%lx\n",
		k_data_addr, k_tags_addr);
	save_mem_page_tags(k_data_addr, k_tags_addr);
	flush_page_to_ram(tags_page);
	flush_cache_page(tags_vma, tags_addr);
	DebugTM("returns with OK for data addr "
		"0x%lx and tags addr 0x%lx\n",
		data_addr, tags_addr);
	up(&mm->swap_info_sem);
	return 0;
}

int
restore_swapped_page_tags(struct mm_struct * mm, struct page *swapped_page,
	e2k_addr_t data_addr)
{
	e2k_addr_t tags_addr = virt_to_tag(data_addr);
	struct page *tags_page;
	struct vm_area_struct *tags_vma;
	e2k_addr_t k_data_addr = (e2k_addr_t)page_address(swapped_page);
	e2k_addr_t k_tags_addr;

	DebugTM("started for data addr 0x%lx\n",
		data_addr);
	DebugTM("will start get_tags_page()\n");

	down(&mm->swap_info_sem);
	tags_page = get_tags_page(mm, data_addr, 1);
	if (tags_page == NULL) {
		DebugTM("get_tags_page() could not "
			"get tags page : out of memory\n");
		up(&mm->swap_info_sem);
		return -1;
	}
	DebugTM("get_tags_page() returned page "
		"structure 0x%p\n", tags_page);
	tags_vma = find_vma(mm, tags_addr);
	if (tags_vma == NULL || tags_vma->vm_start > tags_addr) {
		printk("restore_swapped_page_tags() : could not find VMA for "
			"existing tags addr 0x%lx\n",
			tags_addr);
		BUG();
		return -1;
	}
	k_tags_addr = (e2k_addr_t)page_address(tags_page) +
						(tags_addr & ~PAGE_MASK);
	DebugTM("will start "
		"restore_mem_page_tags() to load tags from addr 0x%lx to "
		"addr 0x%lx\n",
		k_tags_addr, k_data_addr);
	restore_mem_page_tags(k_data_addr, k_tags_addr);
	flush_page_to_ram(tags_page);
	flush_cache_page(tags_vma, tags_addr);
	DebugTM("returns with OK for data addr "
		"0x%lx and tags addr 0x%lx\n",
		data_addr, tags_addr);
	up(&mm->swap_info_sem);
	return 0;
}


void __init
swap_info_cache_init(void)
{
	swap_info_cache =  kmem_cache_create("swp_pg_inf_strct",
                        sizeof(struct swap_page_info), 0,
                        SLAB_HWCACHE_ALIGN, NULL, NULL);
        if (!swap_info_cache)
                panic("Cannot create swap info structures SLAB cache");

} 

void
free_swap_info_struct(swap_page_info_t* info)
{
	        kmem_cache_free(swap_info_cache, info);
}


int 
add_swap_info_to_page(struct mm_struct* mm, struct page* page, e2k_addr_t addr) {
	swap_page_info_t* page_info;
	
	if (PageWithSwapInfo(page)) {
		printk("add_swap_info_to_page() Page 0x%p already has swap "
			"info\n",page);
		BUG();
	}
	page_info = (swap_page_info_t*) kmem_cache_alloc(swap_info_cache,
								SLAB_ATOMIC);
	if (page_info == NULL) return -1;
	DebugTM("Adding swap info to the page "
		"0x%p\n",page);
	page_info->mm = mm;
	page_info->addr = addr;
	page_info->next = NULL;
	page->swap_info = page_info;
	return 0;
}

int
add_swap_info_to_page_next(struct mm_struct *mm, struct page *page,
	e2k_addr_t addr)
{
	swap_page_info_t* page_info;
	
	if (!PageWithSwapInfo(page)) {
		printk("add_swap_info_to_page_rec() Page 0x%p doesnt have "
		"swap info\n",page);
		BUG();
	}
	page_info = (swap_page_info_t*) kmem_cache_alloc(swap_info_cache,
								SLAB_ATOMIC);
	if (page_info == NULL) return -1;
	DebugTM("Adding next swap info to the "
		"page 0x%p",page);
	page_info->mm = mm;
	page_info->addr = addr;
	page_info->next = page->swap_info;
	page->swap_info = page_info;
	return 0;
}

swap_page_info_t *
get_swap_info_from_page(struct page* page)
{
	swap_page_info_t *info = page->swap_info;
	if (!PageWithSwapInfo(page)) {
		printk("get_swap_info_from_page() Page 0x%p doesnt have swap "
			"info\n", page);
		BUG();
	}
	DebugTM("Getting swap info from the page "
		"0x%p\n",page);
	page->swap_info = info->next;
	return info;
}
