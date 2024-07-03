/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 *  page_io.c
 *
 */

#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/pagemap.h>
#include <linux/bio.h>
#include <linux/writeback.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/swapfile.h>
#include <linux/frontswap.h>
#include <linux/blkdev.h>
#include <linux/sysrq.h>
#include <linux/pgtable.h>
#include <linux/swap.h>
#include <linux/swapops.h>

#include <asm/page_io.h>
#include <asm/delay.h>
#include <asm/cmpxchg.h>
#include <asm/e2k_debug.h>

#undef  DEBUG_TAG_PAGE
/*define DEBUG_TAG_PAGE	1 */

#undef DEBUG_M
/*#define DEBUG_M	1 */

#undef  DEBUG_TAG_MODE
#undef  DebugTM
#define DEBUG_TAG_MODE          0       /* Tag memory */
#define DebugTM(...)		DebugPrint(DEBUG_TAG_MODE, ##__VA_ARGS__)

#undef  DEBUG_TAG_MODE_W
#undef  DebugTM_W
#define DEBUG_TAG_MODE_W        1       /* Tag memory */
#define DebugTM_W(...)		DebugPrint(DEBUG_TAG_MODE_W, ##__VA_ARGS__)


#define SetPageLocked	__SetPageLocked
#define ClearPageLocked __ClearPageLocked

static struct tags_swap_page_table tags_swap_table[MAX_SWAPFILES];
static int was_swap_write_page = 0;
static int CLEAR = 0;
static int WRITING = 0;
static int READ_SWAP = 0;
static int READ_SWAP_WITH_TAGS = 0;
static int WRITE_SWAP = 0;
static int WRITE_SWAP_WITH_TAG = 0;
static int READ_SWAP_TAGS_FROM_CASH = 0;
static int PROCESSED_WRITE_SWAP_WITH_TAG = 0;
static int MIN_OFFSET = 0xfffffff;
static int MAX_OFFSET = 0;
static int FREE_ENTRY = 0;
static int LOOP_ENTRY = 0;
static int IO_LOOP_ENTRY = 0;
static int COUNT = 0;
static int WR = 0;


extern void wake_up_page(struct page *page, int bit);
extern struct swap_extent *offset_to_swap_extent(struct swap_info_struct *sis,
						 unsigned long offset);

static void unlock_tag_page(struct page *page)
{
	page = compound_head(page);
	clear_bit_unlock(PG_locked, &page->flags);
	smp_mb__after_atomic();
	wake_up_page(page, PG_locked);
}

static inline int is_busy_tag_page(struct page *page)
{
	return test_bit(PG_locked, &page->flags);
}

static inline void set_buse_tag_page(struct page *page)
{
	return set_bit(PG_locked, &page->flags);
}

/*
 * similar to swap_info_get in swapfile.c
 */
static inline int get_swp_type(struct page *page)
{
	swp_entry_t entry;

	entry.val = page_private(page);
	return swp_type(entry);
}

static inline int get_swp_offset(struct page *page)
{
	swp_entry_t entry;

	entry.val = page_private(page);
	return swp_offset(entry);
}


static struct swap_info_struct *e2k_page_swap_info(struct page *page)
{
	swp_entry_t swap = { .val = page_private(page) };

	return swap_info[swp_type(swap)];
}

static struct swap_info_struct *e2k_swap_info_get(swp_entry_t entry)
{
	struct swap_info_struct *p;
	unsigned long offset, type;

	if (!entry.val)
		goto out;
	type = swp_type(entry);
	if (type >= nr_swapfiles)
		goto bad_nofile;
	p = swap_info[type];
	if (!(p->flags & SWP_USED))
		goto bad_device;
	offset = swp_offset(entry);
	if (offset >= p->max)
		goto bad_offset;
	if (!p->swap_map[offset])
		goto bad_free;
	return p;

bad_free:
	goto out;
bad_offset:
	pr_err("2 swap_free: %08lx\n", entry.val);
	goto out;
bad_device:
	pr_err("3 swap_free: %08lx\n", entry.val);
	goto out;
bad_nofile:
	pr_err("4 swap_free: %08lx\n", entry.val);
out:
	return NULL;
}

/*
 * Now the data of pages and tags are located as follows:
 * Firstly, the data of all swap pages is then their tags
 * N sector for tag  =  (se->start_block +  se->nr_pages )<<(PAGE_SHIFT - 9)+
 *				(offset - se->start_page)
 * N sector for data =  (se->start_block + (offset - se->start_page))
 *						 << (PAGE_SHIFT - 9)
 */
void e2k_map_swap_page(struct page *page, struct bio *bio,
		       struct block_device **bdev)
{
	struct swap_info_struct *sis;
	struct swap_extent *se;
	swp_entry_t entry;
	pgoff_t offset;

	if (!was_swap_write_page)
		BUG();

	entry.val = page_private(page);
	offset = swp_offset(entry);

	sis = e2k_swap_info_get(entry);
	if (!sis)
		BUG();

	*bdev = sis->bdev;

	se = offset_to_swap_extent(sis, offset);

	bio->bi_iter.bi_sector =
		 (((se->start_block + se->nr_pages) << (PAGE_SHIFT - 9)) +
			(offset - se->start_page));
}
#ifdef CONFIG_MCST_MEMORY_SANITIZE
EXPORT_SYMBOL(e2k_map_swap_page); /* for lkdm testing */
#endif


static long e2k_real_map_swap_page1(struct page *page, struct bio *bio, int tag)
{
	struct swap_info_struct *sis;
	struct swap_extent *se;
	swp_entry_t entry;
	pgoff_t offset;
	long sector;

	if (!was_swap_write_page)
		return 0;

	entry.val = page_private(page);
	offset = swp_offset(entry);

	sis = e2k_swap_info_get(entry);
	if (!sis)
		return 0;

	se = offset_to_swap_extent(sis, offset);

	sector = (tag) ?
		 ((se->start_block + se->nr_pages) << (PAGE_SHIFT - 9) +
			(offset - se->start_page)) :
		 (se->start_block + (offset - se->start_page));

	return  sector;
}

static void set_clear_tag_page(struct page *page)
{
	if (is_busy_tag_page(page))
		unlock_tag_page(page);
}

u32 save_tags_from_data(u64 *datap, u8 *tagp)
{
	u32 res = 0;
	int i;

	for (i = 0; i < (int) TAGS_BYTES_PER_PAGE; i++) {
		u64 data_lo, data_hi;
		u8 tag_lo, tag_hi, tag;

		load_qvalue_and_tagq((unsigned long) &datap[2 * i],
				&data_lo, &data_hi, &tag_lo, &tag_hi);
		tag = tag_lo | (tag_hi << 4);

		tagp[i] = tag;
		res |= tag;
	}

	return res;
}

static long save_tags_from_page(struct page *src_page, struct page *dst_page)
{
	u64 *data_addr;
	u8 *tag_addr;
	long res;

	DebugTM("Starting copying the tags from the "
		"page 0x%px (addr 0x%px) to the tags page 0x%px (addr 0x%px)\n",
		src_page, page_address(src_page),
		dst_page, page_address(dst_page));

	tag_addr = (u8 *)page_address(dst_page);
	data_addr = (u64 *)page_address(src_page);
	res = save_tags_from_data(data_addr, tag_addr);
	return res;
}

void restore_tags_for_data(u64 *datap, u8 *tagp)
{
	int i;

	for (i = 0; i < (int) TAGS_BYTES_PER_PAGE; i++) {
		u64 data_lo = datap[2 * i], data_hi = datap[2 * i + 1];
		u32 tag = (u32) tagp[i];

		store_tagged_dword(&datap[2 * i], data_lo, tag);
		store_tagged_dword(&datap[2 * i + 1], data_hi, tag >> 4);
	}
}

static void restore_tags_from_page(struct page *dst_page, struct page *src_page)
{
	u64 *data_addr;
	u8 *tag_addr;

	DebugTM("Starting copying the tags from the "
		"page 0x%px (addr 0x%px) to the data page 0x%px (addr 0x%px)\n",
		src_page, page_address(src_page),
		dst_page, page_address(dst_page));

	tag_addr = (u8 *)page_address(src_page);
	data_addr = (u64 *)page_address(dst_page);
	restore_tags_for_data(data_addr, tag_addr);
	set_clear_tag_page(src_page);
}

static struct bio *e2k_get_swap_bio(gfp_t gfp_flags, struct page *tag_page,
				   struct page *page,
				   bio_end_io_t end_io, int size)
{	int i, nr = thp_nr_pages(page);
	struct bio *bio;

	bio = bio_alloc(gfp_flags, nr);
	if (bio) {
		struct block_device *bdev;

		e2k_map_swap_page(page, bio, &bdev);
		bio_set_dev(bio, bdev);
		bio->bi_end_io = end_io;

		DebugTM(" bi_sector = %llx  page=%px tag_page=%px\n",
			bio->bi_iter.bi_sector, page, tag_page);

		for (i = 0; i < nr; i++)
			bio_add_page(bio, tag_page + i, size, 0);

		VM_BUG_ON(bio->bi_iter.bi_size != PAGE_SIZE * nr);
	}

	return bio;
}

static void clear_tags_was_writing(struct page *page)
{
	struct swap_info_struct *sis = e2k_page_swap_info(page);
	unsigned long offset;
	swp_entry_t entry;

	CLEAR++;
	if (!sis) {
		DebugTM_W(" %s BAD0!!!! page=%px\n", __func__, page);
		return;
	}
	entry.val = page_private(page);
	offset = swp_offset(entry);

	clear_bit(2*offset + 1, sis->tag_swap_map);
}

static void e2k_end_swap_bio_write(struct bio *bio)
{
	struct page *page = bio->bi_io_vec[0].bv_page;

	DebugTM(" page=%px  bi_sector=0x%llx page_address=%px\n",
	       page, (unsigned long long)bio->bi_iter.bi_sector,
	       page_address(bio->bi_io_vec[0].bv_page));
	if (bio->bi_status) {
		SetPageError(page);
		/*
		 * We failed to write the page out to swap-space.
		 * Re-dirty the page in order to avoid it being reclaimed.
		 * Also print a dire warning that things will go BAD (tm)
		 * very quickly.
		 *
		 * Also clear PG_reclaim to avoid rotate_reclaimable_page()
		 */
		set_page_dirty(page);
		pr_info("%s: Write-error %d on swap-device (%u:%u:%llu)\n",
				current->comm, bio->bi_status,
			 	MAJOR(bio_dev(bio)), MINOR(bio_dev(bio)),
				(unsigned long long)bio->bi_iter.bi_sector);
		ClearPageReclaim(page);
	}
	smp_mb__after_atomic();
	wake_up_page(page, PG_writeback);
	bio_put(bio);
	clear_tags_was_writing(page);
	set_clear_tag_page(page);
	PROCESSED_WRITE_SWAP_WITH_TAG++;
}

#ifdef DEBUG_M
#define MAX_CMP_PAGE 8192
struct page *WRITE_PAGE[MAX_CMP_PAGE];
long OFFSET_PAGE[MAX_CMP_PAGE];
int index_write_page;
raw_spinlock_t lock_write_pages;
long FIND_PAGE = 0, NOT_FIND_PAGE = 0;

static void compare_page(struct page *page, struct page *write_page, int j)
{
	int i;
	u64 data, write_data;
	u8 tag, write_tag;
	u64 *addr_page = (u64 *)page_address(page);
	u64 *addr_write_page = (u64 *)page_address(write_page);
	int once = 1;
	static int BAD = 0;

	for (i = 0; i < PAGE_SIZE/8; i++) {
		load_value_and_tagd(addr_page, &data, &tag);
		load_value_and_tagd(addr_write_page, &write_data, &write_tag);
		if (tag != write_tag || data != write_data) {
			if (BAD++ > 10)
				continue;
			if (once) {
				unsigned long offset;
				swp_entry_t entry;
				entry.val = page_private(page);
				offset = swp_offset(entry);
				once = 0;
				pr_info(" ind =%d page=%px offset=0x%lx flags==0x%lx\n",
				       j, page, offset, page->flags);
				tracing_off();
				dump_stack();
			}
			pr_info(" i=%d tag=%d  write_tag=%d data=0x%lx"
			       " write_data=0x%lx addr_page=0x%px"
			       " addr_write_page=%px\n",
			       i, tag, write_tag, data, write_data, addr_page,
			       addr_write_page);

		}
		addr_page++;
		addr_write_page++;
	}
}

static void init_cmp_page(void)
{
	int i;
	struct page *page;

	raw_spin_lock_init(&lock_write_pages);
	index_write_page = 0;
	for (i = 0; i < MAX_CMP_PAGE; i++) {
		page = alloc_page(GFP_KERNEL);
		if (!page)
			panic("Cannot allocate pages for init_cmp_page");
		get_page(page);
		WRITE_PAGE[i] = page;
	}
}

static void save_page(struct page *page)
{
	struct page *res;
	swp_entry_t entry;
	int ind = 0;
	unsigned long flags;

	entry.val = page_private(page);
	raw_spin_lock_irqsave(&lock_write_pages, flags);
	ind = index_write_page;
	index_write_page++;
	if (index_write_page >= MAX_CMP_PAGE) {
		index_write_page = 0;
	}
	raw_spin_unlock_irqrestore(&lock_write_pages, flags);
	res = WRITE_PAGE[ind];
	copy_tagged_page(page_address(res), page_address(page));
	OFFSET_PAGE[ind] = entry.val;
	page_private(res) = entry.val;
}

static void cmp_page(struct page *page)
{
	int i;
	struct swap_info_struct *sis = e2k_page_swap_info(page);
	unsigned long offset;
	swp_entry_t entry;
	unsigned long flags;

	entry.val = page_private(page);
	offset = swp_offset(entry);

	raw_spin_lock_irqsave(&lock_write_pages, flags);
	for (i = 0; i < MAX_CMP_PAGE; i++) {
		if (offset == OFFSET_PAGE[i]) {
			raw_spin_unlock_irqrestore(&lock_write_pages, flags);
			DebugTM(" find OFFSET =0x%lx\n", offset);
			compare_page(page, WRITE_PAGE[i], i);
			FIND_PAGE++;
			return;
		}
	}
	raw_spin_unlock_irqrestore(&lock_write_pages, flags);
	NOT_FIND_PAGE++;
	DebugTM("NOT find OFFSET =0x%lx\n", offset);
}
#else /* !DEBUG_M */
#define cmp_page(x)
#define save_page(x)
#define init_cmp_page()

#endif /* DEBUG_M */

static bool tags_was_writing(struct page *page)
{
	struct swap_info_struct *sis = e2k_page_swap_info(page);
	unsigned long offset;
	swp_entry_t entry;

	if (!sis) {
		DebugTM_W(" %s BAD!!!! page=%px\n", __func__, page);
		return 1;
	}
	entry.val = page_private(page);
	offset = swp_offset(entry);
	return	test_bit(2*offset + 1, sis->tag_swap_map);
}

static int tags_swap_test(struct page *page)
{
	struct swap_info_struct *sis = e2k_page_swap_info(page);
	unsigned long offset;
	swp_entry_t entry;

	entry.val = page_private(page);
	offset = swp_offset(entry);
	if (!sis || offset == 0) {
		DebugTM_W(" == %s BAD!!!! page=%px offset=0x%lx, sis=%px, entry=0x%lx\n",
			  __func__, page, offset, sis, entry.val);
	    return 11;
	}
	return	test_bit(2*offset, sis->tag_swap_map);
}

static void print_all_tag_swap_pages(void)
{
	int i, j;

	show_swap_cache_info();
	pr_info(" %s WRITE_SWAP=%d WRITE_SWAP_WITH_TAG=%d READ_SWAP=%d"
		" READ_SWAP_WITH_TAGS=%d READ_SWAP_TAGS_FROM_CASH=%d"
		" PROCESSED_WRITE_SWAP_WITH_TAG=%d MIN_OFFSET=%d"
		" MAX_OFFSET=%d FREE_ENTRY=%d"
		" LOOP_ENTRY=%d IO_LOOP_ENTRY=%d COUNT=%d WR=%d\n",
		__func__, WRITE_SWAP, WRITE_SWAP_WITH_TAG, READ_SWAP,
		READ_SWAP_WITH_TAGS, READ_SWAP_TAGS_FROM_CASH,
		PROCESSED_WRITE_SWAP_WITH_TAG, MIN_OFFSET, MAX_OFFSET,
		FREE_ENTRY, LOOP_ENTRY, IO_LOOP_ENTRY, COUNT, WR);
	if (!WRITE_SWAP && !READ_SWAP) {
		/* no swap */
		return;
	}
return;
#ifdef DEBUG_M
	pr_info(" %s FIND_PAGE=%ld NOT_FIND_PAGE=%ld\n",
		__func__, FIND_PAGE, NOT_FIND_PAGE);
#endif /* DEBUG_M */
	return;
	for (i = 0; i < MAX_SWAPFILES; i++) {
		struct tags_swap_page_table *curr_tag_page_table =
			&tags_swap_table[i];
		struct page *tag_page;

		if (curr_tag_page_table->size[1] != TAGS_PAGES ||
		    curr_tag_page_table->size[0] != TAGS_READ_PAGES ||
		   !curr_tag_page_table->pages) {
			/* null table */
			continue;
		}
		pr_info("======= i = %d index=%d index_read=%d\n",
		       i, curr_tag_page_table->index,
		       curr_tag_page_table->index_read);

		for (j = 0; j < TAGS_PAGES; j++) {
			tag_page = curr_tag_page_table->pages[j];
			pr_info("  j=%d  tag_page=%px "
			" is_busy_tag_page=%d tags_was_writing=%d"
				" tags_swap_test=%d flags=0x%lx offset=%d\n",
			j, tag_page, is_busy_tag_page(tag_page),
			tags_was_writing(tag_page),
			tags_swap_test(tag_page), tag_page->flags,
			get_swp_offset(tag_page));
		}
	}
}

static struct page *find_swap_page(struct page *page)
{
	struct page *res;
	int i;
	struct tags_swap_page_table *curr_tag_page_table =
			&tags_swap_table[get_swp_type(page)];
	struct page **ptr_page;

	ptr_page = curr_tag_page_table->pages;
	for (i = 0; i < TAGS_PAGES; i++) {
		res = ptr_page[i];
		if (page_private(page) == page_private(res)) {
			DebugTM(" %s FOUND!!!  res =%px\n", __func__, res);
			return res;
		}
	}
	if (tags_was_writing(page)) {
		DebugTM(" %s BAD NO_FIND!!!  CLEAR=%d WRITING=%d "
			 "page=%px SECTOR=0x%lx\n", __func__,
			 CLEAR, WRITING, page,
			 e2k_real_map_swap_page1(page, NULL, 1));
	}
	return NULL;
}

static struct page *get_tag_swap_page(int wr, struct page *page, int *NO_READ)
{
	struct page *res;
	int i, ind;
	struct tags_swap_page_table *curr_tag_page_table;
	int *ptr_ind;
	struct page **ptr_page;
	int type = get_swp_type(page);
	int size;
	struct page *writing_page;
	struct mutex *lock;

	curr_tag_page_table = &tags_swap_table[type];
	size = curr_tag_page_table->size[wr];
	if (wr == 0) {
		/* read */
		ptr_ind = &curr_tag_page_table->index_read;
		ptr_page = curr_tag_page_table->read_pages;
		lock = &(curr_tag_page_table->lock_read_pages);
	} else {
		ptr_ind = &curr_tag_page_table->index;
		ptr_page = curr_tag_page_table->pages;
		lock = &(curr_tag_page_table->lock_pages);
	}
	COUNT = 0;
	WR = wr;
	while (1) {
	    mutex_lock(lock);
	    ind = *ptr_ind;
	    for (i = 0; i < size; i++) {
		res = ptr_page[ind];
		if (is_busy_tag_page(res)) {
			/* change index for next get_tag_swap_page */
			ind = (ind + 1) % size;
		} else {
			/* found free page */
			*ptr_ind = (ind + 1) % size;
			page_private(res) = page_private(page);
			set_buse_tag_page(res);
			if (wr == 0 && tags_was_writing(page)) {
			    /* tags for this page are writing in swap */
			    writing_page = find_swap_page(page);
			    DebugTM(" %s  AFTER WAIT cpu=%d page=%px "
				      " writing_page=%px\n", current->comm,
				smp_processor_id(), page, writing_page);
			    memcpy(page_address(res),
				   page_address(writing_page), PAGE_SIZE/8);
			    *NO_READ = 1;
			}
			mutex_unlock(lock);
#ifdef DEBUG_TAG_PAGE
			if (COUNT) {
				print_all_tag_swap_pages();
			}
#endif /* DEBUG_TAG_PAGE */
			return res;
		}
	    }
	    *ptr_ind = (ind + 1) % size;
	    mutex_unlock(lock);
	    LOOP_ENTRY++;
	    COUNT++;
	    if (wr && total_swapcache_pages() >= size) {
		io_schedule_timeout(5*HZ);
		IO_LOOP_ENTRY++;
	    }
	    wait_on_page_locked(res);
	    if (is_busy_tag_page(res)) {
		wait_on_page_bit(res, PG_locked);
	    }
	}
	/* !!! unreachable place */
	mutex_unlock(lock);
	panic(" +++ERRROR %s CLEAR=%d WRITING=%d\n",
	      current->comm, CLEAR, WRITING);
	return NULL;

}

static void clear_tags_swap(struct page *page)
{
	struct swap_info_struct *sis = e2k_page_swap_info(page);
	unsigned long offset;
	swp_entry_t entry;

	entry.val = page_private(page);
	offset = swp_offset(entry);
	if (!sis || offset == 0) {
		DebugTM_W(" %s BAD!!!! page=%px\n", __func__, page);
		return;
	}
	clear_bit(2*offset, sis->tag_swap_map);
}

static void set_tags_was_writing(struct page *page)
{
	struct swap_info_struct *sis = e2k_page_swap_info(page);
	unsigned long offset;
	swp_entry_t entry;

	WRITING++;
	entry.val = page_private(page);
	offset = swp_offset(entry);
	if (!sis || offset == 0) {
		DebugTM_W(" %s BAD!!!! page=%px\n", __func__, page);
		return;
	}
	set_bit(2*offset + 1, sis->tag_swap_map);
}

static void set_tags_swap(struct page *page)
{
	struct swap_info_struct *sis = e2k_page_swap_info(page);
	unsigned long offset;
	swp_entry_t entry;

	entry.val = page_private(page);
	offset = swp_offset(entry);

	if (!sis || offset == 0) {
		DebugTM_W(" %s BAD!!!! page=%px\n", __func__, page);
		return;
	}
	set_bit(2*offset, sis->tag_swap_map);
}

void tag_swap_write_page(struct page *page, struct writeback_control *wbc)
{
	struct page *dst_page;
	long  res;
	struct bio *bio;
	int size;
	int NO_READ;

	was_swap_write_page++;
	WRITE_SWAP++;
	size = PAGE_SIZE / 8;
	dst_page = get_tag_swap_page(1, page, &NO_READ);
	if (!dst_page) {
		DebugTM(" can't find pages for tags\n");
		panic("tag_swap_write_page can't find pages for tags");
		return;
	}
	res = save_tags_from_page(page, dst_page);
	clear_tags_swap(page);
	if (res) {
		WRITE_SWAP_WITH_TAG++;
		/* DEBUG only */
		save_page(page);
		set_tags_swap(page);
		set_tags_was_writing(dst_page);
		bio = e2k_get_swap_bio(GFP_NOIO, dst_page, page,
			     e2k_end_swap_bio_write, size);
		if (bio == NULL) {
			BUG();
			return;
		}
		count_vm_event(PSWPOUT);
		if (wbc->sync_mode == WB_SYNC_ALL)
			bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_SYNC);
		else
			bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
		submit_bio(bio);
	} else {
		/* if all tags equal 0 than - no save tags */
		set_clear_tag_page(dst_page);
	}
	return;
}


#ifdef CONFIG_MAGIC_SYSRQ
static void sysrq_handle_swap(int key)
{
	print_all_tag_swap_pages();
}

static struct sysrq_key_op sysrq_swap_op = {
	.handler	= sysrq_handle_swap,
	.help_msg	= "debug(g)",
	.action_msg	= "DEBUG",
};
#endif

void e2k_swap_setup(int type, int block_size)
{
	int i;
	struct page *page;
	struct tags_swap_page_table *curr_tag_page_table =
					&tags_swap_table[type];

	DebugTM("swap_setup() Initializing swap, type is %d, "
	       "block_size is  %d\n", type, block_size);
	curr_tag_page_table->size[1] = TAGS_PAGES;
	mutex_init(&curr_tag_page_table->lock_pages);
	curr_tag_page_table->pages =
		kmalloc(TAGS_PAGES * sizeof(void *), GFP_KERNEL);
#ifdef CONFIG_MAGIC_SYSRQ
		register_sysrq_key('x', &sysrq_swap_op);
#endif

	for (i = 0; i < TAGS_PAGES; i++) {
		page = alloc_page(GFP_KERNEL);
		get_page(page);
		if (!page)
			panic("Cannot allocate pages for swap");
		page->mapping = swapper_spaces[type];
		curr_tag_page_table->pages[i] = page;
	}
	/*
	 * for reading swap
	 */
	mutex_init(&curr_tag_page_table->lock_read_pages);
	curr_tag_page_table->read_pages =
		kmalloc(TAGS_READ_PAGES * sizeof(void *), GFP_KERNEL);
	curr_tag_page_table->size[0] = TAGS_READ_PAGES;
	for (i = 0; i < TAGS_READ_PAGES; i++) {
		page = alloc_page(GFP_KERNEL);
		get_page(page);
		if (!page)
			panic("Cannot allocate pages for swap");
		page->mapping = swapper_spaces[type];
		curr_tag_page_table->read_pages[i] = page;
		}
	curr_tag_page_table->index = 0;
	curr_tag_page_table->index_read = 0;
	/* DEBUG only */
	init_cmp_page();
}

static void tags_swap_free(struct swap_info_struct *sis)
{
	unsigned long *tag_swap_map = sis->tag_swap_map;

	BUG_ON(sis == NULL);
	if (!tag_swap_map)
		return;
	DebugTM(" tags_swap_free sis->max =%d\n", sis->max);
	sis->tag_swap_map =  NULL;
	vfree(tag_swap_map);
}

void e2k_remove_swap(struct swap_info_struct *sis)
{
	int i;
	struct page *page;
	struct tags_swap_page_table *curr_tag_page_table =
					&tags_swap_table[sis->type];
	struct page **tbl_write_pages;
	struct page **tbl_read_pages;

	DebugTM("e2k_remove_swap\n");

	mutex_lock(&(curr_tag_page_table->lock_pages));
	mutex_lock(&(curr_tag_page_table->lock_read_pages));

	for (i = 0; i < TAGS_PAGES; i++) {
		page = curr_tag_page_table->pages[i];
		if (!page) {
			continue;
		}
		curr_tag_page_table->pages[i] = NULL;
		page->mapping = NULL;
		ClearPageSwapCache(page);
		clear_bit_unlock(PG_locked, &page->flags);
		if (is_busy_tag_page(page)) {
			wait_on_page_bit(page, PG_locked);
		}
		put_page(page);
		__free_page(page);
	}

	for (i = 0; i < TAGS_READ_PAGES; i++) {
		page = curr_tag_page_table->read_pages[i];
		if (!page) {
			continue;
		}
		curr_tag_page_table->read_pages[i] = NULL;
		if (is_busy_tag_page(page)) {
			wait_on_page_bit(page, PG_locked);
		}
		page->mapping = NULL;
		ClearPageSwapCache(page);
		clear_bit_unlock(PG_locked, &page->flags);
		put_page(page);
		__free_page(page);
	}

	tbl_write_pages = curr_tag_page_table->pages;
	curr_tag_page_table->pages = NULL;
	tbl_read_pages = curr_tag_page_table->read_pages;
	curr_tag_page_table->read_pages = NULL;
	kfree(tbl_read_pages);
	kfree(tbl_write_pages);

	mutex_unlock(&(curr_tag_page_table->lock_read_pages));
	mutex_unlock(&(curr_tag_page_table->lock_pages));

	tags_swap_free(sis);
}

static void e2k_end_swap_bio_read(struct bio *bio)
{
	struct page *page = bio->bi_io_vec[0].bv_page;

	if (bio->bi_status) {
		SetPageError(page);
		ClearPageUptodate(page);
		pr_info("Read-error on swap-device (%u:%u:%llu)\n",
			 	MAJOR(bio_dev(bio)), MINOR(bio_dev(bio)),
				(unsigned long long)bio->bi_iter.bi_sector);
	}
	unlock_page(page);
	bio_put(bio);
}

static struct page *tag_swap_readpage(struct page *page)
{
	struct page *tag_page;
	struct bio *bio;
	int    NO_READ = 0;

	tag_page = get_tag_swap_page(0, page, &NO_READ);
	if (NO_READ) {
		/* page was copyed already*/
		READ_SWAP_TAGS_FROM_CASH++;
		ClearPageLocked(tag_page);
		return tag_page;
	}
	if (!tag_page) {
		DebugTM("tag_swap_readpage can't find pages for tags");
		return NULL;
	}
	bio = e2k_get_swap_bio(GFP_KERNEL, tag_page, page,
			     e2k_end_swap_bio_read, PAGE_SIZE / 8);
	if (bio == NULL) {
		unlock_page(tag_page);
		panic("tag_swap_readpage can't find memory for bio");
	}
	count_vm_event(PSWPIN);
	bio_set_op_attrs(bio, REQ_OP_READ, 0);
	submit_bio(bio);

	wait_on_page_locked(tag_page);
	return tag_page;
}

/* only for compress & decompress */
#ifdef CONFIG_ZSWAP
u8 *alloc_page_with_tags(void)
{
	return kmalloc(PAGE_SIZE * 2, GFP_KERNEL);
}

void free_page_with_tags(u8 *p)
{
	kfree(p);
}

void get_page_with_tags(u8 **dst, u8 *src, int *tag_length)
{
	int res;

	*dst = alloc_page_with_tags();
	BUG_ON(!*dst);

	copy_tagged_page(*dst, src);
	res = save_tags_from_data((u64 *)*dst, (u8 *)(*dst + PAGE_SIZE));
	*tag_length = (res) ? TAGS_BYTES_PER_PAGE : 0;

	return;
}
#endif

static int  was_write_tag_page(struct page *page)
{
	return tags_swap_test(page);
}

int e2k_swap_readpage(struct page *page)
{
	int ret = 0;
	struct swap_info_struct *sis = e2k_page_swap_info(page);
	struct page *tag_page;

	READ_SWAP++;
	if (!was_write_tag_page(page)) {
		ret  =  swap_readpage(page, false);
		return ret;
	}
	READ_SWAP_WITH_TAGS++;
	/* read tags */
	tag_page = tag_swap_readpage(page);
	ret  =  swap_readpage(page, false);
	wait_on_page_locked(page);

	if (!tag_page) {
		DebugTM_W(" ###!!!! %s can't find  tag_page\n", __func__);
		return 0;
	}
	wait_on_page_locked(tag_page);
	restore_tags_from_page(page, tag_page);
	/* DEBUG only */
	cmp_page(page);
	return ret;
}

/*
 * This is optimization for tags_pages
 * It is similar to source code of frontswap .c
 * It needs one bit for every page
 *  if bit =1 we must write and read tags
 *  owherwise  NO WRITE, NO READ tags
 */

/*
 * Called when a swap device is swapon'd.
 */
void tags_swap_init(unsigned type, unsigned long *map)
{
	struct swap_info_struct *sis = swap_info[type];

	BUG_ON(sis == NULL);
	BUG_ON(type >= MAX_SWAPFILES);
	if (WARN_ON(!map))
		return;
	sis->tag_swap_map =  map;
	DebugTM(" tags_swap_init sis->max =%d\n", sis->max);
}

int check_tags(unsigned type, unsigned long beg, unsigned long end)
{
	unsigned long offset;
	struct swap_info_struct *sis = swap_info[type];

	for (offset = beg; offset <= end; offset++) {
		if (test_bit(2*offset, sis->tag_swap_map)) {
			return 1;
		}
	}
	return 0;
}
