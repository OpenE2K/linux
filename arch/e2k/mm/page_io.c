/*
 *  page_io.c
 *
 */

#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/bio.h>
#include <linux/writeback.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/swapops.h>
#include <linux/hash.h>

#include <asm/pgtable.h>
#include <asm/page_io.h>

#undef  DEBUG_TAG_MODE
#undef  DebugTM
#define DEBUG_TAG_MODE          0       /* Tag memory */
#define DebugTM(...)		DebugPrint(DEBUG_TAG_MODE ,##__VA_ARGS__)

//extern void create_empty_buffers(struct page *page, kdev_t dev, unsigned long blocksize);

extern void msleep(unsigned int msecs);
struct tags_page_descr empty_descr;

struct read_table_entry read_table[MAX_SWAPFILES];
struct write_table write_table;

int init_write_table = 1;

#if DEBUG_TAG_MODE
static int already_in_list(struct list_head * pos, struct list_head * main){
	struct list_head *head, *item, *n;
	head = main;
	list_for_each_safe(item, n, head){
		if (item == pos)
			return 1;
	}
	return 0;
}
#endif

void release_tags_page(struct tags_page_descr* descr, int type, int table_type) {
	/* table_type = 1 => page belongs to the write_table, 0 - read_table */
	if (atomic_dec_return(&(descr->locks)) == 0) {
		if (table_type) {
    			unsigned long flags;
			DebugTM("Deleting page 0x%p from write table\n",
				descr->tags_page);
			raw_spin_lock_irqsave(&write_table.entries[type].
								list_lock,
						flags);
			list_del(&descr->list);
			raw_spin_unlock_irqrestore(&write_table.entries[type].
							list_lock, flags);

			raw_spin_lock(&write_table.table_lock);
#if DEBUG_TAG_MODE
			if (already_in_list((struct list_head*)descr, &write_table.clean_pages))
				BUG();
#endif
			list_add(&descr->list, &write_table.clean_pages);
			raw_spin_unlock(&write_table.table_lock);
			DebugTM("release_tags_page, up table_sem 0x%lx\n", (unsigned long)&write_table.table_lock);
			up(&write_table.table_sem);
		} else {
			up(&read_table[type].list_sem);
		}
	}
}

void save_tags_from_page(struct page* src_page, struct page* dst_page, long offset) {
	u64 *data_addr;
        u32 *tag_addr;
	register u64 data;
	register u32 tag;
	register u32 tmp;
	long i;
	
	DebugTM("Starting copying the tags from the "
		"page 0x%p (addr 0x%p) to the tags page 0x%p (addr 0x%p) "
		"with the offset 0x%lx\n",
		src_page, page_address(src_page),
		dst_page, page_address(dst_page), offset);
	
	tag_addr = (u32*)page_address(dst_page) + (offset/sizeof(u32));
	data_addr = (u64*)page_address(src_page);
	for (i = 0; i < PAGE_SIZE/(sizeof(u64) << 2); i++) {
		E2K_LOAD_VAL_AND_TAGD(&data_addr[0], data, tag);
		data_addr++;
		E2K_LOAD_VAL_AND_TAGD(&data_addr[0], data, tmp);
		tag |= (tmp << 4);
		data_addr++;
		E2K_LOAD_VAL_AND_TAGD(&data_addr[0], data, tmp);
		tag |= (tmp << 8);
		data_addr++;
		E2K_LOAD_VAL_AND_TAGD(&data_addr[0], data, tmp);
		tag |= (tmp << 12);
		data_addr++;
		tag_addr[0] = tag;
		tag_addr++;
	}
	DebugTM("Completed\n");
}

void restore_tags_from_page(struct page* dst_page, struct page* src_page, long offset) {
	u64 *data_addr;
        u32 *tag_addr;
	register u64 data;
	register u32 tag;
	long i;
	
	DebugTM("Starting copying the tags from the "
		"page 0x%p (addr 0x%p) to the data page 0x%p (addr 0x%p) "
		"with the offset 0x%lx\n", 
		src_page, page_address(src_page),
		dst_page, page_address(dst_page), offset);
	
	tag_addr = (u32*)page_address(src_page) + (offset/sizeof(u32));
	data_addr = (u64*)page_address(dst_page);
	for (i = 0; i < PAGE_SIZE/(sizeof(u64) << 2); i++) {
		data = data_addr[0];
		tag  = tag_addr[0];
                E2K_STORE_VALUE_WITH_TAG(data_addr, data, tag); 
		tag >>= 4;
		data_addr++;
		data = data_addr[0];
                E2K_STORE_VALUE_WITH_TAG(data_addr, data, tag); 
		tag >>= 4;
		data_addr++;
		data = data_addr[0];
                E2K_STORE_VALUE_WITH_TAG(data_addr, data, tag); 
		tag >>= 4;
		data_addr++;
		data = data_addr[0];
                E2K_STORE_VALUE_WITH_TAG(data_addr, data, tag); 
		data_addr++;
		tag_addr++;
	}
	DebugTM("Completed\n");
}

int lookup_tags_tables(swp_entry_t entry, struct tags_page_descr** __descr) {
	int i, type;
	long offset, shift;
	struct write_table_entry* wtable;
	struct read_table_entry* table;
	struct list_head *head, *item, *n;
	struct tags_page_descr* descr;
	int blk_size;
        unsigned long flags;
	
	type = swp_type(entry);
	offset = swp_offset(entry);
	table = &read_table[type];
	wtable = &write_table.entries[type];
	blk_size = write_table.entries[type].block_size;
	
	if (!offset)
		BUG();
	/* Calculate tags page offset */
	shift = TAGS_SHIFT(offset, blk_size);
	offset -= shift;
	
	/* First check write table. Page we are looking for my be in it.
	 * If it is we increment locks count to prevent reusing of this
	 * page. Later we will copy tags from it and release it. */
	raw_spin_lock_irqsave(&wtable->list_lock, flags);
	/* Check current page */
	if (wtable->page != NULL)
		for (i = 0; i < wtable->page->nr_entries; i++)
			if (wtable->page->entries[i].val == entry.val) {
				/* Increment lock count to prevent page unuse */
				atomic_inc(&wtable->page->locks);
				*__descr = wtable->page;
				raw_spin_unlock_irqrestore(&wtable->list_lock,
									flags);
				return 1;
			}
	/* Check other pages */
	head = &wtable->dirty_pages;
	list_for_each_safe(item, n, head) {
		descr = (struct tags_page_descr*)item;
		for (i = 0; i < PAGES_PER_TAGS_PAGE(blk_size); i++)
			if (descr->entries[i].val == entry.val) {
				/* Increment lock count to prevent page unuse */
				atomic_inc(&descr->locks);
				*__descr = descr;
				raw_spin_unlock_irqrestore(&wtable->list_lock,
									flags);
				return 1;
			}
	}
	raw_spin_unlock_irqrestore(&wtable->list_lock, flags);

	raw_spin_lock_irqsave(&table->list_lock, flags);
	/* Check the read table */
	head = &table->dirty_pages;
	list_for_each_safe(item, n, head) {
		descr = (struct tags_page_descr*)item;
		if (swp_offset(descr->entries[0]) == offset) {
			*__descr = descr;
			if (atomic_inc_return(&descr->locks) == 1) {
				/* Decrement resource count 
				 * No lock because sem_count MUST be > 0 */
				down(&table->list_sem);
			}
			raw_spin_unlock_irqrestore(&table->list_lock, flags);
			return 1;
		}
	}
		
	/* Page was not found */
	/* Check resources */
	raw_spin_unlock_irqrestore(&table->list_lock, flags);
	down(&table->list_sem);
	raw_spin_lock_irqsave(&table->list_lock, flags);

	/* Search the table again in the opposite direction */
	head = &table->dirty_pages;
	list_for_each_safe(item, n, head) {
		descr = (struct tags_page_descr*)item;
		if (atomic_read(&descr->locks) == 0) {
			*__descr = descr;
			/*for (i = 0; i < PAGES_PER_TAGS_PAGE(blk_size); i++) */
			descr->entries[0] = swp_entry(type, offset);
			atomic_inc(&descr->locks);
			raw_spin_unlock_irqrestore(&table->list_lock, flags);
			return 0;
		}
	}
	raw_spin_unlock_irqrestore(&table->list_lock, flags);
	panic("Cant find free page in the read swap table.");
}

int get_tags_page(swp_entry_t entry, struct tags_page_descr** __descr, 
		long* page_shift) {
	int i, type;
	long offset, shift;
	struct write_table_entry* wtable;
	struct read_table_entry* table;
	struct list_head *head, *item, *n;
	struct tags_page_descr* descr;
	int blk_size;
        unsigned long flags;

	type = swp_type(entry);
	offset = swp_offset(entry);
	table = &read_table[type];
	wtable = &write_table.entries[type];
	blk_size = write_table.entries[type].block_size;

	if (!offset)
		BUG();
	/* Calculate tags page offset */
	shift = TAGS_SHIFT(offset, blk_size);
	offset -= shift;
	shift = (shift - 1) * blk_size;
	
	raw_spin_lock_irqsave(&wtable->list_lock, flags);
	/* Check current page */
	if (wtable->page != NULL)
		for (i = 0; i < wtable->page->nr_entries; i++)
			if (wtable->page->entries[i].val == entry.val) {
				*__descr = wtable->page;
				*page_shift = i * blk_size;
				raw_spin_unlock_irqrestore(&wtable->list_lock,
									flags);
				return 1;
			}
	/* Check other pages */
	head = &wtable->dirty_pages;
	list_for_each_safe(item, n, head) {
		descr = (struct tags_page_descr*)item;
		for (i = 0; i < PAGES_PER_TAGS_PAGE(blk_size); i++)
			if (descr->entries[i].val == entry.val) {
				*page_shift = i * blk_size;
				*__descr = descr;
				raw_spin_unlock_irqrestore(&wtable->list_lock,
									flags);
				return 1;
			}
	}
	raw_spin_unlock_irqrestore(&wtable->list_lock, flags);

	raw_spin_lock_irqsave(&table->list_lock, flags);
	head = &table->dirty_pages;
	list_for_each_safe(item, n, head) {
		descr = (struct tags_page_descr*)item;
		if (swp_offset(descr->entries[0]) == offset) {
			*__descr = descr;
			*page_shift = shift;
			raw_spin_unlock_irqrestore(&table->list_lock, flags);
			return 0;
		}
	}
	raw_spin_unlock_irqrestore(&table->list_lock, flags);
	/* Page MUST be in the table */
	BUG();
	return 0;
}

static wait_queue_head_t *page_waitqueue(struct page *page)
{
	const struct zone *zone = page_zone(page);

	return &zone->wait_table[hash_ptr(page, zone->wait_table_bits)];
}

static void e2k_end_swap_bio_write(struct bio *bio, int bytes_done)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct page *page = bio->bi_io_vec[0].bv_page;
	swp_entry_t entry;
	int type;
	struct write_table_entry* table;
	struct list_head *head, *item, *n;
	struct tags_page_descr* descr;
	wait_queue_head_t *waitqueue = page_waitqueue(page);
	unsigned long flags;

	if (bio->bi_iter.bi_size)
		return;

	if (!uptodate)
		SetPageError(page);

/*	if (waitqueue_active(waitqueue))
		wake_up_all(waitqueue);*/
	__wake_up_bit(waitqueue, &page->flags, PG_writeback);
	bio_put(bio);

	entry.val = page->index;
	type = swp_type(entry);
	table = &write_table.entries[type];
	
	/* Delete reference to the page. read_page routines may have extra 
	 * references waiting for IO complete. If locks > 1 then read_page 
	 * must up semaphore. */
	raw_spin_lock_irqsave(&table->list_lock, flags);
	head = &table->dirty_pages;
	list_for_each_safe(item, n, head) {
		descr = (struct tags_page_descr*)item;
		if (descr->tags_page == page) {
			if (atomic_dec_return(&descr->locks) == 0) {
				list_del(item);
				raw_spin_unlock_irqrestore(&table->list_lock,
								flags);
				
				raw_spin_lock_irqsave(&write_table.table_lock,
								flags);
#if DEBUG_TAG_MODE
				if (already_in_list(item, &write_table.clean_pages))
					BUG();
#endif
				list_add(item, &write_table.clean_pages);
				raw_spin_unlock_irqrestore(
					&write_table.table_lock, flags);
				DebugTM("e2k_end_swap_bio_write, up table_sem 0x%lx\n", (unsigned long)&write_table.table_sem);
				up(&write_table.table_sem);
//				printk("First return\n");
				return;
			} else {
				raw_spin_unlock_irqrestore(&table->list_lock,
								flags);
//				printk("Second return\n");
				return;
			}
		}
//		printk("item = 0x%lx\n", (unsigned long)item);
	}
	/* Page must be in the list */
	raw_spin_unlock_irqrestore(&table->list_lock, flags);
	BUG();
}

static struct bio *e2k_get_swap_bio(int gfp_flags, unsigned long offset,
		unsigned long type, unsigned long shift, struct page *page, 
		unsigned long length, bio_end_io_t end_io)
{
	struct bio *bio;

	bio = bio_alloc(gfp_flags, 1);
	if (bio) {
		bio->bi_iter.bi_sector = map_swap_page(page, &bio->bi_bdev);
		bio->bi_iter.bi_sector <<= PAGE_SHIFT - 9;
		bio->bi_io_vec[0].bv_page = page;
		bio->bi_io_vec[0].bv_len = length;
		bio->bi_io_vec[0].bv_offset = 0;
		bio->bi_vcnt = 1;
		bio->bi_iter.bi_idx = 0;
		bio->bi_iter.bi_size = length;
		bio->bi_end_io = end_io;
	}
	return bio;
}

int write_tags_page(struct tags_page_descr* descr, swp_entry_t entry, 
		struct writeback_control *wbc) {
	unsigned long offset, tag_offset, shift;
	struct page* page = descr->tags_page;
	struct bio *bio;
	int rw = WRITE;
	struct write_table_entry* table;
	int blk_size;

	table = &write_table.entries[swp_type(entry)];
	blk_size = table->block_size;
	offset = swp_offset(descr->entries[0]);
	tag_offset = SWAP_TAGS_OFFSET(offset, blk_size);
        shift = TAGS_SHIFT(offset, blk_size) - 1;

	bio = e2k_get_swap_bio(GFP_NOIO, tag_offset, swp_type(entry), shift, 
			page, blk_size, e2k_end_swap_bio_write);
	if (bio == NULL) {
		BUG();
		return -ENOMEM;	
	}
	if (wbc->sync_mode == WB_SYNC_ALL)
		rw |= REQ_SYNC;
	count_vm_event(PSWPOUT);
	DebugTM("my bio->bi_sector = %lx\n", bio->bi_iter.bi_sector);
	submit_bio(rw, bio);
	return 0;
}

