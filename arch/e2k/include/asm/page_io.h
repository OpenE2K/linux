/* $Id: page_io.h,v 1.6 2007/09/05 12:05:52 kostin Exp $
 *
 */

#ifndef	_E2K_PAGE_IO_H
#define	_E2K_PAGE_IO_H

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/swap.h>

#include <asm/types.h>
#include <asm/e2k_api.h>
#include <asm/head.h>
//#include <asm/process.h>

#undef  DEBUG_TAG_MODE
#undef  DebugTM
#define DEBUG_TAG_MODE          0       /* Tag memory */
#define DebugTM(...)		DebugPrint(DEBUG_TAG_MODE ,##__VA_ARGS__)

#define MAX_ENTRIES (PAGE_SIZE/512)
#define PAGES_PER_TAGS_PAGE(blck_size)  (PAGE_SIZE/(blck_size))
#define TAGS_SHIFT(offset, blck_size) ((offset - 1) %\
	       	(PAGES_PER_TAGS_PAGE(blck_size) + 1))
// I dont know what number to choose
#define TAGS_PAGES_FOR_READ 8
// Based on pager_daemon.swap_cluster * (1 << page_cluster)), where current 
// values are 8 & 4. We ignore 8 because we write tags for 8 pages.
#define TAGS_PAGES_FOR_WRITE 16
#define SWAP_TAGS_OFFSET(offset, blck_size)  (offset - \
		TAGS_SHIFT(offset, blck_size))

struct tags_page_descr {
	struct list_head list;
	// Page where we save tags
	struct page* 	tags_page;
	// Swap entries associated with this tags page
	swp_entry_t	entries[MAX_ENTRIES];
	// Current number of saved entries
	long 		nr_entries;
	// Flags
	atomic_t	locks;
};

struct read_table_entry {
	struct tags_page_descr pages[TAGS_PAGES_FOR_READ];
	struct semaphore list_sem;
	raw_spinlock_t list_lock;
	struct list_head dirty_pages;
	int block_size;
};

struct write_table_entry {
	struct tags_page_descr* page;
	raw_spinlock_t list_lock;
	struct list_head dirty_pages;
	int block_size;
};

struct write_table {
	struct tags_page_descr pages[TAGS_PAGES_FOR_WRITE];
	struct write_table_entry entries[MAX_SWAPFILES]; 
	struct semaphore table_sem;
	raw_spinlock_t table_lock;
	struct list_head clean_pages;
};

#endif //_E2K_PAGE_IO_H
