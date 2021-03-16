/* $Id: page_io.h,v 1.6 2007/09/05 12:05:52 kostin Exp $
 *
 */

#ifndef	_E2K_PAGE_IO_H
#define	_E2K_PAGE_IO_H

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/swap.h>
#include <linux/vmalloc.h>

#include <asm/types.h>
#include <asm/e2k_api.h>
#include <asm/head.h>

#undef  DEBUG_TAG_MODE
#undef  DebugTM
#define DEBUG_TAG_MODE          0       /* Tag memory */
#define DebugTM(...)		DebugPrint(DEBUG_TAG_MODE ,##__VA_ARGS__)


#define TAGS_BITS_PER_LONG	4
#define TAGS_BYTES_PER_PAGE	(PAGE_SIZE / sizeof(long) * \
					TAGS_BITS_PER_LONG / 8)

#define TAGS_PAGES 0xfff
#define TAGS_READ_PAGES 0xff

#define TAGS_PAGES_FOR_COMPRESS 0xff
#define TAGS_READ_PAGES_FOR_COMPRESS 0xff

struct tags_swap_page_table {
	struct page **pages;
	struct page **read_pages;
	int index;		/* last used page */
	int index_read;		/* last used page for readpage */
	int size[2];
	spinlock_t lock_pages;
	spinlock_t lock_read_pages;
};

extern void tags_swap_init(unsigned type, unsigned long *map);
extern void e2k_remove_swap(struct swap_info_struct *sis);
extern void restore_tags_for_data(u64 *, u8 *);
extern u32 save_tags_from_data(u64 *, u8 *);
extern void get_page_with_tags(u8 *, u8 *, int *);
extern int  check_tags(unsigned type, unsigned long beg, unsigned long end);

#endif //_E2K_PAGE_IO_H
