/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

#include <linux/swap.h>
#include <linux/swapops.h>

#include <asm/page_tags.h>
#include <asm/e2k_debug.h>


#undef  DEBUG_TAG_MODE
#undef  DebugTM
#define DEBUG_TAG_MODE	0	/* Tag memory */
#define DebugTM(...)	DebugPrint(DEBUG_TAG_MODE, ##__VA_ARGS__)


static DEFINE_XARRAY(tag_pages);


static void *e2k_swap_allocate_tag_storage(void)
{
	return kmalloc(TAGS_BYTES_PER_PAGE, GFP_KERNEL);
}

static void e2k_swap_free_tag_storage(char *storage)
{
	kfree(storage);
}

int e2k_swap_save_tags(struct page *page)
{
	void *tag_storage, *ret;

	tag_storage = e2k_swap_allocate_tag_storage();
	if (!tag_storage)
		return -ENOMEM;

	if (!save_tags_from_data(page_address(page), tag_storage)) {
		e2k_swap_free_tag_storage(tag_storage);
		return 0;
	}

	DebugTM("e2k_swap_save_tags(): save tags 0x%llx for page 0x%llx (index %ld)\n",
		tag_storage, page, page_private(page));

	ret = xa_store(&tag_pages, page_private(page), tag_storage, GFP_KERNEL);
	if (WARN(xa_is_err(ret), "Failed to store swap tags")) {
		e2k_swap_free_tag_storage(tag_storage);
		return xa_err(ret);
	} else if (ret) {
		e2k_swap_free_tag_storage(ret);
	}

	return 0;
}

void e2k_swap_restore_tags(swp_entry_t entry, struct page *page)
{
	void *tags = xa_load(&tag_pages, entry.val);

	if (!tags)
		return;

	DebugTM("e2k_swap_restore_tags(): restore tags 0x%llx for page 0x%llx (index %ld)\n",
		tags, page, entry.val);

	restore_tags_for_data(page_address(page), tags);
}

void e2k_swap_invalidate_tags(int type, pgoff_t offset)
{
	swp_entry_t entry = swp_entry(type, offset);
	void *tags = xa_erase(&tag_pages, entry.val);

	if (!tags)
		return;

	DebugTM("e2k_swap_invalidate_tags(): invalidate tags 0x%llx for index %ld\n",
		tags, entry.val);

	e2k_swap_free_tag_storage(tags);
}

void e2k_swap_invalidate_tags_area(int type)
{
	swp_entry_t entry = swp_entry(type, 0);
	swp_entry_t last_entry = swp_entry(type + 1, 0);
	void *tags;

	DebugTM("e2k_swap_invalidate_tags_area(): type %d\n", type);

	XA_STATE(xa_state, &tag_pages, entry.val);

	xa_lock(&tag_pages);
	xas_for_each(&xa_state, tags, last_entry.val - 1) {
		__xa_erase(&tag_pages, xa_state.xa_index);
		if (tags)
			e2k_swap_free_tag_storage(tags);
	}
	xa_unlock(&tag_pages);
}
