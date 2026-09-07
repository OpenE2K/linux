/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_MODULE_H_
#define _E2K_MODULE_H_
/*
 * This file contains the E2K architecture specific module code.
 */

#ifdef CONFIG_E2K_MODULES_DUPLICATION
struct page_duplication {
	struct list_head list;
	struct page *copy;
	struct page *orig;
	bool is_huge;
};

struct mod_arch_specific {
	/*
	 * Some of module pages are duplicated across NUMA nodes in e2k.
	 * This list is used to track these pages, so that they can be
	 * easily freed when the module is unloaded.
	 * List entries have type 'struct page_duplication'.
	 */
	struct list_head duplicated_pages;
};
#define MODULE_ARCH_INIT { \
	.duplicated_pages = LIST_HEAD_INIT(THIS_MODULE->arch.duplicated_pages) \
}

static inline struct page_duplication *
find_page_in_duplicated_pages_list(struct list_head *duplicated_pages,
				   struct page *page_to_find)
{
	struct page_duplication *item;

	list_for_each_entry(item, duplicated_pages, list) {
		if (item->copy == page_to_find)
			return item;
	}

	return NULL;
}
#else /* !CONFIG_E2K_MODULES_DUPLICATION */
struct mod_arch_specific { };
#endif /* CONFIG_E2K_MODULES_DUPLICATION */

#define Elf_Shdr Elf64_Shdr
#define Elf_Sym Elf64_Sym
#define Elf_Ehdr Elf64_Ehdr

#endif /* _E2K_MODULE_H_ */
