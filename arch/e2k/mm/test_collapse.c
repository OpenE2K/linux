/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/set_memory.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <asm/mmu_types.h>

MODULE_DESCRIPTION("Module for test page collapse written in pageattr.c");
MODULE_AUTHOR("MCST");
MODULE_LICENSE("GPL v2");

#define ENTRIES 512
#define AREAS_IN_MULTI_MODE 10
#define ALLOC_ORDER 9

static void *mem[AREAS_IN_MULTI_MODE] = {NULL};
static unsigned long allocated = 0, aorder;
static size_t areas = 1;

typedef enum test_mode {
	SINGLE,
	MULTI
} test_mode_t;

static void run_test_sceduler(void);

static int test_free_pages(int n)
{
	if (!allocated)
		return -EINVAL;

	for (size_t i = 0; i < n; i++)
		free_pages((unsigned long)mem[i], aorder);

	allocated = 0;
	return 0;
}

static int test_alloc_pages(unsigned long order)
{
	if (allocated)
		return -EINVAL;

	aorder = order;
	allocated = 1 << order;

	struct page *page;
	for (size_t i = 0; i < areas; i++) {
		page = alloc_pages(GFP_KERNEL, order);
		if (!page) {
			test_free_pages(i);
			return -ENOMEM;
		}

		mem[i] = page_address(page);
	}

	return 0;
}

static void test_set_mode(test_mode_t mode)
{
	areas = (mode == MULTI) ? AREAS_IN_MULTI_MODE : 1;
}

static int set_ro_cont(void)
{
	int rc;

	if (!allocated)
		return -EINVAL;

	for (size_t i = 0; i < areas; i++) {
		rc = set_memory_ro((unsigned long)mem[i], allocated);
		if (rc)
			return rc;
	}

	return 0;
}

static int set_ro_dsc(void)
{
	int rc;

	if (!allocated)
		return -EINVAL;

	for (size_t i = 0; i < areas; i++) {
		for (unsigned long j = 0; j < allocated; j += 2)
			if ((rc = set_memory_ro((unsigned long)mem[i] + (j * PAGE_SIZE), 1)))
				return rc;
	}

	return 0;
}

static int set_rw_cont(void)
{
	int rc;

	if (!allocated)
		return -EINVAL;

	for (size_t i = 0; i < areas; i++) {
		if ((rc = set_memory_rw((unsigned long)mem[i], allocated)))
			return rc;
	}

	return 0;
}

static int set_rw_dsc(void)
{
	int rc;

	if (!allocated)
		return -EINVAL;

	for (size_t i = 0; i < areas; i++) {
		for (unsigned long j = 0; j < allocated; j += 2)
			if ((rc = set_memory_rw((unsigned long)mem[i] + (j * PAGE_SIZE), 1)))
				return rc;
	}

	return 0;
}

static int access_read(void)
{
	char temp = 0;
	char *cmem;

	if (!allocated)
		return -EINVAL;
	for (size_t i = 0; i < areas; i++) {
		cmem = (char *)mem[i];
		for (unsigned long j = 0; j < allocated * PAGE_SIZE; j++)
			temp += READ_ONCE(cmem[j]);
	}

	return 0;

}

static int access_write(void)
{
	char *cmem;

	if (!allocated)
		return -EINVAL;

	for (size_t i = 0; i < areas; i++) {
		cmem = (char *)mem[i];
		for (unsigned long j = 0; j < allocated * PAGE_SIZE; j++)
			cmem[j] = j % 42;
	}

	return 0;
}

static int test_map_level(unsigned long addr)
{
	pud_t *pudp = pud_offset(p4d_offset(pgd_offset_k(addr), addr), addr);

	if (kernel_pud_huge(*pudp))
		return E2K_PUD_LEVEL_NUM;

	pmd_t *pmdp = pmd_offset(pudp, addr);

	if (kernel_pmd_huge(*pmdp))
		return E2K_PMD_LEVEL_NUM;

	return E2K_PTE_LEVEL_NUM;
}

static void assert_test_work_handler(struct work_struct *work)
{
	WARN_ON(test_map_level((unsigned long)mem[0]) == E2K_PTE_LEVEL_NUM);

	access_write();
	test_free_pages(areas);

	run_test_sceduler();
}

static DECLARE_DELAYED_WORK(dense_assert, assert_test_work_handler);

static void dense_test(struct work_struct *work)
{
	test_set_mode(SINGLE);
	if (test_alloc_pages(ALLOC_ORDER)) {
		pr_alert("Error: page collapse test (dense) memory allocation failed\n");
		return;
	}

	set_ro_dsc();
	access_read();
	set_rw_dsc();

	run_test_sceduler();

}

static DECLARE_DELAYED_WORK(sparse_assert, assert_test_work_handler);

static void sparse_test(struct work_struct *work)
{
	test_set_mode(MULTI);
	if (test_alloc_pages(ALLOC_ORDER)) {
		pr_alert("Error: page collapse test (sparse) memory allocation failed\n");
		return;
	}

	set_ro_cont();
	access_read();
	set_rw_cont();

	run_test_sceduler();
}

static DECLARE_DELAYED_WORK(dense_work, dense_test);
static DECLARE_DELAYED_WORK(sparse_work, sparse_test);

static struct delayed_work *suite_sched[] = {
	&dense_work,
	&dense_assert,
	&sparse_work,
	&sparse_assert,
	0
};

static size_t nr_current = 0;

static void run_test_sceduler(void)
{
	if (suite_sched[nr_current] != 0) {
		schedule_delayed_work(suite_sched[nr_current], 2 * HZ);
		nr_current++;
	}
}

static int __init collapse_test_init(void)
{
	pr_info("Running collapse pages test suite...\n");

	run_test_sceduler();

	return 0;
}

static void __exit collapse_test_exit(void)
{
	if (allocated)
		test_free_pages(areas);
}

module_init(collapse_test_init);
module_exit(collapse_test_exit);
