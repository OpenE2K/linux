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

void *mem[AREAS_IN_MULTI_MODE] = {NULL};
unsigned long allocated = 0, aorder;
size_t areas = 1;

typedef enum test_mode {
	SINGLE,
	MULTI
} test_mode_t;

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

int test_map_level(unsigned long addr)
{
	pud_t *pudp = pud_offset(p4d_offset(pgd_offset_k(addr), addr), addr);

	if (kernel_pud_huge(*pudp))
		return E2K_PUD_LEVEL_NUM;

	pmd_t *pmdp = pmd_offset(pudp, addr);

	if (kernel_pmd_huge(*pmdp))
		return E2K_PMD_LEVEL_NUM;

	return E2K_PTE_LEVEL_NUM;
}

void assert_test_work_handler(struct work_struct *work)
{
	WARN_ON(test_map_level((unsigned long)mem[0]) == E2K_PTE_LEVEL_NUM);

	access_write();
	test_free_pages(areas);
}

DECLARE_DELAYED_WORK(dense_test_work, assert_test_work_handler);

static void dense_test(struct work_struct *work)
{
	test_set_mode(SINGLE);
	if (test_alloc_pages(ALLOC_ORDER)) {
		pr_err("Error: page collapse test memory allocation failed\n");
		return;
	}

	set_ro_dsc();
	access_read();
	set_rw_dsc();

	schedule_delayed_work(&dense_test_work, 4 * HZ);
}

DECLARE_DELAYED_WORK(sparse_test_work, assert_test_work_handler);

static void sparse_test(struct work_struct *work)
{
	test_set_mode(MULTI);
	if (test_alloc_pages(ALLOC_ORDER)) {
		pr_err("Error: page collapse test memory allocation failed\n");
		return;
	}

	set_ro_cont();
	access_read();
	set_rw_cont();

	schedule_delayed_work(&sparse_test_work, 4 * HZ);
}

DECLARE_DELAYED_WORK(d_work, dense_test);
DECLARE_DELAYED_WORK(s_work, sparse_test);

static int __init collapse_test_init(void)
{
	pr_info("Running collapse pages test suite...\n");

	schedule_delayed_work(&d_work, 0);
	schedule_delayed_work(&s_work, 10 * HZ);

	return 0;
}

static void __exit collapse_test_exit(void)
{
	if (allocated)
		test_free_pages(areas);
}

module_init(collapse_test_init);
module_exit(collapse_test_exit);
