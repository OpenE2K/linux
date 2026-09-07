/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 MCST
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/debugfs.h>

#include <asm/pool.h>

MODULE_DESCRIPTION("Module for testing e2k memory pool");
MODULE_AUTHOR("MCST");
MODULE_LICENSE("GPL");

static int run_pool_create_no_numa(enum pool_allocator allocator, unsigned long capacity,
				   unsigned long objsize)
{
	struct pool *pool;

	pool = pool_create(capacity, objsize, allocator,
			   GFP_KERNEL | __GFP_NOWARN, NUMA_NO_NODE);
	if (!pool)
		return -ENOMEM;

	pool_destroy(pool);

	return 0;
}

static int run_pool_create_numa(enum pool_allocator allocator, unsigned long capacity,
				unsigned long objsize)
{
	struct pool *pools[MAX_NUMNODES] = { NULL };
	int ret = 0, node = 0;

	for_each_node_state(node, N_MEMORY) {
		pools[node] = pool_create(capacity, objsize, allocator,
					  GFP_KERNEL | __GFP_NOWARN, node);
		if (!pools[node]) {
			ret = -ENOMEM;
			break;
		}
	}

	node--;

	for (; node >= 0; node--) {
		if (pools[node])
			pool_destroy(pools[node]);
	}

	return ret;
}

static int run_pool_create(enum pool_allocator allocator, unsigned long capacity,
			   unsigned long objsize, bool test_numa)
{
	return (test_numa) ? run_pool_create_numa(allocator, capacity, objsize) :
			     run_pool_create_no_numa(allocator, capacity, objsize);
}

static unsigned long get_capacity(unsigned int order)
{
	unsigned long capacity = 1 << order;

	if (order > 1) {
		/* Bring some randomness */
		capacity -= get_cycles() % (capacity >> 1);
	}

	return capacity;
}

static int run_pool_create_buddy(bool test_huge, bool test_numa)
{
	int ret = 0, attempts = 5;
	unsigned int order = 0;
	unsigned long capacity = 0, objsize = test_huge ? HPAGE_SHIFT - PAGE_SHIFT : 0;

	pr_info("Test buddy with %s pages %s\n", test_huge ? "huge" : "small",
		test_numa ? "on all nodes" : "on any node");

	for (order = 0;; order++) {
		capacity = get_capacity(order);

		pr_info("Test capacity %ld\n", capacity);

		ret = run_pool_create(POOL_BUDDY, capacity, objsize, test_numa);
		if (ret) {
			attempts--;
			order--;
			pr_info("Failed to allocate a pool for %ld %s pages, %d attempts left\n",
				capacity, test_huge ? "huge" : "small", attempts);
			if (attempts <= 0)
				break;
		}
	}

	return 0;
}

static void test_pool_create_buddy(void)
{
	run_pool_create_buddy(false, false);
	run_pool_create_buddy(true, false);
	run_pool_create_buddy(false, true);
	run_pool_create_buddy(true, true);
}

static int run_pool_create_slab(unsigned long object_size, bool test_numa)
{
	int ret = 0, attempts = 5;
	unsigned int order = 0;
	unsigned long capacity = 0;

	pr_info("Test slab with object size %ld %s\n", object_size,
		test_numa ? "on all nodes" : "on any node");

	for (order = 0;; order++) {
		capacity = get_capacity(order);

		pr_info("Test capacity %ld\n", capacity);

		ret = run_pool_create(POOL_SLAB, capacity, object_size, test_numa);
		if (ret) {
			attempts--;
			order--;
			pr_info("Failed to allocate a pool for %ld objects of size %ld, %d attemps left\n",
				capacity, object_size, attempts);
			if (attempts <= 0)
				break;
		}
	}

	return 0;
}

static unsigned long get_lower(int i)
{
	return 8 << (3 * i);
}

static unsigned long get_upper(int i)
{
	return 8 * get_lower(i);
}

static void test_pool_create_slab_choose_objsize(bool test_numa)
{
	int i = 0;
	unsigned long objsize = 0;

	for (i = 0; i < 4; i++) {
		/*
		 * Choose random slab object size in range [8^(i + 1); 8^(i + 2)).
		 * If i is 0, the range is [8; 8*8); if i is 1, the range is [8*8; 8*8*8),
		 * and so on.
		 *
		 * NB: if slab object size is bigger than one or two 4k-page sizes,
		 * slab allocator turns into buddy under the hood. However, the type of
		 * pool is still POOL_SLAB, and we may test this case with big 'objsize'
		 * when i == 3.
		 */
		objsize = get_cycles() % (get_upper(i) - get_lower(i)) + get_lower(i);

		run_pool_create_slab(objsize, test_numa);
	}
}

static void test_pool_create_slab(void)
{
	test_pool_create_slab_choose_objsize(false);
	test_pool_create_slab_choose_objsize(true);
}

/*
 * Run pool_create() many times with different pool capacities
 * and allocator types to test main and error paths of this function.
 */
static void run_pool_create_tests(void)
{
	test_pool_create_buddy();
	test_pool_create_slab();
}

static atomic_t test_pool_create_running;

static ssize_t read_test_pool_create(struct file *file, char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	char buf[3];

	if (atomic_read(&test_pool_create_running) > 0)
		buf[0] = '1';
	else
		buf[0] = '0';
	buf[1] = '\n';
	buf[2] = '\0';

	return simple_read_from_buffer(user_buf, count, ppos, buf, 2);
}

static ssize_t write_test_pool_create(struct file *file, const char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	if (atomic_inc_return(&test_pool_create_running) > 1) {
		/* The test is already running */
		count = -EBUSY;
		goto out;
	}

	/* Run pool_create() testing */
	run_pool_create_tests();

out:
	atomic_dec(&test_pool_create_running);
	return count;
}

static const struct file_operations test_pool_create_fops = {
	.read =		read_test_pool_create,
	.write =	write_test_pool_create,
	.open =		simple_open,
	.llseek =	default_llseek,
};

static struct dentry *test_pool_create_debugfs_entry;

/*
 * Fault injection mechanism does greatly reduce the time for this
 * test to pass. However, running module init code with fault injection
 * enabled is a bad idea, so this module provides a window after its init
 * code during which user can set up fault injection for the main pool_create()
 * testing. Debugfs hook is created in this function; via this hook user can
 * run pool_create() testing after loading the module and setting up
 * fault injection mechanism.
 */
static int __init test_pool_create(void)
{
	test_pool_create_debugfs_entry = debugfs_create_file("test_pool_create", 0600,
							     arch_debugfs_dir, NULL,
							     &test_pool_create_fops);

	if (!test_pool_create_debugfs_entry)
		return -ENOMEM;

	return 0;
}

static int __init test_pool_init(void)
{
	return test_pool_create();
}
module_init(test_pool_init);

static void __exit test_pool_exit(void)
{
	debugfs_remove(test_pool_create_debugfs_entry);
}
module_exit(test_pool_exit);
