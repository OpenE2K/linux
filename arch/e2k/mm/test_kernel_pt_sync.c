/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 MCST
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/torture.h>

#include <asm/set_memory.h>
#include <asm/e2k_debug.h>

MODULE_DESCRIPTION("Module for 'kernel_pt_lock' synchronization testing");
MODULE_AUTHOR("MCST");
MODULE_LICENSE("GPL");

/*
 * ===== Main idea =====
 * There are several operations that work with kernel page table:
 * - set_memory_*();
 * - memory duplication across NUMA nodes;
 * - page split and page collapse;
 * All of them acquire the same spinlock 'kernel_pt_lock' to synchronize
 * with each other. This stress-test checks that this synchronization
 * works well.
 *
 * ===== Test threads =====
 * To make a pressure upon 'kernel_pt_lock', this test spawns several threads.
 * They can have one of four different types (encoded via enum thread_type):
 *  - COLLAPSE_THREAD: single thread that tests how page collapse works.
 *		       The creation of this thread is enabled by default;
 *		       can be disabled by setting 'test_collapse' module parameter
 *		       to false;
 *  - DUPLICATION_THREAD: these threads run duplication on a memory chunk.
 *			  There is no deduplication operation and page table
 *			  for memory area is duplicated at kernel startup, so
 *			  threads of this type just traverse PT with 'kernel_pt_lock'
 *			  acquired that still can reveal some problems in
 *			  synchronization. The number of duplication threads
 *			  can be specified via 'duplication_threads_num' module
 *			  parameter. If it is negative or absent, 2 duplication
 *			  threads are run.
 *  - CACHE_POLICY_THREAD: single thread that runs set_memory_{wb, uc, wc}()
 *			   on a memory chunk. There can be no more than one
 *			   thread of this type. This thread is spawn by default.
 *			   If not needed, set 'test_cache_policy' module parameter
 *			   to false.
 *  - OTHER_SMA_THREAD: these threads run set_memory_{ro, rw, x, nx, p_noflush}()
 *			functions on a memory chunk. The number of such threads
 *			can be set via 'sma_threads_num' module parameter. If this
 *			parameter is negative or absent, 4 threads of this type
 *			will run.
 *
 * ===== Memory area =====
 * This test allocates a memory area, which is used to run set_memory_*(),
 * duplication and to check page collapse. The size of the area is provided
 * by user via 'area_order' module parameter, although there are some
 * restrictions (see get_area_order()). The area is divided into a number
 * of chunks, so that every thread operates on several adjacent chunks.
 * The number of chunks depens on the number of non-collapse test threads,
 * memory area size and whether collapse is tested at all
 * (for details, see get_chunks_num()).
 *
 * ===== Test timing =====
 * All test threads have two run phases: 'active' and 'sleep'. For duplication,
 * cache policy and other sma threads active phase is a time when they
 * constantly call duplication, set_memory_{wb, uc, wc}() and
 * set_memory_{ro, rw, x, nx, p_noflush}() respectively. Sleep phase is
 * a time when they do nothing but call scheduler until sleep time is over.
 * If collapse test is disabled, active and sleep phases just follow each other.
 *
 * In case of testing collapse, active and sleep phases work in a bit different
 * manner. Collapse thread sets the flag 'collapse_test_time' to false to start
 * its sleep phase. While this flag is false, other threads run their active and
 * sleep phases as usual. After the sleep phase of collapse thread ends, it
 * rises 'collapse_test_time' flag and enters its active phase. When the flag is
 * true, all the threads except collapse thread just run their sleep phases,
 * so do not touch memory area and it can be evenually collapsed by the kernel.
 * The collapse thread also sleeps during its active phase and before the active
 * phase ends it checks that memory area was fully collapsed.
 */

char *torture_type = "kernel_pt_sync";

torture_param(int, duplication_threads_num, -1, "Number of threads that test memory duplication");
torture_param(int, sma_threads_num, -1,
	      "Number of threads that calls set_memory_{ro, rw, x, nx, p_noflush}()");
torture_param(bool, test_cache_policy, true, "Run a thread that calls set_memory_{wb, uc, wc}()");
torture_param(bool, test_collapse, true, "Test that small pages are collapsed to huge page");
torture_param(int, area_order, -1, "Order of memory area on which testing take place");

/* We need one collapse thread if 'test_collapse' is true */
static inline int collapse_threads_num(void)
{
	return test_collapse ? 1 : 0;
}

/* If not provided by user, 2 threads are enough */
static inline int dupl_threads_num(int user_num)
{
	return (user_num >= 0) ? user_num : 2;
}

/*
 * There should be no more than one thread that changes caching policy,
 * see the comment before test_set_memory_cache_policy(). Run this
 * thread if 'test_cache_policy' is true.
 */
static inline int cache_policy_threads_num(void)
{
	return test_cache_policy ? 1 : 0;
}

/* If not provided by user, 4 threads are ok */
static inline int other_sma_threads_num(int user_num)
{
	return (user_num >= 0) ? user_num : 4;
}

#define HUGE_PAGE_ORDER (PMD_SHIFT - PTE_SHIFT)

static inline int get_area_order(int user_order)
{
	/* We need at least one huge page for collapse to run */
	if (test_collapse && (user_order < HUGE_PAGE_ORDER))
		return HUGE_PAGE_ORDER;

	if (user_order < 0)
		return 0;

	if (user_order >= MAX_ORDER)
		return MAX_ORDER - 1;

	return user_order;
}

enum thread_type {
	COLLAPSE_THREAD,
	DUPLICATION_THREAD,
	CACHE_POLICY_THREAD,
	OTHER_SMA_THREAD
};

char *type_to_str(enum thread_type type)
{
	switch (type) {
	case COLLAPSE_THREAD:
		return "'collapse'";
	case DUPLICATION_THREAD:
		return "'duplication'";
	case CACHE_POLICY_THREAD:
		return "'cache policy'";
	case OTHER_SMA_THREAD:
		return "'other sma'";
	default:
		return "'unknown'";
	}
}

struct test_memory {
	unsigned long start;	/* page-aligned start of memory area */
	unsigned int order;	/* order of memory area */
};

static int alloc_area(struct test_memory *mem)
{
	unsigned int order = get_area_order(area_order);

	/*  Allocate one huge page */
	mem->start = __get_free_pages(GFP_KERNEL, order);
	if (!mem->start)
		return -ENOMEM;

	mem->order = order;

	pr_debug("area of size 2^%d pages allocated\n", order);

	return 0;
}

static void free_area(struct test_memory *mem)
{
	free_pages(mem->start, mem->order);
}

struct thread_params {
	/* Thread's index in test_params->params array */
	int idx;

	/* Active and sleep times of the thread */
	int active_time;
	int sleep_time;

	/* Description of memory chunk the thread works with */
	unsigned long start;	/* start address of memory chunk */
	unsigned long pages;	/* chunk size in pages */

	/* Type of current thread */
	enum thread_type type;
};

struct test_params {
	int collapse_threads_num;
	int duplication_threads_num;
	int cache_policy_threads_num;
	int other_sma_threads_num;

	/*
	 * Number of parts the area split to. Each thread works with
	 * a few adjacent parts at a time.
	 */
	unsigned int chunks_num;

	struct test_memory mem;

	/* Pointers to task_structs of test threads */
	struct task_struct **tasks;

	/* Parameters of test threads */
	struct thread_params *params;
};

static inline int get_threads_num(const struct test_params *params)
{
	return	params->collapse_threads_num +
		params->duplication_threads_num +
		params->cache_policy_threads_num +
		params->other_sma_threads_num;
}

static inline unsigned int get_chunks_num(const struct test_params *params)
{
	/* Exclude number of collapse threads since these threads do not modify memory area */
	int memory_threads_num = params->duplication_threads_num +
				 params->cache_policy_threads_num +
				 params->other_sma_threads_num;
	int area_order = params->mem.order;
	int num_pages = 1UL << area_order, num_huge_pages;

	if (params->collapse_threads_num > 0) {
		/*
		 * If we need to test collapse, make sure we will split
		 * every huge page in the area into 8 parts.
		 */
		BUG_ON(area_order < HUGE_PAGE_ORDER);
		num_huge_pages = 1UL << (area_order - HUGE_PAGE_ORDER);
		return max(8 * num_huge_pages, memory_threads_num);
	}

	return min(num_pages, memory_threads_num);
}

static struct test_params *test_params;

static inline unsigned long chunk_start_page(int chunk_num)
{
	unsigned long num_pages = 1UL << test_params->mem.order;
	unsigned long chunks_num = test_params->chunks_num;

	WARN_ON(chunk_num < 0 || chunk_num > chunks_num);

	return num_pages * chunk_num / chunks_num;
}

static unsigned long get_ith_start(int chunk_num)
{
	unsigned long chunks_num = test_params->chunks_num;
	unsigned long start = test_params->mem.start;

	WARN_ON(chunk_num < 0 || chunk_num >= chunks_num);

	return start + PAGE_SIZE * chunk_start_page(chunk_num);
}

static unsigned long get_ith_size(int chunk_num)
{
	unsigned long chunks_num = test_params->chunks_num;

	WARN_ON(chunk_num < 0 || chunk_num >= chunks_num);

	return chunk_start_page(chunk_num + 1) - chunk_start_page(chunk_num);
}

/*
 * Test memory area is split into several chunks. Each thread receives
 * three chunks for testing: the one with number 'chunk_num' and its
 * left and right neighbours (if any).
 */
static void fill_ith_start_and_size(int thread_num, int chunk_num)
{
	struct thread_params *thread_params = &test_params->params[thread_num];
	unsigned long chunks_num = test_params->chunks_num;

	if (chunks_num == 1) {
		thread_params->start = get_ith_start(0);
		thread_params->pages = get_ith_size(0);
	} else if (chunks_num == 2 || chunk_num == 0) {
		thread_params->start = get_ith_start(0);
		thread_params->pages = get_ith_size(0) + get_ith_size(1);
	} else if (chunk_num == chunks_num - 1) {
		thread_params->start = get_ith_start(chunks_num - 2);
		thread_params->pages = get_ith_size(chunks_num - 2) + get_ith_size(chunks_num - 1);
	} else {
		thread_params->start = get_ith_start(chunk_num - 1);
		thread_params->pages = get_ith_size(chunk_num - 1) +
				       get_ith_size(chunk_num) +
				       get_ith_size(chunk_num + 1);
	}
}

static void set_random_start_and_size(int thread_num)
{
	unsigned long chunks_num = test_params->chunks_num;

	fill_ith_start_and_size(thread_num, get_cycles() % chunks_num);
}

static int test_duplication(const struct thread_params *params)
{
	/*
	 * Do not duplicate pages: this test allocates memory area
	 * in linear mapping area, which is duplicated at page table
	 * levels only. An attempt to duplicate pages resulted in
	 * random bugs when memory area was about 2^12 pages, so
	 * it was turned off. But if you are brave enough you may
	 * try to change true -> false and enjoy the debugging process.
	 */
	return kernel_image_duplicate_page_range((void *)params->start,
						 params->pages * PAGE_SIZE, true);
}

/*
 * Changing caching policy attributes in arbitrary order is not allowed
 * by the kernel. It helps to detect buggy drivers.
 *
 * Thats why there can't be more than one thread that changes caching policy
 * attributes: otherwise, changing order will be random.
 */
static int test_set_memory_cache_policy(const struct thread_params *params)
{
	int ret = 0;
	unsigned long start = params->start, size = params->pages;

#define WARN_IF_FAIL(expr) WARN_ONCE(expr, #expr)

	/* Set _wb between every change of memory caching policy */
	ret =		WARN_IF_FAIL(set_memory_uc(start, size));
	ret = ret ?:	WARN_IF_FAIL(set_memory_wb(start, size));
	ret = ret ?:	WARN_IF_FAIL(set_memory_wc(start, size));
	ret = ret ?:	WARN_IF_FAIL(set_memory_wb(start, size));

	return ret;
}

static int test_set_memory_other_sma(const struct thread_params *params)
{
	int ret = 0;
	unsigned long start = params->start, size = params->pages;

#define WARN_IF_FAIL(expr) WARN_ONCE(expr, #expr)

	ret =		WARN_IF_FAIL(set_memory_ro(start, size));
	ret = ret ?:	WARN_IF_FAIL(set_memory_x(start, size));
	ret = ret ?:	WARN_IF_FAIL(set_memory_nx(start, size));
	ret = ret ?:	WARN_IF_FAIL(set_memory_p(start, size));
	ret = ret ?:	WARN_IF_FAIL(set_memory_p_noflush(start, size));

	/*
	 * Do NOT run set_memory_np() and set_memory_np_noflush() here because
	 * present bit can't be resetted after both present and executable bits
	 * were set. Since this multi-threaded test calls set_memory_{x,p,np*}()
	 * in a random order, do never reset present bit to avoid such situation.
	 */

	/* Return back to read-write state so that page collapse can run later */
	ret = ret ?:	WARN_IF_FAIL(set_memory_rw(start, size));

	return ret;
}

static int run_test_func(const struct thread_params *params)
{
	switch (params->type) {
	case COLLAPSE_THREAD:
		/* This function should not be called for collapse thread */
		pr_err("invalid call\n");
		return -EINVAL;
	case DUPLICATION_THREAD:
		return test_duplication(params);
	case CACHE_POLICY_THREAD:
		return test_set_memory_cache_policy(params);
	case OTHER_SMA_THREAD:
		return test_set_memory_other_sma(params);
	default:
		pr_err("wrong thread type\n");
		return -EINVAL;
	}

	unreachable();
}

static int run_test_batch(const struct thread_params *params)
{
	int ret;
	u64 batch_start_time = ktime_get_ns(), cur_time = batch_start_time;

	while (cur_time < batch_start_time + jiffies_to_nsecs(10)) {
		ret = run_test_func(params);
		if (ret)
			return ret;

		cur_time = ktime_get_ns();
	}

	schedule_timeout_interruptible(1);

	return 0;
}

static int run_active_phase(const struct thread_params *params, u64 deadline)
{
	int ret;
	u64 cur_time = ktime_get_ns();

	pr_debug("thread #%d [type %s] starts active phase\n",
		 params->idx, type_to_str(params->type));

	while (cur_time < deadline) {
		ret = run_test_batch(params);
		if (ret)
			return ret;

		cur_time = ktime_get_ns();
	}

	pr_debug("thread #%d [type %s] finished active phase\n",
		 params->idx, type_to_str(params->type));

	return 0;
}

static int run_sleep_phase(const struct thread_params *params, u64 deadline)
{
	u64 cur_time = ktime_get_ns();

	while (cur_time < deadline) {
		/* Sleep for 20 jiffies */
		schedule_timeout_interruptible(20);

		cur_time = ktime_get_ns();
	}

	return 0;
}

static int test_kernel_pt_sync_without_collapse(const struct thread_params *params)
{
	int ret;

	/* Active phase */
	ret = run_active_phase(params, ktime_get_ns() + params->active_time * NSEC_PER_SEC);
	if (ret)
		return ret;

	/* Choose another memory area for the next time */
	set_random_start_and_size(params->idx);

	/* Sleep phase */
	ret = run_sleep_phase(params, ktime_get_ns() + params->sleep_time * NSEC_PER_SEC);

	return ret;
}

/* Used only when collapse_thread is true */
static bool collapse_test_time;

struct collapse_stats {
	unsigned long runs;
	unsigned long failures;
};

static struct collapse_stats collapse_stats;

void print_collapse_stats(void)
{
	if (test_params->collapse_threads_num > 0) {
		if (collapse_stats.failures) {
			pr_info("collapse test results: FAILURE (%ld out of %ld runs failed)\n",
				collapse_stats.failures, collapse_stats.runs);
		} else {
			pr_info("collapse test results: SUCCESS\n");
		}
	}
}

static int run_non_collapse_thread(const struct thread_params *params)
{
	int ret;

	/* Run testing if not waiting for collapse */
	if (!READ_ONCE(collapse_test_time)) {
		ret = run_active_phase(params, ktime_get_ns() + params->active_time * NSEC_PER_SEC);
		if (ret)
			return ret;
	}

	/* Choose another memory area for the next time */
	set_random_start_and_size(params->idx);

	/* Sleep phase */
	ret = run_sleep_phase(params, ktime_get_ns() + params->sleep_time * NSEC_PER_SEC);
	if (ret)
		return ret;

	return 0;
}

/*
 * Checks that memory pointed by addr is mapped as huge (or giant) page. We can't
 * acquire 'kernel_pt_lock' here. Just hope that no other thread is now working
 * with this memory area.
 *
 * Returns -EINVAL on error, 0 if 'addr' points to a huge page and
 * 1 if it points to small page.
 */
static int check_huge_page(unsigned long addr)
{
	pgd_t *pgdp, *pt_root;
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;

	/*
	 * Get PT root directly from MMU register, since neither init_mm is accessible
	 * from a module nor current->mm is valid for a kernel thread.
	 */
	pt_root = (pgd_t *)__va(MMU_IS_SEPARATE_PT() ?
				NATIVE_READ_MMU_OS_PPTB_REG_VALUE() : READ_MMU_U_PPTB());

	pgdp = pgd_offset_pgd(pt_root, addr);
	if (pgd_none(*pgdp) || kernel_pgd_huge(*pgdp))
		return -EINVAL;

	p4dp = p4d_offset(pgdp, addr);
	if (p4d_none(*p4dp) || kernel_p4d_huge(*p4dp))
		return -EINVAL;

	pudp = pud_offset(p4dp, addr);
	if (pud_none(*pudp))
		return -EINVAL;

	if (kernel_pud_huge(*pudp)) {
		pr_debug("giant page found\n");
		return 0;
	}

	pmdp = pmd_offset(pudp, addr);
	if (pmd_none(*pmdp))
		return -EINVAL;

	if (kernel_pmd_huge(*pmdp)) {
		pr_debug("huge page found\n");
		return 0;
	}

	return 1;
}

/*
 * Return value is negative if an error occurred, otherwise value >= 0 is the number
 * of huge pages from area that were not collapsed.
 */
static int check_collapse(const struct test_memory *mem)
{
	int ret;
	unsigned long counter = 0;
	unsigned long start = mem->start, end = start + (1UL << mem->order) * PAGE_SIZE;

	BUG_ON(mem->order < HUGE_PAGE_ORDER);
	BUG_ON(!IS_ALIGNED(mem->start, PMD_SIZE));

	for (; start < end; start += PMD_SIZE) {
		ret = check_huge_page(start);
		if (ret < 0)
			return ret;
		counter += ret;
	}

	if (counter) {
		pr_debug("%ld huge pages out of %ld were not collapsed\n",
			 counter, (end - mem->start) / PMD_SIZE);
	} else {
		pr_debug("all %ld huge pages were collapsed\n",
			 (end - mem->start) / PMD_SIZE);
	}

	return counter;
}

/*
 * Return value is negative if an error occurred, otherwise value >= 0 is the number
 * of huge pages from area that were not collapsed.
 */
static int run_collapse_thread(const struct thread_params *params)
{
	if (READ_ONCE(collapse_test_time)) { /* collapse thread's sleep phase */
		/* Let other threads to run */
		WRITE_ONCE(collapse_test_time, false);
		pr_debug("collapse thread cleared 'collapse_test_time' flag\n");

		/* Provide some time for other threads to run */
		schedule_timeout_interruptible(HZ * params->sleep_time);
	} else { /* collapse thread's active phase */
		int ret;

		/* Prevent other threads from running */
		WRITE_ONCE(collapse_test_time, true);
		pr_debug("collapse thread set 'collapse_test_time' flag\n");

		/* Wait for collapse code to work */
		schedule_timeout_interruptible(HZ * params->active_time);

		/* Check that collapse took place */
		ret = check_collapse(&test_params->mem);
		if (ret < 0) {
			pr_err("collapse test error\n");
			return ret;
		}
		collapse_stats.runs++;
		if (ret > 0) {
			pr_debug("collapse test failed\n");
			collapse_stats.failures++;
		}
	}

	return 0;
}

static int test_kernel_pt_sync_with_collapse(const struct thread_params *params)
{
	if (params->type == COLLAPSE_THREAD)
		return run_collapse_thread(params);
	else
		return run_non_collapse_thread(params);
}

static int test_kernel_pt_sync_internal(void *arg)
{
	const struct thread_params *params = (const struct thread_params *)arg;

	if (test_params->collapse_threads_num)
		return test_kernel_pt_sync_with_collapse(params);
	else
		return test_kernel_pt_sync_without_collapse(params);
}

/* Just a wrapper to fit the thread-running scheme of torture module */
static int test_kernel_pt_sync_threadfn(void *arg)
{
	int ret = 0;
	const struct thread_params *params = (const struct thread_params *)arg;

	pr_debug("thread #%d [type %s] started\n", params->idx, type_to_str(params->type));

	do {
		ret = test_kernel_pt_sync_internal(arg);
	} while (!torture_must_stop() && !ret);

	pr_debug("thread #%d [type %s] exits with status %d\n",
		 params->idx, type_to_str(params->type), ret);

	torture_kthread_stopping(type_to_str(((struct thread_params *)arg)->type));

	return ret;
}

static int start_threads(void)
{
	int i;

	if (!torture_init_begin(torture_type, 1))
		return -EBUSY;

	for (i = 0; i < get_threads_num(test_params); i++) {
		int err = torture_create_kthread(test_kernel_pt_sync_threadfn,
						 &test_params->params[i], test_params->tasks[i]);
		if (torture_init_error(err)) {
			pr_err("failed to create kernel thread #%d\n", i);
			torture_init_end();
			return -EINVAL;
		}
	}

	torture_init_end();

	return 0;
}

static void stop_threads(void)
{
	int i;

	if (torture_cleanup_begin())
		return;

	for (i = 0; i < get_threads_num(test_params); i++)
		torture_stop_kthread(test_kernel_pt_sync_threadfn, test_params->tasks[i]);

	torture_cleanup_end();
}

static int init_collapse_test(void)
{
	int ret;

	ret = check_collapse(&test_params->mem);
	if (ret < 0) {
		return -EINVAL;
	} else if (ret > 0) {
		/*
		 * Allocated area is not yet collapsed, give it some time
		 * to be collapsed first. We set the flag to 'false' here
		 * because collapse thread will check it, set to 'true'
		 * and start waiting for page collapse to take place.
		 */
		collapse_test_time = false;
	} else {
		collapse_test_time = true;
	}

	collapse_stats.runs = 0;
	collapse_stats.failures = 0;

	return 0;
}

static int init_thread_params(void)
{
	int i = 0;
	struct thread_params *thread_params;
	unsigned long collapse = collapse_threads_num(),
		      duplication = dupl_threads_num(duplication_threads_num),
		      cache_policy = cache_policy_threads_num(),
		      other_sma = other_sma_threads_num(sma_threads_num);

	test_params->collapse_threads_num = collapse;
	test_params->duplication_threads_num = duplication;
	test_params->cache_policy_threads_num = cache_policy;
	test_params->other_sma_threads_num = other_sma;

	if (get_threads_num(test_params) < 1) {
		pr_err("no threads requested, nothing to test\n");
		return -EINVAL;
	}

	test_params->chunks_num = get_chunks_num(test_params);

	pr_debug("memory area is split into %d chunks\n", test_params->chunks_num);

	test_params->tasks = kcalloc(get_threads_num(test_params), sizeof(struct task_struct *),
				     GFP_KERNEL);
	if (!test_params->tasks) {
		pr_err("failed to allocate array for thread pointers\n");
		return -ENOMEM;
	}

	test_params->params = kcalloc(get_threads_num(test_params), sizeof(struct thread_params),
				      GFP_KERNEL);
	if (!test_params->params) {
		pr_err("failed to allocate array for thread_params\n");
		kfree(test_params->tasks);
		test_params->tasks = NULL;
		return -ENOMEM;
	}

	for (i = 0; i < get_threads_num(test_params); i++) {
		thread_params = &test_params->params[i];

		thread_params->idx = i;

		set_random_start_and_size(i);

		if (collapse) {
			thread_params->type = COLLAPSE_THREAD;
			collapse--;
		} else if (duplication) {
			thread_params->type = DUPLICATION_THREAD;
			duplication--;
		} else if (cache_policy) {
			thread_params->type = CACHE_POLICY_THREAD;
			cache_policy--;
		} else if (other_sma) {
			thread_params->type = OTHER_SMA_THREAD;
			other_sma--;
		} else {
			/* Something went wrong */
			pr_err("error with number of threads\n");
			kfree(test_params->params);
			return -EINVAL;
		}
	}

	if (collapse || duplication || cache_policy || other_sma) {
		/* Something went wrong */
		pr_err("error with number of threads\n");
		kfree(test_params->params);
		return -EINVAL;
	}

	for (i = 0; i < get_threads_num(test_params); i++) {
		thread_params = &test_params->params[i];

		if (test_params->collapse_threads_num > 0) {
			int active_time = 20, sleep_time = active_time;

			if (thread_params->type == COLLAPSE_THREAD) {
				thread_params->active_time = active_time;
				thread_params->sleep_time = sleep_time;

				if (init_collapse_test()) {
					pr_err("failed to initialize collapse test\n");
					kfree(test_params->params);
					return -EINVAL;
				}
			} else {
				/*
				 * Setting active_time of other threads to no more than
				 * 1/5 of collapse thread's active_time guarantees that
				 * all other threads will stop working in aproximately
				 * 4/5 of collapse thread's active_time before collase thread
				 * wakes up and makes its check.
				 */
				thread_params->active_time = get_cycles() % (active_time / 5) + 1;
				/*
				 * Sleep time for other threads is a delay between active phases.
				 * Do now make it big because this is also a maximum delay between
				 * the time when collapse thread allow other threads to start their
				 * active phase and the time when they actually start it.
				 */
				thread_params->sleep_time = get_cycles() % (active_time / 5) + 1;
			}
		} else {
			/* No collapse testing, just set different time slices for all threads */
			thread_params->active_time = i + 2;
			thread_params->sleep_time = i + 7;
		}
	}

	return 0;
}

static int init_test_params(void)
{
	int ret;

	/* Allocate memory for struct test_params */
	test_params = kcalloc(1, sizeof(struct test_params), GFP_KERNEL);
	if (!test_params) {
		pr_err("failed to allocate memory for struct test_params\n");
		return -ENOMEM;
	}

	/* Allocate memory area to run memory operations on */
	ret = alloc_area(&test_params->mem);
	if (ret) {
		pr_err("failed to allocate memory area for testing\n");
		kfree(test_params);
		return ret;
	}

	ret = init_thread_params();
	if (ret) {
		pr_err("failed to setup thread params\n");
		free_area(&test_params->mem);
		kfree(test_params);
		return -EINVAL;
	}

	return 0;
}

static void destroy_test_params(void)
{
	kfree(test_params->params);
	kfree(test_params->tasks);
	free_area(&test_params->mem);
	kfree(test_params);
	test_params = NULL;
}

static int __init kernel_pt_sync_test_init(void)
{
	int ret;

	/* Allocate and fill test_params structure */
	ret = init_test_params();
	if (ret) {
		pr_err("failed to initialize test parameters\n");
		return -EINVAL;
	}

	/* Run several threads with simultaneous access to the memory area */
	ret = start_threads();
	if (ret) {
		pr_err("failed to start test threads\n");
		destroy_test_params();
		return ret;
	}

	return 0;
}

static void kernel_pt_sync_test_exit(void)
{
	/* Stop test threads */
	stop_threads();

	print_collapse_stats();

	/* Free test_params structure and testing area */
	destroy_test_params();
}

module_init(kernel_pt_sync_test_init);
module_exit(kernel_pt_sync_test_exit);
