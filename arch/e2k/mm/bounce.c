/*
 * arch/e2k/mm/bounce.c
 *
 * Arch specific implementation of bounce buffer handling for block devices.
 * 
 * Copyright (C) 2009-2010 Pavel V. Panteleev (panteleev_p@mcst.ru)
 */

#include <linux/blkdev.h>
#include <asm/e2k_debug.h>

#undef	DEBUG_BOUNCE_MODE
#undef	DebugBOUNCE
#define	DEBUG_BOUNCE_MODE	0	/* bounce buffers */
#define DebugBOUNCE(...)		DebugPrint(DEBUG_BOUNCE_MODE ,##__VA_ARGS__)

#define POOL_SIZE       64
#define ISA_POOL_SIZE   16

static mempool_t *page_pool[MAX_NUMNODES], *isa_page_pool[MAX_NUMNODES];

mempool_t* e2k_page_pool(struct bio *bio)
{
	int node = bio->bi_bdev->bd_disk->node_id;
	int i;

	if (node < 0)
		node = 0;

	for (i = 0; i < MAX_NUMNODES; i++) {
		mempool_t *pool;

		node %= MAX_NUMNODES;
		if (pool = page_pool[node++])
			return pool;
	}

	BUG_ON(1);
	return 0;
}

mempool_t* e2k_isa_page_pool(struct bio *bio)
{
	int node = bio->bi_bdev->bd_disk->node_id;
	int i;

	if (node < 0)
		node = 0;

	for (i = 0; i < MAX_NUMNODES; i++) {
		mempool_t *pool;

		node %= MAX_NUMNODES;
		if (pool = isa_page_pool[node++])
			return pool;
	}

	BUG_ON(1);
	return 0;
}

static void page_pool_free(void *page, void *data)
{
	__free_page(page);
}

#ifdef CONFIG_HIGHMEM
static void *page_hm_pool_alloc(gfp_t gfp_mask, void *pool_data)
{
	int node = (int)pool_data;
	struct page *page;

	if (page = alloc_pages_node(node, gfp_mask, 0)) {
		DebugBOUNCE("page at 0x%lx on node%d.\n",
			page, node);
		return page;
	}
	else {
		DebugBOUNCE("node%d has no memory.\n",
			node);
		DebugBOUNCE("page at 0x%lx.\n", page);
		return alloc_page(gfp_mask);
	}
}

static __init int init_emergency_pool(void)
{
	int    node;
	int    status = 0;
	struct sysinfo i;

	si_meminfo(&i);
	si_swapinfo(&i);
	if (!i.totalhigh)
		return 0;

	memset(page_pool, 0, sizeof(mempool_t *) * MAX_NUMNODES);

	for_each_online_node (node) {
		page_pool[node] =
			mempool_create_node(POOL_SIZE, page_hm_pool_alloc,
				page_pool_free, (void *)node, GFP_KERNEL, node);
		if (page_pool[node])
			status = 1;
		DebugBOUNCE("higmem bounce pool size "
			"on node%d is %d pages.\n", node, POOL_SIZE);
	}

	BUG_ON(!status);

	return 0;
}

__initcall(init_emergency_pool);
#endif

static void *page_isa_pool_alloc(gfp_t gfp_mask, void *pool_data)
{
	int node = (int) (unsigned long) pool_data;
	struct page *page;

	if (page = alloc_pages_node(node, gfp_mask | GFP_DMA, 0)) {
		DebugBOUNCE("page at 0x%lx on "
			"node%d.\n", page, node);
		return page;
	}
	else {
		DebugBOUNCE("node%d has no memory.\n",
			node);
		DebugBOUNCE("page at 0x%lx.\n", page);
		return alloc_page(gfp_mask | GFP_DMA);
	}
}

int init_emergency_isa_pool(void)
{
	static int is_inited = 0;
	int node;
	int status = 0;

	if (is_inited)
		return 0;

	memset(isa_page_pool, 0, sizeof(mempool_t *) * MAX_NUMNODES);
	
	for_each_online_node (node) {
		isa_page_pool[node] =
			mempool_create_node(ISA_POOL_SIZE, page_isa_pool_alloc,
				page_pool_free, (void *)node, GFP_KERNEL, node);
		if (isa_page_pool[node])
			status = 1;
		printk("init_emergency_isa_pool(): bounce pool size on node%d "
			"is %d pages.\n", node, ISA_POOL_SIZE);
	}

	BUG_ON(!status);
	is_inited = 1;

	return 0;
}

