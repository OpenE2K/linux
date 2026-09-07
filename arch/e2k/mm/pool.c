/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

#include <linux/memblock.h>
#include <linux/crash_dump.h>
#include <asm/pool.h>

/*
 * Pools on memblock allocator have different interface (see pool_create_memblock()).
 * That's why do not expose POOL_MEMBLOCK via enum pool_allocator but declare it here
 * for the internal use.
 */
#define POOL_MEMBLOCK POOL_ALLOCATOR_NR

#define DEBUG_POOL 0
#if DEBUG_POOL
# define TracePool(...) trace_printk(__VA_ARGS__)
#else
# define TracePool(fmt, ...) no_printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#endif

static inline unsigned long page_order_to_size(unsigned long order)
{
	return (1UL << order) * PAGE_SIZE;
}

/*
 * pool_alloc_internal() - allocate memory for internal pool data.
 *
 * __ref is used because memblock_alloc() is in section .init.text, but this function
 * is not in init section. Anyway, true value of is_memblock_pool can came from
 * pool_create_memblock() only, which is in init section, so we are free to call
 * functions from init section in that case.
 */
static void * __ref pool_alloc_internal(bool is_memblock_pool, unsigned long order,
				 unsigned long align, gfp_t flags)
{
	struct page *page;

	if (is_memblock_pool)
		return memblock_alloc(page_order_to_size(order), align);

	page = alloc_pages(flags, order);
	if (!page)
		return NULL;

	return page_to_virt(page);
}

/* pool_free_internal() - free internal pool data. */
static void pool_free_internal(bool is_memblock_pool, void *addr, unsigned long order)
{
	if (is_memblock_pool)
		memblock_free(addr, page_order_to_size(order));
	else
		free_pages((unsigned long)addr, order);
}

/* pool_alloc_object() - allocate pool object.
 *
 *__ref is used because memblock_alloc_exact_nid_raw() is __init-ed, but this function
 * is not in init section. Anyway, POOL_MEMBLOCK in pool->allocator can came from
 * pool_create_memblock() only, which is in init section, so we are free to call
 * functions from init section in that case.
 */
static void * __ref pool_alloc_object(struct pool *pool)
{
	gfp_t flags = pool->flags;

	if (!is_kdump_kernel())
		flags |= __GFP_THISNODE;

	switch (pool->allocator) {
	case POOL_SLAB:
		return kmalloc_node(pool->objsize, flags, pool->node);
	case POOL_BUDDY: {
		struct page *p = alloc_pages_node(pool->node, flags,
						  pool->objorder);
		return p ? page_to_virt(p) : NULL;
	}
	case POOL_MEMBLOCK:
		if (is_kdump_kernel())
			return memblock_alloc(pool->objsize, pool->objsize);

		return memblock_alloc_exact_nid_raw(pool->objsize, pool->objsize,
					MEMBLOCK_LOW_LIMIT, MEMBLOCK_ALLOC_ACCESSIBLE,
					pool->node);
	default:
		WARN_ON(1);
		return NULL;
	}
}

static void pool_free_object(struct pool *pool, void *object)
{
	switch (pool->allocator) {
	case POOL_SLAB:
		kfree(object);
		break;
	case POOL_BUDDY:
		free_pages((unsigned long)object, pool->objorder);
		break;
	case POOL_MEMBLOCK:
		/* Current users of memblock pool don't ever free it */
		BUG();
	default:
		WARN_ON(1);
	}
}

static int pool_chunk_init(bool is_memblock_pool, struct pool_chunk *chunk,
			   unsigned long order, unsigned long capacity, gfp_t flags)
{
	chunk->mem = pool_alloc_internal(is_memblock_pool, order, PAGE_SIZE, flags | __GFP_ZERO);
	if (!chunk->mem)
		return -ENOMEM;

	chunk->capacity = capacity;
	chunk->order = order;
	chunk->free_size = capacity;

	return 0;
}

static void pool_chunk_delete(bool is_memblock_pool, struct pool_chunk *chunk)
{
	if (chunk->mem) {
		pool_free_internal(is_memblock_pool, chunk->mem, chunk->order);
		chunk->mem = NULL;
	}
}

static void pool_destroy_chunk_array(struct pool *pool)
{
	bool is_memblock_pool = pool->allocator == POOL_MEMBLOCK;

	for (size_t i = 0; i < pool->num_chunks; i++)
		pool_chunk_delete(is_memblock_pool, pool->chunk + i);

	pool_free_internal(is_memblock_pool, pool->chunk, pool->array_order);
	pool->chunk = NULL;
}

static int pool_create_chunk_array(struct pool *pool, unsigned long capacity)
{
	size_t req_bytes = capacity * sizeof(void *);
	size_t maxorder_size = MAX_ORDER_NR_PAGES * PAGE_SIZE;

	size_t maxorder_chunks = req_bytes / maxorder_size;
	size_t last_chunk_size = req_bytes % maxorder_size;

	size_t capacity_per_max_order = MAX_ORDER_NR_PAGES * PAGE_SIZE / sizeof(void *);

	size_t chunks_num = maxorder_chunks + (last_chunk_size ? 1 : 0);
	size_t chunk_array_size = chunks_num * sizeof(struct pool_chunk);

	bool is_memblock_pool = pool->allocator == POOL_MEMBLOCK;

	pool->num_chunks = 0;

	pool->array_order = order_base_2(PAGE_ALIGN(chunk_array_size) >> PAGE_SHIFT);

	pool->chunk = pool_alloc_internal(is_memblock_pool, pool->array_order,
					  PAGE_SIZE, pool->flags | __GFP_ZERO);

	if (!pool->chunk)
		return -ENOMEM;

	for (size_t i = 0; i < maxorder_chunks; i++) {
		if (pool_chunk_init(is_memblock_pool, pool->chunk + i, MAX_ORDER - 1,
				    capacity_per_max_order, pool->flags)) {
			pool_destroy_chunk_array(pool);
			return -ENOMEM;
		}
		pool->num_chunks++;
	}

	if (last_chunk_size) {
		if (pool_chunk_init(is_memblock_pool, pool->chunk + maxorder_chunks,
				    order_base_2(PAGE_ALIGN(last_chunk_size) >> PAGE_SHIFT),
				    last_chunk_size / sizeof(void *), pool->flags)) {
			pool_destroy_chunk_array(pool);
			return -ENOMEM;
		}
		pool->num_chunks++;
	}

	return 0;
}

static int chunk_alloc_objects(struct pool *pool, struct pool_chunk *chunk)
{
	for (size_t i = 0; i < chunk->capacity; i++) {
		chunk->mem[i] = pool_alloc_object(pool);
		if (!chunk->mem[i])
			return -ENOMEM;
	}

	return 0;
}

static void chunk_free_objects(struct pool *pool, struct pool_chunk *chunk)
{
	if (!chunk->mem)
		return;

	for (size_t i = 0; i < chunk->free_size; i++)
		if (chunk->mem[i])
			pool_free_object(pool, chunk->mem[i]);
}

static void pool_free_objects(struct pool *pool)
{
	for (size_t i = 0; i < pool->num_chunks; i++)
		chunk_free_objects(pool, pool->chunk + i);
}

static int pool_alloc_objects(struct pool *pool)
{
	for (size_t i = 0; i < pool->num_chunks; i++) {
		if (chunk_alloc_objects(pool, pool->chunk + i)) {
			pool_free_objects(pool);
			return -ENOMEM;
		}
	}

	return 0;
}

static struct pool *create_pool(unsigned long capacity, unsigned long objsize,
				enum pool_allocator allocator, gfp_t flags, int node)
{
	int order = order_base_2(PAGE_ALIGN(sizeof(struct pool)) >> PAGE_SHIFT);
	bool is_memblock_pool = allocator == POOL_MEMBLOCK;

	struct pool *pool = pool_alloc_internal(is_memblock_pool, order, PAGE_SIZE, flags);

	if (!pool)
		return NULL;

	pool->flags = flags;
	pool->allocator = allocator;

	if (pool_create_chunk_array(pool, capacity)) {
		pool_free_internal(is_memblock_pool, pool, order);
		return NULL;
	}

	pool->total_capacity = capacity;
	pool->objsize = objsize;
	pool->total_free_size = capacity;
	pool->current_chunk_idx = pool->num_chunks - 1;
	pool->node = node;
	raw_spin_lock_init(&pool->lock);

	if (pool_alloc_objects(pool)) {
		pool_destroy_chunk_array(pool);
		pool_free_internal(is_memblock_pool, pool, order);
		return NULL;
	}

	TracePool("pool_create: type = %s, cap = %lu, objsize = %lu\n",
		  is_memblock_pool ? "memblock" : (allocator == POOL_SLAB) ? "slab" : "buddy",
		  pool->total_capacity, pool->objsize);

	return pool;
}

struct pool *pool_create(unsigned long capacity, unsigned long objsize,
			 enum pool_allocator allocator, gfp_t flags, int node)
{
	if (WARN_ON(allocator != POOL_SLAB && allocator != POOL_BUDDY))
		return NULL;

	return create_pool(capacity, objsize, allocator, flags, node);
}
#ifdef CONFIG_TEST_POOL_MODULE
EXPORT_SYMBOL(pool_create);
#endif

#ifdef CONFIG_DEBUG_PAGEALLOC
struct pool * __init pool_create_memblock(unsigned long capacity, unsigned long objsize, int node)
{
	return create_pool(capacity, objsize, POOL_MEMBLOCK, 0, node);
}
#endif /* CONFIG_DEBUG_PAGEALLOC */

void pool_destroy(struct pool *pool)
{
	int order = order_base_2(PAGE_ALIGN(sizeof(struct pool)) >> PAGE_SHIFT);

	TracePool("pool_destroy: pool = 0x%px\n", pool);

	if (pool->chunk) {
		pool_free_objects(pool);
		pool_destroy_chunk_array(pool);
	}

	free_pages((unsigned long)pool, order);
}
#ifdef CONFIG_TEST_POOL_MODULE
EXPORT_SYMBOL(pool_destroy);
#endif

static void *chunk_get(struct pool_chunk *chunk)
{
	return chunk->mem[--chunk->free_size];
}

static void chunk_put(struct pool_chunk *chunk, void *object)
{
	chunk->mem[chunk->free_size++] = object;
}

static bool chunk_is_empty(struct pool_chunk *chunk)
{
	return !chunk->free_size;
}

static bool chunk_is_full(struct pool_chunk *chunk)
{
	return chunk->free_size == chunk->capacity;
}

void *pool_get(struct pool *pool)
{
	void *object = NULL;
	unsigned long flags;

	raw_spin_lock_irqsave(&pool->lock, flags);

	if (WARN_ON_ONCE(!pool->total_free_size))
		goto unlock;

	struct pool_chunk *cur_chunk = pool->chunk + pool->current_chunk_idx;

	if (chunk_is_empty(cur_chunk)) {
		pool->current_chunk_idx--;
		cur_chunk = pool->chunk + pool->current_chunk_idx;
	}

	object = chunk_get(cur_chunk);
	pool->total_free_size--;

unlock:
	raw_spin_unlock_irqrestore(&pool->lock, flags);

	return object;
}

void pool_put(struct pool *pool, void *object)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&pool->lock, flags);

	if (WARN_ON_ONCE(pool->total_free_size >= pool->total_capacity))
		goto unlock;


	struct pool_chunk *cur_chunk = pool->chunk + pool->current_chunk_idx;

	if (chunk_is_full(cur_chunk)) {
		pool->current_chunk_idx++;
		cur_chunk = pool->chunk + pool->current_chunk_idx;
	}

	chunk_put(cur_chunk, object);
	pool->total_free_size++;

unlock:
	raw_spin_unlock_irqrestore(&pool->lock, flags);
}

void pool_cleanup(struct pool **pool)
{
	if (*pool)
		pool_destroy(*pool);
}

unsigned long pool_free_size(struct pool *pool)
{
	return pool->total_free_size;
}

bool pool_is_empty(struct pool *pool)
{
	return pool->total_free_size == 0;
}
