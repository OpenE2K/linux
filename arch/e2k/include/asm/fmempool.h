/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef FMEMPOOL_H
#define FMEMPOOL_H

/*
 * Fmempool is a mempool with fixed capacity. Allocating all required memory
 * with specified allocator performs in fmempool_create function. Fmempool could
 * be useful in cases where you can't sleep, for example, create pool before
 * spinlock and take memory from it in critical section.
 * Allocated memory releases in fmempool_destroy.
 * fmempool_alloc returns a pointer to preallocated memory.
 */

#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/mempool.h>

typedef struct {
	mempool_t *mem;
	int size, capacity;
	bool initialized;

	mempool_alloc_t *user_alloc_fn;
	mempool_free_t *user_free_fn;

	void *private;
} fmempool_t;

fmempool_t *fmempool_create(int capacity, mempool_alloc_t *alloc_fn,
	mempool_free_t *free_fn, void *pool_data);
void fmempool_destroy(fmempool_t *pool);
void *fmempool_alloc(fmempool_t *pool, gfp_t gfp_mask);
void fmempool_free(void *element, fmempool_t *pool);

static inline fmempool_t *
fmempool_create_slab_pool(int capacity, struct kmem_cache *kc)
{
	return fmempool_create(capacity, mempool_alloc_slab, mempool_free_slab,
		(void *) kc);
}

static inline fmempool_t *
fmempool_create_kmalloc_pool(int capacity, size_t elem_size)
{
	return fmempool_create(capacity, mempool_kmalloc, mempool_kfree,
		(void *) elem_size);
}

static inline fmempool_t *
fmempool_create_page_pool(int capacity, unsigned long order)
{
	return fmempool_create(capacity, mempool_alloc_pages, mempool_free_pages,
		(void *) order);
}

#endif /* FMEMPOOL_H */
