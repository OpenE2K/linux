/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

#ifndef POOL_H
#define POOL_H

#include <linux/kernel.h>
#include <linux/memory.h>
#include <linux/log2.h>

/*
 * Pool pattern implementation. For buddy allocator objsize parameter
 * used as order for pages_alloc.
 * There is no pool resize function, so pool_get returns NULL if pool is
 * empty.
 */

enum pool_allocator {
	POOL_SLAB,
	POOL_BUDDY,
	POOL_ALLOCATOR_NR
};

struct pool_chunk {
	void **mem;		/* array of pointers */
	unsigned long order;	/* order of array of pointers */
	unsigned long free_size; /* current amount objects in chunk */
	unsigned long capacity; /* capacity of chunk */
};

struct pool {
	unsigned long total_capacity; /* number of pointers that pool contains */
	enum pool_allocator allocator;	/* pool's allocator type */
	gfp_t flags;		/* alloc flags */
	unsigned long total_free_size; /* current amount objects in pool */
	union {
		unsigned long objsize; /* size of object in bytes */
		unsigned long objorder; /* order of object in case of buddy allocator */
	};

	struct pool_chunk *chunk;	/* array of chunks of mem for pointers on objects */
	unsigned long num_chunks; /* count of memory chunks in pool */
	unsigned long array_order; /* order of array of chunks */
	unsigned long current_chunk_idx; /* index of current chunk we use */
	int node;		/* NUMA node on which objects should be allocated */
	raw_spinlock_t lock;	/* lock for shared access to pool */
};

#define __pool_autoclean __attribute__((cleanup(pool_cleanup)))

/**
 * pool_create() - create a new pool of objects.
 * @capacity: number of objects, which pool will be contained.
 * @objsize: in case of slab allocator objsize is just an objects size,
 *		but in case of buddy allocator it similar to order for
 *		page allocation.
 * @allocator: type of allocator.
 * @flags: flags for allocator.
 * @node: ID of NUMA node on which pool objects should be allocated;
 *		if memory node does not matter, use NUMA_NO_NODE value.
 *
 * Return: pointer to pool instance.
 */
struct pool *pool_create(unsigned long capacity, unsigned long objsize,
			 enum pool_allocator allocator, gfp_t flags, int node);

#ifdef CONFIG_DEBUG_PAGEALLOC
/**
 * pool_create_memblock() - like pool_create(), but uses memblock allocator.
 * @capacity: number of objects, which pool will be contained.
 * @objsize: objects size in bytes.
 * @node: ID of NUMA node on which pool objects should be allocated;
 *		if memory node does not matter, use NUMA_NO_NODE value.
 *
 * Return: pointer to pool instance.
 */
struct pool * __init pool_create_memblock(unsigned long capacity, unsigned long objsize, int node);
#endif /* CONFIG_DEBUG_PAGEALLOC */

/**
 * pool_destroy() - destroy pool of objects.
 * @pool: pointer to pool that will be destroyed.
 *
 * All objects in pool will be released. Objects that will not be returned
 * into pool need to be released manually.
 */
void pool_destroy(struct pool *pool);

/**
 * pool_get() - take an object from pool.
 * @pool: pointer to pool wherefrom object will be taken.
 *
 * Return: pointer to object or NULL when pool exhausted.
 */
void *pool_get(struct pool *pool);

/**
 * pool_put() - return an object into pool.
 * @pool: pointer to pool where object will be returned.
 * @object: pointer to object.
 *
 * Return objects only into pools wherefrom they was taken.
 */
void pool_put(struct pool *pool, void *object);

void pool_cleanup(struct pool **pool); /* just for compiler's cleanup attribute */

/**
 * pool_free_size() - return count of free objects in pool.
 * @pool: pointer to pool.
 */
unsigned long pool_free_size(struct pool *pool);

/**
 * pool_is_empty() - return if there is no free objects in pool.
 * @pool: pointer to pool.
 */
bool pool_is_empty(struct pool *pool);

#endif /* POOL_H */
