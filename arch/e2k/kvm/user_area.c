/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Contigous virtual area of user memory menegement.
 * The product is compilation of ideas of linux/mm/vmalloc,
 * linux/mm/mmap and arch/e2k/mm/area_alloc.c
 */

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <linux/pgtable.h>

#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

#include "user_area.h"
#include "mmu.h"

#undef	USER_AREA_LOCX_ENABLE

#undef	DEBUG_USER_AREA_MODE
#undef	DebugUA
#define	DEBUG_USER_AREA_MODE	0	/* processes */
#define	DebugUA(fmt, args...)						\
({									\
	if (DEBUG_USER_AREA_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KERNEL_AREA_MODE
#undef	DebugKA
#define	DEBUG_KERNEL_AREA_MODE	0	/* kernel virtual machine debugging */
#define	DebugKA(fmt, args...)						\
({									\
	if (DEBUG_KERNEL_AREA_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_USER_AREA_LOCX_MODE
#undef	DebugLOCX
#define	DEBUG_USER_AREA_LOCX_MODE	0	/* locking guest area */
#define	DebugLOCX(fmt, args...)						\
({									\
	if (DEBUG_USER_AREA_LOCX_MODE || kvm_debug)			\
		pr_warn_once("%s(): " fmt, __func__, ##args);		\
})

/*
 * SLAB cache for user area chunk structures
 */
static struct kmem_cache *user_area_cachep = NULL;
static struct kmem_cache *user_area_chunk_cachep = NULL;

static void user_area_free_queued_chunks(user_area_t *user_area);

int
user_area_caches_init(void)
{
	DebugUA("user_area_caches_init() started\n");
	user_area_cachep =
		kmem_cache_create("user_area", sizeof(user_area_t), 0,
						SLAB_HWCACHE_ALIGN, NULL);
	if (user_area_cachep == NULL) {
		printk(KERN_ERR "Cannot create user memore area structures "
			"SLAB cache");
		return -ENOMEM;
	}
	user_area_chunk_cachep =
		kmem_cache_create("user_area_chunk", sizeof(user_chunk_t), 0,
						SLAB_HWCACHE_ALIGN, NULL);
	if (user_area_chunk_cachep == NULL) {
		printk(KERN_ERR "Cannot create user memore chunk structures "
			"SLAB cache");
		return -ENOMEM;
	}
	DebugUA("user_area_caches_init() finished\n");
	return 0;
}

void
user_area_caches_destroy(void)
{
	DebugUA("user_area_caches_destroy() started\n");
	if (user_area_chunk_cachep) {
		kmem_cache_destroy(user_area_chunk_cachep);
		user_area_chunk_cachep = NULL;
	}
	if (user_area_cachep) {
		kmem_cache_destroy(user_area_cachep);
		user_area_cachep = NULL;
	}
	DebugUA("user_area_caches_destroy() finished\n");
}

#ifdef	CONFIG_DEBUG_USER_AREA

/*
 * Print chunks
 */
static void
user_area_print_chunk(user_chunk_t *chunk)
{
	pr_info("   Chunk 0x%px next 0x%px prev 0x%px start 0x%lx end 0x%lx "
		"size 0x%08lx flags 0x%04lx\n",
		chunk, chunk->next, chunk->prev,
		chunk->start, chunk->end, chunk->size, chunk->flags);
}
static long
user_area_print_all_chunks_in_list(user_chunk_t *chunk_list)
{
	user_chunk_t **p;
	user_chunk_t *next = NULL;
	long chunks_num = 0;

	for (p = &chunk_list; (next = *p); p = &next->next) {
		user_area_print_chunk(next);
		chunks_num++;
	}
	return chunks_num;
}
static long
user_area_print_all_free_chunks(user_area_t *user_area)
{
	long chunks_num;
	pr_info("List of all free chunks in area from 0x%lx to 0x%lx\n",
		user_area->area_start, user_area->area_end);
	chunks_num = user_area_print_all_chunks_in_list(user_area->free_list);
	pr_info("Total number of free chunks is %ld\n", chunks_num);
	return chunks_num;
}
static long
user_area_print_all_busy_chunks(user_area_t *user_area)
{
	long chunks_num;
	pr_info("List of all busy chunks in area from 0x%lx to 0x%lx\n",
		user_area->area_start, user_area->area_end);
	chunks_num = user_area_print_all_chunks_in_list(user_area->busy_list);
	pr_info("Total number of busy chunks is %ld\n", chunks_num);
	return chunks_num;
}
static void
user_area_print_all_chunks(user_area_t *user_area)
{
	long chunks_num;
	long total_num = 0;

	chunks_num = user_area_print_all_free_chunks(user_area);
	total_num += chunks_num;

	chunks_num = user_area_print_all_busy_chunks(user_area);
	total_num += chunks_num;

	pr_info("List of chunks queued to free in area from 0x%lx to 0x%lx\n",
		user_area->area_start, user_area->area_end);
	chunks_num = user_area_print_all_chunks_in_list(
						user_area->to_free_list);
	pr_info("Total number of queued chunks is %ld\n", chunks_num);
	total_num += chunks_num;
	pr_info("Total number of all chunks is %ld\n", total_num);
}
#endif	/* CONFIG_DEBUG_USER_AREA */

/*
 * Find the address of the user virtual memory area into the list of chunks.
 * Look up the first chunk which satisfies  address < shunk_end,  NULL if none.
 * The list should be locked by caller
 */
static inline user_chunk_t *
user_area_find_chunk(user_chunk_t **chunk_list, user_chunk_t ***prev,
	e2k_addr_t start, e2k_size_t size, e2k_size_t align, void *vmap_base)
{
	user_chunk_t **p;
	user_chunk_t *next = NULL;
	e2k_addr_t addr;

	DebugUA("user_area_find_chunk() started: chunk list %px -> %px address "
		"0x%lx size 0x%lx\n",
		chunk_list, *chunk_list, start, size);
	for (p = chunk_list; (next = *p); p = &next->next) {
		DebugUA("user_area_find_chunk() current chunk 0x%px start 0x%lx "
			"end 0x%lx\n",
			next, next->start, next->end);
		addr = next->start;
		addr = ALIGN_TO_SIZE(addr, align);
		if (vmap_base != NULL) {
			if (next->vmap_base == vmap_base)
				break;
		} else if (start == 0) {
			if (next->end - addr >= size)
				break;
		} else if (start < next->end) {
			break;
		}
	}
	DebugUA("user_area_find_chunk() returns chunk %px prev %px -> %px\n",
		next, p, *p);
	*prev = p;
	return next;
}

/*
 * Find a free chunk of the user virtual memory area.
 * The list should be locked by caller
 */
static inline user_chunk_t *
user_area_find_free_chunk(user_area_t *user_area, e2k_addr_t start,
				e2k_size_t size, e2k_size_t align)
{
	user_chunk_t **prev = NULL;
	user_chunk_t *next;
	e2k_addr_t end = start + size;

	DebugUA("user_area_find_free_chunk() started: address 0x%lx end "
		"0x%lx\n", start, end);
	next = user_area_find_chunk(&user_area->free_list, &prev,
					start, size, align, NULL);
	if (next == NULL) {
		DebugUA("user_area_find_free_chunk() area is not found\n");
		return NULL;
	}
	DebugUA("user_area_find_free_chunk() area found: start 0x%lx "
		"end 0x%lx\n", next->start, next->end);
	if (start == 0)
		return next;
	if (start >= next->start && end <= next->end) {
		return next;
	}
	return NULL;
}

/*
 * Find a free chunk of the user virtual memory area.
 * The list should be locked by caller
 */
static inline user_chunk_t *
user_area_find_busy_chunk(user_area_t *user_area, e2k_addr_t start,
				e2k_size_t size)
{
	user_chunk_t **prev = NULL;
	user_chunk_t *next;
	e2k_addr_t end = start + size;

	DebugUA("user_area_find_busy_chunk() started: address 0x%lx end "
		"0x%lx\n", start, end);
	next = user_area_find_chunk(&user_area->busy_list, &prev,
					start, size, 0, NULL);
	if (next == NULL) {
		DebugUA("user_area_find_busy_chunk() area is not found\n");
		return NULL;
	}
	DebugUA("user_area_find_busy_chunk() area found: start 0x%lx "
		"end 0x%lx\n", next->start, next->end);
	return next;
}
static inline user_chunk_t *
user_area_find_vmap_chunk(user_area_t *user_area, void *vmap_base)
{
	user_chunk_t **prev = NULL;
	user_chunk_t *next;

	DebugUA("user_area_find_busy_chunk() started: vmap base %px\n",
		vmap_base);
	next = user_area_find_chunk(&user_area->busy_list, &prev,
						0, 0, 0, vmap_base);
	if (next == NULL) {
		DebugUA("user_area_find_busy_chunk() area is not found\n");
		return NULL;
	}
	DebugUA("user_area_find_busy_chunk() area found: start 0x%lx "
		"end 0x%lx\n",
		next->start, next->end);
	return next;
}

static inline int
user_area_is_busy(user_area_t *user_area, e2k_addr_t address,
				e2k_addr_t size)
{
	user_chunk_t *next;
	unsigned long irq_flags;
	e2k_addr_t end = address + size;

	DebugUA("user_area_is_busy() started: address 0x%lx end 0x%lx\n",
		address, end);
	spin_lock_irqsave(&user_area->area_list_lock, irq_flags);
	next = user_area_find_busy_chunk(user_area, address, size);
	if (next == NULL) {
		spin_unlock_irqrestore(&user_area->area_list_lock, irq_flags);
		DebugUA("user_area_is_busy() area is not found\n");
		return 0;
	}
	DebugUA("user_area_is_busy() area found: start 0x%lx end 0x%lx\n",
		next->start, next->end);
	if (address >= next->start || end > next->start) {
		spin_unlock_irqrestore(&user_area->area_list_lock, irq_flags);
		return 1;
	}
	spin_unlock_irqrestore(&user_area->area_list_lock, irq_flags);
	return 0;
}

/*
 * Insert the chunk of the user virtual memory area to the list of the chunks.
 * The list should be locked by caller
 */
static inline void
user_area_insert_chunk(user_chunk_t **chunk_list, user_chunk_t *chunk)
{
	user_chunk_t *next_chunk;
	user_chunk_t **prev_chunk;

	DebugUA("user_area_insert_chunk() started: chunk list %px -> %px chunk "
		"%px\n", chunk_list, *chunk_list, chunk);
	next_chunk = user_area_find_chunk(chunk_list, &prev_chunk,
						chunk->start, chunk->size, 0,
						NULL);
	DebugUA("user_area_insert_chunk() prev chunk %px next %px\n",
		*prev_chunk, next_chunk);
	*prev_chunk = chunk;
	if (prev_chunk == chunk_list)
		chunk->prev = NULL;
	else
		chunk->prev = (user_chunk_t *)((e2k_addr_t)prev_chunk -
				offsetof(user_chunk_t, next));
	chunk->next = next_chunk;
	if (next_chunk != NULL) {
		next_chunk->prev = chunk;
	}
	DebugUA("user_area_insert_chunk() returns chunk->next %px prev "
		"%px\n", chunk->next, chunk->prev);
}

/*
 * Delete the chunk of the user virtual memory area from the list
 * of the chunks. The list should be locked by caller
 */
static inline void
user_area_delete_chunk(user_chunk_t *chunk_list, e2k_addr_t address)
{
	user_chunk_t **p;
	user_chunk_t *next = NULL;

	DebugUA("user_area_delete_chunk() started: address 0x%lxn",
		address);
	for (p = &chunk_list; (next = *p); p = &next->next) {
		DebugUA("user_area_delete_chunk() current chunk 0x%px "
			"address 0x%lx\n", next, next->start);
		if (next->start == address) {
			break;
		}
	}
	if (next == NULL) {
		DebugUA("user_area_delete_chunk() could not find a chunk "
			"for address 0x%lx\n", address);
		return;
	}
	DebugUA("user_area_delete_chunk() found a chunk 0x%px "
		"for address 0x%lx\n", next, address);

	*p = next->next;
	if (next->next != NULL)
		next->next->prev = next->prev;
	DebugUA("user_area_delete_chunk() deleted chunk 0x%px, from prev "
		"0x%px, next 0x%px\n",
		next, next->prev, next->next);
	next->next = NULL;
	next->prev = NULL;
}

/*
 * Insert the chunk of the user virtual memory area to the list of busy
 * chunks.
 */
static inline void
user_area_insert_busy_chunk(user_area_t *user_area,
				user_chunk_t *busy_chunk)
{
	unsigned long flags;

	DebugUA("user_area_insert_busy_chunk() started: chunk %px\n",
		busy_chunk);
	spin_lock_irqsave(&user_area->area_list_lock, flags);
	if (user_area->flags & USER_AREA_ORDERED) {
		user_area_insert_chunk(&user_area->busy_list, busy_chunk);
		spin_unlock_irqrestore(&user_area->area_list_lock, flags);
		DebugUA("user_area_insert_busy_chunk() returns ordered chunk "
			"chunk->next %px chunk->prev %px\n",
			busy_chunk->next, busy_chunk->prev);
		return;
	}
	busy_chunk->next = user_area->busy_list;
	busy_chunk->prev = NULL;
	if (user_area->busy_list != NULL) {
		user_area->busy_list->prev = busy_chunk;
	}
	user_area->busy_list = busy_chunk;
	spin_unlock_irqrestore(&user_area->area_list_lock, flags);
	DebugUA("user_area_insert_busy_chunk() returns unordered chunk "
		"chunk->next %px chunk->prev %px\n",
		busy_chunk->next, busy_chunk->prev);
}

/*
 * Insert the chunk of the user virtual memory area to the list of free
 * chunks.
 * The list should not be locked
 */
static inline void
user_area_insert_free_chunk(user_area_t *user_area,
				user_chunk_t *free_chunk)
{
	unsigned long flags;

	DebugUA("user_area_insert_free_chunk() started: chunk %px\n",
		free_chunk);
	spin_lock_irqsave(&user_area->area_list_lock, flags);
	if (user_area->flags & USER_AREA_ORDERED) {
		user_area_insert_chunk(&user_area->free_list, free_chunk);
		DebugUA("user_area_insert_free_chunk() returns ordered chunk "
			"chunk->next %px chunk->prev %px\n",
			free_chunk->next, free_chunk->prev);
		user_area->freebytes += free_chunk->size;
		spin_unlock_irqrestore(&user_area->area_list_lock, flags);
		return;
	}
	free_chunk->next = user_area->free_list;
	free_chunk->prev = NULL;
	if (user_area->free_list != NULL) {
		user_area->free_list->prev = free_chunk;
	}
	user_area->free_list = free_chunk;
	user_area->freebytes += free_chunk->size;
	spin_unlock_irqrestore(&user_area->area_list_lock, flags);
	DebugUA("user_area_insert_free_chunk() returns unordered chunk "
		"chunk->next %px chunk->prev %px\n",
		free_chunk->next, free_chunk->prev);
}

/*
 * Insert the chunk of the user virtual memory area to the list of
 * ready to free chunks.
 */
static inline void
user_area_insert_to_free_chunk(user_area_t *user_area,
					user_chunk_t *to_free_chunk)
{
	unsigned long flags;

	DebugUA("user_area_insert_to_free_chunk() started: chunk %px\n",
		to_free_chunk);
	spin_lock_irqsave(&user_area->area_list_lock, flags);
	to_free_chunk->next = user_area->to_free_list;
	to_free_chunk->prev = NULL;
	if (user_area->to_free_list != NULL) {
		user_area->to_free_list->prev = to_free_chunk;
	}
	user_area->to_free_list = to_free_chunk;
	spin_unlock_irqrestore(&user_area->area_list_lock, flags);
	DebugUA("user_area_insert_to_free_chunk() inserted unordered "
		"chunk: chunk->next %px chunk->prev %px\n",
		to_free_chunk->next, to_free_chunk->prev);
}

/*
 * Init new structure of chunk of user virtual memory area
 */
static inline void
user_area_init_chunk(user_chunk_t *new_chunk, e2k_addr_t chunk_start,
	e2k_size_t chunk_size, unsigned long flags)
{
	DebugUA("user_area_init_chunk() started: start 0x%lx size 0x%lx\n",
		chunk_start, chunk_size);
	new_chunk->flags = flags;
	new_chunk->start = chunk_start;
	new_chunk->end = chunk_start + chunk_size;
	new_chunk->size = chunk_size;
	new_chunk->next = NULL;
	new_chunk->prev = NULL;
	new_chunk->pages = NULL;
	new_chunk->nr_pages = 0;
	new_chunk->vmap_base = NULL;

	DebugUA("user_area_init_chunk() finished: start 0x%lx size 0x%lx\n",
		chunk_start, chunk_size);
}

/*
 * Create new structure of chunk of user virtual memory area
 */
static inline user_chunk_t *
user_area_create_chunk(e2k_addr_t chunk_start, e2k_size_t chunk_size,
	unsigned long flags)
{
	user_chunk_t *new_chunk;

	DebugUA("user_area_create_chunk() started: start 0x%lx size 0x%lx\n",
		chunk_start, chunk_size);
	new_chunk = kmem_cache_alloc(user_area_chunk_cachep, GFP_KERNEL);
	if (new_chunk == NULL) {
		printk(KERN_ERR "user_area_create_chunk() could not "
			"allocate cached kernel memory for chunck struct\n");
		return NULL;
	}
	user_area_init_chunk(new_chunk, chunk_start, chunk_size, flags);
	DebugUA("user_area_create_chunk() finished: start 0x%lx size 0x%lx\n",
		chunk_start, chunk_size);
	return new_chunk;
}
static inline user_chunk_t *
user_area_create_empty_chunk(void)
{
	return user_area_create_chunk(0, 0, 0);
}
static inline void
user_area_release_chunk(user_chunk_t *chunk)
{
	BUG_ON(chunk->pages != NULL || chunk->nr_pages != 0);
	if (chunk->vmap_base != NULL) {
		pr_err("%s: virtual mapping is not yet freed, chunk from 0x%lx "
			"to 0x%lx cannot release\n",
			__func__, chunk->start, chunk->end);
	}
	BUG_ON(chunk->vmap_base != NULL);
	BUG_ON(chunk->flags & (USER_AREA_PRESENT | USER_AREA_LOCKED |
				USER_AREA_VMAPPED));
	kmem_cache_free(user_area_chunk_cachep, chunk);
}

/*
 * Delete the address of the user virtual memory area from the list of free
 * chunks.
 * Look up all the chunks which include specified address range.
 * The list should be locked by caller
 */
static inline int
user_area_occupy_chunk(user_area_t *user_area, user_chunk_t *chunk)
{
	user_chunk_t **p;
	user_chunk_t *next;
	user_chunk_t *new_chunk = NULL;
	user_chunk_t *chunk_to_free = NULL;
	user_chunk_t *queue_to_free = NULL;
	e2k_addr_t start = chunk->start;
	e2k_addr_t end = chunk->end;
	unsigned long irq_flags;

	DebugUA("user_area_occupy_chunk() started: chunk 0x%px start 0x%lx "
		"end 0x%lx\n",
		chunk, start, end);
	new_chunk = user_area_create_empty_chunk();
	if (new_chunk == NULL) {
		DebugUA("user_area_occupy_chunk() could not allocate structure "
			"for splited chunk\n");
		return -ENOMEM;
	}
	spin_lock_irqsave(&user_area->area_list_lock, irq_flags);
	for (p = &user_area->free_list; (next = *p); p = &next->next) {
		DebugUA("user_area_occupy_chunk() current chunk 0x%px "
			"start 0x%lx end 0x%lx\n",
			next, next->start, next->end);
		if (chunk_to_free != NULL) {
			chunk_to_free->next = queue_to_free;
			queue_to_free = chunk_to_free;
			chunk_to_free = NULL;
		}

		if ((start < next->start || start >= next->end) &&
			(end <= next->start || end > next->end) &&
			(next->start < start || next->start >= end) &&
			(next->end <= start || next->end > end)) {
			continue;
		}
		if (start > next->start) {
			if (end < next->end) {
				if (new_chunk == NULL) {
					panic("user_area_occupy_chunk() "
						"twice splitting of chunk "
						"from 0x%lx to 0x%lx to free "
						"area from 0x%lx to 0x%lx\n",
						next->start, next->end,
						start, end);
					break;
				}
				user_area_init_chunk(new_chunk,
					next->start, start - next->start,
					next->flags);
				new_chunk->next = next;
				new_chunk->prev = next->prev;
				next->start = end;
				next->size = next->end - end;
				next->prev = new_chunk;
				DebugUA("user_area_occupy_chunk() new chunk "
					"0x%px start 0x%lx end 0x%lx next "
					"chunk start 0x%lx end 0x%lx\n",
					new_chunk, new_chunk->start,
					new_chunk->end, next->start,
					next->end);
				new_chunk = NULL;
				continue;
			}
			next->end = start;
			next->size = start - next->start;
			DebugUA("user_area_occupy_chunk() next chunk "
				"0x%px start 0x%lx end 0x%lx\n",
				next, next->start, next->end);
			continue;
		}
		if (end < next->end) {
			next->start = end;
			next->size = next->end - end;
			DebugUA("user_area_occupy_chunk() next chunk "
				"0x%px start 0x%lx end 0x%lx\n",
				next, next->start, next->end);
			continue;
		}
		*p = next->next;
		if (next->next != NULL) {
			next->next->prev = next->prev;
		}
		chunk_to_free = next;
		DebugUA("user_area_occupy_chunk() will free next chunk "
			"0x%px start 0x%lx end 0x%lx\n",
			next, next->start, next->end);
	}
	spin_unlock_irqrestore(&user_area->area_list_lock, irq_flags);
	if (new_chunk) {
		user_area_release_chunk(new_chunk);
	}
	if (chunk_to_free) {
		user_area_release_chunk(chunk_to_free);
	}
	while (queue_to_free) {
		chunk_to_free = queue_to_free;
		queue_to_free = chunk_to_free->next;
		user_area_release_chunk(chunk_to_free);
	}

	DebugUA("user_area_occupy_chunk() finished\n");
	return 0;
}

/*
 * Create new user virtual memory area descriptor.
 * The function returns 0 on success and < 0 (-errno) if fails.
 */
user_area_t *
user_area_create(e2k_addr_t area_start, e2k_size_t area_size,
						unsigned long flags)
{
	user_area_t *new_area;
	user_chunk_t *free_chunk;

	DebugUA("user_area_create() started to init area start 0x%lx size "
		"0x%lx flags 0x%lx\n", area_start, area_size, flags);
	new_area = kmem_cache_alloc(user_area_cachep, GFP_KERNEL);
	if (new_area == NULL) {
		printk(KERN_ERR "Could not allocate memory for user area "
			"structure\n");
		return NULL;
	}
	new_area->flags = flags;
	new_area->area_start = area_start;
	new_area->area_end = area_start + area_size;
	spin_lock_init(&new_area->area_list_lock);
	new_area->busy_list = NULL;
	free_chunk = user_area_create_chunk(area_start, area_size, flags);
	DebugUA("user_area_create() created free chunk 0x%px to full area\n",
		free_chunk);
	if (free_chunk == NULL)
		return NULL;
	new_area->free_list = free_chunk;
	new_area->to_free_list = NULL;
	new_area->freebytes = area_size;
	DebugUA("user_area_create() returns area start 0x%lx size 0x%lx "
		"flags 0x%lx\n", area_start, area_size, flags);
	return new_area;
}

/*
 * Reserve the chunk of the user virtual memory area
 */
int
user_area_reserve_chunk(user_area_t *user_area, e2k_addr_t area_start,
						e2k_size_t area_size)
{
	user_chunk_t *area_chunk;
	int error;

	DebugUA("user_area_reserve_chunk() started: start 0x%lx size 0x%lx\n",
		area_start, area_size);
	area_chunk = user_area_create_chunk(area_start, area_size,
							user_area->flags);
	if (area_chunk == NULL) {
		DebugUA("user_area_reserve_chunk() Could not allocate "
			"structure to describe reserved chunk of user "
			"memory area\n");
		return -ENOMEM;
	}

	error = user_area_occupy_chunk(user_area, area_chunk);
	if (error < 0) {
		DebugUA("user_area_reserve_chunk() occupy "
			"reserved area failed\n");
		return error;
	}
	area_chunk->flags = USER_AREA_RESERVED;
	user_area_insert_busy_chunk(user_area, area_chunk);

	DebugUA("user_area_reserve_chunk() finished: start 0x%lx size 0x%lx\n",
		area_start, area_size);
	return 0;
}

/*
 * Merge a adjacent chunks into the list of free chunks.
 * The list should be locked by caller
 */
static user_chunk_t *
user_area_merge_chunks(user_area_t *user_area)
{
	user_chunk_t	**p, *tmp, **p1, *tmp1, *to_free;
	user_chunk_t	*queue_to_free = NULL;
	long		n = 0;

	DebugUA("user_area_merge_chunks() started: kmem area 0x%px\n",
		user_area);
	for (p = &user_area->free_list; (tmp = *p); p = &tmp->next) {
		DebugUA("user_area_merge_chunks() chunk to merge 0x%px "
			"start 0x%lx end 0x%lx\n",
			tmp, tmp->start, tmp->end);
		for (p1 = &tmp->next; (tmp1 = *p1); p1 = &tmp1->next) {
			DebugUA("user_area_merge_chunks() current condidate "
				"chunk 0x%px start 0x%lx end 0x%lx\n",
				tmp1, tmp1->start, tmp1->end);
			if (tmp->end == tmp1->start) {
				to_free = tmp1;
				DebugUA("user_area_merge_chunks() will merge "
					"with the chunk 0x%px\n",
					to_free);
				tmp->end = to_free->end;
			} else if (tmp->start == tmp1->end) {
				to_free = tmp1;
				DebugUA("user_area_merge_chunks() will merge "
					"with the chunk 0x%px\n",
					to_free);
				tmp->start = to_free->start;
			} else {
				continue;
			}
			tmp->size += to_free->size;
			if (to_free->prev == NULL)
				user_area->free_list = to_free->next;
			else
				to_free->prev->next = to_free->next;
			if (to_free->next != NULL)
				to_free->next->prev = to_free->prev;
			to_free->next = queue_to_free;
			queue_to_free = to_free;
			n++;
		}
	}
	DebugUA("user_area_merge_chunks() finished: merged %ld chunks\n", n);
	return queue_to_free;
}

#define	TMP_TO_FREE	0x1
#define	BUSY_TO_FREE	0x2
#define	FREE_TO_FREE	0x4
#define	MIN_USER_AREA_ALIGN	(sizeof(void *))

user_chunk_t *
user_area_get_chunk(user_area_t *user_area, e2k_addr_t start, e2k_addr_t size,
	e2k_addr_t align, unsigned long flags)
{
	e2k_addr_t	addr;
	e2k_addr_t	align_add = 0;
	e2k_addr_t	free_end;
	e2k_addr_t	end;
	e2k_size_t	sz;
	user_chunk_t	*tmp = NULL, *busy_chunk = NULL, *free_chunk = NULL;
	user_chunk_t	*queue_to_free = NULL;
	unsigned int	to_free = 0;
	int		try;
	unsigned long	irq_flags;

	DebugUA("user_area_get_chunk() started: kmem area 0x%px start 0x%lx "
		"size 0x%lx align 0x%lx\n",
		user_area, start, size, align);
	if (user_area->to_free_list != NULL)
		user_area_free_queued_chunks(user_area);
	if (start != ALIGN_TO_SIZE(start, align)) {
		printk(KERN_ERR "user_area_get_chunk() start address "
			"0x%lx is not aligned to 0x%lx\n",
			start, align);
		return NULL;
	}
	if (start != ALIGN_TO_SIZE(start, MIN_USER_AREA_ALIGN)) {
		printk(KERN_ERR "user_area_get_chunk() start address "
			"0x%lx is not aligned to 0x%lx\n",
			start, MIN_USER_AREA_ALIGN);
		return NULL;
	}
	size = ALIGN_TO_SIZE(size, MIN_USER_AREA_ALIGN);
	if (start != 0) {
		if (user_area_is_busy(user_area, start, size)) {
			pr_err("user_area_get_chunk() area from 0x%lx "
				"to 0x%lx is partially or fully busy\n",
				start, start + size);
			return NULL;
		}
	}

	busy_chunk = user_area_create_empty_chunk();
	if (start != 0 || align != 0) {
		free_chunk = user_area_create_empty_chunk();
	}

	spin_lock_irqsave(&user_area->area_list_lock, irq_flags);

	for (try = 0; try < 3; try++) {
		tmp = user_area_find_free_chunk(user_area, start,
							size, align);
		if (tmp != NULL)
			break;
		if (try == 0)
			continue;
		if (try == 1) {
			queue_to_free = user_area_merge_chunks(user_area);
			if (queue_to_free)
				continue;
		}
		spin_unlock_irqrestore(&user_area->area_list_lock, irq_flags);

		printk("user_area_get_chunk() could not find chunk\n");
#ifdef	CONFIG_DEBUG_USER_AREA
		user_area_print_all_chunks(user_area);
#endif	/* CONFIG_DEBUG_USER_AREA */
		to_free = (FREE_TO_FREE | BUSY_TO_FREE);
		goto free;
	}
	addr = tmp->start;
	sz = tmp->size;
	free_end = tmp->end;
	if (align != 0) {
		align_add = ALIGN_TO_SIZE(addr, align) - addr;
	}
	DebugUA("user_area_get_chunk() find chunk 0x%px addr 0x%lx start 0x%lx "
		"size 0x%lx\n", tmp, addr, start, sz);
	if (start != 0) {
		end = start + size;
		if (start > addr && busy_chunk == NULL ||
			end < tmp->end && free_chunk == NULL) {
			spin_unlock_irqrestore(&user_area->area_list_lock,
						irq_flags);
			to_free |= (FREE_TO_FREE | BUSY_TO_FREE);
			goto free;
		}
		if (start != addr) {
			tmp->end = start;
			tmp->size = start - addr;
			DebugUA("user_area_get_chunk() left chunk 0x%px end "
				"is now 0x%lx size 0x%lx\n",
				tmp, start, tmp->size);
		}
		if (end != free_end) {
			*free_chunk = *tmp;
			free_chunk->start = end;
			free_chunk->size = free_end - end;
			if (start != addr) {
				free_chunk->prev = tmp;
				tmp->next = free_chunk;
			}
			DebugUA("user_area_get_chunk() new right chunk 0x%px "
				"start 0x%lx end 0x%lx\n",
				free_chunk, end, free_chunk->end);
		} else {
			to_free |= FREE_TO_FREE;
		}
		if (start == addr && end == free_end) {
			if (tmp->next != NULL)
				tmp->next->prev = tmp->prev;
			if (tmp->prev != NULL)
				tmp->prev->next = tmp->next;
			else
				user_area->free_list = tmp->next;
			to_free |= TMP_TO_FREE;
		}
	} else {
		end = addr + align_add + size;
		if (align_add != 0) {
			tmp->end = addr + align_add;
			tmp->size = align_add;
			DebugUA("user_area_get_chunk() left chunk 0x%px end "
				"is now 0x%lx size 0x%lx\n",
				tmp, tmp->end, tmp->size);
		}
		if (sz - align_add > size) {
			if (align_add != 0) {
				*free_chunk = *tmp;
				free_chunk->start = end;
				free_chunk->size = sz - align_add - size;
				free_chunk->end = end + free_chunk->size;
				free_chunk->prev = tmp;
				tmp->next = free_chunk;
				DebugUA("user_area_get_chunk() new right chunk "
					"0x%px start 0x%lx end 0x%lx\n",
					free_chunk, free_chunk->start,
					free_chunk->end);
			} else {
				tmp->start += size;
				tmp->size -= size;
				to_free |= FREE_TO_FREE;
				DebugUA("user_area_get_chunk() right chunk "
					"0x%px start is now 0x%lx size 0x%lx\n",
					tmp, tmp->start, tmp->size);
			}
		} else  if (align_add == 0) {
			if (tmp->next != NULL)
				tmp->next->prev = tmp->prev;
			if (tmp->prev != NULL)
				tmp->prev->next = tmp->next;
			else
				user_area->free_list = tmp->next;
			to_free |= (TMP_TO_FREE | FREE_TO_FREE);
		}
		start = addr + align_add;
	}

	user_area->freebytes -= size;
	spin_unlock_irqrestore(&user_area->area_list_lock, irq_flags);

	user_area_init_chunk(busy_chunk, start, size, flags);

	DebugUA("user_area_get_chunk() finished: user area chunk 0x%px : "
		"start 0x%lx end 0x%lx flags 0x%lx\n",
		busy_chunk, busy_chunk->start, busy_chunk->end,
		busy_chunk->flags);

free:
	if ((to_free & TMP_TO_FREE) && tmp != NULL)
		user_area_release_chunk(tmp);
	if ((to_free & BUSY_TO_FREE) && busy_chunk != NULL) {
		user_area_release_chunk(busy_chunk);
		busy_chunk = NULL;
	}
	if ((to_free & FREE_TO_FREE) && free_chunk != NULL)
		user_area_release_chunk(free_chunk);
	while (free_chunk = queue_to_free) {
		queue_to_free = free_chunk->next;
		user_area_release_chunk(free_chunk);
	}

	return busy_chunk;
}

static inline void
user_area_put_chunk(user_area_t *user_area, user_chunk_t *chunk)
{
	DebugUA("user_area_put_chunk() started: for chunk 0x%px : "
		"start 0x%lx end 0x%lx\n",
		chunk, chunk->start, chunk->end);
	user_area_insert_free_chunk(user_area, chunk);
}

static inline void user_area_free_present_chunk(user_chunk_t *area_chunk)
{
	DebugUA("user_area_free_present_chunk() started for area: start 0x%lx "
		"end 0x%lx\n",
		area_chunk->start, area_chunk->end);

	BUG_ON(!(area_chunk->flags & USER_AREA_PRESENT));
	area_chunk->flags &= ~USER_AREA_PRESENT;
}

static inline void user_area_free_chunk_vmapped(user_chunk_t *area_chunk)
{
	struct page **pages;
	int page;

	DebugUA("user_area_free_chunk_vmapped() started for area: start 0x%lx "
		"end 0x%lx\n",
		area_chunk->start, area_chunk->end);

	pages = area_chunk->pages;
	BUG_ON(pages == NULL || area_chunk->nr_pages <= 0);
	for (page = 0; page < area_chunk->nr_pages; page++) {
		E2K_KVM_BUG_ON(pages[page] == NULL);
	}
	release_pages(pages, area_chunk->nr_pages);
	if (pages != area_chunk->few_pages)
		kfree(pages);
	area_chunk->pages = NULL;
	area_chunk->nr_pages = 0;
	area_chunk->flags &= ~USER_AREA_VMAPPED;
	return;
}

static void user_area_free_chunk_locked(user_chunk_t *chunk_to_free)
{
	e2k_addr_t start = chunk_to_free->start;
	e2k_addr_t end = chunk_to_free->end;
	int ret;

	DebugUA("user_area_free_chunk_locked() chunk %px : "
		"from 0x%lx to 0x%lx\n",
		chunk_to_free, start, end);
	BUG_ON(!(chunk_to_free->flags & USER_AREA_LOCKED));
	if (current->mm) {
		ret = sys_munlock(start, chunk_to_free->size);
		if (ret < 0) {
			DebugUA("user_area_free_chunk_locked() could not "
				"unlock area\n");
		}
	}
	chunk_to_free->flags &= ~USER_AREA_LOCKED;
}

static inline void user_area_free_chunk_alloc(user_chunk_t *area_chunk)
{
	DebugUA("user_area_free_chunk_alloc() started for area: start 0x%lx "
		"end 0x%lx\n",
		area_chunk->start, area_chunk->end);

	if (area_chunk->flags & USER_AREA_LOCKED)
		user_area_free_chunk_locked(area_chunk);
	if (area_chunk->flags & USER_AREA_VMAPPED)
		user_area_free_chunk_vmapped(area_chunk);
	if (area_chunk->flags & USER_AREA_PRESENT)
		user_area_free_present_chunk(area_chunk);
}

static inline int user_area_do_present_chunk(user_chunk_t *area_chunk)
{
	int ret;

	DebugUA("user_area_do_present_chunk() started for area: start 0x%lx "
		"end 0x%lx\n",
		area_chunk->start, area_chunk->end);

	BUG_ON(area_chunk->start & ~PAGE_MASK ||
			area_chunk->end & ~PAGE_MASK);
	ret = __mm_populate(area_chunk->start,
			area_chunk->end - area_chunk->start, false);
	if (ret) {
		DebugUA("user_area_do_present_chunk() could not "
			"allocate all do present user pages\n");
		return ret;
	}
	area_chunk->flags |= USER_AREA_PRESENT;
	DebugUA("user_area_do_present_chunk() allocated and do present "
		"%ld user pages\n",
		(area_chunk->end - area_chunk->start) / PAGE_SIZE);

	return 0;
}

static inline int user_area_do_alloc_chunk_pages(user_chunk_t *area_chunk)
{
	struct page **pages = NULL;
	int npages;
	int ret;

	DebugUA("user_area_do_alloc_chunk_pages() started for area: "
		"start 0x%lx, end 0x%lx\n",
		area_chunk->start, area_chunk->end);

	BUG_ON(area_chunk->start & ~PAGE_MASK ||
			area_chunk->end & ~PAGE_MASK);
	npages = PAGE_ALIGN(area_chunk->size) / PAGE_SIZE;
	DebugUA("user_area_do_alloc_chunk_pages() number of pages is %d\n",
		npages);
	if (npages <= MAX_NUM_A_FEW_PAGES) {
		pages = area_chunk->few_pages;
	} else {
		pages = kzalloc(npages * sizeof(struct page *), GFP_KERNEL);
		if (pages == NULL) {
			DebugUA("user_area_do_alloc_chunk_pages() could not "
				"allocate pages array\n");
			return -ENOMEM;
		}
	}
	ret = get_user_pages_fast(area_chunk->start, npages, 1, pages);
	if (unlikely(ret != npages)) {
		DebugUA("user_area_do_alloc_chunk_pages() could not "
			"allocate user pages\n");
		ret = -ENOMEM;
		goto out;
	}
	area_chunk->pages = pages;
	area_chunk->nr_pages = npages;
	area_chunk->flags |= USER_AREA_VMAPPED;

	DebugUA("user_area_do_alloc_chunk_pages() allocate %d user pages\n",
		ret);
	return 0;
out:
	user_area_free_chunk_vmapped(area_chunk);
	return ret;
}

void __user *user_area_alloc_chunk(user_area_t *user_area, e2k_addr_t start,
				e2k_addr_t size, e2k_addr_t align,
				unsigned long flags)
{
	user_chunk_t *area_chunk;
	unsigned long add_flags;
	int ret;

	if (start != ALIGN_TO_SIZE(start, PAGE_SIZE)) {
		DebugUA("user_area_alloc_chunk() start address 0x%lx is not "
			"PAGE size aligned\n", start);
		return NULL;
	}
	if (size != ALIGN_TO_SIZE(size, PAGE_SIZE)) {
		DebugUA("user_area_alloc_chunk() size 0x%lx is not "
			"PAGE size aligned, so align\n", size);
		size = ALIGN_TO_SIZE(size, PAGE_SIZE);
	}
	if (align < PAGE_SIZE) {
		DebugUA("user_area_alloc_chunk() align 0x%lx is not "
			"PAGE size aligned, so align\n", align);
		align = ALIGN_TO_SIZE(align, PAGE_SIZE);
	}
	area_chunk = user_area_get_chunk(user_area, start, size, align, 0);
	if (area_chunk == NULL) {
		DebugUA("user_area_alloc_chunk() could not get chunk from "
			"0x%lx size 0x%lx align 0x%lx\n",
			start, size, align);
		return NULL;
	}
	add_flags = 0;
	if (flags & KVM_ALLOC_AREA_MAP_FLAGS) {
		unsigned long prot = 0;

		if (flags & KVM_ALLOC_AREA_PROT_READ)
			prot |= PROT_READ;
		if (flags & KVM_ALLOC_AREA_PROT_WRITE)
			prot |= PROT_WRITE;
		if (flags & KVM_ALLOC_AREA_PROT_EXEC)
			prot |= PROT_EXEC;
		if (prot != 0) {
			ret = sys_mprotect(area_chunk->start, area_chunk->size,
						prot);
			if (ret) {
				pr_err("%s() could not change protections "
					"of allocated user chunk from 0x%lx "
					"to 0x%lx, error %d\n",
					__func__, start, start + size, ret);
				goto out_put_chunk;
			}
			add_flags |= (flags & KVM_ALLOC_AREA_MAP_FLAGS);
		}
	}
	if (flags & UA_VMAP_TO_KERNEL) {
		ret = user_area_do_alloc_chunk_pages(area_chunk);
		add_flags |= USER_AREA_VMAPPED;
	} else if (flags & UA_ALLOC_PRESENT) {
		ret = user_area_do_present_chunk(area_chunk);
		add_flags |= USER_AREA_PRESENT;
	} else {
		add_flags |= USER_AREA_ALLOCATED;
		ret = 0;
	}
	if (ret < 0) {
		DebugUA("user_area_alloc_chunk() could not make area "
			"as present\n");
		goto out_put_chunk;
	}
	area_chunk->flags |= add_flags;
	if (flags & UA_ALLOC_LOCKED) {
#ifndef	USER_AREA_LOCX_ENABLE
		DebugLOCX("do not lock guest area from 0x%lx to 0x%lx "
			"make only present\n",
			area_chunk->start,
			area_chunk->start + area_chunk->size);
		ret = user_area_do_present_chunk(area_chunk);
#else	/* USER_AREA_LOCX_ENABLE */
		ret = sys_mlock(area_chunk->start, area_chunk->size);
#endif	/* !USER_AREA_LOCX_ENABLE */
		if (ret < 0) {
			DebugUA("user_area_alloc_present() could not "
				"lock/present area\n");
			goto out_free_alloc;
		}
#ifndef	USER_AREA_LOCX_ENABLE
		area_chunk->flags |= USER_AREA_PRESENT;
#else	/* USER_AREA_LOCX_ENABLE */
		area_chunk->flags |= USER_AREA_LOCKED;
#endif	/* !USER_AREA_LOCX_ENABLE */
	}

	user_area_insert_busy_chunk(user_area, area_chunk);
	return (void *)area_chunk->start;

out_free_alloc:
	user_area_free_chunk_alloc(area_chunk);
out_put_chunk:
	user_area_put_chunk(user_area, area_chunk);
	return NULL;
}

void *map_user_area_to_vmalloc_range(user_area_t *user_area, void *user_base,
					pgprot_t prot)
{
	e2k_addr_t	start = (e2k_addr_t)user_base;
	user_chunk_t	*tmp;
	void		*vmap_base;
	unsigned long	irq_flags;

	DebugKA("started for user area from %px\n", user_base);
	spin_lock_irqsave(&user_area->area_list_lock, irq_flags);
	tmp = user_area_find_busy_chunk(user_area, start, 0);
	spin_unlock_irqrestore(&user_area->area_list_lock, irq_flags);
	if (tmp == NULL) {
		panic("map_user_area_to_vmalloc_range() could not find "
			"busy area: start 0x%lx\n", start);
	} else if (tmp->start != start) {
		panic("map_user_area_to_vmalloc_range() found only busy area: "
			"start 0x%lx end 0x%lx instead of 0x%lx\n",
			tmp->start, tmp->end, start);
	}
	DebugKA("found user area from 0x%lx to 0x%lx\n",
		tmp->start, tmp->end);
	BUG_ON(tmp->pages == NULL || tmp->nr_pages <= 0);
	vmap_base = vmap(tmp->pages, tmp->nr_pages, VM_ALLOC, prot);
	if (vmap_base == NULL) {
		DebugKA("could not map user area %px to kernel VM area\n",
			user_base);
		return NULL;
	}
	tmp->vmap_base = vmap_base;
	DebugKA("user area start 0x%lx end 0x%lx mapped to kernel VM area "
		"allocated from %px\n",
		tmp->start, tmp->end, vmap_base);

	return vmap_base;
}

void unmap_user_area_to_vmalloc_range(user_area_t *user_area, void *vmap_base)
{
	user_chunk_t	*tmp = NULL;
	unsigned long	irq_flags;

	DebugKA("started for user area from %px\n", vmap_base);
	if (user_area == NULL)
		goto only_vmap;
	spin_lock_irqsave(&user_area->area_list_lock, irq_flags);
	tmp = user_area_find_vmap_chunk(user_area, vmap_base);
	spin_unlock_irqrestore(&user_area->area_list_lock, irq_flags);
	if (tmp == NULL) {
		panic("unmap_user_area_to_vmalloc_range() could not find "
			"busy area: start from %px\n", vmap_base);
	} else if (tmp->vmap_base != vmap_base) {
		panic("unmap_user_area_to_vmalloc_range() found only busy "
			"area: from 0x%lx to 0x%lx instead of %px\n",
			tmp->start, tmp->end, vmap_base);
	}
	DebugKA("found user area to unmap from 0x%lx to 0x%lx\n",
		tmp->start, tmp->end);
only_vmap:
	vunmap(vmap_base);
	if (tmp != NULL)
		tmp->vmap_base = NULL;
}

static inline void
user_area_free_chunk_pages(user_area_t *user_area, user_chunk_t *chunk)
{
	user_area_free_chunk_alloc(chunk);
	user_area_put_chunk(user_area, chunk);
}

static void
user_area_do_free_chunk(user_area_t *user_area, void *chunk_base,
				unsigned long flags)
{
	user_chunk_t *tmp;
	e2k_addr_t start = (e2k_addr_t)chunk_base;
	e2k_addr_t end;
	unsigned long irq_flags;

	DebugUA("user_area_do_free_chunk() started: for chunk: start %px\n",
		chunk_base);
	spin_lock_irqsave(&user_area->area_list_lock, irq_flags);
	tmp = user_area_find_busy_chunk(user_area, start, 0);
	if (tmp == NULL) {
		panic("user_area_do_free_chunk() could not find busy area: "
			"start 0x%lx\n", start);
	} else if (tmp->start != start) {
		panic("user_area_do_free_chunk() found only busy area: "
			"start 0x%lx end 0x%lx instead of 0x%lx\n",
			tmp->start, tmp->end, start);
	}
	end = tmp->end;
	DebugUA("user_area_do_free_chunk() delete busy chunk %px: next %px "
		"prev %px\n",
		tmp, tmp->next, tmp->prev);
	if (tmp->next != NULL) {
		tmp->next->prev = tmp->prev;
		DebugUA("user_area_do_free_chunk() next chunk %px: next %px "
			"prev %px\n",
			tmp->next, tmp->next->next, tmp->next->prev);
	}
	if (tmp->prev != NULL) {
		tmp->prev->next = tmp->next;
		DebugUA("user_area_do_free_chunk() prev chunk %px: next %px "
			"prev %px\n",
			tmp->prev, tmp->prev->next, tmp->prev->prev);
	} else {
		user_area->busy_list = tmp->next;
		DebugUA("user_area_do_free_chunk() set head of busy chunks %px: "
			"to %px\n",
			&user_area->busy_list, user_area->busy_list);
	}
	spin_unlock_irqrestore(&user_area->area_list_lock, irq_flags);
	if (flags & USER_AREA_QUEUE) {
		user_area_insert_to_free_chunk(user_area, tmp);
		return;
	}
	user_area_free_chunk_pages(user_area, tmp);
}

static void
user_area_free_queued_chunks(user_area_t *user_area)
{
	user_chunk_t	*queue_to_free;
	user_chunk_t	*tmp;
	int		total = 0;
	unsigned long	irq_flags;

	DebugUA("user_area_free_queued_chunks() started: kmem area 0x%px : "
		"start 0x%lx end 0x%lx\n",
		user_area, user_area->area_start, user_area->area_end);
	if (user_area->to_free_list == NULL) {
		DebugUA("user_area_free_queued_chunks() returns: list "
			"to free is empty\n");
		return;
	}

	spin_lock_irqsave(&user_area->area_list_lock, irq_flags);
	queue_to_free = user_area->to_free_list;
	user_area->to_free_list = NULL;
	spin_unlock_irqrestore(&user_area->area_list_lock, irq_flags);

	while ((tmp = queue_to_free) != NULL) {
		DebugUA("user_area_free_queued_chunks() current chunk "
			"0x%px, start 0x%lx, end 0x%lx\n",
			tmp, tmp->start, tmp->end);
		queue_to_free = tmp->next;
		user_area_free_chunk_pages(user_area, tmp);
		total++;
	}

	DebugUA("user_area_free_queued_chunks() returns with freeed "
		"chunks num %d\n", total);
}

void user_area_free_chunk(user_area_t *user_area, void __user *chunk)
{
	user_area_free_queued_chunks(user_area);
	user_area_do_free_chunk(user_area, chunk, USER_AREA_FREE);
}

void user_area_queue_chunk_to_free(user_area_t *user_area, void *chunk)
{
	user_area_do_free_chunk(user_area, chunk, USER_AREA_QUEUE);
}

static void user_area_free_all_busy_chunks(user_area_t *user_area)
{
	user_chunk_t	*queue_to_free;
	user_chunk_t	*tmp;
	int		total = 0;
	unsigned long	irq_flags;

	DebugUA("user_area_free_all_busy_chunks() started: user area 0x%px : "
		"start 0x%lx end 0x%lx\n",
		user_area, user_area->area_start, user_area->area_end);
	spin_lock_irqsave(&user_area->area_list_lock, irq_flags);
	queue_to_free = user_area->busy_list;
	user_area->busy_list = NULL;
	spin_unlock_irqrestore(&user_area->area_list_lock, irq_flags);

	while ((tmp = queue_to_free) != NULL) {
		DebugUA("user_area_free_all_busy_chunks() current chunk "
			"0x%px, start 0x%lx, end 0x%lx\n",
			tmp, tmp->start, tmp->end);
		queue_to_free = tmp->next;
		user_area_free_chunk_pages(user_area, tmp);
		total++;
	}
	DebugUA("user_area_free_all_busy_chunks() released %d busy chunks\n",
		total);
}

static void user_area_release_all_free_chunks(user_area_t *user_area)
{
	user_chunk_t	*queue_to_free;
	user_chunk_t	*tmp;
	int		total = 0;
	unsigned long	irq_flags;

	DebugUA("user_area_release_all_free_chunks() started: user area 0x%px : "
		"start 0x%lx end 0x%lx\n",
		user_area, user_area->area_start, user_area->area_end);

	user_area_free_queued_chunks(user_area);

	spin_lock_irqsave(&user_area->area_list_lock, irq_flags);
	queue_to_free = user_area->free_list;
	user_area->free_list = NULL;
	spin_unlock_irqrestore(&user_area->area_list_lock, irq_flags);

	while ((tmp = queue_to_free) != NULL) {
		DebugUA("user_area_release_all_free_chunks() current chunk "
			"0x%px, start 0x%lx, end 0x%lx\n",
			tmp, tmp->start, tmp->end);
		queue_to_free = tmp->next;
		user_area_release_chunk(tmp);
		total++;
	}
	DebugUA("user_area_release_all_free_chunks() released %d chunks\n",
		total);
}

/*
 * Release user virtual memory area
 */
void user_area_release(user_area_t *user_area)
{
	DebugUA("user_area_release() started: user area 0x%px : "
		"start 0x%lx end 0x%lx\n",
		user_area, user_area->area_start, user_area->area_end);
	user_area_free_all_busy_chunks(user_area);
	user_area_release_all_free_chunks(user_area);
	if (user_area->busy_list || user_area->free_list ||
		user_area->to_free_list) {
		printk(KERN_ERR "user_area_release() not empty some of lists: "
			"busy %px or free %px or queue to free %px\n",
			user_area->busy_list, user_area->free_list,
			user_area->to_free_list);
	}
}
