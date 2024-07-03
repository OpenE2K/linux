/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_USER_AREA_ALLOC_H
#define _E2K_USER_AREA_ALLOC_H

#include <linux/types.h>
#include <asm/pgalloc.h>


/* user area and chunks flags */
/* WARNING should not intersect with protection flags */
/*	KVM_ALLOC_AREA_PROT_READ/WRITE/EXEC */
/*	KVM_ALLOC_AREA_HUGE */
#define	USER_AREA_CHUNK_ALLOC	0x0001UL
#define	USER_AREA_ORDERED	0x0002UL

#define	USER_AREA_RESERVED	0x0010UL
#define	USER_AREA_ALLOCATED	0x0020UL
#define	USER_AREA_PRESENT	0x0040UL
#define	USER_AREA_LOCKED	0x0080UL
#define	USER_AREA_VMAPPED	0x0100UL

#define	USER_AREA_FREE		0x1000UL
#define	USER_AREA_QUEUE		0x2000UL

/* user area allocation/free flags */
#define	UA_ALLOC_PRESENT	USER_AREA_PRESENT
#define	UA_ALLOC_LOCKED		USER_AREA_LOCKED
#define	UA_VMAP_TO_KERNEL	USER_AREA_VMAPPED

#define	MAX_NUM_A_FEW_PAGES	2	/* optimization for tipical case: */
					/* only a few page need allocate */

typedef	struct user_chunk {
	unsigned long		flags;
	e2k_addr_t		start;
	e2k_addr_t		end;
	e2k_size_t		size;
	struct user_chunk	*next;
	struct user_chunk	*prev;
	struct page		**pages;	/* pages to map to kernel */
	int			nr_pages;	/* number of physical pages */
	void			*vmap_base;	/* kernel virtual area base */
						/* where user area map to */
	struct page		*few_pages[MAX_NUM_A_FEW_PAGES];
} user_chunk_t;

typedef struct user_area {
	unsigned long		flags;
	e2k_addr_t		area_start;
	e2k_addr_t		area_end;
	spinlock_t		area_list_lock;
	user_chunk_t		*free_list;
	user_chunk_t		*busy_list;
	user_chunk_t		*to_free_list;
	e2k_size_t		freebytes;
} user_area_t;

extern int user_area_caches_init(void);
extern void user_area_caches_destroy(void);

extern user_area_t *user_area_create(e2k_addr_t area_start,
				e2k_size_t area_size, unsigned long flags);
extern void user_area_release(user_area_t *user_area);

extern int user_area_reserve_chunk(user_area_t *user_area,
		e2k_addr_t area_start, e2k_size_t area_size);
extern void __user *user_area_alloc_chunk(user_area_t *user_area,
		e2k_addr_t start, e2k_addr_t size, e2k_addr_t align,
		unsigned long flags);

/*
 * Allocate common chunk into the user virtual memory area
 */
static inline void __user *
user_area_alloc(user_area_t *user_area, e2k_size_t size, unsigned long flags)
{
	return user_area_alloc_chunk(user_area, 0, size, 0,
			flags & KVM_ALLOC_AREA_MAP_FLAGS);
}

static inline void __user *
user_area_get(user_area_t *user_area, e2k_addr_t start, e2k_size_t size,
		e2k_size_t align, unsigned long flags)
{
	return user_area_alloc_chunk(user_area, start, size, align,
			flags & KVM_ALLOC_AREA_MAP_FLAGS);
}

static inline void __user *
user_area_alloc_pages(user_area_t *user_area, e2k_addr_t start,
		e2k_addr_t size, e2k_addr_t align, unsigned long flags)
{
	return user_area_alloc_chunk(user_area, start, size, align,
			flags & KVM_ALLOC_AREA_MAP_FLAGS | UA_VMAP_TO_KERNEL);
}

static inline void __user *
user_area_alloc_present(user_area_t *user_area, e2k_addr_t start,
		e2k_addr_t size, e2k_addr_t align, unsigned long flags)
{
	return user_area_alloc_chunk(user_area, start, size, align,
			flags & KVM_ALLOC_AREA_MAP_FLAGS | UA_ALLOC_PRESENT);
}

static inline void __user *
user_area_alloc_zeroed(user_area_t *user_area, e2k_addr_t start,
		e2k_addr_t size, e2k_addr_t align, unsigned long flags)
{
	return user_area_alloc_present(user_area, start, size, align, flags);
}

static inline void __user *
user_area_alloc_locked(user_area_t *user_area, e2k_addr_t start,
		e2k_addr_t size, e2k_addr_t align, unsigned long flags)
{
	return user_area_alloc_chunk(user_area, start, size, align,
			flags & KVM_ALLOC_AREA_MAP_FLAGS | UA_ALLOC_LOCKED);
}

static inline void __user *
user_area_alloc_locked_pages(user_area_t *user_area, e2k_addr_t start,
		e2k_addr_t size, e2k_addr_t align, unsigned long flags)
{
	return user_area_alloc_chunk(user_area, start, size, align,
			flags & KVM_ALLOC_AREA_MAP_FLAGS |
					UA_VMAP_TO_KERNEL | UA_ALLOC_LOCKED);
}

static inline void __user *
user_area_alloc_locked_present(user_area_t *user_area, e2k_addr_t start,
		e2k_addr_t size, e2k_addr_t align, unsigned long flags)
{
	return user_area_alloc_chunk(user_area, start, size, align,
			flags & KVM_ALLOC_AREA_MAP_FLAGS |
					UA_ALLOC_PRESENT | UA_ALLOC_LOCKED);
}

extern void *map_user_area_to_vmalloc_range(user_area_t *user_area,
					void *user_base, pgprot_t prot);
extern void unmap_user_area_to_vmalloc_range(user_area_t *user_area,
					void *vmalloc_area);

extern void user_area_free_chunk(user_area_t *user_area, void __user *chunk);
extern void user_area_queue_chunk_to_free(user_area_t *user_area, void *chunk);

#endif	/* _E2K_USER_AREA_ALLOC_H */


