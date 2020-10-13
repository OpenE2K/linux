#ifndef _E2K_AREA_ALLOC_H
#define _E2K_AREA_ALLOC_H

#include <linux/types.h>
#include <asm/pgalloc.h>


#define	KMEM_AREA_CHUNK_ALLOC	0x0001UL
#define	KMEM_AREA_ORDERED	0x0002UL

#define	KMEM_AREA_ONLY_MAPPED	0x0010UL
#define	KMEM_AREA_ALLOCATED	0x0020UL

#define	KMEM_AREA_BOOT_MODE	0x0100UL
#define	KMEM_AREA_UNMAP		0x0200UL
#define	KMEM_AREA_QUEUE		0x0400UL

typedef	struct area_chunk {
	unsigned long		flags;
	e2k_addr_t		start;
	e2k_addr_t		end;
	e2k_size_t		size;
	struct area_chunk	*next;
	struct area_chunk	*prev;
#ifdef	CONFIG_DEBUG_KMEM_AREA
	long			get_count;
	long			get_pid;
	e2k_addr_t		get_ip;
	char			get_comm[TASK_COMM_LEN];
#endif	/* CONFIG_DEBUG_KMEM_AREA */
} area_chunk_t;

typedef struct kmem_area {
	unsigned long		flags;
	e2k_addr_t		area_start;
	e2k_addr_t		area_end;
	raw_spinlock_t		area_list_lock;
	area_chunk_t		*free_list;
	area_chunk_t		*busy_list;
	area_chunk_t		*to_free_list;
#ifdef CONFIG_E2K_STACK_BEANCOUNTERS
	e2k_size_t		freebytes;
	wait_queue_head_t	queue;
#endif /* CONFIG_E2K_STACK_BEANCOUNTERS */
} kmem_area_t;

extern __init void kmem_area_caches_init(void);
extern __init int kmem_area_create(kmem_area_t *new_area, e2k_addr_t area_start,
		e2k_size_t area_size, unsigned long flags);
extern __init void kmem_area_reserve_chunk(kmem_area_t *kmem_area,
		e2k_addr_t area_start, e2k_size_t area_size);
extern e2k_size_t kmem_area_free_chunk(kmem_area_t *kmem_area, void *chunk,
		int flags);
extern void kmem_area_queue_chunk_to_free(kmem_area_t *kmem_area,
		void *chunk);
extern area_chunk_t *kmem_area_get_chunk(struct task_struct *task,
		kmem_area_t *kmem_area, e2k_size_t size);
extern void *kmem_area_alloc(struct task_struct *task,
		kmem_area_t *kmem_area, e2k_size_t size,
		struct page *page, int gfp_mask, pgprot_t prot);

#endif	/* _E2K_AREA_ALLOC_H */

