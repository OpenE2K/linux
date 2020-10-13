/*  $Id: area_alloc.c,v 1.22 2009/03/03 12:45:14 rev Exp $
 *  arch/e2k/mm/area_alloc.c
 *
 * Contigous virtual area of kernel memory menegement.
 * The product is compilation of ideas of linux/mm/vmalloc and
 * linux/mm/mmap
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>

#ifdef CONFIG_E2K_STACK_BEANCOUNTERS
#include <linux/wait.h>
#endif

#include <asm/uaccess.h>
#include <asm/pgalloc.h>
#include <asm/area_alloc.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

#include <asm/e2k_debug.h>

#undef	DEBUG_AREA_ALLOC_MODE
#undef	DebugAA
#define	DEBUG_AREA_ALLOC_MODE	0	/* processes */
#define DebugAA(...)		DebugPrint(DEBUG_AREA_ALLOC_MODE ,##__VA_ARGS__)

#undef	DEBUG_PTE_MODE
#undef	DebugPT
#define	DEBUG_PTE_MODE		0	/* page table manipulations */
#define DebugPT(...)		DebugPrint(DEBUG_PTE_MODE ,##__VA_ARGS__)

#undef	DEBUG_FIM_MODE
#undef	DebugFIM
#define	DEBUG_FIM_MODE		0	/* Free initial memory */
#define DebugFIM(...)		DebugPrint(DEBUG_FIM_MODE ,##__VA_ARGS__)

#undef	DebugNUMA
#undef	DEBUG_NUMA_MODE
#define	DEBUG_NUMA_MODE		0	/* NUMA */
#define DebugNUMA(...)		DebugPrint(DEBUG_NUMA_MODE ,##__VA_ARGS__)

e2k_addr_t print_kernel_address_ptes(e2k_addr_t address);

/*
 * SLAB cache for kmem_area_t & area_chunk_t structures (kernel memory areas)
 */
static struct kmem_cache *kmem_area_chunk_cachep = NULL;

void __you_cannot_kmalloc_that_much(void)
{
	BUG();
}

__init void kmem_area_caches_init(void)
{
	kmem_area_chunk_cachep = kmem_cache_create("area_chunk_t",
						   sizeof(area_chunk_t), 0,
						   SLAB_HWCACHE_ALIGN, NULL);

	BUG_ON(!kmem_area_chunk_cachep);

	DebugAA("finished\n");
}

#ifdef	CONFIG_DEBUG_KMEM_AREA

/*
 * Print chunks
 */
static void
kmem_area_print_chunk(area_chunk_t *chunk)
{
	printk("   Chunk 0x%p next 0x%p prev 0x%p start 0x%lx end 0x%lx "
		"size 0x%08lx flags 0x%04lx %s : pid %ld IP 0x%lx\n",
		chunk, chunk->next, chunk->prev,
		chunk->start, chunk->end, chunk->size, chunk->flags,
		chunk->get_comm, chunk->get_pid, chunk->get_ip);
}
static long
kmem_area_print_all_chunks_in_list(area_chunk_t *chunk_list)
{
	area_chunk_t **p;
	area_chunk_t *next = NULL;
	long chunks_num = 0;

	for (p = &chunk_list; (next = *p); p = &next->next) {
		kmem_area_print_chunk(next);
		chunks_num ++;
	}
	return chunks_num;
}
static long
kmem_area_print_all_free_chunks(kmem_area_t *kmem_area)
{
	long chunks_num;
	printk("List of all free chunks in area from 0x%lx to 0x%lx\n",
		kmem_area->area_start, kmem_area->area_end);
	chunks_num = kmem_area_print_all_chunks_in_list(kmem_area->free_list);
	printk("Total number of free chunks is %ld\n", chunks_num);
	return chunks_num;
}
static long
kmem_area_print_all_busy_chunks(kmem_area_t *kmem_area)
{
	long chunks_num;
	printk("List of all busy chunks in area from 0x%lx to 0x%lx\n",
		kmem_area->area_start, kmem_area->area_end);
	chunks_num = kmem_area_print_all_chunks_in_list(kmem_area->busy_list);
	printk("Total number of busy chunks is %ld\n", chunks_num);
	return chunks_num;
}
void
kmem_area_print_all_chunks(kmem_area_t *kmem_area)
{
	long chunks_num;
	long total_num = 0;

	chunks_num = kmem_area_print_all_free_chunks(kmem_area);
	total_num += chunks_num;

	chunks_num = kmem_area_print_all_busy_chunks(kmem_area);
	total_num += chunks_num;

	printk("List of chunks queued to free in area from 0x%lx to 0x%lx\n",
		kmem_area->area_start, kmem_area->area_end);
	chunks_num = kmem_area_print_all_chunks_in_list(
						kmem_area->to_free_list);
	printk("Total number of queued chunks is %ld\n", chunks_num);
	total_num += chunks_num;
	printk("Total number of all chunks is %ld\n", total_num);
}
static long total_hanguped_chunks = 0;

/*
 * Find chunk with specified PID and the size of the kernel virtual memory
 * area into the list of chunks.
 * Look up the first chunk which satisfies  size == chunk->size and
 * pid == chunk->pid,  NULL if none.
 * The list should be locked by caller
 */
static inline area_chunk_t *
kmem_area_find_chunk_for_pid(area_chunk_t *chunk_list, e2k_size_t size,
				long pid)
{
	area_chunk_t **p;
	area_chunk_t *next = NULL;

	DebugAA("started: size 0x%lx pid %ld\n",
		size, pid);
	for (p = &chunk_list ; (next = *p) ; p = &next->next) {
		DebugAA("current chunk 0x%p "
			"size 0x%lx pid %ld\n",
			next, next->size, next->get_pid);
		if (next->size == size && next->get_pid == pid) {
			break;
		}
	}
	DebugAA("returns chunk 0x%p prev 0x%p\n",
		next, p);
	return next;
}

static struct task_struct *find_task_by_pid(pid_t nr)
{
	struct pid_namespace *ns;

	if (current->nsproxy == NULL) {
		ns = &init_pid_ns;
	} else {
		ns = current->nsproxy->pid_ns;
	}
	return find_task_by_pid_ns(nr, ns);
}

static void
kmem_area_check_busy_chunks(kmem_area_t *kmem_area)
{
	area_chunk_t	**p, *tmp;
	long		hanguped_chunks = 0;
	int		flags;

//	write_lock(&kmem_area->area_list_lock);
	raw_spin_lock_irqsave(&kmem_area->area_list_lock, flags);
	for (p = &kmem_area->busy_list ; (tmp = *p) ; p = &tmp->next) {
		if (tmp->get_pid == 0 ||
				find_task_by_pid(tmp->get_pid) == NULL) {
			if (tmp->get_count < 0) {
				hanguped_chunks ++;
				continue;
			}
			if (tmp->get_count == 0x1000) {
				printk("Chunk was not freed when task for pid "
					"could not find\n");
				kmem_area_print_chunk(tmp);
				tmp->get_count = -1;
				hanguped_chunks ++;
			} else {
				tmp->get_count ++;
			}
		} else if (tmp->get_count < 0) {
			printk("Task was detected again for hanguped chunk\n");
			kmem_area_print_chunk(tmp);
			tmp->get_count = 0;
		}
	}
	if (total_hanguped_chunks != hanguped_chunks) {
		printk("Total number of hanguped chunks is "
			"now %ld\n", hanguped_chunks);
		total_hanguped_chunks = hanguped_chunks;
	}
	for (p = &kmem_area->free_list ; (tmp = *p) ; p = &tmp->next) {
		if (tmp->get_count == -1) {
			printk("Chunk was freed even so it is not more "
				"hanguped chunk\n");
			kmem_area_print_chunk(tmp);
			tmp->get_count = -2;
			total_hanguped_chunks --;
			printk("Total number of hanguped chunks is "
				"now %ld\n", total_hanguped_chunks);
		} else if (tmp->get_count >= 0) {
			tmp->get_count = -2;
		}
		if (tmp->get_pid == 0)
			continue;
		if (find_task_by_pid(tmp->get_pid) != NULL) {
			if (tmp->get_count <= -0x1001)
				continue;
			if (tmp->get_count == -0x1000) {
				area_chunk_t *busy_chunk;
				busy_chunk = kmem_area_find_chunk_for_pid(
						kmem_area->busy_list, tmp->size,
						tmp->get_pid);
				if (busy_chunk == NULL) {

					printk("Chunk was freed but task for "
						"pid exist\n");
					kmem_area_print_chunk(tmp);
					kmem_area_print_all_free_chunks(
								kmem_area);
				}
			}
			tmp->get_count --;
		}
	}

//	write_unlock(&kmem_area->area_list_lock);
	raw_spin_unlock_irqrestore(&kmem_area->area_list_lock, flags);
}
#endif	/* CONFIG_DEBUG_KMEM_AREA */

/*
 * Find the address of the kernel virtual memory area into the list of chunks.
 * Look up the first chunk which satisfies  address < shunk_end,  NULL if none.
 * The list should be locked by caller
 */
static inline area_chunk_t *
kmem_area_find_chunk(area_chunk_t *chunk_list, area_chunk_t ***prev,
	e2k_addr_t address)
{
	area_chunk_t **p;
	area_chunk_t *next = NULL;

	DebugAA("started: address 0x%lx\n",
		address);
	for (p = &chunk_list ; (next = *p) ; p = &next->next) {
		DebugAA("current chunk 0x%p end "
			"0x%lx\n", next, next->end);
		if (address < next->end) {
			break;
		}
	}
	DebugAA("returns chunk 0x%p prev 0x%p\n",
		next, p);
	*prev = p;
	return next;
}

/*
 * Insert the chunk of the kernel virtual memory area to the list of the chunks.
 * The list should be locked by caller
 */
static inline void
kmem_area_insert_chunk(area_chunk_t *chunk_list, area_chunk_t *chunk)
{
	area_chunk_t	*next_chunk;
	area_chunk_t	**prev_chunk;

	DebugAA("started: chunk 0x%p\n",
		chunk);
	next_chunk = kmem_area_find_chunk(chunk_list, &prev_chunk,
								chunk->start);
	DebugAA("prev chunk 0x%p next 0x%p\n",
		*prev_chunk, next_chunk);
	*prev_chunk = chunk;
	if (prev_chunk == &chunk_list)
		chunk->prev = NULL;
	else
		chunk->prev = (area_chunk_t *)((e2k_addr_t)prev_chunk -
				offsetof (area_chunk_t, next));
//				(e2k_addr_t)chunk->next - (e2k_addr_t)chunk));
	chunk->next = next_chunk;
	if (next_chunk != NULL) {
		next_chunk->prev = chunk;
	}
	DebugAA("returns chunk->next 0x%p prev "
		"0x%p\n", chunk->next, chunk->prev);
}

/*
 * Delete the shunk of the kernel virtual memory area from the list
 * of the chunks. The list should be locked by caller
 */
static inline void
kmem_area_delete_chunk(area_chunk_t *chunk_list, e2k_addr_t address)
{
	area_chunk_t **p;
	area_chunk_t *next = NULL;

	DebugAA("started: address 0x%lxn",
		address);
	for (p = &chunk_list; (next = *p); p = &next->next) {
		DebugAA("current chunk 0x%p "
			"address 0x%lx\n", next, next->start);
		if (next->start == address) {
			break;
		}
	}
	if (next == NULL) {
		DebugAA("could not find a chunk "
			"for address 0x%lx\n", address);
		return;
	}
	DebugAA("found a chunk 0x%p "
		"for address 0x%lx\n", next, address);

	*p = next->next;
	if (next->next != NULL)
		next->next->prev = next->prev;
	DebugAA("deleted chunk 0x%p, from prev "
		"0x%p, next 0x%p\n",
		next, next->prev, next->next);
	next->next = next->prev = NULL;
}

/*
 * Insert the shunk of the kernel virtual memory area to the list of busy
 * chunks.
 * The list should be locked by caller
 */
static inline void
kmem_area_insert_busy_chunk(kmem_area_t *kmem_area, area_chunk_t *busy_chunk)
{
	DebugAA("started: chunk 0x%p\n",
		busy_chunk);
	if (kmem_area->flags & KMEM_AREA_ORDERED) {
		kmem_area_insert_chunk(kmem_area->busy_list, busy_chunk);
		DebugAA("returns ordered chunk "
			"chunk->next 0x%p chunk->prev 0x%p\n",
			busy_chunk->next, busy_chunk->prev);
		return;
	}
	busy_chunk->next = kmem_area->busy_list;
	busy_chunk->prev = NULL;
	if (kmem_area->busy_list != NULL) {
		kmem_area->busy_list->prev = busy_chunk;
	}
	kmem_area->busy_list = busy_chunk;
	DebugAA("returns unordered chunk "
		"chunk->next 0x%p chunk->prev 0x%p\n",
		busy_chunk->next, busy_chunk->prev);
}

/*
 * Insert the chunk of the kernel virtual memory area to the list of free
 * chunks.
 * The list should be locked by caller
 */
static inline void
kmem_area_insert_free_chunk(kmem_area_t *kmem_area, area_chunk_t *free_chunk)
{
	unsigned long flags;
	DebugAA("started: chunk 0x%p\n",
		free_chunk);
	raw_spin_lock_irqsave(&kmem_area->area_list_lock, flags);
	if (kmem_area->flags & KMEM_AREA_ORDERED) {
		kmem_area_insert_chunk(kmem_area->free_list, free_chunk);
		DebugAA("returns ordered chunk "
			"chunk->next 0x%p chunk->prev 0x%p\n",
			free_chunk->next, free_chunk->prev);
#ifdef CONFIG_E2K_STACK_BEANCOUNTERS
		kmem_area->freebytes += free_chunk->size;
#endif /* CONFIG_E2K_STACK_BEANCOUNTERS */
		raw_spin_unlock_irqrestore(&kmem_area->area_list_lock, flags);
		return;
	}
	free_chunk->next = kmem_area->free_list;
	free_chunk->prev = NULL;
	if (kmem_area->free_list != NULL) {
		kmem_area->free_list->prev = free_chunk;
	}
	kmem_area->free_list = free_chunk;
#ifdef CONFIG_E2K_STACK_BEANCOUNTERS
	kmem_area->freebytes += free_chunk->size;
#endif /* CONFIG_E2K_STACK_BEANCOUNTERS */
	raw_spin_unlock_irqrestore(&kmem_area->area_list_lock, flags);
	DebugAA("returns unordered chunk "
		"chunk->next 0x%p chunk->prev 0x%p\n",
		free_chunk->next, free_chunk->prev);
}

/*
 * Insert the shunk of the kernel virtual memory area to the list of
 * ready to free chunks.
 */
static inline void
kmem_area_insert_to_free_chunk(kmem_area_t *kmem_area,
					area_chunk_t *to_free_chunk)
{
	unsigned long flags;
	DebugAA("started: chunk 0x%p\n",
		to_free_chunk);
	raw_spin_lock_irqsave(&kmem_area->area_list_lock, flags);
	to_free_chunk->next = kmem_area->to_free_list;
	to_free_chunk->prev = NULL;
	if (kmem_area->to_free_list != NULL) {
		kmem_area->to_free_list->prev = to_free_chunk;
	}
	kmem_area->to_free_list = to_free_chunk;
	raw_spin_unlock_irqrestore(&kmem_area->area_list_lock, flags);
	DebugAA("inserted unordered "
		"chunk: chunk->next 0x%p chunk->prev 0x%p\n",
		to_free_chunk->next, to_free_chunk->prev);
}

/*
 * Init new structure of chunk of virtual memory area
 */
static inline void
kmem_area_init_chunk(area_chunk_t *new_chunk, e2k_addr_t chunk_start,
	e2k_size_t chunk_size, unsigned long flags)
{
	DebugAA("started: start 0x%lx size 0x%lx\n",
		chunk_start, chunk_size);
	new_chunk->flags = flags;
	new_chunk->start = chunk_start;
	new_chunk->end = chunk_start + chunk_size;
	new_chunk->size = chunk_size;
	new_chunk->next = NULL;
	new_chunk->prev = NULL;
#ifdef	CONFIG_DEBUG_KMEM_AREA
	new_chunk->get_count = -2;
	new_chunk->get_pid = 0;
	new_chunk->get_ip = -1;
	new_chunk->get_comm[0] = '\0';
#endif	/* CONFIG_DEBUG_KMEM_AREA */
	DebugAA("finished: start 0x%lx size 0x%lx\n",
		chunk_start, chunk_size);
}

/*
 * Create new structure of chunk of virtual memory area 
 */
static inline area_chunk_t *
kmem_area_create_chunk(e2k_addr_t chunk_start, e2k_size_t chunk_size,
	unsigned long flags)
{
	area_chunk_t *new_chunk;

	DebugAA("started: start 0x%lx size 0x%lx\n",
		chunk_start, chunk_size);
	new_chunk = kmem_cache_alloc(kmem_area_chunk_cachep, GFP_KERNEL);
	if (new_chunk == NULL) {
		printk(KERN_ERR "kmem_area_create_chunk() could not "
			"allocate cached kernel memory for chunck struct\n");
		return NULL;
	}
	kmem_area_init_chunk(new_chunk, chunk_start, chunk_size, flags);
	DebugAA("finished: start 0x%lx size 0x%lx\n",
		chunk_start, chunk_size);
	return new_chunk;
}

/*
 * Delete the address of the kernel virtual memory area from the list of free
 * chunks.
 * Look up all the chunks which include specified address range.
 * The list should be locked by caller
 */
static inline void
kmem_area_occupy_chunk(kmem_area_t *kmem_area, area_chunk_t *chunk_list,
			 area_chunk_t *chunk, unsigned long irq_flags)
{
	area_chunk_t	**p;
	area_chunk_t	*next;
	area_chunk_t	*new_chunk = NULL;
	area_chunk_t	*free_chunk = NULL;
	e2k_addr_t	start = chunk->start;
	e2k_addr_t	end = chunk->end;

	DebugAA("started: chunk 0x%p start 0x%lx "
		"end 0x%lx\n",
		chunk, start, end);
repeate:
	for (p = &chunk_list ; (next = *p) ; p = &next->next) {
		DebugAA("current chunk 0x%p "
			"start 0x%lx end 0x%lx\n",
			next, next->start, next->end);
		if (free_chunk != NULL) {
			raw_spin_unlock_irqrestore(&kmem_area->area_list_lock,
							irq_flags);
			kmem_cache_free(kmem_area_chunk_cachep, free_chunk);
			free_chunk = NULL;
			raw_spin_lock_irqsave(&kmem_area->area_list_lock,
							irq_flags);
			goto repeate;
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
	                       		 raw_spin_unlock_irqrestore(
						&kmem_area->area_list_lock,
						irq_flags);
					 new_chunk = kmem_cache_alloc(
							kmem_area_chunk_cachep,
							GFP_KERNEL);
	        	            	 raw_spin_lock_irqsave(
						&kmem_area->area_list_lock,
						irq_flags);
					 goto repeate;
				} else {
					kmem_area_init_chunk(new_chunk,
						next->start,
						start - next->start,
						next->flags);
				}
				new_chunk->next = next;
				new_chunk->prev = next->prev;
				next->start = end;
				next->size = next->end - end;
				next->prev = new_chunk;
				DebugAA("new chunk "
					"0x%p start 0x%lx end 0x%lx next "
					"chunk start 0x%lx end 0x%lx\n",
					new_chunk, new_chunk->start,
					new_chunk->end, next->start,
					next->end);
				new_chunk = NULL;
				continue;
			}
			next->end = start;
			next->size = start - next->start;
			DebugAA("next chunk "
				"0x%p start 0x%lx end 0x%lx\n",
				next, next->start, next->end);
			continue;
		}
		if (end < next->end) {
			next->start = end;
			next->size = next->end - end;
			DebugAA("next chunk "
				"0x%p start 0x%lx end 0x%lx\n",
				next, next->start, next->end);
			continue;
		}
		*p = next->next;
		if (next->next == NULL) {
			DebugAA("will free next chunk "
				"0x%p start 0x%lx end 0x%lx\n",
				next, next->start, next->end);
			raw_spin_unlock_irqrestore(&kmem_area->area_list_lock,
							irq_flags);
			kmem_cache_free(kmem_area_chunk_cachep, next);
			raw_spin_lock_irqsave(&kmem_area->area_list_lock,
							irq_flags);
			next = NULL;
			goto repeate;
//			break;
		}
		next->next->prev = next->prev;
		free_chunk = next;
		DebugAA("will free next chunk "
			"0x%p start 0x%lx end 0x%lx\n",
			next, next->start, next->end);
	}
	if (new_chunk) {
		raw_spin_unlock_irqrestore(&kmem_area->area_list_lock,
						irq_flags);
		kmem_cache_free(kmem_area_chunk_cachep, new_chunk);
		raw_spin_lock_irqsave(&kmem_area->area_list_lock, irq_flags);
		goto repeate;
	}

	DebugAA("finished\n");
}

/*
 * Create new kernel virtual memory area descriptor.
 * The function returns 0 on success and < 0 (-errno) if fails.
 */
int __init
kmem_area_create(kmem_area_t *new_area, e2k_addr_t area_start,
	e2k_size_t area_size, unsigned long flags)
{
	area_chunk_t *free_chunk;

	DebugAA("started to init area start 0x%lx size "
		"0x%lx flags 0x%lx\n", area_start, area_size, flags);
	new_area->flags = flags;
	new_area->area_start = area_start;
	new_area->area_end = area_start + area_size;
//	new_area->area_list_lock = RW_LOCK_UNLOCKED(new_area->area_list_lock);
	new_area->area_list_lock = __RAW_SPIN_LOCK_UNLOCKED(
						new_area.area_list_lock);
	new_area->busy_list = NULL;
	free_chunk = kmem_area_create_chunk(area_start, area_size, flags);
	DebugAA("created free chunk 0x%p to full area\n",
		free_chunk);
	if (free_chunk == NULL)
		return -ENOMEM;
	new_area->free_list = free_chunk;
	new_area->to_free_list = NULL;
#ifdef CONFIG_E2K_STACK_BEANCOUNTERS
	new_area->freebytes = area_size;
	init_waitqueue_head(&new_area->queue);
#endif /* CONFIG_E2K_STACK_BEANCOUNTERS */
	DebugAA("returns area start 0x%lx size 0x%lx "
		"flags 0x%lx\n", area_start, area_size, flags);
	return 0;
}

/*
 * Reserve the chunk of the kernel virtual memory area
 */
__init void kmem_area_reserve_chunk(kmem_area_t *kmem_area,
				    e2k_addr_t area_start, e2k_size_t area_size)
{
	area_chunk_t *area_chunk;
	unsigned long flags;

	DebugAA("started: start 0x%lx size 0x%lx\n",
		area_start, area_size);
	area_chunk = kmem_area_create_chunk(area_start, area_size,
			kmem_area->flags);
	if (area_chunk == NULL) {
		printk(KERN_ERR "Could not allocate structure to describe "
			"reserved chunk of kernel memory area\n");
		BUG();
		return;
	}

//	write_lock(&kmem_area->area_list_lock);
	raw_spin_lock_irqsave(&kmem_area->area_list_lock, flags);

	kmem_area_occupy_chunk(kmem_area, kmem_area->free_list, area_chunk, flags);
#ifdef	CONFIG_DEBUG_KMEM_AREA
	area_chunk->get_count = 0;
	area_chunk->get_pid = current->pid;
	area_chunk->get_ip = (e2k_addr_t)__e2k_kernel_return_address(0);
	get_task_comm(area_chunk->get_comm, current);
#endif	/* CONFIG_DEBUG_KMEM_AREA */
	kmem_area_insert_busy_chunk(kmem_area, area_chunk);

//	write_unlock(&kmem_area->area_list_lock);
	raw_spin_unlock_irqrestore(&kmem_area->area_list_lock, flags);

	DebugAA("finished: start 0x%lx size 0x%lx\n",
		area_start, area_size);
}

static inline e2k_size_t
free_area_chunk_pte(pmd_t *pmd, e2k_addr_t address, e2k_addr_t end, int flags)
{
	pte_t		*pte;
	e2k_size_t	pages = 0;

	DebugPT("started: pmd 0x%p from address 0x%lx "
		"to 0x%lx\n",
		pmd, address, end);

	pte = pte_offset_kernel(pmd, address);
	do {
		pte_t page;
		DebugPT("will clear pte 0x%p for addr "
			"0x%lx\n",
			pte, address);
		page = ptep_get_and_clear(&init_mm, address, pte);
		if (pte_none(page)) {
			if (flags & KMEM_AREA_BOOT_MODE) {
				printk("free_area_chunk_pte() : PTE  0x%p = "
					"0x%016lx none for address 0x%016lx\n",
					pte, pte_val(page), address);
			}
		} else if (pte_present(page)) {
			struct page *ptpage = pte_page(page);
			DebugPT("will free page 0x%p "
				"for addr 0x%lx, pte 0x%p = 0x%lx\n",
				ptpage, address, pte, pte_val(page));
			if (flags & KMEM_AREA_BOOT_MODE) {
				if (!page_valid(ptpage)) {
					printk("free_area_chunk_pte() : PTE  "
						"0x%p = 0x%016lx for address "
						"0x%lx points to invalid PFN\n",
						pte, pte_val(page), address);
				} else if (!PageReserved(ptpage)) {
					printk("free_area_chunk_pte() : PTE  "
						"0x%p = 0x%016lx for address "
						"0x%lx points to not reserved "
						"physical page\n",
						pte, pte_val(page), address);
				} else {
					if (!PageReserved(ptpage)) {
						printk("Page 0x%p to free of physical address 0x%lx is not reserved\n",
							ptpage,
							page_to_pfn(ptpage)
								<< PAGE_SHIFT);
						BUG();
					}
					free_reserved_page(ptpage);
					pages ++;
				}
			} else {
				if (page_valid(ptpage) && 
						(!PageReserved(ptpage))) {
					if (flags & KMEM_AREA_UNMAP)
						put_page(ptpage);
					else
						__free_page(ptpage);
					pages ++;
				}
			}
		} else {
			printk(KERN_CRIT "Whee.. Swapped out page in kernel "
				"page table for address 0x%lx\n", address);
		}
	} while (pte ++, address += PAGE_SIZE, address != end);
	DebugPT("finished: pmd 0x%p from address 0x%lx "
		"to 0x%lx\n",
		pmd, address, end);
	return pages;
}

static inline e2k_size_t
free_area_chunk_pmd(pud_t *dir, e2k_addr_t address, e2k_addr_t end, int flags)
{
	pmd_t		*pmd;
	e2k_addr_t	next;
	e2k_size_t	pages = 0;

	DebugPT("started: pud 0x%p from address 0x%lx "
		"to 0x%lx\n",
		dir, address, end);
	pmd = pmd_offset_kernel(dir, address);
	do {
		DebugPT("will free pte of pmd 0x%lx "
			"for addr 0x%lx\n",
			pmd_val(*pmd), address);
		next = pmd_addr_end(address, end);
		if (pmd_none_or_clear_bad_kernel(pmd)) {
			if (flags & KMEM_AREA_BOOT_MODE) {
				printk("free_area_chunk_pte() : PMD  0x%p = "
					"0x%016lx none for address 0x%016lx\n",
					pmd, pmd_val(*pmd), address);
			}
			continue;
		}
		pages += free_area_chunk_pte(pmd, address, next, flags);
	} while (pmd ++, address = next, address != end);
	DebugPT("finished: pud 0x%p from address 0x%lx "
		"to 0x%lx\n",
		dir, address, end);
	return pages;
}

static inline e2k_size_t
free_area_chunk_pud(pgd_t *dir, e2k_addr_t address, e2k_addr_t end, int flags)
{
	pud_t		*pud;
	e2k_addr_t	next;
	e2k_size_t	pages = 0;

	DebugPT("started: pgd 0x%p from address 0x%lx "
		"to 0x%lx\n",
		dir, address, end);
	pud = pud_offset_kernel(dir, address);
	do {
		DebugPT("will free pmd of pud 0x%lx "
			"for addr 0x%lx\n",
			pud_val(*pud), address);
		next = pud_addr_end(address, end);
		if (pud_none_or_clear_bad_kernel(pud)) {
			if (flags & KMEM_AREA_BOOT_MODE) {
				printk("free_area_chunk_pud() : PUD  0x%p = "
					"0x%016lx none for address 0x%016lx\n",
					pud, pud_val(*pud), address);
			}
			continue;
		}
		pages += free_area_chunk_pmd(pud, address, next, flags);
	} while (pud ++, address = next, address != end);
	DebugPT("finished: pgd 0x%p from address 0x%lx "
		"to 0x%lx\n",
		dir, address, end);
	return pages;
}

static e2k_size_t
kmem_area_free_chunk_pages(e2k_addr_t start, e2k_size_t size, int flags)
{
	pgd_t		*dir;
	e2k_addr_t	address = start;
	e2k_addr_t	end = address + size;
	e2k_addr_t	next;
	e2k_size_t	pages = 0;
	int		nid = numa_node_id();

	DebugAA("started: address 0x%lx "
		"size 0x%lx flags 0x%x\n",
		address, size, flags);
	dir = node_pgd_offset_kernel(nid, address);
	flush_cache_all();
	do {
		DebugPT("will free pud of pgd "
			"0x%lx for addr 0x%lx\n",
			pgd_val(*dir), address);
		next = pgd_addr_end(address, end);
		if (pgd_none_or_clear_bad_kernel(dir)) {
			if (flags & KMEM_AREA_BOOT_MODE) {
				printk("free_area_chunk_pages() : PGD  0x%p = "
					"0x%016lx none for address 0x%016lx\n",
					dir, pgd_val(*dir), address);
			}
			continue;
		}
		pages += free_area_chunk_pud(dir, address, next, flags);
	} while (dir ++, address = next, address != end);
#ifdef	CONFIG_NUMA
	all_other_nodes_unmap_kmem_area(nid, start, size);
#endif	/* CONFIG_NUMA */
	flush_tlb_all();
	DebugAA("finished: address 0x%lx "
		"size 0x%lx\n",
		address, size);
	return pages;
}

static inline int
kmem_area_alloc_chunk_pte(int nid, pmd_t *pmd, e2k_addr_t address,
	e2k_addr_t end, int gfp_mask, pgprot_t prot)
{
	pte_t *pte;

	pte = node_pte_alloc_kernel(nid, pmd, address);
	DebugPT("started: node #%d pmd 0x%p "
		"address from 0x%lx to 0x%lx\n",
		nid, pte, address, end);
	if (!pte)
		return -ENOMEM;
	do {
		struct page * page;
		if (!pte_none(*pte)) {
			printk(KERN_ERR "kmem_area_alloc_chunk_pte: page "
				"0x%p = 0x%lx already exists\n",
				pte, pte_val(*pte));
		}
		page = alloc_pages_node(nid, gfp_mask, 0);
		if (!page)
			return -ENOMEM;
		DebugPT("will set pte "
			"0x%p to page 0x%p for addr 0x%lx\n",
			pte, page, address);
		set_pte_at(&init_mm, address, pte, mk_pte(page, prot));
	} while (pte ++, address += PAGE_SIZE, address != end);
	DebugPT("finished: pmd 0x%p address "
		"from 0x%lx to 0x%lx\n",
		pmd, address, end);
	return 0;
}

static inline int
kmem_area_alloc_chunk_pmd(int nid, pud_t *pud, e2k_addr_t address,
	e2k_addr_t end, int gfp_mask, pgprot_t prot)
{
	pmd_t *pmd;
	e2k_addr_t next;

	DebugPT("started: pud 0x%p address "
		"from 0x%lx to 0x%lx\n", pud, address, end);
	pmd = node_pmd_alloc_kernel(nid, pud, address);
	if (!pmd)
		return -ENOMEM;
	do {
		DebugPT("will alloc for pmd 0x%p, "
			"address 0x%lx\n",
			pmd, address);
		next = pmd_addr_end(address, end);
		if (kmem_area_alloc_chunk_pte(nid, pmd, address, next,
							gfp_mask, prot))
			return -ENOMEM;
	} while (pmd ++, address = next, address != end);
	DebugPT("finished: pud 0x%p address "
		"from 0x%lx to 0x%lx\n",
		pud, address, end);
	return 0;
}

static inline int
kmem_area_alloc_chunk_pud(int nid, pgd_t *pgd, e2k_addr_t address,
	e2k_addr_t end, int gfp_mask, pgprot_t prot)
{
	pud_t *pud;
	e2k_addr_t next;

	DebugPT("started: pgd 0x%p address "
		"from 0x%lx to 0x%lx\n", pgd, address, end);

	pud = node_pud_alloc_kernel(nid, pgd, address);
	if (!pud)
		return -ENOMEM;
	do {
		DebugPT("will alloc for pud 0x%p, "
			"address 0x%lx\n",
			pud, address);
		next = pud_addr_end(address, end);
		if (kmem_area_alloc_chunk_pmd(nid, pud, address, next,
							gfp_mask, prot))
			return -(ENOMEM);
	} while (pud ++, address = next, address != end);
	DebugPT("finished: pgd 0x%p address "
		"from 0x%lx to 0x%lx\n",
		pgd, address, end);
	return 0;
}

static int
kmem_area_alloc_chunk_pages(int nid, e2k_addr_t start, e2k_size_t size,
	int gfp_mask, pgprot_t prot)
{
	pgd_t		*dir;
	e2k_addr_t	address = start;
	e2k_addr_t	end = address + size;
	e2k_addr_t	next;
	int		ret;

	DebugNUMA("started on CPU #%d: "
		"address 0x%lx size 0x%lx\n",
		smp_processor_id(), address, size);
	dir = node_pgd_offset_kernel(nid, address);
	do {
		DebugPT("will alloc for "
			"pgd 0x%p, address 0x%lx\n",
			dir, address);
		ret = -ENOMEM;
		next = pgd_addr_end(address, end);
		if (kmem_area_alloc_chunk_pud(nid, dir, address, next,
							gfp_mask, prot))
			break;
		ret = 0;
	} while (dir ++, address = next, address != end);
#ifdef	CONFIG_NUMA
	if (all_other_nodes_map_vm_area(nid, start, size)) {
		panic("Could not map kernel area 0x%lx, size 0x%lx "
			"on all other nodes\n",
			start, size);
	}
#endif	/* CONFIG_NUMA */
	DebugAA("finished: address "
		"0x%lx size 0x%lx\n",
		address, size);
	return ret;
}

/*
 * Map a virtual chunk page to the physical page.
 */
static int
kmem_area_map_chunk_page(e2k_addr_t address, struct page *page,
							pgprot_t prot)
{
	pgd_t	*pgd;
	pud_t	*pud;
	pmd_t	*pmd;
	pte_t	*pte;
	int	nid = numa_node_id();

	DebugNUMA("started on CPU #%d: "
		"address 0x%lx page 0x%p\n",
		smp_processor_id(), address, page);
	if (address & ~PAGE_MASK) {
		printk(KERN_ERR "Trying to kmem_area_map_chunk_page() bad "
			"address (not page aligned) (0x%lx)\n", address);
		return -EINVAL;
	}
	pgd = node_pgd_offset_kernel(nid, address);

	pud = pud_alloc_kernel(&init_mm, pgd, address);
	if (!pud) {
		return -ENOMEM;
	}
	pmd = pmd_alloc_kernel(&init_mm, pud, address);
	if (!pmd) {
		pud_free_kernel(pud);
		return -ENOMEM;
	}
	pte = pte_alloc_kernel(pmd, address);
	if (!pte) {
		pmd_free_kernel(pmd);
		pud_free_kernel(pud);
		return -ENOMEM;
	}
	if (!pte_none(*pte)) {
		printk(KERN_ERR "kmem_area_map_chunk_page: page "
			"already exists\n");
		print_kernel_address_ptes(address);
	}

	if (!PageReserved(page))
		get_page(page);
	DebugAA("will set pte 0x%p to "
		"page 0x%p\n",
		pte, page);
	set_pte_at(&init_mm, address, pte, mk_pte(page, prot));
	DebugAA("set pte 0x%p == 0x%lx\n",
		pte, pte_val(*pte));

#ifdef	CONFIG_NUMA
	if (all_other_nodes_map_vm_area(nid, address, PAGE_SIZE)) {
		panic("Could not map kernel page 0x%lx, size 0x%lx "
			"on all other nodes\n",
			address, PAGE_SIZE);
	}
#endif	/* CONFIG_NUMA */

	DebugAA("finished: address "
		"0x%lx page 0x%p\n",
		address, page);

	return 0;
}

static inline e2k_size_t
kmem_area_free_queued_chunks(kmem_area_t *kmem_area)
{
	area_chunk_t	*tmp;
	e2k_size_t	pages = 0;
	int		flags = 0;
	unsigned long	irq_flags;

	DebugAA("started: kmem area 0x%p\n",
		kmem_area);
	if (kmem_area->to_free_list == NULL) {
		DebugAA("returns: list "
			"to free is empty\n");
		return 0;
	}

	raw_spin_lock_irqsave(&kmem_area->area_list_lock, irq_flags);

	while ((tmp = kmem_area->to_free_list) != NULL) {
		DebugAA("current chunk "
			"0x%p, start 0x%lx, end 0x%lx\n",
			tmp, tmp->start, tmp->end);
		kmem_area->to_free_list = tmp->next;
		if (tmp->next != NULL)
			tmp->next->prev = NULL;
		raw_spin_unlock_irqrestore(&kmem_area->area_list_lock,
						irq_flags);
		if (tmp->flags & KMEM_AREA_ONLY_MAPPED)
			flags |= KMEM_AREA_UNMAP;
		pages += kmem_area_free_chunk_pages(tmp->start,
							tmp->size,flags);
		kmem_area_insert_free_chunk(kmem_area, tmp);
		raw_spin_lock_irqsave(&kmem_area->area_list_lock, irq_flags);
	}

	raw_spin_unlock_irqrestore(&kmem_area->area_list_lock, irq_flags);

	DebugAA("returns with freeed "
		"pages num 0x%lx\n", pages);
	return pages;
}

/*
 * Merge a adjacent shunks into the list of free chunks.
 * The list should be locked by caller
 */
static int
kmem_area_merge_chunks(kmem_area_t *kmem_area)
{
	area_chunk_t	**p, *tmp, **p1, *tmp1, *to_free;
	long		n = 0;

	DebugAA("started: kmem area 0x%p\n",
		kmem_area);
	for (p = &kmem_area->free_list; (tmp = *p); p = &tmp->next) {
		DebugAA("chunk to merge 0x%p "
			"start 0x%lx end 0x%lx\n",
			tmp, tmp->start, tmp->end);
		for (p1 = &tmp->next; (tmp1 = *p1); p1 = &tmp1->next) {
			DebugAA("current condidate "
				"chunk 0x%p start 0x%lx end 0x%lx\n",
				tmp1, tmp1->start, tmp1->end);
			if (tmp->end == tmp1->start) {
				to_free = tmp1;
				DebugAA("will merge "
					"with the chunk 0x%p\n",
					to_free);
				tmp->end = to_free->end;
			} else if (tmp->start == tmp1->end) {
				to_free = tmp1;
				DebugAA("will merge "
					"with the chunk 0x%p\n",
					to_free);
				tmp->start = to_free->start;
			} else {
				continue;
			}
			tmp->size += to_free->size;
			if (to_free->prev == NULL)
				kmem_area->free_list = to_free->next;
			else
				to_free->prev->next = to_free->next;
			if (to_free->next != NULL)
				to_free->next->prev = to_free->prev;
			kmem_cache_free(kmem_area_chunk_cachep, to_free);
			n++;
		}
	}
	DebugAA("finished: merged %ld chunks\n", n);
	return n;
}

static area_chunk_t *
do_kmem_area_get_chunk(struct task_struct *task, kmem_area_t *kmem_area,
		    e2k_addr_t size, unsigned long flags)
{
	e2k_addr_t	addr;
	area_chunk_t	**p, *tmp, *area_chunk = NULL, *chunk_to_free = NULL;
	int		try;
	unsigned long	irq_flags;

	DebugAA("started: kmem area 0x%p size 0x%lx\n",
		kmem_area, size);
	if (kmem_area->to_free_list != NULL)
		kmem_area_free_queued_chunks(kmem_area);
repeat:
	raw_spin_lock_irqsave(&kmem_area->area_list_lock, irq_flags);
 
#ifdef CONFIG_E2K_STACK_BEANCOUNTERS
	if ((kmem_area->freebytes - size) <= KERNEL_MAX_HW_STACK_WATERMARK &&
			!(current->flags & PF_EXITING)) {
		raw_spin_unlock_irqrestore(&kmem_area->area_list_lock,
					   irq_flags);
		return NULL;
	}
#endif /* CONFIG_E2K_STACK_BEANCOUNTERS */

	for (try = 0; try < 3; try ++) {
		for (p = &kmem_area->free_list; (tmp = *p) ; p = &tmp->next) {
			if (tmp->size == size)
				break;
			if (tmp->size >= size && try != 0)
				break;
		}
		if (tmp != NULL)
			break;
		if (try == 0)
			continue;
		if (try == 1) {
			if (kmem_area_merge_chunks(kmem_area) > 0)
				continue;
		}
		raw_spin_unlock_irqrestore(&kmem_area->area_list_lock,
						irq_flags);

		DebugAA("could not find chunk\n");
#ifdef	CONFIG_DEBUG_KMEM_AREA
		kmem_area_print_all_chunks(kmem_area);
#endif	/* CONFIG_DEBUG_KMEM_AREA */
		return NULL;
	}
	addr = tmp->start;
	DebugAA("find chunk 0x%p addr 0x%lx size "
		"0x%lx\n", tmp, addr, tmp->size);
	if (tmp->size > size && area_chunk == NULL) {
		raw_spin_unlock_irqrestore(&kmem_area->area_list_lock,
						irq_flags);
		area_chunk = kmem_cache_alloc(kmem_area_chunk_cachep, GFP_KERNEL);
		if (area_chunk == NULL) {
			return NULL;
		}
		goto repeat;
	} else if (tmp->size > size) {
		kmem_area_init_chunk(area_chunk, addr,size, flags);	
		tmp->start = addr + size;
		tmp->size -= size;
#ifdef	CONFIG_DEBUG_KMEM_AREA
		tmp->get_count = -3;
		tmp->get_pid = 0;
		tmp->get_ip = -1;
		tmp->get_comm[0] = '\0';
#endif	/* CONFIG_DEBUG_KMEM_AREA */
	} else {
		if (area_chunk) {
			chunk_to_free = area_chunk;
		}
		*p = tmp->next;
		if (tmp->next != NULL)
			tmp->next->prev = tmp->prev;
		area_chunk = tmp;
	}
	area_chunk->flags = flags | KMEM_AREA_ONLY_MAPPED;
#ifdef	CONFIG_DEBUG_KMEM_AREA
	area_chunk->get_count = 0;
	area_chunk->get_pid = task->pid;
	area_chunk->get_ip = (e2k_addr_t)__e2k_kernel_return_address(0);
	get_task_comm(area_chunk->get_comm, task);
#endif	/* CONFIG_DEBUG_KMEM_AREA */
	kmem_area_insert_busy_chunk(kmem_area, area_chunk);

#ifdef CONFIG_E2K_STACK_BEANCOUNTERS
	kmem_area->freebytes -= size;
#endif /* CONFIG_E2K_STACK_BEANCOUNTERS */
	raw_spin_unlock_irqrestore(&kmem_area->area_list_lock, irq_flags);
	if (chunk_to_free) {
		kmem_cache_free(kmem_area_chunk_cachep, chunk_to_free);
	}

#ifdef	CONFIG_DEBUG_KMEM_AREA
	kmem_area_check_busy_chunks(kmem_area);
#endif	/* CONFIG_DEBUG_KMEM_AREA */

	DebugAA("finished: kmem area 0x%p size 0x%lx "
		"chunk 0x%p addr 0x%lx flags 0x%lx\n",
		kmem_area, size, area_chunk,
		area_chunk->start, area_chunk->flags);

	return area_chunk;
}

static inline e2k_size_t
kmem_area_do_free_chunk(kmem_area_t *kmem_area, void *chunk, int flags)
{
	e2k_addr_t	addr = (e2k_addr_t)chunk;
	area_chunk_t	**p, *tmp;
	e2k_size_t	pages = 0;
	unsigned long	irq_flags;

	DebugAA("started: kmem area 0x%p chunk 0x%p\n", kmem_area, chunk);
	if (!addr)
		return pages;
	if ((PAGE_SIZE-1) & (unsigned long) addr) {
		pr_err("kmem_area_do_free_chunk() bad address (0x%lx)\n", addr);
		return pages;
	}

	raw_spin_lock_irqsave(&kmem_area->area_list_lock, irq_flags);

	for (p = &kmem_area->busy_list ; (tmp = *p) ; p = &tmp->next) {
		DebugPT("current chunk 0x%p\n",
			tmp);
		if (tmp->start == addr) {
#ifdef	CONFIG_DEBUG_KMEM_AREA
			DebugAA("chunk start "
				"0x%lx OK, flags 0x%lx %s : pid %ld IP 0x%lx\n",
				tmp->start, tmp->flags,
				tmp->get_comm, tmp->get_pid, tmp->get_ip);
#else
			DebugAA("chunk start "
				"0x%lx OK, flags 0x%lx\n",
				tmp->start, tmp->flags);
#endif	/* CONFIG_DEBUG_KMEM_AREA */
			*p = tmp->next;
			if (tmp->next != NULL)
				tmp->next->prev = tmp->prev;

			raw_spin_unlock_irqrestore(&kmem_area->area_list_lock,
							irq_flags);
			if (flags & KMEM_AREA_QUEUE) {
				kmem_area_insert_to_free_chunk(kmem_area,
								tmp);
			} else {
				if (tmp->flags & KMEM_AREA_ONLY_MAPPED)
					flags |= KMEM_AREA_UNMAP;
				pages += kmem_area_free_chunk_pages(
						tmp->start, tmp->size,
						flags);
				kmem_area_insert_free_chunk(kmem_area,
								tmp);
			}

#ifdef	CONFIG_DEBUG_KMEM_AREA
			kmem_area_check_busy_chunks(kmem_area);
#endif	/* CONFIG_DEBUG_KMEM_AREA */

			DebugAA("finished: "
				"chunk 0x%p\n", tmp);
			return pages;
		}
	}

	raw_spin_unlock_irqrestore(&kmem_area->area_list_lock, irq_flags);

	printk(KERN_ERR "Trying to kmem_area_do_free_chunk() nonexistent "
		"chunk of kernel vitual area (0x%lx)\n", addr);
#ifdef	CONFIG_DEBUG_KMEM_AREA
	kmem_area_print_all_chunks(kmem_area);
#endif	/* CONFIG_DEBUG_KMEM_AREA */
	return pages;
}

e2k_size_t
kmem_area_free_chunk(kmem_area_t *kmem_area, void *chunk, int flags)
{
	e2k_size_t pages = 0;
	e2k_size_t qfp = 0;
	e2k_size_t fp = 0;

	qfp = kmem_area_free_queued_chunks(kmem_area);
	fp = kmem_area_do_free_chunk(kmem_area, chunk, flags);
	pages = qfp + fp;

#ifdef CONFIG_E2K_STACK_BEANCOUNTERS
	if (pages > 0)
		wake_up(&kmem_area->queue);
#endif /* CONFIG_E2K_STACK_BEANCOUNTERS */
	return pages;
}

void
kmem_area_queue_chunk_to_free(kmem_area_t *kmem_area, void *chunk)
{
	kmem_area_do_free_chunk(kmem_area, chunk, KMEM_AREA_QUEUE);
}

area_chunk_t *
kmem_area_get_chunk(struct task_struct *task, kmem_area_t *kmem_area,
			e2k_size_t size)
{
	area_chunk_t	*area_chunk;

	DebugAA("started: kmem area 0x%p size 0x%lx\n", kmem_area, size);
	size = PAGE_ALIGN(size);
	if (!size || (size >> PAGE_SHIFT) > get_num_physpages()) {
		BUG();
		return NULL;
	}
	area_chunk = do_kmem_area_get_chunk(task, kmem_area, size,
					KMEM_AREA_CHUNK_ALLOC);
	if (area_chunk == NULL)
		return NULL;
	DebugAA("finished: start addr 0x%lx\n", area_chunk->start);
	return area_chunk;
}

static inline e2k_addr_t
kmem_area_do_alloc_chunk(struct task_struct *task, kmem_area_t *kmem_area,
	e2k_size_t size, struct page *guard_page, int gfp_mask, pgprot_t prot)
{
	area_chunk_t	*area_chunk;
	e2k_addr_t	addr;
	e2k_size_t	alloc_size;
	int		ret;
	int		cpu = task_cpu(task);

	DebugAA("started: CPU #%d kmem area 0x%p size 0x%lx\n",
		cpu, kmem_area, size);
	area_chunk = kmem_area_get_chunk(task, kmem_area, size);
	if (area_chunk == NULL)
		return 0;
	addr = area_chunk->start;
	alloc_size = size;
	if (guard_page != NULL)
		alloc_size -= PAGE_SIZE;
	DebugAA("will start kmem_area_alloc_chunk_pages() addr 0x%lx size 0x%lx\n",
		area_chunk->start, alloc_size);
	ret = kmem_area_alloc_chunk_pages(cpu_to_node(cpu), addr,
						alloc_size, gfp_mask, prot);
	area_chunk->flags &= ~KMEM_AREA_ONLY_MAPPED;
	area_chunk->flags |= KMEM_AREA_ALLOCATED;
	if (ret) {
		kmem_area_free_chunk(kmem_area, (void *)addr, 0);
		return 0;
	}
	DebugAA("finished: start addr 0x%lx\n",
		addr);
	return addr;
}

void *kmem_area_alloc(struct task_struct *task, kmem_area_t *kmem_area,
		      e2k_size_t size, struct page *guard_page,
		      int gfp_mask, pgprot_t prot)
{
	e2k_addr_t	addr;
	e2k_size_t	guard_size;
	int		ret;

	guard_size = (guard_page) ? PAGE_SIZE : 0;

	DebugAA("started: kmem area 0x%p size 0x%lx\n", kmem_area, size);
	addr = kmem_area_do_alloc_chunk(task, kmem_area, size + guard_size,
					guard_page, gfp_mask, prot);
	if (addr == 0)
		return NULL;

	if (guard_page) {
		ret = kmem_area_map_chunk_page(addr + size, guard_page, prot);
		if (ret)
			return NULL;
	}

	DebugAA("finished: start addr 0x%lx\n", addr);

	return (void *)addr;
}
