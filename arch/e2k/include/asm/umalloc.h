
#ifndef _E2K_UMALLOC_H_
#define _E2K_UMALLOC_H_


#include <linux/types.h>



typedef struct {
	u32 m_size;
	u32 m_alloced;
	u32 m_used;
	u32 m_real;
}	mallocstat_t;


		// Small chunk pools

struct  subpoolhdr;
typedef struct subpoolhdr	subpoolhdr_t;

struct  mem_moved_poolhdr;
typedef struct mem_moved_poolhdr mem_moved_poolhdr_t;

// we can't use include/list.h !!!
struct list_head_um{
	struct list_head_um *next, *prev;
};

// we can't use linux/rt_lock.h !!!
struct rt_mutex_um{
	u64    tmp[30];
};
typedef struct {
        struct list_head_um head;
        struct rt_mutex_um lock;
	u32		mainp;
	u32	        size;   // size of chunk 
}	umlc_pool_t;


#define MAX_CHUNKS 10
// index of big chunk
#define BIG_CHUNK_IND (MAX_CHUNKS-1)       


// heap descriptor
typedef struct {
	umlc_pool_t	pools[MAX_CHUNKS];
        atomic_t gc_lock;        // lock for garber collection 
	mem_moved_poolhdr_t	*mem_moved; // reference to mem_moved hdr 
	u32	allused;	// common size of valid arrays to the moment
	u32	allreal;	// sum real sizes of mallocs
	u32	allsize;	// common size occupied by heap
}	allpools_t;


extern void dump_malloc_cart(void);
extern e2k_addr_t sys_malloc(size_t size);
extern void sys_free(e2k_addr_t addr, size_t size);
extern void init_sem_malloc(allpools_t	*allpools);
extern int mem_set_empty_tagged_dw(void __user *ptr, s64 size, u64 dw);
struct task_struct;
extern void init_pool_malloc(struct task_struct *, struct task_struct *);

extern int clean_descriptors(void __user *list, unsigned long list_size);
extern int clean_single_descriptor(e2k_ptr_t descriptor);
#endif	/* _E2K_UMALLOC_H_ */

