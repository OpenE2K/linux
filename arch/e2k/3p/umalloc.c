
#define MALLOCSTANDALONE


#include <linux/types.h>
#include <linux/mman.h>
#include <linux/list.h>
#include <linux/vmalloc.h>
#include <linux/rwsem.h>
#include <linux/semaphore.h>

#include <asm/umalloc.h>
#include <asm/e2k_ptypes.h>
#include <asm/uaccess.h>
#include <asm/process.h>
#include <asm/mmu_context.h>


extern long sys_exit(int error_code);

#define MAX(a,b)                ((a) > (b) ? (a) : (b))
#define MAX_MUSED               16  

#undef  DEBUG_FAIL_RETURN
#ifdef  DEBUG_FAIL_RETURN
#define	FAIL_RETURN		BUG()
#else
#define	FAIL_RETURN		return
#endif 

#define DebugBUG                1
#define	DBUG		        if (DebugBUG) printk

#define DebugUM                 0
#define	DBUM		        if (DebugUM) printk
#define DEBUG_TRACE             0
#define Dbg_trace               if (DEBUG_TRACE) printk
#define DEBUG_GC_TRACE          0
#define Dbg_gc_trace            if (DEBUG_GC_TRACE) printk
#define DEBUG_GC_RES            0
#define Dbg_gc_res              if (DEBUG_GC_RES) printk
#define DEBUG_GC_REMAP          0
#define Dbg_gc_remap            if (DEBUG_GC_REMAP) printk
#define DEBUG_GC_ADDR           0
#define Dbg_gc_addr             if (DEBUG_GC_RES) printk
#define DEBUG_GC_MEM            0
#define Dbg_gc_mem              if (DEBUG_GC_MEM) printk
#define DEBUG_GC_TBL_RES        0
/*
 *
 *         malloc is used  pool 
 *
 *   pool:                    -------------------------
 *          listpoolhdr_t    |                   head  |  -> two order ref 
 *                           |                         |           to next pool     
 *                           |                   mainp | ---   ref to first 
 *                           |                         |   |   free  element
 *                           | (size of pool)    size  |   |   (subpoolhdr_t) 
 *                           | ------------------------|   |
 *                                .....                    |  
 *              subpoolhdr_t |  (size of chunk) size   | <-|
 *                           |                         |
 *                           |(size of chunk's element)|
 *                           |                mainsz   |
 *                           |       mused[MAX_MUSED]  | -----
 *                           |                mainp    |     |          chunk   
 *                           |                ptr      |-----|--------> -----
 *                                ......                     |          |   |
 *                                                           |          |   |
 *         address of first free element's chunk             |_________>|   |
 *                                                                      |   |
 *
 *                                                                     
 */ 
//   i can't include  include/list.h in umalloc.h file for recurrence
//   for this resion  we must use casting 
//       
#define get_list_head(x) ((struct list_head *)&(x)->head)

//   i can't include  linux/rt_lock.h in umalloc.h file for recurrence
//   for this resion  we must use casting 
//
#define get_rt_semaphore(x) ((struct semaphore *)&(x)->lock)

#define check_size_rt_semaphore()                                    \
      if (sizeof(struct semaphore) > sizeof(struct rt_mutex_um)) {\
          printk(" BAD sizeof(struct rt_mutex_um)=%ld < "        \
                 " sizeof(struct semaphore)=%ld  \n",            \
                  sizeof(struct rt_mutex_um),                    \
                  sizeof(struct semaphore));                     \
          BUG();                                                 \
      }        
struct listpoolhdr  {
        struct list_head head;
        u32     mainp;  // index for free mused 
        u32     size;   // size of listpoolhdr
};
typedef struct listpoolhdr listpoolhdr_t;
		// Small chunk pools

struct subpoolhdr  {
	u32	size;	// size of chunk 
	u32	mainsz;	// size of chunk's element
	u32	mused[MAX_MUSED];	// bit mask of valid main chunks
        u32     mainp;  // index for free mused 
        void    *ptr;   // ptr to chunk 
};

struct mem_moved_poolhdr  {
	u32	size;	     // size of chunk 
        u32     mainp;       // index for free element 
        u32     new_mainp;   // index for new added free element
};


//#define	MAX_PIND		8

/*
 * This define is from kernel/traps.c
 */ 
#define S_S(signo) do {	                                \
	siginfo_t info;					\
	info.si_signo = signo;				\
	info.si_errno = 0;				\
	info.si_trapno = TRAP_BRKPT;		        \
	info.si_code  = 0;				\
	force_sig_info(signo, &info, current);		\
} while(0);

#define BIT_INT                   32
#define LAST_BIT                  (BIT_INT-1)
#define WORD(x)                   ((x) >> 5)        /*((x)/BIT_INT) */
#define BIT_NR(x)                    ((x) & 0x1f)      /*((x)%BIT_INT) */
   
#define FLAGS			  (PROT_READ | PROT_WRITE)
#define ALL_FF                    0xffffffff
#define SHIFT(x)                  (BIT_INT - 1 - BIT_NR(x))
#define FIRST_SUBPOOL_IND         MAX(sizeof(subpoolhdr_t),sizeof(listpoolhdr_t))

#define	MEM_MVD_SIZE	          PAGE_SIZE
#define	FIRST_MVD_IND             MAX(sizeof(mem_moved_t),sizeof(mem_moved_poolhdr_t))

struct mem_moved{
    u64	beg_addr;       // used address  
    u64	end_addr;       // end of used address  
    u64	new_addr;       // new address  
};

typedef struct mem_moved mem_moved_t;

struct one_element{
    u64	addr;	          
    u32	size;	          
    u32	ind;	          
    subpoolhdr_t *subpool;
}one_element_t;    


static void add_new_element(u64 new_addr, u64 old_addr, u64 old_len);

   
#define get_first_subpool(x) (subpoolhdr_t *)((char*)(x) + FIRST_SUBPOOL_IND)
/* calculate last posible correct address  for subpoool  */   
#define get_last_subpool(x)  (((x->mainp + sizeof(subpoolhdr_t)) < x->size)?   \
             ((subpoolhdr_t *)((char*)(x) + x->mainp) )                        \
             :( (subpoolhdr_t *)((char*)(x) + x->mainp - sizeof(subpoolhdr_t))))
             

#define subpool_list_for_each_prev(subpool,hdr)                                \
           for (subpool = get_last_subpool(hdr);                               \
                subpool >=  get_first_subpool(hdr);                            \
                     subpool--) 

#define subpool_list_for_each(subpool,hdr)                                     \
           for (subpool = get_first_subpool(hdr);                              \
                subpool <=  get_last_subpool(hdr);                             \
                     subpool++) 

#define deleted_subpool(subpool)   subpool->ptr == NULL                 
   

#define get_first_mem_moved(x) (mem_moved_t *)((char*)(x) + FIRST_MVD_IND)
           
/* calculate last posible correct address  for mem_moved  */
#define get_last_mem_moved(x)                                                  \
         ((mem_moved_t *)((char*)(x) + x->mainp - sizeof(mem_moved_t)))      
           
static int garbage_collection(void);

// ????
#define MAX_PROC_PTE  20
//  may be ~ 1024 ?
#define MAX_USED_MEM  128
static int is_full_mem(void)
{    
        u64   nr_ptes    =  atomic_long_read(&current->mm->nr_ptes) * PAGE_SIZE;
        u64   mem        =  current->mm->context.umpools.allsize;

        if (nr_ptes * MAX_PROC_PTE > mem &&
            current->mm->context.mmap_position > MAX_USED_MEM*TASK32_SIZE) {
               Dbg_gc_res(" nr_ptes =%lx used memory =%lx \n", 
                          nr_ptes, mem);    
               return 1;
        } else {
               return 0;
        }    
         
}    
static e2k_addr_t
ALLOC_MEM(long sz)
{
	e2k_addr_t map_addr;
        int once=0;
again:    
	map_addr =(e2k_addr_t) vm_mmap(NULL, 0L, sz,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS,0L);
        if (once) {
               Dbg_gc_res(" once   map_addr=%lx\n",(u64)map_addr);                 
        }    
	if (map_addr & ~PAGE_MASK) {
            map_addr = 0;
        }    
	DBUM("ALLOC_MEM = 0x%lx : 0x%lx\n", map_addr, sz);
        if ((is_full_mem() || map_addr == 0) && once == 0) {
	        struct task_struct *tsk = current;
                if (xchg(&current->mm->context.umpools.gc_lock.counter, 1)) {
                    while(atomic_read(&current->mm->context.umpools.gc_lock)){
	                    tsk->state = TASK_INTERRUPTIBLE;		
 			    schedule();
                        }    
                    
                } else if (garbage_collection()) {
                        atomic_set(&current->mm->context.umpools.gc_lock,0);
			return map_addr;
                }
                atomic_set(&current->mm->context.umpools.gc_lock,0);
//                sz = 1; //  open for debugging in LMS    
                once = 1;
                goto again;
        }    
	return map_addr;
}


static void FREE_MEM(e2k_addr_t a,  size_t sz)
{
	struct mm_struct *mm = current->mm;

	DBUM("FREE_MEM = 0x%lx : 0x%lx\n", a, sz);
	down_write(&mm->mmap_sem);
	(void) do_munmap(mm, a, sz);
	up_write(&mm->mmap_sem);
}


static int
get_pind(int size, u32 *chsz)
{    
	int pind;
	if (size <= 8) {
		*chsz = 8;
		pind = 0;
	} else if (size <= 16) {
		*chsz = 16;
		pind = 1;
	} else if (size <= 32) {
		*chsz = 32;
		pind = 2;
	} else if (size <= 64) {
		*chsz = 64;
		pind = 3;
	} else if (size <= 128) {
		*chsz = 128;
		pind = 4;
	} else if (size <= 256) {
		*chsz = 256;
		pind = 5;
	} else if (size <= 512) {
		*chsz = 512;
		pind = 6;
	} else if (size <= 1024) {
		*chsz = 1024;
		pind = 7;
	} else if (size <= 2048) {
		*chsz = 2048;
		pind = 8;
	} else { // big chunk 
		*chsz = size;
		pind = 9;
	}
        return pind;
}



static int subpool_is_empty(subpoolhdr_t *sbp)
{
	return (sbp->mused[0] | sbp->mused[1] | sbp->mused[2] |
		sbp->mused[3]  | sbp->mused[4] | sbp->mused[5] |
		sbp->mused[6]  | sbp->mused[7] | sbp->mused[8]  |
		sbp->mused[9]  | sbp->mused[10] | sbp->mused[11]  |
		sbp->mused[12] | sbp->mused[13] | sbp->mused[14]  |
		sbp->mused[15]) == 0;
}


static void
set_used(subpoolhdr_t *sbp, u32 chsz)
{
	int chn = sbp->mainp/sbp->mainsz;
	int i = WORD(chn);
	u32 m = 1 << (SHIFT(chn));

        Dbg_trace(" set_used sbp =%p (%d,%d) sbp->mainp=%x chsz=%x sbp->ptr =%p\n",
                  sbp, i, SHIFT(chn), sbp->mainp, chsz, sbp->ptr);    
	if (i >= MAX_MUSED) {
		DBUG("Too big chunk number %d; sz = %d; \n",
		       i, chsz);
		dump_malloc_cart();
		sys_exit(7009);
	}	
	if (sbp->mused[i] & m) {
		DBUG("Chunk already used. size %u; mused[%d] = 0x%08x   - m = 0x%08x\n"
				"   chn = %d\n",
		       chsz, i, sbp->mused[i], m, chn);
		dump_malloc_cart();
		sys_exit (7009);
	}
	sbp->mused[i] |= m;
        sbp->mainp += chsz;
        
        Dbg_trace(" set_used mused =%08x \n", sbp->mused[i]);
}


static void clear_used(subpoolhdr_t *sbp, int chn)
{
	int i = WORD(chn);
	u32 m = 1 <<(SHIFT(chn));

        Dbg_trace(" clear_used sbp =%p (%d,%d) sbp->mainp=%x bit=%x\n",
                  sbp, i, SHIFT(chn), sbp->mainp, chn);    
	if (i >= MAX_MUSED) {
		DBUG("Clear: Too big chunk number %d; sz = %d in %d;\n",
		       chn, i, sbp->mainsz);
		dump_malloc_cart();
		sys_exit(7009);
	}
	if (!(sbp->mused[i] & m)) {	
		DBUG("Chunk not used. size %u; mused[%d] = 0x%08x   - m = 0x%08x\n",
		       sbp->mainsz, i, sbp->mused[i], m);
//		dump_malloc_cart();
//		sys_exit (7009);
                S_S(SIGABRT);
	}	
	sbp->mused[i] &= ~m;
        Dbg_trace(" clear_used =%08x \n", sbp->mused[i]);
}	

static  void  *
create_new_subpool(u32	chsz, allpools_t *allpools, u32 *size)
{
	u32	sz;
	void	*new;
	
	if (chsz <= 16) {
		sz = 1;
	} else if (chsz <= 128) {
		sz = 2;
	} else if (chsz <= 2048) {
		sz = 4;
	} else {
          // BIG chunk
                sz = chsz;
        } 
        if (chsz <= 2048) {          
		sz *= PAGE_SIZE;
        }

	new = (void  *)ALLOC_MEM(sz);
	if (new == NULL) {
		DBUG("No memory for subpool\n");
		return NULL;
	}
        *size = sz; 
//	memset(new, 0, sz); //!!!! delete for LMS
	allpools->allsize += sz;
	DBUM("create_new_subpool(%d) = 0x%p\n", chsz, new);
	return new;
}
	
	
static void free_subpool(subpoolhdr_t *a, allpools_t *allpools) {
        Dbg_trace("free_subpool a->ptr =%p a->size=%x \n", a->ptr, a->size);

	allpools->allsize -= a->size;
	FREE_MEM((e2k_addr_t)a->ptr, a->size);
        a->ptr = 0;
}

e2k_addr_t sys_malloc(size_t size)
{
	allpools_t	*allpools = &current->mm->context.umpools;
	e2k_addr_t	addr = 0;
	u32		chsz;
	int		pind;
	umlc_pool_t	*mypool;
	e2k_addr_t	mem;
        struct list_head *head;
        subpoolhdr_t     *curr_subpool = NULL;
        struct semaphore *lock;
        
        pind = get_pind(size, &chsz);
	DBUM("sys_malloc size=%lx pind=%d cz=%x\n", size, pind, chsz);
                //    small chunks    
    	mypool = &allpools->pools[pind];
//        check_size_rt_semaphore();
        lock = get_rt_semaphore(mypool);
        down(lock);
	head = get_list_head(mypool);
	DBUM("sys_malloc mainp=%x main_size=%x\n", mypool->mainp, mypool->size);
        if (head->next == NULL) {
            INIT_LIST_HEAD(head);
        }    

	if (list_empty(head) || 
            (mypool->mainp + sizeof(subpoolhdr_t)) > mypool->size) {
		mem = ALLOC_MEM(PAGE_SIZE);
		if (mem == 0) {
			goto out;
		}
                // may be called garbage_collection 
		head = get_list_head(mypool);
                memset((char*)mem, 0, PAGE_SIZE);
        	mypool->mainp = FIRST_SUBPOOL_IND;
                mypool->size  = PAGE_SIZE;
                ((listpoolhdr_t*)mem)->mainp = FIRST_SUBPOOL_IND;  
                ((listpoolhdr_t*)mem)->size = PAGE_SIZE;  
                list_add((struct list_head *)mem, head);
      
	}
        curr_subpool = (subpoolhdr_t*)((char*)head->next + mypool->mainp);
	if (!curr_subpool->ptr) {
                u32  size; 
                void *ptr; 
		// no room in subpool.
                // may be called garbage_collection 
                ptr = create_new_subpool(chsz, allpools ,&size);
		head = get_list_head(mypool);
                curr_subpool = (subpoolhdr_t*)((char*)head->next + mypool->mainp);

                curr_subpool->ptr    = ptr;
                curr_subpool->mainsz = chsz;
                curr_subpool->size   = size;
                curr_subpool->mainp  = 0;
	}
	// There is a room for a chunk
	addr =(e2k_addr_t)curr_subpool->mainp +
                              (e2k_addr_t)curr_subpool->ptr;
	set_used(curr_subpool, chsz);
        if (curr_subpool->mainp >= curr_subpool->size) {
                mypool->mainp += sizeof(subpoolhdr_t);
                ((listpoolhdr_t*)head->next)->mainp += sizeof(subpoolhdr_t);
        }    
 	allpools->allused += chsz;
	allpools->allreal += size;
out:        
        up(lock);
        DBUM("sys_malloc addr =%lx curr_subpool =%p ptr=%p\n",
             addr, curr_subpool, curr_subpool ? curr_subpool->ptr : NULL);
	return addr;
}

void sys_free(e2k_addr_t a, size_t sz)
{
	allpools_t	*allpools = &current->mm->context.umpools;
	u32	        chsz;
	int	        pind;
	umlc_pool_t	*mypool;
	subpoolhdr_t	*subpool;
	e2k_addr_t	addr;
        struct list_head *ln;
        struct list_head *head;
        listpoolhdr_t    *hdr;
        struct semaphore *lock;

	if (a == 0) {
		return;
	}

	// At first assume size is a real chunk size
        pind = get_pind(sz, &chsz);
        Dbg_trace(" sys_free a=%lx sz=%lx \n", a, sz);
//        check_size_rt_semaphore();
        while (pind  <  MAX_CHUNKS) {
	    mypool = &allpools->pools[pind];
            lock = get_rt_semaphore(mypool);
            down(lock);
            head = get_list_head(mypool);
            if (head->next == NULL) {
                pind++;
                up(lock);
                continue;
            }    
	    list_for_each_prev(ln, head) {
		hdr = list_entry(ln, listpoolhdr_t, head);

                Dbg_trace(" sys_free hdr =%p   pind =%d \n", hdr, pind);
                subpool_list_for_each_prev(subpool, hdr) {
                        if (deleted_subpool(subpool)) {
				continue;
                        }    
                        addr = (e2k_addr_t)subpool->ptr;

			if (a < addr || a  >= (addr + subpool->size)) {
				continue;
			}
                        
			if ((a + sz) > (addr+subpool->size)) {
				DBUG("Bad free desk pind =%d (0x%lx, 0x%lx) for (0x%lx, 0x%x) "
                                     " subpool =%p\n",
				       pind, a, sz, addr, subpool->size, subpool);
				dump_malloc_cart();
				// kill process
                                up(lock);
				FAIL_RETURN;
			}
                        /* 
                         * glibc needs full coresponding of address 
                         */ 
                        if ((a - addr) % subpool->mainsz != 0) {
                            up(lock);
                            S_S(SIGABRT);
                            return;
                        }    
			clear_used(subpool, (a - addr) / subpool->mainsz);
			allpools->allused -= subpool->mainsz;
			if (subpool_is_empty(subpool) && subpool->mainp == subpool->size) {
				// subpool is empty. Return it
				free_subpool(subpool, allpools);
			}
	
			DBUM("Free big: 0x%lx -  0x%x\n", addr, subpool->size);
                        up(lock);
			return;
		}
            }
            // go to biger chunk 
            pind++;
            up(lock);
        }    
	DBUG("Bad!!! free desk (0x%lx, 0x%lx) pind =%d curr pind =%d \n ",
             a, sz, get_pind(sz, &chsz), pind);
}


int get_malloc_stat(mallocstat_t *st)
{
	allpools_t	*allpools = &current->mm->context.umpools;
	st->m_used = allpools->allused;
	st->m_real = allpools->allreal;
	st->m_size = allpools->allsize;
	return 0;
}

typedef struct {
	void		*addr;
	size_t		size;
} array_t;

void dump_malloc_cart(void)
{
	allpools_t	*allpools = &current->mm->context.umpools;	
	umlc_pool_t	*mypool;
	subpoolhdr_t	*subpool;
	int		i;	
        struct list_head *head;
        struct list_head *ln;
        listpoolhdr_t    *hdr;

	printk("\n\t\tALLREAL = %u\n", allpools->allreal);
	printk("\t\tUSED      = %u\n", allpools->allused);
	printk("\t\tALLSIZE = %u\n", allpools->allsize);
	
	for (i = 0; i < MAX_CHUNKS; i++) {
		mypool = &allpools->pools[i];
                head = get_list_head(mypool); 
                if (head->next == NULL) {
                    continue;
                }    
		printk("\n\tChunk = %u;     mainp = %u\n", i , mypool->mainp);
	        list_for_each_prev(ln, head) {
		    hdr = list_entry(ln, listpoolhdr_t, head);
                    subpool_list_for_each(subpool, hdr) {
                        if (deleted_subpool(subpool)) {
			        DBUM("DELETED subpool = 0x%lx \n",
                                       (u64)subpool);
				continue;
                        }    
		        printk("subpool = 0x%lx  STARTMP = 0x%x ptr=%p\n",
                            (u64)subpool, (int)subpool->mainsz, subpool->ptr);
                        printk("     %08x%08x%08x%08x\n",
                            subpool->mused[0], subpool->mused[1],
                            subpool->mused[2], subpool->mused[3]);
                        printk("     %08x%08x%08x%08x\n",
                            subpool->mused[4], subpool->mused[5],
                            subpool->mused[6], subpool->mused[7]);
                        printk("     %08x%08x%08x%08x\n",
                            subpool->mused[8], subpool->mused[9],
                            subpool->mused[10], subpool->mused[11]);
                        printk("     %08x%08x%08x%08x\n",
                            subpool->mused[12], subpool->mused[13],
                            subpool->mused[14], subpool->mused[15]);
                    }    
             }
        }
        return;
}

static int
is_filled_chunk(subpoolhdr_t *subpool)
{
        int size, sz, limit;
        u32 *ptr;
        unsigned int tmp, i, j, count=0;
        
        Dbg_gc_trace("    is_filled_chunk subpool =%p \n", subpool);
        size = subpool->size;
        sz = subpool->mainsz;
        ptr = &subpool->mused[0];
        
        limit = subpool->mainp/sz;
	for (i = 0; i < WORD(limit+LAST_BIT); i++) {
        	tmp = ptr[i];
                if (tmp) {
        		for (j = 0; j < BIT_INT ; j++) {
        	            if ((tmp >> j) & 0x1) {
        	                count++;
         	            }
        	        } 
                }        
        }
        /* experemental criterium  > 1/2 full_size */
        Dbg_gc_trace(" is_filled_chunk sz=%d  sz*count=%d size=%d limit=%d"
                  " WORD(limit+LAST_BIT) =%d\n",
                 sz, sz*count, size, limit, WORD(limit+LAST_BIT));
        if (sz*count*2 > size) {     
                return 1;
        }
        return 0;        
}

static void 
print_all_moved_memory(int check)
{
	allpools_t	*allpools = &current->mm->context.umpools;
	mem_moved_poolhdr_t	*hdr;
        mem_moved_t     *mem_moved, *limit, *prev_moved =NULL; 
        mem_moved_t     *old_limit; 
        
        Dbg_gc_trace("print_all_moved_memory \n");
        
        hdr = allpools->mem_moved; 
        if (hdr == NULL) {
            return;
        }    
        printk(" mainp = %d new_mainp =%d FIRST_MVD_IND =%ld count=%ld \n",
               hdr->mainp, hdr->new_mainp, FIRST_MVD_IND,
               (hdr->new_mainp-FIRST_MVD_IND)/sizeof(mem_moved_t));  
        limit = (mem_moved_t *)((char*)(hdr) + hdr->new_mainp - sizeof(mem_moved_t));
        old_limit = (mem_moved_t *)((char*)(hdr) + hdr->mainp - sizeof(mem_moved_t));
        for(mem_moved = get_first_mem_moved(hdr);
            mem_moved <= limit; mem_moved++) {
                printk("(mem_moved=%p) new_addr=%lx  beg_addr =%lx  end_addr =%lx \n",
                    mem_moved, mem_moved->new_addr, mem_moved->beg_addr,
                    mem_moved->end_addr); 
                if (mem_moved == old_limit) {
                    printk("=======================mainp=============\n");
                }    
                if (check && mem_moved->end_addr <= mem_moved->beg_addr) {
                    printk(" ERROR !!! mem_moved->end_addr"
                          " <= mem_moved->beg_addr \n");
                }
                if (check && prev_moved != NULL &&
                    prev_moved->end_addr > mem_moved->beg_addr) {
                    printk(" ERROR !!! prev_moved->end_addr "
                           "<= mem_moved->beg_addr \n");
                } 
                prev_moved = mem_moved;   
        } 
} 


static void 
dump_array(void)
{
        DBUG("     dump_array \n");
	print_all_moved_memory(1);
        dump_malloc_cart();        
}

static int
is_full_pool(subpoolhdr_t *subpool)
{
        int limit, sz;
        int *ptr;
	int    i;	
        unsigned int tmp;
        
        Dbg_gc_trace(" is_full_pool subpool =%p \n", subpool);
        sz = subpool->mainsz;
        ptr = (int *) &subpool->mused[0];
        limit = (subpool->mainp)/sz;
	for (i = 0; i < WORD(limit+LAST_BIT) -1; i++) {
        	tmp = ptr[WORD(i)];            
                if (tmp != ALL_FF) {
                    return 0;
                }    
        }
        if (BIT_NR(limit)) {
                tmp = ptr[WORD(limit+LAST_BIT)-1];            
                if ((tmp >> (SHIFT(BIT_NR(limit))+1)) !=
                    (ALL_FF >> (SHIFT(BIT_NR(limit))+1) )) {
                    return 0;
                }
        }
        return 1;
}

static int
is_empty_pool(subpoolhdr_t *subpool)
{
        int limit, sz;
        unsigned int *ptr;
        unsigned int tmp;
        int i;
       
        Dbg_gc_trace(" is_empty_pool subpool =%p \n", subpool);
        sz = subpool->mainsz;
        ptr = &subpool->mused[0];
        limit = (subpool->mainp)/sz;
	for (i = 0; i < WORD(limit+LAST_BIT); i++) {
        	tmp = ptr[WORD(i)];            
        	if (tmp != 0) {
                    return 0;
                }    
        }
        return 1;
}

static void 
find_element(subpoolhdr_t *subpool, struct one_element* to_st, int maska)
{
        int i,j;
	unsigned int tmp;
        int *ptr;
        int mainsz;
        int limit, sz;
        u64 addr;
    
        Dbg_gc_trace("  find_element subpool =%p maska =%d  size=%d mainsz=%d\n",
                     subpool, maska, subpool->size, subpool->mainsz);
        mainsz = subpool->mainsz;

        to_st->subpool = NULL;
        sz = subpool->mainsz;
        ptr = (int *) &subpool->mused[0];
        limit = (subpool->mainp)/sz; 
        addr = (u64)subpool->ptr;  

 	for (i = 0; i < WORD(limit+LAST_BIT)-1 ; i++) {
        	tmp = ptr[i];
		for (j = 0; j < BIT_INT; j++) {
                        if (((tmp >> (LAST_BIT-j)) & 0x1) == maska) {
                                to_st->ind = (i * BIT_INT) + j;
                                to_st->subpool = subpool;
                                to_st->addr = addr + ((i * BIT_INT) + j)*sz;
                                to_st->size = sz;
                                Dbg_trace(" find_element ind =%d addr =%lx"
                                         " limit=%d" 
                                          " tmp=%x (%d,%d) \n",
                                          to_st->ind, to_st->addr, limit,
                                          tmp, i,j);

                                return;    
                        }
                }    
        }
        /* last word */
        tmp = ptr[WORD(limit+LAST_BIT)-1];
	for (j = 0; j < BIT_NR(limit); j++) {
                  if (((tmp >> (LAST_BIT-j)) & 0x1) == maska) {
                            to_st->ind = ((WORD(limit+LAST_BIT)-1)*BIT_INT) +j;
                            to_st->subpool = subpool;
                            to_st->addr = addr +
                                 (((WORD(limit+LAST_BIT)-1)*BIT_INT)+j)*sz;
                            to_st->size = sz;
                            Dbg_trace("find_element ind =%d addr =%lx limit=%d" 
                                        " tmp=%x (%d,%d) \n",
                                          to_st->ind, to_st->addr, limit,
                                          tmp, WORD(limit+LAST_BIT),j);
                            return;    
                  }
        }    
        printk(" ERROR subpool =%p maska =%d limit=%d tmp=%x is_empty_pool =%d"
               "lastword=%x    ptr[0]=%x\n",
               subpool, maska, limit, tmp, is_empty_pool(subpool),
               ptr[0],  ptr[WORD(limit+LAST_BIT)-1]);        
        dump_malloc_cart();
}

static void 
mark_used_element(struct one_element* to_st)
{    

        int ind = to_st->ind;
	int *pnt;
	int tmp;
        int m;
        subpoolhdr_t * subpool = to_st->subpool;

        Dbg_gc_trace(" mark_used_element subpool=%p ind =%d \n",
                    subpool, ind); 
        if (subpool == NULL) {
                DBUG(" mark_used_element subpool==NULL\n");
        	dump_array();       
        }
        pnt = (int *) &subpool->mused[0];    
	tmp =  pnt[WORD(ind)];
        m = 1 << SHIFT(ind);
        if (tmp & m) {
                DBUG(" mark_used_element tmp=%x m=%x  ind=%x\n",tmp, m, ind);
        	dump_array();       
        }
        pnt[WORD(ind)] = (tmp | m);   
}



static void 
mark_free_element(struct one_element* to_st)
{       
        subpoolhdr_t * subpool = to_st->subpool;
        Dbg_gc_trace(" mark_free_element subpool=%p ind =%d \n",
                    subpool, to_st->ind); 
        if (subpool == NULL) {
                DBUG(" mark_free_element subpool==NULL\n");
        	dump_array();       
        }    
	clear_used(subpool, to_st->ind);
}

static void 
get_free_element(subpoolhdr_t * subpool,struct one_element* to_st)
{       
    
        Dbg_gc_trace(" get_free_element  subpool=%p \n",
                    subpool); 
	find_element(subpool, to_st, 0);         
}

static void 
get_used_element(subpoolhdr_t *subpool,struct one_element* to_st)
{
        Dbg_gc_trace(" get_used_element subpool=%p \n",
                    subpool); 
        find_element(subpool, to_st, 1);
}

/*  
 *  size - number of dword
 */  
static void 
memcpy_with_tags(u64* to, u64* from, u64 size)
{
        long tagged_dword;
        int  sz= size;
        Dbg_gc_trace(" memcpy_with_tags  to=%p from =%p  size =%lx\n",
                      to, from, size);
        for (; 0< sz; to++,from++, sz--) {    
                E2K_LOAD_TAGGED_DWORD(from, to);
                if (0 && DEBUG_GC_RES && E2K_LOAD_TAGD(from) != E2K_NUMERIC_ETAG) {
                    printk("!!! memcpy_with_tags to=%p from=%p tag=%d tagged_dword =%lx\n",
                           to, from, E2K_LOAD_TAGD(from), tagged_dword);
                  
             }
        }        
}    

static void 
cpy_one_element(struct one_element  *to,
                struct one_element  *from)
{
        
        Dbg_gc_trace(" cpy_one_element  to=%lx from =%lx  to->size =%x"
                 "  from->size =%x\n",
                  to->addr, from->addr, to->size, from->size);
        memcpy_with_tags((u64*)to->addr,(u64*)from->addr, to->size/8);
        add_new_element(to->addr, from->addr, to->size);
} 

static void 
cpy_element(subpoolhdr_t *to, subpoolhdr_t *from)
{       
        struct one_element  to_st, from_st; 
    
        Dbg_gc_trace(" cpy_element to =%p from =%p \n", to, from);
        get_free_element(to, &to_st);
        get_used_element(from, &from_st);
        mark_used_element(&to_st);
        mark_free_element(&from_st);
        cpy_one_element(&to_st, &from_st); 
}

static int 
get_size_of_element(subpoolhdr_t *from)
{
        Dbg_gc_trace("  get_size_of_element from =%d \n", from->mainsz);
        return from->mainsz;
}

static int 
cpy(subpoolhdr_t *to, subpoolhdr_t *from)
{
        Dbg_gc_trace("  cpy to =%p from =%p \n", to, from);
        if (get_size_of_element(to) == get_size_of_element(from)) {
                while (!is_full_pool(to) && !is_empty_pool(from)){
                       cpy_element(to, from);
                }    
        }
       
        return is_empty_pool(from);
}

static mem_moved_poolhdr_t * 
get_my_chunk(mem_moved_poolhdr_t *old_hdr)
{
	mem_moved_poolhdr_t	*hdr;
	long 	sz;
        
        Dbg_gc_trace("  get_my_chunk  \n");
        
        if (old_hdr == NULL) {
                sz = MEM_MVD_SIZE;
                hdr = (mem_moved_poolhdr_t *)vmalloc(sz);
                if (hdr == NULL) { 
                    DBUG(" NO MEM for get_my_chunk \n");
                    return NULL;
                }    
        	hdr->mainp = FIRST_MVD_IND;
        } else {
               sz = old_hdr->size + MEM_MVD_SIZE;
               hdr = (mem_moved_poolhdr_t *)vmalloc(sz);
               if (hdr == NULL) { 
                    DBUG(" NO MEM for get_my_chunk \n");
                    return NULL;
               }
               memcpy(hdr, old_hdr, old_hdr->size);
               vfree(old_hdr);    
        }    
	hdr->size  = sz;
        
        return  hdr;  
}

static  void
add_new_element(u64 new_addr, u64 old_addr, u64 old_len)
{
	mem_moved_poolhdr_t	*hdr, *tmp;
        mem_moved_t *curr_moved_mem;
        
        Dbg_gc_trace("add_new_element new_addr =%lx old_addr =%lx"
                  " old_len =%lx\n", new_addr, old_addr, old_len);
        
        
        hdr = current->mm->context.umpools.mem_moved; 
        
        Dbg_gc_trace("add_new_element hdr=%p hdr->mainp=%x  hdr->size=%x\n",
                      hdr, hdr->mainp, hdr->size);
        
           
        /* may be correct previous element */
        curr_moved_mem = (mem_moved_t*)((char*)hdr + hdr->mainp);
        if (hdr->mainp != FIRST_MVD_IND &&
            curr_moved_mem->end_addr == new_addr) {
            curr_moved_mem->end_addr += old_len;
            return;
        }    
        if (hdr->mainp + sizeof(mem_moved_t) > hdr->size) {
            tmp = get_my_chunk(hdr);
            if (tmp == NULL) {
                printk(" No memory !! \n"); 
                dump_array();
            }    
            current->mm->context.umpools.mem_moved = tmp;
            hdr = tmp;
            curr_moved_mem = (mem_moved_t*)((char*)hdr + hdr->mainp);
        }
        curr_moved_mem->new_addr = new_addr;
        curr_moved_mem->beg_addr = old_addr;
        curr_moved_mem->end_addr = old_addr + old_len;
        hdr->mainp += (sizeof(mem_moved_t));
        Dbg_gc_trace("add_new_element hdr=%p hdr->mainp=%x "
                  "new_addr =%lx beg_addr =%lx end_addr =%lx\n",
                   hdr, hdr->mainp, new_addr, old_addr,
                   curr_moved_mem->end_addr);
        
        
}

static void
my_free_subpool(subpoolhdr_t *subpool)
{    
	allpools_t	*allpools = &current->mm->context.umpools;
	int pind ;
        u32 cz;
        
        Dbg_gc_trace(" my_free_subpool subpool=%p \n", subpool);
	if (subpool_is_empty(subpool)) {
                pind = get_pind(subpool->size, &cz);
	        Dbg_gc_res("subpool_is_empty subpool=%p pind=%d subpool->ptr=%p subpool->size=%x\n",
                          subpool, pind, subpool->ptr, subpool->size);
		free_subpool(subpool, allpools);
	}
}

struct head_info{
	struct list_head *last_head;
	struct list_head *head;
        int    mainp;         // address of subpool
        int    size;   
};

typedef struct head_info head_info_t;

static subpoolhdr_t* 
get_next_subpool(head_info_t *head_info)
{
	subpoolhdr_t	*subpool;
	listpoolhdr_t	*hdr;

        Dbg_gc_trace(" get_next_subpool head=%p mainp=%d \n",
                 head_info->head,  head_info->mainp);
        
 	hdr = list_entry(head_info->head, listpoolhdr_t, head);
        if (hdr->mainp >=  hdr->size) {
            if (head_info->head == head_info->last_head) {
                return NULL;
            }    
            head_info->head  = head_info->head->next;
            head_info->mainp = FIRST_SUBPOOL_IND;
        }
 	hdr = list_entry(head_info->head, listpoolhdr_t, head);
        subpool = (subpoolhdr_t*)((char*) hdr + head_info->mainp);
        head_info->mainp +=sizeof(subpoolhdr_t);
        if (subpool->ptr == NULL) {
            return get_next_subpool(head_info);
        }    
        return subpool;
}    
/* 
 *  result = 1 if we copy all posible elements
 */  
static int 
copy_subpools(head_info_t *head_info, subpoolhdr_t**last_subpool,
              subpoolhdr_t *subpool)
{
	subpoolhdr_t	*last = *last_subpool;

        Dbg_gc_trace(" copy_subpools  last =%p subpool=%p\n", last, subpool);
        if (last == NULL) {
             last = get_next_subpool(head_info);
             *last_subpool = last;  
        }    

        while (!is_empty_pool(subpool) && last && last != subpool) {
            if (!cpy(last, subpool)) {
                 last = get_next_subpool(head_info);
                 *last_subpool = last;
            } else {
                 my_free_subpool(subpool);
                 return 0;
            }
        }
        if (last != subpool) {
            return 0; 
        }
        return 1;    
}

static void
check_chunks(void)
{    

        Dbg_gc_trace(" check_chunks   \n");
        if (DEBUG_GC_RES) {
                dump_malloc_cart();
        } 
}

/*
 *  To create  the first part of mem_moved table
 *  (before new_mainp pointer)
 *  The lines are created by copy from not full chunk to 
 *   chunks with little virtual address
 */

static void 
pack_and_cpy(allpools_t	*allpools)
{
	umlc_pool_t	*mypool;
	subpoolhdr_t	*subpool;
	subpoolhdr_t	*last_subpool = NULL;    
        int i;
	struct list_head *ln;
	listpoolhdr_t	*hdr;
	struct list_head *head;
        head_info_t head_info;

        Dbg_gc_trace(" pack_and_cpy \n");
        check_chunks();
        // BIG chunck can't be compressed 
 	for (i = 0; i < MAX_CHUNKS -1; i++) {
		mypool = &allpools->pools[i];
                head = get_list_head(mypool);
                if (head->next== NULL) {
                      // not initialized list 
                        continue;
                }    
                head_info.last_head = head->prev; // last element 
                head_info.head = head->next;      // first element 
                head_info.mainp = FIRST_SUBPOOL_IND;
                head_info.size  = mypool->size;
		Dbg_gc_trace("\n\tChunk = %d   mainp = %u\n", i, mypool->mainp);
	        list_for_each_prev(ln, head) {
 			hdr = list_entry(ln, listpoolhdr_t, head);
                        subpool_list_for_each_prev(subpool, hdr) {
 	                        if (deleted_subpool(subpool)) {
 					continue;
 	                        }    
 	                        if (is_filled_chunk(subpool)) {
  	                               continue;
 	                        }
 	                        if (copy_subpools(&head_info, &last_subpool, subpool)) {
                                       goto next_chunk;
                                }    
                        }        
                }
next_chunk:
		/* Suppress compiler warning */
		(void) 0;
        }
        
}

static void* get_new_address(void *ptr);

static void
change_addr(u64 *ptr)
{    
        u64 tagged_dword;
        int tag;
	int itag =-1;
                  
        E2K_LOAD_VAL_AND_TAGD(ptr, tagged_dword, tag);
        if (tag == E2K_AP_LO_ETAG) {
                /* AP & SAP */
                e2k_rwap_lo_struct_t ap_lo;
                e2k_rwsap_lo_struct_t sap_lo;

                ap_lo.word = tagged_dword;
                itag = ap_lo.E2K_RWAP_lo_itag;
                 /* AP & SAP */
                if (itag == E2K_AP_ITAG) {
                        /* AP */
                        ap_lo.E2K_RWAP_lo_base = (u64)get_new_address(
                                         (void*)ap_lo.E2K_RWAP_lo_base);
                        if (ap_lo.word != tagged_dword) {
                           E2K_STORE_VALUE_WITH_TAG(ptr, 
                                               ap_lo.word, E2K_AP_LO_ETAG);
                           Dbg_gc_addr("ptr=%p ap_lo.word =%lx " 
                                       " tagged_dword =%lx \n",
                                       ptr, ap_lo.word, tagged_dword);
                        }    
                } else if (itag == E2K_SAP_ITAG) {
                        sap_lo.word = tagged_dword;
                        sap_lo.E2K_RWSAP_lo_base = (u64)get_new_address(
                                          (void*)sap_lo.E2K_RWSAP_lo_base);
                        if (sap_lo.word != tagged_dword) {
				E2K_STORE_VALUE_WITH_TAG(ptr,
                                              sap_lo.word, E2K_AP_LO_ETAG);
				Dbg_gc_addr("ptr=%p sap_lo.word =%lx tagged_dword =%lx\n",
                                       ptr, sap_lo.word, tagged_dword);
                        }    
               }    
        } else if (tag == E2K_PL_ETAG) {
                // proc label
                e2k_pl_t pl;
                pl.word = tagged_dword;
		itag = pl.PL_ITAG;
                if (itag == E2K_PL_ITAG) {
			pl.PL_TARGET =  (u64)get_new_address(
                                               (void*)pl.PL_TARGET);
                }
                if (pl.word != tagged_dword) {
                    E2K_STORE_VALUE_WITH_TAG(ptr, pl.word, E2K_PL_ETAG);
                    Dbg_gc_addr("ptr=%p pl.word =%lx tagged_dword =%lx \n",
                                       ptr, pl.word, tagged_dword);
                }    
       }        
}

static void 
correct_memory(u64 addr, u64  end_adr)
{
	u64 	*ptr;

        Dbg_gc_mem("correct_memory addr =%lx end_adr =%lx \n ",
                  addr, end_adr);
        for (ptr  = (u64*)addr;  (u64)ptr < end_adr; ptr++) {
                change_addr(ptr);
                ptr++;            
        }    
}

#define mem_swap(x,y) ({mem_moved_t _z = *(mem_moved_t*)(x);     \
                   *(mem_moved_t*)(x) = *(mem_moved_t*)(y);  \
                   *(mem_moved_t*)(y) = _z;})
/*
 *  This sort is sort from lib/sort.c
 *  The changes are type of  cmp function !!! and define swap
 */  
static
void sort(void *base, size_t num, size_t size,
	  long (*cmp)(const void *, const void *), void* ptr)
{
	/* pre-scale counters for performance */
	int i = (num/2) * size, n = num * size, c, r;
	/* heapify */
	for ( ; i >= 0; i -= size) {
		for (r = i; r * 2 < n; r  = c) {
			c = r * 2;
			if (c < n - size && cmp(base + c, base + c + size) < 0)
				c += size;
			if (cmp(base + r, base + c) >= 0)
				break;
			mem_swap(base + r, base + c);
		}
	}

	/* sort */
	for (i = n - size; i >= 0; i -= size) {
		mem_swap(base, base + i);
		for (r = 0; r * 2 < i; r = c) {
			c = r * 2;
			if (c < i - size && cmp(base + c, base + c + size) < 0)
				c += size;
			if (cmp(base + r, base + c) >= 0)
				break;
			mem_swap(base + r, base + c);
		}
	}
}

static long 
cmp_new_mem_moved(const void *x, const void *y) {
        return ((mem_moved_t *)x)->new_addr - ((mem_moved_t *)y)->new_addr;
}


//  sort by beg_addr field 
static long
cmp_mem_moved(const void *x, const void *y) {
        return ((mem_moved_t *)x)->beg_addr - ((mem_moved_t *)y)->beg_addr;
}

static void
add_element(u64 start_addr, u64 end_addr, u64 new_addr);

//  sort by "new_addr" field 
static void
sort_mem_moved_tabl(allpools_t	*allpools)
{
	mem_moved_poolhdr_t*hdr = allpools->mem_moved;
        mem_moved_t     *mem_moved = get_first_mem_moved(hdr);
        
        Dbg_gc_trace("sort_mem_moved_tabl\n");
	sort((char*)mem_moved, hdr->mainp/sizeof(mem_moved_t) - 1,
             sizeof(mem_moved_t), cmp_mem_moved, NULL);

        hdr->new_mainp = hdr->mainp;
        if (DEBUG_GC_TBL_RES) {
            printk(" AFTER new_addr SORT  nr=%ld \n",
                   hdr->mainp/sizeof(mem_moved_t) - 1);          
            print_all_moved_memory(1);
        }
} 
static void
second_sort_mem_moved_tabl(allpools_t	*allpools)
{
	mem_moved_poolhdr_t*hdr = allpools->mem_moved;
        mem_moved_t     *mem_moved = get_first_mem_moved(hdr);
        
        Dbg_gc_trace("second_sort_mem_moved_tabl\n");
	sort((char*)mem_moved, hdr->mainp/sizeof(mem_moved_t) - 1,
             sizeof(mem_moved_t), cmp_new_mem_moved, NULL);

        if (DEBUG_GC_TBL_RES) {
            printk(" AFTER second_sort SORT  nm=%ld \n",
                   hdr->mainp/sizeof(mem_moved_t) - 1);          
            print_all_moved_memory(0);
        }
} 

static void
sort_all_mem_moved_tabl(allpools_t	*allpools)
{
	mem_moved_poolhdr_t*hdr = allpools->mem_moved;
        mem_moved_t     *mem_moved = get_first_mem_moved(hdr);
        
        Dbg_gc_trace("sort_all_mem_moved_tabl\n");

        if (DEBUG_GC_TBL_RES) {
            printk(" BEFORE SORT  nm=%ld \n",
                   hdr->new_mainp/sizeof(mem_moved_t)-1);          
            print_all_moved_memory(1);
        }    
	sort((char*)mem_moved, hdr->new_mainp/sizeof(mem_moved_t)-1,
             sizeof(mem_moved_t), cmp_mem_moved, NULL);
        if (DEBUG_GC_TBL_RES) {
            printk(" AFTER SORT  nm=%ld \n",
                   hdr->new_mainp/sizeof(mem_moved_t)-1);          
            print_all_moved_memory(1);
        }

}    

static void
add_element(u64 start_addr, u64 end_addr, u64 new_addr)
{
	mem_moved_poolhdr_t *hdr = current->mm->context.umpools.mem_moved;
        mem_moved_t         *mem_moved;
	mem_moved_poolhdr_t *tmp;
        
        Dbg_gc_trace("add_element start_addr=%lx end_addr=%lx "
                    "new_addr=%lx\n",
                    start_addr, end_addr, new_addr);
        
        /* added new element in new_mainp part  */
        if (hdr->new_mainp + sizeof(mem_moved_t) > hdr->size) {
            tmp = get_my_chunk(hdr);
            if (tmp == NULL) {
                printk(" No memory for add_element !! \n"); 
                dump_array();
            }    
            current->mm->context.umpools.mem_moved = tmp;
            hdr = tmp;
        }
        mem_moved = (mem_moved_t*)((char*)hdr + hdr->new_mainp);
        mem_moved->new_addr = new_addr;
        mem_moved->beg_addr = start_addr;
        mem_moved->end_addr = end_addr;
        Dbg_gc_res("add_element mem_moved =%p new_addr=%lx "
                   " start_addr=%lx end_addr=%lx\n",
                   mem_moved, new_addr, start_addr, end_addr);
        hdr->new_mainp += (sizeof(mem_moved_t));
           
}

/*
 *  It need correct ONLY new_addr for old line
 *  (before new_mainp pointer)
 *  mem_moved table are ordered by new_addr field
 */  
static void
correct_mem_moved_table(u64 *res_ind, u64 start_addr, u64 end_addr, u64 new_addr)
{
	mem_moved_poolhdr_t*hdr = current->mm->context.umpools.mem_moved;
        mem_moved_t     *mem_moved; 
        mem_moved_t     *limit; 
        u64             delta; 

        Dbg_gc_trace("correct_mem_moved_table  new_addr=%lx\n", new_addr);

        limit = get_last_mem_moved(hdr);
        if (*res_ind == 0) {
            mem_moved = get_first_mem_moved(hdr);
        } else {
            mem_moved = (mem_moved_t*)*res_ind;
        }    
        for (; mem_moved <= limit; mem_moved++) {
                if (mem_moved->beg_addr >= start_addr &&
                    mem_moved->beg_addr < end_addr) {
                    // It needs split "start_addr, end_addr" line  to
                    // several lines 
                    delta = (mem_moved->end_addr - start_addr);
                    Dbg_gc_res("split_element  mem_moved=%p start_addr=%lx "
                            "end_addr=%lx  new_addr=%lx mem_moved->new_addr=%lx"
                            " delta =%lx\n",
                            mem_moved, start_addr, end_addr, new_addr,
                            mem_moved->new_addr, delta);
                    //correct  new_addr
                    mem_moved->new_addr = new_addr + 
                        (mem_moved->beg_addr - start_addr);
                    
                   // add new  element
                    if (mem_moved->beg_addr != start_addr) {
                        add_element(start_addr, mem_moved->beg_addr, new_addr);
                    }    
                    start_addr = mem_moved->end_addr;
                    new_addr   += delta;    
                    
                } else if (mem_moved->beg_addr > end_addr) {
                    break;
                }    
        }
        if (start_addr != end_addr) {
                add_element(start_addr, end_addr, new_addr); 
        }
        *res_ind = (u64)mem_moved;
}
/*
 *  
 *  Correct only  new_addr" field in first lines
 *  (before new_mainp pointer)
 *  mem_moved table are ordered by new_addr field
 */
static void
second_correct_mem_moved_table(u64 *res_ind, mem_moved_t *new_mem_moved)
{
	mem_moved_poolhdr_t*hdr = current->mm->context.umpools.mem_moved;
        mem_moved_t     *mem_moved; 
        mem_moved_t     *limit; 
        u64             delta; 
        u64             start_addr= new_mem_moved->beg_addr;
        u64             end_addr = new_mem_moved->end_addr;

        Dbg_gc_trace("second_correct_mem_moved_table   res_ind=%lx\n", *res_ind);

        limit = get_last_mem_moved(hdr);
        if (*res_ind == 0) {
            mem_moved = get_first_mem_moved(hdr);
        } else {
            mem_moved = (mem_moved_t*)*res_ind;
        }    
        for (; mem_moved <= limit; mem_moved++) {
                Dbg_gc_res(" second_correct_mem_moved_table new_mem_moved=%p "
                           "beg_addr=%lx end_addr=%lx "
                           "new_mem_moved->new_addr=%lx mem_moved=%p\n",
                           new_mem_moved, new_mem_moved->beg_addr,
                           new_mem_moved->end_addr, new_mem_moved->new_addr,
                           mem_moved);
                if (mem_moved->new_addr >= start_addr &&
                    mem_moved->new_addr < end_addr) {
                    delta = (mem_moved->new_addr - start_addr);
                    // correct old line
                    mem_moved->new_addr = new_mem_moved->new_addr + delta;
                    Dbg_gc_res("correct mem_moved(%p)new_addr=%lx delta=%lx\n",
                                 mem_moved, mem_moved->new_addr, delta);
                     
                } else if (mem_moved->new_addr >= end_addr) {
                    break;
                }    
        }
        *res_ind = (u64)mem_moved;
}

static int
is_needed_correction_vma(struct vm_area_struct *vma, u64 addr)
{
        unsigned long  flags = vma->vm_flags;
        pgd_t			*pgd;
        pud_t			*pud;
        pmd_t			*pmd;
	pte_t			*pte;
        long                     res;

        Dbg_gc_trace("is_needed_correction_vma \n");
        Dbg_gc_res("is_needed_correction_vma addr=%lx \n", addr);
	pgd = pgd_offset(vma->vm_mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
               Dbg_gc_res("is_needed_correction_vma pgd_none=%d pgd_bad=%d\n",
                          pgd_none(*pgd) ,pgd_bad(*pgd));
		return 0;
        }        
	pud = pud_offset(pgd, addr);
	if (pud_none(*pud) || pud_bad(*pud)) {
               Dbg_gc_res("is_needed_correction_vma pud_none=%d pud_bad=%d\n",
                         pud_none(*pud) ,pud_bad(*pud));
		return 0;
        }        
        pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd)) {
             Dbg_gc_res("is_needed_correction_vma pmd_none=%d pmd_bad=%d\n",
                          pmd_none(*pmd) ,pmd_bad(*pmd));
		return 0;
        }    
        pte = pte_offset_kernel(pmd, addr);
        res = pte_valid(*pte);
        
        Dbg_gc_res("is_needed_correction_vma pte_valid=%lx \n",res);

        return (flags & (VM_READ | VM_WRITE)) &&  res;
}    

static void
walk_memory(void)
{
	struct vm_area_struct *vma;
        u64           time;
        long freq = cpu_data[0].proc_freq;
        u64           mem = 0;
        u64           vm_start, vm_end;

        
        Dbg_gc_trace("walk_memory \n");
        time = E2K_GET_DSREG(clkr);
	for(vma = current->mm->mmap; vma != NULL; vma = vma->vm_next) {
            vm_start = vma->vm_start;
            vm_end = vma->vm_end;
            while (vm_start < vm_end) {
		if (is_needed_correction_vma(vma, vm_start)) {
                    mem += PAGE_SIZE;
                    correct_memory(vm_start, vm_start + PAGE_SIZE); 
                }
                vm_start +=PAGE_SIZE;
           }            
        }
        time = E2K_GET_DSREG(clkr) - time;    
        printk(" walk_memory is ended memory =%lx %ld(sec)\n",
                     mem, time/freq);
}

/*
 *
 * It needs to correct only new_addr in old lines  
 * (first part of mem_moved table)
 * After compress_vm we must correct "new_addr" field for old lines
 * 
 */   
static void
second_correct(allpools_t *allpools)
{
        u64 start_ind = 0;
        mem_moved_t     *mem_moved; 
        mem_moved_t     *limit; 
	mem_moved_poolhdr_t*hdr = current->mm->context.umpools.mem_moved;

        Dbg_gc_trace("second_correct \n");
        second_sort_mem_moved_tabl(allpools);

        mem_moved = get_last_mem_moved(hdr);
        limit = (mem_moved_t *)((char*)hdr + hdr->new_mainp);  

        for (mem_moved++ ; mem_moved <= limit; mem_moved++) {
                second_correct_mem_moved_table(&start_ind, mem_moved);
        }    
        
        
}

/*
 *   To create the second part of mem_moved table
 *   (after mainp pointer) new_mainp pointer - first free site
 *   in mem_moved table;
 *   The line are created after mremap_to call 
 */ 
static void
compress_vm(void)
{
	struct vm_area_struct *vma;
	struct vm_area_struct *vma_next;
        unsigned long  len, last_addr;
        unsigned long  start_addr, end_addr;
        long ret;
        u64 start_ind = 0;
        u64 time;
        long freq = cpu_data[0].proc_freq;

        Dbg_gc_trace("compress_vm  \n");
	if (!current->mm){
                DBUG(" compress_vm current->mm == NULL \n");
		return;
        } 
        
        // print new vm
        if (DEBUG_GC_RES) {
            printk(" OLD_VM compress_vm \n");
            print_mmap(current);
        }    
        
	// first 2**32 is reserved for fixed map
//	current->mm->context.mmap_position = TASKP_SIZE - TASK32_SIZE;   ///for debuging !!!
	current->mm->context.mmap_position = TASK32_SIZE;
        last_addr = current->mm->context.mmap_position;
        
        time = E2K_GET_DSREG(clkr);
        // compress vm
	for(vma = current->mm->mmap; vma != NULL; vma = vma_next) {
            
            vma_next = vma->vm_next;
	    Dbg_gc_remap(" vma =%p vm_start=%lx vm_end=%lx vm_flags=%lx last_addr =%lx\n",
                   vma, vma->vm_start, vma->vm_end, vma->vm_flags, last_addr);
                
	    if (is_u_hw_stack_range(vma->vm_start, vma->vm_end))
                continue;
            len = vma->vm_end - vma->vm_start;
		/* Check overlaps of new and old address
                 * mremap_to doesn't work whith overlap
                 */ 
            if (last_addr < vma->vm_start &&
                 (last_addr + len) <= vma->vm_start){
		    bool locked = false;
                    Dbg_gc_remap(" mremap_to before last_addr =%lx vm_start=%lx"
                                 " last_addr + len =%lx\n",
                                 last_addr, vma->vm_start, last_addr + len);
                    
                    start_addr = vma->vm_start;
                    end_addr = vma->vm_end;
                    ret = mremap_to(vma->vm_start, len, last_addr, len,
		    		&locked);
                    if (ret < 0) {
                         printk("ERRR mremap_to =%ld vma->vm_start=%lx"
                                "  len=%lx\n",
                               -ret, start_addr , len); 
                    }    
                    correct_mem_moved_table(&start_ind, 
                                            start_addr, end_addr, ret);
                    Dbg_gc_remap(" do_mremap after  res =%lx vm_start=%lx "
                                " vm_end=%lx last_addr =%lx\n",
                                 ret, start_addr, end_addr, last_addr);  
                    
                    last_addr = ret + len;
            } else {
                    last_addr = vma->vm_end;
            }    
        } 
	current->mm->context.mmap_position = last_addr;
        
        printk("  compress_vm (do_mremap)  is ended %ld(sec)\n",
                     (E2K_GET_DSREG(clkr)-time)/freq);
        Dbg_gc_remap("compress_vm   mmap_position=%lx \n ", last_addr);

        // print new vm
        if (DEBUG_GC_RES) {
                printk("  VM  last_addr =%lx \n", last_addr);
 	 	for(vma = current->mm->mmap; vma != NULL; vma = vma_next) {
            
 	            vma_next = vma->vm_next;
 	            printk(" vm_start=%lx vm_end=%lx vm_flags=%lx \n",
 	                    vma->vm_start, vma->vm_end, vma->vm_flags);
 	        }
        }
                
}

static void
clean_mem(allpools_t	*allpools)
{
	mem_moved_poolhdr_t *hdr = allpools->mem_moved;
        Dbg_gc_trace("clean_mem \n ");
        
        if (hdr) {
                vfree((char*) hdr); 
        }
        allpools->mem_moved = NULL;
}

static void*
get_new_address(void *ptr)
{
        u64 res = (u64)ptr;
	mem_moved_poolhdr_t*hdr = current->mm->context.umpools.mem_moved;
        mem_moved_t     *mem_moved; 
        int      first, limit, curr;
        int      last =0; 

        first = 0;
        limit = (hdr->new_mainp - FIRST_MVD_IND)/sizeof(mem_moved_t) - 1; 
        Dbg_gc_res("get_new_address  ptr=%p limit=%d hdr->new_mainp =%d\n",
                     ptr, limit, hdr->new_mainp);
        if (limit < 0) {
                 return ptr;
        }    
        curr = (limit)/2;
        while(1){ 
                mem_moved = (mem_moved_t *)
                    ((char*)(hdr) + FIRST_MVD_IND + curr*sizeof(mem_moved_t));
                Dbg_gc_res("get_new_address  res =%lx new_addr=%lx "
                           "beg_addr=%lx ptr=%p first =%d curr =%d limit=%d\n",
                            res, mem_moved->new_addr, mem_moved->beg_addr, ptr,
                            first,curr,limit);
               if (mem_moved->beg_addr > res) {
                    limit = curr;
                    if (curr == first || last) {
                        break;
                    }
                    else if (curr == first + 1) {
                        curr = first;
                        last =1;
                    } else {    
                        curr = (curr - first + 1)/2 + first;
                    }    
                } else {  
                    if (mem_moved->end_addr > res) {
                            res = (res - mem_moved->beg_addr)
                                    + mem_moved->new_addr; 
                            Dbg_gc_res("!!! get_new_address "
                                       "res =%lx new_addr=%lx"
                                       "  beg_addr=%lx ptr=%p\n",
                                       res, mem_moved->new_addr, 
                                       mem_moved->beg_addr, ptr);
                            return (void*)res;
                    }        
                    first = curr;
                    if (curr == limit || last) {
                        break;
                    } else if (curr == limit - 1) {
                        curr = limit;
                        last =1;
                    } else {    
                        curr = (limit - curr + 1)/2 + curr;
                    }
                }    
        } 
        
        Dbg_gc_res("get_new_address  ptr=%p first =%d curr =%d limit=%d "
                   " mem_moved->beg_addr=%lx mem_moved->end_addr =%lx \n",
                     ptr, first, curr, limit, mem_moved->beg_addr,
                     mem_moved->end_addr);
        return (void*)res;
}

static void 
correct_kernel_tabl(allpools_t	*allpools)
{
	int             i;
	umlc_pool_t	*mypool;
	subpoolhdr_t	*subpool;
        struct list_head *ln;
        struct list_head *head;
        listpoolhdr_t     *hdr;
        void            *ptr;           

        Dbg_gc_trace("correct_kernel_tabl \n ");
        sort_all_mem_moved_tabl(allpools);       
        for (i =0; i < MAX_CHUNKS; i++) {
	    mypool = &allpools->pools[i];
            head = get_list_head(mypool);
            head = get_new_address(head);
            if (head->next == NULL) {
                continue;
            }
            // correct the list    
            ptr= get_new_address(head->next);
            if (ptr != head->next) {
                Dbg_gc_res("ptr=%p head->next =%p \n",ptr, head->next);
                head->next = ptr;
            }    
            ptr= get_new_address(head->prev);
            if (ptr != head->prev) {
                Dbg_gc_res("ptr=%p head->prev =%p \n",ptr, head->prev);
                head->prev = ptr;
            }
            list_for_each(ln, head) {
                ptr = get_new_address(ln->prev);
                if (ln->prev != ptr) {
                    Dbg_gc_res("ptr=%p ln->prev =%p \n",ptr, ln->prev);
                    ln->prev = ptr;
                }    
                ptr = get_new_address(ln->next);    
                if (ln->next != ptr) {
                    Dbg_gc_res("ptr=%p ln->next =%p \n",ptr, ln->next);
                    ln->next = ptr;
                } 
                hdr = list_entry(ln, listpoolhdr_t, head);
                // correct only chunk (subpool->ptr)     
                subpool_list_for_each_prev(subpool, hdr) {
                    if (subpool->ptr != NULL) {
                        ptr = get_new_address(subpool->ptr);
                        if (ptr != subpool->ptr) {
                            Dbg_gc_res("ptr=%p subpool->ptr =%p \n",
                                       ptr, subpool->ptr);
                            subpool->ptr = ptr;
                        }    
                    }    
                }    
            }
        }      
}
#if 0
/* ONLY for debugging */
#define NNN  12
static int array_pid[NNN];
static int ind_array_pid =0;
static DEFINE_SEMAPHORE(xxx, 1);

static int debug_thread(void *p)
{
   pid_t pid = current->pid; 

   while(1){
       down(&xxx);
       printk (" debug_thread pid =%d p=%p\n", pid, p);
//       __udelay(10, 1);
       up(&xxx);
       
       current->state = TASK_UNINTERRUPTIBLE;
       schedule();
   }
   return 1;   
}    



static void
create_threads()
{  
   int i;
   pid_t pid; 
   struct task_struct *tsk;
   for (i=0; i < 2; i++) {   
        if (ind_array_pid < NNN) {
        	pid = kernel_thread(debug_thread, current, CLONE_FS|CLONE_FILES);
                array_pid[ind_array_pid++] = pid; 
        }        
   }
   for (i=0; i < ind_array_pid; i++) {  
	tsk = find_task_by_pid(array_pid[i]);
        force_sig_specific(SIGSTOP, tsk);
   }    
   
   printk(" create_threads is ended  ind_array_pid=%d\n", ind_array_pid);
}

#endif

static void
stop_all_children_and_parent(void)
{
	struct task_struct *p,*g;
        
        Dbg_gc_trace(" stop_all_children_and_parent \n");
        
//        create_threads();   // for debugging
//        return;
        if (thread_group_empty(current)) {
            return;
        } 
	read_lock(&tasklist_lock);
	do_each_thread(g, p) { 
		if (p !=current && task_tgid(p) == task_tgid(current)) {
//                    force_sig_specific(SIGSTOP, p);
	            send_sig_info(SIGSTOP, SEND_SIG_FORCED, p);
		}
        }  while_each_thread(g, p);	
	read_unlock(&tasklist_lock);
    
}

static void
wakeup_all_children_and_parent(void)
{
	struct task_struct *p,*g;
 
        Dbg_gc_trace(" wakeup_all_children_and_parent begin \n");
        if (thread_group_empty(current)) {
            return;
        } 
	read_lock(&tasklist_lock);
	do_each_thread(g, p) {
		if (p !=current && task_tgid(p) == task_tgid(current)) {
                    wake_up_process(p);
		}
	} while_each_thread(p, g);
	read_unlock(&tasklist_lock);
}
/*
 *    For changes old vm address to new vm address are used mem_moved table 
 *     mem_moved table condists of many lines:
 *       new_addr, beg_addr, end_addr    
 *
 *     The  address in diapason(beg_addr, end_addr) must be changed to new
 *     address (new_add) 
 *     The lines are ordered by beg_addr field ( for quick seach)
 *
 */      
 
static int 
garbage_collection(void)
{

	allpools_t	*allpools = &current->mm->context.umpools;
	mem_moved_poolhdr_t *head;
        u64           time;
        long freq = cpu_data[0].proc_freq;

        printk("garbage_collection is beginning  TASK32_SIZE =%lx"
                    " TASKP_SIZE =%lx"
                    " pid =%d current->mm->context.mmap_position =%lx\n",
                    TASK32_SIZE, TASKP_SIZE, 
                  current->pid, current->mm->context.mmap_position);
        
        if (DEBUG_GC_REMAP) {
		print_mmap(current);
                dump_array();
        }
        
        time = E2K_GET_DSREG(clkr);
        head = get_my_chunk(NULL);
        if (head == NULL) {
               printk(" No memory for garbage_collection \n");
               return 1; 
        }    
        allpools->mem_moved = head; 

        stop_all_children_and_parent();
//        wakeup_all_children_and_parent();
        
//  	down_write(&current->mm->mmap_sem);
        E2K_FLUSHCPU;
	E2K_FLUSH_WAIT;
        pack_and_cpy(allpools); 
//	up_write(&current->mm->mmap_sem);
        
        sort_mem_moved_tabl(allpools);
        compress_vm();
        second_correct(allpools);

        correct_kernel_tabl(allpools);
        walk_memory(); 
        clean_mem(allpools);
        wakeup_all_children_and_parent();
        printk("  garbage_collection  is ended %ld(sec)\n",
                     (E2K_GET_DSREG(clkr)-time)/freq);
        if (DEBUG_GC_REMAP) {
		print_mmap(current);
                dump_array();
        }
        return 0;
}
/*
 * It used to create true context for new process
 */ 
void
init_pool_malloc(struct task_struct *old_tsk, struct task_struct *new_tsk)
{
        allpools_t *allpools = &new_tsk->mm->context.umpools;
        memset(allpools, 0, sizeof(allpools_t));
        init_sem_malloc(allpools);
        new_tsk->mm->context.mmap_position = 
                        old_tsk->mm->context.mmap_position;
}

void
init_sem_malloc(allpools_t *allpools)
{
       struct semaphore *lock;
       int i;
     
       check_size_rt_semaphore();
       for (i =0; i < MAX_CHUNKS; i++) {        
              lock = get_rt_semaphore(&allpools->pools[i]);
              sema_init(lock, 1);
       }
}    
