#include <linux/interval_tree.h>
#include <linux/types.h>
#include <linux/mman.h>
#include <linux/list.h>
#include <linux/vmalloc.h>
#include <linux/rwsem.h>
#include <linux/sched/signal.h>
#include <linux/semaphore.h>
#include <linux/uaccess.h>
#include <linux/pagewalk.h>
#include <linux/hugetlb.h>

#include <asm/umalloc.h>
#include <asm/e2k_ptypes.h>
#include <asm/process.h>
#include <asm/mmu_context.h>
#include <asm/e2k_debug.h>

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

#define DEBUG_CL_DESC		0
#define Dbg_cl_desc(...)	DebugPrint(DEBUG_CL_DESC, ##__VA_ARGS__)

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
 *         address of first free element's chunk             |_________ |   |
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
	long    *ptr;   /* ptr to chunk */
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
#define S_S(signo) do {			\
	kernel_siginfo_t info;		\
	info.si_signo = signo;		\
	info.si_errno = 0;		\
	info.si_trapno = TRAP_BRKPT;	\
	info.si_code  = 0;		\
	force_sig_info(&info);		\
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


/* calculate last posible correct address  for subpoool  */
#define get_last_subpool(x)  ({u32 mainp; u32 size; long *ptr; char *_t;\
				get_user(mainp, &x->mainp);		\
				get_user(size, &x->size);		\
				 _t = (char *)(x) + mainp;		\
				get_user(ptr, &((subpoolhdr_t *)_t)->ptr);\
			(subpoolhdr_t *)(_t -				\
		((((mainp + sizeof(subpoolhdr_t)) >= size) ||		\
		(ptr == NULL &&	mainp > FIRST_SUBPOOL_IND)) ?		\
			sizeof(subpoolhdr_t) : 0)); })

#define get_first_subpool(x) (subpoolhdr_t *)((char *)(x) + FIRST_SUBPOOL_IND)
             
#define subpool_list_for_each_prev(subpool,hdr)                                \
           for (subpool = get_last_subpool(hdr);                               \
                subpool >=  get_first_subpool(hdr);                            \
                     subpool--) 

#define subpool_list_for_each(subpool,hdr)                                     \
           for (subpool = get_first_subpool(hdr);                              \
                subpool <=  get_last_subpool(hdr);                             \
                     subpool++) 

#define deleted_subpool(subpool)  ({long *ptr;				\
		get_user(ptr, &subpool->ptr); ptr == NULL; })
   

#define get_first_mem_moved(x) (mem_moved_t *)((char*)(x) + FIRST_MVD_IND)
           
/* calculate last posible correct address  for mem_moved  */
#define get_last_mem_moved(x)						\
         ((mem_moved_t *)((char*)(x) + x->mainp - sizeof(mem_moved_t)))      
           
#define MAX_PROC_PTE  20

//  may be ~ 1024 ?
#define MAX_USED_MEM  128

static e2k_addr_t
ALLOC_MEM(long sz)
{
	e2k_addr_t map_addr;
        int once=0;
again:    
	map_addr = (e2k_addr_t)vm_mmap_notkillable(NULL, 0L, sz,
					PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS, 0L);
        if (once) {
               Dbg_gc_res("once map_addr=%llx\n", (u64)map_addr);
        }    
	if (map_addr & ~PAGE_MASK) {
            map_addr = 0;
        }    
	DBUM("ALLOC_MEM = 0x%lx : 0x%lx\n", map_addr, sz);
        if (map_addr == 0 && once == 0) {
	        struct task_struct *tsk = current;
                if (xchg(&current->mm->context.umpools.gc_lock.counter, 1)) {
                    while(atomic_read(&current->mm->context.umpools.gc_lock)){
	                    tsk->state = TASK_INTERRUPTIBLE;		
 			    schedule();
                        }    
                    
	} else /*if (garbage_collection()) */{
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
	(void) do_munmap(mm, a, sz, NULL);
	up_write(&mm->mmap_sem);
}

static int
get_pind(unsigned int size, u32 *chsz)
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
	u32 mused_i;
	u32 res = 0;
	int i;

	for (i = 0; i < MAX_MUSED; i++) {
		get_user(mused_i, &sbp->mused[i]);
		res = res | mused_i;
	}
	return res == 0;
}

static void
set_used(subpoolhdr_t *sbp, u32 chsz, umlc_pool_t *mypool)
{
	u32 mainp, mainsz;
	int chn;
	int i;
	u32 m;
	u32 mused_i;

	get_user(mainp, &sbp->mainp);
	get_user(mainsz, &sbp->mainsz);
	chn = mainp / mainsz;
	i = WORD(chn);
	get_user(mused_i, &sbp->mused[i]);
	m = 1 << (SHIFT(chn));

	Dbg_trace("set_used sbp =%px (%d,%d) sbp->mainp=%x chsz=%x\n",
			sbp, i, SHIFT(chn), mainp, chsz);
	if (i >= MAX_MUSED) {
		DBUG("Too big chunk number %d sz = %d\n", i, chsz);
		dump_malloc_cart();
		sys_exit(7009);
	}	
	if (mused_i & m) {
		struct list_head *head = get_list_head(mypool);
		DBUG("Chunk already used. size %u; mused[%d] = 0x%08x   - m = 0x%08x\n"
				"   chn = %d sbp=%px mypool=%px mypool->mainp=%x\n"
				" head->next =%px\n",
			chsz, i, mused_i, m, chn, sbp, mypool,
			mypool->mainp, (char *)head->next);
		dump_malloc_cart();
		sys_exit (7009);
	}
	put_user(mused_i | m , &sbp->mused[i]);
	put_user(mainp + chsz, &sbp->mainp);
	Dbg_trace(" set_used mused =%08x\n", mused_i | m);
}

static void clear_used(subpoolhdr_t *sbp, int chn)
{
	int i = WORD(chn);
	u32 m = 1 <<(SHIFT(chn));
	u32 mused_i;

	get_user(mused_i, &sbp->mused[i]);
        Dbg_trace(" clear_used sbp =%px (%d,%d) sbp->mainp=%x bit=%x\n",
                  sbp, i, SHIFT(chn), sbp->mainp, chn);    
	if (i >= MAX_MUSED) {
		u32 mainsz;

		get_user(mainsz, &sbp->mainsz);
		DBUG("Clear: Too big chunk number %d; sz = %d in %d\n",
		       chn, i, mainsz);
		dump_malloc_cart();
		sys_exit(7009);
	}
	if (!(mused_i & m)) {
		u32 mainsz;

		get_user(mainsz, &sbp->mainsz);
		DBUG("Chunk not used. size %u; mused[%d]=0x%08x m=0x%08x\n",
		       mainsz, i, mused_i, m);
//		dump_malloc_cart();
//		sys_exit (7009);
                S_S(SIGABRT);
	}	
	put_user(mused_i & ~m , &sbp->mused[i]);
	Dbg_trace("clear_used =%08x\n", mused_i & ~m);
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
	DBUM("create_new_subpool(0x%x) = 0x%px\n", chsz, new);
	return new;
}

static void free_subpool(subpoolhdr_t *a, allpools_t *allpools)
{

	DBUM("free_subpool a=%px a->ptr =%px a->size=%x\n", a, a->ptr, a->size);

	if (!a->ptr) {
		return;
	}
	allpools->allsize -= a->size;
	FREE_MEM((e2k_addr_t)a->ptr, a->size);
	memset(a, 0, sizeof(subpoolhdr_t));
}

static int delete_last_subpool(listpoolhdr_t *hdr, umlc_pool_t *mypool,
							allpools_t *allpools)
{
	subpoolhdr_t *last = get_last_subpool(hdr);
	if (deleted_subpool(last) && mypool->mainp > FIRST_SUBPOOL_IND &&
		(subpoolhdr_t *)((char *)get_list_head(mypool)->next +
			    mypool->mainp -  sizeof(subpoolhdr_t)) == last) {
		u32 mainp;
		get_user(mainp, &hdr->mainp);
		put_user(mainp - sizeof(subpoolhdr_t),  &hdr->mainp);
		mypool->mainp -= sizeof(subpoolhdr_t);
		return 1;
	}
	return 0;
}

static void free_compress_subpool(subpoolhdr_t *a, allpools_t *allpools,
			     umlc_pool_t *mypool, listpoolhdr_t *hdr)
{
	subpoolhdr_t *last = get_last_subpool(hdr);
	free_subpool(a, allpools);

	/* delete last ref on subpool */
	if (a == get_last_subpool(hdr)) {
		while (delete_last_subpool(hdr, mypool, allpools)) {
			;
		}
	}
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
	u32 x;
	unsigned long x1;
        
	/* max size for protected malloc*/
	if (size >= 0xffffffffUL) {
		return 0;
	}
        pind = get_pind(size, &chsz);
	DBUM("sys_malloc size=%lx pind=%d cz=%x\n", size, pind, chsz);
                //    small chunks    
    	mypool = &allpools->pools[pind];
//        check_size_rt_semaphore();
        lock = get_rt_semaphore(mypool);
        down(lock);
	head = get_list_head(mypool);
	DBUM("%s mainp=%x main_size=%x head->next=%px head=%px mypool=%px\n",
	  __func__, mypool->mainp, mypool->size, head->next, head, mypool);
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
		put_user(FIRST_SUBPOOL_IND, &((listpoolhdr_t *)mem)->mainp);
		put_user(PAGE_SIZE, &((listpoolhdr_t *)mem)->size);
                list_add((struct list_head *)mem, head);
      
	}
        curr_subpool = (subpoolhdr_t*)((char*)head->next + mypool->mainp);
	DBUM("curr_subpool=%px  curr_subpool->ptr=%px\n",
			curr_subpool, curr_subpool->ptr);
	get_user(x1, &curr_subpool->ptr);
	if (!x1) {
                u32  size; 
                void *ptr; 
		// no room in subpool.
                // may be called garbage_collection 
                ptr = create_new_subpool(chsz, allpools ,&size);
		head = get_list_head(mypool);
                curr_subpool = (subpoolhdr_t*)((char*)head->next + mypool->mainp);
		put_user(ptr, &curr_subpool->ptr);
		put_user(chsz, &curr_subpool->mainsz);
		put_user(size, &curr_subpool->size);
		put_user(0, &curr_subpool->mainp);
	}
	DBUM("sys_malloc addr =%lx curr_subpool =%px ptr=%px mainp=0x%x\n",
		addr, curr_subpool, curr_subpool ? curr_subpool->ptr : NULL,
			curr_subpool->mainp);
	// There is a room for a chunk
	get_user(x, &curr_subpool->mainp);
	get_user(x1, &curr_subpool->ptr);
	addr = (e2k_addr_t)(x1 + x);
	set_used(curr_subpool, chsz, mypool);
        if (curr_subpool->mainp >= curr_subpool->size) {
                mypool->mainp += sizeof(subpoolhdr_t);
                ((listpoolhdr_t*)head->next)->mainp += sizeof(subpoolhdr_t);
        }    
 	allpools->allused += chsz;
	allpools->allreal += size;
out:        
        up(lock);
	DBUM("sys_malloc addr =%lx curr_subpool =%px ptr=%px mainp=0x%x\n",
		addr, curr_subpool, curr_subpool ? curr_subpool->ptr : NULL,
				curr_subpool->mainp);
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
	u32		size;
	u32		mainsz, mainp;
        struct list_head *ln;
        struct list_head *head;
        listpoolhdr_t    *hdr;
        struct semaphore *lock;
	listpoolhdr_t    *last_hdr = NULL;

	if (a == 0) {
		return;
	}
	// At first assume size is a real chunk size
        pind = get_pind(sz, &chsz);
	DBUM(" sys_free a=%lx sz=%lx\n", a, sz);
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
		if (!last_hdr) {
			last_hdr = hdr;
		}
                subpool_list_for_each_prev(subpool, hdr) {
                        if (deleted_subpool(subpool)) {
				continue;
			}
			get_user(addr, &subpool->ptr);
			get_user(size, &subpool->size);
			if (a < addr || a  >= (addr + size)) {
				continue;
			}
			if ((a + sz) > (addr + size)) {
				DBUG("Bad free desk pind =%d (0x%lx, 0x%lx) "
				     "for (0x%lx, 0x%x)  subpool =%px\n",
				       pind, a, sz, addr, size, subpool);
				dump_malloc_cart();
				// kill process
                                up(lock);
				FAIL_RETURN;
			}
                        /* 
                         * glibc needs full coresponding of address 
                         */ 
			get_user(mainsz, &subpool->mainsz);
			if ((a - addr) % mainsz != 0) {
				up(lock);
				S_S(SIGABRT);
				return;
                        }    
			clear_used(subpool, (a - addr) / mainsz);
			allpools->allused -= mainsz;
			get_user(mainp, &subpool->mainp);
			if (subpool_is_empty(subpool) && mainp == size) {
				// subpool is empty. Return it
				free_compress_subpool(subpool, allpools,
						     mypool, last_hdr);
			}
	
			DBUM("Free big: 0x%lx -  0x%x\n", addr, size);
                        up(lock);
			return;
		}
            }
            // go to biger chunk 
            pind++;
            up(lock);
        }    
	DBUG("Bad!!! free desk (0x%lx, 0x%lx) pind =%d curr pind =%d\n",
             a, sz, get_pind(sz, &chsz), pind);
	S_S(SIGABRT);
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
			printk("last_subpool(hdr)=%px first_subpool(hdr)=%px "
				"hdr->mainp=0x%x, hdr->size=0x%x subpool=%px\n",
				get_last_subpool(hdr),
				get_first_subpool(hdr), hdr->mainp,
				hdr->size, subpool);
			if (deleted_subpool(subpool)) {
				printk("DELETED subpool = 0x%llx "
					"mainp=0x%x size=0x%x\n",
					(u64)subpool, subpool->mainp,
					subpool->size);
				continue;
                        }    
		        printk("subpool = 0x%llx  STARTMP = 0x%x ptr=%px\n",
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


static void stop_all_children_and_parent(void)
{
	struct task_struct *t;
        
        Dbg_gc_trace(" stop_all_children_and_parent \n");
        
        if (thread_group_empty(current))
		return;

	rcu_read_lock();
	for_each_thread(current, t) { 
		if (t != current)
			send_sig_info(SIGSTOP, SEND_SIG_PRIV, t);
        }
	rcu_read_unlock();
}

static void wakeup_all_children_and_parent(void)
{
	struct task_struct *t;
 
        Dbg_gc_trace(" wakeup_all_children_and_parent begin \n");

        if (thread_group_empty(current))
		return;

	rcu_read_lock();
	for_each_thread(current, t) { 
		if (t != current)
			send_sig_info(SIGCONT, SEND_SIG_PRIV, t);
        }
	rcu_read_unlock();
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

/*
 * Fill 'ptr' with 'dw' double words
 */
int mem_set_empty_tagged_dw(void __user *ptr, s64 size, u64 dw)
{
	void __user *ptr_aligned;
	s64 size_aligned, size_head, size_tail;

	if (size < 8)
		if (clear_user((void __user *) ptr, size))
			return -EFAULT;

	ptr_aligned = PTR_ALIGN(ptr, 8);
	size_head = (s64 __force) (ptr_aligned - ptr);
	size_aligned = round_down(size - size_head, 8);
	size_tail = size - size_head - size_aligned;

	if (fill_user(ptr, size_head, 0xff) ||
		fill_user_with_tags(ptr, size_aligned, ETAGEWD, dw) ||
		fill_user(ptr_aligned + size_aligned, size_tail, 0xff))
		return -EFAULT;

	return 0;
}

/* Must be no page faults in a function called from TRY_USR_PFAULT block */
__always_inline
static void find_data_in_list(struct rb_root_cached *areas,
		e2k_ptr_t data, unsigned long ptr, unsigned long offset,
		bool kernel_stack)
{
	unsigned long start, last;
	struct interval_tree_node *it;

	if (!kernel_stack)
		might_fault();

	Dbg_cl_desc("data.lo = 0x%lx data.hi = 0x%lx ptr = 0x%lx\n",
			AW(data).lo, AW(data).hi, ptr);

	start = AS(data).ap.base;
	last = AS(data).ap.base + AS(data).size - 1;
	if (!AS(data).size)
		return;

	/* We know that there is no intersection between passed areas
	 * so there is no need to go over *all* intervals intersecting
	 * this particular descriptor: if the first one was not big enough
	 * then all others also won't be. */
	it = interval_tree_iter_first(areas, start, last);
	if (it && it->start <= start && it->last >= last) {
		/*
		 * If we find descriptor in readonly page, we would
		 * catch a reasonable PFAULT on store operation.
		 */
		if (kernel_stack || __range_ok(ptr, 16, PAGE_OFFSET)) {
			__NATIVE_STORE_TAGGED_QWORD(ptr, AW(data).lo,
					AW(data).hi, ETAGNVD, ETAGNVD, offset);
		}
	}
}

__always_inline
static void clean_descriptors_in_psp(struct rb_root_cached *areas,
		unsigned long start, unsigned long end, bool kernel_stack)
{
	unsigned long ptr;

	if (machine.native_iset_ver < E2K_ISET_V5) {
		for (ptr = start; ptr < end; ptr += 64) {
			u64 val0_lo, val0_hi, val1_lo, val1_hi;
			u32 tag0_lo, tag0_hi, tag1_lo, tag1_hi;

			NATIVE_LOAD_VAL_AND_TAGD(ptr, val0_lo, tag0_lo);
			NATIVE_LOAD_VAL_AND_TAGD(ptr + 8, val0_hi, tag0_hi);

			NATIVE_LOAD_VAL_AND_TAGD(ptr + 32, val1_lo, tag1_lo);
			NATIVE_LOAD_VAL_AND_TAGD(ptr + 40, val1_hi, tag1_hi);

			if (unlikely(tag0_hi == E2K_AP_HI_ETAG &&
				     tag0_lo == E2K_AP_LO_ETAG)) {
				e2k_ptr_t data;
				AW(data).lo = val0_lo;
				AW(data).hi = val0_hi;
				find_data_in_list(areas, data, ptr, 8,
						kernel_stack);
			}
			if (unlikely(tag1_hi == E2K_AP_HI_ETAG &&
				     tag1_lo == E2K_AP_LO_ETAG)) {
				e2k_ptr_t data;
				AW(data).lo = val1_lo;
				AW(data).hi = val1_hi;
				find_data_in_list(areas, data, ptr + 32, 8,
						kernel_stack);
			}
		}
	} else {
		for (ptr = start; ptr < end; ptr += 32) {
			u64 val0_lo, val0_hi, val1_lo, val1_hi;
			u32 tag0_lo, tag0_hi, tag1_lo, tag1_hi;

			NATIVE_LOAD_VAL_AND_TAGD(ptr, val0_lo, tag0_lo);
			NATIVE_LOAD_VAL_AND_TAGD(ptr + 16, val0_hi, tag0_hi);

			NATIVE_LOAD_VAL_AND_TAGD(ptr + 8, val1_lo, tag1_lo);
			NATIVE_LOAD_VAL_AND_TAGD(ptr + 24, val1_hi, tag1_hi);

			if (unlikely(tag0_hi == E2K_AP_HI_ETAG &&
				     tag0_lo == E2K_AP_LO_ETAG)) {
				e2k_ptr_t data;
				AW(data).lo = val0_lo;
				AW(data).hi = val0_hi;
				find_data_in_list(areas, data, ptr, 16,
						kernel_stack);
			}
			if (unlikely(tag1_hi == E2K_AP_HI_ETAG &&
				     tag1_lo == E2K_AP_LO_ETAG)) {
				e2k_ptr_t data;
				AW(data).lo = val1_lo;
				AW(data).hi = val1_hi;
				find_data_in_list(areas, data, ptr + 8, 16,
						kernel_stack);
			}
		}
	}
}

static int clean_descriptors_range_user(struct rb_root_cached *areas,
		unsigned long start, unsigned long end, bool proc_stack)
{
	unsigned long ts_flag;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);

	TRY_USR_PFAULT {
		if (!proc_stack) {
			unsigned long ptr;

#pragma loop count (100000)
			for (ptr = start; ptr < end; ptr += 32) {
				u64 val0_lo, val0_hi, val1_lo, val1_hi;
				u32 tag0_lo, tag0_hi, tag1_lo, tag1_hi;

				NATIVE_LOAD_VAL_AND_TAGD(ptr, val0_lo, tag0_lo);
				NATIVE_LOAD_VAL_AND_TAGD(ptr + 8,
						val0_hi, tag0_hi);

				NATIVE_LOAD_VAL_AND_TAGD(ptr + 16,
						val1_lo, tag1_lo);
				NATIVE_LOAD_VAL_AND_TAGD(ptr + 24,
						val1_hi, tag1_hi);

				if (unlikely(tag0_hi == E2K_AP_HI_ETAG &&
					     tag0_lo == E2K_AP_LO_ETAG)) {
					e2k_ptr_t data;
					AW(data).lo = val0_lo;
					AW(data).hi = val0_hi;
					find_data_in_list(areas, data, ptr, 8,
							false);
				}
				if (unlikely(tag1_hi == E2K_AP_HI_ETAG &&
					     tag1_lo == E2K_AP_LO_ETAG)) {
					e2k_ptr_t data;
					AW(data).lo = val1_lo;
					AW(data).hi = val1_hi;
					find_data_in_list(areas, data, ptr + 16,
							8, false);
				}
			}
		} else {
			clean_descriptors_in_psp(areas, start, end, false);
		}
	} CATCH_USR_PFAULT {
		clear_ts_flag(ts_flag);
		return -EFAULT;
	} END_USR_PFAULT;

	clear_ts_flag(ts_flag);

	return 0;
}

static int clean_descriptors_test_walk(unsigned long start, unsigned long end,
				struct mm_walk *walk)
{
	unsigned long vm_flags = walk->vma->vm_flags;

	if ((vm_flags & (VM_PFNMAP|VM_HW_STACK_PCS)) || !(vm_flags & VM_READ))
		return 1;

	return 0;
}

static int clean_descriptors_pte_range(pmd_t *pmd, unsigned long addr,
		unsigned long end, struct mm_walk *walk)
{
	struct rb_root_cached *areas = walk->private;
	const struct vm_area_struct *vma = walk->vma;
	bool proc_stack = !!(vma->vm_flags & VM_HW_STACK_PS);
	const pte_t *pte;
	spinlock_t *ptl;
	int ret = 0;

	if (pmd_none(*pmd))
		goto out;

	if (pmd_trans_unstable(pmd)) {
		ret = clean_descriptors_range_user(areas, addr, end, proc_stack);
		goto out;
	}

	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	for (; addr != end; pte++, addr += PAGE_SIZE) {
		if (!pte_none(*pte)) {
			ret = clean_descriptors_range_user(areas, addr,
					addr + PAGE_SIZE, proc_stack);
			if (ret)
				goto out;
		}
	}
	pte_unmap_unlock(pte - 1, ptl);

out:
	cond_resched();
	return ret;
}

#ifdef CONFIG_HUGETLB_PAGE
/* This function walks within one hugetlb entry in the single call */
static int clean_descriptors_hugetlb_range(pte_t *ptep, unsigned long hmask,
				 unsigned long addr, unsigned long end,
				 struct mm_walk *walk)
{
	struct rb_root_cached *areas = walk->private;
	pte_t pte;
	int ret = 0;

	pte = huge_ptep_get(ptep);
	if (!pte_none(pte))
		ret = clean_descriptors_range_user(areas, addr, end, false);

	cond_resched();

	return ret;
}
#endif /* HUGETLB_PAGE */

static int clean_descriptors_copies(struct rb_root_cached *areas)
{
	struct pt_regs *regs = current_pt_regs();
	u64 pshtp_size;
	int ret;
	struct mm_walk_ops clean_descriptors_walk = {
		.test_walk = clean_descriptors_test_walk,
		.pmd_entry = clean_descriptors_pte_range,
#ifdef CONFIG_HUGETLB_PAGE
		.hugetlb_entry = clean_descriptors_hugetlb_range,
#endif
	};

	/*
	 * Parse part of user stack spilled to kernel
	 */
	pshtp_size = GET_PSHTP_MEM_INDEX(regs->stacks.pshtp);
	if (pshtp_size) {
		unsigned long ptr, end, flags;

		ptr = AS(current_thread_info()->k_psp_lo).base;
		end = ptr + pshtp_size;

		raw_all_irq_save(flags);
		NATIVE_FLUSHCPU;
		clean_descriptors_in_psp(areas, ptr, end, true);
		raw_all_irq_restore(flags);
	}

	stop_all_children_and_parent();

	down_read(&current->mm->mmap_sem);
	ret = walk_page_range(current->mm, 0, current->mm->highest_vm_end,
			&clean_descriptors_walk, areas);
	up_read(&current->mm->mmap_sem);

	wakeup_all_children_and_parent();

	return ret;
}

/*
 * Clean freed user memory and destroy freed descriptors in memory.
 */
int clean_single_descriptor(e2k_ptr_t descriptor)
{
	unsigned long ptr, size;
	struct interval_tree_node it_entry;
	struct rb_root_cached areas = RB_ROOT_CACHED;

	ptr = AS(descriptor).ap.base;
	size = AS(descriptor).size;

	/* Make a copy of a list */
	if (!size)
		return 0;

	it_entry.start = ptr;
	it_entry.last = ptr + size - 1;
	interval_tree_insert(&it_entry, &areas);

	/* Clean all descriptor copies from user memory */
	return clean_descriptors_copies(&areas);
}
/*
 * Clean freed user memory and destroy freed descriptors in memory.
 */
int clean_descriptors(void __user *list_descriptors, unsigned long list_size)
{
	int i, res;
	void __user *addr;
	e2k_ptr_t descriptor;
	u8 tag_lo, tag_hi, tag;
	unsigned long ptr, size;
	struct interval_tree_node *it_array;
	struct rb_root_cached areas = RB_ROOT_CACHED;

	/* We need a copy of a list, because user memory whould be cleaned */
	it_array = kmalloc_array(list_size, sizeof(it_array[0]), GFP_KERNEL);
	if (!it_array)
		return -ENOMEM;

	for (i = 0, addr = list_descriptors; i < list_size; i++, addr += 16) {
		TRY_USR_PFAULT {
			NATIVE_LOAD_TAGGED_QWORD_AND_TAGS(addr,
					AW(descriptor).lo, AW(descriptor).hi,
					tag_lo, tag_hi);
		} CATCH_USR_PFAULT {
			res = -EFAULT;
			goto free_list;
		} END_USR_PFAULT

		tag = (tag_hi << 4) | tag_lo;
		if (unlikely(tag != ETAGAPQ)) {
			pr_info_ratelimited("%s: bad descriptor extag 0x%x hiw=0x%lx low=0x%lx ind=%d\n",
					__func__, tag,
					AW(descriptor).hi, AW(descriptor).lo, i);
			pr_info_ratelimited("%s: list_descriptors: 0x%lx / list_size=%ld\n",
					__func__, list_descriptors, list_size);
			res = -EFAULT;
			goto free_list;
		}

		ptr = AS(descriptor).ap.base;
		size = AS(descriptor).size;
		if (!size)
			continue;

		/* Set memory to empty values */
		res = mem_set_empty_tagged_dw((void __user *) ptr, size,
					0x0baddead0baddead); /*freed mem mark*/
		if (res)
			goto free_list;

		/* Make a copy of a list. Here we check that
		 * there are no intersections between areas -
		 * this fact is used in find_data_in_list() */
		if (unlikely(interval_tree_iter_first(&areas, ptr,
				ptr + size - 1))) {
			pr_info_once("sys_clean_descriptors: intersection between passed areas found\n");
			res = -EINVAL;
			goto free_list;
		}

		it_array[i].start = ptr;
		it_array[i].last = ptr + size - 1;
		interval_tree_insert(&it_array[i], &areas);
	}
	/* Clean all descriptor copies from user memory */
	res = clean_descriptors_copies(&areas);

free_list:
	kfree(it_array);
	return res;
}
