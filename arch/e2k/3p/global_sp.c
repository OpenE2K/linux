
#include <linux/slab.h>
#include <linux/mman.h>
#include <linux/pagemap.h>

#include <asm/e2k_api.h>
#include <asm/3p.h>
#include <asm/e2k_ptypes.h>
#include <asm/e2k_debug.h>
#include <asm/pgalloc.h>
#include <asm/processor.h>
#include <asm/console.h>

#include <asm/cpu_regs_access.h>

#undef	DEBUG_TRAP_CELLAR
#undef	DbgTC
#define	DEBUG_TRAP_CELLAR	0	/* DEBUG_TRAP_CELLAR */
#define DbgTC(...)		DebugPrint(DEBUG_TRAP_CELLAR ,##__VA_ARGS__)


/*
 * The problems of multithreading
 *
 * I. PROBLEM
 * If a stack pointer is written to a global variable seen by other threads
 * there is a problemm accessing it from those threads. There are two
 * possibilities:
 *    1) 'psl' of the reading thread is greater or equal to 'psl' stored in
 *   the pointer. In this case the thread will access not the stack from
 *   which this pointer originated but rather from its own stack (as a
 *   consequence of having the highest part of stack address stored in the
 *   'SBR' per-thread register).
 *     There is also a possibility that although psl is valid (from the point
 *   of view of that thread) the actual address is not - then reading will
 *   generate exc_page_miss or something like that and the process will be
 *   killed with SIGSEGV.
 *    2) 'psl' of the reading thread is less than 'psl' stored in the pointer.
 *   The thread receives exc_illegal_operand and the process is terminated
 *   with SIGILL.
 *
 * II. SOLUTION
 * So the solution is to replace SAP's written to global variables with some
 * invalid value and let the interrupt handler deal with everything. But
 * the written SAP might be pointing to another SAP which points to array
 * of SAP's etc - thus it's impossible to follow all stack pointers in all
 * threads (since that chain of pointers may change at *any* time).
 *
 * There are some subtleties to consider:
 *
 *   1. Since stack addresses are reused, two identical pointers to a stack
 * can point to different values (and even to variables with different
 * types). So to catch such accesses (which as we assume are invalid)
 * the 'age' of a pointer must be keeped track of.
 *
 *   2. Lifetime of any given stack pointer written to global variable
 * is unknown - any thread can read it to a local register which can live
 * forever. So the 'age' of pointers grows indefinitly.
 *
 *   3. It is enough to increase the 'age' on every function return -
 * since this is the only case of a pointer invalidation which is not
 * handled by hardware.
 * This can be optimized further - it is enough to increase the 'age'
 * only on the returns for which there is a global pointer pointing to
 * the released stack frame.
 *
 *   4. So every access to another thread's stack must generate an interrupt.
 * But half-speculative loads can only generate exc_page_miss, so for example
 * just clearing read/write bits in AP is not an option - half-speculative
 * loads from such AP's will only write diagnostic (DP).
 *
 * In current implementation there is an area starting at START_VAL
 * (START_VAL == thread_info->multithread_address) which all created AP's
 * are pointing to. Every new AP created from SAP (when that SAP is written
 * to a global variable or to another thread's stack) is calculated like this:
 * 	AP.size = SAP.size
 * 	AP.index = SAP.index
 * 	AP.base = START_VAL + index;
 * 	index += AP.size
 * So the address in AP is acting as 'age'.
 *
 *   5. Since the address in AP is acting as 'age', when we run out of space
 * in that area we cannot do anythyng anymore. The size of the area is defined
 * at compile time in MAX_MULTITHREAD_SIZE.
 *
 *   6. Changing SAP's to AP's is required only when multithreading. So until
 * there is a second thread we only keep track of globals holding pointers to
 * stack but do not substitute SAP to AP.
 *
 *   7. When SAP is changed to AP we mark ALL frames in current stack to
 * generate exc_last_wish on return. This because informations and pointers
 * in our stack can change at any time, and the other threads accessing
 * our stack must be informed about it.
 *
 * Actually this is an overkill - it is enough to mark only those frames
 * to which that SAP *might point in a future*. So if the SAP is pointing to
 * int (4 bytes) then we know that there will not be any lists in the future
 * pointing to other frames and it is enough to mark with 'last wish' only
 * the frame to which that SAP is pointing.
 *
 *   8. A couple of words about 'age'.
 * In current implementation when last wish interrupt is generated, we add
 * to the globals list a new element with type "TYPE_BOUND" which stores
 * thread ID, psl and time.
 * 	thread ID == current->pid
 * 	psl == PUSD.psl
 * 	time == index
 * where 'index' is the same as in 4).
 *
 * This information is enough to check whether access by some SAP converted
 * to AP is valid.
 *
 *
 * And it would of great help to have hardware support for storing thread
 * number in SAP (even better - store both thread number AND number of
 * last_wish interrupts in SAP). Then this would be SO MUCH faster and
 * simpler...
 */


/*
 *  To check validation of stack pointers which was written in global
 *  for multi_threading 
 */  
#define IS_THIS_THREAD(x) (x->type == TYPE_GLOBAL && current->pid == x->pid)
#define IS_MULTITHREADING (WAS_MULTITHREADING)

typedef u32	Syllabe_t;

typedef struct {
  unsigned mdl : 4;
  unsigned lng : 3;
  unsigned nop : 3;
  unsigned lm  : 1;
  unsigned x   : 1;
  unsigned s   : 1;
  unsigned sh  : 1;
  unsigned c   : 2; // it is mask now
  unsigned cd  : 2; 
  unsigned pl  : 2;
  unsigned ale : 6;
  unsigned al  : 6;
} HS_syllable_fields_t;

#undef DEBUG_SP
//#define DEBUG_SP
#ifdef DEBUG_SP
 #define CHECK_SIZE(x, zz)                                              \
       if ((p_psl - l_psl)* sizeof(e2k_mem_crs_t)                       \
                > AS_STRUCT(regs->stacks.pcsp_hi).ind) {                \
           printk("CHECK_SIZE %s p_psl=%ld  l_psl=%ld ind = %ld \n",    \
                x, p_psl, l_psl, AS_STRUCT(regs->stacks.pcsp_hi).ind);  \
           return zz;                                                   \
       }    
#else  /* !DEBUG_SP */
 #define CHECK_SIZE(x, zz) 
#endif /* DEBUG_SP */

typedef	union HS_syllable_union {
	HS_syllable_fields_t	fields;
	Syllabe_t		word;
} HS_syllable_struct_t;

#define AL(w)   (((HS_syllable_fields_t*)&w)->al)
#define ALE(w)  (((HS_syllable_fields_t*)&w)->ale)
#define PL(w)   (((HS_syllable_fields_t*)&w)->pl)
#define Cd(w)   (((HS_syllable_fields_t*)&w)->cd)
#define C(w)    (((HS_syllable_fields_t*)&w)->c)
#define SH(w)   (((HS_syllable_fields_t*)&w)->sh)
#define S(w)    (((HS_syllable_fields_t*)&w)->s)
#define lm(w) (((HS_syllable_fields_t*)&w)->lm)
#define NOP_CNT(w)  (((HS_syllable_fields_t*)&w)->nop)
#define LNG(w)  ((((HS_syllable_fields_t*)&w)->lng)+1)
#define HS_LNG(w)  (((HS_syllable_fields_t*)&w)->lng)
#define MDL(w)  (((HS_syllable_fields_t*)&w)->mdl)

typedef struct
{

	unsigned ctcond : 9;
	unsigned xxx    : 1;
	unsigned ctop   : 2;
	unsigned aa     : 4;
	unsigned alc    : 2;
	unsigned abp    : 2;
	unsigned xx     : 1;
	unsigned abn    : 2;
	unsigned abg    : 2;
	unsigned x      : 1;
	unsigned vfdi   : 1;
	unsigned srp    : 1;
	unsigned bap    : 1;
	unsigned eap    : 1;
	unsigned ipd    : 2;

} SS_syllable_fields_t;


typedef	union SS_syllable_union {
	SS_syllable_fields_t	fields;
	Syllabe_t		word;
} SS_syllable_struct_t;

#define SSIPD(w)    (((SS_syllable_fields_t*)&w)->ipd)
#define SSEAP(w)    (((SS_syllable_fields_t*)&w)->eap)
#define SSBAP(w)    (((SS_syllable_fields_t*)&w)->bap)
#define SSSRP(w)    (((SS_syllable_fields_t*)&w)->srp)
#define SSVFDI(w)   (((SS_syllable_fields_t*)&w)->vfdi)
#define SSABG(w)    (((SS_syllable_fields_t*)&w)->abg)
#define SSABN(w)    (((SS_syllable_fields_t*)&w)->abn)
#define SSAA(w)     (((SS_syllable_fields_t*)&w)->aa)
#define SSCTOP(w)   (((SS_syllable_fields_t*)&w)->ctop)
#define SSCTCOND(w) (((SS_syllable_fields_t*)&w)->ctcond)

typedef struct {
	unsigned param   : 28;
	unsigned opc     : 4;
} CS1_syllable_fields_t;

typedef	union CS1_syllable_union {
	CS1_syllable_fields_t	fields;
	Syllabe_t		word;
} CS1_syllable_struct_t;


int gsp_is_return(struct pt_regs *regs) 
{

	e2k_rwp_struct_t tir_lo;
	u64 ip;
	HS_syllable_struct_t hs;	
	SS_syllable_struct_t ss;
	int ctop;

	/* Pointer on the instruction that caused the exception
         * is located in corresponding TIR register.
         */  
	tir_lo.E2K_RWP_reg = regs->trap->TIR_lo;
	ip = tir_lo.E2K_RWP_base;

	DbgTC("IP = %lx\n", ip);

	/* We need to read Header Syllabe of instruction interrupted
         * to determine general instruction structure
         */ 

	if (get_user(AS_WORD(hs), (Syllabe_t *) ip) == -EFAULT) {
		return 0;
	}

	DbgTC("HS = %x\n", AS_WORD(hs));

	/* Check presence of Stub Syllabe */
	if (S(hs)) {
		DbgTC("SS does exist\n");
	} else {		
		DbgTC("SS doesn't exist\n");
		return 0;
	}

	/* Stub Syllabe encodes different short fragment of command */
	if (get_user(AS_WORD(ss),
	     (Syllabe_t *) (ip + sizeof (HS_syllable_struct_t))) == -EFAULT) {
		return 0;
	}

	DbgTC("SS = %x\n", AS_WORD(ss));

	/* CTOP field encodes CTPR register in use */
	ctop = SSCTOP(ss);

	/* RETURN always uses CTPR3 */
	if (ctop != 3) {
		DbgTC("SS.CTOP !=3 !!! SS.CTOP = %d\n", ctop);
		return 0;
	} else {		
		DbgTC("SS.CTOP == 3\n");
	}

	/* CTPR3.opc field should match RETURN operation indicator */
	if (AS_STRUCT(regs->ctpr3).opc != RETURN_CT_OPC) {
		DbgTC("ctpr3.opc != RETURN_CT_OPC\n");
		return 0;
	} else {
		DbgTC("ctpr3.opc == RETURN_CT_OPC\n");
	}

	return 1;
}

/*
 * set last_wish for all procedures which psl < l_psl
 */ 
static void set_last_wish(struct pt_regs *regs, int l_psl, int p_psl)
{                          
	e2k_psr_t               psr;
	e2k_mem_crs_t           *cr;
        int                     i, ind;

        E2K_FLUSHC;

        if (p_psl == l_psl) {
		AS_WORD(psr) = AS_STRUCT(regs->crs.cr1_lo).psr;
		AS_STRUCT(psr).lw = 1;
		AS_STRUCT(regs->crs.cr1_lo).psr = AS_WORD(psr);
		DbgTC("lw is SET \n");
        }        

	cr = (e2k_mem_crs_t *) (regs->stacks.pcsp_lo.PCSP_lo_base +
					   regs->stacks.pcsp_hi.PCSP_hi_ind);
	cr -= (p_psl - l_psl);

	E2K_FLUSH_WAIT;

	DbgTC("set_last_wish  l_psl=%d p_psl=%d base=0x%llx ind=0x%x cr=0x%lx\n",
		l_psl, p_psl, regs->stacks.pcsp_lo.PCSP_lo_base,
		regs->stacks.pcsp_hi.PCSP_hi_ind, cr);

        ind = regs->stacks.pcsp_hi.PCSP_hi_ind/sizeof(e2k_mem_crs_t) - (p_psl - l_psl);
        for(i = ind; i >= 0; i--) {
                AS_WORD(psr) =  AS_STRUCT(cr->cr1_lo).psr;
                if (!AS_STRUCT(psr).pm) {
		        AS_STRUCT(psr).lw = 1;
			AS_STRUCT(cr->cr1_lo).psr = AS_WORD(psr);
	                DbgTC("set_last_wish for l_psl=%d cr=0x%lx\n", i, cr);
                }    
                cr -=1;
        }
}

#undef	GET_IP
#define	GET_IP  ( AS(regs->crs.cr0_hi).ip << E2K_ALIGN_INS )

/* change SAP to AP with "rw" == 0 and unique address */

                /* for type TYPE_INIT */                        
#define START_VAL current_thread_info()->multithread_address
#define GET_CURR_ADDRESS(x) (x->lcl_psl + START_VAL)
#define WAS_MODIFIED(x)         (x->old_address)
#define INCR_CURR_ADDRESS(entry, x) entry->lcl_psl+= x
#define IS_CHANGED_ADDRESS(entry, x) ( x >= START_VAL && x <= GET_CURR_ADDRESS(entry))
#define MAX_MULTITHREAD_SIZE (PAGE_SIZE * 100)
#define CAN_INCR_CURR_ADDRESS(entry, x) (entry->lcl_psl + x\
                                                        < MAX_MULTITHREAD_SIZE)
                /* for type TYPE_BOUND */                        
#define GET_TIME(x)             (x->global_p) 

e2k_addr_t get_valid_address(e2k_addr_t address, global_store_t **record);
void  down_read_lock_multithread(void);
void  up_read_lock_multithread(void);
static void print_all_records(void);


global_store_t* get_init_record(void)
{
        global_store_t *entry = current_thread_info()->g_list;
 
      	while (entry != NULL)
	{
                if (entry->type == TYPE_INIT) {
                        return entry;
                 }
		entry = entry->next;
	}
        return NULL;
}

/*
 *   create  new record and change SAP to AP
 *      addr - address in stack ( was readed SAP) 
 */   
static void  create_new_record(pt_regs_t *regs,e2k_addr_t  addr,
                                         long multithread_addr)
{
        global_store_t  *list = current_thread_info()->g_list;
	global_store_t  *new, *last;
        global_store_t  *init = get_init_record();
	register unsigned long	tmp_lo, tmp_hi;		
        union {e2k_rwsap_lo_struct_t sap_lo; e2k_rwap_lo_struct_t ap_lo;} lo;
        union {e2k_rwsap_hi_struct_t sap_hi; e2k_rwap_hi_struct_t ap_hi;} hi; 
	unsigned long	address;		
	unsigned long	base;
	e2k_addr_t	usbr;
        global_store_t  *pnt_record;

        DbgTC("addr=0x%lx multithread_addr=0x%lx\n",
                                        addr, multithread_addr);
        if (get_valid_address(multithread_addr, &pnt_record)==0) {
		DbgTC("bad multithread_addr=%lx\n",
                        multithread_addr);
		return;
        }    


	new = (global_store_t *) kmalloc(sizeof(global_store_t), GFP_ATOMIC);
	if (!new) {
		DbgTC("no memory\n");
		return;
	}

	new->lcl_psl = 0;
	new->global_p = 0;
	new->next = NULL;
        /* for multithreading support */
        new->type = TYPE_GLOBAL;
        new->pid = pnt_record->pid;
        new->sbr = pnt_record->sbr;
        new->word1 = 0;
        new->word2 = 0;
        new->old_address = 0;


	usbr = regs->stacks.sbr;
        E2K_LOAD_TAGGED_QWORD(addr, AS_WORD(lo.sap_lo),
                                              AS_WORD(hi.sap_hi));
        address = GET_CURR_ADDRESS(init);
	if (!CAN_INCR_CURR_ADDRESS(init, AS_STRUCT(hi.sap_hi).size)) {
		printk(" create_new_record very many SAP IND=0x%lx MAX=0x%lx CURR_SIZE=0x%x\n",
			GET_CURR_ADDRESS(init) - START_VAL,
			MAX_MULTITHREAD_SIZE, AS_STRUCT(hi.sap_hi).size);
		return;
	}    
        INCR_CURR_ADDRESS(init, AS_STRUCT(hi.sap_hi).size);
        base = AS_STRUCT(lo.sap_lo).base;
        new->word2 = AS_WORD(hi.sap_hi);

        /* field base for SAP and AP is different */
        AS_STRUCT(lo.ap_lo).base = address;
        AS_AP_STRUCT(lo.ap_lo).itag = E2K_AP_ITAG;
        tmp_lo = AS_WORD(lo.ap_lo);
        tmp_hi = AS_WORD(hi.ap_hi);
        E2K_STORE_TAGGED_QWORD((e2k_addr_t)addr, tmp_lo, tmp_hi,
                                        E2K_AP_LO_ETAG, E2K_AP_HI_ETAG);

        new->new_address = address;
        new->old_address = base;

	if (list == NULL) {
		new->prev = NULL;
		current_thread_info()->g_list = list = new;
	} else {
		last = list;
		/* semaphore is required */
		while (last->next != NULL)
			last = last->next;

		new->prev = last;
		last->next = new;
	}
}    

/*
 * If the result of loadQ (operand - marked AP) is SAP
 * than for different thread must be changed to new marked AP
 *  (if address of SAP is valid or NULL othervise) 
 */
void change_sap(int cnt, pt_regs_t *regs, e2k_addr_t addr,
		long multithread_addr)
{
	struct trap_pt_regs *trap = regs->trap;
	trap_cellar_t *tcellar = trap->tcellar;
	e2k_addr_t usbr;

	usbr = regs->stacks.sbr;
        
        addr -= 8; /* pointed to second word */
	DbgTC("cnt=%d addr=0x%lx usbr=0x%lx "
              "GET_IP=%lx tag(addr)=%x tag(addr+8)=%x pid=%d\n",
                                cnt, addr, usbr, GET_IP,
                                E2K_LOAD_TAGD(addr), E2K_LOAD_TAGD(addr+8),
                                current->pid);

	if (!WAS_MULTITHREADING)
		return;

	if (DEBUG_TRAP_CELLAR)
		print_all_TC(tcellar, trap->tc_count);

	DbgTC("change_sap *addr=0x%lx *(addr + 8)=0x%lx tag(addr)=%x  tag(addr+8)=%x\n",
              *(long*)addr, *(long*)(addr+8),
              E2K_LOAD_TAGD(addr), E2K_LOAD_TAGD((addr+8)));

        down_read_lock_multithread();
	if (IS_SAP_LO(addr) && IS_SAP_HI(addr + 8)) {
                /* change SAP => AP */
                create_new_record(regs, addr, multithread_addr);
        }
        up_read_lock_multithread();
}
   
static int change_sap_to_ap(trap_cellar_t *tcellar, struct pt_regs *regs,
                                          global_store_t* record, int no_check)
{
	e2k_rwsap_lo_struct_t	sap_lo;
	e2k_rwsap_hi_struct_t	sap_hi;
	e2k_rwap_lo_struct_t	ap_lo;
	unsigned int		l_psl;		
	unsigned long		address;		
	unsigned long		base;
        unsigned long           *pnt;
        global_store_t          *init = get_init_record();

	DbgTC("no_check=%d record=%p CURR_ADDRESS=0x%lx"
                         " WAS_MODIFIED(record)=%lx sbr=%lx\n",
                         no_check, record, GET_CURR_ADDRESS(init),
                         WAS_MODIFIED(record),(regs==NULL)? 0 :regs->stacks.sbr); 
	/* Verify if the data is SAP */
	if (record->global_p && !WAS_MODIFIED(record) &&
            (no_check || (IS_SAP_LO(&(tcellar[0].data)) && 
	     IS_SAP_HI(&(tcellar[1].data)))) ) {
	        register unsigned long	tmp_hi, tmp_lo;		

		AS_WORD(sap_lo) = tcellar[0].data;
		AS_WORD(sap_hi) = tcellar[1].data;
                record->word1 = AS_WORD(sap_lo);
                record->word2 = AS_WORD(sap_hi);
		l_psl = AS_STRUCT(sap_lo).psl;
                AS_STRUCT(sap_lo).psl = 0;
                sap_lo.E2K_RWSAP_lo_itag = AP_ITAG;
 //               AS_STRUCT(sap_lo).rw = RW_DISABLE;
                address = GET_CURR_ADDRESS(init);
                if (!CAN_INCR_CURR_ADDRESS(init, AS_STRUCT(sap_hi).size)) {
                    printk(" change_sap_to_ap  very many SAP IND=0x%lx MAX=0x%lx CURR_SIZE=0x%x\n",
                           GET_CURR_ADDRESS(init) - START_VAL,     
                           MAX_MULTITHREAD_SIZE, AS_STRUCT(sap_hi).size);
                    return 0;
                }    
                INCR_CURR_ADDRESS(init, AS_STRUCT(sap_hi).size);
                base = AS_STRUCT(sap_lo).base;
                /* field base for SAP and AP is different */
		AS_WORD(ap_lo) = AS_WORD(sap_lo);
                AS_STRUCT(ap_lo).base = address;
                record->new_address = address;
                /* in tcellar base already increased by regs->stacks.sbr*/
                record->old_address = base;
                AS_AP_STRUCT(ap_lo).itag = E2K_AP_ITAG;
                tmp_lo = AS_WORD(ap_lo);
                tmp_hi = AS_WORD(sap_hi);
                if (!no_check) {
                        pnt = &tcellar[0].data;
                } else {
                        pnt = (unsigned long*)(record->global_p);
                } 
                E2K_STORE_TAGGED_QWORD((e2k_addr_t)pnt, tmp_lo, tmp_hi,
                                        E2K_AP_LO_ETAG, E2K_AP_HI_ETAG);

                if (!no_check && IS_AP_LO(&(tcellar[0].data)) && 
	                IS_AP_HI(&(tcellar[1].data)) ) {
		        DbgTC("now is AP\n");
                }    
		DbgTC("SAP.base=%lx  AP.base=%lx psl=%d tcellar[0].data=%lx tcellar[1].data=%lx CURR_SIZE=%x\n",
			base, address, l_psl,
                        tcellar[0].data, tcellar[0 +1].data,
                        AS_STRUCT(sap_hi).size);

                return 1;
	} 
        return 0;
}

global_store_t *first_record(void)
{
	global_store_t *new;

	new = (global_store_t *) kmalloc(sizeof(global_store_t), GFP_ATOMIC);
	if (!new) {
		DbgTC("no memory\n");
		return NULL;
	}
        NUM_THREAD(new) = 0; /*  (x->orig_psr_lw) */
	new->lcl_psl = 0;
	new->global_p = 0;
	new->next = NULL;
        new->pid = current->pid;
        new->old_address = 0;
	new->prev = NULL;
        new->type = TYPE_INIT;
	current_thread_info()->g_list = new;
        return new;

}

static void init_g_list(int from)
{
	global_store_t *entry = current_thread_info()->g_list;

	DbgTC("pid=%d, list %p START_VAL=%lx from=%d\n",
              current->pid, entry, START_VAL, from);
        
        if (!START_VAL) {
                START_VAL = (e2k_addr_t) vm_mmap(NULL, 0L, MAX_MULTITHREAD_SIZE,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, 0L);
        }    
        if (entry == NULL) {
                /* added new record to have common date for all threads */
                entry = first_record(); 
        }
        if (entry != NULL) {
                NUM_THREAD(entry) += from;
        }        
        if (!current_thread_info()->lock) {
                current_thread_info()->lock = (struct rw_semaphore *)
                                kmalloc(sizeof(struct rw_semaphore), GFP_ATOMIC); 
	        init_rwsem(current_thread_info()->lock);
        }    
        if (!current_thread_info()->lock) {
		DbgTC("no memory\n");
        }    
}    

/*
 * search all globals pointed to SAP and change it to AP
 * only for this thread 
 */
void mark_all_global_sp(struct pt_regs * regs, pid_t pid)
{
	struct trap_pt_regs *trap = regs->trap;
	global_store_t *entry = current_thread_info()->g_list;
        trap_cellar_t tcellar[2];
	int curr_count;

	DbgTC("pid=%d, list %p START_VAL=%lx\n",
              pid, entry, START_VAL);
	init_g_list(1);
        entry = current_thread_info()->g_list;

	if (trap) {
		curr_count = trap->curr_cnt;
		trap->curr_cnt = 0;
	}
 
      	while (entry != NULL)
	{
                if (entry->pid == pid && entry->type == TYPE_GLOBAL) {
                        tcellar[0].data = entry->word1;
                        tcellar[1].data = entry->word2;
                        change_sap_to_ap(tcellar, regs, entry, 1);
                }
		entry = entry->next;
	}

	if (trap)
		trap->curr_cnt = curr_count;

	DbgTC("exitting.\n");
}

static int is_valid_addr(global_store_t *entry, e2k_addr_t address,
                                                e2k_addr_t* offset)
{
	e2k_rwsap_hi_struct_t	sap_hi;
        long                    size ;

	DbgTC("address=%lx entry->new_address=%lx entry=%p\n",
                                        address, entry->new_address, entry);
        AS_WORD(sap_hi) = entry->word2;
        size = AS_STRUCT(sap_hi).size;
        *offset = 0;
        if (entry->new_address <= address &&
                                entry->new_address + size > address) { 
                *offset = address - entry->new_address;
 	        DbgTC("size=%lx\n", size);
                return  1;
        }
        return 0;
}

/*
 *    check that is address now in stack
 */

e2k_addr_t is_correct_entry(global_store_t *record)
{
	global_store_t *entry = current_thread_info()->g_list;

	DbgTC("is_correct_entry new_address=%lx record->pid=%d "
              " record->lcl_psl=%d\n",
              record->new_address, record->pid, record->lcl_psl);
	while (entry != NULL)
	{
                if (entry->type == TYPE_BOUND && entry->pid == record->pid &&
                    record->lcl_psl == entry->lcl_psl) {
	                DbgTC("GET_TIME(entry)=0x%lx \n",
                             GET_TIME(entry));
                        if (GET_TIME(entry) > record->new_address) {
                                return 0;
                        } else {
                            /* very old return */
                                return 1;
                        }    
                }    
		entry = entry->next;
	}
        return 1;
}

e2k_addr_t get_valid_address(e2k_addr_t address, global_store_t **record)
{
	global_store_t *entry = current_thread_info()->g_list;
        e2k_addr_t      offset;
	DbgTC("address=%lx\n", address);
	while (entry != NULL)
	{
        	if (entry->type == TYPE_GLOBAL &&
                        is_valid_addr(entry, address, &offset)) {
                        if (!is_correct_entry(entry)) {
                            return 0;
                        }    
                        *record = entry; 
	                DbgTC("address=%lx old_address=%lx"
                              " pid =%d \n",
                             address, entry->old_address + offset, entry->pid);
                        return entry->old_address + offset;
                }    
		entry = entry->next;
	}
        return 0;
}

static void set_new_bound(int psl, struct pt_regs *regs)
{
	global_store_t *entry = current_thread_info()->g_list;
        global_store_t *new, *last, *list;
        global_store_t *init = get_init_record();

        if (!WAS_MULTITHREADING) {
                return;
        }        
	DbgTC("psl=%d sbr=0x%lx GET_CURR_ADDRESS=%lx\n",
                            psl, regs->stacks.sbr, GET_CURR_ADDRESS(init));
	while (entry != NULL) {
        	if (entry->type == TYPE_BOUND && entry->pid == current->pid &&
                    entry->lcl_psl == psl) {
                        /* update this record */
                        GET_TIME(entry) = GET_CURR_ADDRESS(init); /* as time */
                        entry->sbr = regs->stacks.sbr;
		        DbgTC("update entry=%p\n",entry);
                        return;

                }
                entry = entry->next;
        }    

	new = (global_store_t *) kmalloc(sizeof(global_store_t), GFP_ATOMIC);
	if (!new) {
		DbgTC("no memory\n");
		return;
	}

        DbgTC("new entry=%p\n",new);
	new->pid = current->pid;
	new->lcl_psl = psl;
	new->next = NULL;
        new->type = TYPE_BOUND;
        new->sbr = regs->stacks.sbr;
        GET_TIME(new) = GET_CURR_ADDRESS(init); /* as time */
        INCR_CURR_ADDRESS(init, 16);
        list = current_thread_info()->g_list;
	if (list == NULL) {
		new->prev = NULL;
		current_thread_info()->g_list = list = new;
	} else {
		last = list;
		while (last->next != NULL)
			last = last->next;

		new->prev = last;
		last->next = new;
	}
}    

/*
 * This code must done :
 *   check that address was changed (by change_sap_to_ap())
 *   old address is valid
 *   access to old address can call page_fault
 *   change tcellar (old address => address)
 *   change vma && address
 *   result 0 - this address invalid
 *          1 - changed address 
 *          2 - value of address may be changed 
 *          3 - unknown addr
 */
int interpreted_ap_code(struct pt_regs *regs, struct vm_area_struct **vma,
                                                      e2k_addr_t *address)
{
	struct trap_pt_regs	*trap = regs->trap;
	trap_cellar_t           *tcellar = trap->tcellar;
	int                     curr_count = trap->curr_cnt;
	int                     tc_count = trap->tc_count /3;
        unsigned long           addr = *address; 
        e2k_addr_t              old_address;
	e2k_rwap_lo_struct_t	ap_lo;
	register unsigned long	tmp;
        struct vm_area_struct   *new_vma;
        tc_opcode_t             opcode;
        int                     i, count =-1; 
        global_store_t          *init = get_init_record();
        global_store_t          *pnt_record = NULL;

	DbgTC("interpreted_ap_op addr=%lx curr_count=%d tc_count=%d\n",
					addr, curr_count, tc_count);
        /* find our count */
        for(i = curr_count; i < tc_count; i++ ) {
                AW(opcode) = AS(tcellar[i].condition).opcode;
                if (tcellar[i].address == addr) {
                        count = i;
                        break;
                }        
        } 
        if (count == -1) {
		DbgTC("interpreted_ap_op not find count\n");
                return 3;
        }    
        AW(opcode) = AS(tcellar[count].condition).opcode;
        if (!IS_CHANGED_ADDRESS(init, addr)) {
		DbgTC("interpreted_ap_op not changed address\n");
                return 3;
        }    
	DbgTC("interpreted_ap_op count=%d\n", count);
	if (DEBUG_TRAP_CELLAR)
		print_all_TC(trap->tcellar, trap->tc_count);

	/* Verify if the data is AP */
	if (0 && AS(opcode).fmt == 5 && 
            (!IS_AP_LO(&(tcellar[count].data)) && 
	     !IS_AP_HI(&(tcellar[count].data))) ) {
		DbgTC("interpreted_ap_op not AP IS_AP_LO =%d IS_AP_HI=%d\n",
                      IS_AP_LO(&(tcellar[count].data)), 
                      IS_AP_HI(&(tcellar[count].data)));
                return 2;


        }
        old_address = get_valid_address(*address, &pnt_record);
	DbgTC("interpreted_ap_op old_address=%lx pid=%d curr->pid=%d fmt=%d\n",
                                        old_address,
                                        (old_address)?pnt_record->pid:-1,
                                        current->pid, AS(opcode).fmt);
        if (old_address == 0) {
                return 0;   
        }
        tcellar[count].address = old_address;

        // print_user_address_ptes(current->mm, old_address);
	DbgTC("interpreted_ap_op old_address=%lx *old_address=%lx\n",
		old_address, *(long *)old_address);
        *address = old_address;

        if (IS_AP_LO(&(tcellar[count].data))) {
	        AS_WORD(ap_lo) = tcellar[count].data;
                AS_STRUCT(ap_lo).base = old_address;
                tmp = AS_WORD(ap_lo);
                E2K_STORE_VALUE_WITH_TAG(&tcellar[count].data, tmp,
                                                E2K_AP_LO_ETAG);
        }

	new_vma = find_vma(current->mm, old_address);
	DbgTC("interpreted_ap_op tcellar[%d].data=%lx  new_vma=%p\n",
               count, tcellar[count].data, new_vma);
        if (!new_vma) {
                return 0;
        }
        /* To garantee that old_address has pte */
        /* TODO*/
        if (AS(opcode).fmt == 5) {
                if (current->pid != pnt_record->pid) {
                        return 2;
                } else {
                        return 1;
                }    
        }    
        return 1;
}    

static void delete_list(global_store_t *entry)
{
	global_store_t		*prev, *next;

	prev = entry->prev;
	next = entry->next;
	if (prev != NULL && next != NULL) {
		prev->next = next;
		next->prev = prev;
	} else {
		if (prev != NULL && next == NULL) {
			prev->next = NULL;
		} else {
			if (prev == NULL && next != NULL) {
				next->prev = NULL;
				current_thread_info()->g_list = next;
			} else {
				current_thread_info()->g_list = NULL;
			}
		}
	}
}

void free_global_multithread(void)
{    
	global_store_t *entry = current_thread_info()->g_list;
	global_store_t *advance_entry;
        
	DbgTC("pid=%d, NUM_THREAD=%d \n",
                                current->pid, NUM_THREAD(entry));
        NUM_THREAD(entry)--;
        if (NUM_THREAD(entry) == 0) {
                while (entry != NULL)
	        {
			advance_entry = entry->next;
                        delete_list(entry);
		        kfree((void *) entry);
		        entry = advance_entry;
                }    
        } 
        if (current_thread_info()->lock) {
                kfree((void *)current_thread_info()->lock);
        }        
}

void free_global_sp(void)
{
	global_store_t *entry;
	global_store_t *advance_entry;
	struct mm_struct	*mm;

	mm = current->mm;
        if (!mm) {
	        return;
        }
	down_write(&mm->mmap_sem);
        entry = current_thread_info()->g_list;
	DbgTC("pid=%d, list %p\n", current->pid, entry);
        while (entry != NULL)
	{
		advance_entry = entry->next;	/* to avoid re-usage of   */
						/* an entry after kfree() */
                                /* entry->global_p == 0 is special record */
                if (entry->global_p && IS_THIS_THREAD(entry)) {
                        delete_list(entry);
		        kfree((void *) entry);
		        DbgTC("Entry %p freed\n", entry);
                }
		entry = advance_entry;
	}
        if (current_thread_info()->g_list) {
                free_global_multithread();
        }
        up_write(&mm->mmap_sem);
	DbgTC("exitting.\n");
}

global_store_t *new_record(global_store_t *list,
				      struct pt_regs *regs,
				      e2k_addr_t global,
				      unsigned int l_psl,
				      unsigned int p_psl)
{
	struct trap_pt_regs *trap = regs->trap;
	global_store_t *new, *last;
	trap_cellar_t   *tcellar = trap->tcellar;
	long            tc_count = trap->curr_cnt;


	new = (global_store_t *) kmalloc(sizeof(global_store_t), GFP_ATOMIC);
	if (!new) {
		DbgTC("no memory\n");
		return NULL;
	}

	new->lcl_psl = l_psl;
	new->global_p = global;
	new->next = NULL;
        /* for multithreading support */
        new->type = TYPE_GLOBAL;
        new->pid = current->pid;
        new->word1 = tcellar[tc_count].data;
        new->word2 = tcellar[tc_count + 1].data;
        new->old_address = 0;
        if (IS_MULTITHREADING) {
		DbgTC("global=%lx new=%lx pid=%d\n",
                                                global, new, new->pid);
                change_sap_to_ap(tcellar, regs, new, 0);
        }        
	if (list == NULL) {
		new->prev = NULL;
		current_thread_info()->g_list = list = new;
	} else {
		last = list;
		/* semaphore is required */
		while (last->next != NULL)
			last = last->next;

		new->prev = last;
		last->next = new;
	}

	if (l_psl == p_psl) {
		e2k_psr_t psr;
		AS_WORD(psr) = AS_STRUCT(regs->crs.cr1_lo).psr;
		if (AS_STRUCT(psr).lw) {
			DbgTC("lw was already set in CR1"
                              " l_psl=%d pid=%d\n", l_psl, current->pid);
		} else {
			DbgTC("lw was cleared in CR1 "
                              "l_psl=%d pid=%d\n", l_psl, current->pid);
			AS_STRUCT(psr).lw = 1;
			AS_STRUCT(regs->crs.cr1_lo).psr = AS_WORD(psr);
			DbgTC("lw is SET\n");
		}
		new->orig_psr_lw = AS_STRUCT(psr).lw;
	} else {
		e2k_mem_crs_t *cr;
		e2k_psr_t psr;
		DbgTC("l_psl != p_psl\n");
                E2K_FLUSHC;

		cr = (e2k_mem_crs_t *) (AS_STRUCT(regs->stacks.pcsp_lo).base +
					AS_STRUCT(regs->stacks.pcsp_hi).ind);
                CHECK_SIZE("new_record",new)
		DbgTC("cr = %p\n", cr);
		DbgTC("pcsp.base = %llx\n", AS(regs->stacks.pcsp_lo).base);
		DbgTC("pcsp.ind  = %x\n", AS(regs->stacks.pcsp_hi).ind);
		cr -= (p_psl - l_psl);

		E2K_FLUSH_WAIT;

		AS_WORD(psr) = AS_STRUCT(cr->cr1_lo).psr;
		if (AS_STRUCT(psr).lw) {
			DbgTC("lw was already set in memory\n");
		} else {
			DbgTC("lw was cleared in memory\n");
			AS_STRUCT(psr).lw = 1;
			AS_STRUCT(cr->cr1_lo).psr = AS_WORD(psr);
			DbgTC("lw is SET\n");
		}
		new->orig_psr_lw = AS_STRUCT(psr).lw;
	}
        if (DEBUG_TRAP_CELLAR) {
                print_all_records();
        }
	return new;
}

global_store_t *update_record(global_store_t *record,
					 struct pt_regs *regs, 
					 unsigned int l_psl,
				         unsigned int p_psl)
{
	struct trap_pt_regs *trap = regs->trap;
	unsigned int	old_psl;
	e2k_psr_t	psr;
	trap_cellar_t   *tcellar = trap->tcellar;
	long            tc_count = trap->curr_cnt;


	if (record == NULL) {
		DbgTC("record pointer is NULL\n");
		return NULL;
	}

	DbgTC("record pointer is %p\n", record);
        /* for multithreading support */
        record->pid = current->pid;
        record->word1 = tcellar[tc_count].data;
        record->word2 = tcellar[tc_count + 1].data;
        record->old_address = 0;

	old_psl = record->lcl_psl;

	if (old_psl == l_psl) {
		DbgTC("new local has the same psl.\n");
		return record; /* do nothing */
	}

	/* Clear old last wish */
	if (old_psl == p_psl) {
		AS_WORD(psr) = AS_STRUCT(regs->crs.cr1_lo).psr;
		if (AS_STRUCT(psr).lw) {
			DbgTC("lw was set in CR1\n");
			if (!record->orig_psr_lw) {
				AS_STRUCT(psr).lw = 0;
				AS_STRUCT(regs->crs.cr1_lo).psr = AS_WORD(psr);
				DbgTC("lw is CLEARED\n");
			} else {
				DbgTC("lw remain SET\n");
			}
		} else {
			DbgTC("lw was already cleared "
			      "in CR1\n");
		}
	} else {
		e2k_mem_crs_t *cr;
		DbgTC("l_psl != p_psl\n");

		cr = (e2k_mem_crs_t *) (AS_STRUCT(regs->stacks.pcsp_lo).base +
					AS_STRUCT(regs->stacks.pcsp_hi).ind);
                E2K_FLUSHC;

		DbgTC("cr = %p\n", cr);
		DbgTC("pcsp.base = %llx\n", AS(regs->stacks.pcsp_lo).base);
		DbgTC("pcsp.ind  = %x\n", AS(regs->stacks.pcsp_hi).ind);
		cr -= (p_psl - l_psl);
                CHECK_SIZE("update_record",record);

		E2K_FLUSH_WAIT;

		AS_WORD(psr) = AS_STRUCT(cr->cr1_lo).psr;
		if (AS_STRUCT(psr).lw) {
			DbgTC("lw was set in memory\n");
			if (!record->orig_psr_lw) {
				AS_STRUCT(psr).lw = 0;
				AS_STRUCT(cr->cr1_lo).psr = AS_WORD(psr);
				DbgTC("lw is CLEARED\n");
			} else {
				DbgTC("lw remain SET\n");
			}

		} else {
			DbgTC("lw was already cleared "
			      "in memory\n");
		}
	}


	/* Set new last wish */
	if (l_psl == p_psl) {
		AS_WORD(psr) = AS_STRUCT(regs->crs.cr1_lo).psr;
		if (AS_STRUCT(psr).lw) {
			DbgTC("lw was already set in CR1\n");
		} else {
			DbgTC("lw was cleared in CR1\n");
			AS_STRUCT(psr).lw = 1;
			AS_STRUCT(regs->crs.cr1_lo).psr = AS_WORD(psr);
			DbgTC("lw is SET\n");
		}
		record->orig_psr_lw = AS_STRUCT(psr).lw;
	} else {
		e2k_mem_crs_t *cr;
		DbgTC("l_psl != p_psl\n");

                E2K_FLUSHC;
		cr = (e2k_mem_crs_t *) (AS_STRUCT(regs->stacks.pcsp_lo).base +
					AS_STRUCT(regs->stacks.pcsp_hi).ind);

                CHECK_SIZE("update_record1",record);
		DbgTC("cr = %p\n", cr);
		DbgTC("pcsp.base = %llx\n", AS(regs->stacks.pcsp_lo).base);
		DbgTC("pcsp.ind  = %x\n", AS(regs->stacks.pcsp_hi).ind);
		cr -= (p_psl - l_psl);

		E2K_FLUSH_WAIT;

		AS_WORD(psr) = AS_STRUCT(cr->cr1_lo).psr;
		if (AS_STRUCT(psr).lw) {
			DbgTC("lw was already set in "
				"memory\n");
		} else {
			DbgTC("lw was cleared in memory\n");
			AS_STRUCT(psr).lw = 1;
			AS_STRUCT(cr->cr1_lo).psr = AS_WORD(psr);
			DbgTC("lw is SET\n");
		}
		record->orig_psr_lw = AS_STRUCT(psr).lw;
	}


	/* semaphore is required */
	record->lcl_psl = l_psl;

	return record;
}

void  down_read_lock_multithread(void)
{
        struct rw_semaphore *lock = current_thread_info()->lock;

        if (WAS_MULTITHREADING && lock) {
                down_read(lock);
        }
}

void  up_read_lock_multithread(void)
{
        struct rw_semaphore *lock = current_thread_info()->lock;

        if (WAS_MULTITHREADING && lock) {
                up_read(lock);
        }
}

/*
 * do_global_sp() 
 */

int do_global_sp (struct pt_regs *regs, trap_cellar_t *tcellar)
{
	e2k_addr_t		global;	/* address of the GLOBAL */
	unsigned int		l_psl;		/* PSL of the LOCAL */
	unsigned int		p_psl;		/* PSL of the interrupted */
						/* user procedure */
	e2k_rwsap_lo_struct_t	sap_lo;
	e2k_pusd_lo_t		pusd_lo;
        int                     res;

	global_store_t		*list, *record;


	/* Verify if the data is SAP */
	if ( IS_SAP_LO(&(tcellar[0].data)) && 
	     IS_SAP_HI(&(tcellar[1].data)) ) {

		global = tcellar[0].address;
		AS_WORD(sap_lo) = tcellar[0].data;
		l_psl = AS_STRUCT(sap_lo).psl;

		DbgTC("SAP global addr = %lx, local psl = %d\n",
			global, l_psl);

		DbgTC("SAP global  tcellar[0].data = %lx,  tcellar[1].data = %lx\n",
			tcellar[0].data, tcellar[1].data);
		DbgTC("SAP global  *global = %lx,  *global+8 = %lx\n",
			*(long*)global, *(long*)(global+8));

		DbgTC("SAP   IS_SAP_LO=%d IS_SAP_HI=%d\n",
			IS_SAP_LO(global), IS_SAP_HI(global+8));


	} else {
		DbgTC("The data isn't SAP: data0 = %lx, data1 = %lx\n",
				tcellar[0].data, tcellar[1].data);
		return 1;
	}

	if (! user_mode(regs)) {
		DbgTC("exception happened in kernel mode. "
		      "Exiting.\n");
		return 1;
	}

	AS_WORD(pusd_lo) = AS_WORD(regs->stacks.usd_lo);

	if (AS_STRUCT(pusd_lo).p) {
		DbgTC("protected mode detected gd_lo=0x%lx gd_hi=0x%lx PID=%d\n",
                      AS_WORD(read_GD_lo_reg()),AS_WORD(read_GD_hi_reg()) , current->pid);
		p_psl = AS_STRUCT(pusd_lo).psl;

		/* NOTICE: correction for OS entrance */
		p_psl--;

		DbgTC("interrupted procedure psl = %d\n",
			p_psl);
	} else {
		DbgTC("NON-protected mode detected. "
			"Exiting.\n");
		return 1;
	}
        res = gsp_is_return(regs);
        if (WAS_MULTITHREADING) {
               set_last_wish(regs, l_psl, p_psl + res);
        }    
	/* check if the local is allowed to store in the global */

	if (res) {

	/* This is ugly patch against the case when LOAD/STORE to a global
	 * is located in the same VLIW with CT (control transfer) instruction
	 * associated with RETURN
	 */		
		if (l_psl > (p_psl + 1)) {
			/* Easy case. No need to do anything */

			DbgTC("RETURN case. l_psl > p_psl + 1"
				"Exiting.\n");
			return 1;
		} else {
			if (l_psl == (p_psl + 1)) {				
				list = current_thread_info()->g_list;

			/* Most un-pleasant case, when stored local belongs to
			 * current procedure being executing on the CPU
			 */

			DbgTC("RETURN case."
			      " l_psl == (p_psl + 1)\n");

				for (record = list; record != NULL;
					record = record->next)
				{
					if (record->global_p == global)
						break;
				}
				if (!WAS_MULTITHREADING && record !=  NULL) {


				unsigned int old_psl = record->lcl_psl;

			DbgTC("RETURN case."
			      " record !=  NULL, old_psl = %d\n", old_psl);


				/* Clear old last wish */
				if (old_psl == p_psl) {
					e2k_psr_t psr;
			DbgTC("RETURN case."
			      " old_psl == p_psl\n");
					AS_WORD(psr) =
						AS_STRUCT(regs->crs.cr1_lo).psr;
					if (AS_STRUCT(psr).lw) {
						if (!record->orig_psr_lw) {
						 AS_STRUCT(psr).lw = 0;
						 AS_STRUCT(regs->crs.cr1_lo).psr =
						 		AS_WORD(psr);
						};
					};

				} else {
					e2k_mem_crs_t *cr;
					e2k_psr_t psr;
                                        E2K_FLUSHC;

					DbgTC("RETURN case. old_psl != p_psl\n");
					cr = (e2k_mem_crs_t *)
					   (regs->stacks.pcsp_lo.PCSP_lo_base +
					   regs->stacks.pcsp_hi.PCSP_hi_ind);
 					cr -= (p_psl - l_psl);

					E2K_FLUSH_WAIT;

                                        if (WAS_MULTITHREADING) {
                                            /* set last_wish for all proc  */
                                            int i;
                                            for(i = l_psl; i > 0; i--) {
				                AS_WORD(psr) =
          				          AS_STRUCT(cr->cr1_lo).psr;
                                                if (!AS_STRUCT(psr).pm) {
						  AS_STRUCT(psr).lw = 1;
						  AS_STRUCT(cr->cr1_lo).psr =
						 		AS_WORD(psr);
                                                }    
                                                cr -=1;
                                           }    
                                        } else {    
                                            CHECK_SIZE("do_global_sp ", 1);
					    AS_WORD(psr) =
						AS_STRUCT(cr->cr1_lo).psr;
					    if (AS_STRUCT(psr).lw) {
						if (!record->orig_psr_lw) {
						  AS_STRUCT(psr).lw = 0;
						  AS_STRUCT(cr->cr1_lo).psr =
						 		AS_WORD(psr);
						};
					    };
                                        }
				};

				/* Delete the record from list */
                                delete_list(record);
				kfree((void *) record);
				};

				/* Clear the global with Null Pointer */


			DbgTC("RETURN case."
			      " Clearing of global with addr = %lx\n", global);

				if (!IS_MULTITHREADING){
                                        E2K_STORE_NULLPTR_QWORD(global);
				        return 1;
				}
			};
		};
	} else {
		if (l_psl > p_psl) {
			DbgTC("l_psl > p_psl "
				"Exiting.\n");
			return 1;
		};
	}
	/* The list is defined as one entry per global.
	 * If the address matched an existing entry - just update the record.
	 * If not - create new one.
	 * Update will also move the last_wish flag on a new location in CS.
	 */
	init_g_list(0);

	list = current_thread_info()->g_list;

	/*
	 * Look for the first (the only) record in list that contains
	 * this global's pointer
	 */
	for (record = list; record != NULL; record = record->next)
	{
		if (record->global_p == global)
			break;
	}

	if (IS_MULTITHREADING || record ==  NULL) {
		DbgTC(""
		      " record ==  NULL, call for new_record().\n");
		new_record(list, regs, global, l_psl, p_psl);
	} else {
		DbgTC(""
		      " record ==  NULL, call for update_record().\n");
		update_record(record, regs, l_psl, p_psl);
	}
        
	return 0;
}

static void  print_global_records(global_store_t *entry)
{
	e2k_rwsap_hi_struct_t	sap_hi;
        long                    size;

        AS_WORD(sap_hi) = entry->word2;
        size = AS_STRUCT(sap_hi).size;

        printk("GLOBAL  pid=%d  global=0x%lx psl=%d entry=%p\n", 
                       entry->pid,  entry->global_p, entry->lcl_psl, entry);
        printk(" new_address=0x%lx  old_address=0x%lx"
                       " sbr=0x%lx size=%lx\n", 
                       entry->new_address,  entry->old_address,
                       entry->sbr, size);
} 

static void  print_init_records(global_store_t *entry)
{
	pr_info("INIT pid=%d  GET_CURR_IND=0x%x NUM_THREAD=%d\n", 
		entry->pid,  entry->lcl_psl, NUM_THREAD(entry));
}   

static void  print_bound_records(global_store_t *entry)
{
	printk("BOUND pid=%d  TIME(CURR_IND)=0x%lx entry=%p\n", 
		entry->pid,  GET_TIME(entry), entry);
	printk(" sbr=0x%lx lcl_psl=%d\n", 
		entry->sbr, entry->lcl_psl);
} 

static void print_all_records(void)
{
        global_store_t		*entry = current_thread_info()->g_list;

	DbgTC("print_all_records entry %p \n", entry);
	while (entry != NULL)
        {
                switch (entry->type)
                {    
                  case TYPE_INIT:
                        print_init_records(entry);
                        break;
                 case TYPE_BOUND:
                        print_bound_records(entry);
                        break;
                 case TYPE_GLOBAL:
                        print_global_records(entry);
                        break;
                 default:
                        printk("UNKNOWN entry=%p entry->type =%d\n",
                                                entry, entry->type);
                        break;
                }        
                entry = entry->next;
        }    
}

int delete_records(unsigned int psl_from)
{
	e2k_addr_t		global;	/* address of the GLOBAL */
						/* user procedure */
	unsigned int		g_psl = 0;
	global_store_t		*entry, *advance_entry;
	struct mm_struct	*mm;
	struct vm_area_struct	*vma = NULL;

	DbgTC("Deleting records with psl >= %d\n", psl_from);
	if (current_thread_info()->g_list == NULL) {
		DbgTC("list of globals is empty. Exiting.\n");
		return 1;
	}

	mm = current->mm;
	down_read(&mm->mmap_sem);
	entry = current_thread_info()->g_list;
	while (entry != NULL)
	{
	    advance_entry = entry->next;	/* to avoid re-usage of   */
						/* an entry after kfree() */ 

	    if (entry->lcl_psl >= psl_from && IS_THIS_THREAD(entry)) {	
		global = entry->global_p;

		vma = find_vma(mm, global);
		if (!vma || ((vma->vm_start) > global)) {
			printk(KERN_NOTICE "delete_records(): global %lx "
				" belongs to an unmapped area\n", global);
		} else if ( IS_SAP_LO(global) && 
		     IS_SAP_HI(global + sizeof(e2k_rwsap_lo_struct_t)) ) {

			e2k_rwsap_lo_struct_t	sap_lo;
			AS_WORD(sap_lo) = *(u64 *) global;

			g_psl = AS_STRUCT(sap_lo).psl;

			DbgTC("SAP global addr LO = %lx, "
			      " HI = %lx, "
			      "global psl = %d\n", global,
			       global + sizeof (e2k_rwsap_lo_struct_t), g_psl);

			if (g_psl >= psl_from)
                                E2K_STORE_NULLPTR_QWORD(global);
		} else {
			DbgTC("The data isn't SAP: data0 = %lx, data1 = %lx\n",
					*(u64 *) global,
					*(u64 *) (global + sizeof(u64)));
		}
                delete_list(entry);

		kfree((void *) entry);
		DbgTC("Entry %p freed\n", entry);
	    }

	    entry = advance_entry;

	}
	up_read(&mm->mmap_sem);

	return 0;
}
/*
 * Some remark; Because hardware fault for e3m lw_global_sp may call sometimes 
 * unnecessary (conditional return)
 */ 
int lw_global_sp(struct pt_regs *regs)
{
	e2k_addr_t		global;	/* address of the GLOBAL */
	unsigned int		g_psl = 0;	/* PSL of the GLOBAL */
	unsigned int		p_psl;		/* PSL of the interrupted */
						/* user procedure */
	e2k_pusd_lo_t		pusd_lo;
	global_store_t		*entry, *advance_entry;
	struct mm_struct	*mm;
	struct vm_area_struct	*vma = NULL;

	AS_WORD(pusd_lo) = AS_WORD(regs->stacks.usd_lo);

	if (AS_STRUCT(pusd_lo).p) {
		DbgTC("protected mode detected\n");
		p_psl = AS_STRUCT(pusd_lo).psl;

		/* NOTICE: correction for OS entrance */
		p_psl--;

		DbgTC("interrupted procedure psl = %d\n",
			p_psl);
	} else {
		DbgTC("NON-protected mode detected. "
			"Exiting.\n");
		return 1;
	}

	if (current_thread_info()->g_list == NULL) {
		DbgTC("list of globals is empty. Exiting.\n");
		return 1;
	}
        down_read_lock_multithread();
	mm = current->mm;
	down_read(&mm->mmap_sem);
	entry = current_thread_info()->g_list;
	while (entry != NULL)
	{
	    advance_entry = entry->next;	/* to avoid re-usage of   */
						/* an entry after kfree() */ 

	    if (entry->lcl_psl == (p_psl+1) && IS_THIS_THREAD(entry)) {
                                                /* lms fires LWE after the CT */
		global = entry->global_p;
                
		vma = find_vma(mm, global);
		if (!vma || ((vma->vm_start) > global)) {
			printk(KERN_NOTICE "lw_global_sp(): global %lx belongs to an"
				" unmapped area\n", global);
		} else if ( IS_SAP_LO(global) && 
		     IS_SAP_HI(global + sizeof(e2k_rwsap_lo_struct_t)) ) {

			e2k_rwsap_lo_struct_t	sap_lo;
			AS_WORD(sap_lo) = *(u64 *) global;

			g_psl = AS_STRUCT(sap_lo).psl;

			DbgTC("SAP global addr LO = %lx, "
			      " HI = %lx, "
			      "global psl = %d\n", global,
			       global + sizeof (e2k_rwsap_lo_struct_t), g_psl);

			if (!WAS_MULTITHREADING && g_psl > p_psl)
                                E2K_STORE_NULLPTR_QWORD(global);
		} else {
			DbgTC("The data isn't SAP: data0 = %lx, data1 = %lx\n",
					*(u64 *) global,
					*(u64 *) (global + sizeof(u64)));
		}
                if (!WAS_MULTITHREADING) {
                        delete_list(entry);
        		kfree((void *) entry);
		        DbgTC("Entry %p freed\n", entry);
                }
	    };

	    entry = advance_entry;

	}
        set_new_bound(p_psl+1, regs);
	up_read(&mm->mmap_sem);
        up_read_lock_multithread();
	return 0;
}
