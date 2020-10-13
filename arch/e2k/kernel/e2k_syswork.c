/*
 * This file contains various syswork to run them from user.
 */

#include <linux/delay.h>
#include <linux/ftrace.h>
#include <linux/ide.h>
#include <linux/ratelimit.h>
#include <linux/stat.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/sem.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <linux/mutex.h>
#include <linux/syscalls.h>

#include <asm/e2k_syswork.h>
#include <asm/unistd.h>
#include <asm/ptrace.h>
#include <asm/e2k.h>
#include <asm/process.h>
#include <asm/processor.h>
#include <asm/traps.h>
#include <asm/mmu_context.h>
#include <asm/uaccess.h>
#include <asm/bootinfo.h>
#include <asm/boot_init.h>
#include <asm/boot_recovery.h>
#ifdef CONFIG_RECOVERY
#include <asm/cnt_point.h>
#endif	/* CONFIG_RECOVERY */
#include <asm/bios_map.h>
#include <asm/nmi.h>
#include <asm/cacheflush.h>

#define DEBUG_ACCVM		0
#if DEBUG_ACCVM
# define DebugACCVM(...)	pr_info(__VA_ARGS__)
#else
# define DebugACCVM(...)
#endif

#define	DEBUG_E2K_SYS_WORK	0
#define DbgESW(...)		DebugPrint(DEBUG_E2K_SYS_WORK ,##__VA_ARGS__)

#define	DEBUG_GETCONTEXT	0
#define DbgGC(...)		DebugPrint(DEBUG_GETCONTEXT ,##__VA_ARGS__)

#undef	DEBUG_DUMP_STACK_MODE
#undef	DebugDS
#define	DEBUG_DUMP_STACK_MODE	0
#define DebugDS(...)		DebugPrint(DEBUG_DUMP_STACK_MODE ,##__VA_ARGS__)

/* These will be re-linked against their real values during the second 
 * link stage. Necessary for dump analyzer */

extern unsigned long kallsyms_addresses[] __attribute__((weak));
extern unsigned long kallsyms_num_syms __attribute__((weak,section("data")));
extern u8 kallsyms_names[] __attribute__((weak));
extern u8 kallsyms_token_table[] __attribute__((weak));
extern u16 kallsyms_token_index[] __attribute__((weak));
extern unsigned long kallsyms_markers[] __attribute__((weak));

extern int task_statm(struct mm_struct *, int *, int *, int *, int *);

extern int debug_userstack;

long e2k_lx_dbg = 0;
int end_of_work = 0;

int jtag_stop_var;

void	*kernel_symtab;
long	kernel_symtab_size;
void	*kernel_strtab;
long	kernel_strtab_size;

e2k_addr_t print_kernel_address_ptes(e2k_addr_t address);

#define	IS_KERNEL_THREAD(task, mm)					\
	((mm) == NULL || 						\
		(e2k_addr_t)GET_PS_BASE(task_thread_info(task)) >=	\
								TASK_SIZE)

int debug_userstack = 0;
static int __init userstack_setup(char *str)
{
	debug_userstack = 1;
	return 1;
}
__setup("debug_userstack", userstack_setup);

#ifdef CONFIG_DATA_STACK_WINDOW
int debug_datastack = 0;
static int __init datastack_setup(char *str)
{
	debug_datastack = 1;
	return 1;
}
__setup("debug_datastack", datastack_setup);
#endif


#ifdef CONFIG_PROFILING
additional_info_t additional_info;
disable_interrupt_t disable_interrupt[NR_CPUS];
EXPORT_SYMBOL(disable_interrupt);
char* system_info_name[]= {"disabled interrupts ", 
                           "storing stack_register",
                           "storing TIR",
                           "storing all registers",
                           "storing debug registers",
                           "storing aau registers",
                           "restoring of stack_registers",
                           "restoring all registers",
                           "restoring debug registers",
                           "restoring aau registers",
                           "cpu_idle",
                           "spin_lock",                   
                           "mutex_lock",                  
                           "hard_irq",
                           "switch", 
                           "soft_irq",
                           "preempt_count",
                          }; 
system_info_t system_info[NR_CPUS];
int  enable_collect_interrupt_ticks = 0;
EXPORT_SYMBOL( system_info);
EXPORT_SYMBOL(enable_collect_interrupt_ticks);

long TIME=0;
long TIME1=0;
extern const char *exc_tbl_name[];       
extern unsigned long sys_call_table[NR_syscalls];

static void clear_interrupt_info(void)
{

    memset(&system_info[0], 0, sizeof(system_info));  
    memset(&disable_interrupt[0], 0, sizeof(disable_interrupt));  
    
    TIME = E2K_GET_DSREG(clkr);   
    enable_collect_interrupt_ticks =1;
}


static void print_interrupt_info(void)
{
    int i, j;
    time_info_t* pnt;
    long freq;
    int print_ip = 0;                            // !!!! tmp

    enable_collect_interrupt_ticks = 0;
    freq = cpu_data[0].proc_freq /1000000 ;

    printk("\t\t  ==============PROFILE  INFO=(%ld(ticks) /%ld(mks)/)============== \n",
           TIME1- TIME, (TIME1 - TIME)/freq );
    
    for (j = 0; j < NR_CPUS; j++) {

        printk("\t\t\t CPU%d   \n",j);
        pnt = (time_info_t*) &system_info[j].max_disabled_interrupt;    
        for (i = 0; i < sizeof(system_info_name)/sizeof(void *); i++) {
            printk("  %30s  max time=%10ld   average=%10ld   number=%10ld \n",
                   system_info_name[i],
                   pnt->max_time/freq, 
                   pnt->full_time/freq/((pnt->number == 0)?1 : pnt->number),
                   pnt->number);
            if (print_ip)  {
                printk(" time=%10lx ", pnt->max_begin_time);
                print_symbol("\t\t\t %s",pnt->max_beg_ip);
                print_symbol(" (%s) --- \n",pnt->max_beg_parent_ip);
                print_symbol("\t\t\t\t %s",pnt->max_end_ip);
                print_symbol("( %s) \n",pnt->max_end_parent_ip);
             } 
            pnt++;           
        }
        printk("\n\t\t\t\t system calls   \n");
        for (i = 0; i < NR_syscalls; i++) {
            if (disable_interrupt[j].syscall[i]) {
                print_symbol("  %30s ",sys_call_table[i]);
                printk("average=%5ld   number=%10ld \n",
                    disable_interrupt[j].syscall_time[i]/freq/
                            ((disable_interrupt[j].syscall[i] == 0)? 1
                             : disable_interrupt[j].syscall[i]),
                    disable_interrupt[j].syscall[i]);           
            }    
        }
        
        printk("\n\t\t\t\t interrupts   \n");
        for (i = 0; i < exc_max_num; i++) {
            if (disable_interrupt[j].interrupts[i]) {
                printk("  %30s max time=%5ld average=%5ld   number=%10ld \n",
                    exc_tbl_name[i],  
                    disable_interrupt[j].max_interrupts_time[i]/freq ,
                    disable_interrupt[j].interrupts_time[i]/freq/
                           ((disable_interrupt[j].interrupts[i] == 0) ?1
                              : disable_interrupt[j].interrupts[i]),
                    disable_interrupt[j].interrupts[i]);           
            }    

        }    
        printk("\n\t\t\t\t DO_IRQ   \n");
        for (i = 0; i < NR_VECTORS; i++) { 
            if (disable_interrupt[j].do_irq[i]) {
                printk("  %5d max time=%5ld average=%5ld   number=%10ld \n",
                    i,  
                    disable_interrupt[j].max_do_irq_time[i]/freq ,
                    disable_interrupt[j].do_irq_time[i]/freq/
                            ((disable_interrupt[j].do_irq[i] ==0)? 1
                               : disable_interrupt[j].do_irq[i]),
                    disable_interrupt[j].do_irq[i]);           
            }    
        }    

    }    
    
};
static void stop_interrupt_info(void)
{
    TIME1 = E2K_GET_DSREG(clkr);   
    enable_collect_interrupt_ticks =0;

    printk(" start =%lx stop_interrupt_info =%lx "
           " begin_time(max_disabled_interrupt 0) =%lx"
           " end_time =%lx  max_time =%lx "
           " begin_time(max_disabled_interrupt 1) =%lx "
           " end_time =%lx  max_time =%lx \n",
           TIME, TIME1,  system_info[0].max_disabled_interrupt.begin_time,
           system_info[0].max_disabled_interrupt.begin_time 
                +system_info[0].max_disabled_interrupt.max_time,
           system_info[0].max_disabled_interrupt.max_time, 
           system_info[1].max_disabled_interrupt.begin_time, 
           system_info[1].max_disabled_interrupt.begin_time 
                +system_info[1].max_disabled_interrupt.max_time,
           system_info[1].max_disabled_interrupt.max_time);
    
 };

#else /* !CONFIG_PROFILING */
static void print_interrupt_info(void) {};
static void clear_interrupt_info(void) {};
static void stop_interrupt_info(void) {};
#endif /* CONFIG_PROFILING */


#define SIZE_PSP_STACK (16 * 4096)
#define DATA_STACK_PAGES 16
#define SIZE_DATA_STACK (DATA_STACK_PAGES * PAGE_SIZE)
/* Enough for 64 stack frames */
#define SIZE_CHAIN_STACK 2048

/* Maximum number of user windows where a trap occured
 * for which additional registers will be printed (ctpr's, lsr and ilcr). */
#define MAX_USER_TRAPS 12

/* Maximum number of pt_regs being marked as such
 * when showing kernel data stack */
#define MAX_PT_REGS_SHOWN 30

struct user_trap_regs {
	bool valid;
	u64 frame;
	e2k_ctpr_t ctpr1;
	e2k_ctpr_t ctpr2;
	e2k_ctpr_t ctpr3;
	u64 lsr;
	u64 ilcr;
};

struct stack_regs {
	bool valid;
	struct task_struct *task;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_hi_t cr1_hi;
#if defined(CONFIG_STACK_REG_WINDOW) || defined(CONFIG_DATA_STACK_WINDOW)
	e2k_cr1_lo_t cr1_lo;
#endif
#ifdef CONFIG_STACK_REG_WINDOW
	e2k_psp_lo_t psp_lo;
	e2k_psp_hi_t psp_hi;
	e2k_cr0_lo_t cr0_lo;
	void *base_psp_stack;
	u64 orig_base_psp_stack;
	void *psp_stack_cache;
	u64 size_psp_stack;
	bool show_user_regs;
	struct user_trap_regs user_trap[MAX_USER_TRAPS];
# ifdef CONFIG_GREGS_CONTEXT
	struct {
		u64 gbase[E2K_MAXGR_d];
		u16 gext[E2K_MAXGR_d];
		u8 tag[E2K_MAXGR_d];
		e2k_bgr_t bgr;
		bool valid;
	} gregs;
# endif
#endif
#ifdef CONFIG_DATA_STACK_WINDOW
	bool show_k_data_stack;
	void *base_k_data_stack;
	void *k_data_stack_cache;
	u64 size_k_data_stack;
	void *real_k_data_stack_addr;
	struct {
		unsigned long addr;
		bool valid;
	} pt_regs[MAX_PT_REGS_SHOWN];
#endif
	u64 size_chain_stack;
	void *base_chain_stack;
	u64 orig_base_chain_stack;
	char chain_stack[SIZE_CHAIN_STACK];
};

/* Preallocate psp and data stack cache for the boot CPU so that
 * it can print full stacks from other CPUs as early as possible
 * (at boot time sysrq is handled by the boot CPU). */
#ifdef CONFIG_STACK_REG_WINDOW
char psp_stack_cache[SIZE_PSP_STACK];
#endif
#ifdef CONFIG_DATA_STACK_WINDOW
char k_data_stack_cache[SIZE_DATA_STACK];
#endif

/* This takes up roughly SIZE_CHAIN_STACK bytes
 * of memory for each possible CPU. */
static struct stack_regs stack_regs_cache[NR_CPUS] = {
#ifdef CONFIG_STACK_REG_WINDOW
	[0].psp_stack_cache = psp_stack_cache,
#endif
#ifdef CONFIG_DATA_STACK_WINDOW
	[0].k_data_stack_cache = k_data_stack_cache
#endif
};


/*
 * this proc must be inline proc
 * don't use any call in this procedure 
 * this proc may be used on user chain stack
 * (It needs to use stack's address /user space/)
 */
#define IS_USER_ADDR(x)   (((unsigned long)(x)) < TASK_SIZE)
#define GET_PHYS_ADDR(task, addr) \
		((IS_USER_ADDR(addr)) \
		? (unsigned long)user_address_to_phys(task, addr) \
		: (unsigned long)kernel_address_to_phys(addr))

#ifdef CONFIG_SMP
noinline
static void nmi_copy_current_stack_regs(void *arg)
{
	struct stack_regs *const regs = (struct stack_regs *) arg;
	unsigned long flags;
	s64 cr_ind;
	u64 sz;
	void *dst;
	void *src;
# if defined(CONFIG_STACK_REG_WINDOW) || defined(CONFIG_DATA_STACK_WINDOW)
	int i;
# endif
# ifdef CONFIG_STACK_REG_WINDOW
	struct pt_regs *u_pt_regs;
	s64 psp_ind;
	e2k_cr1_lo_t cr1_lo;
# endif
# ifdef CONFIG_DATA_STACK_WINDOW
	struct pt_regs *pt_regs;
	u64 copied;
	e2k_usd_lo_t usd_lo;
	e2k_pusd_lo_t pusd_lo;
	e2k_usd_hi_t usd_hi;
	e2k_sbr_t sbr;
# endif
	e2k_mem_crs_t *frame;
	int skip;

	regs->task = current;
	regs->valid = 0;
# if defined CONFIG_STACK_REG_WINDOW && defined CONFIG_GREGS_CONTEXT
	regs->gregs.valid = 0;
# endif

	raw_all_irq_save(flags);
	E2K_FLUSHCPU;
	regs->pcsp_hi = READ_PCSP_HI_REG();
	regs->pcsp_lo = READ_PCSP_LO_REG();
# ifdef CONFIG_STACK_REG_WINDOW
	regs->psp_hi = READ_PSP_HI_REG();
	regs->psp_lo = READ_PSP_LO_REG();
# endif
# ifdef CONFIG_DATA_STACK_WINDOW
	if (regs->show_k_data_stack) {
		AW(usd_lo) = AW(pusd_lo) = E2K_GET_DSREG_NV(usd.lo);
		AW(usd_hi) = E2K_GET_DSREG_NV(usd.hi);
		sbr = E2K_GET_DSREG_NV(sbr);
		regs->real_k_data_stack_addr = (void *) ((AS(usd_lo).p) ?
				(sbr + AS(pusd_lo).base) : AS(usd_lo).base);
		regs->real_k_data_stack_addr -= AS(usd_hi).size;
	}
# endif


	/*
	 * We are here:
	 *
	 * ... -> kernel_trap_handler
	 *     -> parse_TIR_registers
	 *     -> do_nm_interrupt
	 *     -> do_nmi
	 *     -> nmi_call_function_interrupt
	 *     -> nmi_copy_current_stack_regs
	 *
	 * Thus we want to skip the last 5 frames
	 * (nmi_copy_current_stack_regs() is not in the stack yet).
	 *
	 * Trimming of the chain stack is trivial - just cut
	 * the last 5 * SZ_OF_CR bytes.
	 *
	 * Trimming of the procedure stack is done using information
	 * from the chain stack.
	 *
	 * Trimming of the data stack is the same as for the procedure stack.
	 */

	cr_ind = AS(regs->pcsp_hi).ind;
# ifdef CONFIG_STACK_REG_WINDOW
	psp_ind = AS(regs->psp_hi).ind;
	cr1_lo = (e2k_cr1_lo_t) E2K_GET_DSREG_NV(cr1.lo);

	/* Skip the first frame (which is in registers */
	psp_ind -= AS(cr1_lo).wbs * EXT_4_NR_SZ;

	if (regs->show_user_regs)
		u_pt_regs = find_trap_regs(current_thread_info()->pt_regs);
# endif

	/* Skip frames in stack */
	skip = 4;
	while (skip--) {
		cr_ind -= SZ_OF_CR;
		if (unlikely(cr_ind <= 0)) {
			/* Something's fishy */
			printk("BAD CR_IND. Is chain stack truncated?\n");
			goto out;
		}

# if defined(CONFIG_STACK_REG_WINDOW) || defined(CONFIG_DATA_STACK_WINDOW)
		frame = (e2k_mem_crs_t *) (AS(regs->pcsp_lo).base + cr_ind);
# endif
# ifdef CONFIG_STACK_REG_WINDOW
		psp_ind -= AS(frame->cr1_lo).wbs * EXT_4_NR_SZ;
		if (regs->show_user_regs && u_pt_regs) {
			u64 user_trap_frame = AS(u_pt_regs->stacks.pcsp_lo).base
					+ AS(u_pt_regs->stacks.pcsp_hi).ind;

			if (user_trap_frame == (u64) frame)
				u_pt_regs = find_trap_regs(u_pt_regs->next);
		}
# endif
	}

# ifdef CONFIG_STACK_REG_WINDOW
	for (i = 0; i < MAX_USER_TRAPS; i++) {
		if (regs->show_user_regs && u_pt_regs) {
			regs->user_trap[i].frame =
					AS(u_pt_regs->stacks.pcsp_lo).base +
					AS(u_pt_regs->stacks.pcsp_hi).ind;

			regs->user_trap[i].ctpr1 = u_pt_regs->ctpr1;
			regs->user_trap[i].ctpr2 = u_pt_regs->ctpr2;
			regs->user_trap[i].ctpr3 = u_pt_regs->ctpr3;
			regs->user_trap[i].lsr = u_pt_regs->lsr;
			regs->user_trap[i].ilcr = u_pt_regs->ilcr;
			regs->user_trap[i].valid = 1;

			u_pt_regs = find_trap_regs(u_pt_regs->next);
		} else {
			regs->user_trap[i].valid = 0;
		}
	}
# endif

	/* Put the last frame in registers
	 * (as it is expected to be in registers) */
	cr_ind -= SZ_OF_CR;
	frame = (e2k_mem_crs_t *) (AS(regs->pcsp_lo).base + cr_ind);
	regs->cr0_hi = frame->cr0_hi;
	regs->cr1_hi = frame->cr1_hi;
# ifdef CONFIG_STACK_REG_WINDOW
	regs->cr0_lo = frame->cr0_lo;
	regs->cr1_lo = frame->cr1_lo;
# endif

	if (unlikely(cr_ind <= 0))
		/* Something's fishy */
		goto out;

	AS(regs->pcsp_hi).ind = cr_ind;

# ifdef CONFIG_STACK_REG_WINDOW
	if (unlikely(psp_ind < 0))
		psp_ind = 0;

	AS(regs->psp_hi).ind = psp_ind;
# endif
# ifdef CONFIG_DATA_STACK_WINDOW
	if (regs->show_k_data_stack)
		regs->real_k_data_stack_addr += 16 * AS(regs->cr1_hi).ussz;

	pt_regs = current_thread_info()->pt_regs;
	if (pt_regs)
		/* The last pt_regs correspond to the NMI, so skip them */
		pt_regs = pt_regs->next;
	for (i = 0; i < MAX_PT_REGS_SHOWN; i++) {
		if (regs->show_k_data_stack && pt_regs) {
			regs->pt_regs[i].valid = 1;
			regs->pt_regs[i].addr = (unsigned long) pt_regs;
			pt_regs = pt_regs->next;
		} else {
			regs->pt_regs[i].valid = 0;
		}
	}
# endif


	/*
	 * Now that we are ready to copy, wait for the flush to finish
	 */
	E2K_FLUSH_WAIT;


        /*
         * Copy a part (or all) of the chain stack.
	 * If it fails then leave regs->valid set to 0.
	 */
	regs->base_chain_stack = regs->chain_stack;
	if (!regs->base_chain_stack)
		goto out;

	cr_ind = AS(regs->pcsp_hi).ind;

	sz = regs->size_chain_stack = min(cr_ind, (s64) SIZE_CHAIN_STACK);

	src = (void *) (AS(regs->pcsp_lo).base + cr_ind - sz);

	dst = regs->base_chain_stack;

	tagged_memcpy_8(dst, src, sz);

	/*
	 * Remember original stack address.
	 */
	regs->orig_base_chain_stack = (u64) src;


# ifdef CONFIG_STACK_REG_WINDOW
        /*
         * Copy a part (or all) of the procedure stack.
	 * Do _not_ set regs->valid to 0 if it fails
	 * (we can still print stack albeit without register windows)
	 */
	regs->base_psp_stack = regs->psp_stack_cache;
	if (!regs->base_psp_stack)
		goto skip_copying_psp_stack;

	psp_ind = AS(regs->psp_hi).ind;

	sz = regs->size_psp_stack = min(psp_ind, (s64) SIZE_PSP_STACK);

	src = (void *) (AS(regs->psp_lo).base + psp_ind - sz);

	dst = regs->base_psp_stack;

	tagged_memcpy_8(dst, src, sz);

	regs->orig_base_psp_stack = (u64) src;

skip_copying_psp_stack:
# endif

# ifdef CONFIG_DATA_STACK_WINDOW
	/*
	 * Copy a part (or all) of the kernel data stack.
	 * Do _not_ set regs->valid to 0 if it fails
	 * (we can still print stack albeit without the kernel data stack)
	 */
	if (!regs->show_k_data_stack) {
		regs->base_k_data_stack = NULL;
		goto skip_copying_k_data_stack;
	}
	if (!IS_ALIGNED((unsigned long) regs->real_k_data_stack_addr, 16)) {
		printk("[%d] %s: kernel data stack is not aligned!\n",
				current->pid, current->comm);
		regs->base_k_data_stack = NULL;
		goto skip_copying_k_data_stack;
	}
	regs->base_k_data_stack = regs->k_data_stack_cache;
	if (!regs->k_data_stack_cache)
		goto skip_copying_k_data_stack;

	regs->size_k_data_stack = sbr -
			(unsigned long) regs->real_k_data_stack_addr;
	if (regs->size_k_data_stack > SIZE_DATA_STACK)
		regs->size_k_data_stack = SIZE_DATA_STACK;

	sz = regs->size_k_data_stack;

	src = regs->real_k_data_stack_addr;

	dst = regs->base_k_data_stack;

	copied = 0;
	do {
		u64 to_copy = min(PAGE_ALIGN((u64) src + 1) - (u64) src,
				sz - copied);

		if (is_kernel_address_valid((unsigned long) (src + copied))) {
			tagged_memcpy_8(dst + copied, src + copied, to_copy);
		} else {
			printk("task %d [%s]: bad kernel data stack page at %lx\n",
				current->pid, current->comm, src + copied);
			memset(dst + copied, 0, to_copy);
		}

		copied += to_copy;
	} while (copied < sz);

skip_copying_k_data_stack:
# endif

# if defined CONFIG_STACK_REG_WINDOW && defined CONFIG_GREGS_CONTEXT
	SAVE_GLOBAL_REGISTERS_CLEAR_TAG(&regs->gregs, true);
	E2K_LOAD_VAL_AND_TAGD(&current_thread_info()->gbase[0],
			regs->gregs.gbase[16], regs->gregs.tag[16]);
	E2K_LOAD_VAL_AND_TAGD(&current_thread_info()->gbase[1],
			regs->gregs.gbase[17], regs->gregs.tag[17]);
	E2K_LOAD_VAL_AND_TAGD(&current_thread_info()->gbase[2],
			regs->gregs.gbase[18], regs->gregs.tag[18]);
	E2K_LOAD_VAL_AND_TAGD(&current_thread_info()->gbase[3],
			regs->gregs.gbase[19], regs->gregs.tag[19]);
	regs->gregs.gext[16] = current_thread_info()->gext[0];
	regs->gregs.gext[17] = current_thread_info()->gext[1];
	regs->gregs.gext[18] = current_thread_info()->gext[2];
	regs->gregs.gext[19] = current_thread_info()->gext[3];

	regs->gregs.valid = 1;
# endif

	regs->valid = 1;

out:
	raw_all_irq_restore(flags);
}

static void
get_cpu_regs_using_nmi(int cpu, struct stack_regs *const regs)
{
	int attempt;

	/* get regs using NMI, try several times
	 * waiting for a total of 30 seconds. */
	regs->valid = 0;
	for (attempt = 0; attempt < 3; attempt++) {
		nmi_call_function_single(cpu, nmi_copy_current_stack_regs,
				regs, 1, 10000);

		if (regs->valid)
			/* Stacks were copied */
			return;

		regs->valid = 0;
	}
}
#endif /* CONFIG_SMP */

/*
 * Copy full or last part of a process stack to a buffer.
 * Is inlined to make sure that the return will not flush stack.
 *
 * Must be called with maskable interrupts disabled because
 * stack registers are protected by IRQ-disable.
 */ 
static inline void
copy_stack_regs(struct task_struct *task, struct stack_regs *const regs)
{
	unsigned long flags;
	u64		cr_ind;
#if defined(CONFIG_STACK_REG_WINDOW) || defined(CONFIG_DATA_STACK_WINDOW)
	int		i;
#endif
#ifdef CONFIG_STACK_REG_WINDOW
	u64		psp_ind;
#endif
#ifdef CONFIG_DATA_STACK_WINDOW
	e2k_usd_lo_t	usd_lo;
	e2k_pusd_lo_t	pusd_lo;
	e2k_usd_hi_t	usd_hi;
	e2k_sbr_t	sbr;
#endif
        u64             sz;
	void		*dst;
	void		*src;
        u64             phys_addr;
	u64 nr_TIRs;
	e2k_tir_t TIRs[TIR_NUM];
	bool print_TIRs = 0;

	if (unlikely(!raw_irqs_disabled()))
		printk("copy_stack_regs called with enabled interrupts!\n");

	if (task == current) {
#ifdef CONFIG_STACK_REG_WINDOW
		struct pt_regs *u_pt_regs;
#endif
#ifdef CONFIG_DATA_STACK_WINDOW
		struct pt_regs *pt_regs;
#endif
		raw_all_irq_save(flags);
		E2K_FLUSHCPU;
		regs->pcsp_hi = READ_PCSP_HI_REG();
		regs->pcsp_lo = READ_PCSP_LO_REG();
		regs->cr0_hi = (e2k_cr0_hi_t)E2K_GET_DSREG_NV(cr0.hi);
		regs->cr1_hi = (e2k_cr1_hi_t)E2K_GET_DSREG_NV(cr1.hi);
#ifdef CONFIG_STACK_REG_WINDOW
		regs->cr0_lo = (e2k_cr0_lo_t)E2K_GET_DSREG_NV(cr0.lo);
		regs->cr1_lo = (e2k_cr1_lo_t)E2K_GET_DSREG_NV(cr1.lo);
		regs->psp_hi = READ_PSP_HI_REG();
		regs->psp_lo = READ_PSP_LO_REG();
		regs->base_psp_stack = (void *) AS_STRUCT(regs->psp_lo).base;
		regs->orig_base_psp_stack = (u64) regs->base_psp_stack;
		regs->size_psp_stack = AS_STRUCT(regs->psp_hi).ind;

		if (regs->show_user_regs)
			u_pt_regs = find_trap_regs(
					current_thread_info()->pt_regs);

		for (i = 0; i < MAX_USER_TRAPS; i++) {
			if (regs->show_user_regs && u_pt_regs) {
				regs->user_trap[i].frame =
					    AS(u_pt_regs->stacks.pcsp_lo).base +
					    AS(u_pt_regs->stacks.pcsp_hi).ind;
				regs->user_trap[i].ctpr1 =
						u_pt_regs->ctpr1;
				regs->user_trap[i].ctpr2 =
						u_pt_regs->ctpr2;
				regs->user_trap[i].ctpr3 =
						u_pt_regs->ctpr3;
				regs->user_trap[i].lsr = u_pt_regs->lsr;
				regs->user_trap[i].ilcr = u_pt_regs->ilcr;
				regs->user_trap[i].valid = 1;

				u_pt_regs = find_trap_regs(u_pt_regs->next);
			} else {
				regs->user_trap[i].valid = 0;
			}
		}
#endif
#ifdef CONFIG_DATA_STACK_WINDOW
		if (regs->show_k_data_stack) {
			AW(usd_lo) = AW(pusd_lo) = E2K_GET_DSREG_NV(usd.lo);
			AW(usd_hi) = E2K_GET_DSREG_NV(usd.hi);
			sbr = E2K_GET_DSREG_NV(sbr);
			regs->base_k_data_stack = (void *) ((AS(usd_lo).p) ?
					(sbr + AS(pusd_lo).base) :
					AS(usd_lo).base);
			/* We found the current data stack frame, but
			 * of intereset is our parent's frame. Move up. */
			regs->base_k_data_stack = regs->base_k_data_stack -
					AS(usd_hi).size +
					16 * AS(regs->cr1_hi).ussz;
			regs->real_k_data_stack_addr = regs->base_k_data_stack;
			regs->size_k_data_stack = sbr -
					(unsigned long) regs->base_k_data_stack;
		} else {
			regs->base_k_data_stack = NULL;
		}

		if (regs->show_k_data_stack)
			pt_regs = current_thread_info()->pt_regs;
		for (i = 0; i < MAX_PT_REGS_SHOWN; i++) {
			if (regs->show_k_data_stack && pt_regs) {
				regs->pt_regs[i].valid = 1;
				regs->pt_regs[i].addr = (unsigned long) pt_regs;
				pt_regs = pt_regs->next;
			} else {
				regs->pt_regs[i].valid = 0;
			}
		}
#endif
#if defined CONFIG_STACK_REG_WINDOW && defined CONFIG_GREGS_CONTEXT
		SAVE_GLOBAL_REGISTERS_CLEAR_TAG(&regs->gregs, true);
		E2K_LOAD_VAL_AND_TAGD(&current_thread_info()->gbase[0],
				regs->gregs.gbase[16], regs->gregs.tag[16]);
		E2K_LOAD_VAL_AND_TAGD(&current_thread_info()->gbase[1],
				regs->gregs.gbase[17], regs->gregs.tag[17]);
		E2K_LOAD_VAL_AND_TAGD(&current_thread_info()->gbase[2],
				regs->gregs.gbase[18], regs->gregs.tag[18]);
		E2K_LOAD_VAL_AND_TAGD(&current_thread_info()->gbase[3],
				regs->gregs.gbase[19], regs->gregs.tag[19]);
		regs->gregs.gext[16] = current_thread_info()->gext[0];
		regs->gregs.gext[17] = current_thread_info()->gext[1];
		regs->gregs.gext[18] = current_thread_info()->gext[2];
		regs->gregs.gext[19] = current_thread_info()->gext[3];

# ifdef CONFIG_E2S_CPU_RF_BUG
		{
			struct pt_regs *rf_regs = task_pt_regs(current);

			if (rf_regs) {
				E2K_LOAD_VAL_AND_TAGD(&rf_regs->e2s_gbase[0],
						regs->gregs.gbase[16],
						regs->gregs.tag[16]);
				E2K_LOAD_VAL_AND_TAGD(&rf_regs->e2s_gbase[1],
						regs->gregs.gbase[17],
						regs->gregs.tag[17]);
				E2K_LOAD_VAL_AND_TAGD(&rf_regs->e2s_gbase[2],
						regs->gregs.gbase[18],
						regs->gregs.tag[18]);
				E2K_LOAD_VAL_AND_TAGD(&rf_regs->e2s_gbase[3],
						regs->gregs.gbase[19],
						regs->gregs.tag[19]);
				E2K_LOAD_VAL_AND_TAGD(&rf_regs->e2s_gbase[4],
						regs->gregs.gbase[20],
						regs->gregs.tag[20]);
				E2K_LOAD_VAL_AND_TAGD(&rf_regs->e2s_gbase[5],
						regs->gregs.gbase[21],
						regs->gregs.tag[21]);
				E2K_LOAD_VAL_AND_TAGD(&rf_regs->e2s_gbase[6],
						regs->gregs.gbase[22],
						regs->gregs.tag[22]);
				E2K_LOAD_VAL_AND_TAGD(&rf_regs->e2s_gbase[7],
						regs->gregs.gbase[23],
						regs->gregs.tag[23]);
			}
		}
# endif

		regs->gregs.valid = 1;
#endif
		regs->base_chain_stack = (void *) AS_STRUCT(regs->pcsp_lo).base;
		regs->orig_base_chain_stack = (u64) regs->base_chain_stack;
		regs->size_chain_stack = AS_STRUCT(regs->pcsp_hi).ind;
		regs->task = current;
		regs->valid = 1;
		raw_all_irq_restore(flags);

		return;
	}

	regs->valid = 0;
#if defined CONFIG_STACK_REG_WINDOW && defined CONFIG_GREGS_CONTEXT
	regs->gregs.valid = 0;
#endif

#ifdef CONFIG_STACK_REG_WINDOW
	for (i = 0; i < MAX_USER_TRAPS; i++)
		regs->user_trap[i].valid = 0;
#endif

#ifdef CONFIG_SMP
again:
#endif
        /* SAVE regs */
	if(!task_curr(task)) {
		struct sw_regs *sw_regs;
		struct thread_info *ti;

copy_sw_regs:
		ti = task_thread_info(task);
		sw_regs = &task->thread.sw_regs;

		regs->pcsp_lo = sw_regs->pcsp_lo;
		regs->pcsp_hi = sw_regs->pcsp_hi;
		/* There is a small window between readings of pcsp_hi and
		 * TS_HW_STACKS_EXPANDED, but it is very small and the
		 * task is not executing right now so it should be OK. */
		if (!test_ti_status_flag(ti, TS_HW_STACKS_EXPANDED))
			regs->pcsp_hi.PCSP_hi_size += KERNEL_PC_STACK_SIZE;

		regs->cr0_hi  = sw_regs->cr0_hi;
		regs->cr1_hi  = sw_regs->cr_ussz;
#ifdef CONFIG_STACK_REG_WINDOW
		regs->cr0_lo  = sw_regs->cr0_lo;
		regs->cr1_lo  = sw_regs->cr_wd;

		regs->psp_lo  = sw_regs->psp_lo;
		regs->psp_hi  = sw_regs->psp_hi;
		if (!test_ti_status_flag(ti, TS_HW_STACKS_EXPANDED))
			regs->psp_hi.PSP_hi_size += KERNEL_P_STACK_SIZE;
#endif
#ifdef CONFIG_DATA_STACK_WINDOW
		regs->base_k_data_stack = NULL;
#endif
	} else {
		struct pt_regs *pt_regs;
		struct trap_pt_regs *trap;

#ifdef CONFIG_SMP
		/* get regs using NMI, try several times */
		get_cpu_regs_using_nmi(task_cpu(task), regs);
		if (regs->valid) {
			if (regs->task == task)
				/* Stacks were copied */
				return;

			/* Some other task is running now, try again */
			regs->valid = 0;
			goto again;
		}
#endif

		/* Still no luck, try pt_regs */
		pt_regs = task_thread_info(task)->pt_regs;

		printk(" * * * * * * * * * ATTENTION * * * * * * * * *\n"
			"Could not get task %d [%s] stack using NMI,\n"
			"used %s instead. The stack is unreliable!\n"
			" * * * * * * * * * * * * * * * * * * * * * * *\n",
			task->pid, task->comm, pt_regs ? "pt_regs" : "sw_regs");

		if (!pt_regs)
			/* Even pt_regs are not available, use sw_regs */
			goto copy_sw_regs;

		trap = ACCESS_ONCE(pt_regs->trap);
		if (trap) {
			/* Print TIRs after copying the stack */
			nr_TIRs = min_t(u64, trap->nr_TIRs, TIR_NUM);
			memcpy(TIRs, trap->TIRs, TIR_NUM);
			print_TIRs = 1;
		}

		regs->pcsp_lo = pt_regs->stacks.pcsp_lo;
		regs->pcsp_hi = pt_regs->stacks.pcsp_hi;
		regs->cr0_hi  = pt_regs->crs.cr0_hi;
		regs->cr1_hi  = pt_regs->crs.cr1_hi;
#ifdef CONFIG_STACK_REG_WINDOW
		regs->cr0_lo  = pt_regs->crs.cr0_lo;
		regs->cr1_lo  = pt_regs->crs.cr1_lo;
		regs->psp_lo  = pt_regs->stacks.psp_lo;
		regs->psp_hi  = pt_regs->stacks.psp_hi;
#endif
#ifdef CONFIG_DATA_STACK_WINDOW
		regs->base_k_data_stack = NULL;
#endif
        }

	/*
	 * We are here. This means that NMI failed and we will be
	 * printing stack using pt_regs or sw_regs. Copy another
	 * task's registers, accessing them directly at physical
	 * address if needed.
	 */

        /*
	 * Copy a part (or all) of the chain stack.
	 * If it fails then leave regs->valid set to 0.
	 */
	cr_ind = AS_STRUCT(regs->pcsp_hi).ind;
	regs->base_chain_stack = (u64 *) regs->chain_stack;
	if (!regs->base_chain_stack)
		goto out;

	regs->size_chain_stack = min(cr_ind, (u64) SIZE_CHAIN_STACK);

	sz = regs->size_chain_stack;

	dst = regs->base_chain_stack;

	src = (void *) (AS_STRUCT(regs->pcsp_lo).base + cr_ind - sz);

	/*
	 * Remember original stack address.
	 */
	regs->orig_base_chain_stack = (u64) src;

	if (unlikely(((long) dst & 0x7) || ((long) src & 0x7)
			|| ((long) sz & 0x7))) {
		printk("Not aligned chain registers!!!\n"
				"src: %lx, dst: %lx, sz: %lx\n", src, dst, sz);
		goto out;
	}

	/* Do the copy */
        if (IS_USER_ADDR(src)) {
		u64 tmp;

		tmp = ALIGN((u64) src + 1, PAGE_SIZE) - (u64) src;
		tmp = min(tmp, sz);
		while (sz) {
			phys_addr = user_address_to_phys(task,
					(e2k_addr_t) src);
			if (phys_addr == -1) {
				if (sz < regs->size_chain_stack) {
					/* We could copy something */
					regs->size_chain_stack -= sz;
					goto finish_copying_chain_stack;
				} else {
					/* Could not copy anything */
					goto out;
				}
			}
			recovery_memcpy_8(dst, (void *) phys_addr, tmp,
					TAGGED_MEM_STORE_REC_OPC,
					LDST_QWORD_FMT << LDST_REC_OPC_FMT_SHIFT
					| MAS_LOAD_PA <<
						LDST_REC_OPC_MAS_SHIFT,
					0);
			dst += tmp;
			src += tmp;
			sz -= tmp;
			tmp = min((u64) PAGE_SIZE, sz);
		}

		if (cpu_has(CPU_HWBUG_QUADRO_STRD))
			flush_DCACHE_range(regs->base_chain_stack,
					regs->size_chain_stack);
	} else {
		bool need_tlb_flush = ((unsigned long) src >= VMALLOC_START &&
				       (unsigned long) src < VMALLOC_END);

		BEGIN_USR_PFAULT("recovery_memcpy_fault",
				 "$.recovery_memcpy_fault");

		/*
		 * Another task could be executing on a user stack mapped
		 * to the kernel. In this case we have to flush our TLB
		 * (see do_sys_execve() for details).
		 */
		if (need_tlb_flush) {
			preempt_disable();
			__flush_tlb_all();
		}
		recovery_memcpy_8(dst, src, sz,
				TAGGED_MEM_STORE_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				TAGGED_MEM_LOAD_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				0);
		if (need_tlb_flush)
			preempt_enable();

		if (END_USR_PFAULT) {
			/* Most probably this was an exiting user task.
			 * It has remapped stacks into kernel and queued
			 * them for freeing, and we tried to access them
			 * when they were being freed. */
			pr_alert("WARNING chain stack was freed under us\n");

			goto out;
		}
	}
finish_copying_chain_stack:

#ifdef CONFIG_STACK_REG_WINDOW
        /* Copy a part (or all) of the procedure stack.
	 * Do _not_ set regs->valid to 0 if it fails
	 * (we can still print stack albeit without register windows) */
	psp_ind = AS_STRUCT(regs->psp_hi).ind;
	regs->base_psp_stack = (u64 *) regs->psp_stack_cache;
	if (!regs->base_psp_stack)
		goto finish_copying_psp_stack;

	regs->size_psp_stack = min(psp_ind, (u64) SIZE_PSP_STACK);

	sz = regs->size_psp_stack;

	dst = regs->base_psp_stack;

	src = (void *) (AS_STRUCT(regs->psp_lo).base + psp_ind - sz);

	if (unlikely(((long) dst & 0x7) || ((long) src & 0x7)
			|| ((long) sz & 0x7))) {
		printk("Not aligned psp registers!!!\n"
				"src: %lx, dst: %lx, sz: %lx\n", src, dst, sz);
		/* We can still print chain stack */
		regs->base_psp_stack = NULL;
		goto finish_copying_psp_stack;
	}

	if (IS_USER_ADDR(src)) {
		u64 tmp;

		tmp = ALIGN((u64) src + 1, PAGE_SIZE) - (u64) src;
		tmp = min(tmp, sz);
		while (sz) {
			phys_addr = user_address_to_phys(task,
					(e2k_addr_t) src);
			if (phys_addr == -1) {
				if (sz < regs->size_psp_stack)
					/* We could copy something */
					regs->size_psp_stack -= sz;
				else
					/* Could not copy anything
					 * (but chain stack still
					 * can be printed). */
					regs->base_psp_stack = NULL;
				goto finish_copying_psp_stack;
			}
			recovery_memcpy_8(dst, (void *) phys_addr, tmp,
					TAGGED_MEM_STORE_REC_OPC,
					LDST_QWORD_FMT << LDST_REC_OPC_FMT_SHIFT
					| MAS_LOAD_PA <<
						LDST_REC_OPC_MAS_SHIFT,
					0);
			dst += tmp;
			src += tmp;
			sz -= tmp;
			tmp = min((u64) PAGE_SIZE, sz);
		}

		if (cpu_has(CPU_HWBUG_QUADRO_STRD))
			flush_DCACHE_range(regs->base_psp_stack,
					regs->size_psp_stack);
	} else {
		bool need_tlb_flush = ((unsigned long) src >= VMALLOC_START &&
				       (unsigned long) src < VMALLOC_END);

		BEGIN_USR_PFAULT("recovery_memcpy_fault",
				 "$.recovery_memcpy_fault");

		/*
		 * Another task could be executing on a user stack mapped
		 * to the kernel. In this case we have to flush our TLB
		 * (see do_sys_execve() for details).
		 */
		if (need_tlb_flush) {
			preempt_disable();
			__flush_tlb_all();
		}
		recovery_memcpy_8(dst, src, sz,
				TAGGED_MEM_STORE_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				TAGGED_MEM_LOAD_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				0);
		if (need_tlb_flush)
			preempt_enable();

		if (END_USR_PFAULT) {
			/* Most probably this was an exiting user task.
			 * It has remapped stacks into kernel and queued
			 * them for freeing, and we tried to access them
			 * when they were being freed. */
			pr_alert("WARNING procedure stack was freed under us\n");
			goto out;
		}
	}

finish_copying_psp_stack:
#endif

        regs->task = task;
        regs->valid = 1;

	if (print_TIRs) {
		printk("-------- TIRs for task [%d] %s:\n",
				task->pid, task->comm);
        	print_all_TIRs(TIRs, nr_TIRs);
		printk("-------------------------------------------------\n");
	}
out:
	return;
}

#ifdef CONFIG_CLI_CHECK_TIME
cli_info_t 	cli_info[2];
tt0_info_t 	tt0_info[2];
int 		cli_info_needed = 0;

void
start_cli_info(void)
{
	printk("start_cli_info: clock %ld\n", E2K_GET_DSREG(clkr));
	memset(cli_info, 0, sizeof(cli_info));
	cli_info_needed = 1;
}

void tt0_prolog_ticks(long ticks)
{
	if (cli_info_needed && Max_tt0_prolog < ticks) {
		Max_tt0_prolog = ticks;
	}
}

void
print_cli_info(void)
{
	
	printk("print_cli_info: for CPU 0\n");	
	printk("Max_tt0_prolog %ld\n", tt0_info[0].max_tt0_prolog);
	printk("max_cli %ld max_cli_ip 0x%lx max_cli_cl %ld end_cl %ld\n",
		cli_info[0].max_cli,
		cli_info[0].max_cli_ip,
		cli_info[0].max_cli_cl,
		cli_info[0].max_cli_cl + cli_info[0].max_cli);
	
	printk("max_gcli %ld max_gcli_ip 0x%lx max_gcli_cl %ld\n",
		cli_info[0].max_gcli,
		cli_info[0].max_gcli_ip,
		cli_info[0].max_gcli_cl);
	printk("\n");
	if (num_online_cpus() == 1) return;

	printk("print_cli_info: for CPU 1\n");
	printk("Max_tt0_prolog %ld\n", tt0_info[1].max_tt0_prolog);
	printk("max_cli %ld max_cli_ip 0x%lx max_cli_cl %ld end_cl %ld\n",
		cli_info[1].max_cli,
		cli_info[1].max_cli_ip,
		cli_info[1].max_cli_cl,
		cli_info[1].max_cli_cl + cli_info[1].max_cli);
	
	printk("max_gcli %ld max_gcli_ip 0x%lx max_gcli_cl %ld\n",
		cli_info[1].max_gcli,
		cli_info[1].max_gcli_ip,
		cli_info[1].max_gcli_cl);
}
#else // CONFIG_CLI_CHECK_TIME
void
print_cli_info(void) {}	
#endif

#define MAX_TICKS_TRUSS 0x10
long ticks_truss1[MAX_TICKS_TRUSS];
int truss_indx1 = 0;
long ticks_truss2[MAX_TICKS_TRUSS];
int truss_indx2 = 0;

inline void do_ticks_truss1(void)
{ 
	ticks_truss1[truss_indx1] = E2K_GET_DSREG(clkr);
	truss_indx1++; truss_indx1 &= (MAX_TICKS_TRUSS - 1);
} 
inline void do_ticks_truss2(void)
{ 
	ticks_truss2[truss_indx2] = E2K_GET_DSREG(clkr);
	truss_indx2++; truss_indx2 &= (MAX_TICKS_TRUSS - 1);
} 

void
print_t_truss(void)
{
	int i;
	printk("truss_indx1 == %d truss_indx2 %d\n",
		truss_indx1, truss_indx2);
	for (i = 0; i < MAX_TICKS_TRUSS; i++) {
		printk("%d t1 %ld t2 %ld\n", i,
			ticks_truss1[i], ticks_truss2[i]);
	}
}

static void print_chain_stack(struct stack_regs *regs,
		int show_reg_window, int skip);
void print_stack(struct task_struct *task);

#define PRINT_MAX_PATH_LENGTH 256
void get_path(struct dentry  *file_dentry, char *path)
{
	struct dentry           *d_parent;
	struct qstr 		*d_name;
	int			i;
	char			path1[PRINT_MAX_PATH_LENGTH];

	d_name = &(file_dentry->d_name);
	strcpy(path, "/");
	strlcat(path, (char *) d_name->name, PRINT_MAX_PATH_LENGTH);
	d_parent = file_dentry->d_parent;
	/* This code is really racy and does not handle everything as
	 * it should so drop out when spinning for too long. When this
	 * happens output will start with a long line if /'s. */
	for (i = 0; i < 50; i++) {
		if (!d_parent)
			break;

		d_name = &(d_parent->d_name);
		if (strcmp((char *) d_name->name, "/") == 0)
			break;

		strcpy(path1, "/");
		strlcat(path1, (char *) d_name->name, PRINT_MAX_PATH_LENGTH);
		strlcat(path1, path, PRINT_MAX_PATH_LENGTH);
		strncpy(path, path1, PRINT_MAX_PATH_LENGTH);
		d_parent = d_parent->d_parent;
	}
	return;
}

void print_mmap(struct task_struct *task)
{
	char path_for_mmap[PRINT_MAX_PATH_LENGTH];
	struct mm_struct 	*mm = task->mm;
	struct vm_area_struct 	*vm_mm;
	struct file 		*vm_file;
	struct dentry           *file_dentry;
	long			all_sz = 0;

	if (mm == NULL) {
		printk("     There aren't mmap areas for pid %d \n", task->pid);
		return;
	}

	printk("============ MMAP AREAS for pid %d =============\n", task->pid);
	vm_mm = mm->mmap;
	vm_file = vm_mm->vm_file;
	file_dentry = vm_file->f_dentry;
	vm_mm = mm->mmap;	
	for (;;) {
		if (vm_mm == NULL) break;
		vm_file = vm_mm->vm_file;
		printk("ADDR 0x%-10lx END 0x%-10lx ",
			vm_mm->vm_start,
			vm_mm->vm_end);
		all_sz += vm_mm->vm_end - vm_mm->vm_start;
		if (vm_mm->vm_flags & VM_WRITE) {
			printk(" WR ");
		}
		if (vm_mm->vm_flags & VM_READ) {
			printk(" RD ");
		}
		if (vm_mm->vm_flags & VM_EXEC) {
			printk(" EX ");
		}
		printk(" PROT 0x%016lx", pgprot_val(vm_mm->vm_page_prot));
		if (vm_file != NULL) {
			file_dentry = vm_file->f_dentry;
			get_path(file_dentry, path_for_mmap);
			printk("        %s", path_for_mmap);
		}
		printk("\n");

		vm_mm = vm_mm->vm_next;
	}	
	printk("============ END OF MMAP AREAS all_sz %ld ======\n", all_sz);
}

void print_chain(e2k_cr0_hi_t cr0_hi,
	    e2k_cr1_hi_t cr1_hi,
	    e2k_cr1_lo_t cr1_lo,
	    struct task_struct *task)
{
	char path_for_chain[PRINT_MAX_PATH_LENGTH];
	unsigned long		ip;
	struct vm_area_struct 	*vm_mm;
	struct dentry           *file_dentry;

	ip = (long)AS_STRUCT(cr0_hi).ip << 3;
	if (ip > PAGE_OFFSET) {
		printk("IP 0x%-11lx   <kernel> ", ip);
		print_symbol(" (%30s) ", ip);
		return;
	} else {
		printk("IP 0x%-11lx    ", ip);
	}
	if (task == NULL) {
		printk("    %s\n", "unknown");
		return;
	}
	vm_mm = find_vma(task->mm, ip);
	if (vm_mm != NULL) {
		if (vm_mm->vm_file == NULL) {
			printk("    %s\n", "unknown");
			return;
		}
		file_dentry = vm_mm->vm_file->f_dentry;
		printk("mmap 0x%-10lx    ", vm_mm->vm_start);
		get_path(file_dentry, path_for_chain);
		printk("    %s", path_for_chain);
		printk("      wbs 0x%x ussz 0x%x br 0x%x\n",
			(int)AS_STRUCT(cr1_lo).wbs,
			(int)AS_STRUCT(cr1_hi).ussz << 4,
			(int)AS_STRUCT(cr1_hi).br);
	} else {
		printk("    %s\n", "unknown");
	}

}

static void print_wd(u64 pcsp_wd, u64 psp_wd, u64 wbs, int n)
{
	int i;
	int j;
	e2k_cr0_hi_t	cr0_hi;
	e2k_cr0_lo_t	cr0_lo;
	e2k_cr1_hi_t	cr1_hi;
	e2k_cr1_lo_t	cr1_lo;
	e2k_br_t	br;
	e2k_psr_t	psr;

	AS_WORD(cr0_lo) = *((u64 *)(pcsp_wd + CR0_LO_I));
	AS_WORD(cr0_hi) = *((u64 *)(pcsp_wd + CR0_HI_I));
	AS_WORD(cr1_lo) = *((u64 *)(pcsp_wd + CR1_LO_I));
	AS_WORD(cr1_hi) = *((u64 *)(pcsp_wd + CR1_HI_I));

	printk("====== PCSP window =====\n");

	printk("cr0_hi ip 0x%lx\n", (long)AS_STRUCT(cr0_hi).ip << 3);
	printk("cr0_lo pf 0x%lx\n", (long)AS_STRUCT(cr0_lo).pf);
	AS_WORD(br) = AS_STRUCT(cr1_hi).br;
	printk("cr1_hi ussz 0x%x br 0x%x : rbs 0x%x rsz 0x%x "
		"rcur 0x%x psz 0x%x pcur 0x%x\n",
		(int)AS_STRUCT(cr1_hi).ussz << 4,
		(int)AS_WORD(br), (int)AS_STRUCT(br).rbs,
		(int)AS_STRUCT(br).rsz, (int)AS_STRUCT(br).rcur,
		(int)AS_STRUCT(br).psz, (int)AS_STRUCT(br).pcur);
	AS_WORD(psr) = AS_STRUCT(cr1_lo).psr;
	printk("cr1_lo: unmie %d nmie %d uie %d lw %d sge %d ie %d pm %d\n",
		(int)AS_STRUCT(psr).unmie,
		(int)AS_STRUCT(psr).nmie,
		(int)AS_STRUCT(psr).uie,
		(int)AS_STRUCT(psr).lw,
		(int)AS_STRUCT(psr).sge,
		(int)AS_STRUCT(psr).ie,
		(int)AS_STRUCT(psr).pm);
	printk("cr1_lo: cuir 0x%x wbs 0x%x wpsz %d wfx %d ein %d "
				"tr 0x%x\n",
		(int)AS_STRUCT(cr1_lo).cuir,
		(int)AS_STRUCT(cr1_lo).wbs,
		(int)AS_STRUCT(cr1_lo).wpsz,
		(int)AS_STRUCT(cr1_lo).wfx,
		(int)AS_STRUCT(cr1_lo).ein,
		(int)AS_STRUCT(cr1_lo).tr);
#if 0
	for (i = SZ_OF_CR - 8; i >= 0; i = i - 8) {
		printk("0x%lx pcsp_wd[%d] 0x%lx\n",
			(u64)(pcsp_wd + i), i, *(u64 *)(pcsp_wd + i));
	}
#endif
	print_chain(cr0_hi, cr1_hi, cr1_lo, NULL);
	printk("====== PSP window == wbs %ld (wbs * EXT_4_NR_SZ)/8 %ld\n",
			wbs, (wbs * EXT_4_NR_SZ) / 8);
	j = 0;
	for (i = wbs * EXT_4_NR_SZ - 8; i >= 0; i = i - 8) {
		if (n > 0 && j > n) break;
		printk("0x%lx  psp_wd[%d] 0x%lx\n",
			(u64)(psp_wd + i), i, *(u64 *)(psp_wd + i));
		j = j + 1;
	}
}

static void
go_hd_stk( e2k_psp_lo_t psp_lo, e2k_psp_hi_t psp_hi,
		e2k_pcsp_hi_t pcsp_hi, e2k_pcsp_lo_t pcsp_lo)
{
	u64		psp_base;
	u64		pcsp_base;
	u64		psp_ind;
	u64		pcsp_ind;
	e2k_cr1_lo_t	cr1_lo;

	psp_base = AS_STRUCT(psp_lo).base;
	psp_ind = AS_STRUCT(psp_hi).ind;
	pcsp_base = AS_STRUCT(pcsp_lo).base;
	pcsp_ind = AS_STRUCT(pcsp_hi).ind;

	for (;;) {
		
		AS_WORD(cr1_lo) = *((u64 *)(pcsp_base + pcsp_ind + CR1_LO_I));
		psp_ind = psp_ind - AS_STRUCT(cr1_lo).wbs * EXT_4_NR_SZ;
		print_wd(pcsp_base + pcsp_ind, psp_base + psp_ind,
			AS_STRUCT(cr1_lo).wbs, 0);
		pcsp_ind = pcsp_ind  - SZ_OF_CR;
		if (pcsp_base >= pcsp_base + pcsp_ind) {
			printk("pcsp_base 0x%lx >= pcsp_base+pcsp_ind 0x%lx\n",
				pcsp_base, pcsp_base+pcsp_ind);
			printk("pcsp_base 0x%lx pcsp_ind 0x%lx\n",
				pcsp_base, pcsp_ind);
			printk("psp_base 0x%lx psp_ind 0x%lx\n",
				psp_base, psp_ind);
			break;
		}
	}
}
void
print_hd_stk(char *str)
{
	unsigned long flags;
	e2k_psp_lo_t	psp_lo;
	e2k_psp_hi_t	psp_hi;
	e2k_pcsp_lo_t	pcsp_lo;
	e2k_pcsp_hi_t	pcsp_hi;
	e2k_usd_lo_t	usd_lo;
	e2k_usd_hi_t 	usd_hi;
	
	printk("=================== print_hd_stk:  =======  %s\n", str);
	print_stack(current);

	raw_all_irq_save(flags);
	E2K_FLUSHCPU;
	psp_hi = READ_PSP_HI_REG();
	psp_lo = READ_PSP_LO_REG();	
	pcsp_hi = READ_PCSP_HI_REG();
	pcsp_lo = READ_PCSP_LO_REG();	
	usd_hi = READ_USD_HI_REG();
	usd_lo = READ_USD_LO_REG();
	
	E2K_FLUSH_WAIT;

	printk("====== USD =========\n");
	printk("usd_lo 0x%lx usd_hi 0x%lx\n", AS_WORD(usd_lo), AS_WORD(usd_hi));
	printk("usd_lo: base %lx p %lx\n", 
		(u64)AS_STRUCT(usd_lo).base,
		(u64)AS_STRUCT(usd_lo).p);

	printk("usd_hi: curptr  %lx size %lx\n", 
		(u64)(usd_hi._USD_hi_curptr),
		(u64)AS_STRUCT(usd_hi).size);
	go_hd_stk(psp_lo, psp_hi, pcsp_hi, pcsp_lo);
	raw_all_irq_restore(flags);
	printk("=================== print_hd_stk: END =======  %s\n", str);
}

#ifdef CONFIG_STACK_REG_WINDOW
/*
 * print_reg_window - print local registers from psp stack
 * @window_base - pointer to the window in psp stack
 * @window_size - size of the window in psp stack (in quadro registers)
 * @fx - do print extensions?
 *
 * Is inlined to make sure that the return will not flush stack.
  */
static inline void
print_reg_window(u64 window_base, int window_size,
		int fx, u64 rbs, u64 rsz, u64 rcur)
{
	int qreg, dreg, dreg_ind;
	u64 *rw = (u64 *)window_base;
	u64 qreg_lo;
	u64 qreg_hi;
	u32 tag_lo;
	u32 tag_hi;
	u64 ext_lo = 0;
	u64 ext_hi = 0;
	char brX0_name[6], brX1_name[6];

	for (qreg = window_size - 1; qreg >= 0; qreg --) {
		dreg_ind = qreg * (EXT_4_NR_SZ / sizeof (*rw));

		E2K_LOAD_VAL_AND_TAGD(&rw[dreg_ind + 0], qreg_lo, tag_lo);
		if (fx)
			ext_hi = rw[dreg_ind + 3];
		if (machine.iset_ver < E2K_ISET_V5) {
			E2K_LOAD_VAL_AND_TAGD(
				&rw[dreg_ind + 1], qreg_hi, tag_hi);
			if (fx)
				ext_lo = rw[dreg_ind + 2];
		} else {
			E2K_LOAD_VAL_AND_TAGD(
				&rw[dreg_ind + 2], qreg_hi, tag_hi);
			if (fx)
				ext_lo = rw[dreg_ind + 1];
		}

		dreg = qreg * 2;

		/* Calculate %br[] register number */
		if (qreg >= rbs && qreg <= (rbs + rsz) && rsz >= rcur) {
			int qbr, brX0, brX1;

			qbr = (qreg - rbs) + ((rsz + 1) - rcur);

			while (qbr > rsz)
				qbr -= rsz + 1;

			brX0 = 2 * qbr;
			brX1 = 2 * qbr + 1;

			snprintf(brX0_name, 7, "%sb%d/", (brX0 < 10) ? "  " :
					((brX0 < 100) ? " " : ""), brX0);
			snprintf(brX1_name, 7, "%sb%d/", (brX0 < 10) ? "  " :
					((brX0 < 100) ? " " : ""), brX1);
		} else {
			memset(brX0_name, ' ', 5);
			memset(brX1_name, ' ', 5);
			brX0_name[5] = 0;
			brX1_name[5] = 0;
		}

		if (fx)
			printk("     %sr%-3d: %x %016lx %04lx "
				"%sr%-3d: %x %016lx %04lx\n",
				brX0_name, dreg, tag_lo, qreg_lo, ext_lo,
				brX1_name, dreg + 1, tag_hi, qreg_hi, ext_hi);
		else
			printk("     %sr%-3d: %x 0x%016lx    "
					"%sr%-3d: %x 0x%016lx\n",
					brX0_name, dreg, tag_lo, qreg_lo,
					brX1_name, dreg + 1, tag_hi, qreg_hi);
	}
}

static inline void print_predicates(e2k_cr0_lo_t cr0_lo, e2k_cr1_hi_t cr1_hi)
{
	u64 pf = AS(cr0_lo).pf;
	u64 i, values = 0, tags = 0;

	for (i = 0; i < 32; i++) {
		values |= (pf & (1ULL << 2 * i)) >> i;
		tags |= (pf & (1ULL << (2 * i + 1))) >> (i + 1);
	}
	printk("      predicates[31:0] %08x   ptags[31:0] %08x   psz %d   pcur %d\n",
		(u32) values, (u32) tags, AS(cr1_hi).psz, AS(cr1_hi).pcur);
}
#endif

void
print_all_TIRs(e2k_tir_t *TIRs, u64 nr_TIRs)
{
	tir_hi_struct_t	tir_hi;
	tir_lo_struct_t	tir_lo;
	int i;

	printk("TIR all registers:\n");
	for (i = nr_TIRs; i >= 0; i --) {
		tir_hi = TIRs[i].TIR_hi;
		tir_lo = TIRs[i].TIR_lo;

		pr_alert("TIR.hi[%d]: 0x%016lx : exc 0x%011lx al 0x%x aa 0x%x #%d\n",
			i, tir_hi.TIR_hi_reg,
			tir_hi.TIR_hi_exc, tir_hi.TIR_hi_al,
			tir_hi.TIR_hi_aa, tir_hi.TIR_hi_j);

		if (AS(tir_hi).exc) {
			u64 exc = AS(tir_hi).exc;
			int nr_intrpt;

			pr_alert("  ");
			for (nr_intrpt = __ffs64(exc); exc != 0;
					exc &= ~(1UL << nr_intrpt),
					nr_intrpt = __ffs64(exc))
				pr_cont(" %s", exc_tbl_name[nr_intrpt]);
			pr_cont("\n");
		}

		pr_alert("TIR.lo[%d]: 0x%016lx : IP 0x%012lx\n",
			i, tir_lo.TIR_lo_reg, tir_lo.TIR_lo_ip);
	}
}

void
print_tc_record(trap_cellar_t *tcellar, int num)
{
	tc_fault_type_t ftype;
	tc_dst_t	dst ;
	tc_opcode_t	opcode;
	u64		data;
	u32		data_tag;

	AW(dst) = AS(tcellar->condition).dst;
	AW(opcode) = AS(tcellar->condition).opcode;
	AW(ftype) = AS(tcellar->condition).fault_type;

	E2K_LOAD_VAL_AND_TAGD(&tcellar->data, data, data_tag);
	printk("   record #%d: address 0x%016lx data 0x%016lx tag 0x%x\n"
	       "              condition 0x%016lx:\n"
	       "                 dst 0x%05x: address 0x%04x, vl %d, vr %d\n"
	       "                 opcode 0x%03x: fmt 0x%02x, npsp 0x%x\n"
	       "                 store 0x%x, s_f  0x%x, mas 0x%x\n"
	       "                 root  0x%x, scal 0x%x, sru 0x%x\n"
	       "                 chan  0x%x, se   0x%x, pm  0x%x\n" 
	       "                 fault_type 0x%x:\n"
	       "                    intl_res_bits = %d MLT_trap     = %d\n"
	       "                    ph_pr_page	   = %d page_bound   = %d\n"
	       "                    io_page       = %d isys_page    = %d\n"
	       "                    prot_page     = %d priv_page    = %d\n"
	       "                    illegal_page  = %d nwrite_page  = %d\n"
	       "                    page_miss     = %d ph_bound     = %d\n"
	       "                    global_sp     = %d\n"
	       "                 miss_lvl 0x%x, num_align 0x%x, empt    0x%x\n"
	       "                 clw      0x%x, rcv       0x%x  dst_rcv 0x%x\n",
	       num,
	       (u64) tcellar->address, data, data_tag,
	       (u64) AW(tcellar->condition), 
	       (u32)AW(dst), (u32)(AS(dst).address), (u32)(AS(dst).vl), 
	       (u32)(AS(dst).vr),
	       (u32)AW(opcode), (u32)(AS(opcode).fmt),(u32)(AS(opcode).npsp), 
	       (u32)AS(tcellar->condition).store,
	       (u32)AS(tcellar->condition).s_f,
	       (u32)AS(tcellar->condition).mas,
	       (u32)AS(tcellar->condition).root,
	       (u32)AS(tcellar->condition).scal,
	       (u32)AS(tcellar->condition).sru,
	       (u32)AS(tcellar->condition).chan,
	       (u32)AS(tcellar->condition).spec,
	       (u32)AS(tcellar->condition).pm,
	       (u32)AS(tcellar->condition).fault_type,
	       (u32)AS(ftype).intl_res_bits,	(u32)(AS(ftype).exc_mem_lock),
	       (u32)AS(ftype).ph_pr_page,	(u32)AS(ftype).page_bound,
	       (u32)AS(ftype).io_page,		(u32)AS(ftype).isys_page,
	       (u32)AS(ftype).prot_page,	(u32)AS(ftype).priv_page,
	       (u32)AS(ftype).illegal_page,	(u32)AS(ftype).nwrite_page,
	       (u32)AS(ftype).page_miss,	(u32)AS(ftype).ph_bound,
	       (u32)AS(ftype).global_sp,
	       (u32)AS(tcellar->condition).miss_lvl, 
	       (u32)AS(tcellar->condition).num_align, 
	       (u32)AS(tcellar->condition).empt, 
	       (u32)AS(tcellar->condition).clw,
	       (u32)AS(tcellar->condition).rcv,
	       (u32)AS(tcellar->condition).dst_rcv);
}

void
print_all_TC(trap_cellar_t *TC, int TC_count)
{
	int i;

	printk("TRAP CELLAR all %d records:\n", TC_count / 3);
	for (i = 0; i < TC_count / 3; i++)
		print_tc_record(&TC[i], i);
}

void
print_task_pt_regs(pt_regs_t *pt_regs)
{
	if (!pt_regs)
		return;

	print_pt_regs("", pt_regs);

	if (from_trap(pt_regs)) {
		struct trap_pt_regs *trap = pt_regs->trap;

		print_all_TIRs(trap->TIRs, trap->nr_TIRs);
		print_all_TC(trap->tcellar, trap->tc_count);
	}
}

#ifdef CONFIG_PROC_FS
int
print_statm(task_pages_info_t *tmm, pid_t pid)
{
	struct task_struct	*tsk = current;
	struct mm_struct *mm = get_task_mm(tsk);
	task_pages_info_t	umm;

	if (!pid || (pid == current->pid)) goto get_mm;

	do {
		tsk = next_task(tsk);
		if (tsk->pid == pid) {
			mm = get_task_mm(tsk);
			break;
		}
	} while(tsk != current);
	
	if (tsk == current) return -1;
get_mm:
	if (tsk->mm) { umm.size =
		task_statm(mm, &umm.shared, &umm.text, &umm.data, &umm.resident);
		copy_to_user((void*)tmm, (void*)&umm, sizeof(task_pages_info_t));
		return 0;
	} else
		return -1;
}
#endif

void
print_pids(void)
{
        struct task_struct 	*g = NULL, *p = NULL;

	do_each_thread(g, p) {
		if (!p) {
			pr_info("print_pids: task pointer == NULL\n");
		} else {
			pr_info("print_pids: pid %d state 0x%lx policy %d name %s\n",
				p->pid, p->state, p->policy, p->comm);
		}
	} while_each_thread(g, p);
}

#ifdef	CONFIG_PRINT_KERNEL_THREADS
int print_kernel_threads = 1;
#else
int print_kernel_threads = 0;
#endif


void notrace print_running_tasks(int show_reg_window)
{
#ifdef CONFIG_SMP
	struct stack_regs *stack_regs;
	int cpu, this_cpu;
#endif
	unsigned long flags;

	/* stack_regs_cache[] is protected by IRQ-disable
	 * (we assume that NMI handlers will not call print_stack() and
	 * do not disable NMIs here as they are used by copy_stack_regs()) */
	raw_local_irq_save(flags);

	pr_alert("\n=========================== RUNNING TASKS begin ==========================\n");
	print_stack_frames(current, show_reg_window, 0);

#ifdef CONFIG_SMP
	this_cpu = raw_smp_processor_id();
	stack_regs = &stack_regs_cache[this_cpu];

	for_each_online_cpu(cpu) {
		if (cpu == this_cpu)
			continue;

		pr_alert("\n");

# ifdef CONFIG_STACK_REG_WINDOW
		stack_regs->show_user_regs = debug_userstack;
# endif
# ifdef CONFIG_DATA_STACK_WINDOW
		stack_regs->show_k_data_stack = debug_datastack;
# endif
		get_cpu_regs_using_nmi(cpu, stack_regs);
		if (stack_regs->valid == 0) {
			pr_alert("WARNING could not get stack from CPU #%d, "
					"stack will not be printed\n", cpu);
			continue;
		}

		print_chain_stack(stack_regs, show_reg_window, 0);
	}
#endif
	raw_local_irq_restore(flags);

	pr_alert("=========================== RUNNING TASKS end ============================\n");
}

void
print_all_mmap(void)
{
        struct task_struct	*g = NULL, *p = NULL;

	read_lock(&tasklist_lock);
	do_each_thread(g, p) {
        	print_mmap(p);
	} while_each_thread(g, p);
	read_unlock(&tasklist_lock);
}


static notrace void __parse_chain_stack(struct task_struct *const p,
		int (*func)(struct task_struct *, e2k_mem_crs_t *,
				unsigned long, void *, void *, void *),
		void *arg1, void *arg2, void *arg3)
{
	unsigned long phys_addr, last_page, flags;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_mem_crs_t *frame;
	u64 base;
	s64 cr_ind;

	if (p == current) {
		raw_all_irq_save(flags);
		E2K_FLUSHC;
		pcsp_hi = READ_PCSP_HI_REG();
		pcsp_lo = READ_PCSP_LO_REG();
		raw_all_irq_restore(flags);
	} else {
		/*
		 * Note that the information from sw_regs is unreliable,
		 * so the actual memory access should be done wtih care.
		 */
		pcsp_lo = p->thread.sw_regs.pcsp_lo;
		pcsp_hi = p->thread.sw_regs.pcsp_hi;
		/* We do not access pcsp_hi.size so there is
		 * no need to check 'TS_HW_STACKS_EXPANDED' */

		last_page = -1;
	}

	base = AS_STRUCT(pcsp_lo).base;
	cr_ind = AS_STRUCT(pcsp_hi).ind;
	frame = (e2k_mem_crs_t *) (base + cr_ind);

	if (p == current)
		E2K_FLUSH_WAIT;

	while (1) {
		e2k_mem_crs_t copied_frame;

		--frame;
		if (frame <= (e2k_mem_crs_t *) base)
			break;

		if (p == current) {
			copied_frame = *frame;
		} else if ((unsigned long) frame >= TASK_SIZE) {
			bool need_tlb_flush =
				       (unsigned long) frame >= VMALLOC_START &&
				       (unsigned long) frame < VMALLOC_END;

			/*
			 * Another task could be executing on a user stack
			 * mapped to the kernel. In this case we have to
			 * flush our TLB (see do_sys_execve() for details).
			 */
			if (need_tlb_flush) {
				raw_all_irq_save(flags);
				flush_TLB_kernel_page((unsigned long) frame);
			}

			/*
			 * Should be careful here - mapped stacks of
			 * other processes can disappear at any moment.
			 * So we disable page fault handling and bail
			 * out at the first error.
			 */
			pagefault_disable();
			BEGIN_USR_PFAULT("lbl___parse_chain_stack", "0f");
			copied_frame = *frame;
			LBL_USR_PFAULT("lbl___parse_chain_stack", "0:");
			pagefault_enable();
			if (need_tlb_flush)
				raw_all_irq_restore(flags);
			if (END_USR_PFAULT)
				break;
		} else {
			/*
			 * We cannot use switch_mm to access another
			 * task's stacks since our own stacks might be
			 * in current->active_mm if we are a user process.
			 */
			unsigned long page = round_down((unsigned long) frame,
					PAGE_SIZE);

			if (page != last_page) {
				phys_addr = user_address_to_phys(p,
						(e2k_addr_t) frame);
				if (phys_addr == -1)
					break;
				last_page = page;
			} else {
				phys_addr -= SZ_OF_CR;
			}

			recovery_memcpy_8(&copied_frame, (void *) phys_addr,
					SZ_OF_CR, TAGGED_MEM_STORE_REC_OPC,
					LDST_QWORD_FMT << LDST_REC_OPC_FMT_SHIFT
					| MAS_LOAD_PA <<
						LDST_REC_OPC_MAS_SHIFT,
					0);
		}

		if (func(p, &copied_frame, (unsigned long) frame,
				arg1, arg2, arg3))
			break;
	}
}

/*
 * Parse the chain stack of @p backwards starting from
 * the last frame and call @func for every frame, passing
 * to it the frame and arguments @arg1, @arg2 and @arg3.
 */
notrace void parse_chain_stack(struct task_struct *p,
		int (*func)(struct task_struct *, e2k_mem_crs_t *,
				unsigned long, void *, void *, void *),
		void *arg1, void *arg2, void *arg3)
{
	if (p == NULL)
		p = current;

	if (p != current) {
		might_sleep();

		/*
		 * Protect p->mm from changing in case the chain stack is there
		 */
		task_lock(p);

		/*
		 * Chain stack and task_struct are freed at different places,
		 * and it's possible that task_struct still exists while stack
		 * does not. Combination of task_lock() and the check for
		 * PF_EXITING takes care of this race - we parse chain stack
		 * only for existing tasks with existing stacks.
		 */
		if (p->flags & PF_EXITING)
			goto out_unlock;
	}

	__parse_chain_stack(p, func, arg1, arg2, arg3);

out_unlock:
	if (p != current)
		task_unlock(p);
}


#ifdef CONFIG_USR_CONTROL_INTERRUPTS        
static notrace int correct_psr_register(struct task_struct *unused,
		e2k_mem_crs_t *frame, void *arg1, void *arg2, void *arg3)
{
	u64 maska = (u64) arg1;
	u64 cr_ip = AS_WORD(frame->cr0_hi);
        e2k_cr1_lo_t   cr1_lo;

	if ((cr_ip < TASK_SIZE)) {
		AS_STRUCT(frame->cr1_lo).psr = maska;
	}
	return 0;
}
#endif /* CONFIG_USR_CONTROL_INTERRUPTS */


static 	char filename_buf[256];

static char *
get_addr_file_name (e2k_addr_t addr, e2k_addr_t *start_addr_p,
			struct task_struct *task)
{
	struct vm_area_struct *vma;
	struct dentry *dentry;
	char *name = NULL, *ptr;

        *start_addr_p = (long) NULL;

	if ((unsigned long) addr >= TASK_SIZE || !task->mm)
		return "";

	vma = find_vma(task->mm, addr);

	if (vma == NULL || vma->vm_start > (unsigned long) addr)
		return NULL;

	/* Assume that load_base == vm_start */
	*start_addr_p = vma->vm_start;

	if (vma->vm_file == NULL || vma->vm_file->f_dentry == NULL)
		return NULL;

	dentry = vma->vm_file->f_dentry;
	ptr = filename_buf + sizeof(filename_buf);
	*--ptr = '\0';

	for (;;) {
		if (dentry->d_name.name) {
			name = (char *) dentry->d_name.name;
		} else {
			return NULL;
		}

		if (dentry->d_parent == NULL || dentry == dentry->d_parent)
			break;

		ptr = ptr - strlen(name);
		strncpy(ptr, name, strlen(name));
		*--ptr = '/';

		dentry = dentry->d_parent;
	}

	return ptr;
}

static DEFINE_RAW_SPINLOCK(print_stack_lock);

/**
 * print_stack_frames - print task's stack to console
 * @task: which task's stack to print?
 * @show_reg_window: print local registers?
 * @skip: how many frames to skip from the top of the stack.
 */
noinline void
print_stack_frames(struct task_struct *task, int show_reg_window, int skip)
{
	unsigned long flags;
	int cpu;
	struct stack_regs *stack_regs;

	if (unlikely(task == NULL)) {
		pr_alert("print_stack: task == NULL\n");
		return;
	}

	if (test_and_set_bit(PRINT_FUNCY_STACK_WORKS, &task->thread.flags)) {
		pr_alert("  %d: print_stack: works already on pid %d\n",
				current->pid, task->pid);
		return;
	}

	/* stack_regs_cache[] is protected by IRQ-disable
	 * (we assume that NMI handlers will not call print_stack() and
	 * do not disable NMIs here as they are used by copy_stack_regs()) */
	raw_local_irq_save(flags);

	if (task == current) {
		pr_alert("%s", linux_banner);
	}

	cpu = raw_smp_processor_id();
	stack_regs = &stack_regs_cache[cpu];

#ifdef CONFIG_STACK_REG_WINDOW
	stack_regs->show_user_regs = debug_userstack;
#endif
#ifdef CONFIG_DATA_STACK_WINDOW
	stack_regs->show_k_data_stack = debug_datastack;
#endif
	copy_stack_regs(task, stack_regs);

	/* All checks of stacks validity are performed in print_chain_stack() */

	print_chain_stack(stack_regs, show_reg_window, skip);

	raw_local_irq_restore(flags);

	clear_bit(PRINT_FUNCY_STACK_WORKS, &task->thread.flags);
}

void print_stack(struct task_struct *task)
{
	print_stack_frames(task, 1, 0);
}
EXPORT_SYMBOL(print_stack);

static inline void
print_funcy_ip(e2k_cr0_hi_t cr0_hi, u64 cr_base, u64 cr_ind,
		struct task_struct *task, u64 orig_base)
{
	e2k_addr_t start_addr, addr;
	char *file_name = NULL;
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	int traced = 0;
#endif

	addr = (long)AS_STRUCT(cr0_hi).ip << 3;

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (task->ret_stack) {
		int index;
		for (index = 0; index <= task->curr_ret_stack; index++)
			if (task->ret_stack[index].fp == orig_base + cr_ind) {
				addr = task->ret_stack[index].ret;
				traced = 1;
				break;
			}
	}
#endif

	file_name = get_addr_file_name(addr, &start_addr, task);
	if (file_name != NULL) {
		printk("  %012lx  %20s", addr,
				(file_name[0] == 0) ? "<kernel>" : file_name);
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
		if (traced)
			print_symbol(" %30s (traced)\n", addr);
		else
#endif
			print_symbol(" %30s\n", addr);
	} else {
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
		if (traced)
			printk("  %012lx (traced)\n", addr);
		else
#endif
			printk("  %012lx\n", addr);
	}
}

#if defined(CONFIG_STACK_REG_WINDOW) || defined(CONFIG_DATA_STACK_WINDOW)
/* This function allocates memory necessary to print
 * procedure stack regsiters from other CPUs */
static int __init
print_stack_init(void)
{
	int cpu;

	/* Even if HOTPLUG is enabled all possible CPUs are present
	 * at boot time, so it is wiser to use cpu_present_mask
	 * instead of cpu_possible_mask (to save memory). */
	for_each_present_cpu(cpu) {
		if (cpu == 0)
			continue;

#ifdef CONFIG_STACK_REG_WINDOW
		stack_regs_cache[cpu].psp_stack_cache = kmalloc(SIZE_PSP_STACK,
				GFP_KERNEL);
		if (stack_regs_cache[cpu].psp_stack_cache == NULL) {
                        printk("WARNING print_stack_init: no memory, printing "
					"running tasks' register stacks from "
					"CPU #%d will not be done\n", cpu);
			continue;
		}
#endif
#ifdef CONFIG_DATA_STACK_WINDOW
		stack_regs_cache[cpu].k_data_stack_cache = kmalloc(
				SIZE_DATA_STACK, GFP_KERNEL);
		if (stack_regs_cache[cpu].k_data_stack_cache == NULL) {
			printk("WARNING print_stack_init: no memory, printing "
					"running tasks' kernel data stacks from"
					" CPU #%d will not be done\n", cpu);
			continue;
		}
#endif
	}

	return 0;
}
/* Initialize printing stacks from other CPUs before initializing those CPUs */
early_initcall(print_stack_init);
#endif

int print_window_regs = 0;  /* may be changed in cmdline "print_window_regs"
                             * (print window regs for all stack(1)
                             * or only for running task(0) 
                             */

static const char state_to_char[] = TASK_STATE_TO_CHAR_STR;

static char task_state_char(unsigned long state)
{
	int bit = state ? __ffs(state) + 1 : 0;

	return bit < sizeof(state_to_char) - 1 ? state_to_char[bit] : '?';
}

#ifdef CONFIG_DATA_STACK_WINDOW
static void print_k_data_stack(struct stack_regs *regs, int *pt_regs_num,
		unsigned long base, u64 size)
{
	unsigned long delta = regs->real_k_data_stack_addr -
			regs->base_k_data_stack;
	bool pt_regs_valid = regs->pt_regs[*pt_regs_num].valid;
	unsigned long pt_regs_addr = regs->pt_regs[*pt_regs_num].addr;
	unsigned long addr;
	bool show_pt_regs;

	if (!size)
		return;

	if (pt_regs_valid && pt_regs_addr >= (unsigned long) base + delta &&
			pt_regs_addr < (unsigned long) base + delta + size) {
		show_pt_regs = 1;
		(*pt_regs_num)++;
	} else {
		show_pt_regs = 0;
	}

	printk("    DATA STACK from %lx to %lx\n", base + delta,
			base + delta + size);
	for (addr = base; addr < base + size; addr += 16) {
		u32 tag_lo, tag_hi;
		u64 value_lo, value_hi;
		bool is_pt_regs_addr = show_pt_regs
				&& (addr + delta) >= pt_regs_addr
				&& (addr + delta) < (pt_regs_addr +
							sizeof(struct pt_regs));

		E2K_LOAD_TAGGED_QWORD_AND_TAGS(addr, value_lo, value_hi,
				tag_lo, tag_hi);
		printk("      %lx (%s+0x%-3lx): %x %016lx    %x %016lx\n",
			addr + delta,
			(is_pt_regs_addr) ? "pt_regs" : "",
			(is_pt_regs_addr) ? (addr + delta - pt_regs_addr) :
					(addr - base),
			tag_lo, value_lo, tag_hi, value_hi);
	}
}
#endif


/*
 * Must be called with disabled interrupts
 */
static void print_chain_stack(struct stack_regs *regs,
		int show_reg_window, int skip)
{
	unsigned long flags;
	bool disable_nmis;
	struct task_struct *task = regs->task;
	u32 attempt, locked = 0;
	s64 size_chain_stack = regs->size_chain_stack;
	u64 new_chain_base = (u64) regs->base_chain_stack;
	u64 orig_chain_base = regs->orig_base_chain_stack;
	s64 cr_ind = size_chain_stack;
	e2k_cr0_hi_t cr0_hi = regs->cr0_hi;
	e2k_cr1_hi_t cr1_hi = regs->cr1_hi;
#if defined(CONFIG_STACK_REG_WINDOW) || defined(CONFIG_DATA_STACK_WINDOW)
	e2k_cr1_lo_t cr1_lo = regs->cr1_lo;
#endif
#ifdef CONFIG_STACK_REG_WINDOW
	u64 size_psp_stack = regs->size_psp_stack;
	u64 new_psp_base = (u64) regs->base_psp_stack;
	u64 orig_psp_base = regs->orig_base_psp_stack;
	s64 psp_ind = size_psp_stack;
	e2k_cr0_lo_t cr0_lo = regs->cr0_lo;
	int trap_num = 0;
#endif
#ifdef CONFIG_DATA_STACK_WINDOW
	e2k_cr1_lo_t prev_cr1_lo;
	e2k_cr1_hi_t prev_k_cr1_hi;
	bool show_k_data_stack = !!regs->base_k_data_stack;
	int pt_regs_num = 0;
	void *base_k_data_stack = regs->base_k_data_stack;
	u64 size_k_data_stack = regs->size_k_data_stack;
#endif

	if (!regs->valid) {
		pr_alert(" BUG print_chain_stack pid=%d valid=0\n", task->pid);
		return;
	}
	if (!regs->base_chain_stack) {
		pr_alert(" BUG could not get task %d stack registers, stack will not be printed\n",
			task->pid);
		return;
	}

	if (unlikely(!raw_irqs_disabled()))
		pr_alert("WARNING: print_chain_stack called with enabled interrupts\n");

	/* If task is current, disable NMIs so that interrupts handlers
	 * will not spill our stacks.*/
	disable_nmis = (task == current);
	if (disable_nmis)
		raw_all_irq_save(flags);
	/* Try locking the spinlock (with 30 seconds timeout) */
	attempt = 0;
	do {
		if (raw_spin_trylock(&print_stack_lock)) {
			locked = 1;
			break;
		}

		/* Wait for 0.001 second. */
		if (disable_nmis)
			raw_all_irq_restore(flags);
		safe_mdelay(1);
		if (disable_nmis)
			raw_all_irq_save(flags);
	} while (attempt++ < 30000);
	if (disable_nmis) {
		E2K_FLUSHCPU;
		E2K_FLUSH_WAIT;
	}

	pr_alert("PROCESS: %s, PID: %d, CPU: %d, state: %c %s (0x%lx), flags: 0x%x\n",
			task->comm == NULL ? "NULL" : task->comm,
			task->pid, task_cpu(task), task_state_char(task->state),
#ifdef CONFIG_SMP
			task_curr(task) ? "oncpu" : "",
#else
			"",
#endif
			task->state, task->flags);

#if defined(CONFIG_STACK_REG_WINDOW)
	if (!regs->base_psp_stack) {
		pr_alert(" WARNING could not get task %d psp stack registers, register windows will not be printed\n",
			task->pid);
		show_reg_window = 0;
	} else {
		show_reg_window = show_reg_window && (task == current
				|| print_window_regs || task_curr(task));
	}

	/* Print header */
	if (show_reg_window) {
		pr_alert("  PSP:  base 0x%016llx ind 0x%08x size 0x%08x\n",
				AS_STRUCT(regs->psp_lo).base,
				AS_STRUCT(regs->psp_hi).ind,
				AS_STRUCT(regs->psp_hi).size);
		pr_alert("  PCSP: base 0x%016llx ind 0x%08x size 0x%08x\n",
				AS_STRUCT(regs->pcsp_lo).base,
				AS_STRUCT(regs->pcsp_hi).ind,
				AS_STRUCT(regs->pcsp_hi).size);
		pr_alert("  ----------------------------------"
			"-----------------------------------\n"
			"        IP (hex)              FILENAME "
			"PROCEDURE\n"
			"  -------------------------------------"
			"--------------------------------\n");
	}
#endif

	if (skip) {
		/* Print how many frames were skipped */
		pr_alert("  < ... %d frames were skipped ... >\n", skip);

		do {
#ifdef CONFIG_STACK_REG_WINDOW
			if (show_reg_window) {
				psp_ind -= AS_STRUCT(cr1_lo).wbs * EXT_4_NR_SZ;

				if (psp_ind < 0 && cr_ind > 0) {
					show_reg_window = 0;
					pr_alert("! Invalid Register Window index"
						" (psp.ind) 0x%lx", psp_ind);
				}
				if (trap_num < MAX_USER_TRAPS &&
					      regs->user_trap[trap_num].valid &&
					      regs->user_trap[trap_num].frame ==
						     (orig_chain_base + cr_ind))
					++trap_num;
			}
#endif
#ifdef CONFIG_DATA_STACK_WINDOW
			if (show_k_data_stack && AS(cr1_lo).pm) {
				u64 k_window_size;
				s64 cur_chain_index;

				/* To find data stack window size we have to
				 * read cr1.hi from current *and* previous
				 * frames */
				cur_chain_index = size_chain_stack;
				do {
					cur_chain_index -= SZ_OF_CR;

					if (cur_chain_index < 0)
						/* This is a thread created with
						 * clone and we have reached
						 * the last kernel frame. */
						break;

					if (IS_ALIGNED(new_chain_base +
							cur_chain_index +
							SZ_OF_CR, PAGE_SIZE)
						&& (-1UL == GET_PHYS_ADDR(task,
							new_chain_base +
							cur_chain_index))) {
						pr_alert("      BAD address =%lx\n",
							new_chain_base +
							cur_chain_index);
						goto out;
					}

					get_kernel_cr1_lo(&prev_cr1_lo,
							new_chain_base,
							cur_chain_index);
				} while (!AS(prev_cr1_lo).pm);

				if (cur_chain_index < 0) {
					k_window_size = size_k_data_stack;
				} else {
					get_kernel_cr1_hi(&prev_k_cr1_hi,
							new_chain_base,
							cur_chain_index);

					k_window_size =
						16 * AS(prev_k_cr1_hi).ussz -
						16 * AS(cr1_hi).ussz;

					if (k_window_size > size_k_data_stack) {
						/* The stack is suspiciously
						 * large */
						k_window_size =
							size_k_data_stack;
						pr_alert("    This frame was not copied fully, first 0x%lx bytes will be shown\n"
							"    The data stack is suspiciously large\n",
								k_window_size);
						show_k_data_stack = 0;
					}
				}
				base_k_data_stack += k_window_size;
				size_k_data_stack -= k_window_size;
				if (!size_k_data_stack)
					show_k_data_stack = 0;
			}
#endif
			cr_ind -= SZ_OF_CR;
			size_chain_stack -= SZ_OF_CR;

			if (-1UL == GET_PHYS_ADDR(task, new_chain_base
					+ size_chain_stack)) {
				pr_alert(" BAD address =%lx\n", new_chain_base
						+ size_chain_stack);
				goto out;
			}

			get_kernel_cr0_hi(&cr0_hi, new_chain_base,
					size_chain_stack);
			get_kernel_cr1_hi(&cr1_hi, new_chain_base,
					size_chain_stack);
#if defined(CONFIG_STACK_REG_WINDOW) || defined(CONFIG_DATA_STACK_WINDOW)
			get_kernel_cr1_lo(&cr1_lo, new_chain_base,
					size_chain_stack);
#endif
#ifdef CONFIG_STACK_REG_WINDOW
			get_kernel_cr0_lo(&cr0_lo, new_chain_base,
					size_chain_stack);
#endif
		} while (--skip);
	}

	if (size_chain_stack > 0 &&
			-1UL == GET_PHYS_ADDR(task, new_chain_base +
					size_chain_stack - SZ_OF_CR)) {
		pr_alert(" BAD address =%lx\n", new_chain_base
				+ size_chain_stack - SZ_OF_CR);
		goto out;
	}

	for (;;) {
		print_funcy_ip(cr0_hi, new_chain_base, cr_ind, task,
				orig_chain_base);

#ifdef CONFIG_STACK_REG_WINDOW
		if (show_reg_window) {
			psp_ind -= AS_STRUCT(cr1_lo).wbs * EXT_4_NR_SZ;

			if (regs->show_user_regs && trap_num < MAX_USER_TRAPS &&
					regs->user_trap[trap_num].valid &&
					regs->user_trap[trap_num].frame ==
						(orig_chain_base + cr_ind)) {
				pr_alert("      ctpr1 %lx ctpr2 %lx ctpr3 %lx\n"
					 "      lsr %lx ilcr %lx\n",
					AW(regs->user_trap[trap_num].ctpr1),
					AW(regs->user_trap[trap_num].ctpr2),
					AW(regs->user_trap[trap_num].ctpr3),
					regs->user_trap[trap_num].lsr,
					regs->user_trap[trap_num].ilcr);
				++trap_num;
			}

			if (!AS(cr1_lo).pm && !regs->show_user_regs) {
				/* Skip user register window */
			} else {
				pr_alert("    PCSP: 0x%lx,  PSP: 0x%lx/0x%x\n",
					orig_chain_base + cr_ind,
					orig_psp_base + psp_ind,
					AS(cr1_lo).wbs * EXT_4_NR_SZ);

				print_predicates(cr0_lo, cr1_hi);

				if (psp_ind < 0 && cr_ind > 0) {
					pr_alert("! Invalid Register Window index"
						" (psp.ind) 0x%lx", psp_ind);
				} else if (psp_ind >= 0) {
					print_reg_window(new_psp_base + psp_ind,
						AS(cr1_lo).wbs, AS(cr1_lo).wfx,
						AS(cr1_hi).rbs, AS(cr1_hi).rsz,
						AS(cr1_hi).rcur);
				}
			}
		}
#endif	/* CONFIG_STACK_REG_WINDOW */
#ifdef CONFIG_DATA_STACK_WINDOW
		if (show_k_data_stack && AS(cr1_lo).pm) {
			u64 k_window_size;
			s64 cur_chain_index;

			/* To find data stack window size we have to
			 * read cr1.hi from current *and* previous frames */
			cur_chain_index = size_chain_stack;
			do {
				cur_chain_index -= SZ_OF_CR;

				if (cur_chain_index < 0)
					/* This is a thread created with clone
					 * and we have reached the last kernel
					 * frame. */
					break;

				if (IS_ALIGNED(new_chain_base + cur_chain_index
							+ SZ_OF_CR, PAGE_SIZE)
						&& (-1UL == GET_PHYS_ADDR(task,
							new_chain_base +
							cur_chain_index))) {
					pr_alert("      BAD address =%lx\n",
							new_chain_base +
							cur_chain_index);
					goto out;
				}

				get_kernel_cr1_lo(&prev_cr1_lo, new_chain_base,
						cur_chain_index);
			} while (!AS(prev_cr1_lo).pm);

			if (cur_chain_index < 0) {
				k_window_size = size_k_data_stack;
			} else {
				get_kernel_cr1_hi(&prev_k_cr1_hi,
					new_chain_base, cur_chain_index);

				k_window_size = 16 * AS(prev_k_cr1_hi).ussz -
						16 * AS(cr1_hi).ussz;
				if (k_window_size > size_k_data_stack) {
					/* The stack is suspiciously large */
					k_window_size = size_k_data_stack;
					pr_alert("    This is the last frame or it was not copied fully\n"
						"The stack is suspiciously large (0x%llx)\n",
							k_window_size);
					show_k_data_stack = 0;
				}
			}
			print_k_data_stack(regs, &pt_regs_num, (unsigned long)
					base_k_data_stack, k_window_size);
			base_k_data_stack += k_window_size;
			size_k_data_stack -= k_window_size;
			if (!size_k_data_stack)
				show_k_data_stack = 0;
		}
#endif

		if (cr_ind < SZ_OF_CR || size_chain_stack < SZ_OF_CR)
			break;

		/* Last frame is bogus (from execve or clone), skip it */
		if (cr_ind == SZ_OF_CR && (task == current ||
				regs->size_chain_stack < SIZE_CHAIN_STACK))
			break;

		cr_ind -= SZ_OF_CR;
		size_chain_stack -= SZ_OF_CR;

		if (IS_ALIGNED(new_chain_base + size_chain_stack + SZ_OF_CR,
								PAGE_SIZE) &&
				(-1UL == GET_PHYS_ADDR(task, new_chain_base
					+ size_chain_stack))) {
			pr_alert(" BAD address =%lx\n", new_chain_base
					+ size_chain_stack + CR0_HI_I);
			break;
		}

		get_kernel_cr0_hi(&cr0_hi, new_chain_base, size_chain_stack);
		get_kernel_cr1_hi(&cr1_hi, new_chain_base, size_chain_stack);
#if defined(CONFIG_STACK_REG_WINDOW) || defined(CONFIG_DATA_STACK_WINDOW)
		get_kernel_cr1_lo(&cr1_lo, new_chain_base, size_chain_stack);
#endif
#ifdef CONFIG_STACK_REG_WINDOW
		get_kernel_cr0_lo(&cr0_lo, new_chain_base, size_chain_stack);
#endif
	};

	if (size_chain_stack < 0)
		pr_alert("INVALID cr_ind SHOULD BE 0\n");

#if defined CONFIG_STACK_REG_WINDOW && defined CONFIG_GREGS_CONTEXT
	if (show_reg_window && regs->show_user_regs && regs->gregs.valid) {
		int i;

		pr_alert("  Global registers: bgr.cur = %d, bgr.val = 0x%x\n",
			AS(regs->gregs.bgr).cur, AS(regs->gregs.bgr).val);
		for (i = 0;  i < 32; i += 2)
			pr_alert("      g%-3d: %hhx %016llx %04hx      "
				"g%-3d: %hhx %016llx %04hx\n",
				i, regs->gregs.tag[i], regs->gregs.gbase[i],
				regs->gregs.gext[i],
				i + 1, regs->gregs.tag[i+1],
				regs->gregs.gbase[i+1], regs->gregs.gext[i+1]);
	}
#endif

out:
	if (locked)
		raw_spin_unlock(&print_stack_lock);
	if (disable_nmis)
		raw_all_irq_restore(flags);
}


#if defined (CONFIG_RECOVERY) && (CONFIG_CNT_POINTS_NUM < 2)

# ifdef CONFIG_SMP
#  define cntp_task_curr(ts)	(ts->on_cpu)
# else
#  define cntp_task_curr(ts)	(ts == current)
# endif

#define CNTP_IS_KERNEL_THREAD(ti, mm)	\
	(mm == NULL || (u64)GET_PS_BASE(ti) >= TASK_SIZE)

static void
cntp_print_reg_window(u64 psp_base, int psp_size, int fx,
				struct task_struct *ts, s64 psp_ind)
{
	int qreg, dreg, dreg_ind;
	u64 *rw;
	u64 qreg_lo;
	u64 qreg_hi;
	u32 tag_lo = 0;
	u32 tag_hi = 0;
	u64 ext_lo = 0;
	u64 ext_hi = 0;

	rw = (u64 *)(cntp_va(psp_base, ts));
	if (rw == (u64 *)-1)
		return;
	rw = rw + psp_ind;

	for (qreg = psp_size - 1; qreg >= 0; qreg --) {

		dreg_ind = qreg * (EXT_4_NR_SZ / sizeof (*rw));
		qreg_lo = rw[dreg_ind + 0];
		qreg_hi = rw[dreg_ind + 1];

		if (fx) {
			ext_lo = rw[dreg_ind + 2];
			ext_hi = rw[dreg_ind + 3];
		}
		dreg = qreg * 2;
		pr_alert("\t%%qr%-2d.hi : %%dr%-2d : %%r%-2d : 0x%x  0x%016lx",
			dreg, dreg + 1, dreg + 1, tag_hi, qreg_hi);
		if (fx) {
			pr_alert("   ext : 0x%02lx\n", ext_hi);
		} else {
			pr_alert("\n");
		}
		pr_alert("\t%%qr%-2d.lo : %%dr%-2d : %%r%-2d : 0x%x  0x%016lx",
			dreg, dreg, dreg, tag_lo, qreg_lo);
		if (fx) {
			pr_alert("   ext : 0x%02lx\n", ext_lo);
		} else {
			pr_alert("\n");
		}
	}
	pr_alert("   PSP: frame base 0x%016lx frame size 0x%08x\n",
		psp_base + psp_ind, psp_size * EXT_4_NR_SZ);
}

static char *
cntp_get_addr_file_name(e2k_addr_t addr, e2k_addr_t *start_addr_p,
						struct task_struct *ts)
{
	struct vm_area_struct * vma;
	struct dentry * dentry;
	struct file * f;
	char * name = NULL;
	char *ptr;
	int i;

	*start_addr_p = (long) NULL;
	if ((u64) addr >= TASK_SIZE)
		return "";
	vma = cntp_find_vma(ts, addr);
	if (vma == NULL || vma->vm_start > (u64) addr)
		return NULL;
	*start_addr_p = vma->vm_start;  /* Assume: load_base == vm_start */
	if (vma->vm_file == NULL)
		return NULL;
	f = (struct file *)cntp_va(vma->vm_file, 0);
	if (f->f_dentry == NULL)
		return NULL;
	dentry = (struct dentry *)cntp_va(f->f_dentry, 0);
	ptr = filename_buf + sizeof(filename_buf);
	*--ptr = '\0';
	for (i = 0; i < 21; i++) {
		if (dentry->d_name.name) {
			name = (char *)cntp_va(dentry->d_name.name, 0);
		} else {
			return NULL;
		}
		if (dentry->d_parent == NULL || 
			dentry == cntp_va(dentry->d_parent, 0))
			break;
		/* look up for another syllable */
		ptr = ptr - strlen(name);
		strncpy(ptr, name, strlen(name));
		*--ptr = '/';
		dentry = cntp_va(dentry->d_parent, 0);
	}
	return ptr;
}

static void
cntp_print_funcy_ip(e2k_cr0_hi_t cr0_hi, struct task_struct *ts)
{
	u64 start_addr, addr;
	char *file_name = NULL;

	addr = (u64)AS_STRUCT(cr0_hi).ip << 3;
	file_name = cntp_get_addr_file_name(
				addr, (e2k_addr_t *)&start_addr, ts);
	if (file_name != NULL) {
		printk(" %012lx ", addr);
		printk(" %20s ", (file_name[0] == 0) ? "<kernel>" : file_name);
		print_symbol(" %30s\n", addr);
	} else {
		printk(" %012lx", addr);
		printk(" %20s ", "<user>");
		print_symbol(" %30s\n", addr);
	}
}

void
cntp_print_chain_stack(struct task_struct *ts)
{
	e2k_pcsp_lo_t	pcsp_lo;
	e2k_pcsp_hi_t	pcsp_hi;
	u64		base;
	u64		base_here;
	s64		cr_ind;
	e2k_cr0_hi_t	cr0_hi;
#ifdef	CONFIG_STACK_REG_WINDOW
	e2k_psp_lo_t	psp_lo;
	e2k_psp_hi_t	psp_hi;
	u64		psp_base;
	e2k_cr1_lo_t	cr1_lo;
	s64		psp_ind;
#endif	/* CONFIG_STACK_REG_WINDOW */
	struct thread_info	*thi;
	struct mm_struct	*mm = ts->mm;
	struct pt_regs		*pt_regs;

	thi = cntp_va(task_thread_info(ts), 0);
	if (CNTP_IS_KERNEL_THREAD(thi, mm)) {
		printk("Task %d is Kernel Thread\n", ts->pid);
	} else {
		printk("Task %d is User Thread\n", ts->pid);
	}
	if (cntp_task_curr(ts) && (thi->pt_regs != NULL)) {
		pt_regs = (struct pt_regs *)cntp_va(thi->pt_regs, 0);
		/* Procedure chain stack pointer */
		pcsp_lo = pt_regs->stacks.pcsp_lo;
		pcsp_hi = pt_regs->stacks.pcsp_hi;
		cr0_hi = pt_regs->crs.cr0_hi;
#ifdef	CONFIG_STACK_REG_WINDOW
		cr1_lo = pt_regs->crs.cr1_lo;
		psp_lo = pt_regs->stacks.psp_lo;
		psp_hi = pt_regs->stacks.psp_hi;
#endif
	} else {
		pcsp_lo = ts->thread.sw_regs.pcsp_lo;
		pcsp_hi = ts->thread.sw_regs.pcsp_hi;
		cr0_hi = ts->thread.sw_regs.cr0_hi;
		if (!test_ti_status_flag(thi, TS_HW_STACKS_EXPANDED))
			pcsp_hi.PCSP_hi_size += KERNEL_PC_STACK_SIZE;

#ifdef	CONFIG_STACK_REG_WINDOW
		cr1_lo = ts->thread.sw_regs.cr_wd;
		psp_lo = ts->thread.sw_regs.psp_lo;
		psp_hi = ts->thread.sw_regs.psp_hi;
		if (!test_ti_status_flag(thi, TS_HW_STACKS_EXPANDED))
			psp_hi.PSP_hi_size += KERNEL_P_STACK_SIZE;
#endif
	}
	cr_ind = AS_STRUCT(pcsp_hi).ind;
	base = AS_STRUCT(pcsp_lo).base;
#ifdef	CONFIG_STACK_REG_WINDOW
	psp_base = AS_STRUCT(psp_lo).base;
	psp_ind = AS_STRUCT(psp_hi).ind;
#endif	/* CONFIG_STACK_REG_WINDOW */
	printk("cntp_print_chain_stack: start\n");
	printk("\n  PROCESS: %s, PID: %d, CPU: %d, %s, PROCEDURE STACK:\n",
		(ts->comm == NULL ? "NULL": ts->comm), ts->pid, task_cpu(ts),
		cntp_task_curr(ts) ? "on cpu":"in switch");
#ifdef	CONFIG_STACK_REG_WINDOW
	printk("  PSP:  base 0x%016lx ind 0x%08x size 0x%08x\n",
		psp_base, AS_STRUCT(psp_hi).ind, AS_STRUCT(psp_hi).size);
#endif
	printk("  PCSP: base 0x%016lx ind 0x%08lx size 0x%08x\n",
		base, cr_ind, AS_STRUCT(pcsp_hi).size);
	printk(" -----------------------------------------------------------------\n");
	printk("       IP (hex)               FILENAME                  PROCEDURE \n");
	printk(" -----------------------------------------------------------------\n");
	cntp_print_funcy_ip(cr0_hi, ts);
	printk("   PCSP: frame ind 0x%08lx\n", cr_ind);
	cr_ind = AS_STRUCT(pcsp_hi).ind;
#if defined(CONFIG_STACK_REG_WINDOW)
	psp_ind = psp_ind - AS_STRUCT(cr1_lo).wbs * EXT_4_NR_SZ;
	if (psp_ind < 0 && cr_ind > 0) {
		printk("Invalid Register Window index (psp.ind) 0x%lx\n",
			psp_ind);
	} else if (psp_ind >= 0) {
		cntp_print_reg_window(psp_base, AS_STRUCT(cr1_lo).wbs,
					AS_STRUCT(cr1_lo).wfx, ts, psp_ind);
	}
#endif	/* CONFIG_STACK_REG_WINDOW */
	base_here = (u64)cntp_va(base, ts);
	if (base_here ==(u64)-1)
		return;
	while (1) {
		cr_ind = cr_ind  - SZ_OF_CR;
		if (cr_ind < 0)
			break;
		AS_WORD(cr0_hi) = *((u64 *)(base_here + cr_ind + CR0_HI_I));
		cntp_print_funcy_ip(cr0_hi, ts);
		printk("   PCSP: frame ind 0x%08lx\n", cr_ind);
#if defined(CONFIG_STACK_REG_WINDOW)
		get_kernel_cr1_lo(&cr1_lo, base_here, cr_ind);
		psp_ind = psp_ind - AS_STRUCT(cr1_lo).wbs * EXT_4_NR_SZ;
		if (psp_ind < 0 && cr_ind > 0) {
			printk("Invalid Register Window ind (psp.ind) 0x%lx\n",
				psp_ind);
		} else if (psp_ind >= 0) {
			cntp_print_reg_window(psp_base, AS_STRUCT(cr1_lo).wbs,
				 AS_STRUCT(cr1_lo).wfx, ts, psp_ind);
		}
#endif	/* CONFIG_STACK_REG_WINDOW */
		if (cr_ind <= 0)
			break;
	}
	if (cr_ind < 0) {
		printk("INVALID cr_ind SHOULD BE 0\n");
	}
#ifdef	CONFIG_STACK_REG_WINDOW
	if (psp_ind > 0) {
		printk("INVALID PSP.ind 0x%016lx on the stack bottom "
			"SHOULD BE <= 0\n", psp_ind);
	}
#endif	/* CONFIG_STACK_REG_WINDOW */
	printk("cntp_print_task_chine_stack: finish\n");
	printk("\n");
}

#endif	/* CONFIG_RECOVERY && (CONFIG_CNT_POINTS_NUM < 2) */

static int
el_sys_mknod(char *dir, char *node)
{
	long 	rval;
  	mode_t 	mode;
	int 	maj = 254;
	int 	min = 254;
	dev_t	dev;
	
  	mode = (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	rval = sys_mkdir(dir, mode);	
	printk("el_sys_mknod: sys_mkdir %s rval %ld\n", dir, rval);
  	dev = (maj << 8) | min;
	rval = sys_mknod(node, mode | S_IFCHR, dev);	
	printk("el_sys_mknod: sys_mknod %s rval %ld dev 0x%ulx\n", 
				node, rval, dev);
	return rval;
}

void
show_stack(struct task_struct *task, unsigned long *sp)
{
	print_stack_frames(task, 1, 0);
}

void
set_tags(__e2k_u64_t* addr, long params) {
	long size,i;
	register __e2k_u64_t dword;
	register __e2k_u32_t tag;

	size = params >> 12; // page size
	if ((size < 0) || ((size % sizeof(__e2k_u64_t)) != 0)) {
		printk("set_tags() Wrong parameter size in 'set_tags' - 0x%lx\n",size);
		return;
	}
	dword = ((params & (0xff0)) >> 4) | ((params & 0xff0) << 4);
	dword = dword | (dword << 16);
	dword = dword | (dword << 32);
	tag = (params & 0xf);
	//printk("set_tags() Starting from 0x%p with size 0x%lx, dword 0x%lx and tag 0x%d\n", addr, size, dword, tag);
//	E2K_PUTTAGD(dword,tag);
        /* After E2K_PUTTAGD must STRONGLY follow STORE_TAG asm
        * to avoid compiler's problems */
	for(i = 0; i < size/sizeof(__e2k_u64_t); i++) {
                E2K_PUTTAGD(dword,tag);
		E2K_STORE_TAGGED_DWORD(addr,dword);
		addr++;
	}
	//printk("set_tags() Finished\n");
}
                                              
static long
check_tags(__e2k_u64_t* addr, long params) {
	long size,i;
	long res = 0;
	register __e2k_u64_t dword, dval;
	register __e2k_u32_t tag, tval;

	size = params >> 12;
	if ((size < 0) || ((size % sizeof(__e2k_u64_t)) != 0)) {
		printk("check_tags() Wrong parameter size in 'set_tags' - 0x%lx\n",
				size);
		return -1;
	}

	dword = ((params & (0xff0)) >> 4) | ((params & 0xff0) << 4);
	dword = dword | (dword << 16);
	dword = dword | (dword << 32);
	tag = (params & 0xf);

	for(i = 0; i < size/sizeof(__e2k_u64_t); i++) {
		BEGIN_USR_PFAULT("lbl_check_tags", "1f");
		E2K_LOAD_VAL_AND_TAGD(addr, dval, tval);
		LBL_USR_PFAULT("lbl_check_tags", "1:");
		if (END_USR_PFAULT)
			return -EFAULT;

		if (dword != dval) {
			printk("check_tags() DWORD 0x%lx differs from expected value 0x%lx, address 0x%p\n", dval, dword, addr);
			return -1;
			res = -1;
		}
		if (tag != tval) {
			printk("check_tags() TAG 0x%d differs from expected value 0x%d, address 0x%p\n", tval, tag, addr);
			return -1;
			res = -1;
		}
		addr++;
	}

	return res;
}

extern e2k_addr_t print_kernel_address_ptes(e2k_addr_t address);
extern void print_vma_and_ptes(struct vm_area_struct *vma, e2k_addr_t address);

long
get_addr_prot(long addr)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	long pgprot;

	tsk = current;
	mm = tsk->mm;
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, addr);
	if (vma == NULL) {
		pgprot = pmd_virt_offset(addr);
		goto end;
	}
	pgprot = pgprot_val(vma->vm_page_prot);

end:	up_read(&mm->mmap_sem);
	if (vma != NULL)
		print_vma_and_ptes(vma, addr);
	else
		print_kernel_address_ptes(addr);
	return pgprot;
}
static void
print_ide_info(int hwif_nr, int unit_nr, ide_drive_t *drive)
{

	printk("hwif %d unit %d\n", hwif_nr, unit_nr);
	printk("drive->name %s\n", drive->name);
	printk("drive->media %d\n", drive->media);
	printk("drive->using_dma %d\n",
			(drive->dev_flags & IDE_DFLAG_USING_DMA) == 1);
	
}
static ide_hwif_t ide_hwifs[MAX_HWIFS];	/* FIXME : ide_hwifs deleted */
static void
all_ide(int what)
{
	unsigned int 	i, unit;
	ide_hwif_t 	 *hwif;
	ide_drive_t 	*drive;
	
	for (i = 0; i < MAX_HWIFS; ++i) {
		hwif = &ide_hwifs[i];
		if (!hwif->present) continue;
		for (unit = 0; unit < MAX_DRIVES; ++unit) {
			drive = hwif->devices[unit];
			if (!(drive->dev_flags & IDE_DFLAG_PRESENT)) continue;
			if (what == ALL_IDE) {
				print_ide_info(i, unit, drive);
				continue;
			}
			if (what == USING_DMA) {
				if (drive->dev_flags & IDE_DFLAG_USING_DMA) {
					printk("IDE %s WITH USING_DMA\n",
						drive->name);
				} else {
					printk("IDE %s WITHOUT USING_DMA\n",
						drive->name);
				}
				break;
			}
		}
	}
}
long
ide_info(long what)
{
	switch(what) {
	case ALL_IDE:
		all_ide(ALL_IDE);
		break;
	case USING_DMA:
		all_ide(USING_DMA);
		break;
	default:
		printk("Unknowing ide_info\n");
		break;
	}
	return 0;
	
}

static 	long 	val_1;
static 	long 	val_2;
static	caddr_t	addr1;
static	caddr_t	addr2;
long
instr_exec(info_instr_exec_t *info)
{
	long la[4];
	long rval = -1;
		
	switch(info->instr_type) {
	case PAR_WRITE:

		if (info->addr1 < 0 && info->addr2 < TASK_SIZE) {
			addr1 = (void *)&la[0];
			addr2 = (void *)info->addr2;
			val_1 = info->val_1;
			val_2 = info->val_2;
			printk("instr_exec:\n");
			E2K_PARALLEL_WRITE(addr1, val_1, addr2, val_2);
			rval = la[0];
		}
		break;
	default:
		printk("Unknowing instr_exec\n");
		break;
	}
	return rval;	
}

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
static void
sys_e2k_print_syscall_times(scall_times_t *times)
{
	e2k_clock_t clock_time, func_time;
	int syscall_num = times->syscall_num;

	printk("   System call # %d execution time info:\n", syscall_num);
	clock_time = CALCULATE_CLOCK_TIME(times->start, times->end);
	printk("      total execution time \t\t\t\t% 8ld\n", clock_time);
	func_time = CALCULATE_CLOCK_TIME(times->scall_switch,
						times->scall_done);
	printk("      execution time without syscall function \t\t% 8ld\n",
		clock_time - func_time );
	clock_time = CALCULATE_CLOCK_TIME(times->start, times->pt_regs_set);
	printk("      pt_regs structure calculation \t\t\t% 8ld\n", clock_time);
	clock_time = CALCULATE_CLOCK_TIME(times->pt_regs_set,
						times->save_stack_regs);
	printk("      stacks registers saving \t\t\t\t% 8ld\n", clock_time);
	clock_time = CALCULATE_CLOCK_TIME(times->save_stack_regs,
						times->save_sys_regs);
	printk("      system registers saving \t\t\t\t% 8ld\n", clock_time);
	clock_time = CALCULATE_CLOCK_TIME(times->save_sys_regs,
						times->save_stacks_state);
	printk("      stacks state saving \t\t\t\t% 8ld\n", clock_time);
	clock_time = CALCULATE_CLOCK_TIME(times->save_stacks_state,
						times->save_thread_state);
	printk("      thread info state saving \t\t\t\t% 8ld\n", clock_time);
	clock_time = CALCULATE_CLOCK_TIME(times->save_thread_state,
						times->scall_switch);
	printk("      time after all savings and before sys "
		"func. \t% 8ld\n", clock_time);
	printk("      syscall function execution time \t\t\t% 8ld\n",
		func_time);
	if (syscall_num == __NR_exit || syscall_num == __NR_execve)
		return;
	clock_time = CALCULATE_CLOCK_TIME(times->scall_done,
					times->restore_thread_state);
	printk("      thread info state restoring \t\t\t% 8ld\n",
		clock_time);
	clock_time = CALCULATE_CLOCK_TIME(times->restore_thread_state,
					times->check_pt_regs);
	printk("      pt_regs structure checking \t\t\t% 8ld\n",
		clock_time);
	if (times->signals_num != 0) {
		clock_time = CALCULATE_CLOCK_TIME(times->check_pt_regs,
					times->do_signal_start);
		printk("      time between checking and start "
			"signal handling \t% 8ld\n",
			clock_time);
		clock_time = CALCULATE_CLOCK_TIME(times->do_signal_start,
					times->do_signal_done);
		printk("      signal handling time \t\t\t\t% 8ld\n",
			clock_time);
		clock_time = CALCULATE_CLOCK_TIME(times->do_signal_done,
					times->restore_start);
		printk("      time between signal handling and "
			"start restoring \t% 8ld\n",
			clock_time);
	} else {
		clock_time = CALCULATE_CLOCK_TIME(times->check_pt_regs,
					times->restore_start);
		printk("      time after checking and before "
			"start restoring \t% 8ld\n",
			clock_time);
	}
	clock_time = CALCULATE_CLOCK_TIME(times->restore_start,
					times->restore_user_regs);
	printk("      time of user registers restoring \t\t% 8ld\n",
		clock_time);
	clock_time = CALCULATE_CLOCK_TIME(times->restore_user_regs,
					times->end);
	printk("      time after restoring and before return \t\t% 8ld\n",
		clock_time);
	printk("      after sys call PSP.ind 0x%lx + PSHTP 0x%lx\n",
		times->psp_ind,
		GET_PSHTP_INDEX(times->pshtp));
	printk("      before done:   PSP.ind 0x%lx + PSHTP 0x%lx\n",
		times->psp_ind_to_done,
		GET_PSHTP_INDEX(times->pshtp_to_done));
}
static void
sys_e2k_print_trap_times(trap_times_t *times)
{
	e2k_clock_t clock_time;
	int tir;

	printk("   Trap #%d info start clock 0x%016lx end clock 0x%016lx\n",
		times->intr_counter, times->start, times->end);
	clock_time = CALCULATE_CLOCK_TIME(times->start, times->end);
	printk("      total execution time \t\t\t\t% 8ld\n", clock_time);
	clock_time = CALCULATE_CLOCK_TIME(times->start, times->pt_regs_set);
	printk("      pt_regs structure calculation \t\t\t% 8ld\n", clock_time);
	tir = times->nr_TIRs;
	printk("      TIRs number %d\n", tir);
	for ( ; tir >= 0; tir --) {
		printk("         TIR[%02d].hi 0x%016lx .lo 0x%016lx\n",
			tir,
			 times->TIRs[tir].TIR_hi.TIR_hi_reg,
			 times->TIRs[tir].TIR_lo.TIR_lo_reg);
	}
	printk("      Total handled trap number %d\n", times->trap_num);
	printk("         Procedure stack bounds %s handled: PSP.ind 0x%lx "
		"size 0x%lx (PSP.ind 0x%lx + PSHTP 0x%lx)\n",
		(times->ps_bounds) ? "WAS" : "was NOT",
		times->psp_hi.PSP_hi_ind,
		times->psp_hi.PSP_hi_size,
		times->psp_ind,
		GET_PSHTP_INDEX(times->pshtp));
	printk("         Chain procedure stack bounds %s handled: PCSP.ind "
		"0x%lx size 0x%lx\n",
		(times->pcs_bounds) ? "WAS" : "was NOT",
		times->pcsp_hi.PCSP_hi_ind,
		times->pcsp_hi.PCSP_hi_size);
	printk("         PSP to done ind 0x%lx size 0x%lx PSHTP 0x%lx\n",
		times->psp_hi_to_done.PSP_hi_ind,
		times->psp_hi_to_done.PSP_hi_size,
		GET_PSHTP_INDEX(times->pshtp_to_done));
	printk("         PCSP to done ind 0x%lx size 0x%lx\n",
		times->pcsp_hi_to_done.PCSP_hi_ind,
		times->pcsp_hi_to_done.PCSP_hi_size);
	printk("         CTPRs saved   1 : 0x%016lx 2 : 0x%016lx 3 : 0x%016lx\n",
		times->ctpr1, times->ctpr2, times->ctpr3);
	printk("         CTPRs to done 1 : 0x%016lx 2 : 0x%016lx 3 : 0x%016lx\n",
		times->ctpr1_to_done, times->ctpr2_to_done, times->ctpr3_to_done);
}

void
sys_e2k_print_kernel_times(struct task_struct *task,
	kernel_times_t *times, long times_num, int times_index)
{
	kernel_times_t *cur_times;
	times_type_t type;
	int count;
	int times_count;
	int cur_index;
	unsigned long flags;

	raw_local_irq_save(flags);
	if (times_num >= MAX_KERNEL_TIMES_NUM) {
		times_count = MAX_KERNEL_TIMES_NUM;
		cur_index = times_index;
	} else {
		times_count = times_num;
		cur_index = times_index - times_num;
		if (cur_index < 0)
			cur_index += MAX_KERNEL_TIMES_NUM;
	}
	printk("Kernel execution time info, process %d (\"%s\"), records "
		"# %d, total events %ld\n",
		task->pid, task->comm == NULL ? "NULL": task->comm,
		times_count, times_num);
	for (count = 0; count < times_count; count ++) {
		cur_times = &times[cur_index];
		type = cur_times->type;
		switch (type) {
		case SYSTEM_CALL_TT:
			sys_e2k_print_syscall_times(&cur_times->of.syscall);
			break;
		case TRAP_TT:
			sys_e2k_print_trap_times(&cur_times->of.trap);
			break;
		default:
			printk("Unknown kernel times structure type\n");
		}
		cur_index ++;
		if (cur_index >= MAX_KERNEL_TIMES_NUM)
			cur_index = 0;
	}
	raw_local_irq_restore(flags);
}
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

#define CMOS_CSUM_ENABLE
#undef CHECK_CSUM

static unsigned long ecmos_read(unsigned long port)
{
#ifdef CHECK_CSUM
	int i;
	u32 sss = 0;
	for (i = CMOS_BASE; i < CMOS_BASE + CMOS_SIZE - 2; i++) {
		sss += (long) bios_read(i);
	}
	printk(" --- sum = %x\n", sss);
	printk(" --- csum = %x\n", (bios_read(CMOS_BASE + BIOS_CSUM + 1) << 8)
			| bios_read(CMOS_BASE + BIOS_CSUM));
#endif

	if (port < CMOS_BASE || port > (CMOS_BASE + CMOS_SIZE - 1))
		return -1;
	return (unsigned long)bios_read(port);
}

static long ecmos_write(unsigned long port, unsigned char val)
{
#ifdef CMOS_CSUM_ENABLE
	unsigned int sum;
	unsigned char byte;
#endif
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (port < BIOS_BOOT_KNAME || port > (BIOS_BOOT_KNAME + name_length))
		return -1;
#ifdef CMOS_CSUM_ENABLE
	sum = ecmos_read(BIOS_CSUM2) << 8;
	sum |= ecmos_read(BIOS_CSUM);
	byte = ecmos_read(port);
	sum = sum - byte + val;
	bios_write(sum & 0xff, BIOS_CSUM);
	bios_write((sum >> 8) & 0xff, BIOS_CSUM2);
#endif
	bios_write(val, port);
	return 0;
}

static struct e2k_bios_param new_bios_sets;
static char cached_cmdline [cmdline_length + 1] = "\0";

static long read_boot_settings(struct e2k_bios_param *bios_settings)
{

	int i, fd;
	long rval;
  	mode_t 	mode;
	mm_segment_t fs;

	/* kernel_name */
	for(i = 0; i < name_length; i++)
		new_bios_sets.kernel_name[i] = bios_read(i + BIOS_BOOT_KNAME);
	new_bios_sets.kernel_name[i] = '\0';
	/* cmd_line */
	if (!cached_cmdline[0]) {
		fs = get_fs();
		set_fs(get_ds());

		mode = (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

		rval = sys_mkdir("/boot", mode);
		rval = sys_mount("/dev/hda1", "/boot", "ext3", 0, NULL);
		if (rval < 0) {
			rval = sys_mount("/dev/hda1", "/boot", "ext2", 0, NULL);
		}
		fd = sys_open("/boot/boot/cmdline", O_RDONLY, 0);
		new_bios_sets.command_line[0] = '\0';
		if (fd >= 0) {
			rval = sys_read(fd, new_bios_sets.command_line,
							cmdline_length + 1);
				memcpy(cached_cmdline, new_bios_sets.command_line,
							cmdline_length + 1);
			rval = sys_close(fd);
		}
		rval = sys_umount("/boot", 0);
		set_fs(fs);
	}
	memcpy(new_bios_sets.command_line, cached_cmdline, cmdline_length + 1);
	/* booting_item */
//	bios_read(BIOS_TEST_FLAG, 0);
	new_bios_sets.booting_item = bios_read(BIOS_BOOT_ITEM);
	/* device number(0 - 3) */
	new_bios_sets.dev_num = bios_read(BIOS_DEV_NUM);
	/* 3 - 38400 other - 115200 */
	new_bios_sets.serial_rate = bios_read(BIOS_SERIAL_RATE);
	if (new_bios_sets.serial_rate == 3)
		new_bios_sets.serial_rate = 38400;
	else
		new_bios_sets.serial_rate = 115200;
	/* boot waiting seconds */
	new_bios_sets.autoboot_timer = bios_read(BIOS_AUTOBOOT_TIMER);
	/* architecture type */
	new_bios_sets.machine_type = bios_read(BIOS_MACHINE_TYPE);

	if (copy_to_user(bios_settings, &new_bios_sets, sizeof(e2k_bios_param_t)))
		return -EFAULT;
	return 0;
}

static long write_boot_settings(struct e2k_bios_param *bios_settings)
{
	int i, fd;
	long rval;
  	mode_t 	mode;
	mm_segment_t fs;
#ifdef CMOS_CSUM_ENABLE
	unsigned int checksum;
#endif

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	if (copy_from_user(&new_bios_sets, bios_settings, sizeof(e2k_bios_param_t)))
		return -EFAULT;
	/* kernel_name */
	if (new_bios_sets.kernel_name[0]) {
		for(i = 0; i < name_length; i++)
			bios_write(new_bios_sets.kernel_name[i],i+BIOS_BOOT_KNAME);
	}
	/* cmd_line */
	if (new_bios_sets.command_line[0]) {
		fs = get_fs();
		set_fs(get_ds());

  		mode = (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

		rval = sys_mkdir("/boot", mode);
		rval = sys_mount("/dev/hda1", "/boot", "ext3", 0, NULL);
		if (rval < 0) {
			rval = sys_mount("/dev/hda1", "/boot", "ext2", 0, NULL);
		}
		fd = sys_open("/boot/boot/cmdline", O_WRONLY, 0);
		if (fd < 0) {
			cached_cmdline[0] = '\0';
		} else {
			rval = sys_write(fd, new_bios_sets.command_line, cmdline_length + 1);
			if (rval < 0) cached_cmdline[0] = '\0';
			else memcpy(cached_cmdline, new_bios_sets.command_line,
							cmdline_length + 1);
			rval = sys_close(fd);
		}
		rval = sys_umount("/boot", 0);
		set_fs(fs);
	}
	/* booting_item */
	bios_write(BIOS_TEST_FLAG, 0);			// reset test flag
	if (new_bios_sets.booting_item != BIOS_UNSET_ONE)
		bios_write(new_bios_sets.booting_item, BIOS_BOOT_ITEM);
	/* device number(0 - 3) */
	if (new_bios_sets.dev_num != BIOS_UNSET_ONE)
		bios_write(new_bios_sets.dev_num, BIOS_DEV_NUM);
	/* 3 - 38400 other - 115200 */
	if (new_bios_sets.serial_rate != BIOS_UNSET_ONE) {
		if (new_bios_sets.serial_rate == 38400)
			bios_write(3, BIOS_SERIAL_RATE);
		else
			bios_write(1, BIOS_SERIAL_RATE);
	}
	/* boot waiting seconds */
	if (new_bios_sets.autoboot_timer != BIOS_UNSET_ONE)
		bios_write(new_bios_sets.autoboot_timer, BIOS_AUTOBOOT_TIMER);
	/* architecture type */
	if (new_bios_sets.machine_type != BIOS_UNSET_ONE)
		bios_write(new_bios_sets.machine_type, BIOS_MACHINE_TYPE);

	/* checksum */
#ifdef CMOS_CSUM_ENABLE
	checksum = _bios_checksum();
	bios_write((checksum) & 0xff, BIOS_CSUM);
	bios_write((checksum >> 8) & 0xff, BIOS_CSUM2);
#endif
	return 0;
}

#ifdef CONFIG_DEBUG_KERNEL
/*
 * Bellow procedures are using for testing kernel procedure/chain/data stacks oferflow.
 * Launch: e2k_syswork(TEST_OVERFLOW, 0, 0);
 */

noinline static int overflow(int recur, u64 x)
{
	psp_struct_t PSP_my   = {{{0}}, {{0}}};
	pcsp_struct_t PCSP_my = {{{0}}, {{0}}};
	u64 psp_base, psp_size, psp_ind, rval;
	u64 pcsp_base, pcsp_size, pcsp_ind;
	u64 t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10;
	/* u64 a[512]; So we can get exc_array_bounds - data stack oferflow */

	PSP_my = READ_PSP_REG();
	psp_base = PSP_my.PSP_base;
	psp_size = PSP_my.PSP_size;
	psp_ind  = PSP_my.PSP_ind;

	PCSP_my = READ_PCSP_REG();
	pcsp_base = PCSP_my.PCSP_base;
	pcsp_size = PCSP_my.PCSP_size;
	pcsp_ind  = PCSP_my.PCSP_ind;

	t0 = recur + 1;
	printk("overflow recur:%d psp_base:0x%lx psp_size:0x%lx psp_ind:0x%lx tick:%ld\n",
			recur, psp_base, psp_size, psp_ind, E2K_GET_DSREG(clkr));
	printk("\tpcsp_base:0x%lx pcsp_size:0x%lx pcsp_ind:0x%lx\n", pcsp_base, pcsp_size, pcsp_ind);
	t1 = psp_base + 1; t2 = psp_base + 2; t3 = psp_base + 3;
	t4 = psp_size + 4; t5 = psp_size + 5; t6 = psp_size + 6; t7 = psp_size + 7;
	t8 = psp_ind  + 8; t9 = psp_ind  + 9; t10 = psp_ind + 10;

	if ((t0 % 10) > 5)
		rval = overflow(t0, t1+t2+t3+t4+t5);
	else
		rval = overflow(t0, t6+t7+t8+t9+t10);
	return rval;
}

static int over_thread(void *__unused)
{
	struct task_struct *cur = current;
	psp_struct_t PSP_my = {{{0}}, {{0}}};
	int psp_base, psp_size, psp_ind, rval;

        printk("over_thread start mm:%p name:%s pid:%d\n", cur->mm, cur->comm, cur->pid);
	PSP_my = READ_PSP_REG();
	psp_base = PSP_my.PSP_base;
	psp_size = PSP_my.PSP_size;
	psp_ind  = PSP_my.PSP_ind;
	printk("over_thread psp_base:0x%x psp_size:0x%x psp_ind:0x%x\n", psp_base, psp_size, psp_ind);
	rval  = overflow(0, 1);
	
        printk("over_thread exiting\n");
        return 0;
}
#endif

#ifdef CONFIG_RECOVERY
static int dmp_info_ready;

#ifndef	CONFIG_EMERGENCY_DUMP
#define	MEMDMP_FLAGS	(RECOVERY_BB_FLAG | MEMORY_DUMP_BB_FLAG)
#else
#define	MEMDMP_FLAGS	(RECOVERY_BB_FLAG)
#endif	/* ! CONFIG_EMERGENCY_DUMP */

void
dump_prepare(u16 dump_dev, u64 dump_sector)
{
	dump_info_t		*dmp_phys;
	u64			flags;
	u64			itsk;

	flags = read_bootblock_flags(bootblock_phys);
	pr_alert("\ndump_prepare()pa-bootinfo:%lx bb_phys:%p initflags: 0x%lx\n",
				init_bootinfo_phys_base, bootblock_phys, flags);
	if ((s16)dump_dev >= 0) {
		if (flags != 0 && flags != MEMDMP_FLAGS) {
			printk("WARNING:unexpected init flags in dump_prepare()\n");
		}
		/* Instruction to BIOS: dump all physical memory prior to
		 * any another actions */
		set_bootblock_flags(bootblock_phys, MEMDMP_FLAGS);
		WRITE_BOOTBLOCK_FIELD(bootblock_phys, dump_dev, dump_dev);
		WRITE_BOOTBLOCK_FIELD(bootblock_phys, dump_sector, dump_sector);
	}
	pr_alert("pa-bootinfo:%lx dev:0x%hx sect:0x%lx flags: 0x%lx init_mm:0x%lx\n",
	  			init_bootinfo_phys_base, dump_dev, dump_sector,
				read_bootblock_flags(bootblock_phys), (u64)&init_mm);

	dmp_phys =&(&bootblock_phys->info)->dmp;
	itsk = (u64)kernel_va_to_pa(&init_task);
	WRITE_BOOTBLOCK_FIELD(dmp_phys, pa_init_task, itsk);
	WRITE_BOOTBLOCK_FIELD(dmp_phys, init_mm, (u64)&init_mm);
	WRITE_BOOTBLOCK_FIELD(dmp_phys, targ_KERNEL_BASE, KERNEL_BASE);
	WRITE_BOOTBLOCK_FIELD(dmp_phys, mm_offset, (u64)offsetof(struct task_struct, mm));
	WRITE_BOOTBLOCK_FIELD(dmp_phys, tasks_offset, (u64)offsetof(struct task_struct, tasks));
	WRITE_BOOTBLOCK_FIELD(dmp_phys, thread_offset, (u64)offsetof(struct task_struct, thread));

	WRITE_BOOTBLOCK_FIELD(dmp_phys, kallsyms_addresses,
						(u64)kallsyms_addresses);
	WRITE_BOOTBLOCK_FIELD(dmp_phys, kallsyms_num_syms,
						(u64)kallsyms_num_syms);
	WRITE_BOOTBLOCK_FIELD(dmp_phys, kallsyms_names,
						(u64)kallsyms_names);
	WRITE_BOOTBLOCK_FIELD(dmp_phys, kallsyms_token_table,
						(u64)kallsyms_token_table);
	WRITE_BOOTBLOCK_FIELD(dmp_phys, kallsyms_token_index,
						(u64)kallsyms_token_index);
	WRITE_BOOTBLOCK_FIELD(dmp_phys, kallsyms_markers,
						(u64)kallsyms_markers);

	WRITE_BOOTBLOCK_FIELD(dmp_phys, _start, (u64)_start);
	WRITE_BOOTBLOCK_FIELD(dmp_phys, _end, (u64)_end);
	WRITE_BOOTBLOCK_FIELD(dmp_phys, _stext, (u64)_stext);
	WRITE_BOOTBLOCK_FIELD(dmp_phys, _etext, (u64)_etext);
#if 0
	WRITE_BOOTBLOCK_FIELD(dmp_phys, _sextratext, (u64)_sextratext);
	WRITE_BOOTBLOCK_FIELD(dmp_phys, _eextratext, (u64)_eextratext);
#endif
	WRITE_BOOTBLOCK_FIELD(dmp_phys, _sinittext, (u64)_sinittext);
	WRITE_BOOTBLOCK_FIELD(dmp_phys, _einittext, (u64)_einittext);
#if 0	
	WRITE_BOOTBLOCK_FIELD(dmp_phys, cpu_trace, (u64)addr_cpu_traces);
	WRITE_BOOTBLOCK_FIELD(dmp_phys, max_trace, (u64)size_max_trace);
	WRITE_BOOTBLOCK_FIELD(dmp_phys, freq,
					(u64)cpu_data[0].proc_freq /1000000);
#endif
	if ((s16)dump_dev >= 0) {
		dmp_info_ready = 1;
	}
}

int
dump_start(void)
{
	if (!dmp_info_ready) {
		printk("ERR: DUMP_PREPARE call should be done first\n");
		return -1;
	}
	restart_system(CORE_DUMP_REST_TYPE, 0);
	/* unreachable */
	BUG();
	/* unreachable */
	return -1;
}
#endif /* CONFIG_RECOVERY && CONFIG_EMERGENCY_DUMP */

/*
 * libunwind support.
 * num - user section number in user Procedure Chain stack;
 * cr_storage - storage to put cr0.lo, cr0.hi, cr1.lo, cr1.hi.
 */
static long get_cr(long num, long *cr_storage)
{
	unsigned long	flags;
	e2k_pcsp_lo_t	pcsp_lo;
	e2k_pcsp_hi_t	pcsp_hi;
	e2k_cr0_hi_t	cr0_hi;    /* ip */
	e2k_cr1_lo_t	cr1_lo;
	u64		pcsp_base;
	s64		cr_ind;
	long		n = 0;
	long		res[4];

	DbgGC("get_cr num:0x%lx cr_storage:%p\n", num, cr_storage);
	raw_all_irq_save(flags);
	E2K_FLUSHC;
	pcsp_hi = READ_PCSP_HI_REG();
	pcsp_lo = READ_PCSP_LO_REG();
	pcsp_base = AS_STRUCT(pcsp_lo).base;
	cr_ind = AS_STRUCT(pcsp_hi).ind;
	cr1_lo  = (e2k_cr1_lo_t)E2K_GET_DSREG_NV(cr1.lo);

	E2K_FLUSH_WAIT;

	while (1) {
		cr_ind = cr_ind - SZ_OF_CR;
		if (cr_ind < 0) {
			printk("get_cr() Invalid num:0x%lx\n", num);
			return -EINVAL;
		}
		AS_WORD(cr0_hi) = *((u64 *)(pcsp_base + cr_ind + CR0_HI_I));
		get_kernel_cr1_lo(&cr1_lo, pcsp_base, cr_ind);
		DbgGC("-- IP 0x%lx kern:%d\n", (long)AS_STRUCT(cr0_hi).ip << 3,
				AS(cr1_lo).pm);
		if (!AS(cr1_lo).pm) {
			if (n == num) {
				break;
			}
			n++;
		}	
	}
	res[0] = *((u64 *)(pcsp_base + cr_ind + CR0_LO_I));
	res[1] = *((u64 *)(pcsp_base + cr_ind + CR0_HI_I));
	res[2] = *((u64 *)(pcsp_base + cr_ind + CR1_LO_I));
	res[3] = *((u64 *)(pcsp_base + cr_ind + CR1_HI_I));
	raw_all_irq_restore(flags);

	DbgGC("0x%lx cr0_hi:0x%lx cr1_lo:0x%lx cr1_hi:0x%lx\n",
		  res[0], res[1], res[2], res[3]);
	if (generic_copy_to_user((void *)cr_storage, (void *)res, sizeof(res))){
		return -EFAULT;
	}
	return 0;
}

#ifdef	CONFIG_EMERGENCY_DUMP
void
start_emergency_dump(void)
{
	if (!dmp_info_ready) {
		printk("ERR: DUMP_PREPARE call should be done first\n");
		return;
	}
	set_bootblock_flags(bootblock_phys,
				MEMDMP_FLAGS | MEMORY_DUMP_BB_FLAG);
	e2k_reset_machine();
}
#else	/* ! CONFIG_EMERGENCY_DUMP */
void
start_emergency_dump(void)
{
}
#endif	/* CONFIG_EMERGENCY_DUMP */

static long copy_current_chain_stack(unsigned long dst,
		unsigned long src, unsigned long size)
{
	e2k_mem_crs_t *from, *to;

	if (!IS_ALIGNED(src, sizeof(*from)) ||
			!IS_ALIGNED(size, sizeof(*from))) {
		DebugACCVM("src or size is not aligned\n");
		return -EINVAL;
	}

	/* Dump chain stack frames to memory */
	raw_all_irq_disable();
	E2K_FLUSHC;
	E2K_FLUSH_WAIT;
	raw_all_irq_enable();

	from = (e2k_mem_crs_t *) (src + size);
	to = (e2k_mem_crs_t *) (dst + size);

	--from;
	--to;

	BEGIN_USR_PFAULT("lbl_copy_current_chain_stack", "2f");
	for (; size > 0; size -= SZ_OF_CR, from--, to--) {
		unsigned long ip;

		DebugACCVM("Copying frame 0x%lx to 0x%lx (pm %d, wbs 0x%x)\n",
			   (u64) from, (u64) to, AS(from->cr1_lo).pm,
			   AS(from->cr1_lo).wbs);

		memset(to, 0, sizeof(*to));

		ip = AS(from->cr0_hi).ip << 3;
		if (ip < TASK_SIZE) {
			AS(to->cr0_hi).ip = AS(from->cr0_hi).ip;
			AS(to->cr1_hi).ussz = AS(from->cr1_hi).ussz;
		}

		AS(to->cr1_lo).wbs = AS(from->cr1_lo).wbs;
		AS(to->cr1_lo).pm = AS(from->cr1_lo).pm;
	}
	LBL_USR_PFAULT("lbl_copy_current_chain_stack", "2:");
	if (END_USR_PFAULT) {
		DebugACCVM("Unhandled page fault at 0x%lx - 0x%lx or 0x%lx - 0x%lx\n",
			   (u64) from, (u64) from + sizeof(*from),
			   (u64) to, (u64) to + sizeof(*to));
		return -EFAULT;
	}

	return 0;
}

static long copy_current_procedure_stack(unsigned long dst,
		unsigned long src, unsigned long size, u64 write,
		unsigned long pcs_base, unsigned long pcs_used_top,
		unsigned long ps_base, unsigned long ps_used_top,
		e2k_cr1_lo_t cr1_lo)
{
	int kernel_mode;
	unsigned long ps_frame_top, ps_frame_size, pcs_frame, prev_boundary,
			copy_bottom, copy_top, len;

	raw_all_irq_disable();
	/* Dump procedure and chain stack frames to memory */
	E2K_FLUSHC;
	if (!write)
		E2K_FLUSHR;
	E2K_FLUSH_WAIT;
	raw_all_irq_enable();

	ps_frame_size = AS(cr1_lo).wbs * EXT_4_NR_SZ;
	ps_frame_top = ps_used_top;
	pcs_frame = pcs_used_top;

	prev_boundary = ps_frame_top;
	kernel_mode = true;

	while (size > 0 && ps_frame_top >= ps_base && pcs_frame >= pcs_base) {
		DebugACCVM("Considering frame at 0x%lx (pm %d, next pm %d)\n",
				ps_frame_top, kernel_mode, AS(cr1_lo).pm);
		if (pcs_frame == pcs_base) {
			/* We have reached the end of stack, copy
			 * or clear the last portion of stack. */
		} else if (kernel_mode && AS(cr1_lo).pm ||
				!kernel_mode && !AS(cr1_lo).pm) {
			/* Boundary not crossed */
			goto do_not_update_boundary;
		}

		WARN_ON_ONCE(prev_boundary < src + size);

		if (write) {
			copy_top = dst + size;
			copy_bottom = max(ps_frame_top, dst);
		} else {
			copy_top = src + size;
			copy_bottom = max(ps_frame_top, src);
		}

		if (copy_top <= copy_bottom)
			goto update_boundary;

		len = copy_top - copy_bottom;
		if (!write) {
			if (kernel_mode) {
				DebugACCVM("Clearing from 0x%lx to 0x%lx (stack from 0x%lx to 0x%lx)\n\n",
						dst + size - len, dst + size,
						src + size - len, src + size);
				if (__clear_user((void *) (dst + size - len),
						len))
					return -EFAULT;
			} else {
				DebugACCVM("Reading from 0x%lx-0x%lx to 0x%lx-0x%lx\n",
						src + size - len, src + size,
						dst + size - len, dst + size);
				if (__copy_in_user_with_tags(
						    (void *) (dst + size - len),
						    (void *) (src + size - len),
						    len))
					return -EFAULT;
			}
		} else if (!kernel_mode) {
			/* Writing user frames to stack */
			int ret, must_flush;

			DebugACCVM("Writing from 0x%lx-0x%lx to 0x%lx-0x%lx\n",
					src + size - len, src + size,
					dst + size - len, dst + size);
repeat_write:
			must_flush = (ps_used_top - copy_top <
					E2K_MAXSR * EXT_4_NR_SZ);
			if (must_flush) {
				raw_all_irq_disable();
				pagefault_disable();
				E2K_FLUSHCPU;
				E2K_FLUSH_WAIT;
			}
			ret = __copy_in_user_with_tags(
					(void *) (dst + size - len),
					(void *) (src + size - len), len);
			if (must_flush) {
				pagefault_enable();
				raw_all_irq_enable();
				if (ret) {
					/* Was a pagefault, try again... */
					if (!__copy_in_user_with_tags(
						    (void *) (dst + size - len),
						    (void *) (src + size - len),
						    len))
						goto repeat_write;
				}
			}

			if (ret)
				return -EFAULT;
		}
		size -= len;

update_boundary:
		/* Save the new boundary */
		prev_boundary = ps_frame_top;

		kernel_mode = !kernel_mode;

do_not_update_boundary:
		if (pcs_frame == pcs_base)
			break;

		pcs_frame -= SZ_OF_CR;
		ps_frame_top -= ps_frame_size;
		if (__get_user(AW(cr1_lo), (u64 *) (pcs_frame + CR1_LO_I)))
			return -EFAULT;
		ps_frame_size = AS(cr1_lo).wbs * EXT_4_NR_SZ;
	}

	return 0;
}

static long do_access_hw_stacks(unsigned long mode,
		unsigned long long __user *frame_ptr, char __user *buf,
		unsigned long buf_size, void __user *real_size, int compat)
{
	struct thread_info *ti = current_thread_info();
	unsigned long pcs_base, pcs_used_top;
	unsigned long ps_base, ps_used_top;
	unsigned long long frame;
	e2k_psp_lo_t psp_lo;
	e2k_psp_hi_t psp_hi;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_pshtp_t pshtp;
	e2k_pcshtp_t pcshtp;
	e2k_cr1_lo_t cr1_lo;
	long ret;

	if (mode != E2K_WRITE_PROCEDURE_STACK) {
		if (get_user(frame, frame_ptr))
			return -EFAULT;
	}

	/*
	 * Calculate stack frame addresses
	 */
	raw_all_irq_disable();
	pcsp_lo = READ_PCSP_LO_REG();
	pcsp_hi = READ_PCSP_HI_REG();
	pcshtp = READ_PCSHTP_REG();
	if (mode != E2K_READ_CHAIN_STACK) {
		psp_lo = READ_PSP_LO_REG();
		psp_hi = READ_PSP_HI_REG();
		pshtp = READ_PSHTP_REG();
	}
	raw_all_irq_enable();

	pcs_base = (unsigned long) GET_PCS_BASE(ti);
	pcs_used_top = pcsp_lo.PCSP_lo_base + pcsp_hi.PCSP_hi_ind +
		       PCSHTP_SIGN_EXTEND(pcshtp);

	if (mode == E2K_READ_CHAIN_STACK) {
		if (frame < pcs_base || frame > pcs_used_top)
			return -EAGAIN;
	} else {
		ps_base = (unsigned long) GET_PS_BASE(ti);
		ps_used_top = psp_lo.PSP_lo_base + psp_hi.PSP_hi_ind +
				GET_PSHTP_INDEX(pshtp);

		if (mode == E2K_READ_PROCEDURE_STACK && (frame < ps_base ||
							 frame > ps_used_top))
			return -EAGAIN;
	}

	if (real_size && (mode == E2K_READ_CHAIN_STACK ||
			  mode == E2K_READ_PROCEDURE_STACK)) {
		unsigned long used_size;

		if (mode == E2K_READ_CHAIN_STACK)
			used_size = frame - pcs_base;
		else /* mode == E2K_READ_PROCEDURE_STACK */
			used_size = frame - ps_base;

		if (compat)
			ret = put_user(used_size, (u32 __user *) real_size);
		else
			ret = put_user(used_size, (u64 __user *) real_size);
		if (ret)
			return -EFAULT;
	}

	if (mode == E2K_WRITE_PROCEDURE_STACK &&
	    !access_ok(VERIFY_WRITE, buf, buf_size) ||
	    mode != E2K_WRITE_PROCEDURE_STACK &&
	    !access_ok(VERIFY_READ, buf, buf_size))
		return -EFAULT;

	switch (mode) {
	case E2K_READ_CHAIN_STACK:
		if (frame - pcs_base > buf_size)
			return -ENOMEM;

		ret = copy_current_chain_stack((unsigned long) buf, pcs_base,
					       frame - pcs_base);
		break;
	case E2K_READ_PROCEDURE_STACK:
		if (frame - ps_base > buf_size)
			return -ENOMEM;

#if DEBUG_ACCVM
		dump_stack();
#endif

		AW(cr1_lo) = E2K_GET_DSREG(cr1.lo);

		ret = copy_current_procedure_stack((unsigned long) buf, ps_base,
				frame - ps_base, false, pcs_base,
				pcs_used_top, ps_base, ps_used_top, cr1_lo);

		break;
	case E2K_WRITE_PROCEDURE_STACK:
		AW(cr1_lo) = E2K_GET_DSREG(cr1.lo);

		ret = copy_current_procedure_stack(ps_base, (unsigned long) buf,
				buf_size, true, pcs_base,
				pcs_used_top, ps_base, ps_used_top, cr1_lo);

		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

long sys_access_hw_stacks(unsigned long mode,
		unsigned long long __user *frame_ptr, char __user *buf,
		unsigned long buf_size, void __user *real_size)
{
	return do_access_hw_stacks(mode, frame_ptr, buf, buf_size,
				   real_size, false);
}

long compat_sys_access_hw_stacks(unsigned long mode,
		unsigned long long __user *frame_ptr, char __user *buf,
		unsigned long buf_size, void __user *real_size)
{
	return do_access_hw_stacks(mode, frame_ptr, buf, buf_size,
				   real_size, true);
}


static long
flush_cmd_caches(e2k_addr_t user_range_arr, e2k_size_t len)
{
	icache_range_array_t icache_range_arr;

	/*
	 * Snooping is done by hardware since V3
	 */
	if (machine.iset_ver >= E2K_ISET_V3)
		return -EPERM;

	icache_range_arr.ranges =
		kmalloc(sizeof(icache_range_t) * len, GFP_KERNEL);
	icache_range_arr.count = len;
	icache_range_arr.mm = current->mm;
	if (copy_from_user(icache_range_arr.ranges, user_range_arr,
			sizeof(icache_range_t) * len)) {
		kfree(icache_range_arr.ranges);
		return -EFAULT;
	}

	flush_icache_range_array(&icache_range_arr);
	kfree(icache_range_arr.ranges);
	return 0;
}

/*
 * sys_e2k_syswork() is to run different system work from user
 */
static int sc_restart = 0;
asmlinkage long
sys_e2k_syswork(long syswork, long arg2, long arg3, long arg4, long arg5)
{

	long rval = 0;

	if (syswork == FAST_RETURN) /* Using to estimate time needed for entering to OS */
		return rval;

	if (!capable(CAP_SYS_ADMIN))
		goto user_syswork;

	switch(syswork) {
	case PRINT_MMAP:
		print_mmap(current);
		break;
	case PRINT_ALL_MMAP:
		print_all_mmap();
		break;
	case PRINT_STACK:
		print_stack(current);
		break;
#ifdef CONFIG_PROC_FS
	case PRINT_STATM:
		rval = print_statm((task_pages_info_t *)arg2, (pid_t) arg3);
		break;
#endif
	case GET_ADDR_PROT:
		rval = get_addr_prot(arg2);
		break;
	case INVALIDATE_ALL_CACHES:
		__invalidate_cache_all();
		break;
	case WRITE_BACK_ALL_CACHES:
		__write_back_cache_all();
		break;
	case PRINT_TASKS:
		/*
		 * Force stacks dump kernel thread to run as soon as we yield:
		 * to do core dump all stacks
		 */
                show_state();
		break;
	case PRINT_REGS:
		DbgESW("PRINT_PT_REGS\n");
		print_cpu_regs((char *) arg2);
		break;	
	case PRINT_PT_REGS:
		DbgESW("PRINT_PT_REGS %p\n", 
			current_thread_info()->pt_regs);
		print_pt_regs((char *) arg2,
				current_thread_info()->pt_regs);
		break;
	case SET_TAGS:
                DbgESW("setting tags: address 0x%lx params 0x%lx\n", 
                		arg2, arg3);
		set_tags((__e2k_u64_t*)arg2, arg3);
		break;
	case CHECK_TAGS:
		DbgESW("checking tags: address 0x%lx params 0x%lx\n", 
			arg2, arg3);
		rval = check_tags((__e2k_u64_t*)arg2, arg3);
		break;	
	case IDE_INFO:
		rval = ide_info(arg2);
		break;
	case INSTR_EXEC:
		rval = instr_exec((info_instr_exec_t *)arg2);
		break;
	case PRINT_T_TRUSS:
		print_t_truss();
		rval = 0;
		break;
	case START_CLI_INFO:
		#ifdef CONFIG_CLI_CHECK_TIME
			start_cli_info();
		#endif
		rval = 0;
		break;
	case PRINT_CLI_INFO:
		print_cli_info();
		rval = 0;
		break;
	case SYS_MKNOD:
		rval = el_sys_mknod((char *) arg2, (char *) arg3);
		break;
	case SET_DBG_MODE:
		e2k_lx_dbg = arg2;
		rval = 0;
		break;
	case START_OF_WORK:
		end_of_work = 0;
		rval = 0;
		break;
	case ADD_END_OF_WORK:
		end_of_work++;
		rval = 0;
		break;
	case GET_END_OF_WORK:
		rval = end_of_work;
		break;  
	case DO_E2K_HALT:
		rval = end_of_work;
		printk("sys_e2k_syswork: E2K_HALT_OK\n");
		E2K_HALT_OK();
		break;
	case READ_ECMOS:
		rval = ecmos_read((u64)arg2);
		break;
	case WRITE_ECMOS:
		rval = ecmos_write((u64)arg2, (u8)arg3);
		break;
	case READ_BOOT:
		rval = read_boot_settings((e2k_bios_param_t *)arg2);
		break;
	case WRITE_BOOT:
		rval = write_boot_settings((e2k_bios_param_t *)arg2);
		break;
	case E2K_SC_RESTART:
		if (sc_restart) {
			DbgESW("restart\n");
			sc_restart = 0;
			return 0;
		}
		DbgESW("start\n");
		sc_restart = 1;
		force_sig(SIGUSR1, current);
		rval = -ERESTARTNOINTR;
		break;
	case PRINT_PIDS:
		print_pids();
		rval = 0;
		break;
	case PRINT_INTERRUPT_INFO:
		print_interrupt_info();
		rval = 0;
		break;
	case CLEAR_INTERRUPT_INFO:
		clear_interrupt_info();
		rval = 0;
		break;
	case STOP_INTERRUPT_INFO:
		stop_interrupt_info();
		rval = 0;
		break;
	case DUMP_PREPARE:
		DbgESW("dump_dev 0x%lx dump_sector 0x%lx\n", 
			arg2, arg3);
#if defined (CONFIG_RECOVERY)
		dump_prepare((u16)arg2, (u64)arg3);
		rval = 0;
#else
		printk(" The kernel was compiled w/o CONFIG_RECOVERY\n");
		rval = -EINVAL;
#endif	/* CONFIG_RECOVERY */
		break;
	case DUMP_START:
#if !defined (CONFIG_RECOVERY)
        	printk(" The kernel was compiled w/o CONFIG_RECOVERY\n");
		rval = -EINVAL;
#else
		rval = dump_start();
#endif	/* CONFIG_RECOVERY*/
		break;
	case TEST_OVERFLOW:
#ifdef CONFIG_DEBUG_KERNEL
	    {
		struct task_struct *over;

		over = kthread_run(over_thread, NULL, "over_thr");
		if (IS_ERR(over))
			printk(" ============IS_ERR============\n");
		printk(" ============over_thread OK============\n");
	    }
#endif /* CONFIG_DEBUG_KERNEL */
		break;
	case USER_CONTROL_INTERRUPT:
#ifndef CONFIG_USR_CONTROL_INTERRUPTS
		printk("The kernel was compiled w/o  "
                       " CONFIG_USR_CONTROL_INTERRUPTS\n");
# else /* CONFIG_USR_CONTROL_INTERRUPTS */
            {
                unsigned long psr;
                arg2 = !!arg2;
                current_thread_info()->flags &= ~_TIF_USR_CONTROL_INTERRUPTS;
                current_thread_info()->flags |= 
                                            arg2 << TIF_USR_CONTROL_INTERRUPTS;
                if (arg2) {
                        psr = (PSR_UIE | PSR_UNMIE | PSR_NMIE | PSR_IE | PSR_SGE); 
                } else {
                        psr = (PSR_NMIE | PSR_IE | PSR_SGE); 
                }    
		parse_chain_stack(current, correct_psr_register,
				(void *) psr, 0, 0);
            }
#endif /* CONFIG_USR_CONTROL_INTERRUPTS */ 
                break; 
	default:
		rval = -1;
		goto user_syswork;
	}
	return rval;

user_syswork:
	switch(syswork) {
	case GET_CONTEXT:
                rval = get_cr((long)arg2, (long *)arg3);
		break;
	case E2K_ACCESS_VM:
		/* DEPRECATED, DON'T USE */
		break;
	case FLUSH_CMD_CACHES:
		rval = flush_cmd_caches(arg2, arg3);
		break;
	default:
		rval = -1;
		pr_info_ratelimited("Unknown e2k_syswork %ld\n", syswork);
		break;
	}
	return rval;
}


void nmi_set_hardware_data_breakpoint(struct data_breakpoint_params *params)
{
	__set_hardware_data_breakpoint(params->address,
			params->size, params->write, params->read,
			params->stop, params->cp_num);
}


/* Special versions of printk() and panic() to use inside of body_of_entry2.c
 * and ttable_entry10_C()i and other functions with disabled data stack.
 *
 * We cannot use functions with variable number of arguments in functions with
 * __interrupt attribute. The attribute makes compiler put all local variables
 * in registers and do not use stack, but these functions pass their parameters
 * through stack and thus conflict with the attribute. So we deceive the
 * compiler: put functions that use stack inside of functions that do not
 * use it.
 *
 * Why use the __interrupt attribute? It is needed because there are calls to
 * clone() and fork() inside of body_of_entry2.c. The stack and frame pointers
 * are cached in local registers, and since the child inherits those registers'
 * contents from its parent, it has pointers to parent's stack in them. Since
 * there is no way to make compiler re-read all those pointers, we use this
 * workaround: add __interrupt attribute and stop using the stack altogether.
 * Functions with constant number of arguments re-read stack and frame pointers
 * in the beginning so they can be called safely. */
notrace void __printk_fixed_args(char *fmt,
		u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7)
{
	printk(fmt, a1, a2, a3, a4, a5, a6, a7);
}

__noreturn notrace void __panic_fixed_args(char *fmt,
		u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7)
{
	panic(fmt, a1, a2, a3, a4, a5, a6, a7);
}

#ifdef CONFIG_TRACING
notrace void ____trace_bprintk_fixed_args(unsigned long ip,
		char *fmt, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6)
{
	__trace_bprintk(ip, fmt, a1, a2, a3, a4, a5, a6);
}
#endif

noinline int user_atomic_cmpxchg_inatomic(u32 *uval, u32 __user *uaddr,
					  u32 oldval, u32 newval, int size)
{
	int uninitialized_var(tmp);

	if (!access_ok(VERIFY_WRITE, uaddr, sizeof(int)))
		return -EFAULT;

	BEGIN_USR_PFAULT("lbl_user_atomic_cmpxchg_inatomic", "3f");
	switch (size) {
	case 1: tmp = __cmpxchg_b(oldval, newval, uaddr);
	case 2: tmp = __cmpxchg_h(oldval, newval, uaddr);
	case 4: tmp = __cmpxchg_w(oldval, newval, uaddr);
	case 8: tmp =  __cmpxchg_d(oldval, newval, uaddr);
	default: WARN_ONCE(1, "Bad argument size for user_cmpxchg");
	}
	LBL_USR_PFAULT("lbl_user_atomic_cmpxchg_inatomic", "3:");
	if (END_USR_PFAULT) {
		DebugUAF("%s (%d) - %s : futex_atomic_cmpxchg data fault %p(%ld)\n",
				__FILE__, __LINE__, __FUNCTION__,
				(uaddr), (sizeof(*uaddr)));

		return -EFAULT;
	}

	*uval = tmp;

	return 0;
}
