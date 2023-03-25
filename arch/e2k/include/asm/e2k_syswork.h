#ifndef _E2K_SYSWORK_H_
#define _E2K_SYSWORK_H_

#include <uapi/asm/e2k_syswork.h>


/****************************/
#define TIME_SHARE	1
/****************************/

/* info_for_other for work_for_other_cpu() */

typedef	struct info_for_other {
	int 	work;
	int 	wait;
} info_for_other_t;

#define PRINT_STK_ON_OTHER	1
#define PRINT_FUNCY_ON_OTHER	2
#define WAIT_ON_OTHER		3

/****************************/

/* info_instr_exec for instr_exec() */

typedef	struct info_instr_exec {
	int	instr_type;
	long 	addr1;
	long 	addr2;
	long 	val_1;
	long 	val_2;
} info_instr_exec_t;

#define PAR_WRITE		1
#define PAR_READ		2
/****************************/

/****************************/
/* get task pages info for PRINT_STATM syswork */
typedef struct user_mm {
	int size;
	int resident;
	int text;
	int data;
	int shared;
} task_pages_info_t;
/****************************/

extern void print_all_task(void);
extern long ide_info(long what);
#ifdef CONFIG_PAGE_DOUBLE_FREE_ENTRAP
extern void save_kernel_chine_stack(struct page *page);
#endif /* CONFIG_PAGE_DOUBLE_FREE_ENTRAP */

extern int is_kernel_address_valid(e2k_addr_t address);


/* This macro fills missing arguments with "(u64) (0)". */
#define EXPAND_ARGS_TO_8(...) \
		__EXPAND_ARGS_TO_8(__VA_ARGS__, 0, 0, 0, 0, 0, 0, 0)
#define __EXPAND_ARGS_TO_8(fmt, a1, a2, a3, a4, a5, a6, a7, ...) \
		fmt, (u64) (a1), (u64) (a2), (u64) (a3), \
		(u64) (a4), (u64) (a5), (u64) (a6), (u64) (a7)

/* This macro is used to avoid printks with variable number of arguments
 * inside of functions with __check_stack attribute.
 *
 * If a call to printk has less than 8 parameters the macro sets any missing
 * arguments to (u64) (0).
 *
 * NOTE: maximum number of arguments that can be passed to a function
 * from within an __interrupt function is 8! */
#define printk_fixed_args(...) \
		__printk_fixed_args(EXPAND_ARGS_TO_8(__VA_ARGS__))
#define __trace_bprintk_fixed_args(...) \
		____trace_bprintk_fixed_args(EXPAND_ARGS_TO_8(__VA_ARGS__))
#define panic_fixed_args(...) \
		__panic_fixed_args(EXPAND_ARGS_TO_8(__VA_ARGS__))
#define delay_printk_fixed_args(...) \
		__delay_printk_fixed_args(EXPAND_ARGS_TO_8(__VA_ARGS__))

extern void __printk_fixed_args(char *fmt,
		u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7);
extern void __panic_fixed_args(char *fmt,
		u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7)
		__noreturn;
#ifdef CONFIG_TRACING
extern void ____trace_bprintk_fixed_args(unsigned long ip,
		char *fmt, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6);
#endif

long do_longjmp(u64 retval, u64 jmp_sigmask, e2k_cr0_hi_t jmp_cr0_hi,
		e2k_cr1_lo_t jmp_cr1_lo, e2k_pcsp_lo_t jmp_pcsp_lo,
		e2k_pcsp_hi_t jmp_pcsp_hi, u32 jmp_br, u32 jmp_psize,
		e2k_fpcr_t fpcr, e2k_fpsr_t fpsr, e2k_pfpfr_t pfpfr, bool restore_fpu);

long write_current_chain_stack(unsigned long dst, void __user *buf,
		unsigned long size);
long copy_current_proc_stack(void __user *buf, void __user *p_stack,
		unsigned long size, int write, unsigned long ps_used_top);

#endif /* _E2K_SYSWORK_H_ */
