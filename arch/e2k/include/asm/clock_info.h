/*
 * Kernel performance measuring tool and support
 */
#ifndef _E2K_CLOCK_INFO_H
#define _E2K_CLOCK_INFO_H

#include <linux/types.h>

#ifndef __ASSEMBLY__
#include <asm/types.h>
#endif	/* __ASSEMBLY__ */

#ifndef __ASSEMBLY__

typedef	u64			e2k_clock_t;

typedef enum {
	SYSTEM_CALL_TT	= 1,	/* system calls */
	TRAP_TT			/* traps */
} times_type_t;

typedef struct {
	int		syscall_num;	/* # of system call */
	int		signals_num;	/* number of handled signals */
	e2k_clock_t	start;		/* start clock of system call */
	e2k_clock_t	end;		/* end clock */
	e2k_clock_t	pt_regs_set;	/* pt_regs structure is set */
	e2k_clock_t	save_stack_regs;
	e2k_clock_t	save_sys_regs;
	e2k_clock_t	save_stacks_state;
	e2k_clock_t	save_thread_state;
	e2k_clock_t	scall_switch;
	e2k_clock_t	scall_done;
	e2k_clock_t	restore_thread_state;
	e2k_clock_t	check_pt_regs;
	e2k_clock_t	do_signal_start;
	e2k_clock_t	do_signal_done;
	e2k_clock_t	restore_start;
	e2k_clock_t	restore_user_regs;
	e2k_pshtp_t	pshtp;
	u64		psp_ind;
	e2k_pshtp_t	pshtp_to_done;
	u64		psp_ind_to_done;
} scall_times_t;

typedef struct {
	e2k_clock_t	start;		/* start clock of system call */
	e2k_clock_t	end;		/* end clock */
	e2k_clock_t	pt_regs_set;	/* pt_regs structure is set */
	e2k_clock_t	signal_done;
	int		nr_TIRs;
	e2k_tir_t	TIRs[TIR_NUM];
	e2k_psp_hi_t	psp_hi;
	e2k_pshtp_t	pshtp;
	u64		psp_ind;
	e2k_pcsp_hi_t	pcsp_hi;
	u64		ctpr1;
	u64		ctpr2;
	u64		ctpr3;
	u8		ps_bounds;
	u8		pcs_bounds;
	int		trap_num;
	e2k_psp_hi_t	psp_hi_to_done;
	e2k_pshtp_t	pshtp_to_done;
	e2k_pcsp_hi_t	pcsp_hi_to_done;
	u64		ctpr1_to_done;
	u64		ctpr2_to_done;
	u64		ctpr3_to_done;
} trap_times_t;

typedef	struct kernel_times {
	times_type_t	type;
	union {
		scall_times_t	syscall;	/* system calls */
		trap_times_t	trap;		/* traps */
	}		of;
} kernel_times_t;

#ifdef	CONFIG_MAX_KERNEL_TIMES_NUM
#define	MAX_KERNEL_TIMES_NUM		CONFIG_MAX_KERNEL_TIMES_NUM
#else
#define	MAX_KERNEL_TIMES_NUM		20
#endif	/* CONFIG_MAX_KERNEL_TIMES_NUM */

#define	INCR_KERNEL_TIMES_COUNT(ti)		{		\
		(ti)->times_index ++;				\
		(ti)->times_num ++;				\
		if ((ti)->times_index >= MAX_KERNEL_TIMES_NUM)	\
			 (ti)->times_index = 0;			\
	}
#define	GET_DECR_KERNEL_TIMES_COUNT(ti, count)		{	\
		(count) = (ti)->times_index;			\
		if ((ti)->times_num == 0)			\
			(ti)->times_num = 1;			\
		(count) --;					\
		if ((count) < 0)				\
			 (count) = MAX_KERNEL_TIMES_NUM - 1;	\
	}
#define	E2K_SAVE_CLOCK_REG(clock)			{	\
		(clock) = E2K_GET_DSREG(clkr);			\
	}
#define	CALCULATE_CLOCK_TIME(start_clock, end_clock)		\
		((end_clock) - (start_clock))

extern void sys_e2k_print_kernel_times(struct task_struct *task,
		kernel_times_t *times, long times_num, int times_index);

#endif	/* __ASSEMBLY__ */
#endif /* _E2K_THREAD_INFO_H */
