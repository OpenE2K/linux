/* linux/include/asm-e2k/traps.h, v 1.0 03/07/2001.
 * 
 * Copyright (C) 2001 MCST 
 *
 * Defenition of traps handling routines.
 */

#ifndef _E2K_TRAPS_H
#define _E2K_TRAPS_H

#include <asm/ptrace.h>

#define GET_NR_TIRS(tir_hi)		((tir_hi >> 56) & 0xff)

/* get aa field of tir_hi register */
#define GET_AA_TIRS(tir_hi)		((tir_hi >> 52) & 0x0f)

typedef void (*exc_function)(struct pt_regs *regs);
extern const exc_function exc_tbl[];
extern const char *exc_tbl_name[];

/*
 * Trap Info Register: the numbers of exceptions
 */

#define	exc_illegal_opcode_num		0	/* 00 */
#define	exc_priv_action_num		1	/* 01 */
#define	exc_fp_disabled_num		2	/* 02 */
#define	exc_fp_stack_u_num		3	/* 03 */
#define	exc_d_interrupt_num		4	/* 04 */
#define	exc_diag_ct_cond_num		5	/* 05 */
#define	exc_diag_instr_addr_num		6	/* 06 */
#define	exc_illegal_instr_addr_num	7	/* 07 */
#define	exc_instr_debug_num		8	/* 08 */
#define	exc_window_bounds_num		9	/* 09 */
#define	exc_user_stack_bounds_num	10	/* 10 */
#define	exc_proc_stack_bounds_num	11	/* 11 */
#define	exc_chain_stack_bounds_num	12	/* 12 */
#define	exc_fp_stack_o_num		13	/* 13 */
#define	exc_diag_cond_num		14	/* 14 */
#define	exc_diag_operand_num		15	/* 15 */
#define	exc_illegal_operand_num		16	/* 16 */
#define	exc_array_bounds_num		17	/* 17 */
#define	exc_access_rights_num		18	/* 18 */
#define	exc_addr_not_aligned_num	19	/* 19 */
#define	exc_instr_page_miss_num		20	/* 20 */
#define	exc_instr_page_prot_num		21	/* 21 */
#define	exc_ainstr_page_miss_num	22	/* 22 */
#define	exc_ainstr_page_prot_num	23	/* 23 */
#define	exc_last_wish_num		24	/* 24 */
#define	exc_base_not_aligned_num	25	/* 25 */

#define	exc_data_debug_num		28	/* 28 */
#define	exc_data_page_num		29	/* 29 */

#define	exc_recovery_point_num		31	/* 31 */
#define	exc_interrupt_num		32	/* 32 */
#define	exc_nm_interrupt_num		33	/* 33 */
#define	exc_div_num			34	/* 34 */
#define	exc_fp_num			35	/* 35 */
#define	exc_mem_lock_num		36	/* 36 */
#define	exc_mem_lock_as_num		37	/* 37 */
#define	exc_mem_error_out_cpu_num	38	/* 38 */
#define	exc_mem_error_MAU_num		39	/* 39 */
#define	exc_mem_error_L2_num		40	/* 40 */
#define	exc_mem_error_L1_35_num		41	/* 41 */
#define	exc_mem_error_L1_02_num		42	/* 42 */
#define	exc_mem_error_ICACHE_num	43	/* 43 */

#define	exc_max_num			43

/*
 * Trap Info Register: the bit mask of exceptions
 */

#define	exc_illegal_opcode_mask		(1UL << exc_illegal_opcode_num)
#define	exc_priv_action_mask		(1UL << exc_priv_action_num)
#define	exc_fp_disabled_mask		(1UL << exc_fp_disabled_num)
#define	exc_fp_stack_u_mask		(1UL << exc_fp_stack_u_num)
#define	exc_d_interrupt_mask		(1UL << exc_d_interrupt_num)
#define	exc_diag_ct_cond_mask		(1UL << exc_diag_ct_cond_num)
#define	exc_diag_instr_addr_mask	(1UL << exc_diag_instr_addr_num)
#define	exc_illegal_instr_addr_mask	(1UL << exc_illegal_instr_addr_num)
#define	exc_instr_debug_mask		(1UL << exc_instr_debug_num)
#define	exc_window_bounds_mask		(1UL << exc_window_bounds_num)
#define	exc_user_stack_bounds_mask	(1UL << exc_user_stack_bounds_num)
#define	exc_proc_stack_bounds_mask	(1UL << exc_proc_stack_bounds_num)
#define	exc_chain_stack_bounds_mask	(1UL << exc_chain_stack_bounds_num)
#define	exc_fp_stack_o_mask		(1UL << exc_fp_stack_o_num)
#define	exc_diag_cond_mask		(1UL << exc_diag_cond_num)
#define	exc_diag_operand_mask		(1UL << exc_diag_operand_num)
#define	exc_illegal_operand_mask	(1UL << exc_illegal_operand_num)
#define	exc_array_bounds_mask		(1UL << exc_array_bounds_num)
#define	exc_access_rights_mask		(1UL << exc_access_rights_num)
#define	exc_addr_not_aligned_mask	(1UL << exc_addr_not_aligned_num)
#define	exc_instr_page_miss_mask	(1UL << exc_instr_page_miss_num)
#define	exc_instr_page_prot_mask	(1UL << exc_instr_page_prot_num)
#define	exc_ainstr_page_miss_mask	(1UL << exc_ainstr_page_miss_num)
#define	exc_ainstr_page_prot_mask	(1UL << exc_ainstr_page_prot_num)
#define	exc_last_wish_mask		(1UL << exc_last_wish_num)
#define	exc_base_not_aligned_mask	(1UL << exc_base_not_aligned_num)

#define	exc_data_debug_mask		(1UL << exc_data_debug_num)
#define	exc_data_page_mask		(1UL << exc_data_page_num)

#define	exc_recovery_point_mask		(1UL << exc_recovery_point_num)
#define	exc_interrupt_mask		(1UL << exc_interrupt_num)
#define	exc_nm_interrupt_mask		(1UL << exc_nm_interrupt_num)
#define	exc_div_mask			(1UL << exc_div_num)
#define	exc_fp_mask			(1UL << exc_fp_num)
#define	exc_mem_lock_mask		(1UL << exc_mem_lock_num)
#define	exc_mem_lock_as_mask		(1UL << exc_mem_lock_as_num)
#define	exc_mem_error_out_cpu_mask	(1UL << exc_mem_error_out_cpu_num)
#define	exc_mem_error_MAU_mask		(1UL << exc_mem_error_MAU_num)
#define	exc_mem_error_L2_mask		(1UL << exc_mem_error_L2_num)
#define	exc_mem_error_L1_35_mask	(1UL << exc_mem_error_L1_35_num)
#define	exc_mem_error_L1_02_mask	(1UL << exc_mem_error_L1_02_num)
#define	exc_mem_error_ICACHE_mask	(1UL << exc_mem_error_ICACHE_num)
#define	exc_mem_error_mask		(exc_mem_error_out_cpu_mask |	\
					exc_mem_error_MAU_mask |	\
					exc_mem_error_L2_mask |		\
					exc_mem_error_L1_35_mask |	\
					exc_mem_error_L1_02_mask |	\
					exc_mem_error_ICACHE_mask)

#define	exc_all_mask			((1UL << (exc_max_num + 1)) - 1UL)

#define	sync_exc_mask			(exc_illegal_opcode_mask |	\
					exc_priv_action_mask |		\
					exc_fp_disabled_mask |		\
					exc_fp_stack_u_mask |		\
					exc_diag_ct_cond_mask |		\
					exc_diag_instr_addr_mask |	\
					exc_illegal_instr_addr_mask |	\
					exc_window_bounds_mask |	\
					exc_user_stack_bounds_mask |	\
					exc_fp_stack_o_mask |		\
					exc_diag_cond_mask |		\
					exc_diag_operand_mask |		\
					exc_illegal_operand_mask |	\
					exc_array_bounds_mask |		\
					exc_access_rights_mask |	\
					exc_addr_not_aligned_mask |	\
					exc_instr_page_miss_mask |	\
					exc_instr_page_prot_mask |	\
					exc_base_not_aligned_mask)

#define	async_exc_mask			(exc_proc_stack_bounds_mask |	\
					exc_chain_stack_bounds_mask |	\
					exc_instr_debug_mask |		\
					exc_ainstr_page_miss_mask |	\
					exc_ainstr_page_prot_mask |	\
					exc_recovery_point_mask |	\
					exc_interrupt_mask |		\
					exc_nm_interrupt_mask |		\
					exc_mem_lock_as_mask |		\
					exc_mem_error_mask)

#define	defer_exc_mask			(exc_data_page_mask |		\
					exc_mem_lock_mask |		\
					exc_d_interrupt_mask |		\
					exc_last_wish_mask)

/* Mask of non-maskable interrupts. "exc_data_debug" and "exc_instr_debug"
 * actually can be either maskable or non-maskable depending on the watched
 * event, but we assume the worst case (non-maskable). */
#define non_maskable_exc_mask		(exc_nm_interrupt_mask | \
					exc_data_debug_mask | \
					exc_instr_debug_mask | \
					exc_mem_lock_as_mask)

#define SET_IP_INTERRUPT(addr)				\
({	int nr_TIRs;					\
	tir_hi_struct_t tir_hi;				\
	tir_hi.TIR_hi_reg = regs->TIR_hi;		\
	nr_TIRs = GET_NR_TIRS(AW(tir_hi));		\
	addr =(void __user *)				\
		(regs->TIRs[nr_TIRs].TIR_lo.TIR_lo_ip);	\
})

#define CHECK_N_FORCE_SIG(regs, addr, signo, trapno, code) \
do { \
	int nr_TIRs; \
	tir_hi_struct_t tir_hi; \
	struct trap_pt_regs *trap = (regs)->trap; \
	if (trap) { \
		AW(tir_hi) = trap->TIR_hi; \
		nr_TIRs = GET_NR_TIRS(AW(tir_hi)); \
		addr = (void __user *) (trap->TIRs[nr_TIRs].TIR_lo.TIR_lo_ip); \
	} else { \
		addr = 0; \
	} \
	force_sig_info(signo, &info, current);				\
} while (0)

#define S_SIG(regs, signo, trapno, code) do {				\
	siginfo_t info;							\
	info.si_signo = signo;                          		\
	info.si_errno = SI_EXC;						\
	info.si_trapno = trapno;					\
	info.si_code = code;						\
	CHECK_N_FORCE_SIG(regs, info.si_addr, signo, trapno, code);	\
} while(0);

extern void do_aau_fault(int aa_field, struct pt_regs *regs);
extern int do_proc_stack_bounds(struct pt_regs *regs);
extern int do_chain_stack_bounds(struct pt_regs *regs);
extern int do_page_fault(struct pt_regs *const regs, e2k_addr_t address,
		tc_cond_t *const condition, const int instr_page);
extern void do_trap_cellar(struct pt_regs *regs, int only_system_tc);

extern void expand_hw_stacks_in_syscall(struct pt_regs *regs);
extern int constrict_hardware_stacks(struct pt_regs *regs,
		struct pt_regs *new_regs);
extern int expand_user_data_stack(struct pt_regs *regs,
		struct task_struct *task, bool gdb);
extern void parse_TIR_registers(struct pt_regs *regs, u64 nmi);
extern void do_notify_resume(struct pt_regs *regs);

#define fp_es	(1UL << 7)	/* error summary status; es set if anyone of */
				/* unmasked exception flags is set */
#define fp_pe	(1UL << 5)	/* precision exception flag */
#define fp_ue	(1UL << 4)	/* underflow exception flag */
#define fp_oe	(1UL << 3)	/* overflow exception flag */
#define fp_ze	(1UL << 2)	/* divide by zero exception flag */
#define fp_de	(1UL << 1)	/* denormalized operand exception flag */
#define fp_ie	(1UL << 0)	/* invalid operation exception flag */
#endif			
