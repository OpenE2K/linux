/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

#include <linux/percpu.h>
#include <asm/cpu_regs.h>
#include <asm/perf_event_types.h>
#include <asm/process.h>
#include <asm/ptrace.h>
#include <asm/regs_state.h>

#define EVENT_VAR(_id)  event_attr_##_id
#define EVENT_PTR(_id) &event_attr_##_id.attr.attr

#define EVENT_ATTR(_name, _id)						\
static struct perf_pmu_events_attr EVENT_VAR(_id) = {			\
	.attr		= __ATTR(_name, 0444, events_sysfs_show, NULL),	\
	.id		= PERF_COUNT_HW_##_id,				\
	.event_str	= NULL,						\
};

static inline void set_perf_event_pending(void) {}
static inline void clear_perf_event_pending(void) {}

static inline unsigned long perf_instruction_pointer(const struct pt_regs *regs)
{
	const struct trap_pt_regs *trap = regs->trap;
	return (trap != NULL && trap->dim_ip_valid) ? trap->dim_ip
						    : instruction_pointer(regs);
}

#define perf_misc_flags(regs) perf_misc_flags(regs)
static inline unsigned long perf_misc_flags(const struct pt_regs *regs)
{
	/* Actual IP registered in DIMAR may not correspond directly to
	 * the point where exception has been delivered.  Thus we rely on
	 * IP instead of other registers to determine user/kernel mode.	*/
	unsigned long ip = perf_instruction_pointer(regs);
	return ip < TASK_SIZE ? PERF_RECORD_MISC_USER : PERF_RECORD_MISC_KERNEL;
}

void perf_data_overflow_handle(struct pt_regs *);
void perf_instr_overflow_handle(struct pt_regs *);
void dimtp_overflow(struct perf_event *event);

#define perf_arch_fetch_caller_regs perf_arch_fetch_caller_regs
static __always_inline void perf_arch_fetch_caller_regs(struct pt_regs *regs,
							unsigned long ip)
{
	unsigned long flags;

	raw_all_irq_save(flags);
	SAVE_STACK_REGS(regs, current_thread_info(), false, false);
	regs->stacks.usd = read_USD_reg();
	regs->stacks.top = (unsigned long) current->stack +
			   KERNEL_C_STACK_OFFSET + KERNEL_C_STACK_SIZE;
	raw_all_irq_restore(flags);
	WARN_ON_ONCE(instruction_pointer(regs) != ip);
}

static inline e2k_dimcr_t dimcr_pause(void)
{
	e2k_dimcr_t dimcr, dimcr_old;

	/*
	 * Stop counting for more precise group counting and also
	 * to avoid races when one counter overflows while another
	 * is being handled.
	 *
	 * Writing %dimcr also clears other pending exc_instr_debug
	 */
	dimcr = read_DIMCR_reg();
	dimcr_old = dimcr;
	dimcr.dimar[0].user = 0;
	dimcr.dimar[0].system = 0;
	dimcr.dimar[1].user = 0;
	dimcr.dimar[1].system = 0;
	write_DIMCR_reg(dimcr);

	return dimcr_old;
}

static inline e2k_dimcr_t dimcr1_pause(void)
{
	e2k_dimcr_t dimcr1, dimcr1_old;

	if (!cpu_has(CPU_FEAT_ISET_V7) || cpu_has(CPU_HWBUG_DIMCR1))
		return (e2k_dimcr_t) { .word = 0 };

	/*
	 * Stop counting for more precise group counting and also
	 * to avoid races when one counter overflows while another
	 * is being handled.
	 *
	 * Writing %dimcr also clears other pending exc_instr_debug
	 */
	dimcr1 = read_DIMCR1_reg();
	dimcr1_old = dimcr1;
	dimcr1.dimar[0].user = 0;
	dimcr1.dimar[0].system = 0;
	dimcr1.dimar[1].user = 0;
	dimcr1.dimar[1].system = 0;
	write_DIMCR1_reg(dimcr1);

	return dimcr1_old;
}

static inline e2k_ddmcr_t ddmcr_pause(void)
{
	e2k_ddmcr_t ddmcr, ddmcr_old;

	/*
	 * Stop counting for more precise group counting and also
	 * to avoid races when one counter overflows while another
	 * is being handled.
	 *
	 * Writing %ddmcr also clears other pending exc_data_debug
	 */
	ddmcr = READ_DDMCR_REG();
	ddmcr_old = ddmcr;
	ddmcr.ddmar[0].user = 0;
	ddmcr.ddmar[0].system = 0;
	ddmcr.ddmar[1].user = 0;
	ddmcr.ddmar[1].system = 0;
	WRITE_DDMCR_REG(ddmcr);

	return ddmcr_old;
}

static inline e2k_ddmcr_t ddmcr1_pause(void)
{
	e2k_ddmcr_t ddmcr1, ddmcr1_old;

	if (!cpu_has(CPU_FEAT_ISET_V7))
		return (e2k_ddmcr_t) { .word = 0 };

	/*
	 * Stop counting for more precise group counting and also
	 * to avoid races when one counter overflows while another
	 * is being handled.
	 *
	 * Writing %ddmcr1 also clears other pending exc_data_debug
	 */
	ddmcr1 = READ_DDMCR1_REG();
	ddmcr1_old = ddmcr1;
	ddmcr1.ddmar[0].user = 0;
	ddmcr1.ddmar[0].system = 0;
	ddmcr1.ddmar[1].user = 0;
	ddmcr1.ddmar[1].system = 0;
	WRITE_DDMCR1_REG(ddmcr1);

	return ddmcr1_old;
}

#ifdef CONFIG_PERF_EVENTS
extern void dimcr_continue(e2k_dimcr_t dimcr_old);
extern void dimcr1_continue(e2k_dimcr_t dimcr1_old);
extern void ddmcr_continue(e2k_ddmcr_t ddmcr_old);
extern void ddmcr1_continue(e2k_ddmcr_t ddmcr1_old);

/*
 * Attention!!! Structures bpf_user_pt_regs_t defined at <uapi/asm/ptrace.h>
 * and user_pt_regs defined at <asm/ptrace.h> must be the same, otherwise
 * the cast is invalid.
 */
#define perf_arch_bpf_user_pt_regs(regs) ((bpf_user_pt_regs_t *) &regs->user_regs)

#else
static inline void dimcr_continue(e2k_dimcr_t dimcr_old)
{
	e2k_dimcr_t dimcr;

	/*
	 * Restart counting
	 */
	dimcr = read_DIMCR_reg();
	dimcr.dimar[0].user = dimcr_old.dimar[0].user;
	dimcr.dimar[0].system = dimcr_old.dimar[0].system;
	dimcr.dimar[1].user = dimcr_old.dimar[1].user;
	dimcr.dimar[1].system = dimcr_old.dimar[1].system;
	write_DIMCR_reg(dimcr);
}

static inline void dimcr1_continue(e2k_dimcr_t dimcr1_old)
{
	e2k_dimcr_t dimcr1;

	if (!cpu_has(CPU_FEAT_ISET_V7) || cpu_has(CPU_HWBUG_DIMCR1))
		return;

	/*
	 * Restart counting
	 */
	dimcr1 = read_DIMCR1_reg();
	dimcr1.dimar[0].user = dimcr1_old.dimar[0].user;
	dimcr1.dimar[0].system = dimcr1_old.dimar[0].system;
	dimcr1.dimar[1].user = dimcr1_old.dimar[1].user;
	dimcr1.dimar[1].system = dimcr1_old.dimar[1].system;
	write_DIMCR1_reg(dimcr1);
}

static inline void ddmcr_continue(e2k_ddmcr_t ddmcr_old)
{
	e2k_ddmcr_t ddmcr;

	/*
	 * Restart counting
	 */
	ddmcr = READ_DDMCR_REG();
	ddmcr.ddmar[0].user = ddmcr_old.ddmar[0].user;
	ddmcr.ddmar[0].system = ddmcr_old.ddmar[0].system;
	ddmcr.ddmar[1].user = ddmcr_old.ddmar[1].user;
	ddmcr.ddmar[1].system = ddmcr_old.ddmar[1].system;
	WRITE_DDMCR_REG(ddmcr);
}

static inline void ddmcr1_continue(e2k_ddmcr_t ddmcr1_old)
{
	e2k_ddmcr_t ddmcr1;

	if (!cpu_has(CPU_FEAT_ISET_V7))
		return;

	/*
	 * Restart counting
	 */
	ddmcr1 = READ_DDMCR1_REG();
	ddmcr1.ddmar[0].user = ddmcr1_old.ddmar[0].user;
	ddmcr1.ddmar[0].system = ddmcr1_old.ddmar[0].system;
	ddmcr1.ddmar[1].user = ddmcr1_old.ddmar[1].user;
	ddmcr1.ddmar[1].system = ddmcr1_old.ddmar[1].system;
	WRITE_DDMCR1_REG(ddmcr1);
}
#endif
