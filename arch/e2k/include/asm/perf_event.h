#pragma once

#include <linux/percpu.h>
#include <asm/cpu_regs.h>
#include <asm/perf_event_types.h>
#include <asm/process.h>
#include <asm/regs_state.h>

static inline void set_perf_event_pending(void) {}
static inline void clear_perf_event_pending(void) {}

void perf_data_overflow_handle(struct pt_regs *);
void perf_instr_overflow_handle(struct pt_regs *);
void dimtp_overflow(struct perf_event *event);

#define perf_arch_fetch_caller_regs perf_arch_fetch_caller_regs
static __always_inline void perf_arch_fetch_caller_regs(struct pt_regs *regs,
							unsigned long ip)
{
	SAVE_STACK_REGS(regs, current_thread_info(), false, false);
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
	dimcr = READ_DIMCR_REG();
	dimcr_old = dimcr;
	AS(dimcr)[0].user = 0;
	AS(dimcr)[0].system = 0;
	AS(dimcr)[1].user = 0;
	AS(dimcr)[1].system = 0;
	WRITE_DIMCR_REG(dimcr);

	return dimcr_old;
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
	AS(ddmcr)[0].user = 0;
	AS(ddmcr)[0].system = 0;
	AS(ddmcr)[1].user = 0;
	AS(ddmcr)[1].system = 0;
	WRITE_DDMCR_REG(ddmcr);

	return ddmcr_old;
}

#ifdef CONFIG_PERF_EVENTS
extern void dimcr_continue(e2k_dimcr_t dimcr_old);
extern void ddmcr_continue(e2k_ddmcr_t ddmcr_old);
#else
static inline void dimcr_continue(e2k_dimcr_t dimcr_old)
{
	e2k_dimcr_t dimcr;

	/*
	 * Restart counting
	 */
	dimcr = READ_DIMCR_REG();
	AS(dimcr)[0].user = AS(dimcr_old)[0].user;
	AS(dimcr)[0].system = AS(dimcr_old)[0].system;
	AS(dimcr)[1].user = AS(dimcr_old)[1].user;
	AS(dimcr)[1].system = AS(dimcr_old)[1].system;
	WRITE_DIMCR_REG(dimcr);
}

static inline void ddmcr_continue(e2k_ddmcr_t ddmcr_old)
{
	e2k_ddmcr_t ddmcr;

	/*
	 * Restart counting
	 */
	ddmcr = READ_DDMCR_REG();
	AS(ddmcr)[0].user = AS(ddmcr_old)[0].user;
	AS(ddmcr)[0].system = AS(ddmcr_old)[0].system;
	AS(ddmcr)[1].user = AS(ddmcr_old)[1].user;
	AS(ddmcr)[1].system = AS(ddmcr_old)[1].system;
	WRITE_DDMCR_REG(ddmcr);
}
#endif
