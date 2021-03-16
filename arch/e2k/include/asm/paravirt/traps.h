/*
 *
 * Copyright (C) 2016 MCST
 *
 * Defenition of paravirtualized kernel traps handling routines.
 */

#ifndef _E2K_ASM_PARAVIRT_TRAPS_H
#define _E2K_ASM_PARAVIRT_TRAPS_H

#include <asm/paravirt/pv_ops.h>
#include <asm/kvm/guest/traps.h>

#define	pv_TIR0_clear_false_exceptions(__TIR_hi, __nr_TIRs)	\
({ \
	u64 TIR; \
	\
	if (!paravirt_enabled()) { \
		TIR = native_TIR0_clear_false_exceptions(__TIR_hi, __nr_TIRs); \
	} else { \
		TIR = kvm_TIR0_clear_false_exceptions(__TIR_hi, __nr_TIRs); \
	} \
	TIR; \
})

static inline void
pv_instr_page_fault(struct pt_regs *regs, tc_fault_type_t ftype,
			const int async_instr)
{
	pv_cpu_ops.instr_page_fault(regs, ftype, async_instr);
}

static inline unsigned long
pv_mmio_page_fault(struct pt_regs *regs, trap_cellar_t *tcellar)
{
	return pv_cpu_ops.mmio_page_fault(regs, (struct trap_cellar *)tcellar);
}
static inline int
pv_do_hw_stack_bounds(struct pt_regs *regs, bool proc_bounds, bool chain_bounds)
{
	return pv_cpu_ops.do_hw_stack_bounds(regs, proc_bounds, chain_bounds);
}
static inline irqreturn_t
pv_handle_interrupt(struct pt_regs *regs)
{
	return pv_cpu_ops.handle_interrupt(regs);
}
static inline void
pv_init_guest_system_handlers_table(void)
{
	pv_cpu_ops.init_guest_system_handlers_table();
}

#ifdef	CONFIG_PARAVIRT_GUEST

#define	TIR0_clear_false_exceptions(__TIR_hi, __nr_TIRs)	\
		pv_TIR0_clear_false_exceptions(__TIR_hi, __nr_TIRs)

static inline void
instr_page_fault(struct pt_regs *regs, tc_fault_type_t ftype,
			const int async_instr)
{
	pv_instr_page_fault(regs, ftype, async_instr);
}
static inline int
do_hw_stack_bounds(struct pt_regs *regs, bool proc_bounds, bool chain_bounds)
{
	return pv_do_hw_stack_bounds(regs, proc_bounds, chain_bounds);
}
static inline void
handle_interrupt(struct pt_regs *regs)
{
	pv_handle_interrupt(regs);
}
static inline unsigned long
mmio_page_fault(struct pt_regs *regs, trap_cellar_t *tcellar)
{
	return pv_mmio_page_fault(regs, tcellar);
}
static inline void
init_guest_system_handlers_table(void)
{
	pv_init_guest_system_handlers_table();
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* _E2K_ASM_PARAVIRT_TRAPS_H */
