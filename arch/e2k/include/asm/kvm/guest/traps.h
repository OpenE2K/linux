/*
 *
 * Copyright (C) 2012 MCST
 *
 * Defenition of kvm guest kernel traps handling routines.
 */

#ifndef _E2K_ASM_KVM_GUEST_TRAPS_H
#define _E2K_ASM_KVM_GUEST_TRAPS_H

#include <linux/kernel.h>
#include <asm/vga.h>
#include <asm/pgtable.h>

extern int kvm_do_hw_stack_bounds(struct pt_regs *regs,
					bool proc_bounds, bool chain_bounds);
extern irqreturn_t guest_do_interrupt(struct pt_regs *regs);
extern unsigned long kvm_do_mmio_page_fault(struct pt_regs *regs,
					trap_cellar_t *tcellar);
extern void kvm_sysrq_showstate_interrupt(struct pt_regs *regs);
extern void kvm_init_system_handlers_table(void);

static inline void
kvm_instr_page_fault(struct pt_regs *regs, tc_fault_type_t ftype,
			const int async_instr)
{
	native_instr_page_fault(regs, ftype, async_instr);
}

static inline u64
kvm_TIR0_clear_false_exceptions(u64 TIR_hi, int nr_TIRs)
{
	/* all false exceptions were cleared while traps passing to guest */
	return TIR_hi;
}

extern int kvm_host_apply_psp_delta_to_signal_stack(unsigned long base,
			unsigned long size, unsigned long start,
			unsigned long end, unsigned long delta);
extern int kvm_host_apply_pcsp_delta_to_signal_stack(unsigned long base,
			unsigned long size, unsigned long start,
			unsigned long end, unsigned long delta);

static inline unsigned long
kvm_mmio_page_fault(struct pt_regs *regs, trap_cellar_t *tcellar)
{
	e2k_addr_t address;

	if (!kernel_mode(regs)) {
		/* trap on user and cannot be to IO */
		return 0;	/* not handled */
	}
	address = tcellar->address;
	if (likely(((address < GUEST_VMALLOC_START ||
			address >= GUEST_VMALLOC_END)) &&
				!KVM_IS_VGA_VRAM_VIRT_ADDR(address))) {
		/* address is out of address space area to IO remap or */
		/* VGA VRAM */
		return 0;	/* not handled */
	}
	return kvm_do_mmio_page_fault(regs, tcellar);
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (paravirtualized pv_ops not used) */

static inline u64
TIR0_clear_false_exceptions(u64 TIR_hi, int nr_TIRs)
{
	return kvm_TIR0_clear_false_exceptions(TIR_hi, nr_TIRs);
}

static inline void
instr_page_fault(struct pt_regs *regs, tc_fault_type_t ftype,
			const int async_instr)
{
	kvm_instr_page_fault(regs, ftype, async_instr);
}

/* The follow function should be deleted */
static inline int
do_hw_stack_bounds(struct pt_regs *regs, bool proc_bounds, bool chain_bounds)
{
	return kvm_do_hw_stack_bounds(regs, proc_bounds, chain_bounds);
}

static inline int host_apply_psp_delta_to_signal_stack(unsigned long base,
			unsigned long size, unsigned long start,
			unsigned long end, unsigned long delta)
{
	if (IS_HV_GM()) {
		return native_host_apply_psp_delta_to_signal_stack(base, size,
							start, end, delta);
	}
	return kvm_host_apply_psp_delta_to_signal_stack(base, size,
							start, end, delta);
}

static inline int host_apply_pcsp_delta_to_signal_stack(unsigned long base,
			unsigned long size, unsigned long start,
			unsigned long end, unsigned long delta)
{
	if (IS_HV_GM()) {
		return native_host_apply_pcsp_delta_to_signal_stack(base, size,
							start, end, delta);
	}
	return kvm_host_apply_pcsp_delta_to_signal_stack(base, size,
							start, end, delta);
}

static inline void
handle_interrupt(struct pt_regs *regs)
{
	guest_do_interrupt(regs);
}
static inline unsigned long
mmio_page_fault(struct pt_regs *regs, trap_cellar_t *tcellar)
{
	return kvm_mmio_page_fault(regs, tcellar);
}
static inline void
init_guest_system_handlers_table(void)
{
	kvm_init_system_handlers_table();
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* _E2K_ASM_KVM_GUEST_TRAPS_H */
