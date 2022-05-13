/* linux/include/asm-e2k/traps.h, v 1.0 03/07/2001.
 * 
 * Copyright (C) 2001 MCST 
 *
 * Defenition of traps handling routines.
 */

#ifndef _E2K_TRAPS_H
#define _E2K_TRAPS_H

#include <linux/interrupt.h>
#include <asm/hw_irq.h>
#include <asm/ptrace.h>
#include <asm/trap_def.h>

typedef void (*exc_function)(struct pt_regs *regs);
extern const exc_function exc_tbl[];
extern const char *exc_tbl_name[];
union pf_mode;

#define S_SIG(regs, signo, trapno, code)				       \
do {									       \
	int nr_TIRs;							       \
	e2k_tir_hi_t tir_hi;						       \
	struct trap_pt_regs *trap = (regs)->trap;			       \
	void __user *addr;						       \
									       \
	if (trap) {							       \
		AW(tir_hi) = trap->TIR_hi;				       \
		nr_TIRs = GET_NR_TIRS(AW(tir_hi));			       \
		addr = (void __user *) (trap->TIRs[nr_TIRs].TIR_lo.TIR_lo_ip); \
	} else {							       \
		addr = 0;						       \
	}								       \
									       \
	force_sig_fault(signo, code, addr, trapno);			       \
} while (0)

extern int pf_on_page_boundary(unsigned long address, tc_cond_t cond);
extern bool is_spurious_qp_store(bool store, unsigned long address,
			int fmt, tc_mask_t mask, unsigned long *pf_address);
extern void parse_TIR_registers(struct pt_regs *regs, u64 exceptions);
extern void do_aau_fault(int aa_field, struct pt_regs *regs);
extern int handle_proc_stack_bounds(struct e2k_stacks *stacks,
		struct trap_pt_regs *trap);
extern int handle_chain_stack_bounds(struct e2k_stacks *stacks,
		struct trap_pt_regs *trap);
extern int do_page_fault(struct pt_regs *const regs, e2k_addr_t address,
		tc_cond_t condition, tc_mask_t mask, const int instr_page,
		union pf_mode *mode_p);
#ifdef CONFIG_KVM_ASYNC_PF
extern void do_pv_apf_wake(struct pt_regs *regs);
#endif /* */
extern void do_trap_cellar(struct pt_regs *regs, int only_system_tc);

extern irqreturn_t native_do_interrupt(struct pt_regs *regs);
extern void do_nm_interrupt(struct pt_regs *regs);
extern void do_mem_error(struct pt_regs *regs);
extern void native_instr_page_fault(struct pt_regs *regs, tc_fault_type_t ftype,
					const int async_instr);

extern void do_trap_cellar(struct pt_regs *regs, int only_system_tc);

extern int constrict_user_data_stack(struct pt_regs *regs, unsigned long incr);
extern int expand_user_data_stack(struct pt_regs *regs, unsigned long incr);
extern void do_notify_resume(struct pt_regs *regs);

extern void coredump_in_future(void);

enum getsp_action {
	GETSP_OP_FAIL = 1,
	GETSP_OP_SIGSEGV,
	GETSP_OP_INCREMENT,
	GETSP_OP_DECREMENT
};
extern enum getsp_action parse_getsp_operation(const struct pt_regs *regs,
		int *incr, void __user **fault_addr);

static inline unsigned int user_trap_init(void)
{
	/* Enable system calls for user's processes. */
	unsigned int linux_osem = 0;

	/* Enable deprecated generic ttable2 syscall entry. */
	linux_osem = 1 << LINUX_SYSCALL_TRAPNUM_OLD;

	/* Enable ttable1 syscall entry - 32-bit syscalls only */
	linux_osem |= 1 << LINUX_SYSCALL32_TRAPNUM;
	/* Enable ttable3 syscall entry - 64-bit syscalls only */
	linux_osem |= 1 << LINUX_SYSCALL64_TRAPNUM;

	/* Enable fast syscalls entries. */
	linux_osem |= 1 << LINUX_FAST_SYSCALL32_TRAPNUM;
	linux_osem |= 1 << LINUX_FAST_SYSCALL64_TRAPNUM;
	linux_osem |= 1 << LINUX_FAST_SYSCALL128_TRAPNUM;

#ifdef CONFIG_PROTECTED_MODE
	linux_osem |= (1 << PMODE_SYSCALL_TRAPNUM);
	linux_osem |= (1 << PMODE_NEW_SYSCALL_TRAPNUM);
#endif /* CONFIG_PROTECTED_MODE */

	return linux_osem;
}

static inline unsigned int guest_trap_init(void)
{
	/* Enable system calls for user's processes. */
	unsigned int linux_osem = user_trap_init();

#ifdef CONFIG_KVM_HOST_MODE
	linux_osem |= HYPERCALLS_TRAPS_MASK;
#endif

	return linux_osem;
}

static inline unsigned int user_hcall_init(void)
{
	unsigned int linux_hcem = 0;

	linux_hcem = 1 << LINUX_HCALL_GENERIC_TRAPNUM;
	linux_hcem |= 1 << LINUX_HCALL_LIGHT_TRAPNUM;

	return linux_hcem;
}

extern char __hypercalls_begin[];
static inline void kernel_trap_mask_init(void)
{
	WRITE_OSEM_REG(user_trap_init());
#ifdef CONFIG_KVM_HOST_MODE
	if (!paravirt_enabled()) {
		machine.rwd(E2K_REG_HCEM, user_hcall_init());
		machine.rwd(E2K_REG_HCEB, (unsigned long) __hypercalls_begin);
	}
#endif
}

static inline int
native_host_apply_psp_delta_to_signal_stack(unsigned long base,
			unsigned long size, unsigned long start,
			unsigned long end, unsigned long delta)
{
	/* native & host kernel cannot be paravirtualized guest */
	return 0;
}

static inline int
native_host_apply_pcsp_delta_to_signal_stack(unsigned long base,
			unsigned long size, unsigned long start,
			unsigned long end, unsigned long delta)
{
	/* native & host kernel cannot be paravirtualized guest */
	return 0;
}

static inline int
native_host_apply_usd_delta_to_signal_stack(unsigned long top,
					unsigned long delta, bool incr)
{
	/* native & host kernel cannot be paravirtualized guest */
	return 0;
}

/*
 * MMIO page fault cannot occur on native or host mode,
 * so ignore such traps
 */
static inline unsigned long
native_mmio_page_fault(struct pt_regs *regs, trap_cellar_t *tcellar)
{
	return 0;
}

#ifdef	CONFIG_VIRTUALIZATION
extern void native_sysrq_showstate_interrupt(struct pt_regs *regs);
static inline void
native_init_guest_system_handlers_table(void)
{
	if (paravirt_enabled()) {
		/* It is native guest */
		setup_PIC_vector_handler(SYSRQ_SHOWSTATE_EPIC_VECTOR,
			native_sysrq_showstate_interrupt, 1,
			"native_sysrq_showstate_interrupt");
	}
}
# ifndef CONFIG_KVM
#  error "Undefined guest virtualization type"
# endif	/* CONFIG_KVM */
#else	/* ! CONFIG_VIRTUALIZATION */
/* it is native host kernel without virtualization support */
static inline void
native_init_guest_system_handlers_table(void)
{
	/* Nothing to do */
}
# define SET_RUNSTATE_IN_USER_TRAP()
# define SET_RUNSTATE_OUT_USER_TRAP()
# define SET_RUNSTATE_IN_KERNEL_TRAP(cur_runstate)
# define SET_RUNSTATE_OUT_KERNEL_TRAP(cur_runstate)
#endif	/* CONFIG_VIRTUALIZATION */

#if	defined(CONFIG_KVM_GUEST_KERNEL)
/* It is pure guest kernel (not paravirtualized) */
#include <asm/kvm/guest/traps.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* It is paravirtualized host and guest kernel */
#include <asm/paravirt/traps.h>
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without any virtualization */
/* or it is native host kernel with virtualization support */

#define	TIR0_clear_false_exceptions(TIR_hi, nr_TIRs)	\
		native_TIR0_clear_false_exceptions(TIR_hi, nr_TIRs)

static inline void
handle_interrupt(struct pt_regs *regs)
{
	native_do_interrupt(regs);
}

extern int apply_psp_delta_to_signal_stack(unsigned long base,
		unsigned long size, unsigned long start, unsigned long end,
		unsigned long delta);
extern int apply_pcsp_delta_to_signal_stack(unsigned long base,
		unsigned long size, unsigned long start, unsigned long end,
		unsigned long delta);
extern int apply_usd_delta_to_signal_stack(unsigned long top, unsigned long delta,
		bool incr, unsigned long *chain_stack_border);

static inline int host_apply_psp_delta_to_signal_stack(unsigned long base,
			unsigned long size, unsigned long start,
			unsigned long end, unsigned long delta)
{
	return native_host_apply_psp_delta_to_signal_stack(base, size,
							start, end, delta);
}

static inline int host_apply_pcsp_delta_to_signal_stack(unsigned long base,
			unsigned long size, unsigned long start,
			unsigned long end, unsigned long delta)
{
	return native_host_apply_pcsp_delta_to_signal_stack(base, size,
							start, end, delta);
}

static inline int host_apply_usd_delta_to_signal_stack(unsigned long top,
					unsigned long delta, bool incr)
{
	return native_host_apply_usd_delta_to_signal_stack(top, delta, incr);
}

static inline unsigned long
mmio_page_fault(struct pt_regs *regs, trap_cellar_t *tcellar)
{
	return native_mmio_page_fault(regs, tcellar);
}
static inline void
init_guest_system_handlers_table(void)
{
	native_init_guest_system_handlers_table();
}
#endif	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */

#endif	/* _E2K_TRAPS_H */
