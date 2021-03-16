#ifndef __E2K_PARAVIRT_TRAP_TABLE_H
#define __E2K_PARAVIRT_TRAP_TABLE_H

#include <asm/paravirt/pv_ops.h>
#include <asm/kvm/cpu_regs_access.h>
#include <asm/kvm/guest/trap_table.h>

#define	pv_ttable_entry1	(pv_cpu_ops.trap_table_entry1)
#define	pv_ttable_entry3	(pv_cpu_ops.trap_table_entry3)
#define	pv_ttable_entry4	(pv_cpu_ops.trap_table_entry4)

static inline void
pv_handle_deferred_traps_in_syscall(struct pt_regs *regs,
					bool use_pt_regs, bool new_hs)
{
	if (pv_cpu_ops.handle_deferred_traps_in_syscall)
		pv_cpu_ops.handle_deferred_traps_in_syscall(regs,
						use_pt_regs, new_hs);
}

static inline void
pv_exit_handle_syscall(e2k_addr_t sbr, e2k_usd_hi_t usd_hi,
			e2k_usd_lo_t usd_lo, e2k_upsr_t upsr)
{
	if (!paravirt_enabled())
		native_exit_handle_syscall(sbr, usd_hi, usd_lo, upsr);
	else
		kvm_exit_handle_syscall(sbr, usd_hi, usd_lo, upsr);
}

static inline void pv_stack_bounds_trap_enable(void)
{
	if (pv_cpu_ops.stack_bounds_trap_enable)
		pv_cpu_ops.stack_bounds_trap_enable();
}
static inline bool
pv_is_proc_stack_bounds(struct thread_info *ti, struct pt_regs *regs)
{
	return pv_cpu_ops.is_proc_stack_bounds(ti, regs);
}
static inline bool
pv_is_chain_stack_bounds(struct thread_info *ti, struct pt_regs *regs)
{
	return pv_cpu_ops.is_chain_stack_bounds(ti, regs);
}

#define	PV_RETURN_TO_USER_PSP_PCSP(thread_info)				\
		PREFIX_RETURN_TO_USER_PSP_PCSP(PV, thread_info)

static inline void
pv_correct_trap_psp_pcsp(struct pt_regs *regs, struct thread_info *thread_info)
{
	pv_cpu_ops.correct_trap_psp_pcsp(regs, thread_info);
}
static inline void
pv_correct_scall_psp_pcsp(struct pt_regs *regs, struct thread_info *thread_info)
{
	pv_cpu_ops.correct_scall_psp_pcsp(regs, thread_info);
}
static inline void
pv_correct_trap_return_ip(struct pt_regs *regs, unsigned long return_ip)
{
	pv_cpu_ops.correct_trap_return_ip(regs, return_ip);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */
/* It is paravirtualized host/guest kernel */
#define	RETURN_TO_USER_PSP_PCSP(thread_info)	\
		PV_RETURN_TO_USER_PSP_PCSP(thread_info)

#define	ttable_entry1		pv_ttable_entry1
#define	ttable_entry3		pv_ttable_entry3
#define	ttable_entry4		pv_ttable_entry4

static inline void
exit_handle_syscall(e2k_addr_t sbr, e2k_usd_hi_t usd_hi,
			e2k_usd_lo_t usd_lo, e2k_upsr_t upsr)
{
	pv_exit_handle_syscall(sbr, usd_hi, usd_lo, upsr);
}

static inline void
handle_deferred_traps_in_syscall(struct pt_regs *regs,
					bool use_pt_regs, bool new_hs)
{
	pv_handle_deferred_traps_in_syscall(regs, use_pt_regs, new_hs);
}

static inline bool
is_proc_stack_bounds(struct thread_info *ti, struct pt_regs *regs)
{
	return pv_is_proc_stack_bounds(ti, regs);
}
static inline bool
is_chain_stack_bounds(struct thread_info *ti, struct pt_regs *regs)
{
	return pv_is_chain_stack_bounds(ti, regs);
}
static inline void
stack_bounds_trap_enable(void)
{
	pv_stack_bounds_trap_enable();
}
static inline void
correct_trap_psp_pcsp(struct pt_regs *regs, thread_info_t *thread_info)
{
	pv_correct_trap_psp_pcsp(regs, thread_info);
}
static inline void
correct_scall_psp_pcsp(struct pt_regs *regs, thread_info_t *thread_info)
{
	pv_correct_scall_psp_pcsp(regs, thread_info);
}
static inline void
correct_trap_return_ip(struct pt_regs *regs, unsigned long return_ip)
{
	pv_correct_trap_return_ip(regs, return_ip);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* __E2K_PARAVIRT_TRAP_TABLE_H */
