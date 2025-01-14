/*
 *
 * Copyright (C) 2001 MCST
 *
 * Defenition of traps handling routines.
 */

#ifndef _E2K_TRAP_TABLE_H
#define _E2K_TRAP_TABLE_H

#include <linux/types.h>
#include <asm/e2k_api.h>
#include <asm/cpu_regs_types.h>
#include <asm/trap_def.h>
#include <asm/glob_regs.h>
#include <asm/mmu_regs_types.h>
#include <asm/e2k_debug.h>

#ifndef	__ASSEMBLY__
#include <asm/process.h>
#endif	/* __ASSEMBLY__ */

#ifdef	__ASSEMBLY__
#include <generated/asm-offsets.h>
#endif	/* __ASSEMBLY__ */

#ifndef	__ASSEMBLY__

#define GDB_BREAKPOINT_STUB_MASK	0xffffffffffffff8fUL
#define	GDB_BREAKPOINT_STUB		0x0dc0c08004000001UL

typedef long (*ttable_entry_args_t)(int sys_num, ...);

static inline bool
is_gdb_breakpoint_trap(struct pt_regs *regs)
{
	u64 __user *instr = (u64 __user *) instruction_pointer(regs);
	u64 val;

	if (!user_mode(regs))
		return false;

	if (host_get_user(val, instr, regs))
		return false;

	return (val & GDB_BREAKPOINT_STUB_MASK) == GDB_BREAKPOINT_STUB;
}

extern void kernel_stack_overflow(unsigned int overflows);
extern void kernel_data_stack_overflow(void);

static inline void native_clear_fork_child_pt_regs(struct pt_regs *childregs)
{
	childregs->sys_rval = 0;
	/*
	 * Remove all pointers to parent's data stack
	 * (these are not needed anyway for system calls)
	 */
	childregs->trap = NULL;
	childregs->aau_context = NULL;
#ifdef CONFIG_KERNEL_TIMES_ACCOUNT
	childregs->scall_times = NULL;
#endif
	childregs->next = NULL;
}

static inline unsigned int
native_is_kernel_data_stack_bounds(bool trap_on_kernel, e2k_usd_lo_t usd_lo)
{
	/* In native case this check is done in assembler in ttable_entry0 */
	return false;
}

static inline void
native_stack_bounds_trap_enable(void)
{
	/* 'sge' flag unused while trap/system calls handling */
	/* so nithing to do */
}
static inline void
native_correct_trap_return_ip(struct pt_regs *regs, unsigned long return_ip)
{
	if (regs == NULL) {
		regs = current_thread_info()->pt_regs;
		BUG_ON(regs == NULL);
	}
	regs->crs.cr0_hi.ip = return_ip >> 3;
}

static inline int
native_do_aau_page_fault(struct pt_regs *const regs, e2k_addr_t address,
		const tc_cond_t condition, const tc_mask_t mask,
		const unsigned int aa_no)
{
	(void)do_page_fault(regs, address, condition, mask, 0, NULL);
	return 0;
}

extern long native_ttable_entry1(int sys_num, ...);
extern long native_ttable_entry3(int sys_num, ...);
extern long native_ttable_entry4(int sys_num, ...);

#define	do_ttable_entry_name(entry)	# entry
#define	ttable_entry_name(entry)	do_ttable_entry_name(entry)

#define	ttable_entry1_name		ttable_entry_name(ttable_entry1)
#define	ttable_entry3_name		ttable_entry_name(ttable_entry3)
#define	ttable_entry4_name		ttable_entry_name(ttable_entry4)

#define	ttable_entry1_func(sys_num, ...) \
({ \
	long rval; \
	rval = ttable_entry1(sys_num, ##__VA_ARGS__); \
	rval; \
})
#define	ttable_entry3_func(sys_num, ...) \
({ \
	long rval; \
	rval = ttable_entry3(sys_num, ##__VA_ARGS__); \
	rval; \
})
#define	ttable_entry4_func(sys_num, ...) \
({ \
	long rval; \
	rval = ttable_entry4(sys_num, ##__VA_ARGS__); \
	rval; \
})

#ifndef	CONFIG_VIRTUALIZATION
#if	CONFIG_CPU_ISET >= 5
# define SYS_RET_TYPE long
#else	/* ! CONFIG_CPU_ISET < 5 */
# define SYS_RET_TYPE void
#endif	/* CONFIG_CPU_ISET >= 5 */
#else	/* CONFIG_VIRTUALIZATION */
# define SYS_RET_TYPE long
#endif	/* ! CONFIG_VIRTUALIZATION */

typedef unsigned long (*system_call_func)(unsigned long arg1,
						unsigned long arg2,
						unsigned long arg3,
						unsigned long arg4,
						unsigned long arg5,
						unsigned long arg6);

typedef unsigned long (*protected_system_call_func)(unsigned long arg1,
						unsigned long arg2,
						unsigned long arg3,
						unsigned long arg4,
						unsigned long arg5,
						unsigned long arg6,
						struct pt_regs *regs);
static inline void native_exit_handle_syscall(e2k_addr_t sbr, e2k_usd_hi_t usd_hi,
		e2k_usd_lo_t usd_lo, e2k_upsr_t upsr, e2k_mem_crs_t crs)
{
	NATIVE_EXIT_HANDLE_SYSCALL(sbr, usd_hi.USD_hi_half, usd_lo.USD_lo_half,
				   upsr.UPSR_reg);
	WRITE_CR0_HI_REG(crs.cr0_hi);
	WRITE_CR0_LO_REG(crs.cr0_lo);
	WRITE_CR1_HI_REG(crs.cr1_hi);
	WRITE_CR1_LO_REG(crs.cr1_lo);
}

extern SYS_RET_TYPE notrace handle_sys_call(system_call_func sys_call,
			long arg1, long arg2, long arg3, long arg4,
			long arg5, long arg6, struct pt_regs *regs);

extern void notrace handle_guest_fast_sys_call(void);
extern void notrace handle_compat_guest_fast_sys_call(void);
extern void notrace handle_prot_guest_fast_sys_call(void);

extern const system_call_func sys_call_table[NR_syscalls];
extern const system_call_func sys_call_table_32[NR_syscalls];
extern const protected_system_call_func sys_call_table_entry8[NR_syscalls];
extern const system_call_func sys_protcall_table[NR_syscalls];
extern const system_call_func sys_call_table_deprecated[NR_syscalls];

#if !defined(CONFIG_PARAVIRT_GUEST) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native kernel without any virtualization */
/* or it is host kernel with virtualization support */

#define	FILL_HARDWARE_STACKS__HW()	NATIVE_FILL_HARDWARE_STACKS__HW()
#define	FILL_HARDWARE_STACKS__SW(sw_fill_sequel)	\
		NATIVE_FILL_HARDWARE_STACKS__SW(sw_fill_sequel)


static inline void clear_fork_child_pt_regs(struct pt_regs *childregs)
{
	native_clear_fork_child_pt_regs(childregs);
}

static inline void
correct_trap_return_ip(struct pt_regs *regs, unsigned long return_ip)
{
	native_correct_trap_return_ip(regs, return_ip);
}
static inline void
stack_bounds_trap_enable(void)
{
	native_stack_bounds_trap_enable();
}

#define	ttable_entry1		native_ttable_entry1
#define	ttable_entry3		native_ttable_entry3
#define	ttable_entry4		native_ttable_entry4

#define	get_ttable_entry1	((ttable_entry_args_t)native_ttable_entry1)
#define	get_ttable_entry3	((ttable_entry_args_t)native_ttable_entry3)
#define	get_ttable_entry4	((ttable_entry_args_t)native_ttable_entry4)

static inline void exit_handle_syscall(e2k_addr_t sbr, e2k_usd_hi_t usd_hi,
		e2k_usd_lo_t usd_lo, e2k_upsr_t upsr, e2k_mem_crs_t crs)
{
	native_exit_handle_syscall(sbr, usd_hi, usd_lo, upsr, crs);
}

static inline unsigned long
kvm_mmio_page_fault(struct pt_regs *regs, trap_cellar_t *tcellar)
{
	return 0;
}

#ifndef	CONFIG_VIRTUALIZATION
/* it is native kernel without any virtualization */

#define	instr_page_fault(__regs, __ftype, __async)	\
		native_do_instr_page_fault(__regs, __ftype, __async)

static inline int
do_aau_page_fault(struct pt_regs *const regs, e2k_addr_t address,
		const tc_cond_t condition, const tc_mask_t mask,
		const unsigned int aa_no)
{
	return native_do_aau_page_fault(regs, address, condition, mask, aa_no);
}

static inline unsigned int
is_kernel_data_stack_bounds(bool on_kernel, e2k_usd_lo_t usd_lo)
{
	return native_is_kernel_data_stack_bounds(on_kernel, usd_lo);
}
#endif	/* ! CONFIG_VIRTUALIZATION */

#endif	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */

#else	/* __ASSEMBLY__ */

/*
 * Global registers map used by kernel
 * Numbers of used global registers see at arch/e2k/include/asm/glob_regs.h
 */

#define	GET_GREG_MEMONIC(greg_no)	%dg ## greg_no
#define	DO_GET_GREG_MEMONIC(greg_no)	GET_GREG_MEMONIC(greg_no)

#define	GCURTASK	DO_GET_GREG_MEMONIC(CURRENT_TASK_GREG)
#define	GCPUOFFSET	DO_GET_GREG_MEMONIC(MY_CPU_OFFSET_GREG)
#define	GCPUID_PREEMPT	DO_GET_GREG_MEMONIC(SMP_CPU_ID_GREG)
/* Macroses for virtualization support on assembler */
#define	GVCPUSTATE	DO_GET_GREG_MEMONIC(GUEST_VCPU_STATE_GREG)

#endif	/* ! __ASSEMBLY__ */

#include <asm/kvm/trap_table.h>

#ifndef __ASSEMBLY__
__always_inline /* For CPU_HWBUG_VIRT_PSIZE_INTERCEPTION */
static void init_pt_regs_for_syscall(struct pt_regs *regs)
{
	regs->next = NULL;
	regs->trap = NULL;

#ifdef CONFIG_USE_AAU
	regs->aau_context = NULL;
#endif

	AW(regs->flags) = 0;
	init_guest_syscalls_handling(regs);
}
#endif

#endif	/* _E2K_TRAP_TABLE_H */
