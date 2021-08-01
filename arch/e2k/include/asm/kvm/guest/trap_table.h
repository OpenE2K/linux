#ifndef __KVM_GUEST_E2K_TRAP_TABLE_H
#define __KVM_GUEST_E2K_TRAP_TABLE_H

/* Does not include this header directly, include <asm/trap_table.h> */

#include <asm/ptrace.h>
#include <asm/gregs.h>

extern int kvm_guest_ttable_entry0(void);
extern long kvm_guest_ttable_entry1(int sys_num,
		u32 arg1, u32 arg2, u32 arg3, u32 arg4, u32 arg5, u32 arg6);
extern long kvm_guest_ttable_entry3(int sys_num,
		u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5, u64 arg6);
extern long kvm_guest_ttable_entry4(int sys_num,
		u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5, u64 arg6);
extern long kvm_guest_ttable_entry5(int sys_num,
		u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5, u64 arg6);
extern long kvm_guest_ttable_entry6(int sys_num,
		u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5, u64 arg6);

static __always_inline void kvm_init_pt_regs_copyed_fields(struct pt_regs *regs)
{
#ifdef	CONFIG_KVM_GUEST_KERNEL
	if (likely(!regs->stack_regs_saved)) {
		regs->copyed.ps_size = 0;
		regs->copyed.pcs_size = 0;
		regs->copyed.pcs_injected_frames_size = 0;
	} else {
		/* the regs is reused and all stacks should be already copyed */
		;
	}
#endif	/* CONFIG_KVM_GUEST_KERNEL */
}

static __always_inline void kvm_init_pt_regs(struct pt_regs *regs)
{
	kvm_init_pt_regs_copyed_fields(regs);
}

static __always_inline void
kvm_init_traps_handling(struct pt_regs *regs, bool user_mode_trap)
{
	kvm_init_pt_regs(regs);
}
static __always_inline void
kvm_init_syscalls_handling(struct pt_regs *regs)
{
	kvm_init_traps_handling(regs, true);	/* now as traps init */
}

static inline void kvm_clear_fork_child_pt_regs(struct pt_regs *childregs)
{
	native_clear_fork_child_pt_regs(childregs);
	kvm_init_pt_regs_copyed_fields(childregs);
}

#define	KVM_FILL_HARDWARE_STACKS()	/* host itself will fill */

extern void kvm_correct_trap_psp_pcsp(struct pt_regs *regs,
						thread_info_t *thread_info);
extern void kvm_correct_scall_psp_pcsp(struct pt_regs *regs,
						thread_info_t *thread_info);
extern void kvm_correct_trap_return_ip(struct pt_regs *regs,
						unsigned long return_ip);

#ifdef	COMMON_KERNEL_USER_HW_STACKS
static inline void
kvm_do_correct_trap_psp_pcsp(struct pt_regs *regs, thread_info_t *thread_info)
{
	NATIVE_CORRECT_TRAP_PSP_PCSP(regs, thread_info);
}
static inline void
kvm_do_correct_scall_psp_pcsp(struct pt_regs *regs, thread_info_t *thread_info)
{
	/* hardware stacks do not increment for system call on guest */
	/* so nothing to do */
}
#endif	/* COMMON_KERNEL_USER_HW_STACKS */

/*
 * Guest trap handler on hardware stacks bounds can be called only on
 * exceptions flags into TIRs, which be passed to guest by host handler.
 * So nothing addition condition to run handler.
 */
static inline bool
kvm_is_proc_stack_bounds(struct thread_info *ti, struct pt_regs *regs)
{
	return false;
}
static inline bool
kvm_is_chain_stack_bounds(struct thread_info *ti, struct pt_regs *regs)
{
	return false;
}

static inline void kvm_set_sge(void)
{
	KVM_WRITE_PSR_REG_VALUE((KVM_READ_PSR_REG_VALUE() | PSR_SGE));
}
static inline void kvm_reset_sge(void)
{
	KVM_WRITE_PSR_REG_VALUE((KVM_READ_PSR_REG_VALUE() & ~PSR_SGE));
}
static inline void boot_kvm_set_sge(void)
{
	BOOT_KVM_WRITE_PSR_REG_VALUE((BOOT_KVM_READ_PSR_REG_VALUE() |
					PSR_SGE));
}
static inline void boot_kvm_reset_sge(void)
{
	BOOT_KVM_WRITE_PSR_REG_VALUE((BOOT_KVM_READ_PSR_REG_VALUE() &
					~PSR_SGE));
}
static inline void
kvm_stack_bounds_trap_enable(void)
{
	/* TODO now sge is always enabled (even in kernel),
	 * so this probably isn't needed anymore */
	kvm_set_sge();
}

static inline int
kvm_do_aau_page_fault(struct pt_regs *const regs, e2k_addr_t address,
		const tc_cond_t condition, const tc_mask_t mask,
		const unsigned int aa_no)
{
	return native_do_aau_page_fault(regs, address, condition, mask, aa_no);
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native KVM guest kernel (not paravirtualized) */

#define	ttable_entry1		kvm_guest_ttable_entry1
#define	ttable_entry3		kvm_guest_ttable_entry3
#define	ttable_entry4		kvm_guest_ttable_entry4
#define	ttable_entry5		kvm_guest_ttable_entry5
#define	ttable_entry6		kvm_guest_ttable_entry6

#define	get_ttable_entry1		\
({ \
	ttable_entry_args_t ttable_entry; \
	ttable_entry = \
		((IS_HV_GM()) ? (ttable_entry_args_t)native_ttable_entry1 : \
				(ttable_entry_args_t)kvm_guest_ttable_entry1); \
	ttable_entry; \
})
#define	get_ttable_entry3		\
({ \
	ttable_entry_args_t ttable_entry; \
	ttable_entry = \
		((IS_HV_GM()) ? (ttable_entry_args_t)native_ttable_entry3 : \
				(ttable_entry_args_t)kvm_guest_ttable_entry3); \
	ttable_entry; \
})

#define	get_ttable_entry4		\
({ \
	ttable_entry_args_t ttable_entry; \
	ttable_entry = \
		((IS_HV_GM()) ? (ttable_entry_args_t)native_ttable_entry4 : \
				(ttable_entry_args_t)kvm_guest_ttable_entry4); \
	ttable_entry; \
})

#define	FILL_HARDWARE_STACKS()	\
do { \
	if (IS_HV_GM()) { \
		NATIVE_FILL_HARDWARE_STACKS(); \
	} else { \
		KVM_FILL_HARDWARE_STACKS(); \
	} \
} while (false)

static inline void
exit_handle_syscall(e2k_addr_t sbr, e2k_usd_hi_t usd_hi,
			e2k_usd_lo_t usd_lo, e2k_upsr_t upsr)
{
	kvm_exit_handle_syscall(sbr, usd_hi, usd_lo, upsr);
}

#define	handle_guest_traps(regs)	/* none any guests */

static __always_inline void
init_guest_traps_handling(struct pt_regs *regs, bool user_mode_trap)
{
	kvm_init_traps_handling(regs, user_mode_trap);
}
static __always_inline void
init_guest_syscalls_handling(struct pt_regs *regs)
{
	kvm_init_syscalls_handling(regs);
}
static inline bool
is_guest_TIRs_frozen(struct pt_regs *regs)
{
	return false;	/* none any guest */
}

static inline void clear_fork_child_pt_regs(struct pt_regs *childregs)
{
	kvm_clear_fork_child_pt_regs(childregs);
}

static inline bool
is_proc_stack_bounds(struct thread_info *ti, struct pt_regs *regs)
{
	return kvm_is_proc_stack_bounds(ti, regs);
}
static inline bool
is_chain_stack_bounds(struct thread_info *ti, struct pt_regs *regs)
{
	return kvm_is_chain_stack_bounds(ti, regs);
}
static inline void
stack_bounds_trap_enable(void)
{
	kvm_stack_bounds_trap_enable();
}

#ifdef	COMMON_KERNEL_USER_HW_STACKS
static inline void
correct_trap_psp_pcsp(struct pt_regs *regs, thread_info_t *thread_info)
{
	kvm_do_correct_trap_psp_pcsp(regs, thread_info);
}
static inline void
correct_scall_psp_pcsp(struct pt_regs *regs, thread_info_t *thread_info)
{
	kvm_do_correct_scall_psp_pcsp(regs, thread_info);
}
#endif	/* COMMON_KERNEL_USER_HW_STACKS */

static inline void
correct_trap_return_ip(struct pt_regs *regs, unsigned long return_ip)
{
	kvm_correct_trap_return_ip(regs, return_ip);
}

static inline bool
handle_guest_last_wish(struct pt_regs *regs)
{
	return false;	/* none any guest and any wishes from */
}

static inline int
do_aau_page_fault(struct pt_regs *const regs, e2k_addr_t address,
		const tc_cond_t condition, const tc_mask_t mask,
		const unsigned int aa_no)
{
	return kvm_do_aau_page_fault(regs, address, condition, mask, aa_no);
}

/*
 * Following functions run on host, check if traps occurred on guest user
 * or kernel, so probably should be passed to guest kernel to handle.
 * Guest has not any own guests
 */
static inline unsigned long
pass_aau_trap_to_guest(struct pt_regs *regs,
			unsigned long TIR_hi, unsigned long TIR_lo)
{
	return 0;
}
static inline unsigned long
pass_the_trap_to_guest(struct pt_regs *regs,
				unsigned long TIR_hi, unsigned long TIR_lo,
				int trap_no)
{
	return 0;
}
static inline unsigned long
pass_stack_bounds_trap_to_guest(struct pt_regs *regs,
				bool proc_bounds, bool chain_bounds)
{
	return 0;
}
static inline unsigned long
pass_coredump_trap_to_guest(struct pt_regs *regs)
{
	return 0;
}
static inline unsigned long
pass_interrupt_to_guest(struct pt_regs *regs, int trap_no,
			unsigned long TIR_hi, unsigned long TIR_lo)
{
	return 0;
}
static inline unsigned long
pass_nm_interrupt_to_guest(struct pt_regs *regs, int trap_no,
			unsigned long TIR_hi, unsigned long TIR_lo)
{
	return 0;
}
static inline unsigned long
pass_virqs_to_guest(struct pt_regs *regs,
			unsigned long TIR_hi, unsigned long TIR_lo)
{
	return 0;
}
static inline unsigned long
pass_clw_fault_to_guest(struct pt_regs *regs, trap_cellar_t *tcellar)
{
	return 0;
}
static inline unsigned long
pass_page_fault_to_guest(struct pt_regs *regs, trap_cellar_t *tcellar)
{
	return 0;
}
static inline void
complete_page_fault_to_guest(unsigned long what_complete)
{
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* __KVM_GUEST_E2K_TRAP_TABLE_H */
