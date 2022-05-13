/*
 * KVM guest kernel processes support
 * Copyright 2011 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_KVM_GUEST_PROCESS_H
#define _E2K_KVM_GUEST_PROCESS_H

#include <asm/kvm/hypercall.h>
#include <asm/cpu_regs_types.h>
#include <asm/stacks.h>
#include <asm/ptrace.h>

/* real flush of hardware stacks should be done by host hypercall */
/* so here nothing to do */
#ifdef CONFIG_KVM_GUEST_HW_PV
# define KVM_FLUSHCPU	\
do \
	if (IS_HV_GM()) { \
		NATIVE_FLUSHCPU; \
	} \
while (false)
# define KVM_FLUSHR	\
do \
	if (IS_HV_GM()) { \
		NATIVE_FLUSHR; \
	} \
while (false)
# define KVM_FLUSHC	\
do \
	if (IS_HV_GM()) { \
		NATIVE_FLUSHC; \
	} \
while (false)
# define BOOT_KVM_FLUSHCPU	\
do \
	if (BOOT_IS_HV_GM()) { \
		NATIVE_FLUSHCPU; \
	} \
while (false)
# define BOOT_KVM_FLUSHR	\
do \
	if (BOOT_IS_HV_GM()) { \
		NATIVE_FLUSHR; \
	} \
while (false)
# define BOOT_KVM_FLUSHC	\
do \
	if (BOOT_IS_HV_GM()) { \
		NATIVE_FLUSHC; \
	} \
while (false)
#else	/* ! CONFIG_KVM_GUEST_HW_PV */
# define KVM_FLUSHCPU
# define KVM_FLUSHR
# define KVM_FLUSHC
# define BOOT_KVM_FLUSHCPU
# define BOOT_KVM_FLUSHR
# define BOOT_KVM_FLUSHC
#endif	/* CONFIG_KVM_GUEST_HW_PV */

#define	kvm_kernel_mode(regs)	kvm_from_kernel_IP((regs)->crs.cr0_hi)

#define	kvm_from_trap_on_kernel(regs)	\
		is_trap_from_kernel(regs, GUEST_TASK_SIZE)

/*
 *  to define kernel_mode in trap we must use trap_ip from trap celler
 *  (in user code may be sys_call and psr may be after sys_call)
 */
#define	kvm_trap_kernel_mode(regs)					\
		(kvm_kernel_mode(regs) && kvm_from_trap_on_kernel(regs))
#define	kvm_trap_user_mode(regs)					\
		(guest_user_mode(regs) && !LIGHT_HYPERCALL_MODE(regs))

static inline void KVM_COPY_STACKS_TO_MEMORY(void)
{
	if (IS_HV_GM())
		NATIVE_COPY_STACKS_TO_MEMORY();
	else
		HYPERVISOR_copy_stacks_to_memory();
}

/* own VCPU state: directly accessible through global registers */
static inline kvm_vcpu_state_t *kvm_get_vcpu_state(void)
{
	unsigned long vcpu_base;

	KVM_GET_VCPU_STATE_BASE(vcpu_base);
	return (kvm_vcpu_state_t *)(vcpu_base);
}

extern void kvm_clean_pc_stack_zero_frame(void *addr, bool user);
extern e2k_cute_t *kvm_get_cut_entry_pointer(int cui, struct page **page);
extern void kvm_put_cut_entry_pointer(struct page *page);

/*
 * Restore proper psize field of WD register
 */
static inline void
kvm_restore_wd_register_psize(e2k_wd_t wd_from)
{
	HYPERVISOR_update_wd_psize(wd_from.WD_psize);
}

/*
 * Preserve current p[c]shtp as they indicate how much to FILL when returning
 */
static inline void
kvm_preserve_user_hw_stacks_to_copy(e2k_stacks_t *u_stacks,
					e2k_stacks_t *cur_stacks)
{
	/* guest user hardware stacks sizes to copy should be updated */
	/* after copying and therefore are not preserve */
}

static __always_inline void
kvm_jump_to_ttable_entry(struct pt_regs *regs, enum restore_caller from)
{
	if (from & (FROM_SYSCALL_N_PROT | FROM_SIGRETURN | FROM_RET_FROM_FORK)) {
		switch (regs->kernel_entry) {
		case 1:
		case 3:
		case 4:
			KVM_WRITE_UPSR_REG(E2K_KERNEL_UPSR_ENABLED);
			/*
			 * Unconditional return to host with guest's return value,
			 * because of only host can recover initial state of stacks
			 * and some other registers state to restart system call
			 */
			E2K_SYSCALL_RETURN(regs->sys_rval);
		default:
			BUG();
		}
	} else if (from & FROM_SYSCALL_PROT_8) {
		/* the syscall restart is not yet implemented */
		BUG();
	} else if (from & FROM_SYSCALL_PROT_10) {
		/* the syscall restart is not yet implemented */
		BUG();
	} else {
		BUG();
	}
}

static inline void kvm_clear_virt_thread_struct(thread_info_t *ti)
{
	/* guest PID/MMID's can be received only after registration on host */
	ti->gpid_nr = -1;
	ti->gmmid_nr = -1;
}

static inline void kvm_release_task_struct(struct task_struct *task)
{
	thread_info_t *ti;
	int ret;

	ti = task_thread_info(task);
	BUG_ON(ti == NULL);
	if (ti->gpid_nr == -1) {
		/* the process was not registered on host, nothing to do */
		BUG_ON(ti->gmmid_nr != -1);
		return;
	}

	ret = HYPERVISOR_release_task_struct(ti->gpid_nr);
	if (ret != 0) {
		pr_err("%s(): could not release task struct of %s (%d) "
			"GPID #%d on host, error %d\n",
			__func__, task->comm, task->pid, ti->gpid_nr, ret);
	}
}

/*
 * These functions for guest kernel, see comment for virtualization at
 *	arch/e2k/include/asm/ptrace.h
 * In this case guest is main kernel and here knows that it is guest
 * Extra kernel is host
 *
 * Get/set kernel stack limits of area reserved at the top of hardware stacks
 * Kernel areas include two part:
 *	guest kernel stack reserved area at top of stack
 *	host kernel stack reserved area at top of stack
 */

static __always_inline e2k_size_t
kvm_get_hw_ps_user_size(hw_stack_t *hw_stacks)
{
	return get_hw_ps_user_size(hw_stacks);
}
static __always_inline e2k_size_t
kvm_get_hw_pcs_user_size(hw_stack_t *hw_stacks)
{
	return get_hw_pcs_user_size(hw_stacks);
}
static __always_inline void
kvm_set_hw_ps_user_size(hw_stack_t *hw_stacks, e2k_size_t u_ps_size)
{
	set_hw_ps_user_size(hw_stacks, u_ps_size);
}
static __always_inline void
kvm_set_hw_pcs_user_size(hw_stack_t *hw_stacks, e2k_size_t u_pcs_size)
{
	set_hw_pcs_user_size(hw_stacks, u_pcs_size);
}

/*
 * Table of pointers to VCPUs state.
 * Own VCPU state pointer is loaded on some global registers to direct access
 * Other VCPUs state pointers can be accessible through this table
 */
extern kvm_vcpu_state_t *vcpus_state[NR_CPUS];

static inline kvm_vcpu_state_t *kvm_get_the_vcpu_state(long vcpu_id)
{
	return vcpus_state[vcpu_id];
}

#define	KVM_ONLY_SET_GUEST_GREGS(ti)	\
		KVM_SET_VCPU_STATE_BASE(kvm_get_the_vcpu_state(	\
							smp_processor_id()))

/* guest kernel does not support own guests and cannot be run as host */
/* so has not the problem - nothing to do */
/* see arch/e2k/include/asm/process.h for more details why and how */
#define	KVM_GUEST_UPDATE_VCPU_THREAD_CONTEXT(task, ti, regs, gti, vcpu)
#define	KVM_GUEST_CHECK_VCPU_THREAD_CONTEXT(__ti)

extern void kvm_vcpu_boot_thread_init(struct task_struct *boot_task);
extern int kvm_copy_kernel_stacks(struct task_struct *new_task,
					unsigned long fn, unsigned long arg);
extern void kvm_define_kernel_hw_stacks_sizes(hw_stack_t *hw_stacks);
extern void boot_kvm_define_kernel_hw_stacks_sizes(hw_stack_t *hw_stacks);
extern void kvm_define_user_hw_stacks_sizes(hw_stack_t *hw_stacks);

extern void kvm_release_hw_stacks(thread_info_t *dead_ti);
extern void kvm_release_kernel_stacks(thread_info_t *dead_ti);
extern int kvm_kmem_area_host_chunk(e2k_addr_t stack_base,
			e2k_size_t stack_size, int hw_flag);
extern void kvm_kmem_area_unhost_chunk(e2k_addr_t stack_base,
			e2k_size_t stack_size);
extern int kvm_switch_to_new_user(e2k_stacks_t *stacks, hw_stack_t *hw_stacks,
			e2k_addr_t cut_base, e2k_size_t cut_size,
			e2k_addr_t entry_point, int cui,
			unsigned long flags, bool kernel);

extern int kvm_clone_prepare_spilled_user_stacks(e2k_stacks_t *child_stacks,
		const e2k_mem_crs_t *child_crs, const struct pt_regs *regs,
		struct sw_regs *new_sw_regs, struct thread_info *new_ti,
		unsigned long clone_flags);
extern int kvm_copy_spilled_user_stacks(e2k_stacks_t *child_stacks,
		e2k_mem_crs_t *child_crs, sw_regs_t *new_sw_regs,
		thread_info_t *new_ti);

extern int kvm_copy_user_stacks(unsigned long clone_flags,
			e2k_addr_t new_stk_base, e2k_size_t new_stk_sz,
			struct task_struct *new_task, pt_regs_t *regs);

extern void kvm_fix_process_pt_regs(thread_info_t *ti, e2k_stacks_t *stacks,
					pt_regs_t *regs, pt_regs_t *old_regs);

extern void __init kvm_setup_arch(void);

#ifdef	COMMON_KERNEL_USER_HW_STACKS
/*
 * Free guest kernel hardware stacks after completion of sys_execve()
 * and switch to new user process. The new process executes on own stacks
 * and old kernel hardware stacks on which was run do_execve() can be released
 * only after switch to new user stacks.
 * WARNING: probably release of stacks should be done earlier (not while exit
 * from the process and deactivate mm), perhaps as pending work
 */
static inline void
kvm_free_old_kernel_hardware_stacks(void)
{
	thread_info_t *ti = current_thread_info();

	if (!test_ts_flag(TS_MAPPED_HW_STACKS_INVALID))
		/* it is not process after sys_execve() */
		return;

	if (test_ts_flag(TS_MAPPED_HW_STACKS)) {
		release_old_hw_stack_mappings(ti);
	} else {
		release_old_kernel_hardware_stacks(ti);
	}

	clear_ts_flag(TS_MAPPED_HW_STACKS_INVALID);
}
#endif	/* COMMON_KERNEL_USER_HW_STACKS */

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* native guest kernel */
#define	E2K_FLUSHCPU	KVM_FLUSHCPU
#define	E2K_FLUSHR	KVM_FLUSHR
#define	E2K_FLUSHC	KVM_FLUSHC
#define	BOOT_FLUSHCPU	KVM_FLUSHCPU
#define	BOOT_FLUSHR	KVM_FLUSHR
#define	BOOT_FLUSHC	KVM_FLUSHC

#define	ONLY_SET_GUEST_GREGS(ti)	KVM_ONLY_SET_GUEST_GREGS(ti)

#define	UPDATE_VCPU_THREAD_CONTEXT(task, ti, regs, gti, vcpu)	\
		KVM_GUEST_UPDATE_VCPU_THREAD_CONTEXT(task, ti, regs, gti, vcpu)
#define	CHECK_VCPU_THREAD_CONTEXT(__ti)	\
		KVM_GUEST_CHECK_VCPU_THREAD_CONTEXT(__ti)

#define GOTO_RETURN_TO_PARAVIRT_GUEST(ret_value)
#define	COND_GOTO_RETURN_TO_PARAVIRT_GUEST(cond, ret_value)
#define GOTO_DONE_TO_PARAVIRT_GUEST()
#define COND_GOTO_DONE_TO_PARAVIRT_GUEST(cond)

#define	do_map_user_hard_stack_to_kernel(node, kstart, ubase, size) \
		do_map_native_user_hard_stack_to_kernel(node, kstart, \
							ubase, size)
#define	resume_vm_thread()	/* none any virtual machines and threads */

static inline bool host_is_at_HV_GM_mode(void)
{
	/* the guest has not own guests, so cannot be as host */
	return false;
}

static inline void COPY_STACKS_TO_MEMORY(void)
{
	KVM_COPY_STACKS_TO_MEMORY();
}

static inline void
clean_pc_stack_zero_frame(void *addr, bool user)
{
	kvm_clean_pc_stack_zero_frame(addr, user);
}

static inline e2k_cute_t *get_cut_entry_pointer(int cui, struct page **page)
{
	return kvm_get_cut_entry_pointer(cui, page);
}

static inline void put_cut_entry_pointer(struct page *page)
{
	kvm_put_cut_entry_pointer(page);
}

static inline void
restore_wd_register_psize(e2k_wd_t wd_from)
{
	kvm_restore_wd_register_psize(wd_from);
}

static inline void
preserve_user_hw_stacks_to_copy(e2k_stacks_t *u_stacks,
					e2k_stacks_t *cur_stacks)
{
	kvm_preserve_user_hw_stacks_to_copy(u_stacks, cur_stacks);
}

static __always_inline void
host_exit_to_usermode_loop(struct pt_regs *regs, bool syscall, bool has_signal)
{
	/* native & guest kernels cannot be as host */
}

static __always_inline void
jump_to_ttable_entry(struct pt_regs *regs, enum restore_caller from)
{
	kvm_jump_to_ttable_entry(regs, from);
}

static inline void
virt_cpu_thread_init(struct task_struct *boot_task)
{
	unsigned long vcpu_state_base;

	KVM_GET_VCPU_STATE_BASE(vcpu_state_base);
	task_thread_info(boot_task)->vcpu_state_base = vcpu_state_base;
}

static inline int
copy_kernel_stacks(struct task_struct *new_task,
			unsigned long fn, unsigned long arg)
{
	if (IS_HV_GM())
		return native_copy_kernel_stacks(new_task, fn, arg);
	else
		return kvm_copy_kernel_stacks(new_task, fn, arg);
}
#ifdef	COMMON_KERNEL_USER_HW_STACKS
static inline int
copy_user_stacks(unsigned long clone_flags,
		e2k_addr_t new_stk_base, e2k_size_t new_stk_sz,
		struct task_struct *new_task, pt_regs_t *regs)
{
	if (IS_HV_GM())
		return native_copy_user_stacks(clone_flags, new_stk_base,
						new_stk_sz, new_task, regs);
	else
		return kvm_copy_user_stacks(clone_flags, new_stk_base,
						new_stk_sz, new_task, regs);
}
#endif	/* COMMON_KERNEL_USER_HW_STACKS */

static inline void
define_kernel_hw_stacks_sizes(hw_stack_t *hw_stacks)
{
	if (IS_HV_GM())
		native_do_define_kernel_hw_stacks_sizes(hw_stacks);
	else
		kvm_define_kernel_hw_stacks_sizes(hw_stacks);
}

static inline void
boot_define_kernel_hw_stacks_sizes(hw_stack_t *hw_stacks)
{
	if (BOOT_IS_HV_GM())
		native_do_define_kernel_hw_stacks_sizes(hw_stacks);
	else
		boot_kvm_define_kernel_hw_stacks_sizes(hw_stacks);
}

static inline void
define_user_hw_stacks_sizes(hw_stack_t *hw_stacks)
{
	if (IS_HV_GM())
		native_define_user_hw_stacks_sizes(hw_stacks);
	else
		kvm_define_user_hw_stacks_sizes(hw_stacks);
}

#ifdef	COMMON_KERNEL_USER_HW_STACKS
static inline void
release_hw_stacks(thread_info_t *dead_ti)
{
	if (IS_HV_GM()) {
		native_release_hw_stacks(dead_ti);
	} else {
		kvm_release_hw_stacks(dead_ti);
	}
}
static inline void
release_kernel_stacks(thread_info_t *dead_ti)
{
	if (IS_HV_GM()) {
		native_release_kernel_stacks(dead_ti);
	} else {
		kvm_release_kernel_stacks(dead_ti);
	}
}
#endif	/* COMMON_KERNEL_USER_HW_STACKS */

#define	GET_PARAVIRT_GUEST_MODE(pv_guest, regs)				\
({									\
	(pv_guest) = false;						\
})

static inline int
switch_to_new_user(e2k_stacks_t *stacks, hw_stack_t *hw_stacks,
			e2k_addr_t cut_base, e2k_size_t cut_size,
			e2k_addr_t entry_point, int cui,
			unsigned long flags, bool kernel)
{
	if (likely(IS_HV_GM())) {
		return native_switch_to_new_user(stacks, hw_stacks,
			cut_base, cut_size, entry_point, cui, flags, kernel);
	} else {
		return kvm_switch_to_new_user(stacks, hw_stacks,
			cut_base, cut_size, entry_point, cui, flags, kernel);
	}
}

static inline int
clone_prepare_spilled_user_stacks(e2k_stacks_t *child_stacks,
		const e2k_mem_crs_t *child_crs, const struct pt_regs *regs,
		struct sw_regs *new_sw_regs, struct thread_info *new_ti,
		unsigned long clone_flags)
{
	if (likely(IS_HV_GM())) {
		return native_clone_prepare_spilled_user_stacks(child_stacks,
				child_crs, regs, new_sw_regs, new_ti,
				clone_flags);
	} else {
		return kvm_clone_prepare_spilled_user_stacks(child_stacks,
				child_crs, regs, new_sw_regs, new_ti,
				clone_flags);
	}
}

static inline int
copy_spilled_user_stacks(e2k_stacks_t *child_stacks, e2k_mem_crs_t *child_crs,
		sw_regs_t *new_sw_regs, thread_info_t *new_ti)
{
	if (likely(IS_HV_GM())) {
		native_copy_spilled_user_stacks(child_stacks, child_crs,
						new_sw_regs, new_ti);
		return 0;
	} else {
		return kvm_copy_spilled_user_stacks(child_stacks, child_crs,
						    new_sw_regs, new_ti);
	}
}

#ifdef	COMMON_KERNEL_USER_HW_STACKS
static inline void
free_old_kernel_hardware_stacks(void)
{
	if (likely(IS_HV_GM())) {
		native_free_old_kernel_hardware_stacks();
	} else {
		kvm_free_old_kernel_hardware_stacks();
	}
}
#endif	/* COMMON_KERNEL_USER_HW_STACKS */

/* the function is not used in guest mode so only to compile without errors */
static __always_inline __interrupt void
complete_switch_to_user_func(void)
{
	/* none own guests, so nothing to do in virtualization mode */
	/* but the function should switch interrupt control from UPSR to */
	/* PSR and set initial state of user UPSR */
	KVM_SET_USER_INITIAL_UPSR(E2K_USER_INITIAL_UPSR);
}
/* the function is not used in guest mode so only to compile without errors */
static __always_inline __interrupt void
complete_go2user(thread_info_t *ti, long fn)
{
	/* none own guests, so nothing to do in virtualization mode */
	/* but the function should restore user UPSR state */
	KVM_WRITE_UPSR_REG(ti->upsr);
}

#define	clear_vm_thread_flags()		/* own virtual machines is not */
					/* supported on guest */
					/* so nothing to clear */

static inline void
clear_virt_thread_struct(thread_info_t *ti)
{
	kvm_clear_virt_thread_struct(ti);
}

static inline void virt_setup_arch(void)
{
	kvm_setup_arch();
}

static inline void free_virt_task_struct(struct task_struct *task)
{
	kvm_release_task_struct(task);
}

#define	usd_cannot_be_expanded(regs)	user_stack_cannot_be_expanded()

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* !(_E2K_KVM_GUEST_PROCESS_H) */
