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

#undef	DEBUG_USER_STACKS_MODE
#undef	DebugKVMUS
#define DEBUG_USER_STACKS_MODE	0
#define	DebugKVMUS(fmt, args...)					\
({									\
	if (DEBUG_USER_STACKS_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

extern bool debug_ustacks;
#undef	DEBUG_USER_STACKS_MODE
#undef	DebugUST
#define	DEBUG_USER_STACKS_MODE	0	/* guest user stacks debug mode */
#define	DebugUST(fmt, args...)						\
({									\
	if (debug_ustacks)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

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

static inline void
kvm_kernel_hw_stack_frames_copy(u64 *dst, const u64 *src, unsigned long size)
{
	fast_tagged_memory_copy(dst, src, size,
			TAGGED_MEM_STORE_REC_OPC |
			MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
			TAGGED_MEM_LOAD_REC_OPC |
			MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT, true);
}

static __always_inline void
kvm_collapse_kernel_ps(u64 *dst, const u64 *src, u64 spilled_size)
{
	e2k_psp_hi_t k_psp_hi;
	u64 ps_ind, ps_size;
	u64 size;

	DebugUST("current host procedure stack index 0x%x, PSHTP 0x%x\n",
		NATIVE_NV_READ_PSP_HI_REG().PSP_hi_ind,
		NATIVE_NV_READ_PSHTP_REG().PSHTP_ind);

	KVM_COPY_STACKS_TO_MEMORY();
	ATOMIC_GET_HW_PS_SIZES(ps_ind, ps_size);

	size = ps_ind - spilled_size;
	BUG_ON(!IS_ALIGNED(size, ALIGN_PSTACK_TOP_SIZE) || (s64) size < 0);

	kvm_kernel_hw_stack_frames_copy(dst, src, size);

	k_psp_hi = NATIVE_NV_READ_PSP_HI_REG();
	k_psp_hi.PSP_hi_ind = size;
	HYPERVISOR_update_psp_hi(k_psp_hi.PSP_hi_half);

	DebugUST("move spilled procedure part from host top %px to "
		"bottom %px, size 0x%llx\n",
		src, dst, size);
	DebugUST("host kernel procedure stack index is now 0x%x, "
		"guest user PSHTP 0x%llx\n",
		k_psp_hi.PSP_hi_ind, spilled_size);
}

static __always_inline void
kvm_collapse_kernel_pcs(u64 *dst, const u64 *src, u64 spilled_size)
{
	e2k_pcsp_hi_t k_pcsp_hi;
	u64 pcs_ind, pcs_size;
	u64 size;

	DebugUST("current host chain stack index 0x%x, PCSHTP 0x%llx\n",
		NATIVE_NV_READ_PCSP_HI_REG().PCSP_hi_ind,
		NATIVE_READ_PCSHTP_REG_SVALUE());

	KVM_COPY_STACKS_TO_MEMORY();
	ATOMIC_GET_HW_PCS_SIZES(pcs_ind, pcs_size);

	size = pcs_ind - spilled_size;
	BUG_ON(!IS_ALIGNED(size, ALIGN_PCSTACK_TOP_SIZE) || (s64) size < 0);

	kvm_kernel_hw_stack_frames_copy(dst, src, size);

	k_pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();
	k_pcsp_hi.PCSP_hi_ind = size;
	HYPERVISOR_update_pcsp_hi(k_pcsp_hi.PCSP_hi_half);

	DebugUST("move spilled chain part from host top %px to "
		"bottom %px, size 0x%llx\n",
		src, dst, size);
	DebugUST("host kernel chain stack index is now 0x%x, "
		"guest user PCSHTP 0x%llx\n",
		k_pcsp_hi.PCSP_hi_ind, spilled_size);
}

static __always_inline int
copy_stack_page_from_kernel(void __user *dst, void *src, e2k_size_t to_copy,
				bool is_chain)
{
	int ret;

	ret = HYPERVISOR_copy_hw_stacks_frames(dst, src, to_copy, is_chain);
	return ret;
}

static __always_inline int
copy_stack_page_to_user(void __user *dst, void *src, e2k_size_t to_copy,
			bool is_chain)
{
	struct page *page = NULL;
	unsigned long addr = (unsigned long)dst;
	void *k_dst;
	e2k_size_t offset;
	mm_segment_t seg;
	unsigned long ts_flag;
	int npages;
	int ret;

	if (to_copy == 0)
		return 0;

	DebugUST("started to copy %s stack from kernel stack %px to user %px "
		"size 0x%lx\n",
		(is_chain) ? "chain" : "procedure",
		src, dst, to_copy);
	seg = get_fs();
	set_fs(K_USER_DS);
	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	do {
		npages = __get_user_pages_fast(addr, 1, 1, &page);
		if (npages == 1)
			break;
		npages = get_user_pages_unlocked(addr, 1, &page, FOLL_WRITE);
		if (npages == 1)
			break;
		clear_ts_flag(ts_flag);
		set_fs(seg);
		ret = -EFAULT;
		goto failed;
	} while (npages != 1);
	clear_ts_flag(ts_flag);
	set_fs(seg);

	offset = addr & ~PAGE_MASK;
	k_dst = page_address(page) + offset;
	DebugUST("copy stack frames from kernel %px to user %px, size 0x%lx\n",
		src, k_dst, to_copy);
	ret = copy_stack_page_from_kernel(k_dst, src, to_copy, is_chain);
	if (ret != 0) {
		pr_err("%s(): copy %s stack to user %px from kernel %px, "
			"size 0x%lx failed, error %d\n",
			__func__, (is_chain) ? "chain" : "procedure",
			src, k_dst, to_copy, ret);
		goto failed_copy;
	}

failed_copy:
	put_page(page);
failed:
	return ret;
}

static __always_inline int
kvm_copy_user_stack_from_kernel(void __user *dst, void *src,
				e2k_size_t to_copy, bool is_chain)
{
	e2k_size_t offset, len;
	int ret;

	if (to_copy == 0)
		return 0;

	DebugUST("started to copy %s stack from kernel stack %px to user %px "
		"size 0x%lx\n",
		(is_chain) ? "chain" : "procedure",
		src, dst, to_copy);
	do {
		offset = (unsigned long)dst & ~PAGE_MASK;
		len = min(to_copy, PAGE_SIZE - offset);
		ret = copy_stack_page_to_user(dst, src, len, is_chain);
		if (ret != 0)
			goto failed;
		dst += len;
		src += len;
		to_copy -= len;
	} while (to_copy > 0);

	return 0;

failed:
	return ret;
}

static __always_inline int
kvm_user_hw_stacks_copy(pt_regs_t *regs, int add_frames_num)
{
	e2k_psp_lo_t psp_lo;
	e2k_psp_hi_t psp_hi;
	e2k_pshtp_t  pshtp;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_pcshtp_t  pcshtp;
	e2k_stacks_t *stacks;
	void __user *dst;
	void *src;
	long to_copy, from, there_are, add_frames_size;
	int ret;

	BUG_ON(irqs_disabled());

	ret = HYPERVISOR_copy_stacks_to_memory();
	if (ret != 0) {
		pr_err("%s(): flush of kernel stacks failed, error %d\n",
			__func__, ret);
		goto failed;
	}

	/* copy user part of procedure stack from kernel back to user */
	stacks = &regs->stacks;
	ATOMIC_READ_HW_STACKS_REGS(psp_lo.PSP_lo_half, psp_hi.PSP_hi_half,
				   pshtp.PSHTP_reg,
				   pcsp_lo.PCSP_lo_half, pcsp_hi.PCSP_hi_half,
				   pcshtp);
	src = (void *)psp_lo.PSP_lo_base;
	DebugUST("procedure stack at kernel from %px, size 0x%x, ind 0x%x, "
		"pshtp 0x%llx\n",
		src, psp_hi.PSP_hi_size, psp_hi.PSP_hi_ind, pshtp.PSHTP_reg);
	BUG_ON(psp_hi.PSP_hi_ind > psp_hi.PSP_hi_size);

	if (stacks->psp_hi.PSP_hi_ind >= stacks->psp_hi.PSP_hi_size) {
		/* procedure stack overflow, need expand */
		ret = handle_proc_stack_bounds(stacks, regs->trap);
		if (unlikely(ret)) {
			pr_err("%s(): could not handle process %s (%d) "
				"procedure stack overflow, error %d\n",
				__func__, current->comm, current->pid, ret);
			goto failed;
		}
	}
	to_copy = GET_PSHTP_MEM_INDEX(stacks->pshtp);
	BUG_ON(to_copy < 0);
	from = stacks->psp_hi.PSP_hi_ind - to_copy;
	BUG_ON(from < 0);
	dst = (void __user *)stacks->psp_lo.PSP_lo_base + from;
	DebugUST("procedure stack at user from %px, ind 0x%x, "
		"pshtp size to copy 0x%lx\n",
		dst, stacks->psp_hi.PSP_hi_ind, to_copy);
	there_are = stacks->psp_hi.PSP_hi_size - from;
	if (there_are < to_copy) {
		pr_err("%s(): user procedure stack overflow, there are 0x%lx "
			"to copy need 0x%lx, not yet implemented\n",
			__func__, there_are, to_copy);
		BUG_ON(true);
	}
	if (to_copy > 0) {
		ret = kvm_copy_user_stack_from_kernel(dst, src, to_copy, false);
		if (ret != 0) {
			pr_err("%s(): procedure stack copying from kernel %px "
				"to user %px, size 0x%lx failed, error %d\n",
				__func__, src, dst, to_copy, ret);
			goto failed;
		}
	}

	/* copy user part of chain stack from kernel back to user */
	add_frames_size = add_frames_num * SZ_OF_CR;
	src = (void *)pcsp_lo.PCSP_lo_base;
	DebugUST("chain stack at kernel from %px, size 0x%x + 0x%lx, ind 0x%x, "
		"pcshtp 0x%x\n",
		src, pcsp_hi.PCSP_hi_size, add_frames_size, pcsp_hi.PCSP_hi_ind,
		pcshtp);
	BUG_ON(pcsp_hi.PCSP_hi_ind + PCSHTP_SIGN_EXTEND(pcshtp) +
				add_frames_size > pcsp_hi.PCSP_hi_size);
	if (stacks->pcsp_hi.PCSP_hi_ind >= stacks->pcsp_hi.PCSP_hi_size) {
		/* chain stack overflow, need expand */
		ret = handle_chain_stack_bounds(stacks, regs->trap);
		if (unlikely(ret)) {
			pr_err("%s(): could not handle process %s (%d) "
				"chain stack overflow, error %d\n",
				__func__, current->comm, current->pid, ret);
			goto failed;
		}
	}
	to_copy = PCSHTP_SIGN_EXTEND(stacks->pcshtp);
	BUG_ON(to_copy < 0);
	from = stacks->pcsp_hi.PCSP_hi_ind - to_copy;
	BUG_ON(from < 0);
	dst = (void *)stacks->pcsp_lo.PCSP_lo_base + from;
	to_copy += add_frames_size;
	BUG_ON(to_copy > pcsp_hi.PCSP_hi_ind + PCSHTP_SIGN_EXTEND(pcshtp));
	DebugUST("chain stack at user from %px, ind 0x%x, "
		"pcshtp size to copy 0x%lx\n",
		dst, stacks->pcsp_hi.PCSP_hi_ind, to_copy);
	there_are = stacks->pcsp_hi.PCSP_hi_size - from;
	if (there_are < to_copy) {
		pr_err("%s(): user chain stack overflow, there are 0x%lx "
			"to copy need 0x%lx, not yet implemented\n",
			__func__, there_are, to_copy);
		BUG_ON(true);
	}
	if (to_copy > 0) {
		ret = kvm_copy_user_stack_from_kernel(dst, src, to_copy, true);
		if (ret != 0) {
			pr_err("%s(): chain stack copying from kernel %px "
				"to user %px, size 0x%lx failed, error %d\n",
				__func__, src, dst, to_copy, ret);
			goto failed;
		}
	}
	if (add_frames_size > 0) {
		/* increment chain stack pointer */
		stacks->pcsp_hi.PCSP_hi_ind += add_frames_size;
	}

failed:
	if (DEBUG_USER_STACKS_MODE)
		debug_ustacks = false;
	return ret;
}

extern void kvm_get_mm_notifier(thread_info_t *ti, struct mm_struct *mm);

/**
 * user_hw_stacks_prepare - prepare user hardware stacks that have been
 *			 SPILLed to kernel back to user space
 * @stacks - saved user stack registers
 * @cur_window_q - size of current window in procedure stack,
 *		   needed only if @copy_full is not set
 * @syscall - true if called upon direct system call exit (no signal handlers)
 *
 * This does two things:
 *
 * 1) It is possible that upon kernel entry pcshtp == 0 in some cases:
 *   - user signal handler had pcshtp==0x20 before return to sigreturn()
 *   - user context had pcshtp==0x20 before return to makecontext_trampoline()
 *   - chain stack underflow happened
 * So it is possible in sigreturn() and traps, but not in system calls.
 * If we are using the trick with return to FILL user hardware stacks than
 * we must have frame in chain stack to return to. So in this case kernel's
 * chain stack is moved up by one frame (0x20 bytes).
 * We also fill the new frame with actual user data and update stacks->pcshtp,
 * this is needed to keep the coherent state where saved stacks->pcshtp values
 * shows how much data from user space has been spilled to kernel space.
 *
 * 2) It is not possible to always FILL all of user data that have been
 * SPILLed to kernel stacks. So we manually copy the leftovers that can
 * not be FILLed to user space.
 * This copy does not update stacks->pshtp and stacks->pcshtp. Main reason
 * is signals: if a signal arrives after copying then it must see a coherent
 * state where saved stacks->pshtp and stacks->pcshtp values show how much
 * data from user space has been spilled to kernel space.
 */
static __always_inline int kvm_user_hw_stacks_prepare(
		struct e2k_stacks *stacks, pt_regs_t *regs,
		u64 cur_window_q, enum restore_caller from, int syscall)
{
	e2k_pcshtp_t u_pcshtp = stacks->pcshtp;
	int ret;

	BUG_ON(!kvm_trap_user_mode(regs));

	BUG_ON(from & FROM_PV_VCPU_MODE);

	/*
	 * 1) Make sure there is free space in kernel chain stack to return to
	 */
	if (!syscall && u_pcshtp == 0) {
		DebugUST("%s(): PCSHTP is empty\n", __func__);
	}

	/*
	 * 2) User data copying will be done some later at
	 *    kvm_prepare_user_hv_stacks()
	 */
	ret = kvm_user_hw_stacks_copy(regs, 0);
	if (ret != 0) {
		pr_err("%s(): copying of hardware stacks failed< error %d\n",
			__func__, ret);
		do_exit(SIGKILL);
	}
	return ret;
}

static inline int
kvm_ret_from_fork_prepare_hv_stacks(struct pt_regs *regs)
{
	return kvm_user_hw_stacks_copy(regs, 0);
}

static inline void kvm_release_task_struct(struct task_struct *task)
{
	thread_info_t *ti;
	int ret;

	ti = task_thread_info(task);
	BUG_ON(ti == NULL);

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

/* own VCPU state: directly accessible through global registers */
static inline kvm_vcpu_state_t *kvm_get_vcpu_state(void)
{
	unsigned long vcpu_base;

	KVM_GET_VCPU_STATE_BASE(vcpu_base);
	return (kvm_vcpu_state_t *)(vcpu_base);
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

static __always_inline void
kernel_hw_stack_frames_copy(u64 *dst, const u64 *src, unsigned long size)
{
	kvm_kernel_hw_stack_frames_copy(dst, src, size);
}

static __always_inline void
collapse_kernel_ps(u64 *dst, const u64 *src, u64 spilled_size)
{
	kvm_collapse_kernel_ps(dst, src, spilled_size);
}

static __always_inline void
collapse_kernel_pcs(u64 *dst, const u64 *src, u64 spilled_size)
{
	kvm_collapse_kernel_pcs(dst, src, spilled_size);
}

static __always_inline void host_user_hw_stacks_prepare(
		struct e2k_stacks *stacks, pt_regs_t *regs,
		u64 cur_window_q, enum restore_caller from, int syscall)
{
	if (regs->sys_num == __NR_e2k_longjmp2) {
		/* hardware stacks already are prepared */
		return;
	}
	kvm_user_hw_stacks_prepare(stacks, regs, cur_window_q,
					from, syscall);
}

static inline int
ret_from_fork_prepare_hv_stacks(struct pt_regs *regs)
{
	return kvm_ret_from_fork_prepare_hv_stacks(regs);
}

static inline void
virt_cpu_thread_init(struct task_struct *boot_task)
{
	unsigned long vcpu_state_base;

	KVM_GET_VCPU_STATE_BASE(vcpu_state_base);
	task_thread_info(boot_task)->vcpu_state_base = vcpu_state_base;
	if (!IS_HV_GM())
		kvm_vcpu_boot_thread_init(boot_task);
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

#define	GET_PARAVIRT_GUEST_MODE(pv_guest, regs)	/* nothing to do */

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
