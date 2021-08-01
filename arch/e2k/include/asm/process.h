/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * include/asm-e2k/process.h
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_PROCESS_H
#define _E2K_PROCESS_H

#include <linux/types.h>
#include <linux/ftrace.h>
#include <linux/rmap.h>
#include <linux/vmalloc.h>
#include <linux/sched/signal.h>

#include <asm/e2k_syswork.h>
#include <asm/p2v/boot_v2p.h>
#include <asm/hw_stacks.h>
#include <asm/mman.h>
#include <asm/pv_info.h>
#include <asm/ptrace.h>
#include <asm/rlimits.h>
#include <asm/mmu_fault.h>
#include <asm/string.h>
#include <asm/protected_mode.h>
#include <asm/e2k_debug.h>
#include <asm/kvm/uaccess.h>	/* host mode support */

#undef	DEBUG_PV_UST_MODE
#undef	DebugUST
#define	DEBUG_PV_UST_MODE	0	/* guest user stacks debug */
#define	DebugUST(fmt, args...)						\
({									\
	if (debug_guest_ust)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PV_SYSCALL_MODE
#define	DEBUG_PV_SYSCALL_MODE	0	/* syscall injection debugging */

#if	DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE
extern bool debug_guest_ust;
#else
#define	debug_guest_ust	false
#endif	/* DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE */

#undef	DEBUG_SS_MODE
#undef	DebugSS
#define	DEBUG_SS_MODE		0	/* stack switching */
#define	DebugSS(fmt, args...)						\
({									\
	if (DEBUG_SS_MODE)						\
		pr_info(fmt, ##args);					\
})

#undef	DEBUG_US_MODE
#undef	DebugUS
#define	DEBUG_US_MODE		0	/* user stacks */
#define	DebugUS(fmt, args...)						\
({									\
	if (DEBUG_US_MODE)						\
		pr_info(fmt, ##args);					\
})

#undef	DEBUG_HS_MODE
#undef	DebugHS
#define	DEBUG_HS_MODE		0	/* hardware stacks */
#define DebugHS(...)		DebugPrint(DEBUG_HS_MODE ,##__VA_ARGS__)

#undef	DEBUG_KS_MODE
#undef	DebugKS
#define	DEBUG_KS_MODE		0	/* kernel stacks */
#define	DebugKS(fmt, args...)						\
({									\
	if (DEBUG_KS_MODE)						\
		pr_info(fmt, ##args);					\
})

#undef	DEBUG_EXECVE_MODE
#undef	DebugEX
#define	DEBUG_EXECVE_MODE	0	/* execve and exit */
#define DebugEX(...)	DebugPrint(DEBUG_EXECVE_MODE, ##__VA_ARGS__)

#undef	DEBUG_KVM_OLD_MODE
#undef	DebugOLD
#define DEBUG_KVM_OLD_MODE	0
#define	DebugOLD(fmt, args...)						\
({									\
	if (DEBUG_KVM_OLD_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PROCESS_MODE
#undef	DbgP
#define	DEBUG_PROCESS_MODE	0	/* processes */
#define	DbgP(fmt, args...)						\
({									\
	if (DEBUG_PROCESS_MODE)						\
		pr_info(fmt, ##args);					\
})

/*
 * additional arch-dep flags for clone()
 */
#define CLONE_GUEST_KERNEL	0x0000010000000000	/* guest kernel */
							/* thread creation */

/*
 * Stack frame types (determinate based on chain registers state):
 * host kernel frame - PSR.pm == 1
 * user frame (host and guest) - PSR.pm == 0 && IP < TASK_SIZE
 * guest kernel frame - PSP.pm == 0 && IP >= GUEST_TASK_SIZE
 */
typedef enum stack_frame {
	kernel_frame_type	= 0,	/* host kernel frame */
	user_frame_type		= 1,	/* user (host or guest) frame */
	guest_kernel_frame_type,	/* guest kernel frame type */
	undefined_frame_type,
} stack_frame_t;

static inline stack_frame_t
get_kernel_stack_frame_type(void)
{
	if (!paravirt_enabled() || IS_HV_GM())
		return kernel_frame_type;
	return guest_kernel_frame_type;
}

static inline stack_frame_t
get_user_stack_frame_type(void)
{
	return user_frame_type;
}

static inline stack_frame_t
get_the_stack_frame_type(e2k_cr0_hi_t cr0_hi,  e2k_cr1_lo_t cr1_lo,
				bool guest, bool ignore_IP)
{
	if (likely(!guest)) {
		/* host kernel: guest kernel is host user */
		if (is_call_from_host_kernel_IP(cr0_hi, cr1_lo, ignore_IP)) {
			return kernel_frame_type;
		} else if (is_call_from_host_user_IP(cr0_hi, cr1_lo,
								true)) {
			return user_frame_type;
		} else {
			pr_err("%s(): unknown host stack frame type: "
				"CR0_hi 0x%llx CR1_lo 0x%llx\n",
				__func__, cr0_hi.CR0_hi_half,
				cr1_lo.CR1_lo_half);
		}
	} else {
		/* guest kernel: frames can be host kernel, guest kernel */
		/* or guest user */
		if (is_call_from_host_kernel_IP(cr0_hi, cr1_lo, ignore_IP)) {
			return kernel_frame_type;
		} else if (is_call_from_guest_kernel_IP(cr0_hi, cr1_lo,
								ignore_IP)) {
			return guest_kernel_frame_type;
		} else if (is_call_from_guest_user_IP(cr0_hi, cr1_lo,
								ignore_IP)) {
			return user_frame_type;
		} else {
			pr_err("%s(): unknown guest stack frame type: "
				"CR0_hi 0x%llx CR1_lo 0x%llx\n",
				__func__, cr0_hi.CR0_hi_half,
				cr1_lo.CR1_lo_half);
		}
	}
	return undefined_frame_type;
}
static inline stack_frame_t
get_stack_frame_type(e2k_cr0_hi_t cr0_hi,  e2k_cr1_lo_t cr1_lo)
{
	return get_the_stack_frame_type(cr0_hi, cr1_lo,
			paravirt_enabled() && !IS_HV_GM(), false);
}

static inline stack_frame_t
get_stack_frame_type_IP(e2k_cr0_hi_t cr0_hi,  e2k_cr1_lo_t cr1_lo,
			bool ignore_IP)
{
	return get_the_stack_frame_type(cr0_hi, cr1_lo,
			paravirt_enabled() && !IS_HV_GM(), ignore_IP);
}

static inline stack_frame_t
get_task_stack_frame_type_IP(struct task_struct *task,
		e2k_cr0_hi_t cr0_hi,  e2k_cr1_lo_t cr1_lo, bool ignore_IP)
{
	return get_the_stack_frame_type(cr0_hi, cr1_lo,
			paravirt_enabled() && !IS_HV_GM() ||
						guest_task_mode(task),
			ignore_IP);
}

static __always_inline int
is_kernel_hardware_stacks(e2k_addr_t p_stack_base, e2k_addr_t pc_stack_base)
{
	if (p_stack_base >= TASK_SIZE || pc_stack_base >= TASK_SIZE) {
		return 1;
	}
	return 0;
}

extern int native_copy_kernel_stacks(struct task_struct *new_task,
		unsigned long fn, unsigned long arg);

static __always_inline e2k_size_t
get_hw_ps_area_user_size(hw_stack_area_t *ps)
{
	return ps->size;
}
static __always_inline e2k_size_t
get_hw_pcs_area_user_size(hw_stack_area_t *pcs)
{
	return pcs->size;
}
static __always_inline void
set_hw_ps_area_user_size(hw_stack_area_t *ps, e2k_size_t u_ps_size)
{
	ps->size = u_ps_size;
}
static __always_inline void
set_hw_pcs_area_user_size(hw_stack_area_t *pcs, e2k_size_t u_pcs_size)
{
	pcs->size = u_pcs_size;
}

static __always_inline e2k_size_t
get_hw_ps_user_size(hw_stack_t *hw_stacks)
{
	return get_hw_ps_area_user_size(&hw_stacks->ps);
}
static __always_inline e2k_size_t
get_hw_pcs_user_size(hw_stack_t *hw_stacks)
{
	return get_hw_pcs_area_user_size(&hw_stacks->pcs);
}
static __always_inline void
set_hw_ps_user_size(hw_stack_t *hw_stacks, e2k_size_t u_ps_size)
{
	set_hw_ps_area_user_size(&hw_stacks->ps, u_ps_size);
}
static __always_inline void
set_hw_pcs_user_size(hw_stack_t *hw_stacks, e2k_size_t u_pcs_size)
{
	set_hw_pcs_area_user_size(&hw_stacks->pcs, u_pcs_size);
}

#define	NATIVE_ONLY_SET_GUEST_GREGS(ti)	\
		/* it is native or host kernel, nothing to set */

static __always_inline int
native_switch_to_new_user(e2k_stacks_t *stacks, hw_stack_t *hw_stacks,
			e2k_addr_t cut_base, e2k_size_t cut_size,
			e2k_addr_t entry_point, int cui,
			unsigned long flags, bool kernel)
{
	return 0;	/* to continue switching at native mode */
}

extern int native_clone_prepare_spilled_user_stacks(e2k_stacks_t *child_stacks,
		const e2k_mem_crs_t *child_crs, const struct pt_regs *regs,
		struct sw_regs *new_sw_regs, struct thread_info *new_ti,
		unsigned long clone_flags);
extern void native_copy_spilled_user_stacks(e2k_stacks_t *child_stacks,
		e2k_mem_crs_t *child_crs, struct sw_regs *new_sw_regs,
		const struct thread_info *new_ti);

/*
 * Functions create all kernel hardware stacks(PS & PCS)
 */
static inline void
native_do_define_kernel_hw_stacks_sizes(hw_stack_t *hw_stacks)
{
	set_hw_ps_user_size(hw_stacks, KERNEL_P_STACK_SIZE);
	set_hw_pcs_user_size(hw_stacks, KERNEL_PC_STACK_SIZE);
}

extern void native_define_kernel_hw_stacks_sizes(hw_stack_t *hw_stacks);
extern void native_define_user_hw_stacks_sizes(hw_stack_t *hw_stacks);

extern void init_sw_user_regs(struct sw_regs *sw_regs,
				bool save_gregs, bool save_binco_regs);

/*
 * The function should be only in-line nad cannot call any other not in-line
 * functions, including printk() or other debugging print
 */
static __always_inline void
goto_new_user_hard_stk(e2k_stacks_t *stacks)
{
	/*
	 * Optimization to do not flush chain stack.
	 *
	 * Old stacks are not needed anymore, do not flush procedure
	 * registers and chain registers - only strip sizes
	 */
	NATIVE_STRIP_PSHTP_WINDOW();
	NATIVE_STRIP_PCSHTP_WINDOW();

	/*
	 * There might be a FILL operation still going right now.
	 * Wait for it's completion before going further - otherwise
	 * the next FILL on the new PSP/PCSP registers will race
	 * with the previous one.
	 *
	 * The first and the second FILL operations will use different
	 * addresses because we will change PSP/PCSP registers, and
	 * thus loads/stores from these two FILLs can race with each
	 * other leading to bad register file (containing values from
	 * both stacks)..
	 */
	E2K_WAIT(_ma_c);

	/*
	 * Since we are switching to user stacks their sizes
	 * have been stripped already, so use RAW_* writes.
	 */
	NATIVE_NV_WRITE_PSP_REG(stacks->psp_hi, stacks->psp_lo);
	NATIVE_NV_WRITE_PCSP_REG(stacks->pcsp_hi, stacks->pcsp_lo);
}

typedef	void (*start_fn)(u64 __start);

extern void switch_to_user_func(long dummy,
		start_fn start_func, e2k_size_t us_size, int cui);
#ifdef CONFIG_PROTECTED_MODE
extern void pm_exit_robust_list(struct task_struct *curr);
extern void protected_switch_to_user_func(long r0, long r1,
		start_fn start_func, e2k_size_t us_size, int cui);
#endif

static inline void native_flush_stacks(void)
{
	NATIVE_FLUSHCPU;
}
static inline void native_flush_regs_stack(void)
{
	NATIVE_FLUSHR;
}
static inline void native_flush_chain_stack(void)
{
	NATIVE_FLUSHC;
}
#define	NATIVE_COPY_STACKS_TO_MEMORY() \
({ \
	NATIVE_FLUSHCPU; \
})

/*
 * Native threads can be scheduled and migrate to other CPUs,
 * but never can change task and thread info structures.
 * Host threads on which are implemented guest VCPUs cannot change
 * task and thread info structures too. But these threads are multithreaded,
 * it means there are many guest kernel and user processes which are runing
 * under that host thread. Each guest process has own stacks, context and
 * switch from one guest process to other causes switching of context and
 * stacks, including host kernel stacks allocated for every such process and
 * used to its run. Guest process stacks and other context is kept into
 * structure guest thread info. Guest process switching means change of
 * guest thread info, but host thread info and task structure stays the same.
 * However there is complexity because of guest processes migration from one
 * VCPU to other. In this case some local variables into dinamic chain of
 * host functions calls (local and procedure registers stacks) can keep values
 * of old host VCPU thread.
 * For example, guest process was trapped on VCPU #0 and after trap handling
 * completion megrated to VCPU #1. Trap on VCPU #0 can set some variables to
 * pointers to current and current_thread_info() structures:
 *	VCPU #0	ti = current_thread_info();
 *		task = current;
 * Further host trap handler start guest trap handler:
 *	VCPU #0	user_trap_handler()
 *			kvm_start_guest_trap_handler()
 *				kvm_trap_handler()
 *					schedule()
 *						......
 *						switch_to()	VCPU #1
 *	VCPU #1	is other host thread and has own current & current_thread_info
 *		other than on VCPU #0
 *					schedule()
 *				kvm_trap_handler()
 *			kvm_start_guest_trap_handler()
 *		user_trap_handler()
 * In this place variables ti and task contain pointers to old structures,
 * point to task & thread info structures of VCPU #0, so should be updated to
 * point to new structures of VCPU #1.
 * Good style is using only direct current & current_thread_info() macroses,
 * but there are some derived values: regs, vcpu, gti ... and them should be
 * updated too.
 * Follow macroses to help to solve this problem
 */
/* native kernel does not support virtualization and cannot be run as host */
/* so has not the problem - nothing to do */
#define	NATIVE_UPDATE_VCPU_THREAD_CONTEXT(task, ti, regs, gti, vcpu)
#define	NATIVE_CHECK_VCPU_THREAD_CONTEXT(__ti)

static inline int __is_privileged_range(struct vm_area_struct *vma,
		e2k_addr_t start, e2k_addr_t end)
{
	while (vma && vma->vm_start < end) {
		if (vma->vm_flags & VM_PRIVILEGED)
			return 1;
		vma = vma->vm_next;
	}

	return 0;
}

static inline int is_privileged_range(e2k_addr_t start, e2k_addr_t end)
{
	return start >= USER_HW_STACKS_BASE || end >= USER_HW_STACKS_BASE;
}

extern	int do_update_vm_area_flags(e2k_addr_t start, e2k_size_t len,
		vm_flags_t flags_to_set, vm_flags_t flags_to_clear);
extern	int create_cut_entry(int tcount,
			      unsigned long code_base, unsigned  code_sz,
			      unsigned long glob_base, unsigned  glob_sz);
extern  int free_cut_entry(unsigned long glob_base, size_t glob_sz,
				unsigned long *code_base, size_t *code_sz);
extern	void  fill_cut_entry(e2k_cute_t *cute_p,
		unsigned long code_base, unsigned  code_sz,
		unsigned long glob_base, unsigned  glob_sz);

extern int alloc_user_hw_stacks(hw_stack_t *hw_stacks, size_t p_size, size_t pc_size);
extern void free_user_hw_stacks(hw_stack_t *hw_stacks);
extern void free_user_old_pc_stack_areas(struct list_head *old_u_pcs_list);
extern int free_user_hardware_stacks(hw_stack_t *u_hw_stacks);

#define	ATOMIC_GET_HW_STACK_INDEXES(ps_ind, pcs_ind)			\
({									\
	unsigned long	psp_hi_val;					\
	unsigned long	pshtp_val;					\
	unsigned long	pcsp_hi_val;					\
	unsigned int	pcshtp_val;					\
	e2k_psp_hi_t	psp_hi;						\
	e2k_pcsp_hi_t	pcsp_hi;					\
	e2k_pshtp_t	pshtp;						\
									\
	ATOMIC_READ_HW_STACKS_SIZES(psp_hi_val, pshtp_val,		\
					pcsp_hi_val, pcshtp_val);	\
	psp_hi.PSP_hi_half = psp_hi_val;				\
	pcsp_hi.PCSP_hi_half = pcsp_hi_val;				\
	pshtp.PSHTP_reg = pshtp_val;					\
	ps_ind = psp_hi.PSP_hi_ind + GET_PSHTP_MEM_INDEX(pshtp);	\
	pcs_ind = pcsp_hi.PCSP_hi_ind + PCSHTP_SIGN_EXTEND(pcshtp_val);	\
})

#define	ATOMIC_GET_HW_STACKS_IND_AND_TOP(ps_ind, pshtop, pcs_ind, pcshtop) \
({									\
	unsigned long	psp_hi_val;					\
	unsigned long	pshtp_val;					\
	unsigned long	pcsp_hi_val;					\
	e2k_psp_hi_t	psp_hi;						\
	e2k_pcsp_hi_t	pcsp_hi;					\
	e2k_pshtp_t	pshtp;						\
									\
	ATOMIC_READ_HW_STACKS_SIZES(psp_hi_val, pshtp_val,		\
					pcsp_hi_val, pcshtop);		\
	psp_hi.PSP_hi_half = psp_hi_val;				\
	pcsp_hi.PCSP_hi_half = pcsp_hi_val;				\
	pshtp.PSHTP_reg = pshtp_val;					\
	ps_ind = psp_hi.PSP_hi_ind;					\
	pshtop = GET_PSHTP_MEM_INDEX(pshtp);				\
	pcs_ind = pcsp_hi.PCSP_hi_ind;					\
})

#define	ATOMIC_GET_HW_PS_SIZES(ps_ind, ps_size)				\
({									\
	unsigned long	psp_hi_val;					\
	unsigned long	pshtp_val;					\
	e2k_psp_hi_t	psp_hi;						\
	e2k_pshtp_t	pshtp;						\
									\
	ATOMIC_READ_HW_PS_SIZES(psp_hi_val, pshtp_val);			\
	psp_hi.PSP_hi_half = psp_hi_val;				\
	pshtp.PSHTP_reg = pshtp_val;					\
	ps_size = psp_hi.PSP_hi_size;					\
	ps_ind = psp_hi.PSP_hi_ind + GET_PSHTP_MEM_INDEX(pshtp);	\
})

#define	ATOMIC_GET_HW_PS_SIZES_AND_BASE(ps_ind, ps_size, ps_base)	\
({									\
	unsigned long	psp_hi_val;					\
	unsigned long	psp_lo_val;					\
	unsigned long	pshtp_val;					\
	e2k_psp_hi_t	psp_hi;						\
	e2k_psp_lo_t	psp_lo;						\
	e2k_pshtp_t	pshtp;						\
									\
	ATOMIC_READ_P_STACK_REGS(psp_lo_val, psp_hi_val, pshtp_val);	\
	psp_hi.PSP_hi_half = psp_hi_val;				\
	psp_lo.PSP_lo_half = psp_lo_val;				\
	pshtp.PSHTP_reg = pshtp_val;					\
	ps_size = psp_hi.PSP_hi_size;					\
	ps_ind = psp_hi.PSP_hi_ind + GET_PSHTP_MEM_INDEX(pshtp);	\
	ps_base = psp_lo.PSP_lo_base;					\
})

#define	ATOMIC_GET_HW_PS_SIZES_BASE_TOP(ps_ind, ps_size, ps_base, pshtop) \
({									\
	unsigned long	psp_hi_val;					\
	unsigned long	psp_lo_val;					\
	unsigned long	pshtp_val;					\
	e2k_psp_hi_t	psp_hi;						\
	e2k_psp_lo_t	psp_lo;						\
	e2k_pshtp_t	pshtp;						\
									\
	ATOMIC_READ_P_STACK_REGS(psp_lo_val, psp_hi_val, pshtp_val);	\
	psp_hi.PSP_hi_half = psp_hi_val;				\
	psp_lo.PSP_lo_half = psp_lo_val;				\
	pshtp.PSHTP_reg = pshtp_val;					\
	ps_size = psp_hi.PSP_hi_size;					\
	ps_ind = psp_hi.PSP_hi_ind;					\
	pshtop = GET_PSHTP_MEM_INDEX(pshtp);				\
	ps_base = psp_lo.PSP_lo_base;					\
})

#define	ATOMIC_GET_HW_PCS_SIZES(pcs_ind, pcs_size)			\
({									\
	unsigned long	pcsp_hi_val;					\
	unsigned int	pcshtp_val;					\
	e2k_pcsp_hi_t	pcsp_hi;					\
									\
	ATOMIC_READ_HW_PCS_SIZES(pcsp_hi_val, pcshtp_val);		\
	pcsp_hi.PCSP_hi_half = pcsp_hi_val;				\
	pcs_size = pcsp_hi.PCSP_hi_size;				\
	pcs_ind = pcsp_hi.PCSP_hi_ind + PCSHTP_SIGN_EXTEND(pcshtp_val);	\
})

#define	ATOMIC_GET_HW_PCS_SIZES_AND_BASE(pcs_ind, pcs_size, pcs_base)	\
({									\
	unsigned long	pcsp_hi_val;					\
	unsigned long	pcsp_lo_val;					\
	unsigned int	pcshtp_val;					\
	e2k_pcsp_hi_t	pcsp_hi;					\
	e2k_pcsp_lo_t	pcsp_lo;					\
									\
	ATOMIC_READ_PC_STACK_REGS(pcsp_lo_val, pcsp_hi_val, pcshtp_val); \
	pcsp_hi.PCSP_hi_half = pcsp_hi_val;				\
	pcsp_lo.PCSP_lo_half = pcsp_lo_val;				\
	pcs_size = pcsp_hi.PCSP_hi_size;				\
	pcs_ind = pcsp_hi.PCSP_hi_ind + PCSHTP_SIGN_EXTEND(pcshtp_val);	\
	pcs_base = pcsp_lo.PCSP_lo_base;				\
})

#define	ATOMIC_GET_HW_PCS_SIZES_BASE_TOP(pcs_ind, pcs_size, pcs_base, pcshtp) \
({									\
	unsigned long	pcsp_hi_val;					\
	unsigned long	pcsp_lo_val;					\
	e2k_pcsp_hi_t	pcsp_hi;					\
	e2k_pcsp_lo_t	pcsp_lo;					\
	e2k_pcshtp_t	pcshtp_val;					\
									\
	ATOMIC_READ_PC_STACK_REGS(pcsp_lo_val, pcsp_hi_val, pcshtp_val); \
	pcsp_hi.PCSP_hi_half = pcsp_hi_val;				\
	pcsp_lo.PCSP_lo_half = pcsp_lo_val;				\
	pcs_size = pcsp_hi.PCSP_hi_size;				\
	pcs_ind = pcsp_hi.PCSP_hi_ind;					\
	pcs_base = pcsp_lo.PCSP_lo_base;				\
	pcshtp = PCSHTP_SIGN_EXTEND(pcshtp_val);			\
})

#define	ATOMIC_GET_HW_PCS_IND_AND_BASE(pcs_ind, pcs_base)		\
({									\
	unsigned long	pcsp_hi_val;					\
	unsigned long	pcsp_lo_val;					\
	unsigned int	pcshtp_val;					\
	e2k_pcsp_hi_t	pcsp_hi;					\
	e2k_pcsp_lo_t	pcsp_lo;					\
									\
	ATOMIC_READ_PC_STACK_REGS(pcsp_lo_val, pcsp_hi_val, pcshtp_val); \
	pcsp_hi.PCSP_hi_half = pcsp_hi_val;				\
	pcsp_lo.PCSP_lo_half = pcsp_lo_val;				\
	pcs_ind = pcsp_hi.PCSP_hi_ind + PCSHTP_SIGN_EXTEND(pcshtp_val);	\
	pcs_base = pcsp_lo.PCSP_lo_base;				\
})

#define	ATOMIC_GET_HW_STACKS_SIZES_AND_BASE(ps_ind, ps_size, ps_base,	\
					pcs_ind, pcs_size, pcs_base)	\
({									\
	unsigned long	psp_hi_val;					\
	unsigned long	psp_lo_val;					\
	unsigned long	pshtp_val;					\
	unsigned long	pcsp_hi_val;					\
	unsigned long	pcsp_lo_val;					\
	unsigned int	pcshtp;						\
	e2k_pshtp_t	pshtp;						\
	e2k_psp_hi_t	psp_hi;						\
	e2k_psp_lo_t	psp_lo;						\
	e2k_pcsp_hi_t	pcsp_hi;					\
	e2k_pcsp_lo_t	pcsp_lo;					\
									\
	ATOMIC_READ_HW_STACKS_REGS(psp_lo, psp_hi, pshtp_val,		\
					pcsp_lo, pcsp_hi, pcshtp);	\
	psp_hi.PSP_hi_half = psp_hi_val;				\
	psp_lo.PSP_lo_half = psp_lo_val;				\
	pshtp.PSHTP_reg = pshtp_val;					\
	ps_size = psp_hi.PSP_hi_size;					\
	ps_ind = psp_hi.PSP_hi_ind + GET_PSHTP_MEM_INDEX(pshtp);	\
	ps_base = psp_lo.PSP_lo_base;					\
	pcsp_hi.PCSP_hi_half = pcsp_hi_val;				\
	pcsp_lo.PCSP_lo_half = pcsp_lo_val;				\
	pcs_size = pcsp_hi.PCSP_hi_size;				\
	pcs_ind = pcsp_hi.PCSP_hi_ind + PCSHTP_SIGN_EXTEND(pcshtp_val);	\
	pcs_base = pcsp_lo.PCSP_lo_base;				\
})

#define	ATOMIC_GET_HW_STACKS_IND_AND_BASE(ps_ind, ps_base,		\
						pcs_ind, pcs_base)	\
({									\
	unsigned long	psp_hi_val;					\
	unsigned long	psp_lo_val;					\
	unsigned long	pshtp_val;					\
	unsigned long	pcsp_hi_val;					\
	unsigned long	pcsp_lo_val;					\
	unsigned int	pcshtp;						\
	e2k_pshtp_t	pshtp;						\
	e2k_psp_hi_t	psp_hi;						\
	e2k_psp_lo_t	psp_lo;						\
	e2k_pcsp_hi_t	pcsp_hi;					\
	e2k_pcsp_lo_t	pcsp_lo;					\
									\
	ATOMIC_READ_HW_STACKS_REGS(psp_lo_val, psp_hi_val, pshtp_val,	\
				pcsp_lo_val, pcsp_hi_val, pcshtp);	\
	psp_hi.PSP_hi_half = psp_hi_val;				\
	psp_lo.PSP_lo_half = psp_lo_val;				\
	pshtp.PSHTP_reg = pshtp_val;					\
	ps_ind = psp_hi.PSP_hi_ind + GET_PSHTP_MEM_INDEX(pshtp);	\
	ps_base = psp_lo.PSP_lo_base;					\
	pcsp_hi.PCSP_hi_half = pcsp_hi_val;				\
	pcsp_lo.PCSP_lo_half = pcsp_lo_val;				\
	pcs_ind = pcsp_hi.PCSP_hi_ind + PCSHTP_SIGN_EXTEND(pcshtp);	\
	pcs_base = pcsp_lo.PCSP_lo_base;				\
})

#define	ATOMIC_GET_HW_STACK_SIZES(ps_ind, ps_size, pcs_ind, pcs_size)	\
({									\
	unsigned long	psp_hi_val;					\
	unsigned long	pshtp_val;					\
	unsigned long	pcsp_hi_val;					\
	unsigned int	pcshtp_val;					\
	e2k_psp_hi_t	psp_hi;						\
	e2k_pcsp_hi_t	pcsp_hi;					\
	e2k_pshtp_t	pshtp;						\
									\
	ATOMIC_READ_HW_STACKS_SIZES(psp_hi_val, pshtp_val,		\
					pcsp_hi_val, pcshtp_val);	\
	psp_hi.PSP_hi_half = psp_hi_val;				\
	pcsp_hi.PCSP_hi_half = pcsp_hi_val;				\
	pshtp.PSHTP_reg = pshtp_val;					\
	ps_size = psp_hi.PSP_hi_size;					\
	pcs_size = pcsp_hi.PCSP_hi_size;				\
	ps_ind = psp_hi.PSP_hi_ind + GET_PSHTP_MEM_INDEX(pshtp);	\
	pcs_ind = pcsp_hi.PCSP_hi_ind + PCSHTP_SIGN_EXTEND(pcshtp_val);	\
})
#define	ATOMIC_GET_HW_HWS_SIZES(hws_ind, hws_size, is_pcs)		\
({									\
	if (is_pcs) {							\
		ATOMIC_GET_HW_PCS_SIZES(hws_ind, hws_size);		\
	} else {							\
		ATOMIC_GET_HW_PS_SIZES(hws_ind, hws_size);		\
	}								\
})

#define	ATOMIC_DO_SAVE_HW_STACKS_REGS(st_regs)				\
({									\
	unsigned long psp_lo;						\
	unsigned long psp_hi;						\
	unsigned long pshtp_val;					\
	unsigned long pcsp_lo;						\
	unsigned long pcsp_hi;						\
	unsigned int  pcshtp;						\
	e2k_pshtp_t pshtp;						\
									\
	ATOMIC_READ_HW_STACKS_REGS(psp_lo, psp_hi, pshtp_val,		\
					pcsp_lo, pcsp_hi, pcshtp);	\
	(st_regs)->psp_hi.PSP_hi_half = psp_hi;				\
	(st_regs)->psp_lo.PSP_lo_half = psp_lo;				\
	pshtp.PSHTP_reg = pshtp_val;					\
	(st_regs)->psp_hi.PSP_hi_ind += GET_PSHTP_MEM_INDEX(pshtp);	\
	(st_regs)->pcsp_hi.PCSP_hi_half = pcsp_hi;			\
	(st_regs)->pcsp_lo.PCSP_lo_half = pcsp_lo;			\
	(st_regs)->pcsp_hi.PCSP_hi_ind += PCSHTP_SIGN_EXTEND(pcshtp);	\
})

static inline void
atomic_save_hw_stacks_regs(e2k_stacks_t *stacks)
{
	ATOMIC_DO_SAVE_HW_STACKS_REGS(stacks);
}

#define ATOMIC_DO_SAVE_ALL_STACKS_REGS(st_regs, cr1_hi_p, usd_lo, usd_hi) \
({									\
	unsigned long psp_lo;						\
	unsigned long psp_hi;						\
	unsigned long pshtp_val;					\
	unsigned long pcsp_lo;						\
	unsigned long pcsp_hi;						\
	unsigned int  pcshtp;						\
	unsigned long cr1_hi_val; /* cotains ussz field for data stack */ \
	e2k_pshtp_t pshtp;						\
	e2k_cr1_hi_t cr1_hi;						\
									\
	ATOMIC_READ_ALL_STACKS_REGS(psp_lo, psp_hi, pshtp_val,		\
					pcsp_lo, pcsp_hi, pcshtp,	\
					(usd_lo), (usd_hi), cr1_hi_val); \
	(st_regs)->psp_hi.PSP_hi_half = psp_hi;				\
	(st_regs)->psp_lo.PSP_lo_half = psp_lo;				\
	pshtp.PSHTP_reg = pshtp_val;					\
	(st_regs)->psp_hi.PSP_hi_ind += GET_PSHTP_MEM_INDEX(pshtp);	\
	(st_regs)->pcsp_hi.PCSP_hi_half = pcsp_hi;			\
	(st_regs)->pcsp_lo.PCSP_lo_half = pcsp_lo;			\
	(st_regs)->pcsp_hi.PCSP_hi_ind += PCSHTP_SIGN_EXTEND(pcshtp);	\
	cr1_hi.CR1_hi_half = cr1_hi_val;				\
	*(cr1_hi_p) = cr1_hi;						\
})
#define ATOMIC_SAVE_ALL_STACKS_REGS(st_regs, cr1_hi_p)			\
({									\
	unsigned long usd_lo;						\
	unsigned long usd_hi;						\
									\
	ATOMIC_DO_SAVE_ALL_STACKS_REGS(st_regs, cr1_hi_p,		\
						usd_lo, usd_hi);	\
	(st_regs)->usd_hi.USD_hi_half = usd_hi;				\
	(st_regs)->usd_lo.USD_lo_half = usd_lo;				\
})

static inline void
atomic_save_all_stacks_regs(e2k_stacks_t *stacks, e2k_cr1_hi_t *cr1_hi_p)
{
	ATOMIC_SAVE_ALL_STACKS_REGS(stacks, cr1_hi_p);
}

#define user_stack_cannot_be_expanded()	test_thread_flag(TIF_USD_NOT_EXPANDED)

#define set_user_stack_cannot_be_expanded()				      \
({									      \
				if (TASK_IS_PROTECTED(current)) {	      \
					set_thread_flag(TIF_USD_NOT_EXPANDED);\
				}					      \
})

typedef enum restore_caller {
	FROM_SYSCALL_N_PROT = 1 << 1,
	FROM_SYSCALL_PROT_8 = 1 << 2,
	FROM_SYSCALL_PROT_10 = 1 << 3,
	FROM_USER_TRAP = 1 << 4,
	FROM_SIGRETURN = 1 << 5,
	FROM_RET_FROM_FORK = 1 << 6,
	FROM_MAKECONTEXT = 1 << 7,
	FROM_RETURN_PV_VCPU_TRAP = 1 << 8,
	FROM_PV_VCPU_SYSCALL = 1 << 10,
	FROM_PV_VCPU_SYSFORK = 1 << 11,
} restore_caller_t;

#define	FROM_PV_VCPU_MODE	(FROM_RETURN_PV_VCPU_TRAP | \
					FROM_PV_VCPU_SYSCALL | \
						FROM_PV_VCPU_SYSFORK)

#ifndef	CONFIG_VIRTUALIZATION
/* it native kernel without virtualization support */

/*
 * Is the CPU at guest Hardware Virtualized mode
 * CORE_MODE.gmi is true only at guest HV mode
 */
static inline bool host_is_at_HV_GM_mode(void)
{
	/* native kernel does not support VMs and cannot be at guest mode */
	return false;
}
#define	usd_cannot_be_expanded(regs)	user_stack_cannot_be_expanded()
						/* all user stacks can be */
						/* expanded if it possible */
#define	clear_vm_thread_flags()		/* virtual machines is not supported */
					/* nothing to clear */

#define	GET_PARAVIRT_GUEST_MODE(pv_guest, regs)	/* nothing to do */

#define	UPDATE_VCPU_THREAD_CONTEXT(__task, __ti, __regs, __gti, __vcpu)	\
		NATIVE_UPDATE_VCPU_THREAD_CONTEXT(__task, __ti, __regs, \
							__gti, __vcpu)
#define	CHECK_VCPU_THREAD_CONTEXT(__ti)	\
		NATIVE_CHECK_VCPU_THREAD_CONTEXT(__ti)

static inline void
clear_virt_thread_struct(thread_info_t *thread_info)
{
	/* virtual machines is not supported */
}

static __always_inline void
host_exit_to_usermode_loop(struct pt_regs *regs, bool syscall, bool has_signal)
{
	/* native & guest kernels cannot be as host */
}

static __always_inline __interrupt void
complete_switch_to_user_func(void)
{
	/* virtualization not supported, so nothing to do */
	/* but the function should switch interrupt control from UPSR to */
	/* PSR and set initial state of user UPSR */
	NATIVE_SET_USER_INITIAL_UPSR(E2K_USER_INITIAL_UPSR);
}
static __always_inline __interrupt void
complete_go2user(thread_info_t *ti, long fn)
{
	/* virtualization not supported, so nothing to do */
	/* but the function should restore user UPSR state */
	NATIVE_WRITE_UPSR_REG(ti->upsr);
}
static inline void free_virt_task_struct(struct task_struct *task)
{
	/* virtual machines is not supported */
}
#else	/* CONFIG_VIRTUALIZATION */
/* It is native host kernel with virtualization support */
/* or paravirtualized host and guest */
/* or native guest kernel
 #include <asm/kvm/process.h>
 */
#endif	/* ! CONFIG_VIRTUALIZATION */

/*
 * Restore proper psize field of WD register
 */
static inline void
native_restore_wd_register_psize(e2k_wd_t wd_from)
{
	e2k_wd_t wd;

	raw_all_irq_disable();
	wd = NATIVE_READ_WD_REG();
	wd.psize = wd_from.WD_psize;
	NATIVE_WRITE_WD_REG(wd);
	raw_all_irq_enable();
}

/*
 * Preserve current p[c]shtp as they indicate how much to FILL when returning
 */
static inline void
native_preserve_user_hw_stacks_to_copy(e2k_stacks_t *u_stacks,
					e2k_stacks_t *cur_stacks)
{
	u_stacks->pshtp = cur_stacks->pshtp;
	u_stacks->pcshtp = cur_stacks->pcshtp;
}

static __always_inline void
native_kernel_hw_stack_frames_copy(u64 *dst, const u64 *src, unsigned long size)
{
	void *dst_tail;
	const void *src_tail;
	u64 copied;
	int i;

	/*
	 * Kernel does not use FP registers so do not copy them.
	 * This only applies to CPUs before V5 instruction set
	 * (since V5 FP registers become general-purpose QP registers).
	 */
	if (cpu_has(CPU_FEAT_QPREG)) {
#pragma loop count (10)
		for (i = 0; i < size / 64; i++)
			E2K_TAGGED_MEMMOVE_64(&dst[8 * i], &src[8 * i]);

		copied = round_down(size, 64);
		dst_tail = (void *) dst + copied;
		src_tail = (void *) src + copied;
	} else {
#pragma loop count (5)
		for (i = 0; i < size / 128; i++)
			E2K_TAGGED_MEMMOVE_128_RF_V2(&dst[16 * i],
					&src[16 * i]);

		copied = round_down(size, 128);
		dst_tail = (void *) dst + copied;
		src_tail = (void *) src + copied;

		if (size & 64) {
			E2K_TAGGED_MEMMOVE_64(dst_tail, src_tail);
			dst_tail += 64;
			src_tail += 64;
		}
	}

	if (size & 32)
		E2K_TAGGED_MEMMOVE_32(dst_tail, src_tail);
}

static __always_inline void
native_collapse_kernel_pcs(u64 *dst, const u64 *src, u64 spilled_size)
{
	e2k_pcsp_hi_t k_pcsp_hi;
	u64 size;
	int i;

	DebugUST("current host chain stack index 0x%x, PCSHTP 0x%llx\n",
		NATIVE_NV_READ_PCSP_HI_REG().PCSP_hi_ind,
		NATIVE_READ_PCSHTP_REG_SVALUE());

	NATIVE_FLUSHC;
	k_pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();

	size = k_pcsp_hi.PCSP_hi_ind - spilled_size;
	BUG_ON(!IS_ALIGNED(size, ALIGN_PCSTACK_TOP_SIZE) || (s64) size < 0);
#pragma loop count (2)
	for (i = 0; i < size / 32; i++) {
		u64 v0, v1, v2, v3;

		v0 = src[4 * i];
		v1 = src[4 * i + 1];
		v2 = src[4 * i + 2];
		v3 = src[4 * i + 3];
		dst[4 * i] = v0;
		dst[4 * i + 1] = v1;
		dst[4 * i + 2] = v2;
		dst[4 * i + 3] = v3;
	}

	k_pcsp_hi.PCSP_hi_ind -= spilled_size;
	NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG(k_pcsp_hi);

	DebugUST("move spilled chain part from host top %px to "
		"bottom %px, size 0x%llx\n",
		src, dst, size);
	DebugUST("host kernel chain stack index is now 0x%x, "
		"guest user PCSHTP 0x%llx\n",
		k_pcsp_hi.PCSP_hi_ind, spilled_size);
}

static __always_inline void
native_collapse_kernel_ps(u64 *dst, const u64 *src, u64 spilled_size)
{
	e2k_psp_hi_t k_psp_hi;
	u64 size;

	DebugUST("current host procedure stack index 0x%x, PSHTP 0x%x\n",
		NATIVE_NV_READ_PSP_HI_REG().PSP_hi_ind,
		NATIVE_NV_READ_PSHTP_REG().PSHTP_ind);

	NATIVE_FLUSHR;
	k_psp_hi = NATIVE_NV_READ_PSP_HI_REG();

	size = k_psp_hi.PSP_hi_ind - spilled_size;
	BUG_ON(!IS_ALIGNED(size, ALIGN_PSTACK_TOP_SIZE) || (s64) size < 0);

	prefetchw_range(src, size);
	native_kernel_hw_stack_frames_copy(dst, src, size);

	k_psp_hi.PSP_hi_ind -= spilled_size;
	NATIVE_NV_NOIRQ_WRITE_PSP_HI_REG(k_psp_hi);

	DebugUST("move spilled procedure part from host top %px to "
		"bottom %px, size 0x%llx\n",
		src, dst, size);
	DebugUST("host kernel procedure stack index is now 0x%x, "
		"guest user PSHTP 0x%llx\n",
		k_psp_hi.PSP_hi_ind, spilled_size);
}

/**
 * find_in_u_pcs_list - find frame offset from old_u_pcs_list
 * @frame - frame to search
 * @delta - chain stack offset will be returned here
 *
 * Returns 0 on success.
 */
static inline int __find_in_old_u_pcs_list(unsigned long frame,
		unsigned long *delta, unsigned long pcs_base,
		unsigned long pcs_top, struct list_head *old_u_pcs_list)
{
	struct old_pcs_area *u_pcs;
	int ret = -ESRCH;

	if (frame >= pcs_base && frame < pcs_top) {
		*delta = 0;
		return 0;
	}

	list_for_each_entry(u_pcs, old_u_pcs_list, list_entry) {
		if (frame >= (unsigned long) u_pcs->base &&
				frame < (unsigned long) u_pcs->base +
							u_pcs->size) {
			*delta = pcs_base - (unsigned long) u_pcs->base;
			ret = 0;
			break;
		}
	}

	return ret;
}

static inline int find_in_old_u_pcs_list(unsigned long frame,
					 unsigned long *delta)
{
	unsigned long pcs_base, pcs_top;

	pcs_base = (unsigned long) CURRENT_PCS_BASE();
	pcs_top = pcs_base +
		get_hw_pcs_user_size(&current_thread_info()->u_hw_stack);

	return __find_in_old_u_pcs_list(frame, delta, pcs_base, pcs_top,
			&current_thread_info()->old_u_pcs_list);
}

static inline int __copy_old_u_pcs_list(struct list_head *to,
					const struct list_head *from)
{
	const struct old_pcs_area *u_pcs_from;
	struct old_pcs_area *u_pcs_to;

	list_for_each_entry(u_pcs_from, from, list_entry) {
		u_pcs_to = kmalloc(sizeof(struct old_pcs_area), GFP_KERNEL);
		if (unlikely(!u_pcs_to))
			return -ENOMEM;

		u_pcs_to->base = u_pcs_from->base;
		u_pcs_to->size = u_pcs_from->size;

		list_add_tail(&u_pcs_to->list_entry, to);
	}

	return 0;
}

static inline int copy_old_u_pcs_list(struct thread_info *to,
				      const struct thread_info *from)
{
	return __copy_old_u_pcs_list(&to->old_u_pcs_list, &from->old_u_pcs_list);
}

static	inline int
update_vm_area_flags(e2k_addr_t start, e2k_size_t len,
		vm_flags_t flags_to_set, vm_flags_t flags_to_clear)
{
	int error = 0;

	down_write(&current->mm->mmap_sem);
	len = PAGE_ALIGN(len + (start & ~PAGE_MASK));
	start &= PAGE_MASK;

	error = do_update_vm_area_flags(start, len, flags_to_set,
					flags_to_clear);

	up_write(&current->mm->mmap_sem);
	return error;
}

extern unsigned long *__alloc_thread_stack_node(int node);
extern void __free_thread_stack(void *address);

extern struct task_struct *init_tasks[];

extern e2k_addr_t get_nested_kernel_IP(pt_regs_t *regs, int n);

#if	defined(CONFIG_PARAVIRT_GUEST)
/* paravirtualized kernel (host and guest) */
#include <asm/paravirt/process.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* It is native guest kernel (without paravirtualization) */
#include <asm/kvm/guest/process.h>
#elif	defined(CONFIG_VIRTUALIZATION) || !defined(CONFIG_VIRTUALIZATION)
/* native kernel with virtualization support */
/* native kernel without virtualization support */
#define	E2K_FLUSHCPU		NATIVE_FLUSHCPU
#define	E2K_FLUSHR		NATIVE_FLUSHR
#define	E2K_FLUSHC		NATIVE_FLUSHC
#define	COPY_STACKS_TO_MEMORY()	NATIVE_COPY_STACKS_TO_MEMORY()
#define GOTO_RETURN_TO_PARAVIRT_GUEST(ret_value)
#define	COND_GOTO_RETURN_TO_PARAVIRT_GUEST(cond, ret_value)
#define GOTO_DONE_TO_PARAVIRT_GUEST()
#define COND_GOTO_DONE_TO_PARAVIRT_GUEST(cond)

#define	ONLY_SET_GUEST_GREGS(ti)	NATIVE_ONLY_SET_GUEST_GREGS(ti)

static inline void
restore_wd_register_psize(e2k_wd_t wd_from)
{
	native_restore_wd_register_psize(wd_from);
}

static inline void
preserve_user_hw_stacks_to_copy(e2k_stacks_t *u_stacks,
					e2k_stacks_t *cur_stacks)
{
	native_preserve_user_hw_stacks_to_copy(u_stacks, cur_stacks);
}

static __always_inline void
kernel_hw_stack_frames_copy(u64 *dst, const u64 *src, unsigned long size)
{
	native_kernel_hw_stack_frames_copy(dst, src, size);
}
static __always_inline void
collapse_kernel_pcs(u64 *dst, const u64 *src, u64 spilled_size)
{
	native_collapse_kernel_pcs(dst, src, spilled_size);
}
static __always_inline void
collapse_kernel_ps(u64 *dst, const u64 *src, u64 spilled_size)
{
	native_collapse_kernel_ps(dst, src, spilled_size);
}

#if	!defined(CONFIG_VIRTUALIZATION)
/* native kernel without virtualization support */
#define	do_map_user_hard_stack_to_kernel(node, kstart, ubase, size) \
		do_map_native_user_hard_stack_to_kernel(node, kstart, \
							ubase, size)
#define	resume_vm_thread()	/* none any virtual machines and threads */
#endif	/* ! CONFIG_VIRTUALIZATION */

static inline void
virt_cpu_thread_init(struct task_struct *boot_task)
{
	/* nothing to do */
}

static inline int
copy_kernel_stacks(struct task_struct *new_task,
		unsigned long fn, unsigned long arg)
{
	return native_copy_kernel_stacks(new_task, fn, arg);
}

#define	define_user_hw_stacks_sizes(hw_stacks)				\
		native_define_user_hw_stacks_sizes(hw_stacks)

static __always_inline int
switch_to_new_user(e2k_stacks_t *stacks, hw_stack_t *hw_stacks,
			e2k_addr_t cut_base, e2k_size_t cut_size,
			e2k_addr_t entry_point, int cui,
			unsigned long flags, bool kernel)
{
	return native_switch_to_new_user(stacks, hw_stacks,
			cut_base, cut_size, entry_point, cui, flags, kernel);
}
static inline int clone_prepare_spilled_user_stacks(e2k_stacks_t *child_stacks,
		const e2k_mem_crs_t *child_crs, const struct pt_regs *regs,
		struct sw_regs *new_sw_regs, struct thread_info *new_ti,
		unsigned long clone_flags)
{
	return native_clone_prepare_spilled_user_stacks(child_stacks,
			child_crs, regs, new_sw_regs, new_ti, clone_flags);
}
static inline int
copy_spilled_user_stacks(struct e2k_stacks *child_stacks,
		e2k_mem_crs_t *child_crs, struct sw_regs *new_sw_regs,
		const struct thread_info *new_ti)
{
	native_copy_spilled_user_stacks(child_stacks, child_crs,
					new_sw_regs, new_ti);
	return 0;
}

#else	/* ??? */
 #error "Undefined virtualization mode"
#endif	/* CONFIG_PARAVIRT_GUEST */

/*
 * Copy hardware stack from user to *current* kernel stack.
 * One has to be careful to avoid hardware FILL of this stack.
 */
static inline int __copy_user_to_current_hw_stack(void *dst, void __user *src,
			unsigned long size, const pt_regs_t *regs, bool chain)
{
	unsigned long min_flt, maj_flt, ts_flag;

	if (likely(!host_test_intc_emul_mode(regs))) {
		if (!__range_ok((unsigned long __force) src, size,
				PAGE_OFFSET))
			return -EFAULT;
	}

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);

	/*
	 * Every page fault here has a chance of FILL'ing the frame
	 * that is being copied, in which case we repeat the copy.
	 */
	do {
		min_flt = READ_ONCE(current->min_flt);
		maj_flt = READ_ONCE(current->maj_flt);

		if (chain)
			E2K_FLUSHC;
		else
			E2K_FLUSHR;

		SET_USR_PFAULT("$.recovery_memcpy_fault");
		fast_tagged_memory_copy_from_user(dst, src, size, regs,
				TAGGED_MEM_STORE_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				TAGGED_MEM_LOAD_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				true);
		if (RESTORE_USR_PFAULT) {
			clear_ts_flag(ts_flag);
			return -EFAULT;
		}
	} while (unlikely(min_flt != READ_ONCE(current->min_flt) ||
			  maj_flt != READ_ONCE(current->maj_flt)));

	clear_ts_flag(ts_flag);
	return 0;
}


static inline int copy_user_to_current_hw_stack(void *dst, void __user *src,
			unsigned long size, pt_regs_t *regs, bool chain)
{
	unsigned long flags;
	int ret;

	raw_all_irq_save(flags);
	ret = __copy_user_to_current_hw_stack(dst, src, size, regs, chain);
	raw_all_irq_restore(flags);

	return ret;
}

static inline int copy_e2k_stack_from_user(void *dst, void __user *src,
					unsigned long size, pt_regs_t *regs)
{
	unsigned long ts_flag;
	int ret;

	if (likely(!host_test_intc_emul_mode(regs))) {
		if (!__range_ok((unsigned long __force) src, size, PAGE_OFFSET))
			return -EFAULT;
	}

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = host_copy_from_user_with_tags(dst, src, size, regs);
	clear_ts_flag(ts_flag);

	return (ret) ? -EFAULT : 0;
}

static inline int copy_e2k_stack_to_user(void __user *dst, void *src,
					 unsigned long size, pt_regs_t *regs)
{
	unsigned long ts_flag;
	int ret;

	if (likely(!host_test_intc_emul_mode(regs))) {
		if (!__range_ok((unsigned long __force) dst, size, PAGE_OFFSET))
			return -EFAULT;
	}

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = host_copy_to_user_with_tags(dst, src, size, regs);
	clear_ts_flag(ts_flag);

	return (ret) ? -EFAULT : 0;
}

DECLARE_PER_CPU(void *, reserve_hw_stacks);
static inline int on_reserve_stacks(void)
{
	e2k_pcsp_lo_t pcsp_lo;
	unsigned long res_base;

	WARN_ON_ONCE(!psr_and_upsr_irqs_disabled());

	pcsp_lo = READ_PCSP_LO_REG();
	res_base = (unsigned long) raw_cpu_read(reserve_hw_stacks);

	return AS(pcsp_lo).base >= res_base + KERNEL_PC_STACK_OFFSET &&
	       AS(pcsp_lo).base < res_base + KERNEL_PC_STACK_OFFSET +
					     KERNEL_PC_STACK_SIZE;
}

static __always_inline int
user_hw_stack_frames_copy(void __user *dst, void *src, unsigned long copy_size,
		const pt_regs_t *regs, unsigned long hw_stack_ind, bool is_pcsp)
{
	unsigned long ts_flag;

	if (unlikely(hw_stack_ind < copy_size)) {
		unsigned long flags;
		raw_all_irq_save(flags);
		if (is_pcsp) {
			E2K_FLUSHC;
		} else {
			E2K_FLUSHR;
		}
		raw_all_irq_restore(flags);
	}

	SET_USR_PFAULT("$.recovery_memcpy_fault");

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	fast_tagged_memory_copy_to_user(dst, src, copy_size, regs,
			TAGGED_MEM_STORE_REC_OPC |
			MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
			TAGGED_MEM_LOAD_REC_OPC |
			MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT, true);
	clear_ts_flag(ts_flag);

	if (RESTORE_USR_PFAULT) {
		pr_err("process %s (%d) %s stack could not be copied "
			"from %px to %px size 0x%lx (out of memory?)\n",
			current->comm, current->pid,
			(is_pcsp) ? "chain" : "procedure",
			src, dst, copy_size);
		return -EFAULT;
	}
	DebugUST("copying guest %s stack spilled to host from %px "
		"to guest kernel stack from %px, size 0x%lx\n",
		(is_pcsp) ? "chain" : "procedure", src, dst, copy_size);

	return 0;
}

static __always_inline int
user_crs_frames_copy(e2k_mem_crs_t __user *u_frame, pt_regs_t *regs,
			e2k_mem_crs_t *crs)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = host_copy_to_user(u_frame, crs, sizeof(*crs), regs);
	clear_ts_flag(ts_flag);
	if (unlikely(ret))
		return -EFAULT;

	return 0;
}

static __always_inline u64 get_wsz(enum restore_caller from)
{
	return NATIVE_READ_WD_REG().size >> 4;
}

static __always_inline int user_psp_stack_copy(e2k_psp_lo_t u_psp_lo,
		e2k_psp_hi_t u_psp_hi, s64 u_pshtp_size,
		e2k_psp_lo_t k_psp_lo, e2k_psp_hi_t k_psp_hi,
		unsigned long copy_size, const pt_regs_t *regs)
{
	void __user *dst;
	void *src;

	dst = (void __user *) (AS(u_psp_lo).base + AS(u_psp_hi).ind -
					u_pshtp_size);
	src = (void *) AS(k_psp_lo).base;

	return user_hw_stack_frames_copy(dst, src, copy_size,
				regs, k_psp_hi.PSP_hi_ind, false);
}

static __always_inline int user_pcsp_stack_copy(e2k_pcsp_lo_t u_pcsp_lo,
		e2k_pcsp_hi_t u_pcsp_hi, s64 u_pcshtp_size,
		e2k_pcsp_lo_t k_pcsp_lo, e2k_pcsp_hi_t k_pcsp_hi,
		unsigned long copy_size, const pt_regs_t *regs)
{
	void __user *dst;
	void *src;

	dst = (void __user *)(AS(u_pcsp_lo).base + AS(u_pcsp_hi).ind -
					u_pcshtp_size);
	src = (void *) AS(k_pcsp_lo).base;

	return user_hw_stack_frames_copy(dst, src, copy_size,
				regs, k_pcsp_hi.PCSP_hi_ind, true);
}

static __always_inline u64 get_ps_clear_size(u64 cur_window_q,
		e2k_pshtp_t pshtp)
{
	s64 u_pshtp_size_q;

	u_pshtp_size_q = GET_PSHTP_Q_INDEX(pshtp);
	if (u_pshtp_size_q > E2K_MAXSR - cur_window_q)
		u_pshtp_size_q = E2K_MAXSR - cur_window_q;

	return E2K_MAXSR - (cur_window_q + u_pshtp_size_q);
}

static __always_inline s64 get_ps_copy_size(u64 cur_window_q, s64 u_pshtp_size)
{
	return u_pshtp_size - (E2K_MAXSR - cur_window_q) * EXT_4_NR_SZ;
}

#ifdef CONFIG_CPU_HAS_FILL_INSTRUCTION
# define E2K_CF_MAX_FILL (E2K_CF_MAX_FILL_FILLC_q * 0x10)
#else
extern int cf_max_fill_return;
# define E2K_CF_MAX_FILL cf_max_fill_return
#endif

static __always_inline s64 get_pcs_copy_size(s64 u_pcshtp_size)
{
	/* Before v6 it was possible to fill no more than 16 registers.
	 * Since E2K_MAXCR_q is much bigger than 16 we can be sure that
	 * there is enough space in CF for the FILL, so there is no
	 * need to take into account space taken by current window. */
	return u_pcshtp_size - E2K_CF_MAX_FILL;
}

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
/* This function is used to fixup ret_stack, so make sure it itself
 * does not rely on correct values in ret_stack by using "notrace". */
notrace
static inline void apply_graph_tracer_delta(unsigned long delta)
{
	int i, last;

	if (likely(!current->ret_stack))
		return;

	last = current->curr_ret_stack;
	for (i = min(last, FTRACE_RETFUNC_DEPTH - 1); i >= 0; i--)
		current->ret_stack[i].fp += delta;
}
#else
static inline void apply_graph_tracer_delta(unsigned long delta)
{
}
#endif

/**
 * user_hw_stacks_copy - copy user hardware stacks that have been
 *			 SPILLed to kernel back to user space
 * @stacks - saved user stack registers
 * @cur_window_q - size of current window in procedure stack,
 *		   needed only if @copy_full is not set
 * @copy_full - set if want to copy _all_ of SPILLed stacks
 *
 * This does not update stacks->pshtp and stacks->pcshtp. Main reason is
 * signals: if a signal arrives after copying then it must see a coherent
 * state where saved stacks->pshtp and stacks->pcshtp values show how much
 * data from user space is spilled to kernel space.
 */
static __always_inline int
native_user_hw_stacks_copy(struct e2k_stacks *stacks,
		pt_regs_t *regs, u64 cur_window_q, bool copy_full)
{
	trap_pt_regs_t *trap = regs->trap;
	e2k_psp_lo_t u_psp_lo = stacks->psp_lo,
		     k_psp_lo = current_thread_info()->k_psp_lo;
	e2k_psp_hi_t u_psp_hi = stacks->psp_hi;
	e2k_pcsp_lo_t u_pcsp_lo = stacks->pcsp_lo,
		      k_pcsp_lo = current_thread_info()->k_pcsp_lo;
	e2k_pcsp_hi_t u_pcsp_hi = stacks->pcsp_hi;
	s64 u_pshtp_size, u_pcshtp_size, ps_copy_size, pcs_copy_size;
	int ret;

	u_pshtp_size = GET_PSHTP_MEM_INDEX(stacks->pshtp);
	u_pcshtp_size = PCSHTP_SIGN_EXTEND(stacks->pcshtp);

	/*
	 * Copy user's part from kernel stacks into user stacks
	 * Update user's stack registers
	 */
	if (copy_full) {
		pcs_copy_size = u_pcshtp_size;
		ps_copy_size = u_pshtp_size;
	} else {
		pcs_copy_size = get_pcs_copy_size(u_pcshtp_size);
		ps_copy_size = get_ps_copy_size(cur_window_q, u_pshtp_size);

		/* Make sure there is enough space in CF for the FILL */
		BUG_ON((E2K_MAXCR_q - 4) * 16 < E2K_CF_MAX_FILL);
	}

	if (likely(pcs_copy_size <= 0 && ps_copy_size <= 0))
			return 0;

	if (unlikely(pcs_copy_size > 0)) {
		e2k_pcsp_hi_t k_pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();

		/* Since not all user data has been SPILL'ed it is possible
		 * that we have already overflown user's hardware stack. */
		if (unlikely(AS(u_pcsp_hi).ind > AS(u_pcsp_hi).size)) {
			ret = handle_chain_stack_bounds(stacks, trap);
			if (unlikely(ret)) {
				pr_warning("process %s (%d) chain stack overflow (out of memory?)\n",
						current->comm, current->pid);
				return ret;
			}

			u_pcsp_lo = stacks->pcsp_lo;
			u_pcsp_hi = stacks->pcsp_hi;
		}

		ret = user_pcsp_stack_copy(u_pcsp_lo, u_pcsp_hi, u_pcshtp_size,
				     k_pcsp_lo, k_pcsp_hi, pcs_copy_size, regs);
		if (ret)
			return ret;
	}

	if (unlikely(ps_copy_size > 0)) {
		e2k_psp_hi_t k_psp_hi = NATIVE_NV_READ_PSP_HI_REG();

		/* Since not all user data has been SPILL'ed it is possible
		 * that we have already overflowed user's hardware stack. */
		if (unlikely(AS(u_psp_hi).ind > AS(u_psp_hi).size)) {
			ret = handle_proc_stack_bounds(stacks, trap);
			if (unlikely(ret)) {
				pr_warning("process %s (%d) procedure stack overflow (out of memory?)\n",
						current->comm, current->pid);
				return ret;
			}

			u_psp_lo = stacks->psp_lo;
			u_psp_hi = stacks->psp_hi;
		}

		ret = user_psp_stack_copy(u_psp_lo, u_psp_hi, u_pshtp_size,
				    k_psp_lo, k_psp_hi, ps_copy_size, regs);
		if (ret)
			return ret;
	}

	return 0;
}

static inline void collapse_kernel_hw_stacks(struct e2k_stacks *stacks)
{
	e2k_pcsp_lo_t k_pcsp_lo = current_thread_info()->k_pcsp_lo;
	e2k_psp_lo_t k_psp_lo = current_thread_info()->k_psp_lo;
	unsigned long flags, spilled_pc_size, spilled_p_size;
	e2k_pshtp_t pshtp = stacks->pshtp;
	u64 *dst;
	const u64 *src;

	spilled_pc_size = PCSHTP_SIGN_EXTEND(stacks->pcshtp);
	spilled_p_size = GET_PSHTP_MEM_INDEX(pshtp);
	DebugUST("guest user spilled to host kernel stack part: chain 0x%lx "
		"procedure 0x%lx\n",
		spilled_pc_size, spilled_p_size);
	/* When user tries to return from the last user frame
	 * we will have pcshtp = pcsp_hi.ind = 0. But situation
	 * with pcsp_hi.ind != 0 and pcshtp = 0 is impossible. */
	if (WARN_ON_ONCE(spilled_pc_size < SZ_OF_CR &&
			 AS(stacks->pcsp_hi).ind != 0))
		do_exit(SIGKILL);

	/* Keep the last user frame (see user_hw_stacks_copy_full()) */
	if (spilled_pc_size >= SZ_OF_CR) {
		spilled_pc_size -= SZ_OF_CR;
		DebugUST("Keep the prev user chain frame, so spilled chain "
			"size is now 0x%lx\n",
			spilled_pc_size);
	}

	raw_all_irq_save(flags);

	if (spilled_pc_size) {
		dst = (u64 *) AS(k_pcsp_lo).base;
		src = (u64 *) (AS(k_pcsp_lo).base + spilled_pc_size);
		collapse_kernel_pcs(dst, src, spilled_pc_size);

		stacks->pcshtp = SZ_OF_CR;

		apply_graph_tracer_delta(-spilled_pc_size);
	}

	if (spilled_p_size) {
		dst = (u64 *) AS(k_psp_lo).base;
		src = (u64 *) (AS(k_psp_lo).base + spilled_p_size);
		collapse_kernel_ps(dst, src, spilled_p_size);

		AS(pshtp).ind = 0;
		stacks->pshtp = pshtp;
	}

	raw_all_irq_restore(flags);
}

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
static __always_inline void native_user_hw_stacks_prepare(
		struct e2k_stacks *stacks, pt_regs_t *regs,
		u64 cur_window_q, enum restore_caller from, int syscall)
{
	e2k_pcshtp_t u_pcshtp = stacks->pcshtp;
	int ret;

	BUG_ON(from & FROM_PV_VCPU_MODE);

	/*
	 * 1) Make sure there is free space in kernel chain stack to return to
	 */
	if (!syscall && u_pcshtp == 0) {
		unsigned long flags;
		e2k_pcsp_lo_t u_pcsp_lo = stacks->pcsp_lo,
			      k_pcsp_lo = current_thread_info()->k_pcsp_lo;
		e2k_pcsp_hi_t u_pcsp_hi = stacks->pcsp_hi, k_pcsp_hi;
		e2k_mem_crs_t __user *u_cframe;
		e2k_mem_crs_t *k_crs;
		u64 u_cbase;
		int ret = -EINVAL;

		raw_all_irq_save(flags);
		E2K_FLUSHC;
		k_pcsp_hi = READ_PCSP_HI_REG();
		BUG_ON(AS(k_pcsp_hi).ind);
		AS(k_pcsp_hi).ind += SZ_OF_CR;
		WRITE_PCSP_HI_REG(k_pcsp_hi);

		k_crs = (e2k_mem_crs_t *) AS(k_pcsp_lo).base;
		u_cframe = (e2k_mem_crs_t __user *) (AS(u_pcsp_lo).base +
						     AS(u_pcsp_hi).ind);
		u_cbase = ((from & FROM_RETURN_PV_VCPU_TRAP) ||
				host_test_intc_emul_mode(regs)) ?
					u_pcsp_lo.PCSP_lo_base :
						(u64) CURRENT_PCS_BASE();
		if ((u64) u_cframe > u_cbase) {
			ret = __copy_user_to_current_hw_stack(k_crs,
				u_cframe - 1, sizeof(*k_crs), regs, true);
		}
		raw_all_irq_restore(flags);

		/* Can happen if application returns until runs out of
		 * chain stack or there is no free memory for stacks.
		 * There is no user stack to return to - die. */
		if (ret) {
			E2K_LMS_HALT_OK;
			SIGDEBUG_PRINT("SIGKILL. %s\n",
				(ret == -EINVAL) ? "tried to return to kernel" :
				       "ran into Out-of-Memory on user stacks");
			force_sig(SIGKILL);
			return;
		}

		if (AS(u_pcsp_hi).ind < SZ_OF_CR) {
			update_pcsp_regs(AS(u_pcsp_lo).base,
					 &u_pcsp_lo, &u_pcsp_hi);
			stacks->pcsp_lo = u_pcsp_lo;
			stacks->pcsp_hi = u_pcsp_hi;
			BUG_ON(AS(u_pcsp_hi).ind < SZ_OF_CR);
		}

		u_pcshtp = SZ_OF_CR;
		stacks->pcshtp = u_pcshtp;
	}

	/*
	 * 2) Copy user data that cannot be FILLed
	 */
	ret = native_user_hw_stacks_copy(stacks, regs, cur_window_q, false);
	if (unlikely(ret))
		do_exit(SIGKILL);
}

#ifndef	CONFIG_VIRTUALIZATION
/* native kernel without virtualization support */
static __always_inline int
user_hw_stacks_copy(struct e2k_stacks *stacks,
		pt_regs_t *regs, u64 cur_window_q, bool copy_full)
{
	return native_user_hw_stacks_copy(stacks, regs, cur_window_q, copy_full);
}

static __always_inline void
host_user_hw_stacks_prepare(struct e2k_stacks *stacks, pt_regs_t *regs,
		u64 cur_window_q, enum restore_caller from, int syscall)
{
	native_user_hw_stacks_prepare(stacks, regs, cur_window_q,
					from, syscall);
}
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* It is native guest kernel (without paravirtualization) */
#include <asm/kvm/guest/process.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* It is paravirtualized kernel (host and guest) */
#include <asm/paravirt/process.h>
#elif	defined(CONFIG_KVM_HOST_MODE)
/* It is host kernel with virtualization support */
#include <asm/kvm/process.h>
#else	/* unknow mode */
#error	"unknown virtualization mode"
#endif	/* !CONFIG_VIRTUALIZATION */

/**
 * user_hw_stacks_copy_full - copy part of user stacks that was SPILLed
 *	into kernel back to user stacks.
 * @stacks - saved user stack registers
 * @regs - pt_regs pointer
 * @crs - last frame to copy
 *
 * If @crs is not NULL then the frame pointed to by it will also be copied
 * to userspace.  Note that 'stacks->pcsp_hi.ind' is _not_ updated after
 * copying since it would leave stack in inconsistent state (with two
 * copies of the same @crs frame), this is left to the caller. *
 *
 * Inlining this reduces the amount of memory to copy in
 * collapse_kernel_hw_stacks().
 */
static inline int user_hw_stacks_copy_full(struct e2k_stacks *stacks,
					pt_regs_t *regs, e2k_mem_crs_t *crs)
{
	int ret;

	/*
	 * Copy part of user stacks that were SPILLed into kernel stacks
	 */
	ret = user_hw_stacks_copy(stacks, regs, 0, true);
	if (unlikely(ret))
		return ret;

	/*
	 * Nothing to FILL so remove the resulting hole from kernel stacks.
	 *
	 * IMPORTANT: there is always at least one user frame at the top of
	 * kernel stack - the one that issued a system call (in case of an
	 * exception we uphold this rule manually, see user_hw_stacks_prepare())
	 * We keep this ABI and _always_ leave space for one user frame,
	 * this way we can later FILL using return trick (otherwise there
	 * would be no space in chain stack for the trick).
	 */
	collapse_kernel_hw_stacks(stacks);

	/*
	 * Copy saved %cr registers
	 *
	 * Caller must take care of filling of resulting hole
	 * (last user frame from pcshtp == SZ_OF_CR).
	 */
	if (crs) {
		e2k_mem_crs_t __user *u_frame;
		int ret;

		u_frame = (void __user *) (AS(stacks->pcsp_lo).base +
					   AS(stacks->pcsp_hi).ind);
		ret = user_crs_frames_copy(u_frame, regs, &regs->crs);
		if (unlikely(ret))
			return ret;
	}

	return 0;
}

extern e2k_addr_t get_nested_kernel_IP(pt_regs_t *regs, int n);
extern unsigned long remap_e2k_stack(unsigned long addr,
		unsigned long old_size, unsigned long new_size, bool after);

extern int find_cui_by_ip(unsigned long ip);
#endif /* _E2K_PROCESS_H */

