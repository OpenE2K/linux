/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
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
#include <asm/e2k_debug.h>
#include <asm/kvm/uaccess.h>	/* host mode support */

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

#define sighandler_trampoline_32	E2K_TRAMPOLINES_START
#define sighandler_trampoline_64	(E2K_TRAMPOLINES_START + 0x100)
#define sighandler_trampoline_128	(E2K_TRAMPOLINES_START + 0x200)
#define makecontext_trampoline_32	(E2K_TRAMPOLINES_START + 0x300)
#define makecontext_trampoline_64	(E2K_TRAMPOLINES_START + 0x400)
#define makecontext_trampoline_128	(E2K_TRAMPOLINES_START + 0x500)

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

struct cached_stacks_entry {
	hw_stack_t stack;
	/* Entry in mm_context_t->cached_stacks */
	struct list_head list_entry;
};

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

#ifdef CONFIG_PROTECTED_MODE
extern void pm_exit_robust_list(struct task_struct *curr);
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
	return start >= USER_ADDR_MAX || end >= USER_ADDR_MAX;
}

extern	int do_update_vm_area_flags(e2k_addr_t start, e2k_size_t len,
		vm_flags_t flags_to_set, vm_flags_t flags_to_clear);

static inline e2k_cute_t __user *native_get_cut_entry_pointer(int cui)
{
	return (e2k_cute_t __user *) USER_CUT_AREA_BASE + cui;
}

static inline void native_put_cut_entry_pointer(struct page *page)
{
	/* nothing to do */
}

extern	int create_cut_entry(int tcount,
			      unsigned long code_base, unsigned  code_sz,
			      unsigned long glob_base, unsigned  glob_sz);
extern  int free_cut_entry(unsigned long glob_base, size_t glob_sz,
				unsigned long *code_base, size_t *code_sz);
extern void fill_kernel_cut_entry(e2k_cute_t *cute_p, bool prot,
		unsigned long code_base, unsigned code_sz,
		unsigned long glob_base, unsigned glob_sz);
extern int __must_check fill_user_cut_entry(e2k_cute_t __user *cute_p, bool prot,
		unsigned long code_base, unsigned code_sz,
		unsigned long glob_base, unsigned glob_sz,
		unsigned long tsd_base, unsigned tsd_sz);
extern int native_clean_pc_stack_zero_frame_kernel(void *addr);
extern int native_clean_pc_stack_zero_frame_user(void __user *addr);

extern int alloc_user_hw_stacks(hw_stack_t *hw_stacks, size_t p_size, size_t pc_size);
extern void free_user_hw_stacks(hw_stack_t *hw_stacks);
extern void free_user_old_pc_stack_areas(struct list_head *old_u_pcs_list);

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
	/* PSR (only for local IRQ mask case) */
	/* and set initial state of user UPSR */
	NATIVE_SET_USER_INITIAL_UPSR();
}
static inline void free_virt_task_struct(struct task_struct *task)
{
	/* virtual machines is not supported */
}
#elif	defined(CONFIG_KVM_HOST_MODE)
/* It is native host kernel with virtualization support */
 #include <asm/kvm/process.h>
#endif	/* ! CONFIG_VIRTUALIZATION */

extern int user_hw_stacks_copy_full(struct e2k_stacks *stacks,
				    pt_regs_t *regs, e2k_mem_crs_t *crs);
extern long flush_hw_stacks_cache(void);
extern int copy_user_second_cframe(const struct pt_regs *regs);
extern long do_sigreturn(void);

static __always_inline int
native_switch_kernel_return_function_to(unsigned long new_function_ip)
{
	e2k_cr0_hi_t cr0_hi = NATIVE_NV_READ_CR0_HI_REG();

	/* probably here should be some validation of the new kernel IP */
	cr0_hi.CR0_hi_IP = new_function_ip;
	NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG(cr0_hi);
	return 0;
}

/*
 * Preserve current p[c]shtp as they indicate how much to FILL when returning
 */
static inline void
preserve_user_hw_stacks_to_copy(e2k_stacks_t *u_stacks, e2k_mem_crs_t *crs)
{
	struct pt_regs *prev_regs = current_pt_regs();
	u64 tind = AS(u_stacks->pshtp).tind;

	/*
	 * Get rid of previous frames before restoring actual frames
	 */
	if (WARN_ON_ONCE(user_hw_stacks_copy_full(&prev_regs->stacks, prev_regs, NULL))) {
		/* User's stack is not available, so just exit */
		do_exit(SIGKILL);
	}

	/*
	 * Update regs.crs with latest version directly from user chain stack
	 * in case signal handler edited return IP with fast_sys_set_return.
	 * Currently there are 2 user frames in memory:
	 *  - (READ_PCSP_REG().base + SZ_OF_CR) frame with sighandler_trampoline;
	 *  - READ_PCSP_REG().base frame with user's ip.
	 */
	*crs = *(e2k_mem_crs_t *) NATIVE_NV_READ_PCSP_REG().base;

	u_stacks->pshtp = prev_regs->stacks.pshtp;
	u_stacks->pcshtp = prev_regs->stacks.pcshtp;

	/*
	 * actual pshtp.tind is used in calculate_recovery_load_to_rf_frame()
	 */
	AS(u_stacks->pshtp).tind = tind;
}

static inline bool native_might_be_sighandler_trampoline(const e2k_mem_crs_t *frame)
{
	u64 ip = frame->cr0_hi.ip << 3;
	return ip == sighandler_trampoline_32 || ip == sighandler_trampoline_64 ||
			ip == sighandler_trampoline_128;
}

/**
 * find_in_u_pcs_list - find frame offset from old_u_pcs_list
 * @frame: frame to search
 * @delta: chain stack offset will be returned here if not NULL
 * @u_hw_stack: current location of hardware stacks
 * @old_u_pcs_list: previous locations of hardware chain stack
 *
 * Return: 0 on success, negative error code otherwise.
 */
static inline int __find_in_old_u_pcs_list(unsigned long frame,
		unsigned long *delta, const struct hw_stack *u_hw_stack,
		const struct list_head *old_u_pcs_list)
{
	unsigned long pcs_base = (unsigned long) u_hw_stack->pcs.base;
	unsigned long pcs_top = pcs_base + u_hw_stack->pcs.size;
	struct old_pcs_area *u_pcs;
	int ret = -ESRCH;

	if (frame >= pcs_base && frame < pcs_top) {
		if (delta)
			*delta = 0;
		return 0;
	}

	list_for_each_entry(u_pcs, old_u_pcs_list, list_entry) {
		if (frame >= (unsigned long) u_pcs->base &&
				frame < (unsigned long) u_pcs->base +
							u_pcs->size) {
			if (delta)
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
	return __find_in_old_u_pcs_list(frame, delta,
			&current_thread_info()->u_hw_stack,
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

	mmap_write_lock(current->mm);
	len = PAGE_ALIGN(len + (start & ~PAGE_MASK));
	start &= PAGE_MASK;

	error = do_update_vm_area_flags(start, len, flags_to_set,
					flags_to_clear);

	mmap_write_unlock(current->mm);
	return error;
}

extern unsigned long *__alloc_thread_stack_node(int node);
extern void __free_thread_stack(void *address);

extern struct task_struct *init_tasks[];

extern e2k_addr_t get_nested_kernel_IP(pt_regs_t *regs, int n);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* It is virtualized guest kernel */
#include <asm/kvm/guest/process.h>
#else
/* native kernel with virtualization support */
/* native kernel without virtualization support */
#define	E2K_FLUSHCPU		NATIVE_FLUSHCPU
#define	E2K_FLUSHR		NATIVE_FLUSHR
#define	E2K_FLUSHC		NATIVE_FLUSHC
#define	COPY_STACKS_TO_MEMORY()	NATIVE_COPY_STACKS_TO_MEMORY()

#define	ONLY_SET_GUEST_GREGS(ti)	NATIVE_ONLY_SET_GUEST_GREGS(ti)

static inline e2k_cute_t __user *get_cut_entry_pointer(int cui, struct page **page)
{
	return native_get_cut_entry_pointer(cui);
}

static __always_inline int
switch_kernel_return_function_to(unsigned long new_function_ip)
{
	return native_switch_kernel_return_function_to(new_function_ip);
}

#define clean_pc_stack_zero_frame_kernel	native_clean_pc_stack_zero_frame_kernel
#define clean_pc_stack_zero_frame_user		native_clean_pc_stack_zero_frame_user
#define put_cut_entry_pointer			native_put_cut_entry_pointer
#define might_be_sighandler_trampoline		native_might_be_sighandler_trampoline
#define copy_kernel_stacks			native_copy_kernel_stacks
#define	define_user_hw_stacks_sizes		native_define_user_hw_stacks_sizes
#define switch_to_new_user			native_switch_to_new_user
#define clone_prepare_spilled_user_stacks	native_clone_prepare_spilled_user_stacks

#if	!defined(CONFIG_VIRTUALIZATION)
/* native kernel without virtualization support */
#define	do_map_user_hard_stack_to_kernel(node, kstart, ubase, size) \
		do_map_native_user_hard_stack_to_kernel(node, kstart, \
							ubase, size)
#define	resume_vm_thread()	/* none any virtual machines and threads */
#endif	/* ! CONFIG_VIRTUALIZATION */

static inline void virt_cpu_thread_init(struct task_struct *boot_task)
{
	/* nothing to do */
}

static inline int copy_spilled_user_stacks(struct e2k_stacks *child_stacks,
		e2k_mem_crs_t *child_crs, struct sw_regs *new_sw_regs,
		const struct thread_info *new_ti)
{
	native_copy_spilled_user_stacks(child_stacks, child_crs,
					new_sw_regs, new_ti);
	return 0;
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

DECLARE_PER_CPU(void *, reserve_hw_stacks);
static inline int on_reserve_stack(void)
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

extern e2k_addr_t get_nested_kernel_IP(pt_regs_t *regs, int n);
extern unsigned long remap_e2k_stack(unsigned long addr,
		unsigned long old_size, unsigned long new_size, bool after);

extern int find_cui_by_ip(unsigned long ip);
#endif /* _E2K_PROCESS_H */

