/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * In-kernel KVM process related definitions
 */

#ifndef __KVM_PROCESS_H
#define __KVM_PROCESS_H

#include <linux/types.h>
#include <linux/kvm.h>

#include <asm/system.h>
#include <asm/trap_table.h>
#include <asm/hw_stacks.h>
#include <asm/regs_state.h>
#include <asm/copy-hw-stacks.h>

#include <asm/kvm/mm.h>
#include <asm/kvm/thread_info.h>
#include <asm/kvm/hypercall.h>
#include <asm/kvm/switch.h>

#include "cpu_defs.h"
#include "irq.h"
#include "mmu.h"
#include "paravirt_sw/gaccess.h"

extern bool debug_guest_user_stacks;
#undef	DEBUG_KVM_GUEST_STACKS_MODE
#undef	DebugGUST
#define	DEBUG_KVM_GUEST_STACKS_MODE	0	/* guest user stacks */
						/* copy debug */
#define	DebugGUST(fmt, args...)						\
({									\
	if (debug_guest_user_stacks)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_GPT_REGS_MODE
#define	DEBUG_GPT_REGS_MODE	0	/* KVM host and guest kernel */
					/* stack activations print */

#ifdef CONFIG_KVM_PARAVIRTUALIZATION

#define	GUEST_KERNEL_THREAD_STACK_SIZE	(64 * 1024U)	/* 64 KBytes */

static inline struct gthread_info *kvm_get_guest_thread_info(struct kvm *kvm, int gpid_nr)
{
	gpid_t *gpid = kvm_find_gpid(&kvm->arch.gpid_table, gpid_nr);
	if (gpid == NULL)
		return NULL;
	return gpid->gthread_info;
}

/*
 * Save and restore current state of host thread which can be changed
 * in the case of long jump throw traps and signals.
 * Host VCPU thread can run any guest thread (multi-thread or multi-stack mode)
 * so store/restore current host state wile switch from one guest thread
 * to other
 */
#define SAVE_HOST_THREAD_STATE(__task, __gti)				\
({									\
	thread_info_t *ti = task_thread_info(__task);			\
	gthread_info_t *gti = (__gti);					\
									\
	gti->pt_regs = ti->pt_regs;					\
})
#define RESTORE_HOST_THREAD_STATE(__task, __gti)			\
({									\
	thread_info_t *ti = task_thread_info(__task);			\
	gthread_info_t *gti = (__gti);					\
									\
	ti->pt_regs = gti->pt_regs;					\
	gti->pt_regs = NULL;						\
})
#define INIT_HOST_THREAD_STATE(new_gti)					\
({									\
	(new_gti)->pt_regs = NULL;					\
})
#define COPY_HOST_THREAD_STATE(cur_gti, new_gti)			\
({									\
	INIT_HOST_THREAD_STATE(new_gti);				\
})

/*
 * Save and restore current state of host thread which can be changed
 * in the case of long jump throw traps and signals.
 * Guest process can cause recursive host kernel activations due to traps,
 * system calls, signal handler running.
 * So it needs save/restore host thread state in each activation of host
 */
#define SAVE_KVM_THREAD_STATE(__ti, __gregs)				\
({									\
	struct pt_regs *regs = (__ti)->pt_regs;				\
									\
	(__gregs)->pt_regs = regs;					\
})
#define RESTORE_KVM_THREAD_STATE(__ti, __gregs)				\
({									\
	struct pt_regs *regs = (__gregs)->pt_regs;			\
									\
	(__ti)->pt_regs = regs;						\
})

#define	IS_GUEST_USER_THREAD(ti)					\
		test_gti_thread_flag((ti)->gthread_info, GTIF_KERNEL_THREAD)

#define	CHECK_BUG(cond, num)						\
({									\
	if (cond) {							\
		E2K_LMS_HALT_OK;					\
		dump_stack();						\
		panic("CHECK_GUEST_KERNEL_DATA_STACK #%d "		\
			"failed\n", num);				\
	}								\
})

#ifdef CONFIG_KVM_GUEST_HW_HCALL
#define	CHECK_GUEST_KERNEL_DATA_STACK(ti, g_sbr, g_usd_size)		\
({									\
	if (!test_ti_status_flag((ti), TS_HOST_AT_VCPU_MODE)) {	\
		/* It is host stack */					\
		CHECK_BUG((g_sbr) != (ti)->u_stack.top, 1);		\
		CHECK_BUG((g_usd_size) > (ti)->u_stack.size, 2);	\
		CHECK_BUG((ti)->u_stack.bottom + (ti)->u_stack.size !=	\
						(ti)->u_stack.top, 3);	\
	} else {							\
		/* It is VCPU stack */					\
		CHECK_BUG((ti)->vcpu->arch.is_hv, 8);			\
	}								\
	if ((ti)->gthread_info == NULL) {				\
		CHECK_BUG(!test_ti_status_flag((ti),			\
				TS_HOST_AT_VCPU_MODE), 4);		\
	} else {							\
		gthread_info_t *gti = (ti)->gthread_info;		\
		e2k_stacks_t *stacks = &gti->stack_regs.stacks;		\
		struct kvm_vcpu *vcpu = (ti)->vcpu;			\
									\
		CHECK_BUG((g_sbr) != stacks->top, 6);			\
		if ((g_sbr) == (ti)->u_stack.top) {			\
			CHECK_BUG(vcpu_usd_base(vcpu, stacks->usd) !=	\
					(ti)->u_stack.bottom, 7);	\
		} else {						\
			CHECK_BUG(vcpu_usd_base(vcpu, stacks->usd) !=	\
					gti->data_stack.bottom, 5);	\
		}							\
	}								\
})
#else /* ! CONFIG_KVM_GUEST_HW_HCALL */
#define	CHECK_GUEST_KERNEL_DATA_STACK(ti, g_sbr, g_usd_size)
#endif /* CONFIG_KVM_GUEST_HW_HCALL */

static inline void
HOST_SAVE_TASK_USER_REGS_TO_SWITCH(struct kvm_vcpu *vcpu,
				   struct sw_regs *sw_regs, bool task_is_binco,
				   bool task_traced)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;

	DO_SAVE_TASK_USER_REGS_TO_SWITCH(sw_regs, task_is_binco, task_traced);
	/* the hardware register was saved by hypercall in vcpu sw context */
	sw_regs->cutd = sw_ctxt->cutd;
}

static inline void
HOST_RESTORE_TASK_USER_REGS_TO_SWITCH(struct kvm_vcpu *vcpu,
				      struct sw_regs *sw_regs,
				      bool task_is_binco, bool task_traced)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;

	DO_RESTORE_TASK_USER_REGS_TO_SWITCH(sw_regs, task_is_binco, task_traced);
	/* the hardware register will be restored by hypercall */
	/* from vcpu software context */
	sw_ctxt->cutd = sw_regs->cutd;
}

#define	SAVE_KVM_HOST_KERNEL_STACKS_STATE(__ti, __gti, __gregs)		\
({									\
	(__gregs)->k_usd_size = USD_IND((__ti)->k_usd);			\
	(__gregs)->k_stk_frame_no = (__gti)->k_stk_frame_no;		\
})
#define	UPDATE_KVM_HOST_KERNEL_STACKS_STATE(__ti, __gti, __usd)		\
({									\
	(__ti)->k_usd = (__usd);					\
	(__gti)->k_stk_frame_no++;					\
})
#define	DO_RESTORE_KVM_HOST_KERNEL_STACKS_STATE(__ti, __gti, __gregs)	\
({									\
	e2k_size_t usd_size = (__gregs)->k_usd_size;			\
									\
	(__ti)->k_usd = new_usd((u64)(thread_info_task(__ti)->stack), usd_size, usd_size);	\
	(__gti)->k_stk_frame_no = (__gregs)->k_stk_frame_no;		\
})
#define	RESTORE_KVM_HOST_KERNEL_STACKS_STATE(__ti)			\
({									\
	gthread_info_t	*gti = (__ti)->gthread_info;			\
	gpt_regs_t	*gregs;						\
									\
	gregs = get_gpt_regs(__ti);					\
	GTI_BUG_ON(gregs == NULL);					\
	DO_RESTORE_KVM_HOST_KERNEL_STACKS_STATE(__ti, gti, gregs);	\
})

#define	UPDATE_KVM_GUEST_KERNEL_STACKS_STATE(__ti, __gti, __usd)	\
({									\
	struct kvm_vcpu *vcpu = (__ti)->vcpu;				\
	e2k_size_t usd_new_size = vcpu_usd_ind(vcpu, (__usd));		\
									\
	/* data stack grows down */					\
	if (usd_new_size > vcpu_usd_ind(vcpu, (__gti)->stack_regs.u_usd)) { \
		gpt_regs_t *gregs;					\
									\
		/* data stack shoulg grow down, bun in some case new */	\
		/* activation can be above last saved state */		\
		/* for example first trap or hypercall after fork() */	\
		pr_debug("%s(): new guest USD size 0x%lx > "		\
			"0x%x current size, base 0x%llx, "		\
			"activation #%d\n",				\
			__func__, usd_new_size,				\
			vcpu_usd_ind(vcpu, (__gti)->stack_regs.u_usd),	\
			vcpu_usd_ptr(vcpu, (__gti))->stack_regs.u_usd),	\
			(__gti)->g_stk_frame_no);			\
		gregs = get_gpt_regs(__ti);				\
		if (gregs != NULL) {					\
			gregs->g_usd_size = usd_new_size;		\
			GTI_BUG_ON(get_next_gpt_regs((__ti), gregs));	\
		}							\
	}								\
	(__gti)->stack_regs.u_usd = (__usd);				\
	(__gti)->g_stk_frame_no++;					\
})
#define	INC_KVM_GUEST_KERNEL_STACKS_STATE(__ti, __gti, usd_new_size)	\
({									\
	struct kvm_vcpu *vcpu = (__ti)->vcpu;				\
									\
	/* data stack grows down */					\
	if ((usd_new_size) >						\
		vcpu_usd_ind(vcpu, (__gti)->stack_regs.stacks.usd)) {	\
		gpt_regs_t *gregs;					\
									\
		/* data stack should grow down, but in some case new */	\
		/* activation can be above last saved state */		\
		/* for example first trap or hypercall after fork() */	\
		pr_debug("%s(): new guest USD size 0x%lx > "		\
			"0x%x current size, base 0x%llx, "		\
			"activation #%d\n",				\
			__func__, (usd_new_size),			\
			vcpu_usd_ind(vcpu, (__gti)->stack_regs.stacks.usd), \
			vcpu_usd_ptr(vcpu, (__gti)->stack_regs.stacks.usd), \
			(__gti)->g_stk_frame_no);			\
		gregs = get_gpt_regs(__ti);				\
		if (gregs != NULL) {					\
			gregs->g_usd_size = (usd_new_size);		\
			GTI_BUG_ON(get_next_gpt_regs((__ti), gregs));	\
		}							\
	}								\
	(__gti)->stack_regs.stacks.usd = vcpu_new_usd(vcpu,		\
			(__gti)->data_stack.bottom, usd_new_size, usd_new_size); \
	(__gti)->g_stk_frame_no++;					\
})
#define	DO_RESTORE_KVM_GUEST_KERNEL_STACKS_STATE(__ti, __gti, __gregs)	\
({									\
	struct kvm_vcpu *vcpu = (__ti)->vcpu;				\
									\
	CHECK_GUEST_KERNEL_DATA_STACK(__ti,				\
		(__gti)->stack_regs.stacks.top, (__gregs)->g_usd_size);	\
	(__gti)->stack_regs.stacks.usd = vcpu_new_usd(vcpu,		\
		(__gti)->data_stack.bottom, (__gregs)->g_usd_size,	\
		(__gregs)->g_usd_size);					\
	(__gti)->g_stk_frame_no = (__gregs)->g_stk_frame_no;		\
})
#define	RESTORE_KVM_GUEST_KERNEL_STACKS_STATE(__ti)			\
({									\
	gthread_info_t	*gti = (__ti)->gthread_info;			\
	gpt_regs_t	*gregs;						\
									\
	gregs = get_gpt_regs(__ti);					\
	GTI_BUG_ON(gregs == NULL);					\
	DO_RESTORE_KVM_GUEST_KERNEL_STACKS_STATE(__ti, gti, gregs);	\
})

#define	DO_RESTORE_KVM_KERNEL_STACKS_STATE(__ti, __gti, __gregs)	\
({									\
	GTI_BUG_ON((__gti) == NULL);					\
	GTI_BUG_ON((__gregs) == NULL);					\
	RESTORE_KVM_THREAD_STATE(__ti, __gregs);			\
	DO_RESTORE_KVM_HOST_KERNEL_STACKS_STATE(__ti, __gti, __gregs);	\
	DO_RESTORE_KVM_GUEST_KERNEL_STACKS_STATE(__ti, __gti, __gregs);	\
})

#define	RETURN_TO_GUEST_KERNEL_DATA_STACK(__ti, __g_usd_size)		\
({									\
	e2k_sbr_t	sbr;						\
	e2k_usd_t	usd;						\
	sbr.base = (__ti)->u_stack.top;					\
	struct kvm_vcpu *vcpu = (__ti)->vcpu;				\
									\
	usd = vcpu_new_usd(vcpu, (__ti)->u_stack.bottom , (__g_usd_size), \
				 (__g_usd_size));			\
	native_write_USBR_USD_regs(sbr, usd);				\
})

#define	KVM_SAVE_GUEST_KERNEL_GREGS_FROM_TI(__ti,			\
			unused__, task__, cpu_id__, cpu_off__)		\
({									\
	kernel_gregs_t *k_gregs = &(__ti)->k_gregs;			\
									\
	ONLY_COPY_FROM_KERNEL_GREGS(k_gregs,				\
		unused__, task__, cpu_id__, cpu_off__);			\
})
#define	KVM_RESTORE_GUEST_KERNEL_GREGS_AT_TI(__ti,			\
			unused__, task__, cpu_id__, cpu_off__)		\
({									\
	kernel_gregs_t *k_gregs = &(__ti)->k_gregs;			\
									\
	ONLY_COPY_TO_KERNEL_GREGS(k_gregs,				\
		unused__, task__, cpu_id__, cpu_off__);			\
})

static inline void print_gpt_regs(gpt_regs_t *gregs)
{
	if (gregs == NULL) {
		pr_info("Empty (NULL) guest pt_regs structures\n");
		return;
	}
	pr_info("guest pt_regs structure at %px: type %d\n",
		gregs, gregs->type);
	pr_info("   data stack state: guest #%d usd size 0x%lx, "
		"host #%d usd size 0x%lx, PCSP ind 0x%lx\n",
		gregs->g_stk_frame_no, gregs->g_usd_size,
		gregs->k_stk_frame_no, gregs->k_usd_size, gregs->pcsp_ind);
	pr_info("   current thread state: pt_regs %px\n", gregs->pt_regs);
}

static inline void print_all_gpt_regs(thread_info_t *ti)
{
	gpt_regs_t *gregs;

	gregs = get_gpt_regs(ti);
	if (gregs == NULL) {
		pr_info("none any guest pt_regs structures\n");
		return;
	}
	do {
		print_gpt_regs(gregs);
		gregs = get_next_gpt_regs(ti, gregs);
	} while (gregs);
}

static inline int
kvm_flush_hw_stacks_to_memory(kvm_hw_stacks_flush_t __user *hw_stacks)
{
	e2k_psp_t psp;
	e2k_pcsp_t pcsp;
	int error = 0;

	NATIVE_FLUSHCPU;

	psp = native_read_PSP_reg();
	pcsp = native_read_PCSP_reg();

	error |= put_user(LO(psp), &LO(hw_stacks->psp));
	error |= put_user(LO(psp), &HI(hw_stacks->psp));
	error |= put_user(LO(pcsp), &LO(hw_stacks->pcsp));
	error |= put_user(HI(pcsp), &HI(hw_stacks->pcsp));

	return error;
}

/*
 * Procedure chain stacks can be mapped to user (user processes)
 * or kernel space (kernel threads). But mapping is always to privileged area
 * and directly can be accessed only by host kernel.
 * SPECIAL CASE: access to current procedure chain stack:
 *	1. Current stack frame must be locked (resident), so access is
 * safety and can use common load/store operations
 *	2. Top of stack can be loaded to the special hardware register file and
 * must be spilled to memory before any access.
 *	3. If items of chain stack are not updated, then spilling is enough to
 * their access
 *	4. If items of chain stack are updated, then interrupts and
 * any calling of function should be disabled in addition to spilling,
 * because of return (done) will fill some part of stack from memory and can be
 * two copy of chain stack items: in memory and in registers file.
 * We can update only in memory and following spill recover not updated
 * value from registers file.
 * Guest kernel can access to items of procedure chain stacks only through
 * following host kernel light hypercalls
 * WARNING:
 *	1. interrupts NOW disabled for any light hypercall
 *	2. should not be any calls of function using data stack
 */
static inline long
kvm_check_guest_active_cr_mem_item(struct kvm_vcpu *vcpu,
				   e2k_addr_t base, e2k_addr_t cr_ind, e2k_addr_t cr_item)
{
	e2k_pcsp_t pcsp;
	e2k_pcshtp_t pcshtp;
	unsigned long pcs_bound;

	if (base & E2K_ALIGN_PCSTACK_MASK)
		return -EINVAL;
	if (cr_ind & ((1UL << E2K_ALIGN_CHAIN_WINDOW) - 1))
		return -EINVAL;
	if (cr_item & (sizeof(u64) - 1))
		return -EINVAL;
	pcsp = native_read_PCSP_reg();
	pcshtp = native_read_PCSHTP_reg();
	pcs_bound = vcpu_pcsp_ind(vcpu, pcsp) + pcshtp.ind;
	if (base < vcpu_pcsp_base(vcpu, pcsp) || base >= vcpu_pcsp_ptr(vcpu, pcsp))
		return -EINVAL;
	if (cr_ind >= pcs_bound)
		return -EINVAL;
	if (base + cr_ind >= vcpu_pcsp_base(vcpu, pcsp) + pcs_bound)
		return -EINVAL;

	if (cr_ind >= vcpu_pcsp_ind(vcpu, pcsp)) {
		/* CR to access is now into hardware chain registers file */
		/* spill it into memory */
		NATIVE_FLUSHC;
	}
	return 0;
}

static inline long
kvm_get_guest_active_cr_mem_item(struct kvm_vcpu *vcpu,
				 unsigned long __user *cr_value,
				 e2k_addr_t base, e2k_addr_t cr_ind,
				 e2k_addr_t cr_item)
{
	unsigned long cr;
	long error;

	error = kvm_check_guest_active_cr_mem_item(vcpu, base, cr_ind, cr_item);
	if (error)
		return error;
	cr = native_get_active_cr_mem_value(base, cr_ind, cr_item);
	error = put_user(cr, cr_value);
	return error;
}

static inline long
kvm_put_guest_active_cr_mem_item(struct kvm_vcpu *vcpu,
				 unsigned long cr_value,
				 e2k_addr_t base, e2k_addr_t cr_ind,
				 e2k_addr_t cr_item)
{
	long error;

	error = kvm_check_guest_active_cr_mem_item(vcpu, base, cr_ind, cr_item);
	if (error)
		return error;
	native_put_active_cr_mem_value(cr_value, base, cr_ind, cr_item);
	return 0;
}

static inline long
kvm_update_guest_kernel_crs(struct kvm_vcpu *vcpu, e2k_mem_crs_t *crs,
			    e2k_mem_crs_t *prev_crs, e2k_mem_crs_t *p_prev_crs)
{
	e2k_mem_crs_t *k_crs;

	raw_all_irq_disable();
	k_crs = (e2k_mem_crs_t *)vcpu_pcsp_base(vcpu, native_read_PCSP_reg());
	E2K_FLUSHC;
	*p_prev_crs = k_crs[0];
	k_crs[0] = *prev_crs;
	k_crs[1] = *crs;
	raw_all_irq_enable();

	return 0;
}

/*
 * These functions for host kernel, see comment about virtualization at
 *	arch/e2k/include/asm/ptrace.h
 * In this case host is main kernel and here knows that it is host
 * Extra kernel is guest
 *
 * Get/set kernel stack limits of area reserved at the top of hardware stacks
 * Kernel areas include two part:
 *	guest kernel stack reserved area at top of stack
 *	host kernel stack reserved area at top of stack
 */

static __always_inline e2k_size_t
kvm_get_guest_hw_ps_user_size(hw_stack_t *hw_stacks)
{
	return get_hw_ps_user_size(hw_stacks);
}

static __always_inline e2k_size_t
kvm_get_guest_hw_pcs_user_size(hw_stack_t *hw_stacks)
{
	return get_hw_pcs_user_size(hw_stacks);
}

static __always_inline void
kvm_set_guest_hw_ps_user_size(hw_stack_t *hw_stacks, e2k_size_t u_ps_size)
{
	set_hw_ps_user_size(hw_stacks, u_ps_size);
}

static __always_inline void
kvm_set_guest_hw_pcs_user_size(hw_stack_t *hw_stacks, e2k_size_t u_pcs_size)
{
	set_hw_pcs_user_size(hw_stacks, u_pcs_size);
}

extern int kvm_copy_hw_stacks_frames(struct kvm_vcpu *vcpu,
				     void *dst, void *src,
				     long size, bool is_chain);

extern void kvm_arch_vcpu_to_wait(struct kvm_vcpu *vcpu);
extern void kvm_arch_vcpu_to_run(struct kvm_vcpu *vcpu);

extern int kvm_start_pv_guest(struct kvm_vcpu *vcpu);
extern int kvm_prepare_pv_vcpu_start_stacks(struct kvm_vcpu *vcpu);
extern int pv_vcpu_setup_thread(struct kvm_vcpu *vcpu);

extern unsigned long kvm_switch_guest_kernel_stacks(struct kvm_vcpu *vcpu,
					  kvm_task_info_t *task_info,
					  char *entry_point,
					  unsigned long *args, int args_num,
					  guest_hw_stack_t *stack_regs);
extern unsigned long kvm_switch_to_virt_mode(struct kvm_vcpu *vcpu,
				   kvm_task_info_t *task_info,
				   guest_hw_stack_t *stack_regs,
				   void (*func) (void *data, void *arg1,
						 void *arg2),
				   void *data, void *arg1, void *arg2);
#else
static inline int pv_vcpu_setup_thread(struct kvm_vcpu *vcpu)
{
	return -ENOTSUPP;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

extern void prepare_stacks_to_startup_vcpu(struct kvm_vcpu *vcpu,
		e2k_mem_ps_t *ps_frames, e2k_mem_crs_t *pcs_frames,
		u64 *args, int args_num, char *entry_point, e2k_psr_t psr,
		e2k_size_t usd_size, e2k_size_t *ps_ind, e2k_size_t *pcs_ind,
		int cui, bool kernel);

extern int kvm_init_vcpu_thread(struct kvm_vcpu *vcpu);
extern void kvm_halt_host_vcpu_thread(struct kvm_vcpu *vcpu);
extern void kvm_spare_host_vcpu_release(struct kvm_vcpu *vcpu);
extern void kvm_guest_vcpu_thread_stop(struct kvm_vcpu *vcpu);
extern void kvm_guest_vcpu_thread_restart(struct kvm_vcpu *vcpu);
extern int kvm_copy_guest_kernel_stacks(struct kvm_vcpu *vcpu,
					kvm_task_info_t *task_info,
					e2k_cr1_t cr1);
extern int kvm_release_guest_task_struct(struct kvm_vcpu *vcpu, int gpid_nr);
extern int kvm_switch_to_guest_new_user(struct kvm_vcpu *vcpu,
					kvm_task_info_t *task_info,
					guest_hw_stack_t *stack_regs);
extern int kvm_clone_guest_user_stacks(struct kvm_vcpu *vcpu,
				       kvm_task_info_t *task_info);
extern int kvm_copy_guest_user_stacks(struct kvm_vcpu *vcpu,
				      kvm_task_info_t *task_info,
				      vcpu_gmmu_info_t *gmmu_info);
extern int kvm_sig_handler_return(struct kvm_vcpu *vcpu,
				  kvm_stacks_info_t *regs_info,
				  unsigned long sigreturn_entry, long sys_rval,
				  guest_hw_stack_t *stack_regs);
extern int kvm_long_jump_return(struct kvm_vcpu *vcpu,
				kvm_long_jump_info_t *regs_info,
				bool switch_stack, u64 to_key);
extern long kvm_guest_vcpu_common_idle(struct kvm_vcpu *vcpu, long timeout,
				       bool interruptable);
extern void kvm_guest_vcpu_relax(void);

#ifdef	CONFIG_SMP
extern int kvm_activate_host_vcpu(struct kvm *kvm, int vcpu_id);
extern int kvm_activate_guest_all_vcpus(struct kvm *kvm);
#endif /* CONFIG_SMP */

extern void kvm_pv_wait(struct kvm *kvm, struct kvm_vcpu *vcpu);
extern int kvm_pv_kick(struct kvm *kvm, int vcpu_id);

extern void prepare_vcpu_startup_args(struct kvm_vcpu *vcpu);
extern void vcpu_clear_signal_stack(struct kvm_vcpu *vcpu);

#ifdef	CONFIG_KVM_HW_VIRTUALIZATION
extern int kvm_start_hv_guest(struct kvm_vcpu *vcpu);
extern void prepare_bu_stacks_to_startup_vcpu(struct kvm_vcpu *);
extern void kvm_init_kernel_intc(struct kvm_vcpu *vcpu);
extern int vcpu_enter_guest(struct kvm_vcpu *);
#else	/* ! CONFIG_KVM_HW_VIRTUALIZATION */
static inline int kvm_start_hv_guest(struct kvm_vcpu *vcpu)
{
	pr_err("Hardware virtualization support turn OFF at kernel config\n");
	VM_BUG_ON(true);
	return -EINVAL;
}

static inline void
prepare_bu_stacks_to_startup_vcpu(struct kvm_vcpu *vcpu, gthread_info_t *gti)
{
	/* are not used */
}
static inline void kvm_init_kernel_intc(struct kvm_vcpu *vcpu) { }
static inline int
vcpu_enter_guest(struct kvm_vcpu *vcpu)
{
	return -ENOTSUPP;
}
#endif	/* CONFIG_KVM_HW_VIRTUALIZATION */


extern long kvm_guest_shutdown(struct kvm_vcpu *vcpu, void *msg, unsigned long reason);

#ifdef CONFIG_KVM_ASYNC_PF
extern int kvm_pv_host_enable_async_pf(struct kvm_vcpu *vcpu,
				       u64 apf_reason_gpa, u64 apf_id_gpa,
				       u32 apf_ready_vector,
				       u32 irq_controller);
#endif /* CONFIG_KVM_ASYNC_PF */

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
extern int kvm_apply_updated_psp_bounds(struct kvm_vcpu *vcpu,
					unsigned long base, unsigned long size,
					unsigned long start, unsigned long end,
					unsigned long delta);
extern int kvm_apply_updated_pcsp_bounds(struct kvm_vcpu *vcpu,
					 unsigned long base, unsigned long size,
					 unsigned long start, unsigned long end,
					 unsigned long delta);
extern int kvm_apply_updated_usd_bounds(struct kvm_vcpu *vcpu,
					unsigned long base, unsigned long delta,
					bool incr);

/**
 * user_hw_stacks_copy - copy guest user hardware stacks that have been
 *			 SPILLed to kernel back to guest kernel stack
 * @vcpu - saved user stack registers
 * @ps_size - copy size of current window in procedure stack,
 * @pcs_size - copy size of current window in chain stack,
 */
static __always_inline int
pv_vcpu_hw_stacks_copy(struct kvm_vcpu *vcpu, pt_regs_t *regs,
		       long ps_size, long pcs_size, long ps_off, long pcs_off)
{
	e2k_stacks_t *g_stacks = &regs->g_stacks;
	e2k_stacks_t *u_stacks = &regs->stacks;
	e2k_psp_t  g_psp = g_stacks->psp,   k_psp = current_thread_info()->k_psp;
	e2k_pcsp_t g_pcsp = g_stacks->pcsp, k_pcsp = current_thread_info()->k_pcsp;
	void *dst, *src;
	int ret;

	DebugGUST("guest user procedure stack state: base 0x%llx size 0x%llx ind 0x%llx PSHTP size %d\n",
		  vcpu_psp_base(vcpu, u_stacks->psp),
		  vcpu_psp_size(vcpu, u_stacks->psp),
		  vcpu_psp_ind(vcpu, u_stacks->psp),
		  PSHTP_MEM_INDEX(u_stacks->pshtp));
	DebugGUST("guest user chain stack state: base 0x%llx size 0x%llx ind 0x%llx PCSHTP size %d\n",
		  vcpu_pcsp_base(vcpu, u_stacks->pcsp),
		  vcpu_pcsp_size(vcpu, u_stacks->pcsp),
		  vcpu_pcsp_ind(vcpu, u_stacks->pcsp),
		  u_stacks->pcshtp.ind);

	/*
	 * Copy guest user's part from kernel stacks into guest kernel stacks
	 * Update guest user's stack registers
	 */

	if (likely(pcs_size <= 0 && ps_size <= 0))
		return 0;

	if (unlikely(pcs_size > 0)) {
		unsigned long flags;
		raw_all_irq_save(flags);
		k_pcsp = native_read_PCSP_reg();
		raw_all_irq_restore(flags);

		if (unlikely(vcpu_pcsp_ind(vcpu, g_pcsp) > vcpu_pcsp_size(vcpu, g_pcsp))) {
			pr_err("%s(): guest kernel stack was overflown : PCSP ind 0x%llx > size 0x%llx\n",
			       __func__, vcpu_pcsp_ind(vcpu, g_pcsp), vcpu_pcsp_size(vcpu, g_pcsp));
			E2K_KVM_BUG_ON(true);
		}

		dst = (void *)(vcpu_pcsp_base(vcpu, g_pcsp) + pcs_off);
		src = (void *)(PCSP_BASE(k_pcsp) + pcs_off);
		DebugGUST("copy guest user chain stack frames from host %px to guest kernel %px, size 0x%lx\n",
			  src, dst, pcs_size);
		ret = user_hw_stack_frames_copy((void __user __force *) dst, src,
				pcs_size, regs, PCSP_IND(k_pcsp) - pcs_off, true);
		if (ret)
			return ret;
		g_pcsp = vcpu_incr_pcsp_ind(vcpu, g_pcsp, pcs_size);
		g_stacks->pcsp = g_pcsp;
		DebugGUST("guest kernel chain stack new ind 0x%llx\n",
			  vcpu_pcsp_ind(vcpu, g_stacks->pcsp));
	}

	if (unlikely(ps_size > 0)) {
		HI(k_psp) = HI(native_read_PSP_reg());

		if (unlikely(vcpu_psp_ind(vcpu, g_psp) > vcpu_psp_size(vcpu, g_psp))) {
			pr_err("%s(): guest kernel stack was overflown : PSP ind 0x%llx > size 0x%llx\n",
			       __func__, vcpu_psp_ind(vcpu, g_psp), vcpu_psp_size(vcpu, g_psp));
			E2K_KVM_BUG_ON(true);
		}

		dst = (void *)(vcpu_psp_base(vcpu, g_psp) + ps_off);
		src = (void *)(PSP_BASE(k_psp) + ps_off);
		DebugGUST("copy guest user procedure stack frames from host %px to guest kernel %px, size 0x%lx\n",
			  src, dst, ps_size);
		ret = user_hw_stack_frames_copy((void __user __force *) dst, src,
				ps_size, regs, PSP_IND(k_psp) - ps_off, false);
		if (ret)
			return ret;
		g_psp = vcpu_incr_psp_ind(vcpu, g_psp, ps_size);
		g_stacks->psp = g_psp;
		DebugGUST("guest kernel procedure stack new ind 0x%llx\n",
			  vcpu_psp_ind(vcpu, g_stacks->psp));
	}

	return 0;
}

static inline int
pv_vcpu_user_hw_stacks_copy_crs(struct kvm_vcpu *vcpu, e2k_stacks_t *g_stacks,
				pt_regs_t *regs, e2k_mem_crs_t *crs)
{
	e2k_mem_crs_t __user *u_frame;
	int ret;

	u_frame = (void __user *)vcpu_pcsp_ptr(vcpu, g_stacks->pcsp);
	DebugGUST("copy last user frame from CRS at %px to guest kernel chain %px (base 0x%llx + ind 0x%llx)\n",
		  crs, u_frame, vcpu_pcsp_base(vcpu, g_stacks->pcsp),
		  vcpu_pcsp_ind(vcpu, g_stacks->pcsp));
	ret = user_crs_frames_copy(u_frame, regs, crs);
	if (unlikely(ret))
		return ret;

	g_stacks->pcsp = vcpu_incr_pcsp_ind(vcpu, g_stacks->pcsp, SZ_OF_CR);
	DebugGUST("guest kernel chain stack index is now 0x%llx\n",
		  vcpu_pcsp_ind(vcpu, g_stacks->pcsp));
	return 0;
}

static inline int
pv_vcpu_user_hw_stacks_copy_ps_frames(struct kvm_vcpu *vcpu,
				      e2k_stacks_t *g_stacks, pt_regs_t *regs,
				      e2k_mem_ps_t *ps_frames, int num_frames)
{
	void __user *u_psframe;
	int ret;

	u_psframe = (void __user *)vcpu_psp_ptr(vcpu, g_stacks->psp);
	DebugGUST("copy #%d user ps frames from %px to guest kernel procedure stack %p (base 0x%llx + ind 0x%llx)\n",
		  num_frames, ps_frames, u_psframe,
		  vcpu_psp_base(vcpu, g_stacks->psp), vcpu_psp_ind(vcpu, g_stacks->psp));
	ret = copy_e2k_stack_to_user(u_psframe, ps_frames,
				     sizeof(e2k_mem_ps_t) * num_frames, regs);
	if (unlikely(ret))
		return ret;

	g_stacks->psp = vcpu_incr_psp_ind(vcpu, g_stacks->psp,
					  sizeof(e2k_mem_ps_t) * num_frames);
	DebugGUST("guest kernel procedure stack index is now 0x%llx\n",
		  vcpu_psp_ind(vcpu, g_stacks->psp));

	return 0;
}

static inline int pv_vcpu_user_hw_stacks_copy_full(struct kvm_vcpu *vcpu,
						   pt_regs_t *regs)
{
	e2k_stacks_t *g_stacks = &regs->g_stacks;
	long ps_copy, pcs_copy, ps_ind, pcs_ind;
	int ret;

	DebugUST("guest kernel procedure stack current state: base 0x%llx size 0x%llx ind 0x%llx\n",
		 vcpu_psp_base(vcpu, g_stacks->psp),
		 vcpu_psp_size(vcpu, g_stacks->psp),
		 vcpu_psp_ind(vcpu, g_stacks->psp));
	DebugUST("guest kernel chain stack current state: base 0x%llx size 0x%llx ind 0x%llx\n",
		 vcpu_pcsp_base(vcpu, g_stacks->pcsp),
		 vcpu_pcsp_size(vcpu, g_stacks->pcsp),
		 vcpu_pcsp_ind(vcpu, g_stacks->pcsp));

	ps_copy = PSHTP_MEM_INDEX(g_stacks->pshtp);
	pcs_copy = g_stacks->pcshtp.ind;
	DebugGUST("guest user size to copy PSHTP 0x%lx PCSHTP 0x%lx\n",
		  ps_copy, pcs_copy);
	ps_ind = vcpu_psp_ind(vcpu, g_stacks->psp);
	if (ps_ind > 0) {
		/* first part of procedure stack was alredy copied */
		ps_copy -= ps_ind;
		E2K_KVM_BUG_ON(ps_copy < 0);
	}
	pcs_ind = vcpu_pcsp_ind(vcpu, g_stacks->pcsp);
	if (pcs_ind > 0) {
		/* first part of chain stack was alredy copied */
		pcs_copy -= pcs_ind;
		E2K_KVM_BUG_ON(pcs_copy < 0);
	}

	/*
	 * Copy part of guest user stacks that were SPILLed into kernel stacks
	 */
	ret = pv_vcpu_hw_stacks_copy(vcpu, regs, ps_copy, pcs_copy,
				     ps_ind, pcs_ind);
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
	collapse_kernel_hw_stacks(regs, g_stacks);

	/*
	 * Copy saved %cr registers
	 *
	 * Caller must take care of filling of resulting hole
	 * (last user frame from pcshtp == SZ_OF_CR).
	 */
	ret = pv_vcpu_user_hw_stacks_copy_crs(vcpu, g_stacks, regs, &regs->crs);
	if (unlikely(ret))
		return ret;

	if (DEBUG_KVM_GUEST_STACKS_MODE && debug_guest_user_stacks)
		debug_guest_user_stacks = false;

	return 0;
}

static inline int
pv_vcpu_user_crs_copy_to_kernel(struct kvm_vcpu *vcpu,
				void *u_frame, e2k_mem_crs_t *crs)
{
	hva_t hva;
	unsigned long ts_flag;
	int ret;
	kvm_arch_exception_t exception;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t) u_frame, true, &exception);
	if (kvm_is_error_hva(hva)) {
		pr_err("%s(): failed to find GPA for dst %px GVA, inject page fault to guest\n",
			__func__, u_frame);
		kvm_vcpu_inject_page_fault(vcpu, u_frame, &exception);
		return -EAGAIN;
	}

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __copy_to_user((void __user *)hva, crs, sizeof(*crs));
	clear_ts_flag(ts_flag);
	if (unlikely(ret)) {
		pr_err("%s(): copy CRS frame to guest kernel stack failed, error %d\n",
			__func__, ret);
		return -EFAULT;
	}

	return 0;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

unsigned long kvm_add_ctx_signal_stack(struct kvm_vcpu *vcpu, u64 key,
				       bool is_main);

void kvm_remove_ctx_signal_stack(struct kvm_vcpu *vcpu, u64 key);

#endif /* __KVM_PROCESS_H */
