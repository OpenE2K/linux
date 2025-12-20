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
#include "gaccess.h"

#undef	DEBUG_KVM_ACTIVATION_MODE
#undef	DebugKVMACT
#define	DEBUG_KVM_ACTIVATION_MODE	0	/* KVM guest kernel data */
						/* stack activations */
						/* debugging */
#define	DebugKVMACT(fmt, args...)					\
({									\
	if (DEBUG_KVM_ACTIVATION_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

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

#define	GUEST_KERNEL_THREAD_STACK_SIZE	(64 * 1024U)	/* 64 KBytes */

static inline struct gthread_info *
kvm_get_guest_thread_info(struct kvm *kvm, int gpid_nr)
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
									\
		CHECK_BUG((g_sbr) != stacks->top, 6);			\
		if ((g_sbr) == (ti)->u_stack.top) {			\
			CHECK_BUG(stacks->usd_lo.USD_lo_base -		\
				stacks->usd_hi.USD_hi_size !=		\
					(ti)->u_stack.bottom, 7);	\
		} else {						\
			CHECK_BUG(stacks->usd_lo.USD_lo_base -		\
				stacks->usd_hi.USD_hi_size !=		\
					gti->data_stack.bottom, 5);	\
		}							\
	}								\
})
#else	/* ! CONFIG_KVM_GUEST_HW_HCALL */
#define	CHECK_GUEST_KERNEL_DATA_STACK(ti, g_sbr, g_usd_size)
#endif	/* CONFIG_KVM_GUEST_HW_HCALL */

static inline void
HOST_SAVE_TASK_USER_REGS_TO_SWITCH(struct kvm_vcpu *vcpu, struct sw_regs *sw_regs,
				   bool task_is_binco, bool task_traced)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;

	DO_SAVE_TASK_USER_REGS_TO_SWITCH(sw_regs, task_is_binco, task_traced);
	/* the hardware register was saved by hypercall in vcpu sw context */
	sw_regs->cutd = sw_ctxt->cutd;
}
static inline void
HOST_RESTORE_TASK_USER_REGS_TO_SWITCH(struct kvm_vcpu *vcpu, struct sw_regs *sw_regs,
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
	(__gregs)->k_usd_size = (__ti)->k_usd_hi.USD_hi_size;		\
	(__gregs)->k_stk_frame_no = (__gti)->k_stk_frame_no;		\
})
#define	UPDATE_KVM_HOST_KERNEL_STACKS_STATE(__ti, __gti, __usd_lo, __usd_hi) \
({									\
	(__ti)->k_usd_lo = (__usd_lo);					\
	(__ti)->k_usd_hi = (__usd_hi);					\
	(__gti)->k_stk_frame_no++;					\
})
#define	DO_RESTORE_KVM_HOST_KERNEL_STACKS_STATE(__ti, __gti, __gregs)	\
({									\
	e2k_size_t usd_size = (__gregs)->k_usd_size;			\
									\
	(__ti)->k_usd_hi.USD_hi_size = usd_size;			\
	(__ti)->k_usd_lo.USD_lo_base =					\
		(u64)thread_info_task(__ti)->stack + usd_size;		\
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

#define	SAVE_KVM_GUEST_KERNEL_STACKS_STATE(__gti, __gregs)		\
({									\
	(__gregs)->g_usd_size =						\
		(__gti)->stack_regs.stacks.usd_hi.USD_hi_size;		\
	(__gregs)->g_stk_frame_no = (__gti)->g_stk_frame_no;		\
})

#define	UPDATE_KVM_GUEST_KERNEL_STACKS_STATE(__ti, __gti, __usd_lo, __usd_hi) \
({									\
	e2k_size_t usd_new_size = (__usd_hi).USD_hi_size;		\
									\
	/* data stack grows down */					\
	if (usd_new_size > (__gti)->stack_regs.u_usd_hi.USD_hi_size) {	\
		gpt_regs_t *gregs;					\
									\
		/* data stack shoulg grow down, bun in some case new */	\
		/* activation can be above last saved state */		\
		/* for example first trap or hypercall after fork() */	\
		pr_debug("%s(): new guest USD size 0x%lx > "		\
			"0x%x current size, base 0x%llx, "		\
			"activation #%d\n",				\
			__func__, usd_new_size,				\
			(__gti)->stack_regs.u_usd_hi.USD_hi_size,	\
			(__gti)->stack_regs.u_usd_lo.USD_lo_base,	\
			(__gti)->g_stk_frame_no);			\
		gregs = get_gpt_regs(__ti);				\
		if (gregs != NULL) {					\
			gregs->g_usd_size = usd_new_size;		\
			GTI_BUG_ON(get_next_gpt_regs((__ti), gregs));	\
		}							\
	}								\
	(__gti)->stack_regs.u_usd_lo = (__usd_lo);			\
	(__gti)->stack_regs.u_usd_hi = (__usd_hi);			\
	(__gti)->g_stk_frame_no++;					\
})
#define	INC_KVM_GUEST_KERNEL_STACKS_STATE(__ti, __gti, usd_new_size)	\
({									\
	/* data stack grows down */					\
	if ((usd_new_size) >						\
		(__gti)->stack_regs.stacks.usd_hi.USD_hi_size) {	\
		gpt_regs_t *gregs;					\
									\
		/* data stack should grow down, but in some case new */	\
		/* activation can be above last saved state */		\
		/* for example first trap or hypercall after fork() */	\
		pr_debug("%s(): new guest USD size 0x%lx > "		\
			"0x%x current size, base 0x%llx, "		\
			"activation #%d\n",				\
			__func__, (usd_new_size),			\
			(__gti)->stack_regs.stacks.usd_hi.USD_hi_size,	\
			(__gti)->stack_regs.stacks.usd_lo.USD_lo_base,	\
			(__gti)->g_stk_frame_no);			\
		gregs = get_gpt_regs(__ti);				\
		if (gregs != NULL) {					\
			gregs->g_usd_size = (usd_new_size);		\
			GTI_BUG_ON(get_next_gpt_regs((__ti), gregs));	\
		}							\
	}								\
	(__gti)->stack_regs.stacks.usd_hi.USD_hi_size = (usd_new_size);	\
	(__gti)->stack_regs.stacks.usd_lo.USD_lo_base =			\
		(__gti)->data_stack.bottom + (usd_new_size);		\
	(__gti)->g_stk_frame_no++;					\
})
#define	DO_RESTORE_KVM_GUEST_KERNEL_STACKS_STATE(__ti, __gti, __gregs)	\
({									\
	CHECK_GUEST_KERNEL_DATA_STACK(__ti,				\
		(__gti)->stack_regs.stacks.top, (__gregs)->g_usd_size);	\
	(__gti)->stack_regs.stacks.usd_hi.USD_hi_size =			\
					(__gregs)->g_usd_size;		\
	(__gti)->stack_regs.stacks.usd_lo.USD_lo_base =			\
		(__gti)->data_stack.bottom + (__gregs)->g_usd_size;	\
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

#define	SAVE_KVM_KERNEL_STACKS_STATE(__ti, __gti, __gregs)		\
({									\
	GTI_BUG_ON((__gti) == NULL);					\
	GTI_BUG_ON((__gregs) == NULL);					\
	SAVE_KVM_THREAD_STATE(__ti, __gregs);				\
	SAVE_KVM_HOST_KERNEL_STACKS_STATE(__ti, __gti, __gregs);	\
	SAVE_KVM_GUEST_KERNEL_STACKS_STATE(gti, __gregs);		\
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
	e2k_sbr_t	sbr = { { 0 } };				\
	e2k_usd_lo_t	usd_lo = { { 0 } };				\
	e2k_usd_hi_t	usd_hi = { { 0 } };				\
	sbr.SBR_base = (__ti)->u_stack.top;				\
	usd_hi.USD_hi_size = (__g_usd_size);				\
	usd_lo.USD_lo_base = (__ti)->u_stack.bottom + (__g_usd_size);	\
	NATIVE_NV_WRITE_USBR_USD_REG(sbr, usd_hi, usd_lo);		\
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
		gregs->k_stk_frame_no, gregs->k_usd_size,
		gregs->pcsp_ind);
	pr_info("   current thread state: pt_regs %px\n",
		gregs->pt_regs);
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
	unsigned long	psp_lo;
	unsigned long	psp_hi;
	unsigned long	pcsp_lo;
	unsigned long	pcsp_hi;
	int error = 0;

	NATIVE_FLUSHCPU;

	psp_lo = NATIVE_NV_READ_PSP_LO_REG_VALUE();
	psp_hi = NATIVE_NV_READ_PSP_HI_REG_VALUE();
	pcsp_lo = NATIVE_NV_READ_PCSP_LO_REG_VALUE();
	pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG_VALUE();

	error |= put_user(psp_lo, &hw_stacks->psp_lo);
	error |= put_user(psp_hi, &hw_stacks->psp_hi);
	error |= put_user(pcsp_lo, &hw_stacks->pcsp_lo);
	error |= put_user(pcsp_hi, &hw_stacks->pcsp_hi);

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
kvm_check_guest_active_cr_mem_item(e2k_addr_t base, e2k_addr_t cr_ind,
							e2k_addr_t cr_item)
{
	e2k_pcsp_lo_t	pcsp_lo;
	e2k_pcsp_hi_t	pcsp_hi;
	e2k_pcshtp_t	pcshtp;
	unsigned long	pcs_bound;

	if (base & E2K_ALIGN_PCSTACK_MASK != 0)
		return -EINVAL;
	if (cr_ind & ((1UL << E2K_ALIGN_CHAIN_WINDOW) - 1) != 0)
		return -EINVAL;
	if (cr_item & (sizeof(e2k_cr0_lo_t) - 1) != 0)
		return -EINVAL;
	pcsp_lo = NATIVE_NV_READ_PCSP_LO_REG();
	pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();
	pcshtp = NATIVE_READ_PCSHTP_REG_SVALUE();
	pcs_bound = pcsp_hi.PCSP_hi_ind + pcshtp;
	if (base < pcsp_lo.PCSP_lo_base ||
		base >= pcsp_lo.PCSP_lo_base + pcsp_hi.PCSP_hi_size)
		return -EINVAL;
	if (cr_ind >= pcs_bound)
		return -EINVAL;
	if (base + cr_ind >= pcsp_lo.PCSP_lo_base + pcs_bound)
		return -EINVAL;

	if (cr_ind >= pcsp_hi.PCSP_hi_ind) {
		/* CR to access is now into hardware chain registers file */
		/* spill it into memory */
		NATIVE_FLUSHC;
	}
	return 0;
}
static inline long
kvm_get_guest_active_cr_mem_item(unsigned long __user *cr_value,
			e2k_addr_t base, e2k_addr_t cr_ind, e2k_addr_t cr_item)
{
	unsigned long cr;
	long error;

	error = kvm_check_guest_active_cr_mem_item(base, cr_ind, cr_item);
	if (error)
		return error;
	cr = native_get_active_cr_mem_value(base, cr_ind, cr_item);
	error = put_user(cr, cr_value);
	return error;
}
static inline long
kvm_put_guest_active_cr_mem_item(unsigned long cr_value,
			e2k_addr_t base, e2k_addr_t cr_ind, e2k_addr_t cr_item)
{
	long error;

	error = kvm_check_guest_active_cr_mem_item(base, cr_ind, cr_item);
	if (error)
		return error;
	native_put_active_cr_mem_value(cr_value, base, cr_ind, cr_item);
	return 0;
}
static inline long
kvm_update_guest_kernel_crs(e2k_mem_crs_t *crs, e2k_mem_crs_t *prev_crs,
			e2k_mem_crs_t *p_prev_crs)
{
	e2k_mem_crs_t *k_crs = (e2k_mem_crs_t *)
			NATIVE_NV_READ_PCSP_LO_REG().base;

	raw_all_irq_disable();
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
		void __user *dst, void __user *src, long size, bool is_chain);

extern void kvm_arch_vcpu_to_wait(struct kvm_vcpu *vcpu);
extern void kvm_arch_vcpu_to_run(struct kvm_vcpu *vcpu);

extern int kvm_start_pv_guest(struct kvm_vcpu *vcpu);
extern void prepare_stacks_to_startup_vcpu(struct kvm_vcpu *vcpu,
		e2k_mem_ps_t *ps_frames, e2k_mem_crs_t *pcs_frames,
		u64 *args, int args_num, char *entry_point, e2k_psr_t psr,
		e2k_size_t usd_size, e2k_size_t *ps_ind, e2k_size_t *pcs_ind,
		int cui, bool kernel);
extern int kvm_prepare_pv_vcpu_start_stacks(struct kvm_vcpu *vcpu);

extern int kvm_init_vcpu_thread(struct kvm_vcpu *vcpu);
extern int hv_vcpu_setup_thread(struct kvm_vcpu *vcpu);
extern int pv_vcpu_setup_thread(struct kvm_vcpu *vcpu);

extern int kvm_switch_guest_kernel_stacks(struct kvm_vcpu *vcpu,
			kvm_task_info_t __user *task_info, char *entry_point,
			unsigned long *args, int args_num,
			guest_hw_stack_t *stack_regs);
extern int kvm_switch_to_virt_mode(struct kvm_vcpu *vcpu,
		kvm_task_info_t __user *task_info,
		guest_hw_stack_t *stack_regs,
		void (*func)(void *data, void *arg1, void *arg2),
		void *data, void *arg1, void *arg2);
extern void kvm_halt_host_vcpu_thread(struct kvm_vcpu *vcpu);
extern void kvm_spare_host_vcpu_release(struct kvm_vcpu *vcpu);
extern void kvm_guest_vcpu_thread_stop(struct kvm_vcpu *vcpu);
extern void kvm_guest_vcpu_thread_restart(struct kvm_vcpu *vcpu);
extern int kvm_copy_guest_kernel_stacks(struct kvm_vcpu *vcpu,
		kvm_task_info_t __user *task_info, e2k_cr1_hi_t cr1_hi);
extern int kvm_release_guest_task_struct(struct kvm_vcpu *vcpu, int gpid_nr);
extern int kvm_switch_to_guest_new_user(struct kvm_vcpu *vcpu,
		kvm_task_info_t __user *task_info,
		guest_hw_stack_t *stack_regs);
extern int kvm_clone_guest_user_stacks(struct kvm_vcpu *vcpu,
		kvm_task_info_t __user *task_info);
extern int kvm_copy_guest_user_stacks(struct kvm_vcpu *vcpu,
		kvm_task_info_t __user *task_info,
		vcpu_gmmu_info_t __user *gmmu_info);
extern int kvm_sig_handler_return(struct kvm_vcpu *vcpu,
		kvm_stacks_info_t *regs_info, unsigned long sigreturn_entry,
		long sys_rval, guest_hw_stack_t *stack_regs);
extern int kvm_long_jump_return(struct kvm_vcpu *vcpu,
				kvm_long_jump_info_t *regs_info,
				bool switch_stack, u64 to_key);
extern long kvm_guest_vcpu_common_idle(struct kvm_vcpu *vcpu,
					long timeout, bool interruptable);
extern void kvm_guest_vcpu_relax(void);

#ifdef	CONFIG_SMP
extern int kvm_activate_host_vcpu(struct kvm *kvm, int vcpu_id);
extern int kvm_activate_guest_all_vcpus(struct kvm *kvm);
#endif	/* CONFIG_SMP */

extern void kvm_pv_wait(struct kvm *kvm, struct kvm_vcpu *vcpu);
extern void kvm_pv_kick(struct kvm *kvm, int vcpu_id);

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

extern long kvm_guest_shutdown(struct kvm_vcpu *vcpu,
				void __user *msg, unsigned long reason);

#ifdef CONFIG_KVM_ASYNC_PF
extern int kvm_pv_host_enable_async_pf(struct kvm_vcpu *vcpu,
				u64 apf_reason_gpa, u64 apf_id_gpa,
				u32 apf_ready_vector, u32 irq_controller);
#endif /* CONFIG_KVM_ASYNC_PF */

extern int kvm_apply_updated_psp_bounds(struct kvm_vcpu *vcpu,
		unsigned long base, unsigned long size,
		unsigned long start, unsigned long end, unsigned long delta);
extern int kvm_apply_updated_pcsp_bounds(struct kvm_vcpu *vcpu,
		unsigned long base, unsigned long size,
		unsigned long start, unsigned long end, unsigned long delta);
extern int kvm_apply_updated_usd_bounds(struct kvm_vcpu *vcpu,
		unsigned long base, unsigned long delta, bool incr);

/**
 * user_hw_stacks_copy - copy guest user hardware stacks that have been
 *			 SPILLed to kernel back to guest kernel stack
 * @vcpu - saved user stack registers
 * @ps_size - copy size of current window in procedure stack,
 * @pcs_size - copy size of current window in chain stack,
 */
static __always_inline int
pv_vcpu_hw_stacks_copy(struct kvm_vcpu *vcpu, pt_regs_t *regs,
		       long ps_size, long pcs_size,
		       long ps_off,  long pcs_off)
{
	e2k_stacks_t *g_stacks = &regs->g_stacks;
	e2k_stacks_t *u_stacks = &regs->stacks;
	e2k_psp_lo_t g_psp_lo = g_stacks->psp_lo,
		     k_psp_lo = current_thread_info()->k_psp_lo;
	e2k_psp_hi_t g_psp_hi = g_stacks->psp_hi;
	e2k_pcsp_lo_t g_pcsp_lo = g_stacks->pcsp_lo,
		      k_pcsp_lo = current_thread_info()->k_pcsp_lo;
	e2k_pcsp_hi_t g_pcsp_hi = g_stacks->pcsp_hi;
	void *dst, *src;
	int ret;

	DebugGUST("guest user procedure stack state: base 0x%llx "
		"size 0x%x ind 0x%x PSHTP size 0x%llx\n",
		u_stacks->psp_lo.PSP_lo_base,
		u_stacks->psp_hi.PSP_hi_size, u_stacks->psp_hi.PSP_hi_ind,
		GET_PSHTP_MEM_INDEX(u_stacks->pshtp));
	DebugGUST("guest user chain stack state: base 0x%llx "
		"size 0x%x ind 0x%x PCSHTP size 0x%llx\n",
		u_stacks->pcsp_lo.PCSP_lo_base,
		u_stacks->pcsp_hi.PCSP_hi_size, u_stacks->pcsp_hi.PCSP_hi_ind,
		PCSHTP_SIGN_EXTEND(u_stacks->pcshtp));

	/*
	 * Copy guest user's part from kernel stacks into guest kernel stacks
	 * Update guest user's stack registers
	 */

	if (likely(pcs_size <= 0 && ps_size <= 0))
			return 0;

	if (unlikely(pcs_size > 0)) {
		e2k_pcsp_hi_t k_pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();

		if (unlikely(g_pcsp_hi.PCSP_hi_ind > g_pcsp_hi.PCSP_hi_size)) {
			pr_err("%s(): guest kernel stack was overflown : "
				"PCSP ind 0x%x > size 0x%x\n",
				__func__, g_pcsp_hi.PCSP_hi_ind,
				g_pcsp_hi.PCSP_hi_size);
			E2K_KVM_BUG_ON(true);
		}

		dst = (void *)(g_pcsp_lo.PCSP_lo_base + pcs_off);
		src = (void *)(k_pcsp_lo.PCSP_lo_base + pcs_off);
		DebugGUST("copy guest user chain stack frames from "
			"host %px to guest kernel %px, size 0x%lx\n",
			src, dst, pcs_size);
		ret = user_hw_stack_frames_copy(dst, src, pcs_size, regs,
					k_pcsp_hi.PCSP_hi_ind - pcs_off, true);
		if (ret)
			return ret;
		g_pcsp_hi.PCSP_hi_ind += pcs_size;
		g_stacks->pcsp_hi = g_pcsp_hi;
		DebugGUST("guest kernel chain stack new ind 0x%x\n",
			g_stacks->pcsp_hi.PCSP_hi_ind);
	}

	if (unlikely(ps_size > 0)) {
		e2k_psp_hi_t k_psp_hi = NATIVE_NV_READ_PSP_HI_REG();

		if (unlikely(g_psp_hi.PSP_hi_ind > g_psp_hi.PSP_hi_size)) {
			pr_err("%s(): guest kernel stack was overflown : "
				"PSP ind 0x%x > size 0x%x\n",
				__func__, g_psp_hi.PSP_hi_ind,
				g_psp_hi.PSP_hi_size);
			E2K_KVM_BUG_ON(true);
		}

		dst = (void *)(g_psp_lo.PSP_lo_base + ps_off);
		src = (void *)(k_psp_lo.PSP_lo_base + ps_off);
		DebugGUST("copy guest user procedure stack frames from "
			"host %px to guest kernel %px, size 0x%lx\n",
			src, dst, ps_size);
		ret = user_hw_stack_frames_copy(dst, src, ps_size, regs,
					k_psp_hi.PSP_hi_ind - ps_off, false);
		if (ret)
			return ret;
		g_psp_hi.PSP_hi_ind += ps_size;
		g_stacks->psp_hi = g_psp_hi;
		DebugGUST("guest kernel procedure stack new ind 0x%x\n",
			g_stacks->psp_hi.PSP_hi_ind);
	}

	return 0;
}

static inline int
pv_vcpu_user_hw_stacks_copy_crs(struct kvm_vcpu *vcpu, e2k_stacks_t *g_stacks,
				pt_regs_t *regs, e2k_mem_crs_t *crs)
{
	e2k_mem_crs_t __user *u_frame;
	gthread_info_t *gti = pv_vcpu_get_gti(vcpu);
	int ret;

	u_frame = (void __user *) g_stacks->pcsp_lo.PCSP_lo_base +
				  g_stacks->pcsp_hi.PCSP_hi_ind;
	DebugGUST("copy last user frame from CRS at %px to guest "
		"kernel chain %px (base 0x%llx + ind 0x%x)\n",
		crs, u_frame, g_stacks->pcsp_lo.PCSP_lo_base,
		g_stacks->pcsp_hi.PCSP_hi_ind);
	ret = user_crs_frames_copy(u_frame, regs, crs);
	if (unlikely(ret))
		return ret;

	g_stacks->pcsp_hi.PCSP_hi_ind += SZ_OF_CR;
	DebugGUST("guest kernel chain stack index is now 0x%x\n",
		g_stacks->pcsp_hi.PCSP_hi_ind);
	return 0;
}

static inline int
pv_vcpu_user_hw_stacks_copy_ps_frames(struct kvm_vcpu *vcpu,
				e2k_stacks_t *g_stacks, pt_regs_t *regs,
				e2k_mem_ps_t *ps_frames, int num_frames)
{
	void __user *u_psframe;
	int ret;
	gthread_info_t *gti = pv_vcpu_get_gti(vcpu);

	u_psframe = (void __user *) g_stacks->psp_lo.PSP_lo_base +
				  g_stacks->psp_hi.PSP_hi_ind;
	DebugGUST("copy #%d user ps frames from %px to guest kernel "
		"procedure stack %p (base 0x%llx + ind 0x%x)\n",
		num_frames, ps_frames, u_psframe,
		g_stacks->psp_lo.PSP_lo_base, g_stacks->psp_hi.PSP_hi_ind);
	ret = copy_e2k_stack_to_user(u_psframe, ps_frames,
			sizeof(e2k_mem_ps_t) * num_frames, regs);
	if (unlikely(ret))
		return ret;

	g_stacks->psp_hi.PSP_hi_ind += sizeof(e2k_mem_ps_t) * num_frames;
	DebugGUST("guest kernel procedure stack index is now 0x%x\n",
		g_stacks->psp_hi.PSP_hi_ind);

	return 0;
}

static inline int pv_vcpu_user_hw_stacks_copy_full(struct kvm_vcpu *vcpu,
						   pt_regs_t *regs)
{
	e2k_stacks_t *g_stacks = &regs->g_stacks;
	long ps_copy, pcs_copy, ps_ind, pcs_ind;
	int ret;

	DebugUST("guest kernel procedure stack current state: base 0x%llx "
		"size 0x%x ind 0x%x\n",
		g_stacks->psp_lo.PSP_lo_base, g_stacks->psp_hi.PSP_hi_size,
		g_stacks->psp_hi.PSP_hi_ind);
	DebugUST("guest kernel chain stack current state: base 0x%llx "
		"size 0x%x ind 0x%x\n",
		g_stacks->pcsp_lo.PCSP_lo_base, g_stacks->pcsp_hi.PCSP_hi_size,
		g_stacks->pcsp_hi.PCSP_hi_ind);

	ps_copy = GET_PSHTP_MEM_INDEX(g_stacks->pshtp);
	pcs_copy = PCSHTP_SIGN_EXTEND(g_stacks->pcshtp);
	DebugGUST("guest user size to copy PSHTP 0x%lx PCSHTP 0x%lx\n",
		ps_copy, pcs_copy);
	ps_ind = g_stacks->psp_hi.PSP_hi_ind;
	if (ps_ind > 0) {
		/* first part of procedure stack was alredy copied */
		ps_copy -= ps_ind;
		E2K_KVM_BUG_ON(ps_copy < 0);
	}
	pcs_ind = g_stacks->pcsp_hi.PCSP_hi_ind;
	if (pcs_ind > 0) {
		/* first part of chain stack was alredy copied */
		pcs_copy -= pcs_ind;
		E2K_KVM_BUG_ON(pcs_copy < 0);
	}

	/*
	 * Copy part of guest user stacks that were SPILLed into kernel stacks
	 */
	ret = pv_vcpu_hw_stacks_copy(vcpu, regs, ps_copy, pcs_copy,
						 ps_ind,  pcs_ind);
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
		void __user *u_frame, e2k_mem_crs_t *crs)
{
	hva_t hva;
	unsigned long ts_flag;
	int ret;
	kvm_arch_exception_t exception;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)u_frame, true, &exception);
	if (kvm_is_error_hva(hva)) {
		pr_err("%s(): failed to find GPA for dst %lx GVA, "
				"inject page fault to guest\n",
				__func__, u_frame);
		kvm_vcpu_inject_page_fault(vcpu, (void *)u_frame,
					&exception);
		return -EAGAIN;
	}

	u_frame = (void *)hva;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __copy_to_user(u_frame, crs, sizeof(*crs));
	clear_ts_flag(ts_flag);
	if (unlikely(ret)) {
		pr_err("%s(): copy CRS frame to guest kernel stack failed, "
			"error %d\n",
			__func__, ret);
		return -EFAULT;
	}

	return 0;
}

unsigned long kvm_add_ctx_signal_stack(struct kvm_vcpu *vcpu, u64 key,
					bool is_main);

void kvm_remove_ctx_signal_stack(struct kvm_vcpu *vcpu, u64 key);

#endif	/* __KVM_PROCESS_H */
