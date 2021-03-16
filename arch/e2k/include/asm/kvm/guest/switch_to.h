#ifndef _ASM_KVM_GUEST_SWITCH_TO_H
#define _ASM_KVM_GUEST_SWITCH_TO_H

#ifdef __KERNEL__

#include <linux/types.h>
#include <asm/mmu_context.h>
#include <asm/regs_state.h>
#include <asm/kvm/guest/process.h>

#undef	DEBUG_KVM_SWITCH_MODE
#undef	DebugKVMSW
#define	DEBUG_KVM_SWITCH_MODE	0	/* KVM switching debugging */
#define	DebugKVMSW(fmt, args...)					\
({									\
	if (DEBUG_KVM_SWITCH_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#define	KVM_UPSR_NMI_SAVE_AND_CLI(flags)			\
({								\
	flags = KVM_READ_UPSR_REG_VALUE();			\
	KVM_WRITE_UPSR_REG_VALUE(flags & ~UPSR_NMIE);		\
})
#define	KVM_RESTORE_USER_UPSR(user_upsr)			\
({								\
	KVM_WRITE_UPSR_REG_VALUE(user_upsr);			\
})

static inline struct task_struct *
kvm_ret_from_fork_get_prev_task(struct task_struct *prev)
{
	prev = current->thread.sw_regs.prev_task;
	BUG_ON(prev == NULL);
	return prev;
}

static inline void
KVM_SAVE_TASK_STACKS_REGS_TO_SWITCH(struct task_struct *task, int save_ip)
{
	struct sw_regs *sw_regs = &task->thread.sw_regs;
	unsigned long usd_lo;
	unsigned long usd_hi;

	ATOMIC_DO_SAVE_ALL_STACKS_REGS(sw_regs,
		&sw_regs->crs.cr1_hi, usd_lo, usd_hi);

	sw_regs->usd_lo.USD_lo_half = usd_lo;
	sw_regs->usd_hi.USD_hi_half = usd_hi;
	sw_regs->top = NATIVE_NV_READ_SBR_REG_VALUE();
	sw_regs->crs.cr1_lo = NATIVE_NV_READ_CR1_LO_REG();
	if (likely(save_ip)) {
		sw_regs->crs.cr0_lo = NATIVE_NV_READ_CR0_LO_REG();
		sw_regs->crs.cr0_hi = NATIVE_NV_READ_CR0_HI_REG();
	}
}
static inline void
KVM_SAVE_TASK_REGS_TO_SWITCH(struct task_struct *task, int save_ip)
{

	/* Save interrupt mask state and disable NMIs */
	KVM_UPSR_NMI_SAVE_AND_CLI(AW(task->thread.sw_regs.upsr));

	KVM_SAVE_TASK_STACKS_REGS_TO_SWITCH(task, save_ip);

	/* global registers and user registers */
	/* will be saved by host kernel while real switch */

}

/*
 * now lcc has problem with structure on registers
 * (It move these structures is stack memory)
 */
static inline void
KVM_RESTORE_TASK_STACKS_REGS_TO_SWITCH(struct task_struct *task, int restore_ip)
{
	u64	sbr = task->thread.sw_regs.top;
	u64	usd_lo = AS_WORD(task->thread.sw_regs.usd_lo);
	u64	usd_hi = AS_WORD(task->thread.sw_regs.usd_hi);
	u64	psp_lo = AS_WORD(task->thread.sw_regs.psp_lo);
	u64	psp_hi = AS_WORD(task->thread.sw_regs.psp_hi);
	u64	pcsp_lo = AS_WORD(task->thread.sw_regs.pcsp_lo);
	u64	pcsp_hi = AS_WORD(task->thread.sw_regs.pcsp_hi);
	u64	cr_wd = AS_WORD(task->thread.sw_regs.crs.cr1_lo);
	u64	cr_ussz = AS_WORD(task->thread.sw_regs.crs.cr1_hi);

	KVM_FLUSHCPU;

	KVM_WRITE_USBR_USD_REG_VALUE(sbr, usd_hi, usd_lo);
	KVM_WRITE_PSP_REG_VALUE(psp_hi, psp_lo);
	KVM_WRITE_PCSP_REG_VALUE(pcsp_hi, pcsp_lo);

	KVM_WRITE_CR1_LO_REG_VALUE(cr_wd);
	KVM_WRITE_CR1_HI_REG_VALUE(cr_ussz);
	if (unlikely(restore_ip)) {
		KVM_WRITE_CR0_LO_REG_VALUE(AW(task->thread.sw_regs.crs.cr0_lo));
		KVM_WRITE_CR0_HI_REG_VALUE(AW(task->thread.sw_regs.crs.cr0_hi));
	}
}
static inline void
KVM_RESTORE_TASK_REGS_TO_SWITCH(struct task_struct *task, int restore_ip)
{
	KVM_RESTORE_TASK_STACKS_REGS_TO_SWITCH(task, restore_ip);

	/* global registers and user registers */
	/* will be restored by host kernel while real switch */

	/* Enable interrupt */
	KVM_RESTORE_USER_UPSR(task->thread.sw_regs.upsr.UPSR_reg);
}

static __always_inline struct task_struct *
kvm_do_switch_to(struct task_struct *prev, struct task_struct *next)
{
	thread_info_t	*next_ti = task_thread_info(next);
	struct sw_regs *sw_regs;
	e2k_size_t	ps_size;
	e2k_size_t	ps_ind;
	e2k_size_t	pcs_size;
	e2k_size_t	pcs_ind;

	DebugKVMSW("started on VCPU #%d to switch %s(%d/%d) parent %s (%d) "
		"-> %s(%d/%d) parent %s (%d)\n",
		smp_processor_id(), prev->comm, prev->pid,
		task_thread_info(prev)->gpid_nr,
		prev->real_parent->comm, prev->real_parent->pid,
		next->comm, next->pid, task_thread_info(next)->gpid_nr,
		next->real_parent->comm, next->real_parent->pid);

	/* Save interrupt mask state and disable NMIs */
	UPSR_ALL_SAVE_AND_CLI(AW(prev->thread.sw_regs.upsr));

	ATOMIC_GET_HW_STACK_SIZES(ps_ind, ps_size, pcs_ind, pcs_size);
	DebugKVMSW("prev task PS ind 0x%lx size 0x%lx\n",
		ps_ind, ps_size);
	DebugKVMSW("prev task PCS ind 0x%lx size 0x%lx\n",
		pcs_ind, pcs_size);
	if (ps_ind + MAX_SRF_SIZE >= ps_size ||
			pcs_ind + SZ_OF_CR >= pcs_size) {
		/*
		 * Hardware stack(s) overflow and need expand stack(s)
		 * before switching to new process to avoid trap in
		 * hypercall while switch will be in progress.
		 * Provoke to trap now to handle stack bounds exception
		 */
		KVM_COPY_STACKS_TO_MEMORY();
		DebugKVMSW("copy stacks to memory to trap on bounds\n");
	}
	KVM_SAVE_TASK_REGS_TO_SWITCH(prev, 1);
	sw_regs = &prev->thread.sw_regs;
	DebugKVMSW("prev task regs saved: PS base 0x%llx ind 0x%x size 0x%x\n",
		sw_regs->psp_lo.PSP_lo_base,
		sw_regs->psp_hi.PSP_hi_ind, sw_regs->psp_hi.PSP_hi_size);
	DebugKVMSW("prev task regs saved: PCS base 0x%llx ind 0x%x size 0x%x\n",
		sw_regs->pcsp_lo.PCSP_lo_base,
		sw_regs->pcsp_hi.PCSP_hi_ind, sw_regs->pcsp_hi.PCSP_hi_size);
	sw_regs = &next->thread.sw_regs;
	DebugKVMSW("next task regs saved: PS base 0x%llx ind 0x%x size 0x%x\n",
		sw_regs->psp_lo.PSP_lo_base,
		sw_regs->psp_hi.PSP_hi_ind, sw_regs->psp_hi.PSP_hi_size);
	DebugKVMSW("next task regs saved: PCS base 0x%llx ind 0x%x size 0x%x\n",
		sw_regs->pcsp_lo.PCSP_lo_base,
		sw_regs->pcsp_hi.PCSP_hi_ind, sw_regs->pcsp_hi.PCSP_hi_size);

	set_current_thread_info(next_ti, next);

	KVM_RESTORE_TASK_REGS_TO_SWITCH(next, 0);

	/* remember previous task to restore after real switch */
	sw_regs->prev_task = prev;

	/* real switch guest kernel stacks can be done only by hypervisor */
	DebugKVMSW("will start hypercall to switch real guest thread stacks\n");
	HYPERVISOR_switch_guest_thread_stacks(
			next_ti->gpid_nr, next_ti->gmmid_nr);

	/* reload locals after hardware and local data stack switch */
	/* now its state contain previous switch from the current */
	next = current;
	prev = current->thread.sw_regs.prev_task;

	/* Restore interrupt mask and enable NMIs */
	UPSR_RESTORE(AW(current->thread.sw_regs.upsr));

	/* return actualized structure of previous task */
	return prev;
}

#define kvm_switch_to(prev, next, last)			\
do {							\
	if (IS_HV_GM()) {				\
		native_switch_to(prev, next, last);	\
	} else {					\
		last = kvm_do_switch_to(prev, next);	\
		e2k_finish_switch(last);		\
	}						\
} while (0)

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */

static inline struct task_struct *
ret_from_fork_get_prev_task(struct task_struct *prev)
{
	return kvm_ret_from_fork_get_prev_task(prev);
}

/* switch_to() should be only macros to update pointer 'prev' at */
/* __schedule() function */
#define	switch_to(prev, next, last)	kvm_switch_to(prev, next, last)

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* __KERNEL__ */

#endif /* _ASM_KVM_GUEST_SWITCH_TO_H */
