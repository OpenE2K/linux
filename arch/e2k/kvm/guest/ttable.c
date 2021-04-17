/*
 *
 * Copyright (C) 2001 MCST
 */

/*
 * Simple E2K KVM guest trap table.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/process.h>
#include <asm/syscalls.h>
#include <asm/fast_syscalls.h>
#include <asm/ptrace.h>
#include <asm/traps.h>
#include <asm/trap_table.h>
#include <asm/regs_state.h>
#include <asm/aau_regs.h>
#include <asm/aau_context.h>
#include <asm/switch_to.h>
#include <asm/e2k_debug.h>

#include <asm/kvm/hypercall.h>
#include <asm/kvm/cpu_regs_access.h>
#include <asm/kvm/aau_regs_access.h>
#include <asm/kvm/mmu_regs_access.h>
#include <asm/kvm/guest/traps.h>
#include <asm/kvm/guest/trap_table.h>
#include <asm/kvm/guest/regs_state.h>

#include "cpu.h"
#include "traps.h"
#include "fast_syscalls.h"

/**************************** DEBUG DEFINES *****************************/


#undef	DEBUG_GUEST_TRAPS
#undef	DebugGT
#define	DEBUG_GUEST_TRAPS	0	/* guest traps trace */
#define	DebugGT(fmt, args...)						\
({									\
	if (DEBUG_GUEST_TRAPS)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

bool debug_ustacks = false;

/*********************************************************************/
static inline void switch_to_guest_kernel_stacks(void)
{
	if (KVM_READ_SBR_REG_VALUE() < GUEST_TASK_SIZE) {
		thread_info_t	*thread_info;
		hw_stack_t	*hw_stacks;
		e2k_usd_hi_t	usd_hi;
		e2k_usd_lo_t	usd_lo;
		e2k_psp_hi_t	psp_hi;
		e2k_pcsp_hi_t	pcsp_hi;

		/* switch to kernel data stack */
		thread_info = current_thread_info();
		usd_lo = thread_info->k_usd_lo;
		usd_hi = thread_info->k_usd_hi;
		KVM_WRITE_USD_REG(usd_hi, usd_lo);
		KVM_WRITE_SBR_REG_VALUE(
			((u64)current->stack + KERNEL_C_STACK_SIZE));
		/* increment hardware stacks sizes on kernel resident part */
		hw_stacks = &thread_info->u_hw_stack;
		psp_hi = KVM_READ_PSP_HI_REG();
		pcsp_hi = KVM_READ_PCSP_HI_REG();
#if 0	/* now guest kernel does not increment hardware stacks on guest */
	/* kernel reserve part */
		psp_hi.PSP_hi_size += kvm_get_hw_ps_guest_limit(hw_stacks);
		pcsp_hi.PCSP_hi_size += kvm_get_hw_pcs_guest_limit(hw_stacks);
		KVM_FLUSHCPU;
		KVM_WRITE_PSP_HI_REG(psp_hi);
		KVM_WRITE_PCSP_HI_REG(pcsp_hi);
		kvm_set_hw_ps_guest_reserved(hw_stacks,
			kvm_get_hw_ps_guest_limit(hw_stacks));
		kvm_set_hw_pcs_guest_reserved(hw_stacks,
			kvm_get_hw_pcs_guest_limit(hw_stacks));
#endif	/* 0 */	/* now guest kernel does not increment hardware stacks */
	/* on guest kernel reserve part */
	}
}
void kvm_correct_trap_psp_pcsp(struct pt_regs *regs,
					thread_info_t *thread_info)
{
	pr_err("%s(): is not implemented\n", __func__);
}
void kvm_correct_scall_psp_pcsp(struct pt_regs *regs,
					thread_info_t *thread_info)
{
	pr_err("%s(): is not implemented\n", __func__);
}

void kvm_correct_trap_return_ip(struct pt_regs *regs, unsigned long return_ip)
{
	int ret;

	native_correct_trap_return_ip(regs, return_ip);
	ret = HYPERVISOR_correct_trap_return_ip(return_ip);
	if (ret) {
		pr_err("%s(): hypervisor could not coorect IP to return, "
			"error %d\n",
			__func__, ret);
		do_exit(SIGKILL);
	}
}

/*
 * The function return boolean value: there is interrupt (MI or NMI) as one
 * of trap to handle
 */
static unsigned long kvm_guest_save_tirs(trap_pt_regs_t *trap)
{
	int tir_no, TIRs_num;
	unsigned long TIR_hi, TIR_lo;
	unsigned long all_interrupts = 0;

	DebugGT("started\n");

	/*
	 * %sbbp LIFO stack is unfreezed by writing %TIR register,
	 * so it must be read before TIRs.
	 * FIXME: not implemented
	 */
	trap->sbbp = NULL;

	trap->nr_TIRs = KVM_READ_TIRs_num();
	for (tir_no = trap->nr_TIRs; tir_no >= 0; tir_no--) {
		TIR_hi = KVM_READ_TIR_HI_REG_VALUE();
		TIR_lo = KVM_READ_TIR_LO_REG_VALUE();
		trap->TIRs[tir_no].TIR_hi.TIR_hi_reg = TIR_hi;
		trap->TIRs[tir_no].TIR_lo.TIR_lo_reg = TIR_lo;
		all_interrupts |= TIR_hi;
	}
	KVM_WRITE_TIR_HI_REG_VALUE(0);
	wmb();	/* to wait clearing of TIRs_num counter at nenory */
	TIRs_num = KVM_READ_TIRs_num();
	if (TIRs_num >= 0) {
		pr_err("%s(): TIRs registers is not cleared, probably "
			"the host had in time to introduce recursive traps\n",
			__func__);
	}
	DebugGT("was saved %d TIRs\n", trap->nr_TIRs - tir_no);
	return all_interrupts;
}

static void kvm_guest_save_trap_cellar(pt_regs_t *regs)
{
	trap_pt_regs_t *trap = regs->trap;
	int tc_count = KVM_READ_MMU_TRAP_COUNT();
	int tc_entries = tc_count / 3;
	int tc_no;

	DebugGT("started, for TC count %d\n", tc_count);
	BUG_ON(tc_count % 3 != 0);
	BUG_ON(tc_entries > MAX_TC_SIZE);
	KVM_SAVE_TRAP_CELLAR(regs, trap);
	trap->tc_count = tc_count;
	trap->curr_cnt = -1;
	trap->ignore_user_tc = 0;
	trap->tc_called = 0;
	trap->from_sigreturn = 0;
	CLEAR_CLW_REQUEST_COUNT(regs);
	KVM_RESET_MMU_TRAP_COUNT();
	DebugGT("was saved %d TC entries\n", tc_no);
}

static void kvm_guest_save_stack_regs(pt_regs_t *regs)
{
	DebugGT("started\n");

	/* stacks registers */
	regs->wd.WD_reg = KVM_READ_WD_REG_VALUE();
	regs->stacks.usd_hi.USD_hi_half = KVM_READ_USD_HI_REG_VALUE();
	regs->stacks.usd_lo.USD_lo_half = KVM_READ_USD_LO_REG_VALUE();
	regs->stacks.top = KVM_READ_SBR_REG_VALUE();
	DebugGT("updated USD: base 0x%llx size 0x%x, top 0x%lx\n",
		regs->stacks.usd_lo.USD_lo_base,
		regs->stacks.usd_hi.USD_hi_size,
		regs->stacks.top);

	regs->crs.cr0_hi.CR0_hi_half = KVM_READ_CR0_HI_REG_VALUE();
	regs->crs.cr0_lo.CR0_lo_half = KVM_READ_CR0_LO_REG_VALUE();
	regs->crs.cr1_hi.CR1_hi_half = KVM_READ_CR1_HI_REG_VALUE();
	regs->crs.cr1_lo.CR1_lo_half = KVM_READ_CR1_LO_REG_VALUE();

	regs->stacks.psp_hi.PSP_hi_half = KVM_READ_PSP_HI_REG_VALUE();
	regs->stacks.psp_lo.PSP_lo_half = KVM_READ_PSP_LO_REG_VALUE();
	regs->stacks.pshtp.PSHTP_reg = KVM_READ_PSHTP_REG_VALUE();
	DebugGT("saved PSP: base 0x%llx size 0x%x, ind 0x%x, pshtp 0x%llx\n",
		regs->stacks.psp_lo.PSP_lo_base,
		regs->stacks.psp_hi.PSP_hi_size,
		regs->stacks.psp_hi.PSP_hi_ind,
		GET_PSHTP_MEM_INDEX(regs->stacks.pshtp));
	regs->stacks.pcsp_hi.PCSP_hi_half = KVM_READ_PCSP_HI_REG_VALUE();
	regs->stacks.pcsp_lo.PCSP_lo_half = KVM_READ_PCSP_LO_REG_VALUE();
	regs->stacks.pcshtp = KVM_READ_PCSHTP_REG_SVALUE();
	DebugGT("saved PCSP: base 0x%llx size 0x%x, ind 0x%x, pcshtp 0x%llx\n",
		regs->stacks.pcsp_lo.PCSP_lo_base,
		regs->stacks.pcsp_hi.PCSP_hi_size,
		regs->stacks.pcsp_hi.PCSP_hi_ind,
		PCSHTP_SIGN_EXTEND(regs->stacks.pcshtp));
	/* Control transfer registers */
	regs->ctpr1.CTPR_reg = KVM_READ_CTPR1_REG_VALUE();
	regs->ctpr2.CTPR_reg = KVM_READ_CTPR2_REG_VALUE();
	regs->ctpr3.CTPR_reg = KVM_READ_CTPR3_REG_VALUE();
	/* Cycles control registers */
	regs->lsr = KVM_READ_LSR_REG_VALUE();
	regs->ilcr = KVM_READ_ILCR_REG_VALUE();
}
#ifdef CONFIG_USE_AAU
static void kvm_save_guest_trap_aau_regs(trap_pt_regs_t *trap, e2k_aau_t *aau)
{
	e2k_aasr_t aasr;
	bool aau_fault = false;
	int i;

	aasr = kvm_read_aasr_reg();
	KVM_SAVE_AAU_MASK_REGS(aau, aasr);
	if (AS(aasr).iab)
		KVM_SAVE_AADS(aau);
	for (i = 0; i <= trap->nr_TIRs; i++) {
		if (GET_AA_TIRS(trap->TIRs[i].TIR_hi.TIR_hi_reg)) {
			aau_fault = true;
			break;
		}
	}

	if (AS(aasr).iab) {
		/* get descriptors & auxiliary registers */
		kvm_get_array_descriptors(aau);
		aau->aafstr = kvm_read_aafstr_reg_value();
	}

	if (AS(aasr).stb) {
		/* get synchronous part of APB */
		kvm_get_synchronous_part(aau);
	}
}
#else /* ! CONFIG_USE_AAU */
static inline void
kvm_save_guest_trap_aau_regs(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
}
#endif /* ! CONFIG_USE_AAU */

/*
 * Real restoring of stack and other CPU registers is made by host
 * Here it need modify VCPU stack registers which were updated by guest
 * into pt_regs structure.
 * VCPU registers emulated as memory copy and write to register updated
 * memory copy of register and set flag 'updated'. This flag is visible
 * to host, so host can update real CPU register state probably through
 * own pt_regs structure
 * FIXME: probably as optimization  it need add 'pt_regs updates flag'
 * to mark registers or other values which updated into structure by guest
 * and should be updated or take into account by host.
 */
static void kvm_guest_restore_stack_regs(pt_regs_t *regs)
{
	u64 updated = 0;

	DebugGT("started\n");

	KVM_WRITE_USD_HI_REG_VALUE(regs->stacks.usd_hi.USD_hi_half);
	KVM_WRITE_USD_LO_REG_VALUE(regs->stacks.usd_lo.USD_lo_half);
	KVM_WRITE_SBR_REG_VALUE(regs->stacks.top);
	UPDATE_CPU_REGS_FLAGS(updated, USD_UPDATED_CPU_REGS);
	DebugGT("updated USD: base 0x%llx size 0x%x, top 0x%lx\n",
		regs->stacks.usd_lo.USD_lo_base,
		regs->stacks.usd_hi.USD_hi_size,
		regs->stacks.top);

	/* hardware stacks cannot be updated or were already updated */
	DebugGT("regs PSP: base 0x%llx size 0x%x, ind 0x%x\n",
		regs->stacks.psp_lo.PSP_lo_base,
		regs->stacks.psp_hi.PSP_hi_size,
		regs->stacks.psp_hi.PSP_hi_ind);
	DebugGT("regs PCSP: base 0x%llx size 0x%x, ind 0x%x\n",
		regs->stacks.pcsp_lo.PCSP_lo_base,
		regs->stacks.pcsp_hi.PCSP_hi_size,
		regs->stacks.pcsp_hi.PCSP_hi_ind);

	/* chain registers can be updated by guest:
	 *  - user data stack expansion (but only cr1_hi.ussz)
	 *  - fixing page fault (cr0_hi.ip) */
	KVM_WRITE_CR0_HI_REG_VALUE(regs->crs.cr0_hi.CR0_hi_half);
	KVM_WRITE_CR0_LO_REG_VALUE(regs->crs.cr0_lo.CR0_lo_half);
	KVM_WRITE_CR1_HI_REG_VALUE(regs->crs.cr1_hi.CR1_hi_half);
	KVM_WRITE_CR1_LO_REG_VALUE(regs->crs.cr1_lo.CR1_lo_half);
	UPDATE_CPU_REGS_FLAGS(updated, CRS_UPDATED_CPU_REGS);
	DebugGT("updated CR: CR1_lo.wbs 0x%x, cr1_hi.ussz 0x%x\n",
		regs->crs.cr1_lo.CR1_lo_wbs,
		regs->crs.cr1_hi.CR1_hi_ussz);

	/* Control transfer registers will be restored by host */

	/* Cycles control registers will be restored by host */

	/* put updates flags to be visible by host */
	PUT_UPDATED_CPU_REGS_FLAGS(updated);
}

/*
 * Restore virtual copy of stack & CRs registers state based on
 * pt_regs structure in thr hope that this structure will always
 * updated if the registers should be changed in the system call
 * FIXME: it should be supported only for certain cases (syscalls)
 */
#ifdef	RESTORE_SYSCALL_REGS
static void kvm_restore_syscall_stack_regs(pt_regs_t *regs)
{
	u64 updated = 0;

	DebugGT("started\n");

	/* user data stacks registers */
	{
	unsigned long sbr = KVM_READ_SBR_REG_VALUE();
	unsigned long usd_lo = KVM_READ_USD_LO_REG_VALUE();
	unsigned long usd_hi = KVM_READ_USD_HI_REG_VALUE();

	if (usd_lo != regs->stacks.usd_lo.USD_lo_half ||
			usd_hi != regs->stacks.usd_hi.USD_hi_half ||
			sbr != regs->stacks.top) {
		KVM_WRITE_USD_HI_REG_VALUE(regs->stacks.usd_hi.USD_hi_half);
		KVM_WRITE_USD_LO_REG_VALUE(regs->stacks.usd_lo.USD_lo_half);
		KVM_WRITE_SBR_REG_VALUE(regs->stacks.top);
		UPDATE_CPU_REGS_FLAGS(updated, USD_UPDATED_CPU_REGS);
		DebugGT("updated USD: base 0x%llx size 0x%x, top 0x%lx\n",
			regs->stacks.usd_lo.USD_lo_base,
			regs->stacks.usd_hi.USD_hi_size,
			regs->stacks.top);
	}
	}

	{
	unsigned long psp_lo = KVM_READ_PSP_LO_REG_VALUE();
	e2k_psp_hi_t psp_hi = KVM_READ_PSP_HI_REG();
	e2k_pshtp_t pshtp = regs->stacks.pshtp;
	unsigned long pcsp_lo = KVM_READ_PCSP_LO_REG_VALUE();
	e2k_pcsp_hi_t pcsp_hi = KVM_READ_PCSP_HI_REG();
	e2k_pcshtp_t pcshtp = regs->stacks.pcshtp;

	/* hardware stacks cannot be updated or were already updated */
	if (psp_lo != regs->stacks.psp_lo.PSP_lo_half ||
			psp_hi.PSP_hi_ind !=
				regs->stacks.psp_hi.PSP_hi_ind -
					GET_PSHTP_MEM_INDEX(pshtp) ||
			psp_hi.PSP_hi_size !=
				regs->stacks.psp_hi.PSP_hi_size) {
		pr_err("%s(): proc stack regs updated:\n"
			"   PSP: base 0x%llx size 0x%x, ind 0x%x "
			"PSHTP 0x%llx\n",
			__func__,
			regs->stacks.psp_lo.PSP_lo_base,
			regs->stacks.psp_hi.PSP_hi_size,
			regs->stacks.psp_hi.PSP_hi_ind,
			GET_PSHTP_MEM_INDEX(pshtp));
		BUG_ON(true);
	}
	if (pcsp_lo != regs->stacks.pcsp_lo.PCSP_lo_half ||
			pcsp_hi.PCSP_hi_ind !=
				regs->stacks.pcsp_hi.PCSP_hi_ind -
					PCSHTP_SIGN_EXTEND(pcshtp) ||
			pcsp_hi.PCSP_hi_size !=
				regs->stacks.pcsp_hi.PCSP_hi_size) {
		pr_err("%s(): chain stack regs updated:\n"
			"   PCSP: base 0x%llx size 0x%x, ind 0x%x "
			"PCSHTP 0x%llx\n",
			__func__,
			regs->stacks.pcsp_lo.PCSP_lo_base,
			regs->stacks.pcsp_hi.PCSP_hi_size,
			regs->stacks.pcsp_hi.PCSP_hi_ind,
			PCSHTP_SIGN_EXTEND(pcshtp));
		BUG_ON(true);
	}
	}

	{
	unsigned long cr0_lo = KVM_READ_CR0_LO_REG_VALUE();
	unsigned long cr0_hi = KVM_READ_CR0_HI_REG_VALUE();
	unsigned long cr1_lo = KVM_READ_CR1_LO_REG_VALUE();
	unsigned long cr1_hi = KVM_READ_CR1_HI_REG_VALUE();

	/* chain registers can be updated by guest system calls:
	 *  - long jump */
	if (cr0_lo != regs->crs.cr0_lo.CR0_lo_half ||
			cr0_hi != regs->crs.cr0_hi.CR0_hi_half ||
			cr1_lo != regs->crs.cr1_lo.CR1_lo_half ||
			cr1_hi != regs->crs.cr1_hi.CR1_hi_half) {
		KVM_WRITE_CR0_HI_REG_VALUE(regs->crs.cr0_hi.CR0_hi_half);
		KVM_WRITE_CR0_LO_REG_VALUE(regs->crs.cr0_lo.CR0_lo_half);
		KVM_WRITE_CR1_HI_REG_VALUE(regs->crs.cr1_hi.CR1_hi_half);
		KVM_WRITE_CR1_LO_REG_VALUE(regs->crs.cr1_lo.CR1_lo_half);
		UPDATE_CPU_REGS_FLAGS(updated, CRS_UPDATED_CPU_REGS);
		DebugGT("updated CR: CR1_lo.wbs 0x%x, cr1_hi.ussz 0x%x\n",
			regs->crs.cr1_lo.CR1_lo_wbs,
			regs->crs.cr1_hi.CR1_hi_ussz);
	}
	}

	/* Control transfer registers will be restored by host */

	/* Cycles control registers will be restored by host */

	/* put updates flags to be visible by host */
	PUT_UPDATED_CPU_REGS_FLAGS(updated);
}
#endif	/* RESTORE_SYSCALL_REGS */

/*
 * Trap occured on user or kernel function but on user's stacks
 * So, it needs to switch to kernel stacks
 * WARNING: host should emulate right state of guest PSR:
 *	switch interrupts mask control to PSR;
 *	disable all interrupts mask;
 *	disable 'sge' mask to prevent stacks bounds traps while guest is
 * saving trap context and only guest enable the mask and traps
 * after saving completion.
 */
int kvm_trap_handler(void)
{
	pt_regs_t	pt_regs;
	trap_pt_regs_t	trap;
#ifdef CONFIG_USE_AAU
	e2k_aau_t	aau_context;
#endif /* CONFIG_USE_AAU */
	pt_regs_t	*regs = &pt_regs;
	thread_info_t	*thread_info = KVM_READ_CURRENT_REG();
	unsigned long	exceptions;
	e2k_psr_t	user_psr;
	e2k_upsr_t	user_upsr;
	bool		irqs_under_upsr;
	bool		in_user_mode;
	bool		has_irqs = false;
	struct task_struct *task = thread_info_task(thread_info);
	int		ret;

	preempt_disable();

	DebugGT("started\n");

#ifdef CONFIG_USE_AAU
	/* AAU context was saved and will be restored by host */
#endif /* CONFIG_USE_AAU */

	/*
	 * All actual pt_regs structures of the process are queued.
	 * The head of this queue is thread_info->pt_regs pointer,
	 * it points to the last (current) pt_regs structure.
	 * The current pt_regs structure points to the previous etc
	 * Queue is empty before first trap or system call on the
	 * any process and : thread_info->pt_regs == NULL
	 */
	trap.flags = 0;
	regs->kernel_entry = 0;
	regs->next = thread_info->pt_regs;
	regs->trap = &trap;
	regs->aau_context = &aau_context;
	thread_info->pt_regs = regs;

	KVM_SWITCH_TO_KERNEL_UPSR(user_psr, user_upsr, irqs_under_upsr,
					false,	/* enable IRQs */
					false);	/* disable nmi */

	/*
	 * Setup guest kernel global registers, pointer to the VCPU state
	 * has been restored by host and other gregs can be cleared,
	 * so restore anyway its state
	 */
	KVM_SAVE_GREGS_AND_SET(thread_info);

	/*
	 * See comments in ttable_entry4() for sc_restart
	 */
	regs->flags = 0;
	init_guest_traps_handling(regs, true	/* user mode trap */);

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	/* FIXME: secondary space support does not implemented for guest */
	/* trap.flags |= TRAP_RP_FLAG; */
#endif


	/* should be before setting user/kernel mode trap on */
	kvm_guest_save_stack_regs(regs);

	/*
	 * See common comments at arch/e2k/kernel/ttable.c user_trap_handler()
	 * Additional note: this trap handler called by host to handle injected
	 * traps on guest user or on guest kernel
	 */
	in_user_mode = kvm_trap_user_mode(regs);
	DebugGT("trap on %s\n", (in_user_mode) ? "user" : "kernel");

	/*
	 * Now we can store all needed trap context into the
	 * current pt_regs structure
	 */
	exceptions = kvm_guest_save_tirs(&trap);
	if (exceptions & (exc_interrupt_mask | exc_nm_interrupt_mask))
		has_irqs = true;

	kvm_guest_save_trap_cellar(regs);

	kvm_save_guest_trap_aau_regs(&trap, &aau_context);

	/* user context was saved, so enable traps on hardware stacks bounds */
	kvm_set_sge();

	/* unfreeze TIRs & trap cellar on host */
	HYPERVISOR_unfreeze_guest_traps();

	/* any checkers with BUG() can be run only after unfreezing TIRs */
	kvm_check_vcpu_id();
	KVM_CHECK_IRQ_STATE(user_psr, user_upsr, irqs_under_upsr,
				has_irqs, in_user_mode);
	if (DEBUG_GUEST_TRAPS)
		print_pt_regs(regs);

	preempt_enable();

	if (unlikely(trap.nr_TIRs < 0)) {
		/* guest has nothing traps and handler was called only */
		/* to copy spilled gueest user part of hardware stacks */
		/* from guest kernel stacks */
		;
		if (DEBUG_USER_STACKS_MODE)
			debug_ustacks = true;
	} else {
		parse_TIR_registers(regs, exceptions);
	}

	DebugGT("all TIRs parsed\n");

	/* parse_TIR_registers() returns with interrupts disabled */
	local_irq_enable();

	if (regs->deferred_traps)
		kvm_handle_deferred_traps(regs);

	if (in_user_mode) {
		u64 wsz = get_wsz(FROM_USER_TRAP);

		ret = kvm_user_hw_stacks_prepare(&regs->stacks, regs,
						 wsz, FROM_USER_TRAP, false);
		if (ret != 0) {
			do_exit(SIGKILL);
		}
	}

	/* here we do signal handling */
	while (unlikely(in_user_mode &&
			!test_delayed_signal_handling(task, thread_info) &&
				signal_pending(task))) {

		DebugGT("will start signal handling\n");
		do_signal(regs);
		/*
		 * We can be here on the new stack and new process,
		 * if signal handler made fork()
		 * So we should reset all pointers
		 */
		thread_info = current_thread_info();
		task = current;
		regs = thread_info->pt_regs;

		/* traps can occur while signal handling and were deferred */
		if (regs->deferred_traps)
			kvm_handle_deferred_traps(regs);
	}

	/* and here we do tasks re-scheduling on a h/w interrupt */
	/* FIXME in case of host_trap_on_guest, received at the end of guest's
	 * signal handler, scheduling ends in panic, caused by
	 * WARN_ON(gti->gregs_active && !gti->gregs_for_currents_valid) in
	 * switch_guest_thread_stacks(). Work around this by checking the
	 * trap_from_host_kernel_mode.
	 */
	if (in_user_mode && !in_interrupt() && need_resched() /*&&
		!trap_from_host_kernel_mode(regs)*/) {
		DebugGT("will start re-scheduling\n");
		schedule();
		DebugGT("re-scheduling completed\n");

		/* traps can occur while scheduling and were deferred */
		if (regs->deferred_traps)
			kvm_handle_deferred_traps(regs);
	}

	if (in_user_mode && test_thread_flag(TIF_NOTIFY_RESUME)) {
		clear_thread_flag(TIF_NOTIFY_RESUME);
		do_notify_resume(regs);
	}

	local_irq_disable();
	/*
	 * Dequeue current pt_regs structure and previous
	 * regs will be now actuale
	 */
	if (regs->deferred_traps)
		kvm_handle_deferred_traps(regs);
	thread_info->pt_regs = regs->next;
	regs->next = NULL;

	/* FIXME: Stack registers can be updated by not all traps handlers, */
	/* so it need here traps mask & conditional statement before the */
	/* follow restore of stack & system registers */
	kvm_guest_restore_stack_regs(regs);
/*	RETURN_TO_USER_PSP_PCSP(thread_info);	no increment of hw stacks */

	/* global regs will be restored by host */

#ifdef CONFIG_USE_AAU
	/* Only host should save/restore of AAU */
#endif

	KVM_RETURN_TO_USER_UPSR(user_upsr, irqs_under_upsr);

	DebugGT("returns with GUEST_TRAP_HANDLED\n");

	return GUEST_TRAP_HANDLED;
}

/*
 * WARNING: host should emulate right state of guest PSR:
 *	switch interrupts mask control to PSR;
 *	disable all interrupts mask;
 * INTERNAL AGREEMENT HOST <-> GUEST: hardware does not update but host should:
 *	disable 'sge' mask to prevent stacks bounds traps while guest is
 * saving trap context and only guest enable the mask and traps
 * after saving completion.
 */
static noinline long kvm_guest_sys_call32(long sys_num_and_entry,
			u32 arg1, u32 arg2,
			u32 arg3, u32 arg4,
			u32 arg5, u32 arg6)
{
	pt_regs_t	pt_regs;
	pt_regs_t	*regs = &pt_regs;
	system_call_func sys_func;
	int		sys_num = sys_num_and_entry & 0xffffffff;
	int		entry = sys_num_and_entry >> 32;
	long		rval;

	sys_func = sys_call_table_32[sys_num];
	/* set IS 32 system call bit at function label */
	sys_func = (system_call_func) ((unsigned long)sys_func | (1UL << 56));

	/* SBR should be saved here because of syscall handlers can use */
	/* this value at user_mode() macros to determine source of calling */
	regs->stacks.top = KVM_READ_SBR_REG_VALUE();
	/* USD is restored in restore_hard_sys_calls() */
	regs->stacks.usd_hi.USD_hi_half = KVM_READ_USD_HI_REG_VALUE();
	regs->stacks.usd_lo.USD_lo_half = KVM_READ_USD_LO_REG_VALUE();
	regs->sys_num = sys_num;
	regs->kernel_entry = entry;

	rval = handle_sys_call(sys_func,
			arg1, arg2, arg3, arg4, arg5, arg6, regs);

	/* set virtual copy of stack & CRs registers state based on */
	/* pt_regs structure in thr hope that this structure will always */
	/* updated if the registers should be changed in the system call */
	/* FIXME: it should be supported only for certain cases (syscalls)
	kvm_restore_syscall_stack_regs(regs);
	 */

	return rval;
}

static noinline long kvm_guest_sys_call64(long sys_num_and_entry,
			u64 arg1, u64 arg2,
			u64 arg3, u64 arg4,
			u64 arg5, u64 arg6)
{
	pt_regs_t	pt_regs;
	pt_regs_t	*regs = &pt_regs;
	system_call_func sys_func;
	int		sys_num = sys_num_and_entry & 0xffffffff;
	int		entry = sys_num_and_entry >> 32;
	long		rval;

	sys_func = sys_call_table[sys_num];
	/* clear IS 32 system call bit at function label */
	sys_func = (system_call_func) ((unsigned long)sys_func & ~(1UL << 56));

	/* SBR should be saved here because of syscall handlers can use */
	/* this value at user_mode() macros to determine source of calling */
	regs->stacks.top = KVM_READ_SBR_REG_VALUE();
	/* USD is restored in restore_hard_sys_calls() */
	regs->stacks.usd_hi.USD_hi_half = KVM_READ_USD_HI_REG_VALUE();
	regs->stacks.usd_lo.USD_lo_half = KVM_READ_USD_LO_REG_VALUE();
	regs->sys_num = sys_num;
	regs->kernel_entry = entry;

	rval = handle_sys_call(sys_func,
			arg1, arg2, arg3, arg4, arg5, arg6, regs);

	/* set virtual copy of stack & CRs registers state based on */
	/* pt_regs structure in thr hope that this structure will always */
	/* updated if the registers should be changed in the system call */
	/* FIXME: it should be supported only for certain cases (syscalls)
	kvm_restore_syscall_stack_regs(regs);
	 */

	return rval;
}

static noinline long kvm_guest_sys_call64_or_32(long sys_num_and_entry,
			u64 arg1, u64 arg2,
			u64 arg3, u64 arg4,
			u64 arg5, u64 arg6)
{
	pt_regs_t	pt_regs;
	pt_regs_t	*regs = &pt_regs;
	const system_call_func *sys_calls_table;
	system_call_func sys_func;
	int		sys_num = sys_num_and_entry & 0xffffffff;
	int		entry = sys_num_and_entry >> 32;
	bool		depr_scall = (sys_num < 0) ? true : false;
	bool		scall_32;
	long		rval;

	scall_32 = (current->thread.flags & E2K_FLAG_32BIT) != 0;
	if (depr_scall)
		sys_num = -sys_num;

	if (scall_32)
		sys_calls_table = sys_call_table_32;
	else if (depr_scall)
		sys_calls_table = sys_call_table_deprecated;
	else
		sys_calls_table = sys_call_table;

	sys_func = sys_calls_table[sys_num];
	if (scall_32)
		/* set IS 32 system call bit at function label */
		sys_func = (system_call_func) ((unsigned long)sys_func |
								(1UL << 56));
	else
		/* clear IS 32 system call bit at function label */
		sys_func = (system_call_func) ((unsigned long)sys_func &
								~(1UL << 56));

	/* SBR should be saved here because of syscall handlers can use */
	/* this value at user_mode() macros to determine source of calling */
	regs->stacks.top = KVM_READ_SBR_REG_VALUE();
	/* USD is restored in restore_hard_sys_calls() */
	regs->stacks.usd_hi.USD_hi_half = KVM_READ_USD_HI_REG_VALUE();
	regs->stacks.usd_lo.USD_lo_half = KVM_READ_USD_LO_REG_VALUE();
	regs->sys_num = sys_num;
	regs->kernel_entry = entry;

	rval = handle_sys_call(sys_func,
			arg1, arg2, arg3, arg4, arg5, arg6, regs);

	/* set virtual copy of stack & CRs registers state based on */
	/* pt_regs structure in thr hope that this structure will always */
	/* updated if the registers should be changed in the system call */
	/* FIXME: it should be supported only for certain cases (syscalls)
	kvm_restore_syscall_stack_regs(regs);
	 */

	return rval;
}

static __interrupt __always_inline int
kvm_guest_fast_sys_call32(int sys_num, u64 arg1, u64 arg2)
{
	kvm_fast_system_call_func func;
	int ret;

	func = kvm_fast_sys_calls_table_32[sys_num & NR_fast_syscalls_mask];
	ret = func(arg1, arg2);
	return ret;
}

static __interrupt __always_inline int
kvm_guest_fast_sys_call64(int sys_num, u64 arg1, u64 arg2)
{
	kvm_fast_system_call_func func;
	int ret;

	func = kvm_fast_sys_calls_table[sys_num & NR_fast_syscalls_mask];
	ret = func(arg1, arg2);
	return ret;
}

/* FIXME: protected fast system calls are not implemented */

/*********************************************************************/

/*
 * The following function should do about the same as assembler part of host
 * system calls entries.
 * To make it on assembler too is not good idea, because of guest operates with
 * virtual CPU hardware (for example, registers are emulated as memory)
 * So it is the same as unprivileged user function
 */
static inline thread_info_t *sys_call_prolog(int sys_num)
{
	thread_info_t *ti = KVM_READ_CURRENT_REG();

	/* save hardware stacks registers at thread info */
	/* same as on host to use the same kernel interface */
	KVM_SAVE_HW_STACKS_AT_TI(ti);

	/* save user gregs and set kernel state of all global registers */
	/* used by kernel to optimize own actions */
	KVM_SAVE_GREGS_AND_SET(ti);
	kvm_check_vcpu_id();

	/*
	 * Host emulates hardware behavior and disables interrupts mask in PSR,
	 * before calling guest system calls entries.
	 * PSR becomes main register to control interrupts.
	 * Save user UPSR state and set kernel UPSR state to enable all
	 * interrupts. But switch control from PSR register to UPSR
	 * will be some later.
	 */
	KVM_DO_SAVE_UPSR_REG(ti->upsr);
	KVM_WRITE_UPSR_REG(E2K_KERNEL_UPSR_ENABLED);

	return ti;
}

/* trap table entry #0 is allways traps/interrupts guest kernel entry */

#define __kvm_guest_ttable_entry0__	\
		__attribute__((__section__(".kvm_guest_ttable_entry0")))

int __kvm_guest_ttable_entry0__
kvm_guest_ttable_entry0(void)
{
	thread_info_t *ti = KVM_READ_CURRENT_REG();
	int ret;

	DebugGT("started guest kernel traps entry\n");
	if (ti == NULL || test_ti_thread_flag(ti, TIF_PSEUDOTHREAD)) {
		DebugGT("guest traps cannot be handled: none or empty current "
			"thread info structure\n");
		return GUEST_TRAP_NOT_HANDLED;
	}
	KVM_SAVE_GREGS_AND_SET(ti);

	/*
	 * Hardware trap operation disables interrupts mask in PSR
	 * and PSR becomes main register to control interrupts.
	 * Switch control from PSR register to UPSR, if UPSR
	 * interrupts control is used and all following trap handling
	 * will be executed under UPSR control
	 * FIXME: guest kernel executes under enabled interrupts,
	 * so it need emulate PSR/UPSR control swicth???
	 */
/*	DO_SWITCH_TO_KERNEL_UPSR(upsr_to_save, 0);	*/

	ret = kvm_trap_handler();

	/*
	 * Return control from UPSR register to PSR, if UPSR
	 * interrupts control is used.
	 * DONE operation restores PSR state at trap point and
	 * recovers interrupts control
	 *
	 * This also disables all interrupts including NMIs.
	 */
/*	RESTORE_USER_UPSR(upsr_to_save);	*/

	/* host saved global register and will restore its */
	return ret;
}

#define __kvm_pv_vcpu_ttable_entry0__	\
		__attribute__((__section__(".kvm_pv_vcpu_ttable_entry0")))

void __interrupt __kvm_pv_vcpu_ttable_entry0__
kvm_pv_vcpu_ttable_entry0(void)
{
	E2K_JUMP(kvm_trap_handler);
}

/* trap table entry #1 is common 32 bits system calls entry */

#define __kvm_guest_ttable_entry1__	\
		__attribute__((__section__(".kvm_guest_ttable_entry1")))

long __kvm_guest_ttable_entry1__
kvm_guest_ttable_entry1(int sys_num,
		u32 arg1, u32 arg2, u32 arg3, u32 arg4, u32 arg5, u32 arg6)
{
	sys_call_prolog(sys_num);

	/* host saved global register and will restore its */
	return (kvm_guest_sys_call32(sys_num | (1UL << 32),
			arg1, arg2, arg3, arg4, arg5, arg6));
}

/* trap table entry #3 is common 64 bits system calls entry */

#define __kvm_guest_ttable_entry3__	\
		__attribute__((__section__(".kvm_guest_ttable_entry3")))

long __kvm_guest_ttable_entry3__
kvm_guest_ttable_entry3(int sys_num,
			u64 arg1, u64 arg2,
			u64 arg3, u64 arg4,
			u64 arg5, u64 arg6)
{
	sys_call_prolog(sys_num);

	/* host saved global register and will restore its */
	return (kvm_guest_sys_call64(sys_num | (3UL << 32),
			arg1, arg2, arg3, arg4, arg5, arg6));
}

/* trap table entry #4 is common 32 or 64 bits system calls entry */

#define __kvm_guest_ttable_entry4__	\
		__attribute__((__section__(".kvm_guest_ttable_entry4")))

long __kvm_guest_ttable_entry4__
kvm_guest_ttable_entry4(int sys_num,
			u64 arg1, u64 arg2,
			u64 arg3, u64 arg4,
			u64 arg5, u64 arg6)
{
	sys_call_prolog(sys_num);

	/* host saved global register and will restore its */
	return kvm_guest_sys_call64_or_32(sys_num | (4UL << 32),
			arg1, arg2, arg3, arg4, arg5, arg6);
}

/* trap table entry #5 is fast 32 bits system calls entry */

#define __kvm_guest_ttable_entry5__	\
		__attribute__((__section__(".kvm_guest_ttable_entry5")))

long __interrupt __kvm_guest_ttable_entry5__
kvm_guest_ttable_entry5(int sys_num,
			u64 arg1, u64 arg2,
			u64 arg3, u64 arg4,
			u64 arg5, u64 arg6)
{
	int ret;

	ret = kvm_guest_fast_sys_call32(sys_num, arg1, arg2);
	return ret;
}

/* trap table entry #6 is fast 64 bits system calls entry */

#define __kvm_guest_ttable_entry6__	\
		__attribute__((__section__(".kvm_guest_ttable_entry6")))

long __interrupt __kvm_guest_ttable_entry6__
kvm_guest_ttable_entry6(int sys_num,
			u64 arg1, u64 arg2,
			u64 arg3, u64 arg4,
			u64 arg5, u64 arg6)
{
	int ret;

	ret = kvm_guest_fast_sys_call64(sys_num, arg1, arg2);
	return ret;
}

/* Pseudo SCALL 32 is used as a guest kernel jumpstart. */

#ifdef	CONFIG_PARAVIRT_GUEST
static	atomic_t __initdata boot_paravirt_init_finished = ATOMIC_INIT(0);
#endif	/* CONFIG_PARAVIRT_GUEST */

#define __ttable_entry32__	\
		__attribute__((__section__(".kvm_guest_startup_entry")))

void  notrace __ttable_entry32__
kvm_guest_startup_entry(int bsp, bootblock_struct_t *bootblock)
{
	unsigned long vcpu_base;

#ifdef	CONFIG_PARAVIRT_GUEST
	cur_pv_v2p_ops = &kvm_v2p_ops;
	if (bsp) {
		kvm_init_paravirt_guest();
#ifdef	CONFIG_SMP
		boot_set_event(&boot_paravirt_init_finished);
	} else {
		boot_wait_for_event(&boot_paravirt_init_finished);
#endif	/* CONFIG_SMP */
	}
#endif	/* CONFIG_PARAVIRT_GUEST */
	/* VCPU state base can be on global register, so save & restore */
	KVM_SAVE_VCPU_STATE_BASE(vcpu_base);
	NATIVE_BOOT_INIT_G_REGS();
	KVM_RESTORE_VCPU_STATE_BASE(vcpu_base);

	boot_startup(bsp, bootblock);
}
