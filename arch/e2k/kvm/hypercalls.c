/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Just as userspace programs request kernel operations through a system
 * call, the Guest requests Host operations through a "hypercall".  You might
 * notice this nomenclature doesn't really follow any logic, but the name has
 * been around for long enough that we're stuck with it.  As you'd expect, this
 * code is basically a one big switch statement.
 */

#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/kvm_host.h>
#include <linux/pgtable.h>

#include <asm/page.h>
#include <asm/regs_state.h>
#include <asm/tlb_regs_access.h>
#include <asm/trap_table.h>
#include <asm/process.h>
#include <asm/fast_syscalls.h>

#include <asm/kvm/mm.h>
#include <asm/kvm/runstate.h>
#include <asm/kvm/switch.h>
#include <asm/kvm/trace_kvm.h>
#include <asm/kvm/proc_context_stacks.h>

#include "process.h"
#include "cpu.h"
#include "mmu.h"
#include "irq.h"
#include "io.h"
#include "mman.h"
#include "time.h"
#include "string.h"
#include "trace-tlb-flush.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE		0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SWITCH_MODE
#undef	DebugKVMSW
#define	DEBUG_KVM_SWITCH_MODE	false	/* guest thread switch debugging */
#define	DebugKVMSW(fmt, args...)					\
({									\
	if (DEBUG_KVM_SWITCH_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SWITCH_HEAD_MODE
#undef	DebugKVMSWH
#define	DEBUG_KVM_SWITCH_HEAD_MODE	false	/* guest thread switch head */
#define	DebugKVMSWH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SWITCH_HEAD_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SWITCH_VCPU_MODE
#undef	DebugSWVCPU
#define	DEBUG_KVM_SWITCH_VCPU_MODE	false	/* guest thread switch to */
						/* other VCPU */
#define	DebugSWVCPU(fmt, args...)					\
({									\
	if (DEBUG_KVM_SWITCH_VCPU_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_MIGRATE_VCPU_MODE
#undef	DebugMGVCPU
#define	DEBUG_KVM_MIGRATE_VCPU_MODE	false	/* guest thread switch to */
						/* other VCPU */
#define	DebugMGVCPU(fmt, args...)					\
({									\
	if (DEBUG_KVM_MIGRATE_VCPU_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

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

#undef	DEBUG_GPT_REGS_MODE
#define	DEBUG_GPT_REGS_MODE	0	/* KVM host and guest kernel */
					/* stack activations print */

int last_light_hcall = -1;

/*
 * Should be inline function and should call from light hypercall or
 * is better to create separate hypercall
 * Do not call any function from here.
 */
static inline void
kvm_switch_guest_thread_stacks(struct kvm_vcpu *vcpu, int gpid_nr, int gmmid_nr)
{
	gthread_info_t	*cur_gti = pv_vcpu_get_gti(vcpu);
	gthread_info_t	*next_gti;
	struct gmm_struct *init_gmm = pv_vcpu_get_init_gmm(vcpu);
	struct gmm_struct *next_gmm;
	struct sw_regs	*cur_gsw;
	struct sw_regs	*next_gsw;
	int		cur_gmmid_nr = pv_vcpu_get_gmm(vcpu)->nid.nr;
	unsigned long	irq_flags;
	bool		migrated = false;
	int		old_vcpu_id = -1;
	int		gtask_is_binco;
	unsigned long	mmu_pid;
	u64 fpcr, fpsr, pfpfr;

	DebugKVMSWH("started to switch from current GPID #%d to #%d GMM #%d\n",
		cur_gti->gpid->nid.nr, gpid_nr, gmmid_nr);

	next_gti = kvm_get_guest_thread_info(vcpu->kvm, gpid_nr);
	if (next_gti == NULL) {
		/* FIXME: we should kill guest kernel, but first it needs */
		/* to  switch to host kernel stacks */
		panic("kvm_switch_guest_thread_stacks() could not find "
			"guest thread GPID #%d\n", gpid_nr);
	}
	if (next_gti->vcpu == NULL) {
		DebugKVMSWH("next thread GPID #%d starts on VCPU #%d "
			"first time\n",
			gpid_nr, vcpu->vcpu_id);
		next_gti->vcpu = vcpu;
	} else if (next_gti->vcpu != vcpu) {
		DebugSWVCPU("next thread GPID #%d migrates from current GPID "
			"#%d VCPU #%d to VCPU #%d\n",
			gpid_nr, cur_gti->gpid->nid.nr,
			next_gti->vcpu->vcpu_id, vcpu->vcpu_id);
		migrated = true;
		old_vcpu_id = next_gti->vcpu->vcpu_id;
		next_gti->vcpu = vcpu;
	} else {
		DebugKVMSWH("next thread GPID #%d continues running "
			"on VCPU #%d\n",
			gpid_nr, vcpu->vcpu_id);
	}
	if (gmmid_nr != pv_vcpu_get_init_gmm(vcpu)->nid.nr) {
		next_gmm = kvm_find_gmmid(&vcpu->kvm->arch.gmmid_table,
						gmmid_nr);
		if (unlikely(next_gmm == NULL)) {
			if (next_gti->gmm == NULL) {
				/* gmm of next gti has been already released */
				/* switch to guest kernel init gmm */
				next_gmm = init_gmm;
			} else {
				/* FIXME: we should kill guest kernel, but first */
				/* it needs to  switch to host kernel stacks */
				panic("could not find new host agent #%d "
					"of guest mm\n", gmmid_nr);
			}
		}
	} else {
		/* new process is kernel thread */
		next_gmm = init_gmm;
	}
	cur_gsw = &cur_gti->sw_regs;

	/* Save interrupt mask state and disable NMIs on host */
	NATIVE_IRQ_NMI_SAVE_AND_CLI(irq_flags);
	WARN_ONCE(nmi_irqs_disabled_flags(irq_flags),
		"Non-maskable interrupts are disabled\n");
	BUG_ON(!irq_reg_disabled_flags(irq_flags));

	/* hardware stack bounds trap must have been provoked by guest */
	/* to handle it before save stacks state and switch to other process */
	/* so here should not be any traps */
	NATIVE_FLUSHCPU;

	ATOMIC_SAVE_CURRENT_STACK_REGS(cur_gsw, &cur_gsw->crs);

	E2K_SET_USER_STACK(DEBUG_KVM_SWITCH_VCPU_MODE);
	DebugKVMSW("current guest thread kernel data stack: base 0x%llx, "
		"size 0x%x, guest top 0x%lx\n",
		cur_gsw->usd_lo.USD_lo_base,
		cur_gsw->usd_hi.USD_hi_size,
		cur_gsw->top);
	DebugKVMSW("current guest thread host kernel data stack : base 0x%llx, "
		"size 0x%x, host top 0x%lx\n",
		cur_gti->stack_regs.stacks.usd_lo.USD_lo_base,
		cur_gti->stack_regs.stacks.usd_hi.USD_hi_size,
		cur_gti->stack_regs.stacks.top);
	DebugKVMSW("current guest thread PS: base 0x%llx, ind 0x%x, "
		"size 0x%x\n",
		cur_gsw->psp_lo.PSP_lo_base,
		cur_gsw->psp_hi.PSP_hi_ind,
		cur_gsw->psp_hi.PSP_hi_size);
	DebugKVMSW("current guest thread PCS: base 0x%llx, ind 0x%x, "
		"size 0x%x\n",
		cur_gsw->pcsp_lo.PCSP_lo_base,
		cur_gsw->pcsp_hi.PCSP_hi_ind,
		cur_gsw->pcsp_hi.PCSP_hi_size);
	DebugKVMSW("current CR0_lo 0x%016llx CR0_hi 0x%016llx "
		"CR1_lo 0x%016llx CR1_hi 0x%016llx\n",
		cur_gsw->crs.cr0_lo.CR0_lo_half,
		cur_gsw->crs.cr0_hi.CR0_hi_half,
		cur_gsw->crs.cr1_lo.CR1_lo_half,
		cur_gsw->crs.cr1_hi.CR1_hi_half);

	gtask_is_binco = cur_gti->task_is_binco;
	AW(cur_gsw->fpu.fpcr) = NATIVE_NV_READ_FPCR_REG_VALUE();
	AW(cur_gsw->fpu.fpsr) = NATIVE_NV_READ_FPSR_REG_VALUE();
	AW(cur_gsw->fpu.pfpfr) = NATIVE_NV_READ_PFPFR_REG_VALUE();
	HOST_SAVE_TASK_USER_REGS_TO_SWITCH(vcpu, cur_gsw, gtask_is_binco,
			false /* task traced */);

	/* global registers should be saved by host */
	if (cur_gti->gmm != NULL) {
		SAVE_PV_VCPU_GLOBAL_REGISTERS(cur_gti);
	}

	/* switch mm to new process, it is actual if user process */
	NATIVE_FLUSHCPU;	/* spill current stacks on current mm */
	next_gmm = switch_guest_mm(next_gti, next_gmm);
	if (next_gti->gmm != NULL && next_gti->gmm == next_gmm) {
		/* set flags of return type to guest kernel or guest user: */
		/* it is to kernel for now */
		host_return_to_guest_kernel(current_thread_info());

		mmu_pid = kvm_switch_to_guest_mmu_pid(vcpu, current_thread_info());
	} else {
		mmu_pid = next_gmm->context.cpumsk[smp_processor_id()];
	}

	/* Should not be print or other functions calling here */

	next_gsw = &next_gti->sw_regs;

	if (!vcpu->arch.is_hv) {
		NATIVE_NV_WRITE_USBR_USD_REG_VALUE(next_gsw->top,
				AW(next_gsw->usd_hi), AW(next_gsw->usd_lo));

		NATIVE_NV_WRITE_PSP_REG(next_gsw->psp_hi, next_gsw->psp_lo);
		NATIVE_NV_WRITE_PCSP_REG(next_gsw->pcsp_hi, next_gsw->pcsp_lo);

		NATIVE_NV_NOIRQ_WRITE_CR0_LO_REG(next_gsw->crs.cr0_lo);
		NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG(next_gsw->crs.cr0_hi);
		NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG(next_gsw->crs.cr1_lo);
		NATIVE_NV_NOIRQ_WRITE_CR1_HI_REG(next_gsw->crs.cr1_hi);
	}

	E2K_SET_USER_STACK(DEBUG_KVM_SWITCH_VCPU_MODE);
	DebugKVMSW("next guest thread kernel data stack: base 0x%llx, "
		"size 0x%x, guest top 0x%lx\n",
		next_gsw->usd_lo.USD_lo_base,
		next_gsw->usd_hi.USD_hi_size,
		next_gsw->top);
	DebugKVMSW("next guest thread host kernel data stack : "
		"base 0x%llx, size 0x%x, host top 0x%lx\n",
		next_gti->stack_regs.stacks.usd_lo.USD_lo_base,
		next_gti->stack_regs.stacks.usd_hi.USD_hi_size,
		next_gti->stack_regs.stacks.top);
	DebugKVMSW("next guest thread PS: base 0x%llx, ind 0x%x, "
		"size 0x%x\n",
		next_gsw->psp_lo.PSP_lo_base,
		next_gsw->psp_hi.PSP_hi_ind,
		next_gsw->psp_hi.PSP_hi_size);
	DebugKVMSW("next guest thread PCS: base 0x%llx, ind 0x%x, "
		"size 0x%x\n",
		next_gsw->pcsp_lo.PCSP_lo_base,
		next_gsw->pcsp_hi.PCSP_hi_ind,
		next_gsw->pcsp_hi.PCSP_hi_size);
	DebugKVMSW("next CR0_lo 0x%016llx CR0_hi 0x%016llx "
		"CR1_lo 0x%016llx CR1_hi 0x%016llx\n",
		next_gsw->crs.cr0_lo.CR0_lo_half,
		next_gsw->crs.cr0_hi.CR0_hi_half,
		next_gsw->crs.cr1_lo.CR1_lo_half,
		next_gsw->crs.cr1_hi.CR1_hi_half);

	gtask_is_binco = next_gti->task_is_binco;
	fpcr = AS_WORD(next_gsw->fpu.fpcr);
	fpsr = AS_WORD(next_gsw->fpu.fpsr);
	pfpfr = AS_WORD(next_gsw->fpu.pfpfr);
	HOST_RESTORE_TASK_USER_REGS_TO_SWITCH(vcpu, next_gsw, gtask_is_binco,
						false /* traced */);
	NATIVE_NV_WRITE_FPCR_REG_VALUE(fpcr);
	NATIVE_NV_WRITE_FPSR_REG_VALUE(fpsr);
	NATIVE_NV_WRITE_PFPFR_REG_VALUE(pfpfr);

	/* global registers should be restored by host */
	if (next_gti->gmm != NULL && next_gti->gmm == next_gmm) {
		/* FIXME: only to debug gregs save/restore, should be deleted */
		E2K_SET_USER_STACK(DEBUG_GREGS_MODE);

		RESTORE_PV_VCPU_GLOBAL_REGISTERS(next_gti);
	}

	pv_vcpu_set_gti(vcpu, next_gti);

	pv_vcpu_switch_guest_host_context(vcpu, cur_gti, next_gti);

	/* Enable NMIs on host */
	NATIVE_IRQ_NMI_STI(irq_flags);

	/* FIXME: only to debug gregs save/restore, should be deleted */
	E2K_SET_USER_STACK(DEBUG_KVM_MIGRATE_VCPU_MODE);
	/* save current state of guest kernel global registers */
	/* it need here save only some registers which can be changed */
	/* after migration, but now all global registers are saved
	if (migrated)
	 */
	SAVE_GUEST_KERNEL_GREGS_COPY(current_thread_info(), next_gti);
	/* g19 is now preempt count, it should be zero when preempting */
	SET_PREEMPT_CNT_GUEST_KERNEL_GREGS_COPY(next_gti, 0);

	DebugMGVCPU("thread GPID #%d migrates from VCPU #%d to "
		"VCPU #%d signal stack entries %ld\n",
		gpid_nr, old_vcpu_id, vcpu->vcpu_id,
		current_thread_info()->signal_stack.used /
			sizeof(struct signal_stack_context));

	if (unlikely(trace_guest_switch_to_enabled())) {
		trace_guest_switch_to(vcpu, cur_gti->gpid->nid.nr, cur_gmmid_nr,
					gpid_nr, gmmid_nr, next_gsw);
		trace_kvm_switch_mmu_guest_pid(vcpu, next_gmm, smp_processor_id(),
					       mmu_pid);
	}
	trace_host_get_gmm_root_hpa(next_gmm, NATIVE_READ_IP_REG_VALUE());
	if (next_gmm != init_gmm) {
		trace_host_get_gmm_root_hpa(init_gmm, NATIVE_READ_IP_REG_VALUE());
	}

	return;
}

/*
 * Hypercall hanlder of tlb flush requests from paravirtualized kernel
 */

static inline unsigned long update_psp_hi(unsigned long psp_hi_value)
{
	e2k_psp_lo_t psp_lo;
	e2k_psp_hi_t psp_hi, new_psp_hi;
	e2k_cr1_lo_t cr1_lo;
	u64 size;
	void *dst, *src;

	NATIVE_FLUSHR;
	psp_lo = NATIVE_NV_READ_PSP_LO_REG();
	psp_hi = NATIVE_NV_READ_PSP_HI_REG();
	cr1_lo = NATIVE_NV_READ_CR1_LO_REG();
	size = cr1_lo.CR1_lo_wbs * EXT_4_NR_SZ;
	new_psp_hi.PSP_hi_half = psp_hi_value;
	dst = (void *)(psp_lo.PSP_lo_base + new_psp_hi.PSP_hi_ind);
	src = (void *)(psp_lo.PSP_lo_base + psp_hi.PSP_hi_ind - size);
	fast_tagged_memory_copy(dst, src, size, true);
	new_psp_hi.PSP_hi_half += size;
	NATIVE_NV_NOIRQ_WRITE_PSP_HI_REG(new_psp_hi);
	return 0;
}

static inline unsigned long update_pcsp_hi(unsigned long pcsp_hi_value)
{
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi, new_pcsp_hi;
	u64 size;
	void *dst, *src;

	NATIVE_FLUSHC;
	pcsp_lo = NATIVE_NV_READ_PCSP_LO_REG();
	pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();
	size = SZ_OF_CR;
	new_pcsp_hi.PCSP_hi_half = pcsp_hi_value;
	dst = (void *)(pcsp_lo.PCSP_lo_base + new_pcsp_hi.PCSP_hi_ind);
	src = (void *)(pcsp_lo.PCSP_lo_base + pcsp_hi.PCSP_hi_ind - size);
	fast_tagged_memory_copy(dst, src, size, true);
	new_pcsp_hi.PCSP_hi_half += size;
	NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG(new_pcsp_hi);
	return 0;
}

static inline void update_wd_psise(unsigned long psize_value)
{
	e2k_cr1_lo_t cr1_lo = NATIVE_NV_READ_CR1_LO_REG();
	cr1_lo.CR1_lo_wpsz = psize_value >> 4;
	NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG(cr1_lo);
}

static DECLARE_BITMAP(unpriv_light_hcalls, KVM_LIGHT_HCALLS_NUM) __ro_after_init;
static DECLARE_BITMAP(unpriv_generic_hcalls, KVM_GENERIC_HCALLS_NUM) __ro_after_init;

static int __init init_unpriv_hcalls(void)
{
	/* Mark hypercalls that are safe to use by non-root user */
	__set_bit(KVM_HCALL_PV_WAIT, unpriv_generic_hcalls);
	__set_bit(KVM_HCALL_PV_KICK, unpriv_generic_hcalls);
#ifdef CONFIG_KVM_ASYNC_PF
	__set_bit(KVM_HCALL_PV_ENABLE_ASYNC_PF, unpriv_generic_hcalls);
#endif
	return 0;
}
pure_initcall(init_unpriv_hcalls);

/*
 * This is the light hypercalls execution.
 * Lighte hypercalls do not:
 *  - switch to kernel stacks
 *  - use data stack
 *  - call any function
 */
notrace __section(".text.entry_hcalls") /* __interrupt */
unsigned long kvm_light_hcalls(unsigned long hcall_num,
		unsigned long arg1, unsigned long arg2,
		unsigned long arg3, unsigned long arg4,
		unsigned long arg5, unsigned long arg6)
{
	struct kvm_vcpu	*vcpu;
	thread_info_t *thread_info;
	gthread_info_t *gti;
	bool from_light_hypercall;
	bool from_generic_hypercall;
	e2k_cr1_lo_t cr1_lo;
	unsigned long irq_flags;
	bool need_inject;
	unsigned long ret = 0;
	unsigned long from_sdisp = hcall_num >> 63;

	hcall_num &= ~(1UL << 63);

	/* Save guest values of global regs and set current pointers instead */
	thread_info = NATIVE_READ_CURRENT_REG();
	vcpu = thread_info->vcpu;

	__guest_exit_light(thread_info, &vcpu->arch);

	/* check VCPU ID of global register and running VCPU */
	kvm_check_vcpu_ids_as_light(vcpu);

	/* set kernel state of UPSR to preserve FP disable exception */
	/* on movfi instructions while global registers saving */
	NATIVE_SWITCH_TO_KERNEL_IRQ_MASK_REG(irq_flags,
					false,	/* enable IRQs */
					false	/* disable NMI */);

	vcpu->mode = OUTSIDE_GUEST_MODE;
	smp_wmb();	/* See the comment in kvm_vcpu_exiting_guest_mode() */

	if (!vcpu->arch.is_hv) {
		/* Do not switch guest MMU context to host MMU one to enable */
		/* light access to guest address space from host. */
		/* All hard cases of access should cause page faults traps */
		/* and switch to host MMU context to handle these faults */
		;
	}

	cr1_lo = NATIVE_NV_READ_CR1_LO_REG();

	gti = thread_info->gthread_info;
	if (gti != NULL) {
		/* save guest kernel UPSR state at guest thread info
		DO_SAVE_GUEST_KERNEL_UPSR(gti, user_upsr);
		 */
	}

	from_light_hypercall = test_thread_flag(TIF_LIGHT_HYPERCALL);
	from_generic_hypercall = test_thread_flag(TIF_GENERIC_HYPERCALL);
	if (!from_light_hypercall)
		set_thread_flag(TIF_LIGHT_HYPERCALL);
	if (from_generic_hypercall)
		clear_thread_flag(TIF_GENERIC_HYPERCALL);

	last_light_hcall = hcall_num;

	trace_kvm_pid(FROM_LIGHT_HYPERCALL, vcpu->kvm->arch.vmid.nr,
		vcpu->vcpu_id, read_guest_PID_reg(vcpu));
	trace_light_hcall(hcall_num, arg1, arg2, arg3, arg4, arg5, arg6);

	/* in common case cannot enable hardware stacks bounds traps, */
	/* disabled by assembler entry of the hypercall handler */
	/* (see arch/e2k/kvm/ttable.S). */
	/* Light hypercalls do not call other functions and run under */
	/* IRQs disabled, but hardware stack bounds trap can be enabled */
	/* for all hypercalls excluding switch to other guest process */
	/* (see comments at kvm_switch_guest_thread_stacks() function */
	if (hcall_num != KVM_HCALL_SWITCH_GUEST_THREAD_STACKS) {
		//TODO needed?? This is only for virtualization w/o hardware support
		//native_set_sge();
	}

	if (!test_bit(hcall_num, unpriv_light_hcalls) &&
			!capable(CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto skip_hcall;
	}

	switch (hcall_num) {
	case KVM_HCALL_COPY_STACKS_TO_MEMORY:
		if ((void *)arg1 == NULL) {
			NATIVE_FLUSHCPU;
		} else {
			ret = kvm_flush_hw_stacks_to_memory(
					(kvm_hw_stacks_flush_t *)arg1);
		}
		break;
	case KVM_HCALL_GET_TLB_SET_TAG:
		ret = get_va_tlb_set_tag(arg1, (int)arg2, (bool)arg3);
		break;
	case KVM_HCALL_GET_TLB_SET_ENTRY:
		ret = pte_val(get_va_tlb_set_entry(arg1, (int)arg2, (bool)arg3));
		break;
	case KVM_HCALL_GET_HOST_MMU_PPTB:
		ret = get_mmu_u_pptb_reg();
		break;
	case KVM_HCALL_GET_HOST_MMU_PID:
		ret = get_mmu_pid_reg();
		break;
	case KVM_HCALL_UPDATE_PCSP_HI:
		update_pcsp_hi(arg1);
		break;
	case KVM_HCALL_UPDATE_PSP_HI:
		update_psp_hi(arg1);
		break;
	case KVM_HCALL_UPDATE_WD_PSIZE:
		update_wd_psise(arg1);
		break;
	case KVM_HCALL_SETUP_IDLE_TASK:
		ret = pv_vcpu_get_gpid_id(vcpu);
		break;
	case KVM_HCALL_UNFREEZE_TRAPS:
		kvm_init_pv_vcpu_trap_handling(vcpu, NULL);
		break;
	case KVM_HCALL_SWITCH_TO_INIT_MM:
		if (likely(kvm_switch_to_init_guest_mm(vcpu))) {

			/* set flags of return type to guest kernel or */
			/* guest user: it is to kernel for now */
			host_return_to_guest_kernel(thread_info);
			/* switch MMU context to guest kernel init mm */
			kvm_switch_to_guest_mmu_pid(vcpu, thread_info);
		}
		break;
	case KVM_HCALL_SWITCH_GUEST_THREAD_STACKS:
		kvm_switch_guest_thread_stacks(vcpu, (int) arg1, (int) arg2);
		break;
	case KVM_HCALL_GET_ACTIVE_CR_MEM_ITEM:
		ret = kvm_get_guest_active_cr_mem_item(
			(unsigned long __user *) arg1, arg2, arg3, arg4);
		break;
	case KVM_HCALL_PUT_ACTIVE_CR_MEM_ITEM:
		ret = kvm_put_guest_active_cr_mem_item(arg1, arg2, arg3, arg4);
		break;
	case KVM_HCALL_MOVE_TAGGED_DATA:
		ret = kvm_move_guest_tagged_data((int)arg1, arg2, arg3);
		break;
	case KVM_HCALL_EXTRACT_TAGS_32:
		ret = kvm_extract_guest_tags_32((u16 *)arg1,
						(const void *)arg2);
		break;
	case KVM_HCALL_INJECT_INTERRUPT:
		/* interrupt will be injected while hypercall return */
		/* see below */
		break;
	case KVM_HCALL_VIRQ_HANDLED:
		/* injected interrupt to handle VIRQs was completed */
		ret = kvm_guest_handled_virqs(vcpu);
		break;
	case KVM_HCALL_TEST_PENDING_VIRQ:
		ret = kvm_test_pending_virqs(vcpu);
		break;
	case KVM_HCALL_GET_HOST_RUNSTATE_KTIME:
		ret = kvm_get_host_runstate_ktime();
		break;
	case KVM_HCALL_GET_GUEST_RUNNING_TIME:
		ret = kvm_get_guest_running_time(vcpu);
		break;
	case KVM_HCALL_READ_DTLB_REG:
		ret = kvm_read_guest_dtlb_reg(arg1);
		break;
	case KVM_HCALL_GET_DAM:
		/* DAM saved & restored by host */
		ret = 0;
		break;
	case KVM_HCALL_FLUSH_DCACHE_LINE:
		ret = kvm_flush_guest_dcache_line(arg1);
		break;
	case KVM_HCALL_CLEAR_DCACHE_L1_SET:
		ret = kvm_clear_guest_dcache_l1_set(arg1, arg2);
		break;
	case KVM_HCALL_FLUSH_DCACHE_RANGE:
		ret = kvm_flush_guest_dcache_range((void *)arg1, arg2);
		break;
	case KVM_HCALL_CLEAR_DCACHE_L1_RANGE:
		ret = kvm_clear_guest_dcache_l1_range((void *)arg1, arg2);
		break;
	case KVM_HCALL_FLUSH_ICACHE_ALL:
		ret = kvm_flush_guest_icache_all();
		break;
	case KVM_HCALL_MMU_PROBE:
		ret = kvm_guest_mmu_probe(arg1, (kvm_mmu_probe_t)arg2);
		break;
	case KVM_HCALL_SET_RETURN_USER_IP:
		ret = kvm_set_return_user_ip((thread_info_t *)arg1, arg2, arg3);
		break;
	case KVM_HCALL_FAST_KERNEL_TAGGED_MEMORY_COPY:
		ret = kvm_fast_guest_kernel_tagged_memory_copy_light_hcall(vcpu,
				(void *)arg1, (void *)arg2, arg3, arg4, arg5, (int)arg6);
		break;
	case KVM_HCALL_FAST_KERNEL_TAGGED_MEMORY_SET:
		ret = kvm_fast_guest_kernel_tagged_memory_set_light_hcall(vcpu,
				(void *)arg1, arg2, arg3, arg4, arg5);
		break;
	case KVM_HCALL_UPDATE_GUEST_KERNEL_CRS:
		ret = kvm_update_guest_kernel_crs((e2k_mem_crs_t *)arg1,
				(e2k_mem_crs_t *)arg2, (e2k_mem_crs_t *)arg3);
		break;
	case KVM_HCALL_TRACING_START:
		tracing_on();
		break;
	case KVM_HCALL_TRACING_STOP:
		tracing_off();
		break;
	default:
		ret = -ENOSYS;
	}

skip_hcall:
	KVM_HOST_CHECK_VCPU_THREAD_CONTEXT(thread_info);

	trace_light_hcall_exit(ret);

	if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu) || cpu_has(CPU_HWBUG_VIRT_TLU_IB)) {
		trace_host_flush_tlb(vcpu);
		kvm_vcpu_flush_tlb(vcpu);
	}

	/* light hypercall execution completed */
	if (!from_light_hypercall)
		clear_thread_flag(TIF_LIGHT_HYPERCALL);
	if (from_generic_hypercall)
		set_thread_flag(TIF_GENERIC_HYPERCALL);

	/* reread guest thread structure pointer, which can be changed */
	/* while switching guest processes hypercall */
	gti = thread_info->gthread_info;

	/* if there are pending VIRQs, then provide with direct injection */
	/* to cause guest interrupting and handling VIRQs */
	need_inject = kvm_try_inject_event_wish(vcpu, thread_info,
				kvm_get_guest_vcpu_UPSR_value(vcpu),
				kvm_get_guest_vcpu_PSR_value(vcpu));

	/* check VCPU ID of global register and running VCPU */
	kvm_check_vcpu_ids_as_light(vcpu);

	/*
	 * Ensure we set mode to IN_GUEST_MODE after we disable
	 * interrupts and before the final VCPU requests check.
	 * See the comment in kvm_vcpu_exiting_guest_mode() and
	 * Documentation/virt/kvm/vcpu-requests.rst
	 */
	smp_store_mb(vcpu->mode, IN_GUEST_MODE);

	__guest_enter_light(thread_info, &vcpu->arch, !!from_sdisp);

	/* from here cannot by any traps including BUG/BUG_ON/E2K_KVM_BUG_ON */
	/* because of host context is switched to guest context */

	if (gti != NULL) {
		/* restore guest kernel UPSR state from guest thread info
		DO_RESTORE_GUEST_KERNEL_UPSR(gti, user_upsr);
		 */
	}

	NATIVE_RETURN_LWISH_TO_KERNEL_IRQ_MASK_REG(irq_flags, need_inject);

	if (!from_sdisp)
		E2K_HRET(ret);

	return ret;
}

/*
 * hardware hypercall should return to new guest stacks and function
 */
static __always_inline void
switch_to_new_hv_vcpu_stacks(struct kvm_vcpu *vcpu,
				guest_hw_stack_t *stack_regs)
{
	e2k_cr0_lo_t cr0_lo;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	e2k_psp_hi_t psp_hi;
	e2k_pcsp_hi_t pcsp_hi;

	/*
	 * Set current chain registers to return to guest upper function
	 */
	cr0_lo = stack_regs->crs.cr0_lo;
	cr0_hi = stack_regs->crs.cr0_hi;
	cr1_lo = stack_regs->crs.cr1_lo;
	cr1_hi = stack_regs->crs.cr1_hi;

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

	/* strip old procedure and chain stacks frames */
	psp_hi = NATIVE_NV_READ_PSP_HI_REG();
	pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();
	psp_hi.PSP_hi_ind = 0;
	pcsp_hi.PCSP_hi_ind = 0;

	NATIVE_NV_NOIRQ_WRITE_CR0_LO_REG(cr0_lo);
	NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG(cr0_hi);
	NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG(cr1_lo);
	NATIVE_NV_NOIRQ_WRITE_CR1_HI_REG(cr1_hi);

	NATIVE_NV_NOIRQ_WRITE_PSP_HI_REG(psp_hi);
	NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG(pcsp_hi);
}

/*
 * hardware hypercall should return to new guest user stacks and function
 */
static __always_inline void
switch_to_new_user_pv_vcpu_stacks(struct kvm_vcpu *vcpu,
				  guest_hw_stack_t *stack_regs)
{
	e2k_cr0_lo_t cr0_lo;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	e2k_psp_lo_t psp_lo;
	e2k_psp_hi_t psp_hi;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;

	/*
	 * Set current chain registers to return to guest upper function
	 */
	cr0_lo = stack_regs->crs.cr0_lo;
	cr0_hi = stack_regs->crs.cr0_hi;
	cr1_lo = stack_regs->crs.cr1_lo;
	cr1_hi = stack_regs->crs.cr1_hi;

	psp_lo = stack_regs->stacks.psp_lo;
	psp_hi = stack_regs->stacks.psp_hi;
	pcsp_lo = stack_regs->stacks.pcsp_lo;
	pcsp_hi = stack_regs->stacks.pcsp_hi;

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

	NATIVE_NV_NOIRQ_WRITE_CR0_LO_REG(cr0_lo);
	NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG(cr0_hi);
	NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG(cr1_lo);
	NATIVE_NV_NOIRQ_WRITE_CR1_HI_REG(cr1_hi);

	NATIVE_NV_WRITE_PSP_REG(psp_hi, psp_lo);
	NATIVE_NV_WRITE_PCSP_REG(pcsp_hi, pcsp_lo);
}

static inline long outdated_hypercall(const char *hcall_name)
{
	pr_err("%s(): hypercall %s is outdated and cannot be supported\n",
		__func__, hcall_name);
	return -ENOSYS;
}

/*
 * This is the core hypercall routine: where the Guest gets what it wants.
 * Or gets killed.  Or, in the case of KVM_HCALL_SHUTDOWN, both.
 */
notrace __section(".text.entry_hcalls")
unsigned long kvm_generic_hcalls(unsigned long hcall_num, unsigned long arg1,
		unsigned long arg2, unsigned long arg3, unsigned long arg4,
		unsigned long arg5, unsigned long arg6, unsigned long gsbr)
{
	thread_info_t	*ti;
	gthread_info_t	*gti = NULL;
	struct kvm_vcpu	*vcpu;
	struct kvm	*kvm;
	gmm_struct_t	*gmm = NULL;
	hpa_t		root, gk_root;
	bool		from_generic_hypercall;
	bool		from_light_hypercall;
	unsigned long	irq_flags;
	e2k_usd_lo_t	k_usd_lo;
	e2k_size_t	g_usd_size;
	e2k_cr1_hi_t	cr1_hi;
	e2k_cr1_lo_t	cr1_lo;
	guest_hw_stack_t stack_regs;
	bool	to_new_stacks = false;
	bool	to_host_vcpu = false;	/* it need return to host qemu thread */
	bool	to_new_user_stacks = false;	/* it need switch to new user */
						/* process */
	bool	to_new_context = false;		/* to new MMU context */
	bool	need_inject, has_signal_pending;
	unsigned guest_enter_flags = FROM_HYPERCALL_SWITCH | USD_CONTEXT_SWITCH | DEBUG_REGS_SWITCH,
		 guest_exit_flags = FROM_HYPERCALL_SWITCH | DEBUG_REGS_SWITCH;
	int	users;
	unsigned long	ret = 0;
	unsigned long	from_sdisp = hcall_num >> 63;

	hcall_num &= ~(1UL << 63);

	ti = NATIVE_READ_CURRENT_REG();
	vcpu = ti->vcpu;

	if (from_sdisp) {
		/* emulate hardware supported HCALL operation */
		users = kvm_pv_switch_to_hcall_host_stacks(vcpu);
		KVM_WARN_ON(users > 1);
		/* root_ptb has been switched in assembler already */
		guest_exit_flags |= DONT_MMU_CONTEXT_SWITCH;
		gmm = pv_vcpu_get_gmm(vcpu);
	}

	if (gmm != NULL) {
		root = gmm->root_hpa;
		gk_root = gmm->gk_root_hpa;
	}
	__guest_exit(ti, &vcpu->arch, guest_exit_flags);
	if (gmm != NULL) {
		trace_host_gmm_root_hpa(pv_vcpu_get_gmm(vcpu), root, gk_root,
					NATIVE_READ_IP_REG_VALUE());
	}

	/* check saved greg and running VCPU IDs: should be the same */
	kvm_check_vcpu_state_greg();

	/*
	 * Hardware system hypercall operation disables interrupts mask in PSR
	 * and PSR becomes main register to control interrupts.
	 * Switch control from PSR register to UPSR, if UPSR
	 * interrupts control is used and all following kernel handler
	 * will be executed under UPSR control
	 * Setting of UPSR should be before global registers saving
	 * to preserve FP disable exception on movfi instructions
	 * while global registers saving
	 */
	NATIVE_SWITCH_TO_KERNEL_IRQ_MASK_REG(irq_flags,
					false,	/* enable IRQs */
					true	/* disable NMI to switch */
						/* mm context */);

	vcpu->mode = OUTSIDE_GUEST_MODE;
	smp_wmb();	/* See the comment in kvm_vcpu_exiting_guest_mode() */

	kvm = vcpu->kvm;

	if (!vcpu->arch.is_hv) {
		struct mm_struct *mm;
		unsigned long mmu_pid;

		/* switch to host MMU context to enable access to guest */
		/* physical memory from host, where this memory mapped */
		/* as virtual space of user QEMU process */
		mm = thread_info_task(ti)->mm;
		mmu_pid = mm->context.cpumsk[smp_processor_id()];
		trace_kvm_switch_to_host_mmu_pid(vcpu, mm, mmu_pid,
						 hypercall_sw_to_host);
	}

	gti = ti->gthread_info;
	if (gti != NULL) {
		/* save guest kernel UPSR state at guest thread info
		DO_SAVE_GUEST_KERNEL_UPSR(gti, upsr_to_save);
		 */
	}

	/* Update run state of guest */
	BUG_ON(kvm_get_guest_vcpu_runstate(vcpu) != RUNSTATE_running);
	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_hcall);

	/* generic hypercall execution starts */
	from_generic_hypercall = test_thread_flag(TIF_GENERIC_HYPERCALL);
	from_light_hypercall = test_thread_flag(TIF_LIGHT_HYPERCALL);
	if (!from_generic_hypercall)
		set_thread_flag(TIF_GENERIC_HYPERCALL);
	if (from_light_hypercall)
		clear_thread_flag(TIF_LIGHT_HYPERCALL);

	trace_kvm_pid(FROM_GENERIC_HYPERCALL, vcpu->kvm->arch.vmid.nr,
		vcpu->vcpu_id, read_guest_PID_reg(vcpu));
	trace_generic_hcall(hcall_num, arg1, arg2, arg3, arg4, arg5, arg6, gsbr);

	/* in common case cannot enable hardware stacks bounds traps, */
	/* disabled by assembler entry of the hypercall handler */
	/* (see arch/e2k/kvm/ttable.S). It can be done only for specific */
	/* hypercalss and at concrete time */
	/* native_set_sge(); */

	if (vcpu->arch.is_hv && hcall_num == KVM_HCALL_SWITCH_TO_VIRT_MODE)
		to_new_stacks = true;

	cr1_lo = NATIVE_NV_READ_CR1_LO_REG();
	vcpu->arch.hcall_irqs_disabled = kvm_guest_vcpu_irqs_disabled(vcpu,
			(vcpu->arch.is_hv) ? irq_flags
					   : kvm_get_guest_vcpu_UPSR_value(vcpu),
			(vcpu->arch.is_hv) ? cr1_lo.CR1_lo_psr
					   : kvm_get_guest_vcpu_PSR_value(vcpu));

	/* save guest stack state to return from hypercall */
	cr1_hi = NATIVE_NV_READ_CR1_HI_REG();
	g_usd_size = cr1_hi.CR1_hi_ussz << 4;

	k_usd_lo = NATIVE_NV_READ_USD_LO_REG();
	raw_local_irq_enable();

	if (!test_bit(hcall_num, unpriv_generic_hcalls) &&
			!capable(CAP_SYS_ADMIN)) {
		pr_info_once("hcall #%lu is for root mode only\n", hcall_num);
		ret = -EPERM;
		goto skip_hcall;
	}

	switch (hcall_num) {
	case KVM_HCALL_PV_WAIT:
		kvm_pv_wait(kvm, vcpu);
		break;
	case KVM_HCALL_PV_KICK:
		kvm_pv_kick(kvm, arg1);
		break;
	case KVM_HCALL_RELEASE_TASK_STRUCT:
		ret = kvm_release_guest_task_struct(vcpu, arg1);
		break;
	case KVM_HCALL_SET_CLOCKEVENT:
		kvm_guest_set_clockevent(vcpu, arg1);
		break;
	case KVM_HCALL_COMPLETE_LONG_JUMP:
		ret = kvm_long_jump_return(vcpu, (kvm_long_jump_info_t *)arg1,
					(bool)arg2, (u64)arg3);
		break;
	case KVM_HCALL_LAUNCH_SIG_HANDLER:
		ret = kvm_sig_handler_return(vcpu, (kvm_stacks_info_t *)arg1,
						arg2, arg3, &stack_regs);
		to_new_user_stacks = true;
		to_new_context = false;
		guest_enter_flags |= DONT_RESTORE_HOST_GREGS;
		break;
	case KVM_HCALL_APPLY_USD_BOUNDS:
		ret = kvm_apply_updated_usd_bounds(vcpu, arg1, arg2, (bool)arg3);
		break;
	case KVM_HCALL_APPLY_PSP_BOUNDS:
		ret = kvm_apply_updated_psp_bounds(vcpu, arg1, arg2, arg3,
							 arg4, arg5);
		break;
	case KVM_HCALL_APPLY_PCSP_BOUNDS:
		ret = kvm_apply_updated_pcsp_bounds(vcpu, arg1, arg2, arg3,
							  arg4, arg5);
		break;
	case KVM_HCALL_CORRECT_TRAP_RETURN_IP:
		ret = kvm_correct_guest_trap_return_ip(arg1);
		break;
	case KVM_HCALL_SWITCH_TO_VIRT_MODE:
		ret = kvm_switch_to_virt_mode(vcpu,
			(kvm_task_info_t *)arg1, &stack_regs,
			(void (*)(void *data, void *arg_1, void *arg_2))arg2,
			(void *)arg3, (void *)arg4, (void *)arg5);
		if (vcpu->arch.is_hv)
			to_new_stacks = true;
		break;
	case KVM_HCALL_SWITCH_GUEST_KERNEL_STACKS:
		ret = kvm_switch_guest_kernel_stacks(vcpu,
				(kvm_task_info_t *)arg1, (char *)arg2,
				(unsigned long *)arg3, (int)arg4,
				&stack_regs);
		break;
	case KVM_HCALL_GUEST_INTR_HANDLER:
		outdated_hypercall("KVM_HCALL_GUEST_INTR_HANDLER");
		break;
	case KVM_HCALL_GUEST_FREE_INTR_HANDLER:
		outdated_hypercall("KVM_HCALL_GUEST_FREE_INTR_HANDLER");
		break;
	case KVM_HCALL_GUEST_INTR_THREAD:
		outdated_hypercall("KVM_HCALL_GUEST_INTR_THREAD");
		break;
	case KVM_HCALL_WAIT_FOR_VIRQ:
		outdated_hypercall("KVM_HCALL_WAIT_FOR_VIRQ");
		break;
	case KVM_HCALL_GET_GUEST_DIRECT_VIRQ:
		ret = kvm_get_guest_direct_virq(vcpu, (int)arg1, (int)arg2);
		break;
	case KVM_HCALL_FREE_GUEST_DIRECT_VIRQ:
		ret = kvm_free_guest_direct_virq(kvm, (int)arg1);
		break;
	case KVM_HCALL_COPY_GUEST_KERNEL_STACKS:
		ret = kvm_copy_guest_kernel_stacks(vcpu,
					(kvm_task_info_t *)arg1, cr1_hi);
		break;
	case KVM_HCALL_UPDATE_HW_STACKS_FRAMES:
		ret = kvm_update_hw_stacks_frames(vcpu,
				(e2k_mem_crs_t *)arg1, (int)arg2,
				(kernel_mem_ps_t *)arg3, (int)arg4, (int)arg5);
		break;
	case KVM_HCALL_COPY_HW_STACKS_FRAMES:
		ret = kvm_copy_hw_stacks_frames(vcpu,
				(void *)arg1, (void *)arg2, arg3, (bool)arg4);
		break;
	case KVM_HCALL_SWITCH_TO_GUEST_NEW_USER:
		ret = kvm_switch_to_guest_new_user(vcpu,
				(kvm_task_info_t *)arg1, &stack_regs);
		to_new_user_stacks = true;
		to_new_context = true;
		break;
	case KVM_HCALL_CLONE_GUEST_USER_STACKS:
		ret = kvm_clone_guest_user_stacks(vcpu,
				(kvm_task_info_t *)arg1);
		break;
	case KVM_HCALL_COPY_GUEST_USER_STACKS:
		ret = kvm_copy_guest_user_stacks(vcpu,
			(kvm_task_info_t *)arg1, (vcpu_gmmu_info_t *)arg2);
		break;
	case KVM_HCALL_PATCH_GUEST_DATA_AND_CHAIN_STACKS:
		ret = kvm_patch_guest_data_and_chain_stacks(vcpu,
				(kvm_data_stack_info_t *)arg1,
				(kvm_pcs_patch_info_t *)arg2, arg3);
		break;
	case KVM_HCALL_GET_GUEST_GLOB_REGS:
		ret = kvm_get_guest_glob_regs(vcpu, (unsigned long **)arg1,
				arg2, (bool)arg3, (unsigned int *)arg4);
		break;
	case KVM_HCALL_SET_GUEST_GLOB_REGS:
		ret = kvm_set_guest_glob_regs(vcpu, (unsigned long **)arg1,
				arg2, (bool)arg3, (unsigned int *)arg4);
		break;
	case KVM_HCALL_GET_GUEST_LOCAL_GLOB_REGS:
		ret = kvm_get_guest_local_glob_regs(vcpu,
					(unsigned long **)arg1, (bool)arg2);
		break;
	case KVM_HCALL_SET_GUEST_LOCAL_GLOB_REGS:
		ret = kvm_set_guest_local_glob_regs(vcpu,
					(unsigned long **)arg1, (bool)arg2);
		break;
	case KVM_HCALL_GET_ALL_GUEST_GLOB_REGS:
		ret = kvm_get_all_guest_glob_regs(vcpu, (unsigned long **)arg1);
		break;
	case KVM_HCALL_RECOVERY_FAULTED_TAGGED_GUEST_STORE:
	case KVM_HCALL_RECOVERY_FAULTED_TAGGED_STORE:
		ret = kvm_recovery_faulted_tagged_guest_store(vcpu, arg1, arg2,
						arg3, arg4, arg5, arg6);
		break;
	case KVM_HCALL_RECOVERY_FAULTED_GUEST_LOAD:
	case KVM_HCALL_RECOVERY_FAULTED_LOAD:
		ret = kvm_recovery_faulted_guest_load(vcpu, arg1, (u64 *)arg2,
						(u8 *)arg3, arg4, (int)arg5);
		break;
	case KVM_HCALL_RECOVERY_FAULTED_GUEST_MOVE:
	case KVM_HCALL_RECOVERY_FAULTED_MOVE:
		ret = kvm_recovery_faulted_guest_move(vcpu, arg1, arg2,
						arg3, arg4, arg5, (u32)arg6);
		break;
	case KVM_HCALL_RECOVERY_FAULTED_LOAD_TO_GUEST_GREG:
	case KVM_HCALL_RECOVERY_FAULTED_LOAD_TO_GREG:
		ret = kvm_recovery_faulted_load_to_guest_greg(vcpu, arg1,
				(int) arg2, arg3, arg4, arg5, arg6);
		break;
	case KVM_HCALL_MOVE_TAGGED_GUEST_DATA:
		ret = kvm_move_tagged_guest_data(vcpu, (int)arg1, arg2, arg3);
		break;
	case KVM_HCALL_COPY_IN_USER_WITH_TAGS:
		ret = kvm_copy_in_user_with_tags((void *)arg1, (void *)arg2, arg3);
		break;
	case KVM_HCALL_FAST_TAGGED_MEMORY_COPY:
		ret = kvm_fast_guest_tagged_memory_copy(vcpu, (void *)arg1,
				(void *)arg2, arg3, NULL, arg4, arg5, (int)arg6);
		break;
	case KVM_HCALL_FAST_TAGGED_MEMORY_SET:
		ret = kvm_fast_guest_tagged_memory_set(vcpu, (void *)arg1,
				arg2, arg3, arg4, NULL, arg5);
		break;
	case KVM_HCALL_FAST_TAGGED_MEMORY_COPY_USER:
		ret = kvm_fast_guest_user_tagged_memory_copy(vcpu, (void *)arg1,
				(void *)arg2, arg3, (void *)arg4, arg5, arg6,
				LDST_PREFETCH_FLAG_GET(arg5));
		break;
	case KVM_HCALL_FAST_TAGGED_MEMORY_SET_USER:
		ret = kvm_fast_guest_user_tagged_memory_set(vcpu, (void *)arg1,
				arg2, arg3, arg4, (void *)arg5, arg6);
		break;
	case KVM_HCALL_PT_ATOMIC_UPDATE:
		ret = kvm_pv_mmu_pt_atomic_update(vcpu, (int)arg1,
				arg2, (void __user *)arg3,
				(pt_atomic_op_t)arg4, arg5);
		break;
	case KVM_HCALL_GUEST_MM_DROP:
		ret = kvm_guest_mm_drop(vcpu, (int)arg1);
		break;
	case KVM_HCALL_ACTIVATE_GUEST_MM:
		ret = kvm_activate_guest_mm(vcpu, (int)arg1, (int)arg2,
						(gpa_t)arg3);
		break;
	case KVM_HCALL_SWITCH_GUEST_MM:
		ret = kvm_pv_switch_guest_mm(vcpu, (int)arg1, (int)arg2,
						(gpa_t)arg3);
		break;
	case KVM_HCALL_VCPU_MMU_STATE:
		ret = kvm_pv_vcpu_mmu_state(vcpu,
				(vcpu_gmmu_info_t __user *)arg1);
		break;
	case KVM_HCALL_BOOT_SPIN_LOCK_SLOW:
		ret = kvm_boot_spin_lock_slow(vcpu, (void *)arg1, (bool)arg2);
		break;
	case KVM_HCALL_BOOT_SPIN_LOCKED_SLOW:
		ret = kvm_boot_spin_locked_slow(vcpu, (void *)arg1);
		break;
	case KVM_HCALL_BOOT_SPIN_UNLOCK_SLOW:
		ret = kvm_boot_spin_unlock_slow(vcpu, (void *)arg1, (bool)arg2);
		break;
	case KVM_HCALL_GUEST_SPIN_LOCK_SLOW:
		ret = kvm_guest_spin_lock_slow(kvm, (void *)arg1, (bool)arg2);
		break;
	case KVM_HCALL_GUEST_SPIN_LOCKED_SLOW:
		ret = kvm_guest_spin_locked_slow(kvm, (void *)arg1);
		break;
	case KVM_HCALL_GUEST_SPIN_UNLOCK_SLOW:
		ret = kvm_guest_spin_unlock_slow(kvm, (void *)arg1, (bool)arg2);
		break;
	case KVM_HCALL_GUEST_CSD_LOCK_CTL:
		ret = kvm_guest_csd_lock_ctl(vcpu,
				(csd_ctl_t)arg1, (void *)arg2);
		break;
	case KVM_HCALL_GUEST_IOPORT_REQ:
		ret = kvm_guest_ioport_request(vcpu, (u16)arg1,
			(u32 __user *)arg2, (u8)arg3, (u8)arg4);
		break;
	case KVM_HCALL_GUEST_IOPORT_STRING_REQ:
		ret = kvm_guest_ioport_string_request(vcpu, (u16)arg1,
			(void __user *)arg2, (u8)arg3, (u32) arg4, (u8)arg5);
		break;
	case KVM_HCALL_GUEST_MMIO_REQ:
		ret = kvm_guest_mmio_request(vcpu, arg1,
			(u64 __user *)arg2, (u8)arg3, (u8)arg4);
		break;
	case KVM_HCALL_CONSOLE_IO:
		ret = kvm_guest_console_io(vcpu, (int)arg1, (int)arg2,
					(char __user *)arg3);
		break;
	case KVM_HCALL_NOTIFY_IO:
		ret = kvm_guest_notify_io(vcpu, (unsigned int)arg1);
		break;
	case KVM_HCALL_GUEST_VCPU_COMMON_IDLE:
		ret = kvm_guest_vcpu_common_idle(vcpu, arg1, (bool)arg2);
		break;
	case KVM_HCALL_GUEST_VCPU_RELAX:
		kvm_guest_vcpu_relax();
		break;
#ifdef	CONFIG_SMP
	case KVM_HCALL_ACTIVATE_GUEST_VCPU:
		ret = kvm_activate_host_vcpu(kvm, (int)arg1);
		break;
	case KVM_HCALL_ACTIVATE_GUEST_ALL_VCPUS:
		ret = kvm_activate_guest_all_vcpus(kvm);
		break;
#endif	/* CONFIG_SMP */
	case KVM_HCALL_HOST_PRINTK:
		ret = kvm_guest_printk_on_host(vcpu, (char __user *)arg1,
						(int)arg2);
		break;
	case KVM_HCALL_GET_SPT_TRANSLATION:
		ret = kvm_get_va_spt_translation(vcpu, arg1,
					(mmu_spt_trans_t __user *)arg2);
		break;
	case KVM_HCALL_DUMP_ALL_TLB:
		tracing_off();
		native_print_all_tlb();
		ret = 0;
		break;
	case KVM_HCALL_DUMP_HOST_AND_GUEST_PT:
		ret = kvm_dump_host_and_guest_pts(kvm, (int)arg1, arg2, arg3);
		break;
	case KVM_HCALL_PRINT_GUEST_KERNEL_PTES:
		ret = kvm_print_guest_kernel_ptes(arg1);
		break;
	case KVM_HCALL_PRINT_GUEST_USER_ADDRESS_PTES:
		ret = kvm_print_guest_user_address_ptes(kvm,
						(int)arg1, arg2);
		break;
	case KVM_HCALL_SHUTDOWN:
		ret = kvm_guest_shutdown(vcpu, (void __user *)arg1, arg2);
		break;
	case KVM_HCALL_DUMP_GUEST_STACK: {
		dump_stack();
		break;
	}
	case KVM_HCALL_FTRACE_STOP:
		if (kvm_ftrace_dump) {
			ftrace_dump(DUMP_ALL);
			tracing_on();
		} else {
			tracing_off();
		}
		break;
	case KVM_HCALL_FTRACE_DUMP:
		ftrace_dump(DUMP_ALL);
		break;
	case KVM_HCALL_DUMP_COMPLETION:
		kvm_complete_vcpu_show_state(vcpu);
		break;
#ifdef CONFIG_KVM_ASYNC_PF
	case KVM_HCALL_PV_ENABLE_ASYNC_PF:
		ret = kvm_pv_host_enable_async_pf(vcpu, (u64) arg1,
				(u64) arg2, (u32) arg3, (u32) arg4);
		break;
#endif /* CONFIG_KVM_ASYNC_PF */
	case KVM_HCALL_MMU_PV_FLUSH_TLB:
		ret = kvm_pv_sync_and_flush_tlb(vcpu,
				(mmu_spt_flush_t __user *)arg1);
		break;
	case KVM_HCALL_SYNC_ADDR_RANGE:
		ret = kvm_pv_sync_addr_range(vcpu, arg1, arg2);
		break;
	case KVM_HCALL_PREPARE_MKCTXT_HW_USER_STACKS:
		ret = kvm_prepare_gst_mkctxt_hw_stacks(vcpu,
					(kvm_proc_ctxt_hw_stacks_t *)arg1);
		break;
	case KVM_HCALL_ADD_CTX_SIGNAL_STACK:
		ret = kvm_add_ctx_signal_stack(vcpu, (u64) arg1,
						(bool)arg2);
		break;
	case KVM_HCALL_REMOVE_CTX_SIGNAL_STACK:
		kvm_remove_ctx_signal_stack(vcpu, (u64) arg1);
		break;
	default:
		pr_err_ratelimited("Bad hypercall #%li\n", hcall_num);
		ret = -ENOSYS;
	}

skip_hcall:
	if (ret == RETURN_TO_HOST_APP_HCRET) {
		to_host_vcpu = true;
		ret = 0;
	}

	raw_all_irq_disable();
	while (need_resched()) {
		raw_all_irq_enable();
		schedule();
		raw_all_irq_disable();
	}

	/* It can be trap on hypercall handler (due to guest user address */
	/* access while copy from/to user for example). So: */
	/* 1) the guest process can be scheduled and migrate to other VCPU */
	/* 2) host VCPU thread was changed and */
	/* 3) need update thread info and */
	/* 4) VCPU satructures pointers */
	KVM_HOST_UPDATE_VCPU_THREAD_CONTEXT(NULL, &ti, NULL, NULL, &vcpu);
	GTI_BUG_ON(gti != ti->gthread_info);

	/* Update run state of guest */
	WARN_ON(kvm_get_guest_vcpu_runstate(vcpu) != RUNSTATE_in_hcall);
	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_running);
	/* update guest system time common with host */
	kvm_update_guest_system_time(vcpu->kvm);

	gti = ti->gthread_info;
	if (gti != NULL) {
		/* restore guest kernel UPSR state from guest thread info
		DO_RESTORE_GUEST_KERNEL_UPSR(gti, upsr_to_save);
		 */
	}

	vcpu->arch.hcall_irqs_disabled = false;

	trace_generic_hcall_exit(ret);

	if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu) || cpu_has(CPU_HWBUG_VIRT_TLU_IB)) {
		trace_host_flush_tlb(vcpu);
		kvm_vcpu_flush_tlb(vcpu);
	}

	/* generic hypercall execution completed */
	if (!from_generic_hypercall)
		clear_thread_flag(TIF_GENERIC_HYPERCALL);
	if (from_light_hypercall)
		set_thread_flag(TIF_LIGHT_HYPERCALL);

	/*
	 * Now we should restore kernel saved stack state and
	 * return to guest kernel data stack, if it need
	 */
	if (ti->gthread_info != NULL &&
		!test_gti_thread_flag(ti->gthread_info, GTIF_KERNEL_THREAD)) {
		RESTORE_KVM_GUEST_KERNEL_STACKS_STATE(ti);
		delete_gpt_regs(ti);
		DebugKVMACT("restored guest data stack : "
			"base 0x%llx, size 0x%x, top 0x%lx\n",
			ti->gthread_info->stack_regs.stacks.usd_lo.USD_lo_base,
			ti->gthread_info->stack_regs.stacks.usd_hi.USD_hi_size,
			ti->gthread_info->stack_regs.stacks.top);
		if (DEBUG_GPT_REGS_MODE)
			print_all_gpt_regs(ti);
	}

	if (to_new_stacks) {
		switch_to_new_hv_vcpu_stacks(vcpu, &stack_regs);
	} else if (to_new_user_stacks) {
		switch_to_new_user_pv_vcpu_stacks(vcpu, &stack_regs);
	}

	/* if there are pending VIRQs, then provide with direct interrupt */
	/* to cause guest interrupting and handling VIRQs */
	has_signal_pending = signal_pending(current);
	if (unlikely(!to_host_vcpu && !has_signal_pending)) {
		need_inject = kvm_try_inject_event_wish(ti->vcpu, ti,
					kvm_get_guest_vcpu_UPSR_value(vcpu),
					kvm_get_guest_vcpu_PSR_value(vcpu));
	} else {
		need_inject = false;
	}

	/*
	 * Ensure we set mode to IN_GUEST_MODE after we disable
	 * interrupts and before the final VCPU requests check.
	 * See the comment in kvm_vcpu_exiting_guest_mode() and
	 * Documentation/virt/kvm/vcpu-requests.rst
	 */
	smp_store_mb(vcpu->mode, IN_GUEST_MODE);

	if (!vcpu->arch.is_hv) {
		/* set flags of return type to guest kernel or guest user: */
		if (likely(!to_new_user_stacks)) {
			/* it is to kernel for now */
			host_return_to_guest_kernel(ti);
		} else {
			/* it is to user for now */
			host_return_to_guest_user(ti, to_new_context);
			/* set current u_pptb context to new user PT */
			kvm_set_vcpu_spt_u_pptb_context(vcpu);
		}
	}

	/* check saved greg and running VCPU IDs: should be the same */
	kvm_check_vcpu_state_greg();

	if (from_sdisp) {
		trace_host_get_gmm_root_hpa(pv_vcpu_get_gmm(vcpu),
					    NATIVE_READ_IP_REG_VALUE());
	}
	__guest_enter(ti, &vcpu->arch, guest_enter_flags);
	if (guest_enter_flags & DONT_RESTORE_HOST_GREGS) {
		CLEAR_HOST_KERNEL_GREGS();
	}

	/* from here cannot by any traps including BUG/BUG_ON/E2K_KVM_BUG_ON */
	/* because of host context is switched to guest context */

	/*
	 * Return control from UPSR register to PSR, if UPSR
	 * interrupts control is used.
	 * RETURN operation restores PSR state at hypercall point and
	 * recovers interrupts control
	 * Restoring of user UPSR should be after global registers restoring
	 * to preserve FP disable exception on movfi instructions
	 * while global registers manipulations
	 */
	NATIVE_RETURN_LWISH_TO_KERNEL_IRQ_MASK_REG(irq_flags, need_inject);

	if (!from_sdisp) {
		E2K_HRET(ret);
	}

	if (!(to_new_user_stacks || to_new_stacks)) {
		users = kvm_pv_restore_hcall_guest_stacks(ti->vcpu);
	} else {
		kvm_pv_clear_hcall_host_stacks(ti->vcpu);
	}

	if (to_host_vcpu || has_signal_pending) {
		return pv_vcpu_return_to_host(ti, vcpu, ret);
	}

	return ret;
}
