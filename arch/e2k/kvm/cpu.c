
/*
 * CPU virtualization
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/uaccess.h>
#include <asm/cpu_regs.h>
#include <asm/trap_table.h>
#include <asm/traps.h>
#include <asm/kvm/process.h>
#include <asm/kvm/runstate.h>
#include <asm/kvm/switch.h>
#include <asm/kvm/trace_kvm_pv.h>
#include "cpu.h"
#include "gregs.h"
#include "process.h"
#include "mmu.h"
#include "gaccess.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_GREGS_MODE
#undef	DebugGREGS
#define	DEBUG_KVM_GREGS_MODE	0	/* global registers debugging */
#define	DebugGREGS(fmt, args...)					\
({									\
	if (DEBUG_KVM_GREGS_MODE)					\
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

#undef	DEBUG_SHADOW_CONTEXT_MODE
#undef	DebugSHC
#define	DEBUG_SHADOW_CONTEXT_MODE 0	/* shadow context debugging */
#define	DebugSHC(fmt, args...)					\
({									\
	if (DEBUG_SHADOW_CONTEXT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_HWS_UPDATE_MODE
#undef	DebugKVMHSU
#define	DEBUG_KVM_HWS_UPDATE_MODE	0	/* hardware stacks frames */
						/* update debugging */
#define	DebugKVMHSU(fmt, args...)					\
({									\
	if (DEBUG_KVM_HWS_UPDATE_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_HWS_PATCH_MODE
#undef	DebugKVMHSP
#define	DEBUG_KVM_HWS_PATCH_MODE	0	/* hardware stacks frames */
						/* patching debug */
#define	DebugKVMHSP(fmt, args...)					\
({									\
	if (DEBUG_KVM_HWS_PATCH_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_GUEST_HS_MODE
#undef	DebugGHS
#define	DEBUG_GUEST_HS_MODE	0	/* Hard Stack expantions */
#define	DebugGHS(fmt, args...)						\
({									\
	if (DEBUG_GUEST_HS_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PV_VCPU_TRAP_MODE
#undef	DebugTRAP
#define	DEBUG_PV_VCPU_TRAP_MODE	0	/* trap injection debugging */
#define	DebugTRAP(fmt, args...)						\
({									\
	if (DEBUG_PV_VCPU_TRAP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PV_VCPU_SIG_MODE
#undef	DebugSIG
#define	DEBUG_PV_VCPU_SIG_MODE	0	/* signals injection debugging */
#define	DebugSIG(fmt, args...)						\
({									\
	if (DEBUG_PV_VCPU_SIG_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PV_UST_MODE
#undef	DebugUST
#define	DEBUG_PV_UST_MODE	0	/* trap injection debugging */
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

bool debug_guest_user_stacks = false;

void kvm_set_pv_vcpu_kernel_image(struct kvm_vcpu *vcpu)
{
	bool nonpaging = !is_paging(vcpu);
	e2k_oscud_lo_t oscud_lo;
	e2k_oscud_hi_t oscud_hi;
	e2k_osgd_lo_t osgd_lo;
	e2k_osgd_hi_t osgd_hi;
	e2k_cute_t *cute_p;
	e2k_addr_t base;
	e2k_cutd_t cutd;

	oscud_lo.OSCUD_lo_half = 0;
	oscud_lo.OSCUD_lo_base = (u64)vcpu->arch.guest_base;
	oscud_hi.OSCUD_hi_half = 0;
	oscud_hi.OSCUD_hi_size = vcpu->arch.guest_size;
	kvm_set_guest_vcpu_OSCUD(vcpu, oscud_hi, oscud_lo);
	DebugKVM("set OSCUD to guest kernel image: base 0x%llx, size 0x%x\n",
			oscud_lo.OSCUD_lo_base, oscud_hi.OSCUD_hi_size);
	kvm_set_guest_vcpu_CUD(vcpu, oscud_hi, oscud_lo);
	DebugKVM("set CUD to init state: base 0x%llx, size 0x%x\n",
		oscud_lo.CUD_lo_base, oscud_hi.CUD_hi_size);

	osgd_lo.OSGD_lo_half = 0;
	osgd_lo.OSGD_lo_base = (u64)vcpu->arch.guest_base;
	osgd_hi.OSGD_hi_half = 0;
	osgd_hi.OSGD_hi_size = vcpu->arch.guest_size;
	kvm_set_guest_vcpu_OSGD(vcpu, osgd_hi, osgd_lo);
	DebugKVM("set OSGD to guest kernel image: base 0x%llx, size 0x%x\n",
		osgd_lo.OSGD_lo_base, osgd_hi.OSGD_hi_size);
	kvm_set_guest_vcpu_GD(vcpu, osgd_hi, osgd_lo);
	DebugKVM("set GD to init state: base 0x%llx, size 0x%x\n",
		osgd_lo.GD_lo_base, osgd_hi.GD_hi_size);

	cute_p = (e2k_cute_t *)kvm_vcpu_hva_to_gpa(vcpu,
					(unsigned long)vcpu->arch.guest_cut);
	base = (e2k_addr_t)cute_p;
	cutd.CUTD_reg = 0;
	cutd.CUTD_base = base;
	kvm_set_guest_vcpu_OSCUTD(vcpu, cutd);
	kvm_set_guest_vcpu_CUTD(vcpu, cutd);
	DebugKVM("set OSCUTD & CUTD to init state: base 0x%llx\n",
		cutd.CUTD_base);
}

void kvm_init_cpu_state(struct kvm_vcpu *vcpu)
{
	{
		u64 osr0;

		osr0 = 0;
		kvm_set_guest_vcpu_OSR0(vcpu, osr0);
		DebugKVM("set OSR0 to init state: base 0x%llx\n",
			osr0);
	}
	{
		e2k_core_mode_t core_mode;

		core_mode.CORE_MODE_reg = 0;
		core_mode.CORE_MODE_pt_v6 = 0;
		core_mode.CORE_MODE_sep_virt_space = 0;
		kvm_set_guest_vcpu_CORE_MODE(vcpu, core_mode);
		DebugKVM("set CORE_MODE to init state: 0x%x\n",
			core_mode.CORE_MODE_reg);
	}

	/* TIRs num from -1: 0 it means 1 TIR */
	kvm_set_guest_vcpu_TIRs_num(vcpu, -1);

	/* Set virtual CPUs registers status to initial value */
	kvm_reset_guest_vcpu_regs_status(vcpu);
}

void kvm_init_cpu_state_idr(struct kvm_vcpu *vcpu)
{
	e2k_idr_t idr = kvm_vcpu_get_idr(vcpu);

	kvm_set_guest_vcpu_IDR(vcpu, idr);
	DebugKVM("set IDR to init state: 0x%llx\n",
		idr.IDR_reg);
}

static void vcpu_write_os_cu_hw_ctxt_to_registers(struct kvm_vcpu *vcpu,
				const struct kvm_hw_cpu_context *hw_ctxt)
{
	/*
	 * CPU shadow context
	 */
	kvm_set_guest_vcpu_OSCUD_lo(vcpu, hw_ctxt->sh_oscud_lo);
	kvm_set_guest_vcpu_OSCUD_hi(vcpu, hw_ctxt->sh_oscud_hi);
	kvm_set_guest_vcpu_OSGD_lo(vcpu, hw_ctxt->sh_osgd_lo);
	kvm_set_guest_vcpu_OSGD_hi(vcpu, hw_ctxt->sh_osgd_hi);
	kvm_set_guest_vcpu_OSCUTD(vcpu, hw_ctxt->sh_oscutd);
	kvm_set_guest_vcpu_OSCUIR(vcpu, hw_ctxt->sh_oscuir);
	DebugSHC("initialized VCPU #%d shadow context\n"
		"SH_OSCUD:  base 0x%llx size 0x%x\n"
		"SH_OSGD:   base 0x%llx size 0x%x\n"
		"CUTD:      base 0x%llx\n"
		"SH_OSCUTD: base 0x%llx\n"
		"SH_OSCUIR: index 0x%x\n",
		vcpu->vcpu_id,
		hw_ctxt->sh_oscud_lo.OSCUD_lo_base,
		hw_ctxt->sh_oscud_hi.OSCUD_hi_size,
		hw_ctxt->sh_osgd_lo.OSGD_lo_base,
		hw_ctxt->sh_osgd_hi.OSGD_hi_size,
		vcpu->arch.sw_ctxt.cutd.CUTD_base,
		hw_ctxt->sh_oscutd.CUTD_base,
		hw_ctxt->sh_oscuir.CUIR_index);
}

void write_hw_ctxt_to_pv_vcpu_registers(struct kvm_vcpu *vcpu,
				const struct kvm_hw_cpu_context *hw_ctxt,
				const struct kvm_sw_cpu_context *sw_ctxt)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	/*
	 * Stack registers
	 */
	kvm_set_guest_vcpu_PSP_lo(vcpu, hw_ctxt->sh_psp_lo);
	kvm_set_guest_vcpu_PSP_hi(vcpu, hw_ctxt->sh_psp_hi);
	kvm_set_guest_vcpu_PCSP_lo(vcpu, hw_ctxt->sh_pcsp_lo);
	kvm_set_guest_vcpu_PCSP_hi(vcpu, hw_ctxt->sh_pcsp_hi);

	DebugSHC("initialized VCPU #%d shadow registers:\n"
		"SH_PSP:   base 0x%llx size 0x%x index 0x%x\n"
		"SH_PCSP:  base 0x%llx size 0x%x index 0x%x\n",
		vcpu->vcpu_id,
		hw_ctxt->sh_psp_lo.PSP_lo_base, hw_ctxt->sh_psp_hi.PSP_hi_size,
		hw_ctxt->sh_psp_hi.PSP_hi_ind, hw_ctxt->sh_pcsp_lo.PCSP_lo_base,
		hw_ctxt->sh_pcsp_hi.PCSP_hi_size,
		hw_ctxt->sh_pcsp_hi.PCSP_hi_ind);

	kvm_set_guest_vcpu_WD(vcpu, hw_ctxt->sh_wd);

	/*
	 * MMU shadow context
	 */
	kvm_write_pv_vcpu_MMU_CR_reg(vcpu, hw_ctxt->sh_mmu_cr);
	kvm_write_pv_vcpu_mmu_PID_reg(vcpu, hw_ctxt->sh_pid);
	DebugSHC("initialized VCPU #%d MMU shadow context:\n"
		"SH_MMU_CR:  value 0x%llx\n"
		"SH_PID:     value 0x%llx\n"
		"GP_PPTB:    value 0x%llx\n"
		"sh_U_PPTB:  value 0x%lx\n"
		"sh_U_VPTB:  value 0x%lx\n"
		"U_PPTB:     value 0x%lx\n"
		"U_VPTB:     value 0x%lx\n"
		"GID:        value 0x%llx\n",
		vcpu->vcpu_id,
		hw_ctxt->sh_mmu_cr, hw_ctxt->sh_pid,
		mmu->get_vcpu_gp_pptb(vcpu),
		mmu->get_vcpu_context_u_pptb(vcpu),
		mmu->get_vcpu_context_u_vptb(vcpu),
		mmu->get_vcpu_u_pptb(vcpu),
		mmu->get_vcpu_u_vptb(vcpu),
		hw_ctxt->gid);

	/*
	 * CPU shadow context
	 */
	vcpu_write_os_cu_hw_ctxt_to_registers(vcpu, hw_ctxt);

	kvm_set_guest_vcpu_OSR0(vcpu, hw_ctxt->sh_osr0);
	DebugSHC("SH_OSR0: value 0x%llx\n", hw_ctxt->sh_osr0);
	kvm_set_guest_vcpu_CORE_MODE(vcpu, hw_ctxt->sh_core_mode);
	DebugSHC("SH_CORE_MODE: value 0x%x, gmi %s, hci %s\n",
		hw_ctxt->sh_core_mode.CORE_MODE_reg,
		(hw_ctxt->sh_core_mode.CORE_MODE_gmi) ? "true" : "false",
		(hw_ctxt->sh_core_mode.CORE_MODE_hci) ? "true" : "false");
}

void kvm_init_pv_vcpu_intc_handling(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	struct kvm_intc_cpu_context *intc_ctxt = &vcpu->arch.intc_ctxt;

	/* MMU intercepts were handled, clear state for new intercepts */
	kvm_clear_intc_mu_state(vcpu);

	/* clear hypervisor intercept event counters */
	intc_ctxt->cu_num = -1;
	intc_ctxt->mu_num = -1;
	intc_ctxt->cur_mu = -1;

	/* clear guest interception TIRs & trap cellar */
	if (likely(!vcpu->arch.trap_wish)) {
		kvm_clear_vcpu_intc_TIRs_num(vcpu);
		regs->traps_to_guest = 0;
	} else {
		/* some trap(s)was (were) injected as wish to handle them */
		regs->traps_to_guest = 0;
	}

	/* replace stacks->top value with real register SBR state */
	regs->stacks.top = regs->g_stacks.top;
}

noinline __interrupt void
startup_pv_vcpu(struct kvm_vcpu *vcpu, guest_hw_stack_t *stack_regs,
		unsigned flags)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	e2k_cr0_lo_t cr0_lo;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	e2k_psp_lo_t psp_lo;
	e2k_psp_hi_t psp_hi;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_sbr_t sbr;
	e2k_usd_lo_t usd_lo;
	e2k_usd_hi_t usd_hi;
	e2k_cutd_t cutd;
	bool is_pv_guest;

	is_pv_guest = test_thread_flag(TIF_PARAVIRT_GUEST);

	cr0_lo = stack_regs->crs.cr0_lo;
	cr0_hi = stack_regs->crs.cr0_hi;
	cr1_lo = stack_regs->crs.cr1_lo;
	cr1_hi = stack_regs->crs.cr1_hi;
	psp_lo = stack_regs->stacks.psp_lo;
	psp_hi = stack_regs->stacks.psp_hi;
	pcsp_lo = stack_regs->stacks.pcsp_lo;
	pcsp_hi = stack_regs->stacks.pcsp_hi;
	sbr.SBR_reg = stack_regs->stacks.top;
	usd_lo = stack_regs->stacks.usd_lo;
	usd_hi = stack_regs->stacks.usd_hi;
	cutd = stack_regs->cutd;

	/* return interrupts control to PSR and disable all IRQs */
	/* disable all IRQs in UPSR to switch mmu context */
	NATIVE_RETURN_TO_KERNEL_UPSR(E2K_KERNEL_UPSR_DISABLED_ALL);

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_running);

	if (unlikely(!(flags & FROM_HYPERCALL_SWITCH))) {
		KVM_BUG_ON(true);	/* now only from hypercall */
		/* save host VCPU data stack pointer registers */
		sw_ctxt->host_sbr = NATIVE_NV_READ_SBR_REG();
		sw_ctxt->host_usd_lo = NATIVE_NV_READ_USD_LO_REG();
		sw_ctxt->host_usd_hi = NATIVE_NV_READ_USD_HI_REG();
	}

	__guest_enter(current_thread_info(), &vcpu->arch, flags);

	/* switch host MMU to VCPU MMU context */
	kvm_switch_to_guest_mmu_pid(vcpu);

	if (flags & FROM_HYPERCALL_SWITCH) {
		int users;

		/* free MMU hypercall stacks */
		users = kvm_pv_put_hcall_guest_stacks(vcpu, false);
		KVM_BUG_ON(users != 0);
	}
	KVM_BUG_ON(host_hypercall_exit(vcpu));

	/* set guest UPSR to initial state */
	NATIVE_WRITE_UPSR_REG(sw_ctxt->upsr);

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

	NATIVE_NV_WRITE_USBR_USD_REG(sbr, usd_hi, usd_lo);

	NATIVE_NV_NOIRQ_WRITE_CUTD_REG(cutd);

	NATIVE_NV_NOIRQ_WRITE_CR0_LO_REG(cr0_lo);
	NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG(cr0_hi);
	NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG(cr1_lo);
	NATIVE_NV_NOIRQ_WRITE_CR1_HI_REG(cr1_hi);

	NATIVE_NV_WRITE_PSP_REG(psp_hi, psp_lo);
	NATIVE_NV_WRITE_PCSP_REG(pcsp_hi, pcsp_lo);

	KVM_COND_GOTO_RETURN_TO_PARAVIRT_GUEST(is_pv_guest, 0);
}

/* See at arch/include/asm/switch.h  the 'flags' argument values */
noinline __interrupt unsigned long
launch_pv_vcpu(struct kvm_vcpu *vcpu, unsigned switch_flags)
{
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	thread_info_t *ti = current_thread_info();
	e2k_cr0_lo_t cr0_lo;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	e2k_psp_lo_t psp_lo;
	e2k_psp_hi_t psp_hi;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	bool is_pv_guest = true;

	is_pv_guest = false;

	cr0_lo = sw_ctxt->crs.cr0_lo;
	cr0_hi = sw_ctxt->crs.cr0_hi;
	cr1_lo = sw_ctxt->crs.cr1_lo;
	cr1_hi = sw_ctxt->crs.cr1_hi;
	psp_lo = hw_ctxt->sh_psp_lo;
	psp_hi = hw_ctxt->sh_psp_hi;
	pcsp_lo = hw_ctxt->sh_pcsp_lo;
	pcsp_hi = hw_ctxt->sh_pcsp_hi;

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_running);

	/* Switch IRQ control to PSR and disable MI/NMIs */
	/* disable all IRQs in UPSR to switch mmu context */
	NATIVE_RETURN_TO_KERNEL_UPSR(E2K_KERNEL_UPSR_DISABLED_ALL);

	/* save host VCPU data stack pointer registers */
	sw_ctxt->host_sbr = NATIVE_NV_READ_SBR_REG();
	sw_ctxt->host_usd_lo = NATIVE_NV_READ_USD_LO_REG();
	sw_ctxt->host_usd_hi = NATIVE_NV_READ_USD_HI_REG();

	__guest_enter(ti, &vcpu->arch, switch_flags);

	/* switch host MMU to VCPU MMU context */
	kvm_switch_to_guest_mmu_pid(vcpu);

	/* from now the host process is at paravirtualized guest (VCPU) mode */
	set_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE);

	if (switch_flags & FROM_HYPERCALL_SWITCH) {
		int users;

		/* free MMU hypercall stacks */
		users = kvm_pv_put_hcall_guest_stacks(vcpu, false);
		KVM_BUG_ON(users != 0);
	}
	KVM_BUG_ON(host_hypercall_exit(vcpu));

	NATIVE_FLUSHCPU;	/* spill all host hardware stacks */

	sw_ctxt->crs.cr0_lo = NATIVE_NV_READ_CR0_LO_REG();
	sw_ctxt->crs.cr0_hi = NATIVE_NV_READ_CR0_HI_REG();
	sw_ctxt->crs.cr1_lo = NATIVE_NV_READ_CR1_LO_REG();
	sw_ctxt->crs.cr1_hi = NATIVE_NV_READ_CR1_HI_REG();

	E2K_WAIT_MA;		/* wait for spill completion */

	hw_ctxt->sh_psp_lo = NATIVE_NV_READ_PSP_LO_REG();
	hw_ctxt->sh_psp_hi = NATIVE_NV_READ_PSP_HI_REG();
	hw_ctxt->sh_pcsp_lo = NATIVE_NV_READ_PCSP_LO_REG();
	hw_ctxt->sh_pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();

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

	KVM_COND_GOTO_RETURN_TO_PARAVIRT_GUEST(is_pv_guest, 0);
	return 0;
}

notrace noinline __interrupt void
pv_vcpu_switch_to_host_from_intc(thread_info_t *ti)
{
	struct kvm_vcpu *vcpu = ti->vcpu;

	KVM_BUG_ON(vcpu == NULL);
	vcpu->arch.from_pv_intc = true;
	(void) switch_to_host_pv_vcpu_mode(ti, vcpu, false /* from vcpu-guest */,
			FULL_CONTEXT_SWITCH | DONT_AAU_CONTEXT_SWITCH |
			DONT_SAVE_KGREGS_SWITCH | DONT_MMU_CONTEXT_SWITCH |
			DONT_TRAP_MASK_SWITCH);
}

notrace noinline __interrupt void
pv_vcpu_return_to_intc_mode(thread_info_t *ti, struct kvm_vcpu *vcpu)
{
	KVM_BUG_ON(vcpu == NULL);
	vcpu->arch.from_pv_intc = false;
	(void) return_to_intc_pv_vcpu_mode(ti, vcpu,
			FULL_CONTEXT_SWITCH | DONT_AAU_CONTEXT_SWITCH |
			DONT_SAVE_KGREGS_SWITCH | DONT_MMU_CONTEXT_SWITCH |
			DONT_TRAP_MASK_SWITCH);
}

void kvm_emulate_pv_vcpu_intc(thread_info_t *ti, pt_regs_t *regs,
				trap_pt_regs_t *trap)
{
	do_emulate_pv_vcpu_intc(ti, regs, trap);
}

void return_from_pv_vcpu_intc(struct thread_info *ti, pt_regs_t *regs)
{
	do_return_from_pv_vcpu_intc(ti, regs);
}

static notrace __always_inline void inject_handler_trampoline(void)
{
	e2k_addr_t sbr;
	e2k_usd_lo_t usd_lo;
	e2k_usd_hi_t usd_hi;

	if (TASK_IS_PROTECTED(current))
		DISABLE_US_CLW();

	/*
	 * Switch to kernel stacks.
	 */
	GET_SIG_RESTORE_STACK(current_thread_info(), sbr, usd_lo, usd_hi);
	NATIVE_NV_WRITE_USBR_USD_REG_VALUE(sbr, AW(usd_hi), AW(usd_lo));

	/*
	 * Switch to %upsr for interrupts control
	 */
	DO_SAVE_UPSR_REG(current_thread_info()->upsr);
	SET_KERNEL_UPSR_WITH_DISABLED_NMI();
}

notrace noinline __interrupt __section(".entry.text")
void trap_handler_trampoline_continue(void)
{
	/* return to hypervisor context */
	return_from_pv_vcpu_inject(current_thread_info()->vcpu);

	inject_handler_trampoline();
	E2K_JUMP(return_pv_vcpu_trap);
}

notrace noinline __interrupt __section(".entry.text")
void syscall_handler_trampoline_continue(u64 sys_rval)
{
	struct kvm_vcpu *vcpu;

	vcpu = current_thread_info()->vcpu;
	/* return to hypervisor context */
	return_from_pv_vcpu_inject(vcpu);

	inject_handler_trampoline();

	syscall_handler_trampoline_start(vcpu, sys_rval);

	E2K_JUMP(return_pv_vcpu_syscall);
}

notrace noinline __interrupt __section(".entry.text")
void syscall_fork_trampoline_continue(u64 sys_rval)
{
	struct kvm_vcpu *vcpu;
	gthread_info_t *gti;

	vcpu = current_thread_info()->vcpu;
	/* return to hypervisor context */
	return_from_pv_vcpu_inject(vcpu);

	gti = pv_vcpu_get_gti(vcpu);
	KVM_BUG_ON(!is_sys_call_pt_regs(&gti->fork_regs));
	gti->fork_regs.sys_rval = sys_rval;

	inject_handler_trampoline();

	E2K_JUMP(return_pv_vcpu_syscall_fork);
}

static void fill_pv_vcpu_handler_trampoline(struct kvm_vcpu *vcpu,
				e2k_mem_crs_t *crs, inject_caller_t from)
{
	memset(crs, 0, sizeof(*crs));

	crs->cr0_lo.CR0_lo_pf = -1ULL;
	if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
		crs->cr0_hi.CR0_hi_IP = (u64)syscall_handler_trampoline;
	} else if (from == FROM_PV_VCPU_TRAP_INJECT) {
		crs->cr0_hi.CR0_hi_IP = (u64)trap_handler_trampoline;
	} else {
		KVM_BUG_ON(true);
	}
	crs->cr1_lo.CR1_lo_psr = E2K_KERNEL_PSR_DISABLED.PSR_reg;
	crs->cr1_lo.CR1_lo_cui = KERNEL_CODES_INDEX;
	if (machine.native_iset_ver < E2K_ISET_V6)
		crs->cr1_lo.CR1_lo_ic = 1;
	if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
		crs->cr1_lo.CR1_lo_wpsz = 1;
		crs->cr1_lo.CR1_lo_wbs = 0;
	} else if (from == FROM_PV_VCPU_TRAP_INJECT) {
		crs->cr1_lo.CR1_lo_wpsz = 0;
		crs->cr1_lo.CR1_lo_wbs = 0;
	} else {
		KVM_BUG_ON(true);
	}
	crs->cr1_hi.CR1_hi_ussz = pv_vcpu_get_gti(vcpu)->us_size >> 4;
}

static void prepare_pv_vcpu_inject_handler_trampoline(struct kvm_vcpu *vcpu,
				e2k_stacks_t *stacks, inject_caller_t from,
				bool guest_user)
{
	e2k_mem_crs_t *k_crs, crs;
	unsigned long flags;

	/*
	 * Prepare 'sighandler_trampoline' frame
	 */
	fill_pv_vcpu_handler_trampoline(vcpu, &crs, from);

	/*
	 * Copy the new frame into chain stack
	 *
	 * See user_hw_stacks_copy_full() for an explanation why this frame
	 * is located at (AS(ti->k_pcsp_lo).base).
	 */
	k_crs = (e2k_mem_crs_t *)current_thread_info()->k_pcsp_lo.PCSP_lo_base;

	raw_all_irq_save(flags);
	E2K_FLUSHC;
	/* User frame from *k_crs has been copied to userspace */
	/* already in user_hw_stacks_copy_full() */
	*k_crs = crs;
	raw_all_irq_restore(flags);

	if (unlikely(stacks->pcshtp > 0)) {
		/* top guest frame was spilled to memory */
		/* and is replaced at by the trampoline frame */
		stacks->pcsp_hi.PCSP_hi_ind += SZ_OF_CR;
	}
	DebugUST("set trampoline CRS at bottom of host stack from %px, "
		"increase guest kernel chain index 0x%x\n",
		k_crs, stacks->pcsp_hi.PCSP_hi_ind);
}

static int prepare_pv_vcpu_inject_handler_frame(struct kvm_vcpu *vcpu,
		pt_regs_t *regs, e2k_stacks_t *stacks, e2k_mem_crs_t *crs)
{
	thread_info_t *ti = current_thread_info();
	gthread_info_t *gti = pv_vcpu_get_gti(vcpu);
	unsigned long flags;
	e2k_mem_crs_t *k_crs;
	long g_pcshtp;
	int cui;

	/*
	 * Update chain stack
	 */
	memset(crs, 0, sizeof(*crs));

	cui = 0;

	/* FIXME: Here it need set guest OSCUD as CUD and remember curren CUD */
	/* which can be guest user CUD
	NATIVE_NV_NOIRQ_WRITE_CUTD_REG(vcpu->arch.hw_ctxt.oscutd);
	*/

	crs->cr0_lo.CR0_lo_pf = -1ULL;
	crs->cr0_hi.CR0_hi_IP = kvm_get_pv_vcpu_ttable_base(vcpu);
	/* real guest VCPU PSR should be as for user - nonprivileged */
	crs->cr1_lo.CR1_lo_psr = E2K_USER_INITIAL_PSR.PSR_reg;
	crs->cr1_lo.CR1_lo_cui = cui;
	if (machine.native_iset_ver < E2K_ISET_V6)
		crs->cr1_lo.CR1_lo_ic = 0;
	crs->cr1_lo.CR1_lo_wbs = 0;
	crs->cr1_hi.CR1_hi_ussz = stacks->usd_hi.USD_hi_size >> 4;

	/*
	 * handle_sys_call() does not restore %cr registers from pt_regs
	 * for performance reasons, so update chain stack in memory too.
	 *
	 * See user_hw_stacks_copy_full() for an explanation why this frame
	 * is located at (AS(ti->k_pcsp_lo).base + SZ_OF_CR).
	 */
	k_crs = (e2k_mem_crs_t *)ti->k_pcsp_lo.PCSP_lo_base;

	raw_all_irq_save(flags);
	E2K_FLUSHC;
	*(k_crs + 1) = *crs;
	raw_all_irq_restore(flags);
	DebugUST("set trap handler chain frame at bottom of host stack "
		"from %px and CRS at %px to return to handler instead of "
		"trap point\n",
		k_crs + 1, crs);

	/* See comment in user_hw_stacks_copy_full() */
	/* but guest user chain stack can be empty */
	g_pcshtp = PCSHTP_SIGN_EXTEND(stacks->pcshtp);
	KVM_BUG_ON(g_pcshtp != SZ_OF_CR && g_pcshtp != 0 && !regs->need_inject);

	return 0;
}

static int prepare_pv_vcpu_syscall_handler_frame(struct kvm_vcpu *vcpu,
						 pt_regs_t *regs)
{
	e2k_stacks_t *g_stacks = &regs->g_stacks;
	e2k_mem_crs_t *crs = &regs->crs;
	e2k_mem_ps_t ps_frames[4];
	e2k_mem_crs_t *k_crs;
	unsigned long flags, ts_flag;
	void __user *u_pframe;
	int arg, cui, wbs, ret;

	/*
	 * Update procedure stack
	 */
	memset(ps_frames, 0, sizeof(ps_frames));

	for (arg = 0; arg <= 6; arg++) {
		int frame = (arg * sizeof(*regs->args)) / (EXT_4_NR_SZ / 2);
		bool lo = (arg & 0x1) == 0x0;
		unsigned long long arg_value;

		if (arg == 0) {
			arg_value = regs->sys_num;
		} else {
			arg_value = regs->args[arg];
		}

		if (machine.native_iset_ver < E2K_ISET_V5) {
			if (lo)
				ps_frames[frame].v2.word_lo = arg_value;
			else
				ps_frames[frame].v2.word_hi = arg_value;
			/* Skip frame[2] and frame[3] - they hold */
			/* extended data not used by kernel */
		} else {
			if (lo)
				ps_frames[frame].v5.word_lo = arg_value;
			else
				ps_frames[frame].v5.word_hi = arg_value;
			/* Skip frame[1] and frame[3] - they hold */
			/* extended data not used by kernel */
		}
		DebugUST("   PS[%d].%s is 0x%016llx\n",
			frame, (lo) ? "lo" : "hi", arg_value);
	}

	u_pframe = (void __user *) (g_stacks->psp_lo.PSP_lo_base +
				    g_stacks->psp_hi.PSP_hi_ind);

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = copy_e2k_stack_to_user(u_pframe, &ps_frames, sizeof(ps_frames),
					regs);
	clear_ts_flag(ts_flag);
	if (ret)
		return -EFAULT;

	g_stacks->psp_hi.PSP_hi_ind += sizeof(ps_frames);
	DebugUST("set system call handler proc frame at bottom of guest "
		"kernel stack from %px\n",
		u_pframe);

	/*
	 * Update chain stack
	 */
	memset(crs, 0, sizeof(*crs));

	cui = 0;
	wbs = (sizeof(*regs->args) * 2 * 8 + (EXT_4_NR_SZ - 1)) / EXT_4_NR_SZ;

	/* FIXME: Here it need set guest OSCUD as CUD and remember curren CUD */
	/* which can be guest user CUD
	NATIVE_NV_NOIRQ_WRITE_CUTD_REG(vcpu->arch.hw_ctxt.oscutd);
	*/

	crs->cr0_lo.CR0_lo_pf = -1ULL;
	crs->cr0_hi.CR0_hi_IP = kvm_get_pv_vcpu_ttable_base(vcpu) +
					regs->kernel_entry *
						E2K_SYSCALL_TRAP_ENTRY_SIZE;
	/* real guest VCPU PSR should be as for user - nonprivileged */
	crs->cr1_lo.CR1_lo_psr = E2K_USER_INITIAL_PSR.PSR_reg;
	crs->cr1_lo.CR1_lo_cui = cui;
	if (machine.native_iset_ver < E2K_ISET_V6)
		crs->cr1_lo.CR1_lo_ic = 0;
	crs->cr1_lo.CR1_lo_wpsz = 4;
	crs->cr1_lo.CR1_lo_wbs = wbs;
	crs->cr1_hi.CR1_hi_ussz = g_stacks->usd_hi.USD_hi_size >> 4;

	/*
	 * handle_sys_call() does not restore %cr registers from pt_regs
	 * for performance reasons, so update chain stack in memory too.
	 *
	 * See user_hw_stacks_copy_full() for an explanation why this frame
	 * is located at (AS(ti->k_pcsp_lo).base + SZ_OF_CR).
	 */
	k_crs = (e2k_mem_crs_t *)current_thread_info()->k_pcsp_lo.PCSP_lo_base;

	raw_all_irq_save(flags);
	E2K_FLUSHC;
	*(k_crs + 1) = *crs;
	raw_all_irq_restore(flags);
	DebugUST("set trap handler chain frame at bottom of host stack "
		"from %px and CRS at %px to return to handler instead of "
		"trap point\n",
		k_crs + 1, crs);

	/* See comment in user_hw_stacks_copy_full() */
	BUG_ON(PCSHTP_SIGN_EXTEND(g_stacks->pcshtp) != SZ_OF_CR);

	return 0;
}

/**
 * setup_pv_vcpu_trap_stack - save priviliged part of interrupted
 * (emulated interception mode) user context to a special privileged area
 * now in user space of host VCPU process (qemu)
 */
static int setup_pv_vcpu_trap_stack(struct kvm_vcpu *vcpu, struct pt_regs *regs,
					inject_caller_t from)
{
	gthread_info_t *gti = pv_vcpu_get_gti(vcpu);
	struct signal_stack_context __user *context;
	pv_vcpu_ctxt_t __user *vcpu_ctxt;
	kvm_host_context_t *host_ctxt;
	int trap_no = 0;
	e2k_psr_t guest_psr;
	bool irq_under_upsr;
	unsigned long ts_flag;
	int ret;

	host_ctxt = &vcpu->arch.host_ctxt;
	if (from == FROM_PV_VCPU_TRAP_INJECT) {
		trap_no = atomic_inc_return(&host_ctxt->signal.traps_num);
		KVM_BUG_ON(atomic_read(&host_ctxt->signal.traps_num) <=
				atomic_read(&host_ctxt->signal.in_work));
	} else if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
		atomic_inc(&host_ctxt->signal.syscall_num);
		KVM_BUG_ON(atomic_read(&host_ctxt->signal.syscall_num) <=
				atomic_read(&host_ctxt->signal.in_syscall));
	} else {
		KVM_BUG_ON(true);
	}

	trace_pv_injection(from, &regs->stacks, &regs->crs,
		atomic_read(&host_ctxt->signal.traps_num),
		atomic_read(&host_ctxt->signal.syscall_num));

	ret = setup_signal_stack(regs, false);
	if (unlikely(ret)) {
		pr_err("%s(): could not create alt stack to save context, "
			"error %d\n",
			__func__, ret);
		return ret;
	}

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);

	context = get_signal_stack();
	vcpu_ctxt = &context->vcpu_ctxt;
	ret = 0;
	if (from == FROM_PV_VCPU_TRAP_INJECT) {
		ret |= __put_user(FROM_PV_VCPU_TRAP_INJECT,
					&vcpu_ctxt->inject_from);
		ret |= __put_user(trap_no, &vcpu_ctxt->trap_no);
	} else if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
		ret |= __put_user(FROM_PV_VCPU_SYSCALL_INJECT,
					&vcpu_ctxt->inject_from);
	} else {
		KVM_BUG_ON(true);
	}
	ret |= __put_user(false, &vcpu_ctxt->in_sig_handler);

	/* emulate guest VCPU PSR state after trap */
	guest_psr = kvm_emulate_guest_vcpu_psr_trap(vcpu, &irq_under_upsr);
	ret |= __put_user(guest_psr.PSR_reg, &(vcpu_ctxt->guest_psr.PSR_reg));
	ret |= __put_user(irq_under_upsr, &(vcpu_ctxt->irq_under_upsr));

	clear_ts_flag(ts_flag);

	return ret;
}

static int setup_pv_vcpu_trap(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	gthread_info_t *gti = pv_vcpu_get_gti(vcpu);
	bool guest_user;
	int ret;

	BUG_ON(!user_mode(regs));
	BUILD_BUG_ON(E2K_ALIGN_STACK !=
			max(E2K_ALIGN_USTACK_SIZE, E2K_ALIGN_PUSTACK_SIZE));

	guest_user = !pv_vcpu_trap_on_guest_kernel(regs);
	regs->is_guest_user = guest_user;
#if DEBUG_PV_UST_MODE
	debug_guest_ust = guest_user;
#endif
	if (guest_user && !regs->g_stacks_valid) {
		prepare_pv_vcpu_inject_stacks(vcpu, regs);
	}

	DebugTRAP("recursive trap injection, already %d trap(s), in work %d "
		"in %s mode\n",
		atomic_read(&vcpu->arch.host_ctxt.signal.traps_num),
		atomic_read(&vcpu->arch.host_ctxt.signal.in_work),
		(guest_user) ? "user" : "kernel");

	if (guest_user && gti->task_is_binco)
		NATIVE_SAVE_RPR_REGS(regs);

	/*
	 * After having called setup_signal_stack() we must unroll signal
	 * stack by calling pop_signal_stack() in case an error happens.
	 */
	ret = setup_pv_vcpu_trap_stack(vcpu, regs, FROM_PV_VCPU_TRAP_INJECT);
	if (ret)
		return ret;

	/*
	 * Copy guest's part of kernel hardware stacks into user
	 */
	if (guest_user) {
		ret = pv_vcpu_user_hw_stacks_copy_full(vcpu, regs);
	} else {
		ret = do_user_hw_stacks_copy_full(&regs->stacks, regs, &regs->crs);
		if (!ret)
			AS(regs->stacks.pcsp_hi).ind += SZ_OF_CR;
	}
	if (ret)
		goto free_signal_stack;

	/*
	 * We want user to return to inject_handler_trampoline so
	 * create fake kernel frame in user's chain stack
	 */
	if (guest_user) {
		prepare_pv_vcpu_inject_handler_trampoline(vcpu,
			&regs->g_stacks, FROM_PV_VCPU_TRAP_INJECT, true);
	} else {
		prepare_pv_vcpu_inject_handler_trampoline(vcpu,
			&regs->stacks, FROM_PV_VCPU_TRAP_INJECT, false);
	}

	/*
	 * guest's trap handler frame should be the last in stacks
	 */
	if (guest_user) {
		ret = prepare_pv_vcpu_inject_handler_frame(vcpu, regs,
						&regs->g_stacks, &regs->crs);
	} else {
		ret = prepare_pv_vcpu_inject_handler_frame(vcpu, regs,
						&regs->stacks, &regs->crs);
	}
	if (ret)
		goto free_signal_stack;

	if (guest_user) {
		/*
		 * Set copy of kernel & host global regs ti initial state:
		 *	kernel gregs is zeroed
		 *	host VCPU state greg is inited by pointer to the VCPU
		 * interface with guest
		 */
		INIT_HOST_GREGS_COPY(current_thread_info(), vcpu);
	} else {
		/* keep the current kernel & host global registers state */
		kvm_check_vcpu_state_greg();
	}

	return 0;

free_signal_stack:
	pop_signal_stack();

	return ret;
}

void insert_pv_vcpu_traps(thread_info_t *ti, pt_regs_t *regs)
{
	struct kvm_vcpu *vcpu;
	int failed;
	int TIRs_num;
	vcpu = ti->vcpu;
	KVM_BUG_ON(vcpu == NULL);

	KVM_BUG_ON(!kvm_test_intc_emul_flag(regs));
	KVM_BUG_ON(vcpu->arch.sw_ctxt.in_hypercall);

	TIRs_num = kvm_get_guest_vcpu_TIRs_num(vcpu);
	if (atomic_read(&vcpu->arch.host_ctxt.signal.traps_num) > 1) {
		pr_debug("%s() recursive trap injection, already %d trap(s), "
			"in work %d\n",
			__func__,
			atomic_read(&vcpu->arch.host_ctxt.signal.traps_num),
			atomic_read(&vcpu->arch.host_ctxt.signal.in_work));
		if (TIRs_num >= 0) {
			pr_err("%s(): guest trap handler did not have time "
				"to read %d TIRs of previous injection\n",
				__func__, TIRs_num);
			KVM_BUG_ON(true);
		}
	} else {
		if (TIRs_num >= 0) {
			pr_err("%s(): new trap before previous TIRs read\n",
				__func__);
			print_all_TIRs(regs->trap->TIRs, regs->trap->nr_TIRs);
			print_pt_regs(regs);
			print_all_TIRs(vcpu->arch.kmap_vcpu_state->
							cpu.regs.CPU_TIRs,
					TIRs_num);
			do_exit(SIGKILL);
		}
	}

	kvm_clear_vcpu_guest_stacks_pending(vcpu, regs);

	kvm_set_pv_vcpu_SBBP_TIRs(vcpu, regs);
	kvm_set_pv_vcpu_trap_cellar(vcpu);
	kvm_set_pv_vcpu_trap_context(vcpu, regs);

	failed = setup_pv_vcpu_trap(vcpu, regs);

	if (failed) {
		do_exit(SIGKILL);
	}

}

static int setup_pv_vcpu_syscall(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	gthread_info_t *gti = pv_vcpu_get_gti(vcpu);
	int ret;

	DebugTRAP("start on VCPU #%d, system call entry #%d/%d, regs at %px\n",
		vcpu->vcpu_id, regs->kernel_entry, regs->sys_num, regs);

	BUG_ON(!user_mode(regs));
	regs->is_guest_user = true;

	BUILD_BUG_ON(E2K_ALIGN_STACK !=
			max(E2K_ALIGN_USTACK_SIZE, E2K_ALIGN_PUSTACK_SIZE));

#if DEBUG_PV_SYSCALL_MODE
	debug_guest_ust = true;
#endif

	KVM_BUG_ON(!is_sys_call_pt_regs(regs));
	gti->fork_regs = *regs;

	if (!regs->g_stacks_valid) {
		prepare_pv_vcpu_inject_stacks(vcpu, regs);
	}

	/*
	 * After having called setup_signal_stack() we must unroll signal
	 * stack by calling pop_signal_stack() in case an error happens.
	 */
	ret = setup_pv_vcpu_trap_stack(vcpu, regs, FROM_PV_VCPU_SYSCALL_INJECT);
	if (ret)
		return ret;

	/*
	 * Copy guest's part of kernel hardware stacks into user
	 */
	ret = pv_vcpu_user_hw_stacks_copy_full(vcpu, regs);
	if (ret)
		goto free_signal_stack;

	/*
	 * We want user to return to inject_handler_trampoline so
	 * create fake kernel frame in user's chain stack
	 */
	prepare_pv_vcpu_inject_handler_trampoline(vcpu, &regs->g_stacks,
				FROM_PV_VCPU_SYSCALL_INJECT, true);

	/*
	 * guest's trap handler frame should be the last in stacks
	 */
	ret = prepare_pv_vcpu_syscall_handler_frame(vcpu, regs);
	if (ret)
		goto free_signal_stack;

	/*
	 * Set copy of kernel & host global regs ti initial state:
	 *	kernel gregs is zeroed
	 *	host VCPU state greg is inited by pointer to the VCPU
	 * interface with guest
	 */
	INIT_HOST_GREGS_COPY(current_thread_info(), vcpu);

	return 0;

free_signal_stack:
	pop_signal_stack();

	return ret;
}

static void insert_pv_vcpu_syscall(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	int failed;

	save_pv_vcpu_sys_call_stack_regs(vcpu, regs);

	failed = setup_pv_vcpu_syscall(vcpu, regs);

	if (!failed) {
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
		if (regs->trap && regs->trap->flags & TRAP_RP_FLAG) {
			pr_err("%s(): binary compliler support is not yet "
				"impleneted for trap in generations mode\n",
				__func__);
			KVM_BUG_ON(true);
		}
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */
	} else {
		do_exit(SIGKILL);
	}

}

static int prepare_pv_vcpu_sigreturn_handler_trampoline(struct kvm_vcpu *vcpu,
				pt_regs_t *regs, inject_caller_t from)
{
	e2k_mem_crs_t crs;

	/*
	 * Create 'sighandler_trampoline' chain stack frame
	 */
	fill_pv_vcpu_handler_trampoline(vcpu, &crs, from);

	/*
	 * Copy the new frame into the top of guest kernel chain stack
	 */
	return pv_vcpu_user_hw_stacks_copy_crs(vcpu, &regs->g_stacks, regs,
						&crs);
}

static int prepare_pv_vcpu_sigreturn_frame(struct kvm_vcpu *vcpu,
			pt_regs_t *regs, unsigned long sigreturn_entry)
{
	e2k_stacks_t *g_stacks = &regs->g_stacks;
	e2k_mem_crs_t *crs = &regs->crs;
	int cui;

	memset(crs, 0, sizeof(*crs));

	cui = 0;

	crs->cr0_lo.CR0_lo_pf = -1ULL;
	crs->cr0_hi.CR0_hi_IP = sigreturn_entry;
	/* real guest VCPU PSR should be as for user - nonprivileged */
	crs->cr1_lo.CR1_lo_psr = E2K_USER_INITIAL_PSR.PSR_reg;
	crs->cr1_lo.CR1_lo_cui = cui;
	if (machine.native_iset_ver < E2K_ISET_V6)
		crs->cr1_lo.CR1_lo_ic = 0;
	crs->cr1_lo.CR1_lo_wbs = 0;
	crs->cr1_hi.CR1_hi_ussz = g_stacks->usd_hi.USD_hi_size >> 4;

	return 0;
}

static int setup_pv_vcpu_sigreturn(struct kvm_vcpu *vcpu,
			pv_vcpu_ctxt_t *vcpu_ctxt, pt_regs_t *regs)
{
	gthread_info_t *gti = pv_vcpu_get_gti(vcpu);
	inject_caller_t from = vcpu_ctxt->inject_from;
	unsigned long sigreturn_entry;
	int ret;

	if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
		DebugSIG("start on VCPU #%d, signal on system call\n",
			vcpu->vcpu_id);
	} else if (from == FROM_PV_VCPU_TRAP_INJECT) {
		DebugSIG("start on VCPU #%d, signal on trap\n",
			vcpu->vcpu_id);
	} else {
		KVM_BUG_ON(true);
	}

	KVM_BUG_ON(!user_mode(regs));
	regs->is_guest_user = true;

	regs->g_stacks_valid = false;
	prepare_pv_vcpu_inject_stacks(vcpu, regs);

	/*
	 * Copy guest user CRS to the bottom of guest kernel stack
	 * to return to trap/system call entry point
	 */
	ret = pv_vcpu_user_hw_stacks_copy_crs(vcpu, &regs->g_stacks, regs,
						&regs->crs);
	if (ret)
		goto error_out;

	/*
	 * We want user to return to inject_handler_trampoline so
	 * create fake kernel frame in user's chain stack
	 */
	ret = prepare_pv_vcpu_sigreturn_handler_trampoline(vcpu, regs, from);
	if (ret)
		goto error_out;

	/*
	 * guest's sigreturn frame should be at on chain stack registers (crs)
	 */
	sigreturn_entry = vcpu_ctxt->sigreturn_entry;
	ret = prepare_pv_vcpu_sigreturn_frame(vcpu, regs, sigreturn_entry);
	if (ret)
		goto error_out;

	return 0;

error_out:
	return ret;
}

noinline __interrupt void
switch_to_pv_vcpu_sigreturn(struct kvm_vcpu *vcpu, e2k_stacks_t *g_stacks,
				e2k_mem_crs_t *g_crs)
{
	e2k_cr0_lo_t cr0_lo;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	e2k_psp_lo_t psp_lo;
	e2k_psp_hi_t psp_hi;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_sbr_t sbr;
	e2k_usd_lo_t usd_lo;
	e2k_usd_hi_t usd_hi;
	e2k_cutd_t cutd;

	cr0_lo = g_crs->cr0_lo;
	cr0_hi = g_crs->cr0_hi;
	cr1_lo = g_crs->cr1_lo;
	cr1_hi = g_crs->cr1_hi;
	psp_lo = g_stacks->psp_lo;
	psp_hi = g_stacks->psp_hi;
	pcsp_lo = g_stacks->pcsp_lo;
	pcsp_hi = g_stacks->pcsp_hi;
	sbr.SBR_reg = g_stacks->top;
	usd_lo = g_stacks->usd_lo;
	usd_hi = g_stacks->usd_hi;
	cutd = vcpu->arch.hw_ctxt.sh_oscutd;

	/* return interrupts control to PSR and disable all IRQs */
	/* disable all IRQs in UPSR to switch mmu context */
	NATIVE_RETURN_TO_KERNEL_UPSR(E2K_KERNEL_UPSR_DISABLED_ALL);

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_running);

	__guest_enter(current_thread_info(), &vcpu->arch, 0);

	/* switch host MMU to VCPU MMU context */
	kvm_switch_to_guest_mmu_pid(vcpu);

	/* from now the host process is at paravirtualized guest (VCPU) mode */
	set_ts_flag(TS_HOST_AT_VCPU_MODE);

	/* set guest UPSR to initial state */
	NATIVE_WRITE_UPSR_REG(E2K_USER_INITIAL_UPSR);

	/* Restore guest kernel & host (vcpu state) global registers */
	HOST_RESTORE_GUEST_KERNEL_GREGS(pv_vcpu_get_gti(vcpu));

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

	NATIVE_NV_WRITE_USBR_USD_REG(sbr, usd_hi, usd_lo);

	NATIVE_NV_NOIRQ_WRITE_CUTD_REG(cutd);

	NATIVE_NV_NOIRQ_WRITE_CR0_LO_REG(cr0_lo);
	NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG(cr0_hi);
	NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG(cr1_lo);
	NATIVE_NV_NOIRQ_WRITE_CR1_HI_REG(cr1_hi);

	NATIVE_NV_WRITE_PSP_REG(psp_hi, psp_lo);
	NATIVE_NV_WRITE_PCSP_REG(pcsp_hi, pcsp_lo);
}

void insert_pv_vcpu_sigreturn(struct kvm_vcpu *vcpu, pv_vcpu_ctxt_t *vcpu_ctxt,
				pt_regs_t *regs)
{
	struct signal_stack_context __user *context;
	pv_vcpu_ctxt_t *u_vcpu_ctxt;
	unsigned long ts_flag;
	int failed;

	failed = setup_pv_vcpu_sigreturn(vcpu, vcpu_ctxt, regs);

	if (failed)
		goto fault;

	/* clear flag of return from signal handler */
	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	context = get_signal_stack();
	u_vcpu_ctxt = &context->vcpu_ctxt;
	failed = __put_user(false, &u_vcpu_ctxt->in_sig_handler);
	clear_ts_flag(ts_flag);

	if (failed)
		goto fault;

	switch_to_pv_vcpu_sigreturn(vcpu, &regs->g_stacks, &regs->crs);

fault:
	user_exit();
	do_exit(SIGKILL);
}

/*
 * The function should return bool 'is the system call from guest?'
 */
bool pv_vcpu_syscall_intc(thread_info_t *ti, pt_regs_t *regs)
{
	struct kvm_vcpu *vcpu = ti->vcpu;

	preempt_disable();

	/* disable all IRQs to switch mmu context */
	raw_all_irq_disable();

	__guest_exit(ti, &vcpu->arch, 0);

	/* return to hypervisor MMU context to emulate intercept */
	kvm_switch_to_host_mmu_pid(current->mm);

	kvm_set_intc_emul_flag(regs);

	raw_all_irq_enable();

	preempt_enable();

	/* replace stacks->top value with real register SBR state */
	regs->stacks.top = regs->g_stacks.top;
	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_intercept);

	insert_pv_vcpu_syscall(vcpu, regs);

	return true;	/* it is system call from guest */
}

static inline unsigned long
kvm_get_host_guest_glob_regs(struct kvm_vcpu *vcpu,
	unsigned long **g_gregs, unsigned long not_get_gregs_mask,
	bool dirty_bgr, unsigned int *bgr)
{
	global_regs_t gregs;
	unsigned long ret = 0;

	preempt_disable();	/* to save on one CPU */
	machine.save_gregs_on_mask(&gregs, dirty_bgr, not_get_gregs_mask);
	preempt_enable();

	if (copy_to_user_with_tags(g_gregs, gregs.g, sizeof(gregs.g))) {
		pr_err("%s(): could not copy global registers to user\n",
			__func__);
		ret = -EFAULT;
	}
	if (bgr != NULL) {
		if (put_user(gregs.bgr.BGR_reg, bgr)) {
			pr_err("%s(): could not copy BGR register to user\n",
				__func__);
			ret = -EFAULT;
		}
	}

	copy_k_gregs_to_gregs(&gregs, &current_thread_info()->k_gregs);

	if (ret == 0) {
		DebugGREGS("get %ld global registers of guest\n",
			sizeof(gregs.g) / sizeof(*gregs.g));
	}
	return ret;
}

unsigned long
kvm_get_guest_glob_regs(struct kvm_vcpu *vcpu,
	__user unsigned long *g_gregs[2], unsigned long not_get_gregs_mask,
	bool dirty_bgr, __user unsigned int *bgr)
{
	hva_t hva;
	kvm_arch_exception_t exception;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)g_gregs, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, "
			"inject page fault to guest\n", g_gregs);
		kvm_vcpu_inject_page_fault(vcpu, (void *)g_gregs, &exception);
		return -EAGAIN;
	}

	g_gregs = (void *)hva;
	if (bgr != NULL) {
		hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)bgr, true, &exception);
		if (kvm_is_error_hva(hva)) {
			DebugKVM("failed to find GPA for dst %lx GVA, "
				"inject page fault to guest\n", bgr);
			kvm_vcpu_inject_page_fault(vcpu, (void *)bgr,
						&exception);
			return -EAGAIN;
		}

		bgr = (void *)hva;
	}
	return kvm_get_host_guest_glob_regs(vcpu, g_gregs, not_get_gregs_mask,
						dirty_bgr, bgr);
}

static inline int
copy_gregs_to_guest_gregs(__user unsigned long *g_gregs[2],
				struct e2k_greg *gregs,
				int gregs_size)
{
	if (copy_to_user_with_tags(g_gregs, gregs, gregs_size)) {
		DebugKVM("could not copy global registers used by kernel "
			"to user\n");
		return -EFAULT;
	}
	return 0;
}

#ifdef	CONFIG_GREGS_CONTEXT
static inline int
copy_k_gregs_to_guest_gregs(__user unsigned long *g_gregs[2],
				global_regs_t *k_gregs)
{
	kernel_gregs_t *kerne_gregs;

	return copy_gregs_to_guest_gregs(
				&g_gregs[KERNEL_GREGS_PAIRS_START],
				&k_gregs->g[KERNEL_GREGS_PAIRS_START],
				sizeof(kerne_gregs->g));
}
#else	/* ! CONFIG_GREGS_CONTEXT */
static inline int
copy_k_gregs_to_guest_gregs(__user unsigned long *g_gregs[2],
				global_regs_t *k_gregs)
{
	return 0;
}
#endif	/* CONFIG_GREGS_CONTEXT */

static inline int
copy_h_gregs_to_guest_gregs(__user unsigned long *g_gregs[2],
				global_regs_t *h_gregs)
{
	host_gregs_t *host_gregs;

	return copy_gregs_to_guest_gregs(
				&g_gregs[HOST_GREGS_PAIRS_START],
				&h_gregs->g[HOST_GREGS_PAIRS_START],
				sizeof(host_gregs->g));
}

static inline int
copy_kernel_gregs_to_guest_gregs(__user unsigned long *g_gregs[2],
				kernel_gregs_t *k_gregs)
{
	return copy_gregs_to_guest_gregs(
				&g_gregs[KERNEL_GREGS_PAIRS_START],
				k_gregs->g,
				sizeof(k_gregs->g));
}

static inline int
copy_host_gregs_to_guest_gregs(__user unsigned long *g_gregs[2],
				host_gregs_t *h_gregs)
{
	return copy_gregs_to_guest_gregs(
				&g_gregs[HOST_GREGS_PAIRS_START],
				h_gregs->g,
				sizeof(h_gregs->g));
}

static inline int
copy_gregs_to_guest_local_gregs(__user unsigned long *l_gregs[2],
				global_regs_t *gregs)
{
	local_gregs_t *local_regs;

	if (copy_to_user_with_tags(l_gregs, &gregs->g[LOCAL_GREGS_START],
					sizeof(local_regs->g))) {
		DebugKVM("could not copy local global registers to user\n");
		return -EFAULT;
	}
	return 0;
}

#ifdef	CONFIG_GREGS_CONTEXT
static inline void
copy_guest_k_gregs_to_guest_gregs(global_regs_t *g_gregs,
					kernel_gregs_t *k_gregs)
{
	kernel_gregs_t *kernel_gregs;

	tagged_memcpy_8(&g_gregs->g[KERNEL_GREGS_PAIRS_START],
			&k_gregs->g[CURRENT_GREGS_PAIRS_INDEX_LO],
			sizeof(kernel_gregs->g));
}
#else	/* ! CONFIG_GREGS_CONTEXT */
static inline void
copy_guest_k_gregs_to_guest_gregs(global_regs_t *g_gregs,
					kernel_gregs_t *k_gregs)
{
	return 0;
}
#endif	/* CONFIG_GREGS_CONTEXT */

static inline void
copy_guest_h_gregs_to_guest_gregs(global_regs_t *g_gregs,
					host_gregs_t *h_gregs)
{
	host_gregs_t *host_gregs;

	tagged_memcpy_8(&g_gregs->g[HOST_GREGS_PAIRS_START],
			&h_gregs->g[HOST_VCPU_STATE_GREGS_PAIRS_INDEX_LO],
			sizeof(host_gregs->g));
}

unsigned long
kvm_get_guest_local_glob_regs(struct kvm_vcpu *vcpu,
				__user unsigned long *u_l_gregs[2],
				bool is_signal)
{
	thread_info_t *ti = current_thread_info();
	global_regs_t gregs;
	unsigned long **l_gregs = u_l_gregs;
	hva_t hva;
	kvm_arch_exception_t exception;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)l_gregs, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, inject page "
				"fault to guest\n", l_gregs);
		kvm_vcpu_inject_page_fault(vcpu, (void *)l_gregs, &exception);
		return -EAGAIN;
	}

	l_gregs = (void *)hva;
	preempt_disable();	/* to restore on one CPU */
	if (is_signal)
		machine.save_gregs_on_mask(&gregs,
				   true,	/* dirty BGR */
				   GLOBAL_GREGS_USER_MASK  | GUEST_GREGS_MASK);
	preempt_enable();
	if (KERNEL_GREGS_MAX_MASK & LOCAL_GREGS_USER_MASK) {
		copy_guest_k_gregs_to_guest_gregs(&gregs, &ti->k_gregs);
	}
	return copy_gregs_to_guest_local_gregs(l_gregs, &gregs);
}

int kvm_get_all_guest_glob_regs(struct kvm_vcpu *vcpu,
				__user unsigned long *g_gregs[2])
{
	thread_info_t *ti = current_thread_info();
	unsigned long **gregs = g_gregs;
	hva_t hva;
	int ret;
	kvm_arch_exception_t exception;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)gregs, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, inject page "
			"fault to guest\n", g_gregs);
		kvm_vcpu_inject_page_fault(vcpu, (void *)g_gregs, &exception);
		return -EAGAIN;
	}

	gregs = (void *)hva;
	ret = kvm_get_host_guest_glob_regs(vcpu, gregs, GUEST_GREGS_MASK,
				true,	/* dirty BGR */
				NULL);
	if (ret)
		return ret;
	ret = copy_kernel_gregs_to_guest_gregs(gregs, &ti->k_gregs);
	ret |= copy_host_gregs_to_guest_gregs(gregs, &ti->h_gregs);
	return ret;
}

unsigned long
kvm_set_guest_glob_regs(struct kvm_vcpu *vcpu,
	__user unsigned long *g_gregs[2], unsigned long not_set_gregs_mask,
	bool dirty_bgr, unsigned int *bgr)
{
	global_regs_t gregs;
	hva_t hva;
	unsigned long ret = 0;
	kvm_arch_exception_t exception;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)g_gregs, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, inject page "
			"fault to guest\n", g_gregs);
		kvm_vcpu_inject_page_fault(vcpu, (void *)g_gregs, &exception);
		return -EAGAIN;
	}

	g_gregs = (void *)hva;
	if (copy_from_user(gregs.g, g_gregs, sizeof(gregs.g))) {
		DebugKVM("could not copy global registers base from user\n");
		ret = -EFAULT;
	}

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)bgr, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, inject page "
			"fault to guest\n", bgr);
		kvm_vcpu_inject_page_fault(vcpu, (void *)bgr, &exception);
		return -EAGAIN;
	}

	bgr = (void *)hva;
	if (get_user(gregs.bgr.BGR_reg, bgr)) {
		DebugKVM("could not copy BGR registers from user\n");
		ret = -EFAULT;
	}
	get_k_gregs_from_gregs(&current_thread_info()->k_gregs, &gregs);

	preempt_disable();	/* to restore on one CPU */
	if (ret == 0) {
		machine.restore_gregs_on_mask(&gregs, dirty_bgr,
						not_set_gregs_mask);
		DebugKVM("set %ld global registers of guest\n",
			sizeof(gregs.g) / sizeof(*gregs.g));
	}
	preempt_enable();
	return ret;
}

#ifdef	CONFIG_GREGS_CONTEXT
static inline void
copy_k_gregs_from_guest_gregs(kernel_gregs_t *k_gregs, global_regs_t *g_gregs)
{
	kernel_gregs_t *kernel_gregs;

	tagged_memcpy_8(&k_gregs->g[CURRENT_GREGS_PAIRS_INDEX_LO],
				&g_gregs->g[KERNEL_GREGS_PAIRS_START],
				sizeof(kernel_gregs->g));
}
#else	/* ! CONFIG_GREGS_CONTEXT */
static inline void
copy_k_gregs_from_guest_gregs(kernel_gregs_t *k_gregs, global_regs_t *g_gregs)
{
	return 0;
}
#endif	/* CONFIG_GREGS_CONTEXT */

static inline void
copy_h_gregs_from_guest_gregs(host_gregs_t *h_gregs, global_regs_t *g_gregs)
{
	host_gregs_t *host_gregs;

	tagged_memcpy_8(&h_gregs->g[HOST_VCPU_STATE_GREGS_PAIRS_INDEX_LO],
				&g_gregs->g[HOST_GREGS_PAIRS_START],
				sizeof(host_gregs->g));
}

static inline void
copy_local_gregs_from_guest_gregs(global_regs_t *l_gregs,
					global_regs_t *g_gregs)
{
	local_gregs_t *local_gregs;

	tagged_memcpy_8(&l_gregs->g[LOCAL_GREGS_START],
				&g_gregs->g[LOCAL_GREGS_START],
				sizeof(local_gregs->g));
}

static inline int
copy_guest_local_gregs_to_gregs(global_regs_t *gregs,
				__user unsigned long *l_gregs[2])
{
	local_gregs_t *local_regs;

	if (copy_from_user_with_tags(&gregs->g[LOCAL_GREGS_START], l_gregs,
					sizeof(local_regs->g))) {
		DebugKVM("could not copy local global registers from user\n");
		return -EFAULT;
	}
	return 0;
}

int kvm_copy_guest_all_glob_regs(struct kvm_vcpu *vcpu,
		global_regs_t *h_gregs, __user unsigned long *g_gregs)
{
	hva_t hva;
	kvm_arch_exception_t exception;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)g_gregs, true, &exception);
	if (kvm_is_error_hva(hva)) {
		pr_err("%s(): failed to find GPA for dst %lx GVA, inject page "
			"fault to guest\n",
			__func__, g_gregs);
		kvm_vcpu_inject_page_fault(vcpu, (void *)g_gregs, &exception);
		return -EAGAIN;
	}

	g_gregs = (void *)hva;
	if (copy_from_user_with_tags(h_gregs->g, g_gregs, sizeof(h_gregs->g))) {
		pr_err("%s(); could not copy global registers from user\n",
			__func__);
		return -EFAULT;
	}

	return 0;
}

unsigned long
kvm_set_guest_local_glob_regs(struct kvm_vcpu *vcpu,
				__user unsigned long *u_l_gregs[2],
				bool is_signal)
{
	thread_info_t *ti = current_thread_info();
	global_regs_t gregs;
	unsigned long **l_gregs = u_l_gregs;
	hva_t hva;
	int ret;
	kvm_arch_exception_t exception;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)l_gregs, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, inject page "
			"fault to guest\n", l_gregs);
		kvm_vcpu_inject_page_fault(vcpu, (void *)l_gregs, &exception);
		return -EAGAIN;
	}

	l_gregs = (void *)hva;
	ret = copy_guest_local_gregs_to_gregs(&gregs, l_gregs);
	if (ret != 0)
		return ret;

	if (KERNEL_GREGS_MAX_MASK & LOCAL_GREGS_USER_MASK) {
		copy_k_gregs_from_guest_gregs(&ti->k_gregs, &gregs);
	}
	if (HOST_KERNEL_GREGS_MASK & LOCAL_GREGS_USER_MASK) {
		copy_h_gregs_from_guest_gregs(&ti->h_gregs, &gregs);
	}
	preempt_disable();	/* to restore on one CPU */
	if (is_signal)
		machine.restore_gregs_on_mask(&gregs,
			true,	/* dirty BGR */
			GLOBAL_GREGS_USER_MASK | GUEST_GREGS_MASK);
	preempt_enable();
	return ret;
}

#ifdef	CONFIG_KVM_HOST_MODE
/* It is paravirtualized host and guest kernel */
/* or native host kernel with virtualization support */
/* FIXME: kvm host and hypervisor features is not supported on guest mode */
/* and all files from arch/e2k/kvm should not be compiled for guest kernel */
/* only arch/e2k/kvm/guest/ implements guest kernel support */
/* So this ifdef should be deleted after excluding arch/e2k/kvm compilation */

#define printk		printk_fixed_args
#define __trace_bprintk	__trace_bprintk_fixed_args
#define panic		panic_fixed_args

/*
 * Return from host kernel to paravirtualized guest kernel image
 * It is used to return/done/call from host kernel to guest kernel
 * shadowed image (paravirtualized images of host and guest kernel).
 * In this case host and guest images start from identical virtual addresses
 * and it need switch from one image page table (only pgd level) to another
 */
unsigned long  notrace __interrupt __to_paravirt_guest
return_to_paravirt_guest(unsigned long ret_value)
{
	thread_info_t *ti = NATIVE_READ_CURRENT_REG();

	/* switch to guest shadow kernel image */
	if (ti->flags & _TIF_PARAVIRT_GUEST) {
		*ti->kernel_image_pgd_p = ti->shadow_image_pgd;
		/* guest and host kernel images are load to equal addresses */
		/* then switch from one to another must flush all caches */
		native_raw_flush_TLB_all();
		native_raw_write_back_CACHE_L12();
	}
	return ret_value;
}

/*
 * Done from host kernel trap handler to paravirtualized guest kernel image
 * WARNING: function should not have any CTPR and AAU based operations
 */
void  notrace __interrupt __to_paravirt_guest
done_to_paravirt_guest(void)
{
	thread_info_t *ti = NATIVE_READ_CURRENT_REG();

	/* switch to guest shadow kernel image */
	*ti->kernel_image_pgd_p = ti->shadow_image_pgd;

	/* guest and host kernel images are loaded to equal addresses */
	/* then switch from one to another must flush all caches */
	native_raw_flush_TLB_all();
	native_raw_write_back_CACHE_L12();

	E2K_DONE();
}

/*
 * Paravirtualized guest kernel function call from host kernel
 */
long  notrace __interrupt __to_paravirt_guest
as_paravirt_guest_entry(unsigned long arg0, unsigned long arg1,
			unsigned long arg2, unsigned long arg3,
			char *entry_point, bool priv_guest)
{
	thread_info_t *ti;
	long ret;

	ret = as_guest_entry_start(arg0, arg1, arg2, arg3,
					entry_point, priv_guest);

	/*
	 * Guest kernel does not use global registers, so need not save
	 * values of global regs. Only set current pointers
	 * If guest kernel use global registers to support PV OPS
	 * (paravirtualized host and guest) then these global registers
	 * were saved earlier.
	 * Guest use one global register to support VCPU state pointer,
	 * this global register was saved also earlier before start guest
	 * kernel process (host does not use this global register).
	 */
	ONLY_SET_KERNEL_GREGS(NATIVE_READ_CURRENT_REG());

	ti = current_thread_info();
	if (ti->flags & _TIF_PARAVIRT_GUEST) {
		/* return to host kernel image from guest shadow */
		*ti->kernel_image_pgd_p = ti->kernel_image_pgd;
		/* guest and host kernel images are load to equal addresses */
		/* then switch from one to another must flush all caches */
		native_raw_flush_TLB_all();
		native_raw_write_back_CACHE_L12();
		/* recalculate per-CPU offset after switch to host */
		/* virtual space, previous setting was based on guest image */
		/* virtual adresses */
		barrier();	/* only for compiler to complete all waitings */
				/* for flushing old guest virtual space */
		ONLY_SET_SMP_CPUS_GREGS(ti);
	}
	return ret;
}
long  notrace __interrupt __to_guest
call_guest_ttable_entry(int sys_num,
		u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5, u64 arg6,
		unsigned long ttable_func)
{
	thread_info_t *ti = current_thread_info();
	unsigned long kernel_image_pgd = pgd_val(ti->kernel_image_pgd);
	unsigned long *kernel_image_pgd_p;
	e2k_upsr_t guest_upsr;
	long ret;

	/* restore guest kernel UPSR state */
	NATIVE_WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_DISABLED));

	KVM_RESTORE_GUEST_KERNEL_UPSR(ti);

	ret = as_guest_ttable_entry(sys_num, arg1, arg2, arg3, arg4, arg5, arg6,
					ttable_func);

	NATIVE_SWITCH_TO_KERNEL_UPSR(guest_upsr,
				false,	/* enable IRQs */
				false	/* disable NMI */);

	/* the guest process can be scheduled and migrate to other VCPU */
	/* so host VCPU thread was changed and need update thread info */
	/* and VCPU satructures pointers */
	ti = NATIVE_READ_CURRENT_REG();

	/* save current state of guest kernel UPSR */
	KVM_SAVE_GUEST_KERNEL_UPSR(ti, guest_upsr);

	if (ti->flags & _TIF_PARAVIRT_GUEST) {
		/* return to host kernel image from guest shadow */
		/* system call (fork(), clone()) can create new mm context */
		/* or switch to other guest pgd, so update pointer */
		/* to kernel image */

		/* reread kernel image pgd, because of ti can be changed */
		kernel_image_pgd = pgd_val(ti->kernel_image_pgd);

		kernel_image_pgd_p = (unsigned long *)ti->kernel_image_pgd_p;
		*kernel_image_pgd_p = kernel_image_pgd;

		/* if guest and host kernel images load to equal addresses */
		/* then switch from one to another must flush all caches */
		native_raw_flush_TLB_all();
		native_raw_write_back_CACHE_L12();
	}
	return ret;
}

#undef	printk
#undef	__trace_bprintk
#undef	panic

/*
 * The following functions (excluding  return_to_guest_ttable_entry) are not
 * used and is here only to can disassemble and help us in creation assembler
 * macros GOTO_GUEST_KERNEL_TTABLE()
 * see file arch/e2k/include/asm/trap_table.h
 */


/* trap table entry #18 is used for auxiliary codes common for host and guest */

void return_to_guest_ttable_entry(unsigned long ttable_func)
{
	e2k_cr1_lo_t	cr1_lo;
	e2k_cr0_hi_t	cr0_hi;
	bool		priv;
	e2k_psr_t	psr;

	cr1_lo = NATIVE_NV_READ_CR1_LO_REG();
	cr0_hi = NATIVE_NV_READ_CR0_HI_REG();

	priv = (ttable_func & PL_PM_MASK) ? true : false;

	AS_WORD(psr) = 0;
	AS_STRUCT(psr).sge = 1;
	AS_STRUCT(psr).ie = 1;				/* sti(); */
	AS_STRUCT(psr).nmie = 1;			/* nm sti(); */
	AS_STRUCT(psr).pm = priv;			/* system/user mode */
	AS_STRUCT(cr1_lo).psr = AS_WORD(psr);
	AS_STRUCT(cr0_hi).ip = ttable_func >> 3;	/* start user IP */

	NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG(cr1_lo);
	NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG(cr0_hi);

	KVM_GOTO_RETURN_TO_PARAVIRT_GUEST(0);
}
long as_guest_ttable_entry_C(int sys_num,
		u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5, u64 arg6,
		unsigned long ttable_func)
{
	return_to_guest_ttable_entry(ttable_func);
	return 0;
}
#else	/* ! CONFIG_KVM_HOST_MODE */
/* It is native guest kernel. */
/* Virtualiztion in guest mode cannot be supported */
unsigned long return_to_paravirt_guest(unsigned long ret_value)
{
	BUG_ON(true);
	return 0;
}
long call_guest_ttable_entry(int sys_num,
		u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5, u64 arg6,
		unsigned long ttable_func)
{
	BUG_ON(true);
	return 0;
}
void return_to_guest_ttable_entry(unsigned long ttable_func)
{
	BUG_ON(true);
}
#endif	/* CONFIG_KVM_HOST_MODE */

void kvm_guest_vcpu_relax(void)
{
	yield();	/* to activate other VCPU waiting for real CPU */
}

int kvm_update_hw_stacks_frames(struct kvm_vcpu *vcpu,
		__user e2k_mem_crs_t *u_pcs_frame, int pcs_frame_ind,
		__user kernel_mem_ps_t *u_ps_frame,
				int ps_frame_ind, int ps_frame_size)
{
	kernel_mem_ps_t ps_frame[KVM_MAX_PS_FRAME_NUM_TO_UPDATE];
	e2k_mem_crs_t pcs_frame;
	e2k_mem_crs_t *pcs;
	e2k_mem_ps_t *ps;
	unsigned long flags;
	bool priv_guest;
	e2k_stacks_t *guest_stacks;
	hva_t hva;
	int ps_ind, pcs_ind;
	int frame;
	int ret;
	kvm_arch_exception_t exception;

	if ((pcs_frame_ind & E2K_ALIGN_PSTACK_TOP_MASK) != 0) {
		DebugKVM("chain stack frame ind 0x%x is not aligned\n",
			pcs_frame_ind);
		return -EINVAL;
	}
	if (ps_frame_size > KVM_MAX_PS_FRAME_SIZE_TO_UPDATE ||
			((ps_frame_size & E2K_ALIGN_PSTACK_TOP_MASK) != 0)) {
		DebugKVM("procedure stack frame size 0x%x is too big or not "
			"aligned\n", ps_frame_size);
		return -EINVAL;
	}
	if ((ps_frame_ind & E2K_ALIGN_PSTACK_TOP_MASK) != 0) {
		DebugKVM("procedure stack frame ind 0x%x is not aligned\n",
			ps_frame_ind);
		return -EINVAL;
	}
	/* hypercalls are running on own hardware stacks */
	guest_stacks = &vcpu->arch.guest_stacks.stacks;
	ps_ind = guest_stacks->psp_hi.PSP_hi_ind;
	pcs_ind = guest_stacks->pcsp_hi.PCSP_hi_ind;
	if (pcs_frame_ind >= pcs_ind) {
		DebugKVM("chain stack frame ind 0x%x is out of current "
			"stack boundaries 0x%x\n",
			pcs_frame_ind, pcs_ind);
		return -EINVAL;
	}
	if (ps_frame_ind + ps_frame_size > ps_ind) {
		DebugKVM("procedure stack frame ind 0x%x and size 0x%x "
			"is out of current stack boundaries 0x%x\n",
			ps_frame_ind, ps_frame_size, ps_ind);
		return -EINVAL;
	}
	ret = kvm_vcpu_copy_from_guest(vcpu, &pcs_frame, u_pcs_frame,
							sizeof(pcs_frame));
	if (unlikely(ret < 0)) {
		DebugKVM("copy chain stack frames from user failed, "
			"maybe retried\n");
		return ret;
	}
	ret = kvm_vcpu_copy_from_guest(vcpu, &ps_frame, u_ps_frame,
							ps_frame_size);
	if (unlikely(ret < 0)) {
		DebugKVM("copy procedure stack frames from user failed, "
			"maybe retried\n");
		return ret;
	}

	/* hardware virtualized guest runs by GLAUNCH at privileged mode */
	priv_guest = vcpu->arch.is_hv;

	raw_all_irq_save(flags);

	/* hypercalls are running on own hardware stacks */
	ps = (e2k_mem_ps_t *)guest_stacks->psp_lo.PSP_lo_base;
	pcs = (e2k_mem_crs_t *)guest_stacks->pcsp_lo.PCSP_lo_base;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)ps, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, inject page "
			"fault to guest\n", ps);
		kvm_vcpu_inject_page_fault(vcpu, (void *)ps, &exception);
		ret = -EAGAIN;
		goto out_error;
	}

	ps = (e2k_mem_ps_t *)hva;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)pcs, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, inject page "
			"fault to guest\n", pcs);
		kvm_vcpu_inject_page_fault(vcpu, (void *)pcs, &exception);
		ret = -EAGAIN;
		goto out_error;
	}

	pcs = (e2k_mem_crs_t *)hva;
	ps = &ps[ps_frame_ind / sizeof(*ps)];
	DebugKVMHSU("procedure stack frame to update: index 0x%x base %px\n",
		ps_frame_ind, ps);
	pcs = &pcs[pcs_frame_ind / sizeof(*pcs)];
	DebugKVMHSU("chain stack frame to update: index 0x%x base %px\n",
		pcs_frame_ind, pcs);

	if (pcs->cr1_lo.CR1_lo_pm && !priv_guest) {
		DebugKVM("try to update host kernel frame\n");
		ret = -EINVAL;
		goto out_error;
	}
	if (ps_frame_size > pcs->cr1_lo.CR1_lo_wbs * EXT_4_NR_SZ) {
		DebugKVM("try to update too big procedure frame\n");
		ret = -EINVAL;
		goto out_error;
	}

	/* FIXME: it need use kvm_vcpu_copy_/to_guest/from_guest() */
	/* functions to update guest hw stacks frames */

	/* now can update only IP field of chain stack registers */
	DebugKVMHSU("will update only CR0_hi IP from %pF to %pF\n",
		(void *)(pcs->cr0_hi.CR0_hi_IP),
		(void *)(pcs_frame.cr0_hi.CR0_hi_IP));
	pcs->cr0_hi = pcs_frame.cr0_hi;

	/* FIXME: tags are not copied */
	for (frame = 0; frame < ps_frame_size / EXT_4_NR_SZ; frame++) {
		if (machine.native_iset_ver < E2K_ISET_V5) {
			ps[frame].v2.word_lo = ps_frame[frame].word_lo;
			ps[frame].v2.word_hi = ps_frame[frame].word_hi;
			/* Skip frame[2] and frame[3] - they hold */
			/* extended data not used by kernel */
		} else {
			ps[frame].v5.word_lo = ps_frame[frame].word_lo;
			ps[frame].v5.word_hi = ps_frame[frame].word_hi;
			/* Skip frame[1] and frame[3] - they hold */
			/* extended data not used by kernel */
		}
	}

	raw_all_irq_restore(flags);

	return 0;

out_error:
	raw_all_irq_restore(flags);
	return ret;
}

int kvm_patch_guest_data_stack(struct kvm_vcpu *vcpu,
		__user kvm_data_stack_info_t *u_ds_patch)
{
	thread_info_t *ti = current_thread_info();
	gthread_info_t *gti = ti->gthread_info;
	kvm_data_stack_info_t ds_patch;
	int ret = 0;

	ret = kvm_vcpu_copy_from_guest(vcpu, &ds_patch, u_ds_patch,
							sizeof(ds_patch));
	if (unlikely(ret < 0)) {
		pr_err("%s(): copy dat stack pointers patch from user "
			"failed, maybe retried\n", __func__);
		return ret;
	}
	if (gti == NULL) {
		pr_err("%s(): process %s (%d) is not guest thread\n",
			__func__, current->comm, current->pid);
		return -EINVAL;
	}
	DebugKVMHSP("host guest kernel data stack bottom 0x%lx "
		"top 0x%lx size 0x%lx\n",
		gti->data_stack.bottom, gti->data_stack.top,
		gti->data_stack.size);
	DebugKVMHSP("native user data stack bottom 0x%lx top 0x%lx "
		"size 0x%lx\n",
		ti->u_stack.bottom, ti->u_stack.top, ti->u_stack.size);
	DebugKVMHSP("current guest kernel data stack top 0x%lx "
		"base 0x%llx size 0x%x\n",
		gti->stack_regs.stacks.u_top,
		gti->stack_regs.stacks.u_usd_lo.USD_lo_base,
		gti->stack_regs.stacks.u_usd_hi.USD_hi_size);
	DebugKVMHSP("patched data stack: top 0x%lx base 0x%lx size 0x%lx\n",
		ds_patch.top, ds_patch.usd_base, ds_patch.usd_size);
	if (ds_patch.protected) {
		pr_err("%s(): patching of protected data stacks is not "
			"yet implemented\n",
			__func__);
		return -EINVAL;
	}
	if (ds_patch.top < gti->data_stack.bottom ||
			ds_patch.top > gti->data_stack.top) {
		DebugKVMHSP("top to patch is out of data stack bounderies\n");
		return -EINVAL;
	}
	if (ds_patch.usd_base < gti->data_stack.bottom ||
			ds_patch.usd_base > gti->data_stack.top) {
		DebugKVMHSP("base to patch is out of data stack bounderies\n");
		return -EINVAL;
	}
	if (ds_patch.usd_base >= ds_patch.top) {
		DebugKVMHSP("base to patch is above of top to patch\n");
		return -EINVAL;
	}
	if (ds_patch.usd_base - ds_patch.usd_size < gti->data_stack.bottom) {
		DebugKVMHSP("base - size to patch is below of stack bottom\n");
		return -EINVAL;
	}
	if (ds_patch.top != gti->stack_regs.stacks.u_top) {
		DebugKVMHSP("will patch top (SBR) of guest kernel data stack "
			"from 0x%lx to 0x%lx\n",
			gti->stack_regs.stacks.u_top, ds_patch.top);
		gti->stack_regs.stacks.u_top = ds_patch.top;
	}
	if (ds_patch.usd_base != gti->stack_regs.stacks.u_usd_lo.USD_lo_base) {
		DebugKVMHSP("will patch base of guest kernel data stack "
			"from 0x%llx to 0x%lx\n",
			gti->stack_regs.stacks.u_usd_lo.USD_lo_base,
			ds_patch.usd_base);
		gti->stack_regs.stacks.u_usd_lo.USD_lo_base = ds_patch.usd_base;
	}
	if (ds_patch.usd_size != gti->stack_regs.stacks.u_usd_hi.USD_hi_size) {
		DebugKVMHSP("will patch size of guest kernel data stack "
			"from 0x%x to 0x%lx\n",
			gti->stack_regs.stacks.u_usd_hi.USD_hi_size,
			ds_patch.usd_size);
		gti->stack_regs.stacks.u_usd_hi.USD_hi_size = ds_patch.usd_size;
	}
	return ret;
}
int kvm_patch_guest_chain_stack(struct kvm_vcpu *vcpu,
		__user kvm_pcs_patch_info_t u_pcs_patch[], int pcs_frames)
{
	kvm_pcs_patch_info_t pcs_patch[KVM_MAX_PCS_FRAME_NUM_TO_PATCH];
	kvm_pcs_patch_info_t *patch;
	e2k_mem_crs_t *pcs, *frame;
	e2k_stacks_t *guest_stacks;
	e2k_addr_t pcs_base;
	hva_t hva;
	e2k_size_t pcs_ind, pcs_size, pcshtop;
	bool priv_guest;
	unsigned long flags;
	int fr_no;
	int ret = 0;
	kvm_arch_exception_t exception;

	if (pcs_frames > KVM_MAX_PCS_FRAME_NUM_TO_PATCH ||
			pcs_frames < 0) {
		pr_err("%s(): PCS frames number %d is too big, can only %d\n",
			__func__, pcs_frames, KVM_MAX_PCS_FRAME_NUM_TO_PATCH);
		return -EINVAL;
	}
	ret = kvm_vcpu_copy_from_guest(vcpu, pcs_patch, u_pcs_patch,
				sizeof(pcs_patch[0]) * pcs_frames);
	if (unlikely(ret < 0)) {
		pr_err("%s(): copy chain stack frames patch from user "
			"failed, maybe retried\n", __func__);
		return ret;
	}

	/* hardware virtualized guest runs by GLAUNCH at privileged mode */
	priv_guest = vcpu->arch.is_hv;

	raw_all_irq_save(flags);

	/* FIXME: disable stack boundaries traps to exclude resident window */
	/* change, because now is implemented patch only frames into */
	/* the resident window */
	//TODO is this needed now ??? native_reset_sge();

	guest_stacks = &vcpu->arch.guest_stacks.stacks;
	pcs_base = guest_stacks->pcsp_lo.PCSP_lo_base;
	pcs_ind = guest_stacks->pcsp_hi.PCSP_hi_ind;
	pcs_size = guest_stacks->pcsp_hi.PCSP_hi_size;
	pcshtop = 0;

	pcs = (e2k_mem_crs_t *)pcs_base;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)pcs, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, inject page "
			"fault to guest\n", pcs);
		kvm_vcpu_inject_page_fault(vcpu, (void *)pcs, &exception);
		ret = -EAGAIN;
		goto out_error;
	}

	pcs = (e2k_mem_crs_t *)hva;
	for (fr_no = 0; fr_no < pcs_frames; fr_no++) {
		patch = &pcs_patch[fr_no];
		DebugKVMHSP("PCS patch #%d will patch frame at ind 0x%x\n",
			fr_no, patch->ind);
		if (patch->ind < 0 || patch->ind >= pcs_ind + pcshtop) {
			DebugKVMHSP("PCS frame ind 0x%x to patch is out of "
				"chain stack boundaries\n",
				patch->ind);
			ret = -EINVAL;
			goto out_error;
		}
		/* FIXME: patching of not resident part of chain stack */
		/* is not implemented */
		WARN_ONCE(1, "stacks are not resident anymore");
		if (patch->ind >= pcs_ind) {
			pr_err("%s(): patching of chain stack frame ind 0x%x "
				"up of current final frame ind 0x%lx\n",
				__func__, patch->ind, pcs_ind);
			ret = -EINVAL;
			goto out_error;
		}
		frame = &pcs[patch->ind / sizeof(*pcs)];
		if (frame->cr1_lo.CR1_lo_pm && !priv_guest) {
			pr_err("%s(): try to patch host kernel frame\n",
				__func__);
			ret = -EINVAL;
			goto out_error;
		}
		if (patch->update_flags == 0) {
			DebugKVMHSP("PCS frame ind 0x%x update flags empty\n",
				patch->ind);
			continue;
		}
		if (patch->update_flags & KVM_PCS_IP_UPDATE_FLAG) {
			DebugKVMHSP("wiil patch IP from 0x%llx to 0x%lx at "
				"PCS frame ind 0x%x\n",
				frame->cr0_hi.CR0_hi_IP, patch->IP, patch->ind);
			frame->cr0_hi.CR0_hi_IP = patch->IP;
		}
		if (patch->update_flags & KVM_PCS_USSZ_UPDATE_FLAG) {
			DebugKVMHSP("wiil patch USD size from 0x%x to 0x%x "
				"at PCS frame ind 0x%x\n",
				frame->cr1_hi.CR1_hi_ussz, patch->usd_size >> 4,
				patch->ind);
			frame->cr1_hi.CR1_hi_ussz = patch->usd_size >> 4;
		}
		if (patch->update_flags & KVM_PCS_WBS_UPDATE_FLAG) {
			DebugKVMHSP("wiil patch wbs from 0x%x to 0x%x at "
				"PCS frame ind 0x%x\n",
				frame->cr1_lo.CR1_lo_wbs, patch->wbs,
				patch->ind);
			frame->cr1_lo.CR1_lo_wbs = patch->wbs;
		}
		if (patch->update_flags & KVM_PCS_WPSZ_UPDATE_FLAG) {
			DebugKVMHSP("wiil patch wpsz from 0x%x to 0x%x at "
				"PCS frame ind 0x%x\n",
				frame->cr1_lo.CR1_lo_wpsz, patch->wpsz,
				patch->ind);
			frame->cr1_lo.CR1_lo_wpsz = patch->wpsz;
		}
	}
	ret = 0;

out_error:

	/* FIXME: enabl stack boundaries traps to include resident window */
	/* change, because now is implemented patch only frames into */
	/* the resident window */
	//TODO needed?? native_set_sge();

	raw_all_irq_restore(flags);

	return ret;
}

int kvm_patch_guest_data_and_chain_stacks(struct kvm_vcpu *vcpu,
		__user kvm_data_stack_info_t *u_ds_patch,
		__user kvm_pcs_patch_info_t u_pcs_patch[], int pcs_frames)
{
	int ret = 0;

	if (u_ds_patch != NULL)
		ret = kvm_patch_guest_data_stack(vcpu, u_ds_patch);
	if (ret != 0)
		return ret;
	if (u_pcs_patch != NULL && pcs_frames != 0)
		ret = kvm_patch_guest_chain_stack(vcpu,
					u_pcs_patch, pcs_frames);
	return ret;
}
