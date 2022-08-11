
/*
 * CPU hardware virtualized support
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/uaccess.h>
#include <asm/cpu_regs.h>
#include <asm/epic.h>
#include <asm/trace.h>
#include <asm/trap_table.h>
#include <asm/traps.h>
#include <asm/mmu_regs_types.h>
#include <asm/system.h>
#include <asm/kvm/cpu_hv_regs_types.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/mmu_hv_regs_types.h>
#include <asm/kvm/mmu_hv_regs_access.h>
#include <asm/kvm/process.h>
#include <asm/kvm/runstate.h>
#include <asm/kvm/switch.h>
#include "cpu_defs.h"
#include "cpu.h"
#include "mmu_defs.h"
#include "mmu.h"
#include "gregs.h"
#include "process.h"
#include "intercepts.h"
#include "io.h"
#include "pic.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_STARTUP_MODE
#undef	DebugKVMSTUP
#define	DEBUG_KVM_STARTUP_MODE	0	/* VCPU startup debugging */
#define	DebugKVMSTUP(fmt, args...)					\
({									\
	if (DEBUG_KVM_STARTUP_MODE)					\
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

#undef	DEBUG_INTC_WAIT_TRAP_MODE
#undef	DebugWTR
#define	DEBUG_INTC_WAIT_TRAP_MODE	0	/* CU wait trap intercept */
#define	DebugWTR(fmt, args...)						\
({									\
	if (DEBUG_INTC_WAIT_TRAP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_IT_MODE
#undef	DebugKVMIT
#define	DEBUG_KVM_IT_MODE	0	/* CEPIC idle timer */
#define	DebugKVMIT(fmt, args...)					\
({									\
	if (DEBUG_KVM_IT_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})
#undef	VM_BUG_ON
#define VM_BUG_ON(cond) BUG_ON(cond)

int __nodedata slt_disable;

static void vcpu_write_os_cu_hw_ctxt_to_registers(struct kvm_vcpu *vcpu,
				const struct kvm_hw_cpu_context *hw_ctxt);

/*
 * FIXME: QEMU should pass physical addresses for entry IP and
 * for any addresses info into arguments list to pass to guest.
 * The function convert virtual physical adresses to physical
 * to enable VCPU startup at nonpaging mode
 */
void prepare_vcpu_startup_args(struct kvm_vcpu *vcpu)
{
	unsigned long entry_IP;
	u64 *args;
	int args_num, arg;
	unsigned long long arg_value;


	DebugKVMSTUP("started on VCPU #%d\n", vcpu->vcpu_id);

	if (is_paging(vcpu)) {
		DebugKVMSTUP("there is paging mode, nothing convertions "
			"need\n");
		return;
	}
	args_num = vcpu->arch.args_num;
	entry_IP = (unsigned long)vcpu->arch.entry_point;

	if (entry_IP >= GUEST_PAGE_OFFSET) {
		entry_IP = __guest_pa(entry_IP);
		vcpu->arch.entry_point = (void *)entry_IP;
	}
	DebugKVMSTUP("VCPU startup entry point at %px\n", (void *)entry_IP);

	args = vcpu->arch.args;

	/* prepare VCPU startup function arguments */
#pragma loop count (2)
	for (arg = 0; arg < args_num; arg++) {
		arg_value = args[arg];
		if (arg_value >= GUEST_PAGE_OFFSET) {
			arg_value = __guest_pa(arg_value);
			args[arg] = arg_value;
		}
		DebugKVMSTUP("   arg[%d] is 0x%016llx\n",
			arg, arg_value);
	}
}

void prepare_stacks_to_startup_vcpu(struct kvm_vcpu *vcpu,
		e2k_mem_ps_t *ps_frames, e2k_mem_crs_t *pcs_frames,
		u64 *args, int args_num, char *entry_point, e2k_psr_t psr,
		e2k_size_t usd_size, e2k_size_t *ps_ind, e2k_size_t *pcs_ind,
		int cui, bool kernel)
{
	e2k_cr0_lo_t cr0_lo;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	unsigned long entry_IP;
	bool priv_guest = vcpu->arch.is_hv;
	int arg;
	int wbs;

	DebugKVMSTUP("started on VCPU #%d\n", vcpu->vcpu_id);

	entry_IP = (unsigned long)entry_point;

	wbs = (sizeof(*args) * 2 * args_num + (EXT_4_NR_SZ - 1)) / EXT_4_NR_SZ;

	/* pcs[0] frame can be empty, because of it should not be returns */
	/* to here and it is used only to fill into current CR registers */
	/* while function on the next frame pcs[1] is running */
	pcs_frames[0].cr0_lo.CR0_lo_pf = -1;
	pcs_frames[0].cr0_hi.CR0_hi_ip = 0;
	pcs_frames[0].cr1_lo.CR1_lo_half = 0;
	pcs_frames[0].cr1_hi.CR1_hi_half = 0;

	/* guest is user of host for pv, GLAUNCH set PSR for hv */
	if (priv_guest) {
		/* guest should be run at privileged mode */
		psr.PSR_pm = 1;
	} else {
		/* guest is not privileged user task of host */
		psr.PSR_pm = 0;
	}

	/* Prepare pcs[1] frame, it is frame of VCPU start function */
	/* Important only only IP (as start of function) */
	cr0_lo.CR0_lo_half = 0;
	cr0_lo.CR0_lo_pf = -1;
	cr0_hi.CR0_hi_half = 0;
	cr0_hi.CR0_hi_IP = entry_IP;
	cr1_lo.CR1_lo_half = 0;
	cr1_lo.CR1_lo_psr = psr.PSR_reg;
	cr1_lo.CR1_lo_wbs = wbs;
	cr1_lo.CR1_lo_wpsz = cr1_lo.CR1_lo_wbs;
	cr1_lo.CR1_lo_cui = cui;
	if (!cpu_has(CPU_FEAT_ISET_V6))
		cr1_lo.CR1_lo_ic = kernel;

	cr1_hi.CR1_hi_half = 0;
	cr1_hi.CR1_hi_ussz = usd_size / 16;
	pcs_frames[1].cr0_lo = cr0_lo;
	pcs_frames[1].cr0_hi = cr0_hi;
	pcs_frames[1].cr1_lo = cr1_lo;
	pcs_frames[1].cr1_hi = cr1_hi;

	DebugKVMSTUP("VCPU start PCS[1]: IP %pF wbs 0x%x\n",
		(void *)(pcs_frames[1].cr0_hi.CR0_hi_ip << 3),
		pcs_frames[1].cr1_lo.CR1_lo_wbs * EXT_4_NR_SZ);
	DebugKVMSTUP("   PCS[%d] CR0 lo: 0x%016llx  hi: 0x%016llx\n",
		1, pcs_frames[1].cr0_lo.CR0_lo_half,
		pcs_frames[1].cr0_hi.CR0_hi_half);
	DebugKVMSTUP("   PCS[%d] CR1 lo: 0x%016llx  hi: 0x%016llx\n",
		1, pcs_frames[1].cr1_lo.CR1_lo_half,
		pcs_frames[1].cr1_hi.CR1_hi_half);
	DebugKVMSTUP("   PCS[%d] CR0 lo: 0x%016llx  hi: 0x%016llx\n",
		0, pcs_frames[0].cr0_lo.CR0_lo_half,
		pcs_frames[0].cr0_hi.CR0_hi_half);
	DebugKVMSTUP("   PCS[%d] CR1 lo: 0x%016llx  hi: 0x%016llx\n",
		0, pcs_frames[0].cr1_lo.CR1_lo_half,
		pcs_frames[0].cr1_hi.CR1_hi_half);

	/* prepare procedure stack frame ps[0] for pcs[1] should contain */
	/* VCPU start function arguments */
#pragma loop count (2)
	for (arg = 0; arg < args_num; arg++) {
		int frame = (arg * sizeof(*args)) / (EXT_4_NR_SZ / 2);
		bool lo = (arg & 0x1) == 0x0;
		unsigned long long arg_value;

		arg_value = args[arg];

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
		DebugKVMSTUP("   PS[%d].%s is 0x%016llx\n",
			frame, (lo) ? "lo" : "hi", arg_value);
	}

	/* set stacks pointers indexes */
	*ps_ind = wbs * EXT_4_NR_SZ;
	*pcs_ind = 2 * SZ_OF_CR;
	DebugKVMSTUP("stacks PS.ind 0x%lx PCS.ind 0x%lx\n",
		*ps_ind, *pcs_ind);
}

void prepare_bu_stacks_to_startup_vcpu(struct kvm_vcpu *vcpu)
{
	bu_hw_stack_t *hypv_backup;
	vcpu_boot_stack_t *boot_stacks;
	e2k_mem_crs_t *pcs_frames;
	e2k_mem_ps_t *ps_frames;
	e2k_size_t ps_ind, pcs_ind;
	bool priv_guest = vcpu->arch.is_hv;
	e2k_psr_t psr;

	DebugKVMSTUP("started on VCPU #%d\n", vcpu->vcpu_id);

	prepare_vcpu_startup_args(vcpu);
	hypv_backup = &vcpu->arch.hypv_backup;
	boot_stacks = &vcpu->arch.boot_stacks;

	ps_frames = (e2k_mem_ps_t *)GET_BACKUP_PS_BASE(hypv_backup);
	VM_BUG_ON(ps_frames == NULL);
	pcs_frames = (e2k_mem_crs_t *)GET_BACKUP_PCS_BASE(hypv_backup);
	VM_BUG_ON(pcs_frames == NULL);

	if (priv_guest)
		psr = E2K_KERNEL_PSR_DISABLED;
	else
		psr = E2K_USER_INITIAL_PSR;
	prepare_stacks_to_startup_vcpu(vcpu, ps_frames, pcs_frames,
			vcpu->arch.args, vcpu->arch.args_num,
			vcpu->arch.entry_point, psr,
			GET_VCPU_BOOT_CS_SIZE(boot_stacks),
			&ps_ind, &pcs_ind, 0, 1);

	/* correct stacks pointers indexes */
	hypv_backup->psp_hi.PSP_hi_ind = ps_ind;
	hypv_backup->pcsp_hi.PCSP_hi_ind = pcs_ind;
	DebugKVMSTUP("backup PS.ind 0x%x PCS.ind 0x%x\n",
		hypv_backup->psp_hi.PSP_hi_ind,
		hypv_backup->pcsp_hi.PCSP_hi_ind);
}

void setup_vcpu_boot_stacks(struct kvm_vcpu *vcpu, gthread_info_t *gti)
{
	thread_info_t	*ti = current_thread_info();
	vcpu_boot_stack_t *boot_stacks;
	e2k_stacks_t	*boot_regs;
	data_stack_t	*data_stack;
	hw_stack_t	*hw_stacks;
	/* FIXME: all addresses of stacks should be physical, if guest */
	/* will be launched at nonpaging mode. */
	/* It should be done while stacks allocation, but may be not done */
	/* and then need do it here */
	bool		nonpaging = !is_paging(vcpu);
	e2k_addr_t	stack_addr;
	e2k_usd_lo_t	usd_lo;
	e2k_psp_lo_t	psp_lo;
	e2k_pcsp_lo_t	pcsp_lo;

	boot_stacks = &vcpu->arch.boot_stacks;
	boot_regs = &boot_stacks->regs.stacks;
	data_stack = &gti->data_stack;
	hw_stacks = &gti->hw_stacks;
	stack_addr = GET_VCPU_BOOT_CS_BASE(boot_stacks);
	if (nonpaging && stack_addr >= GUEST_PAGE_OFFSET) {
		/* see FIXME above */
		stack_addr = __guest_pa(stack_addr);
		SET_VCPU_BOOT_CS_BASE(boot_stacks, stack_addr);
	}
	data_stack->bottom = stack_addr;
	stack_addr = GET_VCPU_BOOT_CS_TOP(boot_stacks);
	if (nonpaging && stack_addr >= GUEST_PAGE_OFFSET) {
		/* see FIXME above */
		stack_addr = __guest_pa(stack_addr);
		SET_VCPU_BOOT_CS_TOP(boot_stacks, stack_addr);
		boot_regs->top = stack_addr;
	}
	data_stack->top = stack_addr;
	data_stack->size = GET_VCPU_BOOT_CS_SIZE(boot_stacks);
	gti->stack = current->stack;
	gti->stack_regs.stacks.top =
		(u64)gti->stack + KERNEL_C_STACK_SIZE;
	gti->stack_regs.stacks.usd_lo = ti->k_usd_lo;
	gti->stack_regs.stacks.usd_hi = ti->k_usd_hi;
	usd_lo = boot_regs->usd_lo;
	if (nonpaging && usd_lo.USD_lo_base >= GUEST_PAGE_OFFSET) {
		/* see FIXME above */
		usd_lo.USD_lo_base = __guest_pa(usd_lo.USD_lo_base);
		boot_regs->usd_lo = usd_lo;
	}
	gti->stack_regs.stacks.u_usd_lo = usd_lo;
	gti->stack_regs.stacks.u_usd_hi = boot_regs->usd_hi;
	gti->stack_regs.stacks.u_top = GET_VCPU_BOOT_CS_TOP(boot_stacks);
	DebugKVMSTUP("guest kernel start thread GPID #%d\n",
		gti->gpid->nid.nr);
	DebugKVMSTUP("guest data stack bottom 0x%lx, top 0x%lx, size 0x%lx\n",
		data_stack->bottom, data_stack->top, data_stack->size);
	DebugKVMSTUP("guest data stack USD: base 0x%llx size 0x%x\n",
		gti->stack_regs.stacks.u_usd_lo.USD_lo_base,
		gti->stack_regs.stacks.u_usd_hi.USD_hi_size);
	DebugKVMSTUP("host  data stack bottom 0x%lx\n",
		gti->stack);

	*hw_stacks = ti->u_hw_stack;
	hw_stacks->ps = boot_stacks->ps;
	hw_stacks->pcs = boot_stacks->pcs;

	stack_addr = (e2k_addr_t)GET_VCPU_BOOT_PS_BASE(boot_stacks);
	if (nonpaging && stack_addr >= GUEST_PAGE_OFFSET) {
		/* see FIXME above */
		stack_addr = __guest_pa(stack_addr);
		SET_VCPU_BOOT_PS_BASE(boot_stacks, (void *)stack_addr);
		SET_PS_BASE(hw_stacks, (void *)stack_addr);
	}
	psp_lo = boot_regs->psp_lo;
	if (nonpaging && psp_lo.PSP_lo_base >= GUEST_PAGE_OFFSET) {
		/* see FIXME above */
		psp_lo.PSP_lo_base = __guest_pa(psp_lo.PSP_lo_base);
		boot_regs->psp_lo = psp_lo;
	}
	gti->stack_regs.stacks.psp_lo = psp_lo;
	gti->stack_regs.stacks.psp_hi = boot_regs->psp_hi;

	stack_addr = (e2k_addr_t)GET_VCPU_BOOT_PCS_BASE(boot_stacks);
	if (nonpaging && stack_addr >= GUEST_PAGE_OFFSET) {
		/* see FIXME above */
		stack_addr = __guest_pa(stack_addr);
		SET_VCPU_BOOT_PCS_BASE(boot_stacks, (void *)stack_addr);
		SET_PCS_BASE(hw_stacks, (void *)stack_addr);
	}
	pcsp_lo = boot_regs->pcsp_lo;
	if (nonpaging && pcsp_lo.PCSP_lo_base >= GUEST_PAGE_OFFSET) {
		/* see FIXME above */
		pcsp_lo.PCSP_lo_base = __guest_pa(pcsp_lo.PCSP_lo_base);
		boot_regs->pcsp_lo = pcsp_lo;
	}
	gti->stack_regs.stacks.pcsp_lo = pcsp_lo;
	gti->stack_regs.stacks.pcsp_hi = boot_regs->pcsp_hi;
	DebugKVMSTUP("guest procedure stack base 0x%lx, size 0x%lx\n",
		GET_PS_BASE(hw_stacks),
		kvm_get_guest_hw_ps_user_size(hw_stacks));
	DebugKVMSTUP("guest procedure chain stack base 0x%lx, size 0x%lx\n",
		GET_PCS_BASE(hw_stacks),
		kvm_get_guest_hw_pcs_user_size(hw_stacks));
	DebugKVMSTUP("guest procedure stack PSP: base 0x%llx size 0x%x ind 0x%x\n",
		gti->stack_regs.stacks.psp_lo.PSP_lo_base,
		gti->stack_regs.stacks.psp_hi.PSP_hi_size,
		gti->stack_regs.stacks.psp_hi.PSP_hi_ind);
	DebugKVMSTUP("guest procedure chain stack PCSP: base 0x%llx size 0x%x ind 0x%x\n",
		gti->stack_regs.stacks.pcsp_lo.PCSP_lo_base,
		gti->stack_regs.stacks.pcsp_hi.PCSP_hi_size,
		gti->stack_regs.stacks.pcsp_hi.PCSP_hi_ind);
}

/*
 * Boot loader should set OSCUD/OSGD to physical base and size of guest kernel
 * image before startup guest. So hypervisor should do same too.
 */
void kvm_set_vcpu_kernel_image(struct kvm_vcpu *vcpu,
		char *kernel_base, unsigned long kernel_size)
{

	KVM_BUG_ON(!vcpu->arch.is_hv &&
			(e2k_addr_t)kernel_base >= GUEST_PAGE_OFFSET);
	vcpu->arch.guest_phys_base = (e2k_addr_t)kernel_base;
	vcpu->arch.guest_base = kernel_base;
	vcpu->arch.guest_size = kernel_size;
	if (vcpu->arch.vcpu_state != NULL) {
		kvm_set_pv_vcpu_kernel_image(vcpu);
	}

	DebugSHC("Guest kernel image: base 0x%lx, size 0x%lx\n",
		vcpu->arch.guest_base, vcpu->arch.guest_size);

}

static void init_guest_image_hw_ctxt(struct kvm_vcpu *vcpu,
				struct kvm_hw_cpu_context *hw_ctxt)
{
	e2k_oscud_lo_t oscud_lo;
	e2k_oscud_hi_t oscud_hi;
	e2k_osgd_lo_t osgd_lo;
	e2k_osgd_hi_t osgd_hi;
	e2k_cutd_t oscutd;
	e2k_cuir_t oscuir;
	e2k_addr_t guest_cut_pa;

	oscud_lo.OSCUD_lo_half = 0;
	oscud_lo.OSCUD_lo_base = (unsigned long)vcpu->arch.guest_base;
	oscud_hi.OSCUD_hi_half = 0;
	oscud_hi.OSCUD_hi_size = vcpu->arch.guest_size;
	hw_ctxt->sh_oscud_lo = oscud_lo;
	hw_ctxt->sh_oscud_hi = oscud_hi;

	osgd_lo.OSGD_lo_half = 0;
	osgd_lo.OSGD_lo_base = (unsigned long)vcpu->arch.guest_base;
	osgd_hi.OSGD_hi_half = 0;
	osgd_hi.OSGD_hi_size = vcpu->arch.guest_size;
	hw_ctxt->sh_osgd_lo = osgd_lo;
	hw_ctxt->sh_osgd_hi = osgd_hi;

	if (vcpu->arch.guest_cut != NULL) {
		guest_cut_pa = kvm_vcpu_hva_to_gpa(vcpu,
					(u64)vcpu->arch.guest_cut);
	} else {
		guest_cut_pa = 0;
	}
	oscutd.CUTD_reg = 0;
	oscutd.CUTD_base = guest_cut_pa;
	oscuir.CUIR_reg = 0;
	hw_ctxt->sh_oscutd = oscutd;
	vcpu->arch.sw_ctxt.cutd = oscutd;
	hw_ctxt->sh_oscuir = oscuir;
}

int vcpu_init_os_cu_hw_ctxt(struct kvm_vcpu *vcpu, kvm_task_info_t *user_info)
{
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	e2k_oscud_lo_t oscud_lo;
	e2k_oscud_hi_t oscud_hi;
	e2k_osgd_lo_t osgd_lo;
	e2k_osgd_hi_t osgd_hi;
	e2k_cutd_t oscutd;
	e2k_cuir_t oscuir;
	e2k_addr_t guest_cut;

	oscud_lo.OSCUD_lo_half = 0;
	oscud_lo.OSCUD_lo_base = user_info->cud_base;
	oscud_hi.OSCUD_hi_half = 0;
	oscud_hi.OSCUD_hi_size = user_info->cud_size;
	hw_ctxt->sh_oscud_lo = oscud_lo;
	hw_ctxt->sh_oscud_hi = oscud_hi;
	/* switch guest CUT (kernel image) to virtual address */
	vcpu->arch.guest_base = (char *)user_info->cud_base;
	vcpu->arch.trap_entry = (char *)user_info->cud_base +
					vcpu->arch.trap_offset;

	osgd_lo.OSGD_lo_half = 0;
	osgd_lo.OSGD_lo_base = user_info->gd_base;
	osgd_hi.OSGD_hi_half = 0;
	osgd_hi.OSGD_hi_size = user_info->gd_size;
	hw_ctxt->sh_osgd_lo = osgd_lo;
	hw_ctxt->sh_osgd_hi = osgd_hi;

	guest_cut = user_info->cut_base;
	oscutd.CUTD_reg = 0;
	oscutd.CUTD_base = guest_cut;
	hw_ctxt->sh_oscutd = oscutd;
	if (vcpu->arch.is_hv) {
		sw_ctxt->cutd = oscutd;	/* for kernel CUTD == OSCUTD */
	}

	oscuir.CUIR_reg = user_info->cui;
	hw_ctxt->sh_oscuir = oscuir;

	/* set OC CU conteext on shadow registers */
	preempt_disable();
	vcpu_write_os_cu_hw_ctxt_to_registers(vcpu, hw_ctxt);
	preempt_enable();

	return 0;
}

static void init_hv_vcpu_intc_ctxt(struct kvm_vcpu *vcpu)
{
	struct kvm_intc_cpu_context *intc_ctxt = &vcpu->arch.intc_ctxt;
	e2k_tir_hi_t TIR_hi;
	e2k_tir_lo_t TIR_lo;

	/* Initialize empty TIRs before first GLAUNCH to avoid showing host's
	 * IP to guest */
	TIR_lo.TIR_lo_reg = GET_CLEAR_TIR_LO(1);
	TIR_hi.TIR_hi_reg = GET_CLEAR_TIR_HI(1);
	kvm_clear_vcpu_intc_TIRs_num(vcpu);
	kvm_update_vcpu_intc_TIR(vcpu, 1, TIR_hi, TIR_lo);

	intc_ctxt->cu_num = -1;
	intc_ctxt->mu_num = -1;
	kvm_reset_intc_info_mu_is_updated(vcpu);
	kvm_reset_intc_info_cu_is_updated(vcpu);
}

static void init_vcpu_intc_ctxt(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.is_hv) {
		/* interceptions is supported by hardware */
		init_hv_vcpu_intc_ctxt(vcpu);
	} else if (vcpu->arch.is_pv) {
		/* interceptions is not supported by hardware */
		/* so nothing to do */
		;
	} else {
		KVM_BUG_ON(true);
	}
}

void kvm_setup_mmu_intc_mode(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	virt_ctrl_mu_t mu;
	mmu_reg_t g_w_imask_mmu_cr;
	mmu_reg_t sh_mmu_cr, sh_pid;

	/* MMU interception control registers state */
	mu.VIRT_CTRL_MU_reg = 0;
	g_w_imask_mmu_cr = 0;

	if (kvm_is_tdp_enable(kvm)) {
		mu.sh_pt_en = 0;
	} else if (kvm_is_shadow_pt_enable(kvm)) {
		mu.sh_pt_en = 1;
	} else {
		KVM_BUG_ON(true);
	}

	if (kvm_is_phys_pt_enable(kvm))
		mu.gp_pt_en = 1;

	/* Guest should not be able to write special MMU/AAU */
	mu.rw_dbg1 = 1;

	if (vcpu->arch.is_hv) {
		if (kvm_is_tdp_enable(kvm)) {
			/* intercept only MMU_CR updates to track */
			/* paging enable/disable */
			mu.rw_mmu_cr = 0;
			g_w_imask_mmu_cr |= _MMU_CR_TLB_EN;
		} else if (kvm_is_shadow_pt_enable(kvm)) {
			/* intercept all read/write MMU CR */
			/* and Page Table Base */
			mu.rr_mmu_cr = 1;
			mu.rr_pptb = 1;
			mu.rr_vptb = 1;
			mu.rw_mmu_cr = 1;
			mu.rw_pptb = 1;
			mu.rw_vptb = 1;
			mu.fl_tlbpg = 1;
			mu.fl_tlb2pg = 1;
			g_w_imask_mmu_cr |= _MMU_CR_TLB_EN;
		} else {
			KVM_BUG_ON(true);
		}
	}
	vcpu->arch.mmu.virt_ctrl_mu = mu;
	vcpu->arch.mmu.g_w_imask_mmu_cr = g_w_imask_mmu_cr;


	/* MMU shadow registers initial state */
	if (vcpu->arch.is_hv || vcpu->arch.is_pv) {
		sh_mmu_cr = mmu_reg_val(MMU_CR_KERNEL_OFF);
		sh_pid = 0;	/* guest kernel should have PID == 0 */
		vcpu_write_SH_MMU_CR_reg(vcpu, sh_mmu_cr);
	} else {
		KVM_BUG_ON(true);
	}
	vcpu->arch.mmu.init_sh_mmu_cr = sh_mmu_cr;
	vcpu->arch.mmu.init_sh_pid = sh_pid;
}

static void kvm_init_lintel_gregs(struct kvm_vcpu *vcpu)
{
	/*
	 * It need only pass pointer to bootinfo structure as %dg1 register
	 * but hypervisor pass as 0 & 1-st parameter and set:
	 *	%dg0 - BSP flag
	 *	%dg1 - bootinfo pointer
	 */
	SET_HOST_GREG(0, vcpu->arch.args[0]);
	SET_HOST_GREG(1, vcpu->arch.args[1]);
}

static void init_backup_hw_ctxt(struct kvm_vcpu *vcpu)
{
	bu_hw_stack_t *hypv_backup;
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;

	if (!vcpu->arch.is_hv) {
		/* there is not support of hardware virtualizsation */
		return;
	}

	/*
	 * Stack registers
	 */
	hypv_backup = &vcpu->arch.hypv_backup;
	hw_ctxt->bu_psp_lo = hypv_backup->psp_lo;
	hw_ctxt->bu_psp_hi = hypv_backup->psp_hi;
	hw_ctxt->bu_pcsp_lo = hypv_backup->pcsp_lo;
	hw_ctxt->bu_pcsp_hi = hypv_backup->pcsp_hi;

	/* set backup stacks to empty state will be done by hardware after */
	/* GLAUNCH, so update software pointers at hypv_backup structure */
	/* for following GLAUNCHes and paravirtualization HCALL emulation */
	hypv_backup->psp_hi.PSP_hi_ind = 0;
	hypv_backup->pcsp_hi.PCSP_hi_ind = 0;
}

void init_hw_ctxt(struct kvm_vcpu *vcpu)
{
	vcpu_boot_stack_t *boot_stacks = &vcpu->arch.boot_stacks;
	guest_hw_stack_t *boot_regs = &boot_stacks->regs;
	kvm_guest_info_t *guest_info = &vcpu->kvm->arch.guest_info;
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;
	epic_page_t *cepic = hw_ctxt->cepic;
	virt_ctrl_cu_t cu;
	union cepic_ctrl epic_reg_ctrl;
	union cepic_esr2 epic_reg_esr2;
	union cepic_timer_lvtt epic_reg_timer_lvtt;
	union cepic_pnmirr_mask epic_reg_pnmirr_mask;
	unsigned int i;

	/*
	 * Stack registers
	 */
	hw_ctxt->sh_psp_lo = boot_regs->stacks.psp_lo;
	hw_ctxt->sh_psp_hi = boot_regs->stacks.psp_hi;
	hw_ctxt->sh_pcsp_lo = boot_regs->stacks.pcsp_lo;
	hw_ctxt->sh_pcsp_hi = boot_regs->stacks.pcsp_hi;

	/* setup initial state of backup stacks */
	init_backup_hw_ctxt(vcpu);

	/* set shadow WD state to initial value */
	hw_ctxt->sh_wd.WD_reg = 0;
	hw_ctxt->sh_wd.WD_fx = 0;

	/* MMU shadow context registers state */
	hw_ctxt->sh_mmu_cr = vcpu->arch.mmu.init_sh_mmu_cr;
	hw_ctxt->sh_pid = vcpu->arch.mmu.init_sh_pid;

	hw_ctxt->gid = vcpu->kvm->arch.vmid.nr;

	/*
	 * CPU shadow context
	 */
	/* FIXME: set guest kernel OSCUD to host OSCUD to allow handling */
	/* traps, hypercalls by host. Real guest OSCUD should be set to */
	/* physical base of guest kernel image
	oscud_lo = kvm_get_guest_vcpu_OSCUD_lo(vcpu);
	oscud_hi = kvm_get_guest_vcpu_OSCUD_hi(vcpu);
	*/
	if (vcpu->arch.is_hv || vcpu->arch.is_pv) {
		/* guest image state should be saved */
		/* by kvm_set_hv_kernel_image() */
		init_guest_image_hw_ctxt(vcpu, hw_ctxt);
	} else {
		KVM_BUG_ON(true);
	}

	/* FIXME: guest now use paravirtualized register (in memory) */
	/* so set shadow OSR0 to host current_thread_info() to enable */
	/* host trap handler
	osr0 = kvm_get_guest_vcpu_OSR0_value(vcpu);
	*/
	if (vcpu->arch.is_hv) {
		hw_ctxt->sh_osr0 = 0;
	} else if (vcpu->arch.is_pv) {
		hw_ctxt->sh_osr0 = (u64) current_thread_info();
	} else {
		KVM_BUG_ON(true);
	}
	if (vcpu->arch.is_hv) {
		hw_ctxt->sh_core_mode = read_SH_CORE_MODE_reg();
	} else if (vcpu->arch.is_pv) {
		hw_ctxt->sh_core_mode = kvm_get_guest_vcpu_CORE_MODE(vcpu);
	} else {
		KVM_BUG_ON(true);
	}
	/* turn ON indicators of GM and enbale hypercalls */
	if (vcpu->arch.is_hv) {
		hw_ctxt->sh_core_mode.CORE_MODE_gmi = 1;
		hw_ctxt->sh_core_mode.CORE_MODE_hci = 1;
	}

	/*
	 * VIRT_CTRL_* registers
	 */
	cu.VIRT_CTRL_CU_reg = 0;
	if (guest_info->is_stranger) {
		/* it need turn ON interceptions on IDR read */
		cu.VIRT_CTRL_CU_rr_idr = 1;
	}
	cu.VIRT_CTRL_CU_rw_sclkr = 1;
	cu.VIRT_CTRL_CU_rw_sclkm3 = 1;
	cu.VIRT_CTRL_CU_virt = 1;

	hw_ctxt->virt_ctrl_cu = cu;
	hw_ctxt->virt_ctrl_mu = vcpu->arch.mmu.virt_ctrl_mu;
	hw_ctxt->g_w_imask_mmu_cr = vcpu->arch.mmu.g_w_imask_mmu_cr;

	/* Set CEPIC reset state */
	if (vcpu->arch.is_hv) {
		epic_reg_ctrl.raw = 0;
		epic_reg_ctrl.bits.bsp_core = kvm_vcpu_is_bsp(vcpu);
		cepic->ctrl = epic_reg_ctrl.raw;
		cepic->id = kvm_vcpu_to_full_cepic_id(vcpu);
		cepic->cpr = 0;
		cepic->esr = 0;
		epic_reg_esr2.raw = 0;
		epic_reg_esr2.bits.mask = 1;
		cepic->esr2 = epic_reg_esr2;
		cepic->cir.raw = 0;
		cepic->esr_new.counter = 0;
		cepic->icr.raw = 0;
		epic_reg_timer_lvtt.raw = 0;
		epic_reg_timer_lvtt.bits.mask = 1;
		cepic->timer_lvtt = epic_reg_timer_lvtt;
		cepic->timer_init = 0;
		cepic->timer_cur = 0;
		cepic->timer_div = 0;
		cepic->nm_timer_lvtt = 0;
		cepic->nm_timer_init = 0;
		cepic->nm_timer_cur = 0;
		cepic->nm_timer_div = 0;
		cepic->svr = 0;
		epic_reg_pnmirr_mask.raw = 0;
		epic_reg_pnmirr_mask.bits.nm_special = 1;
		epic_reg_pnmirr_mask.bits.nm_timer = 1;
		epic_reg_pnmirr_mask.bits.int_violat = 1;
		cepic->pnmirr_mask = epic_reg_pnmirr_mask.raw;
		for (i = 0; i < CEPIC_PMIRR_NR_DREGS; i++)
			cepic->pmirr[i].counter = 0;
		cepic->pnmirr.counter = 0;
		for (i = 0; i < CEPIC_PMIRR_NR_BITS; i++)
			cepic->pmirr_byte[i] = 0;
		for (i = 0; i < 16; i++)
			cepic->pnmirr_byte[i] = 0;
	}

	/* FIXME Initializing CEPIC for APIC v6 model. Ideally, this should be
	 * done by the model itself */
	if (!kvm_vcpu_is_epic(vcpu) && kvm_vcpu_is_hw_apic(vcpu)) {
		union cepic_timer_div reg_div;
		union cepic_svr epic_reg_svr;

		epic_reg_ctrl.bits.soft_en = 1;
		cepic->ctrl = epic_reg_ctrl.raw;

		epic_reg_esr2.bits.vect = 0xfe;
		epic_reg_esr2.bits.mask = 0;
		cepic->esr2 = epic_reg_esr2;

		reg_div.raw = 0;
		reg_div.bits.divider = CEPIC_TIMER_DIV_1;
		cepic->timer_div = reg_div.raw;

		epic_reg_svr.raw = 0;
		epic_reg_svr.bits.vect = 0xff;
		cepic->svr = epic_reg_svr.raw;
	}
}

void kvm_update_guest_stacks_registers(struct kvm_vcpu *vcpu,
					guest_hw_stack_t *stack_regs)
{
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;

	/*
	 * Guest Stack state is now on back UP registers
	 */
	hw_ctxt->sh_psp_lo = stack_regs->stacks.psp_lo;
	hw_ctxt->sh_psp_hi = stack_regs->stacks.psp_hi;
	hw_ctxt->sh_pcsp_lo = stack_regs->stacks.pcsp_lo;
	hw_ctxt->sh_pcsp_hi = stack_regs->stacks.pcsp_hi;
	if (vcpu->arch.is_hv) {
		WRITE_BU_PSP_LO_REG_VALUE(AW(hw_ctxt->sh_psp_lo));
		WRITE_BU_PSP_HI_REG_VALUE(AW(hw_ctxt->sh_psp_hi));
		WRITE_BU_PCSP_LO_REG_VALUE(AW(hw_ctxt->sh_pcsp_lo));
		WRITE_BU_PCSP_HI_REG_VALUE(AW(hw_ctxt->sh_pcsp_hi));
	}
	sw_ctxt->crs.cr0_lo = stack_regs->crs.cr0_lo;
	sw_ctxt->crs.cr0_hi = stack_regs->crs.cr0_hi;
	sw_ctxt->crs.cr1_lo = stack_regs->crs.cr1_lo;
	sw_ctxt->crs.cr1_hi = stack_regs->crs.cr1_hi;

	DebugSHC("update guest stacks registers:\n"
		"BU_PSP:  base 0x%llx size 0x%x index 0x%x\n"
		"BU_PCSP: base 0x%llx size 0x%x index 0x%x\n",
		stack_regs->stacks.psp_lo.PSP_lo_base,
		stack_regs->stacks.psp_hi.PSP_hi_size,
		stack_regs->stacks.psp_hi.PSP_hi_ind,
		stack_regs->stacks.pcsp_lo.PCSP_lo_base,
		stack_regs->stacks.pcsp_hi.PCSP_hi_size,
		stack_regs->stacks.pcsp_hi.PCSP_hi_ind);
}

static void kvm_dump_mmu_tdp_context(struct kvm_vcpu *vcpu, unsigned flags)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	KVM_BUG_ON(!is_tdp_paging(vcpu));

	DebugSHC("Set MMU guest TDP PT context:\n");

	if (DEBUG_SHADOW_CONTEXT_MODE && (flags & GP_ROOT_PT_FLAG)) {
		pr_info("   GP_PPTB: value 0x%llx\n",
			mmu->get_vcpu_context_gp_pptb(vcpu));
	}
	if (DEBUG_SHADOW_CONTEXT_MODE &&
			((flags & U_ROOT_PT_FLAG) ||
				((flags & OS_ROOT_PT_FLAG) &&
					!is_sep_virt_spaces(vcpu)))) {
		pr_info("   U_PPTB:  value 0x%lx\n"
			"   U_VPTB:  value 0x%lx\n",
			mmu->get_vcpu_context_u_pptb(vcpu),
			mmu->get_vcpu_context_u_vptb(vcpu));
	}
	if (DEBUG_SHADOW_CONTEXT_MODE &&
			((flags & OS_ROOT_PT_FLAG) &&
					is_sep_virt_spaces(vcpu))) {
		pr_info("   OS_PPTB: value 0x%lx\n"
			"   OS_VPTB: value 0x%lx\n"
			"   OS_VAB:  value 0x%lx\n",
			mmu->get_vcpu_context_os_pptb(vcpu),
			mmu->get_vcpu_context_os_vptb(vcpu),
			mmu->get_vcpu_context_os_vab(vcpu));
	}
	if (DEBUG_SHADOW_CONTEXT_MODE) {
		pr_info("   SH_PID:  value 0x%llx\n",
			read_guest_PID_reg(vcpu));
	}
	if (DEBUG_SHADOW_CONTEXT_MODE && (flags & SEP_VIRT_ROOT_PT_FLAG)) {
		e2k_core_mode_t core_mode = read_guest_CORE_MODE_reg(vcpu);

		pr_info("   SH_CORE_MODE:  0x%x sep_virt_space: %s\n",
			core_mode.CORE_MODE_reg,
			(core_mode.CORE_MODE_sep_virt_space) ?
				"true" : "false");
	}
}

static void setup_mmu_tdp_context(struct kvm_vcpu *vcpu, unsigned flags)
{
	KVM_BUG_ON(!is_tdp_paging(vcpu));

	/* setup MMU page tables hardware and software context */
	kvm_set_vcpu_the_pt_context(vcpu, flags);

	/* setup user PID on hardware shadow register */
	write_SH_PID_reg(vcpu->arch.mmu.pid);

	if ((flags & SEP_VIRT_ROOT_PT_FLAG) && vcpu->arch.is_pv) {
		e2k_core_mode_t core_mode = read_SH_CORE_MODE_reg();

		/* enable/disable guest separate Page Tables support */
		core_mode.CORE_MODE_sep_virt_space = is_sep_virt_spaces(vcpu);
		write_SH_CORE_MODE_reg(core_mode);
		vcpu->arch.hw_ctxt.sh_core_mode = core_mode;
	}

	kvm_dump_mmu_tdp_context(vcpu, flags);
}

void kvm_setup_mmu_tdp_u_pt_context(struct kvm_vcpu *vcpu)
{
	unsigned flags;

	if (vcpu->arch.mmu.u_context_on) {
		flags = U_ROOT_PT_FLAG;
	} else {
		flags = U_ROOT_PT_FLAG | OS_ROOT_PT_FLAG |
						SEP_VIRT_ROOT_PT_FLAG;
	}
	/* setup MMU page tables hardware and software context */
	setup_mmu_tdp_context(vcpu, flags);
}

void kvm_setup_mmu_tdp_context(struct kvm_vcpu *vcpu)
{
	/* setup MMU page tables hardware and software context */
	setup_mmu_tdp_context(vcpu,
		GP_ROOT_PT_FLAG | OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG |
			SEP_VIRT_ROOT_PT_FLAG);
}

static inline void
kvm_dump_shadow_u_pptb(struct kvm_vcpu *vcpu, const char *title)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	DebugSHC("%s"
		"   sh_U_PPTB:  value 0x%lx\n"
		"   sh_U_VPTB:  value 0x%lx\n"
		"   U_PPTB:     value 0x%lx\n"
		"   U_VPTB:     value 0x%lx\n"
		"   SH_PID:     value 0x%llx\n",
		title,
		mmu->get_vcpu_context_u_pptb(vcpu),
		mmu->get_vcpu_context_u_vptb(vcpu),
		mmu->get_vcpu_u_pptb(vcpu),
		mmu->get_vcpu_u_vptb(vcpu),
		read_guest_PID_reg(vcpu));
}

void kvm_setup_mmu_spt_context(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	/* setup OS and user PT hardware and software context */
	kvm_set_vcpu_pt_context(vcpu);

	if (vcpu->arch.is_hv) {
		e2k_core_mode_t core_mode = read_SH_CORE_MODE_reg();

		/* enable/disable guest separate Page Tables support */
		core_mode.CORE_MODE_sep_virt_space = is_sep_virt_spaces(vcpu);
		write_SH_CORE_MODE_reg(core_mode);
		vcpu->arch.hw_ctxt.sh_core_mode = core_mode;
	}

	kvm_dump_shadow_u_pptb(vcpu, "Set MMU guest shadow OS/U_PT context:\n");

	if (DEBUG_SHADOW_CONTEXT_MODE && is_sep_virt_spaces(vcpu)) {
		pr_info("   sh_OS_PPTB: value 0x%lx\n"
			"   sh_OS_VPTB: value 0x%lx\n"
			"   OS_PPTB:    value 0x%lx\n"
			"   OS_VPTB:    value 0x%lx\n"
			"   SH_OS_VAB:  value 0x%lx\n",
			mmu->get_vcpu_context_os_pptb(vcpu),
			mmu->get_vcpu_context_os_vptb(vcpu),
			mmu->get_vcpu_os_pptb(vcpu),
			mmu->get_vcpu_os_vptb(vcpu),
			mmu->get_vcpu_context_os_vab(vcpu));
	}
	if (DEBUG_SHADOW_CONTEXT_MODE) {
		if (is_phys_paging(vcpu)) {
			pr_info("   GP_PPTB:    value 0x%llx\n",
				mmu->get_vcpu_context_gp_pptb(vcpu));
		}
		if (!vcpu->arch.is_hv) {
			pr_info("   GP_PPTB:    value 0x%llx\n",
				mmu->get_vcpu_gp_pptb(vcpu));
		}
	}
	if (DEBUG_SHADOW_CONTEXT_MODE && is_paging(vcpu)) {
		pr_info("   SH_MMU_CR:  value 0x%llx\n",
			read_guest_MMU_CR_reg(vcpu));
	}
	if (DEBUG_SHADOW_CONTEXT_MODE) {
		e2k_core_mode_t core_mode = read_guest_CORE_MODE_reg(vcpu);

		pr_info("   CORE_MODE:  value 0x%x sep_virt_space: %s\n",
			core_mode.CORE_MODE_reg,
			(core_mode.CORE_MODE_sep_virt_space) ?
				"true" : "false");
	}
}

void kvm_set_mmu_guest_pt(struct kvm_vcpu *vcpu)
{
	mmu_reg_t mmu_cr;

	if (is_tdp_paging(vcpu)) {
		kvm_setup_mmu_tdp_context(vcpu);
	} else if (is_shadow_paging(vcpu)) {
		kvm_setup_mmu_spt_context(vcpu);
	} else {
		KVM_BUG_ON(true);
	}

	/* enable TLB in paging mode */
	mmu_cr = MMU_CR_KERNEL;
	write_guest_MMU_CR_reg(vcpu, mmu_cr);
	DebugSHC("Enable guest MMU paging:\n"
		"   SH_MMU_CR: value 0x%llx\n",
		mmu_cr);
}

void kvm_setup_shadow_u_pptb(struct kvm_vcpu *vcpu)
{
	/* setup new user PT hardware/software context */
	kvm_set_vcpu_u_pt_context(vcpu);

	kvm_dump_shadow_u_pptb(vcpu, "Set MMU guest shadow U_PT context:\n");
}

void mmu_pv_setup_shadow_u_pptb(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	kvm_setup_shadow_u_pptb(vcpu);
	pv_vcpu_set_gmm(vcpu, gmm);
	pv_vcpu_set_active_gmm(vcpu, gmm);
}

void kvm_dump_shadow_os_pt_regs(struct kvm_vcpu *vcpu)
{
	if (is_sep_virt_spaces(vcpu)) {
		DebugSHC("Set MMU guest shadow OS PT context:\n"
			"   SH_OS_PPTB:     value 0x%lx\n"
			"   SH_OS_VPTB:     value 0x%lx\n"
			"   OS_PPTB:        value 0x%lx\n"
			"   OS_VPTB:        value 0x%lx\n"
			"   SH_OS_VAB:      value 0x%lx\n"
			"   OS_VAB:         value 0x%lx\n",
			vcpu->arch.mmu.get_vcpu_context_os_pptb(vcpu),
			vcpu->arch.mmu.get_vcpu_context_os_vptb(vcpu),
			vcpu->arch.mmu.get_vcpu_os_pptb(vcpu),
			vcpu->arch.mmu.get_vcpu_os_vptb(vcpu),
			vcpu->arch.mmu.get_vcpu_context_os_vab(vcpu),
			vcpu->arch.mmu.get_vcpu_os_vab(vcpu));
	} else {
		DebugSHC("Set MMU guest shadow OS/U PT context:\n"
			"   SH_OS/U_PPTB:   value 0x%lx\n"
			"   SH_OS/U_VPTB:   value 0x%lx\n"
			"   OS/U_PPTB:      value 0x%lx\n"
			"   OS/U_VPTB:      value 0x%lx\n",
			vcpu->arch.mmu.get_vcpu_context_u_pptb(vcpu),
			vcpu->arch.mmu.get_vcpu_context_u_vptb(vcpu),
			vcpu->arch.mmu.get_vcpu_u_pptb(vcpu),
			vcpu->arch.mmu.get_vcpu_u_vptb(vcpu));
	}
}

void kvm_setup_shadow_os_pptb(struct kvm_vcpu *vcpu)
{
	/* setup kernel new PT hardware/software context */
	kvm_set_vcpu_os_pt_context(vcpu);

	kvm_dump_shadow_os_pt_regs(vcpu);
}

void kvm_switch_mmu_guest_u_pt(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	/* setup user PT hardware and software context */
	kvm_set_vcpu_u_pt_context(vcpu);

	write_guest_PID_reg(vcpu, mmu->pid);

	kvm_dump_shadow_u_pptb(vcpu, "Set MMU guest shadow U_PT context:\n");
}

void kvm_set_mmu_guest_u_pt(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	e2k_core_mode_t core_mode;

	if (likely(mmu->u_context_on))
		return kvm_switch_mmu_guest_u_pt(vcpu);

	/* setup OS and user PT hardware and software context */
	kvm_set_vcpu_pt_context(vcpu);

	/* setup user PID on hardware shadow register */
	write_guest_PID_reg(vcpu, mmu->pid);

	kvm_dump_shadow_u_pptb(vcpu, "Set MMU guest shadow OS/U_PT context:\n");
	if (DEBUG_SHADOW_CONTEXT_MODE && is_sep_virt_spaces(vcpu)) {
		pr_info("   SH_OS_PPTB: value 0x%lx\n"
			"   SH_OS_VPTB: value 0x%lx\n"
			"   OS_PPTB:    value 0x%lx\n"
			"   OS_VPTB:    value 0x%lx\n"
			"   SH_OS_VAB:  value 0x%lx\n",
			mmu->get_vcpu_context_os_pptb(vcpu),
			mmu->get_vcpu_context_os_vptb(vcpu),
			mmu->get_vcpu_os_pptb(vcpu),
			mmu->get_vcpu_os_vptb(vcpu),
			mmu->get_vcpu_context_os_vab(vcpu));
	}
	if (DEBUG_SHADOW_CONTEXT_MODE && is_phys_paging(vcpu)) {
		pr_info("   GP_PPTB:    value 0x%llx\n",
			mmu->get_vcpu_context_gp_pptb(vcpu));
	}

	/* enable separate Page Tables support */
	core_mode = read_guest_CORE_MODE_reg(vcpu);
	core_mode.CORE_MODE_sep_virt_space = is_sep_virt_spaces(vcpu);
	write_guest_CORE_MODE_reg(vcpu, core_mode);
	DebugSHC("Set separate PT support on guest MMU:\n"
		"   SH_CORE_MODE: 0x%x gmi %s hci %s sep_virt_space %s\n",
		core_mode.CORE_MODE_reg,
		(core_mode.CORE_MODE_gmi) ? "true" : "false",
		(core_mode.CORE_MODE_hci) ? "true" : "false",
		(core_mode.CORE_MODE_sep_virt_space) ? "true" : "false");
}

static void vcpu_write_os_cu_hw_ctxt_to_registers(struct kvm_vcpu *vcpu,
				const struct kvm_hw_cpu_context *hw_ctxt)
{
	/*
	 * CPU shadow context
	 */
	if (vcpu->arch.is_hv) {
		write_SH_OSCUD_LO_reg(hw_ctxt->sh_oscud_lo);
		write_SH_OSCUD_HI_reg(hw_ctxt->sh_oscud_hi);
		write_SH_OSGD_LO_reg(hw_ctxt->sh_osgd_lo);
		write_SH_OSGD_HI_reg(hw_ctxt->sh_osgd_hi);
		write_SH_OSCUTD_reg(hw_ctxt->sh_oscutd);
		write_SH_OSCUIR_reg(hw_ctxt->sh_oscuir);
	}
	DebugSHC("initialized CPU shadow context\n"
		"SH_OSCUD:  base 0x%llx size 0x%x\n"
		"SH_OSGD:   base 0x%llx size 0x%x\n"
		"CUTD:      base 0x%llx\n"
		"SH_OSCUTD: base 0x%llx\n"
		"SH_OSCUIR: index 0x%x\n"
		"Trap table entry at %px\n",
		hw_ctxt->sh_oscud_lo.OSCUD_lo_base,
		hw_ctxt->sh_oscud_hi.OSCUD_hi_size,
		hw_ctxt->sh_osgd_lo.OSGD_lo_base,
		hw_ctxt->sh_osgd_hi.OSGD_hi_size,
		vcpu->arch.sw_ctxt.cutd.CUTD_base,
		hw_ctxt->sh_oscutd.CUTD_base,
		hw_ctxt->sh_oscuir.CUIR_index,
		vcpu->arch.trap_entry);
}

static void write_hw_ctxt_to_hv_vcpu_registers(struct kvm_vcpu *vcpu,
				const struct kvm_hw_cpu_context *hw_ctxt,
				const struct kvm_sw_cpu_context *sw_ctxt)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	epic_page_t *cepic = hw_ctxt->cepic;
	unsigned int i;

	/*
	 * Stack registers
	 */
	WRITE_SH_PSP_LO_REG_VALUE(AW(hw_ctxt->sh_psp_lo));
	WRITE_SH_PSP_HI_REG_VALUE(AW(hw_ctxt->sh_psp_hi));
	WRITE_SH_PCSP_LO_REG_VALUE(AW(hw_ctxt->sh_pcsp_lo));
	WRITE_SH_PCSP_HI_REG_VALUE(AW(hw_ctxt->sh_pcsp_hi));
	WRITE_BU_PSP_LO_REG_VALUE(AW(hw_ctxt->bu_psp_lo));
	WRITE_BU_PSP_HI_REG_VALUE(AW(hw_ctxt->bu_psp_hi));
	WRITE_BU_PCSP_LO_REG_VALUE(AW(hw_ctxt->bu_pcsp_lo));
	WRITE_BU_PCSP_HI_REG_VALUE(AW(hw_ctxt->bu_pcsp_hi));
	/* Filling of backup stacks is made on main PSHTP/PCSHTP and
	 * BU_PSP/BU_PCSP pointers. Switch from main PSHTP/PCSHTP to
	 * shadow SH_PSHTP/SH_PCSHTP is done after filling, so set
	 * shadow SH_PSHTP/SH_PCSHTP to sizes of backup stacks */
	WRITE_SH_PSHTP_REG_VALUE(hw_ctxt->bu_psp_hi.PSP_hi_ind);
	WRITE_SH_PCSHTP_REG_SVALUE(hw_ctxt->bu_pcsp_hi.PCSP_hi_ind);

	DebugSHC("initialized hardware shadow registers:\n"
		"SH_PSP:   base 0x%llx size 0x%x index 0x%x\n"
		"SH_PCSP:  base 0x%llx size 0x%x index 0x%x\n"
		"BU_PSP:   base 0x%llx size 0x%x index 0x%x\n"
		"BU_PCSP:  base 0x%llx size 0x%x index 0x%x\n"
		"SH_PSHTP: value 0x%x\n"
		"SH_PSHTP: value 0x%x\n",
		hw_ctxt->sh_psp_lo.PSP_lo_base, hw_ctxt->sh_psp_hi.PSP_hi_size,
		hw_ctxt->sh_psp_hi.PSP_hi_ind, hw_ctxt->sh_pcsp_lo.PCSP_lo_base,
		hw_ctxt->sh_pcsp_hi.PCSP_hi_size,
		hw_ctxt->sh_pcsp_hi.PCSP_hi_ind, hw_ctxt->bu_psp_lo.PSP_lo_base,
		hw_ctxt->bu_psp_hi.PSP_hi_size, hw_ctxt->bu_psp_hi.PSP_hi_ind,
		hw_ctxt->bu_pcsp_lo.PCSP_lo_base,
		hw_ctxt->bu_pcsp_hi.PCSP_hi_size,
		hw_ctxt->bu_pcsp_hi.PCSP_hi_ind, hw_ctxt->bu_psp_hi.PSP_hi_ind,
		hw_ctxt->bu_pcsp_hi.PCSP_hi_ind);

	WRITE_SH_WD_REG_VALUE(hw_ctxt->sh_wd.WD_reg);

	/*
	 * MMU shadow context 
	 */
	write_SH_MMU_CR_reg(hw_ctxt->sh_mmu_cr);
	write_SH_PID_reg(hw_ctxt->sh_pid);
	write_GID_reg(hw_ctxt->gid);
	DebugSHC("initialized MMU shadow context:\n"
		"SH_MMU_CR:  value 0x%llx\n"
		"SH_PID:     value 0x%llx\n"
		"GP_PPTB:    value 0x%llx\n"
		"sh_U_PPTB:  value 0x%lx\n"
		"sh_U_VPTB:  value 0x%lx\n"
		"SH_OS_PPTB: value 0x%lx\n"
		"SH_OS_VPTB: value 0x%lx\n"
		"SH_OS_VAB:  value 0x%lx\n"
		"GID:        value 0x%llx\n",
		hw_ctxt->sh_mmu_cr, hw_ctxt->sh_pid,
		mmu->get_vcpu_context_gp_pptb(vcpu),
		mmu->get_vcpu_context_u_pptb(vcpu),
		mmu->get_vcpu_context_u_vptb(vcpu),
		mmu->get_vcpu_context_os_pptb(vcpu),
		mmu->get_vcpu_context_os_vptb(vcpu),
		mmu->get_vcpu_context_os_vab(vcpu),
		hw_ctxt->gid);

	/*
	 * CPU shadow context
	 */
	vcpu_write_os_cu_hw_ctxt_to_registers(vcpu, hw_ctxt);

	write_SH_OSR0_reg_value(hw_ctxt->sh_osr0);
	DebugSHC("SH_OSR0: value 0x%llx\n", hw_ctxt->sh_osr0);
	write_SH_CORE_MODE_reg(hw_ctxt->sh_core_mode);
	DebugSHC("SH_CORE_MODE: value 0x%x, gmi %s, hci %s\n",
		hw_ctxt->sh_core_mode.CORE_MODE_reg,
		(hw_ctxt->sh_core_mode.CORE_MODE_gmi) ? "true" : "false",
		(hw_ctxt->sh_core_mode.CORE_MODE_hci) ? "true" : "false");

	/*
	 * VIRT_CTRL_* registers
	 */
	write_VIRT_CTRL_CU_reg(hw_ctxt->virt_ctrl_cu);
	write_VIRT_CTRL_MU_reg(hw_ctxt->virt_ctrl_mu);
	write_G_W_IMASK_MMU_CR_reg(hw_ctxt->g_w_imask_mmu_cr);
	DebugSHC("initialized VIRT_CTRL registers\n"
		"VIRT_CTRL_CU: 0x%llx\n"
		"VIRT_CTRL_MU: 0x%llx, sh_pt_en : %s, gp_pt_en : %s\n"
		"G_W_IMASK_MMU_CR: 0x%llx, tlb_en : %s\n",
		AW(hw_ctxt->virt_ctrl_cu), AW(hw_ctxt->virt_ctrl_mu),
		(hw_ctxt->virt_ctrl_mu.sh_pt_en) ? "true" : "false",
		(hw_ctxt->virt_ctrl_mu.gp_pt_en) ? "true" : "false",
		hw_ctxt->g_w_imask_mmu_cr,
		(hw_ctxt->g_w_imask_mmu_cr & _MMU_CR_TLB_EN) ?
			"true" : "false");

	epic_write_guest_w(CEPIC_CTRL, cepic->ctrl);
	epic_write_guest_w(CEPIC_ID, cepic->id);
	epic_write_guest_w(CEPIC_CPR, cepic->cpr);
	epic_write_guest_w(CEPIC_ESR, cepic->esr);
	epic_write_guest_w(CEPIC_ESR2, cepic->esr2.raw);
	epic_write_guest_w(CEPIC_CIR, cepic->cir.raw);
	epic_write_guest_w(CEPIC_ESR_NEW, cepic->esr_new.counter);
	epic_write_guest_d(CEPIC_ICR, cepic->icr.raw);
	epic_write_guest_w(CEPIC_TIMER_LVTT, cepic->timer_lvtt.raw);
	epic_write_guest_w(CEPIC_TIMER_INIT, cepic->timer_init);
	epic_write_guest_w(CEPIC_TIMER_CUR, cepic->timer_cur);
	epic_write_guest_w(CEPIC_TIMER_DIV, cepic->timer_div);
	epic_write_guest_w(CEPIC_NM_TIMER_LVTT, cepic->nm_timer_lvtt);
	epic_write_guest_w(CEPIC_NM_TIMER_INIT, cepic->nm_timer_init);
	epic_write_guest_w(CEPIC_NM_TIMER_CUR, cepic->nm_timer_cur);
	epic_write_guest_w(CEPIC_NM_TIMER_DIV, cepic->nm_timer_div);
	epic_write_guest_w(CEPIC_SVR, cepic->svr);
	epic_write_guest_w(CEPIC_PNMIRR_MASK, cepic->pnmirr_mask);
	for (i = 0; i < CEPIC_PMIRR_NR_DREGS; i++)
		epic_write_guest_d(CEPIC_PMIRR + i * 8,
			cepic->pmirr[i].counter);
	epic_write_guest_w(CEPIC_PNMIRR, cepic->pnmirr.counter);
}

static void write_hw_ctxt_to_vcpu_registers(struct kvm_vcpu *vcpu,
				const struct kvm_hw_cpu_context *hw_ctxt,
				const struct kvm_sw_cpu_context *sw_ctxt)
{
	if (vcpu->arch.is_hv) {
		write_hw_ctxt_to_hv_vcpu_registers(vcpu, hw_ctxt, sw_ctxt);
	} else if (vcpu->arch.is_pv) {
		write_hw_ctxt_to_pv_vcpu_registers(vcpu, hw_ctxt, sw_ctxt);
	} else {
		KVM_BUG_ON(true);
	}
}

noinline __interrupt
static void launch_hv_vcpu(struct kvm_vcpu_arch *vcpu)
{
	struct thread_info *ti = current_thread_info();
	struct kvm_intc_cpu_context *intc_ctxt = &vcpu->intc_ctxt;
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->sw_ctxt;
	u64 ctpr1 = AW(intc_ctxt->ctpr1), ctpr1_hi = AW(intc_ctxt->ctpr1_hi),
	    ctpr2 = AW(intc_ctxt->ctpr2), ctpr2_hi = AW(intc_ctxt->ctpr2_hi),
	    ctpr3 = AW(intc_ctxt->ctpr3), ctpr3_hi = AW(intc_ctxt->ctpr3_hi),
	    lsr = intc_ctxt->lsr, lsr1 = intc_ctxt->lsr1,
	    ilcr = intc_ctxt->ilcr, ilcr1 = intc_ctxt->ilcr1;

	/*
	 * Here kernel is on guest context including data stack
	 * so nothing complex: calls, prints, etc
	 */

	__guest_enter(ti, vcpu, FULL_CONTEXT_SWITCH | USD_CONTEXT_SWITCH |
				DEBUG_REGS_SWITCH);

	NATIVE_WRITE_CTPR2_REG_VALUE(ctpr2);
	NATIVE_WRITE_CTPR2_HI_REG_VALUE(ctpr2_hi);
#ifdef CONFIG_USE_AAU
	/* These registers must be restored after ctpr2 */
	native_set_aau_aaldis_aaldas(ti, &sw_ctxt->aau_context);
	/* Restore the real guest AASR value */
	RESTORE_GUEST_AAU_AASR(&sw_ctxt->aau_context, 1);
	NATIVE_RESTORE_AAU_MASK_REGS(&sw_ctxt->aau_context);
#endif
	/* issue GLAUNCH instruction.
	 * This macro does not restore %ctpr2 register because of ordering
	 * with AAU restore. */
	E2K_GLAUNCH(ctpr1, ctpr1_hi, ctpr2, ctpr2_hi, ctpr3, ctpr3_hi, lsr, lsr1, ilcr, ilcr1);

	AW(intc_ctxt->ctpr1) = ctpr1;
	/* Make sure that the first kernel memory access is store.
	 * This is needed to flush SLT before trying to load anything. */
	barrier();
	AW(intc_ctxt->ctpr2) = ctpr2;
	AW(intc_ctxt->ctpr3) = ctpr3;
	AW(intc_ctxt->ctpr1_hi) = ctpr1_hi;
	AW(intc_ctxt->ctpr2_hi) = ctpr2_hi;
	AW(intc_ctxt->ctpr3_hi) = ctpr3_hi;
	intc_ctxt->lsr = lsr;
	intc_ctxt->lsr1 = lsr1;
	intc_ctxt->ilcr = ilcr;
	intc_ctxt->ilcr1 = ilcr1;

	__guest_exit(ti, vcpu, FULL_CONTEXT_SWITCH | USD_CONTEXT_SWITCH |
				DEBUG_REGS_SWITCH);
}

static inline bool calculate_g_th(const intc_info_cu_hdr_t *cu_hdr,
		const struct kvm_intc_cpu_context *intc_ctxt)
{
	u64 exceptions = intc_ctxt->exceptions;

	/* Entering trap handler will freeze TIRs, so no need for g_th flag */
	if (cu_hdr->lo.tir_fz)
		return false;

	/* #132939 - hardware always tries to translate guest trap handler upon
	 * interception, so we do not set 'g_th' bit if only exc_instr_page_prot
	 * or exc_instr_page_miss happened (as those are precise traps, they
	 * will be regenerated by hardware anyway). */
	exceptions &= ~(exc_instr_page_prot_mask | exc_instr_page_miss_mask);

	if (exceptions)
		return true;

	return intc_ctxt->cu_num >= 0 && cu_hdr->lo.exc_c;
}

static int vcpu_enter_guest(struct kvm_vcpu *vcpu)
{
	gthread_info_t *gti = current_thread_info()->gthread_info;
	e2k_upsr_t guest_upsr;
	intc_info_cu_t *cu = &vcpu->arch.intc_ctxt.cu;
	intc_info_mu_t *mu = vcpu->arch.intc_ctxt.mu;
	struct kvm_intc_cpu_context *intc_ctxt = &vcpu->arch.intc_ctxt;
	u64 exceptions;
	int ret;
	bool g_th;

	raw_all_irq_disable();
	while (unlikely(current_thread_info()->flags & _TIF_WORK_MASK)) {
		raw_all_irq_enable();

		if (signal_pending(current)) {
			vcpu->run->exit_reason = KVM_EXIT_INTR;
			++vcpu->stat.signal_exits;
			return -EINTR;
		}

		/* and here we do tasks re-scheduling on a h/w interrupt */
		if (need_resched())
			schedule();

		if (test_thread_flag(TIF_NOTIFY_RESUME)) {
			clear_thread_flag(TIF_NOTIFY_RESUME);
			/*
			 * We do not have pt_regs that correspond to
			 * the intercepted context so just pass NULL.
			 */
			do_notify_resume(NULL);
		}

		raw_all_irq_disable();
	}

	preempt_disable();

	if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu)) {
		kvm_vcpu_flush_tlb(vcpu);
	}
	if (kvm_check_request(KVM_REQ_MMU_SYNC, vcpu)) {
		kvm_mmu_sync_roots(vcpu, OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG);
	}

	/* Switch IRQ control to PSR and disable MI/NMIs */
	NATIVE_WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_DISABLED));

	/* Check if guest should enter trap handler after glaunch. */
	g_th = calculate_g_th(&cu->header, intc_ctxt);

	restore_SBBP_TIRs(intc_ctxt->sbbp, intc_ctxt->TIRs, intc_ctxt->nr_TIRs,
			cu->header.lo.tir_fz, g_th);
	kvm_clear_vcpu_intc_TIRs_num(vcpu);

	/* FIXME: simulator bug: simulator does not reexecute requests */
	/* from INTC_INFO_MU unlike the hardware, so do it by software */
	if (vcpu->arch.intc_ctxt.intc_mu_to_move != 0)
		kvm_restore_vcpu_trap_cellar(vcpu);

	/* if intc info structures were updated, then restore registers */
	if (kvm_get_intc_info_mu_is_updated(vcpu)) {
		modify_intc_info_mu_data(intc_ctxt->mu, intc_ctxt->mu_num);
		restore_intc_info_mu(intc_ctxt->mu, intc_ctxt->mu_num);
	}
	if (kvm_get_intc_info_cu_is_updated(vcpu))
		restore_intc_info_cu(&intc_ctxt->cu, intc_ctxt->cu_num);

	/* MMU intercepts were handled, clear state for new intercepts */
	kvm_clear_intc_mu_state(vcpu);

	/* clear hypervisor intercept event counters */
	intc_ctxt->cu_num = -1;
	intc_ctxt->mu_num = -1;
	intc_ctxt->cur_mu = -1;
	kvm_reset_intc_info_mu_is_updated(vcpu);
	kvm_reset_intc_info_cu_is_updated(vcpu);

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_running);

	/* the function should set initial UPSR state */
	if (gti != NULL) {
		KVM_RESTORE_GUEST_KERNEL_UPSR(current_thread_info());
	}

	launch_hv_vcpu(&vcpu->arch);

	/* Guest can switch to other thread, so update guest thread info */
	gti = current_thread_info()->gthread_info;

	save_intc_info_cu(cu, &vcpu->arch.intc_ctxt.cu_num);
	save_intc_info_mu(mu, &vcpu->arch.intc_ctxt.mu_num);

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_intercept);

	/*
	 * %sbbp LIFO stack is unfreezed by writing %TIR register,
	 * so it must be read before TIRs.
	 */
	SAVE_SBBP(intc_ctxt->sbbp);

	/*
	 * Save guest TIRs should be at any case, including empty state
	 */
	exceptions = 0;
	exceptions = SAVE_TIRS(intc_ctxt->TIRs, intc_ctxt->nr_TIRs,
		true); /* from_intc */
	/* un-freeze the TIR's LIFO */
	UNFREEZE_TIRs();
	intc_ctxt->exceptions = exceptions;

	/* save current state of guest kernel UPSR */
	NATIVE_DO_SAVE_UPSR_REG(guest_upsr);
	if (gti != NULL) {
		DO_SAVE_GUEST_KERNEL_UPSR(gti, guest_upsr);
	}

	preempt_enable();

	/* This will enable interrupts */
	ret = parse_INTC_registers(&vcpu->arch);

	/* check requests after intercept handling and do */
	if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu)) {
		kvm_vcpu_flush_tlb(vcpu);
	}

	return ret;
}

static int do_startup_hv_vcpu(struct kvm_vcpu *vcpu, bool first_launch)
{
	bool nonpaging = !is_paging(vcpu);
#ifdef	SWITCH_TO_GUEST_MMU_CONTEXT
	bool host_context;
#endif	/* SWITCH_TO_GUEST_MMU_CONTEXT */
	int ret;

#ifdef	SWITCH_TO_GUEST_MMU_CONTEXT
	if (nonpaging) {
		raw_all_irq_disable();
		/* switch to guest MMU context, guest page faults should */
		/* be handled based on hypervisor U_PPTB page table */
		host_context = kvm_hv_mmu_switch_context(vcpu, false);
		KVM_WARN_ON(!host_context);
		raw_all_irq_enable();
	}
#endif	/* SWITCH_TO_GUEST_MMU_CONTEXT */

	if (kvm_request_pending(vcpu)) {
		if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu)) {
			kvm_vcpu_flush_tlb(vcpu);
		}
	}

	/* loop while some intercept event need be handled at user space */
	do {
		if (DEBUG_INTC_TIRs_MODE &&
				!kvm_check_is_vcpu_intc_TIRs_empty(vcpu)) {
			pr_info("%s(): There are traps injected to handle "
				"by guest\n",
				__func__);
			print_all_TIRs(vcpu->arch.intc_ctxt.TIRs,
					vcpu->arch.intc_ctxt.nr_TIRs);
		}
		ret = vcpu_enter_guest(vcpu);
		if (unlikely(vcpu->arch.exit_shutdown_terminate))
			ret = -1;
	} while (ret == 0 && !first_launch);

#ifdef	SWITCH_TO_GUEST_MMU_CONTEXT
	if (nonpaging) {
		raw_all_irq_disable();
		/* return to host MMU context */
		host_context = kvm_hv_mmu_switch_context(vcpu, true);
		KVM_WARN_ON(host_context);
		raw_all_irq_enable();
	}
#endif	/* SWITCH_TO_GUEST_MMU_CONTEXT */

	return ret;
}

int startup_hv_vcpu(struct kvm_vcpu *vcpu)
{
	return do_startup_hv_vcpu(vcpu, false	/* first launch ? */);
}

static void kvm_epic_write_gstid(int gst_id)
{
	union cepic_gstid reg_gstid;

	reg_gstid.raw = 0;
	reg_gstid.bits.gstid = gst_id;
	epic_write_w(CEPIC_GSTID, reg_gstid.raw);
}

static void kvm_epic_write_gstbase(unsigned long epic_gstbase)
{
	epic_write_d(CEPIC_GSTBASE_LO, epic_gstbase >> PAGE_SHIFT);
}

/*
 * Currently DAT only has 64 rows, so hardware will transform full CEPIC ID
 * back to short to get index
 */
static void kvm_epic_write_dat(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	unsigned int vcpu_id = kvm_vcpu_to_full_cepic_id(vcpu);
	unsigned int cpu = cepic_id_short_to_full(vcpu->cpu);
	unsigned int gst_id = kvm->arch.vmid.nr;
	unsigned long flags;
	union cepic_dat reg;

	reg.raw = 0;
	reg.bits.gst_id = gst_id;
	reg.bits.gst_dst = vcpu_id;
	reg.bits.index = cpu;
	reg.bits.dat_cop = CEPIC_DAT_WRITE;

	raw_spin_lock_irqsave(&vcpu->arch.epic_dat_lock, flags);
	epic_write_d(CEPIC_DAT, reg.raw);

	/* Wait for status bit */
	do {
		cpu_relax();
		reg.raw = (unsigned long) epic_read_w(CEPIC_DAT);
	} while (reg.bits.stat);
	vcpu->arch.epic_dat_active = true;
	raw_spin_unlock_irqrestore(&vcpu->arch.epic_dat_lock, flags);
}

void kvm_epic_invalidate_dat(struct kvm_vcpu_arch *vcpu)
{
	union cepic_dat reg;
	unsigned long flags;

	reg.raw = 0;
	reg.bits.index = cepic_id_short_to_full(arch_to_vcpu(vcpu)->cpu);
	reg.bits.dat_cop = CEPIC_DAT_INVALIDATE;

	raw_spin_lock_irqsave(&vcpu->epic_dat_lock, flags);
	epic_write_w(CEPIC_DAT, (unsigned int)reg.raw);

	/* Wait for status bit */
	do {
		cpu_relax();
		reg.raw = (unsigned long) epic_read_w(CEPIC_DAT);
	} while (reg.bits.stat);

	vcpu->epic_dat_active = false;
	raw_spin_unlock_irqrestore(&vcpu->epic_dat_lock, flags);
}

void kvm_epic_timer_start(void)
{
	union cepic_ctrl2 reg;

	reg.raw = epic_read_w(CEPIC_CTRL2);
	WARN_ON_ONCE(!reg.bits.timer_stop);
	reg.bits.timer_stop = 0;
	epic_write_w(CEPIC_CTRL2, reg.raw);
}

void kvm_epic_timer_stop(bool skip_check)
{
	union cepic_ctrl2 reg;

	reg.raw = epic_read_w(CEPIC_CTRL2);
	WARN_ON_ONCE(!skip_check && reg.bits.timer_stop);
	reg.bits.timer_stop = 1;
	epic_write_w(CEPIC_CTRL2, reg.raw);
}

void kvm_epic_enable_int(void)
{
	union cepic_ctrl2 reg;

	reg.raw = epic_read_w(CEPIC_CTRL2);
	reg.bits.mi_gst_blk = 0;
	reg.bits.nmi_gst_blk = 0;
	epic_write_w(CEPIC_CTRL2, reg.raw);
}

/*
 * PNMIRR "startup_entry" field cannot be restored using "OR"
 * write to PNMIRR as that will create a mix of restored and
 * previous values.  So we restore it by sending startup IPI
 * to ourselves.
 *
 * No need to acquire epic_dat_lock, as we are in the process
 * of restoring the target vcpu (this is the last step).
 */
static void kvm_epic_restore_pnmirr_startup_entry(struct kvm_vcpu *vcpu)
{
	epic_page_t *cepic = vcpu->arch.hw_ctxt.cepic;
	union cepic_pnmirr reg;

	reg.raw = atomic_read(&cepic->pnmirr);
	if (reg.bits.startup)
		kvm_hw_epic_deliver_to_icr(vcpu, reg.bits.startup_entry,
				CEPIC_ICR_DLVM_STARTUP);
}

void kvm_hv_epic_load(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	unsigned int gst_id = kvm->arch.vmid.nr;
	unsigned long epic_gstbase =
		(unsigned long) __pa(page_address(kvm->arch.epic_pages));

	kvm_epic_write_gstid(gst_id);
	kvm_epic_write_gstbase(epic_gstbase);
	kvm_epic_write_dat(vcpu);
	kvm_epic_restore_pnmirr_startup_entry(vcpu);
}


enum hrtimer_restart kvm_epic_idle_timer_fn(struct hrtimer *hrtimer)
{
	struct kvm_vcpu *vcpu = container_of(hrtimer, struct kvm_vcpu, arch.cepic_idle);

	DebugKVMIT("started on VCPU #%d\n", vcpu->vcpu_id);
	vcpu->arch.unhalted = true;
	kvm_vcpu_wake_up(vcpu);

	return HRTIMER_NORESTART;
}

void kvm_init_cepic_idle_timer(struct kvm_vcpu *vcpu)
{
	ASSERT(vcpu != NULL);
	DebugKVMIT("started on VCPU #%d\n", vcpu->vcpu_id);

	hrtimer_init(&vcpu->arch.cepic_idle, CLOCK_MONOTONIC,
		     HRTIMER_MODE_ABS);
	vcpu->arch.cepic_idle.function = kvm_epic_idle_timer_fn;
}

/* Useful for debugging problems with wakeup */
static bool periodic_wakeup = false;
module_param(periodic_wakeup, bool, 0600);

void kvm_epic_start_idle_timer(struct kvm_vcpu *vcpu)
{
	struct hrtimer *hrtimer = &vcpu->arch.cepic_idle;
	struct kvm_arch *kvm = &vcpu->kvm->arch;
	u64 cepic_timer_cur = (u64) vcpu->arch.hw_ctxt.cepic->timer_cur;
	u64 vcpu_idle_timeout_ns = jiffies_to_nsecs(VCPU_IDLE_TIMEOUT);
	u64 delta_ns;

	if (unlikely(cepic_timer_cur == 0 && !periodic_wakeup &&
			!kvm_has_passthrough_device(kvm)))
		return;

	delta_ns = (cepic_timer_cur)
			? ((u64) cepic_timer_cur * NSEC_PER_SEC / kvm->cepic_freq)
			: vcpu_idle_timeout_ns;

	/* Make sure to wake up periodically to check for interrupts
	 * from external devices.  Also do it if debugging option
	 * [periodic_wakeup] is enabled. */
	if (delta_ns > vcpu_idle_timeout_ns && (periodic_wakeup ||
						kvm_has_passthrough_device(kvm)))
		delta_ns = vcpu_idle_timeout_ns;

	ktime_t current_time = hrtimer->base->get_time();
	vcpu->arch.cepic_idle_start_time = current_time;
	hrtimer_start(&vcpu->arch.cepic_idle,
			ktime_add_ns(current_time, delta_ns), HRTIMER_MODE_ABS);
}

static u32 calculate_cepic_timer_cur(struct kvm_vcpu *vcpu, u32 cepic_timer_cur)
{
	struct hrtimer *hrtimer = &vcpu->arch.cepic_idle;
	u64 cepic_freq = vcpu->kvm->arch.cepic_freq;
	u64 cepic_timer_ns = (u64) cepic_timer_cur * NSEC_PER_SEC / cepic_freq;
	u64 passed_time_ns = ktime_to_ns(ktime_sub(hrtimer->base->get_time(),
					vcpu->arch.cepic_idle_start_time));
	if (cepic_timer_ns > passed_time_ns)
		cepic_timer_ns -= passed_time_ns;
	else
		cepic_timer_ns = 0;

	u64 new_timer_cur = max(cepic_timer_ns * cepic_freq / NSEC_PER_SEC, 1ull);
	if (WARN_ON_ONCE(new_timer_cur > (u64) UINT_MAX))
		new_timer_cur = UINT_MAX;
	return new_timer_cur;
}

void kvm_epic_stop_idle_timer(struct kvm_vcpu *vcpu)
{
	struct hrtimer *hrtimer = &vcpu->arch.cepic_idle;
	epic_page_t *cepic = vcpu->arch.hw_ctxt.cepic;
	u32 cepic_timer_cur = (u64) cepic->timer_cur;

	/* Stop the software timer if it is still running */
	hrtimer_cancel(hrtimer);

	/* Adjust CEPIC timer if it is running, otherwise the guest might hang
	 * for a long time.  For example, if guest waits in idle then most of
	 * the time it does not actually execute and thus the timer advances
	 * at a _much_ slower rate; it is hypervisor's duty to forward CEPIC
	 * timer in this case. */
	if (cepic_timer_cur) {
		cepic->timer_cur = calculate_cepic_timer_cur(vcpu, cepic_timer_cur);
		DebugKVMIT("Recalculating cepic timer %d from %x to %x\n",
				vcpu->vcpu_id, cepic_timer_cur, cepic->timer_cur);
	} else {
		DebugKVMIT("Not recalculating cepic timer %d\n", vcpu->vcpu_id);
	}
}

static int kvm_prepare_hv_vcpu_start_stacks(struct kvm_vcpu *vcpu)
{
	prepare_bu_stacks_to_startup_vcpu(vcpu);
	return 0;
}

static int kvm_prepare_vcpu_start_stacks(struct kvm_vcpu *vcpu)
{
	int ret;

	if (vcpu->arch.is_hv) {
		ret = kvm_prepare_hv_vcpu_start_stacks(vcpu);
	} else if (vcpu->arch.is_pv) {
		ret = kvm_prepare_pv_vcpu_start_stacks(vcpu);
	} else {
		KVM_BUG_ON(true);
		ret = -EINVAL;
	}
	return ret;
}

int kvm_start_vcpu_thread(struct kvm_vcpu *vcpu)
{
	int ret;

	DebugKVM("started to start guest kernel on VCPU %d\n",
		vcpu->vcpu_id);


	if (vcpu->arch.is_hv) {
		ret = hv_vcpu_start_thread(vcpu);
	} else if (vcpu->arch.is_pv) {
		ret = pv_vcpu_start_thread(vcpu);
	} else {
		KVM_BUG_ON(true);
		ret = -EINVAL;
	}
	if (ret != 0)
		return ret;

	/* prepare start stacks */
	ret = kvm_prepare_vcpu_start_stacks(vcpu);
	if (ret != 0) {
		pr_err("%s(): could not prepare VCPU #%d start stacks, "
			"error %d\n",
			__func__, vcpu->vcpu_id, ret);
		return ret;
	}

	/* create empty root PT to translate GPA -> PA while guest will */
	/* create own PTs and then switch to them and enable virtual space */
	kvm_hv_setup_nonpaging_mode(vcpu);

	/* hardware context initialization and shadow registers setting */
	/* should be under disabled preemption to exclude scheduling */
	/* and save/restore intermediate state of shadow registers */
	preempt_disable();
	kvm_init_sw_ctxt(vcpu);
	init_hw_ctxt(vcpu);
	kvm_set_vcpu_pt_context(vcpu);
	init_vcpu_intc_ctxt(vcpu);
	write_hw_ctxt_to_vcpu_registers(vcpu,
			&vcpu->arch.hw_ctxt, &vcpu->arch.sw_ctxt);
	preempt_enable();

	/* prefetch MMIO space areas, which should be */
	/* directly accessed by guest */
	kvm_prefetch_mmio_areas(vcpu);

	/* Set global registers to empty state as start state of guest */
	INIT_G_REGS();
	/* Zeroing global registers used by kernel */
	CLEAR_KERNEL_GREGS_COPY(current_thread_info());
	/* Setup guest type special globals registers */
	if (test_kvm_mode_flag(vcpu->kvm, KVMF_LINTEL)) {
		kvm_init_lintel_gregs(vcpu);
	} else {
		/* Set pointer to VCPU state to enable interface with guest */
		INIT_HOST_VCPU_STATE_GREG_COPY(current_thread_info(), vcpu);
	}

	return 0;
}
