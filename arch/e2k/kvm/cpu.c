/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


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
#include <asm/kvm/switch.h>
#include <asm/kvm/trace_kvm_pv.h>
#include <asm/kvm/gregs.h>
#include "cpu.h"
#include "process.h"
#include "mmu.h"
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include "paravirt_sw/gaccess.h"
#include <asm/kvm/paravirt_sw/runstate.h>
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

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

#undef	DEBUG_PV_VCPU_TRAP_MODE
#undef	DebugTRAP
#define	DEBUG_PV_VCPU_TRAP_MODE	0	/* trap injection debugging */
#define	DebugTRAP(fmt, args...)						\
({									\
	if (DEBUG_PV_VCPU_TRAP_MODE)					\
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

#undef	DEBUG_INTC_CU_REG_MODE
#undef	DebugCUREG
#define	DEBUG_INTC_CU_REG_MODE	0	/* CPU reguster access intercept */
					/* events debug mode */
#define	DebugCUREG(fmt, args...)					\
({									\
	if (DEBUG_INTC_CU_REG_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PV_SYSCALL_MODE
#define	DEBUG_PV_SYSCALL_MODE	0	/* syscall injection debugging */

#if	DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE
extern bool debug_guest_ust;
#else
#define	debug_guest_ust	false
#endif /* DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE */

#undef	DEBUG_KVM_STARTUP_MODE
#undef	DebugKVMSTUP
#define	DEBUG_KVM_STARTUP_MODE	0	/* VCPU startup debugging */
#define	DebugKVMSTUP(fmt, args...)					\
({									\
	if (DEBUG_KVM_STARTUP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})


__visible int __nodedata slt_disable;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION

bool debug_guest_user_stacks = false;

void kvm_set_pv_vcpu_kernel_image(struct kvm_vcpu *vcpu)
{
	e2k_cud_t oscud;
	e2k_gd_t osgd;
	e2k_cute_t *cute_p;
	u64 base;
	e2k_cutd_t cutd;

	if (vcpu->arch.vcpu_state == NULL)
		return;

	oscud = vcpu_new_cud(vcpu, (u64)vcpu->arch.guest_phys_base,
			vcpu->arch.guest_size, 0, cud_m64);
	kvm_set_guest_vcpu_OSCUD(vcpu, oscud);
	DebugKVM("set OSCUD to guest kernel image: base 0x%llx, size 0x%llx\n",
		 vcpu_cud_base(vcpu, oscud), vcpu_cud_size(vcpu, oscud));
	kvm_set_guest_vcpu_CUD(vcpu, oscud);
	DebugKVM("set CUD to init state: base 0x%llx, size 0x%llx\n",
		 vcpu_cud_base(vcpu, oscud), vcpu_cud_size(vcpu, oscud));

	osgd = vcpu_new_gd(vcpu, (u64) vcpu->arch.guest_phys_base, vcpu->arch.guest_size);
	kvm_set_guest_vcpu_OSGD(vcpu, osgd);
	DebugKVM("set OSGD to guest kernel image: base 0x%llx, size 0x%llx\n",
		 vcpu_gd_base(vcpu, osgd), vcpu_gd_size(vcpu, osgd));
	kvm_set_guest_vcpu_GD(vcpu, osgd);
	DebugKVM("set GD to init state: base 0x%llx, size 0x%llx\n",
		 vcpu_gd_base(vcpu, osgd), vcpu_gd_size(vcpu, osgd));

	cute_p = (e2k_cute_t *) kvm_vcpu_hva_to_gpa(vcpu, (unsigned long)vcpu->arch.guest_cut);
	base = (e2k_addr_t) cute_p;
	cutd.base = base;
	kvm_set_guest_vcpu_OSCUTD(vcpu, cutd);
	kvm_set_guest_vcpu_CUTD(vcpu, cutd);
	DebugKVM("set OSCUTD & CUTD to init state: base 0x%llx\n", cutd.base);
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

e2k_idr_t kvm_vcpu_get_idr(const struct kvm_vcpu *vcpu)
{
	kvm_guest_info_t *guest_info = &vcpu->kvm->arch.guest_info;
	e2k_idr_t idr = read_IDR_reg();

	if (idr.mdl == guest_info->cpu_mdl) {
		/* In native case must report actual revision to apply
		 * needed workarounds and distinguish engineering samples. */
	} else {
		/* Update IDR in accordance with guest machine CPUs type */
		idr.mdl = guest_info->cpu_mdl;
		idr.rev = guest_info->cpu_rev;
	}
	idr.core = vcpu->vcpu_id;
	idr.pn = 0;	/* FIXME: is not implemented NUMA node id */
	if (guest_info->cpu_iset < E2K_ISET_V3) {
		/* Set IDR.hw_virt to mark guest mode because
		 * iset V2 CPUs do not have CORE_MODE register */
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		idr.hw_virt = vcpu->kvm->arch.is_hv;
#else
		idr.hw_virt = true;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	}

	return idr;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
void kvm_dump_shadow_u_pptb(struct kvm_vcpu *vcpu, const char *title)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	DebugSHC("%s   sh_U_PPTB:  value 0x%lx\n"
		 "   sh_U_VPTB:  value 0x%lx\n"
		 "   U_PPTB:     value 0x%lx\n"
		 "   U_VPTB:     value 0x%lx\n"
		 "   SH_PID:     value 0x%llx\n",
		 title,
		 mmu->get_vcpu_context_u_pptb(vcpu),
		 mmu->get_vcpu_context_u_vptb(vcpu),
		 mmu->get_vcpu_u_pptb(vcpu),
		 mmu->get_vcpu_u_vptb(vcpu), read_guest_PID_reg(vcpu));
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

void prepare_stacks_to_startup_vcpu(struct kvm_vcpu *vcpu,
				    e2k_mem_ps_t *ps_frames,
				    e2k_mem_crs_t *pcs_frames, u64 *args,
				    int args_num, char *entry_point,
				    e2k_psr_t psr, e2k_size_t usd_size,
				    e2k_size_t *ps_ind, e2k_size_t *pcs_ind,
				    int cui, bool kernel)
{
	e2k_cr0_t cr0;
	e2k_cr1_t cr1;
	unsigned long ussz, entry_IP;
	int arg;
	int wbs;

	DebugKVMSTUP("started on VCPU #%d\n", vcpu->vcpu_id);

	entry_IP = (unsigned long)entry_point;

	wbs = (sizeof(*args) * 2 * args_num + (EXT_4_NR_SZ - 1)) / EXT_4_NR_SZ;

	/* pcs[0] frame can be empty, because of it should not be returns */
	/* to here and it is used only to fill into current CR registers */
	/* while function on the next frame pcs[1] is running */
	pcs_frames[0].cr0.pf = -1;
	set_cr0_ip(pcs_frames[0].cr0, 0);
	pcs_frames[0].cr1 = (e2k_cr1_t) { 0 };

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/* guest is user of host for pv, GLAUNCH set PSR for hv */
	/* set mode to run guest */
	if (!vcpu->arch.is_hv)
		psr.pm = 0;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	/* Prepare pcs[1] frame, it is frame of VCPU start function */
	/* Important only only IP (as start of function) */
	cr0.pf = -1;
	set_cr0_ip(cr0, entry_IP);
	cr1 = (e2k_cr1_t) { 0 };
	cr1.psr = AW(psr);
	cr1.wbs = wbs;
	cr1.wpsz = wbs;
	cr1.cui = cui;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (!cpu_has(CPU_FEAT_ISET_V6))
		cr1.ic = kernel;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	ussz = (vcpu_descr_v7(vcpu)) ? 0 : usd_size;
	cr1 = vcpu_set_cr1_ussz(vcpu, cr1, ussz);
	pcs_frames[1].cr0 = cr0;
	pcs_frames[1].cr1 = cr1;

	DebugKVMSTUP("VCPU start PCS[1]: IP %pF wbs 0x%x\n",
		     (void *)get_cr0_ip(pcs_frames[1].cr0),
		     pcs_frames[1].cr1.wbs * EXT_4_NR_SZ);
	DebugKVMSTUP("   PCS[%d] CR0 lo: 0x%016llx  hi: 0x%016llx\n",
		     1, LO(pcs_frames[1].cr0), HI(pcs_frames[1].cr0));
	DebugKVMSTUP("   PCS[%d] CR1 lo: 0x%016llx  hi: 0x%016llx\n",
		     1, LO(pcs_frames[1].cr1), HI(pcs_frames[1].cr1));
	DebugKVMSTUP("   PCS[%d] CR0 lo: 0x%016llx  hi: 0x%016llx\n",
		     0, LO(pcs_frames[0].cr0), HI(pcs_frames[0].cr0));
	DebugKVMSTUP("   PCS[%d] CR1 lo: 0x%016llx  hi: 0x%016llx\n",
		     0, LO(pcs_frames[0].cr1), HI(pcs_frames[0].cr1));

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
				ps_frames[frame].v3.word_lo = arg_value;
			else
				ps_frames[frame].v3.word_hi = arg_value;
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
	DebugKVMSTUP("stacks PS.ind 0x%lx PCS.ind 0x%lx\n", *ps_ind, *pcs_ind);
}

__section(".entry.text")
notrace __interrupt void kvm_switch_debug_regs(struct kvm_sw_cpu_context *sw_ctxt,
		bool guest_enter)
{
	u64 b_dimar0, b_dimar1, b_dimar2, b_dimar3, b_ddmar0, b_ddmar1, b_ddmar2,
	    b_ddmar3, b_dibar0, b_dibar1, b_dibar2, b_dibar3, b_ddbar0, b_ddbar1,
	    b_ddbar2, b_ddbar3, a_dimar0, a_dimar1, a_dimar2, a_dimar3, a_ddmar0,
	    a_ddmar1, a_ddmar2, a_ddmar3, a_dibar0, a_dibar1, a_dibar2, a_dibar3,
	    a_ddbar0, a_ddbar1, a_ddbar2, a_ddbar3;
	e2k_dimcr_t b_dimcr, b_dimcr1, a_dimcr, a_dimcr1;
	e2k_ddmcr_t b_ddmcr, b_ddmcr1, a_ddmcr, a_ddmcr1;
	e2k_dibcr_t b_dibcr, a_dibcr;
	e2k_dibsr_t b_dibsr, a_dibsr;
	e2k_ddbcr_t b_ddbcr, a_ddbcr;
	e2k_ddbsr_t b_ddbsr, a_ddbsr;
	e2k_dimtp_t b_dimtp, a_dimtp;
	bool has_dimcr1 = cpu_has(CPU_FEAT_ISET_V7) && !cpu_has(CPU_HWBUG_DIMCR1);
	bool has_ddmcr1 = cpu_has(CPU_FEAT_ISET_V7);

	b_dibcr = sw_ctxt->dibcr;
	b_ddbcr = sw_ctxt->ddbcr;
	b_dibsr = sw_ctxt->dibsr;
	b_ddbsr = sw_ctxt->ddbsr;
	b_dimcr = sw_ctxt->dimcr;
	b_ddmcr = sw_ctxt->ddmcr;
	b_dibar0 = sw_ctxt->dibar[0];
	b_dibar1 = sw_ctxt->dibar[1];
	b_dibar2 = sw_ctxt->dibar[2];
	b_dibar3 = sw_ctxt->dibar[3];
	b_ddbar0 = sw_ctxt->ddbar[0];
	b_ddbar1 = sw_ctxt->ddbar[1];
	b_ddbar2 = sw_ctxt->ddbar[2];
	b_ddbar3 = sw_ctxt->ddbar[3];
	b_dimar0 = sw_ctxt->dimar[0];
	b_dimar1 = sw_ctxt->dimar[1];
	b_ddmar0 = sw_ctxt->ddmar[0];
	b_ddmar1 = sw_ctxt->ddmar[1];
	b_dimtp = sw_ctxt->dimtp;

	if (has_ddmcr1) {
		b_ddmcr1 = sw_ctxt->ddmcr1;
		b_ddmar2 = sw_ctxt->ddmar[2];
		b_ddmar3 = sw_ctxt->ddmar[3];

		a_ddmcr1 = NATIVE_READ_DDMCR1_REG();
		a_ddmar2 = NATIVE_READ_DDMAR2_REG();
		a_ddmar3 = NATIVE_READ_DDMAR3_REG();
	}

	if (has_dimcr1) {
		b_dimcr1 = sw_ctxt->dimcr1;
		b_dimar2 = sw_ctxt->dimar[2];
		b_dimar3 = sw_ctxt->dimar[3];

		a_dimcr1 = native_read_DIMCR1_reg();
		a_dimar2 = native_read_DIMAR2_reg();
		a_dimar3 = native_read_DIMAR3_reg();
	}

	a_dibcr = native_read_DIBCR_reg();
	a_ddbcr = NATIVE_READ_DDBCR_REG();
	a_dibsr = native_read_DIBSR_reg();
	a_ddbsr = NATIVE_READ_DDBSR_REG();
	a_dimcr = native_read_DIMCR_reg();
	a_ddmcr = NATIVE_READ_DDMCR_REG();
	a_dibar0 = native_read_DIBAR0_reg();
	a_dibar1 = native_read_DIBAR1_reg();
	a_dibar2 = native_read_DIBAR2_reg();
	a_dibar3 = native_read_DIBAR3_reg();
	a_ddbar0 = NATIVE_READ_DDBAR0_REG_VALUE();
	a_ddbar1 = NATIVE_READ_DDBAR1_REG_VALUE();
	a_ddbar2 = NATIVE_READ_DDBAR2_REG_VALUE();
	a_ddbar3 = NATIVE_READ_DDBAR3_REG_VALUE();
	a_ddmar0 = NATIVE_READ_DDMAR0_REG();
	a_ddmar1 = NATIVE_READ_DDMAR1_REG();
	a_dimar0 = native_read_DIMAR0_reg();
	a_dimar1 = native_read_DIMAR1_reg();

	if (guest_enter) {
		a_dimtp = native_read_DIMTP_reg();

		/* These two must be written first to disable monitoring */
		native_write_DIBCR_reg(b_dibcr);
		NATIVE_WRITE_DDBCR_REG(b_ddbcr);
	} else {
		a_dimtp = native_read_guest_DIMTP_reg();
	}
	native_write_DIBARs(b_dibar0, b_dibar1, b_dibar2, b_dibar3);
	native_write_DDBARs(b_ddbar0, b_ddbar1, b_ddbar2, b_ddbar3);
	native_write_DDMAR0_DDMAR1(b_ddmar0, b_ddmar1);
	native_write_DIMAR0_DIMAR1(b_dimar0, b_dimar1);
	native_write_DIBSR_reg(b_dibsr);
	NATIVE_WRITE_DDBSR_REG(b_ddbsr);
	native_write_DIMCR_reg(b_dimcr);
	NATIVE_WRITE_DDMCR_REG(b_ddmcr);
	if (has_ddmcr1) {
		native_write_DDMAR2_DDMAR3(b_ddmar2, b_ddmar3);
		NATIVE_WRITE_DDMCR1_REG(b_ddmcr1);
	}
	if (has_dimcr1) {
		native_write_DIMAR2_DIMAR3(b_dimar2, b_dimar3);
		native_write_DIMCR1_reg(b_dimcr1);
	}
	if (guest_enter) {
		native_write_guest_DIMTP_reg(b_dimtp);
	} else {
		native_write_DIMTP_reg(b_dimtp);

		/* These two must be written last to enable monitoring */
		native_write_DIBCR_reg(b_dibcr);
		NATIVE_WRITE_DDBCR_REG(b_ddbcr);
	}

	sw_ctxt->dibcr = a_dibcr;
	sw_ctxt->ddbcr = a_ddbcr;
	sw_ctxt->dibsr = a_dibsr;
	sw_ctxt->ddbsr = a_ddbsr;
	sw_ctxt->dimcr = a_dimcr;
	sw_ctxt->ddmcr = a_ddmcr;
	sw_ctxt->dibar[0] = a_dibar0;
	sw_ctxt->dibar[1] = a_dibar1;
	sw_ctxt->dibar[2] = a_dibar2;
	sw_ctxt->dibar[3] = a_dibar3;
	sw_ctxt->ddbar[0] = a_ddbar0;
	sw_ctxt->ddbar[1] = a_ddbar1;
	sw_ctxt->ddbar[2] = a_ddbar2;
	sw_ctxt->ddbar[3] = a_ddbar3;
	sw_ctxt->ddmar[0] = a_ddmar0;
	sw_ctxt->ddmar[1] = a_ddmar1;
	sw_ctxt->dimar[0] = a_dimar0;
	sw_ctxt->dimar[1] = a_dimar1;
	sw_ctxt->dimtp = a_dimtp;
	if (has_ddmcr1) {
		sw_ctxt->ddmcr1 = a_ddmcr1;
		sw_ctxt->ddmar[2] = a_ddmar2;
		sw_ctxt->ddmar[3] = a_ddmar3;
	}
	if (has_dimcr1) {
		sw_ctxt->dimcr1 = a_dimcr1;
		sw_ctxt->dimar[2] = a_dimar2;
		sw_ctxt->dimar[3] = a_dimar3;
	}
}
