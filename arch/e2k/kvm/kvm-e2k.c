/*
 * kvm_e2k.c: Basic KVM support On Elbrus series processors
 *
 *
 *	Copyright (C) 2011, MCST.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/percpu.h>
#include <linux/gfp.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/bitops.h>
#include <linux/hrtimer.h>
#include <linux/uaccess.h>
#include <linux/highmem.h>
#include <linux/pci.h>
#include <linux/vgaarb.h>

#include <asm/epic.h>
#include <asm/pgtable.h>
#include <asm/process.h>
#include <asm/regs_state.h>
#include <asm/ptrace.h>
#include <asm/io.h>
#include <asm/e2k-iommu.h>
#include <asm/kvm.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/mmu_hv_regs_types.h>
#include <asm/kvm/runstate.h>
#include <asm/kvm/page_track.h>
#include <asm/kvm/switch.h>
#include <asm/kvm/boot.h>
#include <asm/kvm/async_pf.h>
#include <kvm/iodev.h>

#ifdef	CONFIG_KVM_HOST_MODE

#define CREATE_TRACE_POINTS
#include <asm/kvm/trace_kvm.h>
#include <asm/kvm/trace_kvm_pv.h>
#include <asm/kvm/trace_kvm_hv.h>

#include "user_area.h"
#include "vmid.h"
#include "cpu.h"
#include "mmu.h"
#include "io.h"
#include "process.h"
#include "sic-nbsr.h"
#include "ioapic.h"
#include "pic.h"
#include "irq.h"
#include "time.h"
#include "lt.h"
#include "spmc.h"
#include "gaccess.h"
#include "gregs.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	1	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_RUN_MODE
#undef	DebugKVMRUN
#define	DEBUG_KVM_RUN_MODE	0	/* run debugging */
#define	DebugKVMRUN(fmt, args...)					\
({									\
	if (DEBUG_KVM_RUN_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_EXIT_REQ_MODE
#undef	DebugKVMER
#define	DEBUG_KVM_EXIT_REQ_MODE	0	/* exit request debugging */
#define	DebugKVMER(fmt, args...)					\
({									\
	if (DEBUG_KVM_EXIT_REQ_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_EXIT_REQ_MAIN_MODE
#undef	DebugKVMERM
#define	DEBUG_KVM_EXIT_REQ_MAIN_MODE	0	/* exit request verbose */
#define	DebugKVMERM(fmt, args...)					\
({									\
	if (DEBUG_KVM_EXIT_REQ_MAIN_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_PAGE_FAULT_MODE
#undef	DebugKVMPF
#define	DEBUG_KVM_PAGE_FAULT_MODE	0	/* page fault on KVM */
#define	DebugKVMPF(fmt, args...)					\
({									\
	if (DEBUG_KVM_PAGE_FAULT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_PARAVIRT_FAULT_MODE
#undef	DebugKVMPVF
#define	DEBUG_KVM_PARAVIRT_FAULT_MODE	0	/* paravirt page fault on KVM */
#define	DebugKVMPVF(fmt, args...)					\
({									\
	if (DEBUG_KVM_PARAVIRT_FAULT_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PARAVIRT_PREFAULT_MODE
#undef	DebugPVF
#define	DEBUG_PARAVIRT_PREFAULT_MODE	0	/* paravirt page prefault */
#define	DebugPVF(fmt, args...)						\
({									\
	if (DEBUG_PARAVIRT_PREFAULT_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_IOCTL_MODE
#undef	DebugKVMIOCTL
#define	DEBUG_KVM_IOCTL_MODE	1	/* kernel IOCTL debug */
#define	DebugKVMIOCTL(fmt, args...)					\
({									\
	if (DEBUG_KVM_IOCTL_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_IOC_MODE
#undef	DebugKVMIOC
#define	DEBUG_KVM_IOC_MODE	0	/* kernel IOCTL verbose debug */
#define	DebugKVMIOC(fmt, args...)					\
({									\
	if (DEBUG_KVM_IOC_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_IO_MODE
#undef	DebugKVMIO
#define	DEBUG_KVM_IO_MODE	0	/* kernel virt machine IO debug */
#define	DebugKVMIO(fmt, args...)					\
({									\
	if (DEBUG_KVM_IO_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_IRQ_MODE
#undef	DebugKVMIRQ
#define	DEBUG_KVM_IRQ_MODE	0	/* kernel virt machine IRQ debugging */
#define	DebugKVMIRQ(fmt, args...)					\
({									\
	if (DEBUG_KVM_IRQ_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SHUTDOWN_MODE
#undef	DebugKVMSH
#define	DEBUG_KVM_SHUTDOWN_MODE	1	/* KVM shutdown debugging */
#define	DebugKVMSH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SHUTDOWN_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_HV_MODE
#undef	DebugKVMHV
#define	DEBUG_KVM_HV_MODE	1	/* hardware virtualized VM debugging */
#define	DebugKVMHV(fmt, args...)					\
({									\
	if (DEBUG_KVM_HV_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	VM_BUG_ON
#define VM_BUG_ON(cond) BUG_ON(cond)

MODULE_AUTHOR("Elbrus MCST");
MODULE_DESCRIPTION("E2K arch virtualization driver based on KVM");
MODULE_LICENSE("GPL");

/* mask of available and supported by the hypervisor VM types */
/* depends on hardware, CPU ISET, kernel & hypervisor configuration */
unsigned int kvm_vm_types_available = 0;

extern __read_mostly struct preempt_ops kvm_preempt_ops;

static int kvm_arch_pv_vcpu_init(struct kvm_vcpu *vcpu);
static void kvm_arch_pv_vcpu_uninit(struct kvm_vcpu *vcpu);
static int kvm_arch_pv_vcpu_setup(struct kvm_vcpu *vcpu);
static int kvm_arch_hv_vcpu_init(struct kvm_vcpu *vcpu);
static void kvm_arch_hv_vcpu_uninit(struct kvm_vcpu *vcpu);
static int kvm_arch_hv_vcpu_setup(struct kvm_vcpu *vcpu);
static int kvm_arch_any_vcpu_init(struct kvm_vcpu *vcpu);
static void kvm_arch_any_vcpu_uninit(struct kvm_vcpu *vcpu);
static int kvm_arch_any_vcpu_setup(struct kvm_vcpu *vcpu);

static user_area_t *kvm_find_memory_region(struct kvm *kvm,
			int slot, e2k_addr_t address, e2k_size_t size,
			kvm_guest_mem_type_t type);
static long kvm_arch_ioctl_alloc_guest_area(struct kvm *kvm,
				kvm_guest_area_alloc_t __user *what);
static int gva_to_alias_slot(struct kvm *kvm, gva_t gva);
static int find_shadow_intersection(struct kvm *kvm, e2k_addr_t kernel_base,
		gva_t shadow_base, e2k_size_t area_size);
void kvm_arch_vcpu_free(struct kvm_vcpu *vcpu);
static void kvm_arch_vcpu_release(struct kvm_vcpu *vcpu);
static void free_vcpu_state(struct kvm_vcpu *vcpu);
static int kvm_create_host_info(struct kvm *kvm);
static void kvm_free_host_info(struct kvm *kvm);
static int init_guest_boot_cut(struct kvm_vcpu *vcpu);
static int init_guest_vcpu_state(struct kvm_vcpu *vcpu);
static void kvm_wake_up_all_other_vcpu_host(struct kvm_vcpu *my_vcpu);

struct kvm_stats_debugfs_item debugfs_entries[] = {
	//TODO fill me
	{ NULL }
};

static bool kvm_is_guest_pv_vm(void)
{
	if (paravirt_enabled()) {
		pr_err("KVM: paravirtualized guest cannot support nested VM\n");
		return true;
	}
	return false;
}

#ifdef	CONFIG_KVM_HW_VIRTUALIZATION
static bool kvm_cpu_has_hv_support(void)
{
	e2k_idr_t IDR;

	IDR = read_IDR_reg();
	if (!IDR.hw_virt || machine.native_iset_ver < E2K_ISET_V6) {
		return false;
	}
	DebugKVM("CPUs have hardware virtualization extensions version %d\n",
		IDR.IDR_ms_hw_virt_ver);
	return true;
}

static bool kvm_cpu_hv_disabled(void)
{
	unsigned int CU_HW0;

	CU_HW0 = READ_CU_HW0_REG_VALUE();
	if (CU_HW0 & _CU_HW0_VIRT_DISABLE_MASK) {
		DebugKVM("CPUs hardware virtualization extensions "
			"are disabled\n");
		return true;
	}
	return false;
}

static bool kvm_is_guest_hv_vm(void)
{
	e2k_core_mode_t CORE_MODE;

	CORE_MODE.CORE_MODE_reg = READ_CORE_MODE_REG_VALUE();
	if (CORE_MODE.CORE_MODE_gmi) {
		DebugKVM("KVM: it is hardware virtualized guest VM\n");
		return true;
	}
	return false;
}

static bool kvm_is_hv_enable(void)
{
	if (!kvm_cpu_has_hv_support()) {
		pr_err("KVM: no hardware virtualization extentions\n");
		return false;
	}
	if (kvm_cpu_hv_disabled()) {
		pr_err("KVM: hardware virtualization extentions "
			"are disabled\n");
		return false;
	}
	if (kvm_is_guest_hv_vm()) {
		pr_err("KVM: hardware virtualized guest cannot "
			"run nested VM\n");
		return false;
	}
	return true;
}

static void epic_virt_enable(void)
{
	union prepic_ctrl2 reg_ctrl;
	int node;

	KVM_BUG_ON(!cpu_has(CPU_FEAT_EPIC));

	reg_ctrl.raw = 0;
	reg_ctrl.bits.virt_en = 1;
	if (epic_bgi_mode)
		reg_ctrl.bits.bgi_mode = 1;

	for_each_online_node(node)
		prepic_node_write_w(node, SIC_prepic_ctrl2, reg_ctrl.raw);

	DebugKVM("Enabled virtualization support in PREPIC. bgi_mode=%d\n",
		epic_bgi_mode);
}

/* Set up CEPIC_EPIC_INT (IPI delivery to inactive guest) */
static void kvm_setup_cepic_epic_int(void)
{
	union cepic_epic_int reg;

	reg.raw = 0;
	reg.bits.vect = CEPIC_EPIC_INT_VECTOR;
	epic_write_w(CEPIC_EPIC_INT, reg.raw);
}

static int kvm_hardware_virt_enable(void)
{
	e2k_core_mode_t CORE_MODE;

	/* set guest CORE_MODE register to allow of guest mode indicator */
	/* for guest kernels, so any VM software can see guest mode */
	CORE_MODE.CORE_MODE_reg = read_SH_CORE_MODE_reg_value();
	CORE_MODE.CORE_MODE_gmi = 1;
	CORE_MODE.CORE_MODE_hci = 1;
	write_SH_CORE_MODE_reg_value(CORE_MODE.CORE_MODE_reg);

	DebugKVM("KVM: CPU #%d: set guest CORE_MODE to indicate guest mode "
		"on any VMs\n",
		raw_smp_processor_id());

	if (cpu_has(CPU_FEAT_EPIC)) {
		/* FIXME: epic_virt_enable() should be called once,
		 * not on each CPU */
		epic_virt_enable();
		kvm_epic_timer_stop();
		kvm_setup_cepic_epic_int();
	}

	return 0;
}
#else	/* ! CONFIG_KVM_HW_VIRTUALIZATION */
static bool kvm_is_hv_enable(void)
{
	pr_err("KVM: hardware virtualization mode is turned OFF at "
		"kernel config\n");
	return false;
}
static int kvm_hardware_virt_enable(void)
{
	pr_err("KVM: hardware virtualization mode is turned OFF at "
		"kernel config\n");
	return 0;
}
#endif	/* CONFIG_KVM_HW_VIRTUALIZATION */

#ifdef	CONFIG_KVM_HW_PARAVIRTUALIZATION
static bool kvm_is_hw_pv_enable(void)
{
	if (!kvm_is_hv_enable())
		return false;
	return true;
}

#else	/* ! CONFIG_KVM_HW_PARAVIRTUALIZATION */
static bool kvm_is_hw_pv_enable(void)
{
	pr_err("KVM: hardware paravirtualization mode is turned OFF at "
		"kernel config\n");
	return false;
}
#endif	/* CONFIG_KVM_HW_PARAVIRTUALIZATION */

int kvm_arch_hardware_enable(void)
{
	DebugKVM("started\n");
	if (kvm_is_hv_vm_available() || kvm_is_hw_pv_vm_available())
		return kvm_hardware_virt_enable();
	return 0;
}

void kvm_arch_hardware_disable(void)
{
	DebugKVM("started\n");
}

int kvm_arch_check_processor_compat(void)
{
	DebugKVM("started\n");

	if (kvm_is_hv_vm_available() && !kvm_is_hv_enable()) {
		pr_err("KVM: CPU #%d has not hardware virtualization support\n",
			raw_smp_processor_id());
		atomic_clear_mask(KVM_E2K_HV_VM_TYPE_MASK,
					&kvm_vm_types_available);
	}

	if (kvm_is_hw_pv_vm_available() && !kvm_is_hw_pv_enable()) {
		pr_err("KVM: CPU #%d has not hardware paravirtualization "
			"support\n",
			raw_smp_processor_id());
		atomic_clear_mask(KVM_E2K_HW_PV_VM_TYPE_MASK,
					&kvm_vm_types_available);
	}

	if (kvm_vm_types_available == 0)
		return -EINVAL;
	else
		return 0;
}

#ifdef	CONFIG_KVM_PARAVIRTUALIZATION

static int create_vcpu_state(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	kvm_vcpu_state_t *vcpu_state = NULL;
	kvm_vcpu_state_t *kmap_vcpu_state = NULL;
	e2k_cute_t *cute_p = NULL;
	user_area_t *guest_area;
	e2k_size_t cut_size, size;
	int npages;
	long r;

	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);
	npages = PAGE_ALIGN(sizeof(kvm_vcpu_state_t)) >> PAGE_SHIFT;
	size = (npages << PAGE_SHIFT);
	if (vcpu->arch.is_pv) {
		cut_size = sizeof(*cute_p) * MAX_GUEST_CODES_UNITS;
		size += PAGE_ALIGN(cut_size);
	} else {
		cut_size = 0;
		vcpu->arch.guest_cut = NULL;
	}
	guest_area = kvm_find_memory_region(kvm, -1, 0, size,
						guest_vram_mem_type);
	if (guest_area == NULL) {
		DebugKVM("guest memory regions is not created or empty\n");
		return -EINVAL;
	}
	vcpu_state = user_area_alloc_locked_pages(guest_area, 0,
			sizeof(kvm_vcpu_state_t), 1 << E2K_ALIGN_GLOBALS, 0);
	if (vcpu_state == NULL) {
		DebugKVM("could not allocate VCPU state struct\n");
		r = -ENOMEM;
		goto error;
	}
	/*
	 * VCPU state maps to kernel vmaloc range to have access into
	 * this state from any host kernel threads
	 * For example, it needs for hrtimer callback function, which
	 * can be called on any process
	 */
	kmap_vcpu_state = map_user_area_to_vmalloc_range(guest_area,
						vcpu_state, PAGE_KERNEL);
	if (kmap_vcpu_state == NULL) {
		DebugKVM("could not map VCPU state struct to kernel VM\n");
		r = -ENOMEM;
		goto error;
	}

	memset(vcpu_state, 0, sizeof(kvm_vcpu_state_t));
	vcpu->arch.vcpu_state = vcpu_state;
	vcpu->arch.kmap_vcpu_state = kmap_vcpu_state;
	if (IS_INVALID_GPA(kvm_vcpu_hva_to_gpa(vcpu, (u64)vcpu_state))) {
		pr_err("%s() : could not allocate GPA of VCPU state struct\n",
			__func__);
		r = -ENOMEM;
		goto error;
	}
	kvm_setup_guest_VCPU_ID(vcpu, (const u32)vcpu->vcpu_id);

	if (cut_size == 0) {
		DebugKVM("VCPU #%d state struct allocated at %px\n",
			vcpu->vcpu_id,
			(void *)kvm_vcpu_hva_to_gpa(vcpu,
					(u64)vcpu->arch.vcpu_state));
		return 0;
	}

	cute_p = user_area_alloc_locked(guest_area, 0,
			sizeof(*cute_p) * MAX_GUEST_CODES_UNITS,
			1 << E2K_ALIGN_CUT, 0);
	if (cute_p == NULL) {
		DebugKVM("could not allocate VCPU guest CUT\n");
		r = -ENOMEM;
		goto error;
	}
	memset(cute_p, 0, PAGE_SIZE);
	vcpu->arch.guest_cut = cute_p;
	if (IS_INVALID_GPA(kvm_vcpu_hva_to_gpa(vcpu, (u64)cute_p))) {
		pr_err("%s() : could not allocate GPA of VCPU guest CUT\n",
			__func__);
		r = -ENOMEM;
		goto error;
	}
	DebugKVM("VCPU #%d allocated state struct at %px, CUT at %px\n",
		vcpu->vcpu_id,
		(void *)kvm_vcpu_hva_to_gpa(vcpu, (u64)vcpu->arch.vcpu_state),
		(void *)kvm_vcpu_hva_to_gpa(vcpu, (u64)vcpu->arch.guest_cut));

	return 0;

error:
	if (kmap_vcpu_state != NULL) {
		unmap_user_area_to_vmalloc_range(guest_area, kmap_vcpu_state);
		vcpu->arch.kmap_vcpu_state = NULL;
	}
	if (vcpu_state != NULL) {
		user_area_free_chunk(guest_area, vcpu_state);
		vcpu->arch.vcpu_state = NULL;
	}
	if (cute_p != NULL) {
		user_area_free_chunk(guest_area, cute_p);
		vcpu->arch.guest_cut = NULL;
	}
	return r;
}
static int init_vcpu_state(struct kvm_vcpu *vcpu)
{
	int r;

	r = init_guest_boot_cut(vcpu);
	if (r) {
		DebugKVM("could not create guest CUT\n");
		return r;
	}
	r = init_guest_vcpu_state(vcpu);
	if (r) {
		DebugKVM("could not init VCPU state to start guest\n");
		return r;
	}
	return 0;
}

static void free_vcpu_state(struct kvm_vcpu *vcpu)
{
	user_area_t *guest_area;
	e2k_addr_t area_start;

	DebugKVMSH("%s (%d) started for VCPU #%d\n",
		current->comm, current->pid, vcpu->vcpu_id);
	if (vcpu->arch.vcpu_state != NULL) {
		area_start = (e2k_addr_t)vcpu->arch.vcpu_state;
		guest_area = kvm_find_memory_region(vcpu->kvm,
				-1, area_start, 0, guest_vram_mem_type);
		if (vcpu->arch.kmap_vcpu_state != NULL) {
			unmap_user_area_to_vmalloc_range(guest_area,
						vcpu->arch.kmap_vcpu_state);
			vcpu->arch.kmap_vcpu_state = NULL;
		}
		user_area_free_chunk(guest_area, vcpu->arch.vcpu_state);
		vcpu->arch.vcpu_state = NULL;
	} else if (vcpu->arch.kmap_vcpu_state != NULL) {
		unmap_user_area_to_vmalloc_range(NULL,
					vcpu->arch.kmap_vcpu_state);
		vcpu->arch.kmap_vcpu_state = NULL;
	}
	if (vcpu->arch.guest_cut != NULL) {
		area_start = (e2k_addr_t)vcpu->arch.guest_cut;
		guest_area = kvm_find_memory_region(vcpu->kvm,
				-1, area_start, 0, guest_vram_mem_type);
		user_area_free_chunk(guest_area, vcpu->arch.guest_cut);
		vcpu->arch.guest_cut = NULL;
	}

}
#else	/* ! CONFIG_KVM_PARAVIRTUALIZATION */
static int create_vcpu_state(struct kvm_vcpu *vcpu)
{
	VM_BUG_ON(vcpu->arch.is_pv);
	return 0;
}
static void free_vcpu_state(struct kvm_vcpu *vcpu)
{
	VM_BUG_ON(vcpu->arch.is_pv);
}
#endif	/* CONFIG_KVM_PARAVIRTUALIZATION */

/*
 * Functions to create all kernel backup hardware stacks(PS & PCS)
 * to support intercepts and hypercalls
 */
static inline void
define_backup_hw_stacks_sizes(bu_hw_stack_t *hypv_backup)
{
	SET_BACKUP_PS_SIZE(hypv_backup, HYPV_BACKUP_PS_SIZE);
	SET_BACKUP_PCS_SIZE(hypv_backup, HYPV_BACKUP_PCS_SIZE);
}
static inline void
backup_hw_stacks_init(bu_hw_stack_t *hypv_backup)
{
	e2k_psp_lo_t	psp_lo;
	e2k_psp_hi_t	psp_hi;
	e2k_pcsp_lo_t	pcsp_lo;
	e2k_pcsp_hi_t	pcsp_hi;

	psp_lo.PSP_lo_base = (e2k_addr_t)GET_PS_BASE(hypv_backup);
	psp_hi.PSP_hi_size = GET_BACKUP_PS_SIZE(hypv_backup);
	psp_hi.PSP_hi_ind = 0;
	hypv_backup->psp_lo = psp_lo;
	hypv_backup->psp_hi = psp_hi;

	pcsp_lo.PCSP_lo_base = (e2k_addr_t)GET_PCS_BASE(hypv_backup);
	pcsp_hi.PCSP_hi_size = GET_BACKUP_PCS_SIZE(hypv_backup);
	pcsp_hi.PCSP_hi_ind = 0;
	hypv_backup->pcsp_lo = pcsp_lo;
	hypv_backup->pcsp_hi = pcsp_hi;

	hypv_backup->users = 0;
}
static int
create_vcpu_backup_stacks(struct kvm_vcpu *vcpu)
{
	bu_hw_stack_t	*hypv_backup = &vcpu->arch.hypv_backup;
	e2k_size_t	ps_size;
	e2k_size_t	pcs_size;
	void		*psp_stk;
	void		*pcsp_stk;

	DebugKVMHV("started on task %s(%d) for VCPU #%d\n",
		current->comm, current->pid, vcpu->vcpu_id);

	/* Allocate memory for hypervisor backup hardware stacks */

	define_backup_hw_stacks_sizes(hypv_backup);
	ps_size = GET_BACKUP_PS_SIZE(hypv_backup);
	pcs_size = GET_BACKUP_PCS_SIZE(hypv_backup);

	psp_stk = kvzalloc(ps_size, GFP_KERNEL);
	if (psp_stk == NULL) {
		DebugKVMHV("could not allocate backup procedure stack\n");
		return -ENOMEM;
	}
	pcsp_stk = kvzalloc(pcs_size, GFP_KERNEL);
	if (pcsp_stk == NULL) {
		DebugKVMHV("could not allocate backup procedure chain stack\n");
		goto out_free_p_stack;
	}

	/* Create initial state of backup hardware stacks */

	SET_PS_BASE(hypv_backup, psp_stk);
	DebugKVMHV("allocated backup procedure stack %px, size 0x%lx\n",
		psp_stk, ps_size);

	SET_PCS_BASE(hypv_backup, pcsp_stk);
	DebugKVMHV("allocated backup procedure chain stack %px, size 0x%lx\n",
		pcsp_stk, pcs_size);

	return 0;

out_free_p_stack:
	kvfree(psp_stk);
	SET_PS_BASE(hypv_backup, NULL);

	return -ENOMEM;
}
static void
free_kernel_backup_stacks(bu_hw_stack_t *hypv_backup)
{
	void *psp_stk = GET_PS_BASE(hypv_backup);
	void *pcsp_stk = GET_PCS_BASE(hypv_backup);

	KVM_BUG_ON(hypv_backup->users != 0);

	if (psp_stk != NULL) {
		kvfree(psp_stk);
		SET_PS_BASE(hypv_backup, NULL);
	}
	if (pcsp_stk != NULL) {
		kvfree(pcsp_stk);
		SET_PCS_BASE(hypv_backup, NULL);
	}
}
static int
vcpu_backup_stacks_init(struct kvm_vcpu *vcpu)
{
	backup_hw_stacks_init(&vcpu->arch.hypv_backup);
	return 0;
}

/*
 * Functions to create guest VCPU boot-time data & hardware stacks(PS & PCS)
 * Such stacks for host has been created by boot loader.
 * Hypervisor does not use a boot loader and launch guest VCPUs directly,
 * so should prepare all VCPUs stacks into guest physical memory.
 */
static inline void
define_vcpu_boot_stacks_sizes(vcpu_boot_stack_t *boot_stacks)
{
	SET_VCPU_BOOT_CS_SIZE(boot_stacks, VIRT_KERNEL_C_STACK_SIZE);
	SET_VCPU_BOOT_PS_SIZE(boot_stacks, VIRT_KERNEL_PS_SIZE);
	SET_VCPU_BOOT_PCS_SIZE(boot_stacks, VIRT_KERNEL_PCS_SIZE);
}
static inline void
vcpu_all_boot_stacks_init(vcpu_boot_stack_t *boot_stacks)
{
	e2k_stacks_t	*boot_regs = &boot_stacks->regs.stacks;
	e2k_usd_lo_t	usd_lo;
	e2k_usd_hi_t	usd_hi;
	e2k_psp_lo_t	psp_lo;
	e2k_psp_hi_t	psp_hi;
	e2k_pcsp_lo_t	pcsp_lo;
	e2k_pcsp_hi_t	pcsp_hi;

	SET_VCPU_BOOT_CS_TOP(boot_stacks,
		(e2k_addr_t)GET_VCPU_BOOT_CS_BASE(boot_stacks) +
				GET_VCPU_BOOT_CS_SIZE(boot_stacks));
	boot_regs->top = GET_VCPU_BOOT_CS_TOP(boot_stacks);
	usd_lo.USD_lo_base = GET_VCPU_BOOT_CS_TOP(boot_stacks);
	usd_hi.USD_hi_size = GET_VCPU_BOOT_CS_SIZE(boot_stacks);
	boot_regs->usd_lo = usd_lo;
	boot_regs->usd_hi = usd_hi;

	psp_lo.PSP_lo_base = (e2k_addr_t)GET_VCPU_BOOT_PS_BASE(boot_stacks);
	psp_hi.PSP_hi_size = GET_VCPU_BOOT_PS_SIZE(boot_stacks);
	psp_hi.PSP_hi_ind = 0;
	boot_regs->psp_lo = psp_lo;
	boot_regs->psp_hi = psp_hi;

	pcsp_lo.PCSP_lo_base = (e2k_addr_t)GET_VCPU_BOOT_PCS_BASE(boot_stacks);
	pcsp_hi.PCSP_hi_size = GET_VCPU_BOOT_PCS_SIZE(boot_stacks);
	pcsp_hi.PCSP_hi_ind = 0;
	boot_regs->pcsp_lo = pcsp_lo;
	boot_regs->pcsp_hi = pcsp_hi;
}

/* create VCPU booting local data stack */
static int
alloc_vcpu_boot_c_stack(struct kvm *kvm, vcpu_boot_stack_t *boot_stacks)
{
	e2k_size_t stack_size;
	user_area_t *guest_area;
	void *data_stack;
	unsigned long stack_hva;
	gpa_t stack_gpa;
	long npages;
	int r;

	stack_size = GET_VCPU_BOOT_CS_SIZE(boot_stacks);

	DebugKVMHV("started to allocate stack size of 0x%lx\n",
		stack_size);
	npages = PAGE_ALIGN(stack_size) >> PAGE_SHIFT;
	guest_area = kvm_find_memory_region(kvm, -1, 0, npages << PAGE_SHIFT,
						guest_ram_mem_type);
	if (guest_area == NULL) {
		DebugKVMHV("guest memory regions is not created or empty\n");
		return -ENOMEM;
	}
	data_stack = user_area_alloc(guest_area, stack_size, 0);
	if (data_stack == NULL) {
		DebugKVMHV("could not allocate VCPU booting data stack\n");
		r = -ENOMEM;
		goto free_region;
	}
	boot_stacks->data_stack = data_stack;
	DebugKVMHV("VCPU booting data stack at user space %px\n", data_stack);

	stack_hva = (unsigned long)data_stack;
	stack_gpa = kvm_hva_to_gpa(kvm, stack_hva);
	if (IS_INVALID_GPA(stack_gpa)) {
		pr_err("%s(): could not convert user space address %px to GPA\n",
			__func__, data_stack);
		r = -EINVAL;
		goto free_region;
	}
	SET_VCPU_BOOT_CS_BASE(boot_stacks, (void *)stack_gpa);
	SET_VCPU_BOOT_CS_TOP(boot_stacks, stack_gpa + stack_size);
	DebugKVMHV("VCPU booting data stack at guest space from %px to %px\n",
		(void *)stack_gpa, (void *)(stack_gpa + stack_size));

	return 0;

free_region:
	if (data_stack != NULL) {
		user_area_free_chunk(guest_area, data_stack);
		boot_stacks->data_stack = NULL;
	}
	return r;
}

/* create VCPU booting local data stack */
static void *
alloc_vcpu_boot_hw_stack(struct kvm *kvm, e2k_size_t stack_size)
{
	user_area_t *guest_area;
	void *hw_stack;
	long npages;

	DebugKVMHV("started to allocate stack size of 0x%lx\n",
		stack_size);
	npages = PAGE_ALIGN(stack_size) >> PAGE_SHIFT;
	guest_area = kvm_find_memory_region(kvm, -1, 0, npages << PAGE_SHIFT,
						guest_ram_mem_type);
	if (guest_area == NULL) {
		DebugKVMHV("guest memory regions is not created or empty\n");
		return ERR_PTR(-EINVAL);
	}
	hw_stack = user_area_alloc_present(guest_area, 0, stack_size, 0, 0);
	if (hw_stack == NULL)
		return ERR_PTR(-ENOMEM);

	return hw_stack;
}
static void
free_vcpu_boot_p_stack(struct kvm *kvm, vcpu_boot_stack_t *boot_stacks)
{
	user_area_t *guest_area;
	e2k_addr_t area_start;

	if (boot_stacks->proc_stack == NULL)
		return;
	area_start = (e2k_addr_t)boot_stacks->proc_stack;
	guest_area = kvm_find_memory_region(kvm,
				-1, area_start, 0, guest_ram_mem_type);
	if (guest_area != NULL)
		user_area_free_chunk(guest_area, (void *)area_start);
	boot_stacks->proc_stack = NULL;
}
static void
free_vcpu_boot_pc_stack(struct kvm *kvm, vcpu_boot_stack_t *boot_stacks)
{
	user_area_t *guest_area;
	e2k_addr_t area_start;

	if (boot_stacks->chain_stack == NULL)
		return;
	area_start = (e2k_addr_t)boot_stacks->chain_stack;
	guest_area = kvm_find_memory_region(kvm,
				-1, area_start, 0, guest_ram_mem_type);
	if (guest_area != NULL)
		user_area_free_chunk(guest_area, (void *)area_start);
	boot_stacks->chain_stack = NULL;
}

/* create VCPU booting hardware procedure stack */
static int
alloc_vcpu_boot_p_stack(struct kvm *kvm, vcpu_boot_stack_t *boot_stacks)
{
	void *p_stack;
	e2k_size_t stack_size;
	unsigned long stack_hva;
	gpa_t stack_gpa;
	int r = 0;

	stack_size = GET_VCPU_BOOT_PS_SIZE(boot_stacks);
	p_stack = alloc_vcpu_boot_hw_stack(kvm, stack_size);
	if (IS_ERR(p_stack)) {
		DebugKVMHV("could not allocate VCPU booting procedure stack\n");
		return PTR_ERR(p_stack);
	}
	boot_stacks->proc_stack = p_stack;
	DebugKVMHV("VCPU booting procedure stack at user space %px\n", p_stack);

	stack_hva = (unsigned long)p_stack;
	stack_gpa = kvm_hva_to_gpa(kvm, stack_hva);
	if (IS_INVALID_GPA(stack_gpa)) {
		pr_err("%s(): could not convert user space address %px to GPA\n",
			__func__, p_stack);
		r = -EINVAL;
		goto free_region;
	}
	SET_VCPU_BOOT_PS_BASE(boot_stacks, (void *)stack_gpa);
	DebugKVMHV("VCPU booting procedure stack at guest space "
		"from %px to %px\n",
		(void *)stack_gpa, (void *)(stack_gpa + stack_size));

	return 0;

free_region:
	free_vcpu_boot_p_stack(kvm, boot_stacks);
	return r;
}

/* create VCPU booting hardware procedure chain stack */
static int
alloc_vcpu_boot_pc_stack(struct kvm *kvm, vcpu_boot_stack_t *boot_stacks)
{
	void *pc_stack;
	e2k_size_t stack_size;
	unsigned long stack_hva;
	gpa_t stack_gpa;
	int r = 0;

	stack_size = GET_VCPU_BOOT_PCS_SIZE(boot_stacks);
	pc_stack = alloc_vcpu_boot_hw_stack(kvm, stack_size);
	if (IS_ERR(pc_stack)) {
		DebugKVMHV("could not allocate VCPU booting chain stack\n");
		return PTR_ERR(pc_stack);
	}
	boot_stacks->chain_stack = pc_stack;
	DebugKVMHV("VCPU booting chain stack at user space %px\n", pc_stack);

	stack_hva = (unsigned long)pc_stack;
	stack_gpa = kvm_hva_to_gpa(kvm, stack_hva);
	if (IS_INVALID_GPA(stack_gpa)) {
		pr_err("%s(): could not convert user space address %px to GPA\n",
			__func__, pc_stack);
		r = -EINVAL;
		goto free_region;
	}
	SET_VCPU_BOOT_PCS_BASE(boot_stacks, (void *)stack_gpa);
	DebugKVMHV("VCPU booting procedure chain stack at guest space "
		"from %px to %px\n",
		(void *)stack_gpa, (void *)(stack_gpa + stack_size));

	return 0;

free_region:
	free_vcpu_boot_pc_stack(kvm, boot_stacks);
	return r;
}

static void
free_vcpu_boot_c_stack(struct kvm *kvm, vcpu_boot_stack_t *boot_stacks)
{
	user_area_t *guest_area;
	e2k_addr_t area_start;

	if (boot_stacks->data_stack == NULL)
		return;
	area_start = (e2k_addr_t)boot_stacks->data_stack;
	guest_area = kvm_find_memory_region(kvm,
				-1, area_start, 0, guest_ram_mem_type);
	if (guest_area != NULL)
		user_area_free_chunk(guest_area, (void *)area_start);
	boot_stacks->data_stack = NULL;
}
static void
free_vcpu_boot_stacks(struct kvm_vcpu *vcpu)
{
	vcpu_boot_stack_t *boot_stacks = &vcpu->arch.boot_stacks;

	free_vcpu_boot_c_stack(vcpu->kvm, boot_stacks);
	free_vcpu_boot_p_stack(vcpu->kvm, boot_stacks);
	free_vcpu_boot_pc_stack(vcpu->kvm, boot_stacks);
}

static int
create_vcpu_boot_stacks(struct kvm_vcpu *vcpu)
{
	vcpu_boot_stack_t *boot_stacks = &vcpu->arch.boot_stacks;
	int r;

	DebugKVMHV("started on task %s(%d) for VCPU #%d\n",
		current->comm, current->pid, vcpu->vcpu_id);

	/* FIXME: stacks now allocated in the guest RAM, but addresses */
	/* is virtual/ because of RAM mapped to virtual space */
	/* It need implement allocation with return guest physical address */

	define_vcpu_boot_stacks_sizes(boot_stacks);

	r = alloc_vcpu_boot_c_stack(vcpu->kvm, boot_stacks);
	if (r != 0)
		return r;

	r = alloc_vcpu_boot_p_stack(vcpu->kvm, boot_stacks);
	if (r != 0)
		goto out_free_c_stack;

	r = alloc_vcpu_boot_pc_stack(vcpu->kvm, boot_stacks);
	if (r != 0)
		goto out_free_p_stack;

	/* create VCPU booting stacks */
	vcpu_all_boot_stacks_init(boot_stacks);

	return 0;

out_free_c_stack:
	free_vcpu_boot_c_stack(vcpu->kvm, boot_stacks);
out_free_p_stack:
	free_vcpu_boot_p_stack(vcpu->kvm, boot_stacks);

	return r;
}
static int
vcpu_boot_stacks_init(struct kvm_vcpu *vcpu)
{
	vcpu_all_boot_stacks_init(&vcpu->arch.boot_stacks);
	return 0;
}

static int create_vcpu_host_context(struct kvm_vcpu *vcpu)
{
	kvm_host_context_t *host_ctxt = &vcpu->arch.host_ctxt;
	unsigned long *stack;
	unsigned long addr;

	DebugKVMHV("started on task %s(%d) for VCPU #%d\n",
		current->comm, current->pid, vcpu->vcpu_id);

	KVM_BUG_ON(vcpu->arch.is_hv || !vcpu->arch.is_pv);

	memset(host_ctxt, 0, sizeof(*host_ctxt));

	/*
	 * Calculate kernel stacks registers
	 */
	stack = __alloc_thread_stack_node(numa_node_id());
	if (!stack) {
		pr_err("%s(): could not allocate VCPU #%d host stacks\n",
			__func__, vcpu->vcpu_id);
		return -ENOMEM;
	}
	host_ctxt->stack = stack;
	addr = (unsigned long)stack;
	host_ctxt->pt_regs = NULL;
	host_ctxt->upsr = E2K_USER_INITIAL_UPSR;
	host_ctxt->k_psp_lo.PSP_lo_half = 0;
	host_ctxt->k_psp_lo.PSP_lo_base = addr + KERNEL_P_STACK_OFFSET;
	host_ctxt->k_psp_hi.PSP_hi_half = 0;
	host_ctxt->k_psp_hi.PSP_hi_size = KERNEL_P_STACK_SIZE;
	host_ctxt->k_pcsp_lo.PCSP_lo_half = 0;
	host_ctxt->k_pcsp_lo.PCSP_lo_base = addr + KERNEL_PC_STACK_OFFSET;
	host_ctxt->k_pcsp_hi.PCSP_hi_half = 0;
	host_ctxt->k_pcsp_hi.PCSP_hi_size = KERNEL_PC_STACK_SIZE;
	host_ctxt->k_usd_lo.USD_lo_half = 0;
	host_ctxt->k_usd_lo.USD_lo_base = addr + KERNEL_C_STACK_OFFSET +
						 KERNEL_C_STACK_SIZE;
	host_ctxt->k_usd_hi.USD_hi_half = 0;
	host_ctxt->k_usd_hi.USD_hi_size = KERNEL_C_STACK_SIZE;
	host_ctxt->k_sbr.SBR_reg = host_ctxt->k_usd_lo.USD_lo_base;

	host_ctxt->osem = guest_trap_init();

	host_ctxt->signal.stack.used = 0;
	atomic_set(&host_ctxt->signal.traps_num, 0);
	atomic_set(&host_ctxt->signal.in_work, 0);
	atomic_set(&host_ctxt->signal.syscall_num, 0);
	atomic_set(&host_ctxt->signal.in_syscall, 0);

	return 0;
}
static void destroy_vcpu_host_context(struct kvm_vcpu *vcpu)
{
	kvm_host_context_t *host_ctxt;

	if (likely(vcpu->arch.is_hv || !vcpu->arch.is_pv))
		return;

	host_ctxt = &vcpu->arch.host_ctxt;
	if (host_ctxt->stack != NULL) {
		__free_thread_stack(host_ctxt->stack);
		host_ctxt->stack = NULL;
	}
}

static int kvm_arch_any_vcpu_init(struct kvm_vcpu *vcpu)
{
	int r;

	DebugKVM("started for CPU %d\n", vcpu->vcpu_id);

	vcpu->arch.exit_reason = -1;

	/* create shared with guest kernel structure to pass */
	/* some useful info about host and hypervisor */
	if (vcpu->kvm->arch.host_info == NULL) {
		r = kvm_create_host_info(vcpu->kvm);
		if (r != 0)
			return r;
	}

	/* create VCPU structures to emulate hardware state */
	r = create_vcpu_state(vcpu);
	if (r != 0)
		goto free_host_info;

	return 0;

free_host_info:
	kvm_free_host_info(vcpu->kvm);
	return r;
}
static void kvm_arch_any_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	DebugKVM("started for VCPU #%d\n", vcpu->vcpu_id);

	kvm_free_host_info(vcpu->kvm);
	free_vcpu_state(vcpu);
}
static int kvm_arch_any_vcpu_setup(struct kvm_vcpu *vcpu)
{
	int r;

	DebugKVM("started for CPU %d\n", vcpu->vcpu_id);

	/* init VCPU structures to emulate hardware state */
	r = init_vcpu_state(vcpu);
	if (r != 0)
		return r;

	return 0;
}

#ifdef	CONFIG_KVM_HW_VIRTUALIZATION

static int kvm_arch_hv_vcpu_init(struct kvm_vcpu *vcpu)
{
	int r;

	if (vcpu->kvm->arch.vm_type != KVM_E2K_HV_VM_TYPE &&
			vcpu->kvm->arch.vm_type != KVM_E2K_HW_PV_VM_TYPE)
		return 0;

	DebugKVM("started for VCPU #%d\n", vcpu->vcpu_id);

	vcpu->arch.is_hv = true;

	if (vcpu->kvm->arch.vm_type == KVM_E2K_HW_PV_VM_TYPE) {
		/* paravirtualization support need create and enable */
		r = kvm_arch_pv_vcpu_init(vcpu);
		if (r != 0)
			goto failed;
	}

	return 0;

failed:
	return r;
}
static void kvm_arch_hv_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	if (!vcpu->arch.is_hv)
		return;

	DebugKVM("started for VCPU #%d\n", vcpu->vcpu_id);
	if (vcpu->arch.is_pv)
		/* paravirtualization support need free and disable */
		kvm_arch_pv_vcpu_uninit(vcpu);

	vcpu->arch.is_hv = false;
}

static int kvm_arch_hv_vcpu_setup(struct kvm_vcpu *vcpu)
{
	int r;

	if (!vcpu->arch.is_hv)
		return 0;

	DebugKVM("started for VCPU #%d\n", vcpu->vcpu_id);

	if (vcpu->arch.is_pv) {
		/* paravirtualization support need create and enable */
		r = kvm_arch_pv_vcpu_setup(vcpu);
		if (r != 0)
			return r;
	}

	return 0;
}
#else	/* ! CONFIG_KVM_HW_VIRTUALIZATION */
static int kvm_arch_hv_vcpu_init(struct kvm_vcpu *vcpu)
{
	VM_BUG_ON(vcpu->arch.is_hv);
	return 0;
}
static void kvm_arch_hv_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	VM_BUG_ON(vcpu->arch.is_hv);
}
static int kvm_arch_hv_vcpu_setup(struct kvm_vcpu *vcpu)
{
	VM_BUG_ON(vcpu->arch.is_hv);
	return 0;
}
#endif	/* CONFIG_KVM_HW_VIRTUALIZATION */

#ifdef	CONFIG_KVM_PARAVIRTUALIZATION
static int kvm_arch_pv_vcpu_init(struct kvm_vcpu *vcpu)
{
	if (vcpu->kvm->arch.vm_type != KVM_E2K_SV_VM_TYPE &&
			vcpu->kvm->arch.vm_type != KVM_E2K_SW_PV_VM_TYPE &&
			vcpu->kvm->arch.vm_type != KVM_E2K_HW_PV_VM_TYPE)
		return 0;

	DebugKVM("started for CPU %d\n", vcpu->vcpu_id);

	vcpu->arch.is_pv = true;

	return 0;
}
static void kvm_arch_pv_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	if (!vcpu->arch.is_pv)
		return;

	DebugKVM("started for VCPU #%d\n", vcpu->vcpu_id);

	vcpu->arch.is_pv = false;
}
static int kvm_arch_pv_vcpu_setup(struct kvm_vcpu *vcpu)
{
	if (!vcpu->arch.is_pv)
		return 0;

	DebugKVM("started for CPU %d\n", vcpu->vcpu_id);

	return 0;
}
#else	/* ! CONFIG_KVM_PARAVIRTUALIZATION */
static int kvm_arch_pv_vcpu_init(struct kvm_vcpu *vcpu)
{
	VM_BUG_ON(vcpu->arch.is_pv);
	return 0;
}
static void kvm_arch_pv_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	VM_BUG_ON(vcpu->arch.is_pv);
}
static int kvm_arch_pv_vcpu_setup(struct kvm_vcpu *vcpu)
{
	VM_BUG_ON(vcpu->arch.is_pv);
	return 0;
}
#endif	/* CONFIG_KVM_PARAVIRTUALIZATION */

static void kvm_arch_vcpu_ctxt_init(struct kvm_vcpu *vcpu)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;

	memset(&vcpu->arch.sw_ctxt, 0, sizeof(vcpu->arch.sw_ctxt));
	memset(&vcpu->arch.hw_ctxt, 0, sizeof(vcpu->arch.hw_ctxt));

	sw_ctxt->osem = guest_trap_init();

	if (vcpu->arch.is_hv) {
		guest_hw_stack_t *boot_regs = &vcpu->arch.boot_stacks.regs;

		/* set to initial state some fields */
		sw_ctxt->saved.valid = false;

		/* setup guest boot kernel local data stack */
		sw_ctxt->usd_lo = boot_regs->stacks.usd_lo;
		sw_ctxt->usd_hi = boot_regs->stacks.usd_hi;
		sw_ctxt->sbr.SBR_reg = boot_regs->stacks.top;

		GET_FPU_DEFAULTS(sw_ctxt->fpsr, sw_ctxt->fpcr, sw_ctxt->pfpfr);

		AS(sw_ctxt->dibcr).gm = 1;
		AS(sw_ctxt->ddbcr).gm = 1;
	}
}

static void kvm_arch_vcpu_ctxt_uninit(struct kvm_vcpu *vcpu)
{
	memset(&vcpu->arch.sw_ctxt, 0, sizeof(vcpu->arch.sw_ctxt));
	memset(&vcpu->arch.hw_ctxt, 0, sizeof(vcpu->arch.hw_ctxt));
}

int kvm_vm_ioctl_check_extension(struct kvm *kvm, int ext)
{

	int r;

	DebugKVM("started for ext %d\n", ext);
	switch (ext) {
	case KVM_CAP_IRQCHIP:
		DebugKVM("ioctl is KVM_CAP_IRQCHIP\n");
		r = 1;
		break;
	case KVM_CAP_MP_STATE:
		DebugKVM("ioctl is KVM_CAP_MP_STATE\n");
		r = 1;
		break;
	case KVM_CAP_MAX_VCPUS:
		r = KVM_MAX_VCPUS;
		break;
	case KVM_CAP_NR_MEMSLOTS:
		r = KVM_USER_MEM_SLOTS;
		break;
	case KVM_CAP_IRQ_INJECT_STATUS:
		DebugKVM("ioctl is KVM_CAP_IRQ_INJECT_STATUS\n");
		r = 0;
		break;
	case KVM_CAP_COALESCED_MMIO:
		DebugKVM("ioctl is KVM_CAP_COALESCED_MMIO\n");
		r = 0;
		break;
	case KVM_CAP_SYNC_MMU:
		DebugKVM("ioctl is KVM_CAP_SYNC_MMU\n");
		r = 1;
		break;
	case KVM_CAP_E2K_SV_VM:
		DebugKVM("ioctl is KVM_CAP_E2K_SV_VM\n");
		r = kvm_is_sv_vm_available();
		break;
	case KVM_CAP_E2K_SW_PV_VM:
		DebugKVM("ioctl is KVM_CAP_E2K_SW_PV_VM\n");
		r = kvm_is_sw_pv_vm_available();
		break;
	case KVM_CAP_E2K_HV_VM:
		DebugKVM("ioctl is KVM_CAP_E2K_HV_VM\n");
		r = kvm_is_hv_vm_available();
		break;
	case KVM_CAP_E2K_TDP_MMU:
		DebugKVM("ioctl is KVM_CAP_E2K_TDP_MMU\n");
		r = kvm_is_tdp_enable(kvm);
		break;
	case KVM_CAP_E2K_SHADOW_PT_MMU:
		DebugKVM("ioctl is KVM_CAP_E2K_SHADOW_PT_MMU\n");
		if (kvm->arch.is_hv) {
			r = true;
		} else {
			r = kvm_is_shadow_pt_enable(kvm);
		}
		break;
	case KVM_CAP_ENABLE_CAP_VM:
		r = 1;
		break;
	default:
		DebugKVM("ioctl is unsupported\n");
		r = 0;
	}
	DebugKVM("completed with value %d\n", r);
	return r;

}

static int handle_vm_error(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	kvm_run->exit_reason = KVM_EXIT_UNKNOWN;
	kvm_run->hw.hardware_exit_reason = 1;
	return 0;
}

static int handle_mmio(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	struct kvm_mmio_fragment *frag;

	DebugKVMIO("started for VCPU #%d run area at %px\n",
		vcpu->vcpu_id, kvm_run);

	if (vcpu->mmio_nr_fragments == 0) {
		DebugKVMIO("VCPU #%d nothing to do: none mmio fragments\n",
			vcpu->vcpu_id);
		return -EINVAL;
	} else if (vcpu->mmio_nr_fragments > 1) {
		DebugKVMIO("VCPU #%d too many mmio fragments (%d > 1)\n",
			vcpu->vcpu_id, vcpu->mmio_nr_fragments);
		return -EINVAL;
	}
	frag = &vcpu->mmio_fragments[0];
	kvm_run->mmio.phys_addr = frag->gpa;
	kvm_run->mmio.len = frag->len;
	kvm_run->mmio.is_write = vcpu->mmio_is_write;

	if (vcpu->mmio_is_write)
		memcpy(kvm_run->mmio.data, frag->data, frag->len);
	kvm_run->exit_reason = KVM_EXIT_MMIO;

	DebugKVMIO("returns to host user: phys addr 0x%llx size %d to %s\n",
		kvm_run->mmio.phys_addr, kvm_run->mmio.len,
		(kvm_run->mmio.is_write) ? "write" : "read");
	return 0;
}

static inline unsigned long get_ioport_data_offset(struct kvm_run *kvm_run)
{
	unsigned long data_offset;

	data_offset = ALIGN_TO_SIZE(sizeof(*kvm_run), 1 * 1024);
	if (data_offset >= PAGE_SIZE) {
		panic("get_ioport_data_offset() KVM run area size 0x%lx, "
			"IO data area offset 0x%lx > PAGE SIZE\n",
			sizeof(*kvm_run), data_offset);
	} else if (sizeof(*kvm_run) > data_offset) {
		panic("get_ioport_data_offset() KVM run area size 0x%lx > "
			"IO data area offset 0x%lx\n",
			sizeof(*kvm_run), data_offset);
	}
	return data_offset;
}
static inline unsigned long get_ioport_data_size(struct kvm_run *kvm_run)
{
	unsigned long data_offset;

	data_offset = get_ioport_data_offset(kvm_run);
	return PAGE_SIZE - data_offset;
}
static inline void *get_ioport_data_pointer(struct kvm_run *kvm_run)
{
	return (void *)(((void *)kvm_run) + get_ioport_data_offset(kvm_run));
}

static int handle_ioport(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	DebugKVMIO("started for VCPU #%d run area at %px\n",
		vcpu->vcpu_id, kvm_run);
	kvm_run->io.port = vcpu->arch.ioport.port;
	kvm_run->io.data_offset = get_ioport_data_offset(kvm_run);
	kvm_run->io.size = vcpu->arch.ioport.size;
	kvm_run->io.count = vcpu->arch.ioport.count;
	kvm_run->io.direction =
		(vcpu->arch.ioport.is_out) ? KVM_EXIT_IO_OUT : KVM_EXIT_IO_IN;

	if (vcpu->arch.ioport.is_out) {
		void *data = get_ioport_data_pointer(kvm_run);
		if (vcpu->arch.ioport.string) {
			memcpy(data, vcpu->arch.ioport_data,
				vcpu->arch.ioport.size *
					vcpu->arch.ioport.count);
		} else {
			memcpy(data, &vcpu->arch.ioport.data,
					vcpu->arch.ioport.size);
		}
	}
	kvm_run->exit_reason = KVM_EXIT_IO;

	DebugKVMIO("returns to host user: port 0x%x size %d to %s\n",
		kvm_run->io.port, kvm_run->io.size,
		(kvm_run->io.direction == KVM_EXIT_IO_OUT) ? "write" : "read");
	return 0;
}

static int handle_notify_io(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	kvm_run->exit_reason = KVM_EXIT_E2K_NOTIFY_IO;
	kvm_run->notifier.io = vcpu->arch.notifier_io;
	return 0;
}

static int handle_shutdown(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	DebugKVMSH("started, shutdown type %d\n", vcpu->run->exit_reason);

	kvm_run->exit_reason = vcpu->run->exit_reason;

	raw_spin_lock(&vcpu->arch.exit_reqs_lock);
	vcpu->arch.halted = true;
	raw_spin_unlock(&vcpu->arch.exit_reqs_lock);

	/* FIXME: VCPU request queue is not more used, but need delete all
	 * functionality related to spliting VCPU support into two threads
	if (!vcpu->arch.is_hv) {
		complete(&vcpu->arch.exit_req_done);
		put_exit_req_vcpu(vcpu);
	}
	 */
	if (vcpu->run->exit_reason != KVM_EXIT_E2K_RESTART) {
		vcpu->kvm->arch.halted = true;
	} else if (kvm_run->exit_reason == KVM_EXIT_E2K_RESTART) {
		vcpu->kvm->arch.reboot = true;
	}
	smp_mb();	/* to sure the flag is set */
	/* wake up other host VCPUs to complete guest VCPUs threads */
	kvm_wake_up_all_other_vcpu_host(vcpu);
	return 0;
}

static int (*kvm_guest_exit_handlers[])(struct kvm_vcpu *vcpu,
		struct kvm_run *kvm_run) = {
	[EXIT_REASON_VM_PANIC]		= handle_vm_error,
	[EXIT_REASON_MMIO_REQ]		= handle_mmio,
	[EXIT_REASON_IOPORT_REQ]	= handle_ioport,
	[EXIT_NOTIFY_IO]		= handle_notify_io,
	[EXIT_SHUTDOWN]			= handle_shutdown,
};

static const int kvm_guest_max_exit_handlers =
		sizeof(kvm_guest_exit_handlers) /
			sizeof(*kvm_guest_exit_handlers);

static inline uint32_t kvm_get_exit_reason(struct kvm_vcpu *vcpu)
{
	u32 exit_reason;
	if (vcpu->arch.exit_shutdown_terminate) {
		vcpu->arch.exit_reason = EXIT_SHUTDOWN;
		if (vcpu->arch.exit_shutdown_terminate == KVM_EXIT_E2K_RESTART)
			vcpu->run->exit_reason = KVM_EXIT_E2K_RESTART;
		else
			vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
	}
	exit_reason = vcpu->arch.exit_reason;
	vcpu->arch.exit_reason = -1;
	return exit_reason;
}

/*
 * The guest has exited.  See if we can fix it or if we need userspace
 * assistance.
 */
static int kvm_handle_exit(struct kvm_run *kvm_run, struct kvm_vcpu *vcpu)
{
	u32 exit_reason = kvm_get_exit_reason(vcpu);
	vcpu->arch.last_exit = exit_reason;

	DebugKVMRUN("started on VCPU %d on exit reason %d\n",
		vcpu->vcpu_id, exit_reason);
	if (exit_reason < kvm_guest_max_exit_handlers
			&& kvm_guest_exit_handlers[exit_reason]) {
		return kvm_guest_exit_handlers[exit_reason](vcpu, kvm_run);
	} else if (exit_reason == -1) {
		/* exit reason was not set, try run VCPU again */
		return 1;
	} else {
		kvm_run->exit_reason = KVM_EXIT_UNKNOWN;
		kvm_run->hw.hardware_exit_reason = exit_reason;
		DebugKVM("exit reason %d is unknown\n",
			exit_reason);
	}
	return 0;
}

static int __vcpu_run(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	int r;

	DebugKVMRUN("started on VCPU %d CPU %d\n",
		vcpu->vcpu_id, vcpu->cpu);

	/*
	 * down_read() may sleep and return with interrupts enabled
	 */
	mutex_lock(&vcpu->kvm->slots_lock);

again:
	if (unlikely(signal_pending(current))) {
		r = -EINTR;
		kvm_run->exit_reason = KVM_EXIT_INTR;
		++vcpu->stat.signal_exits;
		goto out;
	}
	if (unlikely(vcpu->arch.halted)) {
		r = -EINVAL;
		kvm_run->exit_reason = KVM_EXIT_SHUTDOWN;
		goto out;
	}
	if (unlikely(vcpu->kvm->arch.halted))
		/* VM halted, terminate all VCPUs */
		goto out;

	preempt_disable();
	local_irq_disable();

	clear_bit(KVM_REQ_KICK, (void *) &vcpu->requests);

	mutex_unlock(&vcpu->kvm->slots_lock);

	/*
	 * Transition to the guest
	 */
	if (likely(vcpu->arch.is_hv)) {
		r = startup_hv_vcpu(vcpu);
		KVM_BUG_ON(r == 0);
	} else if (!vcpu->arch.from_pv_intc) {
		launch_pv_vcpu(vcpu, FULL_CONTEXT_SWITCH | USD_CONTEXT_SWITCH);
	} else {
		return_to_pv_vcpu_intc(vcpu);
	}

	local_irq_enable();
	preempt_enable();

	mutex_lock(&vcpu->kvm->slots_lock);

	r = kvm_handle_exit(kvm_run, vcpu);

	if (r > 0) {
		if (!need_resched())
			goto again;
	}

out:
	mutex_unlock(&vcpu->kvm->slots_lock);
	if (unlikely(vcpu->kvm->arch.halted))
		goto vm_complete;
	if (r > 0) {
		cond_resched();
		mutex_lock(&vcpu->kvm->slots_lock);
		goto again;
	}

	kvm_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_QEMU);

	return r;

vm_complete:
	kvm_run->exit_reason = KVM_EXIT_SHUTDOWN;
	return 0;
}

int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	int r;

	DebugKVMRUN("started\n");

	vcpu_load(vcpu);

	kvm_sigset_activate(vcpu);

	if (unlikely(vcpu->arch.mp_state == KVM_MP_STATE_UNINITIALIZED)) {
		if (kvm_run->immediate_exit) {
			r = -EINTR;
			goto out;
		}
		kvm_vcpu_block(vcpu);
		kvm_clear_request(KVM_REQ_UNHALT, vcpu);
		r = -EAGAIN;
		if (signal_pending(current)) {
			r = -EINTR;
			vcpu->run->exit_reason = KVM_EXIT_INTR;
			++vcpu->stat.signal_exits;
		}
		goto out;
	}

	if (vcpu->arch.ioport.needed) {
		if (!vcpu->arch.ioport.is_out) {
			void *data = get_ioport_data_pointer(kvm_run);
			if (vcpu->arch.ioport.string) {
				memcpy(vcpu->arch.ioport_data, data,
						vcpu->arch.ioport.size *
						vcpu->arch.ioport.count);
			} else {
				memcpy(&vcpu->arch.ioport.data, data,
						vcpu->arch.ioport.size);
			}
		}
		vcpu->arch.ioport.completed = 1;
		vcpu->arch.ioport.needed = 0;
		r = kvm_complete_guest_ioport_request(vcpu);
		if (r) {
			pr_err("%s(): IO PORT request completion failed, "
				"error %d\n",
				__func__, r);
		}
	}

	if (vcpu->mmio_needed) {
		struct kvm_mmio_fragment *frag;
		unsigned len;

		/* Complete previous fragment */
		if (vcpu->mmio_cur_fragment != 0) {
			pr_err("%s(): invalid number of current fragments "
				"(%d != 0)\n",
				__func__,  vcpu->mmio_cur_fragment);
		}
		frag = &vcpu->mmio_fragments[0];
		len = min(8u, frag->len);
		if (!vcpu->mmio_is_write)
			memcpy(frag->data, kvm_run->mmio.data, len);
		vcpu->mmio_read_completed = 1;
		vcpu->mmio_needed = 0;
		r = kvm_complete_guest_mmio_request(vcpu);
		if (r) {
			pr_err("%s(): MMIO request completion failed, "
				"error %d\n",
				__func__, r);
		}
	}
	if (kvm_run->immediate_exit) {
		r = -EINTR;
	} else {
		r = __vcpu_run(vcpu, kvm_run);
	}
out:
	kvm_sigset_deactivate(vcpu);

	if (kvm_run->exit_reason == KVM_EXIT_E2K_RESTART) {
		vcpu->kvm->arch.reboot = true;
	}
	vcpu_put(vcpu);
	return r;
}

/*
 * Set a new alias region.  Aliases map a portion of virtual memory into
 * another portion.  This is useful for guest kernel image loading to
 * own virtual addresses
 */
static int kvm_vm_ioctl_set_memory_alias(struct kvm *kvm,
					 kvm_memory_alias_t __user *alias)
{
	int r, n;
	kvm_memory_alias_t guest_alias;
	struct kvm_mem_alias *p;
	struct kvm_memslots *slots = kvm_memslots(kvm);
	struct kvm_memory_slot *memslot;
	int slot;

	if (kvm_is_shadow_pt_enable(kvm)) {
		pr_err("%s(): support of guest MMU based on shadow PT "
			"so aliasing can be deleted for guest VM\n",
			__func__);
		return -ENOTTY;
	}
	if (copy_from_user(&guest_alias, alias, sizeof(kvm_memory_alias_t)))
		return -EFAULT;
	DebugKVM("started for aliasing from 0x%llx size 0x%llx to 0x%llx\n",
		guest_alias.guest_alias_addr, guest_alias.memory_size,
		guest_alias.target_addr);
	r = -EINVAL;
	/* General sanity checks */
	if (guest_alias.memory_size & (PAGE_SIZE - 1))
		goto out;
	if (guest_alias.guest_alias_addr & (PAGE_SIZE - 1))
		goto out;
	if (guest_alias.slot >= KVM_ALIAS_SLOTS)
		goto out;
	if (guest_alias.guest_alias_addr + guest_alias.memory_size <
						guest_alias.guest_alias_addr)
		goto out;
	if (guest_alias.target_addr + guest_alias.memory_size <
						guest_alias.target_addr)
		goto out;

	mutex_lock(&kvm->slots_lock);
	slot = kvm_gva_to_memslot_unaliased(kvm, guest_alias.target_addr);
	if (slot < 0) {
		mutex_unlock(&kvm->slots_lock);
		goto out;
	}
	memslot = id_to_memslot(slots, slot);
	spin_lock(&kvm->mmu_lock);

	p = &kvm->arch.aliases[guest_alias.slot];
	p->alias_start = guest_alias.guest_alias_addr;
	p->target_start = guest_alias.target_addr;
	p->alias_base_gfn =  memslot->base_gfn + ((guest_alias.target_addr -
				memslot->userspace_addr) >> PAGE_SHIFT);
	p->npages = guest_alias.memory_size >> PAGE_SHIFT;
	p->target_slot = slot;

	for (n = KVM_ALIAS_SLOTS; n > 0; --n)
		if (kvm->arch.aliases[n - 1].npages)
			break;
	kvm->arch.naliases = n;

	spin_unlock(&kvm->mmu_lock);

	mutex_unlock(&kvm->slots_lock);
	DebugKVM("created aliasing from 0x%lx pages 0x%lx to 0x%lx base gfn "
		"0x%llx at slot %d\n",
		p->alias_start, p->npages, p->target_start, p->alias_base_gfn,
		slot);

	return 0;

out:
	DebugKVM("creation failed: error %d\n", r);
	return r;
}

/*
 * Set a new shadow (alias) an area of host kernel virtual into guest kernel
 * virtual space
 */
static int kvm_set_shadow_area(struct kvm *kvm,
			kvm_kernel_area_shadow_t *guest_shadow)
{
	int r;
	struct kvm_kernel_shadow *p;
	unsigned long kernel_start;
	unsigned long kernel_end;
	unsigned long shadow_addr;
	unsigned long area_size;
	int alias_slot;

	DebugKVM("started for shadowing kernel area from 0x%llx size 0x%llx "
		"to guest 0x%llx, slot %d\n",
		guest_shadow->kernel_addr, guest_shadow->area_size,
		guest_shadow->guest_shadow_addr, guest_shadow->slot);
	r = -EINVAL;
	/* General sanity checks */
	kernel_start = guest_shadow->kernel_addr;
	area_size = PAGE_ALIGN_DOWN(guest_shadow->area_size);
	if (kernel_start & ~PAGE_MASK)
		goto out;
	if (guest_shadow->slot >= KVM_SHADOW_SLOTS)
		goto out;
	kernel_end = kernel_start + area_size;
	if (kernel_end < kernel_start)
		goto out;
	if ((kernel_start & PGDIR_MASK) != ((kernel_end - 1) & PGDIR_MASK)) {
		printk(KERN_ERR " kvm_vm_ioctl_set_shadow_area() multiline "
			"shadow is not supported\n");
		goto out;
	}
	shadow_addr = guest_shadow->guest_shadow_addr;
	if ((kernel_start & ~PGDIR_MASK) != (shadow_addr & ~PGDIR_MASK)) {
		printk(KERN_ERR " kvm_vm_ioctl_set_shadow_area() only PGD "
			"level shadow is supported\n");
		goto out;
	}
	mutex_lock(&kvm->slots_lock);
	if (find_shadow_intersection(kvm, kernel_start, shadow_addr,
					area_size)) {
		mutex_unlock(&kvm->slots_lock);
		goto out;
	}
	alias_slot = gva_to_alias_slot(kvm, shadow_addr);
	if (alias_slot < 0) {
		mutex_unlock(&kvm->slots_lock);
		DebugKVM("Could not find alias slot for shadow 0x%lx\n",
			shadow_addr);
		goto out;
	}

	spin_lock(&kvm->mmu_lock);

	p = &kvm->arch.shadows[guest_shadow->slot];
	p->kernel_start = kernel_start;
	p->shadow_start = shadow_addr;
	p->area_size = area_size;
	p->alias_slot = alias_slot;
	kvm->arch.nshadows++;

	spin_unlock(&kvm->mmu_lock);

	mutex_unlock(&kvm->slots_lock);
	DebugKVM("created shadowing at slot %d to alias addr at slot %d\n",
		guest_shadow->slot, alias_slot);

	return 0;

out:
	DebugKVM("setting failed: error %d\n", r);
	return r;
}

/*
 * Create shadow alias into guest virtual space to load guest kernel image
 * into own virtual space instead of host kernel image addresses and later
 * it needs switch only one host kernel pgd entry into host page table
 * to shadow guest pgd entry to enable guest kernel image running on the
 * same addresses as host kernel
 */
static int kvm_vm_ioctl_set_kernel_image_shadow(struct kvm *kvm,
				kvm_kernel_area_shadow_t __user *shadow)
{
	kvm_kernel_area_shadow_t guest_shadow;
	e2k_addr_t kernel_base;
	thread_info_t *ti;
	int r;

	if (copy_from_user(&guest_shadow, shadow,
				sizeof(kvm_kernel_area_shadow_t)))
		return -EFAULT;
	DebugKVM("started for shadowing kernel image from 0x%llx size 0x%llx "
		"to guest 0x%llx\n",
		guest_shadow.kernel_addr, guest_shadow.area_size,
		guest_shadow.guest_shadow_addr);
	kernel_base = guest_shadow.kernel_addr;
	if (kernel_base >= PAGE_ALIGN_UP(KERNEL_TTABLE_BASE) &&
		kernel_base < PAGE_ALIGN_DOWN(KERNEL_TTABLE_END)) {
		if (!kvm_is_sw_pv_vm_available()) {
			pr_err("KVM: hypervisor is not paravirtualized and "
				"cannot run paravirtualized guest\n");
			return -EINVAL;
		}
	}
	r = kvm_set_shadow_area(kvm, &guest_shadow);
	if (r) {
		DebugKVM("shadow area setting failed: error %d\n", r);
		return r;
	}
	if (kernel_base < PAGE_ALIGN_UP(KERNEL_TTABLE_BASE) ||
		kernel_base >= PAGE_ALIGN_DOWN(KERNEL_TTABLE_END)) {
		return 0;
	}
	r = kvm_map_host_ttable_to_shadow(kvm, kernel_base,
					guest_shadow.guest_shadow_addr);
	if (r) {
		DebugKVM("mapping of host trap table to shadow guest failed: "
			"error %d\n", r);
		return r;
	}
	ti = current_thread_info();
	ti->shadow_image_pgd =
		*pgd_offset(current->mm, guest_shadow.guest_shadow_addr);
	ti->paravirt_page_prefault = &kvm_e2k_paravirt_page_prefault;
	set_kvm_mode_flag(kvm, KVMF_PARAVIRT_GUEST);
	DebugKVM("guest kernel is paravirtualized image: host image pgd %px = "
		"0x%lx, shadow pgd 0x%lx\n",
		ti->kernel_image_pgd_p, pgd_val(ti->kernel_image_pgd),
		pgd_val(ti->shadow_image_pgd));
	return PAGE_ALIGN_DOWN(KERNEL_TTABLE_END) -
				PAGE_ALIGN_UP(KERNEL_TTABLE_BASE);
}

vm_fault_t kvm_arch_vcpu_fault(struct kvm_vcpu *vcpu, struct vm_fault *vmf)
{
	DebugKVM("VCPU #%d started for address 0x%lx\n",
		vcpu->vcpu_id, vmf->address);
	return VM_FAULT_SIGBUS;
}

static int kvm_alloc_epic_pages(struct kvm *kvm)
{
	if (kvm->arch.is_hv) {
		DebugKVM("started to alloc pages for EPIC\n");

		kvm->arch.epic_pages = alloc_pages(GFP_KERNEL | __GFP_ZERO,
							MAX_EPICS_ORDER);

		if (!kvm->arch.epic_pages) {
			DebugKVM("failed to alloc memory for EPIC\n");
			return -ENOMEM;
		}
	}

	return 0;
}

static void kvm_free_epic_pages(struct kvm *kvm)
{
	struct page *epic_pages = kvm->arch.epic_pages;

	if (kvm->arch.is_hv) {
		DebugKVM("started to free hw EPIC pages\n");

		__free_pages(epic_pages, MAX_EPICS_ORDER);
	}
}

/* FIXME this only works for IOEPIC #0 and VCPU #0 */
static int kvm_setup_passthrough(struct kvm *kvm)
{
	struct pci_dev *pdev = NULL;
	struct irq_remap_table *irt;

	irt = kmalloc(sizeof(struct irq_remap_table),
		GFP_KERNEL);
	if (!irt)
		return -ENOMEM;

	kvm->arch.irt = irt;
	irt->enabled = false;
	irt->vfio_dev = NULL;

	if (kvm->arch.is_hv) {
		/* Setup passthrough for first device with vfio-pci driver */
		for_each_pci_dev(pdev) {
			if (pdev->driver && !strcmp(pdev->driver->name, "vfio-pci")) {
				int node = dev_to_node(&pdev->dev);

				irt->vfio_dev = pdev;
				pdev->dev.archdata.kvm = kvm;

				if (node == NUMA_NO_NODE)
					node = 0;

				pr_info("Found VFIO device bus %d devfn 0x%x\n",
					pdev->bus->number, pdev->devfn);

				if (pdev->irq >= 16 && pdev->irq <= 19) {
					pr_info("kvm_ioepic: using PCI INTx passthrough (pin %d)\n",
						pdev->irq);
					return 0;
				}

				if (!l_eioh_device(pdev)) {
					pr_warn("kvm_ioepic: IOHub2 interrupt passthrough not supported (IOAPIC pin %d)\n",
						pdev->irq);
					return 0;
				}

				pr_info("kvm_ioepic: passing pin %d to guest\n", pdev->irq);

				irt->enabled = true;
				irt->host_pin = pdev->irq;
				irt->guest_pin = pdev->irq;
				irt->host_node = node;
				irt->guest_node = 0;
				irt->hpa = io_epic_base_node(node) + (irt->host_pin << PAGE_SHIFT);
				/* Set in kvm_ioepic_set_base() */
				irt->gpa = 0;

				return 0;
			}
		}
	}

	return 0;
}

int kvm_setup_legacy_vga_passthrough(struct kvm *kvm)
{
	int ret;
	struct irq_remap_table *irt = kvm->arch.irt;

	if (unlikely(!irt->enabled)) {
		pr_err("%s(): error: trying to pass VGA area without passing any device\n",
			__func__);
		return -EPERM;
	} else {
		ret = vga_get_interruptible(irt->vfio_dev, VGA_RSRC_LEGACY_MEM);
		if (ret) {
			pr_err("%s(): failed to acquire legacy VGA area from vgaarb\n",
				__func__);
			return ret;
		}
	}

	return 0;
}

static void setup_guest_features(struct kvm *kvm)
{
	kvm_guest_info_t *guest_info = &kvm->arch.guest_info;
	unsigned long features = 0;

	guest_info->features = features;
}

static int kvm_setup_guest_info(struct kvm *kvm, void __user *user_info)
{
	kvm_guest_info_t *guest_info = &kvm->arch.guest_info;
	int ret;

	if (copy_from_user(guest_info, user_info, sizeof(*guest_info))) {
		pr_err("%s(): could not copy info from user\n", __func__);
		return -EFAULT;
	}

	guest_info->is_stranger = guest_info->cpu_iset < E2K_ISET_V6;
	if (guest_info->is_stranger) {
		if (kvm_is_epic(kvm)) {
			pr_err("%s(): KVM was set to use 'EPIC', but guest "
				"cpu iset V%d needs at 'APIC'\n",
				__func__, guest_info->cpu_iset);
			return -EINVAL;
		}
		guest_info->mmu_support_pt_v6 = false;
	} else {
		if (!kvm_is_epic(kvm)) {
			pr_err("%s(): KVM was set to use 'APIC', but guest "
				"cpu iset V%d needs at 'EPIC'\n",
				__func__, guest_info->cpu_iset);
			return -EINVAL;
		}
	}

	if (guest_info->is_pv) {
		/* guest is paravirtualized and cannot be run as bare  */
		ret = kvm_disable_tdp_mode(kvm);
		if (ret)
			return ret;
		pr_info("%s(): guest is paravirtualized and  cannot be run "
			"in TDP mode, so mode is disabled\n",
			__func__);
	}

	if (guest_info->cpu_iset == E2K_ISET_V2) {
		/* guest based on iset V2 cannot be run in TDP mode */
		ret = kvm_disable_tdp_mode(kvm);
		if (ret)
			return ret;
		pr_info("%s(): cpu iset V2 cannot be run in TDP mode, "
			"so mode is disabled\n",
			__func__);
	}

	setup_guest_features(kvm);

	return 0;
}

static void kvm_free_passthrough(struct kvm *kvm)
{
	struct irq_remap_table *irt = kvm->arch.irt;

	if (kvm->arch.legacy_vga_passthrough)
		vga_put(irt->vfio_dev, VGA_RSRC_LEGACY_MEM);

	kfree(irt);
}

int kvm_arch_init_vm(struct kvm *kvm, unsigned long vm_type)
{
	int err;

	DebugKVM("started to create VM type %lx\n", vm_type);

	if (vm_type & KVM_E2K_EPIC_VM_FLAG) {
		DebugKVM("creating EPIC VM\n");
		kvm->arch.is_epic = true;
	} else {
		DebugKVM("creating APIC VM\n");
	}

	vm_type &= KVM_E2K_VM_TYPE_MASK;

	if (kvm_is_sv_vm_available() || kvm_is_sw_pv_vm_available())
		kvm->arch.is_pv = true;
	if (kvm_is_hv_vm_available() || kvm_is_hw_pv_vm_available())
		kvm->arch.is_hv = true;

	if (vm_type == 0) {
		/* default VM type, choose max better type */
		if (kvm_is_hw_pv_vm_available())
			vm_type = KVM_E2K_HW_PV_VM_TYPE;
		else if (kvm_is_hv_vm_available())
			vm_type = KVM_E2K_HV_VM_TYPE;
		else if (kvm_is_sw_pv_vm_available())
			vm_type = KVM_E2K_SW_PV_VM_TYPE;
		DebugKVM("will be created VM type %ld\n", vm_type);
	} else {
		switch (vm_type) {
		case KVM_E2K_SV_VM_TYPE:
			if (!kvm_is_sv_vm_available())
				return -EINVAL;
			kvm->arch.is_hv = false;
			break;
		case KVM_E2K_SW_PV_VM_TYPE:
			if (!kvm_is_sw_pv_vm_available())
				return -EINVAL;
			kvm->arch.is_hv = false;
			break;
		case KVM_E2K_HV_VM_TYPE:
			if (!kvm_is_hv_vm_available())
				return -EINVAL;
			kvm->arch.is_pv = false;
			break;
		case KVM_E2K_HW_PV_VM_TYPE:
			if (!kvm_is_hw_pv_vm_available())
				return -EINVAL;
			break;
		default:
			return -EINVAL;
		}
	}
	kvm->arch.vm_type = vm_type;

	kvm_arch_init_vm_mmap(kvm);

	/* BSP id can be defined by ioctl(), now set to default 0 */
	kvm->arch.bsp_vcpu_id = 0;

	err = kvm_alloc_vmid(kvm);
	if (err)
		goto error_vm;
	DebugKVM("allocated VM ID (GID) #%d\n", kvm->arch.vmid.nr);
	set_thread_flag(TIF_VM_CREATED);
	native_current_thread_info()->virt_machine = kvm;

	if (kvm->arch.is_pv && !kvm->arch.is_hv) {
		err = kvm_pv_guest_thread_info_init(kvm);
		if (err)
			goto error_gti;

		err = kvm_guest_pv_mm_init(kvm);
		if (err)
			goto error_gmm;
	}

	kvm_page_track_init(kvm);
	kvm_mmu_init_vm(kvm);

	raw_spin_lock_init(&kvm->arch.virq_lock);
	kvm->arch.max_irq_no = -1;

	INIT_LIST_HEAD(&kvm->arch.assigned_dev_head);

	kvm_arch_init_vm_mmu(kvm);

	err = kvm_alloc_epic_pages(kvm);
	if (err)
		goto error_gmm;

	err = kvm_setup_passthrough(kvm);
	if (err)
		goto error_gmm;

	kvm->arch.reboot = false;
	kvm->arch.num_numa_nodes = 1;
	kvm->arch.max_nr_node_cpu = 0;

	err = kvm_boot_spinlock_init(kvm);
	if (err)
		goto error_gmm;
	err = kvm_guest_spinlock_init(kvm);
	if (err)
		goto error_boot_spinlock;
	err = kvm_guest_csd_lock_init(kvm);
	if (err)
		goto error_spinlock;

	kvm->arch.num_sclkr_run = 0;
	kvm->arch.sh_sclkm3 = 0;
	raw_spin_lock_init(&kvm->arch.sh_sclkr_lock);

	return 0;

error_boot_spinlock:
	kvm_boot_spinlock_destroy(kvm);
error_spinlock:
	kvm_guest_spinlock_destroy(kvm);
error_gmm:
	if (kvm->arch.is_pv && !kvm->arch.is_hv) {
		kvm_pv_guest_thread_info_destroy(kvm);
	}
error_gti:
	native_current_thread_info()->virt_machine = NULL;
	clear_thread_flag(TIF_VM_CREATED);
error_vm:
	return err;
}

static void setup_kvm_features(struct kvm *kvm)
{
	kvm_host_info_t *host_info = kvm->arch.kmap_host_info;
	unsigned long features = 0;

	if (kvm->arch.is_hv) {
		features |= (KVM_FEAT_HV_CPU_MASK |
				KVM_FEAT_HW_HCALL_MASK);
		features |= KVM_FEAT_HV_MMU_MASK;
	}
	if (kvm->arch.is_pv) {
		features |= KVM_FEAT_PV_CPU_MASK;
	}
	if (kvm->arch.is_pv && !kvm->arch.is_hv) {
		/* hypervisor (can) support only paravirtualization */
		features |= (KVM_FEAT_PV_HCALL_MASK |
					KVM_FEAT_PV_MMU_MASK);
	}
	if (kvm_is_epic(kvm)) {
		if (kvm->arch.is_hv && cpu_has(CPU_FEAT_EPIC))
			features |= KVM_FEAT_HV_EPIC_MASK;
		else
			features |= KVM_FEAT_PV_EPIC_MASK;
	} else {	/* can be only APIC */
		if (kvm->arch.is_pv)
			features |= KVM_FEAT_PV_APIC_MASK;
	}

	host_info->features = features;
}

static void kvm_setup_host_info(struct kvm *kvm)
{
	kvm->arch.kmap_host_info->mach_id = native_machine_id;
	kvm->arch.kmap_host_info->cpu_rev = machine.native_rev;
	kvm->arch.kmap_host_info->cpu_iset = machine.native_iset_ver;
	kvm->arch.kmap_host_info->support_hw_hc =
			machine.native_iset_ver >= E2K_ISET_V6;
	if (machine.native_iset_ver >= E2K_ISET_V6 && machine.mmu_pt_v6)
		kvm->arch.kmap_host_info->mmu_support_pt_v6 = true;
	else
		kvm->arch.kmap_host_info->mmu_support_pt_v6 = false;
	setup_kvm_features(kvm);
	kvm->arch.kmap_host_info->clock_rate = CLOCK_TICK_RATE;
	kvm_update_guest_time(kvm);
}

static int kvm_create_host_info(struct kvm *kvm)
{
	kvm_host_info_t *host_info = NULL;
	kvm_host_info_t *kmap_host_info = NULL;
	user_area_t *guest_area;

	int npages;
	long r;

	DebugKVM("started\n");
	mutex_lock(&kvm->lock);
	if (unlikely(kvm->arch.host_info != NULL)) {
		mutex_unlock(&kvm->lock);
		DebugKVM("host info structure is already created at %px\n",
			kvm->arch.host_info);
		return 0;
	}
	npages = PAGE_ALIGN(sizeof(kvm_host_info_t)) >> PAGE_SHIFT;
	guest_area = kvm_find_memory_region(kvm, -1, 0, npages << PAGE_SHIFT,
						guest_vram_mem_type);
	if (guest_area == NULL) {
		DebugKVM("guest memory regions is not created or empty\n");
		r = -ENOMEM;
		goto out;
	}
	host_info = user_area_alloc_locked_pages(guest_area, 0,
			sizeof(kvm_host_info_t), 1 << E2K_ALIGN_GLOBALS, 0);
	if (host_info == NULL) {
		DebugKVM("could not allocate TIME state struct\n");
		r = -ENOMEM;
		goto error;
	}
	DebugKVM("host info structure created at %px\n", host_info);

	/*
	 * host info maps to kernel vmaloc range to have access into
	 * this state from any host kernel threads on kernel addresses
	 * Guest address can change from physical to virtual
	 */
	kmap_host_info = map_user_area_to_vmalloc_range(guest_area,
						host_info, PAGE_KERNEL);
	if (kmap_host_info == NULL) {
		DebugKVM("could not map host info struct to kernel VM\n");
		r = -ENOMEM;
		goto error;
	}

	memset(kmap_host_info, 0, sizeof(kvm_host_info_t));
	kvm->arch.host_info = host_info;
	kvm->arch.kmap_host_info = kmap_host_info;
	kvm->arch.time_state_lock =
		__RAW_SPIN_LOCK_UNLOCKED(&kvm->arch.time_state_lock);
	kvm_setup_host_info(kvm);

	r = 0;
	goto out;

error:
	if (kmap_host_info != NULL) {
		unmap_user_area_to_vmalloc_range(guest_area, kmap_host_info);
		kvm->arch.kmap_host_info = NULL;
	}
	if (host_info != NULL) {
		user_area_free_chunk(guest_area, host_info);
		kvm->arch.host_info = NULL;
	}

out:
	mutex_unlock(&kvm->lock);
	return r;
}

static void kvm_free_host_info(struct kvm *kvm)
{
	DebugKVMSH("%s (%d) started\n",
		current->comm, current->pid);
	if (kvm->arch.host_info != NULL) {
		user_area_t *guest_area;
		e2k_addr_t area_start;

		area_start = (e2k_addr_t)kvm->arch.host_info;
		guest_area = kvm_find_memory_region(kvm,
				-1, area_start, 0, guest_vram_mem_type);
		if (kvm->arch.kmap_host_info != NULL) {
			unmap_user_area_to_vmalloc_range(guest_area,
						kvm->arch.kmap_host_info);
			kvm->arch.kmap_host_info = NULL;
		}
		user_area_free_chunk(guest_area, kvm->arch.host_info);
		kvm->arch.host_info = NULL;
	} else if (kvm->arch.kmap_host_info != NULL) {
		unmap_user_area_to_vmalloc_range(NULL,
					kvm->arch.kmap_host_info);
		kvm->arch.kmap_host_info = NULL;
	}
}

static int kvm_vm_ioctl_get_irqchip(struct kvm *kvm,
					struct kvm_irqchip *chip)
{
	int r;

	DebugKVM("started\n");
	r = 0;
	switch (chip->chip_id) {
	case KVM_IRQCHIP_IOAPIC:
		/* IOEPIC is currently not supported in QEMU */
		if (!kvm_is_epic(kvm))
			r = kvm_get_ioapic(kvm, &chip->chip.ioapic);
		break;
	default:
		r = -EINVAL;
		break;
	}
	return r;
}

static int kvm_vm_ioctl_set_irqchip(struct kvm *kvm, struct kvm_irqchip *chip)
{
	int r;

	DebugKVM("started\n");
	r = 0;
	switch (chip->chip_id) {
	case KVM_IRQCHIP_IOAPIC:
		/* IOEPIC is currently not supported in QEMU */
		if (!kvm_is_epic(kvm))
			r = kvm_set_ioapic(kvm, &chip->chip.ioapic);
		break;
	default:
		r = -ENODEV;
		break;
	}
	return r;
}

int kvm_vm_ioctl_irq_line(struct kvm *kvm, struct kvm_irq_level *irq_event,
			bool line_status)
{
	if (!irqchip_in_kernel(kvm))
		return -ENXIO;

	irq_event->status = kvm_set_irq(kvm, KVM_USERSPACE_IRQ_SOURCE_ID,
					irq_event->irq, irq_event->level,
					line_status);
	return 0;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);
	DebugKVM("does not implemented\n");

	return 0;
}

int kvm_vm_ioctl_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	int r;

	if (cap->flags)
		return -EINVAL;

	switch (cap->cap) {
	default:
		r = -ENODEV;
		break;
	}
	return r;
}

unsigned long kvm_i2c_spi_conf_base[4] = { 0UL, 0UL, 0UL, 0UL,};
unsigned long kvm_spmc_conf_base[4] = { 0UL, 0UL, 0UL, 0UL,};

long kvm_arch_vm_ioctl(struct file *filp,
		unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm = filp->private_data;
	void __user *argp = (void __user *)arg;
	int r = -ENOTTY;

	DebugKVMIOC("started\n");
	switch (ioctl) {
	case KVM_SET_MEMORY_REGION: {
		struct kvm_memory_region kvm_mem;
		struct kvm_userspace_memory_region kvm_userspace_mem;

		DebugKVMIOCTL("ioctl is KVM_SET_MEMORY_REGION\n");
		r = -EFAULT;
		if (copy_from_user(&kvm_mem, argp, sizeof kvm_mem))
			goto out;
		DebugKVM("ioctl(KVM_SET_MEMORY_REGION) for slot ID %d\n",
			kvm_mem.slot);
		kvm_userspace_mem.slot = kvm_mem.slot;
		kvm_userspace_mem.flags = kvm_mem.flags;
		kvm_userspace_mem.guest_phys_addr =
					kvm_mem.guest_phys_addr;
		kvm_userspace_mem.memory_size = kvm_mem.memory_size;
		r = kvm_set_memory_region(kvm, &kvm_userspace_mem);
		break;
	}
	case KVM_ALLOC_GUEST_AREA: {
		kvm_guest_area_alloc_t __user *guest_area;

		DebugKVMIOCTL("ioctl is KVM_ALLOC_GUEST_AREA\n");
		guest_area = (kvm_guest_area_alloc_t __user *)argp;
		r = kvm_arch_ioctl_alloc_guest_area(kvm, guest_area);
		break;
	}
	case KVM_RESERVE_GUEST_AREA: {
		kvm_guest_area_reserve_t __user reserve_area;
		user_area_t *guest_area;

		DebugKVMIOCTL("ioctl is KVM_RESERVE_GUEST_AREA\n");
		r = -EFAULT;
		if (copy_from_user(&reserve_area, argp, sizeof reserve_area))
			goto out;
		r = -EINVAL;
		guest_area = kvm_find_memory_region(kvm, -1,
					reserve_area.start, reserve_area.size,
					reserve_area.type);
		if (!guest_area)
			goto out;
		r = user_area_reserve_chunk(guest_area, reserve_area.start,
				reserve_area.size);
		break;
	}
	case KVM_SET_MEMORY_ALIAS: {
		kvm_memory_alias_t __user *guest_alias;

		DebugKVMIOCTL("ioctl is KVM_SET_MEMORY_ALIAS\n");
		guest_alias = (kvm_memory_alias_t __user *)argp;
		r = kvm_vm_ioctl_set_memory_alias(kvm, guest_alias);
		break;
	}
	case KVM_SET_KERNEL_IMAGE_SHADOW: {
		kvm_kernel_area_shadow_t __user *guest_shadow;

		DebugKVMIOCTL("ioctl is KVM_SET_KERNEL_IMAGE_SHADOW\n");
		guest_shadow = (kvm_kernel_area_shadow_t __user *)argp;
		r = kvm_vm_ioctl_set_kernel_image_shadow(kvm, guest_shadow);
		break;
	}
	case KVM_CREATE_IRQCHIP:
		DebugKVMIOCTL("ioctl is KVM_CREATE_IRQCHIP\n");
		r = -EFAULT;
		r = kvm_io_pic_init(kvm);
		if (r)
			goto out;
		r = kvm_setup_default_irq_routing(kvm);
		if (r) {
			kvm_iopic_release(kvm);
			goto out;
		}
		break;
	case KVM_CREATE_SIC_NBSR:
		DebugKVMIOCTL("ioctl is KVM_CREATE_SIC_NBSR\n");
		r = kvm_nbsr_init(kvm);
		break;
	case KVM_GET_IRQCHIP: {
		/* 0: PIC master, 1: PIC slave, 2: IOAPIC */
		struct kvm_irqchip chip;

		DebugKVMIOCTL("ioctl is KVM_GET_IRQCHIP\n");
		r = -EFAULT;
		if (copy_from_user(&chip, argp, sizeof chip))
				goto out;
		r = -ENXIO;
		if (!irqchip_in_kernel(kvm))
			goto out;
		r = kvm_vm_ioctl_get_irqchip(kvm, &chip);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, &chip, sizeof chip))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_IRQCHIP: {
		/* 0: PIC master, 1: PIC slave, 2: IOAPIC */
		struct kvm_irqchip chip;

		DebugKVMIOCTL("ioctl is KVM_SET_IRQCHIP\n");
		r = -EFAULT;
		if (copy_from_user(&chip, argp, sizeof chip))
			goto out;
		r = -ENXIO;
		if (!irqchip_in_kernel(kvm))
			goto out;
		r = kvm_vm_ioctl_set_irqchip(kvm, &chip);
		break;
	}
	case KVM_SET_PCI_REGION: {
		struct kvm_pci_region pci_region;

		DebugKVMIOCTL("ioctl is KVM_SET_PCI_REGION\n");
		r = -EFAULT;
		if (copy_from_user(&pci_region, argp, sizeof pci_region))
			goto out;
		r = nbsr_setup_pci_region(kvm, &pci_region);
		break;
	}
	case KVM_SET_IRQCHIP_BASE: {
		struct kvm_base_addr_node basen;

		r = -EFAULT;
		if (copy_from_user(&basen, argp, sizeof basen))
			goto out;
		DebugKVMIOCTL("ioctl is KVM_SET_IRQCHIP_BASE to 0x%lx "
			"node %d\n", basen.base, basen.node_id);
		r = kvm_io_pic_set_base(kvm, basen.base,
						basen.node_id);
		break;
	}
	case KVM_SET_SYS_TIMER_BASE: {
		struct kvm_base_addr_node basen;

		r = -EFAULT;
		if (copy_from_user(&basen, argp, sizeof basen))
			goto out;
		DebugKVMIOCTL("ioctl is KVM_SET_SYS_TIMER_BASE to 0x%lx "
			"node %d\n", basen.base, basen.node_id);
		r = kvm_lt_set_base(kvm, basen.node_id, basen.base);
		break;
	}
	case KVM_SET_SPMC_CONF_BASE: {
		struct kvm_base_addr_node basen;

		r = -EFAULT;
		if (copy_from_user(&basen, argp, sizeof basen))
			goto out;

		DebugKVMIOCTL("ioctl is KVM_SET_SPMC_CONF_BASE to 0x%lx "
			"node %d\n", basen.base, basen.node_id);
		kvm_spmc_conf_base[basen.node_id] = basen.base;
		r = kvm_spmc_set_base(kvm, basen.node_id, basen.base);
		break;
	}
	case KVM_SET_SPMC_CONF_BASE_SPMC_IN_QEMU: {
		struct kvm_base_addr_node basen;

		if (copy_from_user(&basen, argp, sizeof basen))
			goto out;
		DebugKVMIOCTL("ioctl is KVM_SET_SPMC_CONF_BASE_SPMC_IN_QEMU "
			"to 0x%lx node %d\n", basen.base, basen.node_id);
		kvm_spmc_conf_base[basen.node_id] = basen.base;
		r = 0;
		break;
	}
	case KVM_SET_I2C_SPI_CONF_BASE: {
		struct kvm_base_addr_node basen;

		if (copy_from_user(&basen, argp, sizeof basen))
			goto out;
		DebugKVMIOCTL("ioctl is KVM_SET_I2C_SPI_CONF_BASE "
			"to 0x%lx node %d\n", basen.base, basen.node_id);
		kvm_i2c_spi_conf_base[basen.node_id] = basen.base;
		r = 0;
		break;
	}
	case KVM_SET_COUNT_NUMA_NODES:
		DebugKVMIOCTL("ioctl is KVM_SET_COUNT_NUMA_NODES to 0x%lx\n",
				arg);
		kvm->arch.num_numa_nodes = arg;
		r = 0;
		break;
	case KVM_SET_MAX_NR_NODE_CPU:
		DebugKVMIOCTL("ioctl is KVM_SET_MAX_NR_NODE_CPU to 0x%lx\n",
				arg);
		kvm->arch.max_nr_node_cpu = arg;
		r = 0;
		break;
	case KVM_SET_CEPIC_FREQUENCY:
		DebugKVMIOCTL("ioctl is KVM_SET_CEPIC_FREQUENCY to %lu Hz\n",
				arg);
		kvm->arch.cepic_freq = arg;
		r = 0;
		break;
	case KVM_SET_WD_PRESCALER_MULT:
		DebugKVMIOCTL("ioctl is KVM_SET_WD_PRESCALER_MULT to %lu\n",
				arg);
		kvm->arch.wd_prescaler_mult = arg;
		r = 0;
		break;
	case KVM_SET_LEGACY_VGA_PASSTHROUGH:
		DebugKVMIOCTL("ioctl is KVM_SET_LEGACY_VGA_PASSTHROUGH to %lu\n",
				arg);
		r = 0;
		if (arg) {
			r = kvm_setup_legacy_vga_passthrough(kvm);
			if (!r)
				kvm->arch.legacy_vga_passthrough = true;
		}
		break;
	case KVM_ENABLE_CAP: {
		struct kvm_enable_cap cap;

		DebugKVMIOCTL("ioctl is KVM_ENABLE_CAP\n");
		r = -EFAULT;
		if (copy_from_user(&cap, argp, sizeof(cap)))
			goto out;
		r = kvm_vm_ioctl_enable_cap(kvm, &cap);
		break;
	}
	case KVM_SET_GUEST_INFO:
		DebugKVMIOCTL("ioctl is KVM_SET_GUEST_INFO\n");
		r = kvm_setup_guest_info(kvm, argp);
		break;
	case KVM_GET_NBSR_STATE: {
		struct kvm_guest_nbsr_state nbsr;
		int node_id;
		DebugKVM("ioctl is KVM_GET_NBSR_STATE\n");
		r = -ENXIO;
		if (copy_from_user(&nbsr, argp, sizeof(nbsr)))
			goto out;
		node_id = nbsr.node_id;
		DebugKVM("ioctl is KVM_GET_NBSR_STATE node %d\n", node_id);

		if (!kvm->arch.nbsr)
			goto out;

		r = kvm_get_nbsr_state(kvm, &nbsr, node_id);
		if (r)
			goto out;

		r = -EFAULT;
		if (copy_to_user(argp, &nbsr,
				sizeof(struct kvm_guest_nbsr_state)))
			goto out;
		r = 0;
		break;
	}
	default:
		DebugKVM("ioctl is not supported\n");
		;
	}
out:
	DebugKVMIOC("returns with value %d\n", r);
	return r;
}

int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu,
		struct kvm_sregs *sregs)
{
	DebugKVM("started\n");
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu,
		struct kvm_sregs *sregs)
{
	DebugKVM("started\n");
	return -EINVAL;
}
int kvm_arch_vcpu_ioctl_translate(struct kvm_vcpu *vcpu,
		struct kvm_translation *tr)
{
	DebugKVM("started\n");
	return -EINVAL;
}

struct kvm_vcpu *kvm_arch_vcpu_create(struct kvm *kvm,
		unsigned int id)
{
	struct kvm_vcpu *vcpu = NULL;
	int r;

	DebugKVM("started for CPU id %d\n", id);
	vcpu = kmem_cache_zalloc(kvm_vcpu_cache, GFP_KERNEL);
	if (!vcpu)
		return ERR_PTR(-ENOMEM);

	r = kvm_vcpu_init(vcpu, kvm, id);
	if (r) {
		kmem_cache_free(kvm_vcpu_cache, vcpu);
		DebugKVM("VCPU init failed: %d\n", r);
		return ERR_PTR(r);
	}
	return vcpu;
}

bool kvm_vcpu_is_bsp(struct kvm_vcpu *vcpu)
{
	return vcpu->vcpu_id == 0;
}

bool kvm_vcpu_compatible(struct kvm_vcpu *vcpu)
{
	return irqchip_in_kernel(vcpu->kvm) == lapic_in_kernel(vcpu);
}

void kvm_arch_vcpu_postcreate(struct kvm_vcpu *vcpu)
{
	DebugKVM("Unimplemented\n");
}

int kvm_arch_vcpu_init(struct kvm_vcpu *vcpu)
{
	int r;

	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);

	if (kvm_vcpu_is_bsp(vcpu)) {
		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	} else {
		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	}

	vcpu->arch.node_id = vcpu->vcpu_id % vcpu->kvm->arch.num_numa_nodes;

	if (!vcpu->kvm->arch.max_nr_node_cpu) {
		pr_err("%s() : not initiated kvm->arch.max_nr_node_cpu"
				" from qemu\n", __func__);
		return -EPERM;
	}
	vcpu->arch.hard_cpu_id = (vcpu->kvm->arch.max_nr_node_cpu *
		vcpu->arch.node_id) + vcpu->vcpu_id /
				vcpu->kvm->arch.num_numa_nodes;
	DebugKVM("started for VCPU %d hard_cpu_id %d\n",
			vcpu->vcpu_id, vcpu->arch.hard_cpu_id);

	init_completion(&vcpu->arch.released);
	mutex_init(&vcpu->arch.lock);
	vcpu->arch.ioport_data = get_ioport_data_pointer(vcpu->run);
	vcpu->arch.ioport_data_size = get_ioport_data_size(vcpu->run);

	if (vcpu->kvm->arch.vm_type == KVM_E2K_SV_VM_TYPE ||
			vcpu->kvm->arch.vm_type == KVM_E2K_SW_PV_VM_TYPE) {
		r = kvm_arch_pv_vcpu_init(vcpu);
		if (r != 0)
			return r;
	}

	if (vcpu->kvm->arch.vm_type == KVM_E2K_HV_VM_TYPE ||
			vcpu->kvm->arch.vm_type == KVM_E2K_HW_PV_VM_TYPE) {
		r = kvm_arch_hv_vcpu_init(vcpu);
		if (r != 0)
			goto pv_uninit;
	}

	r = kvm_arch_any_vcpu_init(vcpu);
	if (r != 0)
		goto pv_uninit;

	/* create hypervisor backup hardware stacks */
	r = create_vcpu_backup_stacks(vcpu);
	if (r != 0)
		goto hv_uninit;

	/* create VCPU booting stacks */
	r = create_vcpu_boot_stacks(vcpu);
	if (r != 0)
		goto free_backup;

	if (!vcpu->arch.is_hv) {
		/* create the host VCPU context for multi-threading */
		r = create_vcpu_host_context(vcpu);
		if (r != 0)
			goto free_boot;
	}

	/* Now that stacks are allocated, we can set
	 * initialize stack registers values for guest */
	kvm_arch_vcpu_ctxt_init(vcpu);

	r = kvm_mmu_create(vcpu);
	if (r < 0)
		goto free_host;

#ifdef CONFIG_KVM_ASYNC_PF
	/*
	 * Async page faults are disabled by default. Paravirtualized guest can
	 * enable it by calling hypercall KVM_HCALL_PV_ENABLE_ASYNC_PF.
	 */
	vcpu->arch.apf.enabled = false;
#endif /* CONFIG_KVM_ASYNC_PF */

	if (irqchip_in_kernel(vcpu->kvm)) {
		r = kvm_create_local_pic(vcpu);
		if (r != 0)
			goto mmu_destroy;
	}

	return 0;

mmu_destroy:
	kvm_mmu_destroy(vcpu);
free_host:
	destroy_vcpu_host_context(vcpu);
free_boot:
	free_vcpu_boot_stacks(vcpu);
free_backup:
	free_kernel_backup_stacks(&vcpu->arch.hypv_backup);
	kvm_arch_vcpu_ctxt_uninit(vcpu);
hv_uninit:
	kvm_arch_hv_vcpu_uninit(vcpu);
pv_uninit:
	kvm_arch_pv_vcpu_uninit(vcpu);
	kvm_arch_any_vcpu_uninit(vcpu);
	return r;
}

int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu)
{
	int r;
	unsigned long epic_gstbase;

	DebugKVM("started\n");
	raw_spin_lock_init(&vcpu->arch.exit_reqs_lock);
	INIT_LIST_HEAD(&vcpu->arch.exit_reqs_list);
	vcpu->arch.halted = false;
	INIT_WORK(&vcpu->arch.dump_work, NULL);
	INIT_LIST_HEAD(&vcpu->arch.vcpus_to_spin);

	if (vcpu->arch.is_hv) {
		/* Set the pointer to the CEPIC page */
		epic_gstbase = (unsigned long)
			page_address(vcpu->kvm->arch.epic_pages);
		vcpu->arch.hw_ctxt.cepic = (epic_page_t *) (epic_gstbase +
			(kvm_vcpu_to_full_cepic_id(vcpu) << PAGE_SHIFT));

		raw_spin_lock_init(&vcpu->arch.epic_dam_lock);
		vcpu->arch.epic_dam_active = false;
		kvm_init_cepic_idle_timer(vcpu);
	}
	vcpu->arch.exit_shutdown_terminate = 0;

	vcpu_load(vcpu);

	if (vcpu->kvm->arch.vm_type == KVM_E2K_SV_VM_TYPE ||
			vcpu->kvm->arch.vm_type == KVM_E2K_SW_PV_VM_TYPE) {
		r = kvm_arch_pv_vcpu_setup(vcpu);
		if (r != 0)
			goto error;
	}

	if (vcpu->kvm->arch.vm_type == KVM_E2K_HV_VM_TYPE ||
			vcpu->kvm->arch.vm_type == KVM_E2K_HW_PV_VM_TYPE) {
		r = kvm_arch_hv_vcpu_setup(vcpu);
		if (r != 0)
			goto error;
	}

	r = kvm_arch_any_vcpu_setup(vcpu);
	if (r != 0)
		goto error;

	/* init hypervisor backup hardware stacks */
	r = vcpu_backup_stacks_init(vcpu);
	if (r != 0)
		goto error;

	/* init VCPU booting stacks */
	r = vcpu_boot_stacks_init(vcpu);
	if (r != 0)
		goto error;

	kvm_mmu_setup(vcpu);

	r = init_pic_state(vcpu);

error:
	vcpu_put(vcpu);
	return r;
}

static int init_guest_vcpu_state(struct kvm_vcpu *vcpu)
{
	kvm_host_info_t *host_info;

	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);

	host_info = vcpu->kvm->arch.host_info;
	BUG_ON(host_info == NULL);
	host_info = (kvm_host_info_t *)kvm_vcpu_hva_to_gpa(vcpu,
						(unsigned long)host_info);
	if (IS_INVALID_GPA((gpa_t)host_info)) {
		pr_err("%s() : could not allocate GPA of host info struct\n",
			__func__);
		goto error;
	}
	vcpu->arch.kmap_vcpu_state->host = host_info;

	if (vcpu->arch.is_pv)
		kvm_init_cpu_state_idr(vcpu);

	if (vcpu->arch.is_hv) {
		DebugKVM("VCPU #%d : setting host info structure at %px\n",
			vcpu->vcpu_id, host_info);
		return 0;
	}

	kvm_init_cpu_state(vcpu);

	kvm_init_mmu_state(vcpu);

	DebugKVM("VCPU #%d : setting host info structure at %px\n",
		vcpu->vcpu_id, host_info);
	return 0;

error:
	kvm_free_host_info(vcpu->kvm);
	return -ENOMEM;
}

void guest_pv_vcpu_state_to_paging(struct kvm_vcpu *vcpu)
{
	kvm_host_info_t *host_info;

	host_info = vcpu->arch.kmap_vcpu_state->host;
	BUG_ON(host_info == NULL || vcpu->kvm->arch.host_info == NULL);
	vcpu->arch.kmap_vcpu_state->host = __guest_va(host_info);
}

int init_cepic_state(struct kvm_vcpu *vcpu)
{
	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);
	if (vcpu->arch.epic)
		kvm_cepic_reset(vcpu);
	if (vcpu->arch.is_pv)
		kvm_init_guest_cepic_virqs_num(vcpu);
	return 0;
}

int init_lapic_state(struct kvm_vcpu *vcpu)
{
	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);
	if (vcpu->arch.apic)
		kvm_lapic_reset(vcpu);
	kvm_init_guest_lapic_virqs_num(vcpu);
	return 0;
}

void kvm_arch_vcpu_blocking(struct kvm_vcpu *vcpu)
{
	DebugKVMRUN("Unimplemented\n");
}

void kvm_arch_vcpu_unblocking(struct kvm_vcpu *vcpu)
{
	DebugKVMRUN("Unimplemented\n");
}

static int init_guest_boot_cut(struct kvm_vcpu *vcpu)
{
	kvm_vcpu_state_t *vcpu_state = vcpu->arch.vcpu_state;
	e2k_cute_t *cute_p = vcpu->arch.guest_cut;

	if (cute_p == NULL) {
		KVM_BUG_ON(!vcpu->arch.is_hv);
		return 0;
	} else {
		KVM_BUG_ON(!vcpu->arch.is_pv);
	}
	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);
	fill_cut_entry(cute_p, 0, 0, 0, 0);
	DebugKVM("created guest CUT entry #0 zeroed at %px\n", cute_p);
	cute_p += GUEST_CODES_INDEX;
	fill_cut_entry(cute_p, 0, 0,
			kvm_vcpu_hva_to_gpa(vcpu, (unsigned long)vcpu_state),
			sizeof(*vcpu_state));
	DebugKVM("created guest CUT entry #%ld from 0x%lx size 0x%lx at %px\n",
		GUEST_CODES_INDEX,
		(void *)kvm_vcpu_hva_to_gpa(vcpu, (unsigned long)vcpu_state),
		sizeof(*vcpu_state), cute_p);
	return 0;
}
static int kvm_arch_ioctl_setup_vcpu(struct kvm_vcpu *vcpu)
{
	/* FIXME: the ioctl() can be deleted, but old version of */
	/* arch KVM API support this ioctl(), so let it be empty */
	return 0;
}

static int kvm_arch_ioctl_vcpu_guest_startup(struct kvm_vcpu *vcpu,
			kvm_vcpu_guest_startup_t __user *guest_startup)
{
	kvm_vcpu_guest_startup_t guest_args;
	e2k_size_t trap_offset;
	int arg;

	if (copy_from_user(&guest_args, guest_startup, sizeof(guest_args))) {
		DebugKVM("copy to %px from user %px failed\n",
			&guest_args, guest_startup);
		return -EFAULT;
	}
	kvm_set_vcpu_kernel_image(vcpu,
		guest_args.kernel_base, guest_args.kernel_size);
	if (vcpu->arch.is_hv) {
		/* should be always ttable #0 */
		trap_offset = 0;
	} else if (vcpu->arch.is_pv) {
		/* can be any ttable # from 32-63 */
		trap_offset = guest_args.trap_off;
	} else {
		KVM_BUG_ON(true);
		trap_offset = 0;
	}
	vcpu->arch.trap_offset = trap_offset;
	vcpu->arch.trap_entry = vcpu->arch.guest_base + trap_offset;
	DebugKVM("guest trap table entry  at %px\n", vcpu->arch.trap_entry);

	vcpu->arch.entry_point = guest_args.entry_point;
	DebugKVM("guest image start point at %px\n", vcpu->arch.entry_point);
	vcpu->arch.args_num = guest_args.args_num;
	DebugKVM("guest image args num is %d\n", vcpu->arch.args_num);
	for (arg = 0; arg < vcpu->arch.args_num; arg++) {
		vcpu->arch.args[arg] = guest_args.args[arg];
		DebugKVM("     arg #%d : 0x%llx\n", arg, vcpu->arch.args[arg]);
	}
	if (guest_args.flags & NATIVE_KERNEL_IMAGE_GUEST_FLAG) {
		set_kvm_mode_flag(vcpu->kvm, KVMF_NATIVE_KERNEL);
		DebugKVM("guest is e2k linux native kernel\n");
	} else if (guest_args.flags & PARAVIRT_KERNEL_IMAGE_GUEST_FLAG) {
		set_kvm_mode_flag(vcpu->kvm, KVMF_PARAVIRT_KERNEL);
		DebugKVM("guest is e2k linux paravirtualized kernel\n");
	} else if (guest_args.flags & LINTEL_IMAGE_GUEST_FLAG) {
		set_kvm_mode_flag(vcpu->kvm, KVMF_LINTEL);
		DebugKVM("guest is e2k LIntel binary compilator\n");
	}

	kvm_init_clockdev(vcpu);

	vcpu_load(vcpu);

	if (vcpu->arch.is_hv || vcpu->arch.is_pv) {
		kvm_start_vcpu_thread(vcpu);
	} else {
		KVM_BUG_ON(true);
	}

	vcpu_put(vcpu);

	set_kvm_mode_flag(vcpu->kvm, KVMF_VCPU_STARTED);

	return 0;
}

/*
 * Mutex should be locked by caller (if needs)
 */
struct kvm_vcpu *kvm_get_vcpu_on_id(struct kvm *kvm, int vcpu_id)
{
	int r;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(r, vcpu, kvm)
		if (vcpu->vcpu_id == vcpu_id)
			return vcpu;
	return ERR_PTR(-ENODEV);
}

/*
 * Mutex should be locked by caller (if needs)
 */
struct kvm_vcpu *kvm_get_vcpu_on_hard_cpu_id(struct kvm *kvm, int hard_cpu_id)
{
	int r;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(r, vcpu, kvm)
		if (vcpu->arch.hard_cpu_id == hard_cpu_id)
			return vcpu;
	return ERR_PTR(-ENODEV);
}

int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	DebugKVM("started\n");
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	DebugKVM("started\n");
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_guest_debug(struct kvm_vcpu *vcpu,
					struct kvm_guest_debug *dbg)
{
	DebugKVM("started\n");
	return -EINVAL;
}

void kvm_halt_host_vcpu_thread(struct kvm_vcpu *vcpu)
{
	DebugKVMSH("%s (%d) started to terminate VCPU #%d thread\n",
		current->comm, current->pid, vcpu->vcpu_id);

	mutex_lock(&vcpu->arch.lock);
	current_thread_info()->vcpu = NULL;
	vcpu->arch.host_task = NULL;
	mutex_unlock(&vcpu->arch.lock);

	kvm_arch_vcpu_release(vcpu);
}

static void kvm_halt_all_host_vcpus(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int r;

	DebugKVMSH("%s (%d) started\n",
		current->comm, current->pid);

	mutex_lock(&kvm->lock);
	kvm_for_each_vcpu(r, vcpu, kvm) {
		if (vcpu != NULL) {
			if (vcpu->arch.host_task != NULL) {
				kvm_halt_host_vcpu_thread(vcpu);
			} else {
				free_vcpu_state(vcpu);
			}
		}
	}
	mutex_unlock(&kvm->lock);
}

static void kvm_wait_for_vcpu_release(struct kvm_vcpu *vcpu)
{
	DebugKVMSH("%s (%d) started to halt VCPU #%d\n",
		current->comm, current->pid, vcpu->vcpu_id);

	if (vcpu->arch.host_task != NULL) {
		kvm_halt_host_vcpu_thread(vcpu);
	} else {
		kvm_arch_vcpu_release(vcpu);
	}

	if (!vcpu->arch.is_hv) {
		wait_for_completion(&vcpu->arch.released);
	}
	DebugKVMSH("VCPU #%d released\n", vcpu->vcpu_id);
}

void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	DebugKVMSH("%s (%d) started for VCPU %d\n",
		current->comm, current->pid, vcpu->vcpu_id);
	kvm_vcpu_uninit(vcpu);
	kvm_free_local_pic(vcpu);
	kmem_cache_free(kvm_vcpu_cache, vcpu);
}

static void kvm_wake_up_all_other_vcpu_host(struct kvm_vcpu *my_vcpu)
{
	struct kvm *kvm = my_vcpu->kvm;
	struct kvm_vcpu *vcpu;
	struct task_struct *host_task;
	int r;

	DebugKVMSH("%s (%d) started\n",
		current->comm, current->pid);

	mutex_lock(&kvm->lock);
	kvm_for_each_vcpu(r, vcpu, kvm) {
		if (vcpu == NULL)
			continue;
		if (vcpu == my_vcpu)
			continue;
		mutex_lock(&vcpu->arch.lock);
		host_task = vcpu->arch.host_task;
		if (host_task != NULL) {
			wake_up_process(host_task);
			DebugKVMSH("waked up host thread %s (%d) VCPU #%d\n",
				host_task->comm, host_task->pid, vcpu->vcpu_id);
		}
		mutex_unlock(&vcpu->arch.lock);
	}
	mutex_unlock(&kvm->lock);
}

static void kvm_arch_release_all_vcpus(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int r;

	DebugKVMSH("%s (%d) started\n",
		current->comm, current->pid);

	/* complete current thread as thread of virtual machine */
	kvm_resume_vm_thread();

	mutex_lock(&kvm->lock);
	kvm_for_each_vcpu(r, vcpu, kvm)
		if (vcpu != NULL) {
			kvm_wait_for_vcpu_release(vcpu);
		}
	mutex_unlock(&kvm->lock);
}

static void kvm_arch_free_all_vcpus(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int r;

	DebugKVMSH("started\n");
	mutex_lock(&kvm->lock);
	kvm_for_each_vcpu(r, vcpu, kvm)
		if (vcpu != NULL) {
			kvm_clear_vcpu(kvm, r);
			kvm_arch_vcpu_free(vcpu);
		}
	mutex_unlock(&kvm->lock);
}

void kvm_ioapic_release(struct kvm *kvm)
{
	int i;

	for (i = 0; i < kvm->arch.num_numa_nodes; i++) {
		struct kvm_ioapic *ioapic = kvm->arch.vioapic[i];

		if (!ioapic)
			continue;

		mutex_lock(&kvm->slots_lock);
		kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS, &ioapic->dev);
		mutex_unlock(&kvm->slots_lock);
		kvm->arch.vioapic[i] = NULL;
		kfree(ioapic);
	}
}

#ifdef	DUMP_PAGE_STRUCT
void dump_page_struct(struct page *page)
{
	unsigned long flags;

	pr_info("\nStruct page 0x%px :\n", page);
	if (page == NULL)
		return;
	flags = page->flags;
	pr_info("   flags 0x%016lx NR %d, node #%d, zone #%d id 0x%x :\n",
		flags, __NR_PAGEFLAGS,
		page_to_nid(page), page_zonenum(page), page_zone_id(page));

	pr_info("   count 0x%08x (starts from 0)\n",
		atomic_read(&page->_count));
	pr_info("   map count 0x%08x (starts from -1) or if SLUB inuse 0x%04x "
		"objects 0x%04x\n",
		atomic_read(&page->_mapcount),
		page->inuse, page->objects);
	pr_info("   union {\n");
	pr_info("      private 0x%016lx mapping 0x%px\n",
		page->private, page->mapping);
	if (flags & (1UL << PG_private))
		pr_info("         private is buffer_heads\n");
	if (flags & (1UL << PG_swapcache))
		pr_info("         private is swp_entry_t\n");
	if (flags & (1UL << PG_buddy))
		pr_info("         private indicates order in the buddy "
			"system\n");
	if (((unsigned long)page->mapping & PAGE_MAPPING_ANON))
		pr_info("         mapping points to anon_vma object\n");
	else
		pr_info("         mapping points to inode address_space\n");
#if USE_SPLIT_PTLOCKS
#ifndef CONFIG_PREEMPT_RT
	pr_info("      spin lock *ptl 0x%px\n", &page->ptl);
#else
	pr_info("      spin lock *ptl 0x%px\n", page->ptl);
#endif
#endif
	pr_info("      SLUB: Pointer to slab 0x%px\n", page->slab);
	pr_info("      Compound tail pages: Pointer to first page 0x%px\n",
		page->first_page);
	pr_info("   }\n");
	pr_info("   union {\n");
	pr_info("      index 0x%016lx offset within mapping\n", page->index);
	pr_info("      SLUB: freelist req. slab lock 0x%px\n", page->freelist);
	pr_info("   }\n");
	pr_info("   lru list head next 0x%px prev 0x%px\n",
		page->lru.next, page->lru.prev);
#if defined(WANT_PAGE_VIRTUAL)
	pr_info("   kernel virtual address 0x%px\n", page->virtual);
#else   /* ! WANT_PAGE_VIRTUAL */
	pr_info("   kernel virtual address 0x%px\n", page_address(page));
#endif /* WANT_PAGE_VIRTUAL */
#ifdef CONFIG_WANT_PAGE_DEBUG_FLAGS
	pr_info("   debug flags 0x%016lx\n", page->debug_flags);
#endif
#if	defined(CONFIG_E2K) && defined(CONFIG_VIRTUALIZATION)
	pr_info("   kvm %px gfn 0x%lx user mapps %d\n",
		page->kvm, page->gfn, atomic_read(&page->user_maps));
#endif	/* CONFIG_E2K && CONFIG_VIRTUALIZATION */
}
#else	/* ! DUMP_PAGE_STRUCT */
void dump_page_struct(struct page *page)
{
}
#endif	/* DUMP_PAGE_STRUCT */

void kvm_arch_memslots_updated(struct kvm *kvm, u64 gen)
{
	/*
	 * memslots->generation has been incremented.
	 * mmio generation may have reached its maximum value.
	 */
	kvm_mmu_invalidate_mmio_sptes(kvm, gen);
}

void kvm_arch_sync_events(struct kvm *kvm)
{
	DebugKVM("started\n");
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	DebugKVMSH("%s (%d) started\n", current->comm, current->pid);

	if (current_thread_info()->virt_machine == NULL)
		current_thread_info()->virt_machine = kvm;
#ifdef	KVM_CAP_DEVICE_ASSIGNMENT
	kvm_free_all_assigned_devices(kvm);
#endif

	kvm_free_all_VIRQs(kvm);
	kvm_free_all_spmc(kvm);
	kvm_free_all_lt(kvm);
	/*
	 * Halting VCPU frees runstate, used by kvm timers.
	 * So PIC, LT, SPMC should be freed first
	 * FIXME: PIC is currently freed later, in kvm_arch_free_all_vcpus()
	 */
	kvm_arch_release_all_vcpus(kvm);
	kvm_halt_all_host_vcpus(kvm);
	kvm_free_host_info(kvm);
	kvm_nbsr_destroy(kvm);
	kvm_iopic_release(kvm);
	kvm_free_passthrough(kvm);
	kvm_free_epic_pages(kvm);
	if (kvm->arch.is_pv) {
		kvm_guest_pv_mm_destroy(kvm);
	}
//	kvm_release_vm_pages(kvm);
//	kvm_free_physmem(kvm);
	kvm_boot_spinlock_destroy(kvm);
	kvm_guest_spinlock_destroy(kvm);
	kvm_guest_csd_lock_destroy(kvm);
	if (kvm->arch.is_pv) {
		kvm_pv_guest_thread_info_destroy(kvm);
	}
	kvm_arch_free_all_vcpus(kvm);
	kvm_mmu_uninit_vm(kvm);
	kvm_page_track_cleanup(kvm);
	kvm_free_vmid(kvm);
	current_thread_info()->virt_machine = NULL;
}

void kvm_arch_vcpu_put(struct kvm_vcpu *vcpu, bool schedule)
{
	unsigned long flags;

	DebugKVMRUN("started on VCPU %d\n", vcpu->vcpu_id);
	trace_vcpu_put(vcpu->vcpu_id, vcpu->cpu);
	set_bit(KVM_REQ_KICK, (void *) &vcpu->requests);

	local_irq_save(flags);
	if (vcpu->arch.is_hv) {
		kvm_epic_timer_stop();
		kvm_epic_invalidate_dat(vcpu);
		machine.save_kvm_context(&vcpu->arch);
		kvm_epic_check_int_status(&vcpu->arch);
		kvm_epic_start_idle_timer(vcpu);
	}
	if (!schedule) {
		machine.save_gregs_dirty_bgr(&vcpu->arch.sw_ctxt.vcpu_gregs);
		copy_k_gregs_to_k_gregs(
			&vcpu->arch.sw_ctxt.vcpu_k_gregs,
			&current_thread_info()->k_gregs);
		machine.restore_gregs(&vcpu->arch.sw_ctxt.host_gregs);
		copy_k_gregs_to_k_gregs(
			&current_thread_info()->k_gregs,
			&vcpu->arch.sw_ctxt.host_k_gregs);
		if (vcpu->arch.is_hv) {
			;
		} else if (vcpu->arch.is_pv) {
			/* switch VCPU guset context to host context */
			pv_vcpu_exit_to_host(vcpu);
		} else {
			KVM_BUG_ON(true);
		}
	}
	local_irq_restore(flags);

	current_thread_info()->vcpu = NULL;
}

DEFINE_PER_CPU(struct kvm_vcpu *, last_vcpu) = NULL;

void kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu, bool schedule)
{
	int last_cpu = vcpu->cpu;
	unsigned long flags;

	DebugKVMRUN("started on VCPU %d CPU %d\n", vcpu->vcpu_id, cpu);

	current_thread_info()->vcpu = vcpu;
	vcpu->cpu = cpu;
	trace_vcpu_load(vcpu->vcpu_id, last_cpu, cpu);
	clear_bit(KVM_REQ_KICK, (void *) &vcpu->requests);

	local_irq_save(flags);
	if (cpu != last_cpu || per_cpu(last_vcpu, cpu) != vcpu) {
		/* bug 113981 comment 18: flush TLB/IB when moving
		 * to a new CPU to fix problems with GID reuse.
		 *
		 * bug 106525 comment 3: flush TLB/IB when changing
		 * VCPU on a real CPU, as MMU PIDs are per-cpu. */
		__flush_tlb_all();
		__flush_icache_all();
	}
	per_cpu(last_vcpu, cpu) = vcpu;

	if (vcpu->arch.is_hv) {
		kvm_epic_stop_idle_timer(vcpu);
		kvm_hv_epic_load(vcpu);
		machine.restore_kvm_context(&vcpu->arch);
		kvm_epic_timer_start();
		kvm_epic_enable_int();
	}
	if (!schedule) {
		machine.save_gregs_dirty_bgr(&vcpu->arch.sw_ctxt.host_gregs);
		copy_k_gregs_to_k_gregs(
			&vcpu->arch.sw_ctxt.host_k_gregs,
			&current_thread_info()->k_gregs);
		machine.restore_gregs(&vcpu->arch.sw_ctxt.vcpu_gregs);
		copy_k_gregs_to_k_gregs(
			&current_thread_info()->k_gregs,
			&vcpu->arch.sw_ctxt.vcpu_k_gregs);
		if (vcpu->arch.is_hv) {
			;
		} else if (vcpu->arch.is_pv) {
			/* switch VCPU host context to guest context */
			pv_vcpu_enter_to_guest(vcpu);
		} else {
			KVM_BUG_ON(true);
		}
	}
	local_irq_restore(flags);
}
void kvm_arch_vcpu_to_wait(struct kvm_vcpu *vcpu)
{
	clear_bit(KVM_REQ_KICK, (void *) &vcpu->requests);
}
void kvm_arch_vcpu_to_run(struct kvm_vcpu *vcpu)
{
	set_bit(KVM_REQ_KICK, (void *) &vcpu->requests);
}
static int kvm_vcpu_ioctl_get_lapic(struct kvm_vcpu *vcpu,
				    struct kvm_lapic_state *s)
{
	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);
	memcpy(s->regs, vcpu->arch.apic->regs, sizeof *s);
	return 0;
}

static int kvm_vcpu_ioctl_set_lapic(struct kvm_vcpu *vcpu,
				    struct kvm_lapic_state *s)
{
	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);
	memcpy(vcpu->arch.apic->regs, s->regs, sizeof *s);
	return 0;
}

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);
	DebugKVM("does not implemented\n");
	return 0;
}

static void kvm_arch_vcpu_release(struct kvm_vcpu *vcpu)
{
	DebugKVMSH("started for VCPU %d\n", vcpu->vcpu_id);

	kvm_init_guest_lapic_virqs_num(vcpu);
	kvm_cancel_clockdev(vcpu);
	free_vcpu_state(vcpu);
	if (!vcpu->arch.is_hv) {
		complete(&vcpu->arch.released);
	}
}
void kvm_arch_vcpu_free(struct kvm_vcpu *vcpu)
{
	DebugKVMSH("started for VCPU %d\n", vcpu->vcpu_id);

	kvm_arch_vcpu_destroy(vcpu);
}

void kvm_arch_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	DebugKVMSH("started for VCPU %d\n", vcpu->vcpu_id);

	vcpu->arch.halted = true;
	kvm_arch_pv_vcpu_uninit(vcpu);
	kvm_arch_vcpu_ctxt_uninit(vcpu);
	kvm_arch_hv_vcpu_uninit(vcpu);
	kvm_arch_any_vcpu_uninit(vcpu);
	/* free hypervisor backup hardware stacks */
	free_kernel_backup_stacks(&vcpu->arch.hypv_backup);
	/* free VCPU booting stacks */
	free_vcpu_boot_stacks(vcpu);
	destroy_vcpu_host_context(vcpu);
	kvm_free_local_pic(vcpu);
	kvm_mmu_destroy(vcpu);
}

long kvm_arch_vcpu_ioctl(struct file *filp,
			 unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;
	long r;
	struct kvm_lapic_state *lapic = NULL;

	DebugKVM("started for VCPU %d ioctl 0x%x\n", vcpu->vcpu_id, ioctl);
	switch (ioctl) {
	case KVM_SETUP_VCPU:
		DebugKVM("ioctl is KVM_SETUP_VCPU\n");
		r = kvm_arch_ioctl_setup_vcpu(vcpu);
		break;
	case KVM_VCPU_GUEST_STARTUP: {
		kvm_vcpu_guest_startup_t __user *guest_startup;

		DebugKVM("ioctl is KVM_VCPU_GUEST_STARTUP\n");
		guest_startup = (kvm_vcpu_guest_startup_t __user *)argp;
		r = kvm_arch_ioctl_vcpu_guest_startup(vcpu, guest_startup);
		break;
	}
	case KVM_INTERRUPT: {
		struct kvm_interrupt irq;

		DebugKVM("ioctl is KVM_INTERRUPT\n");
		r = -EFAULT;
		if (copy_from_user(&irq, argp, sizeof irq))
			goto out;
		r = kvm_vcpu_ioctl_interrupt(vcpu, irq.irq);
		if (r)
			goto out;
		r = 0;
		break;
	}
	case KVM_GET_LAPIC: {
		DebugKVM("ioctl is KVM_GET_LAPIC\n");
		r = -EINVAL;
		if (!vcpu->arch.apic)
			goto out;
		lapic = kzalloc(sizeof(struct kvm_lapic_state), GFP_KERNEL);

		r = -ENOMEM;
		if (!lapic)
			goto out;
		r = kvm_vcpu_ioctl_get_lapic(vcpu, lapic);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, lapic, sizeof(struct kvm_lapic_state)))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_LAPIC: {
		r = -EINVAL;
		DebugKVM("ioctl is KVM_SET_LAPIC\n");
		if (!vcpu->arch.apic)
			goto out;
		lapic = kmalloc(sizeof(struct kvm_lapic_state), GFP_KERNEL);
		r = -ENOMEM;
		if (!lapic)
			goto out;
		r = -EFAULT;
		if (copy_from_user(lapic, argp, sizeof(struct kvm_lapic_state)))
			goto out;
		r = kvm_vcpu_ioctl_set_lapic(vcpu, lapic);
		if (r)
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_VAPIC_ADDR: {
		struct kvm_vapic_addr va;
		DebugKVM("ioctl is KVM_SET_VAPIC_ADDR\n");

		r = -EINVAL;
		if (!irqchip_in_kernel(vcpu->kvm))
			goto out;
		r = -EFAULT;
		if (copy_from_user(&va, argp, sizeof va))
			goto out;
		r = 0;
		kvm_pic_set_vapic_addr(vcpu, va.vapic_addr);
		break;
	}
	default:
		r = -EINVAL;
	}
out:
	return r;
}

static unsigned int
calculate_memory_region_flags(struct kvm_memory_slot *memslot,
						unsigned int flags)
{
	gfn_t base_gfn = memslot->base_gfn;
	e2k_addr_t user_addr = memslot->userspace_addr;

	if (flags & KVM_MEM_TYPE_MASK) {
		/* flags of memory type is already set */
		goto out;
	}
	if (likely(kvm_is_ram_gfn(base_gfn))) {
		if (user_addr >= GUEST_RAM_VIRT_BASE &&
			user_addr < GUEST_RAM_VIRT_BASE +
						GUEST_MAX_RAM_SIZE)
			/* it is guest kernel virtual address */
			/* to map physical RAM */
			flags = KVM_MEM_VCPU_RAM;
		else
			/* it is user application of host (QEMU) address */
			/* to map IO-MEM (probably to emulate frame buffer */
			flags = KVM_MEM_USER_RAM;
	} else if (kvm_is_vcpu_vram_gfn(base_gfn)) {
		if (user_addr >= GUEST_VCPU_VRAM_VIRT_BASE &&
			user_addr < GUEST_VCPU_VRAM_VIRT_BASE +
						GUEST_MAX_VCPU_VRAM_SIZE)
			/* it is guest kernel virtual address to map VRAM */
			flags = KVM_MEM_VCPU_VRAM;
		else
			/* it is unknown address to map VRAM */
			BUG_ON(true);
	} else if (kvm_is_io_vram_gfn(base_gfn)) {
		if (user_addr >= GUEST_IO_VRAM_VIRT_BASE &&
			user_addr < GUEST_IO_VRAM_VIRT_BASE +
						GUEST_IO_VRAM_SIZE)
			/* it is guest kernel virtual address to map IO-VRAM */
			flags = KVM_MEM_IO_VRAM;
		else
			/* it is user application of host (QEMU) address */
			/* to map IO-VRAM (probably to emulate frame buffer */
			flags = KVM_MEM_USER_RAM;
	} else {
		/* it is unknown guest physical page # */
		BUG_ON(true);
	}

out:
	return flags & KVM_MEM_TYPE_MASK;
}

int kvm_arch_prepare_memory_region(struct kvm *kvm,
				struct kvm_memory_slot *memslot,
				const struct kvm_userspace_memory_region *mem,
				enum kvm_mr_change change)
{
	int slot = memslot->id;
	unsigned long guest_size = mem->memory_size;
	int npages = guest_size >> PAGE_SHIFT;
	unsigned int flags = mem->flags;
	gfn_t base_gfn = memslot->base_gfn;
	unsigned long guest_start = memslot->userspace_addr;
	unsigned long guest_end = guest_start + (npages << PAGE_SHIFT);
	user_area_t *guest_area = NULL;
	int node_id;

	DebugKVM("slot %d: base pfn 0x%llx guest virtual from 0x%lx to 0x%lx\n",
		slot, base_gfn, guest_start, guest_end);

	if ((flags & KVM_MEM_TYPE_MASK) == 0)
		flags |= calculate_memory_region_flags(memslot, flags);
	if (memslot->userspace_addr == 0) {
		printk(KERN_ERR "kvm_arch_set_memory_region() slot %d: base "
			"gfn 0x%llx size 0x%x pages is not allocated by user "
			"and cannot be used\n",
			slot, base_gfn, npages);
		return -ENOENT;
	}
	if (flags & KVM_MEM_IO_VRAM) {
		memslot->arch.guest_areas.type = guest_io_vram_mem_type;
		DebugKVM("memory region from 0x%lx to 0x%lx is IO-VRAM\n",
			guest_start, guest_end);
	} else if (flags & KVM_MEM_VCPU_VRAM) {
		memslot->arch.guest_areas.type = guest_vram_mem_type;
		DebugKVM("memory region from 0x%lx to 0x%lx is VRAM\n",
			guest_start, guest_end);
	} else if (flags & KVM_MEM_USER_RAM) {
		memslot->arch.guest_areas.type = guest_user_ram_mem_type;
		DebugKVM("memory region from 0x%lx to 0x%lx is USER-RAM\n",
			guest_start, guest_end);
	} else if (flags & KVM_MEM_VCPU_RAM) {
		memslot->arch.guest_areas.type = guest_ram_mem_type;
		DebugKVM("memory region from 0x%lx to 0x%lx is guest RAM\n",
			guest_start, guest_end);
	} else {
		BUG_ON(true);
	}

	if (change == KVM_MR_DELETE) {
		DebugKVM("memory region should be deleted (some later)\n");
		return 0;
	} else if (change == KVM_MR_FLAGS_ONLY) {
		DebugKVM("should be changed only flags of region: "
			"is not implemented\n");
		return -EINVAL;
	} else if (change == KVM_MR_MOVE) {
		DebugKVM("memory region should be moved\n");
	} else if (change == KVM_MR_CREATE) {
		DebugKVM("memory region should be created\n");
	} else {
		DebugKVM("unknown operation %d for memory region\n",
			change);
		return -EINVAL;
	}

	guest_area = memslot->arch.guest_areas.area;

	/* KVM_MEM_USER_RAM is used by VFIO for mapping PCI BARs for guest */
	if (flags & KVM_MEM_IO_VRAM) {
		DebugKVM("guest area support for this type of memory is not "
			"used, so do not create\n");
		BUG_ON(guest_area != NULL);
		goto out;
	}
	if (guest_area == NULL) {
		guest_area = user_area_create(guest_start, guest_size,
						USER_AREA_ORDERED);
		if (guest_area == NULL) {
			printk(KERN_ERR "kvm_arch_set_memory_region() slot %d: "
				"base gfn 0x%llx guest virtual from 0x%lx "
				"to 0x%lx could not create guest area "
				"support\n",
				slot, base_gfn, guest_start, guest_end);
			return -ENOENT;
		}
		memslot->arch.guest_areas.area = guest_area;
		DebugKVM("created guest area support at %px from 0x%lx "
			"to 0x%lx\n",
			guest_area,
			guest_area->area_start, guest_area->area_end);

		if (flags & KVM_MEM_VCPU_RAM) {
			for (node_id = 0; node_id < kvm->arch.num_numa_nodes;
								node_id++) {
				nbsr_setup_memory_region(kvm->arch.nbsr,
					node_id, gfn_to_gpa(base_gfn),
								guest_size);
				DebugKVM("setup NBSR routers for node #%d "
				"memory region from 0x%llx to 0x%llx\n",
				node_id, gfn_to_gpa(base_gfn),
				gfn_to_gpa(base_gfn) + guest_size);
			}
		}
	} else {
		DebugKVM("guest area support was already created "
			"at %px from 0x%lx to 0x%lx\n",
			guest_area,
			guest_area->area_start, guest_area->area_end);
	}
out:
	return 0;
}

int kvm_gva_to_memslot_unaliased(struct kvm *kvm, gva_t gva)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	struct kvm_memory_slot *memslot;

	DebugKVMPF("started for guest addr 0x%lx\n", gva);
	kvm_for_each_memslot(memslot, slots) {
		DebugKVMPF("current slot #%d base addr 0x%lx size 0x%lx\n",
			memslot->id, memslot->userspace_addr,
			memslot->npages << PAGE_SHIFT);
		if (gva >= memslot->userspace_addr &&
			gva < memslot->userspace_addr +
					(memslot->npages << PAGE_SHIFT))
			return memslot->id;
	}
	DebugKVMPF("guest addres 0x%lx not found\n", gva);
	return -1;
}

static int gva_to_alias_slot(struct kvm *kvm, gva_t gva)
{
	int i;

	DebugKVMPF("started for guest addr 0x%lx\n", gva);
	for (i = 0; i < kvm->arch.naliases; ++i) {
		kvm_mem_alias_t *alias_slot = &kvm->arch.aliases[i];
		unsigned long alias_start = alias_slot->alias_start;

		DebugKVMPF("current slot #%d start addr 0x%lx end 0x%lx\n",
			i, alias_start,
			alias_start + (alias_slot->npages << PAGE_SHIFT));
		if (gva >= alias_start &&
			gva < alias_start + (alias_slot->npages << PAGE_SHIFT))
			return i;
	}
	DebugKVMPF("guest addres 0x%lx not found\n", gva);
	return -1;
}

static gva_t kvm_unalias_gva(struct kvm *kvm, gva_t gva)
{
	kvm_mem_alias_t *alias;
	int slot;

	DebugKVMPF("started for guest addr 0x%lx\n", gva);

	slot = gva_to_alias_slot(kvm, gva);
	if (slot < 0) {
		DebugKVMPF("could not find alias slot for address 0x%lx\n",
			gva);
		return gva;
	}
	alias = &kvm->arch.aliases[slot];
	return alias->target_start + (gva - alias->alias_start);
}
/*
 * convert guest virtual address to guest virtual physical address:
 *	GUEST_PAGE_OFFSET + gfn(gva)
 */
gva_t kvm_gva_to_gpa(struct kvm *kvm, gva_t gva)
{
	int slot;
	gva_t gpa;

	DebugKVMPF("started for guest addr 0x%lx\n", gva);

	gpa = kvm_unalias_gva(kvm, gva);
	slot = kvm_gva_to_memslot_unaliased(kvm, gpa);
	if (slot < 0) {
		DebugKVMPF("could not find memory slot for address 0x%lx\n",
			gpa);
		return (gva_t)-1;
	}
	DebugKVMPF("guest virtual address 0x%lx is virtual physical "
		"address 0x%lx\n", gva, gpa);
	return gpa;
}
gpa_t kvm_vcpu_gva_to_gpa(struct kvm_vcpu *vcpu, gva_t gva, u32 access,
				kvm_arch_exception_t *exception)
{
	gva_t gvpa = kvm_gva_to_gpa(vcpu->kvm, gva);

	if (gvpa == (gva_t)-1)
		return UNMAPPED_GVA;
	return kvm_mmu_gvpa_to_gpa(gvpa);
}

static user_area_t *kvm_do_find_memory_region(struct kvm *kvm,
			int slot, e2k_addr_t address, e2k_size_t size,
			bool phys_mem, e2k_addr_t *virt_address,
			kvm_guest_mem_type_t type)
{
	struct kvm_memory_slot *memslot;
	user_area_t *guest_area;
	kvm_guest_mem_type_t guest_type;
	gpa_t base_gpa;
	e2k_size_t area_size;
	int id, as_id, as_id_from, as_id_to;

	DebugKVM("started for slot %d address 0x%lx size 0x%lx type %s\n",
		slot, address, size,
		(type & guest_vram_mem_type) ? "VRAM" : "RAM");
	if (slot >= 0) {
		if (slot >= KVM_USER_MEM_SLOTS) {
			DebugKVM("slot %d is outside of slots number %d\n",
				slot, KVM_USER_MEM_SLOTS);
			return NULL;
		}
		as_id = slot >> 16;
		id = (u16)slot;
		as_id_from = as_id;
		as_id_to = as_id;
	} else {
		id = -1;
		as_id_from = 0;
		as_id_to = KVM_ADDRESS_SPACE_NUM - 1;
	}
	if (type == 0)
		type = guest_ram_mem_type;

	for (as_id = as_id_from; as_id <= as_id_to; as_id++) {
		kvm_for_each_memslot(memslot, __kvm_memslots(kvm, as_id)) {
			if ((id >= 0) && (id != memslot->id)) {
				DebugKVM("slot %d is not slot to find %d\n",
					memslot->id, id);
				continue;
			}
			if (memslot->arch.guest_areas.area == NULL) {
				DebugKVM("slot %d is empty\n", memslot->id);
				continue;
			}
			guest_type = memslot->arch.guest_areas.type;
			if ((guest_type & type) == 0) {
				DebugKVM("slot %d has other memory type "
					"0x%x != 0x%x to find\n",
					memslot->id, guest_type, type);
				continue;
			}
			guest_area = memslot->arch.guest_areas.area;
			if (phys_mem) {
				base_gpa = gfn_to_gpa(memslot->base_gfn);
				area_size = guest_area->area_end -
						guest_area->area_start;
				if (address < base_gpa ||
					address + size >
						base_gpa + area_size) {
					DebugKVM("start phys address 0x%lx "
						"or end 0x%lx is outside of "
						"slot #%d region from 0x%llx "
						"to 0x%llx\n",
						address, address + size,
						memslot->id,
						base_gpa,
						base_gpa + area_size);
					continue;
				}
				/* convert physical address to virtual */
				/* address of area */
				address = guest_area->area_start +
						(address - base_gpa);
			}
			if (address != 0 &&
				(address < guest_area->area_start ||
					address >= guest_area->area_end)) {
				DebugKVM("address 0x%lx outside of slot #%d "
					"region from 0x%lx to 0x%lx\n",
					address, memslot->id,
					guest_area->area_start,
					guest_area->area_end);
				continue;
			}
			if (size > guest_area->area_end -
						guest_area->area_start) {
				DebugKVM("size 0x%lx of slot #%d < memory "
					"region size 0x%lx to find\n",
					size, memslot->id,
					guest_area->area_end -
						guest_area->area_start);
				continue;
			}
			DebugKVM("found memory region from 0x%lx to 0x%lx "
				"at slot #%d\n",
				guest_area->area_start, guest_area->area_end,
				memslot->id);
			if (phys_mem && virt_address != NULL)
				*virt_address = address;
			return guest_area;
		}
	}
	DebugKVM("could not find any suitable memory slot\n");
	return NULL;
}

static user_area_t *kvm_find_memory_region(struct kvm *kvm,
			int slot, e2k_addr_t address, e2k_size_t size,
			kvm_guest_mem_type_t type)
{
	return kvm_do_find_memory_region(kvm, slot, address, size,
			false, /* phys memory ? */ NULL, type);
}

static user_area_t *kvm_find_phys_memory_region(struct kvm *kvm,
			int slot, gpa_t gpa, e2k_size_t size,
			e2k_addr_t *virt_address, kvm_guest_mem_type_t type)
{
	return kvm_do_find_memory_region(kvm, slot, gpa, size,
			true, /* phys memory ? */ virt_address, type);
}

int kvm_find_shadow_slot(struct kvm *kvm, int slot, e2k_addr_t kernel_addr,
				gva_t shadow_addr)
{
	e2k_addr_t kernel_index;
	gva_t shadow_index;
	int i;

	DebugKVMPVF("started for kernel addr 0x%lx, guest shadow addr 0x%lx, "
		"slot %d\n",
		kernel_addr, shadow_addr, slot);
	kernel_index = kernel_addr & PGDIR_MASK;
	shadow_index = shadow_addr & PGDIR_MASK;
	for (i = slot; i < kvm->arch.nshadows; i++) {
		kvm_kernel_shadow_t *shadow = &kvm->arch.shadows[i];
		e2k_addr_t kernel_base = shadow->kernel_start;
		gva_t shadow_base = shadow->shadow_start;

		DebugKVMPVF("current slot #%d kernel base 0x%lx, shadow base "
			"0x%lx, size 0x%lx\n",
			i, kernel_base, shadow_base, shadow->area_size);
		if (kernel_index == (kernel_base & PGDIR_MASK)) {
			DebugKVMPVF("kernel index found at slot %d\n", i);
			return i;
		}
		if (shadow_index == (shadow_base & PGDIR_MASK)) {
			DebugKVMPVF("shadow index found at slot %d\n", i);
			return i;
		}
	}
	DebugKVMPVF("guest shadow not found\n");
	return -1;
}

static int find_shadow_intersection(struct kvm *kvm, e2k_addr_t kernel_base,
		gva_t shadow_base, e2k_size_t area_size)
{
	e2k_addr_t kernel_index;
	e2k_addr_t shadow_index;
	int slot;

	DebugKVM("started for kernel base 0x%lx, guest shadow base 0x%lx, "
		"size 0x%lx\n", kernel_base, shadow_base, area_size);
	kernel_index = kernel_base & PGDIR_MASK;
	shadow_index = shadow_base & PGDIR_MASK;
	slot = kvm_find_shadow_slot(kvm, 0, kernel_base, shadow_base);
	while (slot >= 0) {
		kvm_kernel_shadow_t *shadow = &kvm->arch.shadows[slot];
		e2k_addr_t kernel_start = shadow->kernel_start;
		e2k_addr_t shadow_start = shadow->shadow_start;
		e2k_size_t size = shadow->area_size;

		DebugKVM("shadow address find at slot %d: kernel start "
			"0x%lx shadow 0x%lx, size 0x%lx\n",
			slot, kernel_start, shadow_start, size);
		if (shadow_base >= shadow_start &&
			shadow_base < shadow_start + size) {
			DebugKVM("shadow address intersection\n");
			return 1;
		}
		if (kernel_base >= kernel_start &&
			kernel_base < kernel_start + size) {
			DebugKVM("kernel address intersection\n");
			return 1;
		}
		if (kernel_index != (kernel_start & PGDIR_MASK) ||
			shadow_index != (shadow_start & PGDIR_MASK)) {
			DebugKVM("different PGD lines\n");
			return 1;
		}
		slot++;
		slot = kvm_find_shadow_slot(kvm, slot, kernel_base,
						shadow_base);
	}
	return 0;
}

static long kvm_arch_ioctl_alloc_guest_area(struct kvm *kvm,
				kvm_guest_area_alloc_t __user *what)
{
	kvm_guest_area_alloc_t guest_chunk;
	user_area_t *guest_area;
	e2k_addr_t region_addr;
	e2k_addr_t size;
	kvm_guest_mem_type_t type;
	bool phys_mem = false;
	unsigned long flags;
	void *chunk;
	int ret = 0;

	if (copy_from_user(&guest_chunk, what, sizeof(guest_chunk))) {
		DebugKVM("copy to %px from user %px failed\n",
			&guest_chunk, what);
		return -EFAULT;
	}
	DebugKVM("started for region %px, start 0x%lx, size 0x%lx type %s "
		"align 0x%lx\n",
		guest_chunk.region, guest_chunk.start, guest_chunk.size,
		(guest_chunk.type & guest_vram_mem_type) ? "VRAM" : "RAM",
		guest_chunk.align);
	size = guest_chunk.size;
	type = guest_chunk.type;
	if (type == 0)
		type = guest_ram_mem_type;
	if (type & guest_ram_mem_type) {
		if (test_kvm_mode_flag(kvm, KVMF_VCPU_STARTED)) {
			/* VCPUs started and RAM is now allocated by */
			/* only guest kernel */
			type &= ~guest_ram_mem_type;
			if (type == 0)
				return -ENOMEM;
		}
	}
	if (guest_chunk.region != NULL) {
		region_addr = (e2k_addr_t)guest_chunk.region;
	} else if (guest_chunk.start != 0) {
		region_addr = guest_chunk.start;
		phys_mem = true;
	} else {
		region_addr = 0;
	}
	/* FIXME: mutex cannot be locked here, because of following */
	/* user_alloc_xxx() functions take this mutex too. */
	/* Now memory slots only are created and deleted and not updated, */
	/* so guest_area cannot be updated by someone else and slots_lock */
	/* mutex can be not locked */
	/* But some sychronization should be made to use of memory balloon */
	/* functionality. Probably it can be get_xxx()/put_xxx() -> */
	/* free_xxx() type mechanism to lock guest_area & memory slot */
	/* updates */
/*	mutex_lock(&kvm->slots_lock); */
	if (!phys_mem) {
		guest_area = kvm_find_memory_region(kvm, -1, region_addr,
					size, type);
	} else {
		guest_area = kvm_find_phys_memory_region(kvm, -1, region_addr,
					size, &guest_chunk.start, type);
	}
	if (guest_area == NULL) {
		DebugKVM("could not find memory region for address 0x%lx\n",
			region_addr);
		ret = -EINVAL;
		goto out_unlock;
	}
	flags = guest_chunk.flags;
	if (flags & KVM_ALLOC_AREA_PRESENT) {
		chunk = user_area_alloc_present(guest_area, guest_chunk.start,
				guest_chunk.size, guest_chunk.align, flags);
	} else if (flags & KVM_ALLOC_AREA_ZEROED) {
		chunk = user_area_alloc_zeroed(guest_area, guest_chunk.start,
				guest_chunk.size, guest_chunk.align, flags);
	} else if (flags & KVM_ALLOC_AREA_LOCKED) {
		chunk = user_area_alloc_locked(guest_area, guest_chunk.start,
				guest_chunk.size, guest_chunk.align, flags);
	} else {
		chunk = user_area_get(guest_area, guest_chunk.start,
				guest_chunk.size, guest_chunk.align, flags);
	}
	if (chunk == NULL) {
		DebugKVM("could not allocate guest area size of 0x%lx\n",
			guest_chunk.size);
		ret = -ENOMEM;
		goto out_unlock;
	}
	DebugKVM("allocated guest area from %px, size of 0x%lx\n",
		chunk, guest_chunk.size);
	guest_chunk.area = chunk;
	if (copy_to_user(what, &guest_chunk, sizeof(guest_chunk))) {
		DebugKVM("copy from %px to user %px failed\n",
			what, &guest_chunk);
		user_area_free_chunk(guest_area, chunk);
		ret = -EFAULT;
		goto out_unlock;
	}
out_unlock:
/*	mutex_unlock(&kvm->slots_lock); see FIXME above */
	return ret;
}

void kvm_arch_flush_shadow_all(struct kvm *kvm)
{
	DebugKVM("started\n");
	kvm_flush_remote_tlbs(kvm);
	kvm_mmu_invalidate_zap_all_pages(kvm);
}

void kvm_arch_sched_in(struct kvm_vcpu *vcpu, int cpu)
{
	/* now is empty, probable can be implemented */
}

long kvm_arch_ioctl_get_guest_address(unsigned long __user *addr)
{
	unsigned long address = -1;
	long r;

	r = get_user(address, addr);
	if (r) {
		DebugKVM("get_user() failed for user address 0x%lx\n", addr);
		return r;
	}
	DebugKVM("started for address 0x%lx\n", addr);
	switch (address) {
	case KVM_GUEST_PAGE_OFFSET:
		DebugKVM("address is KVM_GUEST_PAGE_OFFSET\n");
		address = GUEST_PAGE_OFFSET;
		break;
	case KVM_GUEST_KERNEL_IMAGE_BASE:
		DebugKVM("address is KVM_GUEST_KERNEL_IMAGE_BASE\n");
		address = GUEST_KERNEL_IMAGE_AREA_BASE;
		break;
	case KVM_GUEST_VCPU_VRAM_PHYS_BASE:
		DebugKVM("address is KVM_GUEST_VCPU_VRAM_PHYS_BASE\n");
		address = GUEST_VCPU_VRAM_PHYS_BASE;
		break;
	case KVM_GUEST_VCPU_VRAM_VIRT_BASE:
		DebugKVM("address is KVM_GUEST_VCPU_VRAM_VIRT_BASE\n");
		address = GUEST_VCPU_VRAM_VIRT_BASE;
		break;
	case KVM_GUEST_VCPU_VRAM_SIZE:
		DebugKVM("address is KVM_GUEST_VCPU_VRAM_SIZE\n");
		address = GUEST_ONE_VCPU_VRAM_SIZE;
		break;
	case KVM_GUEST_IO_VRAM_PHYS_BASE:
		DebugKVM("address is KVM_GUEST_IO_VRAM_PHYS_BASE\n");
		address = GUEST_IO_VRAM_PHYS_BASE;
		break;
	case KVM_GUEST_IO_VRAM_VIRT_BASE:
		DebugKVM("address is KVM_GUEST_IO_VRAM_VIRT_BASE\n");
		address = GUEST_IO_VRAM_VIRT_BASE;
		break;
	case KVM_GUEST_IO_VRAM_SIZE:
		DebugKVM("address is KVM_GUEST_IO_VRAM_SIZE\n");
		address = GUEST_IO_VRAM_SIZE;
		break;
	case KVM_GUEST_IO_PORTS_BASE:
		DebugKVM("address is KVM_GUEST_IO_PORTS_BASE\n");
		address = GUEST_IO_PORTS_VIRT_BASE;
		break;
	case KVM_GUEST_NBSR_BASE_NODE_0:
		DebugKVM("address is KVM_GUEST_NBSR_BASE_NODE_0\n");
		address = (unsigned long)THE_NODE_NBSR_PHYS_BASE(0);
		break;
	case KVM_GUEST_NBSR_BASE_NODE_1:
		DebugKVM("address is KVM_GUEST_NBSR_BASE_NODE_1\n");
		address = (unsigned long)THE_NODE_NBSR_PHYS_BASE(1);
		break;
	case KVM_GUEST_NBSR_BASE_NODE_2:
		DebugKVM("address is KVM_GUEST_NBSR_BASE_NODE_2\n");
		address = (unsigned long)THE_NODE_NBSR_PHYS_BASE(2);
		break;
	case KVM_GUEST_NBSR_BASE_NODE_3:
		DebugKVM("address is KVM_GUEST_NBSR_BASE_NODE_3\n");
		address = (unsigned long)THE_NODE_NBSR_PHYS_BASE(3);
		break;
	case KVM_HOST_PAGE_OFFSET:
		DebugKVM("address is KVM_HOST_PAGE_OFFSET\n");
		address = HOST_PAGE_OFFSET;
		break;
	case KVM_HOST_KERNEL_IMAGE_BASE:
		DebugKVM("address is KVM_HOST_KERNEL_IMAGE_BASE\n");
		address = HOST_KERNEL_IMAGE_AREA_BASE;
		break;
	case KVM_KERNEL_AREAS_SIZE:
		DebugKVM("address is KVM_KERNEL_AREAS_SIZE\n");
		address = E2K_KERNEL_AREAS_SIZE;
		break;
	case KVM_SHADOW_KERNEL_IMAGE_BASE:
		DebugKVM("address is KVM_SHADOW_KERNEL_IMAGE_BASE\n");
		address = SHADOW_KERNEL_IMAGE_AREA_BASE;
		break;
	default:
		DebugKVM("ioctl is unsupported\n");
		return -EINVAL;
	}
	DebugKVM("returns address 0x%lx\n", address);
	r = put_user(address, addr);
	if (r) {
		DebugKVM("put_user() failed for user address 0x%lx\n", addr);
	}
	DebugKVM("returns with value %ld\n", r);
	return r;
}

long kvm_arch_dev_ioctl(struct file *filp,
			unsigned int ioctl, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	long r;

	DebugKVM("started for ioctl 0x%x\n", ioctl);
	switch (ioctl) {
	case KVM_GET_GUEST_ADDRESS: {
		unsigned long __user *p = argp;

		DebugKVM("ioctl is KVM_GET_GUEST_ADDRESS\n");
		r = kvm_arch_ioctl_get_guest_address(p);
		break;
	}
	default:
		DebugKVM("ioctl is unsupported\n");
		r = -EINVAL;
	}
	DebugKVM("returns with value %ld\n", r);
	return r;
}

static bool cpu_has_kvm_support(void)
{
	if (kvm_is_guest_pv_vm())
		/* it is guest and it cannot support own virtual machines */
		return false;

#ifdef	CONFIG_KVM_PARAVIRTUALIZATION
	/* software virtualization is enable */
	kvm_vm_types_available = KVM_E2K_SV_VM_TYPE_MASK;
#ifdef	CONFIG_PARAVIRT_GUEST
	/* hypervisor is paravirtualized host and guest kernel */
	kvm_vm_types_available |= KVM_E2K_SW_PV_VM_TYPE_MASK;
#endif	/* CONFIG_PARAVIRT_GUEST */
#endif	/* CONFIG_KVM_PARAVIRTUALIZATION */

#ifdef	CONFIG_KVM_HW_VIRTUALIZATION
	if (kvm_is_hv_enable())
		kvm_vm_types_available |= KVM_E2K_HV_VM_TYPE_MASK;

	if (kvm_is_hw_pv_enable())
		kvm_vm_types_available |= KVM_E2K_HW_PV_VM_TYPE_MASK;
#endif	/* CONFIG_KVM_HW_VIRTUALIZATION */

	return kvm_vm_types_available != 0;
}

static inline bool cpu_virt_disabled(void)
{
	/* paravirtualization is enable at any case */
	/* hardware virtualization prohibition will be checked while creation */
	/* fully virtualized guest machines */
	return false;
}

struct work_struct kvm_dump_stacks;	/* to schedule work to dump */
					/* guest VCPU stacks */
int kvm_arch_init(void *opaque)
{
	int err;

	DebugKVM("started\n");

	if (!cpu_has_kvm_support()) {
		pr_err("KVM: no hardware and paravirtualization "
			"support\n");
		return -EOPNOTSUPP;
	}

	kvm_host_machine_setup(&machine);
	user_area_caches_init();
	err = kvm_vmidmap_init();
	if (err)
		goto out_free_caches;

	err = kvm_mmu_module_init();
	if (err)
		goto out_free_vmidmap;

	INIT_WORK(&kvm_dump_stacks, &wait_for_print_all_guest_stacks);

	return 0;

out_free_vmidmap:
	kvm_vmidmap_destroy();
out_free_caches:
	user_area_caches_destroy();
	return err;
}

void kvm_arch_exit(void)
{
	DebugKVM("started\n");
	kvm_mmu_module_exit();
	user_area_caches_destroy();
	kvm_vmidmap_destroy();
}

int kvm_vm_ioctl_get_dirty_log(struct kvm *kvm, struct kvm_dirty_log *log)
{
	int r;
	int n;
	struct kvm_memslots *slots = kvm_memslots(kvm);
	struct kvm_memory_slot *memslot;
	int is_dirty = 0;

	DebugKVM("started\n");
	mutex_lock(&kvm->slots_lock);

	r = kvm_get_dirty_log(kvm, log, &is_dirty);
	if (r)
		goto out;

	/* If nothing is dirty, don't bother messing with page tables. */
	if (is_dirty) {
		kvm_flush_remote_tlbs(kvm);
		memslot = id_to_memslot(slots, log->slot);
		n = ALIGN(memslot->npages, BITS_PER_LONG) / 8;
		memset(memslot->dirty_bitmap, 0, n);
	}
	r = 0;
out:
	mutex_unlock(&kvm->slots_lock);
	return r;
}

int kvm_arch_hardware_setup(void)
{
	DebugKVM("started\n");
	return 0;
}

void kvm_arch_hardware_unsetup(void)
{
	DebugKVM("started\n");
}

int kvm_arch_vcpu_should_kick(struct kvm_vcpu *vcpu)
{
	return 1;
}

bool kvm_arch_has_vcpu_debugfs(void)
{
	return false;
}

int kvm_arch_create_vcpu_debugfs(struct kvm_vcpu *vcpu)
{
	return 0;
}

gfn_t unalias_gfn(struct kvm *kvm, gfn_t gfn)
{
	DebugKVMPF("started for guest pfn 0x%llx\n", gfn);
	return gfn;
}

/* This is called from pv_wait hcall (CEPIC DAT is active) */
bool kvm_vcpu_has_epic_interrupts(struct kvm_vcpu *vcpu)
{
	union cepic_cir reg_cir;
	union cepic_pnmirr reg_pnmirr;

	/* Check mi_gst by reading CEPIC_CIR.stat */
	reg_cir.raw = epic_read_guest_w(CEPIC_CIR);
	if (!vcpu->arch.hcall_irqs_disabled && reg_cir.bits.stat)
		return true;

	/* Check nmi_gst by reading CEPIC_PNMIRR */
	reg_pnmirr.raw = epic_read_guest_w(CEPIC_PNMIRR);
	if (reg_pnmirr.raw & CEPIC_PNMIRR_BIT_MASK)
		return true;

	return false;
}

static inline bool kvm_vcpu_has_events(struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_has_pic_interrupts(vcpu);
}

int kvm_arch_vcpu_runnable(struct kvm_vcpu *vcpu)
{
	DebugKVMRUN("started for VCPU %d\n", vcpu->vcpu_id);
	return (vcpu->arch.mp_state == KVM_MP_STATE_RUNNABLE) ||
		vcpu->arch.unhalted || kvm_vcpu_has_events(vcpu);
}

int kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	DebugKVMRUN("started for VCPU %d\n", vcpu->vcpu_id);
	mp_state->mp_state = vcpu->arch.mp_state;
	return 0;
}

bool kvm_arch_vcpu_in_kernel(struct kvm_vcpu *vcpu)
{
	return false;
}

static int vcpu_reset(struct kvm_vcpu *vcpu)
{
	int r;

	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);
	vcpu->arch.launched = 0;
	kvm_arch_vcpu_uninit(vcpu);
	r = kvm_arch_vcpu_init(vcpu);
	if (r)
		goto fail;

	r = 0;
fail:
	return r;
}

int kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	int r = 0;

	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);
	vcpu->arch.mp_state = mp_state->mp_state;
	if (vcpu->arch.mp_state == KVM_MP_STATE_UNINITIALIZED)
		r = vcpu_reset(vcpu);
	return r;
}

struct kvm_e2k_info e2k_info = {
	.module			= THIS_MODULE,
};

static int __init kvm_e2k_init(void)
{
	DebugKVM("started\n");

	if (paravirt_enabled())
		/* it is guest virtual machine and guest cannot have */
		/* own guests and be virtualized */
		return -ENOENT;
	/*Register e2k VMM data to kvm side*/
	return kvm_init(&e2k_info, sizeof(struct kvm_vcpu),
				__alignof__(struct kvm_vcpu), THIS_MODULE);
}

static void __exit kvm_e2k_exit(void)
{
	DebugKVM("started\n");
	kvm_exit();
	return;
}
#else	/* ! CONFIG_KVM_HOST_MODE */
static int __init kvm_e2k_init(void)
{
	pr_info("support of KVM is OFF\n");
	return -ENOENT;
}

static void __exit kvm_e2k_exit(void)
{
}
#endif	/* CONFIG_KVM_HOST_MODE */

module_init(kvm_e2k_init)
module_exit(kvm_e2k_exit)
