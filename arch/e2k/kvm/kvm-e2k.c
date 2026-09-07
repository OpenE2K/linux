/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Basic KVM support On Elbrus series processors
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
#include <linux/pgtable.h>
#include <linux/entry-kvm.h>
#include <linux/platform_device.h>
#include <linux/of_irq.h>
#include <linux/sched/debug.h>

#include <asm/fpu/api.h>
#include <asm/process.h>
#include <asm/regs_state.h>
#include <asm/ptrace.h>
#include <asm/io.h>
#include <asm/e2k-iommu.h>
#include <asm/e2k_debug.h>
#include <asm/pic.h>
#include <asm/sclkr.h>
#include <asm/kvm.h>
#include <asm/kvm_host.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/mmu_hv_regs_types.h>
#include <asm/kvm/vcpu-descr-regs.h>
#include <asm/kvm/stacks.h>
#include <asm/kvm/page_track.h>
#include <asm/kvm/switch.h>
#include <asm/kvm/async_pf.h>
#include <asm/kvm/gregs.h>
#include <kvm/iodev.h>
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include <asm/kvm/paravirt_sw/boot.h>
#include <asm/kvm/paravirt_sw/gva_cache.h>
#include <asm/kvm/paravirt_sw/runstate.h>
# endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#ifdef	CONFIG_KVM_HOST_KERNEL

#define CREATE_TRACE_POINTS
# include <asm/kvm/trace_kvm.h>
# include <asm/kvm/trace_kvm_hv.h>
# ifdef CONFIG_KVM_PARAVIRTUALIZATION
# include "paravirt_sw/trace-gmm.h"
#  include <asm/kvm/trace_kvm_pv.h>
# endif /* CONFIG_KVM_PARAVIRTUALIZATION */
#undef	CREATE_TRACE_POINTS

#include "user_area.h"
#include "cpu.h"
#include "mmu.h"
#include "io.h"
#include "process.h"
#include "sic-nbsr.h"
#include "ioapic.h"
#include "pic.h"
#include "irq.h"
#include "lt.h"
#include "spmc.h"
# ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include "paravirt_sw/gaccess.h"
#include "paravirt_sw/time.h"
# endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_UNIMPL_MODE
#undef	DebugUNIMPL
#define	DEBUG_KVM_UNIMPL_MODE	0	/* unimplemeneted features debugging */
#define	DebugUNIMPL(fmt, args...)					\
({									\
	if (DEBUG_KVM_UNIMPL_MODE)					\
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

#undef	DEBUG_KVM_PAGE_FAULT_MODE
#undef	DebugKVMPF
#define	DEBUG_KVM_PAGE_FAULT_MODE	0	/* page fault on KVM */
#define	DebugKVMPF(fmt, args...)					\
({									\
	if (DEBUG_KVM_PAGE_FAULT_MODE)					\
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

#undef	DEBUG_KVM_IOCTL_MODE
#undef	DebugKVMIOCTL
#define	DEBUG_KVM_IOCTL_MODE	0	/* kernel IOCTL debug */
#define	DebugKVMIOCTL(fmt, args...)					\
({									\
	if (DEBUG_KVM_IOCTL_MODE || kvm_debug)				\
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

#undef	DEBUG_KVM_SHUTDOWN_MODE
#undef	DebugKVMSH
#define	DEBUG_KVM_SHUTDOWN_MODE	0	/* KVM shutdown debugging */
#define	DebugKVMSH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SHUTDOWN_MODE || kvm_debug)			\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_HV_MODE
#undef	DebugKVMHV
#define	DEBUG_KVM_HV_MODE	0	/* hardware virtualized VM debugging */
#define	DebugKVMHV(fmt, args...)					\
({									\
	if (DEBUG_KVM_HV_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	VM_BUG_ON
#define VM_BUG_ON(cond) BUG_ON(cond)

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("E2K arch virtualization driver based on KVM");
MODULE_LICENSE("GPL v2");

/* mask of available and supported by the hypervisor VM types */
/* depends on hardware, CPU ISET, kernel & hypervisor configuration */
unsigned int kvm_vm_types_available = 0;

static int kvm_reset_error = 0;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static int kvm_arch_pv_vcpu_init(struct kvm_vcpu *vcpu);
static void kvm_arch_pv_vcpu_uninit(struct kvm_vcpu *vcpu);
static int kvm_arch_pv_vcpu_setup(struct kvm_vcpu *vcpu);
static int kvm_arch_hv_vcpu_init(struct kvm_vcpu *vcpu);
static void kvm_arch_hv_vcpu_uninit(struct kvm_vcpu *vcpu);
static int kvm_arch_hv_vcpu_setup(struct kvm_vcpu *vcpu);
static int kvm_arch_any_vcpu_init(struct kvm_vcpu *vcpu);
static void kvm_arch_any_vcpu_uninit(struct kvm_vcpu *vcpu);
static int kvm_arch_any_vcpu_setup(struct kvm_vcpu *vcpu);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static user_area_t *kvm_find_memory_region(struct kvm *kvm,
					   int slot, e2k_addr_t address,
					   e2k_size_t size,
					   kvm_guest_mem_type_t type);
static long kvm_arch_ioctl_alloc_guest_area(struct kvm *kvm,
					    kvm_guest_area_alloc_t __user *
					    what);
void kvm_arch_vcpu_free(struct kvm_vcpu *vcpu);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static void kvm_arch_vcpu_release(struct kvm_vcpu *vcpu);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
static void vcpu_release_to_reboot(struct kvm_vcpu *vcpu, int order_no);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static void free_vcpu_state(struct kvm_vcpu *vcpu);
static int kvm_create_host_info(struct kvm *kvm);
static void kvm_free_host_info(struct kvm *kvm);
static int init_guest_vcpu_state(struct kvm_vcpu *vcpu);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
static int kvm_arch_vcpu_init(struct kvm_vcpu *vcpu);
static void kvm_arch_vcpu_uninit(struct kvm_vcpu *vcpu);
static int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu);


const struct _kvm_stats_desc kvm_vm_stats_desc[] = {
	KVM_GENERIC_VM_STATS()
};

const struct kvm_stats_header kvm_vm_stats_header = {
	.name_size = KVM_STATS_NAME_SIZE,
	.num_desc = ARRAY_SIZE(kvm_vm_stats_desc),
	.id_offset =  sizeof(struct kvm_stats_header),
	.desc_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE,
	.data_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE +
		       sizeof(kvm_vm_stats_desc),
};

const struct _kvm_stats_desc kvm_vcpu_stats_desc[] = {
	KVM_GENERIC_VCPU_STATS(),
};

const struct kvm_stats_header kvm_vcpu_stats_header = {
	.name_size = KVM_STATS_NAME_SIZE,
	.num_desc = ARRAY_SIZE(kvm_vcpu_stats_desc),
	.id_offset = sizeof(struct kvm_stats_header),
	.desc_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE,
	.data_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE +
		       sizeof(kvm_vcpu_stats_desc),
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
		 IDR.hw_virt_ver);
	return true;
}

static bool kvm_cpu_hv_disabled(void)
{
	if (read_CU_HW0_reg().virt_dsbl) {
		DebugKVM("CPUs hardware virtualization extensions are disabled\n");
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
		pr_err("KVM: hardware virtualization extentions are disabled\n");
		return false;
	}
	if (cpu_has(CPU_FEAT_GUEST)) {
		pr_err("KVM: hardware virtualized guest cannot run nested VM\n");
		return false;
	}
	return true;
}

/* Set up CEPIC_EPIC_INT (IPI delivery to inactive guest) */
static int kvm_setup_cepic_epic_int(void)
{
	int ret, vec = ~0;
	union cepic_epic_int epic_int;
	union cepic_ctrl2 ctrl2;

	ret = pic_get_vector_by_name(NULL, "/kvm", "CEPIC EPIC interrupts", &vec);
	if (ret) {
		pr_err("Failed to get cepic-epic vector: %d\n", ret);
		return ret;
	}

	epic_int.raw = 0;
	epic_int.vect = vec;
	epic_write_w(CEPIC_EPIC_INT, epic_int.raw);

	/* Also enable automatic generation of CEPIC_EPIC_INT on
	 * _current_ vcpu when IPI misses in DAT (i.e. when the
	 * _target_ vcpu is not running) */
	ctrl2.raw = epic_read_w(CEPIC_CTRL2);
	ctrl2.int_hv = 1;
	epic_write_w(CEPIC_CTRL2, ctrl2.raw);

	return 0;
}

static cpumask_t kvm_e2k_hardware_enabled;

static void prepic_set_virt_en(bool on)
{
	union prepic_ctrl2 reg_ctrl;
	int node;

	reg_ctrl.raw = 0;
	reg_ctrl.virt_en = !!on;
	if (epic_bgi_mode)
		reg_ctrl.bgi_mode = 1;

	for_each_online_node(node) {
	    prepic_node_write_w(node, SIC_prepic_ctrl2, reg_ctrl.raw);
	}
	DebugKVM("%s virtualization support in PREPIC. bgi_mode=%d\n",
		 (on) ? "Enabled" : "Disabled", epic_bgi_mode);
}

static int kvm_hardware_virt_enable(void)
{
	e2k_core_mode_t CORE_MODE;
	int ret;

	if (cpu_has(CPU_FEAT_EPIC)) {
		bool was_disabled = cpumask_empty(&kvm_e2k_hardware_enabled);
		if (was_disabled)
			prepic_set_virt_en(true);

		kvm_epic_timer_stop(true);

		ret = kvm_setup_cepic_epic_int();
		if (ret) {
			if (was_disabled)
				prepic_set_virt_en(false);
			return ret;
		}
	}

	/* set guest CORE_MODE register to allow of guest mode indicator */
	/* for guest kernels, so any VM software can see guest mode */
	CORE_MODE = read_SH_CORE_MODE_reg();
	CORE_MODE.gmi = 1;
	CORE_MODE.hci = 1;
	write_SH_CORE_MODE_reg(CORE_MODE);

	DebugKVM("KVM: CPU #%d: set guest CORE_MODE to indicate guest mode on any VMs\n",
			smp_processor_id());

	write_HCEM_reg_value(user_hcall_init());
	write_HCEB_reg_value((unsigned long)__hypercalls_begin);

	cpumask_set_cpu(smp_processor_id(), &kvm_e2k_hardware_enabled);

	return 0;
}

static void kvm_hardware_virt_disable(void)
{
	cpumask_clear_cpu(smp_processor_id(), &kvm_e2k_hardware_enabled);

	write_HCEM_reg_value(0);
	write_HCEB_reg_value(0);

	/* Since PREPIC might be in use right now, we cannot
	 * call `prepic_set_virt_en(false)` here. */
}
#else /* ! CONFIG_KVM_HW_VIRTUALIZATION */
static bool kvm_is_hv_enable(void)
{
	pr_err("KVM: hardware virtualization mode is turned OFF at kernel config\n");
	return false;
}

static int kvm_hardware_virt_enable(void)
{
	pr_err("KVM: hardware virtualization mode is turned OFF at kernel config\n");
	return -ENOTSUPP;
}

static void kvm_hardware_virt_disable(void)
{
	pr_err("KVM: hardware virtualization mode is turned OFF at kernel config\n");
}
#endif /* CONFIG_KVM_HW_VIRTUALIZATION */

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#ifdef	CONFIG_KVM_HW_PARAVIRTUALIZATION
static bool kvm_is_hw_pv_enable(void)
{
	if (!kvm_is_hv_enable())
		return false;
	return true;
}

#else /* ! CONFIG_KVM_HW_PARAVIRTUALIZATION */
static bool kvm_is_hw_pv_enable(void)
{
	pr_err("KVM: hardware paravirtualization mode is turned OFF at kernel config\n");
	return false;
}
#endif /* CONFIG_KVM_HW_PARAVIRTUALIZATION */
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

void kvm_arch_sync_dirty_log(struct kvm *kvm, struct kvm_memory_slot *memslot)
{
	/* Nothing to do */
}

void kvm_arch_flush_remote_tlbs_memslot(struct kvm *kvm,
					const struct kvm_memory_slot *memslot)
{
	/*
	 * All current use cases for flushing the TLBs for a specific memslot
	 * are related to dirty logging, and do the TLB flush out of mmu_lock.
	 * The interaction between the various operations on memslot must be
	 * serialized by slots_locks to ensure the TLB flush from one operation
	 * is observed by any other operation on the same memslot.
	 */
	lockdep_assert_held(&kvm->slots_lock);
	kvm_flush_remote_tlbs(kvm);
}

int kvm_arch_vcpu_precreate(struct kvm *kvm, unsigned int id)
{
	return 0;
}

int kvm_arch_hardware_enable(void)
{
	if (kvm_is_hv_vm_available()
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
			|| kvm_is_hw_pv_vm_available()
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
			) {
		return kvm_hardware_virt_enable();
	}
	return 0;
}

void kvm_arch_hardware_disable(void)
{
	DebugKVM("started\n");
	if (kvm_is_hv_vm_available()
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
			|| kvm_is_hw_pv_vm_available()
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
			) {
		kvm_hardware_virt_disable();
	}
}

int kvm_arch_check_processor_compat(void *opaque)
{
	DebugKVM("started\n");

	if (kvm_is_hv_vm_available() && !kvm_is_hv_enable()) {
		pr_err("KVM: CPU #%d has not hardware virtualization support\n",
		       raw_smp_processor_id());
		atomic_clear_mask(KVM_E2K_HV_VM_TYPE_MASK,
				  &kvm_vm_types_available);
	}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (kvm_is_hw_pv_vm_available() && !kvm_is_hw_pv_enable()) {
		pr_err("KVM: CPU #%d has not hardware paravirtualization support\n",
			raw_smp_processor_id());
		atomic_clear_mask(KVM_E2K_HW_PV_VM_TYPE_MASK, &kvm_vm_types_available);
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	if (kvm_vm_types_available == 0)
		return -EINVAL;
	else
		return 0;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static int create_vcpu_state(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	kvm_vcpu_state_t __user *vcpu_state = NULL;
	kvm_vcpu_state_t *kmap_vcpu_state = NULL;
	e2k_cute_t __user *cute_p = NULL;
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
	guest_area = kvm_find_memory_region(kvm, -1, 0, size, guest_vram_mem_type);
	if (guest_area == NULL) {
		DebugKVM("guest memory regions is not created or empty\n");
		return -EINVAL;
	}
	vcpu_state = user_area_alloc_locked_pages(guest_area, 0,
						  sizeof(kvm_vcpu_state_t),
						  1 << E2K_ALIGN_GLOBALS, 0);
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
							 vcpu_state,
							 PAGE_KERNEL);
	if (kmap_vcpu_state == NULL) {
		DebugKVM("could not map VCPU state struct to kernel VM\n");
		r = -ENOMEM;
		goto error;
	}

	memset(kmap_vcpu_state, 0, sizeof(kvm_vcpu_state_t));
	vcpu->arch.vcpu_state = vcpu_state;
	vcpu->arch.kmap_vcpu_state = kmap_vcpu_state;
	vcpu->arch.guest_vcpu_state = TO_GUEST_VCPU_STATE_POINTER(vcpu);
	if (IS_INVALID_GPA(vcpu->arch.guest_vcpu_state)) {
		pr_err("%s() : could not allocate GPA of VCPU state struct\n",
		       __func__);
		r = -ENOMEM;
		goto error;
	}
	kvm_setup_guest_VCPU_ID(vcpu, (const u32)vcpu->vcpu_id);

	if (cut_size == 0) {
		DebugKVM("VCPU #%d state struct allocated at 0x%llx\n",
			 vcpu->vcpu_id,
			 kvm_vcpu_hva_to_gpa(vcpu, (unsigned long) vcpu->arch.vcpu_state));
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
	if (clear_user(cute_p, PAGE_SIZE)) {
		DebugKVM("could not clear VCPU guest CUT\n");
		r = -EFAULT;
		goto error;
	}
	vcpu->arch.guest_cut = cute_p;
	if (IS_INVALID_GPA(kvm_vcpu_hva_to_gpa(vcpu, (unsigned long) cute_p))) {
		pr_err("%s() : could not allocate GPA of VCPU guest CUT\n",
		       __func__);
		r = -ENOMEM;
		goto error;
	}
	DebugKVM("VCPU #%d allocated state struct at %px, CUT at %px\n",
		 vcpu->vcpu_id,
		 (void *)kvm_vcpu_hva_to_gpa(vcpu, (unsigned long) vcpu->arch.vcpu_state),
		 (void *)kvm_vcpu_hva_to_gpa(vcpu, (unsigned long) vcpu->arch.guest_cut));

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
		area_start = (e2k_addr_t) vcpu->arch.vcpu_state;
		guest_area = kvm_find_memory_region(vcpu->kvm,
						    -1, area_start, 0,
						    guest_vram_mem_type);
		if (vcpu->arch.kmap_vcpu_state != NULL) {
			unmap_user_area_to_vmalloc_range(guest_area,
							 vcpu->
							 arch.kmap_vcpu_state);
			vcpu->arch.kmap_vcpu_state = NULL;
		}
		user_area_free_chunk(guest_area, vcpu->arch.vcpu_state);
		vcpu->arch.vcpu_state = NULL;
	} else if (vcpu->arch.kmap_vcpu_state != NULL) {
		unmap_user_area_to_vmalloc_range(NULL, vcpu->arch.kmap_vcpu_state);
		vcpu->arch.kmap_vcpu_state = NULL;
	}
	vcpu->arch.guest_vcpu_state = INVALID_GPA;

	if (vcpu->arch.guest_cut != NULL) {
		area_start = (e2k_addr_t) vcpu->arch.guest_cut;
		guest_area = kvm_find_memory_region(vcpu->kvm,
						    -1, area_start, 0,
						    guest_vram_mem_type);
		user_area_free_chunk(guest_area, vcpu->arch.guest_cut);
		vcpu->arch.guest_cut = NULL;
	}
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

/*
 * Functions to create all kernel backup hardware stacks(PS & PCS)
 * to support intercepts and hypercalls
 */
static inline void define_backup_hw_stacks_sizes(bu_hw_stack_t *hypv_backup)
{
	hypv_backup->ps.size = HYPV_BACKUP_PS_SIZE;
	hypv_backup->pcs.size = HYPV_BACKUP_PCS_SIZE;
}

static inline void reset_backup_hw_stacks(bu_hw_stack_t *hypv_backup)
{
	hypv_backup->psp = new_psp((u64)GET_PS_BASE(hypv_backup),
			hypv_backup->ps.size, 0);

	hypv_backup->pcsp = new_pcsp((u64)GET_PCS_BASE(hypv_backup),
			hypv_backup->pcs.size, 0);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	hypv_backup->users = 0;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
}

static int create_vcpu_backup_stacks(struct kvm_vcpu *vcpu)
{
	bu_hw_stack_t *hypv_backup = &vcpu->arch.hypv_backup;
	e2k_size_t ps_size;
	e2k_size_t pcs_size;
	void *psp_stk;
	void *pcsp_stk;

	DebugKVMHV("started on task %s(%d) for VCPU #%d\n",
		   current->comm, current->pid, vcpu->vcpu_id);

	/* Allocate memory for hypervisor backup hardware stacks */

	define_backup_hw_stacks_sizes(hypv_backup);
	ps_size = hypv_backup->ps.size;
	pcs_size = hypv_backup->pcs.size;

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

	hypv_backup->ps.base = psp_stk;
	hypv_backup->pcs.base = pcsp_stk;
	DebugKVMHV("allocated backup procedure stack %px, size 0x%lx\n"
		   "allocated backup chain stack %px, size 0x%lx\n",
		   psp_stk, ps_size, pcsp_stk, pcs_size);

	return 0;

out_free_p_stack:
	kvfree(psp_stk);
	SET_PS_BASE(hypv_backup, NULL);

	return -ENOMEM;
}

static void free_kernel_backup_stacks(struct kvm_vcpu *vcpu, bu_hw_stack_t *hypv_backup)
{
	void *psp_stk = GET_PS_BASE(hypv_backup);
	void *pcsp_stk = GET_PCS_BASE(hypv_backup);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	E2K_KVM_BUG_ON(hypv_backup->users != 0);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	if (psp_stk != NULL) {
		kvfree(psp_stk);
		SET_PS_BASE(hypv_backup, NULL);
	}
	if (pcsp_stk != NULL) {
		kvfree(pcsp_stk);
		SET_PCS_BASE(hypv_backup, NULL);
	}
}

static void reset_vcpu_backup_stacks(struct kvm_vcpu *vcpu)
{
	reset_backup_hw_stacks(&vcpu->arch.hypv_backup);
}

static int init_vcpu_backup_stacks(struct kvm_vcpu *vcpu)
{
	reset_vcpu_backup_stacks(vcpu);
	return 0;
}

/*
 * Functions to create guest VCPU boot-time data & hardware stacks(PS & PCS)
 * Such stacks for host has been created by boot loader.
 * Hypervisor does not use a boot loader and launch guest VCPUs directly,
 * so should prepare all VCPUs stacks into guest physical memory.
 */
static void define_vcpu_boot_stacks_sizes(vcpu_boot_stack_t *boot_stacks)
{
	boot_stacks->data.size = VIRT_KERNEL_C_STACK_SIZE;
	boot_stacks->ps.size = VIRT_KERNEL_PS_SIZE;
	boot_stacks->pcs.size = VIRT_KERNEL_PCS_SIZE;
}

static void reset_vcpu_all_boot_stacks(struct kvm_vcpu *vcpu, vcpu_boot_stack_t *boot_stacks)
{
	e2k_stacks_t *boot_regs = &boot_stacks->regs.stacks;

	boot_regs->top = boot_stacks->data.top;
	boot_regs->usd = vcpu_new_usd(vcpu, boot_stacks->data.top - boot_stacks->data.size,
				boot_stacks->data.size, boot_stacks->data.size);

	boot_regs->psp = vcpu_new_psp(vcpu, (u64)GET_VCPU_BOOT_PS_BASE(boot_stacks),
				boot_stacks->ps.size, 0);

	boot_regs->pcsp = vcpu_new_pcsp(vcpu, (u64)GET_VCPU_BOOT_PCS_BASE(boot_stacks),
				boot_stacks->pcs.size, 0);
}

/* create VCPU booting local data stack */
static int
alloc_vcpu_boot_c_stack(struct kvm *kvm, vcpu_boot_stack_t *boot_stacks)
{
	e2k_size_t stack_size = boot_stacks->data.size;
	user_area_t *guest_area;
	void __user *data_stack;
	unsigned long stack_hva;
	gpa_t stack_gpa;
	long npages;
	int r;

	DebugKVMHV("started to allocate stack size of 0x%lx\n", stack_size);
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
	boot_stacks->data.top = stack_gpa + stack_size;
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
static void __user *alloc_vcpu_boot_hw_stack(struct kvm *kvm, e2k_size_t stack_size)
{
	user_area_t *guest_area;
	void __user *hw_stack;
	long npages;

	DebugKVMHV("started to allocate stack size of 0x%lx\n", stack_size);
	npages = PAGE_ALIGN(stack_size) >> PAGE_SHIFT;
	guest_area = kvm_find_memory_region(kvm, -1, 0, npages << PAGE_SHIFT,
					    guest_ram_mem_type);
	if (guest_area == NULL) {
		DebugKVMHV("guest memory regions is not created or empty\n");
		return (void __user __force *)ERR_PTR(-EINVAL);
	}
	hw_stack = user_area_alloc(guest_area, stack_size, 0);
	if (hw_stack == NULL)
		return (void __user __force *)ERR_PTR(-ENOMEM);

	return hw_stack;
}

static void
free_vcpu_boot_p_stack(struct kvm *kvm, vcpu_boot_stack_t *boot_stacks)
{
	user_area_t *guest_area;
	void __user *area_start;

	if (boot_stacks->proc_stack == NULL)
		return;
	area_start = boot_stacks->proc_stack;
	guest_area = kvm_find_memory_region(kvm, -1, (e2k_addr_t)(unsigned long)area_start, 0,
					    guest_ram_mem_type);
	if (guest_area != NULL)
		user_area_free_chunk(guest_area, area_start);
	boot_stacks->proc_stack = NULL;
}

static void
free_vcpu_boot_pc_stack(struct kvm *kvm, vcpu_boot_stack_t *boot_stacks)
{
	user_area_t *guest_area;
	void __user *area_start;

	if (boot_stacks->chain_stack == NULL)
		return;
	area_start = boot_stacks->chain_stack;
	guest_area = kvm_find_memory_region(kvm, -1, (e2k_addr_t)(unsigned long)area_start, 0,
					    guest_ram_mem_type);
	if (guest_area != NULL)
		user_area_free_chunk(guest_area, area_start);
	boot_stacks->chain_stack = NULL;
}

/* create VCPU booting hardware procedure stack */
static int
alloc_vcpu_boot_p_stack(struct kvm *kvm, vcpu_boot_stack_t *boot_stacks)
{
	void __user *p_stack;
	e2k_size_t stack_size;
	unsigned long stack_hva;
	gpa_t stack_gpa;
	int r = 0;

	stack_size = boot_stacks->ps.size;
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
	SET_VCPU_BOOT_PS_BASE(boot_stacks, (void __user __force *)stack_gpa);
	DebugKVMHV("VCPU booting procedure stack at guest space from %px to %px\n",
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
	void __user *pc_stack;
	e2k_size_t stack_size;
	unsigned long stack_hva;
	gpa_t stack_gpa;
	int r = 0;

	stack_size = boot_stacks->pcs.size;
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
	SET_VCPU_BOOT_PCS_BASE(boot_stacks, (void __user __force *)stack_gpa);
	DebugKVMHV("VCPU booting procedure chain stack at guest space from %px to %px\n",
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
	area_start = (e2k_addr_t) boot_stacks->data_stack;
	guest_area = kvm_find_memory_region(kvm, -1, area_start, 0,
					    guest_ram_mem_type);
	if (guest_area != NULL)
		user_area_free_chunk(guest_area, (void __user *)area_start);
	boot_stacks->data_stack = NULL;
}

static void free_vcpu_boot_stacks(struct kvm_vcpu *vcpu)
{
	vcpu_boot_stack_t *boot_stacks = &vcpu->arch.boot_stacks;

	free_vcpu_boot_c_stack(vcpu->kvm, boot_stacks);
	free_vcpu_boot_p_stack(vcpu->kvm, boot_stacks);
	free_vcpu_boot_pc_stack(vcpu->kvm, boot_stacks);
}

static int create_vcpu_boot_stacks(struct kvm_vcpu *vcpu)
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

	/* setup initial state of VCPU booting stacks */
	reset_vcpu_all_boot_stacks(vcpu, boot_stacks);

	return 0;

out_free_c_stack:
	free_vcpu_boot_c_stack(vcpu->kvm, boot_stacks);
out_free_p_stack:
	free_vcpu_boot_p_stack(vcpu->kvm, boot_stacks);

	return r;
}

static void reset_vcpu_boot_stacks(struct kvm_vcpu *vcpu)
{
	reset_vcpu_all_boot_stacks(vcpu, &vcpu->arch.boot_stacks);
}

static int init_vcpu_boot_stacks(struct kvm_vcpu *vcpu)
{
	reset_vcpu_boot_stacks(vcpu);
	return 0;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static int create_vcpu_host_context(struct kvm_vcpu *vcpu)
{
	kvm_host_context_t *host_ctxt = &vcpu->arch.host_ctxt;
	unsigned long *stack;
	unsigned long addr;

	DebugKVMHV("started on task %s(%d) for VCPU #%d\n",
		   current->comm, current->pid, vcpu->vcpu_id);

	E2K_KVM_BUG_ON(vcpu->arch.is_hv || !vcpu->arch.is_pv);

	memset(host_ctxt, 0, sizeof(*host_ctxt));

	/*
	 * Calculate kernel stacks registers
	 */
	stack  = __vmalloc_node(THREAD_SIZE, THREAD_ALIGN, THREADINFO_GFP,
				numa_node_id(), __builtin_return_address(0));
	if (!stack) {
		pr_err("%s(): could not allocate VCPU #%d host stacks\n",
		       __func__, vcpu->vcpu_id);
		return -ENOMEM;
	}
	*stack = STACK_END_MAGIC;
	host_ctxt->stack = stack;
	addr = (unsigned long)stack;
	host_ctxt->pt_regs = NULL;
	host_ctxt->upsr = E2K_USER_INITIAL_UPSR;
	host_ctxt->k_psp = new_psp(addr + KERNEL_P_STACK_OFFSET,
				KERNEL_P_STACK_SIZE, 0);
	host_ctxt->k_pcsp = new_pcsp(addr + KERNEL_PC_STACK_OFFSET,
				KERNEL_PC_STACK_SIZE, 0);
	host_ctxt->k_usd = new_usd(addr + KERNEL_C_STACK_OFFSET,
				   KERNEL_C_STACK_SIZE,
				   KERNEL_C_STACK_SIZE);
	host_ctxt->k_sbr.base = USD_PTR(host_ctxt->k_usd);

	host_ctxt->osem = guest_trap_init(vcpu->kvm);

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
		vfree(host_ctxt->stack);
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
	if (!vcpu->arch.is_hv)
		return 0;

	DebugKVM("started for VCPU #%d\n", vcpu->vcpu_id);

	if (vcpu->arch.is_pv) {
		/* paravirtualization support need create and enable */
		int r = kvm_arch_pv_vcpu_setup(vcpu);
		if (r != 0) {
			return r;
		}
	}

	return 0;
}
#else /* ! CONFIG_KVM_HW_VIRTUALIZATION */
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
#endif /* CONFIG_KVM_HW_VIRTUALIZATION */


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
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static void kvm_arch_vcpu_ctxt_init(struct kvm_vcpu *vcpu)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;

	memset(&vcpu->arch.sw_ctxt, 0, sizeof(vcpu->arch.sw_ctxt));
	memset(&vcpu->arch.hw_ctxt, 0, sizeof(vcpu->arch.hw_ctxt));

	sw_ctxt->osem = guest_trap_init(vcpu->kvm);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (vcpu->arch.is_hv)
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	{
		guest_hw_stack_t *boot_regs = &vcpu->arch.boot_stacks.regs;

		/* setup guest boot kernel local data stack */
		sw_ctxt->usd = boot_regs->stacks.usd;
		sw_ctxt->sbr.base = boot_regs->stacks.top;

		GET_FPU_DEFAULTS(sw_ctxt->fpsr, sw_ctxt->fpcr, sw_ctxt->pfpfr);

		sw_ctxt->dibcr.gm = 1;
		sw_ctxt->ddbcr.gm = 1;

		/* Make sure that on reset we do not reenable L2 prefetcher for Lintel */
		sw_ctxt->l2_prefetcher_enabled = l2_prefetcher_enabled() &&
				!(test_kvm_mode_flag(vcpu->kvm, KVMF_LINTEL) &&
				  cpu_has(CPU_HWBUG_GENERATIONS_L2_PREF));
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
	case KVM_CAP_IOEVENTFD:
		DebugKVM("ioctl is KVM_CAP_IOEVENTFD\n");
		r = 1;
		break;
	case KVM_CAP_MP_STATE:
		DebugKVM("ioctl is KVM_CAP_MP_STATE\n");
		r = 1;
		break;
	case KVM_CAP_IMMEDIATE_EXIT:
		DebugKVM("ioctl is KVM_CAP_IMMEDIATE_EXIT\n");
		r = 1;
		break;
	case KVM_CAP_NR_VCPUS:
		r = num_online_cpus();
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
	case KVM_CAP_E2K_HV_VM:
		DebugKVM("ioctl is KVM_CAP_E2K_HV_VM\n");
		r = kvm_is_hv_vm_available();
		break;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	case KVM_CAP_E2K_SV_VM:
		DebugKVM("ioctl is KVM_CAP_E2K_SV_VM\n");
		r = kvm_is_sv_vm_available();
		break;
	case KVM_CAP_E2K_SW_PV_VM:
		DebugKVM("ioctl is KVM_CAP_E2K_SW_PV_VM\n");
		r = kvm_is_sw_pv_vm_available();
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
#else
	case KVM_CAP_E2K_SV_VM:
	case KVM_CAP_E2K_SW_PV_VM:
		r = false;
		break;
	case KVM_CAP_E2K_TDP_MMU:
	case KVM_CAP_E2K_SHADOW_PT_MMU:
		r = true;
		break;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	case KVM_CAP_E2K_SIC_NBSR_ISET:
		DebugKVM("ioctl is KVM_CAP_E2K_SIC_NBSR_ISET\n");
		r = kvm_is_sic_nbsr_iset_available();
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
	vcpu->mmio_cur_fragment = 0;
	vcpu->arch.mmio_offset = 0;
	frag = &vcpu->mmio_fragments[0];
	kvm_run->mmio.phys_addr = frag->gpa;
	kvm_run->mmio.len = min(8u, frag->len);
	kvm_run->mmio.is_write = vcpu->mmio_is_write;

	if (vcpu->mmio_is_write)
		memcpy(kvm_run->mmio.data, frag->data, min(8u, frag->len));
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
		panic("get_ioport_data_offset() KVM run area size 0x%lx, IO data area offset 0x%lx > PAGE SIZE\n",
		      sizeof(*kvm_run), data_offset);
	} else if (sizeof(*kvm_run) > data_offset) {
		panic("get_ioport_data_offset() KVM run area size 0x%lx > IO data area offset 0x%lx\n",
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

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static int handle_notify_io(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	kvm_run->exit_reason = KVM_EXIT_E2K_NOTIFY_IO;
	kvm_run->notifier.io = vcpu->arch.notifier_io;
	return 0;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static int handle_shutdown(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	DebugKVMSH("started, shutdown type %d\n", kvm_run->exit_reason);

	if (kvm_run->exit_reason == KVM_EXIT_SYSTEM_EVENT) {
		int event_type = kvm_run->system_event.type;

		if (event_type == KVM_SYSTEM_EVENT_RESET) {
			if (!vcpu->kvm->arch.reboot) {
				vcpu->arch.reboot = true;
				vcpu->kvm->arch.reboot = true;
			} else {
				/* reboot is already in progress */
				;
			}
		} else if (event_type == KVM_SYSTEM_EVENT_SHUTDOWN) {
			vcpu->arch.halted = true;
			vcpu->kvm->arch.halted = true;
		} else if (event_type == KVM_SYSTEM_EVENT_CRASH) {
			vcpu->arch.halted = true;
		} else {
			pr_err("%s(): unknown systen event type #%d\n",
			       __func__, event_type);
			kvm_run->exit_reason = KVM_EXIT_UNKNOWN;
			kvm_run->hw.hardware_exit_reason = 1;
		}
	} else {
		E2K_KVM_BUG_ON(true);
		vcpu->arch.halted = true;
		vcpu->kvm->arch.halted = true;
	}
	smp_mb();		/* to sure the flag is set */
	return 0;
}

static int (*kvm_guest_exit_handlers[]) (struct kvm_vcpu *vcpu,
					 struct kvm_run *kvm_run) = {
			[EXIT_REASON_VM_PANIC] = handle_vm_error,
			[EXIT_REASON_MMIO_REQ] = handle_mmio,
			[EXIT_REASON_IOPORT_REQ] = handle_ioport,
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
			[EXIT_NOTIFY_IO] = handle_notify_io,
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
			[EXIT_SHUTDOWN] = handle_shutdown,
		};

static const int kvm_guest_max_exit_handlers =
	sizeof(kvm_guest_exit_handlers) / sizeof(*kvm_guest_exit_handlers);

static inline uint32_t kvm_get_shutdown_reason(struct kvm_vcpu *vcpu)
{
	u32 exit_reason;
	int terminate_reason = vcpu->arch.exit_shutdown_terminate;

	vcpu->run->exit_reason = KVM_EXIT_SYSTEM_EVENT;
	if (terminate_reason == KVM_EXIT_E2K_RESTART) {
		vcpu->run->system_event.type = KVM_SYSTEM_EVENT_RESET;
	} else if (terminate_reason == KVM_EXIT_E2K_SHUTDOWN) {
		vcpu->run->system_event.type = KVM_SYSTEM_EVENT_SHUTDOWN;
	} else if (terminate_reason == KVM_EXIT_E2K_PANIC) {
		vcpu->run->system_event.type = KVM_SYSTEM_EVENT_CRASH;
	} else {
		pr_err("%s(): unknown shutdown reason #%d\n",
		       __func__, terminate_reason);
		E2K_KVM_BUG_ON(true);
	}
	exit_reason = EXIT_SHUTDOWN;
	vcpu->arch.exit_shutdown_terminate = 0;
	return exit_reason;
}

static inline uint32_t kvm_get_exit_reason(struct kvm_vcpu *vcpu)
{
	u32 exit_reason;

	if (vcpu->arch.exit_shutdown_terminate != 0) {
		exit_reason = kvm_get_shutdown_reason(vcpu);
	} else {
		exit_reason = vcpu->arch.exit_reason;
	}
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

	DebugKVMRUN("started on VCPU %d on exit reason %d\n",
		    vcpu->vcpu_id, exit_reason);
	if (exit_reason < kvm_guest_max_exit_handlers
	    && kvm_guest_exit_handlers[exit_reason]) {
		return kvm_guest_exit_handlers[exit_reason] (vcpu, kvm_run);
	} else if (exit_reason == -1) {
		/* exit reason was not set, try run VCPU again */
		return 1;
	} else {
		kvm_run->exit_reason = KVM_EXIT_UNKNOWN;
		kvm_run->hw.hardware_exit_reason = exit_reason;
		DebugKVM("exit reason %d is unknown\n", exit_reason);
	}
	return 0;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static int pv_vcpu_run(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	int r;

	DebugKVMRUN("started on VCPU %d CPU %d\n", vcpu->vcpu_id, vcpu->cpu);

	/*
	 * down_read() may sleep and return with interrupts enabled
	 */
	mutex_lock(&vcpu->kvm->slots_lock);

again:
	if (unlikely(signal_pending(current))) {
		++vcpu->stat.signal_exits;
		goto vm_interrupted;
	}
	if (unlikely(vcpu->kvm->arch.halted)) {
		/* VM halted, terminate all VCPUs */
		goto vm_interrupted;
	}

	local_irq_disable();

	clear_bit(KVM_REQ_KICK, (void *)&vcpu->requests);

	mutex_unlock(&vcpu->kvm->slots_lock);

	/*
	 * Transition to the guest
	 */
	if (!vcpu->arch.from_pv_intc) {
		if (unlikely(!pv_vcpu_get_gmm(vcpu))) {
			local_irq_disable();
			kvm_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_QEMU);
			return -EINVAL;
		}

		launch_pv_vcpu(vcpu, FULL_CONTEXT_SWITCH | USD_CONTEXT_SWITCH);
	} else {
		return_to_pv_vcpu_intc(vcpu);
	}

	local_irq_enable();

	mutex_lock(&vcpu->kvm->slots_lock);

	r = kvm_handle_exit(kvm_run, vcpu);

	if (r > 0) {
		if (!need_resched())
			goto again;
	}

	mutex_unlock(&vcpu->kvm->slots_lock);
	if (r > 0) {
		cond_resched();
		mutex_lock(&vcpu->kvm->slots_lock);
		goto again;
	}

	kvm_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_QEMU);

	return r;

vm_interrupted:
	mutex_unlock(&vcpu->kvm->slots_lock);
	r = -EINTR;
	kvm_run->exit_reason = KVM_EXIT_INTR;
	return r;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static int hv_vcpu_run(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	int r;

	kvm_vcpu_srcu_read_lock(vcpu);

	for (;;) {
		r = vcpu_enter_guest(vcpu);

		if (r != 0)
			break;

		if (unlikely(vcpu->arch.exit_shutdown_terminate))
			break;

		if (__xfer_to_guest_mode_work_pending()) {
			kvm_vcpu_srcu_read_unlock(vcpu);
			r = xfer_to_guest_mode_handle_work(vcpu);
			if (r)
				return r;
			kvm_vcpu_srcu_read_lock(vcpu);
		}
	}

	r = kvm_handle_exit(kvm_run, vcpu);
	KVM_WARN_ON(r > 0);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	kvm_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_QEMU);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	kvm_vcpu_srcu_read_unlock(vcpu);

	return r;
}

static int kvm_complete_userspace_io(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	int r;

	if (vcpu->arch.ioport.needed) {
		if (!vcpu->arch.ioport.is_out) {
			void *data = get_ioport_data_pointer(kvm_run);
			if (vcpu->arch.ioport.string) {
				memcpy(vcpu->arch.ioport_data, data,
				       vcpu->arch.ioport.size * vcpu->arch.ioport.count);
			} else {
				memcpy(&vcpu->arch.ioport.data, data,
				       vcpu->arch.ioport.size);
			}
		}
		vcpu->arch.ioport.completed = 1;
		vcpu->arch.ioport.needed = 0;
		r = kvm_complete_guest_ioport_request(vcpu);
		if (r) {
			pr_err("%s(): IO PORT request completion failed, error %d\n",
				__func__, r);
		}
	}

	if (vcpu->mmio_needed) {
		struct kvm_mmio_fragment *frag;
		unsigned len;
		gpa_t frag_gpa;
		void *frag_data;
		unsigned frag_len;

		/* Complete previous fragment */
		if (vcpu->mmio_cur_fragment != 0) {
			pr_err("%s(): invalid number of current fragments (%d != 0)\n",
			       __func__, vcpu->mmio_cur_fragment);
		}
		frag = &vcpu->mmio_fragments[0];
		frag_data = frag->data + vcpu->arch.mmio_offset;
		frag_gpa = frag->gpa + vcpu->arch.mmio_offset;
		frag_len = frag->len - vcpu->arch.mmio_offset;

		len = min(8u, frag_len);
		if (!vcpu->mmio_is_write)
			memcpy(frag_data, kvm_run->mmio.data, len);

		if (frag_len > 8) {
			/* Go forward to the next mmio piece. */
			vcpu->arch.mmio_offset += len;
			frag_data += len;
			frag_gpa += len;
			frag_len -= len;

			DebugKVMIO("Reexecuting MMIO: gpa 0x%llx data 0x%px len %d is_write %d\n",
			     frag_gpa, frag_data, frag_len,
			     vcpu->mmio_is_write);

			kvm_run->exit_reason = KVM_EXIT_MMIO;
			kvm_run->mmio.phys_addr = frag_gpa;
			if (vcpu->mmio_is_write)
				memcpy(kvm_run->mmio.data, frag_data,
				       min(8u, frag_len));
			kvm_run->mmio.len = min(8u, frag_len);
			kvm_run->mmio.is_write = vcpu->mmio_is_write;

			return 1;
		}

		vcpu->arch.mmio_offset = 0;
		vcpu->mmio_read_completed = 1;
		vcpu->mmio_needed = 0;
		r = kvm_complete_guest_mmio_request(vcpu);
		if (r) {
			pr_err("%s(): MMIO request completion failed, error %d\n",
				__func__, r);
		}
	}

	return 0;
}

int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu)
{
	struct kvm_run *kvm_run = vcpu->run;
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
		r = -EAGAIN;
		if (signal_pending(current)) {
			r = -EINTR;
			vcpu->run->exit_reason = KVM_EXIT_INTR;
			++vcpu->stat.signal_exits;
		}
		goto out;
	}

	r = kvm_complete_userspace_io(vcpu, kvm_run);
	if (r)
		goto out;

	if (kvm_run->immediate_exit) {
		r = -EINTR;
	} else {
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		r = vcpu->arch.is_hv ? hv_vcpu_run(vcpu, kvm_run) : pv_vcpu_run(vcpu, kvm_run);
#else
		r = hv_vcpu_run(vcpu, kvm_run);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	}
out:
	kvm_sigset_deactivate(vcpu);

	vcpu_put(vcpu);

	return r;
}

vm_fault_t kvm_arch_vcpu_fault(struct kvm_vcpu *vcpu, struct vm_fault *vmf)
{
	DebugKVM("VCPU #%d started for address 0x%lx\n",
		 vcpu->vcpu_id, vmf->address);
	return VM_FAULT_SIGBUS;
}

static int kvm_alloc_epic_pages(struct kvm *kvm)
{
	unsigned long epic_gstbase;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (kvm->arch.is_hv)
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	{
		DebugKVM("started to alloc pages for EPIC\n");

		kvm->arch.epic_pages =
		    alloc_pages(GFP_KERNEL | __GFP_RETRY_MAYFAIL | __GFP_ZERO,
				MAX_EPICS_ORDER);

		if (!kvm->arch.epic_pages) {
			DebugKVM("failed to alloc memory for EPIC\n");
			return -ENOMEM;
		}

		epic_gstbase = (unsigned long)page_address(kvm->arch.epic_pages);

		DebugKVM("EPIC gstbase for gstid %d is 0x%lx (PA 0x%llx)\n",
			 kvm->arch.vm_id, epic_gstbase, __pa(epic_gstbase));
	}

	return 0;
}

static void kvm_free_epic_pages(struct kvm *kvm)
{
	struct page *epic_pages = kvm->arch.epic_pages;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (kvm->arch.is_hv)
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	{
		DebugKVM("started to free hw EPIC pages\n");

		__free_pages(epic_pages, MAX_EPICS_ORDER);
	}
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static void setup_guest_features(struct kvm *kvm)
{
	kvm_guest_info_t *guest_info = &kvm->arch.guest_info;
	unsigned long features = 0;

	guest_info->features = features;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static int kvm_setup_guest_info(struct kvm *kvm, const void __user *user_info)
{
	kvm_guest_info_t *guest_info = &kvm->arch.guest_info;

	if (copy_from_user(guest_info, user_info, sizeof(*guest_info)))
		return -EFAULT;

	if (guest_info->cpu_iset > machine.native_iset_ver || guest_info->cpu_iset < 0) {
		pr_info_ratelimited("KVM: cannot run guest compiled with newer iset %d on host with older iset %d\n",
				guest_info->cpu_iset, machine.native_iset_ver);
		return -EINVAL;
	}

	if (guest_info->cpu_iset < E2K_ISET_V7) {
		/* guest cannot support new format of register-descriptors */
		set_kvm_mode_flag(kvm, KVMF_DESCR_V6);
		/* guest cannot support new algorithm of 'getsp' operation */
		set_kvm_mode_flag(kvm, KVMF_GETSP_V6);
	}
	guest_info->is_stranger = guest_info->cpu_iset < E2K_ISET_V6;
	if (guest_info->is_stranger) {
		if (kvm_is_epic(kvm)) {
			pr_info_ratelimited("KVM: set to use 'EPIC' but guest cpu iset V%d needs at 'APIC'\n",
					guest_info->cpu_iset);
			return -EINVAL;
		}
		guest_info->mmu_support_pt_v6 = false;
	} else {
		if (!kvm_is_epic(kvm)) {
			pr_info_ratelimited("KVM: set to use 'APIC', but guest cpu iset V%d needs at 'EPIC'\n",
					guest_info->cpu_iset);
			return -EINVAL;
		}
	}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (guest_info->is_pv) {
		/* guest is paravirtualized and cannot be run as bare  */
		int ret = kvm_disable_tdp_mode(kvm);
		if (ret)
			return ret;
		pr_info("%s(): guest is paravirtualized and  cannot be run in TDP mode, so mode is disabled\n",
			__func__);
	}

	setup_guest_features(kvm);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	return 0;
}

#ifdef KVM_HAVE_LEGACY_VGA_PASSTHROUGH
/*
 * Find first PCI VGA device assigned to VFIO driver.
 * This is unsafe, as it doesn't check user's permissions.
 */
static int kvm_setup_legacy_vga_passthrough(struct kvm *kvm)
{
	struct pci_dev *pdev = NULL;
	int ret;

	while ((pdev = pci_get_class(PCI_CLASS_DISPLAY_VGA << 8, pdev)) != NULL) {
		if (pdev->driver && !strcmp(pdev->driver->name, "vfio-pci"))
			kvm->arch.vga_pt_dev = pdev;
	}

	ret = vga_get_interruptible(kvm->arch.vga_pt_dev, VGA_RSRC_LEGACY_MEM);
	if (ret) {
		pr_err("%s(): failed to acquire legacy VGA area from vgaarb\n",
		       __func__);
		return ret;
	}

	kvm->arch.legacy_vga_passthrough = true;

	return 0;
}

static void kvm_free_legacy_vga_passthrough(struct kvm *kvm)
{
	if (kvm->arch.legacy_vga_passthrough)
		vga_put(kvm->arch.vga_pt_dev, VGA_RSRC_LEGACY_MEM);
}
#else
static void kvm_free_legacy_vga_passthrough(struct kvm *kvm)
{
	/* Nothing to do */
}
#endif

static void kvm_free_passthrough(struct kvm *kvm)
{
	struct pt_device *pt_dev, *tmp;

	list_for_each_entry_safe(pt_dev, tmp, &kvm->arch.pt_device, list) {
		list_del(&pt_dev->list);
		kfree(pt_dev);
	}

	kvm_free_legacy_vga_passthrough(kvm);
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static void kvm_arch_init_vm_mmap(struct kvm *kvm)
{
	kvm->arch.shadow_pt_enable = true;
#ifdef	CONFIG_KVM_PHYS_PT_ENABLE
	kvm->arch.phys_pt_enable = kvm->arch.is_hv;
#ifdef	CONFIG_KVM_TDP_ENABLE
	kvm->arch.tdp_enable = kvm->arch.phys_pt_enable;
#else /* ! CONFIG_KVM_TDP_ENABLE */
	kvm->arch.tdp_enable = false;
#endif /* CONFIG_KVM_TDP_ENABLE */
#else /* ! CONFIG_KVM_PHYS_PT_ENABLE */
	kvm->arch.phys_pt_enable = false;
	kvm->arch.tdp_enable = false;
#endif /* CONFIG_KVM_PHYS_PT_ENABLE */
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static DEFINE_IDA(vmid_ida);

int kvm_arch_init_vm(struct kvm *kvm, unsigned long vm_type)
{
	struct task_struct *p;
	int err;

	DebugKVM("started to create VM type %lx\n", vm_type);

#ifndef CONFIG_KVM_PARAVIRTUALIZATION
	if (!cpu_has(CPU_FEAT_ISET_V6))
		return -ENOTSUPP;
#endif

	if (vm_type & KVM_E2K_EPIC_VM_FLAG) {
		DebugKVM("creating EPIC VM\n");
		kvm->arch.is_epic = true;
	} else {
		DebugKVM("creating APIC VM\n");
	}

	vm_type &= KVM_E2K_VM_TYPE_MASK;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (kvm_is_sv_vm_available() || kvm_is_sw_pv_vm_available())
		kvm->arch.is_pv = true;
	if (kvm_is_hv_vm_available() || kvm_is_hw_pv_vm_available())
		kvm->arch.is_hv = true;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	if (vm_type == 0) {
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		/* default VM type, choose max better type */
		if (kvm_is_hw_pv_vm_available())
			vm_type = KVM_E2K_HW_PV_VM_TYPE;
		else
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
		if (kvm_is_hv_vm_available())
			vm_type = KVM_E2K_HV_VM_TYPE;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		else if (kvm_is_sw_pv_vm_available())
			vm_type = KVM_E2K_SW_PV_VM_TYPE;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
		DebugKVM("will be created VM type %ld\n", vm_type);
	} else {
		switch (vm_type) {
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
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
		case KVM_E2K_HW_PV_VM_TYPE:
			if (!kvm_is_hw_pv_vm_available())
				return -EINVAL;
			break;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
		case KVM_E2K_HV_VM_TYPE:
			if (!kvm_is_hv_vm_available())
				return -EINVAL;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
			kvm->arch.is_pv = false;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
			break;
		default:
			return -EINVAL;
		}
	}
	kvm->arch.vm_type = vm_type;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	kvm_arch_init_vm_mmap(kvm);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	err = ida_alloc_range(&vmid_ida, 1, MMU_GID_SIZE - 1, GFP_KERNEL);
	if (err < 0) {
		goto error_vm;
	}
	kvm->arch.vm_id = err;
	DebugKVM("allocated VM ID (GID) #%d\n", kvm->arch.vm_id);

	rcu_read_lock();
	for_each_thread(current, p)
		task_thread_info(p)->virt_machine = kvm;
	rcu_read_unlock();

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (kvm->arch.is_pv && !kvm->arch.is_hv) {
		err = kvm_pv_guest_thread_info_init(kvm);
		if (err)
			goto error_gti;

		err = kvm_guest_pv_mm_init(kvm);
		if (err)
			goto error_gmm;
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	kvm_page_track_init(kvm);
	kvm_mmu_init_vm(kvm);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	raw_spin_lock_init(&kvm->arch.virq_lock);
	kvm->arch.max_irq_no = -1;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	INIT_LIST_HEAD(&kvm->arch.ioepic_pt_pin);
	INIT_LIST_HEAD(&kvm->arch.pt_device);
	kvm->arch.ioepic_direct_map = true;
	if (!kvm_ioepic_unsafe_direct_map)
		kvm->arch.ioepic_direct_map = false;

	kvm_arch_init_vm_mmu(kvm);

	err = kvm_alloc_epic_pages(kvm);
	if (err)
		goto error_gmm;

	kvm->arch.cepic_freq = is_prototype() ? E2K_PROTO_CEPIC_FREQ : E2K_DEFAULT_CEPIC_FREQ;

	kvm->arch.reboot = false;
	kvm->arch.halted = false;
	atomic_set(&kvm->arch.vcpus_to_reset, 0);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	err = kvm_boot_spinlock_init(kvm);
	if (err)
		goto error_gmm;
	err = kvm_guest_spinlock_init(kvm);
	if (err)
		goto error_boot_spinlock;
	err = kvm_guest_csd_lock_init(kvm);
	if (err)
		goto error_spinlock;

	if (!kvm->arch.is_hv && kvm->arch.is_pv && capable(CAP_SYS_ADMIN)) {
		set_kvm_mode_flag(kvm, KVMF_PRIV_HCALL_ENABLE);
	} else {
		clear_kvm_mode_flag(kvm, KVMF_PRIV_HCALL_ENABLE);
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	kvm->arch.hst_t_off = 0;

	kvm->arch.raw_clock_offset = -(s64) ktime_get_raw_ns();

	return 0;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
error_spinlock:
	kvm_guest_spinlock_destroy(kvm);
error_boot_spinlock:
	kvm_boot_spinlock_destroy(kvm);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
error_gmm:
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (kvm->arch.is_pv && !kvm->arch.is_hv) {
		kvm_pv_guest_thread_info_destroy(kvm);
	}
error_gti:
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	rcu_read_lock();
	for_each_thread(current, p)
		task_thread_info(p)->virt_machine = NULL;
	rcu_read_unlock();
error_vm:
	return err;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static void setup_kvm_features(struct kvm *kvm)
{
	kvm_host_info_t *host_info = kvm->arch.kmap_host_info;
	unsigned long features = 0;

	if (kvm->arch.is_hv) {
		features |= KVM_FEAT_HW_HCALL_MASK | KVM_FEAT_HV_CPU_MASK | KVM_FEAT_HV_MMU_MASK;
	}
	if (kvm->arch.is_pv) {
		features |= KVM_FEAT_PV_CPU_MASK;
	}
	if (kvm->arch.is_pv && !kvm->arch.is_hv) {
		/* hypervisor (can) support only paravirtualization */
		features |= (KVM_FEAT_PV_HCALL_MASK | KVM_FEAT_PV_MMU_MASK);
	}
	if (kvm_is_epic(kvm)) {
		if (kvm->arch.is_hv && cpu_has(CPU_FEAT_EPIC))
			features |= KVM_FEAT_HV_EPIC_MASK;
		else
			features |= KVM_FEAT_PV_EPIC_MASK;
	} else {		/* can be only APIC */
		if (kvm->arch.is_pv)
			features |= KVM_FEAT_PV_APIC_MASK;
	}

	host_info->features = features;
}

static void kvm_setup_host_info(struct kvm *kvm)
{
	kvm_host_info_t *info = kvm->arch.kmap_host_info;
	info->mach_id = native_machine_id;
	info->cpu_rev = machine.native_rev;
	info->cpu_iset = machine.native_iset_ver;
	info->support_hw_hc = machine.native_iset_ver >= E2K_ISET_V6;
	info->mmu_support_pt_v6 = machine.native_iset_ver >= E2K_ISET_V6 &&
				  cpu_has(CPU_FEAT_PAGE_TABLE_V6);

	setup_kvm_features(kvm);
	kvm_update_guest_time(kvm);
}

static int kvm_create_host_info(struct kvm *kvm)
{
	kvm_host_info_t __user *host_info = NULL;
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
						 sizeof(kvm_host_info_t),
						 1 << E2K_ALIGN_GLOBALS, 0);
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
	raw_spin_lock_init(&kvm->arch.time_state_lock);
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
	DebugKVMSH("%s (%d) started\n", current->comm, current->pid);
	if (kvm->arch.host_info != NULL) {
		user_area_t *guest_area;
		e2k_addr_t area_start;

		area_start = (e2k_addr_t) kvm->arch.host_info;
		guest_area = kvm_find_memory_region(kvm,
						    -1, area_start, 0,
						    guest_vram_mem_type);
		if (kvm->arch.kmap_host_info != NULL) {
			unmap_user_area_to_vmalloc_range(guest_area,
							 kvm->
							 arch.kmap_host_info);
			kvm->arch.kmap_host_info = NULL;
		}
		user_area_free_chunk(guest_area, kvm->arch.host_info);
		kvm->arch.host_info = NULL;
	} else if (kvm->arch.kmap_host_info != NULL) {
		unmap_user_area_to_vmalloc_range(NULL, kvm->arch.kmap_host_info);
		kvm->arch.kmap_host_info = NULL;
	}
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#ifdef KVM_HAVE_GET_SET_IRQCHIP
static int kvm_vm_ioctl_get_irqchip(struct kvm *kvm, struct kvm_irqchip *chip)
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

	DebugKVM("started for chip ID %d\n", chip->chip_id);
	r = 0;
	switch (chip->chip_id) {
	case KVM_IRQCHIP_IOAPIC:
		/* IOEPIC is currently not supported in QEMU */
		DebugKVM("IRQ chip is IO-APIC\n");
		if (!kvm_is_epic(kvm))
			r = kvm_set_ioapic(kvm, &chip->chip.ioapic);
		break;
	default:
		DebugKVM("failed: IRQ chip is unknown\n");
		r = -ENODEV;
		break;
	}
	return r;
}
#endif

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
	return -EINVAL;
}

long kvm_arch_vm_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm = filp->private_data;
	void __user *argp = (void __user *)arg;
	int r = -ENOTTY;

	DebugKVMIOC("started\n");
	switch (ioctl) {
	case KVM_GET_ARCH_API_VERSION:
		if (argp != NULL)
			goto out;
		set_kvm_mode_flag(kvm, KVMF_ARCH_API_TAKEN);
		r = KVM_ARCH_API_VERSION;
		break;
	case KVM_ALLOC_GUEST_AREA: {
		kvm_guest_area_alloc_t __user *guest_area;

			DebugKVMIOCTL("ioctl is KVM_ALLOC_GUEST_AREA\n");
			guest_area = (kvm_guest_area_alloc_t __user *) argp;
			r = kvm_arch_ioctl_alloc_guest_area(kvm, guest_area);
			break;
		}
	case KVM_RESERVE_GUEST_AREA:{
		kvm_guest_area_reserve_t reserve_area;
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
	case KVM_CREATE_IRQCHIP:
		DebugKVMIOCTL("ioctl is KVM_CREATE_IRQCHIP\n");
		r = -EFAULT;
		r = kvm_io_pic_init(kvm);
		if (r)
			goto out;
		break;
	case KVM_CREATE_SIC_NBSR:
		DebugKVMIOCTL("ioctl is KVM_CREATE_SIC_NBSR\n");
		r = kvm_nbsr_init(kvm, E2K_ISET_V6);
		break;
	case KVM_CREATE_SIC_NBSR_ISET:
		DebugKVMIOCTL("ioctl is KVM_CREATE_SIC_NBSR_ISET with param 0x%lx\n", arg);
		r = kvm_nbsr_init(kvm, arg);
		break;
	case KVM_RESET_SIC_NBSR:
		DebugKVMIOCTL("ioctl is KVM_RESET_SIC_NBSR\n");
		kvm_nbsr_reset(kvm, kvm->arch.nbsr);
		break;
#ifdef KVM_HAVE_GET_SET_IRQCHIP
	case KVM_GET_IRQCHIP:{
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
	case KVM_SET_IRQCHIP:{
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
#endif
	case KVM_SET_PCI_REGION: {
		struct kvm_pci_region pci_region;

		DebugKVMIOCTL("ioctl is KVM_SET_PCI_REGION\n");
		r = -EFAULT;
		if (copy_from_user(&pci_region, argp, sizeof pci_region))
			goto out;
		r = nbsr_setup_pci_region(kvm, &pci_region);
		break;
	}
	case KVM_SET_IRQCHIP_BASE:
		DebugKVMIOCTL("ioctl is KVM_SET_IRQCHIP_BASE to 0x%lx\n", arg);
		r = kvm_io_pic_set_base(kvm, arg);
		break;
	case KVM_SET_SYS_TIMER_BASE:
		DebugKVMIOCTL("ioctl is KVM_SET_SYS_TIMER_BASE to 0x%lx\n",
			      arg);
		/* only for node #0 is now implemented */
		r = kvm_lt_set_base(kvm, 0, arg);
		break;
	case KVM_SET_SPMC_CONF_BASE:
		DebugKVMIOCTL("ioctl is KVM_SET_SPMC_CONF_BASE to 0x%lx\n",
			      arg);
		/* only for node #0 is now implemented */
		r = kvm_spmc_set_base(kvm, 0, arg);
		break;
#ifdef KVM_HAVE_LEGACY_VGA_PASSTHROUGH
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
#endif
	case KVM_SET_GUEST_INFO:
		DebugKVMIOCTL("ioctl is KVM_SET_GUEST_INFO\n");
		r = kvm_setup_guest_info(kvm, argp);
		break;
	case KVM_GET_NBSR_STATE: {
		struct kvm_guest_nbsr_state nbsr;

		DebugKVM("ioctl is KVM_GET_NBSR_STATE\n");
		r = -ENXIO;
			if (!kvm->arch.nbsr)
				goto out;

		/* FIXME: only node #0 is supported for now */
		r = kvm_get_nbsr_state(kvm, &nbsr);
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

int kvm_arch_vcpu_create(struct kvm_vcpu *vcpu)
{
	int r;

	r = kvm_arch_vcpu_init(vcpu);
	if (r)
		return r;

	return kvm_arch_vcpu_setup(vcpu);
}

bool kvm_vcpu_is_bsp(struct kvm_vcpu *vcpu)
{
	return vcpu->vcpu_id == 0;
}

void kvm_arch_vcpu_postcreate(struct kvm_vcpu *vcpu)
{
	DebugKVM("Unimplemented\n");
}

int kvm_arch_vcpu_init(struct kvm_vcpu *vcpu)
{
	int r;

	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);

	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	init_completion(&vcpu->arch.released);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	mutex_init(&vcpu->arch.lock);
	vcpu->arch.ioport_data = get_ioport_data_pointer(vcpu->run);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	vcpu->arch.ioport_data_size = get_ioport_data_size(vcpu->run);

	switch (vcpu->kvm->arch.vm_type) {
	case KVM_E2K_SV_VM_TYPE:
	case KVM_E2K_SW_PV_VM_TYPE:
		r = kvm_arch_pv_vcpu_init(vcpu);
		if (r != 0)
			return r;
		break;
	case KVM_E2K_HV_VM_TYPE:
	case KVM_E2K_HW_PV_VM_TYPE:
		r = kvm_arch_hv_vcpu_init(vcpu);
		if (r != 0)
			goto pv_uninit;
		break;
	default:
		return -ENOTSUPP;
	}

	r = kvm_arch_any_vcpu_init(vcpu);
	if (r != 0)
		goto pv_uninit;
#else
	if (vcpu->kvm->arch.vm_type != KVM_E2K_HV_VM_TYPE)
		return -ENOTSUPP;

	vcpu->arch.exit_reason = -1;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	/* create hypervisor backup hardware stacks */
	r = create_vcpu_backup_stacks(vcpu);
	if (r != 0)
		goto hv_uninit;

	/* create VCPU booting stacks */
	r = create_vcpu_boot_stacks(vcpu);
	if (r != 0)
		goto free_backup;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (!vcpu->arch.is_hv) {
		/* create the host VCPU context for multi-threading */
		r = create_vcpu_host_context(vcpu);
		if (r != 0)
			goto free_boot;
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

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
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	r = pic_get_vector_by_name(NULL, "/kvm", "KVM SysRq showstate",
			&vcpu->arch.sysrq_showstate_vector);
	if (r)
		goto mmu_destroy;
	r = pic_get_vector_by_name(NULL, "/kvm", "KVM NMI",
			&vcpu->arch.sysrq_nmi_vector);
	if (r)
		goto mmu_destroy;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	r = pic_get_vector_by_name(NULL, "/timer", NULL,
			&vcpu->arch.timer_vector);
	if (r)
		goto mmu_destroy;

	if (irqchip_in_kernel(vcpu->kvm)) {
		r = kvm_create_local_pic(vcpu);
		if (r != 0)
			goto mmu_destroy;
	}

	return 0;

mmu_destroy:
	vcpu_mmu_destroy(vcpu);
free_host:
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	destroy_vcpu_host_context(vcpu);
free_boot:
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	free_vcpu_boot_stacks(vcpu);
free_backup:
	free_kernel_backup_stacks(vcpu, &vcpu->arch.hypv_backup);
	kvm_arch_vcpu_ctxt_uninit(vcpu);
hv_uninit:
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	kvm_arch_hv_vcpu_uninit(vcpu);
pv_uninit:
	kvm_arch_pv_vcpu_uninit(vcpu);
	kvm_arch_any_vcpu_uninit(vcpu);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	return r;
}

int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu)
{
	int r;
	unsigned long epic_gstbase;

	DebugKVM("started\n");

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (vcpu->arch.is_hv)
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	{
		/* Set the pointer to the CEPIC page */
		epic_gstbase = (unsigned long)
		    page_address(vcpu->kvm->arch.epic_pages);
		vcpu->arch.hw_ctxt.cepic = (epic_page_t *) (epic_gstbase +
						(kvm_vcpu_to_full_cepic_id(vcpu) << PAGE_SHIFT));

		raw_spin_lock_init(&vcpu->arch.epic_dat_lock);
		vcpu->arch.epic_dat_active = false;
		kvm_init_cepic_idle_timer(vcpu);
	}

	vcpu_load(vcpu);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	switch (vcpu->kvm->arch.vm_type) {
	case KVM_E2K_SV_VM_TYPE:
	case KVM_E2K_SW_PV_VM_TYPE:
		r = kvm_arch_pv_vcpu_setup(vcpu);
		if (r != 0)
			goto error;
		break;
	case KVM_E2K_HV_VM_TYPE:
	case KVM_E2K_HW_PV_VM_TYPE:
		r = kvm_arch_hv_vcpu_setup(vcpu);
		if (r != 0)
			goto error;
		break;
	default:
		r = -ENOTSUPP;
		goto error;
	}

	r = kvm_arch_any_vcpu_setup(vcpu);
	if (r != 0)
		goto error;
#else
	if (vcpu->kvm->arch.vm_type != KVM_E2K_HV_VM_TYPE)
		return -ENOTSUPP;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	/* init hypervisor backup hardware stacks */
	r = init_vcpu_backup_stacks(vcpu);
	if (r != 0)
		goto error;

	/* init VCPU booting stacks */
	r = init_vcpu_boot_stacks(vcpu);
	if (r != 0)
		goto error;

	kvm_mmu_setup(vcpu);

error:
	vcpu_put(vcpu);
	return r;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static void reset_guest_vcpu_state(struct kvm_vcpu *vcpu)
{
	kvm_host_info_t __user *host_info;

	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);

	host_info = vcpu->kvm->arch.host_info;
	E2K_KVM_BUG_ON(host_info == NULL);
	host_info = (kvm_host_info_t __user __force *) kvm_vcpu_hva_to_gpa(vcpu,
							    (unsigned long)
							    host_info);
	E2K_KVM_BUG_ON(IS_INVALID_GPA((gpa_t)(unsigned long)host_info));
	vcpu->arch.kmap_vcpu_state->host = host_info;

	vcpu->arch.guest_vcpu_state = TO_GUEST_VCPU_STATE_PHYS_POINTER(vcpu);

	if (vcpu->arch.is_pv)
		kvm_reset_cpu_state_idr(vcpu);

	if (vcpu->arch.is_hv)
		goto out;

	kvm_reset_cpu_state(vcpu);

	kvm_reset_mmu_state(vcpu);

out:
	DebugKVM("VCPU #%d : setting host info structure at %px\n",
		 vcpu->vcpu_id, host_info);
}

static int init_guest_vcpu_state(struct kvm_vcpu *vcpu)
{
	kvm_host_info_t __user *host_info;
	gpa_t gpa;

	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);

	host_info = vcpu->kvm->arch.host_info;
	BUG_ON(host_info == NULL);
	gpa = kvm_vcpu_hva_to_gpa(vcpu, (unsigned long)host_info);
	if (IS_INVALID_GPA(gpa)) {
		pr_err("%s() : could not allocate GPA of host info struct\n",
		       __func__);
		goto error;
	}
	return 0;

error:
	kvm_free_host_info(vcpu->kvm);
	return -ENOMEM;
}

void guest_pv_vcpu_state_to_paging(struct kvm_vcpu *vcpu)
{
	kvm_host_info_t __user *host_info;

	host_info = vcpu->arch.kmap_vcpu_state->host;
	BUG_ON(host_info == NULL || vcpu->kvm->arch.host_info == NULL);
	vcpu->arch.kmap_vcpu_state->host = __guest_va(host_info);
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

void reset_cepic_state(struct kvm_vcpu *vcpu)
{
	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (vcpu->arch.epic)
		kvm_cepic_reset(vcpu);
	if (vcpu->arch.is_pv)
		kvm_reset_guest_cepic_virqs_num(vcpu);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
}

void reset_lapic_state(struct kvm_vcpu *vcpu)
{
	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);
	if (vcpu->arch.apic)
		kvm_lapic_restart(vcpu);
}

/*
 * VCPUs halt and wake ups are synchronized on e2k as follows:
 *
 *	VCPU0					VCPU1
 * --------------------------------------------------------------
 *  intercept "wait int"		Variant 1:
 *  kvm_vcpu_block() {			  send IPI to VCPU0
 *    kvm_arch_vcpu_blocking() {	  DAT hit -> write target CIR
 *      clear DAT and save EPIC		  kvm_arch_vcpu_blocking will see CIR.stat
 *    }
 *    < ... >				Variant 2:
 *    kvm_vcpu_check_block() {		  send IPI to VCPU0
 *      check PMIRR/PNMIRR/CIR		  DAT miss -> generate interception
 *      both in shadow registers	  cepic_epic_interrupt() {
 *      and in memory			    kvm_irq_delivery_to_epic():
 *    }					      either send through ICR if DAT
 *    < ... >				      is active (i.e. Variant 1) or
 *    kvm_arch_vcpu_unblocking() {	      write to PMIRR in memory where it
 *      restore EPIC and activate DAT	      will be seen by kvm_vcpu_check_block()
 *    }
 *  }
 *
 * Saving and restoring EPIC in kvm_arch_vcpu_[un]blocking() is necessary
 * because otherwise there is a race: "Variant 2" above could happen between
 * the check in kvm_vcpu_check_block() and the consequent schedule() call, in
 * which case VCPU0 will go sleep but VCPU1 will be sure that VCPU0 was woken.
 *
 * Synchronization is done by using KVM_MP_STATE_HALTED for indication whether
 * EPIC has been saved.  To avoid races we change the state and switch EPIC
 * context under closed interrupts.
 */
void kvm_arch_vcpu_blocking(struct kvm_vcpu *vcpu)
{
	BUG_ON(vcpu->arch.blocked);
	//TODO how this works for apic over hw epic
	if (kvm_vcpu_is_epic(vcpu)) {
		unsigned long flags;

		all_irq_save(flags);
		vcpu->arch.mp_state = KVM_MP_STATE_HALTED;
		kvm_epic_vcpu_blocking(&vcpu->arch);
		kvm_epic_start_idle_timer(vcpu);
		all_irq_restore(flags);
	}
	vcpu->arch.blocked = true;
}

void kvm_arch_vcpu_unblocking(struct kvm_vcpu *vcpu)
{
	BUG_ON(!vcpu->arch.blocked);
	if (kvm_vcpu_is_epic(vcpu)) {
		unsigned long flags;

		all_irq_save(flags);
		kvm_epic_stop_idle_timer(vcpu);
		kvm_epic_vcpu_unblocking(&vcpu->arch);
		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
		all_irq_restore(flags);
	}
	vcpu->arch.blocked = false;
}


#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static int __must_check fill_guest_cut_entry(e2k_cute_t __user *cute_p, enum cud_flag cudf,
		u64 code_base, u64 code_sz, u64 glob_base, u64 glob_sz)
{
	e2k_cute_t cute;
	cute.cud = new_cud(code_base, __ALIGN_MASK(code_sz, E2K_ALIGN_CODES_MASK), 1, cudf);
	cute.gd = new_gd(glob_base, __ALIGN_MASK(glob_sz, E2K_ALIGN_GLOBALS_MASK));

	return copy_to_user(cute_p, &cute, sizeof(cute)) ? -EFAULT : 0;
}

static int reset_guest_boot_cut(struct kvm_vcpu *vcpu)
{
	kvm_vcpu_state_t __user *vcpu_state = vcpu->arch.vcpu_state;
	e2k_cute_t __user *cute_p = vcpu->arch.guest_cut;

	if (cute_p == NULL) {
		E2K_KVM_BUG_ON(!vcpu->arch.is_hv);
		return 0;
	}
	E2K_KVM_BUG_ON(!vcpu->arch.is_pv);
	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);

	if (fill_guest_cut_entry(cute_p, cud_m64, 0, 0, 0, 0))
		return -EFAULT;
	DebugKVM("created guest CUT entry #0 zeroed at %px\n", cute_p);

	cute_p += GUEST_CODES_INDEX;
	if (fill_guest_cut_entry(cute_p, cud_m64, 0, 0,
				kvm_vcpu_hva_to_gpa(vcpu, (unsigned long)vcpu_state),
				sizeof(*vcpu_state)))
		return -EFAULT;

	DebugKVM("created guest CUT entry #%ld from 0x%llx size 0x%lx at %px\n",
		 GUEST_CODES_INDEX,
		 kvm_vcpu_hva_to_gpa(vcpu, (unsigned long)vcpu_state),
		 sizeof(*vcpu_state), cute_p);

	return 0;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static int kvm_setup_vcpu_thread(struct kvm_vcpu *vcpu)
{
	int ret = 0;

	DebugKVM("started to start guest kernel on VCPU %d\n", vcpu->vcpu_id);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (vcpu->arch.is_pv) {
		ret = pv_vcpu_setup_thread(vcpu);
	} else if (!vcpu->arch.is_hv) {
		E2K_KVM_BUG_ON(true);
		ret = -EINVAL;
	}

	kvm_init_clockdev(vcpu);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	set_kvm_mode_flag(vcpu->kvm, KVMF_VCPU_STARTED);

	return ret;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static int kvm_prepare_vcpu_start_stacks(struct kvm_vcpu *vcpu)
{
	int ret;

	if (vcpu->arch.is_hv) {
		ret = kvm_prepare_hv_vcpu_start_stacks(vcpu);
	} else if (vcpu->arch.is_pv) {
		ret = kvm_prepare_pv_vcpu_start_stacks(vcpu);
	} else {
		E2K_KVM_BUG_ON(true);
		ret = -EINVAL;
	}
	return ret;
}

static void init_vcpu_intc_ctxt(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.is_hv) {
		/* interceptions is supported by hardware */
		init_hv_vcpu_intc_ctxt(vcpu);
	} else if (vcpu->arch.is_pv) {
		/* interceptions is not supported by hardware */
		/* but emulated by software paravirtualization */
		init_pv_vcpu_intc_ctxt(vcpu);
	}
}
#else
static int kvm_prepare_vcpu_start_stacks(struct kvm_vcpu *vcpu)
{
	return kvm_prepare_hv_vcpu_start_stacks(vcpu);
}

static void init_vcpu_intc_ctxt(struct kvm_vcpu *vcpu)
{
	init_hv_vcpu_intc_ctxt(vcpu);
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static void write_hw_ctxt_to_vcpu_registers(struct kvm_vcpu *vcpu, const struct kvm_hw_cpu_context
					    *hw_ctxt, const struct kvm_sw_cpu_context
					    *sw_ctxt)
{
	write_hw_ctxt_to_hv_vcpu_registers(vcpu, hw_ctxt, sw_ctxt);
}

static void kvm_init_lintel_gregs(struct kvm_vcpu *vcpu)
{
	/*
	 * It need only pass pointer to bootinfo structure as %dg1 register
	 * but hypervisor pass as 0 & 1-st parameter and set:
	 *      %dg0 - BSP flag
	 *      %dg1 - bootinfo pointer
	 */
	NATIVE_SET_DGREG(0, vcpu->arch.args[0]);
	NATIVE_SET_DGREG(1, vcpu->arch.args[1]);
}

static void init_guest_image_hw_ctxt(struct kvm_vcpu *vcpu,
				     struct kvm_hw_cpu_context *hw_ctxt)
{
	e2k_cuir_t oscuir;
	e2k_cutd_t oscutd;
	e2k_addr_t guest_cut_pa;

	hw_ctxt->sh_oscud = vcpu_new_cud(vcpu, (u64)vcpu->arch.guest_phys_base,
				    vcpu->arch.guest_size, 0, cud_m64);

	hw_ctxt->sh_osgd = vcpu_new_gd(vcpu, (u64)vcpu->arch.guest_phys_base,
				  vcpu->arch.guest_size);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (vcpu->arch.guest_cut != NULL) {
		guest_cut_pa = kvm_vcpu_hva_to_gpa(vcpu, (unsigned long) vcpu->arch.guest_cut);
	} else
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	{
		guest_cut_pa = 0;
	}

	oscutd.base = guest_cut_pa;
	oscuir.index = 0;
	oscuir.checkup = 0;
	hw_ctxt->sh_oscutd = oscutd;
	vcpu->arch.sw_ctxt.cutd = oscutd;
	hw_ctxt->sh_oscuir = oscuir;
}

static void init_hw_ctxt(struct kvm_vcpu *vcpu)
{
	vcpu_boot_stack_t *boot_stacks = &vcpu->arch.boot_stacks;
	guest_hw_stack_t *boot_regs = &boot_stacks->regs;
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;
	struct kvm_arch *kvm = &vcpu->kvm->arch;
	epic_page_t *cepic = hw_ctxt->cepic;
	virt_ctrl_cu_t virt_ctrl_cu;
	union cepic_ctrl epic_reg_ctrl;
	union cepic_esr2 epic_reg_esr2;
	union cepic_timer_lvtt epic_reg_timer_lvtt;
	union cepic_pnmirr_mask epic_reg_pnmirr_mask;
	unsigned int i;

	/*
	 * Stack registers
	 */
	hw_ctxt->sh_psp = boot_regs->stacks.psp;
	hw_ctxt->sh_pcsp = boot_regs->stacks.pcsp;

	/* setup initial state of backup stacks */
	init_backup_hw_ctxt(vcpu);

	/* set shadow WD state to initial value */
	hw_ctxt->sh_wd = (e2k_wd_t) { 0 };

	/* MMU shadow context registers state */
	hw_ctxt->sh_mmu_cr = vcpu->arch.mmu.init_sh_mmu_cr;
	hw_ctxt->sh_pid = vcpu->arch.mmu.init_sh_pid;

	hw_ctxt->gid = kvm->vm_id;

	/*
	 * CPU shadow context
	 */

	/* guest image state should be saved */
	/* by kvm_set_hv_kernel_image() */
	init_guest_image_hw_ctxt(vcpu, hw_ctxt);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/* FIXME: guest now use paravirtualized register (in memory) */
	/* so set shadow OSR0 to host current_thread_info() to enable */
	/* host trap handler
	   osr0 = kvm_get_guest_vcpu_OSR0_value(vcpu);
	 */
#ifdef CONFIG_CPU_HAS_OSR1
	if (vcpu->arch.is_hv) {
		hw_ctxt->sh_osr0 = 0;
		hw_ctxt->sh_osr1 = 0;
	} else if (vcpu->arch.is_pv) {
		hw_ctxt->sh_osr0 = 0;
		hw_ctxt->sh_osr1 = (u64) current_thread_info();
	}
#else
	if (vcpu->arch.is_hv) {
		hw_ctxt->sh_osr0 = 0;
	} else if (vcpu->arch.is_pv) {
		hw_ctxt->sh_osr0 = (u64) current_thread_info();
	}
#endif
	if (vcpu->arch.is_hv) {
		hw_ctxt->sh_core_mode = read_SH_CORE_MODE_reg();
	} else if (vcpu->arch.is_pv) {
		hw_ctxt->sh_core_mode = kvm_get_guest_vcpu_CORE_MODE(vcpu);
	} else {
		E2K_KVM_BUG_ON(true);
	}
	/* turn ON indicators of GM and enbale hypercalls */
	if (vcpu->arch.is_hv) {
		hw_ctxt->sh_core_mode.gmi = 1;
		hw_ctxt->sh_core_mode.hci = 1;
	}
#else
	hw_ctxt->sh_osr0 = 0;
#ifdef CONFIG_CPU_HAS_OSR1
	hw_ctxt->sh_osr1 = 0;
#endif
	hw_ctxt->sh_core_mode = read_SH_CORE_MODE_reg();
	hw_ctxt->sh_core_mode.gmi = 1;
	hw_ctxt->sh_core_mode.hci = 1;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		hw_ctxt->sh_core_mode.getsp_v7 = vcpu_getsp_v7(vcpu);
		hw_ctxt->sh_core_mode.descr_v7 = vcpu_descr_v7(vcpu);
		hw_ctxt->sh_t_off = read_T_OFF();
	} else if (cpu_has(CPU_FEAT_ISET_V6)) {
		hw_ctxt->sh_sclkm3 = read_SCLKM3_reg_value();
	}

	/*
	 * VIRT_CTRL_* registers
	 */
	AW(virt_ctrl_cu) = 0;
	virt_ctrl_cu.rr_idr = 1; /* Must give proper core number */

	/*
	 * It is assumed that only guest's for iset<v7 are allowed
	 * to use sclkr (newer guests must switch to esclk).
	 *
	 * Hypervisor | guest | rw_sclkr | rr_sclkr | sclk_v6 | rw_sclkm3
	 * -----------+-------+----------+----------+---------+----------
	 *      v6    | <=v6  |     1    |   !init  |    X    |    1
	 *      v7    | <=v6  |     X    |     1    |    1    |    1
	 *      v7    |   v7  |     X    |     0    |    0    |    1
	 */
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		bool guest_v7 = (kvm->guest_info.cpu_iset >= E2K_ISET_V7);
		virt_ctrl_cu.since_v7.sclk_v6 = !guest_v7;
		virt_ctrl_cu.rr_sclkr = !guest_v7;
	} else {
		virt_ctrl_cu.v6_only.rw_sclkr = 1;
		virt_ctrl_cu.rr_sclkr = !use_sclk_sched_clock();
	}
	virt_ctrl_cu.rw_sclkm3 = 1;

	virt_ctrl_cu.virt = 1;
	virt_ctrl_cu.hcem = 1;

	hw_ctxt->virt_ctrl_cu = virt_ctrl_cu;
	hw_ctxt->virt_ctrl_mu = vcpu->arch.mmu.virt_ctrl_mu;
	hw_ctxt->g_w_imask_mmu_cr = vcpu->arch.mmu.g_w_imask_mmu_cr;

	/* Set CEPIC reset state */
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (vcpu->arch.is_hv)
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	{
		epic_reg_ctrl.raw = 0;
		epic_reg_ctrl.bsp_core = kvm_vcpu_is_bsp(vcpu);
		cepic->ctrl = epic_reg_ctrl.raw;
		cepic->id = kvm_vcpu_to_full_cepic_id(vcpu);
		cepic->cpr = 0;
		cepic->esr = 0;
		epic_reg_esr2.raw = 0;
		epic_reg_esr2.mask = 1;
		cepic->esr2 = epic_reg_esr2;
		cepic->cir.raw = 0;
		cepic->esr_new.counter = 0;
		cepic->icr.raw = 0;
		epic_reg_timer_lvtt.raw = 0;
		epic_reg_timer_lvtt.mask = 1;
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
		epic_reg_pnmirr_mask.nm_special = 1;
		epic_reg_pnmirr_mask.nm_timer = 1;
		epic_reg_pnmirr_mask.int_violat = 1;
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

		epic_reg_ctrl.soft_en = 1;
		cepic->ctrl = epic_reg_ctrl.raw;

		epic_reg_esr2.vect = 0xfe;
		epic_reg_esr2.mask = 0;
		cepic->esr2 = epic_reg_esr2;

		reg_div.raw = 0;
		reg_div.divider = CEPIC_TIMER_DIV_1;
		cepic->timer_div = reg_div.raw;

		epic_reg_svr.raw = 0;
		epic_reg_svr.vect = 0xff;
		cepic->svr = epic_reg_svr.raw;
	}
}

static int kvm_start_vcpu_thread(struct kvm_vcpu *vcpu)
{
	int ret;

	DebugKVM("started to start guest kernel on VCPU %d\n", vcpu->vcpu_id);

	ret = kvm_init_vcpu_thread(vcpu);
	if (ret != 0)
		return ret;

	ret = kvm_setup_vcpu_thread(vcpu);

	if (ret != 0)
		return ret;

	/* prepare start stacks */
	ret = kvm_prepare_vcpu_start_stacks(vcpu);
	if (ret != 0) {
		pr_err("%s(): could not prepare VCPU #%d start stacks, error %d\n",
			__func__, vcpu->vcpu_id, ret);
		return ret;
	}

	vcpu_load(vcpu);

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
					&vcpu->arch.hw_ctxt,
					&vcpu->arch.sw_ctxt);
	preempt_enable();

	/* prefetch MMIO space areas, which should be */
	/* directly accessed by guest */
	kvm_prefetch_mmio_areas(vcpu);

	/* Set global registers to empty state as start state of guest */
	// FIXME	INIT_G_REGS(true);
	/* Zeroing global registers used by kernel */
	// FIXME	CLEAR_KERNEL_GREGS_COPY(current_thread_info());
	/* Setup guest type special globals registers */
	if (test_kvm_mode_flag(vcpu->kvm, KVMF_LINTEL)) {
		kvm_init_lintel_gregs(vcpu);
	} else {
		/* Set pointer to VCPU state to enable interface with guest */
		// FIXMEINIT_HOST_VCPU_STATE_GREG_COPY(current_thread_info(), vcpu);
	}

	vcpu_put(vcpu);

	return 0;
}

static int kvm_arch_ioctl_reset_vcpu(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	int order_no;
	int err;

	/* VCPU should first be registered */
	order_no = atomic_inc_return(&kvm->arch.vcpus_to_reset);
	if (unlikely(order_no > atomic_read(&kvm->online_vcpus))) {
		/* recursive VCPUs reset */
		atomic_set(&kvm->online_vcpus, 1);
		order_no = 1;
		KVM_WARN_ON(true);
	}
	DebugKVMSH("started on VCPU #%d (number in order is %d)\n",
		   vcpu->vcpu_id, order_no);

	if (kvm_reset_error) {
		/* previous reset failed, kill kvm */
		return kvm_reset_error;
	}

	/* release previous state of VCPU to restart */
	vcpu_release_to_reboot(vcpu, order_no);

	if (order_no == 1) {
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		/* reset VM (common for all VM & VCPUs) */
		err = kvm_boot_spinlock_init(kvm);
		if (err)
			goto out_error;
		err = kvm_guest_spinlock_init(kvm);
		if (err)
			goto out_error;
		err = kvm_guest_csd_lock_init(kvm);
		if (err)
			goto out_error;
		if (unlikely(!vcpu->arch.is_hv && vcpu->arch.is_pv)) {
			kvm_pv_guest_thread_info_reset(kvm);
			kvm_guest_pv_mm_reset(kvm);
		}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
		kvm->arch.halted = false;
		kvm->arch.reboot = false;
	}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	vcpu_boot_spinlock_init(vcpu);
	err = reset_guest_boot_cut(vcpu);
	if (err)
		goto out_error;
	reset_guest_vcpu_state(vcpu);
	kvm_set_pv_vcpu_kernel_image(vcpu);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	reset_vcpu_backup_stacks(vcpu);
	reset_vcpu_boot_stacks(vcpu);
	kvm_mmu_reset(vcpu);
	reset_pic_state(vcpu);

	vcpu->arch.halted = false;
	vcpu->arch.reboot = false;
	vcpu->arch.exit_shutdown_terminate = 0;

	if (order_no == atomic_read(&kvm->online_vcpus))
		atomic_set(&kvm->arch.vcpus_to_reset, 0);

	err = 0;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
out_error:
	if (err)
		kvm_reset_error = err;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	return err;
}

/*
 * Boot loader should set OSCUD/OSGD to physical base and size of guest kernel
 * image before startup guest. So hypervisor should do same too.
 */
static void kvm_set_vcpu_kernel_image(struct kvm_vcpu *vcpu,
				      char *kernel_base,
				      unsigned long kernel_size)
{

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	E2K_KVM_BUG_ON(!vcpu->arch.is_hv &&
		       (e2k_addr_t) kernel_base >= GUEST_PAGE_OFFSET);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	vcpu->arch.guest_phys_base = (e2k_addr_t) kernel_base;
	vcpu->arch.guest_base = kernel_base;
	vcpu->arch.guest_size = kernel_size;

	DebugSHC("Guest kernel image: base 0x%px, size 0x%lx\n",
		 vcpu->arch.guest_base, vcpu->arch.guest_size);

}

static int kvm_arch_ioctl_vcpu_guest_startup(struct kvm_vcpu *vcpu,
					     kvm_vcpu_guest_startup_t __user *
					     guest_startup)
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
				  guest_args.kernel_base,
				  guest_args.kernel_size);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (vcpu->arch.is_hv) {
		/* should be always ttable #0 */
		trap_offset = 0;
	} else if (vcpu->arch.is_pv) {
		/* can be any ttable # from 32-63 */
		trap_offset = guest_args.trap_off;
	} else {
		E2K_KVM_BUG_ON(true);
		trap_offset = 0;
	}
#else
	trap_offset = 0;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
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

	/* Check updated guest type */
	vcpu->arch.sw_ctxt.l2_prefetcher_enabled = l2_prefetcher_enabled() &&
			!(test_kvm_mode_flag(vcpu->kvm, KVMF_LINTEL) &&
			  cpu_has(CPU_HWBUG_GENERATIONS_L2_PREF));

	return 0;
}

/*
 * Mutex should be locked by caller (if needs)
 */
struct kvm_vcpu *kvm_get_vcpu_on_id(struct kvm *kvm, int picid)
{
	unsigned long r;
	struct kvm_vcpu *vcpu;

	if (kvm_is_epic(kvm))
		picid = cepic_id_short_to_full(picid);

	kvm_for_each_vcpu(r, vcpu, kvm)
		if (vcpu->vcpu_id == picid)
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
	current_thread_info()->is_vcpu = NULL;
	vcpu->arch.host_task = NULL;
	mutex_unlock(&vcpu->arch.lock);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	kvm_arch_vcpu_release(vcpu);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
}

static void kvm_halt_all_host_vcpus(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	unsigned long r;

	DebugKVMSH("%s (%d) started\n", current->comm, current->pid);

	mutex_lock(&kvm->lock);
	kvm_for_each_vcpu(r, vcpu, kvm) {
		if (vcpu != NULL) {
			if (vcpu->arch.host_task != NULL) {
				kvm_halt_host_vcpu_thread(vcpu);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
			} else {
				free_vcpu_state(vcpu);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
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
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	} else {
		kvm_arch_vcpu_release(vcpu);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (!vcpu->arch.is_hv) {
		wait_for_completion(&vcpu->arch.released);
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	DebugKVMSH("VCPU #%d released\n", vcpu->vcpu_id);
}

void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	DebugKVMSH("%s (%d) started for VCPU %d\n",
		   current->comm, current->pid, vcpu->vcpu_id);
	kvm_arch_vcpu_uninit(vcpu);
	kvm_free_local_pic(vcpu);
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static void kvm_arch_free_vcpu_virqs(struct kvm_vcpu *vcpu)
{
	DebugKVMSH("VCPU #%d started\n", vcpu->vcpu_id);
	kvm_cancel_clockdev(vcpu);
	kvm_clear_pending_virqs(vcpu);
	kvm_clear_virqs_injected(vcpu);
	kvm_reset_guest_lapic_virqs_num(vcpu);
}

static void kvm_arch_free_all_vcpus_virqs(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	unsigned long r;

	DebugKVMSH("%s (%d) started\n", current->comm, current->pid);
	mutex_lock(&kvm->lock);
	kvm_for_each_vcpu(r, vcpu, kvm) {
		if (vcpu != NULL) {
			kvm_arch_free_vcpu_virqs(vcpu);
		}
	}
	mutex_unlock(&kvm->lock);
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static void kvm_arch_release_all_vcpus(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	unsigned long r;

	DebugKVMSH("%s (%d) started\n", current->comm, current->pid);

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
	unsigned long r;

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
	kfree(kvm->arch.vioapic);
	kvm->arch.vioapic = NULL;
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
		atomic_read(&page->_mapcount), page->inuse, page->objects);
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
#else /* ! WANT_PAGE_VIRTUAL */
	pr_info("   kernel virtual address 0x%px\n", page_address(page));
#endif /* WANT_PAGE_VIRTUAL */
#ifdef CONFIG_WANT_PAGE_DEBUG_FLAGS
	pr_info("   debug flags 0x%016lx\n", page->debug_flags);
#endif
#if	defined(CONFIG_E2K) && defined(CONFIG_VIRTUALIZATION)
	pr_info("   kvm %px gfn 0x%lx user mapps %d\n",
		page->kvm, page->gfn, atomic_read(&page->user_maps));
#endif /* CONFIG_E2K && CONFIG_VIRTUALIZATION */
}
#else /* ! DUMP_PAGE_STRUCT */
void dump_page_struct(struct page *page)
{
}
#endif /* DUMP_PAGE_STRUCT */

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

static void kvm_free_all_interrupts(struct kvm *kvm)
{
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	kvm_free_all_VIRQs(kvm);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	kvm_free_all_spmc(kvm);
	kvm_free_all_lt(kvm);
}

#define	MAX_MASTER_WAITING_TIMES	0x10000
#define	MAX_SLAVE_WAITING_TIMES		(MAX_MASTER_WAITING_TIMES * 16)

static void master_vcpu_to_reboot(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	unsigned flags = (OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG | GP_ROOT_PT_FLAG);

	/* the maseter VCPU releases main KVM structures */
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	kvm_arch_free_all_vcpus_virqs(kvm);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	kvm_free_all_interrupts(kvm);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	kvm_boot_spinlock_destroy(kvm);
	kvm_guest_spinlock_destroy(kvm);
	kvm_guest_csd_lock_destroy(kvm);
	if (unlikely(vcpu->arch.is_pv && !vcpu->arch.is_hv)) {
		kvm_guest_pv_mm_free(kvm);
		kvm_pv_guest_thread_info_free(kvm);
		vcpu_clear_signal_stack(vcpu);
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	mmu_free_roots(vcpu, flags);

	kvm_mmu_destroy(kvm);

	vcpu_mmu_destroy(vcpu);
}

static void slave_vcpu_to_reboot(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (unlikely(vcpu->arch.is_pv && !vcpu->arch.is_hv)) {
		vcpu_clear_signal_stack(vcpu);
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	vcpu_mmu_destroy(vcpu);
}

static void vcpu_release_to_reboot(struct kvm_vcpu *vcpu, int order_no)
{
	DebugKVMSH("%s (%d) VCPU #%d (number in order %d) is %s to reboot\n",
		   current->comm, current->pid,
		   vcpu->vcpu_id, order_no,
		   (order_no == 1) ? "master" : "slave");
	if (order_no == 1) {
		/* it is first VCPU ready to reboot, so will be master */
		master_vcpu_to_reboot(vcpu);
	} else {
		slave_vcpu_to_reboot(vcpu);
	}
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	struct task_struct *p;

	DebugKVMSH("%s (%d) started\n", current->comm, current->pid);

	if (current_thread_info()->virt_machine == NULL)
		current_thread_info()->virt_machine = kvm;

	kvm_free_all_interrupts(kvm);

	/*
	 * Halting VCPU frees runstate, used by kvm timers.
	 * So PIC, LT, SPMC should be freed first
	 * FIXME: PIC is currently freed later, in kvm_arch_free_all_vcpus()
	 */
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (kvm->arch.is_pv && !kvm->arch.is_hv) {
		kvm_guest_pv_mm_destroy(kvm);
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	kvm_arch_release_all_vcpus(kvm);
	kvm_halt_all_host_vcpus(kvm);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	kvm_free_host_info(kvm);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	kvm_nbsr_destroy(kvm);
	kvm_iopic_release(kvm);
	kvm_free_passthrough(kvm);
	kvm_free_epic_pages(kvm);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	kvm_boot_spinlock_destroy(kvm);
	kvm_guest_spinlock_destroy(kvm);
	kvm_guest_csd_lock_destroy(kvm);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	kvm_arch_free_all_vcpus(kvm);
	kvm_mmu_uninit_vm(kvm);
	kvm_page_track_cleanup(kvm);
	ida_free(&vmid_ida, kvm->arch.vm_id);

	rcu_read_lock();
	for_each_thread(current, p)
		task_thread_info(p)->virt_machine = NULL;
	rcu_read_unlock();
}

static void kvm_switch_g_gregs(struct kvm_vcpu *vcpu)
{
	volatile struct global_gregs g_gregs;

	machine.save_global_gregs((struct global_gregs *) &g_gregs);
	machine.restore_global_gregs(&vcpu->arch.sw_ctxt.g_gregs);
	tagged_memcpy_8(&vcpu->arch.sw_ctxt.g_gregs, (struct global_gregs *) &g_gregs,
			sizeof(vcpu->arch.sw_ctxt.g_gregs));
}

void kvm_arch_vcpu_put(struct kvm_vcpu *vcpu, bool schedule)
{
	unsigned long flags;

	DebugKVMRUN("started on VCPU %d\n", vcpu->vcpu_id);
	trace_vcpu_put(vcpu->vcpu_id, vcpu->cpu, schedule);
	trace_kvm_pid(FROM_VCPU_PUT, vcpu->kvm->arch.vm_id, vcpu->vcpu_id,
		      read_guest_PID_reg(vcpu));
	set_bit(KVM_REQ_KICK, (void *)&vcpu->requests);

	local_irq_save(flags);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (vcpu->arch.is_hv)
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
		machine.save_kvm_context(&vcpu->arch);

	kvm_switch_g_gregs(vcpu);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (!schedule && vcpu->arch.is_pv) {
		/* switch VCPU guest context to host context */
		pv_vcpu_exit_to_host(vcpu);
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	local_irq_restore(flags);

	/* remember that this thread is thread of the kvm vcpu */
	/* and only scheduled from cpu or switched to vcpu-qemu mode */
	if (current_thread_info()->vcpu) {
		E2K_KVM_BUG_ON(current_thread_info()->is_vcpu == NULL);
		current_thread_info()->vcpu = NULL;
	} else {
		E2K_KVM_BUG_ON(current_thread_info()->is_vcpu != NULL);
	}
}

static DEFINE_PER_CPU(struct kvm_vcpu *, last_vcpu) = NULL;

void kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu, bool schedule)
{
	int last_cpu = vcpu->cpu;
	unsigned long flags;

	DebugKVMRUN("started on VCPU %d CPU %d\n", vcpu->vcpu_id, cpu);

	if (current_thread_info()->is_vcpu) {
		E2K_KVM_BUG_ON(vcpu != current_thread_info()->is_vcpu);
		current_thread_info()->vcpu = vcpu;
	}

	vcpu->cpu = cpu;
	trace_vcpu_load(vcpu->vcpu_id, last_cpu, cpu, schedule);
	clear_bit(KVM_REQ_KICK, (void *)&vcpu->requests);

	local_irq_save(flags);
	if (cpu != last_cpu || per_cpu(last_vcpu, cpu) != vcpu) {
		/* bug 113981 comment 18: flush TLB/IB when moving
		 * to a new CPU to fix problems with GID reuse.
		 *
		 * bug 106525 comment 3: flush TLB/IB when changing
		 * VCPU on a real CPU, as MMU PIDs are per-cpu. */
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		if (vcpu->arch.is_hv)
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
		{
			local_flush_tlb_all();
			__flush_icache_all();
		}
	}
	per_cpu(last_vcpu, cpu) = vcpu;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (vcpu->arch.is_hv)
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
		machine.restore_kvm_context(&vcpu->arch);

	trace_kvm_pid(FROM_VCPU_LOAD, vcpu->kvm->arch.vm_id, vcpu->vcpu_id,
		      read_guest_PID_reg(vcpu));

	kvm_switch_g_gregs(vcpu);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (!schedule && vcpu->arch.is_pv) {
		/* switch VCPU host context to guest context */
		pv_vcpu_enter_to_guest(vcpu);
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	local_irq_restore(flags);
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
void kvm_arch_vcpu_to_wait(struct kvm_vcpu *vcpu)
{
	clear_bit(KVM_REQ_KICK, (void *)&vcpu->requests);
}

void kvm_arch_vcpu_to_run(struct kvm_vcpu *vcpu)
{
	set_bit(KVM_REQ_KICK, (void *)&vcpu->requests);
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
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	DebugUNIMPL("started for VCPU %d\n", vcpu->vcpu_id);
	DebugUNIMPL("does not implemented\n");
	return 0;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static void kvm_arch_vcpu_release(struct kvm_vcpu *vcpu)
{
	DebugKVMSH("started for VCPU %d\n", vcpu->vcpu_id);

	kvm_arch_free_vcpu_virqs(vcpu);
	free_vcpu_state(vcpu);
	if (!vcpu->arch.is_hv) {
		complete(&vcpu->arch.released);
	}
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

void kvm_arch_vcpu_free(struct kvm_vcpu *vcpu)
{
	DebugKVMSH("started for VCPU %d\n", vcpu->vcpu_id);

	kvm_arch_vcpu_destroy(vcpu);
}

static void kvm_arch_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	unsigned flags = OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG | GP_ROOT_PT_FLAG;

	DebugKVMSH("started for VCPU %d\n", vcpu->vcpu_id);

	vcpu->arch.halted = true;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	kvm_arch_pv_vcpu_uninit(vcpu);
	kvm_arch_hv_vcpu_uninit(vcpu);
	kvm_arch_any_vcpu_uninit(vcpu);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	/* free hypervisor backup hardware stacks */
	free_kernel_backup_stacks(vcpu, &vcpu->arch.hypv_backup);
	/* free VCPU booting stacks */
	free_vcpu_boot_stacks(vcpu);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	destroy_vcpu_host_context(vcpu);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	kvm_free_local_pic(vcpu);
	mmu_free_roots(vcpu, flags);
	vcpu_mmu_destroy(vcpu);
	/* free vcpu ctxt last, it can be used when freeing mmu */
	kvm_arch_vcpu_ctxt_uninit(vcpu);
}

long kvm_arch_vcpu_ioctl(struct file *filp,
			 unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;
	long r;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	struct kvm_lapic_state *lapic = NULL;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	DebugKVM("started for VCPU %d ioctl 0x%x\n", vcpu->vcpu_id, ioctl);
	switch (ioctl) {
	case KVM_VCPU_THREAD_SETUP:
		DebugKVM("ioctl is KVM_VCPU_THREAD_SETUP\n");
		r = kvm_start_vcpu_thread(vcpu);
		break;
	case KVM_RESET_E2K_VCPU:
		DebugKVM("ioctl is KVM_RESET_VCPU\n");
		r = kvm_arch_ioctl_reset_vcpu(vcpu);
		break;
	case KVM_VCPU_GUEST_STARTUP:{
			kvm_vcpu_guest_startup_t __user *guest_startup;

			DebugKVM("ioctl is KVM_VCPU_GUEST_STARTUP\n");
			guest_startup = (kvm_vcpu_guest_startup_t __user *) argp;
			r = kvm_arch_ioctl_vcpu_guest_startup(vcpu, guest_startup);
			break;
		}
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	case KVM_INTERRUPT:{
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
	case KVM_GET_LAPIC:{
			DebugKVM("ioctl is KVM_GET_LAPIC\n");
			r = -EINVAL;
			if (!vcpu->arch.apic)
				goto out;
			lapic =
			    kzalloc(sizeof(struct kvm_lapic_state), GFP_KERNEL);

			r = -ENOMEM;
			if (!lapic)
				goto out;
			r = kvm_vcpu_ioctl_get_lapic(vcpu, lapic);
			if (r)
				goto out;
			r = -EFAULT;
			if (copy_to_user
			    (argp, lapic, sizeof(struct kvm_lapic_state)))
				goto out;
			r = 0;
			break;
		}
	case KVM_SET_LAPIC:{
			r = -EINVAL;
			DebugKVM("ioctl is KVM_SET_LAPIC\n");
			if (!vcpu->arch.apic)
				goto out;
			lapic =
			    kmalloc(sizeof(struct kvm_lapic_state), GFP_KERNEL);
			r = -ENOMEM;
			if (!lapic)
				goto out;
			r = -EFAULT;
			if (copy_from_user
			    (lapic, argp, sizeof(struct kvm_lapic_state)))
				goto out;
			r = kvm_vcpu_ioctl_set_lapic(vcpu, lapic);
			if (r)
				goto out;
			r = 0;
			break;
		}
	case KVM_SET_VAPIC_ADDR:{
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
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	default:
		r = -EINVAL;
	}
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
out:
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	return r;
}

static int kvm_create_memslot(struct kvm *kvm, struct kvm_memory_slot *slot,
		       unsigned long npages)
{
	const pt_struct_t *pt_struct = mmu_pt_get_host_pt_struct(kvm);
	int i;
	gfn_t bgfn = slot->base_gfn;

	DebugKVM("started for slot ID #%d base gfn 0x%llx pages 0x%lx user addr 0x%lx\n",
		 slot->id, bgfn, npages, slot->userspace_addr);
	for (i = 0; i < KVM_NR_PAGE_SIZES; ++i) {
		const pt_level_t *pt_level;
		kvm_lpage_info_t *linfo;
		unsigned long ugfn;
		int lpages;
		int disallow_lpages = 0;
		int level = i + 1;

		if (level > pt_struct->levels_num)
			/* no more levels */
			break;

		pt_level = get_pt_struct_level_on_id(pt_struct, level);
		if (!is_page_pt_level(pt_level) && !is_huge_pt_level(pt_level))
			/* nothing pages on the level */
			continue;

		lpages = gfn_to_index(bgfn + npages - 1, bgfn, pt_level) + 1;

		slot->arch.rmap[i] = kvzalloc(lpages * sizeof(*slot->arch.rmap[i]), GFP_KERNEL);
		if (!slot->arch.rmap[i])
			goto out_free;
		DebugKVM("created RMAP %px to map 0x%x pages on PT level #%d\n",
			 slot->arch.rmap[i], lpages, level);

		if (!is_huge_pt_level(pt_level))
			/* the page table level has not huge pages */
			continue;

		linfo = kvzalloc(lpages * sizeof(*linfo), GFP_KERNEL);
		if (!linfo)
			goto out_free;

		slot->arch.lpage_info[i - 1] = linfo;

		if (bgfn & (KVM_PT_LEVEL_PAGES_PER_HPAGE(pt_level) - 1)) {
			linfo[0].disallow_lpage = 1;
			disallow_lpages++;
		}
		if ((bgfn + npages) &
		    (KVM_PT_LEVEL_PAGES_PER_HPAGE(pt_level) - 1)) {
			linfo[lpages - 1].disallow_lpage = 1;
			disallow_lpages++;
		}
		DebugKVM("created huge pages INFO %px to map 0x%x pages on PT level #%d\n",
			 slot->arch.lpage_info[i - 1], lpages, level);
		ugfn = slot->userspace_addr >> PAGE_SHIFT;
		/*
		 * If the gfn and userspace address are not aligned wrt each
		 * other, or if explicitly asked to, disable large page
		 * support for this slot
		 */
		if ((bgfn ^ ugfn) &
		    (KVM_PT_LEVEL_PAGES_PER_HPAGE(pt_level) - 1)) {
			unsigned long j;

			for (j = 0; j < lpages; ++j)
				linfo[j].disallow_lpage = 1;
			disallow_lpages++;
		}
		if (disallow_lpages != 0) {
			DebugKVM("disallowed %d huge pages on PT level #%d\n",
				 disallow_lpages, level);
		}
	}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (kvm_page_track_create_memslot(slot, npages))
		goto out_free;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	return 0;

out_free:
	for (i = 0; i < KVM_NR_PAGE_SIZES; ++i) {
		const pt_level_t *pt_level;
		int level = i + 1;

		pt_level = &pt_struct->levels[level];
		kvfree(slot->arch.rmap[i]);
		slot->arch.rmap[i] = NULL;
		if (!is_huge_pt_level(pt_level))
			/* the page table level has not huge pages */
			continue;

		kvfree(slot->arch.lpage_info[i - 1]);
		slot->arch.lpage_info[i - 1] = NULL;
	}
	return -ENOMEM;
}

/* User area is allocated here, but freed in kvm_arch_free_memslot */
int kvm_arch_prepare_memory_region(struct kvm *kvm, const struct kvm_memory_slot *old,
				   struct kvm_memory_slot *new, enum kvm_mr_change change)
{
	int slot, npages, node_id;
	unsigned long guest_size, guest_start, guest_end;
	gfn_t base_gfn;
	bool vram;
	user_area_t *guest_area;

	if (change == KVM_MR_DELETE) {
		DebugKVM("memory region should be deleted (some later)\n");
		return 0;
	}

	slot = new->id;
	guest_size = new->npages << PAGE_SHIFT;
	npages = new->npages;
	base_gfn = new->base_gfn;
	guest_start = new->userspace_addr;
	guest_end = guest_start + (npages << PAGE_SHIFT);
	guest_area = NULL;

	/* Compatibility with older qemu-7.2 versions which
	 * did not expect hypervisor without VRAM region */
	vram = kvm_is_vcpu_vram_gfn(base_gfn);

	DebugKVM("slot %d%s: base pfn 0x%llx guest virtual from 0x%lx to 0x%lx\n",
		slot, vram ? " (VRAM)" : "", base_gfn, guest_start, guest_end);

	if (kvm_create_memslot(kvm, new, npages))
		return -ENOMEM;

	if (guest_start == 0) {
		pr_err("%s(): slot %d: base gfn 0x%llx size 0x%x pages is not allocated by user and cannot be used\n",
		       __func__, slot, base_gfn, npages);
		return -ENOENT;
	}

	if (vram)
		new->arch.guest_areas.type = guest_vram_mem_type;
	else
		new->arch.guest_areas.type = guest_ram_mem_type;

	if (change == KVM_MR_FLAGS_ONLY) {
		DebugKVM("should be changed only flags of region: s not implemented\n");
		return -EINVAL;
	} else if (change == KVM_MR_MOVE) {
		DebugKVM("memory region should be moved\n");
	} else if (change == KVM_MR_CREATE) {
		DebugKVM("memory region should be created\n");
	} else {
		DebugKVM("unknown operation %d for memory region\n", change);
		return -EINVAL;
	}

	guest_area = new->arch.guest_areas.area;

	if (guest_area == NULL) {
		guest_area = user_area_create(guest_start, guest_size,
						USER_AREA_ORDERED);
		if (guest_area == NULL) {
			pr_err("kvm_arch_set_memory_region() slot %d: base gfn 0x%llx guest virtual from 0x%lx to 0x%lx could not create guest area support\n",
				slot, base_gfn, guest_start, guest_end);
			return -ENOENT;
		}
		new->arch.guest_areas.area = guest_area;
		DebugKVM("created guest area support at %px from 0x%lx to 0x%lx\n",
			guest_area, guest_area->area_start, guest_area->area_end);

		if (!vram) {
			if (!kvm->arch.nbsr)
				return -EINVAL;

			/* FIXME: it need support NUMA mode, */
			/* now node is only #0 */
			node_id = 0;
			nbsr_setup_memory_region(kvm->arch.nbsr, node_id,
						 gfn_to_gpa(base_gfn), guest_size);
			DebugKVM("setup NBSR routers for node #%d memory region from 0x%llx to 0x%llx\n",
				node_id, gfn_to_gpa(base_gfn),
				gfn_to_gpa(base_gfn) + guest_size);
		}
	} else {
		DebugKVM("guest area support was already created "
			"at %px from 0x%lx to 0x%lx\n",
			guest_area,
			guest_area->area_start, guest_area->area_end);
	}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	new->arch.page_size = kvm_slot_page_size(new, base_gfn);
	DebugKVM("slot ID #%d host page size set to 0x%lx\n",
		slot, new->arch.page_size);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	return 0;
}

void kvm_arch_free_memory_region(struct kvm *kvm,
				 struct kvm_memory_slot *memslot)
{
	unsigned long base_gfn = memslot->base_gfn;
	unsigned long guest_start = memslot->userspace_addr;
	unsigned long npages = memslot->npages;
	unsigned long guest_end = guest_start + (npages << PAGE_SHIFT);
	user_area_t *guest_area;

	DebugKVM("slot base pfn 0x%lx guest virtual from 0x%lx to 0x%lx\n",
		 base_gfn, guest_start, guest_end);
	if (npages == 0)
		return;
	if (memslot->userspace_addr == 0) {
		DebugKVM("slot base gfn 0x%lx size 0x%lx pages is not allocated by user so cannot be freed\n",
			 base_gfn, npages);
		return;
	}
	guest_area = memslot->arch.guest_areas.area;
	if (guest_area == NULL) {
		DebugKVM("slot base gfn 0x%lx guest virtual from 0x%lx to 0x%lx has not guest area support\n",
			 base_gfn, guest_start, guest_end);
		return;
	}
	user_area_release(guest_area);
	memslot->arch.guest_areas.area = NULL;

	return;
}

int kvm_gva_to_memslot_unaliased(struct kvm *kvm, gva_t gva)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	struct kvm_memory_slot *memslot;
	int bkt;

	DebugKVMPF("started for guest addr 0x%lx\n", gva);
	kvm_for_each_memslot(memslot, bkt, slots) {
		DebugKVMPF("current slot #%d base addr 0x%lx size 0x%lx\n",
			   memslot->id, memslot->userspace_addr,
			   memslot->npages << PAGE_SHIFT);
		if (gva >= memslot->userspace_addr &&
		    gva < memslot->userspace_addr + (memslot->npages << PAGE_SHIFT))
			return memslot->id;
	}
	DebugKVMPF("guest addres 0x%lx not found\n", gva);
	return -1;
}

gva_t kvm_gva_to_gpa(struct kvm *kvm, gva_t gva)
{
	int slot;

	DebugKVMPF("started for guest addr 0x%lx\n", gva);

	slot = kvm_gva_to_memslot_unaliased(kvm, gva);
	if (slot < 0) {
		DebugKVMPF("could not find memory slot for address 0x%lx\n",
			gva);
		return (gva_t)-1;
	}

	return gva;
}

#ifndef	CONFIG_KVM_SHADOW_PT_ENABLE
gpa_t kvm_vcpu_gva_to_gpa(struct kvm_vcpu *vcpu, gva_t gva, u32 access,
			  kvm_arch_exception_t *exception)
{
	gva_t gvpa = kvm_gva_to_gpa(vcpu->kvm, gva);

	if (gvpa == (gva_t) -1)
		return UNMAPPED_GVA;
	return (gpa_t)__guest_pa(gvpa);
}
#endif /* ! CONFIG_KVM_SHADOW_PT_ENABLE */

static user_area_t *kvm_do_find_memory_region(struct kvm *kvm,
					      int slot, e2k_addr_t address,
					      e2k_size_t size, bool phys_mem,
					      e2k_addr_t *virt_address,
					      kvm_guest_mem_type_t type)
{
	struct kvm_memory_slot *memslot;
	user_area_t *guest_area;
	kvm_guest_mem_type_t guest_type;
	int id, bkt, as_id, as_id_from, as_id_to;
	int srcu_idx;

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
		id = (u16) slot;
		as_id_from = as_id;
		as_id_to = as_id;
	} else {
		id = -1;
		as_id_from = 0;
		as_id_to = KVM_ADDRESS_SPACE_NUM - 1;
	}
	if (type == 0)
		type = guest_ram_mem_type;

	srcu_idx = srcu_read_lock(&kvm->srcu);
	for (as_id = as_id_from; as_id <= as_id_to; as_id++) {
		kvm_for_each_memslot(memslot, bkt, __kvm_memslots(kvm, as_id)) {
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
				DebugKVM("slot %d has other memory type 0x%x != 0x%x to find\n",
					 memslot->id, guest_type, type);
				continue;
			}
			guest_area = memslot->arch.guest_areas.area;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
			if (phys_mem) {
				gpa_t base_gpa = gfn_to_gpa(memslot->base_gfn);
				e2k_size_t area_size = guest_area->area_end -
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
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
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
			if (size > guest_area->freebytes) {
				DebugKVM("not enough memory in slot #%d "
					"(need 0x%lx, free 0x%lx)\n",
					memslot->id, size,
					guest_area->freebytes);
				continue;
			}
			/*
			 * Avoid allocating memory from low VGA memslot: it
			 * can easily run out of memory for user_area_alloc
			 * FIXME: implement ENOMEM handling for user_area_alloc
			 */
			if (!address && guest_type == guest_ram_mem_type &&
					guest_area->freebytes <= VGA_VRAM_PHYS_BASE) {
				DebugKVM("slot #%d is too small (0x%lx) for allocation, prefer other slots\n",
					memslot->id, guest_area->freebytes);
				continue;
			}
			DebugKVM("found memory region from 0x%lx to 0x%lx at slot #%d\n",
				guest_area->area_start, guest_area->area_end, memslot->id);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
			if (phys_mem && virt_address != NULL)
				*virt_address = address;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
			srcu_read_unlock(&kvm->srcu, srcu_idx);
			return guest_area;
		}
	}
	srcu_read_unlock(&kvm->srcu, srcu_idx);

	DebugKVM("could not find any suitable memory slot\n");
	return NULL;
}

static user_area_t *kvm_find_memory_region(struct kvm *kvm,
					   int slot, e2k_addr_t address,
					   e2k_size_t size,
					   kvm_guest_mem_type_t type)
{
	return kvm_do_find_memory_region(kvm, slot, address, size,
					 false, /* phys memory ? */ NULL, type);
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static user_area_t *kvm_find_phys_memory_region(struct kvm *kvm,
						int slot, gpa_t gpa,
						e2k_size_t size,
						e2k_addr_t *virt_address,
						kvm_guest_mem_type_t type)
{
	return kvm_do_find_memory_region(kvm, slot, gpa, size, true, virt_address, type);
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static long kvm_arch_ioctl_alloc_guest_area(struct kvm *kvm,
					    kvm_guest_area_alloc_t __user *what)
{
	kvm_guest_area_alloc_t guest_chunk;
	user_area_t *guest_area;
	e2k_addr_t size;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	e2k_addr_t region_addr;
	kvm_guest_mem_type_t type;
	bool phys_mem = false;
	unsigned long flags;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	void __user *chunk;
	int ret = 0;

	if (copy_from_user(&guest_chunk, what, sizeof(guest_chunk))) {
		DebugKVM("copy to %px from user %px failed\n",
			 &guest_chunk, what);
		return -EFAULT;
	}
	DebugKVM("started for region %px, start 0x%lx, size 0x%lx type %s align 0x%lx\n",
		 guest_chunk.region, guest_chunk.start, guest_chunk.size,
		 (guest_chunk.type & guest_vram_mem_type) ? "VRAM" : "RAM",
		 guest_chunk.align);
	size = guest_chunk.size;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
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
		region_addr = (e2k_addr_t) guest_chunk.region;
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
		guest_area = kvm_find_memory_region(kvm, -1, region_addr, size, type);
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
#else
	if (guest_chunk.type || guest_chunk.region || guest_chunk.start ||
			(guest_chunk.flags & ~KVM_ALLOC_AREA_LOW)) {
		return -EINVAL;
	}
	if (test_kvm_mode_flag(kvm, KVMF_VCPU_STARTED)) {
		/* VCPUs started and RAM is now allocated by guest */
		return -ENOMEM;
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
	guest_area = kvm_find_memory_region(kvm, -1, 0, size, guest_ram_mem_type);
	if (guest_area == NULL) {
		DebugKVM("could not find memory region\n");
		ret = -EINVAL;
		goto out_unlock;
	}
	chunk = user_area_get(guest_area, guest_chunk.start,
			      guest_chunk.size, guest_chunk.align, 0);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
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
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	E2K_KVM_BUG_ON(vcpu->cpu < 0);

	if (!vcpu->arch.is_hv && vcpu->cpu != cpu)
		mmu_pt_switch_kernel_pgd_range(vcpu, cpu);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
}

static long kvm_arch_ioctl_get_guest_address(unsigned long __user *addr)
{
	struct kvm *kvm = (struct kvm *)current_thread_info()->virt_machine;
	unsigned long address = -1;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	unsigned long cut_size;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	long r;

	if (kvm == NULL || !test_kvm_mode_flag(kvm, KVMF_ARCH_API_TAKEN)) {
		pr_err("qemu version is too old and cannot be run on KVM e2k api version %d\n",
		     KVM_ARCH_API_VERSION);
		return -EINVAL;
	}
	r = get_user(address, addr);
	if (r) {
		DebugKVM("get_user() failed for user address 0x%px\n", addr);
		return r;
	}
	DebugKVM("started for address 0x%px\n", addr);
	switch (address) {
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
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
		cut_size = sizeof(e2k_cute_t) * MAX_GUEST_CODES_UNITS;
		address = round_up(GUEST_ONE_VCPU_VRAM_SIZE, PAGE_SIZE) +
		    round_up(cut_size, PAGE_SIZE);
		break;
	case KVM_HOST_INFO_VRAM_SIZE:
		DebugKVM("address is KVM_HOST_INFO_VRAM_SIZE\n");
		address = round_up(HOST_INFO_VCPU_VRAM_SIZE, PAGE_SIZE);
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
	case KVM_HOST_PAGE_OFFSET:
		DebugKVM("address is KVM_HOST_PAGE_OFFSET\n");
		address = HOST_PAGE_OFFSET;
		break;
	case KVM_KERNEL_AREAS_SIZE:
		DebugKVM("address is KVM_KERNEL_AREAS_SIZE\n");
		address = E2K_KERNEL_AREAS_SIZE;
		break;
	case KVM_SHADOW_KERNEL_IMAGE_BASE:
		DebugKVM("address is KVM_SHADOW_KERNEL_IMAGE_BASE\n");
		address = SHADOW_KERNEL_IMAGE_AREA_BASE;
		break;
#else
	case KVM_GUEST_VCPU_VRAM_PHYS_BASE:
		/* Compatibility with older qemu-7.2 versions which
		 * did not expect hypervisor without VRAM region */
		address = GUEST_VCPU_VRAM_PHYS_BASE;
		break;
	case KVM_GUEST_VCPU_VRAM_SIZE:
	case KVM_HOST_INFO_VRAM_SIZE:
		/* Compatibility with older qemu-7.2 versions which
		 * did not expect hypervisor without VRAM region */
		address = 0x1000;
		break;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	case KVM_GUEST_NBSR_BASE:
		DebugKVM("address is KVM_GUEST_NBSR_BASE\n");
		address = (unsigned long)GUEST_NBSR_BASE;
		break;
	case KVM_HOST_KERNEL_IMAGE_BASE:
		DebugKVM("address is KVM_HOST_KERNEL_IMAGE_BASE\n");
		address = HOST_KERNEL_IMAGE_AREA_BASE;
		break;
	default:
		DebugKVM("ioctl is unsupported\n");
		return -EINVAL;
	}
	DebugKVM("returns address 0x%lx\n", address);
	r = put_user(address, addr);
	if (r) {
		DebugKVM("put_user() failed for user address 0x%px\n", addr);
	}
	DebugKVM("returns with value %ld\n", r);
	return r;
}

long kvm_arch_dev_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	long r = -EINVAL;

	DebugKVM("started for ioctl 0x%x\n", ioctl);
	switch (ioctl) {
	case KVM_GET_GUEST_ADDRESS:{
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
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#ifdef	CONFIG_KVM_HW_VIRTUALIZATION
	if (kvm_is_hv_enable())
		kvm_vm_types_available |= KVM_E2K_HV_VM_TYPE_MASK;

#ifdef	CONFIG_KVM_PARAVIRTUALIZATION
	if (kvm_is_hw_pv_enable())
		kvm_vm_types_available |= KVM_E2K_HW_PV_VM_TYPE_MASK;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
#endif /* CONFIG_KVM_HW_VIRTUALIZATION */

	return kvm_vm_types_available != 0;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
struct work_struct kvm_dump_stacks;	/* to schedule work to dump */
					/* guest VCPU stacks */
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

int kvm_arch_init(void *opaque)
{
	int err;

	DebugKVM("started\n");

	if (!cpu_has_kvm_support()) {
		pr_err("KVM: no hardware and paravirtualization support\n");
		return -EOPNOTSUPP;
	}

	user_area_caches_init();

	err = kvm_mmu_module_init();
	if (err)
		goto out_free_caches;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	INIT_WORK(&kvm_dump_stacks, &wait_for_print_all_guest_stacks);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#ifdef CONFIG_KVM_GVA_CACHE_STAT
	gva_cache_stat_dev_init();
#endif /* GVA_CACHE_STAT */

	return 0;

out_free_caches:
	user_area_caches_destroy();
	return err;
}

void kvm_arch_exit(void)
{
	DebugKVM("started\n");
	kvm_mmu_module_exit();
	user_area_caches_destroy();
}

int kvm_arch_hardware_setup(void *opaque)
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

/* This is called either from another vcpu (CEPIC DAT is not active)
 * or from current VCPU but inside of kvm_arch_vcpu_[un]blocking() pair
 * (DAT is again inactive). */
bool kvm_vcpu_has_epic_interrupts(const struct kvm_vcpu *vcpu)
{
	epic_page_t *cepic = vcpu->arch.hw_ctxt.cepic;

	/* Check mi_gst by reading CEPIC_CIR.stat and PMIRR */
	if (!vcpu->arch.hcall_irqs_disabled) {
		if (cepic->cir.stat)
			return true;

		if (unlikely(epic_bgi_mode)) {
			if (memchr_inv(cepic->pmirr_byte, 0,
			     sizeof(cepic->pmirr_byte) + __must_be_array(cepic->pmirr_byte)))
				return true;
		} else {
			if (memchr_inv(cepic->pmirr, 0,
			     sizeof(cepic->pmirr) + __must_be_array(cepic->pmirr)))
				return true;
		}
	}

	/* Check nmi_gst by reading CEPIC_PNMIRR */
	if (cepic->pnmirr.counter & CEPIC_PNMIRR_BIT_MASK)
		return true;

	return false;
}

/* This is called from kvm_vcpu_block() -> kvm_vcpu_running(),
 * so EPIC has been saved in kvm_arch_vcpu_blocking() already.
 * See kvm_arch_vcpu_blocking() for details.
 *
 * Also this can be called from kvm_arch_dy_runnable(), in
 * which case we also check values in memory. */
static bool kvm_all_vcpus_runnable = false;
int kvm_arch_vcpu_runnable(struct kvm_vcpu *vcpu)
{
	DebugKVMRUN("started for VCPU %d\n", vcpu->vcpu_id);
	return kvm_all_vcpus_runnable || vcpu->arch.intc_ctxt.coredump ||
		vcpu->arch.mp_state == KVM_MP_STATE_RUNNABLE ||
		vcpu->arch.unhalted || kvm_vcpu_has_pic_interrupts(vcpu);
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

static struct kvm_e2k_info e2k_info = {
	.module = THIS_MODULE,
};
bool kvm_debug = false;
module_param_named(e2k_dbg, kvm_debug, bool, 0600);

bool kvm_irq_bypass = true;
module_param_named(e2k_irq_bypass, kvm_irq_bypass, bool, 0600);

bool kvm_ioepic_unsafe_direct_map = false;
module_param_named(e2k_ioepic_unsafe_direct_map, kvm_ioepic_unsafe_direct_map,
		   bool, 0600);

bool kvm_ftrace_dump = false;
module_param_named(e2k_ftrace_dump, kvm_ftrace_dump, bool, 0600);

unsigned int kvm_g_tmr = 0;
module_param_named(e2k_g_tmr, kvm_g_tmr, uint, 0600);

module_param_named(e2k_all_vcpus_runnable, kvm_all_vcpus_runnable, bool, 0600);

static int kvm_e2k_kick_all_vcpus(const char *val, const struct kernel_param *kp)
{
	struct kvm *kvm;

	if (mutex_is_locked(&kvm_lock)) {
		pr_err("%s(): kvm_lock is taken\n", __func__);
		return -EAGAIN;
	}

	mutex_lock(&kvm_lock);
	list_for_each_entry(kvm, &vm_list, vm_list)
		kvm_make_all_cpus_request(kvm, 0);
	mutex_unlock(&kvm_lock);

	return 0;
}

static const struct kernel_param_ops param_ops_kick_all_vcpus = {
	.set = kvm_e2k_kick_all_vcpus,
	.get = param_get_bool,
};

static bool kvm_kick_all_vcpus = false;
module_param_cb(e2k_kick_all_vcpus, &param_ops_kick_all_vcpus, &kvm_kick_all_vcpus, 0600);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
/*
 * pseudo IRQ to emulate SysRq on guest kernel
 */
static irqreturn_t native_sysrq_showstate_interrupt(int irq, void *dev_id)
{
	/* dump stacks uses NMI to interrupt other CPUs and dump current */
	/* process state running on the CPU */
	raw_all_irq_enable();

	/* vcpu state is unavailable on native guest */
	show_state_filter(0);

	dump_stack();

	HYPERVISOR_vcpu_show_state_completion();
	return IRQ_HANDLED;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static irqreturn_t cepic_epic_interrupt(int irq, void *dev_id)
{
	kvm_deliver_cepic_epic_interrupt();
	return IRQ_HANDLED;
}

#ifdef CONFIG_KVM_ASYNC_PF
static irqreturn_t epic_pv_apf_wake(int irq, void *dev_id)
{
	if (pv_apf_read_and_reset_reason() == KVM_APF_PAGE_READY)
		pv_apf_wake();
	else
		pr_err("Guest: async_pf, got spurious ASYNC_PF_WAKE_VECTOR exception\n");

	return IRQ_HANDLED;
}
#endif /* CONFIG_KVM_ASYNC_PF */


static int sysrq_irq = 0;
static int pv_apf_wake_irq = 0;
static int cepic_epic_irq = 0;

static int kvm_starting_cpu(unsigned int cpu)
{
	if (sysrq_irq)
		enable_percpu_irq(sysrq_irq, 0);
	if (pv_apf_wake_irq)
		enable_percpu_irq(pv_apf_wake_irq, 0);
	if (cepic_epic_irq)
		enable_percpu_irq(cepic_epic_irq, 0);
	return 0;
}

static int kvm_dying_cpu(unsigned int cpu)
{
	if (sysrq_irq)
		disable_percpu_irq(sysrq_irq);
	if (pv_apf_wake_irq)
		disable_percpu_irq(pv_apf_wake_irq);
	if (cepic_epic_irq)
		disable_percpu_irq(cepic_epic_irq);
	return 0;
}

static int kvm_probe(struct platform_device *pdev)
{
	int ret, irq;
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	static int __percpu kvm_dummy_dev_id;
	if (!paravirt_enabled()) { /*guest cannot have own guests and be virtualized */
		/*Register e2k VMM data to kvm side */
		ret = kvm_init(&e2k_info, sizeof(struct kvm_vcpu),
			__alignof__(struct kvm_vcpu), THIS_MODULE);
		if (ret)
			return ret;
	}

	if (cpu_has_epic() && !IS_HV_GM()) {
		ret = of_irq_get_byname(np, "CEPIC EPIC interrupts");
		if (WARN_ON(ret <= 0))
			goto err;
		irq = ret;
		ret = request_percpu_irq(irq, cepic_epic_interrupt,
				"CEPIC EPIC interrupts", &kvm_dummy_dev_id);
		if (ret)
			goto err;
		cepic_epic_irq = irq;
	}
#ifdef CONFIG_KVM_ASYNC_PF
	if (IS_HV_GM()) {
		ret = of_irq_get_byname(np, "ASYNC PF WAKE interrupts");
		if (WARN_ON(ret <= 0))
			goto err;
		irq = ret;
		ret = request_percpu_irq(irq, epic_pv_apf_wake,
				"ASYNC PF WAKE interrupts", &kvm_dummy_dev_id);
		if (ret)
			goto err;
		pv_apf_wake_irq = irq;
	}
#endif
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (paravirt_enabled()) { /* It is native guest */
		ret = of_irq_get_byname(np, "KVM SysRq showstate");
		if (WARN_ON(ret <= 0))
			goto err;
		irq = ret;
		ret = request_percpu_irq(irq, native_sysrq_showstate_interrupt,
				"KVM SysRq showstate", &kvm_dummy_dev_id);
		if (ret)
			goto err;
		sysrq_irq = irq;
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
				  "kvm:starting",
				  kvm_starting_cpu,
				  kvm_dying_cpu);

	if (WARN(ret < 0, "%pOF: Failed to setup hotplug state: %d\n", np, ret))
		goto err;

	return 0;
err:
	if (sysrq_irq > 0) {
		disable_percpu_irq(sysrq_irq);
		free_percpu_irq(sysrq_irq, &kvm_dummy_dev_id);
	}
	if (pv_apf_wake_irq > 0) {
		disable_percpu_irq(pv_apf_wake_irq);
		free_percpu_irq(pv_apf_wake_irq, &kvm_dummy_dev_id);
	}
	if (cepic_epic_irq > 0) {
		disable_percpu_irq(cepic_epic_irq);
		free_percpu_irq(cepic_epic_irq, &kvm_dummy_dev_id);
	}
	return ret;
}

static int kvm_remove(struct platform_device *pdev)
{
	kvm_exit();
	return 0;
}
#elif defined(CONFIG_KVM_GUEST_KERNEL) /* !CONFIG_KVM_HOST_KERNEL */
/*
 * pseudo IRQ to emulate SysRq on guest kernel
 */
static irqreturn_t kvm_sysrq_showstate_interrupt(int irq, void *dev_id)
{
	/* dump stacks uses NMI to interrupt other CPUs and dump current */
	/* process state running on the CPU */
	raw_all_irq_enable();

	if (kvm_get_vcpu_state()->do_dump_state)
		show_state_filter(0);
	if (kvm_get_vcpu_state()->do_dump_stack)
		dump_stack();
	HYPERVISOR_vcpu_show_state_completion();
	return IRQ_HANDLED;
}

static int kvm_probe(struct platform_device *pdev)
{
	int ret, irq;
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	int sysrq_irq = 0, kvm_nmi_irq = 0;
	static int kvm_dummy_dev_id;

	if (IS_HV_GM())
		return 0;

	ret = of_irq_get_byname(np, "KVM SysRq showstate");
	if (WARN_ON(ret <= 0))
		goto err;
	irq = ret;
	ret = request_percpu_irq(irq, kvm_sysrq_showstate_interrupt,
				 "KVM SysRq showstate", &kvm_dummy_dev_id);
	if (ret)
		goto err;
	sysrq_irq = irq;

	ret = of_irq_get_byname(np, "KVM NMI");
	if (WARN_ON(ret <= 0))
		goto err;
	irq = ret;
	ret = request_percpu_irq(irq,
			(irq_handler_t)nmi_call_function_interrupt,
			"KVM NMI", &kvm_dummy_dev_id);
	if (ret)
		goto err;
	kvm_nmi_irq = ret;

	return ret;
err:
	if (kvm_nmi_irq > 0) {
		disable_percpu_irq(kvm_nmi_irq);
		free_percpu_irq(kvm_nmi_irq, &kvm_dummy_dev_id);
	}
	if (sysrq_irq > 0) {
		disable_percpu_irq(sysrq_irq);
		free_percpu_irq(sysrq_irq, &kvm_dummy_dev_id);
	}
	return ret;
}
#endif /* !CONFIG_KVM_HOST_KERNEL */

static const struct of_device_id kvm_dt_ids[] = {
	{.compatible = "mcst,kvm"},
	{ /* sentinel value */ }
};
static struct platform_driver kvm_driver = {
	.driver = {
		.name = "kvm",
		.of_match_table = of_match_ptr(kvm_dt_ids),
	},
	.probe    = kvm_probe,
	.remove   = kvm_remove,
};
module_platform_driver(kvm_driver);
MODULE_LICENSE("GPL v2");
