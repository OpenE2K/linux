/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM boot-time initialization
 */

#include <asm/p2v/boot_v2p.h>
#include <linux/types.h>
#include <asm/p2v/boot_init.h>
#include <asm/p2v/boot_phys.h>
#include <asm/p2v/boot_param.h>
#include <asm/p2v/boot_smp.h>
#include <asm/string.h>
#include <asm/console.h>
#include <asm/setup.h>
#include <asm/mmu_context.h>
#include <asm/e2k_sic.h>
#include <asm/cpu_regs.h>
#include <asm/kvm/hypercall.h>
#include <asm/kvm/hvc-console.h>
#include <asm/trap_table.h>

#include <asm/kvm/guest/v2p.h>
#include <asm/kvm/guest/setup.h>
#include <asm/kvm/guest/boot_mmu_context.h>
#include <asm/kvm/guest/traps.h>
#include <asm/kvm/guest/trap_table.h>

#include "boot.h"
#include "process.h"
#include "cpu.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	1	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		do_boot_printk("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_NUMA_MODE
#undef	DebugNUMA
#define	DEBUG_NUMA_MODE	1	/* kernel virtual machine debugging */
#define	DebugNUMA(fmt, args...)						\
({									\
	if (DEBUG_NUMA_MODE)						\
		do_boot_printk("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_MUU_INIT_MODE
#undef	DebugMMU
#define	DEBUG_MUU_INIT_MODE	1	/* MMU init debugging */
#define	DebugMMU(fmt, args...)						\
({									\
	if (DEBUG_MUU_INIT_MODE)					\
		do_boot_printk("%s(): " fmt, __func__, ##args);		\
})

extern char __kvm_guest_ttable_start[];
extern char __kvm_guest_ttable_end[];

/*
 * Table of pointers to VCPUs state.
 * Own VCPU state pointer is loaded on some global registers to direct access
 * Other VCPUs state pointers can be accessible through this table
 */
kvm_vcpu_state_t *vcpus_state[NR_CPUS];

/*
 * Native/guest VM early indicator
 */
static inline bool boot_kvm_early_is_guest_hv_vm(void)
{
	return kvm_vcpu_host_is_hv();
}

static inline void boot_setup_guest_machine_id(void)
{
	e2k_idr_t idr;


	/* setup paravirtualized guest machine IDR */
	idr.IDR_reg = 0;
	idr.IDR_mdl = IDR_E2K_VIRT_MDL;
	idr.IDR_rev = IDR_E2K_VIRT_REV;
	SETUP_IDR_REG_VALUE(idr.IDR_reg);

	/*
	 * At this point we have three machine ids:
	 * - boot_machine.native_id is determined by QEMU parameter
	 * - kvm_vcpu_host_machine_id is host id
	 * - boot_guest_machine_id should be set by the guest here
	 *
	 * Force use of v6 e2k-iommu, independent of guest architecture.
	 */
	boot_guest_machine_id = MACHINE_ID_E2K_VIRT & ~MACHINE_ID_L_IOMMU |
							MACHINE_ID_E2K_IOMMU;
	boot_machine.guest.id = boot_guest_machine_id;
	boot_machine.guest.rev = idr.IDR_rev;
	boot_machine.guest.iset_ver = boot_machine.native_iset_ver;
}

void boot_kvm_setup_machine_id(bootblock_struct_t *bootblock)
{
	bool is_hv_gm;
#ifdef	CONFIG_MMU_PT_V6
	bool host_mmu_pt_v6;
#endif	/* CONFIG_MMU_PT_V6 */

	BUILD_BUG_ON(IS_ENABLED(CONFIG_E2K_MACHINE) && !IS_ENABLED(CONFIG_KVM_GUEST_KERNEL));

	is_hv_gm = boot_kvm_early_is_guest_hv_vm();

	boot_native_setup_machine_id(bootblock);
	boot_setup_guest_machine_id();

#ifdef	CONFIG_E2K_MACHINE
	if ((boot_machine.guest.id & ~MACHINE_ID_SIMUL) !=
			(boot_native_machine_id & ~MACHINE_ID_SIMUL))
		BOOT_BUG("Guest kernel arch does not match QEMU parameter arch");

	if ((boot_native_machine_id & ~MACHINE_ID_SIMUL) !=
			(kvm_vcpu_host_machine_id() & ~MACHINE_ID_SIMUL))
		BOOT_BUG("Guest kernel arch does not match host arch");
#else
	boot_native_machine_id = kvm_vcpu_host_machine_id();
#endif
	boot_machine.native_id = boot_native_machine_id;
	boot_machine.native_rev = kvm_vcpu_host_cpu_rev();
	boot_machine.native_iset_ver = kvm_vcpu_host_cpu_iset();

#ifdef	CONFIG_MMU_PT_V6
	host_mmu_pt_v6 = kvm_vcpu_host_mmu_support_pt_v6();
	if (host_mmu_pt_v6) {
		/* host support new MMU PT structures, so guest can it too */
		boot_machine.mmu_pt_v6 = true;
	} else {
		boot_machine.mmu_pt_v6 = false;
	}
#else	/* ! CONFIG_MMU_PT_V6 */
	boot_machine.mmu_pt_v6 = false;
#endif	/* CONFIG_MMU_PT_V6 */

#ifdef	CONFIG_ONLY_HIGH_PHYS_MEM
	/* on VCPU the low memory cannot be part of the high */
	BOOT_LOW_MEMORY_ENABLED() = true;
#endif	/* CONFIG_ONLY_HIGH_PHYS_MEM */
}

int __init
boot_kvm_probe_memory(node_phys_mem_t *nodes_phys_mem,
			boot_info_t *bootblock)
{
	int ret;

	if (bootblock->signature != BOOTBLOCK_KVM_GUEST_SIGNATURE &&
			bootblock->signature != BOOTBLOCK_BOOT_SIGNATURE) {
		BOOT_BUG("Unknown type of Boot information structure");
		return -ENOMEM;
	}

	ret = boot_bios_probe_memory(nodes_phys_mem, bootblock);
	if (ret < 0) {
		BOOT_BUG("Probe of physical memory failed, error %d|n",
			ret);
		return ret;
	}

	ret = boot_kvm_probe_vram_memory(bootblock);
	if (ret < 0) {
		BOOT_BUG("Probe of virtual RAM failed, error %d|n",
			ret);
		return ret;
	}

	return ret;
}

void __init boot_kvm_check_bootblock(bool bsp, bootblock_struct_t *bootblock)
{
	boot_info_t *boot_info = &bootblock->info;
	e2k_addr_t base_addr, addr;
	e2k_size_t size;
	bool is_base_phys;

	base_addr = BOOT_READ_OSCUD_LO_REG().OSCUD_lo_base;
	is_base_phys = (base_addr < GUEST_PAGE_OFFSET) ? true : false;

	/*
	 * The guest kernel launcher (QEMU) can pass addresses into bootblock
	 * structure both physical (PA) and virtual physical
	 * (VPA == PA + GUEST_PAGE_OFFSET
	 * It need put all adresses to unified format with kernel base
	 */
	if (!is_base_phys)
		return;

	/* all addresses should be PA */
	addr = boot_info->kernel_base;
	if (addr >= GUEST_PAGE_OFFSET) {
		addr = boot_vpa_to_pa(addr);
		boot_info->kernel_base = addr;
	}

	addr = boot_info->mp_table_base;
	if (addr != 0) {
		struct intel_mp_floating *mpf;

		if (addr >= GUEST_PAGE_OFFSET) {
			addr = boot_vpa_to_pa(addr);
			boot_info->mp_table_base = addr;
		}
		mpf = (struct intel_mp_floating *)addr;
		addr = mpf->mpf_physptr;
		if (addr != 0 && addr >= GUEST_PAGE_OFFSET) {
			addr = boot_vpa_to_pa(addr);
			mpf->mpf_checksum = 0;
			mpf->mpf_physptr = addr;
			/* recalculate structure sum */
			mpf->mpf_checksum =
				boot_mpf_do_checksum((unsigned char *)mpf,
							sizeof(*mpf));
		}
	}

	size = boot_info->ramdisk_size;	/* INITRD_SIZE */
	if (size != 0) {
		addr = boot_info->ramdisk_base;	/* INITRD_BASE */
		if (addr >= GUEST_PAGE_OFFSET) {
			addr = boot_vpa_to_pa(addr);
			boot_info->ramdisk_base = addr;
		}
	}
}

e2k_size_t __init
boot_kvm_get_bootblock_size(boot_info_t *bblock)
{
	e2k_size_t area_size = 0;

	if (bblock->signature == BOOTBLOCK_KVM_GUEST_SIGNATURE ||
			bblock->signature == BOOTBLOCK_BOOT_SIGNATURE) {
		area_size = sizeof(bootblock_struct_t);
	} else {
		BOOT_BUG("Unknown type of Boot information structure");
	}
	return area_size;
}

void __init_recv
boot_kvm_cpu_relax(void)
{
	HYPERVISOR_kvm_guest_vcpu_relax();
}

#ifdef	CONFIG_SMP
int __init_recv
boot_kvm_smp_cpu_config(boot_info_t *bootblock)
{
	if (bootblock->signature == BOOTBLOCK_KVM_GUEST_SIGNATURE ||
			bootblock->signature == BOOTBLOCK_BOOT_SIGNATURE) {
		return boot_bios_smp_cpu_config(bootblock);
	} else {
		BOOT_BUG("Unknown type of Boot information structure");
	}
	return 0;
}

void __init_recv
boot_kvm_smp_node_config(boot_info_t *bootblock)
{
	if (bootblock->signature == BOOTBLOCK_KVM_GUEST_SIGNATURE ||
			bootblock->signature == BOOTBLOCK_BOOT_SIGNATURE) {
		boot_bios_smp_node_config(bootblock);
	} else {
		BOOT_BUG("Unknown type of Boot information structure");
	}
}
#endif	/* CONFIG_SMP */

/*
 * Reserve memory of VCPU state structure to communacate with host kernel
 */
static	void __init
boot_kvm_reserve_vcpu_state(void)
{
	e2k_addr_t	area_base;
	e2k_size_t	area_size;

	KVM_GET_VCPU_STATE_BASE(area_base);
	area_size = sizeof(kvm_vcpu_state_t);
	boot_reserve_physmem("VCPU state", area_base, area_size,
			kernel_data_mem_type, BOOT_NOT_IGNORE_BUSY_BANK);
	DebugKVM("The VCPU state reserved area: "
			"base addr 0x%lx size 0x%lx page size 0x%x\n",
			area_base, area_size, PAGE_SIZE);
}

/*
 * Reserve memory of Compilation Units Table for guest kernel
 */
static	void __init
boot_kvm_reserve_kernel_cut(void)
{
	e2k_cutd_t	cutd;
	e2k_addr_t	area_base;
	e2k_size_t	area_size;

	cutd.CUTD_reg = BOOT_KVM_READ_OSCUTD_REG_VALUE();
	area_base = cutd.CUTD_base;
	area_size = sizeof(e2k_cute_t) * MAX_GUEST_CODES_UNITS;
	boot_reserve_physmem("kernel CUT", area_base, area_size,
			kernel_data_mem_type, BOOT_NOT_IGNORE_BUSY_BANK);
	DebugKVM("The kernel CUT reserved area: "
			"base addr 0x%lx size 0x%lx page size 0x%x\n",
			area_base, area_size, PAGE_SIZE);
}

/*
 * Reserve legacy VGA IO memory
 */
static	void __init
boot_kvm_reserve_legacy_VGA_MEM(bool bsp)
{
	e2k_addr_t	area_base;
	e2k_size_t	area_size;

	if (BOOT_IS_BSP(bsp)) {
		area_base = VGA_VRAM_PHYS_BASE;
		area_size = VGA_VRAM_SIZE;
		boot_reserve_physmem("VGA", area_base, area_size, hw_stripped_mem_type,
			BOOT_NOT_IGNORE_BUSY_BANK | BOOT_IGNORE_BANK_NOT_FOUND);

		DebugKVM("Legacy VGA MEM reserved area: "
			"base addr 0x%lx size 0x%lx page size 0x%x\n",
			area_base, area_size, PAGE_SIZE);
	}
}

/*
 * Reserve the memory used by KVM guest boot-time initialization.
 * All the used memory areas enumerate below. If a some new area will be used,
 * then it should be added to the list of already known ones.
 */

void __init
boot_kvm_reserve_all_bootmem(bool bsp, boot_info_t *boot_info)
{
	/*
	 * Reserve kernel image 'text/data/bss' segments.
	 * 'OSCUD' & 'OSGD' register-pointers describe these areas.
	 * 'text' and 'data/bss' segments can intersect or one can include
	 * other.
	 */
	boot_reserve_kernel_image(bsp, boot_info);

	/*
	 * The special virtual physical memory VRAM is now used to emulate
	 * VCPU, VMMU, VSIC and other hardware registers, tables, structures
	 * Reservation can be not made, but only to check reservation areas
	 * intersections (including main memory busy areas) it will be done
	 */
	#define	CHECK_VCPU_VRAM_INTERSECTIONS

#ifdef	CHECK_VCPU_VRAM_INTERSECTIONS

	/*
	 * Reserve memory of VCPU state structure to communacate with
	 * host kernel
	 * (allocated in VRAM)
	 */
	boot_kvm_reserve_vcpu_state();


	/*
	 * Reserve memory of Compilation Units Table for guest kernel
	 * (allocated in VRAM)
	 */
	boot_kvm_reserve_kernel_cut();
#endif	/* CHECK_VCPU_VRAM_INTERSECTIONS */

	/*
	 * Reserve boot information records.
	 */
	boot_reserve_bootblock(bsp, boot_info);

	/*
	 * Reserve memory of boot-time stacks.
	 */
	boot_reserve_stacks(boot_info);

	/*
	 * Reserve legacy VGA IO memory
	 */
	boot_kvm_reserve_legacy_VGA_MEM(bsp);
}

/*
 * The function defines sizes of all guest kernel hardware stacks(PS & PCS)
 * host run on own stacks, the guest stacks should define only
 * own hardware stacks sizes
 */
void __init boot_kvm_define_kernel_hw_stacks_sizes(hw_stack_t *hw_stacks)
{
	kvm_set_hw_ps_user_size(hw_stacks, KVM_GUEST_KERNEL_PS_SIZE);
	kvm_set_hw_pcs_user_size(hw_stacks, KVM_GUEST_KERNEL_PCS_SIZE);
}

static void __init boot_kvm_map_all_phys_memory(boot_info_t *boot_info)
{
	e2k_addr_t	area_phys_base;
	e2k_size_t	area_size;
	e2k_addr_t	area_virt_base;
	int		ret;
	int bank;

	/*
	 * Map the available physical memory into virtual space to direct
	 * access to physical memory using kernel pa <-> va translations
	 * All physical memory pages are mapped to virtual space starting
	 * from 'PAGE_OFFSET'
	 */
	DebugKVM("The physical memory start address 0x%lx, end 0x%lx\n",
		boot_start_of_phys_memory,
		boot_end_of_phys_memory);
	area_phys_base = boot_pa_to_vpa(boot_start_of_phys_memory);
	area_virt_base =
		(e2k_addr_t)__boot_va(boot_start_of_phys_memory);
	area_size = 0;
	for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank++) {
		if (!boot_info->nodes_mem[0].banks[bank].size)
			break;
		area_size += boot_info->nodes_mem[0].banks[bank].size;
	}
	ret = boot_map_physmem(PAGE_MAPPED_PHYS_MEM,
				BOOT_E2K_MAPPED_PHYS_MEM_PAGE_SIZE);
	if (ret <= 0) {
		BOOT_BUG("Could not map physical memory area: "
			"base addr 0x%lx size 0x%lx page size 0x%x to "
			"virtual addr 0x%lx",
			area_phys_base, area_size,
			BOOT_E2K_MAPPED_PHYS_MEM_PAGE_SIZE,
			area_virt_base);
	}
	DebugKVM("The physical memory area: "
		"base addr 0x%lx size 0x%lx is mapped to %d virtual "
		"page(s) base addr 0x%lx page size 0x%x\n",
		area_phys_base, area_size, ret, area_virt_base,
		BOOT_E2K_MAPPED_PHYS_MEM_PAGE_SIZE);
}

void __init boot_kvm_map_all_bootmem(bool bsp, boot_info_t *boot_info)
{
	/* guest kernel image should be registered on host */
	/* for paravirtualization mode without shadow PT support */
	boot_host_kernel_image(bsp);

	if (BOOT_IS_BSP(bsp)) {
		/*
		* Map the kernel image 'text/data/bss' segments.
		*/
		boot_map_kernel_image(populate_image_on_host);


		/*
		* Map all available physical memory
		*/
		boot_kvm_map_all_phys_memory(boot_info);

		/*
		* Map all needed physical areas from boot-info.
		*/
		boot_map_all_bootinfo_areas(boot_info);

		/*
		* Map all available VRAM areas
		*/
		boot_kvm_map_vram_memory(boot_info);
	}

	/*
	* Map the kernel stacks
	*/
	boot_map_kernel_boot_stacks();
}

/*
 * KVM guest kernel started on virtual memory so does not need
 * special switch to virtual space
 */
void __init_recv
boot_kvm_map_needful_to_equal_virt_area(e2k_addr_t stack_top_addr)
{
	return;
}

void boot_kvm_set_kernel_MMU_state_before(void)
{
	vcpu_gmmu_info_t gmmu_info;
	int ret;

	gmmu_info.mmu_cr = MMU_CR_KERNEL;
	/* translation (TLB enable) will be turn ON later */
	gmmu_info.mmu_cr.tlb_en = 0;
	gmmu_info.pid = MMU_KERNEL_CONTEXT;
	DebugMMU("will set MMU_CR 0x%llx PID 0x%llx\n", gmmu_info.mmu_cr, gmmu_info.pid);

	gmmu_info.sep_virt_space = MMU_IS_SEPARATE_PT();
	gmmu_info.pt_v6 = MMU_IS_PT_V6();
	if (gmmu_info.sep_virt_space) {
		gmmu_info.os_pptb = MMU_SEPARATE_KERNEL_PPTB;
		gmmu_info.os_vptb = MMU_SEPARATE_KERNEL_VPTB;
		BUILD_BUG_ON(MMU_SEPARATE_KERNEL_VAB != GUEST_PAGE_OFFSET);
		gmmu_info.os_vab = MMU_SEPARATE_KERNEL_VAB;
		DebugMMU("will set separate OS_PPTB at %p OS_VPTB at %p "
			"OS_VAB at %p\n",
			(void *)gmmu_info.os_pptb, (void *)gmmu_info.os_vptb,
			(void *)gmmu_info.os_vab);

		/* set user PT to kernel PT too as initial state */
		gmmu_info.u_pptb = MMU_SEPARATE_KERNEL_PPTB;
		gmmu_info.u_vptb = MMU_SEPARATE_USER_VPTB;
		DebugMMU("will set user PTs same as OS: U_PPTB at %p "
			"U_VPTB at %p\n",
			(void *)gmmu_info.u_pptb, (void *)gmmu_info.u_vptb);
	} else {
		gmmu_info.u_pptb = MMU_UNITED_KERNEL_PPTB;
		gmmu_info.u_vptb = MMU_UNITED_KERNEL_VPTB;
		DebugMMU("will set united U_PPTB at %p U_VPTB at %p\n",
			(void *)gmmu_info.u_pptb, (void *)gmmu_info.u_vptb);
	}
	gmmu_info.opcode = INIT_STATE_GMMU_OPC;

	ret = HYPERVISOR_vcpu_guest_mmu_state(&gmmu_info);
	if (ret != 0) {
		BOOT_BUG("Could not set guest mmu state by hypercall, "
			"error %d", ret);
	}
}

void boot_kvm_set_kernel_MMU_state_after(void)
{
}

/*
 * Guest kernel is running on virtual space, so it does not need to turn on
 * virtual memory support
 */
void __init_recv
boot_kvm_switch_to_virt(bool bsp, int cpuid,
	void (*boot_init_sequel_func)(bool bsp, int cpuid, int cpus))
{
	bootmem_areas_t *bootmem = boot_kernel_bootmem;
	hw_stack_t	hw_stacks;
	kvm_task_info_t	task_info;
	e2k_psp_lo_t	psp_lo;
	e2k_psp_hi_t	psp_hi;
	e2k_pcsp_lo_t	pcsp_lo;
	e2k_pcsp_hi_t	pcsp_hi;
	e2k_usd_lo_t	usd_lo;
	e2k_usd_hi_t	usd_hi;
	e2k_usbr_t	usbr;
	e2k_cud_lo_t	cud_lo;
	e2k_cud_hi_t	cud_hi;
	e2k_gd_lo_t	gd_lo;
	e2k_gd_hi_t	gd_hi;
	e2k_cutd_t	cutd;
	e2k_size_t	size;
	bool		is_hv;
	int		cpus_to_sync = boot_cpu_to_sync_num;
	int		ret;

	is_hv = BOOT_IS_HV_GM();

	/*
	 * Set all needed MMU registers
	 */
	boot_set_kernel_MMU_state_before();
	boot_set_kernel_MMU_state_after();

	/*
	 * Calculate hardware procedure and chain stacks pointers
	 */

	/*
	 * Set hardware stacks registers
	 */
	AW(psp_lo) = 0;
	AW(psp_hi) = 0;
	AW(pcsp_lo) = 0;
	AW(pcsp_hi) = 0;
#ifndef CONFIG_SMP
	psp_lo.PSP_lo_base = bootmem->boot_ps.virt;
	psp_hi.PSP_hi_size = bootmem->boot_ps.size;
	pcsp_lo.PCSP_lo_base = bootmem->boot_pcs.virt;
	pcsp_hi.PCSP_hi_size = bootmem->boot_pcs.size;
#else
	psp_lo.PSP_lo_base = bootmem->boot_ps[cpuid].virt;
	psp_hi.PSP_hi_size = bootmem->boot_ps[cpuid].size;
	pcsp_lo.PCSP_lo_base = bootmem->boot_pcs[cpuid].virt;
	pcsp_hi.PCSP_hi_size = bootmem->boot_pcs[cpuid].size;
#endif
	psp_hi.PSP_hi_ind = 0;
	pcsp_hi.PCSP_hi_ind = 0;

	/*
	 * Calculate guest kernel OSCUD trap table start
	 */
	cud_lo = NATIVE_READ_OSCUD_LO_REG();
	cud_hi = NATIVE_READ_OSCUD_HI_REG();
	cud_lo.OSCUD_lo_base = (e2k_addr_t)_start;
	cud_hi.OSCUD_hi_size = (e2k_addr_t)_etext - (e2k_addr_t)_start;
	DebugKVM("The kernel CUD virtual area: base addr 0x%lx size 0x%x\n",
		cud_lo.OSCUD_lo_base, cud_hi.OSCUD_hi_size);

	/*
	 * Calculate guest kernel OSGD area
	 */
	gd_lo = NATIVE_READ_OSGD_LO_REG();
	gd_hi = NATIVE_READ_OSGD_HI_REG();
	size = (e2k_addr_t)_edata_bss - (e2k_addr_t)_sdata_bss;
	size = ALIGN_TO_MASK(size, E2K_ALIGN_OS_GLOBALS_MASK);
	gd_lo.OSCUD_lo_base = (e2k_addr_t)_sdata_bss;
	gd_hi.OSCUD_hi_size = size;

	/* calculate virtual CUTD pointer */
	cutd.CUTD_reg = BOOT_KVM_READ_OSCUTD_REG_VALUE();
	cutd.CUTD_base = (e2k_addr_t)__boot_va(cutd.CUTD_base);
	DebugKVM("The kernel CUT virtual area: base addr 0x%lx size 0x%x\n",
		cutd.CUTD_base, sizeof(e2k_cute_t) * 1);

	/* Enable control of PS & PCS stack bounds */
	boot_kvm_set_sge();

	/*
	 * Calculate User Stack registers init kernel stack addresses.
	 * Set stack pointer to the very begining of initial stack to collapse
	 * useless previous stack frames
	 */
	AW(usd_lo) = 0;
	AW(usd_hi) = 0;
	AW(usbr) = 0;
#ifndef CONFIG_SMP
	usbr.USBR_base = bootmem->boot_stack.virt + bootmem->boot_stack.size;
	usd_lo.USD_lo_base = bootmem->boot_stack.virt +
			bootmem->boot_stack.virt_offset;
	usd_hi.USD_hi_size = bootmem->boot_stack.virt_offset;
#else
	usbr.USBR_base = bootmem->boot_stack[cpuid].virt +
			 bootmem->boot_stack[cpuid].size;
	usd_lo.USD_lo_base = bootmem->boot_stack[cpuid].virt +
			bootmem->boot_stack[cpuid].virt_offset;
	usd_hi.USD_hi_size = bootmem->boot_stack[cpuid].virt_offset;
#endif
	usd_lo.USD_lo_p = 0;

	/*
	 * Real switch to new init stacks can be done only by hypervisor
	 */

	boot_define_kernel_hw_stacks_sizes(&hw_stacks);

#ifndef CONFIG_SMP
	task_info.sp_offset = bootmem->boot_stack.size;
	task_info.us_base = bootmem->boot_stack.virt;
	task_info.us_size = bootmem->boot_stack.size;
	task_info.ps_base = bootmem->boot_ps.virt;
	task_info.init_ps_size = bootmem->boot_ps.size;
	task_info.pcs_base = bootmem->boot_pcs.virt;
	task_info.init_pcs_size = bootmem->boot_pcs.size;
#else
	task_info.sp_offset = bootmem->boot_stack[cpuid].size;
	task_info.us_base = bootmem->boot_stack[cpuid].virt;
	task_info.us_size = bootmem->boot_stack[cpuid].size;
	task_info.ps_base = bootmem->boot_ps[cpuid].virt;
	task_info.init_ps_size = bootmem->boot_ps[cpuid].size;
	task_info.pcs_base = bootmem->boot_pcs[cpuid].virt;
	task_info.init_pcs_size = bootmem->boot_pcs[cpuid].size;
#endif
	task_info.flags = 0;
	BUG_ON(task_info.sp_offset > task_info.us_size);
	task_info.us_ps_size = kvm_get_hw_ps_user_size(&hw_stacks);
	task_info.ps_size = task_info.us_ps_size;
	task_info.ps_offset = 0;
	task_info.ps_top = task_info.init_ps_size;
	task_info.us_pcs_size = kvm_get_hw_pcs_user_size(&hw_stacks);
	task_info.pcs_size = task_info.us_pcs_size;
	task_info.pcs_offset = 0;
	task_info.pcs_top = task_info.init_pcs_size;
	task_info.flags |= (DO_PRESENT_HW_STACKS_TASK_FLAG |
				PS_HAS_NOT_GUARD_PAGE_TASK_FLAG |
				PCS_HAS_NOT_GUARD_PAGE_TASK_FLAG);
	task_info.cud_base = cud_lo.OSCUD_lo_base;
	task_info.cud_size = cud_hi.OSCUD_hi_size;
	task_info.gd_base = gd_lo.OSGD_lo_base;
	task_info.gd_size = gd_hi.OSGD_hi_size;
	task_info.cut_base = cutd.CUTD_base;
	/* only 1 entry for guest kernel: cui #0 */
	task_info.cut_size = sizeof(e2k_cute_t) * 1;
	task_info.cui = 0;

	/*
	 * Set hardware stacks registers
	 */
	BOOT_KVM_FLUSHCPU;
	BOOT_KVM_WRITE_PSP_REG(psp_hi, psp_lo);
	BOOT_KVM_WRITE_PCSP_REG(pcsp_hi, pcsp_lo);

	/*
	 * Switch User Stack registers to init kernel stack addresses.
	 * Set stack pointer to the very begining of initial stack to collapse
	 * useless previous stack frames
	 */
	BOOT_KVM_WRITE_USBR_USD_REG_VALUE(AW(usbr), AW(usd_hi), AW(usd_lo));

	/*
	 * Set guest kernel OSCUD to trap table start (only virtual copies
	 * of registers at memory)
	 */
	BOOT_KVM_WRITE_GD_LO_REG(gd_lo);
	BOOT_KVM_WRITE_GD_HI_REG(gd_hi);
	BOOT_KVM_COPY_WRITE_OSGD_LO_REG_VALUE(gd_lo.GD_lo_half);
	BOOT_KVM_COPY_WRITE_OSGD_HI_REG_VALUE(gd_hi.GD_hi_half);
	BOOT_KVM_WRITE_CUTD_REG_VALUE(cutd.CUTD_reg);
	BOOT_KVM_COPY_WRITE_OSCUTD_REG_VALUE(cutd.CUTD_reg);
	BOOT_KVM_WRITE_CUD_LO_REG(cud_lo);
	BOOT_KVM_WRITE_CUD_HI_REG(cud_hi);
	BOOT_KVM_COPY_WRITE_OSCUD_HI_REG_VALUE(cud_hi.CUD_hi_half);
	/* should be set last because of the OSCUD.base is used */
	/* to convert boot-time VA<->PA */
	__E2K_WAIT_ALL;
	BOOT_KVM_COPY_WRITE_OSCUD_LO_REG_VALUE(cud_lo.CUD_lo_half);
	if (is_hv) {
		/* set virtual CUTD/OSCUTD pointer */
		BOOT_KVM_WRITE_OSCUTD_REG_VALUE(cutd.CUTD_reg);
		/* set hardware registers copies too */
		/* to enable native trap table and handlers */
		NATIVE_WRITE_OSCUD_HI_REG_VALUE(cud_hi.CUD_hi_half);
		/* should be set last because of the OSCUD.base is used */
		/* to convert boot-time VA<->PA */
		__E2K_WAIT_ALL;
		NATIVE_WRITE_OSCUD_LO_REG_VALUE(cud_lo.CUD_lo_half);
	}

	ret = HYPERVISOR_switch_to_virt_mode(&task_info,
		(void (*)(void *, void *, void *))boot_init_sequel_func,
					(void *) (long) bsp,
					(void *) (long) cpuid,
					(void *) (long) cpus_to_sync);
	if (ret) {
		boot_panic("could not switch to new init kernel stacks,"
			"error %d\n", ret);
	}

	/* guest kernel should run under hardware stacks bounds enable */
	kvm_stack_bounds_trap_enable();

#ifdef CONFIG_KVM_GUEST_HW_PV
	boot_init_sequel_func(bsp, cpuid, cpus_to_sync);
#endif
}

/*
 * Clear kernel BSS segment in native mode
 */

void __init boot_kvm_clear_bss(void)
{
	e2k_size_t	size;
	unsigned long	*bss_p;

	bss_p = (unsigned long *)(&__bss_start);
	bss_p = boot_kvm_va_to_pa(bss_p);
	size = (e2k_addr_t)__bss_stop - (e2k_addr_t)__bss_start;
	DebugKVM("Kernel BSS segment will be cleared from "
		"physical address 0x%lx size 0x%lx\n",
		bss_p, size);
	boot_fast_memset(bss_p, 0, size);
}

/*
 * Sequel of process of initialization. This function is run into virtual
 * space and controls termination of boot-time init and start kernel init
 */

void __init init_kvm_terminate_boot_init(bool bsp, int cpuid)
{
	kvm_vcpu_state_t *my_vcpu_state;

	/* Set pointer of the VCPU state at table */
	/* to enable access from/to other VCPUs */
	KVM_GET_VCPU_STATE_BASE(my_vcpu_state);
	vcpus_state[cpuid] = my_vcpu_state;
	DebugKVM("VCPU #%d state at %px populated for other vcpus\n",
		cpuid, my_vcpu_state);

	/*
	 * Start kernel initialization on bootstrap processor.
	 * Other processors will do some internal initialization and wait
	 * for commands from bootstrap processor.
	 */
	init_start_kernel_init(bsp, cpuid);

}

void __init
boot_kvm_parse_param(bootblock_struct_t *bootblock)
{
	boot_native_parse_param(bootblock);
}
