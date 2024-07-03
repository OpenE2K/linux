/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/* $Id: boot_head.c,v 1.41 2009/02/24 15:15:42 atic Exp $
 * Control of boot-time initialization.
 */

#include <asm/p2v/boot_v2p.h>
#include <linux/init_task.h>

#include <asm/p2v/boot_irqflags.h>
#include <asm/p2v/boot_init.h>
#include <asm/p2v/boot_param.h>
#include <asm/p2v/boot_phys.h>
#include <asm/p2v/boot_smp.h>
#include <asm/p2v/boot_map.h>
#include <asm/p2v/boot_mmu_context.h>
#include <asm/boot_recovery.h>
#include <asm/e2k_debug.h>
#include <asm/pic.h>
#include <asm/e2k_sic.h>
#include <asm/regs_state.h>
#include <asm/setup.h>
#include <asm/mmu_context.h>
#include <asm/mmu_regs_access.h>
#include <asm/simul.h>
#include <asm/p2v/boot_console.h>
#include <asm/kvm/boot.h>
#include <asm/kvm/hvc-console.h>

#include "boot_string.h"

#undef	DEBUG_BOOT_MODE
#undef	boot_printk
#undef	DebugB
#undef	DEBUG_BOOT_INFO_MODE
#define	DEBUG_BOOT_MODE		0	/* Boot process */
#define	DEBUG_BOOT_INFO_MODE	0	/* Boot info */
#define	boot_printk		if (DEBUG_BOOT_MODE) do_boot_printk
#define	DebugB			if (DEBUG_BOOT_MODE) dump_printk

atomic_t 	boot_cpucount = ATOMIC_INIT(0);

#ifndef	CONFIG_SMP
unsigned char	boot_init_started = 0;	/* boot-time initialization */
					/* has been started */
unsigned char	_va_support_on = 0;	/* virtual addressing support */
					/* has turned on */
#else
unsigned char	boot_init_started[NR_CPUS] = { [0 ... (NR_CPUS-1)] = 0 };
					/* boot-time initialization */
					/* has been started on CPU */
unsigned char	_va_support_on[NR_CPUS] = { [0 ... (NR_CPUS-1)] = 0 };
					/* virtual addressing support */
					/* has turned on on CPU */
#endif	/* CONFIG_SMP */

bootblock_struct_t *bootblock_phys;	/* bootblock structure */
					/* physical pointer */
bootblock_struct_t *bootblock_virt;	/* bootblock structure */
					/* virtual pointer */
static atomic_t __initdata boot_bss_cleaning_finished = ATOMIC_INIT(0);
#ifdef	CONFIG_SMP
static atomic_t __initdata bootblock_checked = ATOMIC_INIT(0);
static atomic_t __initdata boot_info_setup_finished = ATOMIC_INIT(0);
#endif	/* CONFIG_SMP */

static bool cpu_model_mismatch;

bool	pv_ops_is_set = false;
#define	boot_pv_ops_is_set	boot_native_get_vo_value(pv_ops_is_set)

/* SCALL 12 is used as a kernel jumpstart */
void  notrace __section(".ttable_entry12")
ttable_entry12(int n, bootblock_struct_t *bootblock)
{
	bool bsp;

	/* CPU will stall if we have unfinished memory operations.
	 * This shows bootloader problems if they present */
	__E2K_WAIT_ALL;

	bsp = boot_early_pic_is_bsp();
	/* Convert virtual PV_OPS function addresses to physical */
	if (bsp) {
		native_pv_ops_to_boot_ops();
		boot_pv_ops_is_set = true;
	} else {
		while (!boot_pv_ops_is_set)
			native_cpu_relax();
	}

	/* Clear global registers and set current pointers to 0 */
	/* to indicate that current_thread_info() is not ready yet */
	BOOT_INIT_G_REGS();

	boot_startup(bsp, bootblock);
}

/*
 * Native/guest VM indicator
 */
static bool boot_is_guest_hv_vm(struct machdep *mach)
{
	e2k_core_mode_t CORE;

	CORE.CORE_MODE_reg = boot_native_read_CORE_MODE_reg_value();
	return !!CORE.CORE_MODE_gmi;
}

static void boot_setup_machine_cpu_features(struct machdep *machine)
{
	int cpu = machine->native_id & MACHINE_ID_CPU_TYPE_MASK;
	int revision = machine->native_rev;
	int iset_ver = machine->native_iset_ver;
	bool is_hardware_guest;
	int guest_cpu;
	cpuhas_initcall_t *fn, *start, *end, *fnv;

#ifdef CONFIG_KVM_GUEST_KERNEL
	guest_cpu = machine->guest.id & MACHINE_ID_CPU_TYPE_MASK;
#else
	guest_cpu = cpu;
#endif

	if (iset_ver >= E2K_ISET_V6) {
		e2k_core_mode_t core_mode = BOOT_READ_CORE_MODE_REG();
		is_hardware_guest = core_mode.gmi;
	} else {
		is_hardware_guest = false;
	}

	start = (cpuhas_initcall_t *) __cpuhas_initcalls;
	end = (cpuhas_initcall_t *) __cpuhas_initcalls_end;
	fn = boot_vp_to_pp(start);
	for (fnv = start; fnv < end; fnv++, fn++)
		boot_func_to_pp(*fn)(cpu, revision, iset_ver, guest_cpu,
				     is_hardware_guest, machine);
}

void __init_recv boot_setup_iset_features(struct machdep *machine)
{
	/* Initialize this as early as possible (but after setting cpu
	 * id and revision and boot_machine.native_iset_ver) */
	boot_setup_machine_cpu_features(machine);

#ifdef CONFIG_GREGS_CONTEXT
	if (machine->native_iset_ver < E2K_ISET_V5) {
		machine->save_kernel_gregs = &save_kernel_gregs_v3;
		machine->save_gregs = &save_gregs_v3;
		machine->save_local_gregs = &save_local_gregs_v3;
		machine->save_gregs_dirty_bgr = &save_gregs_dirty_bgr_v3;
		machine->save_gregs_on_mask = &save_gregs_on_mask_v3;
		machine->restore_gregs = &restore_gregs_v3;
		machine->restore_local_gregs = &restore_local_gregs_v3;
		machine->restore_gregs_on_mask = &restore_gregs_on_mask_v3;
	} else {
		machine->save_kernel_gregs = &save_kernel_gregs_v5;
		machine->save_gregs = &save_gregs_v5;
		machine->save_local_gregs = &save_local_gregs_v5;
		machine->save_gregs_dirty_bgr = &save_gregs_dirty_bgr_v5;
		machine->save_gregs_on_mask = &save_gregs_on_mask_v5;
		machine->restore_gregs = &restore_gregs_v5;
		machine->restore_local_gregs = &restore_local_gregs_v5;
		machine->restore_gregs_on_mask = &restore_gregs_on_mask_v5;
	}
#endif

#ifdef CONFIG_USE_AAU
	if (machine->native_iset_ver < E2K_ISET_V5) {
		machine->calculate_aau_aaldis_aaldas =
				&calculate_aau_aaldis_aaldas_v3;
		machine->do_aau_fault = &do_aau_fault_v3;
		machine->save_aaldi = &save_aaldi_v3;
		machine->get_aau_context = &get_aau_context_v3;
	} else if (machine->native_iset_ver == E2K_ISET_V5) {
		machine->calculate_aau_aaldis_aaldas =
				&calculate_aau_aaldis_aaldas_v5;
		machine->do_aau_fault = &do_aau_fault_v5;
		machine->save_aaldi = &save_aaldi_v5;
		machine->get_aau_context = &get_aau_context_v5;
	} else {
		machine->calculate_aau_aaldis_aaldas =
				&calculate_aau_aaldis_aaldas_v6;
		machine->do_aau_fault = &do_aau_fault_v6;
		machine->save_aaldi = &save_aaldi_v5;
		machine->get_aau_context = &get_aau_context_v5;
	}
#endif

#ifdef CONFIG_MLT_STORAGE
	machine->invalidate_MLT = &invalidate_MLT_v3;

	if (machine->native_iset_ver >= E2K_ISET_V6)
		machine->get_and_invalidate_MLT_context =
				&get_and_invalidate_MLT_context_v6;
	else
		machine->get_and_invalidate_MLT_context =
				&get_and_invalidate_MLT_context_v3;
#endif

	if (machine->native_iset_ver < E2K_ISET_V6) {
		machine->rrd = &rrd_v3;
		machine->rwd = &rwd_v3;
		machine->boot_rrd = &boot_rrd_v3;
		machine->boot_rwd = &boot_rwd_v3;
	} else {
		machine->rrd = &rrd_v6;
		machine->rwd = &rwd_v6;
		machine->boot_rrd = &boot_rrd_v6;
		machine->boot_rwd = &boot_rwd_v6;
		machine->save_kvm_context = &save_kvm_context_v6;
		machine->restore_kvm_context = &restore_kvm_context_v6;
		machine->save_dimtp = &save_dimtp_v6;
		machine->restore_dimtp = &restore_dimtp_v6;
		machine->clear_dimtp = &clear_dimtp_v6;
	}

	if (machine->native_iset_ver < E2K_ISET_V5) {
		machine->get_cu_hw1 = &native_get_cu_hw1_v3;
		machine->set_cu_hw1 = &native_set_cu_hw1_v3;
	} else {
		machine->get_cu_hw1 = &native_get_cu_hw1_v5;
		machine->set_cu_hw1 = &native_set_cu_hw1_v5;
	}

	if (machine->native_iset_ver >= E2K_ISET_V6) {
		machine->C1_enter = C1_enter_v6;
		machine->C3_enter = C3_enter_v6;
	} else  {
		machine->C1_enter = C1_enter_v3;
		machine->C3_enter = C3_enter_v3;
	}

#ifdef CONFIG_SMP
	/* Use `wait trap` instead of `wait int` even on v6 CPUs
	 * since it allows ignoring maskable interrupts. */
	machine->clk_off = native_clock_off_v3;
	machine->clk_on = native_clock_on_v3;
#endif
}

void __init_recv
boot_common_setup_arch_mmu(struct machdep *machine, pt_struct_t *pt_struct)
{
	pt_level_t *pmd_level;
	pt_level_t *pud_level;

	pmd_level = &pt_struct->levels[E2K_PMD_LEVEL_NUM];
	pud_level = &pt_struct->levels[E2K_PUD_LEVEL_NUM];

	pmd_level->page_size = E2K_2M_PAGE_SIZE;
	pmd_level->page_shift = PMD_SHIFT;
	pmd_level->page_offset = ~PMD_MASK;

	if (machine->native_iset_ver >= E2K_ISET_V5) {

		pud_level->is_huge = true;
		pud_level->dtlb_type = FULL_ASSOCIATIVE_DTLB_TYPE;
	}
}

void boot_native_setup_machine_id(bootblock_struct_t *bootblock)
{
	unsigned int mach_id = boot_get_e2k_machine_id();

#ifdef CONFIG_E2K_MACHINE
	boot_cpu_model_mismatch = mach_id != (boot_native_machine_id & ~MACHINE_ID_SIMUL);
#else
	boot_native_machine_id = mach_id;
	if (bootblock->info.mach_flags & SIMULATOR_MACH_FLAG)
		boot_native_machine_id |= MACHINE_ID_SIMUL;
#endif

	switch (mach_id) {
	case MACHINE_ID_E2S:
		boot_e2s_setup_arch();
		break;
	case MACHINE_ID_E8C:
		boot_e8c_setup_arch();
		break;
	case MACHINE_ID_E1CP:
		boot_e1cp_setup_arch();
		break;
	case MACHINE_ID_E8C2:
		boot_e8c2_setup_arch();
		break;
	case MACHINE_ID_E12C:
		boot_e12c_setup_arch();
		break;
	case MACHINE_ID_E16C:
		boot_e16c_setup_arch();
		break;
	case MACHINE_ID_E2C3:
		boot_e2c3_setup_arch();
		break;
	case MACHINE_ID_E48C:
		boot_e48c_setup_arch();
		break;
	case MACHINE_ID_E8V7:
		boot_e8v7_setup_arch();
		break;
	default:
		BOOT_BUG("Unknown CPU model 0x%lx\n", mach_id);
		break;
	}
	boot_machine.native_id = boot_native_machine_id;
}

void boot_loader_type_banner(boot_info_t *boot_info)
{
	if (boot_info->signature == BOOTBLOCK_ROMLOADER_SIGNATURE) {
		boot_printk("Boot information passed by ROMLOADER\n");
	} else if (boot_info->signature == BOOTBLOCK_BOOT_SIGNATURE) {
		boot_printk("Boot information passed by BIOS\n");
	} else if (boot_info->signature == BOOTBLOCK_KVM_GUEST_SIGNATURE) {
		boot_printk("Boot information passed by HOST kernel "
			"to KVM GUEST\n");
	} else {
		BOOT_BUG("Boot information passed by unknown loader\n");
	}
}

static void __init
boot_setup(bool bsp, bootblock_struct_t *bootblock)
{
	register boot_info_t		*boot_info = &bootblock->info;
	register e2k_rwap_lo_struct_t	reg_lo = {{ 0 }};
	register e2k_rwap_hi_struct_t	reg_hi = {{ 0 }};
	register e2k_addr_t		addr;
	register e2k_size_t		size;
#ifdef CONFIG_NUMA
	unsigned int cpuid;
#endif

	/*
	 * Set 'data/bss' segment CPU registers OSGD & GD
	 * to kernel image unit
	 *
	 * TODO This conflicts with later usage of GD as a pointer
	 * into current.  So this better be removed, but then
	 * GD must not be relied on to pass _sdata address in p2v/.
	 */

	addr = (e2k_addr_t)_sdata_bss;
	BOOT_BUG_ON(addr & E2K_ALIGN_OS_GLOBALS_MASK,
			"Kernel 'data' segment start address 0x%lx "
			"is not aligned to mask 0x%lx\n",
			addr, E2K_ALIGN_OS_GLOBALS_MASK);
	addr = (e2k_addr_t)boot_vp_to_pp(&_sdata_bss);
	reg_lo.GD_lo_base = addr;
	reg_lo._GD_lo_rw = E2K_GD_RW_PROTECTIONS;

	/* Assume that BSS is placed immediately after data */
	size = (unsigned long) (_edata_bss - _sdata_bss);
	size = ALIGN_TO_MASK(size, E2K_ALIGN_OS_GLOBALS_MASK);
	reg_hi.GD_hi_size = size;
	reg_hi._GD_hi_curptr = 0;

	BOOT_WRITE_GD_REG(reg_hi, reg_lo);
	BOOT_WRITE_OSGD_REG(reg_hi, reg_lo);

	boot_printk("Kernel DATA/BSS segment pointers OSGD & GD are set to "
		"base physical address 0x%lx size 0x%lx\n",
		addr, size);

#ifdef	CONFIG_SMP
	boot_printk("Kernel boot-time initialization in progress "
		"on CPU %d PIC id %d\n",
		boot_smp_processor_id(),
		boot_early_pic_read_id());
#endif	/* CONFIG_SMP */

	/*
	 * Clear kernel BSS segment (on BSP only)
	 */
	if (BOOT_IS_BSP(bsp)) {
		boot_clear_bss();
		boot_set_event(&boot_bss_cleaning_finished);
	} else {
		boot_wait_for_event(&boot_bss_cleaning_finished);
	}

#ifdef CONFIG_NUMA
	/*
	 * Do initialization of CPUs possible and present masks again because
	 * these masks could be cleared while BSS cleaning
	 */
	cpuid = boot_smp_processor_id();
	boot_set_phys_cpu_present(cpuid);

	boot___apicid_to_node[cpuid] = boot_numa_node_id();
#endif

	/*
	 * Set 'text' segment CPU registers OSCUD & CUD
	 * to kernel image unit
	 */

	addr = (e2k_addr_t)_start;
	BOOT_BUG_ON(addr & E2K_ALIGN_OSCU_MASK,
			"Kernel 'text' segment start address 0x%lx "
			"is not aligned to mask 0x%lx\n",
			addr, E2K_ALIGN_OSCU_MASK);
	addr = (e2k_addr_t)boot_vp_to_pp(&_start);
	reg_lo.CUD_lo_base = addr;
	reg_lo.CUD_lo_c = E2K_CUD_CHECKED_FLAG;
	reg_lo._CUD_lo_rw = E2K_CUD_RW_PROTECTIONS;

	size = (e2k_addr_t)_etext - (e2k_addr_t)_start;
	size = ALIGN_TO_MASK(size, E2K_ALIGN_OSCU_MASK);
	reg_hi.CUD_hi_size = size;
	reg_hi._CUD_hi_curptr = 0;

	BOOT_WRITE_CUD_REG(reg_hi, reg_lo);
	BOOT_WRITE_OSCUD_REG(reg_hi, reg_lo);

	boot_printk("Kernel TEXT segment pointers OSCUD & CUD are set to "
		"base physical address 0x%lx size 0x%lx\n",
		addr, size);

	if (BOOT_IS_BSP(bsp)) {
		boot_check_bootblock(bsp, bootblock);
#ifdef	CONFIG_SMP
		boot_set_event(&bootblock_checked);
	} else {
		boot_wait_for_event(&bootblock_checked);
#endif	/* CONFIG_SMP */
	}

	if (addr != boot_info->kernel_base) {
		BOOT_WARNING("Kernel start address 0x%lx is not the same "
			"as base address to load kernel in bootblock "
			"structure 0x%lx\n",
			addr, boot_info->kernel_base);
		boot_info->kernel_base = addr;
	}
	BOOT_BUG_ON(size > boot_info->kernel_size,
		"Kernel size 0x%lx is not the same "
		"as size to load kernel in bootblock structure 0x%lx\n",
		size, boot_info->kernel_size);

	/*
	 * Remember phys. address of boot information block in
	 * an appropriate data structure.
	 */
	if (BOOT_IS_BSP(bsp)) {
		boot_bootblock_phys = bootblock;
		boot_bootinfo_phys_base = (e2k_addr_t)boot_bootblock_phys;

		boot_printk("Boot block physical address: 0x%lx\n",
			boot_bootblock_phys);

		boot_loader_type_banner(boot_info);
		if (DEBUG_BOOT_INFO_MODE) {
			int i;
			for (i = 0; i < sizeof(bootblock_struct_t) / 8; i ++) {
				do_boot_printk("boot_info[%d] = 0x%lx\n",
					i, ((u64 *)boot_info)[i]);
			}
		}
#ifdef	CONFIG_SMP
		boot_setup_smp_cpu_config(boot_info);
		boot_set_event(&boot_info_setup_finished);
	} else {
		boot_wait_for_event(&boot_info_setup_finished);
		if (boot_smp_processor_id() >= NR_CPUS) {
			BOOT_BUG("CPU #%d : this processor number >= than max supported CPU number %d\n",
				boot_smp_processor_id(),
				NR_CPUS);
		}
#endif	/* CONFIG_SMP */
	}
}

/*
 * Sequel of process of initialization. This function is run into virtual
 * space and controls farther system boot
 */
static void __init
boot_init_sequel(bool bsp, int cpuid, int cpus_to_sync)
{
	boot_set_kernel_MMU_state_after();

	init_unmap_virt_to_equal_phys(bsp, cpus_to_sync);

	va_support_on = 1;

	/*
	 * SYNCHRONIZATION POINT
	 * At this point all processors should complete switching to
	 * virtual memory
	 * After synchronization all processors can terminate
	 * boot-time initialization of virtual memory support
	 *
	 * No tracepoint calls before sync all processors should be. All cpus
	 * should end switching to virtual memory support to prevent accessing
	 * to memory by high and low physical addresses simultaneously inside
	 * boot tracepoint. It needs only in the case of
	 * CONFIG_ONLY_HIGH_PHYS_MEM enabled.
	 */
#if 0
	EARLY_BOOT_TRACEPOINT("SYNCHRONIZATION POINT");
#endif
	init_sync_all_processors(cpus_to_sync);

#ifdef CONFIG_SMP
	if (bsp)
#endif
		EARLY_BOOT_TRACEPOINT("kernel boot-time init finished");

	/*
	 * Reset processors number for recovery
	 */
	init_reset_smp_processors_num();

	/*
	 * Initialize dump_printk() - simple printk() which
	 * outputs straight to the serial port.
	 */
#if defined(CONFIG_SERIAL_PRINTK)
	setup_serial_dump_console(&bootblock_virt->info);
#endif

	/*
	 * Show disabled caches
	 */
#ifdef	CONFIG_SMP
	if (bsp) {
#endif	/* CONFIG_SMP */
		if (disable_caches != MMU_CR_CD_EN) {
			if (disable_caches == MMU_CR_CD_D1_DIS)
				dump_printk("Disable L1 cache\n");
			else if (disable_caches == MMU_CR_CD_D_DIS)
				dump_printk("Disable L1 and L2 caches\n");
			else if (disable_caches == MMU_CR_CD_DIS)
				dump_printk("Disable L1, L2 and L3 caches\n");
		}
		if (disable_secondary_caches)
			dump_printk("Disable secondary INTEL caches\n");
		if (disable_IP)
			dump_printk("Disable IB prefetch\n");
		DebugB("MMU CR 0x%llx\n", AW(READ_MMU_CR()));
#ifdef	CONFIG_SMP
	}
#endif	/* CONFIG_SMP */

	/*
	 * Terminate boot-time initialization and start kernel init
	 */
	init_terminate_boot_init(bsp, cpuid);

#ifndef	CONFIG_SMP
#undef	cpuid
#endif	/* CONFIG_SMP */
}

/*
 * Control process of boot-time initialization.
 * Loader or bootloader program should call this function to start boot
 * process of the system. The function provide for virtual memory support
 * and switching to execution into the virtual space. The following part
 * of initialization should be made by 'boot_init_sequel()' function, which
 * will be run with virtual environment support.
 */
static void __init
boot_init(bool bsp, bootblock_struct_t *bootblock)
{
	register int	cpuid;

	cpuid = boot_smp_get_processor_id();
	boot_smp_set_processor_id(cpuid);
	boot_printk("boot_init() started on CPU #%d\n", cpuid);

#ifndef CONFIG_SMP
	if (!bsp) {
		boot_atomic_dec(&boot_cpucount);
		while (1) /* Idle if not boot CPU */
			boot_cpu_relax();
	} else {
#endif /* !CONFIG_SMP */
		boot_set_phys_cpu_present(cpuid);
#ifndef CONFIG_SMP
	}
#endif /* !CONFIG_SMP */
	/*
	 * Preserve recursive call of boot, if some trap occured
	 * while trap table is not installed
	 */

	if (boot_boot_init_started) {
		if (boot_va_support_on) {
			INIT_BUG("Recursive call of boot_init(), perhaps, "
				"due to trap\n");
		} else {
			BOOT_BUG("Recursive call of boot_init(), perhaps, "
				"due to trap\n");
		}
	} else {
		boot_boot_init_started = 1;
	}

	/*
	 * Initialize virtual memory support for farther system boot and
	 * switch sequel initialization to the function 'boot_init_sequel()'
	 * into the real virtual space. Should not be return here.
	 */

	boot_printk("Kernel boot-time initialization started\n");
	boot_setup(bsp, bootblock);
	boot_mem_init(bsp, cpuid, &bootblock->info, boot_init_sequel);
}

void __ref
boot_startup(bool bsp, bootblock_struct_t *bootblock)
{
	boot_info_t	*boot_info = NULL;
	u16		signature;
#ifdef	CONFIG_RECOVERY
	int	recovery = bootblock->kernel_flags & RECOVERY_BB_FLAG;
#else	/* ! CONFIG_RECOVERY  */
	#define		recovery	0
#endif	/* CONFIG_RECOVERY */

	/* CPU will stall if we have unfinished memory operations.
	 * This shows bootloader problems if they present */
	__E2K_WAIT_ALL;

	if (bsp)
		EARLY_BOOT_TRACEPOINT("kernel boot-time init started");

	if (!recovery && bsp) {
		/*
		 * Be careful with initialization order here.
		 *
		 * 1) boot_setup_machine_id() sets the defaults for current processor
		 * (including iset, mmu_separate_pt, etc).
		 *
		 * 2) Command line parameters could specify non-default values, so
		 * boot_parse_param() is called next.
		 *
		 * 3) Now that we know what CPU we are executing on, we can call
		 * boot_setup_iset_features() to initialize cpu_has() subsystem.
		 */

		boot_setup_machine_id(bootblock);
		boot_parse_param(bootblock);
		boot_setup_iset_features(&boot_machine);

		/* set indicator of guest hardware virtualized VM */
		/* can be called only after 'boot_rrd' setup */
		boot_machine.gmi = boot_is_guest_hv_vm(&boot_machine);

		boot_common_setup_arch_mmu(&boot_machine,
					   boot_pgtable_struct_p);
	}

	/* early setup CPU # */
	boot_smp_set_processor_id(boot_early_pic_read_id());

#if defined(CONFIG_SERIAL_BOOT_PRINTK)
	if (!recovery)
		boot_setup_serial_console(bsp, &bootblock->info);
#endif

#ifdef	CONFIG_EARLY_VIRTIO_CONSOLE
	if (boot_paravirt_enabled()) {
		/* only guest kernel can use VIRTIO HVC console */
#ifdef	CONFIG_SMP
		if (!bsp)
			while (!boot_early_virtio_cons_enabled) {
				mb();	/* wait for all read completed */
			}
		else
#endif	/* CONFIG_SMP */
		boot_hvc_l_cons_init(bootblock->info.serial_base);
	}
#endif	/* CONFIG_EARLY_VIRTIO_CONSOLE */

	/* Delay the check until after the console initialization */
	if (bsp)
		BOOT_BUG_ON(boot_cpu_model_mismatch, "Kernel is built for a different CPU model\n");

#if defined(DEBUG_BOOT_INFO) && DEBUG_BOOT_INFO
	if (bsp)
		do_boot_printk("bootblock 0x%x, flags 0x%x\n",
				bootblock, bootblock->kernel_flags);
#endif

	/*
	 * BIOS loader has following incompatibilities with kernel
	 * boot process assumption:
	 *	1. Not set USBR register to C stack high address
	 *	2. Set PSP register size to full procedure stack memory
	 *	   when this size should be without last page (last page
	 *	   used as guard to preserve stack overflow)
	 *	3. Set PCSP register size to full procedure chain stack memory
	 *	   when this size should be without last page (last page
	 *	   used as guard to preserve stack overflow)
	 */
	boot_info = &bootblock->info;
	signature = boot_info->signature;

	if (signature == BOOTBLOCK_BOOT_SIGNATURE) {
		e2k_usbr_t	USBR = { {0} };
		usd_struct_t	USD;
		psp_struct_t	PSP;
		pcsp_struct_t	PCSP;

		if (!recovery) {
			boot_read_USD_reg(&USD);
			USBR.USBR_base = PAGE_ALIGN_DOWN(USD.USD_base);
			boot_write_USBR_reg(USBR);

			boot_read_PSP_reg(&PSP);
			PSP.PSP_size -= PAGE_SIZE;
			boot_write_PSP_reg(PSP);

			boot_read_PCSP_reg(&PCSP);
			PCSP.PCSP_size -= PAGE_SIZE;
			boot_write_PCSP_reg(PCSP);
		}
	}

	/*
	 * Set PSR/UPSR register to the initial state with disabled interrupts.
	 * NMI must be disabled too because spurious interrupts can occur
	 * while booting and kernel is not ready yet to handle any traps
	 * or interrupts.
	 * Also switch control from PSR register to UPSR for local
	 * PCR.ie/nmie mask case
	 */
	BOOT_SET_KERNEL_IRQ_MASK();

	/*
	 * Check supported CPUs number. Some structures and tables
	 * allocated support only NR_CPUS number of CPUs
	 */
	if (boot_smp_processor_id() >= NR_CPUS) {
		static int printed = 0;

		/* Make sure the message gets out on !SMP kernels
		 * which have spinlocks compiled out. */
		if (!xchg(boot_vp_to_pp(&printed), 1)) {
			BOOT_BUG("CPU #%d : this processor number >= than max supported CPU number %d\n",
				boot_smp_processor_id(), NR_CPUS);
		}

		for (;;)
			cpu_relax();
	}

#ifdef	CONFIG_RECOVERY
	if (recovery)
		boot_recovery(bsp, bootblock);
	else
#endif	/* CONFIG_RECOVERY */
		boot_init(bsp, bootblock);
}

static int __init boot_set_iset(char *cmd)
{
	unsigned long iset;

	if (*cmd != 'v') {
		boot_printk("Bad 'iset' kernel parameter value: \"%s\"\n", cmd); 
		return 1;
	}

	++cmd;

	iset = boot_simple_strtoul(cmd, &cmd, 0);
	boot_printk("Setting machine iset version to %d\n", iset);

	boot_machine.native_iset_ver = iset;

	return 0;
}
boot_param("iset", boot_set_iset);

/*
 * Clear kernel BSS segment in native mode
 */
void __init boot_native_clear_bss(void)
{
	e2k_size_t		size;
	unsigned long		*bss_p;

	bss_p = (unsigned long *)boot_vp_to_pp(&__bss_start);
	size = (e2k_addr_t)__bss_stop - (e2k_addr_t)__bss_start;
	boot_printk("Kernel BSS segment will be cleared from "
		"physical address 0x%lx size 0x%lx\n",
		bss_p, size);
	boot_fast_memset(bss_p, 0, size);
}

void __init
boot_native_check_bootblock(bool bsp, bootblock_struct_t *bootblock)
{
	/* nothing to check */
}

/*
 * Start kernel initialization on bootstrap processor.
 * Other processors will do some internal initialization and wait
 * for commands from bootstrap processor.
 */
void __init init_start_kernel_init(bool bsp, int cpuid)
{
	setup_stack_print();

	if (BOOT_IS_BSP(bsp)) {
		init_preempt_count_resched(INIT_PREEMPT_COUNT, false);
		e2k_start_kernel();
	} else {
		init_preempt_count_resched(PREEMPT_ENABLED, false);
		e2k_start_secondary(cpuid);
	}

	/*
	 * Never should be here
	 */
	BUG();
	boot_panic("BOOT: Return from start_kernel().\n");
	E2K_HALT_ERROR(-1);
}

/*
 * Sequel of process of initialization. This function is run into virtual
 * space and controls termination of boot-time init and start kernel init
 */
void __init init_native_terminate_boot_init(bool bsp, int cpuid)
{

	/*
	 * Flush instruction and data cashes to delete all physical
	 * instruction and data pages
	 */
	flush_ICACHE_all();

	/*
	 * Start kernel initialization process
	 */
	init_start_kernel_init(bsp, cpuid);
}
