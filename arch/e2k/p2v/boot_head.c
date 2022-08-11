/* $Id: boot_head.c,v 1.41 2009/02/24 15:15:42 atic Exp $
 *
 * Control of boot-time initialization.
 *
 * Copyright (C) 2001 Salavat Guiliazov <atic@mcst.ru>
 */

#include <linux/init_task.h>

#include <asm/p2v/boot_v2p.h>
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
#define	DebugB			if (DEBUG_BOOT_MODE) printk

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
#ifdef	CONFIG_SMP
static atomic_t __initdata boot_bss_cleaning_finished = ATOMIC_INIT(0);
static atomic_t __initdata bootblock_checked = ATOMIC_INIT(0);
static atomic_t __initdata boot_info_setup_finished = ATOMIC_INIT(0);
#endif	/* CONFIG_SMP */

bool	pv_ops_is_set = false;
#define	boot_pv_ops_is_set	boot_native_get_vo_value(pv_ops_is_set)

/* SCALL 12 is used as a kernel jumpstart */
void  notrace __section(.ttable_entry12)
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
static inline bool boot_is_guest_hv_vm(struct machdep *mach)
{
	if (likely(mach->native_iset_ver > E2K_ISET_V2)) {
		/* there is CPU register CORE_MODE to check 'gmi' */
		e2k_core_mode_t CORE;

		CORE.CORE_MODE_reg = boot_native_read_CORE_MODE_reg_value();
		return !!CORE.CORE_MODE_gmi;
	} else {
		/* host set IDR.hw_virt instead of CORE_MODE.gmi */
		/* (this field is reserved on iset V2) */
		e2k_idr_t IDR;

		IDR.IDR_reg = boot_native_read_IDR_reg_value();
		return !!IDR.hw_virt;
	}
}

static void boot_setup_machine_cpu_features(struct machdep *machine)
{
	int cpu = machine->native_id & MACHINE_ID_CPU_TYPE_MASK;
	int revision = machine->native_rev;
	int iset_ver = machine->native_iset_ver;
	int guest_cpu;
	cpuhas_initcall_t *fn, *start, *end, *fnv;

#ifdef CONFIG_KVM_GUEST_KERNEL
	guest_cpu = machine->guest.id & MACHINE_ID_CPU_TYPE_MASK;
#else
	guest_cpu = cpu;
#endif

	start = (cpuhas_initcall_t *) __cpuhas_initcalls;
	end = (cpuhas_initcall_t *) __cpuhas_initcalls_end;
	fn = boot_vp_to_pp(start);
	for (fnv = start; fnv < end; fnv++, fn++)
		boot_func_to_pp(*fn)(cpu, revision, iset_ver, guest_cpu,
				     machine);
}

void __init_recv boot_setup_iset_features(struct machdep *machine)
{
	/* Initialize this as early as possible (but after setting cpu
	 * id and revision and boot_machine.native_iset_ver) */
	boot_setup_machine_cpu_features(machine);

#ifdef CONFIG_GREGS_CONTEXT
	if (machine->native_iset_ver < E2K_ISET_V5) {
		machine->save_kernel_gregs = &save_kernel_gregs_v2;
		machine->save_gregs = &save_gregs_v2;
		machine->save_local_gregs = &save_local_gregs_v2;
		machine->save_gregs_dirty_bgr = &save_gregs_dirty_bgr_v2;
		machine->save_gregs_on_mask = &save_gregs_on_mask_v2;
		machine->restore_gregs = &restore_gregs_v2;
		machine->restore_local_gregs = &restore_local_gregs_v2;
		machine->restore_gregs_on_mask = &restore_gregs_on_mask_v2;
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
				&calculate_aau_aaldis_aaldas_v2;
		machine->do_aau_fault = &do_aau_fault_v2;
		machine->save_aaldi = &save_aaldi_v2;
		machine->get_aau_context = &get_aau_context_v2;
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

#ifdef	CONFIG_SECONDARY_SPACE_SUPPORT
	machine->flushts = ((machine->native_iset_ver < E2K_ISET_V3) ?
				NULL : &flushts_v3);
#endif

#ifdef CONFIG_MLT_STORAGE
	if (machine->native_iset_ver >= E2K_ISET_V6) {
		machine->invalidate_MLT = &invalidate_MLT_v3;
		machine->get_and_invalidate_MLT_context =
				&get_and_invalidate_MLT_context_v6;
	} else if (machine->native_iset_ver >= E2K_ISET_V3) {
		machine->invalidate_MLT = &invalidate_MLT_v3;
		machine->get_and_invalidate_MLT_context =
				&get_and_invalidate_MLT_context_v3;
	} else {
		machine->invalidate_MLT = &invalidate_MLT_v2;
		machine->get_and_invalidate_MLT_context =
				&get_and_invalidate_MLT_context_v2;
	}
#endif

	if (machine->native_iset_ver == E2K_ISET_V2) {
		machine->rrd = &rrd_v2;
		machine->rwd = &rwd_v2;
		machine->boot_rrd = &boot_rrd_v2;
		machine->boot_rwd = &boot_rwd_v2;
	} else if (machine->native_iset_ver < E2K_ISET_V6) {
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
		machine->get_cu_hw1 = &native_get_cu_hw1_v2;
		machine->set_cu_hw1 = &native_set_cu_hw1_v2;
	} else {
		machine->get_cu_hw1 = &native_get_cu_hw1_v5;
		machine->set_cu_hw1 = &native_set_cu_hw1_v5;
	}

	if (machine->native_iset_ver >= E2K_ISET_V6) {
		machine->C1_enter = C1_enter_v6;
		machine->C3_enter = C3_enter_v6;
	} else if (machine->native_iset_ver >= E2K_ISET_V3) {
		machine->C1_enter = C1_enter_v2;
		machine->C3_enter = C3_enter_v3;
	} else {
		machine->C1_enter = C1_enter_v2;
	}

#ifdef CONFIG_SMP
	if (machine->native_iset_ver >= E2K_ISET_V3) {
		machine->clk_off = clock_off_v3;
		machine->clk_on = clock_on_v3;
	}
#endif
}

void __init_recv
boot_common_setup_arch_mmu(struct machdep *machine, pt_struct_t *pt_struct)
{
	pt_level_t *pmd_level;
	pt_level_t *pud_level;

	if (boot_machine_has(machine, CPU_HWBUG_PAGE_A))
		pt_struct->accessed_mask = _PAGE_A_SW_V2;

	pmd_level = &pt_struct->levels[E2K_PMD_LEVEL_NUM];
	pud_level = &pt_struct->levels[E2K_PUD_LEVEL_NUM];
	if (machine->native_iset_ver >= E2K_ISET_V3) {
		pmd_level->page_size = E2K_2M_PAGE_SIZE;
		pmd_level->page_shift = PMD_SHIFT;
		pmd_level->page_offset = ~PMD_MASK;
		pmd_level->huge_ptes = 1;
	} else {
		pmd_level->page_size = E2K_4M_PAGE_SIZE;
		pmd_level->page_shift = PMD_SHIFT + 1;
		pmd_level->page_offset = E2K_4M_PAGE_SIZE - 1;
		pmd_level->huge_ptes = 2;
		pmd_level->boot_set_pte = boot_vp_to_pp(&boot_set_double_pte);
		pmd_level->boot_get_huge_pte =
				boot_vp_to_pp(&boot_get_double_huge_pte);
		pmd_level->init_pte_clear = &init_double_pte_clear;
		pmd_level->init_get_huge_pte = &init_get_double_huge_pte;
		pmd_level->split_pt_page = &split_multiple_pmd_page;

		pud_level->map_pt_huge_page_to_prev_level =
				&map_pud_huge_page_to_multiple_pmds;
	}
	if (machine->native_iset_ver >= E2K_ISET_V5) {

		pud_level->is_huge = true;
		pud_level->huge_ptes = 1;
		pud_level->dtlb_type = FULL_ASSOCIATIVE_DTLB_TYPE;
	}
}

void boot_native_setup_machine_id(bootblock_struct_t *bootblock)
{
#ifdef	CONFIG_E2K_MACHINE
#if defined(CONFIG_E2K_ES2_DSP) || defined(CONFIG_E2K_ES2_RU)
	boot_es2_setup_arch();
#elif defined(CONFIG_E2K_E2S)
	boot_e2s_setup_arch();
#elif defined(CONFIG_E2K_E8C)
	boot_e8c_setup_arch();
#elif defined(CONFIG_E2K_E8C2)
	boot_e8c2_setup_arch();
#elif defined(CONFIG_E2K_E1CP)
	boot_e1cp_setup_arch();
#elif defined(CONFIG_E2K_E12C)
	boot_e12c_setup_arch();
#elif defined(CONFIG_E2K_E16C)
	boot_e16c_setup_arch();
#elif defined(CONFIG_E2K_E2C3)
	boot_e2c3_setup_arch();
#else
#    error "E2K MACHINE type does not defined"
#endif
#else	/* ! CONFIG_E2K_MACHINE */
	int		simul_flag;
	int		iohub_flag;
	int		mach_id = 0;

	simul_flag = bootblock->info.mach_flags & SIMULATOR_MACH_FLAG;
	iohub_flag = bootblock->info.mach_flags & IOHUB_MACH_FLAG;
	if (simul_flag)
		mach_id |= MACHINE_ID_SIMUL;
	if (iohub_flag)
		mach_id |= MACHINE_ID_E2K_IOHUB;

	mach_id |= boot_get_e2k_machine_id();
#if CONFIG_E2K_MINVER == 2
	if (mach_id == MACHINE_ID_ES2_DSP_LMS ||
			mach_id == MACHINE_ID_ES2_RU_LMS ||
			mach_id == MACHINE_ID_ES2_DSP ||
			mach_id == MACHINE_ID_ES2_RU) {
		boot_es2_setup_arch();
	} else
#endif
#if CONFIG_E2K_MINVER <= 3
	if (mach_id == MACHINE_ID_E2S_LMS ||
			mach_id == MACHINE_ID_E2S) {
		boot_e2s_setup_arch();
	} else
#endif
#if CONFIG_E2K_MINVER <= 4
	if (mach_id == MACHINE_ID_E8C_LMS ||
			mach_id == MACHINE_ID_E8C) {
		boot_e8c_setup_arch();
	} else if (mach_id == MACHINE_ID_E1CP_LMS ||
			mach_id == MACHINE_ID_E1CP) {
		boot_e1cp_setup_arch();
	} else
#endif
#if CONFIG_E2K_MINVER <= 5
	if (mach_id == MACHINE_ID_E8C2_LMS ||
			mach_id == MACHINE_ID_E8C2) {
		boot_e8c2_setup_arch();
	} else
#endif
#if CONFIG_E2K_MINVER <= 6
	if (mach_id == MACHINE_ID_E12C_LMS ||
			mach_id == MACHINE_ID_E12C) {
		boot_e12c_setup_arch();
	} else if (mach_id == MACHINE_ID_E16C_LMS ||
			mach_id == MACHINE_ID_E16C) {
		boot_e16c_setup_arch();
	} else if (mach_id == MACHINE_ID_E2C3_LMS ||
			mach_id == MACHINE_ID_E2C3) {
		boot_e2c3_setup_arch();
	}
#endif /* CONFIG_E2K_MINVER */

	boot_native_machine_id = mach_id;
#endif /* CONFIG_E2K_MACHINE */
	boot_machine.native_id = boot_native_machine_id;
}

static void __init
boot_loader_type_banner(boot_info_t *boot_info)
{
	if (boot_info->signature == ROMLOADER_SIGNATURE) {
		boot_printk("Boot information passed by ROMLOADER\n");
	} else if (boot_info->signature == X86BOOT_SIGNATURE) {
		boot_printk("Boot information passed by BIOS (x86)\n");
	} else if (boot_info->signature == KVM_GUEST_SIGNATURE) {
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
	 */

	addr = (e2k_addr_t)_sdata;
	BOOT_BUG_ON(addr & E2K_ALIGN_OS_GLOBALS_MASK,
			"Kernel 'data' segment start address 0x%lx "
			"is not aligned to mask 0x%lx\n",
			addr, E2K_ALIGN_OS_GLOBALS_MASK);
	addr = (e2k_addr_t)boot_vp_to_pp(&_sdata);
	reg_lo.GD_lo_base = addr;
	reg_lo._GD_lo_rw = E2K_GD_RW_PROTECTIONS;

	/* Assume that BSS is placed immediately after data */
	size = (e2k_addr_t)_edata_bss - (e2k_addr_t)_sdata;
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
#ifdef	CONFIG_SMP
	if (bsp) {
#endif	/* CONFIG_SMP */
		boot_clear_bss();
#ifdef	CONFIG_SMP
		boot_set_event(&boot_bss_cleaning_finished);
	} else {
		boot_wait_for_event(&boot_bss_cleaning_finished);
	}
#endif	/* CONFIG_SMP */

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
	 * Set Trap Cellar pointer and MMU register to kernel image area
	 * and reset Trap Counter register
	 * In NUMA mode now we set pointer to base trap cellar on
	 * bootstrap node
	 */

	boot_set_MMU_TRAP_POINT(boot_trap_cellar);
	boot_reset_MMU_TRAP_COUNT();

	boot_printk("Kernel trap cellar set to physical address 0x%lx "
		"MMU_TRAP_CELLAR_MAX_SIZE 0x%x kernel_trap_cellar 0x%lx\n",
		boot_kernel_trap_cellar, MMU_TRAP_CELLAR_MAX_SIZE,
		BOOT_KERNEL_TRAP_CELLAR);

	/*
	 * Remember phys. address of boot information block in
	 * an appropriate data structure.
	 */

#ifdef	CONFIG_SMP
	if (bsp) {
#endif	/* CONFIG_SMP */
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
	}
#endif	/* CONFIG_SMP */
}

/*
 * Sequel of process of initialization. This function is run into virtual
 * space and controls farther system boot
 */
static void __init
boot_init_sequel(bool bsp, int cpuid, int cpus_to_sync)
{
	boot_set_kernel_MMU_state_after();

	va_support_on = 1;

	/*
	 * SYNCHRONIZATION POINT #3
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
	EARLY_BOOT_TRACEPOINT("SYNCHRONIZATION POINT #3");
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
		if (disable_caches != _MMU_CD_EN) {
			if (disable_caches == _MMU_CD_D1_DIS)
				pr_info("Disable L1 cache\n");
			else if (disable_caches == _MMU_CD_D_DIS)
				pr_info("Disable L1 and L2 caches\n");
			else if (disable_caches == _MMU_CD_DIS)
				pr_info("Disable L1, L2 and L3 caches\n");
		}
		if (disable_secondary_caches)
			pr_info("Disable secondary INTEL caches\n");
		if (disable_IP == _MMU_IPD_DIS)
			pr_info("Disable IB prefetch\n");
		DebugB("MMU CR 0x%llx\n", READ_MMU_CR());
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

	/*
	 * An early parse of cmd line.
	 */
#ifdef	CONFIG_SMP
	if (bsp) {
#endif	/* CONFIG_SMP */
		boot_machine.cmdline_iset_ver = false;
		boot_parse_param(bootblock);
#ifdef	CONFIG_SMP
	}
#endif	/* CONFIG_SMP */

	if (!recovery && bsp) {
		boot_setup_machine_id(bootblock);
		boot_setup_iset_features(&boot_machine);

		/* set indicator of guest hardware virtualized VM */
		/* can be called only after 'boot_rrd' setup */
		boot_machine.gmi = boot_is_guest_hv_vm(&boot_machine);

		boot_common_setup_arch_mmu(&boot_machine,
					   boot_pgtable_struct_p);
	}

	/* early setup CPU # */
	boot_smp_set_processor_id(boot_early_pic_read_id());

	/* Try to determine automatically if we are under virtualization */
#ifndef CONFIG_CPU_ES2
	if (bsp) {
		e2k_core_mode_t core_mode;

		AW(core_mode) = NATIVE_READ_CORE_MODE_REG_VALUE();
		if (core_mode.gmi)
			boot_machine.native_iset_ver = E2K_ISET_V6;
	}
#endif

#if defined(CONFIG_SERIAL_BOOT_PRINTK)
	if (!recovery) {
		boot_setup_serial_console(bsp, &bootblock->info);
	}
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

#if defined(DEBUG_BOOT_INFO) && DEBUG_BOOT_INFO
	if (bsp) {
		/*
		 * Set boot strap CPU id to enable erly boot print with
		 * nodes and CPUs numbers
		 */
		int cpu_id = boot_early_pic_read_id();
		boot_smp_set_processor_id(cpu_id);
		do_boot_printk("bootblock 0x%x, flags 0x%x\n",
				bootblock, bootblock->kernel_flags);
	}
#endif

	/*
	 * BIOS/x86 loader has following incompatibilities with kernel
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

	if (signature == X86BOOT_SIGNATURE) {
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
	 * Set UPSR register in the initial state (where interrupts
	 * are disabled). NMI should be disabled too, because of spureous
	 * interrupts can be occur while booting time and kernel is not now
	 * ready to handle any traps and interrupts.
	 * Switch control from PSR register to UPSR if it needs
	*/
	BOOT_SET_KERNEL_UPSR();

	/*
	 * Check supported CPUs number. Some structures and tables
	 * allocated support only NR_CPUS number of CPUs
	 */
	if (boot_smp_processor_id() >= NR_CPUS) {
		static int printed = 0;

		/* Make sure the message gets out on !SMP kernels
		 * which have spinlocks compiled out. */
		if (!xchg(boot_vp_to_pp(&printed), 1)) {
			BOOT_BUG_POINT("boot_startup()");
			BOOT_BUG("CPU #%d : this processor number >= than max supported CPU number %d\n",
				boot_smp_processor_id(), NR_CPUS);
		}

		for (;;)
			cpu_relax();
	}

#ifdef	CONFIG_RECOVERY
	if (recovery)
		boot_recovery(bootblock);
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
	boot_machine.cmdline_iset_ver = true;

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

	if (bsp) {
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
	 * Terminate boot-time initialization of virtual memory support
	 */
	init_mem_term(cpuid);

	/*
	 * Start kernel initialization process
	 */
	init_start_kernel_init(bsp, cpuid);
}
