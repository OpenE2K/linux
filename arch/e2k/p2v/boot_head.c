/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Control of boot-time initialization.
 */

#define DEBUG_CPU_REGS 0

#include <asm/p2v/boot_v2p.h>
#include <linux/init_task.h>

#include <asm/p2v/boot_irqflags.h>
#include <asm/p2v/boot_init.h>
#include <asm/p2v/boot_param.h>
#include <asm/p2v/boot_phys.h>
#include <asm/p2v/boot_smp.h>
#include <asm/p2v/boot_head.h>
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
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include <asm/kvm/paravirt_sw/boot.h>
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
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

atomic_t boot_cpucount = ATOMIC_INIT(0);

#ifndef	CONFIG_SMP
unsigned char boot_init_started = 0;	/* boot-time initialization */
					/* has been started */
unsigned char _va_support_on = 0;	/* virtual addressing support */
					/* has turned on */
#else
unsigned char boot_init_started[NR_CPUS] = {[0 ... (NR_CPUS - 1)] = 0 };

					/* boot-time initialization */
					/* has been started on CPU */
unsigned char _va_support_on[NR_CPUS] = {[0 ... (NR_CPUS - 1)] = 0 };

					/* virtual addressing support */
					/* has turned on on CPU */
#endif /* CONFIG_SMP */

bootblock_struct_t *bootblock_phys;	/* bootblock structure */
					/* physical pointer */
bootblock_struct_t *bootblock_virt;	/* bootblock structure */
					/* virtual pointer */
static atomic_t __initdata boot_bss_cleaning_finished = ATOMIC_INIT(0);
#ifdef	CONFIG_SMP
static atomic_t __initdata bootblock_checked = ATOMIC_INIT(0);
static atomic_t __initdata boot_info_setup_finished = ATOMIC_INIT(0);
#endif /* CONFIG_SMP */

static bool cpu_model_mismatch;

static bool pv_ops_is_set = false;
#define	boot_pv_ops_is_set	boot_native_get_vo_value(pv_ops_is_set)

/*
 * Determine whether current CPU supports QP format.
 * Can be used before cpu features subsystem initialization.
 */
static bool boot_early_get_qp(void)
{
	u32 mdl = boot_read_IDR_reg().mdl;
	return !(mdl <= IDR_E2S_MDL || mdl == IDR_E8C_MDL || mdl == IDR_E1CP_MDL);
}

/* SCALL 12 is used as a kernel jumpstart */
void notrace __section(".ttable_entry12")
__visible ttable_entry12(int n, bootblock_struct_t *bootblock)
{
	bool bsp;

	/* CPU will stall if we have unfinished memory operations.
	 * This shows bootloader problems if they present */
	__E2K_WAIT_ALL;

	boot_write_UPSR_reg(E2K_KERNEL_UPSR_LOC_IRQ_DISABLED_ALL);

	bsp = boot_early_pic_is_bsp();
	/* Convert virtual PV_OPS function addresses to physical */
	if (bsp) {
		native_pv_ops_to_boot_ops();
		boot_pv_ops_is_set = true;
	} else {
		while (!boot_pv_ops_is_set)
			native_cpu_relax();
	}

	/*
	 * Clear global registers and set current pointers to 0
	 * to indicate that current_thread_info() is not ready yet.
	 */
	bool clear_qp = boot_early_get_qp();
	BOOT_INIT_G_REGS(clear_qp);

	boot_startup(bsp, bootblock);
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

	is_hardware_guest = boot_native_read_CORE_MODE_reg().gmi;

	start = (cpuhas_initcall_t *) __cpuhas_initcalls;
	end = (cpuhas_initcall_t *) __cpuhas_initcalls_end;
	fn = boot_vp_to_pp(start);
	for (fnv = start; fnv < end; fnv++, fn++) {
		boot_func_to_pp(*fn) (cpu, revision, iset_ver, guest_cpu,
				      is_hardware_guest, boot_cpu_features);
	}

	BUILD_BUG_ON_MSG(NR_CPU_FEATURES > 128, "%g23 and %g24 are not enough to hold all cpu features, please expand into %g25 too");
}

static void __init_recv boot_setup_iset_features(struct machdep *machine)
{
	/* Initialize this as early as possible (but after setting cpu
	 * id and revision and boot_machine.native_iset_ver) */
	boot_setup_machine_cpu_features(machine);

	if (machine->native_iset_ver < E2K_ISET_V5) {
		machine->save_global_gregs = &save_global_gregs_v3;
		machine->restore_global_gregs = &restore_global_gregs_v3;
		machine->restore_local_gregs = &restore_local_gregs_v3;
		machine->save_scratch_gregs = &save_scratch_gregs_v3;
		machine->restore_scratch_gregs = &restore_scratch_gregs_v3;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		machine->save_local_gregs = &save_local_gregs_v3;
		machine->save_gregs_on_mask = &save_gregs_on_mask_v3;
		machine->restore_gregs_on_mask = &restore_gregs_on_mask_v3;
#endif
	} else {
		machine->save_global_gregs = &save_global_gregs_v5;
		machine->restore_global_gregs = &restore_global_gregs_v5;
		machine->restore_local_gregs = &restore_local_gregs_v5;
		machine->save_scratch_gregs = &save_scratch_gregs_v5;
		machine->restore_scratch_gregs = &restore_scratch_gregs_v5;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		machine->save_local_gregs = &save_local_gregs_v5;
		machine->save_gregs_on_mask = &save_gregs_on_mask_v5;
		machine->restore_gregs_on_mask = &restore_gregs_on_mask_v5;
#endif
	}

	if (machine->native_iset_ver < E2K_ISET_V5) {
		machine->calculate_aau_aaldis_aaldas = &calculate_aau_aaldis_aaldas_v3;
		machine->do_aau_fault = &do_aau_fault_v3;
		machine->get_aau_context = &get_aau_context_v3;
	} else if (machine->native_iset_ver == E2K_ISET_V5) {
		machine->calculate_aau_aaldis_aaldas = &calculate_aau_aaldis_aaldas_v5;
		machine->do_aau_fault = &do_aau_fault_v5;
		machine->get_aau_context = &get_aau_context_v5;
	} else {
		machine->calculate_aau_aaldis_aaldas = &calculate_aau_aaldis_aaldas_v6;
		machine->do_aau_fault = &do_aau_fault_v6;
		machine->get_aau_context = &get_aau_context_v5;
	}

#ifdef CONFIG_MLT_STORAGE
	if (machine->native_iset_ver >= E2K_ISET_V6)
		machine->get_and_invalidate_MLT_context = &get_and_invalidate_MLT_context_v6;
	else
		machine->get_and_invalidate_MLT_context = &get_and_invalidate_MLT_context_v3;
#endif

	if (machine->native_iset_ver == E2K_ISET_V6) {
		machine->save_kvm_context = &save_kvm_context_v6;
		machine->restore_kvm_context = &restore_kvm_context_v6;
	} else if (machine->native_iset_ver >= E2K_ISET_V7) {
		machine->save_kvm_context = &save_kvm_context_v7;
		machine->restore_kvm_context = &restore_kvm_context_v7;
	}

	if (machine->native_iset_ver >= E2K_ISET_V6) {
		machine->C1_enter = C1_enter_v6;
		machine->C3_enter = C3_enter_v6;
	} else {
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

noinline
static void set_usfs_v7(u64 usfs)
{
	e2k_cr1_t cr1 = read_CR1_reg();
	write_CR1_reg(set_cr1_ussz(cr1, usfs));
}

noinline
static void convert_cpu_regs_to_v7(void)
{
	e2k_psp_t	psp;
	e2k_pcsp_t	pcsp;
	e2k_usd_t	usd;
	e2k_gd_t	gd;
	e2k_cud_t	cud;
	e2k_mem_crs_t 	*crsp;
	e2k_dimtp_t	dimtp;
	e2k_sbr_t sbr;

	e2k_core_mode_t cm = native_read_CORE_MODE_reg();
	if (cm.descr_v7) {
		cm.macp_enbl = cpu_has(CPU_FEAT_MADM);
		cm.getsp_v7 = 1;
		native_write_CORE_MODE_reg(cm);
		return;
	}

	/*
	 * 1) Read v6 registers
	 */

	E2K_FLUSHCPU;

	psp  = native_read_PSP_reg();
	pcsp = native_read_PCSP_reg();
	usd  = native_read_USD_reg();
	/* We sure CUD and OSCUD & GD and OSGD are the same */
	gd   = native_read_GD_reg();
	cud  = native_read_CUD_reg();
	dimtp = native_read_DIMTP_reg();

	psp  = new_psp(psp.Base, psp.Size, psp.Ind);
	pcsp = new_pcsp(pcsp.Base, pcsp.Size, pcsp.Ind);
	gd   = new_gd(gd.Base, _edata_bss - _sdata_bss);
	cud  = new_cud(cud.Base, _end - _start, 1, cud_m64);

	/*
	 * 2) Update ussz field in chain stack
	 */

	/* v6 %usd does not have full size, try to get it from chain stack */
	u64 usd_full_size = 0;

	u64 prev_ussz = 0;
	for (crsp = (e2k_mem_crs_t *)PCSP_BASE(pcsp); crsp < K_PCSP_PTR(pcsp); crsp++) {
		u64 ussz = get_cr1_ussz(crsp->cr1);
		usd_full_size = max(usd_full_size, ussz);

		/*
		 * At least the first frame will be empty because there is
		 * nowhere to return from it.  Also for this reason we have
		 * no needed information to update the second frame.
		 */
		set_cr1p_ussz(&crsp->cr1, (prev_ussz > ussz) ? (prev_ussz - ussz) : 0);

		prev_ussz = ussz;
	}

	e2k_cr1_t cr1 = read_CR1_reg();
	u64 cr1_ussz = get_cr1_ussz(cr1);
	write_CR1_reg(set_cr1_ussz(cr1, prev_ussz - cr1_ussz));

	/*
	 * 3) Calculate new %usd/%sbr values now that we have usd_full_size
	 */

	usd  = new_usd(usd.Ptr - usd.Ind, usd_full_size, usd.Ind);
	sbr  = (e2k_sbr_t) { .base = USD_BASE(usd) + USD_SIZE_V7(usd) };

	/*
	 * 4) Write all registers
	 */

	/* Must be before all other regs write */
	cm.descr_v7 = 1;
	cm.getsp_v7 = 1;
	cm.macp_enbl = cpu_has(CPU_FEAT_MADM);
	native_write_CORE_MODE_reg(cm);

	/* Also clears %usfs */
	native_write_stacks(psp, pcsp, usd, sbr);

	native_write_GD_reg(gd);
	native_write_CUD_reg(cud);
	native_write_OSGD_reg(gd);
	native_write_OSCUD_reg(cud);
	native_write_DIMTP_reg(dimtp);

	/* Set %usfs */
	set_usfs_v7(cr1_ussz - USD_IND(usd));
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

	if (boot_cpu_has(CPU_FEAT_ISET_V5)) {
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
		boot_printk("Boot information passed by HOST kernel to KVM GUEST\n");
	} else {
		BOOT_BUG("Boot information passed by unknown loader\n");
	}
}

static void __init boot_setup(bool bsp, bootblock_struct_t *bootblock)
{
	register boot_info_t *boot_info = &bootblock->info;
	register e2k_gd_t gd;
	register e2k_cud_t cud;
	register e2k_addr_t addr;
	register e2k_size_t size;
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

	addr = (e2k_addr_t) _sdata_bss;
	BOOT_BUG_ON(addr & E2K_ALIGN_OS_GLOBALS_MASK,
		    "Kernel 'data' segment start address 0x%lx is not aligned to mask 0x%lx\n",
		    addr, E2K_ALIGN_OS_GLOBALS_MASK);
	addr = (e2k_addr_t) boot_vp_to_pp(&_sdata_bss);

	/* Assume that BSS is placed immediately after data */
	size = (unsigned long)(_edata_bss - _sdata_bss);
	size = __ALIGN_MASK(size, E2K_ALIGN_OS_GLOBALS_MASK);

	gd = new_gd(addr, size);

	boot_write_GD_reg(gd);
	boot_write_OSGD_reg(gd);

	boot_printk("Kernel DATA/BSS segment pointers OSGD & GD are set to base physical address 0x%lx size 0x%lx\n",
		addr, size);

#ifdef	CONFIG_SMP
	boot_printk("Kernel boot-time initialization in progress on CPU %d PIC id %d\n",
		    boot_smp_processor_id(), boot_early_pic_read_id());
#endif /* CONFIG_SMP */

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

	addr = (e2k_addr_t) _start;
	BOOT_BUG_ON(addr & E2K_ALIGN_OSCU_MASK,
		    "Kernel 'text' segment start address 0x%lx is not aligned to mask 0x%lx\n",
		    addr, E2K_ALIGN_OSCU_MASK);
	addr = (e2k_addr_t) boot_vp_to_pp(&_start);
	size = (e2k_addr_t) _etext - (e2k_addr_t) _start;
	size = __ALIGN_MASK(size, E2K_ALIGN_OSCU_MASK);
	cud = new_cud(addr, size, 1, cud_m64);

	boot_write_CUD_reg(cud);
	boot_write_OSCUD_reg(cud);

	boot_printk("Kernel TEXT segment pointers OSCUD & CUD are set to base physical address 0x%lx size 0x%lx\n",
		addr, size);

	if (BOOT_IS_BSP(bsp)) {
		boot_check_bootblock(bsp, bootblock);
#ifdef	CONFIG_SMP
		boot_set_event(&bootblock_checked);
	} else {
		boot_wait_for_event(&bootblock_checked);
#endif /* CONFIG_SMP */
	}

	if (addr != boot_info->kernel_base) {
		BOOT_WARNING("Kernel start address 0x%lx is not the same as\n"
			     "base address to load kernel in bootblock structure 0x%lx\n",
			addr, boot_info->kernel_base);
		boot_info->kernel_base = addr;
	}
	BOOT_BUG_ON(size > boot_info->kernel_size,
		    "Kernel size 0x%lx is not the same as size to load kernel in bootblock structure 0x%lx\n",
		    size, boot_info->kernel_size);

	/*
	 * Remember phys. address of boot information block in
	 * an appropriate data structure.
	 */
	if (BOOT_IS_BSP(bsp)) {
		boot_bootblock_phys = bootblock;
		boot_printk("Boot block physical address: 0x%lx\n", bootblock);

		boot_loader_type_banner(boot_info);
		if (DEBUG_BOOT_INFO_MODE) {
			int i;
			for (i = 0; i < sizeof(bootblock_struct_t) / 8; i++) {
				do_boot_printk("boot_info[%d] = 0x%lx\n",
					       i, ((u64 *) boot_info)[i]);
			}
		}
#ifdef	CONFIG_SMP
		boot_setup_smp_cpu_config(boot_info);
		boot_set_event(&boot_info_setup_finished);
	} else {
		boot_wait_for_event(&boot_info_setup_finished);
		if (boot_smp_processor_id() >= NR_CPUS) {
			BOOT_BUG("CPU #%d : this CPU number >=  max supported CPU number %d\n",
			     boot_smp_processor_id(), NR_CPUS);
		}
#endif	/* CONFIG_SMP */
	}
}

/*
 * Sequel of process of initialization. This function is run into virtual
 * space and controls farther system boot
 */
void __init boot_init_sequel(bool bsp, int cpuid, int cpus_to_sync)
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
	 * Terminate boot-time initialization and start kernel init
	 */
	init_terminate_boot_init(bsp, cpuid);

#ifndef	CONFIG_SMP
#undef	cpuid
#endif /* CONFIG_SMP */
}

/*
 * Control process of boot-time initialization.
 * Loader or bootloader program should call this function to start boot
 * process of the system. The function provide for virtual memory support
 * and switching to execution into the virtual space. The following part
 * of initialization should be made by 'boot_init_sequel()' function, which
 * will be run with virtual environment support.
 */
static void __init boot_init(bool bsp, bootblock_struct_t *bootblock)
{
	register int cpuid;

	cpuid = boot_smp_get_processor_id();
	boot_smp_set_processor_id(cpuid);
	boot_printk("boot_init() started on CPU #%d\n", cpuid);

#ifndef CONFIG_SMP
	if (!bsp) {
		boot_atomic_dec(&boot_cpucount);
		while (1)	/* Idle if not boot CPU */
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
			INIT_BUG("Recursive call of boot_init(), perhaps, due to trap\n");
		} else {
			BOOT_BUG("Recursive call of boot_init(), perhaps, due to trap\n");
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
	boot_mem_init(bsp, cpuid, &bootblock->info);
}

void __ref boot_startup(bool bsp, bootblock_struct_t *bootblock)
{
	boot_info_t *boot_info = NULL;
	u16 signature;
#ifdef	CONFIG_RECOVERY
	int recovery = bootblock->boot_flags & RECOVERY_BB_FLAG;
#else /* ! CONFIG_RECOVERY  */
#define		recovery	0
#endif /* CONFIG_RECOVERY */

	/* CPU will stall if we have unfinished memory operations.
	 * This shows bootloader problems if they present */
	__E2K_WAIT_ALL;

	if (bsp)
		EARLY_BOOT_TRACEPOINT("kernel boot-time init started");

	/*
	 * Be careful with initialization order here.
	 *
	 * 1) boot_setup_machine_id() sets the defaults for current
	 * processor (including iset, mmu_separate_pt, etc).
	 *
	 * 2) Command line parameters could specify non-default values,
	 * so boot_parse_param() is called next.
	 *
	 * 3) Now that we know what CPU we are executing on, we can call
	 * boot_setup_iset_features() to initialize cpu_has() subsystem.
	 */
	if (!recovery && bsp) {
		boot_setup_machine_id(bootblock);
		boot_parse_param(bootblock);
		boot_setup_iset_features(&boot_machine);
		boot_common_setup_arch_mmu(&boot_machine, boot_pgtable_struct_p);
	}

	/*
	 * Guest VCPUs can be launched with significant time delays.
	 * It need to wait until they all get together and the main
	 * CPU's/machine's features will be set by bsp.
	 * The latter is also true for the native mode
	 */
#ifdef CONFIG_SMP
	boot_cpu_to_sync_num = bootblock->info.num_of_cpus;
	smp_mb();	/* all cpus should see number od cpus to sync */
	boot_sync_all_processors(); /* For what? See above */
#endif /* CONFIG_SMP */

	/* Propagate features to all CPUs %g */
	if (!bsp) {
		cpuhas_greg0 = boot_cpu_features[0];
		cpuhas_greg1 = boot_cpu_features[1];
	}

	if (boot_cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		convert_cpu_regs_to_v7();
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
		} else
#endif /* CONFIG_SMP */
			boot_hvc_l_cons_init(bootblock->info.serial_base);
	}
#endif /* CONFIG_EARLY_VIRTIO_CONSOLE */

	/* Delay the check until after the console initialization */
	if (boot_cpu_model_mismatch) {
		if (bsp) {
			BOOT_BUG("Kernel is built for a different CPU model\n");
		} else {
			for (;;)
				cpu_relax();
		}
	}

#if defined(DEBUG_BOOT_INFO) && DEBUG_BOOT_INFO
	if (bsp)
		do_boot_printk("bootblock 0x%x, flags 0x%x\n", bootblock, bootblock->boot_flags);
#endif

	/*
	 * BIOS loader has following incompatibilities with kernel
	 * boot process assumption:
	 *      1. Not set USBR register to C stack high address
	 *      2. Set PSP register size to full procedure stack memory
	 *         when this size should be without last page (last page
	 *         used as guard to preserve stack overflow)
	 *      3. Set PCSP register size to full procedure chain stack memory
	 *         when this size should be without last page (last page
	 *         used as guard to preserve stack overflow)
	 */
	boot_info = &bootblock->info;
	signature = boot_info->signature;

	if (signature == BOOTBLOCK_BOOT_SIGNATURE && !recovery) {
		e2k_usd_t usd = boot_read_USD_reg();
		e2k_usbr_t usbr = (e2k_usbr_t) { .base = PAGE_ALIGN(USD_PTR(usd)) };
		e2k_psp_t psp = boot_read_PSP_reg();
		e2k_pcsp_t pcsp = boot_read_PCSP_reg();

		boot_write_USBR_reg(usbr);

		psp = new_psp(PSP_BASE(psp), PSP_SIZE(psp) - PAGE_SIZE, PSP_IND(psp));

		pcsp = new_pcsp(PCSP_BASE(pcsp),
				PCSP_SIZE(pcsp) - PAGE_SIZE, PCSP_IND(pcsp));

		boot_write_hw_stacks(psp, pcsp);
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
			BOOT_BUG("CPU #%d : this CPU number >= max supported CPU number %d\n",
			     boot_smp_processor_id(), NR_CPUS);
		}

		for (;;)
			cpu_relax();
	}
#ifdef	CONFIG_RECOVERY
	if (recovery)
		boot_recovery(bsp, bootblock);
	else
#endif /* CONFIG_RECOVERY */
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

__boot_setup("iset", boot_set_iset);

/*
 * Clear kernel BSS segment in native mode
 */
void __init boot_native_clear_bss(void)
{
	e2k_size_t size;
	unsigned long *bss_p;

	bss_p = (unsigned long *)boot_vp_to_pp(&__bss_start);
	size = (e2k_addr_t) __bss_stop - (e2k_addr_t) __bss_start;
	boot_printk("Kernel BSS segment will be cleared from physical address 0x%lx size 0x%lx\n",
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
		kernel_voffset = KERNEL_BASE - bootblock_virt->info.kernel_base;
#ifdef CONFIG_KASAN
		kasan_early_init();
#endif
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

void boot_cpu_relax(void)
{
	E2K_NOP(7);
}


