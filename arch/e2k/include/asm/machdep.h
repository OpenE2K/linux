/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_MACHDEP_H_
#define _E2K_MACHDEP_H_

#include <linux/init.h>
#include <linux/types.h>

#include <uapi/asm/iset_ver.h>

#ifdef CONFIG_USE_AAU
#include <asm/aau_regs_types.h>
#endif
#include <asm/cpu_features.h>
#include <asm/sections.h>
#include <asm/mmu_types.h>

#ifdef __KERNEL__

struct cpuinfo_e2k;
struct pt_regs;
struct seq_file;
struct e2k_global_regs;
struct kernel_gregs;
struct local_gregs;
#ifdef CONFIG_USE_AAU
struct e2k_aau_context;
#endif
struct e2k_mlt;
struct kvm_vcpu_arch;
struct thread_info;
union e2k_dimtp;

#include <asm/kvm/machdep.h>	/* virtualization support */

typedef void (*restore_gregs_fn_t)(const struct e2k_global_regs *);
typedef void (*save_gregs_fn_t)(struct e2k_global_regs *);
typedef struct machdep {
	int		native_id;		/* machine Id */
	int		native_rev;		/* cpu revision */
	e2k_iset_ver_t	native_iset_ver;	/* Instruction set version */
	bool		cmdline_iset_ver;	/* iset specified in cmdline */
	/* MMU is set to use new page table structures */
	bool		mmu_pt_v6;
	/* MMU is set to use separate PTs for kernel and users */
	bool		mmu_separate_pt;
	bool		L3_enable;		/* cache L3 is enable */
	bool		gmi;			/* is hardware virtualized */
						/* guest VM */
	e2k_addr_t	io_area_base;
	e2k_addr_t	io_area_size;
	u8		max_nr_node_cpus;
	u8		nr_node_cpus;
	u8		node_iolinks;
	e2k_addr_t	pcicfg_area_phys_base;
	e2k_size_t	pcicfg_area_size;
	e2k_addr_t	nsr_area_phys_base;
	u64		tlb_addr_line_num;
	u64		tlb_addr_line_num2;
	u8		tlb_addr_line_num_shift2;
	u8		tlb_addr_set_num;
	u8		tlb_addr_set_num_shift;
	e2k_size_t	sic_mc_size;
	u8		sic_mc_count;
	u32		sic_mc1_ecc;
	u32		sic_io_str1;
	u8		qnr1_offset;

	unsigned long cpu_features[(NR_CPU_FEATURES + 63) / 64];

	e2k_addr_t (*get_nsr_area_phys_base)(void);
	void (*setup_apic_vector_handlers)(void);
#ifdef CONFIG_SMP
	void (*clk_off)(void);
	void (*clk_on)(int);
#endif
	void (*C1_enter)(void);
	void (*C3_enter)(void);

	/* Often used pointers are placed close to each other */

	void (*save_kernel_gregs)(struct kernel_gregs *);
	void (*save_gregs)(struct e2k_global_regs *);
	void (*save_local_gregs)(struct local_gregs *, bool is_signal);
	save_gregs_fn_t save_gregs_dirty_bgr;
	restore_gregs_fn_t restore_gregs;
	void (*save_gregs_on_mask)(struct e2k_global_regs *, bool dirty_bgr,
					unsigned long not_save_gregs_mask);
	void (*restore_local_gregs)(const struct local_gregs *, bool is_signal);
	void (*restore_gregs_on_mask)(struct e2k_global_regs *, bool dirty_bgr,
					unsigned long not_restore_gregs_mask);

	void (*save_dimtp)(union e2k_dimtp *);
	void (*restore_dimtp)(const union e2k_dimtp *);
	void (*clear_dimtp)(void);

	void (*save_kvm_context)(struct kvm_vcpu_arch *);
	void (*restore_kvm_context)(const struct kvm_vcpu_arch *);

#ifdef CONFIG_USE_AAU
	void (*calculate_aau_aaldis_aaldas)(const struct pt_regs *regs,
			e2k_aalda_t *aaldas, struct e2k_aau_context *context);
	void (*do_aau_fault)(int aa_field, struct pt_regs *regs);
	void (*save_aaldi)(u64 *aaldis);
	void (*get_aau_context)(struct e2k_aau_context *, e2k_aasr_t);
#endif

	unsigned long	(*rrd)(int reg);
	void		(*rwd)(int reg, unsigned long value);
	unsigned long	(*boot_rrd)(int reg);
	void		(*boot_rwd)(int reg, unsigned long value);

	u64		(*get_cu_hw1)(void);
	void		(*set_cu_hw1)(u64);

#ifdef CONFIG_MLT_STORAGE
	void		(*invalidate_MLT)(void);
	void		(*get_and_invalidate_MLT_context)(struct e2k_mlt *mlt_state);
#endif

	void		(*setup_arch)(void);
	void		(*setup_cpu_info)(struct cpuinfo_e2k *c);
	int		(*show_cpuinfo)(struct seq_file *m, void *v);
	void		(*init_IRQ)(void);

	int		(*set_wallclock)(unsigned long nowtime);
	unsigned long	(*get_wallclock)(void);

	void		(*restart)(char *cmd);
	void		(*power_off)(void);
	void		(*halt)(void);
	void		(*arch_reset)(char *cmd);
	void		(*arch_halt)(void);

	int		(*get_irq_vector)(void);

	/* virtualization support: guest kernel and host/hypervisor */
	guest_machdep_t	guest;	/* guest additional fields (used only by */
				/* guest at arch/e2k/kvm/guest/xxx) */
} machdep_t;


/*
 * When executing on pure guest kernel, guest_cpu will be set to
 * 'machine.guest.id', i.e. to what hardware guest *thinks* it's
 * being executed on.
 */
typedef void (*cpuhas_initcall_t)(int cpu, int revision, int iset_ver,
		int guest_cpu, bool is_hardware_guest, struct machdep *machine);
extern cpuhas_initcall_t __cpuhas_initcalls[], __cpuhas_initcalls_end[];

/*
 * feature =
 *	if ('is_static')
 *		'static_cond' checked at build time;
 *	else
 *		'dynamic_cond' checked in runtime;
 */
#ifndef BUILD_CPUHAS_INITIALIZERS
# define CPUHAS(feat, is_static, static_cond, dynamic_cond) \
	static const char feat##_is_static = !!(is_static); \
	static const char feat##_is_set_statically = !!(static_cond);

#else /* #ifdef BUILD_CPUHAS_INITIALIZERS */
# include <linux/bitops.h>
# define CPUHAS(feat, _is_static, static_cond, dynamic_cond) \
	__init \
	static void feat##_initializer(const int cpu, const int revision, \
			const int iset_ver, const int guest_cpu, \
			bool is_hardware_guest, struct machdep *const machine) { \
		bool is_static = (_is_static); \
		if (is_static && (static_cond) || !is_static && (dynamic_cond)) \
			set_bit(feat, (machine)->cpu_features); \
	} \
	static cpuhas_initcall_t __cpuhas_initcall_##feat __used \
			__section(".cpuhas_initcall") = &feat##_initializer;
#endif


/* Most of these bugs are not emulated on simulator but
 * set them anyway to make kernel running on a simulator
 * behave in the same way as on real hardware. */

/* #58397, #76626, #148643 - CLW does not work.
 * Workaround - do not use it. */
CPUHAS(CPU_HWBUG_CLW,
		!IS_ENABLED(CONFIG_CPU_E2S) && !IS_ENABLED(CONFIG_CPU_E12C) &&
			!IS_ENABLED(CONFIG_CPU_E16C) && !IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		cpu == IDR_E2S_MDL && revision == 0 ||
			cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0 ||
			cpu == IDR_E2C3_MDL && revision <= 1);
/* #78411 - Sometimes exc_illegal_instr_addr is generated
 * instead of exc_instr_page_miss.
 * Workaround - always return to user from exc_illegal_instr_addr. */
CPUHAS(CPU_HWBUG_SPURIOUS_EXC_ILL_INSTR_ADDR,
		!IS_ENABLED(CONFIG_CPU_E2S),
		false,
		cpu == IDR_E2S_MDL && revision <= 1);
 /* #100984 - e8c: DMA to neighbour node slows down.
  * Workaround - allocate DMA buffers only in the device node. */
CPUHAS(CPU_HWBUG_CANNOT_DO_DMA_IN_NEIGHBOUR_NODE,
		!IS_ENABLED(CONFIG_CPU_E8C),
		false,
		cpu == IDR_E8C_MDL && revision <= 2);
/* #88644 - data profiling events are lost if overflow happens
 * under closed NM interrupts; also DDMCR writing does not clear
 * pending exc_data_debug exceptions.
 * Workaround - disable data monitor profiling in kernel. */
CPUHAS(CPU_HWBUG_KERNEL_DATA_MONITOR,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		IS_ENABLED(CONFIG_CPU_E2S) || IS_ENABLED(CONFIG_CPU_E8C) ||
			IS_ENABLED(CONFIG_CPU_E1CP),
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
			cpu == IDR_E1CP_MDL);
/* #89495 - write barrier does not work (even for atomics).
 * Workaround - special command sequence after every read-acquire. */
CPUHAS(CPU_HWBUG_WRITE_MEMORY_BARRIER,
		!IS_ENABLED(CONFIG_CPU_E8C),
		false,
		cpu == IDR_E8C_MDL && revision <= 1);
/* #89653 - some hw counter won't reset, which may cause corruption of DMA.
 * Workaround - reset machine until the counter sets in good value */
CPUHAS(CPU_HWBUG_BAD_RESET,
		!IS_ENABLED(CONFIG_CPU_E8C),
		false,
		cpu == IDR_E8C_MDL && revision <= 1);
/* #90514 - hardware hangs after modifying code with a breakpoint.
 * Workaround - use HS.lng from the instruction being replaced. */
CPUHAS(CPU_HWBUG_BREAKPOINT_INSTR,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		IS_ENABLED(CONFIG_CPU_E2S) || IS_ENABLED(CONFIG_CPU_E8C) ||
			IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
			cpu == IDR_E8C2_MDL);
/* #92834, #96516 - hang because of hardware problems.
 * Workaround - boot activates watchdog, kernel should disable it */
CPUHAS(CPU_HWBUG_E8C_WATCHDOG,
		!IS_ENABLED(CONFIG_CPU_E8C),
		false,
		cpu == IDR_E8C_MDL && revision <= 1);
/* #94466 */
CPUHAS(CPU_HWBUG_IOMMU,
		!IS_ENABLED(CONFIG_CPU_E2S),
		false,
		cpu == IDR_E2S_MDL && revision <= 2);
/* #95860 - WC memory conflicts with DAM.
 * Workaround - "wait st_c" between WC writes and cacheable loads */
CPUHAS(CPU_HWBUG_WC_DAM,
		!IS_ENABLED(CONFIG_CPU_E2S) && !IS_ENABLED(CONFIG_CPU_E8C) &&
		!IS_ENABLED(CONFIG_CPU_E8C2),
		false,
		cpu == IDR_E2S_MDL && revision <= 2 ||
		cpu == IDR_E8C_MDL && revision <= 1 ||
		cpu == IDR_E8C2_MDL && revision == 0);
/* 96719 - combination of flags s_f=0, store=1, sru=1 is possible
 * Workaround - treat it as s_f=1, store=1, sru=1 */
CPUHAS(CPU_HWBUG_TRAP_CELLAR_S_F,
		IS_ENABLED(CONFIG_E2K_MACHINE) && !IS_ENABLED(CONFIG_CPU_E8C2),
		IS_ENABLED(CONFIG_CPU_E2S) || IS_ENABLED(CONFIG_CPU_E8C) ||
			IS_ENABLED(CONFIG_CPU_E1CP),
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
			cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL && revision == 0);
/* #97594 - %cr1_lo.ss flag is lost if ext. interrupt arrives faster.
 * Workaround - manually set %cr1_lo.ss again in interrupt handler */
CPUHAS(CPU_HWBUG_SS,
		!IS_ENABLED(CONFIG_CPU_E2S) && !IS_ENABLED(CONFIG_CPU_E8C) &&
		!IS_ENABLED(CONFIG_CPU_E1CP) && !IS_ENABLED(CONFIG_CPU_E8C2),
		false,
		cpu == IDR_E2S_MDL && revision <= 2 ||
		cpu == IDR_E8C_MDL && revision <= 2 ||
		cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL && revision == 0);
/* #99302 - %aaldv sometimes is not restored properly.
 * Workaround - insert 'wait ma_c' barrier */
CPUHAS(CPU_HWBUG_AAU_AALDV,
		IS_ENABLED(CONFIG_E2K_MACHINE) && !IS_ENABLED(CONFIG_CPU_E8C2),
		IS_ENABLED(CONFIG_CPU_E2S) || IS_ENABLED(CONFIG_CPU_E8C) ||
			IS_ENABLED(CONFIG_CPU_E1CP),
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
			cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL && revision == 0);
/* #103223 - LAPIC does not send EoI to IO_APIC for level interrupts.
 * Workaround - wait under closed interrupts until APIC_ISR clears */
CPUHAS(CPU_HWBUG_LEVEL_EOI,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		IS_ENABLED(CONFIG_CPU_E2S) || IS_ENABLED(CONFIG_CPU_E8C) ||
			IS_ENABLED(CONFIG_CPU_E1CP) || IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
			cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL);
/* #104865 - hardware might generate a false single step interrupt
 * Workaround - clean frame 0 of PCS during the allocation */
CPUHAS(CPU_HWBUG_FALSE_SS,
		IS_ENABLED(CONFIG_E2K_MACHINE) && !IS_ENABLED(CONFIG_CPU_E2S) &&
			!IS_ENABLED(CONFIG_CPU_E8C),
		IS_ENABLED(CONFIG_CPU_E1CP) || IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E2S_MDL && revision <= 2 ||
			cpu == IDR_E8C_MDL && revision <= 2 ||
			cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL);
/* #117649 - false exc_data_debug are generated based on _previous_
 * values in ld/st address registers.
 * Workaround - forbid data breakpoint on the first 31 bytes
 * (hardware prefetch works with 32 bytes blocks). */
CPUHAS(CPU_HWBUG_SPURIOUS_EXC_DATA_DEBUG,
		IS_ENABLED(CONFIG_E2K_MACHINE) && !IS_ENABLED(CONFIG_CPU_E12C) &&
			!IS_ENABLED(CONFIG_CPU_E16C) && !IS_ENABLED(CONFIG_CPU_E2C3),
		IS_ENABLED(CONFIG_CPU_E2S) || IS_ENABLED(CONFIG_CPU_E8C) ||
			IS_ENABLED(CONFIG_CPU_E1CP) || IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
			cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL ||
			cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0 ||
			cpu == IDR_E2C3_MDL && revision == 0);
/* #119084 - several TBL flushes in a row might fail to flush L1D.
 * Workaround - insert "wait fl_c" immediately after every TLB flush */
CPUHAS(CPU_HWBUG_TLB_FLUSH_L1D,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E8C2_MDL);
/* #121311 - asynchronous entries in INTC_INFO_MU always have "pm" bit set.
 * Workaround - use "pm" bit saved in guest's chain stack. */
CPUHAS(CPU_HWBUG_GUEST_ASYNC_PM,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0 ||
			cpu == IDR_E2C3_MDL && revision == 0);
/* #122946 - conflict new interrupt while sync signal turning off.
 * Workaround - waiting for C0 after "wait int=1" */
CPUHAS(CPU_HWBUG_C3_SYNC,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C),
		false,
		cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0);
/* #123567 - a load after an intersecting store can read wrong date from L1.
 * Workaround - insert at least 1 real wide instruction between
 * (i.e. not from `nop X`, X > 0). */
CPUHAS(CPU_HWBUG_INTERSECTING_L1_ACCESSES,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		IS_ENABLED(CONFIG_CPU_E8C2) || IS_ENABLED(CONFIG_CPU_E12C) ||
			IS_ENABLED(CONFIG_CPU_E16C),
		cpu == IDR_E8C2_MDL || cpu == IDR_E12C_MDL || cpu == IDR_E16C_MDL);
/* #124206 - instruction buffer stops working
 * Workaround - prepare %ctpr's in glaunch/trap handler entry;
 * avoid rbranch in glaunch/trap handler entry and exit. */
CPUHAS(CPU_HWBUG_L1I_STOPS_WORKING,
		IS_ENABLED(CONFIG_E2K_MACHINE) && !IS_ENABLED(CONFIG_CPU_E12C) &&
			!IS_ENABLED(CONFIG_CPU_E16C) && !IS_ENABLED(CONFIG_CPU_E2C3),
		IS_ENABLED(CONFIG_CPU_E2S) || IS_ENABLED(CONFIG_CPU_E8C) ||
			IS_ENABLED(CONFIG_CPU_E1CP) || IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
			cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL ||
			cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0 ||
			cpu == IDR_E2C3_MDL && revision == 0);
/* #124947 - CLW clearing by OS must be done on the same CPU that started the
 * hardware clearing operation to avoid creating a stale L1 entry.
 * Workaround - forbid migration until CLW clearing is finished in software. */
CPUHAS(CPU_HWBUG_CLW_STALE_L1_ENTRY,
		IS_ENABLED(CONFIG_E2K_MACHINE) && !IS_ENABLED(CONFIG_CPU_E12C) &&
			!IS_ENABLED(CONFIG_CPU_E16C),
		IS_ENABLED(CONFIG_CPU_E2S) || IS_ENABLED(CONFIG_CPU_E8C) ||
			IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL || cpu == IDR_E8C2_MDL ||
			cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0);
/* #124951 - enabling RAM Self Refresh when refresh is in progress won't work.
 * Workaround - set MC_PERF0.arp_en=0 when enabling Self Refresh. */
CPUHAS(CPU_HWBUG_RAM_SELF_REFRESH,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0 ||
			cpu == IDR_E2C3_MDL && revision == 0);
/* #125405 - CPU pipeline freeze feature conflicts with performance monitoring.
 * Workaround - disable pipeline freeze when monitoring is enabled.
 *
 * Note (#132311): disable workaround on e16c.rev0/e2c3.rev0/e12c.rev0 since it
 * conflicts with #134929 workaround. */
CPUHAS(CPU_HWBUG_PIPELINE_FREEZE_MONITORS,
		IS_ENABLED(CONFIG_E2K_MACHINE) && !IS_ENABLED(CONFIG_CPU_E12C) &&
			!IS_ENABLED(CONFIG_CPU_E16C) && !IS_ENABLED(CONFIG_CPU_E2C3),
		IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E8C2_MDL ||
			cpu == IDR_E12C_MDL && revision > 0 ||
			cpu == IDR_E16C_MDL && revision > 0 ||
			cpu == IDR_E2C3_MDL && revision > 0);
/* #126587 - "wait ma_c=1" does not wait for all L2$ writebacks to complete
 * when disabling CPU core with "wait trap=1" algorithm.
 * Workaround - manually insert 66 NOPs before "wait trap=1" */
CPUHAS(CPU_HWBUG_C3_WAIT_MA_C,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		IS_ENABLED(CONFIG_CPU_E2S) || IS_ENABLED(CONFIG_CPU_E8C) ||
			IS_ENABLED(CONFIG_CPU_E1CP),
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL || cpu == IDR_E1CP_MDL);
/* #128127 - Intercepting SCLKM3 write does not prevent guest from writing it.
 * Workaround - Update SH_SCLKM3 in intercept handler */
CPUHAS(CPU_HWBUG_VIRT_SCLKM3_INTC,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0 ||
			cpu == IDR_E2C3_MDL && revision == 0);
/* #128350 - glaunch increases guest's pusd.psl by 1 on phase 1
 * Workaround - decrease guest's pusd.psl by 1 before glaunch */
CPUHAS(CPU_HWBUG_VIRT_PUSD_PSL,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0 ||
			cpu == IDR_E2C3_MDL && revision == 0);
/* #129848 - alignment of usd_hi write depends on current usd_lo.p
 * Workaround - write usd_lo before usd_hi, while keeping 2 tact distance from sbr write.
 * Valid sequences are: sbr, nop, usd.lo, usd.hi OR sbr, usd.lo, usd.hi, usd.lo */
CPUHAS(CPU_HWBUG_USD_ALIGNMENT,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		IS_ENABLED(CONFIG_CPU_E2S) || IS_ENABLED(CONFIG_CPU_E8C) ||
			IS_ENABLED(CONFIG_CPU_E1CP) || IS_ENABLED(CONFIG_CPU_E8C2) ||
			IS_ENABLED(CONFIG_CPU_E16C) || IS_ENABLED(CONFIG_CPU_E2C3) ||
			IS_ENABLED(CONFIG_CPU_E12C),
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
			cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL ||
			cpu == IDR_E16C_MDL || cpu == IDR_E2C3_MDL ||
			cpu == IDR_E12C_MDL);
/* #129870 (#131465) - prefetches into %empty register do not work.
 * Workaround - add "L1 cache disable" MAS to prefetch into L2 instead. */
CPUHAS(CPU_HWBUG_PREFETCH_EMPTY,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0 ||
			cpu == IDR_E2C3_MDL && revision == 0);
/* #130039 - intercepting some specific sequences of call/return/setwd
 * (that change WD.psize in a specific way) does not work.
 * Workaround - avoid those sequences. */
CPUHAS(CPU_HWBUG_VIRT_PSIZE_INTERCEPTION,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0 ||
			cpu == IDR_E2C3_MDL && revision == 0);
/* #130066, #134351 - L1/L2 do not respect "lal"/"las"/"sas"/"st_rel" barriers.
 * Workaround - do not use "las"/"sas"/"st_rel", and add 5 nops after "lal".
 * #133605 - "lal"/"las"/"sas"/"sal" barriers do not work in certain conditions.
 * Workaround - add {nop} before them.
 *
 * Note that #133605 workaround is split into two parts:
 * CPU_NO_HWBUG_SOFT_WAIT - for e16c/e2c3
 * CPU_HWBUG_SOFT_WAIT_E8C2 - for e8c2
 * This is done because it is very convenient to merge #130066, #134351
 * and #133605 bugs workarounds together for e16c/e2c3. */
CPUHAS(CPU_NO_HWBUG_SOFT_WAIT,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3),
		true,
		!(cpu == IDR_E12C_MDL && revision == 0 ||
		  cpu == IDR_E16C_MDL && revision == 0 ||
		  cpu == IDR_E2C3_MDL && revision == 0));
CPUHAS(CPU_HWBUG_SOFT_WAIT_E8C2,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E8C2_MDL);
/* #130433, #132693, #149522 - C3 idle state does not work.
 * Workaround - do not use it. */
CPUHAS(CPU_HWBUG_C3,
		IS_ENABLED(CONFIG_E2K_MACHINE) && !IS_ENABLED(CONFIG_CPU_E12C) &&
			!IS_ENABLED(CONFIG_CPU_E16C),
		IS_ENABLED(CONFIG_CPU_E8C) || IS_ENABLED(CONFIG_CPU_E1CP) ||
			IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E8C_MDL || cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL ||
			cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0);
/* #130291 - HRET does not clean INTC_INFO_CU/INTC_PTR_CU.
 * Workaround - clean it before each HRET */
CPUHAS(CPU_HWBUG_HRET_INTC_CU,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		IS_ENABLED(CONFIG_CPU_E2C3) || IS_ENABLED(CONFIG_CPU_E12C) ||
			IS_ENABLED(CONFIG_CPU_E16C),
		cpu == IDR_E2C3_MDL || cpu == IDR_E12C_MDL ||
			cpu == IDR_E16C_MDL);
/* #136011 - Imagination GPU does not support disabling PCIe No Snoop capability.
 * Workaround - always assume that the GPU might issue No Snoop accesses. */
CPUHAS(CPU_HWBUG_IMGGPU_NOSNOOP_ALWAYS_ON,
		!IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		cpu == IDR_E2C3_MDL && revision == 0);
/* #137438 - synchronization problems with credits in L3$
 * when disabling CPU core with "wait trap=1" algorithm.
 * Workaround - issue special NBSR writes */
CPUHAS(CPU_HWBUG_C3_CREDITS_L3,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		IS_ENABLED(CONFIG_CPU_E8C) || IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E8C_MDL || cpu == IDR_E8C2_MDL);
/* #137536 - intercept (or interrupt), after writing CR, while hardware is
 * waiting for fill CF may corrupt all other CRs
 * Workaround - add wait ma_c=1 to the same instruction, as CR write
 * This workaround covers most possible cases, but not all of them */
CPUHAS(CPU_HWBUG_INTC_CR_WRITE,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		(cpu == IDR_E12C_MDL && revision == 0 ||
		 cpu == IDR_E16C_MDL && revision == 0 ||
		 cpu == IDR_E2C3_MDL && revision == 0) &&
			is_hardware_guest);
/* #142262 - tagged 'ldw' instruction does not work
 * Workaround - insert 4 bubbles between tagged 'ldw' and potentially
 * aliasing previous 'stw'. */
CPUHAS(CPU_HWBUG_TAGGED_LDW,
		!IS_ENABLED(CONFIG_CPU_E16C) && !IS_ENABLED(CONFIG_CPU_E12C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		cpu == IDR_E16C_MDL && revision <= 1 ||
			cpu == IDR_E2C3_MDL && revision <= 1 ||
			cpu == IDR_E12C_MDL && revision == 0);
/* e8c2 implementation of flush_tlb_page does not wait for the finish
 * of L1D flushing when flushing 1GB page.
 * Workaround - add another "flush_tlb_page + wait fl_c" pair on any
 * address, or use "flush_tlb_all". */
CPUHAS(CPU_HWBUG_GIGANTIC_FLUSH,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E8C2_MDL);
/* #124144 (#142159) - TLU search for IB may return incorrect address,
 * if it runs concurrently with glaunch/hret.
 * Workaround - full tlb/ib flush before each glaunch/hret */
CPUHAS(CPU_HWBUG_VIRT_TLU_IB,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C),
		false,
		cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0);
/* #136177 - no DMA through the links B and C.
 * Workaround - do DMA through bounce buffer  */
CPUHAS(CPU_HWBUG_CANNOT_DO_DMA_THROUGH_LINKS_B_AND_C,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C),
		false,
		cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0);
/* 140436 (143456, 152233) - jump (of any kind) to some IPs is not supported
 * Workaround - mark non-jump-target labels as such so that GAS can work its magic.
 * This one requires preprocessor-time fixing so grep for CPU_HWBUG_JUMP */
/* #143157, #141618 - user exc_instr_debug and exc_data_debug could occure in kernel */
CPUHAS(CPU_HWBUG_EXC_DEBUG,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		CONFIG_CPU_ISET_MIN <= 6,
		iset_ver <= E2K_ISET_V6);
/* #144224 - sclkm1.div is 1 MHz less sametimes
 * Workaround - use previous correct frequency */
CPUHAS(CPU_HWBUG_SCLKM1_DIV,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		IS_ENABLED(CONFIG_CPU_E8C2) || IS_ENABLED(CONFIG_CPU_E2C3),
		cpu == IDR_E8C2_MDL);
/* #143614 - Secondary bus reset is broken on some PCIe bridges
 * Workaround - do not use it */
CPUHAS(CPU_HWBUG_SECONDARY_BUS_RESET,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0 ||
			cpu == IDR_E2C3_MDL && revision == 0);
/* #144323 - ib may raise (a)instr_page_miss guest exception, instead of the expected
 * intercept, if async AAU code is in the same page, as the normal missing code
 * Workaround - cause an intercept by adding an extra code read after handling page miss */
CPUHAS(CPU_HWBUG_INTC_INSTR_PAGE_MISS,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		(cpu == IDR_E12C_MDL && revision == 0 ||
		 cpu == IDR_E16C_MDL && revision <= 1 ||
		 cpu == IDR_E2C3_MDL && revision <= 2) &&
			is_hardware_guest);
/* #146897, #140436, #77417 - complex bug with jumps to the end of 4Kb page and with
 * placement of asynchronious programm code
 * Workaround - for BPF JIT, it is enough to move all destination labels and function calls
 * outside two regions: [0xdc0..0xdf8] and [0xee0 - 0xff8]
 * For full workaround see bug #146897 comment 58 */
CPUHAS(CPU_HWBUG_CODE_PLACEMENT,
		IS_ENABLED(CONFIG_E2K_MACHINE) && !IS_ENABLED(CONFIG_CPU_E2C3),
		IS_ENABLED(CONFIG_CPU_E2S) || IS_ENABLED(CONFIG_CPU_E8C) ||
			IS_ENABLED(CONFIG_CPU_E1CP) || IS_ENABLED(CONFIG_CPU_E8C2) ||
			IS_ENABLED(CONFIG_E12C) || IS_ENABLED(CONFIG_CPU_E16C),
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
			cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL ||
			cpu == IDR_E12C_MDL || cpu == IDR_E16C_MDL ||
			cpu == IDR_E2C3_MDL && revision <= 1);
/* #146903 - glaunch zeroes guest's CLW mask due to incorrectly restored us_cl_low
 * Workaround - trigger correct hardware restore of us_cl_low on v6
 * by writing us_cl_up value to us_cl_b, and immediately restoring usd_lo */
CPUHAS(CPU_HWBUG_CLW_LOW_RESTORE,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		IS_ENABLED(CONFIG_CPU_E2C3) || IS_ENABLED(CONFIG_CPU_E12C) ||
			IS_ENABLED(CONFIG_CPU_E16C),
		cpu == IDR_E2C3_MDL || cpu == IDR_E12C_MDL ||
			cpu == IDR_E16C_MDL);

/*
 * Not bugs but features go here
 */

/* Support for WC mapping of legacy VGA area at 0xa0000 phys. address. */
CPUHAS(CPU_FEAT_WC_LEGACY_VGA,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		false /* bug 141028 !IS_ENABLED(CONFIG_CPU_E1CP) */,
		false /* bug 141028 cpu != IDR_E1CP_MDL */);
/* Rely on IDR instead of iset version to choose between APIC and EPIC.
 * For guest we use it's own fake IDR so that we choose between APIC and
 * EPIC based on what hardware guest *thinks* it's being executed on. */
CPUHAS(CPU_FEAT_EPIC,
		IS_ENABLED(CONFIG_E2K_MACHINE) &&
		!IS_ENABLED(CONFIG_KVM_GUEST_KERNEL),
		!IS_ENABLED(CONFIG_CPU_E2S) && !IS_ENABLED(CONFIG_CPU_E8C) &&
		!IS_ENABLED(CONFIG_CPU_E1CP) && !IS_ENABLED(CONFIG_CPU_E8C2),
		guest_cpu != IDR_E2S_MDL && guest_cpu != IDR_E8C_MDL &&
		guest_cpu != IDR_E1CP_MDL && guest_cpu != IDR_E8C2_MDL &&
		guest_cpu != IDR_E2K_VIRT_MDL);
/* Shows which user registers must be saved upon trap entry/exit */
CPUHAS(CPU_FEAT_TRAP_V5,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		CONFIG_CPU_ISET_MIN == 5,
		iset_ver == E2K_ISET_V5);
CPUHAS(CPU_FEAT_TRAP_V6,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 6,
		CONFIG_CPU_ISET_MIN >= 6,
		iset_ver >= E2K_ISET_V6);
/* QP registers: only since iset V5 */
CPUHAS(CPU_FEAT_QPREG,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 5,
		CONFIG_CPU_ISET_MIN >= 5,
		iset_ver >= E2K_ISET_V5);
/* Hardware prefetcher that resides in L2 and works on phys. addresses */
CPUHAS(CPU_FEAT_HW_PREFETCHER_L2,
		IS_ENABLED(CONFIG_E2K_MACHINE) && !IS_ENABLED(CONFIG_CPU_E12C),
		!IS_ENABLED(CONFIG_CPU_E2S) && !IS_ENABLED(CONFIG_CPU_E8C) &&
			!IS_ENABLED(CONFIG_CPU_E1CP) && !IS_ENABLED(CONFIG_CPU_E8C2) &&
			!IS_ENABLED(CONFIG_CPU_E16C) && !IS_ENABLED(CONFIG_CPU_E2C3),
		!(cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL || cpu == IDR_E1CP_MDL ||
		  cpu == IDR_E8C2_MDL || cpu == IDR_E16C_MDL || cpu == IDR_E2C3_MDL ||
		  cpu == IDR_E12C_MDL && revision == 0));
/* When flushing high order page table entries we must also flush
 * all links below it.  E.g. when flushing PMD also flush PMD->PTE
 * link (i.e. DTLB entry for address 0xff8000000000|(address >> 9)).
 *
 * Otherwise the following can happen:
 * 1) High-order page is allocated.
 * 2) Someone accesses the PMD->PTE link (e.g. half-spec. load) and
 *    creates invalid entry in DTLB.
 * 3) High-order page is split into 4 Kb pages.
 * 4) Someone accesses the PMD->PTE link address (e.g. DTLB entry
 *    probe) and reads the invalid entry created earlier.
 *
 * Since v6 we have separate TLBs for intermediate page table levels
 * (TLU_CACHE.PWC) and for last level and invalid records (TLB).
 * So the invalid entry created in 2) would go into TLB while access
 * in 4) will search TLU_CACHE.PWC rendering this flush unneeded. */
CPUHAS(CPU_FEAT_SEPARATE_TLU_CACHE,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 6,
		CONFIG_CPU_ISET_MIN >= 6,
		iset_ver >= E2K_ISET_V6);
/* Set if FILLR instruction is supported.
 *
 * #135233 - FILLR does not work in hardware guests.
 * Workaround - do not use it in hardware guests. */
CPUHAS(CPU_FEAT_FILLR,
		!IS_ENABLED(CONFIG_CPU_E16C) && !IS_ENABLED(CONFIG_CPU_E12C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3),
		CONFIG_CPU_ISET_MIN >= 6,
		iset_ver >= E2K_ISET_V6 &&
			!((cpu == IDR_E16C_MDL || cpu == IDR_E12C_MDL ||
			   cpu == IDR_E2C3_MDL) && is_hardware_guest));
/* Set if FILLC instruction is supported.
 *
 * #135233 - software emulation of FILLC does not work in hardware guests.
 * Workaround - use FILLC in hardware guests. */
CPUHAS(CPU_FEAT_FILLC,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 6,
		CONFIG_CPU_ISET_MIN >= 6,
		iset_ver >= E2K_ISET_V6);
/* Separate user and kernel virtual spaces: only since iset V6 */
CPUHAS(CPU_FEAT_SEP_VIRT_SPACE,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 6,
		IS_ENABLED(CONFIG_MMU_SEP_VIRT_SPACE),
		machine->mmu_separate_pt);
/* Page table format from iset v6 */
CPUHAS(CPU_FEAT_PAGE_TABLE_V6,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 6,
		IS_ENABLED(CONFIG_MMU_PT_V6),
		machine->mmu_pt_v6);
/* Optimized version of machine.iset check */
CPUHAS(CPU_FEAT_ISET_V5,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 5,
		CONFIG_CPU_ISET_MIN >= 5,
		iset_ver >= E2K_ISET_V5);
CPUHAS(CPU_FEAT_ISET_V6,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 6,
		CONFIG_CPU_ISET_MIN >= 6,
		iset_ver >= E2K_ISET_V6);
CPUHAS(CPU_FEAT_ISET_V7,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 7,
		CONFIG_CPU_ISET_MIN >= 7,
		iset_ver >= E2K_ISET_V7);
/* CPU_FEAT_ISET_NOT_V7 == !CPU_FEAT_ISET_V7 == "Is this <v7 cpu?" */
CPUHAS(CPU_FEAT_ISET_NOT_V7,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 7,
		CONFIG_CPU_ISET_MIN < 7,
		iset_ver < E2K_ISET_V7);
CPUHAS(CPU_FEAT_GLOBAL_IRQ_MASK,
		true,
		IS_ENABLED(CONFIG_GLOBAL_IRQ_MASK) ||
			IS_ENABLED(CONFIG_KVM_GUEST_KERNEL),
		false);


static inline unsigned long test_feature_dynamic(struct machdep *machine, int feature)
{
	unsigned long *addr = machine->cpu_features;

	return 1UL & (addr[feature / 64] >> (feature & 63));
}

#define test_feature(machine, feature) \
	((feature##_is_static) ? \
		(feature##_is_set_statically) : \
		test_feature_dynamic(machine, feature))

#define	boot_machine_has(machine_p, feature)	\
		test_feature(machine_p, feature)
#define boot_cpu_has(feature)	boot_machine_has(&boot_machine, feature)

#ifdef CONFIG_BOOT_E2K
# define cpu_has(feature)	test_feature(&machine, feature)
#elif defined(E2K_P2V)
# define cpu_has(feature)	boot_cpu_has(feature)
#else
# define cpu_has(feature)	test_feature(&machine, feature)
#endif

/* Normally cpu_has() is passed symbolic name of feature (e.g. CPU_FEAT_*),
 * use this one instead if only numeric value of feature is known. */
#define cpu_has_by_value(feature) test_feature_dynamic(&machine, feature)

extern void cpu_set_feature(struct machdep *machine, int feature);
extern void cpu_clear_feature(struct machdep *machine, int feature);


extern machdep_t	machine;
extern pt_struct_t	pgtable_struct;

#if defined E2K_P2V && !defined CONFIG_BOOT_E2K
# define boot_machine		(boot_get_vo_value(machine))
# define boot_pgtable_struct	((pt_struct_t)boot_get_vo_value(pgtable_struct))
# define boot_pgtable_struct_p	boot_vp_to_pp(&pgtable_struct)
#else
# define boot_machine		machine
# define boot_pgtable_struct	pgtable_struct
# define boot_pgtable_struct_p	(&pgtable_struct)
#endif

/* Returns true in guest running with hardware virtualization support */
#if CONFIG_CPU_ISET_MIN >= 3 && !defined E2K_P2V
# define IS_HV_GM()	(cpu_has(CPU_FEAT_ISET_V6) && READ_CORE_MODE_REG().gmi)
#else
# define IS_HV_GM()	(machine.gmi)
#endif

#define	IS_IRQ_MASK_GLOBAL()	cpu_has(CPU_FEAT_GLOBAL_IRQ_MASK)

extern void save_kernel_gregs_v3(struct kernel_gregs *);
extern void save_kernel_gregs_v5(struct kernel_gregs *);
extern void save_gregs_v3(struct e2k_global_regs *);
extern void save_gregs_v5(struct e2k_global_regs *);
extern void save_local_gregs_v3(struct local_gregs *, bool is_signal);
extern void save_local_gregs_v5(struct local_gregs *, bool is_signal);
extern void save_gregs_dirty_bgr_v3(struct e2k_global_regs *);
extern void save_gregs_dirty_bgr_v5(struct e2k_global_regs *);
extern void save_gregs_on_mask_v3(struct e2k_global_regs *, bool dirty_bgr,
					unsigned long mask_not_save);
extern void save_gregs_on_mask_v5(struct e2k_global_regs *, bool dirty_bgr,
					unsigned long mask_not_save);
extern void restore_gregs_v3(const struct e2k_global_regs *);
extern void restore_gregs_v5(const struct e2k_global_regs *);
extern void restore_local_gregs_v3(const struct local_gregs *, bool is_signal);
extern void restore_local_gregs_v5(const struct local_gregs *, bool is_signal);
extern void restore_gregs_on_mask_v3(struct e2k_global_regs *, bool dirty_bgr,
					unsigned long mask_not_restore);
extern void restore_gregs_on_mask_v5(struct e2k_global_regs *, bool dirty_bgr,
					unsigned long mask_not_restore);
extern void save_dimtp_v6(union e2k_dimtp *);
extern void restore_dimtp_v6(const union e2k_dimtp *);
extern void clear_dimtp_v6(void);
extern void save_kvm_context_v6(struct kvm_vcpu_arch *);
extern void restore_kvm_context_v6(const struct kvm_vcpu_arch *);
extern void qpswitchd_sm(int);

#ifdef CONFIG_USE_AAU
extern void calculate_aau_aaldis_aaldas_v3(const struct pt_regs *regs,
		e2k_aalda_t *aaldas, struct e2k_aau_context *context);
extern void calculate_aau_aaldis_aaldas_v5(const struct pt_regs *regs,
		e2k_aalda_t *aaldas, struct e2k_aau_context *context);
extern void calculate_aau_aaldis_aaldas_v6(const struct pt_regs *regs,
		e2k_aalda_t *aaldas, struct e2k_aau_context *context);
extern void do_aau_fault_v3(int aa_field, struct pt_regs *regs);
extern void do_aau_fault_v5(int aa_field, struct pt_regs *regs);
extern void do_aau_fault_v6(int aa_field, struct pt_regs *regs);
extern void save_aaldi_v3(u64 *aaldis);
extern void save_aaldi_v5(u64 *aaldis);
extern void get_aau_context_v3(struct e2k_aau_context *, e2k_aasr_t);
extern void get_aau_context_v5(struct e2k_aau_context *, e2k_aasr_t);
#endif

extern unsigned long boot_native_read_IDR_reg_value(void);

unsigned long rrd_v3(int);
unsigned long rrd_v3(int);
unsigned long rrd_v6(int);
void rwd_v3(int reg, unsigned long value);
void rwd_v6(int reg, unsigned long value);
unsigned long boot_rrd_v3(int);
unsigned long boot_rrd_v6(int);
void boot_rwd_v3(int reg, unsigned long value);
void boot_rwd_v6(int reg, unsigned long value);

/* Supported registers for machine->rrd()/rwd() */
enum {
	E2K_REG_HCEM,
	E2K_REG_HCEB,
	E2K_REG_OSCUTD,
	E2K_REG_OSCUIR,
};

u64 native_get_cu_hw1_v3(void);
u64 native_get_cu_hw1_v5(void);
void native_set_cu_hw1_v3(u64);
void native_set_cu_hw1_v5(u64);

void invalidate_MLT_v3(void);
void get_and_invalidate_MLT_context_v3(struct e2k_mlt *mlt_state);
void get_and_invalidate_MLT_context_v6(struct e2k_mlt *mlt_state);

#ifdef CONFIG_SMP
void native_clock_off_v3(void);
void native_clock_on_v3(int cpu);
#endif

void C1_enter_v3(void);
void C1_enter_v6(void);
void C3_enter_v3(void);
void C3_enter_v6(void);
#endif /* __KERNEL__ */

#endif /* _E2K_MACHDEP_H_ */
