#ifndef _E2K_MACHDEP_H_
#define _E2K_MACHDEP_H_

#include <linux/init.h>
#include <linux/types.h>

#include <uapi/asm/iset_ver.h>

#include <asm/sections.h>
#include <asm/aau_regs_types.h>
#include <asm/mmu_types.h>
#include <asm/mlt.h>

#ifdef __KERNEL__

enum {
	CPU_HWBUG_LARGE_PAGES,
	CPU_HWBUG_LAPIC_TIMER,
	CPU_HWBUG_PIO_READS,
	CPU_HWBUG_ATOMIC,
	CPU_HWBUG_CLW,
	CPU_HWBUG_PAGE_A,
	CPU_HWBUG_SPURIOUS_EXC_ILL_INSTR_ADDR,
	CPU_HWBUG_UNALIGNED_LOADS,
	CPU_HWBUG_CANNOT_DO_DMA_IN_NEIGHBOUR_NODE,
	CPU_HWBUG_DMA_AT_APIC_ADDR,
	CPU_HWBUG_KERNEL_DATA_MONITOR,
	CPU_HWBUG_WRITE_MEMORY_BARRIER,
	CPU_HWBUG_BAD_RESET,
	CPU_HWBUG_BREAKPOINT_INSTR,
	CPU_HWBUG_E8C_WATCHDOG,
	CPU_HWBUG_IOMMU,
	CPU_HWBUG_WC_DAM,
	CPU_HWBUG_TRAP_CELLAR_S_F,
	CPU_HWBUG_SS,
	CPU_HWBUG_AAU_AALDV,
	CPU_HWBUG_LEVEL_EOI,
	CPU_HWBUG_FALSE_SS,
	CPU_HWBUG_SPURIOUS_EXC_DATA_DEBUG,
	CPU_HWBUG_TLB_FLUSH_L1D,
	CPU_HWBUG_GUEST_ASYNC_PM,
	CPU_HWBUG_L1I_STOPS_WORKING,
	CPU_HWBUG_CLW_STALE_L1_ENTRY,
	CPU_HWBUG_C3_WAIT_MA_C,
	CPU_HWBUG_VIRT_SCLKM3_INTC,
	CPU_FEAT_WC_PCI_PREFETCH,
	CPU_FEAT_FLUSH_DC_IC,
	CPU_FEAT_EPIC,
	CPU_FEAT_TRAP_V5,
	CPU_FEAT_TRAP_V6,
	CPU_FEAT_QPREG,
	CPU_FEAT_ISET_V3,
	CPU_FEAT_ISET_V5,
	CPU_FEAT_ISET_V6,
	CPU_HWBUG_E16C_SLEEP,
	NR_CPU_FEATURES
};

struct cpuinfo_e2k;
struct pt_regs;
struct seq_file;
struct global_regs;
struct kernel_gregs;
struct local_gregs;
struct e2k_aau_context;
struct kvm_vcpu_arch;
struct e2k_dimtp;
struct thread_info;

#include <asm/kvm/machdep.h>	/* virtualization support */

typedef struct machdep {
	int		native_id;		/* machine Id */
	int		native_rev;		/* cpu revision */
	e2k_iset_ver_t	native_iset_ver;	/* Instruction set version */
	bool		cmdline_iset_ver;	/* iset specified in cmdline */
	bool		mmu_pt_v6;		/* MMU is setting up to use */
						/* new page table structures */
	bool		mmu_separate_pt;	/* MMU was set to use */
						/* separate PTs for kernel */
						/* and users */
	bool		L3_enable;		/* cache L3 is enable */
	bool		gmi;			/* is hardware virtualized */
						/* guest VM */
	e2k_addr_t	x86_io_area_base;
	e2k_addr_t	x86_io_area_size;
	u8		max_nr_node_cpus;
	u8		nr_node_cpus;
	u8		node_iolinks;
	e2k_addr_t	pcicfg_area_phys_base;
	e2k_size_t	pcicfg_area_size;
	e2k_addr_t	nsr_area_phys_base;
	e2k_size_t	nbsr_area_offset;
	e2k_size_t	nbsr_area_size;
	e2k_addr_t	copsr_area_phys_base;
	e2k_size_t	copsr_area_size;
	u8		mlt_size;
	u8		tlb_lines_bits_num;
	u64		tlb_addr_line_num;
	u64		tlb_addr_line_num2;
	u8		tlb_addr_line_num_shift2;
	u8		tlb_addr_set_num;
	u8		tlb_addr_set_num_shift;
	e2k_size_t	sic_mc_size;
	u8		sic_mc_count;
	u32		sic_mc1_ecc;
	u32		sic_io_str1;
	u32		clock_tick_rate;

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
	void (*save_gregs)(struct global_regs *);
	void (*save_local_gregs)(struct local_gregs *, bool is_signal);
	void (*save_gregs_dirty_bgr)(struct global_regs *);
	void (*save_gregs_on_mask)(struct global_regs *, bool dirty_bgr,
					unsigned long not_save_gregs_mask);
	void (*restore_gregs)(const struct global_regs *);
	void (*restore_local_gregs)(const struct local_gregs *, bool is_signal);
	void (*restore_gregs_on_mask)(struct global_regs *, bool dirty_bgr,
					unsigned long not_restore_gregs_mask);

	void (*save_dimtp)(e2k_dimtp_t *);
	void (*restore_dimtp)(const e2k_dimtp_t *);

	void (*save_kvm_context)(struct kvm_vcpu_arch *);
	void (*restore_kvm_context)(const struct kvm_vcpu_arch *);

	void (*calculate_aau_aaldis_aaldas)(const struct pt_regs *regs,
		      struct thread_info *ti, struct e2k_aau_context *context);
	void (*do_aau_fault)(int aa_field, struct pt_regs *regs);
	void (*save_aaldi)(u64 *aaldis);
	void (*get_aau_context)(struct e2k_aau_context *);

	unsigned long	(*rrd)(int reg);
	void		(*rwd)(int reg, unsigned long value);
	unsigned long	(*boot_rrd)(int reg);
	void		(*boot_rwd)(int reg, unsigned long value);

	u64		(*get_cu_hw1)(void);
	void		(*set_cu_hw1)(u64);

#ifdef CONFIG_MLT_STORAGE
	void		(*invalidate_MLT)(void);
	void		(*get_and_invalidate_MLT_context)(e2k_mlt_t *mlt_state);
#endif

	void		(*flushts)(void);

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
	host_machdep_t	host;	/* host additional fields (used only by */
				/* host at arch/e2k/kvm/xxx) */
	guest_machdep_t	guest;	/* guest additional fields (used only by */
				/* guest at arch/e2k/kvm/guest/xxx) */
} machdep_t;


/*
 * When executing on pure guest kernel, guest_cpu will be set to
 * 'machine.guest.id', i.e. to what hardware guest *thinks* it's
 * being executed on.
 */
typedef void (*cpuhas_initcall_t)(int cpu, int revision, int iset_ver,
		int guest_cpu, struct machdep *machine);
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
			struct machdep *const machine) { \
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

/* #47176 - Large pages do not work.
 * Workaround - do not use them. */
CPUHAS(CPU_HWBUG_LARGE_PAGES,
		!IS_ENABLED(CONFIG_CPU_ES2),
		false,
		cpu == IDR_ES2_DSP_MDL && revision < 1);
/* #56947 - lapic timer can lose interrupts.
 * Workaround - do not use oneshot mode. */
CPUHAS(CPU_HWBUG_LAPIC_TIMER,
		!IS_ENABLED(CONFIG_CPU_ES2),
		false,
		cpu == IDR_ES2_DSP_MDL && revision < 1);
/* #69194 - PIO reads can hang processor.
 * Workaround - serialize PIO reads on every CPU. */
CPUHAS(CPU_HWBUG_PIO_READS,
		!IS_ENABLED(CONFIG_CPU_ES2),
		false,
		cpu == IDR_ES2_DSP_MDL && (revision <= 1 || revision == 6) ||
		cpu == IDR_ES2_RU_MDL && revision <= 1);
/* #71610 - Atomic operations can be non-atomic
 * Workaround - flush data cache line.
 * This workaround increases the count of DCACHE flushes,
 * Turmalin has hardware bug with flushes so don't use
 * this workaround on it. */
CPUHAS(CPU_HWBUG_ATOMIC,
		!IS_ENABLED(CONFIG_CPU_ES2),
		false,
		cpu == IDR_ES2_DSP_MDL);
/* #58397, #76626 - CLW does not work.
 * Workaround - do not use it. */
CPUHAS(CPU_HWBUG_CLW,
		!IS_ENABLED(CONFIG_CPU_ES2) && !IS_ENABLED(CONFIG_CPU_E2S),
		false,
		cpu == IDR_ES2_DSP_MDL && (revision <= 1 || revision == 6) ||
		cpu == IDR_ES2_RU_MDL && revision <= 1 ||
		cpu == IDR_E2S_MDL && revision == 0);
/* #76626 - "Page accessed" bit in PTE does not work.
 * Workaround - always set it. */
CPUHAS(CPU_HWBUG_PAGE_A,
		!IS_ENABLED(CONFIG_CPU_ES2),
		false,
		cpu == IDR_ES2_DSP_MDL && (revision <= 1 || revision == 6) ||
		cpu == IDR_ES2_RU_MDL && revision <= 1);
/* #78411 - Sometimes exc_illegal_instr_addr is generated
 * instead of exc_instr_page_miss.
 * Workaround - always return to user from exc_illegal_instr_addr. */
CPUHAS(CPU_HWBUG_SPURIOUS_EXC_ILL_INSTR_ADDR,
		!IS_ENABLED(CONFIG_CPU_E2S),
		false,
		cpu == IDR_E2S_MDL && revision <= 1);
/* #83160 - unaligned loads do not work
 * Workaround - limit the stream of unaligned loads to less
 * than 32 bytes per cycle and put "wait ld_c" before it. */
CPUHAS(CPU_HWBUG_UNALIGNED_LOADS,
		!IS_ENABLED(CONFIG_CPU_ES2),
		false,
		cpu == IDR_ES2_DSP_MDL && (revision <= 1 || revision == 6) ||
		cpu == IDR_ES2_RU_MDL && revision <= 1)
/* #83884 - es2 deadlocks on DMA to neighbour node.
 * #100984 - # DMA to neighbour node slows down.
 * Workaround - allocate DMA buffers only in the device node. */
CPUHAS(CPU_HWBUG_CANNOT_DO_DMA_IN_NEIGHBOUR_NODE,
		!IS_ENABLED(CONFIG_CPU_ES2) && !IS_ENABLED(CONFIG_CPU_E8C),
		false,
		cpu == IDR_ES2_DSP_MDL && (revision <= 1 || revision == 6) ||
		cpu == IDR_ES2_RU_MDL && revision <= 1 ||
		cpu == IDR_E8C_MDL && revision <= 2);
/* #83884 - es2 deadlock on DMA at
 *	 (APIC_DEFAULT_PHYS_BASE & 0x7fffFFFF) address.
 * Workaround - reserve the 4K page at this address. */
CPUHAS(CPU_HWBUG_DMA_AT_APIC_ADDR,
		!IS_ENABLED(CONFIG_CPU_ES2),
		false,
		cpu == IDR_ES2_DSP_MDL);
/* #88644 - data profiling events are lost if overflow happens
 * under closed NM interrupts.
 * Workaround - disable data monitor profiling in kernel. */
CPUHAS(CPU_HWBUG_KERNEL_DATA_MONITOR,
		!IS_ENABLED(CONFIG_CPU_ES2) && !IS_ENABLED(CONFIG_CPU_E2S) &&
		!IS_ENABLED(CONFIG_CPU_E8C) && !IS_ENABLED(CONFIG_CPU_E1CP),
		false,
		cpu == IDR_ES2_DSP_MDL || cpu == IDR_ES2_RU_MDL ||
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
		cpu == IDR_E1CP_MDL);
/* #89495 - write barrier does not work (even for atomics).
 * Workaround - special command sequence after every read-acquire. */
CPUHAS(CPU_HWBUG_WRITE_MEMORY_BARRIER,
		!IS_ENABLED(CONFIG_CPU_E8C),
		false,
		cpu == IDR_E8C_MDL && revision <= 1);
/* On some processor's revisions writecombine memory
 * in prefetchable PCI area is not allowed. */
CPUHAS(CPU_FEAT_WC_PCI_PREFETCH,
		!IS_ENABLED(CONFIG_CPU_ES2),
		true,
		!((cpu == IDR_ES2_DSP_MDL || cpu == IDR_ES2_RU_MDL) &&
		  revision == 0));
/* #82499 - Instruction Cache must be handled carefully
 * when flush_dc_line also flushes IC by physical address. */
CPUHAS(CPU_FEAT_FLUSH_DC_IC,
		CONFIG_CPU_ISET != 0,
		CONFIG_CPU_ISET >= 3,
		iset_ver >= E2K_ISET_V3);
/* #89653 - some hw counter won't reset, which may cause corruption of DMA.
 * Workaround - reset machine until the counter sets in good value */
CPUHAS(CPU_HWBUG_BAD_RESET,
		!IS_ENABLED(CONFIG_CPU_E8C),
		false,
		cpu == IDR_E8C_MDL && revision <= 1);
/* #90514 - hardware hangs after modifying code with a breakpoint.
 * Workaround - use HS.lng from the instruction being replaced. */
CPUHAS(CPU_HWBUG_BREAKPOINT_INSTR,
		!IS_ENABLED(CONFIG_CPU_ES2) && !IS_ENABLED(CONFIG_CPU_E2S) &&
		!IS_ENABLED(CONFIG_CPU_E8C) && !IS_ENABLED(CONFIG_CPU_E8C2),
		false,
		cpu == IDR_ES2_DSP_MDL || cpu == IDR_ES2_RU_MDL ||
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
		!IS_ENABLED(CONFIG_CPU_ES2) && !IS_ENABLED(CONFIG_CPU_E2S) &&
		!IS_ENABLED(CONFIG_CPU_E8C) && !IS_ENABLED(CONFIG_CPU_E1CP) &&
		!IS_ENABLED(CONFIG_CPU_E8C2),
		false,
		cpu == IDR_ES2_DSP_MDL || cpu == IDR_ES2_RU_MDL ||
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
		cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL && revision == 0);
/* #97594 - %cr1_lo.ss flag is lost if ext. interrupt arrives faster.
 * Workaround - manually set %cr1_lo.ss again in interrupt handler */
CPUHAS(CPU_HWBUG_SS,
		!IS_ENABLED(CONFIG_CPU_ES2) && !IS_ENABLED(CONFIG_CPU_E2S) &&
		!IS_ENABLED(CONFIG_CPU_E8C) && !IS_ENABLED(CONFIG_CPU_E1CP) &&
		!IS_ENABLED(CONFIG_CPU_E8C2),
		false,
		cpu == IDR_ES2_DSP_MDL || cpu == IDR_ES2_RU_MDL ||
		cpu == IDR_E2S_MDL && revision <= 2 ||
		cpu == IDR_E8C_MDL && revision <= 2 ||
		cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL && revision == 0);
/* #99302 - %aaldv sometimes is not restored properly.
 * Workaround - insert 'wait ma_c' barrier */
CPUHAS(CPU_HWBUG_AAU_AALDV,
		!IS_ENABLED(CONFIG_CPU_ES2) && !IS_ENABLED(CONFIG_CPU_E2S) &&
		!IS_ENABLED(CONFIG_CPU_E8C) && !IS_ENABLED(CONFIG_CPU_E1CP) &&
		!IS_ENABLED(CONFIG_CPU_E8C2),
		false,
		cpu == IDR_ES2_DSP_MDL || cpu == IDR_ES2_RU_MDL ||
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
		cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL && revision == 0);
/* #103223 - LAPIC does not send EoI to IO_APIC for level interrupts.
 * Workaround - wait under closed interrupts until APIC_ISR clears */
CPUHAS(CPU_HWBUG_LEVEL_EOI,
		!IS_ENABLED(CONFIG_CPU_ES2) && !IS_ENABLED(CONFIG_CPU_E2S) &&
		!IS_ENABLED(CONFIG_CPU_E8C) && !IS_ENABLED(CONFIG_CPU_E1CP) &&
		!IS_ENABLED(CONFIG_CPU_E8C2),
		false,
		cpu == IDR_ES2_DSP_MDL || cpu == IDR_ES2_RU_MDL ||
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
		cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL);
/* #104865 - hardware might generate a false single step interrupt
 * Workaround - clean frame 0 of PCS during the allocation */
CPUHAS(CPU_HWBUG_FALSE_SS,
		!IS_ENABLED(CONFIG_CPU_ES2) && !IS_ENABLED(CONFIG_CPU_E2S) &&
		!IS_ENABLED(CONFIG_CPU_E8C) && !IS_ENABLED(CONFIG_CPU_E1CP) &&
		!IS_ENABLED(CONFIG_CPU_E8C2),
		false,
		cpu == IDR_ES2_DSP_MDL || cpu == IDR_ES2_RU_MDL ||
		cpu == IDR_E2S_MDL && revision <= 2 ||
		cpu == IDR_E8C_MDL && revision <= 2 ||
		cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL);
/* #117649 - false exc_data_debug are generated based on _previous_
 * values in ld/st address registers.
 * Workaround - forbid data breakpoint on the first 31 bytes
 * (hardware prefetch works with 32 bytes blocks). */
CPUHAS(CPU_HWBUG_SPURIOUS_EXC_DATA_DEBUG,
		!IS_ENABLED(CONFIG_CPU_ES2) && !IS_ENABLED(CONFIG_CPU_E2S) &&
		!IS_ENABLED(CONFIG_CPU_E8C) && !IS_ENABLED(CONFIG_CPU_E1CP) &&
		!IS_ENABLED(CONFIG_CPU_E8C2) && !IS_ENABLED(CONFIG_CPU_E12C) &&
		!IS_ENABLED(CONFIG_CPU_E16C) && !IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		cpu == IDR_ES2_DSP_MDL || cpu == IDR_ES2_RU_MDL ||
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
		cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL ||
		cpu == IDR_E12C_MDL && revision == 0 ||
		cpu == IDR_E16C_MDL && revision == 0 ||
		cpu == IDR_E2C3_MDL && revision == 0);
/* #119084 - several TBL flushes in a row might fail to flush L1D.
 * Workaround - insert "wait fl_c" immediately after every TLB flush */
CPUHAS(CPU_HWBUG_TLB_FLUSH_L1D,
		!IS_ENABLED(CONFIG_CPU_E8C2),
		false,
		cpu == IDR_E8C2_MDL);
/* #121311 - asynchronous entries in INTC_INFO_MU always have "pm" bit set.
 * Workaround - use "pm" bit saved in guest's chain stack. */
CPUHAS(CPU_HWBUG_GUEST_ASYNC_PM,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
		!IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		cpu == IDR_E12C_MDL || cpu == IDR_E16C_MDL ||
		cpu == IDR_E2C3_MDL);
/* #122946 - conflict new interrupt while sync signal turning off.
 * Workaround - wating for C0 after E2K_WAIT_V6 */
CPUHAS(CPU_HWBUG_E16C_SLEEP,
		!IS_ENABLED(CONFIG_CPU_E16C),
		false,
		cpu == IDR_E16C_MDL && revision == 0);
/* #124206 - instruction buffer stops working
 * Workaround - prepare %ctpr's in glaunch/trap handler entry;
 * avoid rbranch in glaunch/trap handler entry and exit. */
CPUHAS(CPU_HWBUG_L1I_STOPS_WORKING,
		!IS_ENABLED(CONFIG_CPU_ES2) && !IS_ENABLED(CONFIG_CPU_E2S) &&
		!IS_ENABLED(CONFIG_CPU_E8C) && !IS_ENABLED(CONFIG_CPU_E1CP) &&
		!IS_ENABLED(CONFIG_CPU_E8C2) && !IS_ENABLED(CONFIG_CPU_E12C) &&
		!IS_ENABLED(CONFIG_CPU_E16C) && !IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		cpu == IDR_ES2_DSP_MDL || cpu == IDR_ES2_RU_MDL ||
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
		cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL ||
		cpu == IDR_E12C_MDL || cpu == IDR_E16C_MDL ||
		cpu == IDR_E2C3_MDL);
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
		!IS_ENABLED(CONFIG_CPU_E16C) && !IS_ENABLED(CONFIG_CPU_E2C3) &&
		!IS_ENABLED(CONFIG_CPU_E12C),
		false,
		cpu == IDR_E16C_MDL && revision == 0 ||
		cpu == IDR_E12C_MDL && revision == 0 ||
		cpu == IDR_E2C3_MDL && revision == 0);
/* Rely on IDR instead of iset version to choose between APIC and EPIC.
 * For guest we use it's own fake IDR so that we choose between APIC and
 * EPIC based on what hardware guest *thinks* it's being executed on. */
CPUHAS(CPU_FEAT_EPIC,
		IS_ENABLED(CONFIG_E2K_MACHINE) &&
		!IS_ENABLED(CONFIG_KVM_GUEST_KERNEL),
		!IS_ENABLED(CONFIG_CPU_ES2) && !IS_ENABLED(CONFIG_CPU_E2S) &&
		!IS_ENABLED(CONFIG_CPU_E8C) && !IS_ENABLED(CONFIG_CPU_E1CP) &&
		!IS_ENABLED(CONFIG_CPU_E8C2),
		guest_cpu != IDR_ES2_DSP_MDL && guest_cpu != IDR_ES2_RU_MDL &&
		guest_cpu != IDR_E2S_MDL && guest_cpu != IDR_E8C_MDL &&
		guest_cpu != IDR_E1CP_MDL && guest_cpu != IDR_E8C2_MDL);
/* Shows which user registers must be saved upon trap entry/exit */
CPUHAS(CPU_FEAT_TRAP_V5,
		CONFIG_CPU_ISET != 0,
		CONFIG_CPU_ISET == 5,
		iset_ver == E2K_ISET_V5);
CPUHAS(CPU_FEAT_TRAP_V6,
		CONFIG_CPU_ISET != 0,
		CONFIG_CPU_ISET >= 6,
		iset_ver >= E2K_ISET_V6);
/* QP registers: only since iset V5 */
CPUHAS(CPU_FEAT_QPREG,
		CONFIG_CPU_ISET != 0,
		CONFIG_CPU_ISET >= 5,
		iset_ver >= E2K_ISET_V5);
/* Optimized version of machine.iset check */
CPUHAS(CPU_FEAT_ISET_V3,
		CONFIG_CPU_ISET != 0,
		CONFIG_CPU_ISET >= 3,
		iset_ver >= E2K_ISET_V3);
CPUHAS(CPU_FEAT_ISET_V5,
		CONFIG_CPU_ISET != 0,
		CONFIG_CPU_ISET >= 5,
		iset_ver >= E2K_ISET_V5);
CPUHAS(CPU_FEAT_ISET_V6,
		CONFIG_CPU_ISET != 0,
		CONFIG_CPU_ISET >= 6,
		iset_ver >= E2K_ISET_V6);


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

#ifndef E2K_P2V
# define cpu_has(feature)	test_feature(&machine, feature)
#else
# define cpu_has(feature)	boot_cpu_has(feature)
#endif

/* Normally cpu_has() is passed symbolic name of feature (e.g. CPU_FEAT_*),
 * use this one instead if only numeric value of feature is known. */
#define cpu_has_by_value(feature) test_feature_dynamic(&machine, feature)

extern void cpu_set_feature(struct machdep *machine, int feature);
extern void cpu_clear_feature(struct machdep *machine, int feature);


extern __nodedata machdep_t	machine;
extern __nodedata pt_struct_t	pgtable_struct;

#define	boot_machine		(boot_get_vo_value(machine))
#define	boot_pgtable_struct	((pt_struct_t)boot_get_vo_value(pgtable_struct))
#define	boot_pgtable_struct_p	boot_vp_to_pp(&pgtable_struct)

#if	CONFIG_CPU_ISET >= 6
#  define	IS_CPU_ISET_V6()	true
#elif	CONFIG_CPU_ISET >= 1
#  define	IS_CPU_ISET_V6()	false
#elif	CONFIG_CPU_ISET == 0
# ifdef	E2K_P2V
#  define	IS_CPU_ISET_V6()	\
			(boot_machine.native_iset_ver >= E2K_ISET_V6)
# else	/* ! E2K_P2V */
#  define	IS_CPU_ISET_V6()	\
			(machine.native_iset_ver >= E2K_ISET_V6)
# endif	/* E2K_P2V */
#else	/* CONFIG_CPU_ISET undefined or negative */
# warning "Undefined CPU ISET VERSION #, IS_CPU_ISET_V6 is defined dinamicaly"
# ifdef	E2K_P2V
#  define	IS_CPU_ISET_V6()	\
			(boot_machine.native_iset_ver >= E2K_ISET_V6)
# else	/* ! E2K_P2V */
#  define	IS_CPU_ISET_V6()	\
			(machine.native_iset_ver >= E2K_ISET_V6)
# endif	/* E2K_P2V */
#endif	/* CONFIG_CPU_ISET 0-6 */

#define	IS_HV_GM()		(machine.gmi)

extern void save_kernel_gregs_v2(struct kernel_gregs *);
extern void save_kernel_gregs_v5(struct kernel_gregs *);
extern void save_gregs_v2(struct global_regs *);
extern void save_gregs_v5(struct global_regs *);
extern void save_local_gregs_v2(struct local_gregs *, bool is_signal);
extern void save_local_gregs_v5(struct local_gregs *, bool is_signal);
extern void save_gregs_dirty_bgr_v2(struct global_regs *);
extern void save_gregs_dirty_bgr_v5(struct global_regs *);
extern void save_gregs_on_mask_v2(struct global_regs *, bool dirty_bgr,
					unsigned long mask_not_save);
extern void save_gregs_on_mask_v5(struct global_regs *, bool dirty_bgr,
					unsigned long mask_not_save);
extern void restore_gregs_v2(const struct global_regs *);
extern void restore_gregs_v5(const struct global_regs *);
extern void restore_local_gregs_v2(const struct local_gregs *, bool is_signal);
extern void restore_local_gregs_v5(const struct local_gregs *, bool is_signal);
extern void restore_gregs_on_mask_v2(struct global_regs *, bool dirty_bgr,
					unsigned long mask_not_restore);
extern void restore_gregs_on_mask_v5(struct global_regs *, bool dirty_bgr,
					unsigned long mask_not_restore);
extern void save_dimtp_v6(e2k_dimtp_t *);
extern void restore_dimtp_v6(const e2k_dimtp_t *);
extern void save_kvm_context_v6(struct kvm_vcpu_arch *);
extern void restore_kvm_context_v6(const struct kvm_vcpu_arch *);
extern void qpswitchd_sm(int);

extern void calculate_aau_aaldis_aaldas_v2(const struct pt_regs *regs,
		struct thread_info *ti, struct e2k_aau_context *context);
extern void calculate_aau_aaldis_aaldas_v5(const struct pt_regs *regs,
		struct thread_info *ti, struct e2k_aau_context *context);
extern void calculate_aau_aaldis_aaldas_v6(const struct pt_regs *regs,
		struct thread_info *ti, struct e2k_aau_context *context);
extern void do_aau_fault_v2(int aa_field, struct pt_regs *regs);
extern void do_aau_fault_v5(int aa_field, struct pt_regs *regs);
extern void do_aau_fault_v6(int aa_field, struct pt_regs *regs);
extern void save_aaldi_v2(u64 *aaldis);
extern void save_aaldi_v5(u64 *aaldis);
extern void get_aau_context_v2(struct e2k_aau_context *);
extern void get_aau_context_v5(struct e2k_aau_context *);

extern void flushts_v3(void);

extern unsigned long boot_native_read_IDR_reg_value(void);

unsigned long rrd_v2(int);
unsigned long rrd_v3(int);
unsigned long rrd_v6(int);
void rwd_v2(int reg, unsigned long value);
void rwd_v3(int reg, unsigned long value);
void rwd_v6(int reg, unsigned long value);
unsigned long boot_rrd_v2(int);
unsigned long boot_rrd_v3(int);
unsigned long boot_rrd_v6(int);
void boot_rwd_v2(int reg, unsigned long value);
void boot_rwd_v3(int reg, unsigned long value);
void boot_rwd_v6(int reg, unsigned long value);

/* Supported registers for machine->rrd()/rwd() */
enum {
	E2K_REG_CORE_MODE,
	E2K_REG_HCEM,
	E2K_REG_HCEB,
	E2K_REG_OSCUTD,
	E2K_REG_OSCUIR,
};

u64 native_get_cu_hw1_v2(void);
u64 native_get_cu_hw1_v5(void);
void native_set_cu_hw1_v2(u64);
void native_set_cu_hw1_v5(u64);

void invalidate_MLT_v2(void);
void invalidate_MLT_v3(void);
void get_and_invalidate_MLT_context_v2(e2k_mlt_t *mlt_state);
void get_and_invalidate_MLT_context_v3(e2k_mlt_t *mlt_state);
void get_and_invalidate_MLT_context_v6(e2k_mlt_t *mlt_state);

#ifdef CONFIG_SMP
void clock_off_v3(void);
void clock_on_v3(int cpu);
#endif

void C1_enter_v2(void);
void C1_enter_v6(void);
void C3_enter_v3(void);
void C3_enter_v6(void);
#endif /* __KERNEL__ */

#endif /* _E2K_MACHDEP_H_ */
