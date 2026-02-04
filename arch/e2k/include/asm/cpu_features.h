/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_ASM_CPU_FEATURES_H
#define _E2K_ASM_CPU_FEATURES_H

#ifndef __ASSEMBLY__

#include <linux/build_bug.h>
#include <linux/const.h>
#include <linux/init.h>
#include <linux/kconfig.h>
#include <linux/stringify.h>

#include <uapi/asm/bootinfo.h>
#include <asm/cpu_feature_values.h>
#include <asm/glob_regs.h>
#include <asm/iset_ver.h>
#include <asm/p2v/boot_v2p.h>

/* CPU model numbers */
#define IDR_NONE                0x00    /* No such hardware exists */
#define IDR_E2S_MDL             CPU_TYPE_E2S
#define IDR_E8C_MDL             CPU_TYPE_E8C
#define IDR_E1CP_MDL            CPU_TYPE_E1CP
#define IDR_E8C2_MDL            CPU_TYPE_E8C2
#define IDR_E12C_MDL            CPU_TYPE_E12C
#define IDR_E16C_MDL            CPU_TYPE_E16C
#define IDR_E2C3_MDL            CPU_TYPE_E2C3
#define IDR_E48C_MDL            CPU_TYPE_E48C
#define IDR_E8V7_MDL            CPU_TYPE_E8V7

#define IDR_E2K_VIRT_MDL        0x00    /* machine is virtual, so CPUs also */


/* Usually kernel reads features from %g (see cpuhas_gregN), but
 * this global is needed to initialize %g upon kernel entry. */
extern unsigned long cpu_features[(NR_CPU_FEATURES + 63) / 64];

#if defined E2K_P2V && !defined CONFIG_BOOT_E2K
# define boot_cpu_features	(boot_vp_to_pp(&(cpu_features[0])))
#else
# define boot_cpu_features	cpu_features
#endif

/*
 * When executing on pure guest kernel, guest_cpu will be set to
 * 'machine.guest.id', i.e. to what hardware guest *thinks* it's
 * being executed on.
 */
typedef void (*cpuhas_initcall_t) (int cpu, int revision, int iset_ver,
				   int guest_cpu, bool is_hardware_guest,
				   unsigned long *features);
extern cpuhas_initcall_t __cpuhas_initcalls[], __cpuhas_initcalls_end[];

/*
 * For quick access put cpu features into %g registers.
 */
register u64 cpuhas_greg0 __asm__("%g" __stringify(CPUHAS_GREG0));
register u64 cpuhas_greg1 __asm__("%g" __stringify(CPUHAS_GREG1));

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
# include <asm/bitsperlong.h>
# define CPUHAS(feat, is_static, static_cond, dynamic_cond) \
	static const char feat##_is_static = !!(is_static); \
	static const char feat##_is_set_statically = !!(static_cond); \
	__init \
	static void feat##_initializer(const int cpu, const int revision, \
			const int iset_ver, const int guest_cpu, \
			bool is_hardware_guest, unsigned long *features) { \
		bool check_is_static = (is_static); \
		if (check_is_static && (static_cond) || !check_is_static && (dynamic_cond)) { \
			if (feat < 64) { \
				cpuhas_greg0 |= _BITULL(feat); \
			} else if (feat >= 64 && feat < 128) { \
				cpuhas_greg1 |= _BITULL(feat - 64); \
			} \
			/* Inline set_bit() manually to avoid dependency hell */ \
			features[feat / __BITS_PER_LONG] |= 1UL << (feat % __BITS_PER_LONG); \
		} \
	} \
	static cpuhas_initcall_t __cpuhas_initcall_##feat __used \
			__section(".cpuhas_initcall") = &feat##_initializer;
#endif /* BUILD_CPUHAS_INITIALIZERS */

/* Most of these bugs are not emulated on simulator but
 * set them anyway to make kernel running on a simulator
 * behave in the same way as on real hardware. */

/* #58397, #76626, #148643, #159024, #162483, #163036 - CLW does not work.
 * Workaround - do not use it. */
CPUHAS(CPU_HWBUG_CLW,
		!IS_ENABLED(CONFIG_CPU_E2S) && !IS_ENABLED(CONFIG_CPU_E12C) &&
			!IS_ENABLED(CONFIG_CPU_E16C) && !IS_ENABLED(CONFIG_CPU_E2C3) &&
			!IS_ENABLED(CONFIG_CPU_E48C),
		false,
		cpu == IDR_E2S_MDL && revision == 0 ||
			cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision <= 1 ||
			cpu == IDR_E2C3_MDL && revision <= 1 ||
			cpu == IDR_E48C_MDL && revision == 0);
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
/* #105047/rm 27379 - optimized DMA mode %sic_hw1.dma_wr_glue_en does not work.
 * Workaround - disable it. */
CPUHAS(CPU_HWBUG_DMA_WR_GLUE,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 6,
		IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E8C2_MDL);
/* #116851 - hardware might generate a false exc_diag_operand for quad strqp.
 * Workaround - use speculative mode. */
CPUHAS(CPU_HWBUG_TAGGED_STRQP,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E8C2_MDL);
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
/* #120921 - cannot simultaneously clear %sclkm1.mode and set %sclkm1.mdiv.
 * Workaround - clear %sclkm1.mode, wait for %sclkr, then set %sclkm1.mdiv */
CPUHAS(CPU_HWBUG_SCLKM1_WRITE,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		IS_ENABLED(CONFIG_CPU_E2C3) || IS_ENABLED(CONFIG_E16C) ||
			IS_ENABLED(CONFIG_CPU_E12C),
		cpu == IDR_E2C3_MDL || cpu == IDR_E16C_MDL || cpu == IDR_E12C_MDL);
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
/* #127329 - %virt_ctrl_cu write does not work
 * Workaround - wide instruction with `rwd` must also contain `nop X`, X != 0 */
CPUHAS(CPU_HWBUG_RW_VIRT_CTRL_CU,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0 ||
			cpu == IDR_E2C3_MDL && revision == 0);
/* #127983 - sclkr "int" mode does not work when cpu core is paused (C3 state).
 * Workaround - pause cpuidle when using "int" mode */
CPUHAS(CPU_HWBUG_SCLKR_INT_C3,
		IS_ENABLED(CONFIG_E2K_MACHINE),
			IS_ENABLED(CONFIG_CPU_E2S) || IS_ENABLED(CONFIG_CPU_E8C) ||
			IS_ENABLED(CONFIG_CPU_E1CP) || IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
			cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL);
/* #128127 - Intercepting SCLKM3 write does not prevent guest from writing it.
 * Workaround - Update SH_SCLKM3 in intercept handler */
CPUHAS(CPU_HWBUG_VIRT_SCLKM3_INTC,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0 ||
			cpu == IDR_E2C3_MDL && revision == 0);
/* #128142 - code 0 in INTC_INFO_CU[2*i].event_code hangs hardware.
 * Workaround - manually remove such entries from list */
CPUHAS(CPU_HWBUG_INTC_INFO_CU_0,
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
 * #159721 - a pair of store instruction with specific MAS do not work.
 * Workaround - insert four instructions between such stores.
 *
 * Note that #133605/#159721 workarounds are split into several parts:
 * CPU_NO_HWBUG_SOFT_WAIT - for e16c/e2c3/e12c
 * CPU_NO_HWBUG_STORE_RELEASE - for e16c/e2c3/e12c
 * CPU_HWBUG_SOFT_WAIT_E8C2 - for e8c2
 * CPU_HWBUG_STORE_MAS - for e16c/e2c3/e12c
 *
 * This is done because it is very convenient to merge all workarounds
 * together for e16c/e12c/e2c3. */
CPUHAS(CPU_NO_HWBUG_SOFT_WAIT,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3),
		true,
		!(cpu == IDR_E12C_MDL && revision == 0 ||
		  cpu == IDR_E16C_MDL && revision == 0 ||
		  cpu == IDR_E2C3_MDL && revision == 0));
CPUHAS(CPU_NO_HWBUG_STORE_RELEASE,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3) && !IS_ENABLED(CONFIG_CPU_E48C),
		true,
		!(cpu == IDR_E12C_MDL && revision == 0 ||
		  cpu == IDR_E16C_MDL && revision <= 2 ||
		  cpu == IDR_E2C3_MDL && revision <= 2 ||
		  cpu == IDR_E48C_MDL && revision == 0));
CPUHAS(CPU_HWBUG_STORE_MAS,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3) && !IS_ENABLED(CONFIG_CPU_E48C),
		false,
		cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision <= 2 ||
			cpu == IDR_E2C3_MDL && revision <= 2 ||
			cpu == IDR_E48C_MDL && revision == 0);
CPUHAS(CPU_HWBUG_SOFT_WAIT_E8C2,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E8C2_MDL);
/* #130433, #132693, #149522, rm 25681 - C3 idle state does not work.
 * Workaround - do not use it. */
CPUHAS(CPU_HWBUG_C3,
		IS_ENABLED(CONFIG_E2K_MACHINE) && !IS_ENABLED(CONFIG_CPU_E12C) &&
			!IS_ENABLED(CONFIG_CPU_E16C) && !IS_ENABLED(CONFIG_CPU_E48C),
		IS_ENABLED(CONFIG_CPU_E8C) || IS_ENABLED(CONFIG_CPU_E1CP) ||
			IS_ENABLED(CONFIG_CPU_E8C2),
		cpu == IDR_E8C_MDL || cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL ||
			cpu == IDR_E12C_MDL && revision == 0 ||
			cpu == IDR_E16C_MDL && revision == 0 ||
			cpu == IDR_E48C_MDL && revision == 0);
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
/* #137536 - intercept (or interrupt), after writing CR which in turn is
 * blocked in hardware by previous FILL CF, may corrupt all other CRs.
 * Workaround - add wait ma_c=1 to the same instruction, as CR write
 * There are some variants:
 *  - In guest add barrier to every CR write and another before all writes;
 *  - In host v5/v6 add barrier to the first CR write only and another before all writes;
 *  - In host v3/v4 add barrier to the first CR write only.
 *
 * Split workaround accordingly: CPU_HWBUG_CR_BEFORE_WRITES determines whether
 * additional `wait` before all writes is required and CPU_HWBUG_CR_EVERY_WRITE/
 * CPU_HWBUG_CR_FIRST_WRITE determine whether `wait` is needed for `rwd %cr`.
 *
 * CPU_NO_HWBUG_CR_WRITE is compile-time combination of all of the above,
 * so if it is set then bug is not possible (but not the other way around). */
CPUHAS(CPU_HWBUG_CR_BEFORE_WRITES,
		CONFIG_CPU_ISET_MIN >= 7,
		false,
		cpu == IDR_E12C_MDL && revision == 0 ||
		cpu == IDR_E16C_MDL && revision == 0 ||
		cpu == IDR_E2C3_MDL && revision == 0 ||
		cpu == IDR_E8C2_MDL ||
		is_hardware_guest &&
			(cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL || cpu == IDR_E1CP_MDL));
CPUHAS(CPU_HWBUG_CR_EVERY_WRITE,
		CONFIG_CPU_ISET_MIN >= 7,
		false,
		(cpu == IDR_E12C_MDL && revision == 0 ||
		 cpu == IDR_E16C_MDL && revision == 0 ||
		 cpu == IDR_E2C3_MDL && revision == 0 ||
		 cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
		 cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL) &&
			is_hardware_guest);
CPUHAS(CPU_HWBUG_CR_FIRST_WRITE,
		CONFIG_CPU_ISET_MIN >= 7,
		false,
		(cpu == IDR_E12C_MDL && revision == 0 ||
		 cpu == IDR_E16C_MDL && revision == 0 ||
		 cpu == IDR_E2C3_MDL && revision == 0 ||
		 cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
		 cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL) &&
			!is_hardware_guest);
CPUHAS(CPU_NO_HWBUG_CR_WRITE,
		true,
		CONFIG_CPU_ISET_MIN >= 7,
		true);
/* 140436 (143456, 152233) - jump (of any kind) to some IPs is not supported
 * Workaround - mark non-jump-target labels as such so that GAS can work its magic.
 * This one requires preprocessor-time fixing so grep for CPU_HWBUG_JUMP */
/* #142262 - tagged 'ldw' instruction does not work
 * Workaround - insert 4 bubbles between tagged 'ldw' and potentially
 * aliasing previous 'stw'. */
CPUHAS(CPU_HWBUG_TAGGED_LDW,
		!IS_ENABLED(CONFIG_CPU_E16C) && !IS_ENABLED(CONFIG_CPU_E12C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3),
		false,
		cpu == IDR_E16C_MDL && revision <= 2 ||
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
/* #143157, #141618 - user exc_instr_debug and exc_data_debug could occure in kernel */
CPUHAS(CPU_HWBUG_EXC_DEBUG,
		IS_ENABLED(CONFIG_E2K_MACHINE),
		CONFIG_CPU_ISET_MIN <= 6,
		iset_ver <= E2K_ISET_V6);
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
 * outside two regions: [0xdc0 - 0xdf8] and [0xee0 - 0xff8].
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
/* #146903, #148619 - glaunch zeroes guest's CLW mask due to incorrectly restored us_cl_low
 * Workaround - trigger correct hardware restore of us_cl_low on v6
 * by writing us_cl_up value to us_cl_b, and immediately restoring usd_lo */
CPUHAS(CPU_HWBUG_CLW_LOW_RESTORE,
		IS_ENABLED(CONFIG_E2K_MACHINE) && !IS_ENABLED(CONFIG_CPU_E48C),
		IS_ENABLED(CONFIG_CPU_E2C3) || IS_ENABLED(CONFIG_CPU_E12C) ||
			IS_ENABLED(CONFIG_CPU_E16C),
		cpu == IDR_E2C3_MDL || cpu == IDR_E12C_MDL || cpu == IDR_E16C_MDL ||
			cpu == IDR_E48C_MDL && revision == 0);
/* #152622 - ITLB for large pages is too small.
 * Workaround - reduce number of large code pages used by kernel. */
CPUHAS(CPU_HWBUG_ITLB_LARGE_PAGES,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 8,
		CONFIG_CPU_ISET_MIN <= 6 || IS_ENABLED(CONFIG_CPU_E48C),
		cpu == IDR_E2S_MDL || cpu == IDR_E8C_MDL ||
			cpu == IDR_E1CP_MDL || cpu == IDR_E8C2_MDL ||
			cpu == IDR_E12C_MDL || cpu == IDR_E16C_MDL ||
			cpu == IDR_E2C3_MDL || cpu == IDR_E48C_MDL);
/* #156885 - MADM registers access will not work.
 * Workaround - do not access them. */
CPUHAS(CPU_HWBUG_MADM_REGISTERS,
		!IS_ENABLED(CONFIG_CPU_E48C),
		false,
		cpu == IDR_E48C_MDL && revision == 0);
/* rm 22735 - there are no DIMCR1/DDMAR2/DDMAR3 registers.
 * Workaround - do not access them. */
CPUHAS(CPU_HWBUG_DIMCR1,
		!IS_ENABLED(CONFIG_CPU_E48C),
		false,
		cpu == IDR_E48C_MDL && revision == 0);
/* #157558 - HCALL improperly switches compilation units, leading to bad
 * CUIR/GD/CUD and sometimes to a spurious 'exc_illegal_instr_addr' trap on
 * first IP of host hypercall handler.
 *
 * Workaround - ignore spurious interrupt and switch compilation unit with
 * 'done'; it's not guaranteed because trap is generated only when guest's
 * CUD.prot=1 and guest's CUD/GD are missing from hypervisor page tables. */
CPUHAS(CPU_HWBUG_HCALL_EXC_ILL_INSTR_ADDR,
		!IS_ENABLED(CONFIG_CPU_E2C3) && !IS_ENABLED(CONFIG_CPU_E12C) &&
			!IS_ENABLED(CONFIG_CPU_E16C),
		false,
		cpu == IDR_E2C3_MDL && revision <= 2 ||
			cpu == IDR_E16C_MDL && revision <= 1 ||
			cpu == IDR_E12C_MDL && revision == 0);
/* #160330 - speculative loads (not semi-spec.) crossing page boundary lose tags.
 * Workaround - do not use speculative mode for unaligned loads. */
CPUHAS(CPU_HWBUG_UNALIGNED_LOADS,
		!IS_ENABLED(CONFIG_CPU_E48C),
		false,
		cpu == IDR_E48C_MDL && revision == 0);
/* #163114 - atomics can cause unexpected exc_data_page in guest.
 * Workaround - use address before issuing "lock wait" load. */
CPUHAS(CPU_NO_HWBUG_ATOMIC_SPURIOUS_FAULT,
		/* If editing this please also update condition for BEFORE_ATOMIC() */
		!IS_ENABLED(CONFIG_CPU_E2C3) && !IS_ENABLED(CONFIG_CPU_E12C) &&
			!IS_ENABLED(CONFIG_CPU_E16C),
		true,
		!is_hardware_guest ||
			(cpu != IDR_E2C3_MDL && cpu != IDR_E12C_MDL && cpu != IDR_E16C_MDL));
/* #164666 - "wait int=1" instruction can trigger falsely.
 * Workaround - issue it under closed all interrupts, and avoid
 * `ibranch(d) ? #MLOCK [|| %cmp] [|| %clp]` instructions right
 * before it. */
CPUHAS(CPU_HWBUG_WAIT_INT,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 7,
		IS_ENABLED(CONFIG_CPU_E2C3) || IS_ENABLED(CONFIG_CPU_E12C) ||
			IS_ENABLED(CONFIG_CPU_E16C),
		cpu == IDR_E2C3_MDL || cpu == IDR_E12C_MDL ||
			cpu == IDR_E16C_MDL);
/* #165225 - some instructions are not allowed after "rwd %lsr{1}".
 * Workaround - use "{nop}" after "rwd" to avoid those instructions. */
CPUHAS(CPU_HWBUG_RWD_LSR,
		!IS_ENABLED(CONFIG_CPU_E48C),
		false,
		cpu == IDR_E48C_MDL && revision == 0);
/* #165658 - rrsh/rwsh check %core_mode.descr_v7 when accessing %ctpr.
 * Workaround - temporarily assign %core_mode.descr_v7=%sh_core_mode.descr_v7. */
CPUHAS(CPU_HWBUG_RRSH_RWSH_CTPR,
		!IS_ENABLED(CONFIG_CPU_E48C),
		false,
		cpu == IDR_E48C_MDL && revision == 0);
/* #165679 - rrsh checks %core_mode.descr_v7 instead of %sh_core_mode.descr_v7.
 * Workaround - temporarily assign %core_mode.descr_v7=%sh_core_mode.descr_v7. */
CPUHAS(CPU_HWBUG_RRSH_DESCR_V7,
		!IS_ENABLED(CONFIG_CPU_E48C),
		false,
		cpu == IDR_E48C_MDL && revision == 0);

/* rm 27719 - ibranchd/rbranch instruction can corrupt 'inactive' %ctpr.
 * Workaround - do not use them when any %ctpr is in 'inactive' state. */
CPUHAS(CPU_HWBUG_BRANCH_ACTIVATES_CTPR,
		/* If editing this please also update condition for BEFORE_ATOMIC() */
		!IS_ENABLED(CONFIG_CPU_E2C3) && !IS_ENABLED(CONFIG_CPU_E12C) &&
			!IS_ENABLED(CONFIG_CPU_E16C) && !IS_ENABLED(CONFIG_CPU_E48C),
		false,
		cpu == IDR_E2C3_MDL || cpu == IDR_E12C_MDL || cpu == IDR_E16C_MDL ||
			cpu == IDR_E48C_MDL && revision == 0);

CPUHAS(CPU_FEAT_E48C_MAKET,
		!IS_ENABLED(CONFIG_CPU_E48C),
		false,
		cpu == IDR_E48C_MDL && revision == 0);


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
/* Hardware prefetcher that resides in TLB */
CPUHAS(CPU_FEAT_HW_PREFETCHER_TLB,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 7,
		CONFIG_CPU_ISET_MIN >= 7,
		iset_ver >= E2K_ISET_V7);
/* Hardware prefetcher that resides in L1 */
CPUHAS(CPU_FEAT_HW_PREFETCHER_L1,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 7,
		CONFIG_CPU_ISET_MIN >= 7,
		iset_ver >= E2K_ISET_V7);
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
 * 2) Someone accesses the PMD->PTE link (e.g. semi-spec. load) and
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
		iset_ver >= E2K_ISET_V6 && IS_ENABLED(CONFIG_MMU_SEP_VIRT_SPACE));
/* Page table format from iset v6 */
CPUHAS(CPU_FEAT_PAGE_TABLE_V6,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 6,
		IS_ENABLED(CONFIG_MMU_PT_V6),
		iset_ver >= E2K_ISET_V6 && IS_ENABLED(CONFIG_MMU_PT_V6));
/* Speculative loads are allowed to cross into unmapped page,
 * in which case not read data is replaced by zeros. */
CPUHAS(CPU_FEAT_PARTIAL_SPEC_LOAD,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 7,
		CONFIG_CPU_ISET_MIN >= 7,
		iset_ver >= E2K_ISET_V7);
/* Atomic operations are supported by ldrd/strd */
CPUHAS(CPU_FEAT_ATOMIC_LDRD,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 6,
		CONFIG_CPU_ISET_MIN >= 6,
		iset_ver >= E2K_ISET_V6);
/* Descriptor format from v7, used both in protected mode and
 * for some CPU registers (PCSP, PSP, USD, DIMTP, ...)
 * Also %cr1.ussz field has changed it's meaning. */
CPUHAS(CPU_FEAT_V7_CPU_REGS,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 7,
		CONFIG_CPU_ISET_MIN >= 7,
		iset_ver >= E2K_ISET_V7);
/* Memory Access Debug Modes support, currently for protected mode
 * execution only.  Useful for performant protection from memory errors. */
CPUHAS(CPU_FEAT_MADM,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 7,
		CONFIG_CPU_ISET_MIN >= 7,
		iset_ver >= E2K_ISET_V7);
/* Optimized version of machine.iset check */
CPUHAS(CPU_FEAT_ISET_V5,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 5,
		CONFIG_CPU_ISET_MIN >= 5,
		iset_ver >= E2K_ISET_V5);
CPUHAS(CPU_FEAT_ISET_V6,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 6,
		CONFIG_CPU_ISET_MIN >= 6,
		iset_ver >= E2K_ISET_V6);
/* CPU_FEAT_ISET_NOT_V6 == !CPU_FEAT_ISET_V6 == "Is this <v6 cpu?" */
CPUHAS(CPU_FEAT_ISET_NOT_V6,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 6,
		CONFIG_CPU_ISET_MIN < 6,
		iset_ver < E2K_ISET_V6);
CPUHAS(CPU_FEAT_ISET_V7,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 7,
		CONFIG_CPU_ISET_MIN >= 7,
		iset_ver >= E2K_ISET_V7);
/* CPU_FEAT_ISET_NOT_V7 == !CPU_FEAT_ISET_V7 == "Is this <v7 cpu?" */
CPUHAS(CPU_FEAT_ISET_NOT_V7,
		IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 7,
		CONFIG_CPU_ISET_MIN < 7,
		iset_ver < E2K_ISET_V7);
/*
 * #143130; rm 29416 - the ability to calibrate voltmeters VM has been implemented.
 * VM0 CH0 is used for calibration in e2c3, e16c version >= 2, e12c version >= 1,
 * e8v7 version >= 0, e48c version >= 1. */
CPUHAS(CPU_FEAT_IMPROVED_VM,
		!IS_ENABLED(CONFIG_CPU_E12C) && !IS_ENABLED(CONFIG_CPU_E16C) &&
			!IS_ENABLED(CONFIG_CPU_E2C3) && !IS_ENABLED(CONFIG_CPU_E8V7) &&
			!IS_ENABLED(CONFIG_CPU_E48C),
		false,
		cpu == IDR_E12C_MDL && revision >= 1 ||
			cpu == IDR_E16C_MDL && revision >= 2 ||
			cpu == IDR_E2C3_MDL && revision >= 2 ||
			cpu == IDR_E8V7_MDL && revision >= 0 ||
			cpu == IDR_E48C_MDL && revision >= 1);
CPUHAS(CPU_FEAT_GLOBAL_IRQ_MASK,
		true,
		IS_ENABLED(CONFIG_GLOBAL_IRQ_MASK) ||
			IS_ENABLED(CONFIG_KVM_GUEST_KERNEL),
		false);
/* MMUCR.svsc - support for more strict separation of kernel and user
 * virtual spaces.  This allows to avoid constant page table switches
 * around every get_user/put_user/etc and protect from side channel
 * attacks on kernel. */
CPUHAS(CPU_FEAT_SVSC,
		(IS_ENABLED(CONFIG_E2K_MACHINE) || CONFIG_CPU_ISET_MIN >= 7) &&
			!IS_ENABLED(CONFIG_CPU_E48C),
		CONFIG_CPU_ISET_MIN >= 7,
		iset_ver >= E2K_ISET_V7 && !(cpu == IDR_E48C_MDL && revision == 0));
/* Are we hardware guest? */
CPUHAS(CPU_FEAT_GUEST, false, false, is_hardware_guest);


static __always_inline bool test_feature_dynamic_gregs(int feature)
{
	if (feature < 64) {
		return cpuhas_greg0 & _BITULL(feature);
	} else if (feature >= 64 && feature < 128) {
		return cpuhas_greg1 & _BITULL(feature - 64);
	} else {
		BUILD_BUG_ON_MSG(1, "%g23 and %g24 are not enough to hold all cpu features, please expand into %g25 too");
	}
}

static __always_inline bool test_feature_dynamic_mem(int feature)
{
	unsigned long *addr = &cpu_features[0];

	return 1UL & (addr[feature / 64] >> (feature & 63));
}

/* For fast system calls it's simpler to just use values in memory
 * since this way we preserve user's %g values for the case of coredump. */
#ifdef E2K_FAST_SYSCALL
# define test_feature_dynamic test_feature_dynamic_mem
#else
# define test_feature_dynamic test_feature_dynamic_gregs
#endif /* E2K_FAST_SYSCALL */

/**
 * cpu_has() - check feature on CPU we are executing on
 * @feature: feature to check from cpu_feature_values.h
 *
 * IMPORTANT: for performance reasons this relies on %g registers,
 * which are restored to user's values before return to user.
 * This means that cpu_has() _cannot_ be used when exiting traps
 * and syscalls, use cpu_has_slow() or alternatives instead.
 */
#define cpu_has(feature) ((feature##_is_static) \
				? feature##_is_set_statically \
				: test_feature_dynamic(feature))

/**
 * cpu_has_slow() - same as cpu_has() but avoids using %g registers
 *		    at the cost of performance.
 * @feature: feature to check from cpu_feature_values.h
 */
#define cpu_has_slow(feature) ((feature##_is_static) \
				? feature##_is_set_statically \
				: test_feature_dynamic_mem(feature))

#define boot_cpu_has cpu_has

/* Normally cpu_has() is passed symbolic name of feature (e.g. CPU_FEAT_*),
 * use this one instead if only numeric value of feature is known. */
static __always_inline unsigned long cpu_has_by_value(int feature)
{
	unsigned long *addr = &cpu_features[0];

	return 1UL & (addr[feature / 64] >> (feature & 63));
}

/*
 * These require extra care because alternatives are *not* reparsed
 * after feature's update, so these can be used when the feature is
 * accessed _only_ through the cpu_has() API.
 */
extern void cpu_set_feature(unsigned long *features, int feature);
extern void cpu_clear_feature(unsigned long *features, int feature);
#endif /* __ASSEMBLY__ */

#endif
