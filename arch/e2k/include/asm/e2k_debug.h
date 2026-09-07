/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * asm-e2k/e2k_debug.h
 */
#ifndef _E2K_DEBUG_H_
#define _E2K_DEBUG_H_

#include <linux/types.h>
#include <linux/kernel.h>

#include <asm/debug_print.h>
#include <asm/boot_profiling.h>
#include <asm/mas.h>
#include <asm/cpu_regs.h>
#include <asm/nmi.h>
#include <asm/ptrace.h>
#include <asm/current.h>
#include <asm/system.h>
#include <asm/machdep.h>
#include <asm/e2k_api.h>
#include <asm/mmu_fault.h>
#include <asm/io.h>
#include <asm/e2k.h>
#include <asm/pgtable_def.h>
#include <asm/traps.h>

#define	IS_KERNEL_THREAD(task, mm) \
({ \
	e2k_addr_t ps_base; \
	\
	ps_base = (e2k_addr_t)task_thread_info(task)->u_hw_stack.ps.base; \
	((mm) == NULL || ps_base >= TASK_SIZE); \
})

extern void print_stack_frames(struct task_struct *task,
		const struct pt_regs *pt_regs, int show_reg_window) __cold;
extern void native_print_all_tlb(void);
extern void print_va_tlb(e2k_addr_t addr, bool huge_page) __cold;
extern void print_va_all_tlb_levels(e2k_addr_t addr, bool huge_page) __cold;
extern void print_all_TC(const trap_cellar_t *TC, int TC_count) __cold;
extern void print_tc_record(const trap_cellar_t *tcellar, int num) __cold;
extern u64 print_all_TIRs(const e2k_tir_t *TIRs, u64 nr_TIRs) __cold;
extern void print_address_page_tables(unsigned long address, int last_level_only) __cold;
extern void print_pt_regs(const pt_regs_t *regs) __cold;
extern void print_kernel_address_ptes(e2k_addr_t address) __cold;
extern void print_vma_and_ptes(struct vm_area_struct *, e2k_addr_t) __cold;

#ifdef CONFIG_PROTECTED_MODE
extern void __user *e2k_alloc_user_data_stack(unsigned long len);
#endif

__init extern void setup_stack_print(void);

extern void set_protected_mode_flags(void);

extern int debug_signal;
extern int debug_userstack;
extern int debug_pagefault;
extern int debug_semi_spec;
extern int print_window_regs;
extern int debug_protected_mode;
#ifdef CONFIG_DATA_STACK_WINDOW
extern int debug_datastack;
#endif

static inline void native_print_address_tlb(unsigned long address)
{
	print_va_all_tlb_levels(address, 0);
}

/**
 * *chain_write_fn_t - write corrected chain frame from inside of parse_chain_fn_t
 * @real_frame_addr: corresponding argument of parse_chain_fn_t
 * @crs: updated frame to write at @real_frame_addr
 */
typedef int (*chain_write_fn_t)(unsigned long real_frame_addr, const e2k_mem_crs_t *crs);

/**
 * *parse_chain_fn_t - function to be called on every frame in chain stack
 * @crs: contents of current frame in chain stack
 * @real_frame_addr: real address of current frame, can be used to modify frame
 *                   with the help of @write_frame
 * @corrected_frame_addr: address of current frame where it would be in stack
 * @write_frame: call this to write @crs after modifying it
 * @arg: passed argument from parse_chain_stack()
 *
 * The distinction between @real_frame_addr and @corrected_frame_addr is
 * important. Normally top of user chain stack is spilled to kernel chain
 * stack, in which case @real_frame_addr points to spilled frame in kernel
 * stack and @corrected_frame_addr holds the address in userspace where
 * the frame _would_ be if it was spilled to userspace. In all other cases
 * these two variables are equal.
 *
 * Generally @corrected_frame_addr is used in comparisons and
 * @real_frame_addr is used for modifying stack in memory.
 *
 * IMPORTANT: if function wants to modify frame contents it must use
 * the supplied @edit_begin and @edit_end functions.
 */
typedef int (*parse_chain_fn_t)(e2k_mem_crs_t *crs,
		unsigned long real_frame_addr, unsigned long corrected_frame_addr,
		chain_write_fn_t write_frame, void *arg);
extern notrace long parse_chain_stack(bool user, bool mm_locked, struct task_struct *p,
				      parse_chain_fn_t func, void *arg);

extern notrace int ____parse_chain_stack(bool user, bool mm_locked, struct task_struct *p,
			parse_chain_fn_t func, void *arg, unsigned long delta_user,
			unsigned long top, unsigned long bottom);

static inline int
native_do_parse_chain_stack(bool user, bool mm_locked, struct task_struct *p,
		parse_chain_fn_t func, void *arg, unsigned long delta_user,
		unsigned long top, unsigned long bottom)
{
	return ____parse_chain_stack(user, mm_locked, p, func, arg, delta_user, top, bottom);
}

#define NATIVE_IS_USER_ADDR(task, addr)		\
		(((e2k_addr_t)(addr)) < NATIVE_TASK_SIZE)

#define SIZE_PSP_STACK (16 * 4096)
#define DATA_STACK_PAGES 16
#define SIZE_DATA_STACK (DATA_STACK_PAGES * PAGE_SIZE)

#define SIZE_CHAIN_STACK	KERNEL_PC_STACK_SIZE
#define	VIRT_SIZE_CHAIN_STACK	VIRT_KERNEL_PCS_SIZE

/* Maximum number of user windows where a trap occured
 * for which additional registers will be printed (ctpr's, lsr and ilcr). */
#define MAX_USER_TRAPS 12

/* Maximum number of pt_regs being marked as such
 * when showing kernel data stack */
#define MAX_PT_REGS_SHOWN 30

struct printed_trap_regs {
	bool valid;
	u64 frame;
	e2k_ctpr_t ctpr1;
	e2k_ctpr_t ctpr2;
	e2k_ctpr_t ctpr3;
	u64 lsr;
	u64 ilcr;
	u64 lsr1;
	u64 ilcr1;
	u64 sbbp[SBBP_ENTRIES_NUM];

	/* Chosen depending on user_mode() */
	bool user;
	union {
		struct local_gregs u_gregs;
		struct scratch_gregs k_gregs;
	};
};

typedef struct stack_regs {
	bool used;
	bool valid;
	bool ignore_banner;
	struct task_struct *task;
	e2k_mem_crs_t crs;
	e2k_pcsp_t pcsp;
	e2k_psp_t psp;
	volatile void *base_psp_stack;
	u64 user_size_psp_stack;
	u64 orig_base_psp_stack_u;
	u64 orig_base_psp_stack_k;
	volatile void *psp_stack_cache;
	u64 size_psp_stack;
	bool show_user_regs;
	struct printed_trap_regs trap[MAX_USER_TRAPS];
	struct global_gregs global_gregs;
	bool gregs_valid;
#ifdef CONFIG_DATA_STACK_WINDOW
	bool show_k_data_stack;
	void *base_k_data_stack;
	void *k_data_stack_cache;
	u64 size_k_data_stack;
	void *real_k_data_stack_addr;
	struct {
		unsigned long addr;
		bool valid;
	} pt_regs[MAX_PT_REGS_SHOWN];
#endif
	u64 size_chain_stack;
	void *base_chain_stack;
	u64 user_size_chain_stack;
	u64 orig_base_chain_stack_u;
	u64 orig_base_chain_stack_k;
	void *chain_stack_cache;
} stack_regs_t;

extern void print_chain_stack(struct stack_regs *regs, int show_reg_window);
extern void copy_stack_regs(struct task_struct *task,
		const struct pt_regs *limit_regs, struct stack_regs *regs);
extern void fill_trap_stack_regs(const pt_regs_t *trap_pt_regs,
				 struct printed_trap_regs *regs_trap);

extern struct stack_regs stack_regs_cache[NR_CPUS];

#ifndef	CONFIG_KVM_GUEST_KERNEL
/* it is native kernel without any virtualization */
/* or it is native host kernel with virtualization support */
/* or it is paravirtualized host and guest kernel */

static inline void print_address_tlb(unsigned long address)
{
	native_print_address_tlb(address);
}

static inline int
do_parse_chain_stack(bool user, bool mm_locked, struct task_struct *p,
		parse_chain_fn_t func, void *arg, unsigned long delta_user,
		unsigned long top, unsigned long bottom)
{
	return native_do_parse_chain_stack(user, mm_locked, p, func, arg, delta_user, top, bottom);
}
#endif /* !CONFIG_KVM_GUEST_KERNEL */

#ifndef	CONFIG_VIRTUALIZATION
/* it is native kernel without any virtualization */
#define	print_all_guest_stacks()	/* nothing to do */
#define	debug_guest_regs(task)		false	/* none any guests */
#define	get_cpu_type_name()		"CPU"	/* real CPU */

static inline void
print_guest_stack(struct task_struct *task,
		  stack_regs_t * const regs, bool show_reg_window)
{
	return;
}

static inline void print_all_tlb(void)
{
	native_print_all_tlb();
}

static inline void host_ftrace_stop(void)
{
	return;
}

static inline void host_ftrace_dump(void)
{
	return;
}

static inline void host_tracing_stop(void)
{
	return;
}

static inline void host_tracing_start(void)
{
	return;
}

static const bool kvm_debug = false;
#else /* CONFIG_VIRTUALIZATION */
/* it is native host kernel with virtualization support */
/* or it is paravirtualized host/guest kernel */
/* or it is native guest kernel */
#include <asm/kvm/debug.h>
#endif /* ! CONFIG_VIRTUALIZATION */

/*
 * Print Chain Regs CR0 and CR1
 */
#undef	DEBUG_CRs_MODE
#undef	DebugCRs
#define	DEBUG_CRs_MODE		0
#define	DebugCRs(POS)		if (DEBUG_CRs_MODE) print_chain_stack_regs(POS)
extern inline void print_chain_stack_regs(char *point)
{
	register e2k_cr0_t cr0;
	register e2k_cr1_t cr1;
	register u64 pf;

	pr_info("Procedure chain registers state");
	if (point != NULL)
		pr_info(" at %s :", point);
	pr_info("\n");

	cr0 = read_CR0_reg();
	pf = cr0.pf;
	pr_info("        CR0: hi ip 0x%llx, pf pf 0x%llx\n", get_cr0_ip(cr0), pf);
	cr1 = read_CR1_reg();
	pr_info("        CR1: ussz 0x%llx br 0x%llx\n", get_cr1_ussz(cr1), (u64) cr1.br);
	pr_info("             unmie %d nmie %d uie %d lw %d sge %d ie %d pm %d\n",
		(int)cr1.unmie, (int)cr1.nmie, (int)cr1.uie,
		(int)cr1.lw, (int)cr1.sge, (int)cr1.ie, (int)cr1.pm);
	pr_info("                cuir 0x%x wbs 0x%x wpsz %d wfx %d ein %d\n",
		(int)cr1.cuir, (int)cr1.wbs, (int)cr1.wpsz, (int)cr1.wfx, (int)cr1.ein);

}

/*
 * Registers CPU
 */
static inline void print_cpu_regs(char *str)
{
	register e2k_usd_t usd;
	register e2k_psp_t psp;
	register e2k_pcsp_t pcsp;
	register e2k_cr0_t cr0;
	register e2k_cr1_t cr1;

	pr_info("%s\n	%s", str, "CPU REGS value:\n");
	pr_info("sbr	 %llx\n", read_SBR_reg().word);
	pr_info("usbr	 %llx\n", read_USBR_reg().word);
	usd = read_USD_reg();
	if (USD_P(usd)) {
		pr_info("PUSD: p_base 0x%x, size 0x%llx, psl 0x%x\n",
			usd.P_ptr, USD_IND(usd), USD_PSL(usd));
	} else {
		pr_info("USD: base 0x%llx, size 0x%llx\n",
			USD_PTR(usd), USD_IND(usd));
	}
	psp = read_PSP_reg();
	pr_info("psp: ip 0x%08llx, ind %llx size %llx\n",
		(u64)PSP_BASE(psp), (u64)PSP_IND(psp), (u64)PSP_SIZE(psp));
	pcsp = read_PCSP_reg();
	pr_info("pcsp: base 08%llx, size 08%llx, ind 08%llx\n",
		(u64)PCSP_BASE(pcsp), (u64)PCSP_SIZE(pcsp), (u64)PCSP_IND(pcsp));
	cr0 = read_CR0_reg();
	pr_info("cr0 : ip %llx\n", get_cr0_ip(cr0));
	cr1 = read_CR1_reg();
	pr_info("cr1 : rbs %x, rsz %x, rcur %x, psz %x,\n"
		"pcur %x, ussz %llx, wpsz %x, wbs %x, psr %x\n",
		cr1.rbs, cr1.rsz, cr1.rcur, cr1.psz, cr1.pcur,
		get_cr1_ussz(cr1), cr1.wpsz, cr1.wbs, cr1.psr);
	pr_info("wd %llx\n", read_WD_reg().word);
}

static inline void print_USD(char *prolog, e2k_usd_t usd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		pr_info("%s: USD: base 0x%llx, ind 0x%llx, size 0x%llx. lo:hi 0x%llx : 0x%llx\n",
			prolog, USD_BASE(usd), USD_IND(usd), USD_SIZE_V7(usd), LO(usd), HI(usd));
	} else {
		pr_info("%s: USD: base 0x%llx, ind 0x%llx. lo:hi 0x%llx : 0x%llx\n",
			prolog, USD_BASE(usd), USD_IND(usd), LO(usd), HI(usd));
	}
}


extern e2k_addr_t print_user_address_ptes(struct mm_struct *mm, e2k_addr_t address);

/*
 * Set instruction data breakpoint at virtual address @addr.
 *
 * NOTE: breakpoint is set only for the current thread!
 * To set it for the whole system, remove restoring of
 * debug registers on a task switch.
 */
static inline int set_hardware_instr_breakpoint(u64 addr,
		const int stop, const int cp_num, const int v)
{
	e2k_dibcr_t dibcr = read_DIBCR_reg();
	e2k_dibsr_t dibsr;
	u64 dibar = (u64) addr;

	switch (cp_num) {
	case 0:
		write_DIBAR0_reg(dibar);
		dibcr.v0 = !!v;
		dibcr.t0 = 1ULL;
		break;
	case 1:
		write_DIBAR1_reg(dibar);
		dibcr.v1 = !!v;
		dibcr.t1 = 1ULL;
		break;
	case 2:
		write_DIBAR2_reg(dibar);
		dibcr.v2 = !!v;
		dibcr.t2 = 1ULL;
		break;
	case 3:
		write_DIBAR3_reg(dibar);
		dibcr.v3 = !!v;
		dibcr.t3 = 1ULL;
		break;
	default:
		if (__builtin_constant_p(cp_num))
			BUILD_BUG();
		return -EINVAL;
	}

	dibcr.stop = !!stop;

	dibsr.word = read_DIBSR_reg().word & ~E2K_DIBSR_MASK(cp_num);

	write_DIBCR_reg(dibcr);
	write_DIBSR_reg(dibsr);

	return 0;
}


/*
 * Set hardware data breakpoint at virtual address @addr.
 *
 * NOTE: breakpoint is set only for the current thread!
 * To set it for the whole system, remove restoring of
 * debug registers on a task switch.
 */
static inline int set_hardware_data_breakpoint(u64 addr, u64 size,
		int write, int read, int stop, int cp_num, int v)
{
	u64 ddbcr, ddbsr;
	u64 ddbar = (u64) addr;

	switch (size) {
	case 1:
		size = 1;
		break;
	case 2:
		size = 2;
		break;
	case 4:
		size = 3;
		break;
	case 8:
		size = 4;
		break;
	case 16:
		size = 5;
		break;
	default:
		if (__builtin_constant_p(size))
			BUILD_BUG();
		return -EINVAL;
	}

	switch (cp_num) {
	case 0:
		WRITE_DDBAR0_REG_VALUE(ddbar);
		break;
	case 1:
		WRITE_DDBAR1_REG_VALUE(ddbar);
		break;
	case 2:
		WRITE_DDBAR2_REG_VALUE(ddbar);
		break;
	case 3:
		WRITE_DDBAR3_REG_VALUE(ddbar);
		break;
	default:
		if (__builtin_constant_p(cp_num))
			BUILD_BUG();
		return -EINVAL;
	}

	/* Rewrite only the requested breakpoint. */
	ddbcr = (
		 (!!v << 0)	/* enable */
		 | (0ULL << 1)	/* primary space */
		 | ((!!write) << 2)
		 | ((!!read) << 3)
		 | (size << 4)
		 | (1ULL << 7)	/* sync */
		 | (1ULL << 8)	/* speculative */
		 | (1ULL << 9)	/* ap */
		 | (1ULL << 10)	/* spill/fill */
		 | (1ULL << 11)	/* hardware */
		 | (1ULL << 12)	/* generate exc_data_debug */
		) << (cp_num * 14);
	ddbcr |= READ_DDBCR_REG_VALUE() & ~E2K_DDBCR_MASK(cp_num);

	ddbsr = READ_DDBSR_REG_VALUE() & ~E2K_DDBSR_MASK(cp_num);

	WRITE_DDBCR_REG_VALUE(ddbcr);
	WRITE_DDBSR_REG_VALUE(ddbsr);
	if (stop) {
		e2k_dibcr_t dibcr = read_DIBCR_reg();
		dibcr.stop = 1;
		write_DIBCR_reg(dibcr);
	}

	return 0;
}

static inline int reset_hardware_data_breakpoint(void *addr)
{
	u64 ddbcr;
	u64 ddbsr;
	u64 ddbar;
	int cp_num;

	ddbcr = READ_DDBCR_REG_VALUE();
	for (cp_num = 0; cp_num < 4; cp_num++, ddbcr >>= 14) {
		if (!(ddbcr & 0x1))	/* valid */
			continue;
		switch (cp_num) {
		case 0:
			ddbar = READ_DDBAR0_REG();
			break;
		case 1:
			ddbar = READ_DDBAR1_REG();
			break;
		case 2:
			ddbar = READ_DDBAR2_REG();
			break;
		case 3:
			ddbar = READ_DDBAR3_REG();
			break;
		default:
			if (__builtin_constant_p(cp_num))
				BUILD_BUG();
			return -EINVAL;
		}
		if ((ddbar & E2K_VA_MASK) == ((e2k_addr_t)addr & E2K_VA_MASK))
			break;
	}
	if (cp_num >= 4)
		return cp_num;

	/* Reset only the requested breakpoint. */
	ddbcr = READ_DDBCR_REG_VALUE() & (~(0x3FFFULL << (cp_num * 14)));
	ddbsr = READ_DDBSR_REG_VALUE() & (~(0x3FFFULL << (cp_num * 14)));
	mb();	/* wait for completion of all load/store in progress */
	WRITE_DDBCR_REG_VALUE(ddbcr);
	WRITE_DDBSR_REG_VALUE(ddbsr);

	switch (cp_num) {
	case 0:
		WRITE_DDBAR0_REG_VALUE(0);
		break;
	case 1:
		WRITE_DDBAR1_REG_VALUE(0);
		break;
	case 2:
		WRITE_DDBAR2_REG_VALUE(0);
		break;
	case 3:
		WRITE_DDBAR3_REG_VALUE(0);
		break;
	default:
		if (__builtin_constant_p(cp_num))
			BUILD_BUG();
		return -EINVAL;
	}

	return cp_num;
}

struct data_breakpoint_params {
	void *address;
	u64 size;
	int write;
	int read;
	int stop;
	int cp_num;
};
extern void nmi_set_hardware_data_breakpoint(struct data_breakpoint_params *params);
/**
 * set_hardware_data_breakpoint_on_each_cpu() - set hardware data breakpoint
 *                                              on every online cpu.
 * @addr: virtual address of the breakpoint.
 *
 * This uses non-maskable interrupts to set the breakpoint for the whole
 * system atomically. That is, by the time this function returns the
 * breakpoint will be set everywhere.
 */
#define set_hardware_data_breakpoint_on_each_cpu( \
		addr, sz, wr, rd, st, cp) \
({ \
	struct data_breakpoint_params params; \
	MAYBE_BUILD_BUG_ON((sz) != 1 && (sz) != 2 && (sz) != 4 \
			&& (sz) != 8 && (sz) != 16); \
	MAYBE_BUILD_BUG_ON((cp) != 0 && (cp) != 1 \
			&& (cp) != 2 && (cp) != 3); \
	params.address = (addr); \
	params.size = (sz); \
	params.write = (wr); \
	params.read = (rd); \
	params.stop = (st); \
	params.cp_num = (cp); \
	nmi_on_each_cpu(nmi_set_hardware_data_breakpoint, &params, 1, 0); \
})


extern int jtag_stop_var;
static inline void jtag_stop(void)
{
	set_hardware_data_breakpoint((u64) &jtag_stop_var,
				     sizeof(jtag_stop_var), 1, 0, 1, 3, 1);

	jtag_stop_var = 0;

	/* Wait for the hardware to stop us */
	wmb();
}


#include <asm/aau_regs_types.h>

/* print some aux. & AAU registers */
static inline void
print_aau_regs(char *str, e2k_aau_t *context, struct pt_regs *regs,
	       struct thread_info *ti)
{
	int i;
	bool old_iset;

	old_iset = (machine.native_iset_ver < E2K_ISET_V5);

	if (str)
		pr_info("%s\n", str);

	pr_info("\naasr register = 0x%x (state: %s, iab: %d, stb: %d)\n"
		"ctpr2          = 0x%llx\n"
		"lsr            = 0x%llx\n"
		"ilcr           = 0x%llx\n",
		AW(regs->aasr),
		aau_null(regs->aasr) ? "NULL" :
		aau_ready(regs->aasr) ? "READY" :
		aau_active(regs->aasr) ? "ACTIVE" :
		aau_stopped(regs->aasr) ? "STOPPED" :
						"undefined",
		regs->aasr.iab, regs->aasr.stb,
		LO(regs->ctpr2), regs->lsr, regs->ilcr);

	if (aau_stopped(regs->aasr)) {
		pr_info("aaldv          = 0x%llx\n"
			"aaldm          = 0x%llx\n",
			AW(context->aaldv), AW(context->aaldm));
	} else {
		/* AAU can be in active state in kernel - automatic
		 * stop by hardware upon trap enter does not work. */
		pr_info("AAU is not in STOPPED or ACTIVE states, AALDV and "
			"AALDM will not be printed\n");
	}

	if (regs->aasr.iab) {
		for (i = 0; i < 32; i++) {
			pr_info("aad[%d].hi = 0x%llx ", i,
				HI(context->aads[i]));
			pr_info("aad[%d].lo = 0x%llx\n", i,
				LO(context->aads[i]));
		}

		for (i = 0; i < 8; i++) {
			pr_info("aaincr[%d] = 0x%llx\n", i, (old_iset) ?
				(u32) context->aaincrs[i] :
				context->aaincrs[i]);
		}
		pr_info("aaincr_tags = 0x%x\n", context->aaincr_tags);

		for (i = 0; i < 16; i++) {
			pr_info("aaind[%d] = 0x%llx\n", i, (old_iset) ?
				(u64) (u32) context->aainds[i] :
				context->aainds[i]);
		}
		pr_info("aaind_tags = 0x%x\n", context->aaind_tags);
	} else {
		pr_info("IAB flag in AASR is not set, following registers "
			"will not be printed: AAD, AAIND, AAIND_TAGS, "
			"AAINCR, AAINCR_TAGS\n");
	}

	if (regs->aasr.stb) {
		for (i = 0; i < 16; i++) {
			pr_info("aasti[%d] = 0x%llx\n", i, (old_iset) ?
				(u64) (u32) context->aastis[i] :
				context->aastis[i]);
		}
		pr_info("aasti_tags = 0x%x\n", context->aasti_tags);
	} else {
		pr_info("STB flag in AASR is not set, following registers\n"
			"will not be printed: AASTI, AASTI_TAGS\n");
	}

	if (ti) {
		for (i = 0; i < 32; i++) {
			pr_info("aaldi[%d] = 0x%llx ", i, (old_iset) ?
				(u64) (u32) context->aaldi[i] :
				context->aaldi[i]);
			pr_info("aaldi[%d] = 0x%llx\n", i + 32, (old_iset) ?
				(u64) (u32) context->aaldi[i + 32] :
				context->aaldi[i + 32]);
		}

		for (i = 0; i < 32; i++) {
			pr_info("aalda[%d] = 0x%x ", i, AW(ti->aalda[i]));
			pr_info("aalda[%d] = 0x%x\n", i + 32,
				AW(ti->aalda[i + 32]));
		}
	}

	pr_info("aafstr = 0x%x\n", read_aafstr_reg_value());
	pr_info("aafstr = 0x%x\n", context->aafstr);
}

#define	SIGDEBUG_PRINT(format, ...) \
do { \
	if (debug_signal) \
		pr_info("%s (pid=%d): " format, \
				current->comm, current->pid, ##__VA_ARGS__); \
} while (0)

extern void __debug_signal_print(const char *message,
				 struct pt_regs *regs, bool print_stack) __cold;

static inline void debug_signal_print(const char *message,
				      struct pt_regs *regs, bool print_stack)
{
	if (likely(!debug_signal))
		return;

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (TASK_IS_BINCO(current) && debug_signal == SIG_PF_DEBUG_NOBINCOMP)
		return;
#endif

	__debug_signal_print(message, regs, print_stack);
}

#endif /* _E2K_DEBUG_H_ */
