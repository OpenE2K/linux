/*
 * asm-e2k/e2k_debug.h
 */
#ifndef _E2K_DEBUG_H_
#define _E2K_DEBUG_H_

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/kernel.h>

#include <asm/debug_print.h>
#include <asm/boot_profiling.h>
#include <asm/mas.h>
#include <asm/cpu_regs_access.h>
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

#define	CHK_DEBUGGER(trapnr, signr, error_code, address, regs, after)

extern void print_stack_frames(struct task_struct *task,
		struct pt_regs *pt_regs, int show_reg_window) __cold;
extern void print_mmap(struct task_struct *task) __cold;
extern void print_va_tlb(e2k_addr_t addr, int large_page) __cold;
extern void print_all_TC(const trap_cellar_t *TC, int TC_count) __cold;
extern void print_tc_record(const trap_cellar_t *tcellar, int num) __cold;
extern u64 print_all_TIRs(const e2k_tir_t *TIRs, u64 nr_TIRs) __cold;
extern void print_address_page_tables(unsigned long address,
		int last_level_only) __cold;
extern void print_pt_regs(const pt_regs_t *regs) __cold;

__init extern void setup_stack_print(void);

static inline void print_address_tlb(unsigned long address)
{
	print_va_tlb(address, 0);
	print_va_tlb(pte_virt_offset(round_down(address, PTE_SIZE)), 0);
	print_va_tlb(pmd_virt_offset(round_down(address, PMD_SIZE)), 0);
	print_va_tlb(pud_virt_offset(round_down(address, PUD_SIZE)), 0);
}

/**
 * *parse_chain_fn_t - function to be called on every frame in chain stack
 * @crs - contents of current frame in chain stack
 * @real_frame_addr - real address of current frame, can be used to modify frame
 * @corrected_frame_addr - address of current frame where it would be in stack
 * @flags - PCF_FLUSH_NEEDED if chain stack flush is needed before modifying,
 *	    PCF_IRQS_CLOSE_NEEDED if irqs should be closed before modifying
 * @arg - passed argument from parse_chain_stack()
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
 * IMPORTANT: if function wants to modify frame contents it must flush
 * chain stack if @flush_needed is set.
 */
#define PCF_FLUSH_NEEDED 0x1
#define PCF_IRQS_CLOSE_NEEDED 0x2
typedef int (*parse_chain_fn_t)(e2k_mem_crs_t *crs,
		unsigned long real_frame_addr,
		unsigned long corrected_frame_addr,
		int flags, void *arg);
#define PCS_USER 0x1
#define PCS_OPEN_IRQS 0x2
extern notrace int parse_chain_stack(int flags, struct task_struct *p,
				     parse_chain_fn_t func, void *arg);


extern	void	*kernel_symtab;
extern	long	kernel_symtab_size;
extern	void	*kernel_strtab;
extern	long	kernel_strtab_size;

#define	boot_kernel_symtab	boot_get_vo_value(kernel_symtab)
#define	boot_kernel_symtab_size	boot_get_vo_value(kernel_symtab_size)
#define	boot_kernel_strtab	boot_get_vo_value(kernel_strtab)
#define	boot_kernel_strtab_size	boot_get_vo_value(kernel_strtab_size)

#define NATIVE_IS_USER_ADDR(task, addr)		\
		(((e2k_addr_t)(addr)) < NATIVE_TASK_SIZE)
#define NATIVE_GET_PHYS_ADDR(task, addr)	\
({									\
	e2k_addr_t phys;						\
	if (NATIVE_IS_USER_ADDR(task, addr))				\
		phys = (unsigned long)user_address_to_pva(task, addr);	\
	else								\
		phys = (unsigned long)kernel_address_to_pva(addr);	\
	phys;								\
})

/* Read instruction word (two syllables) from IP address */
static inline unsigned long
native_read_instr_on_IP(e2k_addr_t ip, e2k_addr_t phys_ip)
{
	return NATIVE_READ_MAS_D(phys_ip, MAS_LOAD_PA);
}
/* Write modified instruction word at IP address */
static inline void
native_modify_instr_on_IP(e2k_addr_t ip, e2k_addr_t phys_ip,
				unsigned long instr_word)
{
	NATIVE_WRITE_MAS_D(phys_ip, instr_word, MAS_STORE_PA);
}

#define SIZE_PSP_STACK (16 * 4096)
#define DATA_STACK_PAGES 16
#define SIZE_DATA_STACK (DATA_STACK_PAGES * PAGE_SIZE)

#define SIZE_CHAIN_STACK KERNEL_PC_STACK_SIZE

/* Maximum number of user windows where a trap occured
 * for which additional registers will be printed (ctpr's, lsr and ilcr). */
#define MAX_USER_TRAPS 12

/* Maximum number of pt_regs being marked as such
 * when showing kernel data stack */
#define MAX_PT_REGS_SHOWN 30

typedef struct printed_trap_regs {
	bool valid;
	u64 frame;
	e2k_ctpr_t ctpr1;
	e2k_ctpr_t ctpr2;
	e2k_ctpr_t ctpr3;
	e2k_ctpr_hi_t ctpr1_hi;
	e2k_ctpr_hi_t ctpr2_hi;
	e2k_ctpr_hi_t ctpr3_hi;
	u64 lsr;
	u64 ilcr;
	u64 lsr1;
	u64 ilcr1;
	u64 sbbp[SBBP_ENTRIES_NUM];
} printed_trap_regs_t;

typedef struct stack_regs {
	bool used;
	bool valid;
	bool ignore_banner;
	struct task_struct *task;
	e2k_mem_crs_t crs;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_psp_lo_t psp_lo;
	e2k_psp_hi_t psp_hi;
	void *base_psp_stack;
	u64 user_size_psp_stack;
	u64 orig_base_psp_stack_u;
	u64 orig_base_psp_stack_k;
	void *psp_stack_cache;
	u64 size_psp_stack;
	bool show_trap_regs;
	bool show_user_regs;
	struct printed_trap_regs trap[MAX_USER_TRAPS];
#ifdef CONFIG_GREGS_CONTEXT
	struct global_regs gregs;
	bool gregs_valid;
#endif
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

extern void print_chain_stack(struct stack_regs *regs,
				int show_reg_window);

#ifndef	CONFIG_VIRTUALIZATION
/* it is native kernel without any virtualization */
#define GET_PHYS_ADDR(task, addr)	NATIVE_GET_PHYS_ADDR(task, addr)
#define	print_all_guest_stacks()	/* nothing to do */
#define	print_guest_vcpu_stack(vcpu)	/* nothing to do */
#define	debug_guest_regs(task)		false	/* none any guests */
#define	get_cpu_type_name()		"CPU"	/* real CPU */

/* Read instruction word (two syllables) from IP address */
static inline unsigned long
read_instr_on_IP(e2k_addr_t ip, e2k_addr_t phys_ip)
{
	return native_read_instr_on_IP(ip, phys_ip);
}
/* Write modified instruction word at IP address */
static inline void
modify_instr_on_IP(e2k_addr_t ip, e2k_addr_t phys_ip,
				unsigned long instr_word)
{
	native_modify_instr_on_IP(ip, phys_ip, instr_word);
}
static inline void
print_guest_stack(struct task_struct *task,
		stack_regs_t *const regs, bool show_reg_window)
{
	return;
}
static inline void
host_ftrace_stop(void)
{
	return;
}
static inline void
host_ftrace_dump(void)
{
	return;
}
#else	/* CONFIG_VIRTUALIZATION */
/* it is native host kernel with virtualization support */
/* or it is paravirtualized host/guest kernel */
/* or it is native guest kernel */
#include <asm/kvm/debug.h>
#endif	/* ! CONFIG_VIRTUALIZATION */

/*
 * Print Chain Regs CR0 and CR1
 */
#undef	DEBUG_CRs_MODE
#undef	DebugCRs
#define	DEBUG_CRs_MODE		0
#define	DebugCRs(POS)		if (DEBUG_CRs_MODE) print_chain_stack_regs(POS)
extern inline void
print_chain_stack_regs(char *point)
{
	register e2k_cr0_hi_t cr0_hi = READ_CR0_HI_REG();
	register e2k_cr0_lo_t cr0_lo = READ_CR0_LO_REG();
	register e2k_cr1_hi_t cr1_hi = READ_CR1_HI_REG();
	register e2k_cr1_lo_t cr1_lo = READ_CR1_LO_REG();
	register e2k_psr_t psr;

	printk("Procedure chain registers state");
	if (point != NULL)
		printk(" at %s :", point);
	printk("\n");

	printk("        CR0.hi ip 0x%lx\n", (long)AS_STRUCT(cr0_hi).ip << 3);
	printk("        CR0.lo pf 0x%lx\n", (long)AS_STRUCT(cr0_lo).pf);
	printk("        CR1.hi ussz 0x%x br 0x%x\n",
		(int)AS_STRUCT(cr1_hi).ussz << 4, (int)AS_STRUCT(cr1_hi).br);
	AS_WORD(psr) = AS_STRUCT(cr1_lo).psr;
	printk("        CR1.lo: unmie %d nmie %d uie %d lw %d sge %d ie %d "
		"pm %d\n",
		(int)AS_STRUCT(psr).unmie,
		(int)AS_STRUCT(psr).nmie,
		(int)AS_STRUCT(psr).uie,
		(int)AS_STRUCT(psr).lw,
		(int)AS_STRUCT(psr).sge,
		(int)AS_STRUCT(psr).ie,
		(int)AS_STRUCT(psr).pm);
	printk("                cuir 0x%x wbs 0x%x wpsz %d wfx %d ein %d\n",
		(int)AS_STRUCT(cr1_lo).cuir, (int)AS_STRUCT(cr1_lo).wbs,
		(int)AS_STRUCT(cr1_lo).wpsz, (int)AS_STRUCT(cr1_lo).wfx,
		(int)AS_STRUCT(cr1_lo).ein);
}

/*
 * Registers CPU
 */

#define	DebugCpuR(str)	if (DEBUG_CpuR_MODE) print_cpu_regs(str)
#define	DebugSPRs(POS)	if (DEBUG_SPRs_MODE) print_stack_pointers_reg(POS)
static inline void
print_cpu_regs(char *str)
{
	pr_info("%s\n	%s", str, "CPU REGS value:\n");
	pr_info("usbr	 %llx\n", READ_SBR_REG_VALUE());
	pr_info("usd.hi.curptr %llx usd.hi.size %llx\n",
		READ_USD_HI_REG_VALUE() & 0xffffffff,
		(READ_USD_HI_REG_VALUE() >> 32) & 0xffffffff);
	pr_info("usd.lo.base 0x%llx\n",
		READ_USD_LO_REG_VALUE() & 0xffffffffffff);
	pr_info("psp.hi.ind %llx psp.hi.size %llx\n",
		READ_PSP_HI_REG_VALUE() & 0xffffffff,
		(READ_PSP_HI_REG_VALUE() >> 32) & 0xffffffff);
	pr_info("psp.lo	 %llx\n", READ_PSP_LO_REG_VALUE());
	pr_info("pcsp.hi.ind %llx pcsp.hi.size %llx\n",
		READ_PCSP_HI_REG_VALUE() & 0xffffffff,
		(READ_PCSP_HI_REG_VALUE() >> 32) & 0xffffffff);
	pr_info("pcsp.lo	 %llx\n", READ_PCSP_LO_REG_VALUE());
	pr_info("cr0.hi.ip %llx\n",
		READ_CR0_HI_REG_VALUE() & ~0x7UL);
	pr_info("cr1.hi.rbs %llx cr1.hi.rsz %llx\ncr1.hi.rcur %llx "
		"cr1.hi.psz %llx cr1.hi.pcur %llx\ncr1.hi.ussz %llx\n",
		READ_CR1_HI_REG_VALUE() & 0x3f,
		READ_CR1_HI_REG_VALUE() >> 6  & 0x3f,
		READ_CR1_HI_REG_VALUE() >> 12 & 0x3f,
		READ_CR1_HI_REG_VALUE() >> 18 & 0x1f,
		READ_CR1_HI_REG_VALUE() >> 23 & 0x1f,
		READ_CR1_HI_REG_VALUE() >> 36 & 0xfffffff);
	pr_info("cr1.lo.wpsz %llx cr1.lo.wbs %llx cr1.lo.psr %llx\n",
		(READ_CR1_LO_REG_VALUE() >> 26) & 0x7f,
		(READ_CR1_LO_REG_VALUE() >> 33) & 0x7f,
		(READ_CR1_LO_REG_VALUE() >> 57) & 0x7);
	pr_info("wd %llx\n", READ_WD_REG_VALUE());
}

extern inline void
print_stack_pointers_reg(char *point)
{
	register e2k_psp_hi_t	psp_hi = READ_PSP_HI_REG();
	register e2k_psp_lo_t	psp_lo = READ_PSP_LO_REG();
	register e2k_pcsp_hi_t	pcsp_hi = READ_PCSP_HI_REG();
	register e2k_pcsp_lo_t	pcsp_lo = READ_PCSP_LO_REG();
	register long		pshtp_reg = READ_PSHTP_REG_VALUE() &
						0xffffUL;
	register long		pcshtp_reg = READ_PCSHTP_REG_SVALUE() &
						0xffffUL;

	pr_info("Stack pointer registers state");
	if (point != NULL)
		pr_info(" at %s :", point);
	pr_info("\n");
	pr_info("   USBR_base 0x%llx\n",
		READ_USBR_REG().USBR_base);
	pr_info("   USD_size 0x%x USD_p %d USD_base 0x%llx\n",
		READ_USD_HI_REG().USD_hi_size,
		READ_USD_LO_REG().USD_lo_p,
		READ_USD_LO_REG().USD_lo_base);

	pr_info("   PSP_size 0x%x PSP_ind 0x%x PSP_base 0x%lx PSHTP "
		"0x%llx (0x%lx)\n",
		psp_hi.PSP_hi_size,
		psp_hi.PSP_hi_ind, pshtp_reg,
		psp_lo.PSP_lo_base,
		(long)(psp_hi.PSP_hi_ind + pshtp_reg));
	if (psp_hi.PSP_hi_ind + pshtp_reg >= psp_hi.PSP_hi_size) {
		pr_info("PROCEDURE STACK OVERFLOW 0x%lx > size 0x%x\n",
			(long)(psp_hi.PSP_hi_ind + pshtp_reg),
			psp_hi.PSP_hi_size);
	}
	pr_info("   PCSP_size 0x%x PCSP_ind 0x%x PCSP_base 0x%lx "
		"PCSHTP 0x%llx (0x%lx)\n",
		pcsp_hi.PCSP_hi_size,
		pcsp_hi.PCSP_hi_ind, pcshtp_reg,
		pcsp_lo.PCSP_lo_base,
		(long)(pcsp_hi.PCSP_hi_ind + pcshtp_reg));

	DebugCRs(point);

}

static inline int print_siginfo(siginfo_t *info, struct pt_regs *regs)
{
	pr_info("Signal #%d info structure:\n"
		"   errno %d code %d pid %d uid %d\n"
		"   trap #%d address 0x%px\n",
		info->si_signo, info->si_errno, info->si_code, info->si_pid,
		info->si_uid, info->si_trapno, info->si_addr);

	print_pt_regs(regs);

	return 1;
}


/*
 * Print Switch Regs
 */
extern inline void
print_sw_regs(char *point, sw_regs_t *sw_regs)
{
	pr_info("%s\n", point);
	pr_info("top: %lx\n", sw_regs->top);
	pr_info("usd_lo: %llx\n", AS_WORD(sw_regs->usd_lo));
	pr_info("usd_hi: %llx\n", AS_WORD(sw_regs->usd_hi));
	pr_info("psp_lo: %llx\n", AS_WORD(sw_regs->psp_lo));
	pr_info("psp_hi: %llx\n", AS_WORD(sw_regs->psp_hi));
	pr_info("pcsp_lo: %llx\n", AS_WORD(sw_regs->pcsp_lo));
	pr_info("pcsp_hi: %llx\n", AS_WORD(sw_regs->pcsp_hi));
}

/*
 * Print PAGE_FAULT (TC TRAP_CELLAR)
 */

#define DebugTC(a, b) \
	if(DEBUG_PAGE_FAULT_MODE) print_tc_state(a, b);
#include <asm/mmu.h>
static inline void print_tc_state(const trap_cellar_t *tcellar, int num)
{
	tc_fault_type_t ftype;
	tc_dst_t	dst ;
	tc_opcode_t	opcode;
	u64		data;
	u8		data_tag;

	AW(dst) = AS(tcellar->condition).dst;
	AW(opcode) = AS(tcellar->condition).opcode;
	AW(ftype) = AS(tcellar->condition).fault_type;

	load_value_and_tagd(&tcellar->data, &data, &data_tag);

	printk("\n----------------------------"
	       "TRAP_CELLAR record #%d:"
	       "-----------------------------\n"
	       "address   = 0x%016lx\n"
	       "data      = 0x%016llx tag = 0x%x\n"
	       "condition = 0x%016llx:\n"
	       " dst    = 0x%05x: address = 0x%04x, vl   = 0x%x, vr = 0x%x\n"
	       " opcode = 0x%03x:   fmt     = 0x%02x,   npsp = 0x%x\n\n"
	       " store = 0x%x, s_f  = 0x%x, mas = 0x%x\n"
	       " root  = 0x%x, scal = 0x%x, sru = 0x%x\n"
	       " chan  = 0x%x, se   = 0x%x, pm  = 0x%x\n\n" 
	       " fault_type = 0x%x:\n"
	       "  intl_res_bits	   = %d MLT_trap         = %d\n"
	       "  ph_pr_page	   = %d page_bound       = %d\n"
	       "  io_page          = %d isys_page        = %d\n"
	       "  prot_page        = %d priv_page        = %d\n"
	       "  illegal_page     = %d nwrite_page      = %d\n"
	       "  page_miss        = %d ph_bound         = %d\n"
	       "  global_sp        = %d\n\n"
	       " miss_lvl = 0x%x, num_align = 0x%x, empt    = 0x%x\n"
	       " clw      = 0x%x, rcv       = 0x%x  dst_rcv = 0x%x\n"
	       "----------------------------------------------------"
	       "---------------------------\n", num,
	       tcellar->address,
		data, data_tag,
	       AW(tcellar->condition), 
	       (u32)AW(dst),(u32)(AS(dst).address), (u32)(AS(dst).vl), 
	       (u32)(AS(dst).vr),
	       (u32)AW(opcode), (u32)(AS(opcode).fmt),(u32)(AS(opcode).npsp), 
	       (u32)AS(tcellar->condition).store,
	       (u32)AS(tcellar->condition).s_f,
	       (u32)AS(tcellar->condition).mas,
	       (u32)AS(tcellar->condition).root,
	       (u32)AS(tcellar->condition).scal,
	       (u32)AS(tcellar->condition).sru,
	       (u32)AS(tcellar->condition).chan,
	       (u32)AS(tcellar->condition).spec,
	       (u32)AS(tcellar->condition).pm,
	       (u32)AS(tcellar->condition).fault_type,
	       (u32)AS(ftype).intl_res_bits,	(u32)(AS(ftype).exc_mem_lock),
	       (u32)AS(ftype).ph_pr_page,	(u32)AS(ftype).page_bound,
	       (u32)AS(ftype).io_page,		(u32)AS(ftype).isys_page,
	       (u32)AS(ftype).prot_page,	(u32)AS(ftype).priv_page,
	       (u32)AS(ftype).illegal_page,	(u32)AS(ftype).nwrite_page,
	       (u32)AS(ftype).page_miss,	(u32)AS(ftype).ph_bound,
	       (u32)AS(ftype).global_sp,
	       (u32)AS(tcellar->condition).miss_lvl, 
	       (u32)AS(tcellar->condition).num_align, 
	       (u32)AS(tcellar->condition).empt, 
	       (u32)AS(tcellar->condition).clw,
	       (u32)AS(tcellar->condition).rcv,
	       (u32)AS(tcellar->condition).dst_rcv);

}


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
	u64 dibcr, dibsr, dibar = (u64) addr;

	switch (cp_num) {
	case 0: WRITE_DIBAR0_REG_VALUE(dibar); break;
	case 1: WRITE_DIBAR1_REG_VALUE(dibar); break;
	case 2: WRITE_DIBAR2_REG_VALUE(dibar); break;
	case 3: WRITE_DIBAR3_REG_VALUE(dibar); break;
	default:
		if (__builtin_constant_p((cp_num)))
			BUILD_BUG();
		return -EINVAL;
	}

	/* Rewrite only the requested breakpoint. */
	dibcr = (
		!!(v) /* enable*/
		| (1ULL << 1) /* generate exc_instr_debug */
	) << (cp_num * 2);
	dibcr |= (!!stop << 9);
	dibcr |= READ_DIBCR_REG_VALUE() & ~E2K_DIBCR_MASK(cp_num);

	dibsr = READ_DIBSR_REG_VALUE() & ~E2K_DIBSR_MASK(cp_num);

	WRITE_DIBCR_REG_VALUE(dibcr);
	WRITE_DIBSR_REG_VALUE(dibsr);

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
		const int write, const int read,
		const int stop, const int cp_num, const int v)
{
	u64 ddbcr, ddbsr, ddbar = (u64) addr;

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
		if (__builtin_constant_p((size)))
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
		if (__builtin_constant_p((cp_num)))
			BUILD_BUG();
		return -EINVAL;
	}

	/* Rewrite only the requested breakpoint. */
	ddbcr = (
		!!(v) /* enable*/
		| (0ULL << 1) /* primary space */
		| ((!!write) << 2)
		| ((!!read) << 3)
		| (size << 4)
		| (1ULL << 7) /* sync */
		| (1ULL << 8) /* speculative */
		| (1ULL << 9) /* ap */
		| (1ULL << 10) /* spill/fill */
		| (1ULL << 11) /* hardware */
		| (1ULL << 12) /* generate exc_data_debug */
	) << (cp_num * 14);
	ddbcr |= READ_DDBCR_REG_VALUE() & ~E2K_DDBCR_MASK(cp_num);

	ddbsr = READ_DDBSR_REG_VALUE() & ~E2K_DDBSR_MASK(cp_num);

	WRITE_DDBCR_REG_VALUE(ddbcr);
	WRITE_DDBSR_REG_VALUE(ddbsr);
	if (stop) {
		e2k_dibcr_t dibcr;

		dibcr = READ_DIBCR_REG();
		AS(dibcr).stop = 1;
		WRITE_DIBCR_REG(dibcr);
	}

	return 0;
}

static inline int reset_hardware_data_breakpoint(void *addr)
{
	u64 ddbcr, ddbsr, ddbar;
	int cp_num;

	ddbcr = READ_DDBCR_REG_VALUE();
	for (cp_num = 0; cp_num < 4; cp_num++, ddbcr >>= 14) {
		if (!(ddbcr & 0x1))	/* valid */
			continue;
		switch (cp_num) {
		case 0:
			ddbar = READ_DDBAR0_REG_VALUE();
			break;
		case 1:
			ddbar = READ_DDBAR1_REG_VALUE();
			break;
		case 2:
			ddbar = READ_DDBAR2_REG_VALUE();
			break;
		case 3:
			ddbar = READ_DDBAR3_REG_VALUE();
			break;
		default:
			if (__builtin_constant_p((cp_num)))
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
		if (__builtin_constant_p((cp_num)))
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
extern void nmi_set_hardware_data_breakpoint(
		struct data_breakpoint_params *params);
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


#ifdef CONFIG_USE_AAU
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
		AW(context->aasr),
		AAU_NULL(context->aasr) ? "NULL" :
		AAU_READY(context->aasr) ? "READY" :
		AAU_ACTIVE(context->aasr) ? "ACTIVE" :
		AAU_STOPPED(context->aasr) ? "STOPPED":
						"undefined",
		AS(context->aasr).iab,
		AS(context->aasr).stb,
		AW(regs->ctpr2), regs->lsr, regs->ilcr);

	if (AAU_STOPPED(context->aasr)) {
		pr_info("aaldv          = 0x%llx\n"
			"aaldm          = 0x%llx\n",
			AW(context->aaldv), AW(context->aaldm));
	} else {
		/* AAU can be in active state in kernel - automatic
		 * stop by hardware upon trap enter does not work. */
		pr_info("AAU is not in STOPPED or ACTIVE states, AALDV and "
			"AALDM will not be printed\n");
	}

	if (AS(context->aasr).iab) {
		for (i = 0; i < 32; i++) {
			pr_info("aad[%d].hi = 0x%llx ", i,
					AW(context->aads[i]).hi);
			pr_info("aad[%d].lo = 0x%llx\n", i,
					AW(context->aads[i]).lo);
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

	if (AS(context->aasr).stb) {
		for (i = 0; i < 16; i++) {
			pr_info("aasti[%d] = 0x%llx\n", i, (old_iset) ?
					(u64) (u32) context->aastis[i] :
					context->aastis[i]);
		}
		pr_info("aasti_tags = 0x%x\n", context->aasti_tags);
	} else {
		pr_info("STB flag in AASR is not set, following registers "
				"will not be printed: AASTI, AASTI_TAGS\n");
	}

	if (ti) {
		for (i = 0; i < 32; i++) {
			pr_info("aaldi[%d] = 0x%llx ", i, (old_iset) ?
					(u64) (u32) context->aaldi[i] :
					context->aaldi[i]);
			pr_info("aaldi[%d] = 0x%llx\n", i+32, (old_iset) ?
					(u64) (u32) context->aaldi[i+32] :
					context->aaldi[i+32]);
		}

		for (i = 0; i < 32; i++) {
			pr_info("aalda[%d] = 0x%x ", i, AW(ti->aalda[i]));
			pr_info("aalda[%d] = 0x%x\n", i + 32,
				AW(ti->aalda[i+32]));
		}
	}

	pr_info("aafstr = 0x%x\n", read_aafstr_reg_value());
	pr_info("aafstr = 0x%x\n", context->aafstr);
}
#endif /* CONFIG_USE_AAU */

extern int debug_signal;
#define	SIGDEBUG_PRINT(format, ...) \
do { \
	if (debug_signal) \
		pr_info("%s (pid=%d): " format, \
				current->comm, current->pid, ##__VA_ARGS__); \
} while (0)

extern int debug_trap;

#endif	/* !(__ASSEMBLY__) */

#endif /* _E2K_DEBUG_H_ */
