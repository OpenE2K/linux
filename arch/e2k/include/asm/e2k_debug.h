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
#include <asm/io.h>

#include <asm/lms.h>
#include <asm/e3m.h>
#include <asm/e2k.h>

#define	CHK_DEBUGGER(trapnr, signr, error_code, address, regs, after)

extern void print_running_tasks(int show_reg_window);
extern void print_stack(struct task_struct *task);
extern void print_stack_frames(struct task_struct *task,
		int show_reg_window, int skip);
extern void print_mmap(struct task_struct *task);
extern void print_va_tlb(e2k_addr_t addr, int large_page);
extern void print_task_pt_regs(pt_regs_t *pt_regs);
extern void print_all_TC(trap_cellar_t *TC, int TC_count);
extern void print_tc_record(trap_cellar_t *tcellar, int num);
extern void print_all_TIRs(e2k_tir_t *TIRs, u64 nr_TIRs);


/*
 * Parse the chain stack of @p backwards starting from
 * the last frame and call @func for every frame, passing
 * to it the frame contents, frame address and arguments
 * @arg1, @arg2 and @arg3.
 */
extern notrace void parse_chain_stack(struct task_struct *p,
		int (*func)(struct task_struct *, e2k_mem_crs_t *,
				unsigned long, void *, void *, void *),
		void *arg1, void *arg2, void *arg3);


extern	void	*kernel_symtab;
extern	long	kernel_symtab_size;
extern	void	*kernel_strtab;
extern	long	kernel_strtab_size;

#define	boot_kernel_symtab	boot_get_vo_value(kernel_symtab)
#define	boot_kernel_symtab_size	boot_get_vo_value(kernel_symtab_size)
#define	boot_kernel_strtab	boot_get_vo_value(kernel_strtab)
#define	boot_kernel_strtab_size	boot_get_vo_value(kernel_strtab_size)

/*
 * Input/Output
 */
static inline void e2k_outb(char c)
{
	printk("%c",c);
}
static inline void e2k_lms_outb(char c)
{
	outb(c, LMS_CONS_DATA_PORT);
}

static inline void
e2k_debug_outb(char c)
{
	if (BOOT_IS_MACHINE_SIM) {
		e2k_lms_outb(c);
	} else {
		e2k_outb(c);
	}
}

static inline void e2k_debug_putc(char c)
{
	e2k_debug_outb(c);
}

static inline void e2k_debug_puts(char *s)
{

	while (*s)
		e2k_debug_putc(*s++);
}

extern void rom_puts(char *s);
extern void rom_printk(char const *fmt, ...);

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
	register e2k_cr0_hi_t cr0_hi = (e2k_cr0_hi_t)E2K_GET_DSREG_NV(cr0.hi);
	register e2k_cr0_lo_t cr0_lo = (e2k_cr0_lo_t)E2K_GET_DSREG_NV(cr0.lo);
	register e2k_cr1_hi_t cr1_hi = (e2k_cr1_hi_t)E2K_GET_DSREG_NV(cr1.hi);
	register e2k_cr1_lo_t cr1_lo = (e2k_cr1_lo_t)E2K_GET_DSREG_NV(cr1.lo);
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
	printk("                cuir 0x%x wbs 0x%x wpsz %d wfx %d ein %d "
				"tr 0x%x\n",
		(int)AS_STRUCT(cr1_lo).cuir, (int)AS_STRUCT(cr1_lo).wbs,
		(int)AS_STRUCT(cr1_lo).wpsz, (int)AS_STRUCT(cr1_lo).wfx,
		(int)AS_STRUCT(cr1_lo).ein, (int)AS_STRUCT(cr1_lo).tr);
}

/*
 * Registers CPU
 */

#define	DebugCpuR(str)	if (DEBUG_CpuR_MODE) print_cpu_regs(str)
#define	DebugSPRs(POS)	if (DEBUG_SPRs_MODE) print_stack_pointers_reg(POS)
extern inline void
print_cpu_regs(char *str)
{
	printk("%s\n	%s", str, "CPU REGS value:\n");
	printk("usbr	 %lx\n", READ_SBR_REG_VALUE());
	printk("usd.hi.curptr %lx usd.hi.size %lx\n",
		READ_USD_HI_REG_VALUE() & 0xffffffff,
		(READ_USD_HI_REG_VALUE() >> 32) & 0xffffffff);
	printk("usd.lo.base 0x%lx\n",
		READ_USD_LO_REG_VALUE() & 0xffffffffffff);
	printk("psp.hi.ind %lx psp.hi.size %lx\n",
		READ_PSP_HI_REG_VALUE() & 0xffffffff,
		(READ_PSP_HI_REG_VALUE() >> 32) & 0xffffffff);
	printk("psp.lo	 %lx\n", READ_PSP_LO_REG_VALUE());
	printk("pcsp.hi.ind %lx pcsp.hi.size %lx\n",
		READ_PCSP_HI_REG_VALUE() & 0xffffffff,
		(READ_PCSP_HI_REG_VALUE() >> 32) & 0xffffffff);
	printk("pcsp.lo	 %lx\n", READ_PCSP_LO_REG_VALUE());
	printk("cr0.hi.ip %lx\n",
		E2K_GET_DSREG_NV(cr0.hi) & ~0x7UL);
	printk("cr1.hi.rbs %lx cr1.hi.rsz %lx\ncr1.hi.rcur %lx \
		cr1.hi.psz %lx cr1.hi.pcur %lx\ncr1.hi.ussz %lx\n",
		E2K_GET_DSREG_NV(cr1.hi) & 0x3f,
		(E2K_GET_DSREG_NV(cr1.hi)) >> 6  & 0x3f,
		(E2K_GET_DSREG_NV(cr1.hi)) >> 12 & 0x3f,
		(E2K_GET_DSREG_NV(cr1.hi)) >> 18 & 0x1f,
		(E2K_GET_DSREG_NV(cr1.hi)) >> 23 & 0x1f,
		(E2K_GET_DSREG_NV(cr1.hi)) >> 36 & 0xfffffff);
	printk("cr1.lo.wpsz %lx cr1.lo.wbs %lx cr1.lo.psr %lx\n",
		(E2K_GET_DSREG_NV(cr1.lo) >> 26) & 0x7f,
		(E2K_GET_DSREG_NV(cr1.lo) >> 33) & 0x7f,
		(E2K_GET_DSREG_NV(cr1.lo) >> 57) & 0x7);
	printk("wd %lx\n", E2K_GET_DSREG(wd));
}

extern inline void
print_stack_pointers_reg(char *point)
{
	register e2k_psp_hi_t	psp_hi = READ_PSP_HI_REG();
	register e2k_psp_lo_t	psp_lo = READ_PSP_LO_REG();
	register e2k_pcsp_hi_t	pcsp_hi = READ_PCSP_HI_REG();
	register e2k_pcsp_lo_t	pcsp_lo = READ_PCSP_LO_REG();
	register long		pshtp_reg = E2K_GET_DSREG(pshtp) & 0xffffUL;
	register long		pcshtp_reg = E2K_GET_DSREG(pcshtp) & 0xffffUL;

	printk("Stack pointer registers state");
	if (point != NULL)
		printk(" at %s :", point);
	printk("\n");
	printk("   USBR_base 0x%llx\n",
		READ_USBR_REG().USBR_base);
	printk("   USD_size 0x%x USD_p %d USD_base 0x%llx\n",
		READ_USD_HI_REG().USD_hi_size,
		READ_USD_LO_REG().USD_lo_p,
		READ_USD_LO_REG().USD_lo_base);

	printk("   PSP_size 0x%x PSP_ind 0x%x PSP_base 0x%lx PSHTP "
		"0x%llx (0x%lx)\n",
		psp_hi.PSP_hi_size,
		psp_hi.PSP_hi_ind, pshtp_reg,
		psp_lo.PSP_lo_base,
		(long)(psp_hi.PSP_hi_ind + pshtp_reg));
	if (psp_hi.PSP_hi_ind + pshtp_reg >= psp_hi.PSP_hi_size) {
		printk("PROCEDURE STACK OVERFLOW 0x%lx > size 0x%x\n",
			(long)(psp_hi.PSP_hi_ind + pshtp_reg),
			psp_hi.PSP_hi_size);
	}
	printk("   PCSP_size 0x%x PCSP_ind 0x%x PCSP_base 0x%lx "
		"PCSHTP 0x%llx (0x%lx)\n",
		pcsp_hi.PCSP_hi_size,
		pcsp_hi.PCSP_hi_ind, pcshtp_reg,
		pcsp_lo.PCSP_lo_base,
		(long)(pcsp_hi.PCSP_hi_ind + pcshtp_reg));

	DebugCRs(point);

}
/*
 * Print pt_regs
 */
extern inline void
print_pt_regs(char *str, pt_regs_t *pt_regs)
{
	e2k_br_t	br;
	e2k_psr_t	psr;

	printk("%s\n	%s", str, "PT_REGS value:\n");

	printk("pt_regs->sbr: %lx\n", pt_regs->stacks.sbr);
	printk("pt_regs->usd_lo: base %llx p %x\n", 
		AS_STRUCT(pt_regs->stacks.usd_lo).base,
		AS_STRUCT(pt_regs->stacks.usd_lo).p);

	printk("pt_regs->usd_hi: curptr  %x size %x\n", 
		pt_regs->stacks.usd_hi._USD_hi_curptr,
		pt_regs->stacks.usd_hi.USD_hi_size);
	
	printk("pt_regs->psp_lo: base %llx\n",
		AS_STRUCT(pt_regs->stacks.psp_lo).base);
	printk("pt_regs->psp_hi: ind %x size %x\n",
		AS_STRUCT(pt_regs->stacks.psp_hi).ind,
		AS_STRUCT(pt_regs->stacks.psp_hi).size);
	printk("pt_regs->pcsp_lo: base %llx\n",
		AS_STRUCT(pt_regs->stacks.pcsp_lo).base);
	printk("pt_regs->pcsp_hi: ind %x size %x\n",
		AS_STRUCT(pt_regs->stacks.pcsp_hi).ind,
		AS_STRUCT(pt_regs->stacks.pcsp_hi).size);

	printk("pt_regs->CR0.hi ip 0x%lx\n",
		(long)AS_STRUCT(pt_regs->crs.cr0_hi).ip << 3);
	printk("pt_regs->CR0.lo pf 0x%lx\n",
		(long)AS_STRUCT(pt_regs->crs.cr0_lo).pf);
	AS_WORD(br) = AS_STRUCT(pt_regs->crs.cr1_hi).br;
	printk("pt_regs->CR1.hi ussz 0x%x br 0x%x : rbs 0x%x rsz 0x%x "
		"rcur 0x%x psz 0x%x pcur 0x%x\n",
		(int)AS_STRUCT(pt_regs->crs.cr1_hi).ussz << 4,
		(int)AS_WORD(br), (int)AS_STRUCT(br).rbs,
		(int)AS_STRUCT(br).rsz, (int)AS_STRUCT(br).rcur,
		(int)AS_STRUCT(br).psz, (int)AS_STRUCT(br).pcur);
	AS_WORD(psr) = AS_STRUCT(pt_regs->crs.cr1_lo).psr;
	printk("pt_regs->CR1.lo: unmie %d nmie %d uie %d lw %d sge %d ie %d "
		"pm %d\n",
		(int)AS_STRUCT(psr).unmie,
		(int)AS_STRUCT(psr).nmie,
		(int)AS_STRUCT(psr).uie,
		(int)AS_STRUCT(psr).lw,
		(int)AS_STRUCT(psr).sge,
		(int)AS_STRUCT(psr).ie,
		(int)AS_STRUCT(psr).pm);
	printk("pt_regs->CR1.lo: cuir 0x%x wbs 0x%x wpsz %d wfx %d ein %d "
				"tr 0x%x\n",
		(int)AS_STRUCT(pt_regs->crs.cr1_lo).cuir,
		(int)AS_STRUCT(pt_regs->crs.cr1_lo).wbs,
		(int)AS_STRUCT(pt_regs->crs.cr1_lo).wpsz,
		(int)AS_STRUCT(pt_regs->crs.cr1_lo).wfx,
		(int)AS_STRUCT(pt_regs->crs.cr1_lo).ein,
		(int)AS_STRUCT(pt_regs->crs.cr1_lo).tr);
	printk("pt_regs->wd.base: %x wd.size %x wd.psize %x fx %x\n",
		AS_STRUCT(pt_regs->wd).base,
		AS_STRUCT(pt_regs->wd).size,
		AS_STRUCT(pt_regs->wd).psize,
		AS_STRUCT(pt_regs->wd).fx);
}

static inline int print_siginfo(siginfo_t *info, struct pt_regs *regs)
{
	pr_info("Signal #%d info structure:\n"
		"   errno %d code %d pid %d uid %d\n"
		"   trap #%d address 0x%p\n",
		info->si_signo, info->si_errno, info->si_code, info->si_pid,
		info->si_uid, info->si_trapno, info->si_addr);

	print_pt_regs("Signal pt_regs", regs);

	return 1;
}


/*
 * Print Switch Regs
 */
#define	DebugSWregs(POS, sw_regs) \
	if (DEBUG_SWREGS_MODE) print_sw_regs(POS, sw_regs)

extern inline void
print_sw_regs(char *point, sw_regs_t *sw_regs)
{
	printk("%s\n", point);
	printk("sbr: %lx\n", sw_regs->sbr);
	printk("usd_lo: %llx\n", AS_WORD(sw_regs->usd_lo));
	printk("usd_hi: %llx\n", AS_WORD(sw_regs->usd_hi));
	printk("psp_lo: %llx\n", AS_WORD(sw_regs->psp_lo));
	printk("psp_hi: %llx\n", AS_WORD(sw_regs->psp_hi));
	printk("pcsp_lo: %llx\n", AS_WORD(sw_regs->pcsp_lo));
	printk("pcsp_hi: %llx\n", AS_WORD(sw_regs->pcsp_hi));
}


/*
 * Print PAGE_FAULT (TC TRAP_CELLAR)
 */

#define DebugTC(a, b) \
	if(DEBUG_PAGE_FAULT_MODE) print_tc_state(a, b);
#include <asm/mmu.h>
extern inline void print_tc_state(trap_cellar_t *tcellar, int num) {
	tc_fault_type_t ftype;
	tc_dst_t	dst ;
	tc_opcode_t	opcode;
	u64		data;
	u32		data_tag;

	AW(dst) = AS(tcellar->condition).dst;
	AW(opcode) = AS(tcellar->condition).opcode;
	AW(ftype) = AS(tcellar->condition).fault_type;

	E2K_LOAD_VAL_AND_TAGD(&tcellar->data, data, data_tag);
	
	printk("\n----------------------------"
	       "TRAP_CELLAR record #%d:"
	       "-----------------------------\n"
	       "address   = 0x%016lx\n"
	       "data      = 0x%016llx tag = 0x%x\n"
	       "condition = 0x%016lx:\n"
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


/* Set hardware data breakpoint at virtual address @addr.
 *
 * NOTE: breakpoint is set only for the current thread!
 * To set it for the whole system, remove restoring of
 * debug registers on a task switch.
 *
 * NOTE2: this function may lose breakpoints if executed
 * concurrently on several processors! Use spinlocks to counter. */
#define set_hardware_data_breakpoint(addr, size, write, read, stop, cp_num) \
({ \
	BUILD_BUG_ON((size) != 1 && (size) != 2 && (size) != 4 \
			&& (size) != 8 && (size) != 16); \
	BUILD_BUG_ON((cp_num) != 0 && (cp_num) != 1 \
			&& (cp_num) != 2 && (cp_num) != 3); \
	__set_hardware_data_breakpoint((void *) (addr), size, write, \
			read, stop, cp_num); \
})
static inline int __set_hardware_data_breakpoint(void *addr, u64 size,
		const int write, const int read,
		const int stop, const int cp_num)
{
	u64 ddbcr, ddbsr = 0, dibcr = (!!stop) << 9, dibsr = 0xfffff,
			ddbar = (u64) addr;

	switch (size) {
	case 1: size = 1; break;
	case 2: size = 2; break;
	case 4: size = 3; break;
	case 8: size = 4; break;
	case 16: size = 5; break;
	default: return -EINVAL;
	}

	switch (cp_num) {
	case 0: E2K_SET_MMUREG(ddbar0, ddbar); break;
	case 1: E2K_SET_MMUREG(ddbar1, ddbar); break;
	case 2: E2K_SET_MMUREG(ddbar2, ddbar); break;
	case 3: E2K_SET_MMUREG(ddbar3, ddbar); break;
	default: return -EINVAL;
	}

	ddbcr = (
		1UL /* enable*/
		| (0 << 1) /* primary space */
		| ((!!write) << 2)
		| ((!!read) << 3)
		| (size << 4)
		| (1 << 7) /* sync */
		| (1 << 8) /* speculative */
		| (1 << 9) /* ap */
		| (1 << 10) /* spill/fill */
		| (1 << 11) /* hardware */
		| (1 << 12) /* generate exc_data_debug */
	) << (cp_num * 14);

	/* Rewrite only the requested breakpoint. */
	ddbcr |= E2K_GET_MMUREG(ddbcr) & (~(0x3FFFULL << (cp_num * 14)));

	E2K_SET_MMUREG(ddbcr, ddbcr);
	E2K_SET_MMUREG(ddbsr, ddbsr);
	E2K_SET_DSREG(dibcr, dibcr);
	E2K_SET_DSREG(dibsr, dibsr);

	return 0;
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
static inline void jtag_stop()
{
	set_hardware_data_breakpoint(&jtag_stop_var, sizeof(jtag_stop_var),
				     1, 0, 1, 3);

	jtag_stop_var = 0;

	/* Wait for the hardware to stop us */
	wmb();
}


#ifdef CONFIG_USE_AAU
#define DebugAAU(str, context) \
	if(DEBUG_AR_MODE) print_aau_regs(str, context)
#include "asm/aau_regs.h"

/* print some aux. & AAU registers */
static inline void
print_aau_regs(char *str, e2k_aau_t *context, struct pt_regs *regs)
{
	int i;
	
	printk(str);
	
	printk("\naasr register = 0x%x (state: %s, iab: %d, stb: %d)\n"
		"ctpr2          = 0x%lx\n"
		"lsr            = 0x%lx\n"
		"ilcr           = 0x%lx\n",
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
		printk( "aaldv          = 0x%lx\n"
			"aaldm          = 0x%lx\n",
			AW(context->aaldv), AW(context->aaldm));
	} else {
		/* AAU can be in active state in kernel - automatic
		 * stop by hardware upon trap enter does not work. */
		printk("AAU is not in STOPPED or ACTIVE states, AALDV and "
			"AALDM will not be printed\n");
	}

	if (AS(context->aasr).iab) {
		for (i = 0; i < 32; i++) {
			printk("aad[%d].hi = 0x%lx ", i,
					AW(context->aads[i]).hi);
			printk("aad[%d].lo = 0x%lx\n", i,
					AW(context->aads[i]).lo);
		}

		for (i = 0; i < 8; i++)
			printk("aaincr[%d] = 0x%x \n", i, context->aaincrs[i]);
		printk("aaincr_tags = 0x%x \n", context->aaincr_tags);

		for (i = 0; i < 16; i++)
			printk("aaind[%d] = 0x%x \n", i, context->aainds[i]);
		printk("aaind_tags = 0x%x \n", context->aaind_tags);
	} else {
		printk("IAB flag in AASR is not set, following registers "
			"will not be printed: AAD, AAIND, AAIND_TAGS, "
			"AAINCR, AAINCR_TAGS\n");
	}

	if (AS(context->aasr).stb) {
		for (i = 0; i < 16; i++)
			printk("aasti[%d] = 0x%x\n", i, context->aastis[i]);
		printk("aasti_tags = 0x%x\n", context->aasti_tags);
	} else {
		printk("STB flag in AASR is not set, following registers "
				"will not be printed: AASTI, AASTI_TAGS\n");
	}

	for (i = 0; i < 32; i++) {
		printk("aaldi[%d] = 0x%x ",i, context->aaldi[i]);
		printk("aaldi[%d] = 0x%x \n",i+32, context->aaldi[i+32]);
	}

	for (i = 0; i < 32; i++) {
		printk("aalda[%d] = 0x%x ", i, AW(context->aalda[i]));
		printk("aalda[%d] = 0x%x\n", i+32, AW(context->aalda[i+32]));
	}
	
	printk("aafstr = 0x%x \n", E2K_GET_AAUREG(aafstr, 5));
	printk("aafstr = 0x%x \n", context->aafstr);
}
#endif /* CONFIG_USE_AAU */

extern int debug_signal;
#define	SIGDEBUG_PRINT(format, ...) \
do { \
	if (debug_signal) \
		pr_info("%s (pid=%d): " format, \
				current->comm, current->pid ,##__VA_ARGS__); \
} while (0)

#endif	/* !(__ASSEMBLY__) */

#endif /* _E2K_DEBUG_H_ */
