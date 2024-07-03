/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file based on host functions to dump stack and some other
 * kernel structures. But host_printk() is used to output all these things
 * In some cases it allows to avoid the breaking problems into the output
 * subsystem of the kernel
 */

#include <stdarg.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/seq_buf.h>
#include <linux/delay.h>

#include <asm/e2k_debug.h>
#include <asm/unistd.h>
#include <asm/ptrace.h>
#include <asm/regs_state.h>
#include <asm/e2k.h>
#include <asm/process.h>
#include <asm/processor.h>
#include <asm/pci.h>
#include <asm/traps.h>
#include <asm/mmu_context.h>
#include <asm/host_printk.h>

static void host_print_chain_stack(struct stack_regs *regs, int show_rf_window);

/*
 * print_reg_window - print local registers from psp stack
 * @window_base - pointer to the window in psp stack
 * @window_size - size of the window in psp stack (in quadro registers)
 * @fx - do print extensions?
  */
static void print_reg_window(u64 window_base, int window_size,
		int fx, e2k_cr1_hi_t cr1_hi)
{
	int qreg, dreg, dreg_ind;
	u64 *rw = (u64 *)window_base;
	u64 qreg_lo, qreg_hi, ext_lo, ext_hi;
	u8 tag_lo, tag_hi, tag_ext_lo, tag_ext_hi;
	char brX0_name[6], brX1_name[6];
	u64 rbs, rsz, rcur;

	rbs = AS(cr1_hi).rbs;
	rsz = AS(cr1_hi).rsz;
	rcur = AS(cr1_hi).rcur;

	for (qreg = window_size - 1; qreg >= 0; qreg--) {
		dreg_ind = qreg * (EXT_4_NR_SZ / sizeof(*rw));

		load_value_and_tagd(&rw[dreg_ind + 0], &qreg_lo, &tag_lo);
		if (machine.native_iset_ver < E2K_ISET_V5) {
			load_value_and_tagd(&rw[dreg_ind + 1],
					&qreg_hi, &tag_hi);
			if (fx) {
				ext_lo = rw[dreg_ind + 2];
				ext_hi = rw[dreg_ind + 3];
			}
		} else {
			load_value_and_tagd(&rw[dreg_ind + 2],
					&qreg_hi, &tag_hi);
			if (fx) {
				load_value_and_tagd(&rw[dreg_ind + 1],
						&ext_lo, &tag_ext_lo);
				load_value_and_tagd(&rw[dreg_ind + 3],
						&ext_hi, &tag_ext_hi);
			}
		}

		dreg = qreg * 2;

		/* Calculate %br[] register number */
		if (qreg >= rbs && qreg <= (rbs + rsz) && rsz >= rcur) {
			int qbr, brX0, brX1;

			qbr = (qreg - rbs) + ((rsz + 1) - rcur);

			while (qbr > rsz)
				qbr -= rsz + 1;

			brX0 = 2 * qbr;
			brX1 = 2 * qbr + 1;

			snprintf(brX0_name, 7, "%sb%d/", (brX0 < 10) ? "  " :
					((brX0 < 100) ? " " : ""), brX0);
			snprintf(brX1_name, 7, "%sb%d/", (brX0 < 10) ? "  " :
					((brX0 < 100) ? " " : ""), brX1);
		} else {
			memset(brX0_name, ' ', 5);
			memset(brX1_name, ' ', 5);
			brX0_name[5] = 0;
			brX1_name[5] = 0;
		}

		if (fx) {
			if (machine.native_iset_ver < E2K_ISET_V5) {
				host_pr_alert("     %sr%-3d: %hhx 0x%016llx "
					"%04hx %sr%-3d: %hhx 0x%016llx %04hx\n",
					brX0_name, dreg, tag_lo, qreg_lo,
					(u16) ext_lo, brX1_name, dreg + 1,
					tag_hi, qreg_hi, (u16) ext_hi);
			} else {
				host_pr_alert("     %sr%-3d: %hhx 0x%016llx   "
					"ext: %hhx %016llx\n"
					"     %sr%-3d: %hhx 0x%016llx   ext: "
					"%hhx %016llx\n",
					brX1_name, dreg + 1, tag_hi, qreg_hi,
					tag_ext_hi, ext_hi, brX0_name, dreg,
					tag_lo, qreg_lo, tag_ext_lo, ext_lo);
			}
		} else {
			host_pr_alert("     %sr%-3d: %hhx 0x%016llx    "
				"%sr%-3d: %hhx 0x%016llx\n",
				brX0_name, dreg, tag_lo, qreg_lo,
				brX1_name, dreg + 1, tag_hi, qreg_hi);
		}
	}
}

static inline void print_predicates(e2k_cr0_lo_t cr0_lo, e2k_cr1_hi_t cr1_hi)
{
	u64 pf = AS(cr0_lo).pf;
	u64 i, values = 0, tags = 0;

	for (i = 0; i < 32; i++) {
		values |= (pf & (1ULL << 2 * i)) >> i;
		tags |= (pf & (1ULL << (2 * i + 1))) >> (i + 1);
	}
	host_pr_info("      predicates[31:0] %08x   ptags[31:0] %08x   "
		"psz %d   pcur %d\n",
		(u32) values, (u32) tags,
		cr1_hi.CR1_hi_psz, cr1_hi.CR1_hi_pcur);
}

u64 host_print_all_TIRs(const e2k_tir_t *TIRs, u64 nr_TIRs)
{
	e2k_tir_hi_t tir_hi;
	e2k_tir_lo_t tir_lo;
	u64 all_interrupts = 0;
	int i;

	host_printk("TIR all registers:\n");
	for (i = nr_TIRs; i >= 0; i--) {
		tir_hi = TIRs[i].TIR_hi;
		tir_lo = TIRs[i].TIR_lo;

		all_interrupts |= AW(tir_hi);

		host_pr_alert("TIR.hi[%d]: 0x%016llx : exc 0x%011llx al 0x%x "
			"aa 0x%x #%d\n",
			i, AW(tir_hi), tir_hi.exc, tir_hi.al,
			tir_hi.aa, tir_hi.j);

		if (tir_hi.exc) {
			u64 exc = tir_hi.exc;
			int nr_intrpt;

			host_pr_alert("  ");
			for (nr_intrpt = __ffs64(exc); exc != 0;
					exc &= ~(1UL << nr_intrpt),
					nr_intrpt = __ffs64(exc))
				host_pr_cont(" %s", exc_tbl_name[nr_intrpt]);
			host_pr_cont("\n");
		}

		host_pr_alert("TIR.lo[%d]: 0x%016llx : IP 0x%012llx\n",
			i, tir_lo.TIR_lo_reg, tir_lo.TIR_lo_ip);
	}

	return all_interrupts & (exc_all_mask | aau_exc_mask);
}

void host_print_tc_record(const trap_cellar_t *tcellar, int num)
{
	tc_fault_type_t ftype;
	tc_dst_t	dst;
	tc_opcode_t	opcode;
	u64		data;
	u8		data_tag;

	AW(dst) = AS(tcellar->condition).dst;
	AW(opcode) = AS(tcellar->condition).opcode;
	AW(ftype) = AS(tcellar->condition).fault_type;

	load_value_and_tagd(&tcellar->data, &data, &data_tag);
	/* FIXME: data has tag, but E2K_LOAD_TAGGED_DWORD() is privileged */
	/* action? guest will be trapped */
	if (!paravirt_enabled()) {
		load_value_and_tagd(&tcellar->data, &data, &data_tag);
	} else {
		data = tcellar->data;
		data_tag = 0;
	}
	host_printk("   record #%d: address 0x%016llx data 0x%016llx tag 0x%x\n"
		"              condition 0x%016llx:\n"
		"                 dst 0x%05x: address 0x%04x, vl %d, vr %d\n"
		"                 opcode 0x%03x: fmt 0x%02x, npsp 0x%x\n"
		"                 store 0x%x, s_f  0x%x, mas 0x%x\n"
		"                 root  0x%x, scal 0x%x, sru 0x%x\n"
		"                 chan  0x%x, se   0x%x, pm  0x%x\n"
		"                 fault_type 0x%x:\n"
		"                    intl_res_bits = %d MLT_trap     = %d\n"
		"                    ph_pr_page	   = %d global_sp    = %d\n"
		"                    io_page       = %d isys_page    = %d\n"
		"                    prot_page     = %d priv_page    = %d\n"
		"                    illegal_page  = %d nwrite_page  = %d\n"
		"                    page_miss     = %d ph_bound     = %d\n"
		"                 miss_lvl 0x%x, num_align 0x%x, empt    0x%x\n"
		"                 clw      0x%x, rcv       0x%x  dst_rcv 0x%x\n",
		num,
		(u64)tcellar->address, data, data_tag,
		(u64)AW(tcellar->condition),
		(u32)AW(dst), (u32)(AS(dst).address), (u32)(AS(dst).vl),
		(u32)(AS(dst).vr),
		(u32)AW(opcode), (u32)(AS(opcode).fmt), (u32)(AS(opcode).npsp),
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
		(u32)AS(ftype).ph_pr_page,	(u32)AS(ftype).global_sp,
		(u32)AS(ftype).io_page,		(u32)AS(ftype).isys_page,
		(u32)AS(ftype).prot_page,	(u32)AS(ftype).priv_page,
		(u32)AS(ftype).illegal_page,	(u32)AS(ftype).nwrite_page,
		(u32)AS(ftype).page_miss,	(u32)AS(ftype).ph_bound,
		(u32)AS(tcellar->condition).miss_lvl,
		(u32)AS(tcellar->condition).num_align,
		(u32)AS(tcellar->condition).empt,
		(u32)AS(tcellar->condition).clw,
		(u32)AS(tcellar->condition).rcv,
		(u32)AS(tcellar->condition).dst_rcv);
}

void host_print_all_TC(const trap_cellar_t *TC, int TC_count)
{
	int i;

	if (!TC_count)
		return;

	host_printk("TRAP CELLAR all %d records:\n", TC_count / 3);
	for (i = 0; i < TC_count / 3; i++)
		print_tc_record(&TC[i], i);
}

/*
 * Print pt_regs
 */
void host_print_pt_regs(const pt_regs_t *regs)
{
	const e2k_mem_crs_t *crs = &regs->crs;

	if (!regs)
		return;

	host_pr_info("	PT_REGS value:\n");

	host_pr_info("usd: base 0x%llx, size 0x%x, p %d, sbr: 0x%lx\n",
		regs->stacks.usd_lo.USD_lo_base,
		regs->stacks.usd_hi.USD_hi_size, regs->stacks.usd_lo.USD_lo_p,
		regs->stacks.top);

	host_pr_info("psp: base %llx, ind %x, size %x\n",
		AS(regs->stacks.psp_lo).base,
		AS(regs->stacks.psp_hi).ind, AS(regs->stacks.psp_hi).size);
	host_pr_info("pcsp: base %llx, ind %x, size %x\n",
		AS(regs->stacks.pcsp_lo).base,
		AS(regs->stacks.pcsp_hi).ind, AS(regs->stacks.pcsp_hi).size);

	host_pr_info("cr0.lo: pf 0x%llx, cr0.hi: ip 0x%llx\n",
		AS(crs->cr0_lo).pf, AS(crs->cr0_hi).ip << 3);
	host_pr_info("cr1.lo: unmie %d, nmie %d, uie %d, lw %d, sge %d, "
		"ie %d, pm %d\n"
		"        cuir 0x%x, wbs 0x%x, wpsz 0x%x, wfx %d, ss %d, "
		"ein %d\n",
		AS(crs->cr1_lo).unmie, AS(crs->cr1_lo).nmie,
		AS(crs->cr1_lo).uie,
		AS(crs->cr1_lo).lw, AS(crs->cr1_lo).sge, AS(crs->cr1_lo).ie,
		AS(crs->cr1_lo).pm, AS(crs->cr1_lo).cuir, AS(crs->cr1_lo).wbs,
		AS(crs->cr1_lo).wpsz, AS(crs->cr1_lo).wfx, AS(crs->cr1_lo).ss,
		AS(crs->cr1_lo).ein);
	host_pr_info("cr1.hi: ussz 0x%x, wdbl %d\n"
		"        rbs 0x%x, rsz 0x%x, rcur 0x%x, psz 0x%x, pcur 0x%x\n",
		AS(crs->cr1_hi).ussz, AS(crs->cr1_hi).wdbl, AS(crs->cr1_hi).rbs,
		AS(crs->cr1_hi).rsz, AS(crs->cr1_hi).rcur, AS(crs->cr1_hi).psz,
		AS(crs->cr1_hi).pcur);
	host_pr_info("WD: base 0x%x, size 0x%x, psize 0x%x, fx %d, dbl %d\n",
		regs->wd.base, regs->wd.size, regs->wd.psize, regs->wd.fx,
		regs->wd.dbl);
	if (from_syscall(regs)) {
		host_pr_info("regs->kernel_entry: %d, syscall #%d\n",
			regs->kernel_entry, regs->sys_num);
	} else {
		const struct trap_pt_regs *trap = regs->trap;
		u64 exceptions;

		host_pr_info("ctpr1: base 0x%llx, tag 0x%x, opc 0x%x, "
			"ipd 0x%x\n",
			AS(regs->ctpr1).ta_base, AS(regs->ctpr1).ta_tag,
			AS(regs->ctpr1).opc, AS(regs->ctpr1).ipd);
		host_pr_info("ctpr2: base 0x%llx, tag 0x%x, opcode 0x%x, "
			"prefetch 0x%x\n",
			AS(regs->ctpr2).ta_base, AS(regs->ctpr2).ta_tag,
			AS(regs->ctpr2).opc, AS(regs->ctpr2).ipd);
		host_pr_info("ctpr3: base 0x%llx, tag 0x%x, opcode 0x%x, "
			"prefetch 0x%x\n",
			AS(regs->ctpr3).ta_base, AS(regs->ctpr3).ta_tag,
			AS(regs->ctpr3).opc, AS(regs->ctpr3).ipd);
		host_pr_info("regs->trap: 0x%px\n", regs->trap);
#ifdef CONFIG_USE_AAU
		host_pr_info("AAU context at 0x%px\n", regs->aau_context);
#endif

		exceptions = print_all_TIRs(trap->TIRs, trap->nr_TIRs);
		print_all_TC(trap->tcellar, trap->tc_count);
		if (exceptions & exc_data_debug_mask) {
			host_pr_info("ddbcr 0x%llx, ddmcr 0x%llx, "
				"ddbsr 0x%llx\n",
				READ_DDBCR_REG_VALUE(), READ_DDMCR_REG_VALUE(),
				READ_DDBSR_REG_VALUE());
			host_pr_info("ddbar0 0x%llx, ddbar1 0x%llx, "
				"ddbar2 0x%llx, ddbar3 0x%llx\n",
				READ_DDBAR0_REG_VALUE(),
				READ_DDBAR1_REG_VALUE(),
				READ_DDBAR2_REG_VALUE(),
				READ_DDBAR3_REG_VALUE());
			host_pr_info("ddmar0 0x%llx, ddmar1 0x%llx\n",
				READ_DDMAR0_REG_VALUE(),
				READ_DDMAR1_REG_VALUE());
		}
		if (exceptions & exc_instr_debug_mask) {
			host_pr_info("dibcr 0x%x, dimcr 0x%llx, dibsr 0x%x\n",
				READ_DIBCR_REG_VALUE(),
				READ_DIMCR_REG_VALUE(),
				READ_DIBSR_REG_VALUE());
			host_pr_info("dibar0 0x%llx, dibar1 0x%llx, "
				"dibar2 0x%llx, dibar3 0x%llx\n",
				READ_DIBAR0_REG_VALUE(),
				READ_DIBAR1_REG_VALUE(),
				READ_DIBAR2_REG_VALUE(),
				READ_DIBAR3_REG_VALUE());
			host_pr_info("dimar0 0x%llx, dimar1 0x%llx\n",
				READ_DIMAR0_REG_VALUE(),
				READ_DIMAR1_REG_VALUE());
		}
	}
}

static int get_addr_name(u64 addr, char *buf, size_t len,
		unsigned long *start_addr_p, struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	int ret = 0, locked;

	if (addr >= TASK_SIZE || !mm)
		return -ENOENT;

	/*
	 * This function is used when everything goes south
	 * so do not try too hard to lock mmap_lock
	 */
	locked = mmap_read_trylock(mm);

	vma = find_vma(mm, addr);
	if (!vma || vma->vm_start > addr || !vma->vm_file) {
		ret = -ENOENT;
		goto out_unlock;
	}

	/* seq_buf_path() locks init_fs.seq which is normally
	 * locked with enabled interrupts, so we cannot reliably
	 * call it if we are in interrupt */
	if (!in_irq()) {
		struct seq_buf s;

		seq_buf_init(&s, buf, len);
		seq_buf_path(&s, &vma->vm_file->f_path, "\n");

		if (seq_buf_used(&s) < len)
			buf[seq_buf_used(&s)] = 0;
		else
			buf[len - 1] = 0;
	} else {
		buf[0] = 0;
	}

	/* Assume that load_base == vm_start */
	if (start_addr_p)
		*start_addr_p = vma->vm_start;

out_unlock:
	if (locked)
		mmap_read_unlock(mm);

	return ret;
}


static DEFINE_RAW_SPINLOCK(print_stack_lock);

/**
 * print_stack_frames - print task's stack to console
 * @task: which task's stack to print?
 * @pt_regs: skip stack on top of this pt_regs structure
 * @show_reg_window: print local registers?
 */
static noinline void
host_print_stack_frames(struct task_struct *task, struct pt_regs *pt_regs,
		   int show_reg_window)
{
	unsigned long flags;
	int cpu;
	bool used;
	struct stack_regs *stack_regs;

	/* if this is guest, stop tracing in host to avoid buffer overwrite */
	host_ftrace_stop();

	if (!task)
		task = current;

	if (test_and_set_bit(PRINT_FUNCY_STACK_WORKS_BIT,
			&task->thread.flags)) {
		host_pr_alert("  %d: print_stack: works already on pid %d\n",
				current->pid, task->pid);
		if (task != current)
			return;
	}

	/*
	 * stack_regs_cache[] is protected by IRQ-disable
	 * (we assume that NMI handlers will not call dump_stack() and
	 * do not disable NMIs here as they are used by copy_stack_regs())
	 */
	raw_local_irq_save(flags);

	if (task == current) {
		host_pr_alert("%s", linux_banner);
	}

	cpu = raw_smp_processor_id();
	stack_regs = &stack_regs_cache[cpu];

	used = xchg(&stack_regs->used, 1);
	if (used) {
		host_pr_alert("  %d: print stack: works already on cpu %d\n",
				current->pid, cpu);
	} else {
		stack_regs->show_trap_regs = debug_trap;
		stack_regs->show_user_regs = debug_userstack;
#ifdef CONFIG_DATA_STACK_WINDOW
		stack_regs->show_k_data_stack = debug_datastack;
#endif
		copy_stack_regs(task, pt_regs, stack_regs);

		/* All checks of stacks validity are
		 * performed in print_chain_stack() */

		host_print_chain_stack(stack_regs, show_reg_window);
	}

	/* if task is host of guest VM or VCPU, then print guest stacks */
	print_guest_stack(task, stack_regs, show_reg_window);

	stack_regs->used = 0;

	raw_local_irq_restore(flags);

	clear_bit(PRINT_FUNCY_STACK_WORKS_BIT, &task->thread.flags);
}

static inline void print_funcy_ip(u64 addr, u64 cr_base, u64 cr_ind,
			struct task_struct *task, u64 orig_base)
{
	unsigned long start_addr;
	char buf[64];
	int traced = 0;

	if (addr < TASK_SIZE) {
		if (!get_addr_name(addr, buf, sizeof(buf),
					&start_addr, task->mm)) {
			host_pr_alert("  0x%-12llx   %s (@0x%lx)\n", addr,
					buf, start_addr);
		} else {
			host_pr_alert("  0x%-12llx   <anonymous>\n", addr);
		}

		return;
	}

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (task->ret_stack) {
		int index;
		for (index = 0; index <= task->curr_ret_stack; index++)
			if (task->ret_stack[index].fp == orig_base + cr_ind) {
				addr = task->ret_stack[index].ret;
				traced = 1;
				break;
			}
	}
#endif

	host_pr_alert("  0x%-12llx   %pF%s", addr, (void *) addr,
			(traced) ? " (traced)" : "");
}

#ifdef CONFIG_DATA_STACK_WINDOW
static void print_k_data_stack(struct stack_regs *regs, int *pt_regs_num,
		unsigned long base, u64 size)
{
	unsigned long delta = regs->real_k_data_stack_addr -
			regs->base_k_data_stack;
	bool pt_regs_valid = regs->pt_regs[*pt_regs_num].valid;
	unsigned long pt_regs_addr = regs->pt_regs[*pt_regs_num].addr;
	unsigned long addr;
	bool show_pt_regs;

	if (!size)
		return;

	if (pt_regs_valid && pt_regs_addr >= (unsigned long) base + delta &&
			pt_regs_addr < (unsigned long) base + delta + size) {
		show_pt_regs = 1;
		(*pt_regs_num)++;
	} else {
		show_pt_regs = 0;
	}

	host_printk("    DATA STACK from %lx to %llx\n", base + delta,
			base + delta + size);
	for (addr = base; addr < base + size; addr += 16) {
		u8 tag_lo, tag_hi;
		u64 value_lo, value_hi;
		bool is_pt_regs_addr = show_pt_regs
				&& (addr + delta) >= pt_regs_addr
				&& (addr + delta) < (pt_regs_addr +
							sizeof(struct pt_regs));

		load_qvalue_and_tagq(addr, &value_lo, &value_hi,
						&tag_lo, &tag_hi);
		host_printk("      %lx (%s+0x%-3lx): %x %016llx    %x %016llx\n",
			addr + delta,
			(is_pt_regs_addr) ? "pt_regs" : "",
			(is_pt_regs_addr) ? (addr + delta - pt_regs_addr) :
					(addr - base),
			tag_lo, value_lo, tag_hi, value_hi);
	}
}
#endif

/*
 * Must be called with disabled interrupts
 */
static void host_print_chain_stack(struct stack_regs *regs, int show_reg_window)
{
	unsigned long flags;
	bool disable_nmis;
	struct task_struct *task = regs->task;
	u32 attempt, locked = 0;
	u64 new_chain_base = (u64) regs->base_chain_stack;
	u64 orig_chain_base, orig_psp_base;
	s64 cr_ind = regs->size_chain_stack;
	s64 kernel_size_chain_stack = regs->size_chain_stack -
				      regs->user_size_chain_stack;
	e2k_mem_crs_t crs = regs->crs;
	u64 new_psp_base = (u64) regs->base_psp_stack;
	s64 psp_ind = regs->size_psp_stack;
	s64 kernel_size_psp_stack = regs->size_psp_stack -
				    regs->user_size_psp_stack;
	stack_frame_t cur_frame;
	bool ignore_ip = false;
	int trap_num = 0;
#ifdef CONFIG_DATA_STACK_WINDOW
	e2k_cr1_lo_t prev_cr1_lo;
	e2k_cr1_hi_t prev_k_cr1_hi;
	bool show_k_data_stack = !!regs->base_k_data_stack;
	int pt_regs_num = 0;
	void *base_k_data_stack = regs->base_k_data_stack;
	u64 size_k_data_stack = regs->size_k_data_stack;
#endif
	int last_user_windows = 2;
	int i;
	int timeout = is_prototype() ? 150000 : 30000;

	if (!regs->valid) {
		host_pr_alert(" BUG print_chain_stack pid=%d valid=0\n",
						(task) ? task->pid : -1);
		return;
	}
	if (!regs->base_chain_stack) {
		host_pr_alert(" BUG could not get task %s (%d) stack "
			"registers, stack will not be printed\n",
			task->comm, task->pid);
		return;
	}

	if (unlikely(!raw_irqs_disabled()))
		host_pr_alert("WARNING: print_chain_stack called with enabled "
			"interrupts\n");

	/* If task is current, disable NMIs so that interrupts handlers
	 * will not spill our stacks.*/
	disable_nmis = (task == current);
	if (disable_nmis)
		raw_all_irq_save(flags);
	/* Try locking the spinlock (with 30 seconds timeout) */
	attempt = 0;
	do {
		if (raw_spin_trylock(&print_stack_lock)) {
			locked = 1;
			break;
		}

		/* Wait for 0.001 second. */
		if (disable_nmis)
			raw_all_irq_restore(flags);
		udelay(1000);
		if (disable_nmis)
			raw_all_irq_save(flags);
	} while (attempt++ < timeout);
	if (disable_nmis) {
		COPY_STACKS_TO_MEMORY();
	}

	debug_userstack |= (print_window_regs && debug_guest_regs(task));

	if (!regs->ignore_banner) {
		if (IS_KERNEL_THREAD(task, task->mm)) {
			host_pr_info("Task %s(%d) is Kernel Thread\n",
				task->comm, task->pid);
		} else {
			host_pr_info("Task %s(%d) is User Thread\n",
				task->comm, task->pid);
		}

		host_pr_alert("PROCESS: %s, PID: %d, %s: %d, state: %c %s "
			"(0x%lx), flags: 0x%x\n",
			task->comm == NULL ? "NULL" : task->comm,
			task->pid,
			get_cpu_type_name(),
			task_cpu(task), task_state_to_char(task),
#ifdef CONFIG_SMP
			task_curr(task) ? "oncpu" : "",
#else
			"",
#endif
			task->state, task->flags);
	}

	if (!regs->base_psp_stack) {
		host_pr_alert(" WARNING could not get task %s(%d) procedure "
			"stack registers, register windows will not be "
			"printed\n",
			task->comm, task->pid);
		show_reg_window = 0;
	} else {
		show_reg_window = show_reg_window && (task == current ||
				print_window_regs || task_curr(task) ||
				debug_guest_regs(task));
	}

	/* Print header */
	if (show_reg_window) {
		host_pr_alert("  PSP:  base 0x%016llx ind 0x%08x size 0x%08x\n",
				AS_STRUCT(regs->psp_lo).base,
				AS_STRUCT(regs->psp_hi).ind,
				AS_STRUCT(regs->psp_hi).size);
		host_pr_alert("  PCSP: base 0x%016llx ind 0x%08x size 0x%08x\n",
				AS_STRUCT(regs->pcsp_lo).base,
				AS_STRUCT(regs->pcsp_hi).ind,
				AS_STRUCT(regs->pcsp_hi).size);
		host_pr_alert("  ---------------------------------------------"
			"------------------------\n"
			"      IP (hex)     PROCEDURE/FILE(@ Library load "
			"address)\n"
			"  ---------------------------------------------------"
			"------------------\n");
	}

	for (;;) {
		if (kernel_size_chain_stack > 0) {
			orig_chain_base = regs->orig_base_chain_stack_k;
			kernel_size_chain_stack -= SZ_OF_CR;
		} else {
			orig_chain_base = regs->orig_base_chain_stack_u;
		}
		print_funcy_ip(AS(crs.cr0_hi).ip << 3, new_chain_base, cr_ind,
				task, orig_chain_base);

		if (show_reg_window) {
			psp_ind -= AS(crs.cr1_lo).wbs * EXT_4_NR_SZ;

			if (regs->show_trap_regs && trap_num < MAX_USER_TRAPS &&
			    regs->trap[trap_num].valid &&
			    regs->trap[trap_num].frame ==
					orig_chain_base + cr_ind) {
				if (machine.native_iset_ver >= E2K_ISET_V6) {
					host_pr_alert("      ctpr1 %llx:%llx "
						"ctpr2 %llx:%llx ctpr3 "
						"%llx:%llx\n"
						"lsr %llx ilcr %llx lsr1 %llx "
						"ilcr1 %llx\n",
						AW(regs->trap[trap_num].ctpr1_hi),
						AW(regs->trap[trap_num].ctpr1),
						AW(regs->trap[trap_num].ctpr2_hi),
						AW(regs->trap[trap_num].ctpr2),
						AW(regs->trap[trap_num].ctpr3_hi),
						AW(regs->trap[trap_num].ctpr3),
						regs->trap[trap_num].lsr,
						regs->trap[trap_num].ilcr,
						regs->trap[trap_num].lsr1,
						regs->trap[trap_num].ilcr1);
				} else if (machine.native_iset_ver == E2K_ISET_V5) {
					host_pr_alert("      ctpr1 %llx ctpr2 "
						"%llx ctpr3 %llx\n"
						"      lsr %llx ilcr %llx lsr1 "
						"%llx ilcr1 %llx\n",
						AW(regs->trap[trap_num].ctpr1),
						AW(regs->trap[trap_num].ctpr2),
						AW(regs->trap[trap_num].ctpr3),
						regs->trap[trap_num].lsr,
						regs->trap[trap_num].ilcr,
						regs->trap[trap_num].lsr1,
						regs->trap[trap_num].ilcr1);
				} else {
					host_pr_alert("      ctpr1 %llx ctpr2 "
						"%llx ctpr3 %llx\n"
						"      lsr %llx ilcr %llx\n",
						AW(regs->trap[trap_num].ctpr1),
						AW(regs->trap[trap_num].ctpr2),
						AW(regs->trap[trap_num].ctpr3),
						regs->trap[trap_num].lsr,
						regs->trap[trap_num].ilcr);
				}
				for (i = 0; i < SBBP_ENTRIES_NUM; i += 4) {
					host_pr_alert("      sbbp%-2d  0x%-12llx "
						"0x%-12llx 0x%-12llx 0x%-12llx\n",
						i, regs->trap[trap_num].sbbp[i],
						regs->trap[trap_num].sbbp[i + 1],
						regs->trap[trap_num].sbbp[i + 2],
						regs->trap[trap_num].sbbp[i + 3]);
				}
				++trap_num;
			}
			cur_frame = get_task_stack_frame_type_IP(task,
					crs.cr0_hi, crs.cr1_lo, ignore_ip);
			if (cur_frame != user_frame_type ||
			    regs->show_user_regs || last_user_windows) {
				/* Show a couple of last user windows - usually
				 * there is something useful there */
				if ((cur_frame == user_frame_type) &&
						last_user_windows)
					--last_user_windows;

				if (kernel_size_psp_stack > 0) {
					orig_psp_base =
						regs->orig_base_psp_stack_k;
					kernel_size_psp_stack -=
						AS(crs.cr1_lo).wbs * EXT_4_NR_SZ;
				} else {
					orig_psp_base =
						regs->orig_base_psp_stack_u;
				}

				host_pr_alert("    PCSP: 0x%llx,  PSP: "
					"0x%llx/0x%x\n",
					orig_chain_base + cr_ind,
					orig_psp_base + psp_ind,
					AS(crs.cr1_lo).wbs * EXT_4_NR_SZ);

				print_predicates(crs.cr0_lo, crs.cr1_hi);

				if (psp_ind < 0 && cr_ind > 0) {
					host_pr_alert("! Invalid Register "
						"Window index (psp.ind) 0x%llx",
						psp_ind);
				} else if (psp_ind >= 0) {
					print_reg_window(new_psp_base + psp_ind,
						AS(crs.cr1_lo).wbs,
						AS(crs.cr1_lo).wfx, crs.cr1_hi);
				}
			}
		}
#ifdef CONFIG_DATA_STACK_WINDOW
		if (show_k_data_stack &&
		    call_from_kernel_mode(crs.cr0_hi, crs.cr1_lo)) {
			u64 k_window_size;
			s64 cur_chain_index;

			/* To find data stack window size we have to
			 * read cr1.hi from current *and* previous frames */
			cur_chain_index = cr_ind;
			do {
				cur_chain_index -= SZ_OF_CR;
				if (cur_chain_index < 0)
					/* This is a thread created with clone
					 * and we have reached the last kernel
					 * frame. */
					break;

				get_kernel_cr1_lo(&prev_cr1_lo, new_chain_base,
						cur_chain_index);
			} while (!AS(prev_cr1_lo).pm);

			if (cur_chain_index < 0) {
				k_window_size = size_k_data_stack;
			} else {
				get_kernel_cr1_hi(&prev_k_cr1_hi,
					new_chain_base, cur_chain_index);

				k_window_size = 16 * AS(prev_k_cr1_hi).ussz -
						16 * AS(crs.cr1_hi).ussz;
				if (k_window_size > size_k_data_stack) {
					/* The stack is suspiciously large */
					k_window_size = size_k_data_stack;
					host_pr_alert("    This is the last "
						"frame or it was not copied fully\n"
						"The stack is suspiciously "
						"large (0x%llx)\n",
						k_window_size);
					show_k_data_stack = 0;
				}
			}
			print_k_data_stack(regs, &pt_regs_num, (unsigned long)
					base_k_data_stack, k_window_size);
			base_k_data_stack += k_window_size;
			size_k_data_stack -= k_window_size;
			if (!size_k_data_stack)
				show_k_data_stack = 0;
		}
#endif

		if (cr_ind < SZ_OF_CR)
			break;

		cr_ind -= SZ_OF_CR;

		/*
		 * Last frame is bogus (from execve or clone), skip it.
		 *
		 * For kernel threads there is one more reserved frame
		 * (for start_thread())
		 */
		if ((cr_ind == 0 ||
		     cr_ind == SZ_OF_CR && (task->flags & PF_KTHREAD)) &&
		    (task == current ||
		     regs->size_chain_stack < SIZE_CHAIN_STACK))
			break;

		crs = *(e2k_mem_crs_t *) (new_chain_base + cr_ind);
	}

	if (cr_ind < 0)
		host_pr_alert("INVALID cr_ind SHOULD BE 0\n");

#ifdef CONFIG_GREGS_CONTEXT
	if (show_reg_window && regs->show_user_regs && regs->gregs_valid) {
		int i;

		host_pr_alert("  Global registers: bgr.cur = %d, "
			"bgr.val = 0x%x\n",
			AS(regs->gregs.bgr).cur, AS(regs->gregs.bgr).val);
		for (i = 0;  i < 32; i += 2) {
			u64 val_lo, val_hi;
			u8 tag_lo, tag_hi;

			load_value_and_tagd(&regs->gregs.g[i + 0].base,
					&val_lo, &tag_lo);
			load_value_and_tagd(&regs->gregs.g[i + 1].base,
					&val_hi, &tag_hi);

			if (machine.native_iset_ver < E2K_ISET_V5) {
				host_pr_alert("       g%-3d: %hhx %016llx "
					"%04hx      "
					"g%-3d: %hhx %016llx %04hx\n",
					i, tag_lo, val_lo,
					(u16) regs->gregs.g[i].ext,
					i + 1, tag_hi, val_hi,
					(u16) regs->gregs.g[i+1].ext);
			} else {
				u64 ext_lo_val, ext_hi_val;
				u8 ext_lo_tag, ext_hi_tag;

				load_value_and_tagd(&regs->gregs.g[i + 0].ext,
					&ext_lo_val, &ext_lo_tag);
				load_value_and_tagd(&regs->gregs.g[i + 1].ext,
					&ext_hi_val, &ext_hi_tag);

				host_pr_alert("       g%-3d: %hhx %016llx   "
					"ext: %hhx %016llx\n"
					"       g%-3d: %hhx %016llx   "
					"ext: %hhx %016llx\n",
					i, tag_lo, val_lo,
					ext_lo_tag, ext_lo_val,
					i + 1, tag_hi, val_hi,
					ext_hi_tag, ext_hi_val);
			}
		}
	}
#endif

	if (locked)
		raw_spin_unlock(&print_stack_lock);
	if (disable_nmis)
		raw_all_irq_restore(flags);
}

void host_dump_stack(void)
{
	host_print_stack_frames(current, NULL, 1);
}

void host_dump_stack_func(void)
{
	host_print_stack_frames(current, NULL, 0);
}
