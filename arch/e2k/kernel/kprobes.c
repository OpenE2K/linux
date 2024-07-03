/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Kernel Probes (KProbes)
 * arch/e2k/kernel/kprobes.c
 */

#include <linux/kprobes.h>
#include <linux/preempt.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/kdebug.h>

#include <asm/process.h>
#include <asm/ptrace.h>

DEFINE_PER_CPU(struct kprobe *, current_kprobe);
DEFINE_PER_CPU(struct kprobe_ctlblk, kprobe_ctlblk);

static void replace_instruction(unsigned long *src, unsigned long phys_dst,
				int instr_size)
{
	int i;

	for (i = 0; i < instr_size / 8; i++)
		NATIVE_WRITE_MAS_D(phys_dst + 8 * i, src[i], MAS_STORE_PA);
}

static unsigned long copy_instr(unsigned long *src, unsigned long *dst,
				int duplicated_dst)
{
	unsigned long phys_ip_dst;
	int node;
	int instr_size;
	instr_cs0_t *cs0;
	void *instr;

	/*
	 * Copy instruction to a local variable
	 */
	instr_size = get_instr_size_by_vaddr((unsigned long) src);
	instr = __builtin_alloca(instr_size);
	memcpy(instr, src, instr_size);

	/*
	 * Jump values must be corrected when they are relative to %ip
	 */
	cs0 = find_cs0(instr);
	if (cs0) {
		instr_hs_t *hs = (instr_hs_t *) &E2K_GET_INSTR_HS(instr);
		instr_ss_t *ss;
		signed long delta;

		if (hs->s)
			ss = (instr_ss_t *) &E2K_GET_INSTR_SS(instr);
		else
			ss = NULL;

		if (cs0->ctp_opc == CS0_CTP_OPC_DISP && cs0->ctpr ||
		    cs0->ctp_opc == CS0_CTP_OPC_LDISP && cs0->ctpr == 2 ||
		    cs0->ctp_opc == CS0_CTP_OPC_PUTTSD && cs0->ctpr == 0 ||
		    cs0->ctp_opc == CS0_CTP_OPC_IBRANCH && !cs0->ctpr &&
				ss && !ss->ctop) {
			delta = (signed long) src - (signed long) dst;
			cs0->cof2.disp += delta >> 3L;
		} else if (cs0->ctp_opc == CS0_CTP_OPC_PREF && !cs0->ctpr) {
			signed long pref_dst = (signed long) src +
				((signed long) cs0->pref.pdisp << 40L) >> 33L;

			delta = pref_dst - (signed long) dst;
			cs0->pref.pdisp = delta >> 7L;
		}
	}

	for_each_node_has_dup_kernel(node) {
		phys_ip_dst = node_kernel_address_to_phys(node,
						(e2k_addr_t) dst);
		if (phys_ip_dst == -EINVAL) {
			printk(KERN_ALERT"kprobes: can't find phys_ip\n");
			return -EFAULT;
		}

		replace_instruction(instr, phys_ip_dst, instr_size);

		if (!duplicated_dst)
			break;

		/* Modules are not duplicated */
		if (!is_duplicated_code((unsigned long) dst))
			break;
	}

	return instr_size;
}

int __kprobes arch_prepare_kprobe(struct kprobe *p)
{
	int instr_size;

	p->ainsn.insn = get_insn_slot();
	if (!p->ainsn.insn)
		return -ENOMEM;

	instr_size = copy_instr((unsigned long *)p->addr,
				(unsigned long *)p->ainsn.insn, false);
	if (instr_size < 0) {
		printk(KERN_ALERT"kprobes: can't get instruction size\n");
		return -EFAULT;
	}

	/*
	 * We need to store one additional instruction after the copied one
	 * to make sure processor won't generate exc_illegal_opcode instead
	 * of exc_last_wish/exc_instr_debug (exc_illegal_opcode has priority).
	 */
	*(unsigned long *) &p->ainsn.insn[instr_size] = 0UL;

	return 0;
}

static void arch_replace_insn_all_nodes(unsigned long insn, unsigned long ip)
{
	unsigned long phys_ip;
	int node;

	for_each_node_has_dup_kernel(node) {
		phys_ip = node_kernel_address_to_phys(node, ip);
		if (phys_ip == -EINVAL) {
			printk(KERN_ALERT"kprobes: can't find phys_ip\n");
			WARN_ON_ONCE(1);
			break;
		}

		NATIVE_WRITE_MAS_D(phys_ip, insn, MAS_STORE_PA);
	}
}

static void flush_instruction(struct kprobe *p)
{
	unsigned long addr = (unsigned long) p->addr;

	flush_icache_range(addr, addr +
				 MAX_INSN_SIZE * sizeof(kprobe_opcode_t));
}

void __kprobes arch_arm_kprobe(struct kprobe *p)
{
	unsigned long break_instr;

	break_instr = KPROBE_BREAK_1;

	if (cpu_has(CPU_HWBUG_BREAKPOINT_INSTR)) {
		instr_hs_t *hs, *break_hs;

		hs = (instr_hs_t *) p->addr;
		break_hs = (instr_hs_t *) &break_instr;

		break_hs->lng = hs->lng;
	}

	arch_replace_insn_all_nodes(break_instr, (unsigned long)p->addr);
	flush_instruction(p);
}

void __kprobes arch_disarm_kprobe(struct kprobe *p)
{
	copy_instr((unsigned long *) p->ainsn.insn,
		   (unsigned long *) p->addr, true);
	flush_instruction(p);
}

static void __kprobes
install_interrupt(struct pt_regs *regs, int single_step, kprobe_opcode_t **ret_addr)
{
	/* Set exception to fire on return */
	if (single_step) {
		if (cpu_has(CPU_HWBUG_SS))
			set_ts_flag(TS_SINGLESTEP_KERNEL);
		AS(regs->crs.cr1_lo).ss = 1;
		AS(regs->crs.cr1_lo).ie = 0;
		AS(regs->crs.cr1_lo).nmie = 0;
	} else {
		AS(regs->crs.cr1_lo).lw = 1;
	}

	/* Save return ip */
	if (ret_addr) {
		unsigned long flags, base, index, spilled;

		raw_all_irq_save(flags);

		base = regs->stacks.pcsp_lo.base;
		index = regs->stacks.pcsp_hi.ind;
		spilled = READ_PCSP_HI_REG().ind;

		if (spilled <= index)
			E2K_FLUSHC;

		e2k_mem_crs_t *frame = (e2k_mem_crs_t *) (base + index) - 1;
		*ret_addr = (kprobe_opcode_t *) (frame->cr0_hi.ip << 3);

		raw_all_irq_restore(flags);
	}
}

static void __kprobes prepare_singlestep(struct kprobe *p, struct pt_regs *regs)
{
	install_interrupt(regs, true, NULL);

	regs->crs.cr0_hi.ip = (u64)(p->ainsn.insn) >> 3;
}

static int maybe_is_call(void *instr)
{
	instr_cs1_t *cs1;
	instr_hs_t *hs;
	instr_ss_t *ss;

	hs = (instr_hs_t *) &E2K_GET_INSTR_HS(instr);
	if (hs->s)
		ss = (instr_ss_t *) &E2K_GET_INSTR_SS(instr);
	else
		ss = NULL;

	cs1 = find_cs1(instr);
	if (cs1 && ss && ss->ctop && cs1->opc == CS1_OPC_CALL)
		return true;

	return false;
}

static void __kprobes resume_execution(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long slot_addr = (unsigned long) p->ainsn.insn;
	int instr_size = get_instr_size_by_vaddr(slot_addr);

	if ((AS(regs->crs.cr0_hi).ip << 3) == slot_addr + instr_size) {
		/*
		 * Instruction did not jump so set the next %ip
		 * to point after the kprobed instruction.
		 */
		AS(regs->crs.cr0_hi).ip = (u64)(p->addr + instr_size) >> 3;
	} else if (maybe_is_call(p->ainsn.insn)) {
		/*
		 * Instruction could be a call. In this case
		 * check _previous_ chain stack frame.
		 */
		unsigned long flags, base, index, spilled;
		e2k_mem_crs_t *frame;

		raw_all_irq_save(flags);

		base = AS(regs->stacks.pcsp_lo).base;
		index = AS(regs->stacks.pcsp_hi).ind;
		spilled = AS(READ_PCSP_HI_REG()).ind;

		if (spilled < index)
			E2K_FLUSHC;

		frame = (e2k_mem_crs_t *) (base + index);
		--frame;

		if ((AS(frame->cr0_hi).ip << 3) == slot_addr + instr_size)
			AS(frame->cr0_hi).ip = (u64)(p->addr + instr_size) >> 3;

		raw_all_irq_restore(flags);
	}
}

static void __kprobes set_current_kprobe(struct kprobe *p)
{
	__this_cpu_write(current_kprobe, p);
}

static int __kprobes kprobe_handler(struct pt_regs *regs)
{
	struct kprobe *p;
	kprobe_opcode_t *addr;
	struct kprobe_ctlblk *kcb;

	addr = (kprobe_opcode_t *)instruction_pointer(regs);

	/*
	 * We don't want to be preempted for the entire
	 * duration of kprobe processing.
	 */
	preempt_disable();

	/* Check we're not actually recursing */
	if (kprobe_running())
		goto no_kprobe;

	p = get_kprobe(addr);
	if (!p)
		goto no_kprobe;

	set_current_kprobe(p);
	if (p->pre_handler && p->pre_handler(p, regs))
		/* handler has already set things up, so skip ss setup */
		return 1;

	prepare_singlestep(p, regs);

	kcb = get_kprobe_ctlblk();

	kcb->kprobe_status = KPROBE_HIT_SS;

	return 1;

no_kprobe:
	preempt_enable_no_resched();

	return 0;
}

void __kprobes kprobe_instr_debug_handle(struct pt_regs *regs)
{
	struct kprobe *cur = kprobe_running();
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk();
	unsigned long flags;
	e2k_dibsr_t dibsr;
	bool singlestep;

	if (!cur || kcb->kprobe_status != KPROBE_HIT_SS)
		return;

	/*
	 * Make sure another overflow does not happen while
	 * we are handling this one to avoid races.
	 */
	raw_all_irq_save(flags);
	dibsr = READ_DIBSR_REG();
	singlestep = dibsr.ss;
	if (singlestep) {
		if (cpu_has(CPU_HWBUG_SS))
			clear_ts_flag(TS_SINGLESTEP_KERNEL);
		dibsr.ss = 0;
		WRITE_DIBSR_REG(dibsr);
	}

	/*
	 * Re-enable interrupts in %psr
	 */
	if (AS(regs->crs.cr1_lo).uie)
		AS(regs->crs.cr1_lo).ie = 1;
	if (AS(regs->crs.cr1_lo).unmie)
		AS(regs->crs.cr1_lo).nmie = 1;
	raw_all_irq_restore(flags);

	if (!singlestep)
		return;

	if (cur->post_handler) {
		kcb->kprobe_status = KPROBE_HIT_SSDONE;
		cur->post_handler(cur, regs, 0);
	}

	resume_execution(cur, regs);
	reset_current_kprobe();
	preempt_enable_no_resched();
}

int __kprobes kprobe_fault_handler(struct pt_regs *regs, int trapnr)
{
	struct kprobe *cur = kprobe_running();
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk();

	if (cur->fault_handler && cur->fault_handler(cur, regs, trapnr))
		return 1;

	/*
	 * No need to call resume_execution() or do anything else -
	 * exc_instr_debug will still be delivered.
	 */

	return 0;
}
NOKPROBE_SYMBOL(kprobe_fault_handler);

/*
 * Handling exceptions
 */
int __kprobes kprobe_exceptions_notify(struct notifier_block *self,
						unsigned long val, void *data)
{
	struct die_args *args = (struct die_args *)data;
	int ret = NOTIFY_DONE;

	switch (val) {
	case DIE_BREAKPOINT:
		if (kprobe_handler(args->regs))
			ret = NOTIFY_STOP;
		break;
	default:
		break;
	}

	return ret;
}

int __init arch_init_kprobes(void)
{
	return 0;
}


bool arch_within_kprobe_blacklist(unsigned long addr)
{
	return  (addr >= (unsigned long) __kprobes_text_start &&
		 addr < (unsigned long) __kprobes_text_end) ||
		(addr >= (unsigned long) _t_entry &&
		 addr < (unsigned long) _t_entry_end) ||
		(addr >= (unsigned long) __entry_handlers_start &&
		 addr < (unsigned long) __entry_handlers_end);
}

#ifdef CONFIG_KRETPROBES
void __kprobes arch_prepare_kretprobe(struct kretprobe_instance *ri,
				      struct pt_regs *regs)
{
	install_interrupt(regs, false, &ri->ret_addr);
}

int arch_trampoline_kprobe(struct kprobe *p)
{
	/* We don't use trampoline */
	return 0;
}
NOKPROBE_SYMBOL(arch_trampoline_kprobe);

void recycle_rp_inst(struct kretprobe_instance *ri);
void kretprobe_hash_lock(struct task_struct *tsk, struct hlist_head **head,
			 unsigned long *flags);
void kretprobe_hash_unlock(struct task_struct *tsk, unsigned long *flags);

int kretprobe_last_wish_handle(struct pt_regs *regs)
{
	struct kretprobe_instance *ri = NULL;
	struct hlist_head *head;
	struct hlist_node *tmp;
	unsigned long flags, ret_address;
	int handled = 0;

	/*
	 * It is possible to have multiple instances associated with a given
	 * exc_last_wish because more than one return probe was registered
	 * for a target function.
	 */
	kretprobe_hash_lock(current, &head, &flags);
	hlist_for_each_entry_safe(ri, tmp, head, hlist) {
		if (ri->task != current)
			/* another task is sharing our hash bucket */
			continue;

		ret_address = (unsigned long) ri->ret_addr;
		if (ret_address != instruction_pointer(regs))
			/*
			 * Any other instances associated with this task
			 * are for other calls deeper on the call stack.
			 */
			break;

		if (ri->rp && ri->rp->handler) {
			handled = 1;
			ri->rp->handler(ri, regs);
		}

		recycle_rp_inst(ri);
	}
	kretprobe_hash_unlock(current, &flags);

	return handled;
}
#endif
