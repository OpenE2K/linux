/*
 * Kernel Probes (KProbes)
 * arch/e2k/kernel/kprobes.c
 */

#include <linux/kprobes.h>
#include <linux/preempt.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/kdebug.h>

#include <asm/ptrace.h>

DEFINE_PER_CPU(struct kprobe *, current_kprobe);
DEFINE_PER_CPU(struct kprobe_ctlblk, kprobe_ctlblk);

static int get_instr_size_by_vaddr(unsigned long addr)
{
	int instr_size;
	instr_syl_t *syl;
	instr_hs_t hs;

	syl = &E2K_GET_INSTR_HS((e2k_addr_t)addr);
	hs.word = *syl;
	instr_size = E2K_GET_INSTR_SIZE(hs);

	return instr_size;
}

static void replace_instruction(unsigned long *src, unsigned long phys_dst,
				int instr_size)
{
	int i;

	for (i = 0; i < instr_size / 8; i++)
		E2K_WRITE_MAS_D(phys_dst + 8 * i, src[i], MAS_STORE_PA);
}

static unsigned long copy_instr(unsigned long *src, unsigned long *dst,
				int duplicated_dst)
{
	unsigned long phys_ip_dst;
	int node;
	int instr_size;

	instr_size = get_instr_size_by_vaddr((unsigned long) src);

	for_each_node_has_dup_kernel(node) {
		phys_ip_dst = node_kernel_address_to_phys(node,
						(e2k_addr_t) dst);
		if (phys_ip_dst == -EINVAL) {
			printk(KERN_ALERT"kprobes: can't find phys_ip\n");
			return -EFAULT;
		}

		replace_instruction(src, phys_ip_dst, instr_size);

		if (!duplicated_dst || !THERE_IS_DUP_KERNEL)
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

	p->ainsn.insn[instr_size/sizeof(unsigned long)] = KPROBE_BREAK_2;

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

		E2K_WRITE_MAS_D(phys_ip, insn, MAS_STORE_PA);

		if (!THERE_IS_DUP_KERNEL)
			break;
	}
}

void __kprobes arch_arm_kprobe(struct kprobe *p)
{
	arch_replace_insn_all_nodes(KPROBE_BREAK_1, (unsigned long)p->addr);
	flush_insn_slot(p);
}

void __kprobes arch_disarm_kprobe(struct kprobe *p)
{
	copy_instr((unsigned long *) p->ainsn.insn,
		   (unsigned long *) p->addr, true);
	flush_insn_slot(p);
}

static void __kprobes prepare_singlestep(struct kprobe *p, struct pt_regs *regs)
{
	regs->crs.cr0_hi.fields.ip = (u64)(p->ainsn.insn) >> 3;
}

static void __kprobes resume_execution(struct kprobe *p, struct pt_regs *regs)
{
	int instr_size = get_instr_size_by_vaddr((unsigned long)p->ainsn.insn);

	regs->crs.cr0_hi.fields.ip = (u64)(p->addr + instr_size/8) >> 3;
}

static void __kprobes set_current_kprobe(struct kprobe *p)
{
	__get_cpu_var(current_kprobe) = p;
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
	if (kprobe_running()) {
		p = get_kprobe(addr);
		if (p) {
			goto no_kprobe;
		} else {
			p = kprobe_running();
			if (p->break_handler && p->break_handler(p, regs))
				goto ss_kprobe;
		}
	}

	p = get_kprobe(addr);
	if (!p)
		goto no_kprobe;

	set_current_kprobe(p);
	if (p->pre_handler && p->pre_handler(p, regs))
		return 1;

ss_kprobe:
	prepare_singlestep(p, regs);

	kcb = get_kprobe_ctlblk();

	kcb->kprobe_status = KPROBE_HIT_SS;

	return 1;

no_kprobe:
	preempt_enable_no_resched();

	return 0;
}

static int __kprobes post_kprobe_handler(struct pt_regs *regs)
{
	struct kprobe *cur = kprobe_running();
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk();

	if (!cur)
		return 0;

	if (cur->post_handler) {
		kcb->kprobe_status = KPROBE_HIT_SSDONE;
		cur->post_handler(cur, regs, 0);
	}

	resume_execution(cur, regs);
	reset_current_kprobe();
	preempt_enable_no_resched();

	return 1;
}

int __kprobes kprobe_fault_hadler(struct pt_regs *regs, int trapnr)
{
	struct kprobe *cur = kprobe_running();
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk();

	if (cur->fault_handler && cur->fault_handler(cur, regs, trapnr))
		return 1;

	if (kcb->kprobe_status & KPROBE_HIT_SS) {
		resume_execution(cur, regs);
		preempt_enable_no_resched();
	}

	return 0;
}

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
	case DIE_SSTEP:
		if (post_kprobe_handler(args->regs))
			ret = NOTIFY_STOP;
		break;
	default:
		break;
	}

	return ret;
}

int __kprobes setjmp_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct jprobe *jp = container_of(p, struct jprobe, kp);
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk();

	memcpy(&kcb->jprobe_saved_regs, regs, sizeof(struct pt_regs));

	regs->crs.cr0_hi.fields.ip = (unsigned long)jp->entry >> 3;

	return 1;
}

void __kprobes jprobe_return(void)
{
	E2K_KPROBES_BREAKPOINT;
}

int __kprobes longjmp_break_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk();

	memcpy(regs, &kcb->jprobe_saved_regs, sizeof(struct pt_regs));
	preempt_enable_no_resched();

	return 1;
}

int __init arch_init_kprobes(void)
{
	return 0;
}
