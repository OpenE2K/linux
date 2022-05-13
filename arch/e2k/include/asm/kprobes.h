#ifndef __ASM_E2K_KPROBES_H
#define __ASM_E2K_KPROBES_H

#include <asm-generic/kprobes.h>

#ifdef CONFIG_KPROBES

#include <linux/ptrace.h>
#include <linux/types.h>

#include <asm/kdebug.h>
#include <asm/cpu_regs_types.h>
#include <asm/trap_def.h>
#include <asm/cacheflush.h>

#define __ARCH_WANT_KPROBES_INSN_SLOT

typedef u8 kprobe_opcode_t;

#define KPROBE_BREAK_1	0x0dc0c04004000001UL

/*
 * We need to store one additional instruction after the copied one
 * to make sure processor won't generate exc_illegal_opcode instead
 * of exc_last_wish/exc_instr_debug (exc_illegal_opcode has priority).
 */
#define MAX_INSN_SIZE	(E2K_INSTR_MAX_SIZE + sizeof(unsigned long))

struct arch_specific_insn {
	kprobe_opcode_t *insn;
};

/* per-cpu kprobe control block */
#define MAX_STACK_SIZE 256
struct kprobe_ctlblk {
	int kprobe_status;
};

#define kretprobe_blacklist_size	0
#define arch_remove_kprobe(p)	do { } while (0)

#define flush_insn_slot(p) \
do { \
	unsigned long slot = (unsigned long) p->ainsn.insn; \
	flush_icache_range(slot, slot + \
				 MAX_INSN_SIZE * sizeof(kprobe_opcode_t)); \
} while (0)

extern int __kprobes kprobe_fault_handler(struct pt_regs *regs, int trapnr);
extern int __kprobes kprobe_exceptions_notify(struct notifier_block *self,
					unsigned long val, void *data);

static inline int is_kprobe_break1_trap(struct pt_regs *regs)
{
	u64 *instr = (u64 *)GET_IP_CR0_HI(regs->crs.cr0_hi);

	if (cpu_has(CPU_HWBUG_BREAKPOINT_INSTR))
		return (*instr & ~E2K_INSTR_HS_LNG_MASK) ==
		       (KPROBE_BREAK_1 & ~E2K_INSTR_HS_LNG_MASK);
	else
		return *instr == KPROBE_BREAK_1;
}

extern void kprobe_instr_debug_handle(struct pt_regs *);
#else
static inline int is_kprobe_break1_trap(struct pt_regs *regs)
{
	return false;
}

static inline void kprobe_instr_debug_handle(struct pt_regs *regs) { }
#endif /* #ifdef CONFIG_KPROBES */

#ifdef CONFIG_KRETPROBES
extern int kretprobe_last_wish_handle(struct pt_regs *);
#else
static inline int kretprobe_last_wish_handle(struct pt_regs *regs)
{
	return 0;
}
#endif

#endif /*__ASM_E2K_KPROBES_H */
