#ifndef __ASM_E2K_KPROBES_H
#define __ASM_E2K_KPROBES_H

#include <linux/ptrace.h>
#include <linux/types.h>

#include <asm/kdebug.h>
#include <asm/cpu_regs.h>
#include <asm/cacheflush.h>

#define __ARCH_WANT_KPROBES_INSN_SLOT

typedef u64		kprobe_opcode_t;

#define KPROBE_BREAK_1	0x0dc0c04004000001UL
#define KPROBE_BREAK_2	0x0dc0c06004000001UL

/*
 * We need to store in one slot both original instruction which may be
 * E2K_INSTR_MAX_SIZE size and KPROBE_BREAK_2 which is unsigned long
 */

#define MAX_INSN_SIZE	(E2K_INSTR_MAX_SIZE + sizeof(unsigned long))

struct arch_specific_insn {
	kprobe_opcode_t *insn;
};

/* per-cpu kprobe control block */
struct kprobe_ctlblk {
	int kprobe_status;
	struct pt_regs jprobe_saved_regs;
};

#define kretprobe_blacklist_size	0
#define arch_remove_kprobe(p)	do { } while (0)

#define flush_insn_slot(p)					\
do {									\
	flush_icache_range((unsigned long)p->addr,			\
	(unsigned long)p->addr +		\
	(MAX_INSN_SIZE * sizeof(kprobe_opcode_t)));	\
} while (0)

extern int __kprobes kprobe_exceptions_notify(struct notifier_block *self,
					unsigned long val, void *data);

#endif /*__ASM_E2K_KPROBES_H */
