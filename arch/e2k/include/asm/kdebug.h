#ifndef _ASM_E2K_KDEBUG_H
#define _ASM_E2K_KDEBUG_H

#include <linux/notifier.h>

struct pt_regs;

/* Grossly misnamed. */
enum die_val {
	DIE_OOPS = 1,
	DIE_BREAKPOINT
};

extern void printk_address(unsigned long address, int reliable);
extern void show_trace(struct task_struct *t, struct pt_regs *regs,
		       unsigned long *sp, unsigned long bp);
extern void __show_regs(struct pt_regs *regs, int all);
extern void show_regs(struct pt_regs *regs);
extern unsigned long oops_begin(void);
extern void oops_end(unsigned long, struct pt_regs *, int signr);

#endif /* _ASM_E2K_KDEBUG_H */
