#ifndef _ASM_E2K_KDEBUG_H
#define _ASM_E2K_KDEBUG_H

#include <linux/notifier.h>

struct pt_regs;

/* Grossly misnamed. */
enum die_val {
	DIE_OOPS = 1,
	DIE_BREAKPOINT
};

extern void die(const char *str, struct pt_regs *regs, long err) __cold;

#endif /* _ASM_E2K_KDEBUG_H */
