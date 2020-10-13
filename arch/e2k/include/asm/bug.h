#ifndef _E2K_BUG_H
#define _E2K_BUG_H
#ifdef CONFIG_BUG

#include <asm/e2k.h>

struct task_struct;
extern void print_stack(struct task_struct *task);

#define	_BUG			INIT_BUG
#define	_BG			printk
#define BUG()			do { _BG("kernel BUG at %s:%d!\n", \
					__FILE__, __LINE__); \
					E2K_HALT_ERROR(100); } while (0)
#define HAVE_ARCH_BUG

#endif

#include <asm-generic/bug.h>

#endif	/* _E2K_BUG_H */
