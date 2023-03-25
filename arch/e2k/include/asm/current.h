#ifndef _E2K_CURRENT_H
#define _E2K_CURRENT_H

#include <linux/compiler.h>
#include <asm/glob_regs.h>

struct task_struct;
register struct task_struct *current DO_ASM_GET_GREG_MEMONIC(
							CURRENT_TASK_GREG);
#define	native_current()	current

#endif /* _E2K_CURRENT_H */
