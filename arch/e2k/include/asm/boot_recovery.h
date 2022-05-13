/* $Id: boot_recovery.h,v 1.12 2009/06/29 11:52:31 atic Exp $
 *
 * boot-time recovery of kernel from control point.
 */

#ifndef _E2K_BOOT_RECOVERY_H
#define _E2K_BOOT_RECOVERY_H

#include <asm/types.h>
#include <asm/console.h>
#include <asm/cpu_regs_types.h>

/* To use stgd upon kernel entry task_struct must be aligned
 * (since %gd_lo.base points to it) */
struct aligned_task {
	struct task_struct t;
} __aligned(E2K_ALIGN_GLOBALS_SZ);
extern struct aligned_task task_to_restart[];
extern struct task_struct *task_to_recover;

/*
 * Forwards of boot-time functions to recover system state
 */

extern void	boot_recovery(bootblock_struct_t *bootblock);
extern void	recover_kernel(void);
extern int	restart_system(void (*restart_func)(void *), void *arg);

#define	full_phys_mem			nodes_phys_mem

#define	START_KERNEL_SYSCALL	12

extern inline void
scall2(bootblock_struct_t *bootblock)
{
	(void) E2K_SYSCALL(START_KERNEL_SYSCALL,	/* Trap number */
			   0,				/* empty sysnum */
			   1,				/* single argument */
			   (long) bootblock);		/* the argument */
}

#endif /* _E2K_BOOT_RECOVERY_H */
