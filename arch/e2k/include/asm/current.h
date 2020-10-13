#ifndef _E2K_CURRENT_H
#define _E2K_CURRENT_H

#ifdef __KERNEL__
#ifndef __ASSEMBLY__

#include <linux/compiler.h>

#ifndef CONFIG_E2S_CPU_RF_BUG
struct task_struct;
register struct task_struct *current __asm__ ("%g17");
#else
# include <linux/thread_info.h>

# define current (current_thread_info()->task)
#endif

#endif /* __ASSEMBLY__ */
#endif /* __KERNEL__ */

#endif /* _E2K_CURRENT_H */
