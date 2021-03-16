#ifndef _DEBUG_PRINT_H_
#define _DEBUG_PRINT_H_

#include <linux/sched.h>
#include <asm/current.h>

#ifdef __KERNEL__
#ifndef __ASSEMBLY__

#ifdef E2K_P2V

#include <asm/p2v/boot_console.h>

# define DebugPrint(condition, fmt, ...) \
do { \
	if (condition) \
		do_boot_printk("%s: " fmt, __func__ ,##__VA_ARGS__); \
} while (0)

# define DebugPrintCont(condition, fmt, ...) \
do { \
	if (condition) \
		do_boot_printk(fmt, ##__VA_ARGS__); \
} while (0)

#else

# define DebugPrint(condition, fmt, ...) \
do { \
	if (condition) \
		printk(KERN_DEBUG "%d %d %s: " fmt,	\
			raw_smp_processor_id(), current->pid, __func__ , \
			##__VA_ARGS__); \
} while (0)

# define DebugPrintCont(condition, fmt, ...) \
do { \
	if (condition) \
		printk(KERN_DEBUG fmt, ##__VA_ARGS__); \
} while (0)

#endif

#endif
#endif
#endif /* _DEBUG_PRINT_H_ */
