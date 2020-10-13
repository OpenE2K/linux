#ifndef _DEBUG_PRINT_H_
#define _DEBUG_PRINT_H_

#include <asm/current.h>

#ifdef __KERNEL__
#ifndef __ASSEMBLY__

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

# endif
#endif

#endif /* _DEBUG_PRINT_H_ */
