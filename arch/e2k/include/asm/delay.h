#ifndef _E2K_DELAY_H_
#define _E2K_DELAY_H_

#include <linux/param.h>

#ifdef CONFIG_SMP
#include <asm/processor.h>
#include <asm/smp.h>
#endif 

#define MAX_UDELAY_MS	100

/*
 * Private __udelay() forms a delay of <usec> microseconds 
 * <lps> is a pre-calculated loops/sec value
 * 
 * Implemented in arch/e2k/lib/delay.c
 */

extern void __udelay(unsigned long usecs, unsigned long lpj);

/*
 * Public __delay() forms a delay from <loops> idle cycles 
 * 
 * Implemented in arch/e2k/lib/delay.c
 */

extern void __delay(unsigned long loops);

/*
 * Public udelay() forms a delay of <usec> microseconds
 */

#ifdef CONFIG_SMP
#define __udelay_val raw_my_cpu_data.loops_per_jiffy
#else
extern unsigned long loops_per_jiffy;
#define __udelay_val loops_per_jiffy
#endif

#define udelay(usecs) __udelay((usecs),__udelay_val)

/* This mdelay does not use uninitialized per-cpu variables,
 * so it is safe to use anywhere (but it will finish _much_
 * faster if called before 'loops_per_jiffy' is measured). */
#define safe_mdelay(msecs) \
({ \
	long __i; \
	for (__i = 0; __i < msecs; __i++) \
		 __udelay(1000, loops_per_jiffy); \
})

#endif /* _E2K_DELAY_H_ */
