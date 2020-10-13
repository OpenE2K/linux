
#include <linux/sched.h>
#include <linux/delay.h>
#include <asm/processor.h>
#include <asm/delay.h>
#include <asm/timer.h>
#include <linux/module.h>
#include <asm/string.h>

#ifdef CONFIG_SMP
#include <asm/smp.h>
#endif


void notrace __delay(unsigned long loops)
{
	cycles_t start, now;

	start = get_cycles();

	do {
		now = get_cycles();
        } while ((now - start) < loops);
}

void notrace __udelay(unsigned long usecs, unsigned long lpj)
{
	__delay( (usecs * lpj) * HZ / USEC_PER_SEC );
}
EXPORT_SYMBOL(__udelay);

int read_current_timer(unsigned long *timer_val)
{
	*timer_val = get_cycles();

	return 0;
}

