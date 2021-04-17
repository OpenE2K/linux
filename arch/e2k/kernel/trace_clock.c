/*
 * e2k trace clocks
 */

#include <linux/init.h>

#include <asm/trace_clock.h>
#include <asm/cpu_regs.h>
#include <asm/timex.h>

/*
 * trace_clock_e2k_clkr(): A clock that is just the cycle counter.
 *
 * Unlike the other clocks, this is not in nanoseconds.
 */
__section(.entry_handlers)
notrace u64 trace_clock_e2k_clkr(void)
{
	return get_cycles();
}
