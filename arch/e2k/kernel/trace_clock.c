/*
 * e2k trace clocks
 */
#include <asm/trace_clock.h>
#include <asm/timex.h>

/*
 * trace_clock_e2k_clkr(): A clock that is just the cycle counter.
 *
 * Unlike the other clocks, this is not in nanoseconds.
 */
notrace u64 trace_clock_e2k_clkr(void)
{
	return get_cycles();
}
