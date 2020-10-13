#ifndef _E2K_SGE_H
#define _E2K_SGE_H

#ifdef __KERNEL__

#include <linux/irqflags.h>

#include <asm/system.h>
#include <asm/thread_info.h>

static inline int sge_checking_enabled()
{
	return test_ts_flag(TS_HW_STACKS_EXPANDED);
}

/*
 * When we are switching to a new task we do not
 * know whether it is kernel (with SGE enabled) or
 * user (with SGE disabled) thread, so we have to
 * manually update PSR.sge.
 */
static __always_inline void update_sge_checking()
{
	if (test_ts_flag(TS_HW_STACKS_EXPANDED))
		e2k_set_sge();
	else
		e2k_reset_sge();
}

#endif /* __KERNEL__ */
#endif /* _E2K_SGE_H */
