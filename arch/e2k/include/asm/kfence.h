/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * e2k KFENCE support.
 */

#ifndef _ASM_E2K_KFENCE_H
#define _ASM_E2K_KFENCE_H

#ifndef MODULE

#include <asm/set_memory.h>


static inline bool arch_kfence_init_pool(void)
{
	return true;
}

static inline bool kfence_protect_page(unsigned long addr, bool protect)
{
	if (WARN_ON(IS_USER_ADDR(addr)))
		return false;
	/*
	 * We need to avoid IPIs, as we may get KFENCE allocations or faults with interrupts
	 * disabled.
	 */
	if (protect ? set_memory_np_noflush(addr, 1) : set_memory_p_noflush(addr, 1))
		return false;

	/*
	 * Flush this CPU's TLB, assuming whoever did the allocation/free is
	 * likely to continue running on this CPU.
	 */
	flush_TLB_kernel_page(addr);

	return true;
}

#endif /* !MODULE */

#endif /* _ASM_E2K_KFENCE_H */
