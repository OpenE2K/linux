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
#include <linux/kfence.h>

extern bool arch_kfence_initialized;

#ifdef CONFIG_KFENCE
static inline bool intersects_kfence(unsigned long addr, unsigned long size)
{
	return __kfence_pool && range_intersects((unsigned long)__kfence_pool,
		KFENCE_POOL_SIZE, addr, size);
}

/* Force 4K pages for __kfence_pool to avoid memory allocation
 * for splitting pages: in kfence_guarded_alloc set_memory_attr calls
 * in raw_spinlock critical section.
 */
static inline bool arch_kfence_init_pool(void)
{
	bool ret = !set_memory_4k((unsigned long)__kfence_pool,
		PAGE_ALIGN(KFENCE_POOL_SIZE) >> PAGE_SHIFT);

	arch_kfence_initialized = ret;

	return ret;
}
#else
static inline bool intersects_kfence(unsigned long addr, unsigned long size)
{
	return false;
}

static inline bool arch_kfence_init_pool(void)
{
	return true;
}
#endif /* CONFIG_KFENCE */



static inline bool kfence_protect_page(unsigned long addr, bool protect)
{
	if (WARN_ON(IS_USER_ADDR(addr)))
		return false;

	if (protect ? set_memory_np(addr, 1) : set_memory_p(addr, 1))
		return false;

	return true;
}

#endif /* !MODULE */

#endif /* _ASM_E2K_KFENCE_H */
