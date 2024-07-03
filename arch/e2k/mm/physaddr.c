/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/mmdebug.h>
#include <asm/head.h>
#include <asm/page.h>

phys_addr_t __pa_lm_debug(unsigned long vaddr)
{
	VIRTUAL_BUG_ON(vaddr < PAGE_OFFSET || vaddr >= PAGE_OFFSET + MAX_PM_SIZE);
	return __pa_lm_nodebug(vaddr);
}
EXPORT_SYMBOL(__pa_lm_debug);

phys_addr_t __pa_symbol_debug(unsigned long vaddr)
{
	VIRTUAL_BUG_ON(vaddr < KERNEL_BASE || vaddr >= KERNEL_END);
	return __pa_symbol_nodebug(vaddr);
}
EXPORT_SYMBOL(__pa_symbol_debug);