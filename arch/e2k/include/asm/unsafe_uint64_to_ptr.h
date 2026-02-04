/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 MCST
 */

#ifndef _UNSAFE_UINT64_TO_PTR_H_
#define _UNSAFE_UINT64_TO_PTR_H_

#ifdef CONFIG_PROTECTED_MODE

#include <asm/e2k_debug.h>

int get_descriptor_ranges_on_global_or_pl(unsigned long addr, e2k_addr_t *base,
					  unsigned long *length, e2k_pl_t *pl,
					  bool *is_global, bool *is_pl,
					  struct pt_regs *regs);

int get_cute_cui_by_func_addr(unsigned long addr, e2k_cute_t *cute, int *cui,
			      struct pt_regs *regs);

int get_descriptor_ranges_on_stacks(unsigned long addr, e2k_addr_t *base,
				    unsigned long *length, int options,
				    struct pt_regs *regs);

int get_descriptor_ranges_on_mm(unsigned long addr, e2k_addr_t *base,
				unsigned long *length, struct pt_regs *regs);

#endif /* CONFIG_PROTECTED_MODE */

#endif /* _UNSAFE_UINT64_TO_PTR_H_ */