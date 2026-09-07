/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_BUG_H
#define _E2K_BUG_H

#include <linux/compiler_attributes.h>

#ifdef CONFIG_BUG
# include <asm/e2k_api.h>

# define BUG() \
do { \
	__EMIT_BUG(0); \
	unreachable(); \
} while (0)

# define __WARN_FLAGS(flags) __EMIT_BUG(BUGFLAG_WARNING|(flags));

# define HAVE_ARCH_BUG
#endif /* CONFIG_BUG */

/* Add __cold for better instruction scheduling */
extern __printf(4, 5)
void warn_slowpath_fmt(const char *file, const int line, unsigned taint,
		       const char *fmt, ...) __cold;
extern __printf(1, 2) void __warn_printk(const char *fmt, ...) __cold;

#include <asm-generic/bug.h>

#endif	/* _E2K_BUG_H */
