#ifndef _E2K_BUG_H
#define _E2K_BUG_H

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

#include <asm-generic/bug.h>

#endif	/* _E2K_BUG_H */
