/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_KBUILD_H
#define __LINUX_KBUILD_H

#if defined CONFIG_E2K && defined __LCC__
# define pragma_no_asm_inline _Pragma ("no_asm_inline")
#else
# define pragma_no_asm_inline
#endif

#define DEFINE(sym, val) \
	pragma_no_asm_inline asm volatile("\n.ascii \"->" #sym " %0 " #val "\"" : : "i" (val))

#define BLANK() pragma_no_asm_inline asm volatile("\n.ascii \"->\"" : : )

#define OFFSET(sym, str, mem) \
	DEFINE(sym, offsetof(struct str, mem))

#define COMMENT(x) \
	asm volatile("\n.ascii \"->#" x "\"")

#endif
