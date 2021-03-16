/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SPARC_SECTIONS_H
#define __SPARC_SECTIONS_H

/* nothing to see, move along */
#include <asm-generic/sections.h>

#ifndef	CONFIG_RECOVERY
#define	__init_recv	__init
#define	__initdata_recv	__initdata
#else
#define	__init_recv
#define	__initdata_recv
#endif	/* ! (CONFIG_RECOVERY) */

#if !defined(CONFIG_RECOVERY) && !defined(CONFIG_SERIAL_PRINTK) && \
	!defined(CONFIG_LMS_CONSOLE)
#define	__init_cons			__init
#else
#define	__init_cons
#endif	/* boot console used after init completion */

#define __interrupt
#define __init_kexec	__init

#ifdef CONFIG_MCST
#ifndef	CONFIG_RECOVERY
#define	__init_recv			__init
#else
#define	__init_recv
#endif	/* ! (CONFIG_RECOVERY) */

#if !defined(CONFIG_RECOVERY) && !defined(CONFIG_SERIAL_PRINTK) && \
	!defined(CONFIG_LMS_CONSOLE)
#define	__init_cons			__init
#else
#define	__init_cons
#endif	/* boot console used after init completion */

#define __interrupt
#define __init_kexec	__init
#endif /* CONFIG_MCST */

/* sparc entry point */
extern char _start[];

extern char __leon_1insn_patch[];
extern char __leon_1insn_patch_end[];

#endif
