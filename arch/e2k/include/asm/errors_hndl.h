/* $Id: errors_hndl.h,v 1.6 2009/01/22 17:10:07 atic Exp $
 *
 * Handling of errors of boot-time & initialization.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_ERRORS_HNDL_H
#define	_E2K_ERRORS_HNDL_H

#include <asm/types.h>

#ifndef __ASSEMBLY__
#include <stdarg.h>

extern void	boot_bug(const char *fmt_v, ...);
extern void	boot_warning(const char *fmt_v, ...);
extern void	init_bug(const char *fmt_v, ...);
extern void	init_warning(const char *fmt_v, ...);

#define	BOOT_BUG	boot_bug
#define	BOOT_WARNING	boot_warning
#define	BOOT_BUG_POINT(func_name) \
		do_boot_printk("kernel boot-time BUG at %s:%d:%s\n", __FILE__, \
			__LINE__, func_name)

#define	BOOT_WARNING_POINT(func_name) \
		do_boot_printk("kernel boot-time WARNING at %s:%d:%s\n", \
			__FILE__, __LINE__, func_name)

#define	init_printk	dump_printk
#define	init_vprintk	dump_vprintk
#define	INIT_BUG	init_bug
#define	INIT_WARNING	init_warning
#define	INIT_BUG_POINT(func_name) \
		init_printk("kernel initialization BUG at %s:%d:%s\n", \
			__FILE__, __LINE__, func_name)

#define	INIT_WARNING_POINT(func_name) \
		init_printk("kernel initialization WARNING at %s:%d:%s\n", \
			__FILE__, __LINE__, func_name)

#define	boot_printk	if (DEBUG_BOOT_MODE) do_boot_printk

#endif /* !(__ASSEMBLY__) */

#endif /* !(_E2K_ERRORS_HNDL_H) */
