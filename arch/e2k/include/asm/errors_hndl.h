/* $Id: errors_hndl.h,v 1.6 2009/01/22 17:10:07 atic Exp $
 *
 * Handling of errors of boot-time & initialization.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_ERRORS_HNDL_H
#define	_E2K_ERRORS_HNDL_H

#ifndef __ASSEMBLY__

#include <asm/types.h>
#include <asm/console.h>
#include <asm/p2v/boot_console.h>

extern void	init_bug(const char *fmt_v, ...) __noreturn __cold;
extern void	init_warning(const char *fmt_v, ...) __cold;

extern void	boot_bug(const char *fmt_v, ...) __noreturn __cold;
extern void	boot_warning(const char *fmt_v, ...) __cold;
#define BOOT_BUG_POINT(func_name) \
	do_boot_printk("kernel boot-time BUG at %s:%d:%s\n", __FILE__, \
	__LINE__, func_name)
#define BOOT_BUG_ON(condition, format...) ({				\
	int __ret_warn_on = !!(condition);				\
	if (unlikely(__ret_warn_on)) {					\
		do_boot_printk("kernel boot-time BUG at %s:%d:%s\n",	\
			__FILE__, __LINE__, __FUNCTION__);		\
		boot_bug(format);					\
	}								\
	unlikely(__ret_warn_on);					\
})
#define BOOT_BUG(format...) \
do { \
	do_boot_printk("kernel boot-time BUG at %s:%d:%s\n", \
			__FILE__, __LINE__, __FUNCTION__); \
	boot_bug(format); \
} while (0)

#define BOOT_WARNING(format...) \
do { \
	do_boot_printk("kernel boot-time WARNING at %s:%d:%s\n", \
			__FILE__, __LINE__, __FUNCTION__); \
	boot_warning(format); \
} while (0)

#define	boot_native_panic(fmt, args...)	\
		do_boot_printk(fmt, ##args)

#define	init_printk	dump_printk
#define	init_vprintk	dump_vprintk
#define INIT_BUG(format...) \
do { \
	init_printk("kernel init-time BUG at %s:%d:%s\n", \
			__FILE__, __LINE__, __FUNCTION__); \
	init_bug(format); \
} while (0)
#define INIT_WARNING(format...) \
do { \
	init_printk("kernel init-time WARNING at %s:%d:%s\n", \
			__FILE__, __LINE__, __FUNCTION__); \
	init_warning(format); \
} while (0)

#endif /* !(__ASSEMBLY__) */

#endif /* !(_E2K_ERRORS_HNDL_H) */
