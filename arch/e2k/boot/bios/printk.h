/*
 * $Id: printk.h,v 1.1 2005/08/19 13:17:27 kostin Exp $
 */

#ifndef _PRINTK_H_
#define _PRINTK_H_

extern void rom_printk(char const *fmt, ...);
#define do_printk rom_printk

#undef printk_emerg
#undef printk_alert
#undef printk_crit
#undef printk_err
#undef printk_warning
#undef printk_notice
#undef printk_info
#undef printk_debug
#undef printk_spew

#ifdef BIOS_DEBUG
#define printk_emerg(fmt, arg...)   do_printk(fmt, ##arg)
#define printk_alert(fmt, arg...)   do_printk(fmt, ##arg)
#define printk_crit(fmt, arg...)    do_printk(fmt, ##arg)
#define printk_err(fmt, arg...)     do_printk(fmt, ##arg)
#define printk_warning(fmt, arg...) do_printk(fmt, ##arg)
#define printk_notice(fmt, arg...)  do_printk(fmt, ##arg)
#define printk_info(fmt, arg...)    do_printk(fmt, ##arg)
#define printk_debug(fmt, arg...)   if (BIOS_DEBUG > 0) do_printk(fmt, ##arg)
#define printk_spew(fmt, arg...)    if (BIOS_DEBUG > 1) do_printk(fmt, ##arg)
#else
#define printk_emerg(fmt, arg...)   do_printk(fmt, ##arg)
#define printk_alert(fmt, arg...)   do_printk(fmt, ##arg)
#define printk_crit(fmt, arg...)    do_printk(fmt, ##arg)
#define printk_err(fmt, arg...)     do_printk(fmt, ##arg)
#define printk_warning(fmt, arg...) do_printk(fmt, ##arg)
#define printk_notice(fmt, arg...)  do_printk(fmt, ##arg)
#define printk_info(fmt, arg...)    do_printk(fmt, ##arg)
#define printk_debug(fmt, arg...)
#define printk_spew(fmt, arg...)
#endif

#endif
