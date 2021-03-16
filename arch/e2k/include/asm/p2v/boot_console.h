#ifndef	_E2K_P2V_BOOT_CONSOLE_H_
#define	_E2K_P2V_BOOT_CONSOLE_H_

#ifdef __KERNEL__

#ifndef __ASSEMBLY__
#include <stdarg.h>
#include <asm/types.h>
#include <asm-l/console_types.h>
#include <asm/kvm/hvc-console.h>

#ifdef CONFIG_SERIAL_BOOT_PRINTK

# define boot_serial_boot_console_opts \
		boot_get_vo_value(serial_boot_console_opts)
# define boot_opts_entry(opts, member)					\
({									\
	serial_console_opts_t *opts_p = boot_vp_to_pp(opts);		\
	typeof(opts_p->member) entry;					\
	entry = opts_p->member;						\
	((typeof(opts_p->member))boot_vp_to_pp(entry));			\
})
# define boot_opts_func_entry(opts, func)				\
({									\
	serial_console_opts_t *opts_p = boot_vp_to_pp(opts);		\
	typeof(opts_p->func) entry;					\
	entry = opts_p->func;						\
	((typeof(opts_p->func))boot_func_to_pp(entry));			\
})
# define boot_serial_boot_console_opts_entry(entry) \
		boot_opts_entry(boot_serial_boot_console_opts, entry)
# define boot_serial_boot_console_opts_func_entry(func) \
		boot_opts_func_entry(boot_serial_boot_console_opts, func)

extern unsigned char serial_dump_console_num;
#define boot_serial_boot_console_num  boot_get_vo_value(serial_dump_console_num)

extern void __init_recv boot_setup_serial_console(bool bsp, boot_info_t *);
#endif /* CONFIG_SERIAL_BOOT_PRINTK */

# ifdef CONFIG_SERIAL_AM85C30_BOOT_CONSOLE
extern serial_console_opts_t am85c30_serial_boot_console;
# endif

#ifdef	CONFIG_BOOT_PRINTK
extern void do_boot_printk(char const *fmt_v, ...);
extern void boot_vprintk(char const *fmt_v, va_list ap_v);
extern void boot_bug(const char *fmt_v, ...);
extern void boot_warning(const char *fmt_v, ...);

#else	/* !CONFIG_BOOT_PRINTK */
# define do_boot_printk(...)
# define boot_vprintk(...)
static inline void boot_bug(const char *fmt_v, ...)
{
}
static inline void boot_warning(const char *fmt_v, ...)
{
}
#endif /* CONFIG_BOOT_PRINTK */

#define	boot_printk	if (DEBUG_BOOT_MODE) do_boot_printk

#endif /* __ASSEMBLY__ */

#endif  /* __KERNEL__ */
#endif  /* _E2K_P2V_BOOT_CONSOLE_H_ */
