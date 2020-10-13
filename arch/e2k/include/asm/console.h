
#ifndef	_E2K_CONSOLE_H_
#define	_E2K_CONSOLE_H_

#ifdef __KERNEL__

#ifndef __ASSEMBLY__
#include <linux/init.h>
#include <asm/types.h>
#include <stdarg.h>
#include <asm/io.h>
#include <asm/boot_head.h>
#include <asm-l/console.h>
#include <asm/e2k.h>

#ifdef CONFIG_SERIAL_BOOT_PRINTK

# define boot_serial_boot_console_opts \
		boot_get_vo_value(serial_boot_console_opts)
# define boot_opts_entry(opts, member)					\
({									\
	serial_console_opts_t *opts_p = boot_vp_to_pp(opts);		\
	typeof (opts_p->member) entry;					\
	entry = opts_p->member;						\
	((typeof (opts_p->member))boot_vp_to_pp(entry));		\
})
# define boot_serial_boot_console_opts_entry(entry) \
		boot_opts_entry(boot_serial_boot_console_opts, entry)

extern unsigned char serial_dump_console_num;
#define boot_serial_boot_console_num  boot_get_vo_value(serial_dump_console_num)

extern void __init_recv boot_setup_serial_console(boot_info_t *);

extern void __init_cons do_boot_printk(char const *fmt_v, ...);
extern void __init_cons boot_vprintk(char const *fmt_v, va_list ap_v);
extern void __init_recv boot_bug(const char *fmt_v, ...);
extern void __init_recv boot_warning(const char *fmt_v, ...);

# ifdef CONFIG_SERIAL_NS16550_BOOT_CONSOLE
extern serial_console_opts_t ns16550_serial_boot_console;
# endif

# ifdef CONFIG_SERIAL_AM85C30_BOOT_CONSOLE
extern serial_console_opts_t am85c30_serial_boot_console;
# endif
#else
# define do_boot_printk(...)
# define boot_vprintk(...)
# define boot_bug(...)
# define boot_warning(...)
#endif /* SERIAL_BOOT_PRINTK */

extern void		init_bug(const char *fmt_v, ...);
extern void		init_warning(const char *fmt_v, ...);

#endif /* __ASSEMBLY__ */

#endif  /* __KERNEL__ */
#endif  /* _E2K_CONSOLE_H_ */
