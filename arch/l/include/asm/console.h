
#ifndef	_L_CONSOLE_H_
#define	_L_CONSOLE_H_

#ifndef __ASSEMBLY__
#include <linux/init.h>
#include <linux/spinlock_types.h>
#include <stdarg.h>
#include <asm/bootinfo.h>
#include <asm/sections.h>
#include <asm-l/console_types.h>

#ifdef	CONFIG_SERIAL_PRINTK
# ifdef CONFIG_SERIAL_AM85C30_CONSOLE
extern serial_console_opts_t am85c30_serial_console;
# endif

extern serial_console_opts_t *serial_console_opts;
# define opts_entry(opts, member) opts->member
# define serial_console_opts_entry(entry) opts_entry(serial_console_opts, entry)

extern unsigned char serial_dump_console_num;

extern void *get_serial_console_io_base(void);

extern void setup_serial_dump_console(boot_info_t *);
#endif	/* CONFIG_SERIAL_PRINTK */

#ifdef	CONFIG_L_EARLY_PRINTK
extern void dump_printk(char const *fmt_v, ...);
extern void dump_vprintk(char const *fmt, va_list ap);
extern void dump_puts(const char *s);
extern void dump_putns(const char *s, int n);

# ifdef CONFIG_EARLY_DUMP_CONSOLE
extern void register_early_dump_console(void);
# else
static inline void register_early_dump_console(void) { };
# endif

# ifdef CONFIG_EARLY_PRINTK
extern int switch_to_early_dump_console(void);
extern void switch_from_early_dump_console(void);
# endif

#else	/* !CONFIG_L_EARLY_PRINTK */
# define dump_printk	printk
# define dump_vprintk	vprintk
# define dump_puts(s)	printk("%s", (s))
static inline void register_early_dump_console(void) { };

#endif	/* CONFIG_L_EARLY_PRINTK */

#if defined(CONFIG_SERIAL_AM85C30_CONSOLE) && defined(CONFIG_SERIAL_L_ZILOG)
extern raw_spinlock_t *uap_a_reg_lock;
#endif

#endif /* __ASSEMBLY__ */
#endif  /* _L_CONSOLE_H_ */
