
#ifndef	_L_CONSOLE_H_
#define	_L_CONSOLE_H_

#ifndef __ASSEMBLY__
#include <linux/init.h>
#include <linux/spinlock.h>
#include <asm/types.h>
#include <stdarg.h>
#include <asm/io.h>
#include <asm/bootinfo.h>
#include <asm/sections.h>

#define	L_LMS_CONS_DATA_PORT		LMS_CONS_DATA_PORT
#define	L_LMS_CONS_STATUS_PORT		LMS_CONS_STATUS_PORT

#define SERIAL_CONSOLE_8250_NAME	"8250"

#if defined CONFIG_SERIAL_PRINTK || defined CONFIG_SERIAL_BOOT_PRINTK
# define SERIAL_CONSOLE_16550_NAME	"ns16550"
# define SERIAL_CONSOLE_AM85C30_NAME	"AM85C30"

typedef struct serial_console_opts_ {
	char* name;
	unsigned long long io_base;
	unsigned char (*serial_getc)(void);
	int (*serial_tstc)(void);
	int (*init)(boot_info_t *boot_info);
	void (*serial_putc)(unsigned char c);
} serial_console_opts_t;
#endif /* SERIAL_PRINTK || SERIAL_BOOT_PRINTK */

#ifdef	CONFIG_SERIAL_PRINTK
# ifdef CONFIG_SERIAL_NS16550_CONSOLE
extern serial_console_opts_t ns16550_serial_console;
# endif

# ifdef CONFIG_SERIAL_AM85C30_CONSOLE
extern serial_console_opts_t am85c30_serial_console;
# endif

extern serial_console_opts_t *serial_console_opts;
# define opts_entry(opts, member) opts->member
# define serial_console_opts_entry(entry) opts_entry(serial_console_opts, entry)

extern unsigned char serial_dump_console_num;

extern void __init_recv setup_serial_dump_console(boot_info_t *);

extern void dump_printk(char const *fmt_v, ...);
extern void dump_vprintk(char const *fmt, va_list ap);
extern void dump_puts(const char *s);
extern void dump_putns(const char *s, int n);

# ifdef CONFIG_EARLY_DUMP_CONSOLE
extern void register_early_dump_console(void);
# else
static inline void register_early_dump_console(void) { };
# endif

#else	/* CONFIG_SERIAL_PRINTK */

# define dump_printk	printk
# define dump_vprintk	vprintk
# define dump_puts(s)	printk("%s", (s))

#endif	/* CONFIG_SERIAL_PRINTK */

/* l_boot_printk() is deprecated, use dump_printk() instead. */
static inline notrace __deprecated int l_boot_printk(const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = vprintk(fmt, args);
	va_end(args);
	return r;
}

#ifdef CONFIG_SERIAL_PRINTK
extern int use_boot_printk_all;
extern int use_boot_printk;
extern int console_initialized;
#endif

extern arch_spinlock_t vprint_lock;

#endif /* __ASSEMBLY__ */
#endif  /* _L_CONSOLE_H_ */
