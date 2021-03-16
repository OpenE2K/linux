#ifndef	_L_CONSOLE_TYPES_H_
#define	_L_CONSOLE_TYPES_H_

#ifndef __ASSEMBLY__
#include <asm/bootinfo.h>
#ifdef CONFIG_E2K
# include <asm/p2v/boot_spinlock_types.h>
extern boot_spinlock_t vprint_lock;
#endif

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
	int (*init)(void *serial_io_base);
	void (*serial_putc)(unsigned char c);
} serial_console_opts_t;
#endif /* SERIAL_PRINTK || SERIAL_BOOT_PRINTK */

#endif /* __ASSEMBLY__ */
#endif  /* _L_CONSOLE_H_ */
