#ifdef CONFIG_EARLY_DUMP_CONSOLE
#include <linux/console.h>
#endif
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <asm/console.h>
#include <stdarg.h>
#include <asm/head.h>

#undef  DEBUG_SC_MODE
#undef  DebugSC
#define	DEBUG_SC_MODE	0	/* serial console debug */
#define	DebugSC		if (DEBUG_SC_MODE) dump_printk


/* list of all enabled serial consoles, NULL terminated */
static serial_console_opts_t* serial_dump_consoles[] = {
#if defined(CONFIG_SERIAL_NS16550_CONSOLE)
	&ns16550_serial_console,
#endif	/* SERIAL NS16550 CONSOLE */
#if defined(CONFIG_SERIAL_AM85C30_CONSOLE)
	&am85c30_serial_console,
#endif	/* SERIAL AM85C30 CONSOLE */
	NULL,
};

static volatile int serial_console_inited = 0;
serial_console_opts_t *serial_console_opts = NULL;
unsigned char serial_dump_console_num = 0;

/*
 * Iterates through the list of serial consoles,
 * returning the first one that initializes successfully.
 */
void __init_recv
setup_serial_dump_console(boot_info_t *boot_info)
{
	serial_console_opts_t **consoles = serial_dump_consoles;
	serial_console_opts_t *console;
	int i;

	DebugSC("setup_serial_dump_console() started for consoles "
		"list 0x%lx\n", consoles);
#ifdef	CONFIG_E2K
#ifdef	CONFIG_SMP
	if (!IS_BOOT_STRAP_CPU()) {
		DebugSC("setup_serial_dump_console() CPU is not BSP "
			"waiting for init completion\n");
		while(!serial_console_inited);
		DebugSC("setup_serial_dump_console() waiting for init "
			"completed\n");
		return;
	}
#endif	/* CONFIG_SMP */
#endif	/* CONFIG_E2K */

	/* find most preferred working serial console */
	i = 0;
	console = consoles[i];
	DebugSC("setup_serial_dump_console() start console is 0x%lx\n",
		console);
	while (console != NULL) {
		DebugSC("setup_serial_dump_console() console "
			"init entry 0x%lx\n", console->init);
		if (console->init != NULL) {
			if (console->init(boot_info) == 0) {
				serial_console_opts = console;
				serial_console_inited = 1;
				DebugSC("setup_serial_dump_console() set "
					"this console for using\n");
				return;
			}
		}
		i++;
		console = consoles[i];
		DebugSC("setup_serial_dump_console() next console "
			"pointer 0x%lx\n", console);
	}
	dump_printk("setup_serial_dump_console() could not find working "
		"serial console\n");
	serial_console_inited = -1;
}


#define	FALSE	0
#define	TRUE	1

#define	is_digit(c)	((c >= '0') && (c <= '9'))


static char	temp[80];
static int __init_cons
cvt(unsigned long val, char *buf, long radix, char *digits)
{
	register char *cp = temp;
	register int length = 0;

	if (val == 0) {
		/* Special case */
		*cp++ = '0';
	} else {
		while (val) {
			*cp++ = digits[val % radix];
			val /= radix;
		}
	}
	while (cp != temp) {
		*buf++ = *--cp;
		length++;
	}
	*buf = '\0';
	return (length);
}

static	const char	all_dec[] = "0123456789";
static	const char	all_hex[] = "0123456789abcdef";
static	const char	all_HEX[] = "0123456789ABCDEF";

/* spin lock to synchronize print on SMP */
arch_spinlock_t vprint_lock = __ARCH_SPIN_LOCK_UNLOCKED;

static void  do_dump_vprintk(const char *fmt_v, va_list ap_v);
void dump_vprintk(const char *fmt_v, va_list ap_v);


/*
 *  procedures for dump_kernel
 *  they may be called from trap and sys_rq
 *  those proc are the same as boot_proc but used only virt memory
 */ 

void 
dump_printk(char const *fmt_v, ...)
{
	va_list ap;

	va_start(ap, fmt_v);
	dump_vprintk(fmt_v, ap);
	va_end(ap);
}

#if defined(CONFIG_LMS_CONSOLE)
static __interrupt void outb_nostack(unsigned char byte, unsigned long port)
{
	E2K_WRITE_MAS_B(X86_IO_AREA_PHYS_BASE + port, byte, MAS_IOADDR);
}

static __interrupt u32 inl_nostack(unsigned long port)
{
	return E2K_READ_MAS_W(X86_IO_AREA_PHYS_BASE + port, MAS_IOADDR);
}
#endif

static inline void 
dump_putc(char c)
{
#if defined(CONFIG_LMS_CONSOLE)
	if (!IS_MACHINE_SIM) {
		/* LMS debug port can be used only on simulator */
	} else if (inl_nostack(LMS_CONS_DATA_PORT) != 0xFFFFFFFF) {

		while (inl_nostack(LMS_CONS_DATA_PORT))
			;

		outb_nostack(c, LMS_CONS_DATA_PORT);
		outb_nostack(0, LMS_CONS_DATA_PORT);
	}
#endif /* CONFIG_LMS_CONSOLE */

	if (serial_console_opts != NULL) {
		serial_console_opts->serial_putc(c);
	}
}


__interrupt void dump_vprintk(const char *fmt_v, va_list ap_v)
{
	unsigned long flags;

	/* Disable NMIs as well as normal interrupts
	 * (to avoid deadlock since dump_printk() might be
	 * called from NMI handler). */
#ifdef CONFIG_E2K
	raw_all_irq_save(flags);
#else
	raw_local_irq_save(flags);
#endif
	arch_spin_lock(&vprint_lock);
	do_dump_vprintk(fmt_v, ap_v);
	arch_spin_unlock(&vprint_lock);
#ifdef CONFIG_E2K
	raw_all_irq_restore(flags);
#else
	raw_local_irq_restore(flags);
#endif
}

static char	buf[32];
static __interrupt void do_dump_vprintk(const char *fmt_v, va_list ap_v)
{
	register char *fmt = (char *)fmt_v;
#ifdef CONFIG_E90S
	va_list ap = ap_v;
#else
	register va_list ap = ap_v;
#endif
	register char c, sign, *cp;
	register int left_prec, right_prec, zero_fill, var_size;
	register int length = 0, pad, pad_on_right, always_blank_fill;
	register long long val = 0;

	/* Strip loglevel from the string? */
	if (fmt[0] == KERN_SOH_ASCII && fmt[1]) {
		switch (fmt[1]) {
		case '0' ... '7':
		case 'd':
			fmt += 2;
			break;
		}
	}

	while ((c = *fmt++) != 0) {
		if (c == '%') {
			c = *fmt++;
			left_prec = right_prec = pad_on_right = var_size = 0;
			if (c == '-') {
				c = *fmt++;
				pad_on_right++;
				always_blank_fill = TRUE;
			} else {
				always_blank_fill = FALSE;
			}
			if (c == '0') {
				zero_fill = TRUE;
				c = *fmt++;
			} else {
				zero_fill = FALSE;
			}
			while (is_digit(c)) {
				left_prec = (left_prec * 10) + (c - '0');
				c = *fmt++;
			}
			if (c == '.') {
				c = *fmt++;
				zero_fill++;
				while (is_digit(c)) {
					right_prec = (right_prec * 10) +
							(c - '0');
					c = *fmt++;
				}
			} else {
				right_prec = left_prec;
			}
			if (c == 'l' || c == 'L') {
				var_size = sizeof(long);
				c = *fmt++;
				if (c == 'l' || c == 'L') {
					var_size = sizeof(long long);
					c = *fmt++;
				}
			} else if (c == 'h') {
				c = *fmt++;
				if (c == 'h') {
					c = *fmt++;
					var_size = sizeof(char);
				} else {
					var_size = sizeof(short);
				}
			} else if (c == 'z' || c == 'Z') {
				c = *fmt++;
				var_size = sizeof(size_t);
			} else if (c == 't') {
				c = *fmt++;
				var_size = sizeof(ptrdiff_t);
			} else {
				var_size = 4;
			}
			if (c == 'p') {
				var_size = sizeof(void *);
			}
			sign = '\0';
			if (c == 'd' || c == 'i' || c == 'u' ||\
					 c == 'x' || c == 'X' || c == 'p') {
				int var_signed = (c == 'd'|| c == 'i');
				switch (var_size) {
				case sizeof(long long):
					if (var_signed)
						val = (long long)
							va_arg(ap, long long);
					else
						val = (unsigned long long)
							va_arg(ap, long long);
					break;
				case sizeof(int):
					if (var_signed)
						val = (int) va_arg(ap, int);
					else
						val = (unsigned int)
								va_arg(ap, int);
					break;
				case sizeof(short):
					if (var_signed)
						val = (short) va_arg(ap, int);
					else
						val = (unsigned short)
							va_arg(ap, int);
					break;
				case sizeof(char):
					if (var_signed)
						val = (char) va_arg(ap, int);
					else
						val = (unsigned char)
							va_arg(ap, int);
					break;
				}
				if (val < 0 && (c == 'd' || c == 'i')) {
					sign = '-';
					val = -val;
				}
				if (c == 'd' || c == 'i' || c == 'u') {
					length = cvt(val, buf, 10,
					(char*)all_dec);
				} else if (c == 'x' || c == 'p') {
					length = cvt(val, buf, 16,
						(char*)all_hex);
				} else if (c == 'X') {
					length = cvt(val, buf, 16,
						(char*)all_HEX);
				}
				cp = buf;
			} else if (c == 's') {
				cp = va_arg(ap, char *);
				cp = cp;
				length = strlen(cp);
			} else if (c == 'c') {
				c = va_arg(ap, int);
				dump_putc(c);
				continue;
			} else {
				dump_putc('?');
				continue;
			}

			pad = left_prec - length;
			if (sign != '\0') {
				pad--;
			}
			if (zero_fill && !always_blank_fill) {
				c = '0';
				if (sign != '\0') {
					dump_putc(sign);
					sign = '\0';
				}
			} else {
				c = ' ';
			}
			if (!pad_on_right) {
				while (pad-- > 0) {
					dump_putc(c);
				}
			}
			if (sign != '\0') {
				dump_putc(sign);
			}
			while (length-- > 0) {
				dump_putc(c = *cp++);
				if (c == '\n') {
					dump_putc('\r');
				}
			}
			if (pad_on_right) {
				if (zero_fill && !always_blank_fill)
					c = '0';
				else
					c = ' ';

				while (pad-- > 0) {
					dump_putc(c);
				}
			}
		} else {
			dump_putc(c);
			if (c == '\n') {
				dump_putc('\r');
			}
		}
	}
}

__interrupt void dump_putns(const char *s, int n)
{
	unsigned long flags;

	/* Disable NMIs as well as normal interrupts
	 * (to avoid deadlock since dump_printk() might be
	 * called from NMI handler). */
#ifdef CONFIG_E2K
	raw_all_irq_save(flags);
#else
	raw_local_irq_save(flags);
#endif
	arch_spin_lock(&vprint_lock);

	while (n--) {
		if (*s == '\n')
			dump_putc('\r');
		dump_putc(*s++);
	}

	arch_spin_unlock(&vprint_lock);
#ifdef CONFIG_E2K
	raw_all_irq_restore(flags);
#else
	raw_local_irq_restore(flags);
#endif

}

__interrupt void dump_puts(const char *s)
{
	unsigned long flags;

	/* Disable NMIs as well as normal interrupts
	 * (to avoid deadlock since dump_printk() might be
	 * called from NMI handler). */
#ifdef CONFIG_E2K
	raw_all_irq_save(flags);
#else
	raw_local_irq_save(flags);
#endif
	arch_spin_lock(&vprint_lock);

	while (*s) {
		if (*s == '\n')
			dump_putc('\r');
		dump_putc(*s++);
	}

	arch_spin_unlock(&vprint_lock);
#ifdef CONFIG_E2K
	raw_all_irq_restore(flags);
#else
	raw_local_irq_restore(flags);
#endif
}


#ifdef CONFIG_EARLY_DUMP_CONSOLE
static __init void early_dump_write(struct console *con, const char *s,
		unsigned int count)
{
	unsigned long flags, i;

	/* Disable NMIs as well as normal interrupts
	 * (to avoid deadlock since dump_printk() might be
	 * called from NMI handler). */
# ifdef CONFIG_E2K
	raw_all_irq_save(flags);
# else
	raw_local_irq_save(flags);
# endif
	arch_spin_lock(&vprint_lock);
	for (i = 0; i < count; i++) {
		if (s[i] == '\n')
			dump_putc('\r');
		dump_putc(s[i]);
	}
	arch_spin_unlock(&vprint_lock);
# ifdef CONFIG_E2K
	raw_all_irq_restore(flags);
# else
	raw_local_irq_restore(flags);
# endif
}

static __initdata struct console early_dump_console = {
	.name = "early_dump",
	.write = early_dump_write,
	.flags = CON_BOOT | CON_PRINTBUFFER | CON_ANYTIME,
	.index = -1,
	.device = 0
};

__init void register_early_dump_console()
{
	if (serial_console_opts == NULL)
		return;

	register_console(&early_dump_console);
}
#endif

