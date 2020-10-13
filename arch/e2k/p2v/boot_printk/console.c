#include <linux/init.h>
#include <stdarg.h>
#include <asm/head.h>
#include <asm/boot_head.h>
#include <asm/console.h>
#include <asm/boot_param.h>

#undef  DEBUG_SC_MODE
#undef  DebugSC
#define	DEBUG_SC_MODE	0	/* serial console debug */
#define	DebugSC		if (DEBUG_SC_MODE) do_boot_printk

#define	FALSE	0
#define	TRUE	1

#define	is_digit(c)	((c >= '0') && (c <= '9'))

/*
 * Serial dump console num setup
 */

static int __init boot_dump_console_set(char *cmd)
{
	boot_serial_boot_console_num = boot_simple_strtoul(cmd, &cmd, 0);
	return 0;
}
boot_param("dump_console", boot_dump_console_set);

/* list of all enabled serial consoles, NULL terminated */
static serial_console_opts_t* serial_boot_consoles[] = {
#if defined(CONFIG_SERIAL_NS16550_BOOT_CONSOLE)
	&ns16550_serial_boot_console,
#endif	/* SERIAL NS16550 CONSOLE */
#if defined(CONFIG_SERIAL_AM85C30_BOOT_CONSOLE)
	&am85c30_serial_boot_console,
#endif	/* SERIAL AM85C30 CONSOLE */
	NULL,
};

static volatile int serial_boot_console_inited = 0;
serial_console_opts_t *serial_boot_console_opts = NULL;
#define	boot_serial_boot_console_inited \
		boot_get_vo_value(serial_boot_console_inited)
#define	boot_serial_boot_consoles	boot_vp_to_pp(serial_boot_consoles)

/*
 * Iterates through the list of serial consoles,
 * returning the first one that initializes successfully.
 */
void __init_recv
boot_setup_serial_console(boot_info_t *boot_info)
{
	serial_console_opts_t **consoles = boot_serial_boot_consoles;
	serial_console_opts_t *console;
	int i;

	DebugSC("boot_setup_serial_console() started for consoles "
		"list 0x%lx\n", consoles);

#ifdef	CONFIG_SMP
	if (!IS_BOOT_STRAP_CPU()) {
		DebugSC("boot_setup_serial_console() CPU is not BSP "
			"waiting for init completion\n");
		while(!boot_serial_boot_console_inited)
			;
		DebugSC("boot_setup_serial_console() waiting for init "
			"completed\n");
		return;
	}
#endif	/* CONFIG_SMP */

	/* find most preferred working serial console */
	i = 0;
	console = consoles[i];
	DebugSC("boot_setup_serial_console() start console is 0x%lx\n",
		console);
	while (console != NULL) {
		int (*boot_init)(boot_info_t *boot_info);

		boot_init = boot_opts_entry(console, init);
		DebugSC("boot_setup_serial_console() console phys "
			"init entry 0x%lx\n", boot_init);
		if (boot_init != NULL) {
			if (boot_init(boot_info) == 0) {
				boot_serial_boot_console_opts = console;
				boot_serial_boot_console_inited = 1;
				DebugSC("boot_setup_serial_console() set "
					"this console for using\n");
				return;
			}
		}
		i++;
		console = consoles[i];
		DebugSC("boot_setup_serial_console() next console "
			"pointer 0x%lx\n", console);
	}
	do_boot_printk("boot_setup_serial_console() could not find working "
		"serial console\n");
	boot_serial_boot_console_inited = -1;
}


static void __init_cons
boot_putc(char c)
{
#if defined(CONFIG_LMS_CONSOLE)
	if (!BOOT_IS_MACHINE_SIM) {
		/* LMS debug port can be used only on simulator */
	} else if (boot_inl(LMS_CONS_DATA_PORT) != 0xFFFFFFFF) {

		while (boot_inl(LMS_CONS_DATA_PORT));

		boot_outb(LMS_CONS_DATA_PORT, c);
		boot_outb(LMS_CONS_DATA_PORT, 0);
	}
#endif /* CONFIG_LMS_CONSOLE */

#if defined(CONFIG_SERIAL_BOOT_PRINTK)
	if (boot_serial_boot_console_opts != NULL)
		boot_serial_boot_console_opts_entry(serial_putc)(c);
#endif /* serial console or LMS console or early printk */
}


/*
 * Write formatted output while booting process is in the progress and
 * virtual memory support is not still ready
 * All function pointer arguments consider as pointers to virtual addresses and
 * convert to conforming physical pointers (These are the pointer of format
 * 'fmt_v', pointer of operand list 'ap_v' and pointers in the operands list).
 * Therefore, all passed pointer arguments should be virtual (without any
 * conversion)
 */

static char boot_temp[80];

static int __init_cons
boot_cvt(unsigned long val, char *buf, long radix, char *digits)
{
	register char *temp = boot_vp_to_pp(boot_temp);
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

static char boot_buf[32];
static const char boot_all_dec[] = "0123456789";
static const char boot_all_hex[] = "0123456789abcdef";
static const char boot_all_HEX[] = "0123456789ABCDEF";

static void __init_cons
do_boot_vprintk(const char *fmt_v, va_list ap_v)
{
	register char *fmt = boot_vp_to_pp(fmt_v);
	register va_list ap = boot_vp_to_pp(ap_v);
	register char c, sign, *cp;
	register int left_prec, right_prec, zero_fill, var_size;
	register int length = 0, pad, pad_on_right, always_blank_fill;
	register char *buf = boot_vp_to_pp(boot_buf);
	register long long val = 0;

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
						val = (short) va_arg(ap, short);
					else
						val = (unsigned short)
							va_arg(ap, short);
					break;
				case sizeof(char):
					if (var_signed)
						val = (char) va_arg(ap, char);
					else
						val = (unsigned char)
							va_arg(ap, char);
					break;
				}
				if (val < 0 && (c == 'd' || c == 'i')) {
					sign = '-';
					val = -val;
				}
				if (c == 'd' || c == 'i' || c == 'u') {
					length = boot_cvt(val, buf, 10,
						boot_vp_to_pp(boot_all_dec));
				} else if (c == 'x' || c == 'p') {
					length = boot_cvt(val, buf, 16,
						boot_vp_to_pp(boot_all_hex));
				} else if (c == 'X') {
					length = boot_cvt(val, buf, 16,
						boot_vp_to_pp(boot_all_HEX));
				}
				cp = buf;
			} else if (c == 's') {
				cp = va_arg(ap, char *);
				cp = boot_vp_to_pp(cp);
				length = strlen(cp);
			} else if (c == 'c') {
				c = va_arg(ap, char);
				boot_putc(c);
				continue;
			} else {
				boot_putc('?');
				continue;
			}

			pad = left_prec - length;
			if (sign != '\0') {
				pad--;
			}
			if (zero_fill && !always_blank_fill) {
				c = '0';
				if (sign != '\0') {
					boot_putc(sign);
					sign = '\0';
				}
			} else {
				c = ' ';
			}
			if (!pad_on_right) {
				while (pad-- > 0) {
					boot_putc(c);
				}
			}
			if (sign != '\0') {
				boot_putc(sign);
			}
			while (length-- > 0) {
				boot_putc(c = *cp++);
				if (c == '\n') {
					boot_putc('\r');
				}
			}
			if (pad_on_right) {
				if (zero_fill && !always_blank_fill)
					c = '0';
				else
					c = ' ';

				while (pad-- > 0) {
					boot_putc(c);
				}
			}
		} else {
			boot_putc(c);
			if (c == '\n') {
				boot_putc('\r');
			}
		}
	}
}


static void __init_cons
boot_prefix_printk(char const *fmt_v, ...)
{
	register va_list ap;

	va_start(ap, fmt_v);
	do_boot_vprintk(fmt_v, ap);
	va_end(ap);
}


#ifndef CONFIG_SERIAL_PRINTK
/* dump_printk() is not configured, so define
 * the spinlock to synchronize print on SMP here. */
arch_spinlock_t vprint_lock = __ARCH_SPIN_LOCK_UNLOCKED;
#endif

void __init_cons
boot_vprintk(const char *fmt_v, va_list ap_v)
{
	unsigned long flags;

	/* Disable NMIs as well as normal interrupts */
	raw_all_irq_save(flags);
	arch_spin_lock(boot_vp_to_pp(&vprint_lock));
	boot_prefix_printk("BOOT NODE %d CPU %d: ",
		boot_numa_node_id(), boot_smp_processor_id());
	do_boot_vprintk(fmt_v, ap_v);
	arch_spin_unlock(boot_vp_to_pp(&vprint_lock));
	raw_all_irq_restore(flags);
}

void __init_cons
boot_vprintk_no_prefix(const char *fmt_v, va_list ap_v)
{
	unsigned long flags;

	/* Disable NMIs as well as normal interrupts */
	raw_all_irq_save(flags);
	arch_spin_lock(boot_vp_to_pp(&vprint_lock));
	do_boot_vprintk(fmt_v, ap_v);
	arch_spin_unlock(boot_vp_to_pp(&vprint_lock));
	raw_all_irq_restore(flags);
}

void __init_cons
do_boot_printk(char const *fmt_v, ...)
{
	register va_list ap;

	va_start(ap, fmt_v);
	boot_vprintk(fmt_v, ap);
	va_end(ap);
}

void __init_cons
boot_puts(char *s)
{
	s = boot_vp_to_pp(s);
	while (*s)
		boot_putc(*s++);
}


/*
 * Handler of boot-time errors.
 * The error message is output on console and CPU goes to suspended state
 * (executes infinite unmeaning cicle).
 * In simulation mode CPU is halted with error sign.
 */

void __init_recv
boot_bug(const char *fmt_v, ...)
{
	register va_list ap;

	va_start(ap, fmt_v);
	boot_vprintk(fmt_v, ap);
	va_end(ap);
	boot_vprintk_no_prefix("\n\n\n", NULL);

#ifdef	CONFIG_SMP
	boot_set_event(&boot_error_flag);
#endif	/* CONFIG_SMP */

	BOOT_E2K_HALT_ERROR(1);

	for (;;)
		cpu_relax();
}

/*
 * Handler of boot-time warnings.
 * The warning message is output on console and CPU continues execution of
 * boot process.
 */

void __init_recv
boot_warning(const char *fmt_v, ...)
{
	register va_list ap;

	va_start(ap, fmt_v);
	boot_vprintk(fmt_v, ap);
	va_end(ap);
	boot_vprintk_no_prefix("\n", NULL);
}

