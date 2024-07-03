/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifdef CONFIG_EARLY_DUMP_CONSOLE
#include <linux/console.h>
#endif
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <asm/console.h>
#include <stdarg.h>
#include <asm/head.h>
#include <asm/io.h>
#ifdef CONFIG_E2K
#include <asm/pic.h>
#endif
#include <asm/smp.h>

#ifdef CONFIG_E2K
# include <asm/p2v/boot_spinlock.h>
#else
# define boot_spinlock_t arch_spinlock_t
# define arch_boot_spin_lock arch_spin_lock
# define arch_boot_spin_unlock arch_spin_unlock
# define __BOOT_SPIN_LOCK_UNLOCKED __ARCH_SPIN_LOCK_UNLOCKED
#endif

#undef  DEBUG_SC_MODE
#undef  DebugSC
#define	DEBUG_SC_MODE	0	/* serial console debug */
#define	DebugSC		if (DEBUG_SC_MODE) dump_printk

#ifdef	CONFIG_SERIAL_PRINTK
/* list of all enabled serial consoles, NULL terminated */
static serial_console_opts_t* serial_dump_consoles[] = {
#if defined(CONFIG_SERIAL_AM85C30_CONSOLE)
	&am85c30_serial_console,
#endif	/* SERIAL AM85C30 CONSOLE */
	NULL,
};

static volatile int serial_console_inited = 0;
serial_console_opts_t *serial_console_opts = NULL;
static void *serial_console_io_base = NULL;
unsigned char serial_dump_console_num = 0;

static void __init_recv setup_serial_console_io_base(boot_info_t *boot_info)
{
	serial_console_io_base = (void *)boot_info->serial_base;
}

void *get_serial_console_io_base(void)
{
	return serial_console_io_base;
}

/*
 * Iterates through the list of serial consoles,
 * returning the first one that initializes successfully.
 */
void __init_recv setup_serial_dump_console(boot_info_t *boot_info)
{
	serial_console_opts_t **consoles = serial_dump_consoles;
	serial_console_opts_t *console;
	int i;

	DebugSC("setup_serial_dump_console() started for consoles "
		"list 0x%lx\n", consoles);

	setup_serial_console_io_base(boot_info);

#ifdef	CONFIG_E2K
#ifdef	CONFIG_SMP
	if (!read_pic_bsp()) {
		DebugSC("setup_serial_dump_console() CPU is not BSP "
			"waiting for init completion\n");
		while (!serial_console_inited)
			cpu_relax();
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
			if (console->init(serial_console_io_base) == 0) {
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
#endif	/* CONFIG_SERIAL_PRINTK */

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
boot_spinlock_t vprint_lock = __BOOT_SPIN_LOCK_UNLOCKED;

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
	debug_cons_outb(byte, port);
}

static __interrupt u32 inl_nostack(unsigned long port)
{
	return debug_cons_inl(port);
}
#endif

#ifdef	CONFIG_SERIAL_PRINTK
static void serial_dump_putc(char c)
{
	if (serial_console_opts != NULL) {
		serial_console_opts->serial_putc(c);
		return;
	}
}
#else	/* !CONFIG_SERIAL_PRINTK */
static void serial_dump_putc(char c)
{
}
#endif	/* CONFIG_SERIAL_PRINTK */

#ifdef	CONFIG_LMS_CONSOLE
static void LMS_dump_putc(char c)
{
	if (!NATIVE_IS_MACHINE_SIM) {
		/* LMS debug port can be used only on simulator */
	} else if (inl_nostack(LMS_CONS_DATA_PORT) != 0xffffffff) {

		while (inl_nostack(LMS_CONS_DATA_PORT))
			;

		outb_nostack(c, LMS_CONS_DATA_PORT);
		outb_nostack(0, LMS_CONS_DATA_PORT);
	}
}
#else	/* !CONFIG_LMS_CONSOLE */
static void LMS_dump_putc(char c)
{
}
#endif	/* CONFIG_LMS_CONSOLE */

void early_serial_write(struct console *con, const char *s,
		unsigned int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (s[i] == '\n')
			serial_dump_putc('\r');
		serial_dump_putc(s[i]);
	}
}

#ifdef	CONFIG_LMS_CONSOLE
static void early_LMS_write(struct console *con, const char *s,
		unsigned int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (s[i] == '\n')
			LMS_dump_putc('\r');
		LMS_dump_putc(s[i]);
	}
}
#endif	/* CONFIG_LMS_CONSOLE */

static inline void dump_putc(char c)
{
	LMS_dump_putc(c);

	serial_dump_putc(c);

	/* guest kernel virtual console support */
	virt_console_dump_putc(c);
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
	arch_boot_spin_lock(&vprint_lock);
	do_dump_vprintk(fmt_v, ap_v);
	arch_boot_spin_unlock(&vprint_lock);
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
	arch_boot_spin_lock(&vprint_lock);

	while (n--) {
		if (*s == '\n')
			dump_putc('\r');
		dump_putc(*s++);
	}

	arch_boot_spin_unlock(&vprint_lock);
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
	arch_boot_spin_lock(&vprint_lock);

	while (*s) {
		if (*s == '\n')
			dump_putc('\r');
		dump_putc(*s++);
	}

	arch_boot_spin_unlock(&vprint_lock);
#ifdef CONFIG_E2K
	raw_all_irq_restore(flags);
#else
	raw_local_irq_restore(flags);
#endif
}


#ifdef CONFIG_EARLY_DUMP_CONSOLE
static void early_dump_write(struct console *con, const char *s,
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
	arch_boot_spin_lock(&vprint_lock);
	for (i = 0; i < count; i++) {
		if (s[i] == '\n')
			dump_putc('\r');
		dump_putc(s[i]);
	}
	arch_boot_spin_unlock(&vprint_lock);
# ifdef CONFIG_E2K
	raw_all_irq_restore(flags);
# else
	raw_local_irq_restore(flags);
# endif
}

static struct console early_serial_console = {
	.name = "early-ttyS",
	.write = early_serial_write,
	.flags = CON_BOOT | CON_PRINTBUFFER | CON_ANYTIME,
	.index = -1,
	.device = 0
};

#ifdef	CONFIG_LMS_CONSOLE
static struct console early_LMS_console = {
	.name = "early-ttyLMS",
	.write = early_LMS_write,
	.flags = CON_BOOT | CON_PRINTBUFFER | CON_ANYTIME,
	.index = -1,
	.device = 0
};
#endif	/* CONFIG_LMS_CONSOLE */

static struct console early_dump_console = {
	.name = "early-dump",
	.write = early_dump_write,
	.flags = CON_BOOT | CON_PRINTBUFFER | CON_ANYTIME,
	.index = -1,
	.device = 0
};

/*
 * FIXME: The next function and its call with support functions should
 * be deleted to use only interface of early printk consoles registration.
 * (see bellow the function setup_early_printk()). But that means the mandatory
 * presence of early console option on command line.
 * The dump_printk() interface can be kept to have output to direct console.
 */
__init void register_early_dump_console(void)
{
	if (early_console)
		return;

	register_console(&early_dump_console);

# ifdef CONFIG_EARLY_PRINTK
	early_console = &early_dump_console;
# endif
}

static __init void register_early_console(struct console *con, int keep_early)
{
	if (con == NULL) {
		pr_err("ERROR: earlyprintk=... cannot init console\n");
		return;
	}
	if (con->index != -1) {
		printk(KERN_CRIT "ERROR: earlyprintk= %s already used\n",
			con->name);
		return;
	}
	early_console = con;
	early_console->flags |= CON_BOOT;
	register_console(early_console);
}

#define DEFAULT_BAUD 115200

static __init char *early_serial_init(char *s, int *idx, char **options)
{
	unsigned long baud = DEFAULT_BAUD;
	char *e;

	/* syntax: ttyS<port #>,<baud> : examples ttyS0/ttyS0,115200 ... */
	if (*s == ',') {
		++s;
		*options = s;
	}

	if (*s) {
		int port;

		port = simple_strtoul(s, &e, 10);
		if (s != e) {
			*idx = port;
		}
		s += strcspn(s, ",");
		if (*s == ',') {
			s++;
			*options = s;
		}
	}

	if (*s) {
		baud = simple_strtoull(s, &e, 0);
		if (baud == 0 || s == e)
			baud = DEFAULT_BAUD;
		s = e;
	}
	return s;
}

#ifdef	CONFIG_LMS_CONSOLE
static __init char *early_LMS_init(char *s)
{
	char *e;

	/* syntax: ttyLMS<port #> : examples ttyLMS/ttyLMS0,ttyLMS1 ... */
	if (*s) {
		unsigned port;

		port = simple_strtoul(s, &e, 10);
		s = e;
	}

	return s;
}
#endif	/* CONFIG_LMS_CONSOLE */

#ifdef	CONFIG_EARLY_VIRTIO_CONSOLE
static __init char *early_hvc_init(char *s,  int *idx)
{
	char *e;

	/* syntax: hvc<port #> : examples hvc/hvc0 */
	if (*s) {
		int port;

		port = simple_strtoul(s, &e, 10);
		if (s != e) {
			*idx = port;
		}
		s = e;
	}

	return s;
}
#endif	/* CONFIG_EARLY_VIRTIO_CONSOLE */

typedef struct early_console {
	char	*name;
	bool	keep;
	int	idx;
	char	*options;
} early_console_t;

#define	MAX_EARLY_CONSELES_NUM	3	/* ttyS, ttyLMS, hvc */

static int __init setup_early_printk(char *buf)
{
	bool keep;
	early_console_t consoles[MAX_EARLY_CONSELES_NUM];
	early_console_t *console = &consoles[0];
	int consoles_num = 0, c;

	if (!buf)
		return 0;

	if (early_console) {
		/* early console has been already registered otherwise */
		return 0;
	}

	/* WARNING: keep option applies to all 'earlyprintk=' consoles */
	keep = (strstr(buf, "keep") != NULL);

	while (*buf != '\0') {
		bool found;

		found = false;

		if (!strncmp(buf, "ttyS", 4)) {
			int sidx = 0;
			char *soptions = NULL;

			buf = early_serial_init(buf + 4, &sidx, &soptions);
			register_early_console(&early_serial_console, keep);
			console->name = "ttyS";
			console->keep = keep;
			console->idx  = sidx;
			console->options = soptions;
			consoles_num++;
			if (consoles_num >= MAX_EARLY_CONSELES_NUM) {
				break;
			}
			console++;
			found = true;
		}

#ifdef	CONFIG_LMS_CONSOLE
		if (!strncmp(buf, "ttyLMS", 6)) {
			buf = early_LMS_init(buf + 6);
			register_early_console(&early_LMS_console, keep);
			console->name = "ttyLMS";
			console->keep = keep;
			console->idx  = 0;
			console->options = NULL;
			consoles_num++;
			if (consoles_num >= MAX_EARLY_CONSELES_NUM) {
				break;
			}
			console++;
			found = true;
		}
#endif	/* CONFIG_LMS_CONSOLE */

#ifdef	CONFIG_EARLY_VIRTIO_CONSOLE
		if (!strncmp(buf, "hvc", 3)) {\
			struct console *hvc_con;
			int hvc_idx = 0;

			buf = early_hvc_init(buf + 3, &hvc_idx);
			hvc_con = hvc_l_early_cons_init(hvc_idx);
			if (hvc_con == NULL) {
				pr_err("%s(): could not create early HVC "
					"console. ignore the hvc console\n",
					__func__);
			} else {
				register_early_console(hvc_con, keep);
				console->name = "hvc";
				console->keep = keep;
				console->idx  = hvc_idx;
				console->options = NULL;
				consoles_num++;
				if (consoles_num >= MAX_EARLY_CONSELES_NUM) {
					break;
				}
				console++;
			}
			found = true;
		}
#endif	/* CONFIG_EARLY_VIRTIO_CONSOLE */

		if (!found) {
			buf++;
		}
	}

	for (c = 0; c < consoles_num; c++) {
		/* WARNING: prefered consoles have to be added */
		/* only after registration of all early consoles */
		/* the order of consoles is important and should be kept */
		console = &consoles[c];
		if (console->keep) {
			add_preferred_console(console->name,
					console->idx, console->options);
		}
	}
	return 0;
}
early_param("earlyprintk", setup_early_printk);

# ifdef CONFIG_EARLY_PRINTK
int switch_to_early_dump_console()
{
	return 0;
}

void switch_from_early_dump_console()
{
}
# endif

#endif	/* CONFIG_EARLY_DUMP_CONSOLE */


/*
 * Temporary dumper until RealTime patch gains
 * proper support for console_flush_on_panic().
 */
#include <linux/kmsg_dump.h>

static void kmsg_dumper_stdout(struct kmsg_dumper *dumper,
			       enum kmsg_dump_reason reason,
			       struct kmsg_dumper_iter *iter)
{
	static char line[1024];
	size_t len = 0;

	dump_puts("kmsg_dump (dump of the whole printk buffer on panic(), can have some lines doubled but will probably output more messages including KERN_DEBUG ones and those that just had no time to be printed before panic()):\n");
	while (kmsg_dump_get_line(iter, true, line, sizeof(line), &len)) {
		line[len] = '\0';
		dump_puts(line);
	}
}

static struct kmsg_dumper kmsg_dumper = {
	.dump = kmsg_dumper_stdout
};

int __init kmsg_dumper_stdout_init(void)
{
	return kmsg_dump_register(&kmsg_dumper);
}
arch_initcall(kmsg_dumper_stdout_init);
