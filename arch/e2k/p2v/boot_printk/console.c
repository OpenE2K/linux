/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/p2v/boot_v2p.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/stdarg.h>

#include <asm/head.h>
#include <asm/p2v/boot_head.h>
#include <asm/e2k.h>
#include <asm/io.h>
#include <asm/simul.h>
#include <asm/p2v/boot_console.h>
#include <asm/p2v/boot_irqflags.h>
#include <asm/p2v/boot_param.h>
#include <asm/p2v/boot_smp.h>

#include "../boot_string.h"

#undef  DEBUG_SC_MODE
#undef  DebugSC
#define	DEBUG_SC_MODE	0	/* serial console debug */
#define	DebugSC		if (DEBUG_SC_MODE) do_boot_printk

#define	FALSE	0
#define	TRUE	1

#define CONSOLE_CHANNEL_DENY	0xff

#define	is_digit(c)	((c >= '0') && (c <= '9'))

#ifdef	CONFIG_SERIAL_BOOT_PRINTK

bool serial_console_enable = false;
static bool serial_console_cmd = false;
static bool lms_console_cmd = false;
bool hvc_console_cmd = false;
unsigned long io_area_phys_base = -1;
static int serial_console_index = -1;
#ifdef	CONFIG_LMS_CONSOLE
static bool lms_console_enable = false;
#define boot_lms_console_enable	boot_get_vo_value(lms_console_enable)
#else	/* !CONFIG_LMS_CONSOLE */
# define lms_console_enable	false
#define boot_lms_console_enable	lms_console_enable
#endif	/* CONFIG_LMS_CONSOLE */

#define boot_serial_console_enable boot_get_vo_value(serial_console_enable)
#define boot_serial_console_cmd	boot_get_vo_value(serial_console_cmd)
#define boot_lms_console_cmd	boot_get_vo_value(lms_console_cmd)
#define boot_io_area_phys_base	boot_get_vo_value(io_area_phys_base)
#define boot_serial_console_index boot_get_vo_value(serial_console_index)

/*
 * Serial dump console num setup
 */
static int __init boot_dump_console_set(char *cmd)
{
	if (boot_strlen(cmd) == 2 && !boot_strcmp(cmd, "no")) {
		boot_serial_dump_console_num = SERIAL_DUMP_CONSOLE_DENY;
	} else {
		boot_serial_dump_console_num = boot_simple_strtoul(cmd, &cmd, 0);
		if (boot_serial_dump_console_num > 1)
			boot_serial_dump_console_num = 0;
	}
	return 0;
}
__boot_setup("dump_console", boot_dump_console_set);

static void parse_console_params(boot_info_t *info)
{
	char *cmdline;

	if (info->kernel_args_string_pnt) {
		/* command line pointer */
		cmdline = (char *)info->kernel_args_string_pnt;
	} else if (!boot_strncmp(info->kernel_args_string,
				 boot_vp_to_pp((char *)KERNEL_ARGS_STRING_EX_SIGNATURE),
				 KERNEL_ARGS_STRING_EX_SIGN_SIZE)) {
		/* Extended command line (512 bytes) */
		cmdline = (char *)info->kernel_args_string_ex;
	} else {
		/* Standart command line (128 bytes) */
		cmdline = (char *)info->kernel_args_string;
	}

	if (boot_strstr(cmdline, boot_vp_to_pp((char *)"dump_console=1"))) {
		boot_serial_dump_console_num = 1;
	} else if (boot_strstr(cmdline, "dump_console=no")) {
		boot_serial_dump_console_num = CONSOLE_CHANNEL_DENY;
	}

	if (boot_strstr(cmdline, boot_vp_to_pp((char *)"console=ttyS")) != NULL) {
		boot_serial_console_cmd = true;
	} else {
		boot_serial_console_cmd = false;
	}

	if (boot_strstr(cmdline, boot_vp_to_pp((char *)"LMS")) != NULL) {
		boot_lms_console_cmd = true;
	} else {
		boot_lms_console_cmd = false;
	}

	if (boot_strstr(cmdline, boot_vp_to_pp((char *)"console=hvc")) != NULL) {
		boot_hvc_console_cmd = true;
	} else {
		boot_hvc_console_cmd = false;
	}
}

/* list of all enabled serial consoles, NULL terminated */
static serial_console_opts_t* serial_boot_consoles[] = {
#if defined(CONFIG_SERIAL_AM85C30_BOOT_CONSOLE)
	&am85c30_serial_boot_console,
#endif	/* SERIAL AM85C30 CONSOLE */
	NULL,
};

static volatile int serial_boot_console_inited = 0;
static serial_console_opts_t *serial_boot_console_opts = NULL;
#define	boot_serial_boot_console_inited \
		boot_get_vo_value(serial_boot_console_inited)
#define	boot_serial_boot_consoles	\
		boot_vp_to_pp((serial_console_opts_t **)serial_boot_consoles)

/*
 * Iterates through the list of serial consoles,
 * returning the first one that initializes successfully.
 */
void __init_recv
boot_setup_serial_console(bool bsp, boot_info_t *boot_info)
{
	serial_console_opts_t **consoles = boot_serial_boot_consoles;
	serial_console_opts_t *console;
	int i;

	DebugSC("boot_setup_serial_console() started for consoles "
		"list 0x%lx\n", consoles);

#ifdef	CONFIG_SMP
	if (!bsp) {
		DebugSC("boot_setup_serial_console() CPU is not BSP "
			"waiting for init completion\n");
		while(!boot_serial_boot_console_inited)
			boot_cpu_relax();
		DebugSC("boot_setup_serial_console() waiting for init "
			"completed\n");
		return;
	}
#endif	/* CONFIG_SMP */

	parse_console_params(boot_info);

#ifdef	CONFIG_LMS_CONSOLE
	bool is_simulator;
	is_simulator = !!(boot_info->mach_flags & SIMULATOR_MACH_FLAG);
	if (boot_lms_console_cmd && is_simulator && !BOOT_IS_HV_GM()) {
		boot_lms_console_enable = true;
	}

	if (boot_read_IDR_reg().mdl == IDR_E1CP_MDL)
		boot_io_area_phys_base = E2K_LEGACY_SIC_IO_AREA_PHYS_BASE;
	else
		boot_io_area_phys_base = E2K_FULL_SIC_IO_AREA_PHYS_BASE;
#endif	/* CONFIG_LMS_CONSOLE */

	/* find most preferred working serial console */
	i = 0;
	console = consoles[i];
	DebugSC("boot_setup_serial_console() start console is 0x%lx\n",
		console);
	while (console != NULL) {
		int (*boot_init)(void *serial_base);

		boot_init = boot_opts_func_entry(console, init);
		DebugSC("boot_setup_serial_console() console phys "
			"init entry 0x%lx\n", boot_init);
		if (boot_init != NULL) {
			if (boot_init((void *)boot_info->serial_base) == 0) {
				boot_serial_boot_console_opts = console;
				boot_serial_console_index = i;
				boot_serial_console_enable = true;
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
#endif	/* CONFIG_SERIAL_BOOT_PRINTK */

static void __init_cons
boot_putc(char c)
{
#if defined(CONFIG_LMS_CONSOLE)
	if (likely(!boot_lms_console_enable)) {
		/* LMS debug port can be used only on simulator */
	} else if (boot_debug_cons_inl(LMS_CONS_DATA_PORT) != 0xFFFFFFFF) {

		while (boot_debug_cons_inl(LMS_CONS_DATA_PORT))
			;

		boot_debug_cons_outb(c, LMS_CONS_DATA_PORT);
		boot_debug_cons_outb(0, LMS_CONS_DATA_PORT);
	}
#endif /* CONFIG_LMS_CONSOLE */

#if defined(CONFIG_SERIAL_BOOT_PRINTK)
	if (boot_serial_boot_console_opts != NULL)
		boot_serial_boot_console_opts_func_entry(serial_putc)(c);
#endif /* serial console or LMS console or early printk */

#ifdef	CONFIG_EARLY_VIRTIO_CONSOLE
	if (boot_early_virtio_cons_enabled) {
		boot_hvc_l_raw_putc(c);
	}
#endif	/* CONFIG_EARLY_VIRTIO_CONSOLE */
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
	register char *temp = boot_vp_to_pp((char *)boot_temp);
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
	register const char *fmt = boot_vp_to_pp(fmt_v);
	register va_list ap = boot_vp_to_pp(ap_v);
	register char c, sign, *cp;
	register int left_prec, right_prec, zero_fill, var_size;
	register int length = 0, pad, pad_on_right, always_blank_fill;
	register char *buf = boot_vp_to_pp((char *)boot_buf);
	register long long val = 0;

	while ((c = *fmt++) != 0) {
		if (c == '%') {
			c = *fmt++;
			left_prec = 0;
			right_prec = 0;
			pad_on_right = 0;
			var_size = 0;
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
					length = boot_cvt(val, buf, 10,
						boot_vp_to_pp((char *)
								boot_all_dec));
				} else if (c == 'x' || c == 'p') {
					length = boot_cvt(val, buf, 16,
						boot_vp_to_pp((char *)
								boot_all_hex));
				} else if (c == 'X') {
					length = boot_cvt(val, buf, 16,
						boot_vp_to_pp((char *)
								boot_all_HEX));
				}
				cp = buf;
			} else if (c == 's') {
				cp = va_arg(ap, char *);
				cp = boot_vp_to_pp(cp);
				length = boot_strlen(cp);
			} else if (c == 'c') {
				c = va_arg(ap, int);
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


#ifndef CONFIG_L_EARLY_PRINTK
/* dump_printk() is not configured, so define
 * the spinlock to synchronize print on SMP here. */
boot_spinlock_t vprint_lock = __BOOT_SPIN_LOCK_UNLOCKED;
#endif	/* !CONFIG_L_EARLY_PRINTK */

void __init_cons
boot_vprintk(const char *fmt_v, va_list ap_v)
{
	unsigned long flags;

	/* Disable NMIs as well as normal interrupts */
	boot_raw_all_irq_save(flags);
	boot_spin_lock(&vprint_lock);
	if (boot_numa_node_id_initialized()) {
		boot_prefix_printk("BOOT NODE %d CPU %d: ",
			boot_numa_node_id(), boot_smp_processor_id());
	} else {
		boot_prefix_printk("BOOT CPU_TOTAL %d: ", boot_smp_processor_id());
	}
	do_boot_vprintk(fmt_v, ap_v);
	boot_spin_unlock(&vprint_lock);
	boot_raw_all_irq_restore(flags);
}

static void __init_cons
boot_vprintk_no_prefix(const char *fmt_v, va_list ap_v)
{
	unsigned long flags;

	/* Disable NMIs as well as normal interrupts */
	boot_raw_all_irq_save(flags);
	boot_spin_lock(&vprint_lock);
	do_boot_vprintk(fmt_v, ap_v);
	boot_spin_unlock(&vprint_lock);
	boot_raw_all_irq_restore(flags);
}

#ifdef CONFIG_BOOT_PRINTK
void __init_cons
do_boot_printk(char const *fmt_v, ...)
{
	register va_list ap;

	va_start(ap, fmt_v);
	boot_vprintk(fmt_v, ap);
	va_end(ap);
}
#endif

/*
 * Handler of boot-time errors.
 * The error message is output on console and CPU goes to suspended state
 * (executes infinite unmeaning cicle).
 * In simulation mode CPU is halted with error sign.
 */

#ifdef CONFIG_BOOT_PRINTK
void boot_bug(const char *fmt_v, ...)
#else  /* !CONFIG_BOOT_PRINTK */
static inline void boot_bug(const char *fmt_v, ...)
#endif /* !CONFIG_BOOT_PRINTK */
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
		boot_cpu_relax();
}

/*
 * Handler of boot-time warnings.
 * The warning message is output on console and CPU continues execution of
 * boot process.
 */

#ifdef CONFIG_BOOT_PRINTK
void __init_recv
boot_warning(const char *fmt_v, ...)
{
	register va_list ap;

	va_start(ap, fmt_v);
	boot_vprintk(fmt_v, ap);
	va_end(ap);
	boot_vprintk_no_prefix("\n", NULL);
}
#endif /* CONFIG_BOOT_PRINTK */

