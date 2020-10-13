
#include <linux/types.h>
#include <asm/e2k_debug.h>
#include <asm/console.h>
#include <stdarg.h>

#if defined(CONFIG_BIOS)
#include "bios/bios.h"
#endif

#define FALSE 0
#define TRUE  1

#if defined(CONFIG_VGA_CONSOLE)
extern void vga_init(void);
extern void vga_putc(const char c);
extern int keyb_present;
extern int keyb_tstc(void);
extern int keyb_getc(void);
#endif

#if defined(CONFIG_LMS_CONSOLE)
extern void console_putc(const char c);
#endif

#ifdef CONFIG_E2K_SIC
#if defined(CONFIG_SERIAL_AM85C30_BOOT_CONSOLE)
extern unsigned long com_port;
extern void serial_putc(unsigned long com_port, const char c);
extern unsigned char serial_getc(unsigned long com_port);
#endif
#else
#if defined(CONFIG_SERIAL_NS16550_BOOT_CONSOLE)
extern unsigned short serial_init(int chan, int boot);
extern void serial_putc(unsigned short com_port, const char c);
extern int serial_tstc(unsigned short com_port);
extern unsigned char serial_getc(unsigned short com_port);
extern unsigned short com_port;
extern boot_info_t *boot_info;
#endif
#endif

#define is_digit(c) ((c >= '0') && (c <= '9'))

#ifndef CONFIG_E2K_SIC
void rom_stdio_init(void)
{

#if defined(CONFIG_BIOS) && defined(CONFIG_SERIAL_NS16550_BOOT_CONSOLE)
	if (!hardware.serial) {
		com_port = serial_init(0, 0);
	}
	boot_info->serial_base = com_port;
#endif

}
#endif

int rom_strlen(char *s)
{
	int len = 0;
	while (*s++) len++;
	return len;
}

#ifndef CONFIG_E2K_SIC
int rom_tstc(void)
{
	int rval = 0;
#if defined (CONFIG_BIOS) && defined(CONFIG_SERIAL_NS16550_BOOT_CONSOLE)
	if (hardware.serial) {
		rval = serial_tstc(com_port);
	};
#endif
	if (rval)
		return rval;

#if defined (CONFIG_BIOS) && defined(CONFIG_VGA_CONSOLE)

	if (hardware.keyboard) {
		rval = keyb_tstc();
	};
#endif
	return rval;

}
#endif

#ifndef CONFIG_E2K_SIC
int rom_getc(void)
{
	while (1) {

#if defined (CONFIG_BIOS) && defined(CONFIG_SERIAL_NS16550_BOOT_CONSOLE)
	if (hardware.serial) {
		if (serial_tstc(com_port)) {
			return serial_getc(com_port);
		}
#if !defined(CONFIG_VGA_CONSOLE)
		else
		{
			continue;
		}
#endif
	};
#endif /* serial console */

#if defined(CONFIG_VGA_CONSOLE)
#if defined(CONFIG_BIOS)
	if (hardware.keyboard)
#endif /* CONFIG_BIOS */
	{
		if (keyb_tstc()) {
			return keyb_getc();
		} else {
			continue;
		};
	}
#endif
		break;
	}

	return 0;

}

#else
int rom_getc(void)
{
#if defined (CONFIG_BIOS) && defined(CONFIG_SERIAL_AM85C30_BOOT_CONSOLE)
	if (hardware.serial) {
		return serial_getc(com_port);
	}
#endif /* serial console */

#if defined(CONFIG_VGA_CONSOLE)
#if defined(CONFIG_BIOS)
	if (hardware.keyboard)
#endif /* CONFIG_BIOS */
	{
		if (keyb_tstc()) {
			return keyb_getc();
		}
	}
#endif
	return 0;
}
#endif


void rom_putc(char c)
{
#if defined(CONFIG_LMS_CONSOLE)
#if defined(CONFIG_BIOS)
	if (hardware.dbgport)
#endif /* CONFIG_BIOS */
	{
		console_putc(c);
	};
#endif /* E2K console */

#if defined (CONFIG_BIOS) && \
	((!defined(CONFIG_E2K_SIC) && \
		defined(CONFIG_SERIAL_NS16550_BOOT_CONSOLE)) || \
			(defined(CONFIG_E2K_SIC) && \
				defined(CONFIG_SERIAL_AM85C30_BOOT_CONSOLE)))
	if (hardware.serial) {
		serial_putc(com_port, c);
		if ( c == '\n' )
			serial_putc(com_port, '\r');
	}
#endif /* serial console */

#if defined(CONFIG_VGA_CONSOLE)
#if defined(CONFIG_BIOS)
	if (hardware.video)
#endif /* CONFIG_BIOS */
	{
		vga_putc(c);
	}
#endif /* VGA console */

}

void rom_puts(char *s)
{

	while (*s)
		rom_putc(*s++);
}

int rom_cvt(unsigned long val, char *buf, long radix, char *digits)
{
	char temp[80];
	char *cp = temp;
	int length = 0;

	if (val == 0)
	{ /* Special case */
		*cp++ = '0';
	} else
		while (val)
		{
			*cp++ = digits[val % radix];
			val /= radix;
		}

	while (cp != temp)
	{
		*buf++ = *--cp;
		length++;
	}
	*buf = '\0';
	return length;
}

void
rom_vprintk(const char *fmt0, va_list ap)
{

	char c, sign, *cp = NULL;
	int left_prec, right_prec, zero_fill, length = 0, pad, pad_on_right;
	char buf[32];
	long val;

	while ((c = *fmt0++) != 0)
	{
		if (c == '%')
		{
			c = *fmt0++;
			left_prec = right_prec = pad_on_right = 0;
			if (c == '-')
			{
				c = *fmt0++;
				pad_on_right++;
			}
			if (c == '0')
			{
				zero_fill = TRUE;
				c = *fmt0++;
			} else
			{
				zero_fill = FALSE;
			}
			while (is_digit(c))
			{
				left_prec = (left_prec * 10) + (c - '0');
				c = *fmt0++;
			}
			if (c == '.')
			{
				c = *fmt0++;
				zero_fill++;
				while (is_digit(c))
				{
					right_prec = (right_prec * 10) + (c - '0');
					c = *fmt0++;
				}
			} else
			{
				right_prec = left_prec;
			}

			sign = '\0';

#ifdef CONFIG_E2K_SIC // BUG кривой switch ... перескакиваем не на ту метку по коду
		  // процедуры switch 
			if (c == 'd'){
				val = va_arg(ap, int);
				if (val < 0)
					{
						sign = '-';
						val = -val;
					}
				length = rom_cvt(val, buf, 10, "0123456789");
				cp = buf;
			}else if (c == 'x'){
				val = va_arg(ap, unsigned int);
				length = rom_cvt(val, buf, 16, "0123456789abcdef");
				cp = buf;
			}else if (c == 'X'){
				val = va_arg(ap, unsigned long);
				length = rom_cvt(val, buf, 16, "0123456789ABCDEF");
				cp = buf;
			}else if (c == 'p'){
				val = va_arg(ap, unsigned long);
				length = rom_cvt(val, buf, 16, "0123456789abcdef");
				cp = buf;
			}else if (c == 's'){
				cp = va_arg(ap, char *);
				length = rom_strlen(cp);
			}else if (c == 'c'){
				c = va_arg(ap, char);
				rom_putc(c);
				continue;
			}else{
				rom_putc('?');
			}
#else
			switch (c)
			{

			case 'd':
			case 'x':
			case 'X':

				val = va_arg(ap, int);
				switch (c)
				{
				case 'd':

					if (val < 0)
					{
						sign = '-';
						val = -val;
					}


					length = rom_cvt(val, buf, 10, "0123456789");
					break;
				case 'x':
					length = rom_cvt(val, buf, 16, "0123456789abcdef");
					break;
				case 'X':
					length = rom_cvt(val, buf, 16, "0123456789ABCDEF");
					break;
				}
				cp = buf;
				break;
			case 's':
				cp = va_arg(ap, char *);
				length = rom_strlen(cp);
				break;
			case 'c':
				c = va_arg(ap, char);
				rom_putc(c);
				continue;
			default:
				rom_putc('?');
			}
#endif
			pad = left_prec - length;
			if (sign != '\0')
			{
				pad--;
			}
			if (zero_fill)
			{
				c = '0';
				if (sign != '\0')
				{
					rom_putc(sign);
					sign = '\0';
				}
			} else
			{
				c = ' ';
			}
			if (!pad_on_right)
			{
				while (pad-- > 0)
				{
					rom_putc(c);
				}
			}
			if (sign != '\0')
			{
				rom_putc(sign);
			}
			while (length-- > 0)
			{
				rom_putc(c = *cp++);
				if (c == '\n')
				{
					rom_putc('\r');
				}
			}
			if (pad_on_right)
			{
				while (pad-- > 0)
				{
					rom_putc(c);
				}
			}
		} else
		{
			rom_putc(c);
			if (c == '\n')
			{
				rom_putc('\r');
			}
		}
	}
}

void
rom_printk(char const *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	rom_vprintk(fmt, ap);
	va_end(ap);
}
