/*
 * COM1 NS16550 support
 */

#include <linux/types.h>
#include <linux/serial.h>
#include <linux/serial_reg.h>

#include <asm/serial.h>
#include <asm/console.h>
#include <asm/boot_head.h>
#include <asm/io.h>

#undef  DEBUG_SC_MODE
#undef  DebugSC
#define	DEBUG_SC_MODE	0	/* serial console debug */
#define	DebugSC		if (DEBUG_SC_MODE) do_boot_printk


#define BOTH_EMPTY	(UART_LSR_TEMT | UART_LSR_THRE)

static unsigned short		ns16550_com_port = NS16550_SERIAL_PORT_0;
extern serial_console_opts_t	ns16550_serial_boot_console;
#define	boot_ns16550_com_port		\
		boot_get_vo_value(ns16550_com_port)
#define	boot_ns16550_serial_boot_console	\
		((serial_console_opts_t)	\
			(boot_get_vo_value(ns16550_serial_boot_console)))

static inline void
ns16550_com_outb(u16 port, u8 byte)
{
       boot_outb(port, byte);
}

static inline u8
ns16550_com_inb(u16 port)
{
	return boot_inb(port);
}

static int __init
boot_ns16550_init(boot_info_t *boot_info)
{

	DebugSC("boot_ns16550_init() started\n");
#ifdef	CONFIG_E90S
	return (-ENODEV);
#endif	/* CONFIG_E90S */

#ifdef	__e2k__
	if (boot_machine_id != MACHINE_ID_E3M &&
		boot_machine_id != MACHINE_ID_E3M_LMS) {
		DebugSC("boot_ns16550_init() on this machine NS16550 timer "
			"is not used\n");
		return (-ENODEV);
	}
#endif	/* __e2k__ */
	boot_ns16550_com_port = boot_info->serial_base;
	if (boot_info->serial_base == 0 || !(
		boot_info->serial_base == NS16550_SERIAL_PORT_0 ||
		boot_info->serial_base == NS16550_SERIAL_PORT_1 ||
		boot_info->serial_base == NS16550_SERIAL_PORT_2 ||
		boot_info->serial_base == NS16550_SERIAL_PORT_3)
		) {
		boot_ns16550_com_port = NS16550_SERIAL_PORT_0;
		do_boot_printk("boot_ns16550_init() Serial console port"
			"passed 0x%x, set port #0 0x%x by default\n",
			boot_info->serial_base,
 			NS16550_SERIAL_PORT_0);
	} else {
		boot_ns16550_com_port = boot_info->serial_base;
		do_boot_printk("boot_ns16550_init() Serial console port passed 0x%x\n", boot_info->serial_base);
	}
	boot_ns16550_serial_boot_console.io_base = boot_ns16550_com_port;
	return (0);
}

void
boot_ns16550_serial_putc(unsigned char c)
{
	unsigned short port;

	port = boot_ns16550_com_port + 2 * boot_serial_boot_console_num;
	while ((ns16550_com_inb(port + (UART_LSR)) & BOTH_EMPTY) != BOTH_EMPTY)
		;
	ns16550_com_outb(port, c);
}

unsigned char
boot_ns16550_serial_getc(void)
{
	unsigned short port;

	port = boot_ns16550_com_port + 2 * boot_serial_boot_console_num;
	while ((ns16550_com_inb(port + (UART_LSR)) & UART_LSR_DR) == 0)
		;
	return ns16550_com_inb(port);
}

int
boot_ns16550_serial_tstc(void)
{
	unsigned short port;

	port = boot_ns16550_com_port + 2 * boot_serial_boot_console_num;
	return ((ns16550_com_inb(port + (UART_LSR)) & UART_LSR_DR) != 0);
}

/* NS16550 serial console opts struct */
serial_console_opts_t ns16550_serial_boot_console = {
	.name		= SERIAL_CONSOLE_16550_NAME,
	.io_base	= 0,
	.init		= &boot_ns16550_init,
	.serial_putc	= &boot_ns16550_serial_putc,
	.serial_getc	= &boot_ns16550_serial_getc,
	.serial_tstc	= &boot_ns16550_serial_tstc,
};
