/*
 * COM1 NS16550 support
 */

#include <linux/types.h>
#include <linux/serial.h>
#include <linux/serial_reg.h>

#include <asm/serial.h>
#include <asm/console.h>
#include <asm/io.h>

#undef  DEBUG_SC_MODE
#undef  DebugSC
#define	DEBUG_SC_MODE	0	/* serial console debug */
#define	DebugSC		if (DEBUG_SC_MODE) dump_printk


#define BOTH_EMPTY	(UART_LSR_TEMT | UART_LSR_THRE)

static unsigned short		ns16550_com_port = NS16550_SERIAL_PORT_0;
extern serial_console_opts_t	ns16550_serial_console;

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
ns16550_init(boot_info_t *boot_info)
{

	DebugSC("ns16550_init() started\n");
#ifdef	CONFIG_E90S
	return (-ENODEV);
#endif	/* CONFIG_E90S */

#ifdef CONFIG_E2K
	if (machine_id != MACHINE_ID_E3M &&
		machine_id != MACHINE_ID_E3M_LMS) {
		DebugSC("ns16550_init() on this machine NS16550 timer "
			"is not used\n");
		return (-ENODEV);
	}
#endif	/* __e2k__ */
	ns16550_com_port = boot_info->serial_base;
	if (boot_info->serial_base == 0
			|| !(boot_info->serial_base == NS16550_SERIAL_PORT_0 ||
			boot_info->serial_base == NS16550_SERIAL_PORT_1 ||
			boot_info->serial_base == NS16550_SERIAL_PORT_2 ||
			boot_info->serial_base == NS16550_SERIAL_PORT_3)) {
		ns16550_com_port = NS16550_SERIAL_PORT_0;
		dump_printk("ns16550_init() Serial console port"
				"passed 0x%x, set port #0 0x%x by default\n",
				boot_info->serial_base,
 				NS16550_SERIAL_PORT_0);
	} else {
		ns16550_com_port = boot_info->serial_base;
		dump_printk("ns16550_init() Serial console port passed 0x%x\n", boot_info->serial_base);
	}
	ns16550_serial_console.io_base = ns16550_com_port;
	return (0);
}

static __interrupt void ns16550_serial_putc(unsigned char c)
{
	unsigned short port;

	port = ns16550_com_port + 2 * serial_dump_console_num;
	while ((ns16550_com_inb(port + (UART_LSR)) & BOTH_EMPTY) != BOTH_EMPTY)
		;
	ns16550_com_outb(port, c);
}

static __interrupt unsigned char ns16550_serial_getc(void)
{
	unsigned short port;

	port = ns16550_com_port + 2 * serial_dump_console_num;
	while ((ns16550_com_inb(port + (UART_LSR)) & UART_LSR_DR) == 0)
		;
	return ns16550_com_inb(port);
}

int
ns16550_serial_tstc(void)
{
	unsigned short port;

	port = ns16550_com_port + 2 * serial_dump_console_num;
	return ((ns16550_com_inb(port + (UART_LSR)) & UART_LSR_DR) != 0);
}

/* NS16550 serial console opts struct */
serial_console_opts_t ns16550_serial_console = {
	.name		= SERIAL_CONSOLE_16550_NAME,
	.io_base	= 0,
	.init		= &ns16550_init,
	.serial_putc	= &ns16550_serial_putc,
	.serial_getc	= &ns16550_serial_getc,
	.serial_tstc	= &ns16550_serial_tstc,
};
