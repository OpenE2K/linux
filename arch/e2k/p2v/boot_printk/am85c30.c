/*
 * COM port console AM85C30 support
 */

#include <linux/types.h>
#include <linux/pci_ids.h>
#include <linux/serial.h>
#include <linux/serial_reg.h>

#include <asm/serial.h>
#include <asm/bootinfo.h>
#include <asm/console.h>
#include <asm/io.h>

#undef  DEBUG_SC_MODE
#undef  DebugSC
#define	DEBUG_SC_MODE	0	/* serial console debug */
#define	DebugSC		if (DEBUG_SC_MODE) do_boot_printk

static unsigned long		am85c30_com_port = 0;
extern serial_console_opts_t	am85c30_serial_boot_console;

#define	boot_am85c30_com_port		boot_get_vo_value(am85c30_com_port)
#define	boot_am85c30_serial_boot_console		\
		((serial_console_opts_t)	\
			(boot_get_vo_value(am85c30_serial_boot_console)))

static inline void
am85c30_com_outb(u64 iomem_addr, u8 byte)
{
 	boot_writeb(byte, (void __iomem *)iomem_addr);
}

static inline u8
am85c30_com_inb(u64 iomem_addr)
{
	return boot_readb((void __iomem *)iomem_addr);
}

static inline u8
am85c30_com_inb_command(u64 iomem_addr, u8 reg_num)
{
	boot_writeb(reg_num, (void __iomem *)iomem_addr);
	return boot_readb((void __iomem *)iomem_addr);
}

static inline void
am85c30_com_outb_command(u64 iomem_addr, u8 reg_num, u8 val)
{
	boot_writeb(reg_num, (void __iomem *)iomem_addr);
	boot_writeb(val, (void __iomem *)iomem_addr);
}

static void
boot_am85c30_serial_putc(unsigned char c)
{
	unsigned long port;

	port = boot_am85c30_com_port + 2 * boot_serial_boot_console_num;
	while ((am85c30_com_inb_command(port, AM85C30_RR0) & AM85C30_D2) == 0)
		;
	am85c30_com_outb(port + 0x01, c);
}

static unsigned char
boot_am85c30_serial_getc(void)
{
	unsigned long port;

	port = boot_am85c30_com_port + 2 * boot_serial_boot_console_num;
	while (((am85c30_com_inb_command(port, AM85C30_RR0)) & AM85C30_D0) == 0)
		;
	return am85c30_com_inb(port + 0x01);
}

static int __init
boot_am85c30_init(boot_info_t *boot_info)
{
	unsigned long serial_base;

	DebugSC("boot_am85c30_init() started\n");
#ifdef	__e2k__
	if (!BOOT_HAS_MACHINE_E2K_IOHUB) {
		DebugSC("boot_am85c30_init() on this machine AM85C30 serial "
			"device is not used\n");
		return (-ENODEV);
	}
#endif	/* __e2k__ */

	serial_base = boot_info->serial_base;
	if (serial_base == 0) {
		do_boot_printk("boot_am85c30_init() Serial console base IO "
			"address is not passed by BIOS\n");
		do_boot_printk("boot_am85c30_init() Serial console is not "
			"enabled\n");
		return (-ENODEV);
	}
	boot_am85c30_com_port = serial_base;
	boot_am85c30_serial_boot_console.io_base = serial_base;
	DebugSC("boot_am85c30_init() enabled serial console at 0x%lx "
		"IO memory base\n", serial_base);
	return (0);
}

/* AM85C30 serial console opts struct */
serial_console_opts_t am85c30_serial_boot_console = {
	.name		= SERIAL_CONSOLE_AM85C30_NAME,
	.io_base	= 0,
	.serial_putc	= boot_am85c30_serial_putc,
	.serial_getc	= boot_am85c30_serial_getc,
	.init		= boot_am85c30_init,
};
