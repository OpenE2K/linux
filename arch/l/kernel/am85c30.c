/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * COM port console AM85C30 support
 */

#include <linux/types.h>
#include <linux/pci_ids.h>
#include <linux/serial.h>
#include <linux/serial_reg.h>
#include <linux/spinlock.h>

#include <asm/serial.h>
#include <asm/bootinfo.h>
#include <asm/console.h>
#include <asm/io.h>

#include <uapi/asm-generic/errno-base.h>

#undef  DEBUG_SC_MODE
#undef  DebugSC
#define	DEBUG_SC_MODE	0	/* serial console debug */
#define	DebugSC		if (DEBUG_SC_MODE) dump_printk

static unsigned long		am85c30_com_port = 0;
extern serial_console_opts_t	am85c30_serial_console;

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

#if defined(CONFIG_SERIAL_L_ZILOG)
static inline unsigned long lock_l_zilog(void)
{
	unsigned long flags;

	if (uap_a_reg_lock) {
# ifdef CONFIG_E2K
		raw_all_irq_save(flags);
# else
		raw_local_irq_save(flags);
# endif
		arch_spin_lock(&uap_a_reg_lock->raw_lock);
	} else {
		raw_local_save_flags(flags);
	}

	return flags;
}

static inline void unlock_l_zilog(unsigned long flags)
{
	if (uap_a_reg_lock) {
		arch_spin_unlock(&uap_a_reg_lock->raw_lock);
# ifdef CONFIG_E2K
		raw_all_irq_restore(flags);
# else
		raw_local_irq_restore(flags);
# endif
	}
}
#else
static inline unsigned long lock_l_zilog(void)
{
	return 0;
}

static inline unsigned long unlock_l_zilog(unsigned long flags)
{
	return 0;
}
#endif

static __interrupt void am85c30_serial_putc(unsigned char c)
{
	unsigned long port = am85c30_com_port + 2 * serial_dump_console_num;
	unsigned long flags;
	u8 cmd_saved;

	flags = lock_l_zilog();

	cmd_saved = am85c30_com_inb_command(port, AM85C30_RR1);

	am85c30_com_outb_command(port, AM85C30_WR1,
		cmd_saved & ~(AM85C30_EXT_INT_ENAB | AM85C30_TxINT_ENAB |
							AM85C30_RxINT_MASK));

	while ((am85c30_com_inb_command(port, AM85C30_RR0) & AM85C30_D2) == 0)
		cpu_relax();
	am85c30_com_outb(port + 0x01, c);

	while ((am85c30_com_inb_command(port, AM85C30_RR0) & AM85C30_D2) == 0)
		cpu_relax();
	am85c30_com_outb_command(port, AM85C30_WR0, AM85C30_RES_Tx_P);
	am85c30_com_outb_command(port, AM85C30_WR1, cmd_saved);

	unlock_l_zilog(flags);
}

static __interrupt unsigned char am85c30_serial_getc(void)
{
	unsigned long port;
	unsigned long flags;
	u8 ret;

	flags = lock_l_zilog();

	port = am85c30_com_port + 2 * serial_dump_console_num;
	while (((am85c30_com_inb_command(port, AM85C30_RR0)) & AM85C30_D0) == 0)
		cpu_relax();
	ret = am85c30_com_inb(port + 0x01);

	unlock_l_zilog(flags);

	return ret;
}

static int __init
am85c30_init(void *serial_base)
{
	DebugSC("am85c30_init() started\n");

	if (!serial_base || serial_dump_console_num == SERIAL_DUMP_CONSOLE_DENY) {
		dump_printk("am85c30_init() Serial console base IO address is not passed "
			"by BIOS or serial dump console is not allowed\n");
		dump_printk("am85c30_init() Serial console is not "
			"enabled\n");
		return (-ENODEV);
	}
	am85c30_com_port = (unsigned long)serial_base;
	am85c30_serial_console.io_base = (unsigned long)serial_base;
	DebugSC("am85c30_init() enabled serial console at %px "
		"IO memory base\n", serial_base);
	return (0);
}

/* AM85C30 serial console opts struct */
serial_console_opts_t am85c30_serial_console = {
	.name		= SERIAL_CONSOLE_AM85C30_NAME,
	.io_base	= 0,
	.serial_putc	= am85c30_serial_putc,
	.serial_getc	= am85c30_serial_getc,
	.init		= am85c30_init,
};
