#ifndef _I8042_IO_H
#define _I8042_IO_H

/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

/*
 * Names.
 */

#define I8042_KBD_PHYS_DESC "isa0060/serio0"
#define I8042_AUX_PHYS_DESC "isa0060/serio1"
#define I8042_MUX_PHYS_DESC "isa0060/serio%d"

/*
 * IRQs.
 */

#ifdef __alpha__
# define I8042_KBD_IRQ	1
# define I8042_AUX_IRQ	(RTC_PORT(0) == 0x170 ? 9 : 12)	/* Jensen is special */
#elif defined(__arm__)
/* defined in include/asm-arm/arch-xxx/irqs.h */
#include <asm/irq.h>
#elif defined(CONFIG_SH_CAYMAN)
#include <asm/irq.h>
#elif defined(CONFIG_PPC)
extern int of_i8042_kbd_irq;
extern int of_i8042_aux_irq;
# define I8042_KBD_IRQ  of_i8042_kbd_irq
# define I8042_AUX_IRQ  of_i8042_aux_irq
#elif defined(CONFIG_MCST)
#define I8042_KBD_IRQ	i8042_kbd_irq
#define I8042_AUX_IRQ	i8042_aux_irq
static int i8042_kbd_irq = 1;
static int i8042_aux_irq = 12;

#include <linux/pci.h>

#else
# define I8042_KBD_IRQ	1
# define I8042_AUX_IRQ	12
#endif


/*
 * Register numbers.
 */

#ifdef CONFIG_MCST
#define I8042_COMMAND_REG	((unsigned long) i8042_command_reg)
#define I8042_STATUS_REG	((unsigned long) i8042_command_reg)
#define I8042_DATA_REG		((unsigned long) i8042_data_reg)

static void __iomem *i8042_command_reg = (void __iomem *)0x64;
static void __iomem *i8042_data_reg = (void __iomem *)0x60;

static inline int i8042_read_data_io(void)
{
	return inb(I8042_DATA_REG);
}

static inline int i8042_read_status_io(void)
{
	return inb(I8042_STATUS_REG);
}

static inline void i8042_write_data_io(int val)
{
	outb(val, I8042_DATA_REG);
}

static inline void i8042_write_command_io(int val)
{
	outb(val, I8042_COMMAND_REG);
}
static inline int i8042_read_data_pci(void)
{
	return readb(I8042_DATA_REG);
}

static inline int i8042_read_status_pci(void)
{
	return readb(I8042_STATUS_REG);
}

static inline void i8042_write_data_pci(int val)
{
	writeb(val, I8042_DATA_REG);
}

static inline void i8042_write_command_pci(int val)
{
	writeb(val, I8042_COMMAND_REG);
}

static int (*i8042_read_data)(void) = i8042_read_data_io;
static int (*i8042_read_status)(void) = i8042_read_status_io;
static void (*i8042_write_data)(int val) = i8042_write_data_io;
static void (*i8042_write_command)(int val) = i8042_write_command_io;

static bool __initdata i8042_nopci = 0;
module_param_named(nopci, i8042_nopci, bool, 0);
MODULE_PARM_DESC(nokbd, "Do not probe MCST pci controller.");
#else
#define I8042_COMMAND_REG	0x64
#define I8042_STATUS_REG	0x64
#define I8042_DATA_REG		0x60

static inline int i8042_read_data(void)
{
	return inb(I8042_DATA_REG);
}

static inline int i8042_read_status(void)
{
	return inb(I8042_STATUS_REG);
}

static inline void i8042_write_data(int val)
{
	outb(val, I8042_DATA_REG);
}

static inline void i8042_write_command(int val)
{
	outb(val, I8042_COMMAND_REG);
}
#endif

static inline int i8042_platform_init(void)
{
/*
 * On some platforms touching the i8042 data register region can do really
 * bad things. Because of this the region is always reserved on such boxes.
 */
#if defined(CONFIG_PPC)
	if (check_legacy_ioport(I8042_DATA_REG))
		return -ENODEV;
#endif
#if !defined(__sh__) && !defined(__alpha__) && !defined(__e2k__)
	if (!request_region(I8042_DATA_REG, 16, "i8042"))
		return -EBUSY;
#endif

	i8042_reset = 1;
#ifdef CONFIG_MCST
	/* r7683: aporia-2: add pci ps/2 controller support. dima@mcst.ru */
	{
		struct pci_dev *pdev = 
				pci_get_device(PCI_VENDOR_ID_MCST_TMP,
						PCI_DEVICE_ID_MCST_PS2, NULL);
		if (!i8042_nopci && pdev) {
			void __iomem *r = pci_iomap(pdev, 0, 0);
			i8042_command_reg = r + 2;
			i8042_data_reg = r;
			i8042_kbd_irq = i8042_aux_irq = pdev->irq;
			i8042_read_data = i8042_read_data_pci;
			i8042_read_status = i8042_read_status_pci;
			i8042_write_data = i8042_write_data_pci;
			i8042_write_command = i8042_write_command_pci;
		}
	}
#endif
	return 0;
}

static inline void i8042_platform_exit(void)
{
#if !defined(__sh__) && !defined(__alpha__) && !defined(__e2k__)
	release_region(I8042_DATA_REG, 16);
#endif
}

#endif /* _I8042_IO_H */
