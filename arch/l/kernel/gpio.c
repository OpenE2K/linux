/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/io.h>
#include <linux/pci.h>

#if IS_ENABLED(CONFIG_INPUT_LTC2954)
#include <linux/platform_device.h>
#include <linux/gpio_keys.h>
#include <linux/input.h>
#endif /* CONFIG_INPUT_LTC2954 */

#include <asm/epic.h>
#include <asm/gpio.h>
#include <asm/iolinkmask.h>
#include <asm/io_apic.h>

#include <linux/mcst/gpio.h>
/* Offsets from BAR for MCST GPIO registers */
#define L_GPIO_CNTRL	0x00
#define L_GPIO_DATA		0x04
#define L_GPIO_INT_CLS	0x08
#define L_GPIO_INT_LVL	0x0c
#define L_GPIO_INT_EN	0x10
#define L_GPIO_INT_STS	0x14

#define L_GPIO_ONE_MASK(x)	(1 << (x))
#define L_GPIO_ZERO_MASK(x)	(~(1 << (x)))

/* Configuration values */
#define L_GPIO_CNTRL_IN		0x00000000	/* Input mode for all pins */
#define L_GPIO_CNTRL_OUT	0x0000ffff	/* Output mode for all pins */
#define L_GPIO_INT_ENABLE	0x0000ffff	/* Interrupts enabled for all */
#define L_GPIO_INT_DISABLE	0x00000000	/* Interrupts disabled for all*/
#define L_GPIO_INT_CLS_LVL	0x00000000	/* Enable level interrupts */
#define L_GPIO_INT_CLS_EDGE	0x0000ffff	/* Enable edge interrupts */
#define L_GPIO_INT_LVL_RISE	0x0000ffff     /* Rising edge detection (0->1)*/
#define L_GPIO_INT_LVL_FALL 0x00000000	/* Falling edeg detection */

/* Predefined default configuration values */
/* Input mode for all pins by default: */
#define L_GPIO_CNTRL_DEF	L_GPIO_CNTRL_IN
/* Interrupts from all pins disabled by default: */
#define L_GPIO_INT_EN_DEF	L_GPIO_INT_DISABLE
/* Interrupt mode for all pins - egde interrupts: */
#define L_GPIO_INT_CLS_DEF	L_GPIO_INT_CLS_EDGE
/* Interrupt mode for all pins - falling egde detection: */
#define L_GPIO_INT_LVL_DEF	L_GPIO_INT_LVL_FALL

/* Sets of gpios */
#define IOHUB_IRQ0_GPIO_START	0
#define IOHUB_IRQ0_GPIO_END	7
#define IOHUB_IRQ1_GPIO_START   8
#define IOHUB_IRQ1_GPIO_END	15

#define DRV_NAME "l-gpio"

 #define L_GPIO_MAX_IRQS       2

struct l_gpio_data {
	int bar;
	int lines;
	struct {
		int nr;
		int start;
		int end;
	} irq[L_GPIO_MAX_IRQS];
};


struct l_gpio {
	struct gpio_chip chip; /*Must be the first*/
	resource_size_t base;
	void __iomem *base_ioaddr;
	struct pci_dev *pdev;
	raw_spinlock_t lock;
	int irq_base;
	struct l_gpio *next;
	struct l_gpio_data data;
};

/* Registering gpio-bound devices on board. This is embedded style. */
#if IS_ENABLED(CONFIG_INPUT_LTC2954)

struct gpio_keys_button ltc2954_descr = {
	.code = KEY_SLEEP,
	.gpio = LTC2954_IRQ_GPIO_PIN,
	.active_low = 0,
	.type = EV_KEY,
	.wakeup = 0,
	.debounce_interval = 0,
};

static struct gpio_keys_platform_data ltc2954_button_pdata = {
	.buttons = &ltc2954_descr,
	.nbuttons = 1,
	.rep = 0,
};

static struct platform_device ltc2954_dev = {
	.name = "ltc2954",
	.id = -1,
	.num_resources = 0,
	.dev = {
		.platform_data = &ltc2954_button_pdata,
		},
};
#endif /* CONFIG_INPUT_LTC2954 */

static int register_l_gpio_bound_devices(void)
{

	int err = 0;

	/* Only power button is available today: */
#if IS_ENABLED(CONFIG_INPUT_LTC2954)
	err = platform_device_register(&ltc2954_dev);
	if (err < 0)
		pr_err("failed to register ltc2954 device\n");
#endif /* CONFIG_INPUT_LTC2954_BUTTON */

	return err;
}

/* Generic GPIO interface */

/*
 * Set the state of an output GPIO line.
 */
static void l_gpio_set_value(struct gpio_chip *c,
				unsigned int offset, int state)
{
	struct l_gpio *chip = (struct l_gpio *)c;
	unsigned long flags;
	unsigned int x;

	raw_spin_lock_irqsave(&chip->lock, flags);
	x = readl(chip->base_ioaddr + L_GPIO_DATA);
	if (state)
		x |= L_GPIO_ONE_MASK(offset);
	else
		x &= L_GPIO_ZERO_MASK(offset);

	writel(x, chip->base_ioaddr + L_GPIO_DATA);
	raw_spin_unlock_irqrestore(&chip->lock, flags);
}

/*
 * Read the state of a GPIO line.
 */
static int __l_gpio_get_value(struct gpio_chip *c, unsigned int offset)
{
	struct l_gpio *chip = (struct l_gpio *)c;
	unsigned int x = readl(chip->base_ioaddr + L_GPIO_DATA);

	return (x & L_GPIO_ONE_MASK(offset)) ? 1 : 0;
}

static int l_gpio_get_value(struct gpio_chip *c, unsigned int offset)
{
	struct l_gpio *chip = (struct l_gpio *)c;
	unsigned long flags;
	int x;

	raw_spin_lock_irqsave(&chip->lock, flags);
	x = __l_gpio_get_value(c, offset);
	raw_spin_unlock_irqrestore(&chip->lock, flags);

	return x;
}

/*
 * Configure the GPIO line as an input.
 */
static int l_gpio_direction_input(struct gpio_chip *c, unsigned offset)
{
	struct l_gpio *chip = (struct l_gpio *)c;
	unsigned long flags;
	unsigned int x;

	raw_spin_lock_irqsave(&chip->lock, flags);
	x = readl(chip->base_ioaddr + L_GPIO_CNTRL);
	x &= L_GPIO_ZERO_MASK(offset);
	writel(x, chip->base_ioaddr + L_GPIO_CNTRL);
	raw_spin_unlock_irqrestore(&chip->lock, flags);

	return 0;
}

/*
 * Configure the GPIO line as an output.
 */
static int l_gpio_direction_output(struct gpio_chip *c, unsigned offset,
				      int val)
{
	struct l_gpio *chip = (struct l_gpio *)c;
	unsigned long flags;
	unsigned int x;

	raw_spin_lock_irqsave(&chip->lock, flags);
	x = readl(chip->base_ioaddr + L_GPIO_CNTRL);
	x |= L_GPIO_ONE_MASK(offset);
	writel(x, chip->base_ioaddr + L_GPIO_CNTRL);
	raw_spin_unlock_irqrestore(&chip->lock, flags);
	l_gpio_set_value(c, offset, val);

	return 0;
}

/*
 * Map GPIO line to IRQ number.
 */
static int l_gpio_to_irq(struct gpio_chip *c, unsigned int pin)
{
	struct l_gpio *chip = (struct l_gpio *)c;

	return (chip->irq_base + pin);
}

/* GPIOLIB interface */
static struct l_gpio *l_gpios_set;

/*
 * GPIO IRQ
 */

static int irq_to_gpio(unsigned int irq)
{
	struct l_gpio *chip = irq_get_chip_data(irq);

	return (irq - chip->irq_base);
}

static void l_gpio_irq_disable(struct irq_data *irq_data)
{
	unsigned long flags;
	unsigned int x;
	unsigned int irq = irq_data->irq;
	struct l_gpio *chip = irq_get_chip_data(irq);
	int offset = irq_to_gpio(irq);

	raw_spin_lock_irqsave(&chip->lock, flags);
	x = readl(chip->base_ioaddr + L_GPIO_INT_EN);
	x &= L_GPIO_ZERO_MASK(offset);
	writel(x, chip->base_ioaddr + L_GPIO_INT_EN);
	raw_spin_unlock_irqrestore(&chip->lock, flags);

	return;
}

static void l_gpio_irq_enable(struct irq_data *irq_data)
{
	unsigned long flags;
	unsigned int x;
	unsigned int irq = irq_data->irq;
	struct l_gpio *chip = irq_get_chip_data(irq);
	int offset = irq_to_gpio(irq);

	raw_spin_lock_irqsave(&chip->lock, flags);
	x = readl(chip->base_ioaddr + L_GPIO_INT_EN);
	x |= L_GPIO_ONE_MASK(offset);
	writel(x, chip->base_ioaddr + L_GPIO_INT_EN);
	raw_spin_unlock_irqrestore(&chip->lock, flags);

	return;
}

static int l_gpio_irq_type(struct irq_data *irq_data, unsigned type)
{
	unsigned long flags;
	unsigned int irq = irq_data->irq;
	struct l_gpio *chip = irq_get_chip_data(irq);
	int offset = irq_to_gpio(irq);
	unsigned int cls, lvl;

	if (offset < 0 || offset > chip->chip.ngpio) {
		return -EINVAL;
	}

	raw_spin_lock_irqsave(&chip->lock, flags);

	cls = readl(chip->base_ioaddr + L_GPIO_INT_CLS);
	lvl = readl(chip->base_ioaddr + L_GPIO_INT_LVL);

	switch (type) {
	case IRQ_TYPE_EDGE_BOTH:
		cls |= L_GPIO_ONE_MASK(offset);
		/*
		 * Since the hardware doesn't support interrupts on both edges,
		 * emulate it in the software by setting the single edge
		 * interrupt and switching to the opposite edge while ACKing
		 * the interrupt
		 */
		if (__l_gpio_get_value(&chip->chip, offset))
			lvl &= L_GPIO_ZERO_MASK(offset); /* falling */
		else
			lvl |= L_GPIO_ONE_MASK(offset); /* rising */
		break;
	case IRQ_TYPE_EDGE_RISING:
		cls |= L_GPIO_ONE_MASK(offset);
		lvl |= L_GPIO_ONE_MASK(offset);
		break;
	case IRQ_TYPE_EDGE_FALLING:
		cls |= L_GPIO_ONE_MASK(offset);
		lvl &= L_GPIO_ZERO_MASK(offset);
		break;
	case IRQ_TYPE_LEVEL_HIGH:
		cls &= L_GPIO_ZERO_MASK(offset);
		lvl |= L_GPIO_ONE_MASK(offset);
		break;
	case IRQ_TYPE_LEVEL_LOW:
		cls &= L_GPIO_ZERO_MASK(offset);
		lvl &= L_GPIO_ZERO_MASK(offset);
		break;
	default:
		break;
	}
	writel(lvl, chip->base_ioaddr + L_GPIO_INT_LVL);
	writel(cls, chip->base_ioaddr + L_GPIO_INT_CLS);

	raw_spin_unlock_irqrestore(&chip->lock, flags);

	return 0;
}

static int l_gpio_irq_set_affinity(struct irq_data *irq_data,
		const struct cpumask *mask, bool force)
{
#ifdef CONFIG_SMP
	int ret = 0, i;
	unsigned int irq = irq_data->irq;
	struct l_gpio *chip = irq_get_chip_data(irq);
	struct irq_data *iopic_data;
	struct irq_chip *iopic_chip;

	for (i = 0; chip->data.irq[i].nr && ret == 0; i++) {
		iopic_data = irq_get_irq_data(chip->data.irq[i].nr);
		iopic_chip = irq_get_chip(chip->data.irq[i].nr);

		if (iopic_chip)
			ret = iopic_chip->irq_set_affinity(iopic_data, mask, force);
	else
		pr_alert("Error: gpio: could not set IRQ#%d affinity. Did not boot pass info about it?\n",
			chip->data.irq[i].nr);
	}
	return ret;
#else
	return IRQ_SET_MASK_OK;
#endif
}

static void l_gpio_irq_handler(struct irq_desc *desc)
{
	int irq = irq_desc_get_irq(desc);
	unsigned int x;
	unsigned int i;
	struct irq_chip *ch = irq_desc_get_chip(desc);
	struct l_gpio *chip = irq_desc_get_handler_data(desc);
	unsigned start = 0, end = chip->chip.ngpio;
	chained_irq_enter(ch, desc);

	x = readl(chip->base_ioaddr + L_GPIO_INT_STS);

	for (i = 0; chip->data.irq[i].nr &&
		     i < ARRAY_SIZE(chip->data.irq); i++) {
		if (chip->data.irq[i].nr == irq && chip->data.irq[i].end) {
			start = chip->data.irq[i].start;
			end = chip->data.irq[i].end;
			break;
		}
	}
	for (i = start; i <= end; i++) {
		int pin_irq = chip->irq_base + i;
		u32 type = irq_get_trigger_type(pin_irq);
		if (!(x & (1 << i)))
			continue;
		/*
		 * Switch the interrupt edge to the opposite edge
		 * of the interrupt which got triggered for the case
		 * of emulating both edges
		 */
		if ((type & IRQ_TYPE_SENSE_MASK) == IRQ_TYPE_EDGE_BOTH) {
			l_gpio_irq_type(irq_get_irq_data(pin_irq),
						IRQ_TYPE_EDGE_BOTH);
		}
		generic_handle_irq(pin_irq);
	}

	writel(x, chip->base_ioaddr + L_GPIO_INT_STS);
	chained_irq_exit(ch, desc);
}

static struct irq_chip l_gpio_irqchip = {
	.name = "l-gpio-irqchip",
	.irq_enable  = l_gpio_irq_enable,
	.irq_disable = l_gpio_irq_disable,
	.irq_unmask  = l_gpio_irq_enable,
	.irq_mask    = l_gpio_irq_disable,
	.irq_set_type = l_gpio_irq_type,
	.irq_set_affinity = l_gpio_irq_set_affinity,
};

static int __init l_gpio_probe(struct pci_dev *pdev,
				  const struct pci_device_id *pci_id,
				  struct l_gpio *c)
{
	int err;
	int i, bar = c->data.bar;

	err = pci_enable_device_mem(pdev);
	if (err) {
		dev_err(&pdev->dev, "can't enable l-gpio device MEM\n");
		goto done;
	}

	/* set up the driver-specific struct */
	c->base = pci_resource_start(pdev, bar);
	c->base_ioaddr = pci_iomap(pdev, bar, 0);
	c->pdev = pdev;
	raw_spin_lock_init(&(c->lock));

	dev_info(&pdev->dev, "allocated PCI BAR #%d: base 0x%llx\n", bar,
		 (unsigned long long)c->base);
#if 0 /* do not touch boot settings */
	/* Default Input/Output mode for all pins: */
	writel(L_GPIO_CNTRL_DEF, c->base_ioaddr + L_GPIO_CNTRL);
	/* Default interrupt enable/disable for all pins: */
	writel(L_GPIO_INT_EN_DEF, c->base_ioaddr + L_GPIO_INT_EN);
	/* Default interrupt mode level/edge for all pins: */
	writel(L_GPIO_INT_CLS_DEF, c->base_ioaddr + L_GPIO_INT_CLS);
	/* Default rising/falling edge detection for all pins (if edge): */
	writel(L_GPIO_INT_LVL_DEF, c->base_ioaddr + L_GPIO_INT_LVL);
#endif
	/* finally, register with the generic GPIO API */
	err = gpiochip_add(&(c->chip));
	if (err)
		goto release_region;

	for (i = 0; c->data.irq[i].nr && i < ARRAY_SIZE(c->data.irq); i++)
		;
	if (i == 0)
		goto out;

	/*TODO: rewrite to gpiochip_irqchip_add() */
	c->irq_base = irq_alloc_descs_from(get_nr_irqs_gsi(), (c->chip).ngpio,
					   pcibus_to_node(pdev->bus));
	if (c->irq_base < 0) {
		dev_err(&pdev->dev, "could not reserve %d irq numbers for l-gpio\n",
				(c->chip).ngpio);
		goto release_chip;
	}

	for (i = 0; c->data.irq[i].nr &&
			i < ARRAY_SIZE(c->data.irq); i++) {
		irq_set_handler_data(c->data.irq[i].nr, c);
		irq_set_chained_handler(c->data.irq[i].nr,
						l_gpio_irq_handler);
	}

	/* To virtual irq_desc's: */
	for (i = 0; i < (c->chip).ngpio; i++) {
		irq_set_chip_and_handler(i + c->irq_base,
					      &l_gpio_irqchip,
					      handle_simple_irq);
		irq_set_chip_data(i + c->irq_base, c);
	}
out:
	dev_info(&pdev->dev, DRV_NAME
		": L-GPIO support successfully loaded (irq base: %d).\n",
		c->irq_base);
	return 0;

release_chip:
	gpiochip_remove(&(c->chip));
release_region:
	pci_iounmap(pdev, c->base_ioaddr);
	pci_release_region(pdev, c->data.bar);
done:
	return err;
}

static void __exit l_gpio_remove(struct l_gpio *p)
{
	struct pci_dev *pdev = p->pdev;
	int bar = p->data.bar;

	gpiochip_remove(&(p->chip));
	pci_iounmap(pdev, p->base_ioaddr);
	pci_release_region(pdev, bar);
}

static struct l_gpio_data l_iohub_private_data = {
	.bar = 1,
	.lines = ARCH_NR_IOHUB_GPIOS,
	.irq = {
		{ .nr = 8, .start = 0, .end = 7, },
		{ .nr = 9, .start = 8, .end = ARCH_NR_IOHUB_GPIOS - 1, }
	},
};

static struct l_gpio_data l_pci_private_data = {
	.bar = 0,
	.lines = 16,
};

static struct l_gpio_data l_iohub2_private_data = {
	.bar = 0,
	.lines = ARCH_NR_IOHUB2_GPIOS,
	.irq = {
		{ .nr = 7 }
	},
};

static struct l_gpio_data l_iohub3_private_data = {
	.bar = 0,
	.lines = 16,
	.irq = {
		{ .nr = 12 }
	},
};

static struct pci_device_id __initdata l_gpio_pci_tbl[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_GPIO_MPV_EIOH),
	 .driver_data = (unsigned long)&l_iohub3_private_data},
	{PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_GPIO_MPV),
	 .driver_data = (unsigned long)&l_iohub2_private_data},
	{PCI_DEVICE(PCI_AC97GPIO_VENDOR_ID_ELBRUS,
		    PCI_AC97GPIO_DEVICE_ID_ELBRUS),
	 .driver_data = (unsigned long)&l_iohub_private_data},
	{PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_GPIO),
	 .driver_data = (unsigned long)&l_pci_private_data},
	{},
};

MODULE_DEVICE_TABLE(pci, l_gpio_pci_tbl);

#ifdef CONFIG_OF_GPIO
static struct device_node *l_gpio_get_of_node(struct pci_dev *pdev,
			struct l_gpio_data *d)
{
	int node = dev_to_node(&pdev->dev);
	char path[32];
	if (pdev->dev.of_node)
		return pdev->dev.of_node;

	/* Check for system gpio */
	if (pdev->device != PCI_DEVICE_ID_MCST_GPIO_MPV_EIOH &&
		pdev->device != PCI_DEVICE_ID_MCST_GPIO_MPV &&
		pdev->device != PCI_AC97GPIO_DEVICE_ID_ELBRUS) {
		return NULL;
	}

	/* Check if iohuh2 connected to eioh or iohuh2 to eioh */
	if (cpu_has_epic() && iohub_generation(pdev) < 2) {
		memset(d->irq, 0, sizeof(d->irq));
		return NULL;
	}
	if (!cpu_has_epic() && iohub_generation(pdev) >= 2) {
		memset(d->irq, 0, sizeof(d->irq));
		return NULL;
	}
	if (node < 0)
		node = 0;
	sprintf(path, "/l_gpio@%d", node);

	return of_find_node_by_path(path);
}
#endif

/*
 * We can't use the standard PCI driver registration stuff here, since
 * that allows only one driver to bind to each PCI device (and we want
 * multiple drivers to be able to bind to the device: AC97 and GPIO).  
 * Instead, manually scan for the PCI device, request a single region, 
 * and keep track of the devices that we're using.
 */

static int __init l_gpio_init(void)
{
	struct pci_dev *pdev = NULL;
	int err = -ENODEV;
	int i, j = 0, base = 0;
	struct l_gpio *next, *old = NULL;

	for (i = 0; i < ARRAY_SIZE(l_gpio_pci_tbl) - 1; i++) {
		while ((pdev = pci_get_device(l_gpio_pci_tbl[i].vendor,
					      l_gpio_pci_tbl[i].device,
					      pdev))) {
			struct l_gpio_data *d;
			struct gpio_chip *c;
			if (!(next = kzalloc(sizeof(*next), GFP_KERNEL)))
				return -ENOMEM;
			d = &next->data;
			memcpy(d, (void *)l_gpio_pci_tbl[i].driver_data, sizeof(*d));

			c = (struct gpio_chip *)next;
			c->owner = THIS_MODULE;
			c->label = DRV_NAME;
			c->direction_input = l_gpio_direction_input;
			c->direction_output = l_gpio_direction_output;
			c->get = l_gpio_get_value;
			c->set = l_gpio_set_value;
			c->to_irq = l_gpio_to_irq;
			c->base = base;
			c->ngpio = d->lines;
			c->can_sleep = 0;
#ifdef CONFIG_OF_GPIO
			c->of_node = l_gpio_get_of_node(pdev, d);
#endif

			/*
			 * GPIO/MPV in IOHub2 has 4 IOAPIC IRQs:
			 * 6 and 9 - for MPV
			 * 7 and 11 - for GPIO
			 * On EPIC systems IRQs are recalculated in
			 * fixup_iohub2_dev_irq(), and pdev->irq has the
			 * IRQ for MPV. Add 1 to get IRQ for GPIO.
			 */
			if (cpu_has_epic() && d == &l_iohub2_private_data)
				d->irq[0].nr = pdev->irq + 1;

			/* FIXME: We need universal function to choose between
			 * native_ioapic_set_affinity and native_ioepic_set_affinity
			 * in l_gpio_irq_set_affinity */
			if (cpu_has_epic() && d == &l_iohub3_private_data) {
				l_gpio_irqchip.irq_set_affinity = NULL;
			}

			err = l_gpio_probe(pdev, &l_gpio_pci_tbl[i], next);

			if (err)
				pci_dev_put(pdev);
			if (old)
				old->next = next;
			else
				l_gpios_set = next;
			old = next;
			base += d->lines;
			j++;
		}
	}

	if (l_gpios_set)
		err = register_l_gpio_bound_devices();

	return err;
}

static void __exit l_gpio_exit(void)
{
	struct l_gpio *p;
	for (p = l_gpios_set; p; p = p->next) {
		l_gpio_remove(p);
		pci_dev_put(p->pdev);
	}

}

module_init(l_gpio_init);
module_exit(l_gpio_exit);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("Elbrus MCST GPIO driver");
MODULE_LICENSE("GPL v2");
