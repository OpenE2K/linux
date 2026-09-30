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
	struct irq_chip irq_chip;
	void __iomem *regs;
	struct pci_dev *pdev;
	raw_spinlock_t lock;
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
static void l_gpio_set_value(struct gpio_chip *gc,
				unsigned int offset, int state)
{
	struct l_gpio *c = gpiochip_get_data(gc);
	unsigned long flags;
	unsigned int x;

	raw_spin_lock_irqsave(&c->lock, flags);
	x = readl(c->regs + L_GPIO_DATA);
	if (state)
		x |= L_GPIO_ONE_MASK(offset);
	else
		x &= L_GPIO_ZERO_MASK(offset);

	writel(x, c->regs + L_GPIO_DATA);
	raw_spin_unlock_irqrestore(&c->lock, flags);
}

/*
 * Read the state of a GPIO line.
 */
static int __l_gpio_get_value(struct l_gpio *c, unsigned int offset)
{
	unsigned int x = readl(c->regs + L_GPIO_DATA);

	return (x & L_GPIO_ONE_MASK(offset)) ? 1 : 0;
}

static int l_gpio_get_value(struct gpio_chip *gc, unsigned int offset)
{
	struct l_gpio *c = gpiochip_get_data(gc);
	unsigned long flags;
	int x;

	raw_spin_lock_irqsave(&c->lock, flags);
	x = __l_gpio_get_value(c, offset);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return x;
}

static int l_gpio_get_direction(struct gpio_chip *gc, unsigned offset)
{
	struct l_gpio *c = gpiochip_get_data(gc);
	unsigned x = readl(c->regs + L_GPIO_CNTRL);

	return !(x & BIT(offset));
}
/*
 * Configure the GPIO line as an input.
 */
static int l_gpio_direction_input(struct gpio_chip *gc, unsigned offset)
{
	struct l_gpio *c = gpiochip_get_data(gc);
	unsigned long flags;
	unsigned int x;

	raw_spin_lock_irqsave(&c->lock, flags);
	x = readl(c->regs + L_GPIO_CNTRL);
	x &= L_GPIO_ZERO_MASK(offset);
	writel(x, c->regs + L_GPIO_CNTRL);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return 0;
}

/*
 * Configure the GPIO line as an output.
 */
static int l_gpio_direction_output(struct gpio_chip *gc, unsigned offset,
				      int val)
{
	struct l_gpio *c = gpiochip_get_data(gc);
	unsigned long flags;
	unsigned int x;

	raw_spin_lock_irqsave(&c->lock, flags);
	x = readl(c->regs + L_GPIO_CNTRL);
	x |= L_GPIO_ONE_MASK(offset);
	writel(x, c->regs + L_GPIO_CNTRL);
	raw_spin_unlock_irqrestore(&c->lock, flags);
	l_gpio_set_value(gc, offset, val);

	return 0;
}

/* GPIOLIB interface */
static struct l_gpio *l_gpios_set;

/*
 * GPIO IRQ
 */
static void l_gpio_irq_disable(struct irq_data *idt)
{
	unsigned long flags;
	unsigned int x;
	struct gpio_chip *gc = irq_data_get_irq_chip_data(idt);
	struct l_gpio *c = gpiochip_get_data(gc);
	int offset = irqd_to_hwirq(idt);

	raw_spin_lock_irqsave(&c->lock, flags);
	x = readl(c->regs + L_GPIO_INT_EN);
	x &= L_GPIO_ZERO_MASK(offset);
	writel(x, c->regs + L_GPIO_INT_EN);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return;
}

static void l_gpio_irq_enable(struct irq_data *idt)
{
	unsigned long flags;
	unsigned int x;
	struct gpio_chip *ch = irq_data_get_irq_chip_data(idt);
	struct l_gpio *c = gpiochip_get_data(ch);
	int offset = irqd_to_hwirq(idt);

	raw_spin_lock_irqsave(&c->lock, flags);
	x = readl(c->regs + L_GPIO_INT_EN);
	x |= L_GPIO_ONE_MASK(offset);
	writel(x, c->regs + L_GPIO_INT_EN);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return;
}

static int l_gpio_irq_type(struct irq_data *idt, unsigned type)
{
	unsigned long flags;
	irq_flow_handler_t handler;
	struct gpio_chip *ch = irq_data_get_irq_chip_data(idt);
	struct l_gpio *c = gpiochip_get_data(ch);
	int offset = irqd_to_hwirq(idt);
	unsigned int cls, lvl;

	if (offset < 0 || offset > ch->ngpio)
		return -EINVAL;

	raw_spin_lock_irqsave(&c->lock, flags);

	cls = readl(c->regs + L_GPIO_INT_CLS);
	lvl = readl(c->regs + L_GPIO_INT_LVL);

	switch (type) {
	case IRQ_TYPE_EDGE_BOTH:
		handler = handle_edge_irq;
		cls |= L_GPIO_ONE_MASK(offset);
		/*
		 * Since the hardware doesn't support interrupts on both edges,
		 * emulate it in the software by setting the single edge
		 * interrupt and switching to the opposite edge while ACKing
		 * the interrupt
		 */
		if (__l_gpio_get_value(c, offset))
			lvl &= L_GPIO_ZERO_MASK(offset); /* falling */
		else
			lvl |= L_GPIO_ONE_MASK(offset); /* rising */
		break;
	case IRQ_TYPE_EDGE_RISING:
		handler = handle_edge_irq;
		cls |= L_GPIO_ONE_MASK(offset);
		lvl |= L_GPIO_ONE_MASK(offset);
		break;
	case IRQ_TYPE_EDGE_FALLING:
		handler = handle_edge_irq;
		cls |= L_GPIO_ONE_MASK(offset);
		lvl &= L_GPIO_ZERO_MASK(offset);
		break;
	case IRQ_TYPE_LEVEL_HIGH:
		handler = handle_level_irq;
		cls &= L_GPIO_ZERO_MASK(offset);
		lvl |= L_GPIO_ONE_MASK(offset);
		break;
	case IRQ_TYPE_LEVEL_LOW:
		handler = handle_level_irq;
		cls &= L_GPIO_ZERO_MASK(offset);
		lvl &= L_GPIO_ZERO_MASK(offset);
		break;
	default:
		raw_spin_unlock_irqrestore(&c->lock, flags);
		return -EINVAL;
	}
	writel(lvl, c->regs + L_GPIO_INT_LVL);
	writel(cls, c->regs + L_GPIO_INT_CLS);

	raw_spin_unlock_irqrestore(&c->lock, flags);
	irq_set_handler_locked(idt, handler);
	return 0;
}

static irqreturn_t l_gpio_irq_handler(int irq, void *dev_id)
{
	unsigned int x;
	unsigned int i;
	irqreturn_t ret = IRQ_NONE;
	struct l_gpio *c = dev_id;
	struct gpio_chip *gc = &c->chip;
	unsigned start = 0, end = gc->ngpio;

	x = readl(c->regs + L_GPIO_INT_STS);

	for (i = 0; c->data.irq[i].nr &&
		     i < ARRAY_SIZE(c->data.irq); i++) {
		if (c->data.irq[i].nr == irq && c->data.irq[i].end) {
			start = c->data.irq[i].start;
			end = c->data.irq[i].end;
			break;
		}
	}
	for (i = start; i <= end; i++) {
		u32 type;
		if (!(x & (1 << i)))
			continue;
		irq = irq_find_mapping(gc->irq.domain, i);
		type = irq_get_trigger_type(irq);

		/*
		 * Switch the interrupt edge to the opposite edge
		 * of the interrupt which got triggered for the case
		 * of emulating both edges
		 */
		if ((type & IRQ_TYPE_SENSE_MASK) == IRQ_TYPE_EDGE_BOTH) {
			l_gpio_irq_type(irq_get_irq_data(irq),
						IRQ_TYPE_EDGE_BOTH);
		}
		generic_handle_irq(irq);
		ret = IRQ_HANDLED;
	}

	if (ret == IRQ_HANDLED)
		writel(x, c->regs + L_GPIO_INT_STS);

	return ret;
}

static void l_gpio_irq_ack(struct irq_data *data)
{
	/* Do nothing: just to prevent handle_edge_irq()
	 * from calling NULL-pointer */
}

static const struct irq_chip l_gpio_irqchip = {
	.name = "l-gpio-irqchip",
	.irq_ack     = l_gpio_irq_ack,
	.irq_enable  = l_gpio_irq_enable,
	.irq_disable = l_gpio_irq_disable,
	.irq_unmask  = l_gpio_irq_enable,
	.irq_mask    = l_gpio_irq_disable,
	.irq_set_type = l_gpio_irq_type,
	.flags = IRQCHIP_SET_TYPE_MASKED | IRQCHIP_MASK_ON_SUSPEND,
};

static int l_gpio_probe(struct pci_dev *pdev, struct l_gpio *c)
{
	int err;
	struct gpio_chip *gc = &c->chip;
	struct gpio_irq_chip *girq = &gc->irq;
	int i, bar = c->data.bar;

	err = pci_enable_device_mem(pdev);
	if (err) {
		dev_err(&pdev->dev, "can't enable l-gpio device MEM\n");
		goto done;
	}

	/* set up the driver-specific struct */
	c->regs = pci_iomap(pdev, bar, 0);
	c->pdev = pdev;
	raw_spin_lock_init(&(c->lock));

#if 0 /* do not touch boot settings */
	/* Default Input/Output mode for all pins: */
	writel(L_GPIO_CNTRL_DEF, c->regs + L_GPIO_CNTRL);
	/* Default interrupt enable/disable for all pins: */
	writel(L_GPIO_INT_EN_DEF, c->regs + L_GPIO_INT_EN);
	/* Default interrupt mode level/edge for all pins: */
	writel(L_GPIO_INT_CLS_DEF, c->regs + L_GPIO_INT_CLS);
	/* Default rising/falling edge detection for all pins (if edge): */
	writel(L_GPIO_INT_LVL_DEF, c->regs + L_GPIO_INT_LVL);
#endif

	c->irq_chip = l_gpio_irqchip;
	girq->chip = &c->irq_chip;
	/* This will let us handle the parent IRQ in the driver */
	girq->parent_handler = NULL;
	girq->num_parents = 0;
	girq->parents = NULL;
	girq->default_type = IRQ_TYPE_NONE;
	girq->handler = handle_bad_irq;

	err = gpiochip_add_data(gc, c);
	if (err)
		goto err;
	for (i = 0; c->data.irq[i].nr && i < ARRAY_SIZE(c->data.irq); i++)
		;
	if (i == 0)
		goto out;

	for (i = 0; !err && c->data.irq[i].nr &&
				i < ARRAY_SIZE(c->data.irq); i++) {
		err = request_irq(c->data.irq[i].nr, l_gpio_irq_handler,
			IRQF_SHARED, "l-gpio", c);
	}
	if (err) {
		dev_err(&pdev->dev, "IRQ handler registering failed (%d)\n", err);
		for (i = i - 1; i >= 0; i--)
			free_irq(c->data.irq[i].nr, c);
		goto err2;
	}

out:
	dev_info(&pdev->dev, DRV_NAME
		": L-GPIO support successfully loaded.\n");
	return 0;
err2:
	gpiochip_remove(gc);
err:
	pci_iounmap(pdev, c->regs);
	pci_release_region(pdev, c->data.bar);
done:
	return err;
}

static void __exit l_gpio_remove(struct l_gpio *c)
{
	int i;
	struct pci_dev *pdev = c->pdev;
	struct gpio_chip *gc = &c->chip;
	int bar = c->data.bar;

	gpiochip_remove(gc);
	for (i = 0; c->data.irq[i].nr && i < ARRAY_SIZE(c->data.irq); i++) {
		free_irq(c->data.irq[i].nr, c);
	}
	pci_iounmap(pdev, c->regs);
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

static int l_gpio_init_one(struct pci_dev *pdev, const struct l_gpio_data *drv_data)
{
	int err = -ENODEV;
	struct l_gpio *next, *old = NULL;

	struct l_gpio_data *d;
	struct gpio_chip *c;
	if (!(next = kzalloc(sizeof(*next), GFP_KERNEL)))
		return -ENOMEM;
	d = &next->data;
	memcpy(d, drv_data, sizeof(*d));

	c = (struct gpio_chip *)next;
	c->owner = THIS_MODULE;
	c->label = DRV_NAME;
	c->get_direction = l_gpio_get_direction;
	c->direction_input = l_gpio_direction_input;
	c->direction_output = l_gpio_direction_output;
	c->get = l_gpio_get_value;
	c->set = l_gpio_set_value;
	c->ngpio = d->lines;
	c->can_sleep = 0;
	c->of_node = l_gpio_get_of_node(pdev, d);
	/*just to make gpiochip_irqchip_add() happy (linux-5.4)*/
	c->parent = &pdev->dev;

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

	err = l_gpio_probe(pdev, next);

	if (err)
		pci_dev_put(pdev);
	if (old)
		old->next = next;
	else
		l_gpios_set = next;
	old = next;


	if (!l_gpios_set)
		err = register_l_gpio_bound_devices();

	return err;
}
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
	int err = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(l_gpio_pci_tbl) - 1; i++) {
		while ((pdev = pci_get_device(l_gpio_pci_tbl[i].vendor,
					      l_gpio_pci_tbl[i].device,
					      pdev))) {
			struct l_gpio_data *d = (struct l_gpio_data *)
					l_gpio_pci_tbl[i].driver_data;
			err = l_gpio_init_one(pdev, d);
			if (err)
				goto out;
		}
	}

	if (l_gpios_set)
		err = register_l_gpio_bound_devices();
out:
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
