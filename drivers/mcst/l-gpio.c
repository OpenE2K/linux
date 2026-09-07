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
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/of_irq.h>
#if IS_ENABLED(CONFIG_INPUT_LTC2954)
#include <linux/platform_device.h>
#include <linux/gpio_keys.h>
#include <linux/input.h>
#endif /* CONFIG_INPUT_LTC2954 */
#include <asm/gpio.h>
#include <asm/pic.h>

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

struct l_gpio {
	struct gpio_chip chip; /*Must be the first*/
	void __iomem *regs;
	raw_spinlock_t lock;
};

/* Registering gpio-bound devices on board. This is embedded style. */
#if IS_ENABLED(CONFIG_INPUT_LTC2954)

static struct gpio_keys_button ltc2954_descr = {
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
	int ret = 0;
	/* Power button is availble only in iohub1 */
	if (!IS_MACHINE_E2S)
		return 0;

	/* Only power button is available today: */
#if IS_ENABLED(CONFIG_INPUT_LTC2954)
	ret = platform_device_register(&ltc2954_dev);
	if (ret < 0)
		pr_err("failed to register ltc2954 device\n");
#endif /* CONFIG_INPUT_LTC2954_BUTTON */

	return ret;
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

	x = readl(c->regs + L_GPIO_INT_STS);

	for (i = 0; i < gc->ngpio; i++) {
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
		generic_handle_domain_irq(gc->irq.domain, i);
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
	.flags = IRQCHIP_IMMUTABLE,
	 GPIOCHIP_IRQ_RESOURCE_HELPERS,
};

static int __l_gpio_probe(struct platform_device *pdev, struct l_gpio *c)
{
	int ret;
	int irq;
	struct resource *r;
	struct gpio_chip *gc = &c->chip;
	struct device *dev = &pdev->dev;
	struct gpio_irq_chip *girq = &gc->irq;
	int i, irq_nr = platform_irq_count(pdev);

	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!r) {
		dev_err(dev, "No MEM resource available!\n");
		return -ENOMEM;
	}
	c->regs = devm_ioremap_resource(dev, r);
	if (IS_ERR(c->regs)) {
		dev_err(dev,
			"Unable to ioremap base (%ld)!\n", PTR_ERR(c->regs));
		return PTR_ERR(c->regs);
	}
	raw_spin_lock_init(&c->lock);

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
	gpio_irq_chip_set_chip(girq, &l_gpio_irqchip);
	/* This will let us handle the parent IRQ in the driver */
	girq->parent_handler = NULL;
	girq->num_parents = 0;
	girq->parents = NULL;
	girq->default_type = IRQ_TYPE_NONE;
	girq->handler = handle_bad_irq;

	for (i = ret = 0; i < irq_nr && !ret; i++) {
		irq = platform_get_irq(pdev, i);
		ret = devm_request_irq(dev, irq, l_gpio_irq_handler,
				IRQF_NO_THREAD, "l-gpio", c);
	}
	if (ret) {
		dev_err(dev, "IRQ handler registering failed (%d)\n", ret);
		goto out;
	}
	/* finally, register with the generic GPIO API */
	ret = devm_gpiochip_add_data(dev, gc, c);
	if (ret)
		goto out;

	dev_info(dev, DRV_NAME
		": l-gpio support successfully loaded.\n");
out:
	return ret;
}

static int __exit l_gpio_remove(struct platform_device *pdev)
{
	return 0;
}

static int l_gpio_probe(struct platform_device *pdev)
{
	int ret = -ENODEV;
	u32 ngpio;
	struct l_gpio *c;
	struct gpio_chip *gc;
	struct device *dev = &pdev->dev;
	int node = dev_to_node(dev);
	if (node < 0)
		node = 0;
	ret = of_property_read_u32(dev->of_node, "ngpios", &ngpio);
	if (ret) {
		dev_err(dev, "no 'ngpios' property: %d\n", ret);
		return ret;
	}
	if (!(c = kzalloc(sizeof(*c), GFP_KERNEL)))
		return -ENOMEM;

	gc = (struct gpio_chip *)c;
	gc->owner = THIS_MODULE;
	gc->label = DRV_NAME;
	gc->get_direction = l_gpio_get_direction;
	gc->direction_input = l_gpio_direction_input;
	gc->direction_output = l_gpio_direction_output;
	gc->get = l_gpio_get_value;
	gc->set = l_gpio_set_value;
	gc->ngpio = ngpio;
	gc->base = node * ngpio;
	gc->can_sleep = 0;
	gc->of_node = dev->of_node;

	ret = __l_gpio_probe(pdev, c);

	ret = register_l_gpio_bound_devices();

	return ret;
}

static const struct of_device_id l_gpio_of_match[] = {
	{ .compatible = "mcst,l-gpio", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, l_gpio_of_match);

static struct platform_driver l_gpio_platform_driver = {
	.probe = l_gpio_probe,
	.remove = l_gpio_remove,
	.driver = {
		.name = "l-gpio",
		.of_match_table = l_gpio_of_match,
	}
};

module_platform_driver(l_gpio_platform_driver);
MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("Elbrus MCST GPIO driver");
MODULE_LICENSE("GPL v2");
