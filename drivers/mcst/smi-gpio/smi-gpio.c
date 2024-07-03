#define DEBUG
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <asm/gpio.h>
#include <linux/pci.h>
#include <linux/io.h>
#include "smi_drv.h"
#include "ddk768/ddk768_reg.h"

struct smi_gpio {
	void __iomem *regs;
	struct pci_dev *pci_dev;
	struct gpio_chip gpio_chip;
	struct irq_chip irq_chip;
	raw_spinlock_t lock;
	struct platform_device *pdev;
};
static int smi_gpio_get(struct gpio_chip *chip, unsigned pin);

#define smi_r(__offset)				\
({								\
	u32 __val = readl(p->regs + (__offset));		\
	DRM_DEBUG("r: %x:% 8x\n", __offset, __val);		\
	__val;							\
})

#define smi_w(__val, __offset)	do {				\
	u32 __val2 = __val;					\
	DRM_DEBUG("w: %x:% 8x\n", __offset, __val2);		\
	writel(__val2, p->regs + (__offset));			\
} while (0)

#define smi_mod_bit(__reg, __bit, __value) do {			\
	u32 __tmp = smi_r(__reg);				\
	if (__value)						\
		__tmp |= BIT(__bit);				\
	else							\
		__tmp &= ~BIT(__bit);				\
	smi_w(__tmp, __reg);					\
} while (0)

static void smi_gpio_irq_disable(struct irq_data *d)
{
	unsigned long flags;
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct smi_gpio *p = gpiochip_get_data(gc);
	unsigned pin = irqd_to_hwirq(d);

	raw_spin_lock_irqsave(&p->lock, flags);
	smi_mod_bit(INT_MASK, INT_MASK_GPIO0_SHIFT + pin, false);
	smi_mod_bit(GPIO_INTERRUPT_SETUP,
		    GPIO_INTERRUPT_SETUP_ENABLE_SHIFT + pin, false);
	raw_spin_unlock_irqrestore(&p->lock, flags);
}

static void smi_gpio_irq_enable(struct irq_data *d)
{
	unsigned long flags;
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct smi_gpio *p = gpiochip_get_data(gc);
	unsigned pin = irqd_to_hwirq(d);

	raw_spin_lock_irqsave(&p->lock, flags);
	smi_w(BIT(pin), GPIO_INTERRUPT_STATUS);
	smi_mod_bit(GPIO_INTERRUPT_SETUP,
		    GPIO_INTERRUPT_SETUP_ENABLE_SHIFT + pin, true);
	smi_mod_bit(INT_MASK, INT_MASK_GPIO0_SHIFT + pin, true);
	raw_spin_unlock_irqrestore(&p->lock, flags);
}

static void __smi_gpio_irq_set_type(struct smi_gpio *p,
						 unsigned pin,
						 bool
						 active_high_rising_edge,
						 bool level_trigger)
{
	/* follow steps in the GPIO documentation for
	 * "Setting Edge-Sensitive Interrupt Input Mode" and
	 * "Setting Level-Sensitive Interrupt Input Mode"
	 */

	smi_mod_bit(GPIO_INTERRUPT_SETUP,
		    GPIO_INTERRUPT_SETUP_ACTIVE_SHIFT + pin,
		    active_high_rising_edge);

	smi_mod_bit(GPIO_INTERRUPT_SETUP,
		    GPIO_INTERRUPT_SETUP_TRIGGER_SHIFT + pin,
		    level_trigger);
}

static int smi_gpio_irq_set_type(struct irq_data *d, unsigned type)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct smi_gpio *p = gpiochip_get_data(gc);
	unsigned pin = irqd_to_hwirq(d);
	unsigned long flags;
	int ret = 0;

	DRM_DEBUG("sense irq = %d, type = %d\n", pin, type);
	if (pin > 6) /* only seven pins can be programmed as interrupt GPIO */
		return -EDOM;

	raw_spin_lock_irqsave(&p->lock, flags);
	switch (type & IRQ_TYPE_SENSE_MASK) {
	case IRQ_TYPE_EDGE_BOTH:
		/*
		 * Since the hardware doesn't support interrupts on both edges,
		 * emulate it in the software by setting the single edge
		 * interrupt and switching to the opposite edge while ACKing
		 * the interrupt
		 */
		if (smi_gpio_get(gc, pin)) /* falling */
			__smi_gpio_irq_set_type(p, pin, false, false);
		else /* rising */
			__smi_gpio_irq_set_type(p, pin, true, false);
		break;
	case IRQ_TYPE_LEVEL_HIGH:
		__smi_gpio_irq_set_type(p, pin, true, true);
		break;
	case IRQ_TYPE_LEVEL_LOW:
		__smi_gpio_irq_set_type(p, pin, false, true);
		break;
	case IRQ_TYPE_EDGE_RISING:
		__smi_gpio_irq_set_type(p, pin, true, false);
		break;
	case IRQ_TYPE_EDGE_FALLING:
		__smi_gpio_irq_set_type(p, pin, false, false);
		break;
	default:
		ret = -EINVAL;
		goto out;
	}
	smi_mod_bit(GPIO_MUX, pin, false);
	raw_spin_unlock_irqrestore(&p->lock, flags);
out:
	return ret;
}

static irqreturn_t smi_gpio_irq_handler(int irq, void *dev_id)
{
	struct smi_gpio *p = dev_id;
	u32 pending;
	unsigned pin, irqs_handled = 0;

	while ((pending = smi_r(GPIO_INTERRUPT_STATUS) &
		smi_r(GPIO_INTERRUPT_SETUP) &
		GPIO_INTERRUPT_SETUP_ENABLE_MASK)) {
		u32 type, irq;
		pin = __ffs(pending);
		smi_w(BIT(pin), GPIO_INTERRUPT_STATUS);
		irq = irq_find_mapping(p->gpio_chip.irq.domain, pin);
		type = irq_get_trigger_type(irq);
		/*
		 * Switch the interrupt edge to the opposite edge
		 * of the interrupt which got triggered for the case
		 * of emulating both edges
		 */
		if ((type & IRQ_TYPE_SENSE_MASK) == IRQ_TYPE_EDGE_BOTH) {
			smi_gpio_irq_set_type(irq_get_irq_data(irq),
						IRQ_TYPE_EDGE_BOTH);
		}
		generic_handle_irq(irq);
		irqs_handled++;
	}

	return irqs_handled ? IRQ_HANDLED : IRQ_NONE;
}


static int smi_gpio_get_direction(struct gpio_chip *chip, unsigned pin)
{
	struct smi_gpio *p = gpiochip_get_data(chip);

	return !(smi_r(GPIO_DATA_DIRECTION) & BIT(pin));
}

static int smi_gpio_direction_input(struct gpio_chip *chip,
				    unsigned pin)
{
	struct smi_gpio *p = gpiochip_get_data(chip);
	unsigned long flags;
	raw_spin_lock_irqsave(&p->lock, flags);
	smi_mod_bit(GPIO_DATA_DIRECTION, pin, false);
	raw_spin_unlock_irqrestore(&p->lock, flags);
	return 0;
}

static int smi_gpio_get(struct gpio_chip *chip, unsigned pin)
{
	struct smi_gpio *p = gpiochip_get_data(chip);
	return !!(smi_r(GPIO_DATA) & BIT(pin));
}

static void smi_gpio_set(struct gpio_chip *chip, unsigned pin,
			 int value)
{
	struct smi_gpio *p = gpiochip_get_data(chip);
	unsigned long flags;

	raw_spin_lock_irqsave(&p->lock, flags);
	smi_mod_bit(GPIO_DATA, pin, value);
	raw_spin_unlock_irqrestore(&p->lock, flags);
}

static int smi_gpio_direction_output(struct gpio_chip *chip,
				     unsigned pin, int value)
{
	struct smi_gpio *p = gpiochip_get_data(chip);
	unsigned long flags;
	raw_spin_lock_irqsave(&p->lock, flags);
	smi_mod_bit(GPIO_DATA_DIRECTION, pin, true);
	raw_spin_unlock_irqrestore(&p->lock, flags);
	return 0;
}

static int smi_gpio_probe(struct platform_device *pdev)
{
	int ret;
	struct smi_gpio *p;
	struct gpio_chip *gpio_chip;
	struct irq_chip *irq_chip;
	struct device *dev = &pdev->dev;
	const char *name = dev_name(dev);
	struct pci_dev *pci_dev = pci_get_device(PCI_VENDOR_ID_SMI,
						 PCI_DEVID_SM768,
						 NULL);
	if (!pci_dev)
		return -ENODEV;
	p = devm_kzalloc(dev, sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	p->regs = devm_ioremap(dev, pci_resource_start(pci_dev, 1),
			       pci_resource_len(pci_dev, 1));
	if (IS_ERR(p->regs))
		return PTR_ERR(p->regs);
	p->pci_dev = pci_dev;
	p->pdev = pdev;
	raw_spin_lock_init(&p->lock);

	platform_set_drvdata(pdev, p);

	gpio_chip = &p->gpio_chip;
	gpio_chip->get_direction = smi_gpio_get_direction;
	gpio_chip->direction_input = smi_gpio_direction_input;
	gpio_chip->get = smi_gpio_get;
	gpio_chip->direction_output = smi_gpio_direction_output;
	gpio_chip->set = smi_gpio_set;
	gpio_chip->label = name;
	gpio_chip->parent = dev;
	gpio_chip->owner = THIS_MODULE;
	gpio_chip->base = -1;
	gpio_chip->ngpio = 32;

	irq_chip = &p->irq_chip;
	irq_chip->name = name;
	/* FIXME: rpm_resume() returns -EACCES during request_irq() */
	/* irq_chip->parent_device = dev; */
	irq_chip->irq_mask = smi_gpio_irq_disable;
	irq_chip->irq_unmask = smi_gpio_irq_enable;
	irq_chip->irq_set_type = smi_gpio_irq_set_type;
	irq_chip->flags =
	    IRQCHIP_SET_TYPE_MASKED | IRQCHIP_MASK_ON_SUSPEND;

	ret = gpiochip_add_data(gpio_chip, p);
	if (ret) {
		dev_err(dev, "failed to add GPIO controller\n");
		goto err0;
	}

	ret =
	    gpiochip_irqchip_add(gpio_chip, irq_chip, 0, handle_level_irq,
				 IRQ_TYPE_NONE);
	if (ret) {
		dev_err(dev, "cannot add irqchip\n");
		goto err1;
	}

	if (devm_request_irq(dev, pci_dev->irq, smi_gpio_irq_handler,
			     IRQF_SHARED, name, p)) {
		dev_err(dev, "failed to request IRQ\n");
		ret = -ENOENT;
		goto err1;
	}

	return 0;

err1:
	gpiochip_remove(gpio_chip);
err0:
	return ret;
}

static int smi_gpio_remove(struct platform_device *pdev)
{
	struct smi_gpio *p = platform_get_drvdata(pdev);
	pci_dev_put(p->pci_dev);
	gpiochip_remove(&p->gpio_chip);
	return 0;
}

static const struct of_device_id __maybe_unused smi_gpio_dt_ids[] = {
	{.compatible = "smi,gpio", },
	{ }
};

MODULE_DEVICE_TABLE(of, smi_gpio_dt_ids);

static struct platform_driver smi_gpio_driver = {
	.driver = {
		   .name = "smi-gpio",
		   .of_match_table = of_match_ptr(smi_gpio_dt_ids),
		    },
	.probe = smi_gpio_probe,
	.remove = smi_gpio_remove,
};

module_platform_driver(smi_gpio_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
