#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <asm/gpio.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <drm/drmP.h>
#include "mga2_regs.h"

struct mga2_gpio {
	void __iomem *regs;
	struct pci_dev *pci_dev;
	struct gpio_chip gpio_chip;
	struct irq_chip irq_chip;
	raw_spinlock_t lock;
	struct platform_device *pdev;
};

#define mga2_r(__offset)				\
({								\
	u32 __val = readl(p->regs + (__offset));		\
	DRM_DEBUG("r: %x: %s\n", __val, # __offset);		\
	__val;							\
})

#define mga2_w(__val, __offset) do {				\
	u32 __val2 = __val;					\
	DRM_DEBUG("w: %x %s: %s\n",				\
		__val2, #__val, #__offset);			\
	writel(__val2, p->regs + (__offset));			\
} while (0)

#define mga2_mod_bit(__reg, __bit, __value) do {			\
	u32 __tmp = mga2_r(__reg);				\
	if (__value)						\
		__tmp |= BIT(__bit);				\
	else							\
		__tmp &= ~BIT(__bit);				\
	mga2_w(__tmp, __reg);					\
} while (0)

static int mga2_gpio_get_direction(struct gpio_chip *chip, unsigned offset)
{
	struct mga2_gpio *p = gpiochip_get_data(chip);

	return !(mga2_r(MGA2_VID3_GPIO_DIR) & BIT(offset));
}

static int mga2_gpio_direction_input(struct gpio_chip *chip,
				    unsigned offset)
{
	struct mga2_gpio *p = gpiochip_get_data(chip);
	unsigned long flags;
	raw_spin_lock_irqsave(&p->lock, flags);
	mga2_mod_bit(MGA2_VID3_GPIO_DIR, offset, false);
	raw_spin_unlock_irqrestore(&p->lock, flags);
	return 0;
}

static int mga2_gpio_get(struct gpio_chip *chip, unsigned offset)
{
	struct mga2_gpio *p = gpiochip_get_data(chip);
	return !!(mga2_r(MGA2_VID3_GPIO_IN) & BIT(offset));
}

static void mga2_gpio_set(struct gpio_chip *chip, unsigned offset,
			 int value)
{
	struct mga2_gpio *p = gpiochip_get_data(chip);
	unsigned long flags;

	raw_spin_lock_irqsave(&p->lock, flags);
	mga2_mod_bit(MGA2_VID3_GPIO_OUT, offset, value);
	raw_spin_unlock_irqrestore(&p->lock, flags);
}

static int mga2_gpio_direction_output(struct gpio_chip *chip,
				     unsigned offset, int value)
{
	struct mga2_gpio *p = gpiochip_get_data(chip);
	unsigned long flags;
	raw_spin_lock_irqsave(&p->lock, flags);
	mga2_mod_bit(MGA2_VID3_GPIO_DIR, offset, true);
	raw_spin_unlock_irqrestore(&p->lock, flags);
	return 0;
}

static int mga2_gpio_probe(struct platform_device *pdev)
{
	int ret;
	struct mga2_gpio *p;
	struct gpio_chip *gpio_chip;
	struct device *dev = &pdev->dev;
	const char *name = dev_name(dev);
	struct pci_dev *pci_dev = pci_get_device(PCI_VENDOR_ID_MCST_TMP,
						 PCI_DEVICE_ID_MCST_MGA2,
						 NULL);
	if (!pci_dev)
		return -ENODEV;
	p = devm_kzalloc(dev, sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	p->regs = devm_ioremap(dev, pci_resource_start(pci_dev, 2),
			       pci_resource_len(pci_dev, 2));
	if (IS_ERR(p->regs))
		return PTR_ERR(p->regs);
	p->pci_dev = pci_dev;
	p->pdev = pdev;
	raw_spin_lock_init(&p->lock);

	platform_set_drvdata(pdev, p);

	gpio_chip = &p->gpio_chip;
	gpio_chip->get_direction = mga2_gpio_get_direction;
	gpio_chip->direction_input = mga2_gpio_direction_input;
	gpio_chip->get = mga2_gpio_get;
	gpio_chip->direction_output = mga2_gpio_direction_output;
	gpio_chip->set = mga2_gpio_set;
	gpio_chip->label = name;
	gpio_chip->parent = dev;
	gpio_chip->owner = THIS_MODULE;
	gpio_chip->base = -1;
	gpio_chip->ngpio = 8;

	ret = gpiochip_add_data(gpio_chip, p);
	if (ret) {
		dev_err(dev, "failed to add GPIO controller\n");
		goto err0;
	}
	return 0;
err0:
	return ret;
}

static int mga2_gpio_remove(struct platform_device *pdev)
{
	struct mga2_gpio *p = platform_get_drvdata(pdev);
	gpiochip_remove(&p->gpio_chip);
	pci_dev_put(p->pci_dev);
	return 0;
}

static const struct of_device_id __maybe_unused mga2_gpio_dt_ids[] = {
	{.compatible = "mcst,mga2-gpio", },
	{ }
};

MODULE_DEVICE_TABLE(of, mga2_gpio_dt_ids);

static struct platform_driver mga2_gpio_driver = {
	.driver = {
		   .name = "mga2-gpio",
		   .of_match_table = of_match_ptr(mga2_gpio_dt_ids),
		    },
	.probe = mga2_gpio_probe,
	.remove = mga2_gpio_remove,
};

module_platform_driver(mga2_gpio_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Dmitry.E.Cherednichenko <Dmitry.E.Cherednichenko@mcst.ru>");
