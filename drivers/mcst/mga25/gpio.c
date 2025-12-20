/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include "drv.h"
#include <asm/gpio.h>

#define	 MGA2_GPIO_MUX		0x00000
#define	 MGA2_GPIO_MUXSETRST	0x00004
# define MGA2_GPIO_SET_OFFSET	8
#define	 MGA2_GPIO_PUP		0x00008
#define	 MGA2_GPIO_PUPSETRST	0x0000C
#define	 MGA2_GPIO_DIR		0x00010
#define	 MGA2_GPIO_DIRSETRST	0x00014
#define	 MGA2_GPIO_OUT		0x00018
#define	 MGA2_GPIO_OUTSETRST	0x0001C
#define	 MGA2_GPIO_IN		0x00020

struct mga25_gpio {
	void __iomem *regs;
	struct gpio_chip gpio_chip;
	struct irq_chip irq_chip;
	struct platform_device *pdev;
};

#define mga25_r(__offset)				\
({								\
	u32 __val = readl(p->regs + (__offset));		\
	/*DRM_DEBUG("r: %x: %s\n", __val, # __offset);*/	\
	__val;							\
})

#define mga25_w(__val, __offset) do {				\
	u32 __val2 = __val;					\
	/*DRM_DEBUG("w: %x %s: %s\n",				\
		__val2, #__val, #__offset);*/			\
	writel(__val2, p->regs + (__offset));			\
} while (0)

static int mga25_gpio_get_direction(struct gpio_chip *chip, unsigned offset)
{
	struct mga25_gpio *p = gpiochip_get_data(chip);

	return !(mga25_r(MGA2_GPIO_DIR) & BIT(offset));
}

static int mga25_gpio_direction_input(struct gpio_chip *chip,
				    unsigned offset)
{
	struct mga25_gpio *p = gpiochip_get_data(chip);
	u32 v = BIT(offset);
	mga25_w(v, MGA2_GPIO_DIRSETRST);
	return 0;
}

static int mga25_gpio_get(struct gpio_chip *chip, unsigned offset)
{
	struct mga25_gpio *p = gpiochip_get_data(chip);
	return !!(mga25_r(MGA2_GPIO_IN) & BIT(offset));
}

static void mga25_gpio_set(struct gpio_chip *chip, unsigned offset,
			 int value)
{
	struct mga25_gpio *p = gpiochip_get_data(chip);
	u32 v = BIT(offset);
	if (value)
		v <<= MGA2_GPIO_SET_OFFSET;
	mga25_w(v, MGA2_GPIO_OUTSETRST);
}

static int mga25_gpio_direction_output(struct gpio_chip *chip,
				     unsigned offset, int value)
{
	struct mga25_gpio *p = gpiochip_get_data(chip);
	u32 v = BIT(offset);
	u32 d = v << MGA2_GPIO_SET_OFFSET;
	if (value)
		v <<= MGA2_GPIO_SET_OFFSET;
	mga25_w(v, MGA2_GPIO_OUTSETRST);
	mga25_w(d, MGA2_GPIO_DIRSETRST);

	return 0;
}

static int mga25_gpio_set_config(struct gpio_chip *gpio, unsigned int nr,
				unsigned long config)
{
	enum pin_config_param param = pinconf_to_config_param(config);

	/* The GPIO's are open drain */
	if (param != PIN_CONFIG_DRIVE_OPEN_DRAIN)
		return -ENOTSUPP;

	return 0;
}

static int mga25_gpio_probe(struct platform_device *pdev)
{
	int ret;
	u32 ngpio;
	struct mga25_gpio *p;
	struct gpio_chip *c;
	struct device *dev = &pdev->dev;
	const char *name = dev_name(dev);
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);

	p = devm_kzalloc(dev, sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	p->regs = devm_ioremap_resource(dev, res);
	if (IS_ERR(p->regs))
		return PTR_ERR(p->regs);
	p->pdev = pdev;

	platform_set_drvdata(pdev, p);

	c = &p->gpio_chip;
	c->get_direction	= mga25_gpio_get_direction;
	c->direction_input	= mga25_gpio_direction_input;
	c->get			= mga25_gpio_get;
	c->direction_output	= mga25_gpio_direction_output;
	c->set			= mga25_gpio_set;
	c->set_config		= mga25_gpio_set_config;
	c->label = name;
	c->parent = dev;
	c->owner = THIS_MODULE;
	c->base = -1;
	ret = of_property_read_u32(pdev->dev.of_node, "ngpios", &ngpio);
	if (ret) {
		dev_err(dev, "no 'ngpios' property: %d\n", ret);
		goto err0;
	}
	c->ngpio = ngpio;
	ret = gpiochip_add_data(c, p);
	if (ret) {
		dev_err(dev, "failed to add GPIO controller: %d\n", ret);
		goto err0;
	}
	return 0;
err0:
	return ret;
}

static int mga25_gpio_remove(struct platform_device *pdev)
{
	struct mga25_gpio *p = platform_get_drvdata(pdev);
	gpiochip_remove(&p->gpio_chip);
	return 0;
}

static const struct of_device_id __maybe_unused mga25_gpio_dt_ids[] = {
	{.compatible = "mcst,mga2x-gpio", },
	{ }
};

MODULE_DEVICE_TABLE(of, mga25_gpio_dt_ids);

struct platform_driver mga25_gpio_driver = {
	.driver = {
		   .name = "mga2-gpio",
		   .of_match_table = of_match_ptr(mga25_gpio_dt_ids),
		    },
	.probe = mga25_gpio_probe,
	.remove = mga25_gpio_remove,
};
