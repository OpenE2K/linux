#include "drv.h"
#include <asm/gpio.h>

#define MGA2_PWM0_CTRL	0x0000
/* PWB bits are common for PWM0 and PWM1 */
# define MGA2_B_PWMENABLE (1 << 31)
# define MGA2_B_PWMINVERT (1 << 30)
# define MGA2_B_PWMVALUE_OFFSET  0

#define MGA2_PWM0_PERIOD	0x0004
# define MGA2_B_PWMPRESCL_OFFSET 16
# define MGA2_B_PWMPERIOD_OFFSET 0

#define MGA2_PWM_PERIOD_MASK 0xffff
#define MGA2_PWM_REGS_SZ	0x10
#define MGA2_PWM_MAX_DIVISION	(1 << 16)
#define MGA2_PWM_MAX_CYCLE	(1 << 17)
#define MGA2_CLK_RATE	(500 * 1000 * 1000) /*Hz FIXME:*/

struct mga2_gw {
	void __iomem *regs;
	struct gpio_chip gpio_chip;
	struct irq_chip irq_chip;
	struct platform_device *pdev;
};

#define mga2_r(__offset)				\
({								\
	u32 __val = readl(p->regs + (__offset) + offset * MGA2_PWM_REGS_SZ);		\
	/*DRM_DEBUG("r: %x: %s\n", __val, # __offset);*/	\
	__val;							\
})

#define mga2_w(__val, __offset) do {				\
	u32 __val2 = __val;					\
	DRM_DEBUG("w: %x %s: %s\n",				\
		__val2, #__val, #__offset);			\
	writel(__val2, p->regs + (__offset) + offset * MGA2_PWM_REGS_SZ);			\
} while (0)

static int mga2_gw_get_direction(struct gpio_chip *chip, unsigned offset)
{
	struct mga2_gw *p = gpiochip_get_data(chip);

	return !(mga2_r(MGA2_PWM0_CTRL) & MGA2_B_PWMENABLE);
}

static int mga2_gw_direction_input(struct gpio_chip *chip,
				    unsigned offset)
{
	struct mga2_gw *p = gpiochip_get_data(chip);
	mga2_w(0, MGA2_PWM0_CTRL);
	return 0;
}

static int mga2_gw_get(struct gpio_chip *chip, unsigned offset)
{
	return 0;
}

static void mga2_gw_set(struct gpio_chip *chip, unsigned offset,
			 int value)
{
	struct mga2_gw *p = gpiochip_get_data(chip);
	value = value ? 0xffff : 0;
	mga2_w(value | MGA2_B_PWMENABLE, MGA2_PWM0_CTRL);
}

static int mga2_gw_direction_output(struct gpio_chip *chip,
				     unsigned offset, int value)
{
	struct mga2_gw *p = gpiochip_get_data(chip);
	value = value ? 0xffff : 0;
	mga2_w(2, MGA2_PWM0_PERIOD);
	mga2_w(value | MGA2_B_PWMENABLE, MGA2_PWM0_CTRL);
	return 0;
}

static int mga2_gw_probe(struct platform_device *pdev)
{
	int ret;
	u32 ngpio;
	struct mga2_gw *p;
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
	c->get_direction = mga2_gw_get_direction;
	c->direction_input = mga2_gw_direction_input;
	c->get = mga2_gw_get;
	c->direction_output = mga2_gw_direction_output;
	c->set = mga2_gw_set;
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

static int mga2_gw_remove(struct platform_device *pdev)
{
	struct mga2_gw *p = platform_get_drvdata(pdev);
	gpiochip_remove(&p->gpio_chip);
	return 0;
}

static const struct of_device_id __maybe_unused mga2_gw_dt_ids[] = {
	{.compatible = "mcst,mga2x-wg", },
	{ }
};

MODULE_DEVICE_TABLE(of, mga2_gw_dt_ids);

struct platform_driver mga2_gpio_pwm_driver = {
	.driver = {
		   .name = "mga2-gpio-pwm",
		   .of_match_table = of_match_ptr(mga2_gw_dt_ids),
		    },
	.probe = mga2_gw_probe,
	.remove = mga2_gw_remove,
};
