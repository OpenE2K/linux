/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include "drv.h"
#include <linux/pwm.h>

#define MGA2_PWM0_CTRL	0x0000
/* PWB bits are common for PWM0 and PWM1 */
# define MGA2_B_PWMENABLE (1 << 31)
# define MGA2_B_PWMINVERT (1 << 30)
# define MGA2_B_PWMVALUE_OFFSET  0

#define MGA2_PWM0_PERIOD	0x0004
# define MGA2_B_PWMPRESCL_OFFSET 16
# define MGA2_B_PWMPERIOD_OFFSET 0

#define MGA2_PWM_PERIOD_MASK 0xffff
#define MGA2_PWM_DUTY_MASK 0x1ffff
#define MGA2_PWM_REGS_SZ	0x10
#define MGA2_PWM_MAX_DIVISION	(1 << 16)
#define MGA2_PWM_MAX_CYCLE	(1 << 16)
#define MGA2_DEFAULT_CLK_RATE	(500 * 1000 * 1000)

struct mga25_pwm_chip {
	struct pwm_chip chip;
	void __iomem *regs;
	unsigned long rate;
};

static inline struct mga25_pwm_chip *to_mga25_chip(struct pwm_chip *chip)
{
	return container_of(chip, struct mga25_pwm_chip, chip);
}

#define mga25_r(__offset)					\
({								\
	u32 __val = readl(mga2->regs + (__offset) +		\
			pwm->hwpwm * MGA2_PWM_REGS_SZ);	\
	DRM_DEBUG("r: %x: %s\n", __val, # __offset);		\
	__val;							\
})

#define mga25_w(__val, __offset)	do {				\
	u32 __val2 = __val;					\
	DRM_DEBUG("w: %x %s: %s\n",				\
		__val2, #__val, #__offset); \
	writel(__val2, mga2->regs + (__offset) +		\
			pwm->hwpwm * MGA2_PWM_REGS_SZ);	\
} while (0)

static int mga25_pwm_get_clock_division(int period_ns, unsigned long rate)
{
	u64 rem = 0, div;
	div = div64_u64_rem(period_ns * rate, NSEC_PER_SEC *
					MGA2_PWM_MAX_CYCLE, &rem);
	if (rem)
		div++;
	return div < MGA2_PWM_MAX_DIVISION ? div : -ERANGE;
}

static int mga25_pwm_set_counter(struct mga25_pwm_chip *mga2,
			       struct pwm_device *pwm, int div,
			       int duty_ns, int period_ns)
{
	u64 one_cycle, prd, high;	/* 0.01 nanoseconds */
	one_cycle = NSEC_PER_SEC * 100ULL * div / mga2->rate;

	high = duty_ns * 100ULL / one_cycle;
	prd = period_ns * 100ULL / one_cycle;
	DRM_DEBUG("duty: %d period: %d (%lld %lld %lld)\n",
		duty_ns, period_ns, one_cycle, high, prd);

	/* Avoid prohibited setting */
	if (prd == 0)
		return -EINVAL;

	 /*0 -> 1/Fpwm, 1 -> 2/Fpwm ... 1 -> 65536/Fpwm */
	mga25_w(((div - 1) << MGA2_B_PWMPRESCL_OFFSET) | (prd - 1),
						MGA2_PWM0_PERIOD);
	mga25_w(high | MGA2_B_PWMENABLE,
				MGA2_PWM0_CTRL);
	return 0;
}

static int mga25_pwm_apply(struct pwm_chip *chip, struct pwm_device *pwm,
			   const struct pwm_state *state)
{
	struct mga25_pwm_chip *mga2 = to_mga25_chip(chip);
	int div, ret;
	mga25_w(0, MGA2_PWM0_CTRL);
	if (!state->enabled)
		return 0;
	div = mga25_pwm_get_clock_division(state->period, mga2->rate);
	if (div < 0)
		return div;

	/* TODO: handle state->polarity */
	ret = mga25_pwm_set_counter(mga2, pwm, div,
				    state->duty_cycle, state->period);
	if (ret < 0)
		return div;
	return ret;
}

static void mga25_pwm_get_state(struct pwm_chip *chip, struct pwm_device *pwm,
				 struct pwm_state *state)
{
	struct mga25_pwm_chip *mga2 = to_mga25_chip(chip);
	u64 tmp, multi, rate = mga2->rate * 100ULL;
	u32 v, prescale;

	v = mga25_r(MGA2_PWM0_CTRL);
	if (v & MGA2_B_PWMENABLE)
		state->enabled = true;
	else
		state->enabled = false;

	if (v & MGA2_B_PWMINVERT)
		state->polarity = PWM_POLARITY_INVERSED;
	else
		state->polarity = PWM_POLARITY_NORMAL;

	v = mga25_r(MGA2_PWM0_PERIOD);
	prescale = v >> MGA2_B_PWMPRESCL_OFFSET;
	multi = NSEC_PER_SEC * (prescale + 1) * 100ULL;

	tmp = (v & MGA2_PWM_PERIOD_MASK) * multi;
	state->period = div64_u64(tmp, rate);

	v = mga25_r(MGA2_PWM0_CTRL);
	tmp = (v & MGA2_PWM_DUTY_MASK) * multi;
	state->duty_cycle = div64_u64(tmp, rate);
}

static const struct pwm_ops mga25_pwm_ops = {
	.get_state = mga25_pwm_get_state,
	.apply =  mga25_pwm_apply,
	.owner = THIS_MODULE,
};

static int mga25_pwm_probe(struct platform_device *pdev)
{
	int ret;
	u32 tmp;
	struct mga25_pwm_chip *mga2;
	struct device *dev = &pdev->dev;
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);

	mga2 = devm_kzalloc(&pdev->dev, sizeof(*mga2), GFP_KERNEL);
	if (!mga2)
		return -ENOMEM;
	mga2->regs = devm_ioremap_resource(&pdev->dev, res);
	if (!mga2)
		return -ENOMEM;
	if (IS_ERR(mga2->regs))
		return PTR_ERR(mga2->regs);
	mga2->chip.ops = &mga25_pwm_ops;
	mga2->chip.dev = &pdev->dev;
	mga2->chip.base = -1;
	mga2->chip.of_xlate = of_pwm_xlate_with_flags;
	mga2->chip.of_pwm_n_cells = 3;

	ret = of_property_read_u32(pdev->dev.of_node, "npwms", &tmp);
	if (ret) {
		dev_err(dev, "no 'npwms' property: %d\n", ret);
		goto err0;
	}

	mga2->chip.npwm = tmp;

	ret = of_property_read_u32(pdev->dev.of_node->parent,
				 "clock-frequency", &tmp);
	if (ret) {
		ret = 0;
		tmp = MGA2_DEFAULT_CLK_RATE;
	}

	mga2->rate = tmp;

	DRM_DEBUG("clock rate: %d\n", tmp);

	platform_set_drvdata(pdev, mga2);

	return pwmchip_add(&mga2->chip);
err0:
	return ret;
}

static int mga25_pwm_remove(struct platform_device *pdev)
{
	struct mga25_pwm_chip *mga2 = platform_get_drvdata(pdev);
	return pwmchip_remove(&mga2->chip);
}

static const struct of_device_id __maybe_unused mga25_pwm_dt_ids[] = {
	{.compatible = "mcst,mga2x-pwm", },
	{ }
};

MODULE_DEVICE_TABLE(of, mga25_pwm_dt_ids);

struct platform_driver mga25_pwm_driver = {
	.driver = {
		   .name = "mga2-pwm",
		   .of_match_table = of_match_ptr(mga25_pwm_dt_ids),
		    },
	.probe = mga25_pwm_probe,
	.remove = mga25_pwm_remove,
};
