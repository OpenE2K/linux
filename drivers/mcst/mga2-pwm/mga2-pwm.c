#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pwm.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <drm/drmP.h>
#include "mga2_regs.h"

struct mga2_pwm_chip {
	struct pwm_chip chip;
	void __iomem *regs;
	struct pci_dev *pci_dev;
};

static inline struct mga2_pwm_chip *to_mga2_chip(struct pwm_chip *chip)
{
	return container_of(chip, struct mga2_pwm_chip, chip);
}

#define mga2_r(__offset)					\
({								\
	u32 __val = readl(mga2->regs + (__offset) +		\
			pwm->hwpwm * MGA2_VID3_PWM_REGS_SZ);	\
	DRM_DEBUG("r: %x: %s\n", __val, # __offset);		\
	__val;							\
})

#define mga2_w(__val, __offset)	do {				\
	u32 __val2 = __val;					\
	DRM_DEBUG("w: %x %s: %s\n",				\
		__val2, #__val, #__offset); \
	writel(__val2, mga2->regs + (__offset) +		\
			pwm->hwpwm * MGA2_VID3_PWM_REGS_SZ);	\
} while (0)

static int mga2_pwm_get_clock_division(int period_ns)
{
	unsigned long long max;
	unsigned int div;

	for (div = 0; div < MGA2_PWM_MAX_DIVISION; div++) {
		max = NSEC_PER_SEC * MGA2_PWM_MAX_CYCLE *
		    (1 << div) / MGA2_CLK_RATE;
		if (period_ns <= max)
			break;
	}

	return (div <= MGA2_PWM_MAX_DIVISION) ? div : -ERANGE;
}

static int mga2_pwm_set_counter(struct mga2_pwm_chip *mga2,
			       struct pwm_device *pwm, int div,
			       int duty_ns, int period_ns)
{
	u64 one_cycle, prd, high;	/* 0.01 nanoseconds */
	one_cycle = NSEC_PER_SEC * 100ULL * (1 << div) / MGA2_CLK_RATE;

	high = duty_ns * 100ULL / one_cycle;
	prd = period_ns * 100ULL / one_cycle;
	DRM_DEBUG("duty: %d period: %d (%lld %lld %lld)\n",
		duty_ns, period_ns, one_cycle, high, prd);

	/* Avoid prohibited setting */
	if (prd == 0)
		return -EINVAL;

	 /*0 -> 1/Fpwm, 1 -> 2/Fpwm ... 1 -> 65536/Fpwm */
	mga2_w(prd - 1, MGA2_VID3_PWM0_PERIOD);
	mga2_w((div << MGA2_VID3_B_PWMPRESCL_OFFSET) |
		high | MGA2_VID3_B_PWMENABLE,
				MGA2_VID3_PWM0_CTRL);
	return 0;
}

static int mga2_pwm_apply(struct pwm_chip *chip, struct pwm_device *pwm,
			   const struct pwm_state *state)
{
	struct mga2_pwm_chip *mga2 = to_mga2_chip(chip);
	int div, ret;
	mga2_w(0, MGA2_VID3_PWM0_CTRL);
	if (!state->enabled)
		return 0;
	div = mga2_pwm_get_clock_division(state->period);
	if (div < 0)
		return div;

	/* TODO: handle state->polarity */
	ret = mga2_pwm_set_counter(mga2, pwm, div,
				    state->duty_cycle, state->period);
	if (ret < 0)
		return div;
	return ret;
}

static void mga2_pwm_get_state(struct pwm_chip *chip, struct pwm_device *pwm,
				 struct pwm_state *state)
{
	struct mga2_pwm_chip *mga2 = to_mga2_chip(chip);
	u64 tmp, multi, rate = MGA2_CLK_RATE * 100ULL;
	u32 value, prescale;

	value = mga2_r(MGA2_VID3_PWM0_CTRL);
	if (value & MGA2_VID3_B_PWMENABLE)
		state->enabled = true;
	else
		state->enabled = false;

	if (value & MGA2_VID3_B_PWMINVERT)
		state->polarity = PWM_POLARITY_INVERSED;
	else
		state->polarity = PWM_POLARITY_NORMAL;

	value = mga2_r(MGA2_VID3_PWM0_CTRL);
	prescale = value >> MGA2_VID3_B_PWMPRESCL_OFFSET;
	multi = NSEC_PER_SEC * (1 << prescale) * 100ULL;

	tmp = (value & MGA2_VID3_PWM_PERIOD_MASK) * multi;
	state->duty_cycle = div64_u64(tmp, rate);

	value = mga2_r(MGA2_VID3_PWM0_PERIOD);
	tmp = (value & MGA2_VID3_PWM_PERIOD_MASK) * multi;
	state->period = div64_u64(tmp, rate);
}

static const struct pwm_ops mga2_pwm_ops = {
	.get_state = mga2_pwm_get_state,
	.apply =  mga2_pwm_apply,
	.owner = THIS_MODULE,
};

static int mga2_pwm_probe(struct platform_device *pdev)
{
	struct mga2_pwm_chip *mga2;
	struct pci_dev *pci_dev = pci_get_device(PCI_VENDOR_ID_MCST_TMP,
						 PCI_DEVICE_ID_MCST_MGA2,
						 NULL);
	if (!pci_dev)
		return -ENODEV;
	mga2 = devm_kzalloc(&pdev->dev, sizeof(*mga2), GFP_KERNEL);
	if (!mga2)
		return -ENOMEM;

	mga2->regs = devm_ioremap(&pdev->dev, pci_resource_start(pci_dev, 2),
				 pci_resource_len(pci_dev, 2));
	if (IS_ERR(mga2->regs))
		return PTR_ERR(mga2->regs);
	mga2->pci_dev = pci_dev;
	mga2->chip.ops = &mga2_pwm_ops;
	mga2->chip.dev = &pdev->dev;
	mga2->chip.base = -1;
	mga2->chip.npwm = 2;
	mga2->chip.of_xlate = of_pwm_xlate_with_flags;
	mga2->chip.of_pwm_n_cells = 3;

	platform_set_drvdata(pdev, mga2);

	return pwmchip_add(&mga2->chip);
}

static int mga2_pwm_remove(struct platform_device *pdev)
{
	struct mga2_pwm_chip *mga2 = platform_get_drvdata(pdev);
	pci_dev_put(mga2->pci_dev);
	return pwmchip_remove(&mga2->chip);
}

static const struct of_device_id __maybe_unused mga2_pwm_dt_ids[] = {
	{.compatible = "mcst,mga2-pwm", },
	{ }
};

MODULE_DEVICE_TABLE(of, mga2_pwm_dt_ids);

static struct platform_driver mga2_pwm_driver = {
	.driver = {
		   .name = "mga2-pwm",
		   .of_match_table = of_match_ptr(mga2_pwm_dt_ids),
		    },
	.probe = mga2_pwm_probe,
	.remove = mga2_pwm_remove,
};

module_platform_driver(mga2_pwm_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Dmitry.E.Cherednichenko <Dmitry.E.Cherednichenko@mcst.ru>");
