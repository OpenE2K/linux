#define DEBUG
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pwm.h>
#include <linux/pci.h>
#include <linux/io.h>
#include "smi_drv.h"
#include "ddk768/ddk768_reg.h"

struct smi_pwm_chip {
	struct pwm_chip chip;
	void __iomem *regs;
	struct pci_dev *pci_dev;
};

static inline struct smi_pwm_chip *to_smi_chip(struct pwm_chip *chip)
{
	return container_of(chip, struct smi_pwm_chip, chip);
}


#define smi_r(__offset)				\
({								\
	u32 __val = readl(smi->regs + (__offset));		\
	DRM_DEBUG("r: %x:%x\n", __offset, __val);		\
	__val;							\
})

#define smi_w(__val, __offset)	do {				\
	u32 __val2 = __val;					\
	DRM_DEBUG("w: %x:%x\n", __offset, __val2);		\
	writel(__val2, smi->regs + (__offset));			\
} while (0)


#define SMI_PWM_MAX_DIVISION	PWM_CONTROL_CLOCK_DIVIDE_32768
#define SMI_PWM_MAX_CYCLE	(1 << 12)
#define SMI_CLK_RATE	(42 * 1000 * 1000)

static int smi_pwm_get_clock_division(int period_ns)
{
	unsigned long long max;
	unsigned int div;

	for (div = 0; div <= SMI_PWM_MAX_DIVISION; div++) {
		max = (1ULL << div) * NSEC_PER_SEC * SMI_PWM_MAX_CYCLE;
		do_div(max, SMI_CLK_RATE);
		if (period_ns <= max)
			break;
	}

	return (div <= SMI_PWM_MAX_DIVISION) ? div : -ERANGE;
}

static int smi_pwm_set_counter(struct smi_pwm_chip *smi,
			       struct pwm_device *pwm, int div,
			       int duty_ns, int period_ns)
{
	unsigned long long one_cycle, prd, low, high;	/* 0.01 nanoseconds */
	u32 ctrl_reg = PWM_CONTROL + pwm->hwpwm * 4;

	one_cycle = NSEC_PER_SEC * 100ULL * (1 << div);
	do_div(one_cycle, SMI_CLK_RATE);
	high = duty_ns * 100ULL;
	do_div(high, one_cycle);
	prd = period_ns * 100ULL;
	do_div(prd, one_cycle);
	low = prd - high;

	/* Avoid prohibited setting */
	if (low == 0 || high == 0)
		return -EINVAL;

	smi_w(((high - 1) << PWM_CONTROL_HIGH_COUNTER_SHIFT) |
	      ((low - 1) << PWM_CONTROL_LOW_COUNTER_SHIFT) |
	      (div << PWM_CONTROL_CLOCK_DIVIDE_SHIFT) |
	      PWM_CONTROL_STATUS_ENABLE, ctrl_reg);
	return 0;
}

static int smi_pwm_config(struct pwm_chip *chip, struct pwm_device *pwm,
			  int duty_ns, int period_ns)
{
	struct smi_pwm_chip *smi = to_smi_chip(chip);
	int div, ret;

	DRM_DEBUG("duty: %d, period: %d\n", duty_ns, period_ns);
	div = smi_pwm_get_clock_division(period_ns);
	if (div < 0)
		return div;
	if (!pwm_is_enabled(pwm) && !duty_ns && !pwm->state.duty_cycle)
		return 0;


	ret = smi_pwm_set_counter(smi, pwm, div, duty_ns, period_ns);

	return ret;
}

static int smi_pwm_enable(struct pwm_chip *chip, struct pwm_device *pwm)
{
	struct smi_pwm_chip *smi = to_smi_chip(chip);
	smi_w((1 << (pwm->hwpwm + GPIO_MUX_PWM_SHIFT)) |
	      smi_r(GPIO_MUX), GPIO_MUX);

	return 0;
}

static void smi_pwm_disable(struct pwm_chip *chip, struct pwm_device *pwm)
{
	struct smi_pwm_chip *smi = to_smi_chip(chip);
	smi_w(~(1 << (pwm->hwpwm + GPIO_MUX_PWM_SHIFT)) &
	      smi_r(GPIO_MUX), GPIO_MUX);
}

static const struct pwm_ops smi_pwm_ops = {
	.config = smi_pwm_config,
	.enable = smi_pwm_enable,
	.disable = smi_pwm_disable,
	.owner = THIS_MODULE,
};

static int smi_pwm_probe(struct platform_device *pdev)
{
	struct smi_pwm_chip *smi;
	struct pci_dev *pci_dev = pci_get_device(PCI_VENDOR_ID_SMI,
					   PCI_DEVID_SM768,
					   NULL);
	if (!pci_dev)
		return -ENODEV;
	smi = devm_kzalloc(&pdev->dev, sizeof(*smi), GFP_KERNEL);
	if (!smi)
		return -ENOMEM;

	smi->regs = devm_ioremap(&pdev->dev, pci_resource_start(pci_dev, 1),
				 pci_resource_len(pci_dev, 1));
	if (IS_ERR(smi->regs))
		return PTR_ERR(smi->regs);
	smi->pci_dev = pci_dev;
	smi->chip.ops = &smi_pwm_ops;
	smi->chip.dev = &pdev->dev;
	smi->chip.base = -1;
	smi->chip.npwm = 3;
	smi->chip.of_xlate = of_pwm_xlate_with_flags;
	smi->chip.of_pwm_n_cells = 3;

	platform_set_drvdata(pdev, smi);

	return pwmchip_add(&smi->chip);
}

static int smi_pwm_remove(struct platform_device *pdev)
{
	struct smi_pwm_chip *smi = platform_get_drvdata(pdev);
	pci_dev_put(smi->pci_dev);
	return pwmchip_remove(&smi->chip);
}

static const struct of_device_id __maybe_unused smi_pwm_dt_ids[] = {
	{.compatible = "smi,pwm", },
	{ }
};

MODULE_DEVICE_TABLE(of, smi_pwm_dt_ids);

static struct platform_driver smi_pwm_driver = {
	.driver = {
		   .name = "smi-pwm",
		   .of_match_table = of_match_ptr(smi_pwm_dt_ids),
		    },
	.probe = smi_pwm_probe,
	.remove = smi_pwm_remove,
};

module_platform_driver(smi_pwm_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
