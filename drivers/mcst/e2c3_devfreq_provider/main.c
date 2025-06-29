#include "main.h"

/* Freq tables and corresponding f_pll value taken from pcs_freq_calc.xls file
http://www.lab.sun.mcst.ru/honey/elbrus_2c3/doc/hw/pcs/pcs_freq_calc.xls */

static unsigned long freq_table_2000[] = {
						MHz(2000), MHz(1882), MHz(1778), MHz(1684),
						MHz(1600), MHz(1524), MHz(1455), MHz(1391),
						MHz(1333), MHz(1280), MHz(1231), MHz(1185),
						MHz(1143), MHz(1103), MHz(1067), MHz(1032),
						MHz(1000), MHz(941),  MHz(889),  MHz(842),
						MHz(800),  MHz(762),  MHz(727),  MHz(696),
						MHz(667),  MHz(640),  MHz(615),  MHz(593),
						MHz(571),  MHz(552),  MHz(533),  MHz(516),
						MHz(500),  MHz(471),  MHz(444),  MHz(421),
						MHz(400),  MHz(381),  MHz(364),  MHz(348),
						MHz(333),  MHz(320),  MHz(308),  MHz(296),
						MHz(286),  MHz(276),  MHz(267),  MHz(258),
					};

static unsigned long freq_table_1600[] = {
						MHz(1600), MHz(1506), MHz(1422), MHz(1347),
						MHz(1280), MHz(1219), MHz(1164), MHz(1113),
						MHz(1067), MHz(1024), MHz(985),  MHz(948),
						MHz(914),  MHz(883),  MHz(853),  MHz(826),
						MHz(800),  MHz(753),  MHz(711),  MHz(674),
						MHz(640),  MHz(610),  MHz(582),  MHz(557),
						MHz(533),  MHz(512),  MHz(492),  MHz(474),
						MHz(457),  MHz(441),  MHz(427),  MHz(413),
						MHz(400),  MHz(376),  MHz(356),  MHz(337),
						MHz(320),  MHz(305),  MHz(291),  MHz(278),
						MHz(267),  MHz(256),  MHz(246),  MHz(237),
						MHz(229),  MHz(221),  MHz(213),  MHz(206),
					};

static unsigned long freq_table_1333[] = {
						MHz(1333), MHz(1255), MHz(1185), MHz(1123),
						MHz(1066), MHz(1016), MHz(969),  MHz(927),
						MHz(889),  MHz(853),  MHz(820),  MHz(790),
						MHz(762),  MHz(735),  MHz(711),  MHz(688),
						MHz(667),  MHz(627),  MHz(592),  MHz(561),
						MHz(533),  MHz(508),  MHz(485),  MHz(464),
						MHz(444),  MHz(427),  MHz(410),  MHz(395),
						MHz(381),  MHz(368),  MHz(355),  MHz(344),
						MHz(333),  MHz(314),  MHz(296),  MHz(281),
						MHz(267),  MHz(254),  MHz(242),  MHz(232),
						MHz(222),  MHz(213),  MHz(205),  MHz(197),
						MHz(190),  MHz(184),  MHz(178),  MHz(172),
					};

static unsigned long freq_table_1000[] = {
						MHz(1000), MHz(941), MHz(889), MHz(842),
						MHz(800),  MHz(762), MHz(727), MHz(696),
						MHz(667),  MHz(640), MHz(615), MHz(593),
						MHz(571),  MHz(552), MHz(533), MHz(516),
						MHz(500),  MHz(471), MHz(444), MHz(421),
						MHz(400),  MHz(381), MHz(364), MHz(348),
						MHz(333),  MHz(320), MHz(308), MHz(296),
						MHz(286),  MHz(276), MHz(267), MHz(258),
						MHz(250),  MHz(235), MHz(222), MHz(211),
						MHz(200),  MHz(190), MHz(182), MHz(174),
						MHz(167),  MHz(160), MHz(154), MHz(148),
						MHz(143),  MHz(138), MHz(133), MHz(129),
					};

#ifdef DEBUG
static inline void e2c3_print_freq_table(const unsigned long *freq_table,
				const unsigned int divF_limit_lo,
				const unsigned int divF_limit_hi)
{
	unsigned int index = 0;
	for (index = divF_limit_lo; index <= divF_limit_hi; ++index)
		pr_info("{ %lu }\n", freq_table[index]);
}
#endif

static inline unsigned long *e2c3_get_freq_table(const int f_pll)
{
	switch (f_pll) {
	case F_PLL_VALUE(2000):
		return freq_table_2000;
	case F_PLL_VALUE(1600):
		return freq_table_1600;
	case F_PLL_VALUE(1333):
		return freq_table_1333;
	case F_PLL_VALUE(1000):
		return freq_table_1000;
	default:
		return NULL;
	}
}

static inline void e2c3_get_divF_limits(const char *reg, unsigned int *divF_limit_lo,
									unsigned int *divF_limit_hi)
{
	const unsigned int val = readl(reg + PMC_FREQ_CORE_MON_REGISTER);
	*divF_limit_lo = (val & LIMIT_LO_MASK) >> DIV_F_LIMIT_LO_REGISTER_SHIFT;
	*divF_limit_hi = (val & LIMIT_HI_MASK) >> DIV_F_LIMIT_HI_REGISTER_SHIFT;
}

static int e2c3_devfreq_provider_probe(struct platform_device *pdev)
{
	long err = 0;
	const int f_pll = e2c3_get_f_pll(0);
	struct resource *res = NULL;
	char *reg = NULL;
	unsigned int divF_limit_lo = 0;
	unsigned int divF_limit_hi = 0;
	struct e2c3_devfreq_provider *provider = NULL;

	unsigned long *freq_table = e2c3_get_freq_table(f_pll);
	if (unlikely(!freq_table)) {
		print_debug_err("Wrong f_pll value=%d\n", &pdev->dev, f_pll);
		return -EINVAL;
	}

#ifdef DEBUG
	print_debug_info("f_pll=%d\n", &pdev->dev, f_pll);
#endif

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (unlikely(IS_ERR_OR_NULL(res))) {
		print_debug_err("Couldn`t get resource, res error=%ld\n", &pdev->dev, PTR_ERR(res));
		return PTR_ERR(res);
	}

#ifdef DEBUG
	print_debug_info("res->start=0x%llx, res->size=%lld\n",
			&pdev->dev, res->start, resource_size(res));
#endif

	reg = devm_ioremap(&pdev->dev, res->start, resource_size(res));
	if (unlikely(IS_ERR_OR_NULL(reg))) {
		print_debug_err("Couldn`t remap resource, reg error=%ld\n",
			&pdev->dev, PTR_ERR(reg));
		return PTR_ERR(reg);
	}

	e2c3_get_divF_limits(reg, &divF_limit_lo, &divF_limit_hi);
	if (unlikely((divF_limit_lo > MAX_DIVF_VALUE) ||
		(divF_limit_hi > MAX_DIVF_VALUE) || (divF_limit_lo > divF_limit_hi))) {
		print_debug_err("Wrong divF limits, divF_limit_lo=0x%x, divF_limit_hi=0x%x\n",
						&pdev->dev, divF_limit_lo, divF_limit_hi);
		return -EINVAL;
	}

#ifdef DEBUG
	print_debug_info("divF_limit_lo=0x%x, divF_limit_hi=0x%x\n",
			&pdev->dev, divF_limit_lo, divF_limit_hi);

	pr_info("size of freq table=%u\n", divF_limit_hi - divF_limit_lo + 1);

	pr_info("freq_table:\n");
	e2c3_print_freq_table(freq_table, divF_limit_lo, divF_limit_hi);

#endif

	provider = devm_kzalloc(&pdev->dev, sizeof(*provider), GFP_KERNEL);
	if (unlikely(!provider)) {
		print_debug_err("Couldn`t allocate memory\n", &pdev->dev);
		return -ENOMEM;
	}

	provider->reg = reg;
	provider->freq_table = freq_table;
	provider->dev = &pdev->dev;
	provider->divF_limit_lo = divF_limit_lo;
	provider->divF_limit_hi = divF_limit_hi;

#ifdef DEBUG
	print_debug_info("min_freq=%lu, max_freq=%lu\n",
			&pdev->dev, freq_table[divF_limit_hi], freq_table[divF_limit_lo]);
#endif

	err = e2c3_init_dvfs(provider);
	if (unlikely(err)) {
		print_debug_err("Couldn`t init DVFS, err=%ld\n", &pdev->dev, err);
		return err;
	}

	dev_set_drvdata(&pdev->dev, provider);
	dev_info(&pdev->dev, "Device probed\n");
	return err;
}

static int e2c3_devfreq_provider_remove(struct platform_device *pdev)
{
	const struct e2c3_devfreq_provider *provider = dev_get_drvdata(&pdev->dev);

	e2c3_deinit_dvfs(provider);

	dev_info(&pdev->dev, "Device removed\n");
	return 0;
}

static const struct of_device_id e2c3_devfreq_provider_driver_of[] = {
	{ .compatible = "mcst,devfreq_pmc_dev" },
	{},
};
MODULE_DEVICE_TABLE(of, e2c3_devfreq_provider_driver_of);

static struct platform_driver e2c3_devfreq_provider_driver = {
	.driver = {
		.name = "e2c3_devfreq_provider",
		.of_match_table = of_match_ptr(e2c3_devfreq_provider_driver_of),
	},
	.probe = e2c3_devfreq_provider_probe,
	.remove = e2c3_devfreq_provider_remove,
};

module_platform_driver(e2c3_devfreq_provider_driver);

MODULE_AUTHOR("Semyon Baklitskiy, Semen.D.Baklitskiy@mcst.ru");
MODULE_LICENSE("GPL");
