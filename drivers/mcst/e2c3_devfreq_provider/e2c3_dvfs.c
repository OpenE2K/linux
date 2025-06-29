#include "main.h"

static inline const unsigned int e2c3_get_divF(const struct e2c3_devfreq_provider *provider,
								const unsigned long freq)
{
	unsigned int divF;
	for (divF = provider->divF_limit_lo;
		divF <= provider->divF_limit_hi; ++divF) {
		if (freq == provider->freq_table[divF])
			return divF;
	}

	return MAX_DIVF_VALUE + 1;
}

static inline int e2c3_set_freq(const struct e2c3_devfreq_provider *provider,
								const unsigned long freq)

{
	char *reg = provider->reg + PMC_FREQ_CORE_CTRL_REGISTER;
	const unsigned int divF = e2c3_get_divF(provider, freq);
	const unsigned int val = (ENABLE << ENABLE_CHANGING_BFS_REGISTER_SHIFT) |
					(SOFT_CHANGE_FREQ_MODE << MODE_REGISTER_SHIFT)  |
					(divF << PROGR_DIV_F_REGISTER_SHIFT)            |
					(ENABLE << RMWEN_REGISTER_SHIFT);

#ifdef DEBUG
	unsigned int val_afret_writel = 0;
	unsigned int progr_divF = 0;
#endif

	if (unlikely(divF == (MAX_DIVF_VALUE + 1))) {
		print_debug_err("Given wrong freq=%lu\n", provider->dev, freq);
		return -EINVAL;
	}

#ifdef DEBUG
	print_debug_info("freq=%lu, divF=0x%x, val=%u\n", provider->dev, freq, divF, val);
#endif

	writel(val, reg);

#ifdef DEBUG
	val_afret_writel = readl(reg);
	progr_divF = (val_afret_writel & PROGR_DIV_F_MASK) >> PROGR_DIV_F_REGISTER_SHIFT;
	print_debug_info("After writel val_after_writel=%u, progr_divF=0x%x\n",
					provider->dev, val_afret_writel, progr_divF);
	dev_info(provider->dev, "Set freq=%lu Hz", freq);
#endif
	return 0;
}

static inline long e2c3_freq_abs(const long val)
{
	if (val < 0)
		return -1 * val;

	return val;
}

static inline unsigned long e2c3_round_freq(const struct e2c3_devfreq_provider *provider,
							const unsigned long freq)

{
	unsigned int index;
	unsigned long closest = provider->freq_table[provider->divF_limit_lo];
	unsigned long closest_distance = e2c3_freq_abs((long)freq - (long)closest);
	unsigned long distance;

	for (index = provider->divF_limit_lo + 1;
		index <= provider->divF_limit_hi; ++index) {
		distance = e2c3_freq_abs((long)freq - (long)provider->freq_table[index]);

		if (closest_distance < distance) {
			return closest;

		} else if (distance < closest_distance) {
			closest = provider->freq_table[index];
			closest_distance = distance;
		}
	}

	return closest;
}

static inline unsigned long e2c3_get_current_freq(const struct e2c3_devfreq_provider *provider)
{
	const char *reg = provider->reg + PMC_FREQ_CORE_CTRL_REGISTER;

	const unsigned int val = readl(reg);
	const unsigned int mode = (val & MODE_MASK) >> MODE_REGISTER_SHIFT;
	unsigned int divF;

	switch (mode) {
	case INIT_FREQ_MODE:
		divF = (val & DIV_F_CURR_MASK) >> DIV_F_CURR_REGISTER_SHIFT;
		break;

	case SOFT_CHANGE_FREQ_MODE:
		divF = (val & PROGR_DIV_F_MASK) >> PROGR_DIV_F_REGISTER_SHIFT;
		break;

	default:
		print_debug_err("Wrong mode=%u\n", provider->dev, mode);
		return -EINVAL;
	}

	if (unlikely(divF > provider->divF_limit_hi || divF < provider->divF_limit_lo)) {
		print_debug_err("Wrong divF=0x%x\n", provider->dev, divF);
		return -EINVAL;
	}

#ifdef DEBUG
	print_debug_info("mode=%u, divF=0x%x, freq_table[divF]=%lu\n",
					provider->dev, mode, divF, provider->freq_table[divF]);
#endif

	return provider->freq_table[divF];
}

static inline int e2c3_devfreq_target(struct device *dev, unsigned long *requested_freq,
									unsigned int flags)
{
	int err = 0;

	const struct e2c3_devfreq_provider *provider = dev_get_drvdata(dev);
	const unsigned long round_freq = e2c3_round_freq(provider, *requested_freq);
	const unsigned long current_freq = e2c3_get_current_freq(provider);

	if (unlikely(current_freq == E2C3_GET_CURRENT_FREQ_ERR)) {
		print_debug_err("Couldn`t set freq, err=%d", dev, err);
		return -EINVAL;
	}

	if (round_freq == current_freq) {
		*requested_freq = current_freq;
		return 0;
	}

#ifdef DEBUG
	print_debug_info("requested_freq_before=%lu\n", dev, *requested_freq);
#endif

	err = e2c3_set_freq(provider, round_freq);

	if (unlikely(err)) {
		print_debug_err("Couldn`t set freq, err=%d", dev, err);
		*requested_freq = current_freq;
		return err;
	}

	*requested_freq = round_freq;

#ifdef DEBUG
	print_debug_info("requested_freq_after=%lu\n", dev, *requested_freq);
#endif
	return err;
}

static inline int e2c3_devfreq_get_cur_freq(struct device *dev, unsigned long *freq)
{
	const struct e2c3_devfreq_provider *provider = dev_get_drvdata(dev);
	const unsigned long current_freq = e2c3_get_current_freq(provider);

	if (unlikely(current_freq == E2C3_GET_CURRENT_FREQ_ERR)) {
		print_debug_err("Couldn`t get current freq\n", dev);
		return -EINVAL;
	}

	*freq = current_freq;
	return 0;
}

static int e2c3_fill_opp_table(const struct e2c3_devfreq_provider *provider)
{
	int err = 0;
	unsigned int index;

	for (index = provider->divF_limit_lo; index <= provider->divF_limit_hi; ++index) {
		err = dev_pm_opp_add(provider->dev, provider->freq_table[index], VOLTAGE);
		if (unlikely(err)) {
			print_debug_err("Couldn`t add OPP\n, err=%d", provider->dev, err);
			return err;
		}
	}

	return err;
}

static void e2c3_clear_opp_table(const struct e2c3_devfreq_provider *provider)
{
	unsigned int index;

	for (index = provider->divF_limit_lo; index <= provider->divF_limit_hi; ++index)
		dev_pm_opp_remove(provider->dev, provider->freq_table[index]);

}

void e2c3_deinit_dvfs(const struct e2c3_devfreq_provider *provider)
{
	devm_devfreq_remove_device(provider->dev, provider->devfreq_device);
	e2c3_clear_opp_table(provider);

	dev_info(provider->dev, "DVFS deactivated!\n");
}

long e2c3_init_dvfs(struct e2c3_devfreq_provider *provider)
{
	int err = 0;
	struct devfreq_dev_profile *devfreq_dev_profile = NULL;
	struct devfreq *devfreq_device = NULL;
	struct device *dev = provider->dev;

	devfreq_dev_profile = devm_kzalloc(dev,
						sizeof(*devfreq_dev_profile),
						GFP_KERNEL);

	if (unlikely(!devfreq_dev_profile)) {
		print_debug_err("Couldn`t allocate memory\n", dev);
		return -ENOMEM;
	}

	err = e2c3_fill_opp_table(provider);
	if (unlikely(err)) {
		print_debug_err("Failed to fill OPP table with data, err=%d\n", dev, err);
		return err;
	}

	devfreq_dev_profile->freq_table = &(provider->freq_table[provider->divF_limit_lo]);
	devfreq_dev_profile->max_state = (provider->divF_limit_hi - provider->divF_limit_lo + 1);
	devfreq_dev_profile->initial_freq = e2c3_get_current_freq(provider);
	if (unlikely(devfreq_dev_profile->initial_freq == E2C3_GET_CURRENT_FREQ_ERR)) {
		print_debug_err("Couldn`t set initial freq\n", dev);
		return -EINVAL;
	}

	devfreq_dev_profile->polling_ms = POLLING_INTERVAL; /* t_step = 2.6 us */
	devfreq_dev_profile->target = e2c3_devfreq_target;
	devfreq_dev_profile->get_cur_freq = e2c3_devfreq_get_cur_freq;

	devfreq_device = devm_devfreq_add_device(dev, devfreq_dev_profile,
					"userspace", NULL);

	if (unlikely(IS_ERR_OR_NULL(devfreq_device))) {
		print_debug_err("Failed to add devfreq device, err=%ld\n",
						dev, PTR_ERR(devfreq_device));

		e2c3_clear_opp_table(provider);
		return PTR_ERR(devfreq_device);
	}

	devfreq_device->scaling_min_freq = provider->freq_table[provider->divF_limit_hi];
	devfreq_device->scaling_max_freq = provider->freq_table[provider->divF_limit_lo];

	dev_info(dev, "DVFS activated: %lu-%lu Hz, polling=%u ms\n",
			provider->freq_table[provider->divF_limit_hi],
			provider->freq_table[provider->divF_limit_lo],
			POLLING_INTERVAL);

	provider->devfreq_device = devfreq_device;
	return err;
}
