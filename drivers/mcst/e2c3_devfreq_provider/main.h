#ifndef MAIN_H
#define MAIN_H

#include <linux/devfreq.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>

#define MAX_DIVF_VALUE 0x2f
#define MHz(arg) (arg * 1000000)
#define VOLTAGE 800000

#define OFFSET(val) val /* In bytes */

/* Describrion of registers and shifts taken from pcs_config.pdf file
http://www.lab.sun.mcst.ru/honey/elbrus_2c3/doc/hw/pcs/pcs_config.pdf */

#define LIMIT_HI_MASK    (63 << 12) /* 0x3F << 12 */
#define LIMIT_LO_MASK    (63 << 18) /* 0x3F << 18 */
#define DIV_F_CURR_MASK  (63 << 24) /* 0x3F << 24 */
#define PROGR_DIV_F_MASK (63 << 4)  /* 0x3f << 4 */
#define MODE_MASK        (7 << 1)   /* 0x7 << 1 */

#define DIV_F_LIMIT_LO_REGISTER_SHIFT 18
#define DIV_F_LIMIT_HI_REGISTER_SHIFT 12
#define DIV_F_CURR_REGISTER_SHIFT     24

#define PMC_FREQ_CORE_MON_REGISTER    OFFSET(0)
#define PMC_FREQ_CORE_CTRL_REGISTER   OFFSET(4)

#define F_PLL_VALUE(val) val

#define ENABLE_CHANGING_BFS_REGISTER_SHIFT 0
#define ENABLE 1
#define MODE_REGISTER_SHIFT 1
#define SOFT_CHANGE_FREQ_MODE 3
#define INIT_FREQ_MODE 0
#define PROGR_DIV_F_REGISTER_SHIFT 4
#define RMWEN_REGISTER_SHIFT 31

#define E2C3_GET_CURRENT_FREQ_ERR (unsigned long)(-EINVAL)
#define POLLING_INTERVAL 100

#define print_debug_info(str, dev, ...)  pr_info("%s: %s %s %d: " str, dev_name(dev), __FILE__, \
				__PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__)

#define print_debug_err(str, dev, ...) pr_err("%s: %s %s %d: " str, dev_name(dev), __FILE__, \
				__PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__)

struct e2c3_devfreq_provider {
	struct device *dev;
	struct devfreq *devfreq_device;
	char *reg;
	unsigned long *freq_table;
	unsigned int divF_limit_lo;
	unsigned int divF_limit_hi;
};

int e2c3_get_f_pll(const int);
long e2c3_init_dvfs(struct e2c3_devfreq_provider *);
void e2c3_deinit_dvfs(const struct e2c3_devfreq_provider *);

#endif /* MAIN_H */
