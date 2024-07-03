#include <linux/platform_device.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/cpu.h>

#define MAX_NODE 4

static struct platform_device *e2c3_sensors_pdev[MAX_NODE];

struct pcsm_data {
	struct platform_device *pdev;
	struct device *hdev;
	int node;
};

static int e2c3_sensors_pcsm_init(void)
{
	if (!(IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C))
		return -ENODEV;

	int error = 0;
	int node;
	struct device *dev = cpu_subsys.dev_root;

	for_each_online_node(node) {
		e2c3_sensors_pdev[node] = platform_device_register_data(dev,
										"pcsm_drv", node,
										NULL, 0);

		if (IS_ERR(e2c3_sensors_pdev[node])) {
			int success_node;
			dev_err(dev, "failed to create PCSM platform device");

			for (success_node = 0; success_node < node; ++success_node)
				platform_device_unregister(e2c3_sensors_pdev[success_node]);

			return PTR_ERR(e2c3_sensors_pdev[node]);
		}

		set_dev_node(&e2c3_sensors_pdev[node]->dev, node);
	}

	return error;
} /* e2c3_sensors_pcsm_init */

static void e2c3_sensors_pcsm_exit(void)
{
	if (!(IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C))
		return;

	int node;

	for_each_online_node(node)
		platform_device_unregister(e2c3_sensors_pdev[node]);

} /* e2c3_sensors_pcsm_exit */

module_init(e2c3_sensors_pcsm_init);
module_exit(e2c3_sensors_pcsm_exit);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("Module for Power Control System");
MODULE_LICENSE("GPL v2");
