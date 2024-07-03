#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/kernel.h>
#include <linux/cpu.h>
#include <linux/of.h>

#define DRIVER_VERSION		"1.4"
#define	MAX_NODE	4

struct platform_device *e8c_sensors_pdev[MAX_NODE];

static int e8c_sensors_pcs_init(void)
{
	int node;
	char str[64];
	struct device *dev = cpu_subsys.dev_root;
	struct device_node *np;

	sprintf(str, "/pcs@%d", 0);
		np = of_find_node_by_path(str);

	if ((np != NULL) && (of_device_is_compatible(np, "mcst,pcs")))
		return 0;

	if (machine.native_id != MACHINE_ID_E8C &&
			machine.native_id != MACHINE_ID_E8C2)
		return -ENODEV;

	for_each_online_node(node) {
		e8c_sensors_pdev[node] = platform_device_register_data(dev, "pcs", node, NULL, 0);

		if (IS_ERR(e8c_sensors_pdev[node])) {
			int success_node;
			dev_err(dev, "failed to create PCS platform device");

			for (success_node = 0; success_node < node; ++success_node)
				platform_device_unregister(e8c_sensors_pdev[success_node]);

			return PTR_ERR(e8c_sensors_pdev[node]);
		}

		set_dev_node(&e8c_sensors_pdev[node]->dev, node);
	}

	return 0;
} /* e8c_sensors_pcs_init */

static void e8c_sensors_pcs_exit(void)
{
	int node;

	for_each_online_node(node)
		platform_device_unregister(e8c_sensors_pdev[node]);

} /* e8c_sensors_pcs_exit */

module_init(e8c_sensors_pcs_init);
module_exit(e8c_sensors_pcs_exit);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("e8c/e8c2 pcs driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRIVER_VERSION);
