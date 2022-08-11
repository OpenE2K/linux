/*
 * CPU idle for r2000 machines.
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 *
 * Maintainer: Andrey Kuyan <andrey.s.kuyan@mcst.ru>
 */


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/cpuidle.h>
#include <linux/io.h>
#include <linux/export.h>
#include <linux/sched.h>

#include <asm/thread_info.h>
#include <asm/processor.h>
#include <asm/io.h>
#include <asm/e90s.h>

#define R2000P_MAX_STATES	4

/* ASI Regs: */
#define E90S_R2000_PWRCTRL_REG_ADDR	0x38


static struct platform_device *pdev;

static int e90s_enter_idle(struct cpuidle_device *dev,
				struct cpuidle_driver *drv, int index)
{
	int state;

	local_irq_enable();
	switch (index) {
	case 0: return index;
	case 1:
		state = 1;
		break;
	case 2:
		state = 3;
		break;
	case 3:
		state = 6;	/* Note: for R2000 index < 3 */
		break;
	default:
		return -1;
	}
	writeq_asi(state, E90S_R2000_PWRCTRL_REG_ADDR, ASI_LSU_CONTROL);
	return index;
}

static struct cpuidle_driver e90s_idle_driver = {
	.name			= "e90s_idle",
	.owner			= THIS_MODULE,
	.states[0]		= {
		.enter                  = e90s_enter_idle,
		.exit_latency           = 1,
		.target_residency       = 1,
		.name                   = "C0",
		.desc                   = "Idle busy loop",
	},
	.states[1]		= {
		.enter			= e90s_enter_idle,
		.exit_latency		= 10000,
		.target_residency	= 10,
		.name			= "C1",
		.desc			= "Stop decoding only",
	},
	.states[2]		= {
		.enter			= e90s_enter_idle,
		.exit_latency		= 40,
		.target_residency	= 20,
		.name			= "C3",
		.desc			= "Stop decoding and L1",
	},
	.states[3]		= {
		.enter			= e90s_enter_idle,
		.exit_latency		= 2000,
		.target_residency	= 1000,
		.name			= "C6",
		.desc			= "Reduces CPU voltage down to 0 V",
	},
	.state_count = R2000P_MAX_STATES, /* will be reset for R2000 */
};

/* Initialize CPU idle by registering the idle states */
static int e90s_cpuidle_probe(struct platform_device *pdev)
{
	int rev = get_cpu_revision();
	if (rev < 0x10)
		return -EINVAL;
	if (rev < 0x20) /* walk around bug 123699 */
		e90s_idle_driver.state_count = 2;
	return cpuidle_register(&e90s_idle_driver, NULL);
}

static int e90s_cpuidle_remove(struct platform_device *pdev)
{
	int rev = get_cpu_revision();
	if (rev < 0x10)
		return -EINVAL;
	cpuidle_unregister(&e90s_idle_driver);
	return 0;
}

static struct platform_driver e90s_cpuidle_driver = {
	.probe = e90s_cpuidle_probe,
	.remove = e90s_cpuidle_remove,
	.driver = {
		   .name = "e90s_cpuidle",
		   .owner = THIS_MODULE,
		   },
};

static int __init e90s_cpuidle_init(void)
{
	int rc;
	int rev = get_cpu_revision();
	if (rev < 0x10)
		return -ENODEV;
	pdev = platform_device_alloc("e90s_cpuidle", 0);
	if (!pdev)
		return -ENOMEM;


	rc = platform_device_add(pdev);
	if (rc) {
		rc = -ENODEV;
		goto undo_platform_dev_alloc;
	}
	rc = platform_driver_register(&e90s_cpuidle_driver);
	if (rc)
		goto undo_platform_dev_add;
	return 0;

undo_platform_dev_add:
	platform_device_del(pdev);
undo_platform_dev_alloc:
	platform_device_put(pdev);
	return rc;
}

static void __exit e90s_cpuidle_exit(void)
{
	platform_driver_unregister(&e90s_cpuidle_driver);
	if (pdev) {
		platform_device_del(pdev);
		platform_device_put(pdev);
	}
}

MODULE_AUTHOR("Andrey Kuyan <andrey.s.kuyan@mcst.ru>");
MODULE_DESCRIPTION("E90S cpu idle driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:e90s-cpuidle");

module_init(e90s_cpuidle_init);
module_exit(e90s_cpuidle_exit);
