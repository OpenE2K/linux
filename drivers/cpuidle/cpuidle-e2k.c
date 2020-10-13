/*
 * CPU idle for E2K machines ES2, E2S, E8C.
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 *
 * Maintainer: Evgeny Kravtsunov <kravtsunov_e@mcst.ru>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/cpuidle.h>
#include <linux/io.h>
#include <linux/export.h>

#include <asm/cpuidle_legacy.h>

#define E2K_MAX_STATES	2

static struct platform_device *pdev;

static int e2k_enter_idle(struct cpuidle_device *dev,
			struct cpuidle_driver *drv,
			int index)
{
	thread_info_t *thread_info = current_thread_info();

	thread_info->wtrap_jump_addr = PG_JMP;

	if (index == 0) {
		while (!need_resched()) {
			default_idle();
		}
	} else if (index == 1) {
		if (!IS_MACHINE_ES2 &&
		    !IS_MACHINE_E2S &&
		    !IS_MACHINE_E8C) {
			while (!need_resched()) {
				default_idle();
			}
		} else {
			SET_WTRAP_JUMP_ADDR("jump_over_wtrap", "1f");
			local_irq_enable();
			wtrap();
			JUMP_OVER_WTRAP_LABEL("jump_over_wtrap", "1:");
		}
	}
	return index;
}

static struct cpuidle_driver e2k_idle_driver = {
	.name			= "e2k_idle",
	.owner			= THIS_MODULE,
	.states[0]		= {
		.enter                  = e2k_enter_idle,
		.exit_latency           = 1,
		.target_residency       = 10000,
		.flags                  = CPUIDLE_FLAG_TIME_VALID,
		.name                   = "C0",
		.desc                   = "Idle busy loop",
	},
	.states[1]		= {
		.enter			= e2k_enter_idle,
		.exit_latency		= 10,
		.target_residency	= 10000,
		.flags			= CPUIDLE_FLAG_TIME_VALID,
		.name			= "C1",
		.desc			= "CPU clock gating",
		
	},
	.state_count = E2K_MAX_STATES,
};

/* Initialize CPU idle by registering the idle states */
static int e2k_cpuidle_probe(struct platform_device *pdev)
{
	return cpuidle_register(&e2k_idle_driver, NULL);
}

static int e2k_cpuidle_remove(struct platform_device *pdev)
{
	cpuidle_unregister(&e2k_idle_driver);
	return 0;
}

static struct platform_driver e2k_cpuidle_driver = {
	.probe = e2k_cpuidle_probe,
	.remove = e2k_cpuidle_remove,
	.driver = {
		   .name = "e2k_cpuidle",
		   .owner = THIS_MODULE,
		   },
};

static int __init e2k_cpuidle_init(void)
{
	int rc;

	pdev = platform_device_alloc("e2k_cpuidle", 0);
	if (!pdev)
		return -ENOMEM;

	rc = platform_device_add(pdev);
	if (rc) {
		rc = -ENODEV;
		goto undo_platform_dev_alloc;
	}

	rc = platform_driver_register(&e2k_cpuidle_driver);
	if (rc) {
		goto undo_platform_dev_add;
	}
	return 0;

undo_platform_dev_add:
	platform_device_del(pdev);
undo_platform_dev_alloc:
	platform_device_put(pdev);
	return rc;
}

static void __exit e2k_cpuidle_exit(void)
{
	platform_driver_unregister(&e2k_cpuidle_driver);
	if (pdev) {
		platform_device_del(pdev);
		platform_device_put(pdev);
	}
} 

MODULE_AUTHOR("Evgeny Kravtsunov <kravtsunov_e@mcst.ru>");
MODULE_DESCRIPTION("E2K cpu idle driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:e2k-cpuidle");

module_init(e2k_cpuidle_init);
module_exit(e2k_cpuidle_exit);

