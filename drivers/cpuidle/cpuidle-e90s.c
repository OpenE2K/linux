/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

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

#include <asm/tlb.h>
#include <asm/thread_info.h>
#include <asm/processor.h>
#include <asm/io.h>
#include <asm/e90s.h>

/* ASI Regs: */
#define E90S_R2000_PWRCTRL_REG_ADDR	0x38

static struct platform_device *e90s_idle_pdev;

static inline void e90s_flush_icache(void)
{
	__asm__ __volatile__("stxa	%%g0, [%%g0] %0"
			     : /* No outputs */
			     : "i" (ASI_IC_TAG));
}

static inline bool e90s_cstate_bug(void) /*Bug 139677*/
{
	return get_cpu_revision() == 0x20;
}

static void e90s_enter_c6(void)
{
	struct mm_struct *mm;
	save_and_clear_fpu();
	__e90s_enter_c6();
	mm = current->active_mm;
	tsb_context_switch_ctx(mm, CTX_HWBITS(mm->context));
	local_irq_enable();
}
static int e90s_enter_idle(struct cpuidle_device *dev,
				struct cpuidle_driver *drv, int index)
{
	int state;

	switch (index) {
	case 0: return index;
	case 1:
		state = 1;
		break;
	case 2:
		state = 3;
		if (e90s_cstate_bug()) {
			local_irq_enable();
			e90s_flush_icache();
			writeq_asi(state, E90S_R2000_PWRCTRL_REG_ADDR,
						ASI_DCU_CONTROL_REG);
			__asm__ __volatile__(
			"nop; nop; nop; nop; nop; nop; nop; nop;"
			"nop; nop; nop; nop; nop; nop; nop; nop;"
			"nop; nop; nop; nop;"
			     : : );
			return index;
		}
		break;
	case 3:
		state = 6;	/* Note: for R2000 index < 3 */
		e90s_enter_c6();
		return index;
	default:
		return -1;
	}
	local_irq_enable();
	writeq_asi(state, E90S_R2000_PWRCTRL_REG_ADDR, ASI_DCU_CONTROL_REG);

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
	.state_count = 2, /* will be adjusted later */
};

/* Initialize CPU idle by registering the idle states */
static int e90s_cpuidle_probe(struct platform_device *pdev)
{
	return cpuidle_register(&e90s_idle_driver, NULL);
}

static int e90s_cpuidle_remove(struct platform_device *pdev)
{
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
	/* see head_64.S */
	BUILD_BUG_ON(sizeof(system_state) != 4 || SYSTEM_BOOTING != 0);
	switch (e90s_get_cpu_type()) {
	case E90S_CPU_R1000:
		return 0;
	case E90S_CPU_R2000:
		if (get_cpu_revision() > 0x18) /* bug 123699 */
			e90s_idle_driver.state_count = 3;
		break;
	case E90S_CPU_R2000P:
		e90s_idle_driver.state_count = 4;
		break;
	}

	e90s_idle_pdev = platform_device_alloc("e90s_cpuidle", 0);
	if (!e90s_idle_pdev)
		return -ENOMEM;

	rc = platform_device_add(e90s_idle_pdev);
	if (rc) {
		rc = -ENODEV;
		goto undo_platform_dev_alloc;
	}
	rc = platform_driver_register(&e90s_cpuidle_driver);
	if (rc)
		goto undo_platform_dev_add;
	return 0;

undo_platform_dev_add:
	platform_device_del(e90s_idle_pdev);
undo_platform_dev_alloc:
	platform_device_put(e90s_idle_pdev);
	return rc;
}

static void __exit e90s_cpuidle_exit(void)
{
	platform_driver_unregister(&e90s_cpuidle_driver);
	if (e90s_idle_pdev) {
		platform_device_del(e90s_idle_pdev);
		platform_device_put(e90s_idle_pdev);
	}
}

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("E90S cpu idle driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:e90s-cpuidle");

module_init(e90s_cpuidle_init);
module_exit(e90s_cpuidle_exit);
