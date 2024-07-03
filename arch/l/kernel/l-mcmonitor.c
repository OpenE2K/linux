/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include <asm/l-mcmonitor.h>


static struct delayed_work l_mcmonitor;
static unsigned int l_mcmonitor_period;


#ifdef L_MCMONITOR_TEST_SIZE
static bool l_mcmonitor_test;

static int __init l_mcmonitor_test_setup(char *str)
{
	l_mcmonitor_test = true;
	return 1;
}
__setup("mcmonitor_test", l_mcmonitor_test_setup);

static int l_mcmonitor_flush_cache(void)
{
	unsigned long a = __get_free_pages(GFP_KERNEL, MAX_ORDER - 1);

	if (!a)
		return -ENOMEM;

	memset((void *)a, 0, 1UL << (MAX_ORDER - 1 + PAGE_SHIFT));
	free_pages(a, MAX_ORDER - 1);

	return 0;
}

static int l_mcmonitor_ecc_test(void)
{
	int ret = 0;
	unsigned long flags;

	u64 *a = kzalloc_node(L_MCMONITOR_TEST_SIZE, GFP_KERNEL, 0);
	if (!a)
		return -ENOMEM;

	if ((ret = l_mcmonitor_flush_cache()))
		return ret;

	raw_local_irq_save(flags);
	l_mcmonitor_fill_data(a, true);
	raw_local_irq_restore(flags);

	ret = l_mcmonitor_cmp(a);
	if (ret)
		print_hex_dump(KERN_INFO, "b:", DUMP_PREFIX_OFFSET, 32, 8,
				a, L_MCMONITOR_TEST_SIZE, 0);

	/* restore ecc */
	raw_local_irq_save(flags);
	l_mcmonitor_fill_data(a, false);
	raw_local_irq_restore(flags);

	kfree(a);

	return ret;
}
#endif

static int __init l_mcmonitor_period_setup(char *str)
{
	l_mcmonitor_period = simple_strtoul(str, NULL, 0);
	return 1;
}
__setup("mcmonitor_period=", l_mcmonitor_period_setup);

static void do_l_mcmonitor(struct work_struct *work)
{
	static u16 last_MC_ECC[MAX_NUMNODES][SIC_MAX_MC_COUNT] = {};
	int node, i;

#ifdef L_MCMONITOR_TEST_SIZE
	if (l_mcmonitor_test) {
		if (num_online_cpus() != 1) {
			pr_err("l-mcmonitor: can't run test\n");
		} else {
			int ret = l_mcmonitor_ecc_test();

			pr_info("l-mcmonitor: test %s: %d\n",
				 ret ? "failed" : "passed", ret);
		}

		l_mcmonitor_test = 0;
	}
#endif

	for_each_online_node(node) {
		for (i = 0; i < SIC_MC_COUNT; i++) {
			char s[256];
			l_mc_ecc_struct_t ecc;
			u32 cnt = l_mc_get_error_cnt(&ecc, node, i);

			if ((cnt - last_MC_ECC[node][i]) == 0)
				continue;

			last_MC_ECC[node][i] = cnt;

			pr_warn("MC error DETECTED on  node%d: %s\n",
				   node, l_mc_get_error_str(&ecc, i, s,
							    sizeof(s)));
		}
	}

	if (l_mcmonitor_period)
		queue_delayed_work(system_power_efficient_wq, &l_mcmonitor,
				   l_mcmonitor_period * HZ);
}

#ifdef CONFIG_SYSCTL
static int proc_do_l_mcmonitor_period(struct ctl_table *table, int write,
			void __user *buffer, size_t *lenp, loff_t *ppos)
{
	unsigned long old_period = l_mcmonitor_period;
	int res;

	res = proc_douintvec(table, write, buffer, lenp, ppos);

	if (write && !res && !old_period && l_mcmonitor_period)
		queue_delayed_work(system_power_efficient_wq, &l_mcmonitor, 0);

	return res;
}

/* Place file period in /proc/sys/dev/mc */
static ctl_table period_table[] = {
	{
		.procname	= "period",
		.data		= &l_mcmonitor_period,
		.maxlen		= sizeof(l_mcmonitor_period),
		.mode		= 0644,
		.proc_handler	= proc_do_l_mcmonitor_period,
	},
	{}
};

static ctl_table mc_table[] = {
	{
		.procname	= "mc",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= period_table,
	},
	{}
};

/* Make sure that /proc/sys/dev is there */
static ctl_table root_table[] = {
	{
		.procname	= "dev",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= mc_table,
	},
	{}
};
#endif

static int __init l_mcmonitor_init(void)
{
	if (!l_mcmonitor_supported()) { /* XXX: see bug 116361. */
		pr_notice("l-mcmonitor: not supported\n");
		return 0;
	}

	if (!l_mcmonitor_eec_enabled())
		pr_notice("l-mcmonitor: ecc not enabled\n");

	INIT_DEFERRABLE_WORK(&l_mcmonitor, do_l_mcmonitor);

#ifdef CONFIG_SYSCTL
	register_sysctl_table(root_table);
#endif

	if (l_mcmonitor_period)
		queue_delayed_work(system_power_efficient_wq, &l_mcmonitor, 0);

	return 0;
}
arch_initcall(l_mcmonitor_init);
