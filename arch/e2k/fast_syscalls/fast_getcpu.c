/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/seqlock.h>

#include <asm/fast_syscalls.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>

notrace __interrupt __section(".entry.text")
int fast_sys_getcpu(unsigned __user *cpup, unsigned __user *nodep,
		    struct getcpu_cache __user *unused)
{
	struct thread_info *const ti = (struct thread_info *) read_CURRENT_reg_value();
	int cpu = task_cpu(thread_info_task(ti));
	int ret = 0;

	cpup = (typeof(cpup)) ((unsigned long) cpup & E2K_VA_MASK);
	nodep = (typeof(nodep)) ((unsigned long) nodep & E2K_VA_MASK);
	if (unlikely((unsigned long) cpup + sizeof(unsigned) > user_addr_max() ||
		     (unsigned long) nodep + sizeof(unsigned) > user_addr_max()))
		return -EFAULT;

	if (nodep) {
		int node = cpu_to_node(cpu);

		ret = __put_user_switched_pt(node, nodep);
	}
	if (cpup)
		ret = unlikely(ret) ? ret : __put_user_switched_pt(cpu, cpup);

	return ret;
}

