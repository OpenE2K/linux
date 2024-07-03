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
	struct thread_info *const ti = READ_CURRENT_REG();
	int cpu = task_cpu(thread_info_task(ti));
	int ret = 0;

	cpup = (typeof(cpup)) ((u64 __user) cpup & E2K_VA_MASK);
	nodep = (typeof(nodep)) ((u64 __user) nodep & E2K_VA_MASK);
	if (unlikely((u64) cpup + sizeof(unsigned) > ti->addr_limit.seg
			|| (u64) nodep + sizeof(unsigned) > ti->addr_limit.seg))
		return -EFAULT;

	if (nodep) {
		int node = cpu_to_node(cpu);

		ret = __put_user_switched_pt(node, nodep);
	}
	if (cpup)
		ret = unlikely(ret) ? ret : __put_user_switched_pt(cpu, cpup);

	return ret;
}

