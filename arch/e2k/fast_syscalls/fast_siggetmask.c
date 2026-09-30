/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/fast_syscalls.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>

notrace __interrupt __section(".entry.text")
int fast_sys_siggetmask(u64 __user *oset, size_t sigsetsize)
{
	struct thread_info *const ti = read_CURRENT_reg_value();
	struct task_struct *task = thread_info_task(ti);
	u64 set;

	set = task->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

	oset = (typeof(oset)) ((unsigned long) oset & E2K_VA_MASK);
	if (unlikely((unsigned long) oset + sizeof(sigset_t) > user_addr_max()))
		return -EFAULT;

	return put_user_switched_pt(set, oset);
}
