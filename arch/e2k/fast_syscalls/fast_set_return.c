/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/fast_syscalls.h>
#include <asm/process.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>

notrace __section(".entry.text")
int fast_sys_set_return(u64 ip, int flags)
{
	return native_do_fast_sys_set_return(ip, flags);
}