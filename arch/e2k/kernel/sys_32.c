/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/sysctl.h>
#include <linux/unistd.h>
#include <linux/uaccess.h>

#include <asm/siginfo.h>
#include <asm/process.h>
#include <asm/mmu_context.h>
#include <asm/ptrace.h>


/* warning: next two assume little endian */
asmlinkage long sys32_pread64(unsigned int fd, char __user *ubuf,
		compat_size_t count, unsigned long poslo, unsigned long poshi)
{
	return sys_pread64(fd, ubuf, count, (poshi << 32) | poslo);
}

asmlinkage long sys32_pwrite64(unsigned int fd, char __user *ubuf,
		compat_size_t count, unsigned long poslo, unsigned long poshi)
{
	return sys_pwrite64(fd, ubuf, count, (poshi << 32) | poslo);
}

asmlinkage long sys32_readahead(int fd, unsigned long offlo,
		unsigned long offhi, compat_size_t count)
{
	return sys_readahead(fd, (offhi << 32) | offlo, count);
}

asmlinkage long sys32_fadvise64(int fd, unsigned long offlo,
		unsigned long offhi, compat_size_t len, int advice)
{
	return sys_fadvise64_64(fd, (offhi << 32) | offlo, len, advice);
}

asmlinkage long sys32_fadvise64_64(int fd,
		unsigned long offlo, unsigned long offhi,
		unsigned long lenlo, unsigned long lenhi, int advice)
{
	return sys_fadvise64_64(fd, (offhi << 32) | offlo,
			(lenhi << 32) | lenlo, advice);
}

asmlinkage long sys32_sync_file_range(int fd,
		unsigned long off_low, unsigned long off_high,
		unsigned long nb_low, unsigned long nb_high, int flags)
{
	return sys_sync_file_range(fd, (off_high << 32) | off_low,
			(nb_high << 32) | nb_low, flags);
}

asmlinkage long sys32_fallocate(int fd, int mode,
		unsigned long offlo, unsigned long offhi,
		unsigned long lenlo, unsigned long lenhi)
{
	return sys_fallocate(fd, mode, (offhi << 32) | offlo,
			     (lenhi << 32) | lenlo);
}

asmlinkage long sys32_truncate64(const char __user * path,
		unsigned long low, unsigned long high)
{
	return sys_truncate(path, (high << 32) | low);
}

asmlinkage long sys32_ftruncate64(unsigned int fd,
		unsigned long low, unsigned long high)
{
	return sys_ftruncate(fd, (high << 32) | low);
}

long compat_arch_ptrace(struct task_struct *child, compat_long_t request,
	compat_ulong_t caddr, compat_ulong_t cdata)
{
	return common_ptrace(child, (long)request, (long)caddr, (long)cdata, true);
}


