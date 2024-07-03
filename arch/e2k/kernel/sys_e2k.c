/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains various random system calls that
 * have a non-standard calling sequence on the Linux/E2K
 * platform.
 */

#include <linux/sched.h>
#include <linux/sem.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <linux/utsname.h>
#include <linux/file.h>		/* doh, must come after sched.h... */
#include <linux/mm.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/compat.h>

#include <asm/mman.h>
#include <asm/rlimits.h>


#undef	DEBUG_SYS_CALLS_MODE
#undef	DebugSC
#define	DEBUG_SYS_CALLS_MODE	0	/* system calls */
#define DebugSC(...)		DebugPrint(DEBUG_SYS_CALLS_MODE ,##__VA_ARGS__)

/*
 * Old cruft
 */
SYSCALL_DEFINE1(uname, struct old_utsname __user *, name)
{
	int err;

	DebugSC("sys_uname entered.\n");

	if (!name)
		return -EFAULT;
	down_read(&uts_sem);
	err = copy_to_user(name, utsname(), sizeof (*name));
	up_read(&uts_sem);

	DebugSC("sys_uname exited.\n");

	return err?-EFAULT:0;
}


/*
 * Linux version of mmap()
 *
 *  offset "off" is measuring in bytes.
 */
SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
		unsigned long, prot, unsigned long, flags, unsigned long, fd,
		unsigned long, off)
{
	if (off & ~PAGE_MASK)
		return -EINVAL;

	return ksys_mmap_pgoff(addr, len, prot, flags, fd, off >> PAGE_SHIFT);
}


/*
 * mmap2() is like mmap() except that the offset is expressed in units
 * of PAGE_SIZE (instead of bytes).  This allows to mmap2() (pieces
 * of) files that are larger than the address space of the CPU.
 */
SYSCALL_DEFINE6(mmap2, unsigned long, addr, unsigned long, len,
		int, prot, int, flags, int, fd, long, pgoff)
{
	return ksys_mmap_pgoff(addr, len, prot, flags, fd, pgoff);
}

static inline unsigned int rlimit_translate_resource(unsigned int resource)
{
	switch (resource) {
	case RLIMIT_P_STACK:	return RLIMIT_P_STACK_EXT;
	case RLIMIT_PC_STACK:	return RLIMIT_PC_STACK_EXT;
	}
	return resource;
}

asmlinkage long e2k_sys_prlimit64(pid_t pid, unsigned int resource,
			const struct rlimit64 __user *new_rlim,
			struct rlimit64 __user *old_rlim)
{
	return sys_prlimit64(pid, rlimit_translate_resource(resource), new_rlim,
			     old_rlim);
}

asmlinkage long e2k_sys_getrlimit(unsigned int resource,
	struct rlimit __user *rlim)
{
	return sys_getrlimit(rlimit_translate_resource(resource), rlim);
}

#ifdef __ARCH_WANT_SYS_OLD_GETRLIMIT
asmlinkage long e2k_sys_old_getrlimit(unsigned int resource,
	struct rlimit __user *rlim)
{
	return sys_old_getrlimit(rlimit_translate_resource(resource), rlim);
}
#endif

asmlinkage long e2k_sys_setrlimit(unsigned int resource,
	struct rlimit __user *rlim)
{
	return sys_setrlimit(rlimit_translate_resource(resource), rlim);
}

#ifdef	CONFIG_COMPAT
asmlinkage long compat_e2k_sys_getrlimit(unsigned int resource,
	struct compat_rlimit __user *rlim)
{
	return compat_sys_getrlimit(rlimit_translate_resource(resource), rlim);
}

asmlinkage long compat_e2k_sys_setrlimit(unsigned int resource,
	struct compat_rlimit __user *rlim)
{
	return compat_sys_setrlimit(rlimit_translate_resource(resource), rlim);
}
#endif

