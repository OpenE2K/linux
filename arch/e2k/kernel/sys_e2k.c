
/* linux/arch/e2k/kernel/sys_e2k.c, v 1.1 07/27/2001.
 * 
 * Copyright (C) 2001 MCST 
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


#undef	DEBUG_SYS_CALLS_MODE
#undef	DebugSC
#define	DEBUG_SYS_CALLS_MODE	0	/* system calls */
#define DebugSC(...)		DebugPrint(DEBUG_SYS_CALLS_MODE ,##__VA_ARGS__)

/*
 * Old cruft
 */
asmlinkage long sys_uname(struct old_utsname * name)
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
asmlinkage unsigned long sys_mmap(unsigned long addr, unsigned long len,
	unsigned long prot, unsigned long flags, unsigned long fd,
	unsigned long off)
{
	unsigned long ret;
	
	if (off & ~PAGE_MASK)
		return -EINVAL;

	if (!TASK_IS_BINCO(current) &&
	    (current->thread.flags & E2K_FLAG_32BIT)) {
		if (len > TASK32_SIZE ||
		    ((flags & MAP_FIXED) && (addr + len) > TASK32_SIZE)) {
			return -EINVAL;
		}
	}

	ret = sys_mmap_pgoff(addr, len, prot, flags, fd, off >> PAGE_SHIFT);

	if (!TASK_IS_BINCO(current) &&
			(current->thread.flags & E2K_FLAG_32BIT)
			&& !(current->thread.flags & E2K_FLAG_PROTECTED_MODE)) {
		if (!(ret & ~PAGE_MASK) && (ret + len) > TASK32_SIZE) {
			do_munmap(current->mm, ret, len);
			ret = -ENOMEM;
		}
        }

	return ret;
}


/*
 * mmap2() is like mmap() except that the offset is expressed in units
 * of PAGE_SIZE (instead of bytes).  This allows to mmap2() (pieces
 * of) files that are larger than the address space of the CPU.
 */
asmlinkage unsigned long sys_mmap2(unsigned long addr, unsigned long len,
		int prot, int flags, int fd, long pgoff)
{
	return sys_mmap_pgoff(addr, len, prot, flags, fd, pgoff);
}


static inline unsigned int rlimit_translate_resource(unsigned int resource)
{
	switch (resource) {
	case RLIM_P_STACK:	return RLIM_P_STACK_EXT;
	case RLIM_PC_STACK:	return RLIM_PC_STACK_EXT;
	}
	return resource;
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

