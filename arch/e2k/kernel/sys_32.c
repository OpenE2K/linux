/* linux/arch/e2k/kernel/sys_32.c 1.10 08/21/2001.
 * 
 * Copyright (C) 2001 MCST 
 */

/**************************** DEBUG DEFINES *****************************/

#define	DEBUG_TRAP_CELLAR	0	/* DEBUG_TRAP_CELLAR */
#define DbgTC(...)		DebugPrint(DEBUG_TRAP_CELLAR ,##__VA_ARGS__)
#define	DEBUG_SIG_MODE		0	/* Signal handling */
#define DebugSig(...)		DebugPrint(DEBUG_SIG_MODE ,##__VA_ARGS__)
#define	DEBUG_32		0	/* processes */
#define DebugP_32(...)		DebugPrint(DEBUG_32 ,##__VA_ARGS__)

#undef	DEBUG_EXECVE_MODE
#undef	DebugEX
#define	DEBUG_EXECVE_MODE	0	/* execve and exit */
#define DebugEX(...)		DebugPrint(DEBUG_EXECVE_MODE ,##__VA_ARGS__)

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

#include <asm/uaccess.h>
#include <asm/siginfo.h>
#include <asm/process.h>

#include <linux/unistd.h>
#include <asm/mmu_context.h>
#include <asm/lms.h>


long
sys_rt_sigaction32(int sig, const struct sigaction *act, struct sigaction *oact,
		 size_t sigsetsize)
{
	struct k_sigaction new_sa, old_sa;
	struct k_sigaction32 new_sa32, old_sa32;
	int ret = -EINVAL;

	DebugSig("start (%d, %p, %p, %ld)\n",
			sig, act, oact, sigsetsize);
	DebugSig("sz sa_mask %ld  sz sa_mask32 %ld\n",
		sizeof(new_sa.sa.sa_mask), sizeof(new_sa32.sa.sa_mask));
	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		goto out;

	if (act) {
		if (copy_from_user(&new_sa32.sa, act, sizeof(new_sa32.sa)))
			return -EFAULT;
	}
	DebugSig("sa_handler 0x%lx\n",
			(u64)new_sa32.sa.sa_handler);
	new_sa.sa.sa_handler = (__sighandler_t)(u64)new_sa32.sa.sa_handler;
	new_sa.sa.sa_restorer = (__sigrestore_t)(u64)new_sa32.sa.sa_restorer;
	new_sa.sa.sa_flags = new_sa32.sa.sa_flags;
	new_sa.sa.sa_mask.sig[0] = (int)new_sa32.sa.sa_mask.sig[0];
	
	ret = do_sigaction(sig, act ? &new_sa : NULL, oact ? &old_sa : NULL);
	if (ret) return ret;
	if (!oact) return ret;
	
	old_sa32.sa.sa_handler = (u64)(old_sa.sa.sa_handler) & 0xFFFFFFFF;
	old_sa32.sa.sa_restorer = (u64)(old_sa.sa.sa_restorer) & 0xFFFFFFFF;
	old_sa32.sa.sa_flags = (u32)old_sa.sa.sa_flags;
	old_sa32.sa.sa_mask.sig[0] = old_sa.sa.sa_mask.sig[0];
	
	if (copy_to_user(oact, &old_sa32.sa, sizeof(old_sa32.sa)))
			return -EFAULT;
	
out:
	return ret;
}

struct timeval32 {
        int          tv_sec;         /* seconds */
        int     tv_usec;        /* microseconds */
};

extern struct timezone sys_tz;

asmlinkage long sys_gettimeofday32(struct timeval *tv, struct timezone *tz)
{
	
	if (tv) {
		struct timeval ktv;
		struct timeval32 tv32;
		do_gettimeofday(&ktv);
		tv32.tv_sec = ktv.tv_sec & 0xffffffff;
		tv32.tv_usec = ktv.tv_usec & 0xffffffff;
		if (copy_to_user(tv, &tv32, sizeof(tv32)))
				return -EFAULT;
	}
	if (tz) {
		if (copy_to_user(tz, &sys_tz, sizeof(sys_tz)))
			return -EFAULT;
	}
	return 0;
}

asmlinkage long sys_settimeofday32(struct timeval *tv, struct timezone *tz)
{
	
	struct timeval32	new_tv32;
	struct timezone 	new_tz;
	struct timespec		new_tv;

	if (tv) {
		if (copy_from_user(&new_tv32, tv, sizeof(new_tv32)))
			return -EFAULT;
		
	}
	if (tz) {
		if (copy_from_user(&new_tz, tz, sizeof(*tz)))
			return -EFAULT;
	}
	new_tv.tv_sec = new_tv32.tv_sec;
	new_tv.tv_nsec = new_tv32.tv_usec * 1000;
	return do_sys_settimeofday(tv ? &new_tv : NULL, tz ? &new_tz : NULL);
	return 0;
}

#ifdef CONFIG_COMPAT
int copy_siginfo_to_user32(struct compat_siginfo __user *to,
			   const siginfo_t *from)
{
	int err = 0;

	if (!access_ok(VERIFY_WRITE, to, sizeof(compat_siginfo_t)))
		return -EFAULT;

	BEGIN_USR_PFAULT("lbl_copy_siginfo_to_user32", "0f");
	/*
	 * If you change siginfo_t structure, please make sure that
	 * this code is fixed accordingly.
	 * It should never copy any pad contained in the structure
	 * to avoid security leaks, but must copy the generic
	 * 3 ints plus the relevant union member.
	 */
	to->si_signo = from->si_signo;
	to->si_errno = from->si_errno;
	to->si_code = (short) from->si_code;

	if (from->si_code < 0) {
		to->si_pid = from->si_pid;
		to->si_uid = from->si_uid;
		to->si_ptr = ptr_to_compat(from->si_ptr);
	} else {
		/*
		 * First 32bits of unions are always present:
		 * si_pid === si_band === si_tid === si_addr(LS half)
		 */
		to->_sifields._pad[0] = from->_sifields._pad[0];
		switch (from->si_code >> 16) {
		case __SI_FAULT >> 16:
			break;
		case __SI_SYS >> 16:
			to->si_syscall = from->si_syscall;
			to->si_arch = from->si_arch;
			break;
		case __SI_CHLD >> 16:
			to->si_utime = from->si_utime;
			to->si_stime = from->si_stime;
			to->si_status = from->si_status;
			/* FALL THROUGH */
		default:
		case __SI_KILL >> 16:
			to->si_uid = from->si_uid;
			break;
		case __SI_POLL >> 16:
			to->si_fd = from->si_fd;
			break;
		case __SI_TIMER >> 16:
			to->si_overrun = from->si_overrun;
			to->si_ptr = ptr_to_compat(from->si_ptr);
			break;
			 /* This is not generated by the kernel as of now.  */
		case __SI_RT >> 16:
		case __SI_MESGQ >> 16:
			to->si_uid = from->si_uid;
			to->si_int = from->si_int;
			break;
		}
	}
	LBL_USR_PFAULT("lbl_copy_siginfo_to_user32", "0:");
	if (END_USR_PFAULT)
		err = -EFAULT;

	return err;
}

int copy_siginfo_from_user32(siginfo_t *to, compat_siginfo_t __user *from)
{
	int err = 0;

	if (!access_ok(VERIFY_READ, from, sizeof(compat_siginfo_t)))
		return -EFAULT;

	BEGIN_USR_PFAULT("lbl_copy_siginfo_from_user32", "1f");
	to->si_signo = from->si_signo;
	to->si_errno = from->si_errno;
	to->si_code = from->si_code;

	to->si_pid = from->si_pid;
	to->si_uid = from->si_uid;
	to->si_ptr = compat_ptr(from->si_ptr);
	LBL_USR_PFAULT("lbl_copy_siginfo_from_user32", "1:");
	if (END_USR_PFAULT)
		err = -EFAULT;

	return err;
}
#endif

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
	return arch_ptrace(child, (long)request, (long)caddr, (long)cdata);
}


