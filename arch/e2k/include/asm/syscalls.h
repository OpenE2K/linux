/*
 * syscalls.h - Linux syscall interfaces (arch-specific)
 *
 * Copyright (c) 2008 Jaswinder Singh Rajput
 *
 * This file is released under the GPLv2.
 * See the file COPYING for more details.
 */

#ifndef _ASM_E2K_SYSCALLS_H
#define _ASM_E2K_SYSCALLS_H

#include <linux/compiler.h>
#include <linux/linkage.h>
#include <linux/types.h>

extern unsigned long sys_mmap(unsigned long addr, unsigned long len,
		unsigned long prot, unsigned long flags,
		unsigned long fd, unsigned long off);
extern unsigned long sys_mmap2(unsigned long addr, unsigned long len,
		int prot, int flags, int fd, long pgoff);
extern pid_t sys_clone2(unsigned long flags, unsigned long arg2,
		unsigned long long arg3, struct pt_regs *regs,
		int __user *parent_tidptr, int __user *child_tidptr,
		unsigned long tls);
extern long e2k_sys_clone(unsigned long clone_flags,
		e2k_addr_t new_sp, struct pt_regs *regs,
		int __user *parent_tidptr, int __user *child_tidptr, u64 tls);
extern long e2k_sys_vfork(struct pt_regs *regs);
extern long sys_e2k_longjmp2(struct jmp_info *regs, u64 retval);
extern long sys_e2k_syswork(long syswork, long arg2,
		long arg3, long arg4, long arg5);
extern long e2k_sys_execve(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);

extern long sys_stat64(const char __user *filename,
		struct stat64 __user *statbuf);
extern long sys_fstat64(unsigned long fd, struct stat64 __user *statbuf);
extern long sys_lstat64(const char __user *filename,
		struct stat64 __user *statbuf);

#ifdef CONFIG_RECOVERY
extern long sys_cnt_point(void);
#endif

#ifdef CONFIG_MAC_
extern int sys_macctl(register int request, register void *data,
		register int size);
#endif

extern asmlinkage long sys_set_backtrace(unsigned long *__user buf,
		size_t count, size_t skip, unsigned long flags);
extern asmlinkage long sys_get_backtrace(unsigned long *__user buf,
		size_t count, size_t skip, unsigned long flags);
extern long sys_access_hw_stacks(unsigned long mode,
		unsigned long long __user *frame_ptr, char __user *buf,
		unsigned long buf_size, void __user *real_size);

extern long e2k_sys_getrlimit(unsigned int resource,
		struct rlimit __user *rlim);
#ifdef __ARCH_WANT_SYS_OLD_GETRLIMIT
extern long e2k_sys_old_getrlimit(unsigned int resource,
		struct rlimit __user *rlim);
#endif
extern long e2k_sys_setrlimit(unsigned int resource,
		struct rlimit __user *rlim);

#ifdef	CONFIG_COMPAT
extern long compat_sys_lseek(unsigned int fd, int offset, unsigned int whence);
extern long sys_gettimeofday32(struct timeval *tv, struct timezone *tz);
extern long sys_settimeofday32(struct timeval *tv, struct timezone *tz);
extern long compat_sys_sigpending(u32 *);
extern long compat_sys_sigprocmask(int, u32 *, u32 *);
extern long sys32_pread64(unsigned int fd, char __user *ubuf,
		compat_size_t count, unsigned long poslo, unsigned long poshi);
extern long sys32_pwrite64(unsigned int fd, char __user *ubuf,
		compat_size_t count, unsigned long poslo, unsigned long poshi);
extern long sys32_readahead(int fd, unsigned long offlo,
		unsigned long offhi, compat_size_t count);
extern long sys32_fadvise64(int fd, unsigned long offlo,
		unsigned long offhi, compat_size_t len, int advice);
extern long sys32_fadvise64_64(int fd,
		unsigned long offlo, unsigned long offhi,
		unsigned long lenlo, unsigned long lenhi, int advice);
extern long sys32_sync_file_range(int fd,
		unsigned long off_low, unsigned long off_high,
		unsigned long nb_low, unsigned long nb_high, int flags);
extern long sys32_fallocate(int fd, int mode,
		unsigned long offlo, unsigned long offhi,
		unsigned long lenlo, unsigned long lenhi);
extern long sys32_truncate64(const char __user *path,
		unsigned long low, unsigned long high);
extern long sys32_ftruncate64(unsigned int fd,
		unsigned long low, unsigned long high);
extern long compat_e2k_sys_execve(const char __user *filename,
		const compat_uptr_t __user *argv,
		const compat_uptr_t __user *envp);
extern asmlinkage long compat_sys_set_backtrace(unsigned int *__user buf,
		size_t count, size_t skip, unsigned long flags);
extern asmlinkage long compat_sys_get_backtrace(unsigned int *__user buf,
		size_t count, size_t skip, unsigned long flags);
extern long compat_sys_access_hw_stacks(unsigned long mode,
		unsigned long long __user *frame_ptr, char __user *buf,
		unsigned long buf_size, void __user *real_size);
extern long compat_e2k_sys_getrlimit(unsigned int resource,
	struct compat_rlimit __user *rlim);
extern long compat_e2k_sys_setrlimit(unsigned int resource,
		struct compat_rlimit __user *rlim);
#endif

#endif /* _ASM_E2K_SYSCALLS_H */
