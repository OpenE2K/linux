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
#include <linux/compat.h>
#include <linux/linkage.h>
#include <linux/types.h>

extern unsigned long sys_mmap(unsigned long addr, unsigned long len,
		unsigned long prot, unsigned long flags,
		unsigned long fd, unsigned long off);
extern unsigned long sys_mmap2(unsigned long addr, unsigned long len,
		int prot, int flags, int fd, long pgoff);
extern pid_t sys_clone_thread(unsigned long flags, unsigned long arg2,
		unsigned long long arg3, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls);
extern long sys_e2k_longjmp2(struct jmp_info *regs, u64 retval);
extern long sys_e2k_syswork(long syswork, long arg2,
		long arg3, long arg4, long arg5);
extern long e2k_sys_execve(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);
extern long e2k_sys_execveat(int fd, const char __user *filename,
		      const char __user *const __user *argv,
		      const char __user *const __user *envp,
		      int flags);

extern long sys_stat64(const char __user *filename,
		struct stat64 __user *statbuf);
extern long sys_fstat64(unsigned long fd, struct stat64 __user *statbuf);
extern long sys_lstat64(const char __user *filename,
		struct stat64 __user *statbuf);

extern asmlinkage long sys_set_backtrace(unsigned long *__user buf,
		size_t count, size_t skip, unsigned long flags);
extern asmlinkage long sys_get_backtrace(unsigned long *__user buf,
		size_t count, size_t skip, unsigned long flags);
extern long sys_access_hw_stacks(unsigned long mode,
		unsigned long long __user *frame_ptr, char __user *buf,
		unsigned long buf_size, void __user *real_size);

extern long e2k_sys_prlimit64(pid_t pid, unsigned int resource,
			const struct rlimit64 __user *new_rlim,
			struct rlimit64 __user *old_rlim);
extern long e2k_sys_getrlimit(unsigned int resource,
		struct rlimit __user *rlim);
#ifdef __ARCH_WANT_SYS_OLD_GETRLIMIT
extern long e2k_sys_old_getrlimit(unsigned int resource,
		struct rlimit __user *rlim);
#endif
extern long e2k_sys_setrlimit(unsigned int resource,
		struct rlimit __user *rlim);

#ifdef	CONFIG_PROTECTED_MODE
extern long protected_sys_clean_descriptors(void __user *addr,
					    unsigned long	size,
					    const unsigned long flags,
					    const unsigned long unused4,
					    const unsigned long unused5,
					    const unsigned long unused6,
					    struct pt_regs	*regs);
/* Flags for the function above see in arch/include/uapi/asm/protected_mode.h */
/* 0 - clean freed descriptor list */

extern long protected_sys_rt_sigaction(int sig,
			const void __user *ptr, void __user *ptr2,
			const size_t sigsetsize);
extern long protected_sys_rt_sigaction_ex(int sig,
			const void __user *ptr, void __user *ptr2,
			const size_t sigsetsize);
extern long protected_sys_mq_notify(const long a1,
					const unsigned long __user a2);
extern long protected_sys_timer_create(const long	a1, /* clockid */
				const unsigned long __user a2, /* sevp */
				const unsigned long __user a3, /* timerid */
				const unsigned long	unused4,
				const unsigned long	unused5,
				const unsigned long	unused6,
				const struct pt_regs	*regs);
extern long protected_sys_rt_sigtimedwait(const unsigned long __user a1,
		const unsigned long __user a2, const unsigned long __user a3,
		const unsigned long a4);
extern long protected_sys_sysctl(const unsigned long __user a1);
extern long protected_sys_clone(const unsigned long	a1,	/* flags */
			 const unsigned long	a2,	/* new_stackptr */
			 const unsigned long __user a3,/* parent_tidptr */
			 const unsigned long __user a4,/*  child_tidptr */
			 const unsigned long __user a5,/* tls */
			 const unsigned long	unused6,
			 struct pt_regs	*regs);
extern long protected_sys_execve(const unsigned long __user a1,/* filename*/
			  const unsigned long __user a2,/* argv[] */
			  const unsigned long __user a3,/* envp[] */
			  const unsigned long	unused4,
			  const unsigned long	unused5,
			  const unsigned long	unused6,
			  const struct pt_regs	*regs);
extern long protected_sys_execveat(const unsigned long dirfd,	/*a1 */
			    const unsigned long __user pathname,/* a2 */
			    const unsigned long __user argv,	/* a3 */
			    const unsigned long __user envp,	/* a4 */
			    const unsigned long		flags,	/* a5 */
			    const unsigned long	unused6,
			    const struct pt_regs	*regs);
extern long protected_sys_futex(const unsigned long __user uaddr,
			 const unsigned long	futex_op,
			 const unsigned long	val,
			 const unsigned long	a4, /* timeout/val2 */
			 const unsigned long __user uaddr2,
			 const unsigned long	val3,
			 const struct pt_regs	*regs);
extern long protected_sys_getgroups(const long		a1, /* size */
			    const unsigned long __user a2, /* list[] */
			    const unsigned long unused3,
			    const unsigned long unused4,
			    const unsigned long unused5,
			    const unsigned long unused6,
			    const struct pt_regs  *regs);
extern long protected_sys_setgroups(const long		a1, /* size */
			    const unsigned long __user a2, /* list[] */
			    const unsigned long unused3,
			    const unsigned long unused4,
			    const unsigned long unused5,
			    const unsigned long unused6,
			    const struct pt_regs  *regs);
extern long protected_sys_ipc(const unsigned long	call,	/* a1 */
			      const long		first,	/* a2 */
			      const unsigned long	second,	/* a3 */
			      const unsigned long	third,	/* a4 */
			      const unsigned long __user ptr,	/* a5 */
			      const long		fifth,	/* a6 */
			      const struct pt_regs	*regs);
extern long protected_sys_mmap(const unsigned long a1, /* start */
			       const unsigned long a2, /* length */
			       const unsigned long a3, /* prot */
			       const unsigned long a4, /* flags */
			       const unsigned long a5, /* fd */
			       const unsigned long a6, /* offset/bytes */
					struct pt_regs	*regs);
extern long protected_sys_mmap2(const unsigned long a1, /* start */
			       const unsigned long a2, /* length */
			       const unsigned long a3, /* prot */
			       const unsigned long a4, /* flags */
			       const unsigned long a5, /* fd */
			       const unsigned long a6, /* offset/pages */
					struct pt_regs	*regs);
extern long protected_sys_munmap(const unsigned long __user a1, /* addr */
				 const unsigned long        a2, /* length */
				 const unsigned long unused3,
				 const unsigned long unused4,
				 const unsigned long unused5,
				 const unsigned long unused6,
				 struct	pt_regs	*regs);
extern long protected_sys_mremap(const unsigned long __user old_address,
				const unsigned long old_size,
				const unsigned long new_size,
				const unsigned long flags,
				const unsigned long new_address,
				const unsigned long a6,	/* unused */
				struct pt_regs *regs);
extern long protected_sys_readv(const unsigned long        a1, /* fd */
			 const unsigned long __user a2, /* iov */
			 const unsigned long        a3, /* iovcnt */
			 const unsigned long	unused4,
			 const unsigned long	unused5,
			 const unsigned long	unused6,
			 const struct pt_regs	*regs);
extern long protected_sys_semctl(const long	semid,	/* a1 */
				 const long	semnum,	/* a2 */
				 const long	cmd,	/* a3 */
				 const unsigned long __user ptr, /* a4 */
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs	*regs);
extern long protected_sys_shmat(const long	shmid,		/* a1 */
			 const unsigned long __user shmaddr,	/* a2 */
			 const long		shmflg,		/* a3 */
			 const unsigned long	unused4,
			 const unsigned long	unused5,
			 const unsigned long	unused6,
			 struct pt_regs		*regs);
extern long protected_sys_writev(const unsigned long        a1, /* fd */
			  const unsigned long __user a2, /* iov */
			  const unsigned long        a3, /* iovcnt */
			  const unsigned long	unused4,
			  const unsigned long	unused5,
			  const unsigned long	unused6,
			  const struct pt_regs	*regs);
extern long protected_sys_preadv(const unsigned long        a1, /* fd */
			  const unsigned long __user a2, /* iov */
			  const unsigned long        a3, /* iovcnt */
			  const unsigned long        a4, /* offset_l */
			  const unsigned long        a5, /* offset_h */
			  const unsigned long	unused6,
			  const struct pt_regs	*regs);
extern long protected_sys_pwritev(const unsigned long        a1, /* fd */
			  const unsigned long __user a2, /* iov */
			  const unsigned long        a3, /* iovcnt */
			  const unsigned long        a4, /* offset_l */
			  const unsigned long        a5, /* offset_h */
			  const unsigned long	unused6,
			  const struct pt_regs	*regs);
extern long protected_sys_preadv2(const unsigned long        a1, /* fd */
			  const unsigned long __user a2, /* iov */
			  const unsigned long        a3, /* iovcnt */
			  const unsigned long        a4, /* offset_l */
			  const unsigned long        a5, /* offset_h*/
			  const unsigned long        a6, /* flags */
			  const struct pt_regs	*regs);
extern long protected_sys_pwritev2(const unsigned long        a1, /* fd */
			   const unsigned long __user a2, /* iov */
			   const unsigned long        a3, /* iovcnt */
			   const unsigned long        a4, /* offset_l */
			   const unsigned long        a5, /* offset_h*/
			   const unsigned long        a6, /* flags */
			   const struct pt_regs	*regs);
extern long protected_sys_socketcall(const unsigned long a1, /* call */
			      const unsigned long __user a2, /* args */
			      const unsigned long unused3,
			      const unsigned long unused4,
			      const unsigned long unused5,
			      const unsigned long unused6,
			      const struct pt_regs	*regs);
extern long protected_sys_sendmsg(const unsigned long	sockfd,
			      const unsigned long __user msg,
			      const unsigned long	flags,
			      const unsigned long unused4,
			      const unsigned long unused5,
			      const unsigned long unused6,
			      const struct pt_regs	*regs);
extern long protected_sys_sendmmsg(const unsigned long	sockfd,
			   const unsigned long __user msgvec,
			   const unsigned long		vlen,
			   const unsigned long		flags,
			   const unsigned long unused5,
			   const unsigned long unused6,
			   const struct pt_regs		*regs);
extern long protected_sys_recvmsg(const unsigned long	socket,
			      const unsigned long __user message,
			      const unsigned long	flags,
			      const unsigned long unused4,
			      const unsigned long unused5,
			      const unsigned long unused6,
			      const struct pt_regs	*regs);
extern long protected_sys_recvmmsg(const unsigned long	socket,
			      const unsigned long __user message,
			      const unsigned long	vlen,
			      const unsigned long	flags,
			      const unsigned long __user timeout,
			      const unsigned long unused6,
			      const struct pt_regs	*regs);
extern long protected_sys_olduselib(const unsigned long __user a1, /* library */
				    const unsigned long __user a2); /* umdd */
	/* NB> 'olduselib' is obsolete syscall; unsupported in CPU ISET V6 */
extern long protected_sys_uselib(const unsigned long __user a1, /* library */
				 const unsigned long __user a2); /* umdd */
extern long protected_sys_sigaltstack(const stack_prot_t __user *ss_128,
					stack_prot_t __user *old_ss_128,
				      const unsigned long	unused3,
				      const unsigned long	unused4,
				      const unsigned long	unused5,
				      const unsigned long	unused6,
				      const struct pt_regs	*regs);
extern long protected_sys_unuselib(const unsigned long	__user a1, /* addr */
			const unsigned long	a2,
			const unsigned long	a3,
			const unsigned long	a4,
			const unsigned long	a5,
			const unsigned long	a6,
				struct pt_regs	*regs);
extern long protected_sys_get_backtrace(const unsigned long __user buf,
				 size_t count, size_t skip,
				 unsigned long flags,
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs *regs);
extern long protected_sys_set_backtrace(const unsigned long __user buf,
				 size_t count, size_t skip,
				 unsigned long flags,
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs *regs);
extern long protected_sys_set_robust_list(
				 const unsigned long __user listhead, /* a1 */
				 const size_t len,	/* a2 */
				 const unsigned long unused3,
				 const unsigned long unused4,
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs	*regs);
extern long protected_sys_get_robust_list(const unsigned long pid,
				 unsigned long __user head_ptr,
				 unsigned long __user len_ptr);
extern long protected_sys_process_vm_readv(const unsigned long pid, /*a1*/
				 const struct iovec __user *lvec, /* a2 */
				 unsigned long liovcnt,           /* a3 */
				 const struct iovec __user *rvec, /* a4 */
				 unsigned long riovcnt,           /* a5 */
				 unsigned long flags,             /* a6 */
				 const struct pt_regs	*regs);
extern long protected_sys_process_vm_writev(const unsigned long pid, /*a1*/
				 const struct iovec __user *lvec, /* a2 */
				 unsigned long liovcnt,           /* a3 */
				 const struct iovec __user *rvec, /* a4 */
				 unsigned long riovcnt,           /* a5 */
				 unsigned long flags,             /* a6 */
				 const struct pt_regs	*regs);
extern long protected_sys_vmsplice(int				fd,     /* a1 */
				 const struct iovec __user	*iov,   /* a2 */
				 unsigned long			nr_segs, /*a3 */
				 unsigned int			flags,  /* a4 */
				 const unsigned long		unused5,
				 const unsigned long		unused6,
				 const struct pt_regs		*regs);
extern long protected_sys_keyctl(const int		operation, /* a1 */
				 const unsigned long		arg2,
				 const unsigned long		arg3,
				 const unsigned long		arg4,
				 const unsigned long		arg5,
				 const unsigned long		unused6,
				 const struct pt_regs		*regs);
extern long protected_sys_prctl(const int		option, /* a1 */
				 const unsigned long		arg2,
				 const unsigned long		arg3,
				 const unsigned long		arg4,
				 const unsigned long		arg5,
				 const unsigned long		unused6,
				 const struct pt_regs		*regs);
extern long protected_sys_ioctl(const int		fd,		/* a1 */
				const unsigned long	request,	/* a2 */
				const unsigned long __user argp,	/* a3 */
				const unsigned long	unused4,
				const unsigned long	unused5,
				const unsigned long	unused6,
				const struct pt_regs	*regs);
extern long protected_sys_bpf(const int cmd,			/* a1 */
			      const unsigned long __user attr,	/* a2 */
			      const unsigned int size,		/* a3 */
			      const unsigned long unused4,
			      const unsigned long unused5,
			      const unsigned long unused6,
			      const struct pt_regs *regs);
extern long protected_sys_epoll_ctl(const unsigned long epfd,	/* a1 */
				    const unsigned long op,	/* a2 */
				    const unsigned long fd,	/* a3 */
				    void __user	*event,	/* a4 */
				    const unsigned long unused5,
				    const unsigned long unused6,
				    const struct pt_regs *regs);
extern long protected_sys_epoll_wait(const unsigned long epfd,		/* a1 */
				     void __user	*event,		/* a2 */
				     const long		maxevents,	/* a3 */
				     const long		timeout,	/* a4 */
				     const unsigned long unused5,
				     const unsigned long unused6,
				     const struct pt_regs *regs);
extern long protected_sys_epoll_pwait(const unsigned long epfd,		/* a1 */
				      void __user	*event,		/* a2 */
				      const long	maxevents,	/* a3 */
				      const long	timeout,	/* a4 */
				      const unsigned long sigmask,	/* a5 */
				      const unsigned long sigsetsize,	/* a6 */
				      const struct pt_regs *regs);
extern long protected_sys_pselect6(const long		nfds,		/* a1 */
				   const unsigned long readfds,		/* a2 */
				   const unsigned long writefds,	/* a3 */
				   const unsigned long exceptfds,	/* a4 */
				   const unsigned long timeout,		/* a5 */
				   const unsigned long sigmask,		/* a6 */
				   const struct pt_regs *regs);
extern long protected_sys_rt_sigqueueinfo(const long		tgid,	/* a1 */
				     const long			sig,	/* a2 */
				     const unsigned long __user uinfo,	/* a3 */
				     const unsigned long unused4,
				     const unsigned long unused5,
				     const unsigned long unused6,
				     const struct pt_regs *regs);
extern long protected_sys_rt_tgsigqueueinfo(const long		tgid,	/* a1 */
				     const long			tid,	/* a2 */
				     const long			sig,	/* a3 */
				     const unsigned long __user uinfo,	/* a4 */
				     const unsigned long unused5,
				     const unsigned long unused6,
				     const struct pt_regs *regs);
extern long protected_sys_pidfd_send_signal(const long		pidfd,	/* a1 */
				     const long			sig,	/* a2 */
				     const unsigned long __user info,	/* a3 */
				     unsigned long		flags,	/* a4 */
				     const unsigned long unused5,
				     const unsigned long unused6,
				     const struct pt_regs *regs);
extern long protected_sys_waitid(const long	which,		/* a1 */
			  const long		pid,		/* a2 */
			  const unsigned long __user *infop,	/* a3 */
			  const long		options,	/* a4 */
			  const unsigned long __user *ru,	/* a5 */
			  const unsigned long unused6,
			  const struct pt_regs *regs);
extern long protected_sys_io_uring_register(const unsigned long	fd,	/* a1 */
				     const unsigned long	opcode,	/* a2 */
				     const unsigned long __user arg,	/* a3 */
				     const unsigned long nr_args,	/* a4 */
				     const unsigned long unused5,
				     const unsigned long unused6,
				     const struct pt_regs *regs);
extern long protected_sys_kexec_load(const unsigned long entry,		/* a1 */
			      const unsigned long	nr_segments,	/* a2 */
			      const unsigned long __user segments,	/* a3 */
			      const unsigned long	flags,		/* a4 */
			      const unsigned long unused5,
			      const unsigned long unused6,
			      const struct pt_regs *regs);

extern int arch_init_pm_sc_debug_mode(const int debug_mask);

/*
 * Storing descriptor attributes in the sival_ptr_list list.
 * The descriptor may be restored with the function that follows.
 */
static inline
void store_descriptor_attrs(void *kernel_ptr,
			    const long user_ptr_lo, const long user_ptr_hi,
			    const int ptr_tags, const int signum)
{
	struct sival_ptr_list *new;

	/* Saving kernel_ptr in sival_ptr_list: */
	new = kmalloc(sizeof(*new), GFP_KERNEL);
	new->kernel_ptr = kernel_ptr;
	new->user_ptr_lo = user_ptr_lo;
	new->user_ptr_hi = user_ptr_hi;
	new->user_tags = ptr_tags;
	new->signum = signum;

	/* Saving sival_ptr in sival_ptr_list: */
	down_write(&(current->mm->context.sival_ptr_list_sem));
	/* Add new element as head of the list */
	list_add(&new->link, &(current->mm->context.sival_ptr_list_head));
	up_write(&(current->mm->context.sival_ptr_list_sem));
}

/*
 * Returns record with saved descriptor attributes (in sival_ptr_list)
 *         for the given pointer/signal number couple or NULL.
 */
static inline
struct sival_ptr_list *get_descriptor_attrs(const void *kernel_ptr,
					    const int signum)
{
	struct sival_ptr_list *ret = NULL, *siptrl_ln;

	/*
	 * We look thru sival_ptr_list to find a record with the same
	 *        kernel pointer and signum if specified:
	 */
	down_read(&current->mm->context.sival_ptr_list_sem);
	list_for_each_entry(siptrl_ln,
			   &current->mm->context.sival_ptr_list_head, link) {
		if (siptrl_ln->kernel_ptr == kernel_ptr) {
			if (!signum || (siptrl_ln->signum == signum)) {
				ret = siptrl_ln;
				break;
			}
		}
	}
	up_read(&current->mm->context.sival_ptr_list_sem);
	return ret;
}
#endif	/* CONFIG_PROTECTED_MODE */

#ifdef	CONFIG_COMPAT
extern long compat_sys_lseek(unsigned int fd, int offset, unsigned int whence);
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
extern long compat_e2k_sys_execveat(int fd, const char __user *filename,
		      const compat_uptr_t __user *argv,
		      const compat_uptr_t __user *envp,
		      int flags);
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
