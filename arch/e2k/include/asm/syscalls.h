/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Linux syscall interfaces (arch-specific)
 */

#ifndef _ASM_E2K_SYSCALLS_H
#define _ASM_E2K_SYSCALLS_H

#include <linux/compiler.h>
#include <linux/compat.h>
#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/futex.h>
#include <asm/prot_compat.h>
#include <asm/prot_signal.h>

extern long sys_mmap(unsigned long addr, unsigned long len,
		unsigned long prot, unsigned long flags,
		unsigned long fd, unsigned long off);
extern long sys_mmap2(unsigned long addr, unsigned long len,
		int prot, int flags, int fd, long pgoff);
extern pid_t sys_clone_thread(unsigned long flags, unsigned long arg2,
		unsigned long long arg3, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls);
extern long sys_e2k_longjmp2(struct jmp_info __user *regs, u64 retval);
extern long sys_e2k_syswork(long syswork, long arg2, long arg3);
extern long sys_sigreturn(u64 flags);

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

struct ucontext;
extern long sys_setcontext(const struct ucontext __user *ucp,
		int sigsetsize);
extern long sys_makecontext(struct ucontext __user *ucp, void __user *func,
		u64 args_size, void __user *args, int sigsetsize);
extern long sys_freecontext(struct ucontext __user *ucp);
extern long sys_swapcontext(struct ucontext __user *oucp,
		const struct ucontext __user *ucp, int sigsetsize);

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
			const struct prot_sigaction  __user *act,
			struct prot_sigaction  __user *oact,
			const size_t sigsetsize);

extern long protected_sys_mq_notify(mqd_t mqdes,
				const  struct prot_sigevent __user *sevp,
				long,
				long,
				long,
				long,
				const struct pt_regs	*regs);
extern long protected_sys_timer_create(clockid_t which_clock,
		struct prot_sigevent __user *user_sev, timer_t __user *timerid,
		u64 unused4, u64 unused5, u64 unused6, const struct pt_regs *regs);
extern long protected_sys_sysctl(const unsigned long a1);
extern long protected_sys_clone(const unsigned long	a1,	/* flags */
			 const unsigned long	a2,	/* new_stackptr */
			 const unsigned long a3,/* parent_tidptr */
			 const unsigned long a4,/*  child_tidptr */
			 const unsigned long a5,/* tls */
			 const unsigned long	unused6,
			 struct pt_regs	*regs);
extern long protected_sys_clone3(void __user	*protected_uargs,
				 const size_t	size,
			 const unsigned long	unused3,
			 const unsigned long	unused4,
			 const unsigned long	unused5,
			 const unsigned long	unused6,
			 struct pt_regs	*regs);
extern long protected_sys_execve(const char __user *filename,
		const void __user *u_argv, const void __user *u_envp,
		unsigned long unused4, unsigned long unused5,
		unsigned long unused6, const struct pt_regs *regs);
extern long protected_sys_execveat(int dirfd, const char __user *filename,
		const void __user *u_argv, const void __user *u_envp,
		int flags, unsigned long unused6, const struct pt_regs *regs);
extern long protected_sys_futex(const unsigned long uaddr,
			 const unsigned long	futex_op,
			 const unsigned long	val,
			 const unsigned long a4, /* timeout/val2 */
			 const unsigned long uaddr2,
			 const unsigned long	val3,
			 const struct pt_regs	*regs);
long protected_sys_futex_waitv(struct prot_futex_waitv __user	*waiters,
			       unsigned int			nr_futexes,
			       unsigned int			flags,
			       struct __kernel_timespec __user	*timeout,
			       clockid_t			clockid,
			const unsigned long unused6,
			const struct pt_regs *regs);

extern long protected_sys_getgroups(const long		a1, /* size */
			    const unsigned long a2, /* list[] */
			    const unsigned long unused3,
			    const unsigned long unused4,
			    const unsigned long unused5,
			    const unsigned long unused6,
			    const struct pt_regs  *regs);
extern long protected_sys_setgroups(const long		a1, /* size */
			    const unsigned long a2, /* list[] */
			    const unsigned long unused3,
			    const unsigned long unused4,
			    const unsigned long unused5,
			    const unsigned long unused6,
			    const struct pt_regs  *regs);
extern long protected_sys_ipc(const unsigned long call, /* a1 */
			      long		first,	/* a2 */
			      unsigned long	second,	/* a3 */
			      unsigned long	third,	/* a4 */
			      void __user *const ptr,	/* a5 */
			      long		fifth,	/* a6 */
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
extern long protected_sys_munmap(const unsigned long	addr,	/* a1 */
				 unsigned long		length,	/* a2 */
				 const unsigned long unused3,
				 const unsigned long unused4,
				 const unsigned long unused5,
				 const unsigned long unused6,
				 struct	pt_regs	*regs);
extern long protected_sys_mremap(const unsigned long old_address,
				const unsigned long old_size,
				const unsigned long new_size,
				const unsigned long flags,
				const unsigned long new_address,
				const unsigned long a6,	/* unused */
				struct pt_regs *regs);
extern long protected_sys_mlock(unsigned long	addr,
				size_t	len,
				const unsigned long unused3,
				const unsigned long unused4,
				const unsigned long unused5,
				const unsigned long unused6,
				const struct pt_regs *regs);
extern long protected_sys_mlock2(unsigned long	addr,
				 size_t		len,
				 unsigned int	flags,
				const unsigned long unused4,
				const unsigned long unused5,
				const unsigned long unused6,
				const struct pt_regs *regs);
extern long protected_sys_munlock(unsigned long	addr,
				  size_t	len,
				const unsigned long unused3,
				const unsigned long unused4,
				const unsigned long unused5,
				const unsigned long unused6,
				const struct pt_regs *regs);
extern long protected_sys_move_pages(int pid,
				unsigned long nr_pages,
				const void __user * __user *pages,
				const int __user *nodes,
				int __user *status,
				int flags,
				const struct pt_regs *regs);
extern long protected_sys_open(const char __user *pathname,
			       int		flags,
			       mode_t		mode,
				const unsigned long unused4,
				const unsigned long unused5,
				const unsigned long unused6,
				const struct pt_regs	*regs);
extern long protected_sys_readv(unsigned long fd, const void __user *vec,
			 int vlen, unsigned long a4,
			 unsigned long a5, unsigned long a6,
			 const struct pt_regs *regs);
extern long protected_sys_semctl(const long	semid,	/* a1 */
				 const long	semnum,	/* a2 */
				 const long	cmd,	/* a3 */
				 void __user	*ptr,	/* a4 */
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs	*regs);
extern long protected_sys_shmat(const long	shmid,		/* a1 */
			 const unsigned long shmaddr,	/* a2 */
			 const long		shmflg,		/* a3 */
			 const unsigned long	unused4,
			 const unsigned long	unused5,
			 const unsigned long	unused6,
			 struct pt_regs		*regs);
extern long protected_sys_write(const unsigned int	fd,
				const void __user	*buff,
				const size_t		count,
			  const unsigned long	unused4,
			  const unsigned long	unused5,
			  const unsigned long	unused6,
			  const struct pt_regs	*regs);
extern long protected_sys_writev(unsigned long fd, const void __user *vec,
		int vlen, unsigned long a4, unsigned long a5,
		unsigned long a6, const struct pt_regs *regs);
extern long protected_sys_preadv(unsigned long fd, const void __user *vec,
		int vlen, unsigned long pos_l, unsigned long pos_h,
		unsigned long a6, const struct pt_regs *regs);
extern long protected_sys_pwritev(unsigned long fd, const void __user *vec,
		int vlen, unsigned long pos_l, unsigned long pos_h,
		unsigned long a6, const struct pt_regs *regs);
extern long protected_sys_preadv2(unsigned long fd, const void __user *vec,
		int vlen, unsigned long pos_l, unsigned long pos_h,
		rwf_t flags, const struct pt_regs *regs);
extern long protected_sys_pwritev2(unsigned long fd, const void __user *vec,
		int vlen, unsigned long offset_l,
		unsigned long offset_h, rwf_t flags,
		struct pt_regs *regs);
extern long protected_sys_socketcall(const unsigned long call,
			      const unsigned long __user *args,
			      const unsigned long unused3,
			      const unsigned long unused4,
			      const unsigned long unused5,
			      const unsigned long unused6,
			      const struct pt_regs	*regs);
extern long protected_sys_accept(const int	sockfd,
				 struct sockaddr __user *addr,
				 int __user *addrlen,
			      const unsigned long unused4,
			      const unsigned long unused5,
			      const unsigned long unused6,
			      const struct pt_regs	*regs);
extern long protected_sys_accept4(const int	sockfd,
				  struct sockaddr __user *addr,
				  int __user *addrlen,
				  const int	flags,
			      const unsigned long unused5,
			      const unsigned long unused6,
			      const struct pt_regs	*regs);
extern long protected_sys_getpeername(const int sockfd,
				      struct sockaddr __user *addr, int __user *addrlen,
			const unsigned long unused4,
			const unsigned long unused5,
			const unsigned long unused6,
			const struct pt_regs *regs);
extern long protected_sys_getsockname(const int sockfd,
				      struct sockaddr __user *addr, int __user *addrlen,
			const unsigned long unused4,
			const unsigned long unused5,
			const unsigned long unused6,
			const struct pt_regs *regs);
extern long protected_sys_getsockopt(const int sockfd, const int level, const int optname,
				     char __user *optval,
				     int __user *optlen,
			      const unsigned long unused6,
			      const struct pt_regs	*regs);
extern long protected_sys_setsockopt(const int sockfd, const int level, const int optname,
				     char __user *optval,
				     int	optlen,
			      const unsigned long unused6,
			      const struct pt_regs	*regs);
extern long protected_sys_recvfrom(const int sockfd,
				   void __user *buff, size_t size, const unsigned flags,
				   struct sockaddr __user *src_addr, int __user *strlen,
				const struct pt_regs	*regs);
extern long protected_sys_sendmsg(const unsigned int	sockfd,
			      const void __user		*msg,
			      const unsigned int	flags,
			      const unsigned long unused4,
			      const unsigned long unused5,
			      const unsigned long unused6,
			      const struct pt_regs	*regs);
extern long protected_sys_sendmmsg(const unsigned int	sockfd,
				   struct protected_mmsghdr __user *msgvec,
				   const unsigned int	vlen,
				   const unsigned int	flags,
				   const unsigned long unused5,
				   const unsigned long unused6,
				   const struct pt_regs		*regs);
extern long protected_sys_recvmsg(const unsigned int	socket,
			      const void __user		*message,
			      const unsigned int	flags,
			      const unsigned long unused4,
			      const unsigned long unused5,
			      const unsigned long unused6,
			      const struct pt_regs	*regs);
extern long protected_sys_recvmmsg(const unsigned long	socket,
			      const struct protected_mmsghdr __user *message,
			      const unsigned int  vlen,
			      const unsigned int flags,
			      const unsigned long timeout,
			      const unsigned long unused6,
			      const struct pt_regs	*regs);
extern long protected_sys_uselib(const char __user *library,
				 const unsigned long a2, /* umdd */
				const unsigned long	unused3,
				const unsigned long	unused4,
				const unsigned long	unused5,
				const unsigned long	unused6,
				const struct pt_regs	*regs);
extern long protected_sys_sigaltstack(const struct prot_stack __user *ss_128,
					struct prot_stack __user *old_ss_128,
				      const unsigned long	unused3,
				      const unsigned long	unused4,
				      const unsigned long	unused5,
				      const unsigned long	unused6,
				      const struct pt_regs	*regs);
extern long protected_sys_unuselib(const unsigned long a1, /* addr */
			const unsigned long	unused2,
			const unsigned long	unused3,
			const unsigned long	unused4,
			const unsigned long	unused5,
			const unsigned long	unused6,
				struct pt_regs	*regs);
extern long protected_sys_get_backtrace(const unsigned long buf,
				 size_t count, size_t skip,
				 unsigned long flags,
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs *regs);
extern long protected_sys_set_backtrace(const unsigned long buf,
				 size_t count, size_t skip,
				 unsigned long flags,
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs *regs);
extern long protected_sys_set_robust_list(
				 const unsigned long listhead, /* a1 */
				 const size_t len,	/* a2 */
				 const unsigned long unused3,
				 const unsigned long unused4,
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs	*regs);
extern long protected_sys_get_robust_list(const unsigned long pid,
		e2k_ptr_t __user *head_ptr, size_t __user *len_ptr);
extern long protected_sys_process_vm_readv(const unsigned long	pid,	/* a1 */
				 const struct prot_iovec __user *lvec,	/* a2 */
				 unsigned long		liovcnt,	/* a3 */
				 const struct prot_iovec __user *rvec,	/* a4 */
				 unsigned long		riovcnt,	/* a5 */
				 unsigned long		flags,		/* a6 */
				 const struct pt_regs	*regs);
extern long protected_sys_process_vm_writev(const unsigned long pid,	/*a1*/
				 const struct prot_iovec __user *lvec,	/* a2 */
				 unsigned long			liovcnt,/* a3 */
				 const struct prot_iovec __user *rvec,	/* a4 */
				 unsigned long			riovcnt,/* a5 */
				 unsigned long			flags,	/* a6 */
				 const struct pt_regs	*regs);
extern long protected_sys_vmsplice(int				fd,     /* a1 */
				 const struct prot_iovec __user	*iov,   /* a2 */
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
extern long protected_sys_bpf(const int cmd,			/* a1 */
					void __user *attr,	/* a2 */
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
extern long protected_sys_epoll_pwait(const unsigned long	epfd,		/* a1 */
				      void __user		*event,		/* a2 */
				      const long		maxevents,	/* a3 */
				      const long		timeout,	/* a4 */
				      const unsigned long sigmask,	/* a5 */
				      const unsigned long	sigsetsize,	/* a6 */
				      const struct pt_regs *regs);
extern long protected_sys_epoll_pwait2(const unsigned long   epfd,       /* a1 */
		      void __user       *event,     /* a2 */
		      const long        maxevents,  /* a3 */
		      const unsigned long timeout,  /* a4 */
		      const unsigned long sigmask,  /* a5 */
		      const unsigned long   sigsetsize, /* a6 */
		      const struct pt_regs *regs);
extern long protected_sys_select(int			nfds,		/* a1 */
				 fd_set __user		*readfds,	/* a2 */
				 fd_set __user		*writefds,	/* a3 */
				 fd_set __user		*exceptfds,	/* a4 */
				 struct __kernel_old_timeval __user *timeout,	/* a5 */
				 const unsigned long	unused6,
				 const struct pt_regs *regs);
extern long protected_sys_pselect6(const long			nfds,		/* a1 */
				   const unsigned long readfds,		/* a2 */
				   const unsigned long writefds,		/* a3 */
				   const unsigned long exceptfds,	/* a4 */
				   const unsigned long timeout,		/* a5 */
				   const unsigned long sigmask,		/* a6 */
				   const struct pt_regs *regs);
extern long prot_rt_sigtimedwait(
				sigset_t __user *uthese,
				struct prot_siginfo __user *uinfo,
				struct __kernel_timespec __user *uts,
				size_t sigsetsize,
				const unsigned long unused5,
				const unsigned long unused6,
				const struct pt_regs *regs);
extern long protected_sys_mincore(const unsigned long	addr,	/* a1 */
				 size_t			length,	/* a2 */
				 unsigned char __user	*vec,	/* a3 */
				 const unsigned long unused4,
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs *regs);
extern long protected_sys_process_madvise(const long	pidfd,		/* a1 */
				   void __user		*vec,		/* a2 */
				   const long		len,		/* a3 */
				   const unsigned long	behavior,	/* a4 */
				   const unsigned long	flags,		/* a5 */
				   const unsigned long unused6,		/* a6 */
				   const struct pt_regs *regs);
extern long protected_sys_rt_sigqueueinfo(const long	tgid,	/* a1 */
				     const long		sig,	/* a2 */
				     const void __user *uinfo,	/* a3 */
				     const unsigned long unused4,
				     const unsigned long unused5,
				     const unsigned long unused6,
				     const struct pt_regs *regs);
extern long protected_sys_rt_tgsigqueueinfo(const long	tgid,	/* a1 */
				     const long		tid,	/* a2 */
				     const long		sig,	/* a3 */
				     const void __user *uinfo,	/* a4 */
				     const unsigned long unused5,
				     const unsigned long unused6,
				     const struct pt_regs *regs);
extern long protected_sys_waitid(const long	which,		/* a1 */
			  const long		pid,		/* a2 */
			  void		__user *infop,		/* a3 */
			  const long		options,	/* a4 */
			  void		__user *ru,		/* a5 */
			  const unsigned long unused6,
			  const struct pt_regs *regs);
extern long protected_sys_io_submit(const aio_context_t	ctx_id,		/* a1 */
				    const long		nr,		/* a2 */
				    const struct iocb __user * __user *iocbpp,	/* a3 */
			    const unsigned long unused4,
			    const unsigned long unused5,
			    const unsigned long unused6,
			    const struct pt_regs *regs);
extern long protected_sys_io_uring_register(unsigned int fd,
				     unsigned int opcode,	/* a2 */
				     void __user *arg,		/* a3 */
				     unsigned int nr_args,	/* a4 */
				     const unsigned long unused5,
				     const unsigned long unused6,
				     const struct pt_regs *regs);
extern long protected_sys_io_uring_enter(unsigned int fd, u32 to_submit,
				  u32 min_complete, u32 flags,
				  const void __user *argp,      /* a5 */
				  size_t argsz,                 /* a6 */
				  const struct pt_regs *regs);

extern long protected_sys_kexec_load(unsigned long entry, unsigned long nr_segments,
		unsigned long segments, unsigned long flags, unsigned long unused5,
		unsigned long unused6, const struct pt_regs *regs);
extern long protected_sys_ptrace(long		request,
				 long		pid,
				 unsigned long	addr,
				 unsigned long	data,
				const unsigned long unused5,
				const unsigned long unused6,
				const struct pt_regs *regs);
extern long protected_sys_mprotect(void			*addr,
				   size_t		len,
				   unsigned long	prot,
				const unsigned long unused4,
				const unsigned long unused5,
				const unsigned long unused6,
				const struct pt_regs *regs);
extern long protected_sys_add_key(const char __user *type,
				  const char __user *description,
				  const void __user *payload,
				  size_t plen,
				  key_serial_t destringid,
			const unsigned long unused6,
			const struct pt_regs *regs);
extern long protected_sys_sched_setattr(pid_t pid,
					struct sched_attr __user *attr,
					unsigned int flags,
				 const unsigned long unused4,
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs *regs);
extern long protected_sys_sched_getattr(pid_t pid,
					struct sched_attr __user *attr,
					unsigned int size,
					unsigned int flags,
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs *regs);
extern long sys_unsafe_uint64_to_ptr(unsigned long		addr,
				     unsigned long		options,
				     void __user		*ret_addr,
				const unsigned long unused4,
				const unsigned long unused5,
				const unsigned long unused6,
				struct pt_regs	*regs);

struct ucontext_prot;
extern long protected_sys_setcontext(
		const struct ucontext_prot __user *ucp,
		int sigsetsize);
extern long protected_sys_makecontext(struct ucontext_prot __user *ucp,
		void __user *func, u64 args_size, void __user *args, int sigsetsize);
extern long protected_sys_freecontext(struct ucontext_prot __user *ucp);
extern long protected_sys_swapcontext(struct ucontext_prot __user *oucp,
		const struct ucontext_prot __user *ucp, int sigsetsize);
extern long protected_sys_set_mempolicy_home_node(void __user *start,
						  unsigned long len,
						  unsigned long home_node,
						  unsigned long flags,
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs *regs);
extern long protected_sys_brk(unsigned long addr,
					const unsigned long unused_a2,
					const unsigned long unused_a3,
					const unsigned long unused_a4,
					const unsigned long unused_a5,
					const unsigned long unused_a6,
				struct pt_regs	*regs);
extern long protected_syscall_notyetsupported(const unsigned long unused_a1,
					      const unsigned long unused_a2,
					      const unsigned long unused_a3,
					      const unsigned long unused_a4,
					      const unsigned long unused_a5,
					      const unsigned long unused_a6,
					struct pt_regs	*regs);
extern long protected_sys_msgctl(int msqid, int cmd, void __user * buf,
				 long a4, long a5, long a6, const struct pt_regs *regs);

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

struct ucontext_32;
extern long compat_sys_setcontext(const struct ucontext_32 __user *ucp,
		int sigsetsize);
extern long compat_sys_makecontext(struct ucontext_32 __user *ucp,
		void __user *func, u64 args_size, void __user *args, int sigsetsize);
extern long compat_sys_freecontext(struct ucontext_32 __user *ucp);
extern long compat_sys_swapcontext(struct ucontext_32 __user *oucp,
		const struct ucontext_32 __user *ucp, int sigsetsize);

#endif /* CONFIG_COMPAT */

extern
const char *sys_call_ID_to_name[];

#define SYSCALL_NAME_ON_ID(sys_num) \
	(((u32) (sys_num)) < NR_syscalls ? sys_call_ID_to_name[(u32) (sys_num)] : "BadSyscallID")

#endif /* _ASM_E2K_SYSCALLS_H */
